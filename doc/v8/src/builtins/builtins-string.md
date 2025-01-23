Response: Let's break down the thought process for analyzing this C++ code for V8's string builtins.

1. **Initial Skim and Identification of Key Areas:**

   - Read through the code, paying attention to comments starting with `// ES6 section`. These clearly indicate which JavaScript string methods are being implemented.
   - Notice the `BUILTIN` macros. These are V8's way of defining built-in functions. The names within the `BUILTIN` macro (e.g., `StringFromCodePoint`, `StringPrototypeLastIndexOf`) directly correspond to JavaScript string methods.
   - Identify included header files. These hint at the functionalities involved: `builtins-utils-inl.h`, `builtins.h` (general builtins), `heap-inl.h` (memory management), `logging/counters.h` (performance tracking), `numbers/conversions.h`, `objects/objects-inl.h`, `intl-objects.h` (internationalization), `base/strings.h`, `regexp/regexp-utils.h`, `strings/string-builder-inl.h`, `strings/string-case.h`, `strings/unicode-inl.h`, `strings/unicode.h`. The string-related headers are particularly important.
   - Look for helper functions and namespaces. The anonymous namespace at the beginning suggests utility functions specific to this file.

2. **Mapping C++ Builtins to JavaScript Methods:**

   - Systematically go through each `BUILTIN` function and identify the corresponding JavaScript `String` method based on the ES6 section comment and the `BUILTIN` name. Create a list:
     - `StringFromCodePoint` -> `String.fromCodePoint()`
     - `StringPrototypeLastIndexOf` -> `String.prototype.lastIndexOf()`
     - `StringPrototypeLocaleCompare` -> `String.prototype.localeCompare()`
     - `StringPrototypeNormalize` -> `String.prototype.normalize()`
     - `StringPrototypeToLocaleLowerCase` -> `String.prototype.toLocaleLowerCase()`
     - `StringPrototypeToLocaleUpperCase` -> `String.prototype.toLocaleUpperCase()`
     - `StringPrototypeToLowerCase` -> `String.prototype.toLowerCase()`
     - `StringPrototypeToUpperCase` -> `String.prototype.toUpperCase()`
     - `StringRaw` -> `String.raw()`

3. **Analyzing the Functionality of Each Builtin:**

   - **`StringFromCodePoint`:**
     - The code iterates through arguments, treats them as code points, validates them, and builds a string. It handles both single-byte and two-byte characters (for characters outside the basic multilingual plane).
     - The helper functions `IsValidCodePoint` and `NextCodePoint` handle validation and conversion of input arguments to code points.

   - **`StringPrototypeLastIndexOf`:**
     - Directly calls `String::LastIndexOf`. This suggests the core logic for `lastIndexOf` might reside in a lower-level string utility class.

   - **`StringPrototypeLocaleCompare`:**
     - Has `#ifndef V8_INTL_SUPPORT`. This is a key observation. It indicates this is a fallback implementation when internationalization support is *not* compiled in. The code performs a basic character-by-character comparison.

   - **`StringPrototypeNormalize`:**
     - Similar to `localeCompare`, it has `#ifndef V8_INTL_SUPPORT`. This fallback implementation only validates the normalization form argument.

   - **Case Conversion (`toLocaleLowerCase`, `toLocaleUpperCase`, `toLowerCase`, `toUpperCase`):**
     - These all delegate to a common `ConvertCase` function.
     - The `ConvertCase` function handles both one-byte and two-byte strings. It attempts an optimization for ASCII strings.
     - It uses `unibrow::Mapping` for case conversion, suggesting it relies on Unicode data for correct conversions.
     - The `ConvertCaseHelper` function does the actual character-by-character conversion.

   - **`StringRaw`:**
     - Implements the template literal raw string functionality. It accesses the `raw` property of the template object and interleaves the raw parts with the evaluated expressions.
     - It uses `IncrementalStringBuilder` for efficient string construction.

4. **Connecting C++ to JavaScript Examples:**

   - For each builtin, think about how the corresponding JavaScript method is used and what it does. Provide simple, illustrative examples. Focus on the core functionality demonstrated by the C++ code. For instance:
     - `String.fromCodePoint`: Show how it creates strings from Unicode code points.
     - `String.prototype.lastIndexOf`: Demonstrate finding the last occurrence of a substring.
     - `String.prototype.localeCompare`: Show basic comparisons (important to note the fallback behavior).
     - `String.prototype.normalize`: Show the concept of normalization (even if the C++ is basic).
     - Case conversion: Show simple examples of converting case.
     - `String.raw`: Demonstrate how it prevents escape sequence interpretation.

5. **Summarizing the Functionality:**

   - Combine the analysis of each builtin into a concise summary. Highlight the main purpose of the file (implementing JavaScript string built-in methods).
   - Mention the use of helper functions, Unicode handling, and the special handling of internationalization.

6. **Review and Refine:**

   - Read through the summary and examples. Ensure they are accurate and clear.
   - Check for any missing key aspects or potential misunderstandings. For example, the optimization in `ConvertCase` for ASCII strings is worth mentioning. The use of `HandleScope` for memory management in V8 is a detail, but not strictly necessary for a functional summary.

**Self-Correction/Refinement during the process:**

- Initially, I might just list the JavaScript methods. But then I'd realize I need to explain *what* each C++ function does in relation to its JavaScript counterpart.
- I might overlook the `#ifndef V8_INTL_SUPPORT` initially, but a second pass would catch it and highlight the fallback behavior for `localeCompare` and `normalize`.
- When explaining the case conversion, I'd need to emphasize the Unicode handling and the optimization for ASCII strings.
- For `StringRaw`, realizing it's about template literals and the `raw` property is crucial.

By following these steps, one can systematically analyze the C++ code and effectively explain its functionality and its relationship to JavaScript. The key is to connect the C++ implementation details to the observable behavior of the corresponding JavaScript methods.
这个C++源代码文件 `builtins-string.cc` 位于 V8 引擎的 `v8/src/builtins` 目录下，负责实现 **JavaScript 中 `String` 对象的一些内置方法 (built-in methods)**。

**主要功能归纳:**

该文件包含了以下 JavaScript `String` 构造函数和原型方法的 C++ 实现：

* **`String.fromCodePoint(...codePoints)`:**  根据指定的 Unicode 码点序列创建一个字符串。
* **`String.prototype.lastIndexOf(searchString [, position])`:**  返回指定子字符串在字符串中最后一次出现的索引，从 `position` 开始向前搜索。
* **`String.prototype.localeCompare(that)`:**  比较两个字符串在当前区域设置下的顺序。 (在没有国际化支持的情况下，提供一个简单的基于字符编码的比较)
* **`String.prototype.normalize([form])`:**  按照指定的 Unicode 规范化形式返回字符串。 (在没有国际化支持的情况下，仅验证参数并返回原字符串)
* **`String.prototype.toLocaleLowerCase()`:**  根据宿主环境的当前区域设置将字符串转换为小写。 (在没有国际化支持的情况下，提供一个基本的转换)
* **`String.prototype.toLocaleUpperCase()`:**  根据宿主环境的当前区域设置将字符串转换为大写。 (在没有国际化支持的情况下，提供一个基本的转换)
* **`String.prototype.toLowerCase()`:**  将字符串转换为小写。
* **`String.prototype.toUpperCase()`:**  将字符串转换为大写。
* **`String.raw(template, ...substitutions)`:**  返回由模板字符串的原始字面量组成的字符串。

**与 JavaScript 功能的关系和示例:**

这个 C++ 文件中的代码是 V8 引擎实现 JavaScript `String` 对象行为的核心部分。当你在 JavaScript 中调用这些 `String` 方法时，V8 引擎最终会执行这里定义的 C++ 代码。

下面用 JavaScript 举例说明其中一些方法的对应关系：

**1. `String.fromCodePoint()`**

```javascript
// JavaScript
let str1 = String.fromCodePoint(65, 97, 0x4E00); // 65 是 'A'，97 是 'a'，0x4E00 是汉字 '一'
console.log(str1); // 输出: A一

// C++ (builtins-string.cc 中的 StringFromCodePoint 函数负责实现这个功能)
// 该函数会接收参数 65, 97, 0x4E00，然后构建相应的字符串。
```

**2. `String.prototype.lastIndexOf()`**

```javascript
// JavaScript
let str2 = "hello world hello";
let lastIndex = str2.lastIndexOf("hello");
console.log(lastIndex); // 输出: 12

// C++ (builtins-string.cc 中的 StringPrototypeLastIndexOf 函数负责实现)
// 该函数会接收字符串 "hello world hello" 和搜索字符串 "hello"，然后执行查找逻辑。
```

**3. `String.prototype.localeCompare()`**

```javascript
// JavaScript
let str3 = "apple";
let str4 = "banana";
let result = str3.localeCompare(str4);
console.log(result); // 输出: -1 (表示 "apple" 在本地排序中排在 "banana" 之前)

// C++ (builtins-string.cc 中的 StringPrototypeLocaleCompare 函数负责实现)
// 如果没有国际化支持，则会进行简单的字符编码比较。
// 如果有国际化支持，可能会委托给更复杂的 ICU 库进行处理。
```

**4. `String.prototype.toUpperCase()`**

```javascript
// JavaScript
let str5 = "hello";
let upperStr = str5.toUpperCase();
console.log(upperStr); // 输出: HELLO

// C++ (builtins-string.cc 中的 StringPrototypeToUpperCase 函数负责实现)
// 该函数会遍历字符串 "hello" 的每个字符，并将其转换为大写。
```

**5. `String.raw()`**

```javascript
// JavaScript
let name = "Bob";
let template = `Hello\n${name}!`;
let rawTemplate = String.raw`Hello\n${name}!`;

console.log(template);     // 输出: Hello
                         //       Bob!
console.log(rawTemplate);  // 输出: Hello\nBob!

// C++ (builtins-string.cc 中的 StringRaw 函数负责实现)
// 该函数会处理模板字符串，提取原始字面量部分，并替换掉表达式的结果。
```

**总结:**

`builtins-string.cc` 文件是 V8 引擎中非常重要的一个组成部分，它直接负责实现 JavaScript 中 `String` 对象的核心功能。理解这个文件中的代码，可以更深入地了解 JavaScript 字符串操作的底层实现机制。需要注意的是，一些与国际化相关的方法 (如 `localeCompare` 和 `normalize`) 在没有国际化支持的情况下会提供简化的实现，真正的国际化支持通常由 V8 引擎的其他部分（例如与 ICU 库的集成）来完成。

### 提示词
```
这是目录为v8/src/builtins/builtins-string.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "src/builtins/builtins-utils-inl.h"
#include "src/builtins/builtins.h"
#include "src/heap/heap-inl.h"  // For ToBoolean. TODO(jkummerow): Drop.
#include "src/logging/counters.h"
#include "src/numbers/conversions.h"
#include "src/objects/objects-inl.h"
#ifdef V8_INTL_SUPPORT
#include "src/objects/intl-objects.h"
#endif
#include "src/base/strings.h"
#include "src/regexp/regexp-utils.h"
#include "src/strings/string-builder-inl.h"
#include "src/strings/string-case.h"
#include "src/strings/unicode-inl.h"
#include "src/strings/unicode.h"

namespace v8 {
namespace internal {

namespace {  // for String.fromCodePoint

bool IsValidCodePoint(Isolate* isolate, Handle<Object> value) {
  if (!IsNumber(*value) && !Object::ToNumber(isolate, value).ToHandle(&value)) {
    return false;
  }

  if (Object::NumberValue(
          *Object::ToInteger(isolate, value).ToHandleChecked()) !=
      Object::NumberValue(*value)) {
    return false;
  }

  if (Object::NumberValue(*value) < 0 ||
      Object::NumberValue(*value) > 0x10FFFF) {
    return false;
  }

  return true;
}

static constexpr base::uc32 kInvalidCodePoint = static_cast<base::uc32>(-1);

base::uc32 NextCodePoint(Isolate* isolate, BuiltinArguments args, int index) {
  Handle<Object> value = args.at(1 + index);
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, value, Object::ToNumber(isolate, value), kInvalidCodePoint);
  if (!IsValidCodePoint(isolate, value)) {
    isolate->Throw(*isolate->factory()->NewRangeError(
        MessageTemplate::kInvalidCodePoint, value));
    return kInvalidCodePoint;
  }
  return DoubleToUint32(Object::NumberValue(*value));
}

}  // namespace

// ES6 section 21.1.2.2 String.fromCodePoint ( ...codePoints )
BUILTIN(StringFromCodePoint) {
  HandleScope scope(isolate);
  int const length = args.length() - 1;
  if (length == 0) return ReadOnlyRoots(isolate).empty_string();
  DCHECK_LT(0, length);

  // Optimistically assume that the resulting String contains only one byte
  // characters.
  std::vector<uint8_t> one_byte_buffer;
  one_byte_buffer.reserve(length);
  base::uc32 code = 0;
  int index;
  for (index = 0; index < length; index++) {
    code = NextCodePoint(isolate, args, index);
    if (code == kInvalidCodePoint) {
      return ReadOnlyRoots(isolate).exception();
    }
    if (code > String::kMaxOneByteCharCode) {
      break;
    }
    one_byte_buffer.push_back(code);
  }

  if (index == length) {
    RETURN_RESULT_OR_FAILURE(
        isolate, isolate->factory()->NewStringFromOneByte(base::Vector<uint8_t>(
                     one_byte_buffer.data(), one_byte_buffer.size())));
  }

  std::vector<base::uc16> two_byte_buffer;
  two_byte_buffer.reserve(length - index);

  while (true) {
    if (code <=
        static_cast<base::uc32>(unibrow::Utf16::kMaxNonSurrogateCharCode)) {
      two_byte_buffer.push_back(code);
    } else {
      two_byte_buffer.push_back(unibrow::Utf16::LeadSurrogate(code));
      two_byte_buffer.push_back(unibrow::Utf16::TrailSurrogate(code));
    }

    if (++index == length) {
      break;
    }
    code = NextCodePoint(isolate, args, index);
    if (code == kInvalidCodePoint) {
      return ReadOnlyRoots(isolate).exception();
    }
  }

  Handle<SeqTwoByteString> result;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, result,
      isolate->factory()->NewRawTwoByteString(
          static_cast<int>(one_byte_buffer.size() + two_byte_buffer.size())));

  DisallowGarbageCollection no_gc;
  CopyChars(result->GetChars(no_gc), one_byte_buffer.data(),
            one_byte_buffer.size());
  CopyChars(result->GetChars(no_gc) + one_byte_buffer.size(),
            two_byte_buffer.data(), two_byte_buffer.size());

  return *result;
}

// ES6 section 21.1.3.9
// String.prototype.lastIndexOf ( searchString [ , position ] )
BUILTIN(StringPrototypeLastIndexOf) {
  HandleScope handle_scope(isolate);
  return String::LastIndexOf(isolate, args.receiver(),
                             args.atOrUndefined(isolate, 1),
                             args.atOrUndefined(isolate, 2));
}

#ifndef V8_INTL_SUPPORT
// ES6 section 21.1.3.10 String.prototype.localeCompare ( that )
//
// For now, we do not do anything locale specific.
// If internationalization is enabled, then intl.js will override this function
// and provide the proper functionality, so this is just a fallback.
BUILTIN(StringPrototypeLocaleCompare) {
  HandleScope handle_scope(isolate);

  isolate->CountUsage(v8::Isolate::UseCounterFeature::kStringLocaleCompare);
  static const char* const kMethod = "String.prototype.localeCompare";

  DCHECK_LE(2, args.length());

  TO_THIS_STRING(str1, kMethod);
  Handle<String> str2;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, str2,
                                     Object::ToString(isolate, args.at(1)));

  if (str1.is_identical_to(str2)) return Smi::zero();  // Equal.
  int str1_length = str1->length();
  int str2_length = str2->length();

  // Decide trivial cases without flattening.
  if (str1_length == 0) {
    if (str2_length == 0) return Smi::zero();  // Equal.
    return Smi::FromInt(-str2_length);
  } else {
    if (str2_length == 0) return Smi::FromInt(str1_length);
  }

  int end = str1_length < str2_length ? str1_length : str2_length;

  // No need to flatten if we are going to find the answer on the first
  // character. At this point we know there is at least one character
  // in each string, due to the trivial case handling above.
  int d = str1->Get(0) - str2->Get(0);
  if (d != 0) return Smi::FromInt(d);

  str1 = String::Flatten(isolate, str1);
  str2 = String::Flatten(isolate, str2);

  DisallowGarbageCollection no_gc;
  String::FlatContent flat1 = str1->GetFlatContent(no_gc);
  String::FlatContent flat2 = str2->GetFlatContent(no_gc);

  for (int i = 0; i < end; i++) {
    if (flat1.Get(i) != flat2.Get(i)) {
      return Smi::FromInt(flat1.Get(i) - flat2.Get(i));
    }
  }

  return Smi::FromInt(str1_length - str2_length);
}

// ES6 section 21.1.3.12 String.prototype.normalize ( [form] )
//
// Simply checks the argument is valid and returns the string itself.
// If internationalization is enabled, then intl.js will override this function
// and provide the proper functionality, so this is just a fallback.
BUILTIN(StringPrototypeNormalize) {
  HandleScope handle_scope(isolate);
  TO_THIS_STRING(string, "String.prototype.normalize");

  Handle<Object> form_input = args.atOrUndefined(isolate, 1);
  if (IsUndefined(*form_input, isolate)) return *string;

  Handle<String> form;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, form,
                                     Object::ToString(isolate, form_input));

  if (!(String::Equals(isolate, form, isolate->factory()->NFC_string()) ||
        String::Equals(isolate, form, isolate->factory()->NFD_string()) ||
        String::Equals(isolate, form, isolate->factory()->NFKC_string()) ||
        String::Equals(isolate, form, isolate->factory()->NFKD_string()))) {
    Handle<String> valid_forms =
        isolate->factory()->NewStringFromStaticChars("NFC, NFD, NFKC, NFKD");
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewRangeError(MessageTemplate::kNormalizationForm, valid_forms));
  }

  return *string;
}
#endif  // !V8_INTL_SUPPORT


#ifndef V8_INTL_SUPPORT
namespace {

inline bool ToUpperOverflows(base::uc32 character) {
  // y with umlauts and the micro sign are the only characters that stop
  // fitting into one-byte when converting to uppercase.
  static const base::uc32 yuml_code = 0xFF;
  static const base::uc32 micro_code = 0xB5;
  return (character == yuml_code || character == micro_code);
}

template <class Converter>
V8_WARN_UNUSED_RESULT static Tagged<Object> ConvertCaseHelper(
    Isolate* isolate, Tagged<String> string, Tagged<SeqString> result,
    uint32_t result_length, unibrow::Mapping<Converter, 128>* mapping) {
  DisallowGarbageCollection no_gc;
  // We try this twice, once with the assumption that the result is no longer
  // than the input and, if that assumption breaks, again with the exact
  // length.  This may not be pretty, but it is nicer than what was here before
  // and I hereby claim my vaffel-is.
  //
  // NOTE: This assumes that the upper/lower case of an ASCII
  // character is also ASCII.  This is currently the case, but it
  // might break in the future if we implement more context and locale
  // dependent upper/lower conversions.
  bool has_changed_character = false;

  // Convert all characters to upper case, assuming that they will fit
  // in the buffer
  StringCharacterStream stream(string);
  unibrow::uchar chars[Converter::kMaxWidth];
  // We can assume that the string is not empty
  base::uc32 current = stream.GetNext();
  bool ignore_overflow = Converter::kIsToLower || IsSeqTwoByteString(result);
  for (uint32_t i = 0; i < result_length;) {
    bool has_next = stream.HasMore();
    base::uc32 next = has_next ? stream.GetNext() : 0;
    uint32_t char_length = mapping->get(current, next, chars);
    if (char_length == 0) {
      // The case conversion of this character is the character itself.
      result->Set(i, current);
      i++;
    } else if (char_length == 1 &&
               (ignore_overflow || !ToUpperOverflows(current))) {
      // Common case: converting the letter resulted in one character.
      DCHECK(static_cast<base::uc32>(chars[0]) != current);
      result->Set(i, chars[0]);
      has_changed_character = true;
      i++;
    } else if (result_length == string->length()) {
      bool overflows = ToUpperOverflows(current);
      // We've assumed that the result would be as long as the
      // input but here is a character that converts to several
      // characters.  No matter, we calculate the exact length
      // of the result and try the whole thing again.
      //
      // Note that this leaves room for optimization.  We could just
      // memcpy what we already have to the result string.  Also,
      // the result string is the last object allocated we could
      // "realloc" it and probably, in the vast majority of cases,
      // extend the existing string to be able to hold the full
      // result.
      uint32_t next_length = 0;
      if (has_next) {
        next_length = mapping->get(next, 0, chars);
        if (next_length == 0) next_length = 1;
      }
      uint32_t current_length = i + char_length + next_length;
      while (stream.HasMore()) {
        current = stream.GetNext();
        overflows |= ToUpperOverflows(current);
        // NOTE: we use 0 as the next character here because, while
        // the next character may affect what a character converts to,
        // it does not in any case affect the length of what it convert
        // to.
        int char_length = mapping->get(current, 0, chars);
        if (char_length == 0) char_length = 1;
        current_length += char_length;
        if (current_length > String::kMaxLength) {
          AllowGarbageCollection allocate_error_and_return;
          THROW_NEW_ERROR_RETURN_FAILURE(isolate,
                                         NewInvalidStringLengthError());
        }
      }
      // Try again with the real length.  Return signed if we need
      // to allocate a two-byte string for to uppercase.
      return (overflows && !ignore_overflow) ? Smi::FromInt(-current_length)
                                             : Smi::FromInt(current_length);
    } else {
      for (uint32_t j = 0; j < char_length; j++) {
        result->Set(i, chars[j]);
        i++;
      }
      has_changed_character = true;
    }
    current = next;
  }
  if (has_changed_character) {
    return result;
  } else {
    // If we didn't actually change anything in doing the conversion
    // we simple return the result and let the converted string
    // become garbage; there is no reason to keep two identical strings
    // alive.
    return string;
  }
}

template <class Converter>
V8_WARN_UNUSED_RESULT static Tagged<Object> ConvertCase(
    Handle<String> s, Isolate* isolate,
    unibrow::Mapping<Converter, 128>* mapping) {
  s = String::Flatten(isolate, s);
  uint32_t length = s->length();
  // Assume that the string is not empty; we need this assumption later
  if (length == 0) return *s;

  // Simpler handling of ASCII strings.
  //
  // NOTE: This assumes that the upper/lower case of an ASCII
  // character is also ASCII.  This is currently the case, but it
  // might break in the future if we implement more context and locale
  // dependent upper/lower conversions.
  if (s->IsOneByteRepresentation()) {
    // Same length as input.
    Handle<SeqOneByteString> result =
        isolate->factory()->NewRawOneByteString(length).ToHandleChecked();
    DisallowGarbageCollection no_gc;
    String::FlatContent flat_content = s->GetFlatContent(no_gc);
    DCHECK(flat_content.IsFlat());
    bool has_changed_character = false;
    uint32_t index_to_first_unprocessed =
        FastAsciiConvert<Converter::kIsToLower>(
            reinterpret_cast<char*>(result->GetChars(no_gc)),
            reinterpret_cast<const char*>(
                flat_content.ToOneByteVector().begin()),
            length, &has_changed_character);
    // If not ASCII, we discard the result and take the 2 byte path.
    if (index_to_first_unprocessed == length)
      return has_changed_character ? *result : *s;
  }

  Handle<SeqString> result;  // Same length as input.
  if (s->IsOneByteRepresentation()) {
    result = isolate->factory()->NewRawOneByteString(length).ToHandleChecked();
  } else {
    result = isolate->factory()->NewRawTwoByteString(length).ToHandleChecked();
  }

  Tagged<Object> answer =
      ConvertCaseHelper(isolate, *s, *result, length, mapping);
  if (IsException(answer, isolate) || IsString(answer)) return answer;

  DCHECK(IsSmi(answer));
  // In this case we need to retry with a new string of the given length.
  // If the value is negative, the string must be a two-byte string.
  int int_answer = Smi::ToInt(answer);
  if (s->IsOneByteRepresentation() && int_answer > 0) {
    length = int_answer;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, result, isolate->factory()->NewRawOneByteString(length));
  } else {
    length = abs(int_answer);
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, result, isolate->factory()->NewRawTwoByteString(length));
  }
  return ConvertCaseHelper(isolate, *s, *result, length, mapping);
}

}  // namespace

BUILTIN(StringPrototypeToLocaleLowerCase) {
  HandleScope scope(isolate);
  TO_THIS_STRING(string, "String.prototype.toLocaleLowerCase");
  return ConvertCase(string, isolate,
                     isolate->runtime_state()->to_lower_mapping());
}

BUILTIN(StringPrototypeToLocaleUpperCase) {
  HandleScope scope(isolate);
  TO_THIS_STRING(string, "String.prototype.toLocaleUpperCase");
  return ConvertCase(string, isolate,
                     isolate->runtime_state()->to_upper_mapping());
}

BUILTIN(StringPrototypeToLowerCase) {
  HandleScope scope(isolate);
  TO_THIS_STRING(string, "String.prototype.toLowerCase");
  return ConvertCase(string, isolate,
                     isolate->runtime_state()->to_lower_mapping());
}

BUILTIN(StringPrototypeToUpperCase) {
  HandleScope scope(isolate);
  TO_THIS_STRING(string, "String.prototype.toUpperCase");
  return ConvertCase(string, isolate,
                     isolate->runtime_state()->to_upper_mapping());
}
#endif  // !V8_INTL_SUPPORT

// ES6 #sec-string.prototype.raw
BUILTIN(StringRaw) {
  HandleScope scope(isolate);
  Handle<Object> templ = args.atOrUndefined(isolate, 1);
  const uint32_t argc = args.length();
  Handle<String> raw_string =
      isolate->factory()->NewStringFromAsciiChecked("raw");

  Handle<JSReceiver> cooked;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, cooked,
                                     Object::ToObject(isolate, templ));

  Handle<JSAny> raw;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, raw,
      Cast<JSAny>(Object::GetProperty(isolate, cooked, raw_string)));
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, raw,
                                     Object::ToObject(isolate, raw));
  Handle<Object> raw_len;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, raw_len,
      Object::GetProperty(isolate, raw, isolate->factory()->length_string()));

  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, raw_len,
                                     Object::ToLength(isolate, raw_len));

  IncrementalStringBuilder result_builder(isolate);
  // Intentional spec violation: we ignore {length} values >= 2^32, because
  // assuming non-empty chunks they would generate too-long strings anyway.
  const double raw_len_number = Object::NumberValue(*raw_len);
  const uint32_t length = raw_len_number > std::numeric_limits<uint32_t>::max()
                              ? std::numeric_limits<uint32_t>::max()
                              : static_cast<uint32_t>(raw_len_number);
  if (length > 0) {
    Handle<Object> first_element;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, first_element,
                                       Object::GetElement(isolate, raw, 0));

    Handle<String> first_string;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, first_string, Object::ToString(isolate, first_element));
    result_builder.AppendString(first_string);

    for (uint32_t i = 1, arg_i = 2; i < length; i++, arg_i++) {
      if (arg_i < argc) {
        Handle<String> argument_string;
        ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
            isolate, argument_string,
            Object::ToString(isolate, args.at(arg_i)));
        result_builder.AppendString(argument_string);
      }

      Handle<Object> element;
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, element,
                                         Object::GetElement(isolate, raw, i));

      Handle<String> element_string;
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, element_string,
                                         Object::ToString(isolate, element));
      result_builder.AppendString(element_string);
    }
  }

  RETURN_RESULT_OR_FAILURE(isolate, result_builder.Finish());
}

}  // namespace internal
}  // namespace v8
```