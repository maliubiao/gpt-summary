Response:
Let's break down the thought process for analyzing this V8 C++ source code.

**1. Initial Skim and Understanding the Context:**

* **File Path:** `v8/src/builtins/builtins-string.cc` immediately tells us this file contains the implementation of built-in string methods in V8. The `.cc` extension signifies C++ source.
* **Copyright Header:**  Standard boilerplate, confirming it's part of the V8 project.
* **Includes:** The `#include` directives are crucial. They point to the core functionalities this code depends on:
    * `builtins-utils-inl.h`, `builtins.h`:  General V8 built-in infrastructure.
    * `heap/heap-inl.h`:  Heap management, hinting at object creation.
    * `logging/counters.h`: Usage tracking.
    * `numbers/conversions.h`: Converting between number types.
    * `objects/objects-inl.h`, `objects/intl-objects.h`: V8's object model, particularly string objects and potentially internationalization.
    * `base/strings.h`:  Basic string utilities.
    * `regexp/regexp-utils.h`: Regular expression related functions.
    * `strings/string-builder-inl.h`, `strings/string-case.h`, `strings/unicode-inl.h`, `strings/unicode.h`: String manipulation and Unicode support.
* **Namespaces:**  `v8::internal` is where V8's internal implementation lives. The anonymous namespace `{}` is for file-local helper functions.

**2. Identifying Key Functionalities (The Core Logic):**

* **`StringFromCodePoint`:** The name strongly suggests converting Unicode code points to strings. The code confirms this by iterating through arguments, validating them as code points, and constructing the resulting string (handling both one-byte and two-byte characters).
* **`StringPrototypeLastIndexOf`:**  A standard JavaScript string method. The code calls an internal `String::LastIndexOf` function, indicating this is a direct implementation.
* **`StringPrototypeLocaleCompare`:**  Another familiar JavaScript string method for locale-aware comparison. The `#ifndef V8_INTL_SUPPORT` block is a big clue: it provides a basic, non-internationalized fallback.
* **`StringPrototypeNormalize`:** Deals with Unicode normalization forms. Again, the `#ifndef V8_INTL_SUPPORT` suggests a simplified version when internationalization is disabled.
* **`ConvertCaseHelper` and `ConvertCase` (within the `#ifndef V8_INTL_SUPPORT` block):** These functions handle converting strings to upper and lower case. The logic includes optimizations for ASCII strings and handling cases where a single character expands to multiple characters.
* **`StringPrototypeToLocaleLowerCase`, `StringPrototypeToLocaleUpperCase`, `StringPrototypeToLowerCase`, `StringPrototypeToUpperCase`:** These built-ins call the `ConvertCase` function, confirming their purpose.
* **`StringRaw`:** Implements the `String.raw()` template literal tag function. It processes the template object and arguments to construct the raw string.

**3. Answering the Specific Questions:**

* **Functionality Listing:**  Based on the identified key functionalities, it's straightforward to list them.
* **Torque Source:**  The file extension is `.cc`, not `.tq`, so it's C++.
* **JavaScript Relationship and Examples:**  For each identified built-in function, its corresponding JavaScript method is usually obvious (e.g., `StringFromCodePoint` maps to `String.fromCodePoint()`). Providing simple JavaScript examples demonstrates the connection.
* **Code Logic Reasoning (Input/Output):**  Focus on the non-trivial functions like `StringFromCodePoint` and `ConvertCase`. Choose simple but illustrative inputs to show the logic (e.g., single code point, multiple code points, code points requiring surrogate pairs).
* **Common Programming Errors:**  Think about how developers might misuse these JavaScript string methods. Examples include providing invalid code points to `String.fromCodePoint()`, assuming `localeCompare()` does a simple alphabetical comparison, or misunderstanding how `String.raw()` works with template literals.

**4. Refinement and Organization:**

* Group related functionalities together (e.g., case conversion methods).
* Use clear and concise language.
* Format the output for readability (e.g., using bullet points, code blocks).
* Double-check the accuracy of the information.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Maybe some of these functions deal with regular expressions because of the include."
* **Correction:** While there's a regexp include, the functions themselves don't directly manipulate regular expressions. The include is likely for internal string operations that might be used by regex functionality elsewhere.
* **Initial thought:** "The `ConvertCaseHelper` seems overly complex."
* **Clarification:**  Recognize that the complexity arises from optimizations (like the two-pass approach) and handling Unicode's variable-width character representations.

By following this structured approach, we can systematically analyze the C++ source code and provide a comprehensive and accurate answer to the user's request. The key is to understand the context, identify the core functionalities, and then relate them back to their JavaScript counterparts and potential usage scenarios.
这个C++源代码文件 `v8/src/builtins/builtins-string.cc` 实现了 V8 JavaScript 引擎中 `String` 对象的内置方法（built-in functions）。

**功能列表:**

该文件主要包含了以下 `String` 对象的内置方法的实现：

* **`String.fromCodePoint(...codePoints)`:**  根据指定的 Unicode 码点创建一个字符串。
* **`String.prototype.lastIndexOf(searchString[, position])`:**  返回调用该方法的字符串中最后一次出现指定值的索引，如果没找到则返回 -1。
* **`String.prototype.localeCompare(that)`:**  返回一个数字来指示一个参考字符串是否在排序顺序前面或后面，或者与给定的字符串相同。 此方法提供了一种特定于语言环境的字符串比较方式。 (在未启用国际化支持的情况下，提供一个简单的实现)
* **`String.prototype.normalize([form])`:**  按照指定的一种 Unicode 归一化形式将字符串归一化。 (在未启用国际化支持的情况下，仅验证参数并返回原字符串)
* **`String.prototype.toLocaleLowerCase()`:**  根据宿主环境的当前区域设置将调用该方法的字符串转换为小写形式。 (在未启用国际化支持的情况下，提供一个基础实现)
* **`String.prototype.toLocaleUpperCase()`:**  根据宿主环境的当前区域设置将调用该方法的字符串转换为大写形式。 (在未启用国际化支持的情况下，提供一个基础实现)
* **`String.prototype.toLowerCase()`:**  将调用该方法的字符串转换为小写形式。 (在未启用国际化支持的情况下，提供一个基础实现)
* **`String.prototype.toUpperCase()`:**  将调用该方法的字符串转换为大写形式。 (在未启用国际化支持的情况下，提供一个基础实现)
* **`String.raw(template, ...substitutions)`:**  是一个模板字符串的标签函数，用来获取模板字符串的原始字面量内容（即不进行任何转义）。

**关于 `.tq` 后缀:**

`v8/src/builtins/builtins-string.cc` **不是**以 `.tq` 结尾的。 因此，它不是 V8 Torque 源代码。 Torque 是 V8 用于定义内置函数的一种类型安全的 DSL (Domain Specific Language)。  `.cc` 结尾的文件是 C++ 源代码。

**与 JavaScript 功能的关系及示例:**

这个 C++ 文件直接实现了 JavaScript 中 `String` 对象的方法。  下面是一些 JavaScript 示例，展示了这些方法的功能：

* **`String.fromCodePoint()`:**

```javascript
console.log(String.fromCodePoint(65));   // 输出 "A"
console.log(String.fromCodePoint(97, 98, 99)); // 输出 "abc"
console.log(String.fromCodePoint(0x1F600)); // 输出 "😀" (笑脸 emoji)
```

* **`String.prototype.lastIndexOf()`:**

```javascript
const str = 'canal';
console.log(str.lastIndexOf('a'));     // 输出 3
console.log(str.lastIndexOf('a', 2));  // 输出 1
console.log(str.lastIndexOf('z'));     // 输出 -1
```

* **`String.prototype.localeCompare()`:**

```javascript
const a = 'apple';
const b = 'banana';
console.log(a.localeCompare(b)); // 输出 -1 (在大多数语言环境中，'apple' 在 'banana' 之前)
console.log(b.localeCompare(a)); // 输出 1
console.log(a.localeCompare(a)); // 输出 0
```

* **`String.prototype.normalize()`:**

```javascript
const str1 = '\u00F1'; // ñ (单个字符)
const str2 = 'n\u0303'; // n + 组合字符 ̃
console.log(str1 === str2); // 输出 false
console.log(str1.normalize() === str2.normalize()); // 输出 true (都归一化为 NFC 形式)
```

* **`String.prototype.toLocaleLowerCase()` 和 `String.prototype.toLowerCase()`:**

```javascript
const str = 'ALPHABET';
console.log(str.toLowerCase());         // 输出 "alphabet"
console.log(str.toLocaleLowerCase());   // 在大多数情况下也输出 "alphabet"，但在某些语言环境中可能不同 (例如土耳其语的 'I')
```

* **`String.prototype.toLocaleUpperCase()` 和 `String.prototype.toUpperCase()`:**

```javascript
const str = 'alphabet';
console.log(str.toUpperCase());         // 输出 "ALPHABET"
console.log(str.toLocaleUpperCase());   // 在大多数情况下也输出 "ALPHABET"，但在某些语言环境中可能不同 (例如土耳其语的 'i')
```

* **`String.raw()`:**

```javascript
const name = 'Bob';
console.log(`Hi\n${name}!`);          // 输出 "Hi\nBob!" (换行符被解释)
console.log(String.raw`Hi\n${name}!`); // 输出 "Hi\\nBob!" (换行符未被解释，保持原始字面量)
```

**代码逻辑推理 (假设输入与输出):**

**示例 1: `StringFromCodePoint`**

* **假设输入:**  `args` 包含数字 `65`, `98`, `0x1F603` (分别代表 'A', 'b', 和 "😃")
* **内部处理:**
    * 遍历 `args` 中的每个数字。
    * 验证这些数字是否是有效的 Unicode 码点 (0 到 0x10FFFF)。
    * 将码点转换为对应的字符。
    * 将字符组合成字符串。
* **预期输出:** 一个 V8 内部的字符串对象，其 JavaScript 值等同于 `"Ab😃"`。

**示例 2: `StringPrototypeLastIndexOf`**

* **假设输入:**
    * `args.receiver()` (调用 `lastIndexOf` 的字符串) 是 `"banana"`。
    * `args.atOrUndefined(isolate, 1)` (搜索字符串) 是 `"an"`。
    * `args.atOrUndefined(isolate, 2)` (起始位置，可选) 未提供。
* **内部处理:**
    * 从字符串的末尾开始向前搜索 `"an"`。
    * 找到最后一次出现的索引。
* **预期输出:**  一个 V8 内部的数字对象，其 JavaScript 值等同于 `3` (因为 `"an"` 最后一次出现在 "banana" 的索引 3 的位置)。

**用户常见的编程错误:**

* **`String.fromCodePoint()` 中使用无效的码点:**

```javascript
console.log(String.fromCodePoint(-1));    // RangeError: Invalid code point -1
console.log(String.fromCodePoint(0x110000)); // RangeError: Invalid code point 1114112
```
   **错误说明:** 用户提供的数字超出了 Unicode 码点的有效范围。

* **误解 `String.prototype.localeCompare()` 的行为:**

```javascript
const arr = ['zebra', 'apple', 'Banana'];
arr.sort();
console.log(arr); // 输出 ["Banana", "apple", "zebra"] (默认排序是区分大小写的)

arr.sort((a, b) => a.localeCompare(b));
console.log(arr); // 输出 ["apple", "Banana", "zebra"] (使用 localeCompare 进行不区分大小写的排序，但仍然考虑语言环境)
```
   **错误说明:** 用户可能期望简单的字母顺序排序，而 `localeCompare` 会根据语言环境进行排序，可能导致与预期不同的结果。

* **错误地使用 `String.raw()`:**

```javascript
const userDir = 'C:\\Users\\John';
console.log(userDir);                    // 输出 "C:\Users\John" (反斜杠被转义)
console.log(String.raw`C:\Users\John`);  // 输出 "C:\\Users\\John" (反斜杠未被转义)
```
   **错误说明:** 用户可能不理解 `String.raw()` 的目的是获取原始字符串内容，而不会进行转义。在不需要转义的情况下，直接使用普通字符串可能更清晰。

总而言之，`v8/src/builtins/builtins-string.cc` 是 V8 引擎中至关重要的文件，它使用 C++ 代码高效地实现了 JavaScript 中常用的字符串操作，并考虑了性能和国际化等方面的因素。

Prompt: 
```
这是目录为v8/src/builtins/builtins-string.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-string.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
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

"""

```