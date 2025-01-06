Response: Let's break down the thought process for analyzing this C++ code and connecting it to JavaScript's URI functions.

**1. Initial Skim and Keyword Spotting:**

First, I'd quickly read through the code, looking for familiar terms and patterns. I'd immediately notice:

* **`// Copyright 2016 the V8 project authors`**:  This confirms it's part of V8, the JavaScript engine for Chrome and Node.js. This is a crucial clue.
* **`#include "src/strings/uri.h"`**:  The file name itself suggests it deals with URIs.
* **`namespace v8 { namespace internal { ... } }`**:  This indicates it's internal V8 implementation details.
* **`DecodeURI` and `EncodeURI`**: These are strong hints about the functionality.
* **`%`**: The presence of the percent sign strongly suggests URI encoding/decoding is involved.
* **`IsReservedPredicate`, `IsUnescapePredicateInUriComponent`, `IsUriSeparator`**: These look like helper functions to classify URI characters.
* **`TwoDigitHex`**:  This points to handling hexadecimal representations, likely for percent-encoded characters.
* **`Utf8::Encode`, `Utf8::Decode`**:  This confirms UTF-8 encoding/decoding is part of the process, which is essential for handling international characters in URIs.
* **`MaybeHandle<String>`, `Handle<String>`**: These are V8's internal ways of managing strings, further solidifying the connection to JavaScript strings.
* **`NewStringFromOneByte`, `NewRawTwoByteString`, `NewConsString`**: These are V8 functions for creating different types of strings (one-byte, two-byte, concatenated).

**2. Focusing on the Main Functions:**

The function signatures are key:

* **`MaybeHandle<String> Uri::Decode(Isolate* isolate, Handle<String> uri, bool is_uri)`**: This clearly takes a V8 string representing a URI and returns a decoded string. The `is_uri` parameter likely differentiates between full URIs and URI components.
* **`MaybeHandle<String> Uri::Encode(Isolate* isolate, Handle<String> uri, bool is_uri)`**:  The counterpart to `Decode`, encoding a URI string.
* **`MaybeHandle<String> Uri::Escape(Isolate* isolate, Handle<String> string)`**:  This suggests a more general escaping mechanism, potentially used for `escape()` in JavaScript.
* **`MaybeHandle<String> Uri::Unescape(Isolate* isolate, Handle<String> string)`**:  The counterpart to `Escape`, potentially for `unescape()`.

**3. Analyzing the `Decode` Function's Logic:**

* The code iterates through the input URI string.
* It looks for `%` characters, which indicate percent-encoded sequences.
* `TwoDigitHex` is used to convert the hex digits after `%` into numbers.
* It handles multi-byte UTF-8 sequences.
* It distinguishes between one-byte and two-byte characters.
* The `is_uri` flag influences whether reserved characters are re-encoded.

**4. Analyzing the `Encode` Function's Logic:**

* The code iterates through the input string.
* It checks characters against `IsUnescapePredicateInUriComponent` and `IsUriSeparator` to decide if they need encoding.
* `EncodeSingle` and `EncodePair` handle encoding single and surrogate pair characters into UTF-8 byte sequences.
* `AddEncodedOctetToBuffer` adds the `%HH` encoded representation to the buffer.

**5. Analyzing the `Escape` and `Unescape` Functions:**

* These functions seem to implement a different, more general escaping mechanism.
* `UnescapeChar` handles both `%HH` and `%uHHHH` formats.
* `EscapePrivate` encodes characters outside a specific set using `%HH` or `%uHHHH`.
* The logic seems closer to JavaScript's `escape()` and `unescape()`.

**6. Connecting to JavaScript:**

Based on the function names, parameters, and internal logic, the connection to JavaScript becomes clearer:

* **`Uri::Decode` likely implements the core logic for `decodeURI()` and `decodeURIComponent()`**. The `is_uri` flag probably distinguishes between the two.
* **`Uri::Encode` likely implements the core logic for `encodeURI()` and `encodeURIComponent()`**. Again, `is_uri` likely differentiates them.
* **`Uri::Escape` likely implements the logic for the deprecated `escape()` function.**  The encoding rules seem to match.
* **`Uri::Unescape` likely implements the logic for the deprecated `unescape()` function.**

**7. Constructing the JavaScript Examples:**

With the understanding of the C++ code's functionality, I can now create JavaScript examples that demonstrate the equivalent behavior:

* **`decodeURI()`/`decodeURIComponent()`**: Show how they decode percent-encoded characters, handling UTF-8 and reserved characters appropriately.
* **`encodeURI()`/`encodeURIComponent()`**: Demonstrate how they encode characters, paying attention to the sets of characters that are encoded by each function.
* **`escape()`/`unescape()`**:  Illustrate their specific encoding/decoding behavior, highlighting the differences from the `encodeURI`/`decodeURI` family.

**8. Refinement and Clarification:**

Finally, I'd review my analysis and examples, ensuring they are accurate, clear, and address the prompt's request to explain the functionality and its relationship to JavaScript. I'd emphasize the internal nature of the C++ code within the V8 engine.

This step-by-step approach, starting with high-level observation and gradually digging into the details, allows for a comprehensive understanding and the ability to connect the C++ implementation to the corresponding JavaScript functionality.
这个C++源代码文件 `uri.cc` 位于 V8 JavaScript 引擎的 `src/strings` 目录下，它的主要功能是**实现 URI（统一资源标识符）的编码和解码操作**。

更具体地说，它提供了以下核心功能：

1. **`Uri::Decode(Isolate* isolate, Handle<String> uri, bool is_uri)`:**  这个函数负责解码 URI 字符串。它接收一个 V8 字符串对象 `uri` 和一个布尔值 `is_uri` 作为输入。
    * 如果 `is_uri` 为 `true`，则按照完整 URI 的解码规则进行解码。这意味着保留字符（例如 `#`, `?`, `/` 等）不会被解码。
    * 如果 `is_uri` 为 `false`，则按照 URI 组件的解码规则进行解码。这意味着保留字符也会被解码。
    * 它处理 `%` 编码的字符，包括单字节和多字节 UTF-8 字符。
    * 如果解码过程中遇到无效的 `%` 编码，会抛出一个 `URIError`。

2. **`Uri::Encode(Isolate* isolate, Handle<String> uri, bool is_uri)`:** 这个函数负责编码 URI 字符串。它同样接收一个 V8 字符串对象 `uri` 和一个布尔值 `is_uri` 作为输入。
    * 如果 `is_uri` 为 `true`，则按照完整 URI 的编码规则进行编码。这意味着某些保留字符（URI 分隔符）不会被编码。
    * 如果 `is_uri` 为 `false`，则按照 URI 组件的编码规则进行编码。这意味着更多的字符会被编码。
    * 它将不安全的字符和非 ASCII 字符编码为 `%` 加上两位十六进制数的形式。

3. **`Uri::Escape(Isolate* isolate, Handle<String> string)` 和 `Uri::Unescape(Isolate* isolate, Handle<String> string)`:** 这两个函数实现了更通用的字符串转义和反转义功能，类似于 JavaScript 中已废弃的 `escape()` 和 `unescape()` 函数的行为。它们会将某些字符转换为 `%uXXXX` 或 `%XX` 的形式。

**与 JavaScript 的功能关系以及示例:**

这个 `uri.cc` 文件中的代码是 V8 引擎实现 JavaScript 中与 URI 处理相关的全局函数的核心。 具体来说，它直接支持了以下 JavaScript 函数：

* **`decodeURI(encodedURI)`:**  在 JavaScript 中，`decodeURI()` 函数用于解码由 `encodeURI()` 创建的 URI。 `Uri::Decode` 函数在 `is_uri` 为 `true` 时实现了 `decodeURI()` 的逻辑。

   ```javascript
   // JavaScript 示例
   const encoded = "https://example.com/path%20with%20spaces?query=param%26value";
   const decoded = decodeURI(encoded);
   console.log(decoded); // 输出: "https://example.com/path with spaces?query=param&value"
   ```

* **`decodeURIComponent(encodedURIComponent)`:**  `decodeURIComponent()` 函数用于解码由 `encodeURIComponent()` 创建的 URI 组件。 `Uri::Decode` 函数在 `is_uri` 为 `false` 时实现了 `decodeURIComponent()` 的逻辑。

   ```javascript
   // JavaScript 示例
   const encodedComponent = "param%26value";
   const decodedComponent = decodeURIComponent(encodedComponent);
   console.log(decodedComponent); // 输出: "param&value"
   ```

* **`encodeURI(uri)`:**  在 JavaScript 中，`encodeURI()` 函数通过用转义序列替换某些字符来对 URI 进行编码。 `Uri::Encode` 函数在 `is_uri` 为 `true` 时实现了 `encodeURI()` 的逻辑。

   ```javascript
   // JavaScript 示例
   const uri = "https://example.com/path with spaces?query=param&value";
   const encoded = encodeURI(uri);
   console.log(encoded); // 输出: "https://example.com/path%20with%20spaces?query=param&value"
   ```

* **`encodeURIComponent(component)`:**  `encodeURIComponent()` 函数通过用一到四个表示字符的 UTF-8 编码的转义序列替换每一个字符（除了字母数字字符、! - . * ' ( ) 和 ~）来对 URI 组件进行编码。 `Uri::Encode` 函数在 `is_uri` 为 `false` 时实现了 `encodeURIComponent()` 的逻辑。

   ```javascript
   // JavaScript 示例
   const component = "param&value";
   const encodedComponent = encodeURIComponent(component);
   console.log(encodedComponent); // 输出: "param%26value"
   ```

* **`escape(string)` (已废弃):**  虽然已经废弃，但 `Uri::Escape` 函数实现了类似 `escape()` 的功能。

   ```javascript
   // JavaScript 示例 (请注意: escape() 已废弃，不推荐使用)
   const str = "Hello World!";
   const escapedStr = escape(str);
   console.log(escapedStr); // 输出: "Hello%20World%21"
   ```

* **`unescape(string)` (已废弃):**  与 `escape()` 对应，`Uri::Unescape` 实现了类似 `unescape()` 的功能。

   ```javascript
   // JavaScript 示例 (请注意: unescape() 已废弃，不推荐使用)
   const escapedStr = "Hello%20World%21";
   const unescapedStr = unescape(escapedStr);
   console.log(unescapedStr); // 输出: "Hello World!"
   ```

**总结:**

`v8/src/strings/uri.cc` 文件是 V8 引擎中处理 URI 编码和解码的核心 C++ 代码。它实现了 JavaScript 中 `decodeURI`, `decodeURIComponent`, `encodeURI`, `encodeURIComponent`, 以及已废弃的 `escape` 和 `unescape` 函数的基础逻辑。通过操作 V8 内部的字符串对象，它使得 JavaScript 能够安全可靠地处理和表示 URI 数据。

Prompt: 
```
这是目录为v8/src/strings/uri.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/strings/uri.h"

#include <vector>

#include "src/execution/isolate-inl.h"
#include "src/strings/char-predicates-inl.h"
#include "src/strings/string-search.h"
#include "src/strings/unicode-inl.h"

namespace v8 {
namespace internal {

namespace {  // anonymous namespace for DecodeURI helper functions
bool IsReservedPredicate(base::uc16 c) {
  switch (c) {
    case '#':
    case '$':
    case '&':
    case '+':
    case ',':
    case '/':
    case ':':
    case ';':
    case '=':
    case '?':
    case '@':
      return true;
    default:
      return false;
  }
}

bool IsReplacementCharacter(const uint8_t* octets, int length) {
  // The replacement character is at codepoint U+FFFD in the Unicode Specials
  // table. Its UTF-8 encoding is 0xEF 0xBF 0xBD.
  if (length != 3 || octets[0] != 0xEF || octets[1] != 0xBF ||
      octets[2] != 0xBD) {
    return false;
  }
  return true;
}

bool DecodeOctets(const uint8_t* octets, int length,
                  std::vector<base::uc16>* buffer) {
  size_t cursor = 0;
  base::uc32 value = unibrow::Utf8::ValueOf(octets, length, &cursor);
  if (value == unibrow::Utf8::kBadChar &&
      !IsReplacementCharacter(octets, length)) {
    return false;
  }

  if (value <=
      static_cast<base::uc32>(unibrow::Utf16::kMaxNonSurrogateCharCode)) {
    buffer->push_back(value);
  } else {
    buffer->push_back(unibrow::Utf16::LeadSurrogate(value));
    buffer->push_back(unibrow::Utf16::TrailSurrogate(value));
  }
  return true;
}

int TwoDigitHex(base::uc16 character1, base::uc16 character2) {
  if (character1 > 'f') return -1;
  int high = base::HexValue(character1);
  if (high == -1) return -1;
  if (character2 > 'f') return -1;
  int low = base::HexValue(character2);
  if (low == -1) return -1;
  return (high << 4) + low;
}

template <typename T>
void AddToBuffer(base::uc16 decoded, String::FlatContent* uri_content,
                 int index, bool is_uri, std::vector<T>* buffer) {
  if (is_uri && IsReservedPredicate(decoded)) {
    buffer->push_back('%');
    base::uc16 first = uri_content->Get(index + 1);
    base::uc16 second = uri_content->Get(index + 2);
    DCHECK_GT(std::numeric_limits<T>::max(), first);
    DCHECK_GT(std::numeric_limits<T>::max(), second);

    buffer->push_back(first);
    buffer->push_back(second);
  } else {
    buffer->push_back(decoded);
  }
}

bool IntoTwoByte(int index, bool is_uri, int uri_length,
                 String::FlatContent* uri_content,
                 std::vector<base::uc16>* buffer) {
  for (int k = index; k < uri_length; k++) {
    base::uc16 code = uri_content->Get(k);
    if (code == '%') {
      int two_digits;
      if (k + 2 >= uri_length ||
          (two_digits = TwoDigitHex(uri_content->Get(k + 1),
                                    uri_content->Get(k + 2))) < 0) {
        return false;
      }
      k += 2;
      base::uc16 decoded = static_cast<base::uc16>(two_digits);
      if (decoded > unibrow::Utf8::kMaxOneByteChar) {
        uint8_t octets[unibrow::Utf8::kMaxEncodedSize];
        octets[0] = decoded;

        int number_of_continuation_bytes = 0;
        while ((decoded << ++number_of_continuation_bytes) & 0x80) {
          if (number_of_continuation_bytes > 3 || k + 3 >= uri_length) {
            return false;
          }
          if (uri_content->Get(++k) != '%' ||
              (two_digits = TwoDigitHex(uri_content->Get(k + 1),
                                        uri_content->Get(k + 2))) < 0) {
            return false;
          }
          k += 2;
          base::uc16 continuation_byte = static_cast<base::uc16>(two_digits);
          octets[number_of_continuation_bytes] = continuation_byte;
        }

        if (!DecodeOctets(octets, number_of_continuation_bytes, buffer)) {
          return false;
        }
      } else {
        AddToBuffer(decoded, uri_content, k - 2, is_uri, buffer);
      }
    } else {
      buffer->push_back(code);
    }
  }
  return true;
}

bool IntoOneAndTwoByte(DirectHandle<String> uri, bool is_uri,
                       std::vector<uint8_t>* one_byte_buffer,
                       std::vector<base::uc16>* two_byte_buffer) {
  DisallowGarbageCollection no_gc;
  String::FlatContent uri_content = uri->GetFlatContent(no_gc);

  int uri_length = uri->length();
  for (int k = 0; k < uri_length; k++) {
    base::uc16 code = uri_content.Get(k);
    if (code == '%') {
      int two_digits;
      if (k + 2 >= uri_length ||
          (two_digits = TwoDigitHex(uri_content.Get(k + 1),
                                    uri_content.Get(k + 2))) < 0) {
        return false;
      }

      base::uc16 decoded = static_cast<base::uc16>(two_digits);
      if (decoded > unibrow::Utf8::kMaxOneByteChar) {
        return IntoTwoByte(k, is_uri, uri_length, &uri_content,
                           two_byte_buffer);
      }

      AddToBuffer(decoded, &uri_content, k, is_uri, one_byte_buffer);
      k += 2;
    } else {
      if (code > unibrow::Utf8::kMaxOneByteChar) {
        return IntoTwoByte(k, is_uri, uri_length, &uri_content,
                           two_byte_buffer);
      }
      one_byte_buffer->push_back(code);
    }
  }
  return true;
}

}  // anonymous namespace

MaybeHandle<String> Uri::Decode(Isolate* isolate, Handle<String> uri,
                                bool is_uri) {
  uri = String::Flatten(isolate, uri);
  std::vector<uint8_t> one_byte_buffer;
  std::vector<base::uc16> two_byte_buffer;

  if (!IntoOneAndTwoByte(uri, is_uri, &one_byte_buffer, &two_byte_buffer)) {
    THROW_NEW_ERROR(isolate, NewURIError());
  }

  if (two_byte_buffer.empty()) {
    return isolate->factory()->NewStringFromOneByte(base::Vector<const uint8_t>(
        one_byte_buffer.data(), static_cast<int>(one_byte_buffer.size())));
  }

  Handle<SeqTwoByteString> result;
  int result_length =
      static_cast<int>(one_byte_buffer.size() + two_byte_buffer.size());
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, result, isolate->factory()->NewRawTwoByteString(result_length));

  DisallowGarbageCollection no_gc;
  base::uc16* chars = result->GetChars(no_gc);
  if (!one_byte_buffer.empty()) {
    CopyChars(chars, one_byte_buffer.data(), one_byte_buffer.size());
    chars += one_byte_buffer.size();
  }
  if (!two_byte_buffer.empty()) {
    CopyChars(chars, two_byte_buffer.data(), two_byte_buffer.size());
  }

  return result;
}

namespace {  // anonymous namespace for EncodeURI helper functions
bool IsUnescapePredicateInUriComponent(base::uc16 c) {
  if (IsAlphaNumeric(c)) {
    return true;
  }

  switch (c) {
    case '!':
    case '\'':
    case '(':
    case ')':
    case '*':
    case '-':
    case '.':
    case '_':
    case '~':
      return true;
    default:
      return false;
  }
}

bool IsUriSeparator(base::uc16 c) {
  switch (c) {
    case '#':
    case ':':
    case ';':
    case '/':
    case '?':
    case '$':
    case '&':
    case '+':
    case ',':
    case '@':
    case '=':
      return true;
    default:
      return false;
  }
}

void AddEncodedOctetToBuffer(uint8_t octet, std::vector<uint8_t>* buffer) {
  buffer->push_back('%');
  buffer->push_back(base::HexCharOfValue(octet >> 4));
  buffer->push_back(base::HexCharOfValue(octet & 0x0F));
}

void EncodeSingle(base::uc16 c, std::vector<uint8_t>* buffer) {
  char s[4] = {};
  int number_of_bytes;
  number_of_bytes =
      unibrow::Utf8::Encode(s, c, unibrow::Utf16::kNoPreviousCharacter, false);
  for (int k = 0; k < number_of_bytes; k++) {
    AddEncodedOctetToBuffer(s[k], buffer);
  }
}

void EncodePair(base::uc16 cc1, base::uc16 cc2, std::vector<uint8_t>* buffer) {
  char s[4] = {};
  int number_of_bytes =
      unibrow::Utf8::Encode(s, unibrow::Utf16::CombineSurrogatePair(cc1, cc2),
                            unibrow::Utf16::kNoPreviousCharacter, false);
  for (int k = 0; k < number_of_bytes; k++) {
    AddEncodedOctetToBuffer(s[k], buffer);
  }
}

}  // anonymous namespace

MaybeHandle<String> Uri::Encode(Isolate* isolate, Handle<String> uri,
                                bool is_uri) {
  uri = String::Flatten(isolate, uri);
  int uri_length = uri->length();
  std::vector<uint8_t> buffer;
  buffer.reserve(uri_length);

  bool throw_error = false;
  {
    DisallowGarbageCollection no_gc;
    String::FlatContent uri_content = uri->GetFlatContent(no_gc);

    for (int k = 0; k < uri_length; k++) {
      base::uc16 cc1 = uri_content.Get(k);
      if (unibrow::Utf16::IsLeadSurrogate(cc1)) {
        k++;
        if (k < uri_length) {
          base::uc16 cc2 = uri->Get(k);
          if (unibrow::Utf16::IsTrailSurrogate(cc2)) {
            EncodePair(cc1, cc2, &buffer);
            continue;
          }
        }
      } else if (!unibrow::Utf16::IsTrailSurrogate(cc1)) {
        if (IsUnescapePredicateInUriComponent(cc1) ||
            (is_uri && IsUriSeparator(cc1))) {
          buffer.push_back(cc1);
        } else {
          EncodeSingle(cc1, &buffer);
        }
        continue;
      }

      // String::FlatContent DCHECKs its contents did not change during its
      // lifetime. Throwing the error inside the loop may cause GC and move the
      // string contents.
      throw_error = true;
      break;
    }
  }

  if (throw_error) THROW_NEW_ERROR(isolate, NewURIError());
  return isolate->factory()->NewStringFromOneByte(base::VectorOf(buffer));
}

namespace {  // Anonymous namespace for Escape and Unescape

template <typename Char>
int UnescapeChar(base::Vector<const Char> vector, int i, int length,
                 int* step) {
  uint16_t character = vector[i];
  int32_t hi = 0;
  int32_t lo = 0;
  if (character == '%' && i <= length - 6 && vector[i + 1] == 'u' &&
      (hi = TwoDigitHex(vector[i + 2], vector[i + 3])) > -1 &&
      (lo = TwoDigitHex(vector[i + 4], vector[i + 5])) > -1) {
    *step = 6;
    return (hi << 8) + lo;
  } else if (character == '%' && i <= length - 3 &&
             (lo = TwoDigitHex(vector[i + 1], vector[i + 2])) > -1) {
    *step = 3;
    return lo;
  } else {
    *step = 1;
    return character;
  }
}

template <typename Char>
MaybeHandle<String> UnescapeSlow(Isolate* isolate, Handle<String> string,
                                 int start_index) {
  bool one_byte = true;
  uint32_t length = string->length();

  int unescaped_length = 0;
  {
    DisallowGarbageCollection no_gc;
    base::Vector<const Char> vector = string->GetCharVector<Char>(no_gc);
    for (uint32_t i = start_index; i < length; unescaped_length++) {
      int step;
      if (UnescapeChar(vector, i, length, &step) >
          String::kMaxOneByteCharCode) {
        one_byte = false;
      }
      i += step;
    }
  }

  DCHECK_LT(start_index, length);
  Handle<String> first_part =
      isolate->factory()->NewProperSubString(string, 0, start_index);

  int dest_position = 0;
  Handle<String> second_part;
  DCHECK_LE(unescaped_length, String::kMaxLength);
  if (one_byte) {
    Handle<SeqOneByteString> dest = isolate->factory()
                                        ->NewRawOneByteString(unescaped_length)
                                        .ToHandleChecked();
    DisallowGarbageCollection no_gc;
    base::Vector<const Char> vector = string->GetCharVector<Char>(no_gc);
    for (uint32_t i = start_index; i < length; dest_position++) {
      int step;
      dest->SeqOneByteStringSet(dest_position,
                                UnescapeChar(vector, i, length, &step));
      i += step;
    }
    second_part = dest;
  } else {
    Handle<SeqTwoByteString> dest = isolate->factory()
                                        ->NewRawTwoByteString(unescaped_length)
                                        .ToHandleChecked();
    DisallowGarbageCollection no_gc;
    base::Vector<const Char> vector = string->GetCharVector<Char>(no_gc);
    for (uint32_t i = start_index; i < length; dest_position++) {
      int step;
      dest->SeqTwoByteStringSet(dest_position,
                                UnescapeChar(vector, i, length, &step));
      i += step;
    }
    second_part = dest;
  }
  return isolate->factory()->NewConsString(first_part, second_part);
}

bool IsNotEscaped(uint16_t c) {
  if (IsAlphaNumeric(c)) {
    return true;
  }
  //  @*_+-./
  switch (c) {
    case '@':
    case '*':
    case '_':
    case '+':
    case '-':
    case '.':
    case '/':
      return true;
    default:
      return false;
  }
}

template <typename Char>
static MaybeHandle<String> UnescapePrivate(Isolate* isolate,
                                           Handle<String> source) {
  int index;
  {
    DisallowGarbageCollection no_gc;
    StringSearch<uint8_t, Char> search(isolate, base::StaticOneByteVector("%"));
    index = search.Search(source->GetCharVector<Char>(no_gc), 0);
    if (index < 0) return source;
  }
  return UnescapeSlow<Char>(isolate, source, index);
}

template <typename Char>
static MaybeHandle<String> EscapePrivate(Isolate* isolate,
                                         Handle<String> string) {
  DCHECK(string->IsFlat());
  uint32_t escaped_length = 0;
  uint32_t length = string->length();

  {
    DisallowGarbageCollection no_gc;
    base::Vector<const Char> vector = string->GetCharVector<Char>(no_gc);
    for (uint32_t i = 0; i < length; i++) {
      uint16_t c = vector[i];
      if (c >= 256) {
        escaped_length += 6;
      } else if (IsNotEscaped(c)) {
        escaped_length++;
      } else {
        escaped_length += 3;
      }

      // We don't allow strings that are longer than a maximal length.
      DCHECK_LT(String::kMaxLength, 0x7FFFFFFF - 6);   // Cannot overflow.
      if (escaped_length > String::kMaxLength) break;  // Provoke exception.
    }
  }

  // No length change implies no change.  Return original string if no change.
  if (escaped_length == length) return string;

  Handle<SeqOneByteString> dest;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, dest, isolate->factory()->NewRawOneByteString(escaped_length));
  int dest_position = 0;

  {
    DisallowGarbageCollection no_gc;
    base::Vector<const Char> vector = string->GetCharVector<Char>(no_gc);
    for (uint32_t i = 0; i < length; i++) {
      uint16_t c = vector[i];
      if (c >= 256) {
        dest->SeqOneByteStringSet(dest_position, '%');
        dest->SeqOneByteStringSet(dest_position + 1, 'u');
        dest->SeqOneByteStringSet(dest_position + 2,
                                  base::HexCharOfValue(c >> 12));
        dest->SeqOneByteStringSet(dest_position + 3,
                                  base::HexCharOfValue((c >> 8) & 0xF));
        dest->SeqOneByteStringSet(dest_position + 4,
                                  base::HexCharOfValue((c >> 4) & 0xF));
        dest->SeqOneByteStringSet(dest_position + 5,
                                  base::HexCharOfValue(c & 0xF));
        dest_position += 6;
      } else if (IsNotEscaped(c)) {
        dest->SeqOneByteStringSet(dest_position, c);
        dest_position++;
      } else {
        dest->SeqOneByteStringSet(dest_position, '%');
        dest->SeqOneByteStringSet(dest_position + 1,
                                  base::HexCharOfValue(c >> 4));
        dest->SeqOneByteStringSet(dest_position + 2,
                                  base::HexCharOfValue(c & 0xF));
        dest_position += 3;
      }
    }
  }

  return dest;
}

}  // anonymous namespace

MaybeHandle<String> Uri::Escape(Isolate* isolate, Handle<String> string) {
  DirectHandle<String> result;
  string = String::Flatten(isolate, string);
  return string->IsOneByteRepresentation()
             ? EscapePrivate<uint8_t>(isolate, string)
             : EscapePrivate<base::uc16>(isolate, string);
}

MaybeHandle<String> Uri::Unescape(Isolate* isolate, Handle<String> string) {
  DirectHandle<String> result;
  string = String::Flatten(isolate, string);
  return string->IsOneByteRepresentation()
             ? UnescapePrivate<uint8_t>(isolate, string)
             : UnescapePrivate<base::uc16>(isolate, string);
}

}  // namespace internal
}  // namespace v8

"""

```