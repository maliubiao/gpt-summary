Response:
Let's break down the thought process for analyzing the `v8/src/strings/uri.cc` file and generating the response.

1. **Understand the Goal:** The request asks for a functional description of the C++ code, its relation to JavaScript, potential Torque implementation (based on file extension), example usage, logic reasoning, and common programming errors it might prevent.

2. **Initial Scan for Key Information:**  Quickly read through the code, looking for function names, class names, and comments. Keywords like "DecodeURI", "EncodeURI", "Escape", "Unescape", "IsReservedPredicate", etc., immediately stand out and suggest the core functionality. The copyright notice confirms it's part of V8. Includes like `<vector>`, `"src/execution/isolate-inl.h"`, etc., hint at its dependencies and purpose within V8.

3. **Identify Core Functionalities (Top-Down):**
    * The namespace `v8::internal::Uri` suggests this code deals with URI (Uniform Resource Identifier) processing within V8's internal implementation.
    * The functions `Decode` and `Encode` are prominent and clearly indicate URI decoding and encoding. The `is_uri` parameter suggests they handle slightly different flavors of URI encoding/decoding.
    * `Escape` and `Unescape` functions are also present, indicating general string escaping/unescaping, potentially related to URI components but potentially more general.

4. **Analyze Individual Functions and Their Logic:**
    * **`Decode`:**
        * Takes a `String` (V8's string representation) and a boolean `is_uri`.
        * Flattens the string (ensures it's in a contiguous memory block).
        * Uses helper functions like `IntoOneAndTwoByte` and `IntoTwoByte` to perform the actual decoding.
        * `IntoOneAndTwoByte` iterates through the string, looking for `%` encoded sequences.
        * It handles both single-byte and multi-byte UTF-8 characters.
        * It seems to convert `%xx` (and `%uxxxx`) sequences into their corresponding Unicode characters.
        * The `is_uri` flag affects how reserved characters are handled during decoding (they remain encoded if `is_uri` is true).
        * If decoding fails, it throws a `URIError`.
        * It returns a new `String` with the decoded content.
    * **`Encode`:**
        * Similar structure to `Decode`, takes a `String` and `is_uri`.
        * Iterates through the string.
        * Uses helper functions `EncodeSingle` and `EncodePair` to encode characters.
        * It encodes characters that are not alphanumeric or in a specific "unescaped" set.
        * Handles surrogate pairs correctly for characters outside the BMP.
        * `is_uri` influences which separator characters are left unencoded.
        * Throws a `URIError` on invalid surrogate pairs.
        * Returns a new `String` with the encoded content.
    * **`Escape`:**
        * More general escaping.
        * Encodes characters outside a specific "not escaped" set (alphanumeric, `@*_+-./`) using `%xx` or `%uxxxx` encoding.
        * Doesn't take an `is_uri` flag, suggesting a more generic purpose.
    * **`Unescape`:**
        * Reverses the `Escape` operation.
        * Looks for `%xx` and `%uxxxx` sequences and converts them back to characters.

5. **Infer the Purpose of Helper Functions:**  The anonymous namespaces group related helper functions.
    * **Decode Helpers:** `IsReservedPredicate`, `IsReplacementCharacter`, `DecodeOctets`, `TwoDigitHex`, `AddToBuffer`, `IntoTwoByte`, `IntoOneAndTwoByte`. These are clearly about the mechanics of decoding URI-encoded strings.
    * **Encode Helpers:** `IsUnescapePredicateInUriComponent`, `IsUriSeparator`, `AddEncodedOctetToBuffer`, `EncodeSingle`, `EncodePair`. These handle the encoding process.
    * **Escape/Unescape Helpers:** `UnescapeChar`, `UnescapeSlow`, `IsNotEscaped`, `UnescapePrivate`, `EscapePrivate`. These handle the more general escaping and unescaping logic.

6. **Relate to JavaScript:**
    * The names "Decode" and "Encode" strongly suggest a connection to JavaScript's built-in `decodeURI`, `decodeURIComponent`, `encodeURI`, and `encodeURIComponent` functions.
    * The `is_uri` parameter hints at the distinction between the "component" and full URI versions.
    * Provide JavaScript examples demonstrating the analogous behavior.

7. **Check for Torque:** The request specifically asks about `.tq` files. Since the provided code is `.cc`, it's C++, *not* Torque. State this clearly.

8. **Code Logic Reasoning (Hypothetical Input/Output):**  Choose simple examples to illustrate the encoding and decoding processes. Focus on edge cases like reserved characters (for `Decode` with `is_uri=true`) and multi-byte characters.

9. **Common Programming Errors:** Think about what could go wrong when dealing with URI encoding/decoding.
    * Incorrectly encoding reserved characters.
    * Double encoding.
    * Not encoding characters that *should* be encoded.
    * Trying to decode invalidly encoded sequences.
    * Mismatched `encodeURI`/`encodeURIComponent` and `decodeURI`/`decodeURIComponent`.

10. **Structure the Response:** Organize the findings logically with clear headings and bullet points. Start with a general summary, then delve into specifics for each function and concept. Ensure the JavaScript examples are clear and directly related to the C++ code's functionality.

11. **Review and Refine:**  Read through the generated response to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For example, initially, I might have just said "deals with URI encoding/decoding," but refining it to mention the distinction between full URIs and URI components makes the explanation more precise. Double-check the JavaScript examples for correctness.

This detailed breakdown shows how to systematically analyze source code to understand its functionality and its relationship to higher-level concepts like JavaScript APIs. The key is to combine careful reading with domain knowledge (in this case, understanding URI encoding) and logical deduction.
This C++ source code file `v8/src/strings/uri.cc` in the V8 JavaScript engine implements the functionality for encoding and decoding Uniform Resource Identifiers (URIs). Let's break down its features:

**Core Functionality:**

* **URI Encoding (`Uri::Encode`)**: This function takes a string as input and encodes it according to URI encoding rules. This involves replacing certain characters with one, two, three, or four escape sequences representing the UTF-8 encoding of the character (e.g., space becomes `%20`). It has an `is_uri` flag to differentiate between encoding a full URI and a URI component.
* **URI Decoding (`Uri::Decode`)**: This function reverses the encoding process. It takes an encoded URI string and decodes the escape sequences (like `%20`) back into their original characters. It also has an `is_uri` flag.
* **General Escaping (`Uri::Escape`)**: This function provides a more general escaping mechanism, converting characters outside a defined set (alphanumeric and `@*_+-./`) into `%xx` or `%uxxxx` escape sequences.
* **General Unescaping (`Uri::Unescape`)**: This function reverses the general escaping process, converting `%xx` and `%uxxxx` sequences back to their characters.

**Relation to JavaScript and Examples:**

Yes, `v8/src/strings/uri.cc` directly relates to the implementation of the following JavaScript global functions:

* **`encodeURI(uri)`**:  This JavaScript function uses the logic implemented in `Uri::Encode` with the `is_uri` flag set to `true`. It encodes special characters in a complete URI, but does *not* encode characters that have special meaning in the URI syntax itself (like `#`, `?`, etc.).
* **`encodeURIComponent(uriComponent)`**: This JavaScript function uses the logic implemented in `Uri::Encode` with the `is_uri` flag set to `false`. It encodes all special characters, including those with syntactic meaning in URIs.
* **`decodeURI(encodedURI)`**: This JavaScript function uses the logic implemented in `Uri::Decode` with the `is_uri` flag set to `true`. It decodes a complete URI.
* **`decodeURIComponent(encodedURIComponent)`**: This JavaScript function uses the logic implemented in `Uri::Decode` with the `is_uri` flag set to `false`. It decodes a URI component.
* **`escape(string)`**:  While largely deprecated, this older JavaScript function's behavior is similar to `Uri::Escape`.
* **`unescape(string)`**:  Similarly deprecated, this function's behavior is similar to `Uri::Unescape`.

**JavaScript Examples:**

```javascript
// Encoding a full URI
const uri = "https://www.example.com/search?q=v8 source code#fragment";
const encodedURI = encodeURI(uri);
console.log(encodedURI); // Output: "https://www.example.com/search?q=v8%20source%20code#fragment"
const decodedURI = decodeURI(encodedURI);
console.log(decodedURI); // Output: "https://www.example.com/search?q=v8 source code#fragment"

// Encoding a URI component
const uriComponent = "v8 source code";
const encodedURIComponent = encodeURIComponent(uriComponent);
console.log(encodedURIComponent); // Output: "v8%20source%20code"
const decodedURIComponent = decodeURIComponent(encodedURIComponent);
console.log(decodedURIComponent); // Output: "v8 source code"

// Using escape (deprecated, avoid in new code)
const str = "Hello World!";
const escapedStr = escape(str);
console.log(escapedStr); // Output: "Hello%20World%21"
const unescapedStr = unescape(escapedStr);
console.log(unescapedStr); // Output: "Hello World!"
```

**Torque Source Code:**

The comment explicitly states that if the file ended with `.tq`, it would be a Torque source file. Since `v8/src/strings/uri.cc` ends with `.cc`, it is **not** a Torque source file. It's standard C++ code. Torque is a TypeScript-like language used within V8 for generating optimized C++ code. While the *functionality* might be exposed to Torque (or generated by Torque in other parts of V8), this specific file is C++.

**Code Logic Reasoning (Hypothetical Input and Output):**

**Scenario 1: `Uri::Decode` with `is_uri = false` (like `decodeURIComponent`)**

* **Input:**  `"%E4%BD%A0%E5%A5%BD%21"` (UTF-8 encoding of "你好!")
* **Process:** The function will identify the `%` signs followed by hexadecimal digits. It will convert `%E4`, `%BD`, `%A0`, `%E5`, `%A5`, `%BD` into their corresponding byte values, interpret them as UTF-8 encoded characters, and then construct a Unicode string.
* **Output:** `"你好!"`

**Scenario 2: `Uri::Encode` with `is_uri = true` (like `encodeURI`)**

* **Input:** `"https://example.com/path with spaces?q=你好#fragment"`
* **Process:** The function will iterate through the string.
    * `https://example.com/path` will remain unchanged.
    * ` ` (space) will be encoded as `%20`.
    * `with` will remain unchanged.
    * ` ` (space) will be encoded as `%20`.
    * `spaces` will remain unchanged.
    * `?q=` will remain unchanged.
    * `"你好"` will be encoded (e.g., `%E4%BD%A0%E5%A5%BD`).
    * `#fragment` will remain unchanged (as `encodeURI` doesn't encode URI separators).
* **Output:** `"https://example.com/path%20with%20spaces?q=%E4%BD%A0%E5%A5%BD#fragment"`

**User-Common Programming Errors:**

1. **Mismatched Encode/Decode Functions:**  A common error is using `decodeURI` on a string that was encoded using `encodeURIComponent`, or vice versa. This can lead to incorrect decoding because the sets of characters encoded by each function are different.

   ```javascript
   const component = "hello#world";
   const encodedComponent = encodeURIComponent(component); // "hello%23world"
   const incorrectlyDecoded = decodeURI(encodedComponent);
   console.log(incorrectlyDecoded); // Output: "hello%23world" (The '#' is not decoded)

   const correctlyDecoded = decodeURIComponent(encodedComponent);
   console.log(correctlyDecoded); // Output: "hello#world"
   ```

2. **Double Encoding:**  Accidentally encoding a string multiple times.

   ```javascript
   const text = "data with spaces";
   const encodedOnce = encodeURIComponent(text);
   const encodedTwice = encodeURIComponent(encodedOnce);
   console.log(encodedTwice); // Output: "data%2520with%2520spaces"
   const decodedOnce = decodeURIComponent(encodedTwice);
   console.log(decodedOnce); // Output: "data%20with%20spaces" (Still encoded once)
   const decodedTwice = decodeURIComponent(decodedOnce);
   console.log(decodedTwice); // Output: "data with spaces"
   ```

3. **Not Encoding When Necessary:** Forgetting to encode data before including it in a URL, which can lead to the URL being interpreted incorrectly by the server or other systems.

   ```javascript
   const userInput = "search term with / and ?";
   const url = `https://example.com/search?q=${userInput}`;
   console.log(url); // Output: "https://example.com/search?q=search term with / and ?" (Likely incorrect)

   const encodedInput = encodeURIComponent(userInput);
   const correctUrl = `https://example.com/search?q=${encodedInput}`;
   console.log(correctUrl); // Output: "https://example.com/search?q=search%20term%20with%20%2F%20and%20%3F"
   ```

4. **Encoding Characters That Shouldn't Be Encoded (Using the Wrong Function):** Using `encodeURIComponent` when `encodeURI` is more appropriate for encoding a full URL, leading to unnecessary encoding of URI separators.

   ```javascript
   const fullUrl = "https://example.com/path?param=value";
   const overlyEncoded = encodeURIComponent(fullUrl);
   console.log(overlyEncoded);
   // Output: "https%3A%2F%2Fexample.com%2Fpath%3Fparam%3Dvalue" (The slashes, question mark, and equals sign are unnecessarily encoded)
   ```

In summary, `v8/src/strings/uri.cc` provides the foundational C++ implementation for URI encoding and decoding functionalities used by JavaScript. Understanding its role helps clarify how JavaScript handles URLs and data transmission in web applications.

### 提示词
```
这是目录为v8/src/strings/uri.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/strings/uri.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```