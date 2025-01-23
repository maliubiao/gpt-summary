Response:
The user wants to understand the functionality of the C++ source code file `v8/src/strings/unicode.cc`. The request also includes specific checks and examples related to Torque, JavaScript, code logic, and common programming errors. Finally, it asks for a summary of the file's purpose based on the provided first part of the code.

Here's a breakdown of the thought process:

1. **Identify the core purpose:** The filename and the initial comments clearly indicate that this file deals with Unicode functionality within V8.

2. **Scan for key functionalities:** Look for function definitions, data structures, and namespaces that hint at the tasks performed. Keywords like "Utf8", "Utf16", "Uppercase", "Letter", "Lookup", and "Validate" are strong indicators.

3. **Address specific constraints:**
    * **Torque:**  Check if the filename ends with `.tq`. In this case, it doesn't.
    * **JavaScript relation:** Determine if the C++ code relates to any JavaScript string or Unicode operations. Functions like checking if a character is uppercase or a letter directly map to JavaScript's string methods.
    * **Code logic:** Analyze the `LookupPredicate` and `LookupMapping` functions. These involve searching tables based on character values. Think about providing example inputs and outputs.
    * **Common programming errors:** Consider scenarios where developers might misuse Unicode handling, especially with UTF-8 and UTF-16 encoding/decoding.
    * **Summarization:** Based on the identified functionalities, formulate a concise summary of the file's role.

4. **Elaborate on identified functionalities:**
    * **Unicode Tables:** The code uses static arrays (`kUppercaseTable`, `kLetterTable`, etc.) to store Unicode property information.
    * **Lookup Functions:** `LookupPredicate` and `LookupMapping` are crucial for efficiently retrieving information about a character from these tables. Explain their search strategies (binary and interpolation).
    * **UTF-8 Handling:** The `Utf8` namespace provides functions for decoding, validating, and calculating the value of UTF-8 encoded characters.
    * **UTF-16 Handling:** The `Utf16` namespace includes a function to replace unpaired surrogate code points, which is important for well-formed UTF-16.
    * **Character Properties:**  The code defines functions like `Uppercase::Is` and `Letter::Is` to check if a given character has specific Unicode properties.

5. **Construct examples and explanations:**
    * **JavaScript example:** Show how the C++ `Uppercase::Is` and `Letter::Is` relate to JavaScript's string methods like `toUpperCase()` and checking character categories.
    * **Code logic example:**  For `LookupPredicate`, assume a character within a known range in the table and explain how the binary search narrows down the possibilities. For `LookupMapping`, focus on how it retrieves mappings based on the character and the table structure. Provide hypothetical inputs and expected boolean outputs for `LookupPredicate`.
    * **Common errors example:** Illustrate errors like incorrect UTF-8 encoding or not handling surrogate pairs properly in JavaScript.

6. **Refine the summary:** Combine the identified functionalities into a clear and concise summary of the file's overall purpose within V8's string processing. Emphasize its role in providing fundamental Unicode support.

7. **Structure the response:** Organize the information logically, addressing each part of the user's request. Use clear headings and bullet points for readability.

**Self-Correction/Refinement during thought process:**

* **Initial thought:**  Focus only on the specific functions explicitly named in the code.
* **Correction:** Broaden the scope to include the overall purpose and the underlying mechanisms like the Unicode tables.
* **Initial thought:**  Provide a complex code logic example.
* **Correction:** Simplify the example for clarity and focus on the basic principle of the lookup functions.
* **Initial thought:**  Only mention encoding/decoding.
* **Correction:**  Also highlight the importance of validation and handling of potentially malformed data.

By following this thought process, the generated response effectively addresses all aspects of the user's request and provides a comprehensive understanding of the provided C++ code snippet.
好的，让我们来分析一下 `v8/src/strings/unicode.cc` 这个文件的功能。

**功能归纳：**

从提供的代码片段来看，`v8/src/strings/unicode.cc` 这个文件主要负责提供 **Unicode 相关的底层支持**，用于 V8 引擎处理字符串。 它包含了一系列用于操作和查询 Unicode 字符属性的函数和数据结构。

**具体功能点：**

1. **Unicode 表格查找:**
   - 代码中定义了大量的静态常量数组，如 `kUppercaseTable0`，`kLetterTable0` 等，这些数组很可能是用于存储 Unicode 字符属性的表格。
   - 提供了 `LookupPredicate` 函数，用于在这些表格中查找特定字符是否存在或满足特定条件。该函数使用了二分查找和插值查找的混合策略来提高查找效率。
   - 提供了 `LookupMapping` 函数，用于查找字符的映射关系，例如大小写转换等。

2. **UTF-8 编码处理:**
   - 提供了 `Utf8` 命名空间，其中包含：
     - `CalculateValue`:  用于从 UTF-8 字节序列中解码出一个 Unicode 字符。
     - `ValueOfIncremental` 和 `ValueOfIncrementalFinish`:  用于增量式地解码 UTF-8 字节序列，这在处理不完整的 UTF-8 数据时非常有用。
     - `ValidateEncoding`:  用于验证给定的字节序列是否是合法的 UTF-8 编码。

3. **UTF-16 编码处理:**
   - 提供了 `Utf16` 命名空间，其中包含：
     - `ReplaceUnpairedSurrogates`: 用于处理 UTF-16 中的非配对代理对，将其替换为 U+FFFD (替换字符)。

4. **字符属性判断:**
   - 提供了 `Uppercase::Is` 和 `Letter::Is` 函数，用于判断一个 Unicode 字符是否为大写字母或字母。这些函数的实现可能依赖于之前提到的 Unicode 表格查找。

5. **WTF-8 编码处理 (WebAssembly 支持):**
   - 在定义了 `V8_ENABLE_WEBASSEMBLY` 宏的情况下，提供了 `Wtf8` 命名空间，包含：
     - `ValidateEncoding`: 用于验证 WTF-8 编码的合法性。
     - `ScanForSurrogates`: 用于扫描 WTF-8 字节序列中的代理字符。

**关于 .tq 结尾：**

根据您的描述，如果 `v8/src/strings/unicode.cc` 以 `.tq` 结尾，那么它就是一个 V8 Torque 源代码文件。从您提供的文件路径和结尾来看，它是一个 `.cc` 文件，所以目前 **不是** Torque 源代码。

**与 JavaScript 的关系 (举例说明):**

`v8/src/strings/unicode.cc` 中提供的功能是 JavaScript 字符串操作的基础。JavaScript 引擎在底层会调用这些 C++ 函数来实现各种字符串方法。

例如：

```javascript
const str = "你好WORLD";

// JavaScript 的 toUpperCase() 方法在底层可能会调用类似于 Uppercase::Is 的函数来判断字符是否需要转换
const upperStr = str.toUpperCase();
console.log(upperStr); // 输出：你好WORLD (因为中文和部分符号没有对应的大写)

// JavaScript 判断字符是否是字母的逻辑在底层可能依赖于 Letter::Is
for (let i = 0; i < str.length; i++) {
  // 这里只是一个概念性的演示，实际 JavaScript 没有直接暴露这样的接口
  // if (底层C++函数判断 str[i] 是字母) {
  //   console.log(`${str[i]} 是一个字母`);
  // }
}
```

**代码逻辑推理 (假设输入与输出):**

**假设输入 `LookupPredicate`:**

- `table`: 指向 `kUppercaseTable0` 数组的指针
- `size`: `kUppercaseTable0Size` 的值 (455)
- `chr`: 字符 'A' (Unicode 码点 65)

**预期输出 `LookupPredicate`:**

- `true` (因为 'A' 是一个大写字母，并且应该存在于 `kUppercaseTable0` 中)

**假设输入 `Utf8::CalculateValue`:**

- `str`:  一个指向包含 UTF-8 编码 "你好" 的字节序列的指针 (例如：`\xE4\xBD\xA0\xE5\xA5\xBD`)
- `max_length`:  字节序列的长度 (6)
- `cursor`:  指向一个 `size_t` 变量的指针 (用于存储解码的字节数)

**预期输出 `Utf8::CalculateValue`:**

- 返回 Unicode 字符 '你' (假设第一次调用)
- `cursor` 指向的变量的值会更新为解码 '你' 所用的字节数 (3)

**用户常见的编程错误 (举例说明):**

1. **不正确的 UTF-8 编码:**
   ```javascript
   // 错误：尝试使用不完整的 UTF-8 序列
   const buffer = new Uint8Array([0xE4, 0xBD]); // "你" 的前两个字节
   const textDecoder = new TextDecoder();
   const decodedString = textDecoder.decode(buffer);
   console.log(decodedString); // 可能输出乱码或抛出错误
   ```
   V8 的 `Utf8::ValidateEncoding` 可以用来提前检测这种错误。

2. **错误地处理 UTF-16 代理对:**
   ```javascript
   // 错误：尝试单独处理代理对的一部分
   const highSurrogate = String.fromCharCode(0xD800); // 高位代理
   const lowSurrogate = String.fromCharCode(0xDC00);  // 低位代理
   console.log(highSurrogate.length); // 输出 1
   console.log(lowSurrogate.length);  // 输出 1
   console.log(highSurrogate + lowSurrogate); // 输出一个字符
   ```
   V8 的 `Utf16::ReplaceUnpairedSurrogates` 用于处理这种不完整的情况。

**第 1 部分功能归纳:**

总而言之，`v8/src/strings/unicode.cc` 的第 1 部分主要提供了 V8 引擎处理 Unicode 字符串的基础功能，包括：

- **Unicode 字符属性的查找和判断。**
- **UTF-8 和 UTF-16 编码的解码、验证和处理。**
- **为 WebAssembly 提供 WTF-8 编码的支持。**

这些功能是 JavaScript 引擎正确处理各种语言字符和文本的基础。

### 提示词
```
这是目录为v8/src/strings/unicode.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/strings/unicode.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This file was generated at 2014-10-08 15:25:47.940335

#include "src/strings/unicode.h"

#include <stdio.h>
#include <stdlib.h>

#include <vector>

#include "src/strings/unicode-inl.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/third_party/utf8-decoder/generalized-utf8-decoder.h"
#endif

#ifdef V8_INTL_SUPPORT
#include "unicode/uchar.h"
#endif

namespace unibrow {

#ifndef V8_INTL_SUPPORT
static const int kStartBit = (1 << 30);
static const int kChunkBits = (1 << 13);
#endif  // !V8_INTL_SUPPORT

static const uchar kSentinel = static_cast<uchar>(-1);

/**
 * \file
 * Implementations of functions for working with Unicode.
 */

using int16_t = signed short;     // NOLINT
using uint16_t = unsigned short;  // NOLINT
using int32_t = int;              // NOLINT

#ifndef V8_INTL_SUPPORT
// All access to the character table should go through this function.
template <int D>
static inline uchar TableGet(const int32_t* table, int index) {
  return table[D * index];
}

static inline uchar GetEntry(int32_t entry) { return entry & (kStartBit - 1); }

static inline bool IsStart(int32_t entry) { return (entry & kStartBit) != 0; }

/**
 * Look up a character in the Unicode table using a mix of binary and
 * interpolation search.  For a uniformly distributed array
 * interpolation search beats binary search by a wide margin.  However,
 * in this case interpolation search degenerates because of some very
 * high values in the lower end of the table so this function uses a
 * combination.  The average number of steps to look up the information
 * about a character is around 10, slightly higher if there is no
 * information available about the character.
 */
static bool LookupPredicate(const int32_t* table, uint16_t size, uchar chr) {
  static const int kEntryDist = 1;
  uint16_t value = chr & (kChunkBits - 1);
  unsigned int low = 0;
  unsigned int high = size - 1;
  while (high != low) {
    unsigned int mid = low + ((high - low) >> 1);
    uchar current_value = GetEntry(TableGet<kEntryDist>(table, mid));
    // If we've found an entry less than or equal to this one, and the
    // next one is not also less than this one, we've arrived.
    if ((current_value <= value) &&
        (mid + 1 == size ||
         GetEntry(TableGet<kEntryDist>(table, mid + 1)) > value)) {
      low = mid;
      break;
    } else if (current_value < value) {
      low = mid + 1;
    } else if (current_value > value) {
      // If we've just checked the bottom-most value and it's not
      // the one we're looking for, we're done.
      if (mid == 0) break;
      high = mid - 1;
    }
  }
  int32_t field = TableGet<kEntryDist>(table, low);
  uchar entry = GetEntry(field);
  bool is_start = IsStart(field);
  return (entry == value) || (entry < value && is_start);
}
#endif  // !V8_INTL_SUPPORT

template <int kW>
struct MultiCharacterSpecialCase {
  static const uchar kEndOfEncoding = kSentinel;
  uchar chars[kW];
};

#ifndef V8_INTL_SUPPORT
// Look up the mapping for the given character in the specified table,
// which is of the specified length and uses the specified special case
// mapping for multi-char mappings.  The next parameter is the character
// following the one to map.  The result will be written in to the result
// buffer and the number of characters written will be returned.  Finally,
// if the allow_caching_ptr is non-null then false will be stored in
// it if the result contains multiple characters or depends on the
// context.
// If ranges are linear, a match between a start and end point is
// offset by the distance between the match and the start. Otherwise
// the result is the same as for the start point on the entire range.
template <bool ranges_are_linear, int kW>
static int LookupMapping(const int32_t* table, uint16_t size,
                         const MultiCharacterSpecialCase<kW>* multi_chars,
                         uchar chr, uchar next, uchar* result,
                         bool* allow_caching_ptr) {
  static const int kEntryDist = 2;
  uint16_t key = chr & (kChunkBits - 1);
  uint16_t chunk_start = chr - key;
  unsigned int low = 0;
  unsigned int high = size - 1;
  while (high != low) {
    unsigned int mid = low + ((high - low) >> 1);
    uchar current_value = GetEntry(TableGet<kEntryDist>(table, mid));
    // If we've found an entry less than or equal to this one, and the next one
    // is not also less than this one, we've arrived.
    if ((current_value <= key) &&
        (mid + 1 == size ||
         GetEntry(TableGet<kEntryDist>(table, mid + 1)) > key)) {
      low = mid;
      break;
    } else if (current_value < key) {
      low = mid + 1;
    } else if (current_value > key) {
      // If we've just checked the bottom-most value and it's not
      // the one we're looking for, we're done.
      if (mid == 0) break;
      high = mid - 1;
    }
  }
  int32_t field = TableGet<kEntryDist>(table, low);
  uchar entry = GetEntry(field);
  bool is_start = IsStart(field);
  bool found = (entry == key) || (entry < key && is_start);
  if (found) {
    int32_t value = table[2 * low + 1];
    if (value == 0) {
      // 0 means not present
      return 0;
    } else if ((value & 3) == 0) {
      // Low bits 0 means a constant offset from the given character.
      if (ranges_are_linear) {
        result[0] = chr + (value >> 2);
      } else {
        result[0] = entry + chunk_start + (value >> 2);
      }
      return 1;
    } else if ((value & 3) == 1) {
      // Low bits 1 means a special case mapping
      if (allow_caching_ptr) *allow_caching_ptr = false;
      const MultiCharacterSpecialCase<kW>& mapping = multi_chars[value >> 2];
      int length = 0;
      for (length = 0; length < kW; length++) {
        uchar mapped = mapping.chars[length];
        if (mapped == MultiCharacterSpecialCase<kW>::kEndOfEncoding) break;
        if (ranges_are_linear) {
          result[length] = mapped + (key - entry);
        } else {
          result[length] = mapped;
        }
      }
      return length;
    } else {
      // Low bits 2 means a really really special case
      if (allow_caching_ptr) *allow_caching_ptr = false;
      // The cases of this switch are defined in unicode.py in the
      // really_special_cases mapping.
      switch (value >> 2) {
        case 1:
          // Really special case 1: upper case sigma.  This letter
          // converts to two different lower case sigmas depending on
          // whether or not it occurs at the end of a word.
          if (next != 0 && Letter::Is(next)) {
            result[0] = 0x03C3;
          } else {
            result[0] = 0x03C2;
          }
          return 1;
        default:
          return 0;
      }
      return -1;
    }
  } else {
    return 0;
  }
}
#endif  // !V8_INTL_SUPPORT

// This method decodes an UTF-8 value according to RFC 3629 and
// https://encoding.spec.whatwg.org/#utf-8-decoder .
uchar Utf8::CalculateValue(const uint8_t* str, size_t max_length,
                           size_t* cursor) {
  DCHECK_GT(max_length, 0);
  DCHECK_GT(str[0], kMaxOneByteChar);

  State state = State::kAccept;
  Utf8IncrementalBuffer buffer = 0;
  uchar t;

  const uint8_t* start = str;
  const uint8_t* end = str + max_length;

  do {
    t = ValueOfIncremental(&str, &state, &buffer);
  } while (str < end && t == kIncomplete);

  *cursor += str - start;
  return (state == State::kAccept) ? t : kBadChar;
}

// Finishes the incremental decoding, ensuring that if an unfinished sequence
// is left that it is replaced by a replacement char.
uchar Utf8::ValueOfIncrementalFinish(State* state) {
  if (*state == State::kAccept) {
    return kBufferEmpty;
  } else {
    DCHECK_GT(*state, State::kAccept);
    *state = State::kAccept;
    return kBadChar;
  }
}

bool Utf8::ValidateEncoding(const uint8_t* bytes, size_t length) {
  State state = State::kAccept;
  Utf8IncrementalBuffer throw_away = 0;
  for (size_t i = 0; i < length && state != State::kReject; i++) {
    Utf8DfaDecoder::Decode(bytes[i], &state, &throw_away);
  }
  return state == State::kAccept;
}

// static
void Utf16::ReplaceUnpairedSurrogates(const uint16_t* source_code_units,
                                      uint16_t* dest_code_units,
                                      size_t length) {
  // U+FFFD (REPLACEMENT CHARACTER)
  constexpr uint16_t kReplacement = 0xFFFD;

  for (size_t i = 0; i < length; i++) {
    const uint16_t source_code_unit = source_code_units[i];
    const size_t copy_index = i;
    uint16_t dest_code_unit = source_code_unit;
    if (IsLeadSurrogate(source_code_unit)) {
      // The current code unit is a leading surrogate. If it's not followed by a
      // trailing surrogate, replace it with the replacement character.
      if (i == length - 1 || !IsTrailSurrogate(source_code_units[i + 1])) {
        dest_code_unit = kReplacement;
      } else {
        // Copy the paired trailing surrogate. The paired leading surrogate will
        // be copied below.
        ++i;
        dest_code_units[i] = source_code_units[i];
      }
    } else if (IsTrailSurrogate(source_code_unit)) {
      // All paired trailing surrogates are skipped above, so this branch is
      // only for those that are unpaired.
      dest_code_unit = kReplacement;
    }
    dest_code_units[copy_index] = dest_code_unit;
  }
}

#if V8_ENABLE_WEBASSEMBLY
bool Wtf8::ValidateEncoding(const uint8_t* bytes, size_t length) {
  using State = GeneralizedUtf8DfaDecoder::State;
  auto state = State::kAccept;
  uint32_t current = 0;
  uint32_t previous = 0;
  for (size_t i = 0; i < length; i++) {
    GeneralizedUtf8DfaDecoder::Decode(bytes[i], &state, &current);
    if (state == State::kReject) return false;
    if (state == State::kAccept) {
      if (Utf16::IsTrailSurrogate(current) &&
          Utf16::IsLeadSurrogate(previous)) {
        return false;
      }
      previous = current;
      current = 0;
    }
  }
  return state == State::kAccept;
}

// Precondition: valid WTF-8.
void Wtf8::ScanForSurrogates(v8::base::Vector<const uint8_t> wtf8,
                             std::vector<size_t>* surrogate_offsets) {
  // A surrogate codepoint is encoded in a three-byte sequence:
  //
  //   0xED [0xA0,0xBF] [0x80,0xBF]
  //
  // If the first byte is 0xED, you already have a 50% chance of the value being
  // a surrogate; you just have to check the second byte.  (There are
  // three-byte non-surrogates starting with 0xED whose second byte is in
  // [0x80,0x9F].)  Could speed this up with SWAR; most likely case is that no
  // byte in the array is 0xED.
  const uint8_t kWtf8SurrogateFirstByte = 0xED;
  const uint8_t kWtf8SurrogateSecondByteHighBit = 0x20;

  for (size_t i = 0; i < wtf8.size(); i++) {
    if (wtf8[i] == kWtf8SurrogateFirstByte &&
        (wtf8[i + 1] & kWtf8SurrogateSecondByteHighBit)) {
      // Record the byte offset of the encoded surrogate.
      surrogate_offsets->push_back(i);
    }
  }
}
#endif  // V8_ENABLE_WEBASSEMBLY

// Uppercase:            point.category == 'Lu'
// TODO(jshin): Check if it's ok to exclude Other_Uppercase characters.
#ifdef V8_INTL_SUPPORT
bool Uppercase::Is(uchar c) { return static_cast<bool>(u_isupper(c)); }
#else
static const uint16_t kUppercaseTable0Size = 455;
static const int32_t kUppercaseTable0[455] = {
    1073741889, 90,         1073742016, 214,        1073742040, 222,
    256,        258,        260,        262,        264,        266,
    268,        270,        272,        274,        276,        278,
    280,        282,        284,        286,        288,        290,
    292,        294,        296,        298,        300,        302,
    304,        306,        308,        310,        313,        315,
    317,        319,        321,        323,        325,        327,
    330,        332,        334,        336,        338,        340,
    342,        344,        346,        348,        350,        352,
    354,        356,        358,        360,        362,        364,
    366,        368,        370,        372,        374,        1073742200,
    377,        379,        381,        1073742209, 386,        388,
    1073742214, 391,        1073742217, 395,        1073742222, 401,
    1073742227, 404,        1073742230, 408,        1073742236, 413,
    1073742239, 416,        418,        420,        1073742246, 423,
    425,        428,        1073742254, 431,        1073742257, 435,
    437,        1073742263, 440,        444,        452,        455,
    458,        461,        463,        465,        467,        469,
    471,        473,        475,        478,        480,        482,
    484,        486,        488,        490,        492,        494,
    497,        500,        1073742326, 504,        506,        508,
    510,        512,        514,        516,        518,        520,
    522,        524,        526,        528,        530,        532,
    534,        536,        538,        540,        542,        544,
    546,        548,        550,        552,        554,        556,
    558,        560,        562,        1073742394, 571,        1073742397,
    574,        577,        1073742403, 582,        584,        586,
    588,        590,        880,        882,        886,        895,
    902,        1073742728, 906,        908,        1073742734, 911,
    1073742737, 929,        1073742755, 939,        975,        1073742802,
    980,        984,        986,        988,        990,        992,
    994,        996,        998,        1000,       1002,       1004,
    1006,       1012,       1015,       1073742841, 1018,       1073742845,
    1071,       1120,       1122,       1124,       1126,       1128,
    1130,       1132,       1134,       1136,       1138,       1140,
    1142,       1144,       1146,       1148,       1150,       1152,
    1162,       1164,       1166,       1168,       1170,       1172,
    1174,       1176,       1178,       1180,       1182,       1184,
    1186,       1188,       1190,       1192,       1194,       1196,
    1198,       1200,       1202,       1204,       1206,       1208,
    1210,       1212,       1214,       1073743040, 1217,       1219,
    1221,       1223,       1225,       1227,       1229,       1232,
    1234,       1236,       1238,       1240,       1242,       1244,
    1246,       1248,       1250,       1252,       1254,       1256,
    1258,       1260,       1262,       1264,       1266,       1268,
    1270,       1272,       1274,       1276,       1278,       1280,
    1282,       1284,       1286,       1288,       1290,       1292,
    1294,       1296,       1298,       1300,       1302,       1304,
    1306,       1308,       1310,       1312,       1314,       1316,
    1318,       1320,       1322,       1324,       1326,       1073743153,
    1366,       1073746080, 4293,       4295,       4301,       7680,
    7682,       7684,       7686,       7688,       7690,       7692,
    7694,       7696,       7698,       7700,       7702,       7704,
    7706,       7708,       7710,       7712,       7714,       7716,
    7718,       7720,       7722,       7724,       7726,       7728,
    7730,       7732,       7734,       7736,       7738,       7740,
    7742,       7744,       7746,       7748,       7750,       7752,
    7754,       7756,       7758,       7760,       7762,       7764,
    7766,       7768,       7770,       7772,       7774,       7776,
    7778,       7780,       7782,       7784,       7786,       7788,
    7790,       7792,       7794,       7796,       7798,       7800,
    7802,       7804,       7806,       7808,       7810,       7812,
    7814,       7816,       7818,       7820,       7822,       7824,
    7826,       7828,       7838,       7840,       7842,       7844,
    7846,       7848,       7850,       7852,       7854,       7856,
    7858,       7860,       7862,       7864,       7866,       7868,
    7870,       7872,       7874,       7876,       7878,       7880,
    7882,       7884,       7886,       7888,       7890,       7892,
    7894,       7896,       7898,       7900,       7902,       7904,
    7906,       7908,       7910,       7912,       7914,       7916,
    7918,       7920,       7922,       7924,       7926,       7928,
    7930,       7932,       7934,       1073749768, 7951,       1073749784,
    7965,       1073749800, 7983,       1073749816, 7999,       1073749832,
    8013,       8025,       8027,       8029,       8031,       1073749864,
    8047,       1073749944, 8123,       1073749960, 8139,       1073749976,
    8155,       1073749992, 8172,       1073750008, 8187};
static const uint16_t kUppercaseTable1Size = 86;
static const int32_t kUppercaseTable1[86] = {
    258,        263,  1073742091, 269,  1073742096, 274,        277,
    1073742105, 285,  292,        294,  296,        1073742122, 301,
    1073742128, 307,  1073742142, 319,  325,        387,        1073744896,
    3118,       3168, 1073744994, 3172, 3175,       3177,       3179,
    1073745005, 3184, 3186,       3189, 1073745022, 3200,       3202,
    3204,       3206, 3208,       3210, 3212,       3214,       3216,
    3218,       3220, 3222,       3224, 3226,       3228,       3230,
    3232,       3234, 3236,       3238, 3240,       3242,       3244,
    3246,       3248, 3250,       3252, 3254,       3256,       3258,
    3260,       3262, 3264,       3266, 3268,       3270,       3272,
    3274,       3276, 3278,       3280, 3282,       3284,       3286,
    3288,       3290, 3292,       3294, 3296,       3298,       3307,
    3309,       3314};
static const uint16_t kUppercaseTable5Size = 101;
static const int32_t kUppercaseTable5[101] = {
    1600, 1602, 1604, 1606, 1608, 1610, 1612, 1614,       1616, 1618,
    1620, 1622, 1624, 1626, 1628, 1630, 1632, 1634,       1636, 1638,
    1640, 1642, 1644, 1664, 1666, 1668, 1670, 1672,       1674, 1676,
    1678, 1680, 1682, 1684, 1686, 1688, 1690, 1826,       1828, 1830,
    1832, 1834, 1836, 1838, 1842, 1844, 1846, 1848,       1850, 1852,
    1854, 1856, 1858, 1860, 1862, 1864, 1866, 1868,       1870, 1872,
    1874, 1876, 1878, 1880, 1882, 1884, 1886, 1888,       1890, 1892,
    1894, 1896, 1898, 1900, 1902, 1913, 1915, 1073743741, 1918, 1920,
    1922, 1924, 1926, 1931, 1933, 1936, 1938, 1942,       1944, 1946,
    1948, 1950, 1952, 1954, 1956, 1958, 1960, 1073743786, 1965, 1073743792,
    1969};
static const uint16_t kUppercaseTable7Size = 2;
static const int32_t kUppercaseTable7[2] = {1073749793, 7994};
bool Uppercase::Is(uchar c) {
  int chunk_index = c >> 13;
  switch (chunk_index) {
    case 0:
      return LookupPredicate(kUppercaseTable0, kUppercaseTable0Size, c);
    case 1:
      return LookupPredicate(kUppercaseTable1, kUppercaseTable1Size, c);
    case 5:
      return LookupPredicate(kUppercaseTable5, kUppercaseTable5Size, c);
    case 7:
      return LookupPredicate(kUppercaseTable7, kUppercaseTable7Size, c);
    default:
      return false;
  }
}
#endif  // V8_INTL_SUPPORT

// Letter:               point.category in ['Lu', 'Ll', 'Lt', 'Lm', 'Lo', 'Nl']
#ifdef V8_INTL_SUPPORT
bool Letter::Is(uchar c) { return static_cast<bool>(u_isalpha(c)); }
#else
static const uint16_t kLetterTable0Size = 431;
static const int32_t kLetterTable0[431] = {
    1073741889, 90,         1073741921, 122,        170,        181,
    186,        1073742016, 214,        1073742040, 246,        1073742072,
    705,        1073742534, 721,        1073742560, 740,        748,
    750,        1073742704, 884,        1073742710, 887,        1073742714,
    893,        895,        902,        1073742728, 906,        908,
    1073742734, 929,        1073742755, 1013,       1073742839, 1153,
    1073742986, 1327,       1073743153, 1366,       1369,       1073743201,
    1415,       1073743312, 1514,       1073743344, 1522,       1073743392,
    1610,       1073743470, 1647,       1073743473, 1747,       1749,
    1073743589, 1766,       1073743598, 1775,       1073743610, 1788,
    1791,       1808,       1073743634, 1839,       1073743693, 1957,
    1969,       1073743818, 2026,       1073743860, 2037,       2042,
    1073743872, 2069,       2074,       2084,       2088,       1073743936,
    2136,       1073744032, 2226,       1073744132, 2361,       2365,
    2384,       1073744216, 2401,       1073744241, 2432,       1073744261,
    2444,       1073744271, 2448,       1073744275, 2472,       1073744298,
    2480,       2482,       1073744310, 2489,       2493,       2510,
    1073744348, 2525,       1073744351, 2529,       1073744368, 2545,
    1073744389, 2570,       1073744399, 2576,       1073744403, 2600,
    1073744426, 2608,       1073744434, 2611,       1073744437, 2614,
    1073744440, 2617,       1073744473, 2652,       2654,       1073744498,
    2676,       1073744517, 2701,       1073744527, 2705,       1073744531,
    2728,       1073744554, 2736,       1073744562, 2739,       1073744565,
    2745,       2749,       2768,       1073744608, 2785,       1073744645,
    2828,       1073744655, 2832,       1073744659, 2856,       1073744682,
    2864,       1073744690, 2867,       1073744693, 2873,       2877,
    1073744732, 2909,       1073744735, 2913,       2929,       2947,
    1073744773, 2954,       1073744782, 2960,       1073744786, 2965,
    1073744793, 2970,       2972,       1073744798, 2975,       1073744803,
    2980,       1073744808, 2986,       1073744814, 3001,       3024,
    1073744901, 3084,       1073744910, 3088,       1073744914, 3112,
    1073744938, 3129,       3133,       1073744984, 3161,       1073744992,
    3169,       1073745029, 3212,       1073745038, 3216,       1073745042,
    3240,       1073745066, 3251,       1073745077, 3257,       3261,
    3294,       1073745120, 3297,       1073745137, 3314,       1073745157,
    3340,       1073745166, 3344,       1073745170, 3386,       3389,
    3406,       1073745248, 3425,       1073745274, 3455,       1073745285,
    3478,       1073745306, 3505,       1073745331, 3515,       3517,
    1073745344, 3526,       1073745409, 3632,       1073745458, 3635,
    1073745472, 3654,       1073745537, 3714,       3716,       1073745543,
    3720,       3722,       3725,       1073745556, 3735,       1073745561,
    3743,       1073745569, 3747,       3749,       3751,       1073745578,
    3755,       1073745581, 3760,       1073745586, 3763,       3773,
    1073745600, 3780,       3782,       1073745628, 3807,       3840,
    1073745728, 3911,       1073745737, 3948,       1073745800, 3980,
    1073745920, 4138,       4159,       1073746000, 4181,       1073746010,
    4189,       4193,       1073746021, 4198,       1073746030, 4208,
    1073746037, 4225,       4238,       1073746080, 4293,       4295,
    4301,       1073746128, 4346,       1073746172, 4680,       1073746506,
    4685,       1073746512, 4694,       4696,       1073746522, 4701,
    1073746528, 4744,       1073746570, 4749,       1073746576, 4784,
    1073746610, 4789,       1073746616, 4798,       4800,       1073746626,
    4805,       1073746632, 4822,       1073746648, 4880,       1073746706,
    4885,       1073746712, 4954,       1073746816, 5007,       1073746848,
    5108,       1073746945, 5740,       1073747567, 5759,       1073747585,
    5786,       1073747616, 5866,       1073747694, 5880,       1073747712,
    5900,       1073747726, 5905,       1073747744, 5937,       1073747776,
    5969,       1073747808, 5996,       1073747822, 6000,       1073747840,
    6067,       6103,       6108,       1073748000, 6263,       1073748096,
    6312,       6314,       1073748144, 6389,       1073748224, 6430,
    1073748304, 6509,       1073748336, 6516,       1073748352, 6571,
    1073748417, 6599,       1073748480, 6678,       1073748512, 6740,
    6823,       1073748741, 6963,       1073748805, 6987,       1073748867,
    7072,       1073748910, 7087,       1073748922, 7141,       1073748992,
    7203,       1073749069, 7247,       1073749082, 7293,       1073749225,
    7404,       1073749230, 7409,       1073749237, 7414,       1073749248,
    7615,       1073749504, 7957,       1073749784, 7965,       1073749792,
    8005,       1073749832, 8013,       1073749840, 8023,       8025,
    8027,       8029,       1073749855, 8061,       1073749888, 8116,
    1073749942, 8124,       8126,       1073749954, 8132,       1073749958,
    8140,       1073749968, 8147,       1073749974, 8155,       1073749984,
    8172,       1073750002, 8180,       1073750006, 8188};
static const uint16_t kLetterTable1Size = 87;
static const int32_t kLetterTable1[87] = {
    113,        127,        1073741968, 156,        258,        263,
    1073742090, 275,        277,        1073742105, 285,        292,
    294,        296,        1073742122, 301,        1073742127, 313,
    1073742140, 319,        1073742149, 329,        334,        1073742176,
    392,        1073744896, 3118,       1073744944, 3166,       1073744992,
    3300,       1073745131, 3310,       1073745138, 3315,       1073745152,
    3365,       3367,       3373,       1073745200, 3431,       3439,
    1073745280, 3478,       1073745312, 3494,       1073745320, 3502,
    1073745328, 3510,       1073745336, 3518,       1073745344, 3526,
    1073745352, 3534,       1073745360, 3542,       1073745368, 3550,
    3631,       1073745925, 4103,       1073745953, 4137,       1073745969,
    4149,       1073745976, 4156,       1073745985, 4246,       1073746077,
    4255,       1073746081, 4346,       1073746172, 4351,       1073746181,
    4397,       1073746225, 4494,       1073746336, 4538,       1073746416,
    4607,       1073746944, 8191};
static const uint16_t kLetterTable2Size = 4;
static const int32_t kLetterTable2[4] = {1073741824, 3509, 1073745408, 8191};
static const uint16_t kLetterTable3Size = 2;
static const int32_t kLetterTable3[2] = {1073741824, 8191};
static const uint16_t kLetterTable4Size = 2;
static const int32_t kLetterTable4[2] = {1073741824, 8140};
static const uint16_t kLetterTable5Size = 100;
static const int32_t kLetterTable5[100] = {
    1073741824, 1164,       1073743056, 1277,       1073743104, 1548,
    1073743376, 1567,       1073743402, 1579,       1073743424, 1646,
    1073743487, 1693,       1073743520, 1775,       1073743639, 1823,
    1073743650, 1928,       1073743755, 1934,       1073743760, 1965,
    1073743792, 1969,       1073743863, 2049,       1073743875, 2053,
    1073743879, 2058,       1073743884, 2082,       1073743936, 2163,
    1073744002, 2227,       1073744114, 2295,       2299,       1073744138,
    2341,       1073744176, 2374,       1073744224, 2428,       1073744260,
    2482,       2511,       1073744352, 2532,       1073744358, 2543,
    1073744378, 2558,       1073744384, 2600,       1073744448, 2626,
    1073744452, 2635,       1073744480, 2678,       2682,       1073744510,
    2735,       2737,       1073744565, 2742,       1073744569, 2749,
    2752,       2754,       1073744603, 2781,       1073744608, 2794,
    1073744626, 2804,       1073744641, 2822,       1073744649, 2830,
    1073744657, 2838,       1073744672, 2854,       1073744680, 2862,
    1073744688, 2906,       1073744732, 2911,       1073744740, 2917,
    1073744832, 3042,       1073744896, 8191};
static const uint16_t kLetterTable6Size = 6;
static const int32_t kLetterTable6[6] = {1073741824, 6051,       1073747888,
                                         6086,       1073747915, 6139};
static const uint16_t kLetterTable7Size = 48;
static const int32_t kLetterTable7[48] = {
    1073748224, 6765,       1073748592, 6873,       1073748736, 6918,
    1073748755, 6935,       6941,       1073748767, 6952,       1073748778,
    6966,       1073748792, 6972,       6974,       1073748800, 6977,
    1073748803, 6980,       1073748806, 7089,       1073748947, 7485,
    1073749328, 7567,       1073749394, 7623,       1073749488, 7675,
    1073749616, 7796,       1073749622, 7932,       1073749793, 7994,
    1073749825, 8026,       1073749862, 8126,       1073749954, 8135,
    1073749962, 8143,       1073749970, 8151,       1073749978, 8156};
bool Letter::Is(uchar c) {
  int chunk_index = c >> 13;
  switch (chunk_index) {
    case 0:
      return LookupPredicate(kLetterTable0, kLetterTable0Size, c);
    case 1:
      return LookupPredicate(kLetterTable1, kLetterTable1Size, c);
    case 2:
      return LookupPredicate(kLetterTable2, kLetterTable2Size, c);
    case 3:
      return LookupPredicate(kLetterTable3, kLetterTable3Size, c);
    case 4:
      return LookupPredicate(kLetterTable4, kLetterTable4Size, c);
    case 5:
      return LookupPredicate(kLetterTable5, kLetterTable5Size, c);
    case 6:
      return LookupPredicate(kLetterTable6, kLetterTable6Size, c);
    case 7:
      return LookupPredicate(kLetterTable7, kLetterTable7Size, c);
    default:
      return false;
  }
}
#endif

#ifndef V8_INTL_SUPPORT
// ID_Start:             ((point.category in ['Lu', 'Ll', 'Lt', 'Lm', 'Lo',
// 'Nl'] or 'Other_ID_Start' in point.properties) and ('Pattern_Syntax' not in
// point.properties) and ('Pattern_White_Space' not in point.properties)) or
// ('JS_ID_Start' in point.properties)

static const uint16_t kID_StartTable0Size = 434;
static const int32_t kID_StartTable0[434] = {
    36,         1073741889, 90,         92,         95,         1073741921,
    122,        170,        181,        186,        1073742016, 214,
    1073742040, 246,        1073742072, 705,        1073742534, 721,
    1073742560, 740,        748,        750,        1073742704, 884,
    1073742710, 887,        1073742714, 893,        895,        902,
    1073742728, 906,        908,        1073742734, 929,        1073742755,
    1013,       1073742839, 1153,       1073742986, 1327,       1073743153,
    1366,       1369,       1073743201, 1415,       1073743312, 1514,
    1073743344, 1522,       1073743392, 1610,       1073743470, 1647,
    1073743473, 1747,       1749,       1073743589, 1766,       1073743598,
    1775,       1073743610, 1788,       1791,       1808,       1073743634,
    1839,       1073743693, 1957,       1969,       1073743818, 2026,
    1073743860, 2037,       2042,       1073743872, 2069,       2074,
    2084,       2088,       1073743936, 2136,       1073744032, 2226,
    1073744132, 2361,       2365,       2384,       1073744216, 2401,
    1073744241, 2432,       1073744261, 2444,       1073744271, 2448,
    1073744275, 2472,       1073744298, 2480,       2482,       1073744310,
    2489,       2493,       2510,       1073744348, 2525,       1073744351,
    2529,       1073744368, 2545,       1073744389, 2570,       1073744399,
    2576,       1073744403, 2600,       1073744426, 2608,       1073744434,
    2611,       1073744437, 2614,       1073744440, 2617,       1073744473,
    2652,       2654,       1073744498, 2676,       1073744517, 2701,
    1073744527, 2705,       1073744531, 2728,       1073744554, 2736,
    1073744562, 2739,       1073744565, 2745,       2749,       2768,
    1073744608, 2785,       1073744645, 2828,       1073744655, 2832,
    1073744659, 2856,       1073744682, 2864,       1073744690, 2867,
    1073744693, 2873,       2877,       1073744732, 2909,       1073744735,
    2913,       2929,       2947,       1073744773, 2954,       1073744782,
    2960,       1073744786, 2965,       1073744793, 2970,       2972,
    1073744798, 2975,       1073744803, 2980,       1073744808, 2986,
    1073744814, 3001,       3024,       1073744901, 3084,       1073744910,
    3088,       1073744914, 3112,       1073744938, 3129,       3133,
    1073744984, 3161,       1073744992, 3169,       1073745029, 3212,
    1073745038, 3216,       1073745042, 3240,       1073745066, 3251,
    1073745077, 3257,       3261,       3294,       1073745120, 3297,
    1073745137, 3314,       1073745157, 3340,       1073745166, 3344,
    1073745170, 3386,       3389,       3406,       1073745248, 3425,
    1073745274, 3455,       1073745285, 3478,       1073745306, 3505,
    1073745331, 3515,       3517,       1073745344, 3526,       1073745409,
    3632,       1073745458, 3635,       1073745472, 3654,       1073745537,
    3714,       3716,       1073745543, 3720,       3722,       3725,
    1073745556, 3735,       1073745561, 3743,       1073745569, 3747,
    3749,       3751,       1073745578, 3755,       1073745581, 3760,
    1073745586, 3763,       3773,       1073745600, 3780,       3782,
    1073745628, 3807,       3840,       1073745728, 3911,       1073745737,
    3948,       1073745800, 3980,       1073745920, 4138,       4159,
    1073746000, 4181,       1073746010, 4189,       4193,
```