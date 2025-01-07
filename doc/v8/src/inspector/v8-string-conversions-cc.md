Response:
Let's break down the thought process for analyzing this C++ code and fulfilling the request.

1. **Understand the Core Task:** The primary goal is to explain the functionality of `v8-string-conversions.cc`. This immediately suggests focusing on string encoding conversions.

2. **Initial Scan for Key Information:** Read through the code, looking for:
    * **Includes:**  `iostream`, `limits`, `vector` are standard, but `src/base/logging.h` and particularly the `v8_inspector` namespace hint at the context: V8's inspector and logging.
    * **Namespaces:** `v8_inspector` confirms the context. The anonymous namespace `namespace { ... }` suggests utility functions not intended for external use.
    * **Type Aliases:** `UChar` and `UChar32` are defined, indicating the code deals with different character sizes. `UChar` being `char16_t` and `UChar32` being `uint32_t` tells us it's working with UTF-16 and potentially UTF-32.
    * **Constants:** `replacementCharacter` suggests handling of invalid or unrepresentable characters. `firstByteMark` hints at UTF-8 encoding structure.
    * **Enums:** `ConversionResult` is crucial. It defines the possible outcomes of the conversion functions.
    * **Functions:** The presence of `convertUTF16ToUTF8` and `convertUTF8ToUTF16` is the most important clue. These are the core conversion functions.
    * **Macros:** `U_IS_BMP`, `U_IS_SUPPLEMENTARY`, `U_IS_SURROGATE`, `U16_LEAD`, `U16_TRAIL` are clearly related to Unicode character properties and UTF-16 surrogate pairs.
    * **Global Functions (outside anonymous namespace):** `UTF16ToUTF8` and `UTF8ToUTF16` are the public interfaces.

3. **Focus on the Conversion Functions:** The `convertUTF16ToUTF8` and `convertUTF8ToUTF16` functions are the heart of this file. Analyze their logic:
    * **`convertUTF16ToUTF8`:**
        * Iterates through UTF-16 characters.
        * Handles surrogate pairs to form a `UChar32`.
        * Determines the number of bytes needed for the UTF-8 representation.
        * Performs bit manipulation to create the UTF-8 byte sequence.
        * Checks for buffer overflows (`targetEnd`).
        * Uses `strict` mode to handle invalid surrogate pairs.
    * **`convertUTF8ToUTF16`:**
        * Iterates through UTF-8 bytes.
        * Determines the length of the UTF-8 sequence.
        * Validates the UTF-8 sequence using `isLegalUTF8`.
        * Reads the UTF-8 sequence into a `UChar32`.
        * Handles characters within the BMP and supplementary planes.
        * Converts supplementary characters into UTF-16 surrogate pairs.
        * Handles invalid UTF-8 sequences and surrogate values (based on `strict`).

4. **Analyze Helper Functions and Constants:**
    * **`isASCII`:** Simple check for ASCII characters.
    * **`inlineUTF8SequenceLength`:** Determines the length of a UTF-8 sequence based on the first byte.
    * **`isLegalUTF8`:** Validates a UTF-8 sequence.
    * **`readUTF8Sequence`:** Converts a UTF-8 byte sequence to a `UChar32`.
    * **Macros:**  Understand their role in identifying BMP, supplementary, and surrogate code points and manipulating surrogate pairs.

5. **Understand the Public Interface:** The `UTF16ToUTF8` and `UTF8ToUTF16` functions provide the main entry points. They:
    * Handle null or empty input.
    * Allocate memory for the output.
    * Call the core conversion functions.
    * Handle potential errors (like unpaired surrogates in `UTF16ToUTF8`).
    * Resize the output buffer to the actual converted length.

6. **Address Specific Request Points:** Now, systematically address each point in the request:

    * **Functionality:** Summarize the core purpose: converting between UTF-16 and UTF-8. Mention the context within V8's inspector.

    * **Torque:** Check the file extension. Since it's `.cc`, it's not Torque.

    * **JavaScript Relationship:**  Think about where string conversions are relevant in JavaScript. JavaScript strings are internally often represented as UTF-16. When JavaScript interacts with external systems (like network requests, file I/O) that might use UTF-8, conversions are needed. Provide illustrative examples using `TextEncoder` and `TextDecoder`.

    * **Code Logic Inference (Hypothetical Input/Output):** Choose a simple example for each conversion direction. Demonstrate how a UTF-16 string becomes UTF-8 and vice-versa. Include examples of ASCII and non-ASCII characters.

    * **Common Programming Errors:** Consider common mistakes developers make when dealing with encodings:
        * Incorrectly assuming ASCII.
        * Not handling potential buffer overflows.
        * Mishandling or ignoring encoding errors.
        * Mixing up encoding and decoding. Provide concrete C++ examples related to the functions in the file.

7. **Structure and Refine:** Organize the information logically with clear headings and explanations. Use bullet points or numbered lists for readability. Ensure the language is clear and concise. Double-check for accuracy and completeness. For instance, initially, I might have forgotten to explicitly mention the `strict` parameter and its implications. A review would catch this. Also, ensure the JavaScript examples are accurate and relevant.

By following this structured approach, combining code analysis with an understanding of the request's specific points, we can effectively explain the functionality of the given C++ source code.
好的，让我们来分析一下 `v8/src/inspector/v8-string-conversions.cc` 这个文件的功能。

**主要功能:**

这个 C++ 文件提供了一组实用函数，用于在 UTF-16 和 UTF-8 两种字符串编码格式之间进行转换。这些转换功能主要用于 V8 引擎的 Inspector 模块。Inspector 模块允许开发者对运行中的 JavaScript 代码进行调试和分析，而这些调试信息可能需要在不同的编码格式之间进行转换，以便于传输和展示。

**具体功能分解:**

1. **`convertUTF16ToUTF8` 函数:**
   - 将 UTF-16 编码的字符串转换为 UTF-8 编码。
   - 支持严格模式 (`strict` 参数)，在严格模式下，遇到无效的 UTF-16 字符（例如，未配对的代理对）会返回错误。
   - 如果目标缓冲区空间不足，会返回 `targetExhausted` 错误。
   - 如果源字符串包含不合法的 UTF-16 序列，会返回 `sourceIllegal` 错误。

2. **`convertUTF8ToUTF16` 函数:**
   - 将 UTF-8 编码的字符串转换为 UTF-16 编码。
   - 同样支持严格模式，用于处理不合法的 UTF-8 序列或 UTF-16 代理对。
   - 可以选择性地检查源字符串是否全部为 ASCII 字符 (`sourceAllASCII` 参数）。
   - 如果目标缓冲区空间不足，会返回 `targetExhausted` 错误。
   - 如果源字符串包含不合法的 UTF-8 序列，会返回 `sourceIllegal` 错误。

3. **`UTF16ToUTF8` 函数:**
   - 提供了一个更方便的接口，将 UTF-16 字符串（`std::basic_string<UChar>`，其中 `UChar` 是 `char16_t` 的别名）转换为 `std::string` 类型的 UTF-8 字符串。
   - 内部调用 `convertUTF16ToUTF8` 函数。
   - 遇到未配对的 UTF-16 代理对时，会用替换字符 (U+FFFD) 代替。

4. **`UTF8ToUTF16` 函数:**
   - 提供了一个更方便的接口，将 UTF-8 字符串（`const char*`）转换为 `std::basic_string<UChar>` 类型的 UTF-16 字符串。
   - 内部调用 `convertUTF8ToUTF16` 函数。
   - 如果转换过程中遇到错误，会返回一个空的 UTF-16 字符串。

**关于文件扩展名 `.tq`:**

如果 `v8/src/inspector/v8-string-conversions.cc` 的文件扩展名是 `.tq`，那么它将是一个 **V8 Torque 源代码文件**。Torque 是 V8 使用的一种领域特定语言（DSL），用于生成高效的 C++ 代码，特别是用于实现 JavaScript 语言的内置函数和操作。但目前来看，这个文件是 `.cc`，所以它是标准的 C++ 源代码。

**与 JavaScript 的关系 (以及 JavaScript 示例):**

虽然这个文件本身是 C++ 代码，但它的功能与 JavaScript 的字符串处理密切相关。JavaScript 内部使用的字符串通常是 UTF-16 编码。当 JavaScript 需要与外部系统（例如，通过网络发送数据或与 C++ 代码交互）交换数据时，可能需要将字符串转换为 UTF-8 编码，因为 UTF-8 在互联网上更常见。

**JavaScript 示例:**

```javascript
// JavaScript 字符串默认是 UTF-16 编码

const utf16String = "你好，世界！🌍";

// 将 JavaScript 字符串编码为 UTF-8 (使用 TextEncoder API)
const encoder = new TextEncoder();
const utf8Array = encoder.encode(utf16String);

console.log(utf8Array); // 输出 UTF-8 编码的 Uint8Array

// 将 UTF-8 编码的 Uint8Array 解码为 JavaScript 字符串 (使用 TextDecoder API)
const decoder = new TextDecoder();
const decodedString = decoder.decode(utf8Array);

console.log(decodedString); // 输出 "你好，世界！🌍" (与原始字符串相同)
```

在这个例子中，`TextEncoder` API 的 `encode()` 方法的功能类似于 `v8-string-conversions.cc` 中的 `UTF16ToUTF8` 函数，而 `TextDecoder` API 的 `decode()` 方法的功能类似于 `UTF8ToUTF16` 函数。V8 引擎内部在实现这些 JavaScript API 时，很可能就会用到类似 `v8-string-conversions.cc` 中提供的底层转换功能。

**代码逻辑推理 (假设输入与输出):**

**假设输入 (UTF-16):**  `UChar source[] = {'H', 'e', 'l', 'l', 'o', 0x4E00, 0x754C};`  // "Hello世界" (0x4E00 是 '世' 的 Unicode 码点，0x754C 是 '界' 的 Unicode 码点)

**预期输出 (UTF-8):**  一个 `char` 数组或 `std::string`，包含 "Hello世界" 的 UTF-8 编码。根据 UTF-8 编码规则，非 ASCII 字符会占用多个字节：
- '世' (U+4E00) 编码为 `E4 B8 96`
- '界' (U+754C) 编码为 `E7 95 8C`

因此，预期的 UTF-8 输出应该是：`'H', 'e', 'l', 'l', 'o', 0xE4, 0xB8, 0x96, 0xE7, 0x95, 0x8C`

**使用 `UTF16ToUTF8` 函数进行转换的逻辑推理:**

1. 函数遍历输入的 UTF-16 数组 `source`。
2. 对于 ASCII 字符 ('H', 'e', 'l', 'l', 'o')，每个 UTF-16 字符直接转换为一个对应的 UTF-8 字节。
3. 当遇到非 ASCII 字符时：
   - 对于 '世' (0x4E00)，`convertUTF16ToUTF8` 会判断其 Unicode 码点范围，并生成对应的 3 字节 UTF-8 序列 `0xE4 0xB8 0x96`。
   - 对于 '界' (0x754C)，同样生成 3 字节 UTF-8 序列 `0xE7 95 8C`。
4. 最终将所有转换后的字节组合成 UTF-8 字符串。

**假设输入 (UTF-8):** `const char source[] = "你好吗";` (假设这段字符串是以 UTF-8 编码的)

**预期输出 (UTF-16):** `UChar output[] = {0x4F60, 0x597D, 0x5417};` // "你好吗" 的 UTF-16 编码

**使用 `UTF8ToUTF16` 函数进行转换的逻辑推理:**

1. 函数遍历输入的 UTF-8 字节流。
2. 它会根据每个字节的前几位来判断当前字符是 ASCII 字符还是多字节 UTF-8 字符。
3. 对于 "你" (`0xE4 0xBD 0xA0`)，函数会识别出这是一个 3 字节的 UTF-8 序列，并将其解码为对应的 UTF-16 码点 `0x4F60`。
4. 对于 "好" (`0xE5 0xA5 0xBD`)，解码为 `0x597D`。
5. 对于 "吗" (`0xE5 0x90 0x97`)，解码为 `0x5417`。
6. 最终将解码后的 UTF-16 码点组合成 UTF-16 字符串。

**用户常见的编程错误:**

1. **假设字符串总是 ASCII:** 很多初学者可能没有意识到 Unicode 和不同的编码格式，错误地假设所有字符串都是简单的 ASCII 字符。这会导致在处理非英语字符时出现乱码。

   ```c++
   // 错误示例：假设所有字符都是单字节的
   std::string convertToUpperCase(const std::string& input) {
       std::string output = input;
       for (char& c : output) {
           if (c >= 'a' && c <= 'z') {
               c = c - 32; // 错误的假设，对于非 ASCII 字符无效
           }
       }
       return output;
   }

   // 例如，输入 UTF-8 编码的 "你好"，这个函数不会正确处理。
   ```

2. **缓冲区溢出:** 在进行字符串转换时，如果没有正确估计目标缓冲区的大小，可能会导致缓冲区溢出。`v8-string-conversions.cc` 中的函数通过参数传递缓冲区大小并返回错误码来帮助避免这个问题。

   ```c++
   // 错误示例：目标缓冲区太小
   std::string utf16ToUtf8Bad(const std::u16string& utf16) {
       std::string utf8(utf16.length(), '\0'); // 假设 UTF-8 长度与 UTF-16 相同，错误！
       // ... 调用转换函数，但 utf8 的大小可能不足以容纳所有 UTF-8 字符
       return utf8;
   }
   ```

3. **忽略编码错误:** 在进行编码转换时，可能会遇到无效的字符序列。忽略这些错误可能会导致数据损坏或安全问题。`v8-string-conversions.cc` 提供了严格模式来帮助检测这些错误。

   ```c++
   // 错误示例：没有检查转换函数的返回值
   void convertAndPrint(const std::u16string& utf16) {
       std::string utf8;
       // ... 调用 convertUTF16ToUTF8，但没有检查返回值
       std::cout << utf8 << std::endl; // 如果转换失败，utf8 可能包含不完整或错误的数据
   }
   ```

4. **混淆编码格式:** 开发者可能会混淆 UTF-8 和 UTF-16，导致使用错误的转换函数或以错误的编码方式解析字符串。

   ```c++
   // 错误示例：将 UTF-8 字符串误认为 UTF-16 处理
   std::string processStringAsUTF16(const std::string& utf8String) {
       std::u16string utf16String = reinterpret_cast<const char16_t*>(utf8String.data()); // 错误！
       // ... 对 utf16String 进行操作，结果将是错误的
       return "";
   }
   ```

总而言之，`v8/src/inspector/v8-string-conversions.cc` 提供了一组可靠的底层工具，用于在 V8 引擎的 Inspector 模块中处理字符串编码转换，这对于调试和分析 JavaScript 代码至关重要。理解这些转换机制有助于开发者避免常见的字符串处理错误。

Prompt: 
```
这是目录为v8/src/inspector/v8-string-conversions.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/inspector/v8-string-conversions.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/inspector/v8-string-conversions.h"

#include <limits>
#include <vector>

#include "src/base/logging.h"

namespace v8_inspector {
namespace {
using UChar = char16_t;
using UChar32 = uint32_t;

bool isASCII(UChar c) { return !(c & ~0x7F); }

const UChar replacementCharacter = 0xFFFD;

inline int inlineUTF8SequenceLengthNonASCII(char b0) {
  if ((b0 & 0xC0) != 0xC0) return 0;
  if ((b0 & 0xE0) == 0xC0) return 2;
  if ((b0 & 0xF0) == 0xE0) return 3;
  if ((b0 & 0xF8) == 0xF0) return 4;
  return 0;
}

inline int inlineUTF8SequenceLength(char b0) {
  return isASCII(b0) ? 1 : inlineUTF8SequenceLengthNonASCII(b0);
}

// Once the bits are split out into bytes of UTF-8, this is a mask OR-ed
// into the first byte, depending on how many bytes follow.  There are
// as many entries in this table as there are UTF-8 sequence types.
// (I.e., one byte sequence, two byte... etc.). Remember that sequences
// for *legal* UTF-8 will be 4 or fewer bytes total.
static const unsigned char firstByteMark[7] = {0x00, 0x00, 0xC0, 0xE0,
                                               0xF0, 0xF8, 0xFC};

enum ConversionResult {
  conversionOK,     // conversion successful
  sourceExhausted,  // partial character in source, but hit end
  targetExhausted,  // insuff. room in target for conversion
  sourceIllegal     // source sequence is illegal/malformed
};

ConversionResult convertUTF16ToUTF8(const UChar** sourceStart,
                                    const UChar* sourceEnd, char** targetStart,
                                    char* targetEnd, bool strict) {
  ConversionResult result = conversionOK;
  const UChar* source = *sourceStart;
  char* target = *targetStart;
  while (source < sourceEnd) {
    UChar32 ch;
    uint32_t bytesToWrite = 0;
    const UChar32 byteMask = 0xBF;
    const UChar32 byteMark = 0x80;
    const UChar* oldSource =
        source;  // In case we have to back up because of target overflow.
    ch = static_cast<uint16_t>(*source++);
    // If we have a surrogate pair, convert to UChar32 first.
    if (ch >= 0xD800 && ch <= 0xDBFF) {
      // If the 16 bits following the high surrogate are in the source buffer...
      if (source < sourceEnd) {
        UChar32 ch2 = static_cast<uint16_t>(*source);
        // If it's a low surrogate, convert to UChar32.
        if (ch2 >= 0xDC00 && ch2 <= 0xDFFF) {
          ch = ((ch - 0xD800) << 10) + (ch2 - 0xDC00) + 0x0010000;
          ++source;
        } else if (strict) {  // it's an unpaired high surrogate
          --source;           // return to the illegal value itself
          result = sourceIllegal;
          break;
        }
      } else {     // We don't have the 16 bits following the high surrogate.
        --source;  // return to the high surrogate
        result = sourceExhausted;
        break;
      }
    } else if (strict) {
      // UTF-16 surrogate values are illegal in UTF-32
      if (ch >= 0xDC00 && ch <= 0xDFFF) {
        --source;  // return to the illegal value itself
        result = sourceIllegal;
        break;
      }
    }
    // Figure out how many bytes the result will require
    if (ch < static_cast<UChar32>(0x80)) {
      bytesToWrite = 1;
    } else if (ch < static_cast<UChar32>(0x800)) {
      bytesToWrite = 2;
    } else if (ch < static_cast<UChar32>(0x10000)) {
      bytesToWrite = 3;
    } else if (ch < static_cast<UChar32>(0x110000)) {
      bytesToWrite = 4;
    } else {
      bytesToWrite = 3;
      ch = replacementCharacter;
    }

    target += bytesToWrite;
    if (target > targetEnd) {
      source = oldSource;  // Back up source pointer!
      target -= bytesToWrite;
      result = targetExhausted;
      break;
    }
    switch (bytesToWrite) {
      case 4:
        *--target = static_cast<char>((ch | byteMark) & byteMask);
        ch >>= 6;
        [[fallthrough]];
      case 3:
        *--target = static_cast<char>((ch | byteMark) & byteMask);
        ch >>= 6;
        [[fallthrough]];
      case 2:
        *--target = static_cast<char>((ch | byteMark) & byteMask);
        ch >>= 6;
        [[fallthrough]];
      case 1:
        *--target = static_cast<char>(ch | firstByteMark[bytesToWrite]);
    }
    target += bytesToWrite;
  }
  *sourceStart = source;
  *targetStart = target;
  return result;
}

/**
 * Is this code point a BMP code point (U+0000..U+ffff)?
 * @param c 32-bit code point
 * @return TRUE or FALSE
 * @stable ICU 2.8
 */
#define U_IS_BMP(c) ((uint32_t)(c) <= 0xFFFF)

/**
 * Is this code point a supplementary code point (U+010000..U+10FFFF)?
 * @param c 32-bit code point
 * @return TRUE or FALSE
 * @stable ICU 2.8
 */
#define U_IS_SUPPLEMENTARY(c) ((uint32_t)((c)-0x010000) <= 0xFFFFF)

/**
 * Is this code point a surrogate (U+d800..U+dfff)?
 * @param c 32-bit code point
 * @return TRUE or FALSE
 * @stable ICU 2.4
 */
#define U_IS_SURROGATE(c) (((c)&0xFFFFF800) == 0xD800)

/**
 * Get the lead surrogate (0xD800..0xDBFF) for a
 * supplementary code point (0x010000..0x10FFFF).
 * @param supplementary 32-bit code point (U+010000..U+10FFFF)
 * @return lead surrogate (U+D800..U+DBFF) for supplementary
 * @stable ICU 2.4
 */
#define U16_LEAD(supplementary) (UChar)(((supplementary) >> 10) + 0xD7C0)

/**
 * Get the trail surrogate (0xDC00..0xDFFF) for a
 * supplementary code point (0x010000..0x10FFFF).
 * @param supplementary 32-bit code point (U+010000..U+10FFFF)
 * @return trail surrogate (U+DC00..U+DFFF) for supplementary
 * @stable ICU 2.4
 */
#define U16_TRAIL(supplementary) (UChar)(((supplementary)&0x3FF) | 0xDC00)

// This must be called with the length pre-determined by the first byte.
// If presented with a length > 4, this returns false.  The Unicode
// definition of UTF-8 goes up to 4-byte sequences.
static bool isLegalUTF8(const unsigned char* source, int length) {
  unsigned char a;
  const unsigned char* srcptr = source + length;
  switch (length) {
    default:
      return false;
    // Everything else falls through when "true"...
    case 4:
      if ((a = (*--srcptr)) < 0x80 || a > 0xBF) return false;
      [[fallthrough]];
    case 3:
      if ((a = (*--srcptr)) < 0x80 || a > 0xBF) return false;
      [[fallthrough]];
    case 2:
      if ((a = (*--srcptr)) > 0xBF) return false;

      // no fall-through in this inner switch
      switch (*source) {
        case 0xE0:
          if (a < 0xA0) return false;
          break;
        case 0xED:
          if (a > 0x9F) return false;
          break;
        case 0xF0:
          if (a < 0x90) return false;
          break;
        case 0xF4:
          if (a > 0x8F) return false;
          break;
        default:
          if (a < 0x80) return false;
      }
      [[fallthrough]];

    case 1:
      if (*source >= 0x80 && *source < 0xC2) return false;
  }
  if (*source > 0xF4) return false;
  return true;
}

// Magic values subtracted from a buffer value during UTF8 conversion.
// This table contains as many values as there might be trailing bytes
// in a UTF-8 sequence.
static const UChar32 offsetsFromUTF8[6] = {0x00000000UL,
                                           0x00003080UL,
                                           0x000E2080UL,
                                           0x03C82080UL,
                                           static_cast<UChar32>(0xFA082080UL),
                                           static_cast<UChar32>(0x82082080UL)};

static inline UChar32 readUTF8Sequence(const char*& sequence, size_t length) {
  UChar32 character = 0;

  // The cases all fall through.
  switch (length) {
    case 6:
      character += static_cast<unsigned char>(*sequence++);
      character <<= 6;
      [[fallthrough]];
    case 5:
      character += static_cast<unsigned char>(*sequence++);
      character <<= 6;
      [[fallthrough]];
    case 4:
      character += static_cast<unsigned char>(*sequence++);
      character <<= 6;
      [[fallthrough]];
    case 3:
      character += static_cast<unsigned char>(*sequence++);
      character <<= 6;
      [[fallthrough]];
    case 2:
      character += static_cast<unsigned char>(*sequence++);
      character <<= 6;
      [[fallthrough]];
    case 1:
      character += static_cast<unsigned char>(*sequence++);
  }

  return character - offsetsFromUTF8[length - 1];
}

ConversionResult convertUTF8ToUTF16(const char** sourceStart,
                                    const char* sourceEnd, UChar** targetStart,
                                    UChar* targetEnd, bool* sourceAllASCII,
                                    bool strict) {
  ConversionResult result = conversionOK;
  const char* source = *sourceStart;
  UChar* target = *targetStart;
  UChar orAllData = 0;
  while (source < sourceEnd) {
    int utf8SequenceLength = inlineUTF8SequenceLength(*source);
    if (sourceEnd - source < utf8SequenceLength) {
      result = sourceExhausted;
      break;
    }
    // Do this check whether lenient or strict
    if (!isLegalUTF8(reinterpret_cast<const unsigned char*>(source),
                     utf8SequenceLength)) {
      result = sourceIllegal;
      break;
    }

    UChar32 character = readUTF8Sequence(source, utf8SequenceLength);

    if (target >= targetEnd) {
      source -= utf8SequenceLength;  // Back up source pointer!
      result = targetExhausted;
      break;
    }

    if (U_IS_BMP(character)) {
      // UTF-16 surrogate values are illegal in UTF-32
      if (U_IS_SURROGATE(character)) {
        if (strict) {
          source -= utf8SequenceLength;  // return to the illegal value itself
          result = sourceIllegal;
          break;
        }
        *target++ = replacementCharacter;
        orAllData |= replacementCharacter;
      } else {
        *target++ = static_cast<UChar>(character);  // normal case
        orAllData |= character;
      }
    } else if (U_IS_SUPPLEMENTARY(character)) {
      // target is a character in range 0xFFFF - 0x10FFFF
      if (target + 1 >= targetEnd) {
        source -= utf8SequenceLength;  // Back up source pointer!
        result = targetExhausted;
        break;
      }
      *target++ = U16_LEAD(character);
      *target++ = U16_TRAIL(character);
      orAllData = 0xFFFF;
    } else {
      if (strict) {
        source -= utf8SequenceLength;  // return to the start
        result = sourceIllegal;
        break;  // Bail out; shouldn't continue
      } else {
        *target++ = replacementCharacter;
        orAllData |= replacementCharacter;
      }
    }
  }
  *sourceStart = source;
  *targetStart = target;

  if (sourceAllASCII) *sourceAllASCII = !(orAllData & ~0x7F);

  return result;
}

// Helper to write a three-byte UTF-8 code point to the buffer, caller must
// check room is available.
static inline void putUTF8Triple(char*& buffer, UChar ch) {
  *buffer++ = static_cast<char>(((ch >> 12) & 0x0F) | 0xE0);
  *buffer++ = static_cast<char>(((ch >> 6) & 0x3F) | 0x80);
  *buffer++ = static_cast<char>((ch & 0x3F) | 0x80);
}
}  // namespace

std::string UTF16ToUTF8(const UChar* stringStart, size_t length) {
  if (!stringStart || !length) return std::string();

  // Allocate a buffer big enough to hold all the characters
  // (an individual UTF-16 UChar can only expand to 3 UTF-8 bytes).
  // Optimization ideas, if we find this function is hot:
  //  * We could speculatively create a CStringBuffer to contain 'length'
  //    characters, and resize if necessary (i.e. if the buffer contains
  //    non-ascii characters). (Alternatively, scan the buffer first for
  //    ascii characters, so we know this will be sufficient).
  //  * We could allocate a CStringBuffer with an appropriate size to
  //    have a good chance of being able to write the string into the
  //    buffer without reallocing (say, 1.5 x length).
  if (length > std::numeric_limits<unsigned>::max() / 3) return std::string();

  std::string output(length * 3, '\0');
  const UChar* characters = stringStart;
  const UChar* characters_end = characters + length;
  char* buffer = &*output.begin();
  char* buffer_end = &*output.end();
  while (characters < characters_end) {
    // Use strict conversion to detect unpaired surrogates.
    ConversionResult result = convertUTF16ToUTF8(
        &characters, characters_end, &buffer, buffer_end, /* strict= */ true);
    DCHECK_NE(result, targetExhausted);
    // Conversion fails when there is an unpaired surrogate.  Put
    // replacement character (U+FFFD) instead of the unpaired
    // surrogate.
    if (result != conversionOK) {
      DCHECK_LE(0xD800, *characters);
      DCHECK_LE(*characters, 0xDFFF);
      // There should be room left, since one UChar hasn't been
      // converted.
      DCHECK_LE(buffer + 3, buffer_end);
      putUTF8Triple(buffer, replacementCharacter);
      ++characters;
    }
  }

  output.resize(buffer - output.data());
  return output;
}

std::basic_string<UChar> UTF8ToUTF16(const char* stringStart, size_t length) {
  if (!stringStart || !length) return std::basic_string<UChar>();
  std::vector<UChar> buffer(length);
  UChar* bufferStart = buffer.data();

  UChar* bufferCurrent = bufferStart;
  const char* stringCurrent = reinterpret_cast<const char*>(stringStart);
  if (convertUTF8ToUTF16(&stringCurrent,
                         reinterpret_cast<const char*>(stringStart + length),
                         &bufferCurrent, bufferCurrent + buffer.size(), nullptr,
                         true) != conversionOK)
    return std::basic_string<UChar>();
  size_t utf16Length = bufferCurrent - bufferStart;
  return std::basic_string<UChar>(bufferStart, bufferStart + utf16Length);
}

}  // namespace v8_inspector

"""

```