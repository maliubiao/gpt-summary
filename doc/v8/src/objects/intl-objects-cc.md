Response:
The user wants a summary of the functionality of the `v8/src/objects/intl-objects.cc` file. They also have some specific questions related to file extensions, JavaScript connections, code logic, and common programming errors. I need to go through the provided code and identify its core responsibilities.

**Plan:**

1. **General Functionality:** Read through the included headers and the code itself to understand the main purpose of the file. It seems heavily related to internationalization (Intl) features in V8.
2. **File Extension:** Determine if the file ending (`.cc`) indicates a Torque source file.
3. **JavaScript Connection:** Identify how the C++ code interacts with JavaScript Intl API functionalities. Provide a JavaScript example.
4. **Code Logic/Inference:** Look for specific functions or algorithms where input and output can be inferred. Provide an example.
5. **Common Programming Errors:** Think about common pitfalls developers might encounter when using the Intl features that this file supports.
6. **Summarize Functionality:**  Combine the findings into a concise summary for part 1.
```
这是目录为v8/src/objects/intl-objects.cc的一个v8源代码， 请列举一下它的功能,
如果v8/src/objects/intl-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

**v8/src/objects/intl-objects.cc 的功能:**

根据提供的代码片段，`v8/src/objects/intl-objects.cc` 文件是 V8 JavaScript 引擎中负责实现国际化 (Internationalization - Intl) 相关对象功能的 C++ 源代码文件。它主要负责以下方面：

1. **提供 Intl API 的底层实现:**  这个文件包含了实现 JavaScript 中 `Intl` 对象及其相关构造函数（如 `Intl.Collator`, `Intl.DateTimeFormat`, `Intl.NumberFormat`, `Intl.Locale` 等）功能的 C++ 代码。它连接了 V8 的 JavaScript 运行时环境和 ICU (International Components for Unicode) 库，ICU 提供了实际的国际化处理能力。

2. **字符串大小写转换:**  实现了高性能的字符串大小写转换，特别是针对 Latin-1 编码的字符串进行了优化。它处理了特殊情况，例如德语中的 sharp-S (ß) 转换为 "SS"。

3. **语言标签规范化:**  提供了将 BCP 47 语言标签规范化的功能，确保语言标签的格式正确。

4. **区域设置 (Locale) 处理:**  负责创建、处理和比较 ICU 的 `Locale` 对象，以及与 JavaScript 的 `Intl.Locale` 对象进行交互。

5. **资源加载和验证:** 涉及到 ICU 资源的加载和验证，确保 Intl 功能可以正确访问本地化数据。

6. **与 ICU 库的交互:**  代码中大量使用了 ICU 库提供的类和函数，例如 `icu::Locale`, `icu::UnicodeString`, `icu::Collator`, `icu::DateFormat`, `icu::NumberFormat` 等，来完成国际化相关的操作。

**关于文件扩展名:**

`v8/src/objects/intl-objects.cc` 以 `.cc` 结尾，这意味着它是一个标准的 C++ 源代码文件，而不是 V8 Torque 源代码文件（Torque 文件的扩展名是 `.tq`）。

**与 JavaScript 功能的关系及示例:**

`v8/src/objects/intl-objects.cc` 中的代码直接支撑着 JavaScript 的 `Intl` API。当你使用 JavaScript 的 Intl 对象时，V8 引擎会调用这个文件中的 C++ 代码来执行相应的国际化操作。

**JavaScript 示例:**

```javascript
// 使用 Intl.Collator 进行字符串排序
const collator = new Intl.Collator('zh-Hans-CN');
const list = ['你好', '世界', '你好世界'];
const sortedList = list.sort(collator.compare);
console.log(sortedList); // 输出根据中文拼音排序后的数组

// 使用 Intl.NumberFormat 格式化数字
const numberFormat = new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' });
const formattedNumber = numberFormat.format(1234.56);
console.log(formattedNumber); // 输出 "$1,234.56"

// 使用 Intl.DateTimeFormat 格式化日期
const dateTimeFormat = new Intl.DateTimeFormat('ja-JP', { year: 'numeric', month: 'long', day: 'numeric' });
const formattedDate = dateTimeFormat.format(new Date());
console.log(formattedDate); // 输出类似 "2023年 10月 27日" 的日期字符串

// 使用 Intl.Locale 获取和操作区域设置信息
const locale = new Intl.Locale('en-US-u-nu-arab');
console.log(locale.language); // 输出 "en"
console.log(locale.region);   // 输出 "US"
console.log(locale.getNumberingSystem()); // 输出 "arab"
```

在上述 JavaScript 代码中，当你创建 `Intl.Collator`、`Intl.NumberFormat`、`Intl.DateTimeFormat` 或 `Intl.Locale` 的实例并调用其方法时，V8 引擎会调用 `v8/src/objects/intl-objects.cc` 中相应的 C++ 代码来完成诸如排序、数字格式化、日期格式化以及区域设置信息处理等操作.

**代码逻辑推理 (假设输入与输出):**

考虑 `Intl::ConvertToLower` 函数，它将字符串转换为小写。

**假设输入:** 一个 JavaScript 字符串 "HELLO"

**代码逻辑推理:**  `Intl::ConvertToLower` 会遍历字符串的每个字符，并将其转换为小写。对于 ASCII 字符，它会使用快速的转换方法。

**假设输出:**  C++ 函数会返回一个新的字符串 "hello"。 在 JavaScript 中，调用 ` "HELLO".toLowerCase()` 最终会返回 "hello"。

**用户常见的编程错误:**

1. **区域设置 (Locale) 名称错误:**  传递了无效的区域设置字符串给 `Intl` 构造函数，例如 `new Intl.Collator('invalid-locale')`。这可能导致运行时错误或使用默认的区域设置。

   ```javascript
   try {
     const collator = new Intl.Collator('xyz-123'); // 错误的区域设置
   } catch (error) {
     console.error("区域设置错误:", error); // 可能会抛出 RangeError
   }
   ```

2. **未处理可能的异常:** 某些 `Intl` 操作可能会因为区域设置或选项的无效性而抛出异常，但开发者可能没有正确地捕获和处理这些异常。

3. **对 `Intl` 对象进行浅拷贝或修改:**  `Intl` 对象通常包含内部状态，不应该被直接修改或进行不正确的拷贝。

4. **假设默认行为:**  依赖于某些 `Intl` 方法的默认行为而不显式指定选项，可能导致在不同的环境中表现不一致。例如，不指定排序规则可能在不同浏览器或操作系统上产生不同的排序结果。

**功能归纳 (第 1 部分):**

`v8/src/objects/intl-objects.cc` 文件是 V8 引擎中实现 JavaScript 国际化 (Intl) API 核心功能的 C++ 源代码。它负责处理字符串大小写转换、语言标签规范化、区域设置管理以及与 ICU 库的交互，为 JavaScript 开发者提供了强大的国际化能力。该文件不是 Torque 源代码。
```
### 提示词
```
这是目录为v8/src/objects/intl-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/intl-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/intl-objects.h"

#include <algorithm>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "src/api/api-inl.h"
#include "src/base/logging.h"
#include "src/base/strings.h"
#include "src/common/globals.h"
#include "src/date/date.h"
#include "src/execution/isolate.h"
#include "src/execution/local-isolate.h"
#include "src/handles/global-handles.h"
#include "src/heap/factory.h"
#include "src/objects/js-collator-inl.h"
#include "src/objects/js-date-time-format-inl.h"
#include "src/objects/js-locale-inl.h"
#include "src/objects/js-locale.h"
#include "src/objects/js-number-format-inl.h"
#include "src/objects/js-temporal-objects.h"
#include "src/objects/managed-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/option-utils.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/smi.h"
#include "src/objects/string.h"
#include "src/strings/string-case.h"
#include "unicode/basictz.h"
#include "unicode/brkiter.h"
#include "unicode/calendar.h"
#include "unicode/coll.h"
#include "unicode/datefmt.h"
#include "unicode/decimfmt.h"
#include "unicode/formattedvalue.h"
#include "unicode/localebuilder.h"
#include "unicode/localematcher.h"
#include "unicode/locid.h"
#include "unicode/normalizer2.h"
#include "unicode/numberformatter.h"
#include "unicode/numfmt.h"
#include "unicode/numsys.h"
#include "unicode/timezone.h"
#include "unicode/ures.h"
#include "unicode/ustring.h"
#include "unicode/uvernum.h"  // U_ICU_VERSION_MAJOR_NUM

#ifndef V8_INTL_SUPPORT
#error Internationalization is expected to be enabled.
#endif  // V8_INTL_SUPPORT

#define XSTR(s) STR(s)
#define STR(s) #s
static_assert(
    V8_MINIMUM_ICU_VERSION <= U_ICU_VERSION_MAJOR_NUM,
    "v8 is required to build with ICU " XSTR(V8_MINIMUM_ICU_VERSION) " and up");
#undef STR
#undef XSTR

namespace v8::internal {

namespace {

inline constexpr uint8_t AsOneByte(uint16_t ch) {
  DCHECK_LE(ch, kMaxUInt8);
  return static_cast<uint8_t>(ch);
}

constexpr uint8_t kToLower[256] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
    0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73,
    0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B,
    0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83,
    0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B,
    0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3,
    0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB,
    0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xD7,
    0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3,
    0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB,
    0xFC, 0xFD, 0xFE, 0xFF,
};

inline constexpr uint8_t ToLatin1Lower(uint8_t ch) {
  static_assert(std::numeric_limits<decltype(ch)>::max() < arraysize(kToLower));
  return kToLower[ch];
}
// Ensure callers explicitly truncate uint16_t.
inline constexpr uint8_t ToLatin1Lower(uint16_t ch) = delete;

// Does not work for U+00DF (sharp-s), U+00B5 (micron), U+00FF, or two-byte
// values.
inline constexpr uint8_t ToLatin1Upper(uint8_t ch) {
  DCHECK(ch != 0xDF && ch != 0xB5 && ch != 0xFF);
  return ch &
         ~((IsAsciiLower(ch) || (((ch & 0xE0) == 0xE0) && ch != 0xF7)) << 5);
}
// Ensure callers explicitly truncate uint16_t.
inline constexpr uint8_t ToLatin1Upper(uint16_t ch) = delete;

bool ToUpperFastASCII(base::Vector<const uint16_t> src,
                      DirectHandle<SeqOneByteString> result) {
  // Do a faster loop for the case where all the characters are ASCII.
  uint16_t ored = 0;
  int32_t index = 0;
  for (const uint16_t* it = src.begin(); it != src.end(); ++it) {
    uint16_t ch = *it;
    ored |= ch;
    result->SeqOneByteStringSet(index++, ToAsciiUpper(ch));
  }
  return !(ored & ~0x7F);
}

const uint16_t sharp_s = 0xDF;

template <typename Char>
bool ToUpperOneByte(base::Vector<const Char> src, uint8_t* dest,
                    int* sharp_s_count) {
  // Still pretty-fast path for the input with non-ASCII Latin-1 characters.

  // There are two special cases.
  //  1. U+00B5 and U+00FF are mapped to a character beyond U+00FF.
  //  2. Lower case sharp-S converts to "SS" (two characters)
  *sharp_s_count = 0;
  for (auto it = src.begin(); it != src.end(); ++it) {
    uint8_t ch = AsOneByte(*it);
    if (V8_UNLIKELY(ch == sharp_s)) {
      ++(*sharp_s_count);
      continue;
    }
    if (V8_UNLIKELY(ch == 0xB5 || ch == 0xFF)) {
      // Since this upper-cased character does not fit in an 8-bit string, we
      // need to take the 16-bit path.
      return false;
    }
    *dest++ = ToLatin1Upper(ch);
  }

  return true;
}

template <typename Char>
void ToUpperWithSharpS(base::Vector<const Char> src,
                       DirectHandle<SeqOneByteString> result) {
  int32_t dest_index = 0;
  for (auto it = src.begin(); it != src.end(); ++it) {
    uint8_t ch = AsOneByte(*it);
    if (ch == sharp_s) {
      result->SeqOneByteStringSet(dest_index++, 'S');
      result->SeqOneByteStringSet(dest_index++, 'S');
    } else {
      result->SeqOneByteStringSet(dest_index++, ToLatin1Upper(ch));
    }
  }
}

inline int FindFirstUpperOrNonAscii(Tagged<String> s, int length) {
  for (int index = 0; index < length; ++index) {
    uint16_t ch = s->Get(index);
    if (V8_UNLIKELY(IsAsciiUpper(ch) || ch & ~0x7F)) {
      return index;
    }
  }
  return length;
}

const UChar* GetUCharBufferFromFlat(const String::FlatContent& flat,
                                    std::unique_ptr<base::uc16[]>* dest,
                                    int32_t length) {
  DCHECK(flat.IsFlat());
  if (flat.IsOneByte()) {
    if (!*dest) {
      dest->reset(NewArray<base::uc16>(length));
      CopyChars(dest->get(), flat.ToOneByteVector().begin(), length);
    }
    return reinterpret_cast<const UChar*>(dest->get());
  } else {
    return reinterpret_cast<const UChar*>(flat.ToUC16Vector().begin());
  }
}

template <typename T>
MaybeHandle<T> New(Isolate* isolate, Handle<JSFunction> constructor,
                   Handle<Object> locales, Handle<Object> options,
                   const char* method_name) {
  Handle<Map> map;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, map,
      JSFunction::GetDerivedMap(isolate, constructor, constructor));
  return T::New(isolate, map, locales, options, method_name);
}
}  // namespace

const uint8_t* Intl::ToLatin1LowerTable() { return &kToLower[0]; }

icu::UnicodeString Intl::ToICUUnicodeString(Isolate* isolate,
                                            DirectHandle<String> string,
                                            int offset) {
  DCHECK(string->IsFlat());
  DisallowGarbageCollection no_gc;
  std::unique_ptr<base::uc16[]> sap;
  // Short one-byte strings can be expanded on the stack to avoid allocating a
  // temporary buffer.
  constexpr unsigned int kShortStringSize = 80;
  UChar short_string_buffer[kShortStringSize];
  const UChar* uchar_buffer = nullptr;
  const String::FlatContent& flat = string->GetFlatContent(no_gc);
  // We read the length from the heap, so it may be untrusted (in the sandbox
  // attacker model) and we therefore need to use an unsigned int here when
  // comparing it against the kShortStringSize.
  uint32_t length = string->length();
  DCHECK_LE(offset, length);
  if (flat.IsOneByte() && length <= kShortStringSize) {
    CopyChars(short_string_buffer, flat.ToOneByteVector().begin(), length);
    uchar_buffer = short_string_buffer;
  } else {
    uchar_buffer = GetUCharBufferFromFlat(flat, &sap, length);
  }
  return icu::UnicodeString(uchar_buffer + offset, length - offset);
}

namespace {

icu::StringPiece ToICUStringPiece(Isolate* isolate, DirectHandle<String> string,
                                  int offset = 0) {
  DCHECK(string->IsFlat());
  DisallowGarbageCollection no_gc;

  const String::FlatContent& flat = string->GetFlatContent(no_gc);
  if (!flat.IsOneByte()) return icu::StringPiece();

  int32_t length = string->length();
  const char* char_buffer =
      reinterpret_cast<const char*>(flat.ToOneByteVector().begin());
  if (!String::IsAscii(char_buffer, length)) {
    return icu::StringPiece();
  }

  return icu::StringPiece(char_buffer + offset, length - offset);
}

MaybeHandle<String> LocaleConvertCase(Isolate* isolate, DirectHandle<String> s,
                                      bool is_to_upper, const char* lang) {
  auto case_converter = is_to_upper ? u_strToUpper : u_strToLower;
  uint32_t src_length = s->length();
  uint32_t dest_length = src_length;
  UErrorCode status;
  Handle<SeqTwoByteString> result;
  std::unique_ptr<base::uc16[]> sap;

  if (dest_length == 0) return ReadOnlyRoots(isolate).empty_string_handle();

  // This is not a real loop. It'll be executed only once (no overflow) or
  // twice (overflow).
  for (int i = 0; i < 2; ++i) {
    // Case conversion can increase the string length (e.g. sharp-S => SS) so
    // that we have to handle RangeError exceptions here.
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, result, isolate->factory()->NewRawTwoByteString(dest_length));
    DisallowGarbageCollection no_gc;
    DCHECK(s->IsFlat());
    String::FlatContent flat = s->GetFlatContent(no_gc);
    const UChar* src = GetUCharBufferFromFlat(flat, &sap, src_length);
    status = U_ZERO_ERROR;
    dest_length =
        case_converter(reinterpret_cast<UChar*>(result->GetChars(no_gc)),
                       dest_length, src, src_length, lang, &status);
    if (status != U_BUFFER_OVERFLOW_ERROR) break;
  }

  // In most cases, the output will fill the destination buffer completely
  // leading to an unterminated string (U_STRING_NOT_TERMINATED_WARNING).
  // Only in rare cases, it'll be shorter than the destination buffer and
  // |result| has to be truncated.
  DCHECK(U_SUCCESS(status));
  if (V8_LIKELY(status == U_STRING_NOT_TERMINATED_WARNING)) {
    DCHECK(dest_length == result->length());
    return result;
  }
  DCHECK(dest_length < result->length());
  return SeqString::Truncate(isolate, result, dest_length);
}

}  // namespace

// A stripped-down version of ConvertToLower that can only handle flat one-byte
// strings and does not allocate. Note that {src} could still be, e.g., a
// one-byte sliced string with a two-byte parent string.
// Called from TF builtins.
Tagged<String> Intl::ConvertOneByteToLower(Tagged<String> src,
                                           Tagged<String> dst) {
  DCHECK_EQ(src->length(), dst->length());
  DCHECK(src->IsOneByteRepresentation());
  DCHECK(src->IsFlat());
  DCHECK(IsSeqOneByteString(dst));

  DisallowGarbageCollection no_gc;

  const int length = src->length();
  String::FlatContent src_flat = src->GetFlatContent(no_gc);
  uint8_t* dst_data = Cast<SeqOneByteString>(dst)->GetChars(no_gc);

  if (src_flat.IsOneByte()) {
    const uint8_t* src_data = src_flat.ToOneByteVector().begin();

    bool has_changed_character = false;
    int index_to_first_unprocessed =
        FastAsciiConvert<true>(reinterpret_cast<char*>(dst_data),
                               reinterpret_cast<const char*>(src_data), length,
                               &has_changed_character);

    if (index_to_first_unprocessed == length) {
      return has_changed_character ? dst : src;
    }

    // If not ASCII, we keep the result up to index_to_first_unprocessed and
    // process the rest.
    for (int index = index_to_first_unprocessed; index < length; ++index) {
      dst_data[index] = ToLatin1Lower(src_data[index]);
    }
  } else {
    DCHECK(src_flat.IsTwoByte());
    int index_to_first_unprocessed = FindFirstUpperOrNonAscii(src, length);
    if (index_to_first_unprocessed == length) return src;

    const uint16_t* src_data = src_flat.ToUC16Vector().begin();
    CopyChars(dst_data, src_data, index_to_first_unprocessed);
    for (int index = index_to_first_unprocessed; index < length; ++index) {
      // Truncating cast of two-byte src character to one-byte value. For valid
      // cases (where a one-byte sliced string points to a two-byte parent) this
      // will not lose any information, but we need to truncate anyway to
      // avoid undefined behavior if the parent string is corrupted.
      dst_data[index] = ToLatin1Lower(AsOneByte(src_data[index]));
    }
  }

  return dst;
}

MaybeHandle<String> Intl::ConvertToLower(Isolate* isolate, Handle<String> s) {
  if (!s->IsOneByteRepresentation()) {
    // Use a slower implementation for strings with characters beyond U+00FF.
    return LocaleConvertCase(isolate, s, false, "");
  }

  int length = s->length();

  // We depend here on the invariant that the length of a Latin1
  // string is invariant under ToLowerCase, and the result always
  // fits in the Latin1 range in the *root locale*. It does not hold
  // for ToUpperCase even in the root locale.

  // Scan the string for uppercase and non-ASCII characters for strings
  // shorter than a machine-word without any memory allocation overhead.
  // TODO(jshin): Apply this to a longer input by breaking FastAsciiConvert()
  // to two parts, one for scanning the prefix with no change and the other for
  // handling ASCII-only characters.

  bool is_short = length < static_cast<int>(sizeof(uintptr_t));
  if (is_short) {
    bool is_lower_ascii = FindFirstUpperOrNonAscii(*s, length) == length;
    if (is_lower_ascii) return s;
  }

  DirectHandle<SeqOneByteString> result =
      isolate->factory()->NewRawOneByteString(length).ToHandleChecked();

  return Handle<String>(Intl::ConvertOneByteToLower(*s, *result), isolate);
}

MaybeHandle<String> Intl::ConvertToUpper(Isolate* isolate, Handle<String> s) {
  int32_t length = s->length();
  if (s->IsOneByteRepresentation() && length > 0) {
    Handle<SeqOneByteString> result =
        isolate->factory()->NewRawOneByteString(length).ToHandleChecked();

    DCHECK(s->IsFlat());
    int sharp_s_count;
    bool is_result_single_byte;
    {
      DisallowGarbageCollection no_gc;
      String::FlatContent flat = s->GetFlatContent(no_gc);
      uint8_t* dest = result->GetChars(no_gc);
      if (flat.IsOneByte()) {
        base::Vector<const uint8_t> src = flat.ToOneByteVector();
        bool has_changed_character = false;
        int index_to_first_unprocessed = FastAsciiConvert<false>(
            reinterpret_cast<char*>(result->GetChars(no_gc)),
            reinterpret_cast<const char*>(src.begin()), length,
            &has_changed_character);
        if (index_to_first_unprocessed == length) {
          return has_changed_character ? result : s;
        }
        // If not ASCII, we keep the result up to index_to_first_unprocessed and
        // process the rest.
        is_result_single_byte =
            ToUpperOneByte(src.SubVector(index_to_first_unprocessed, length),
                           dest + index_to_first_unprocessed, &sharp_s_count);
      } else {
        DCHECK(flat.IsTwoByte());
        base::Vector<const uint16_t> src = flat.ToUC16Vector();
        if (ToUpperFastASCII(src, result)) return result;
        is_result_single_byte = ToUpperOneByte(src, dest, &sharp_s_count);
      }
    }

    // Go to the full Unicode path if there are characters whose uppercase
    // is beyond the Latin-1 range (cannot be represented in OneByteString).
    if (V8_UNLIKELY(!is_result_single_byte)) {
      return LocaleConvertCase(isolate, s, true, "");
    }

    if (sharp_s_count == 0) return result;

    // We have sharp_s_count sharp-s characters, but the result is still
    // in the Latin-1 range.
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, result,
        isolate->factory()->NewRawOneByteString(length + sharp_s_count));
    DisallowGarbageCollection no_gc;
    String::FlatContent flat = s->GetFlatContent(no_gc);
    if (flat.IsOneByte()) {
      ToUpperWithSharpS(flat.ToOneByteVector(), result);
    } else {
      ToUpperWithSharpS(flat.ToUC16Vector(), result);
    }

    return result;
  }

  return LocaleConvertCase(isolate, s, true, "");
}

std::string Intl::GetNumberingSystem(const icu::Locale& icu_locale) {
  // Ugly hack. ICU doesn't expose numbering system in any way, so we have
  // to assume that for given locale NumberingSystem constructor produces the
  // same digits as NumberFormat/Calendar would.
  UErrorCode status = U_ZERO_ERROR;
  std::unique_ptr<icu::NumberingSystem> numbering_system(
      icu::NumberingSystem::createInstance(icu_locale, status));
  if (U_SUCCESS(status) && !numbering_system->isAlgorithmic()) {
    return numbering_system->getName();
  }
  return "latn";
}

namespace {

Maybe<icu::Locale> CreateICULocale(const std::string& bcp47_locale) {
  DisallowGarbageCollection no_gc;

  // Convert BCP47 into ICU locale format.
  UErrorCode status = U_ZERO_ERROR;

  icu::Locale icu_locale = icu::Locale::forLanguageTag(bcp47_locale, status);
  if (U_FAILURE(status) || icu_locale.isBogus()) {
    return Nothing<icu::Locale>();
  }

  return Just(icu_locale);
}

}  // anonymous namespace

// static

MaybeHandle<String> Intl::ToString(Isolate* isolate,
                                   const icu::UnicodeString& string) {
  return isolate->factory()->NewStringFromTwoByte(base::Vector<const uint16_t>(
      reinterpret_cast<const uint16_t*>(string.getBuffer()), string.length()));
}

MaybeHandle<String> Intl::ToString(Isolate* isolate,
                                   const icu::UnicodeString& string,
                                   int32_t begin, int32_t end) {
  return Intl::ToString(isolate, string.tempSubStringBetween(begin, end));
}

namespace {

Handle<JSObject> InnerAddElement(Isolate* isolate, Handle<JSArray> array,
                                 int index,
                                 DirectHandle<String> field_type_string,
                                 DirectHandle<String> value) {
  // let element = $array[$index] = {
  //   type: $field_type_string,
  //   value: $value
  // }
  // return element;
  Factory* factory = isolate->factory();
  Handle<JSObject> element = factory->NewJSObject(isolate->object_function());
  JSObject::AddProperty(isolate, element, factory->type_string(),
                        field_type_string, NONE);

  JSObject::AddProperty(isolate, element, factory->value_string(), value, NONE);
  // TODO(victorgomes): Temporarily forcing a fatal error here in case of
  // overflow, until Intl::AddElement can handle exceptions.
  if (JSObject::AddDataElement(array, index, element, NONE).IsNothing()) {
    FATAL("Fatal JavaScript invalid size error when adding element");
    UNREACHABLE();
  }
  return element;
}

}  // namespace

void Intl::AddElement(Isolate* isolate, Handle<JSArray> array, int index,
                      DirectHandle<String> field_type_string,
                      DirectHandle<String> value) {
  // Same as $array[$index] = {type: $field_type_string, value: $value};
  InnerAddElement(isolate, array, index, field_type_string, value);
}

void Intl::AddElement(Isolate* isolate, Handle<JSArray> array, int index,
                      DirectHandle<String> field_type_string,
                      DirectHandle<String> value,
                      Handle<String> additional_property_name,
                      DirectHandle<String> additional_property_value) {
  // Same as $array[$index] = {
  //   type: $field_type_string, value: $value,
  //   $additional_property_name: $additional_property_value
  // }
  Handle<JSObject> element =
      InnerAddElement(isolate, array, index, field_type_string, value);
  JSObject::AddProperty(isolate, element, additional_property_name,
                        additional_property_value, NONE);
}

namespace {

// Build the shortened locale; eg, convert xx_Yyyy_ZZ  to xx_ZZ.
//
// If locale has a script tag then return true and the locale without the
// script else return false and an empty string.
bool RemoveLocaleScriptTag(const std::string& icu_locale,
                           std::string* locale_less_script) {
  icu::Locale new_locale = icu::Locale::createCanonical(icu_locale.c_str());
  const char* icu_script = new_locale.getScript();
  if (icu_script == nullptr || strlen(icu_script) == 0) {
    *locale_less_script = std::string();
    return false;
  }

  const char* icu_language = new_locale.getLanguage();
  const char* icu_country = new_locale.getCountry();
  icu::Locale short_locale = icu::Locale(icu_language, icu_country);
  *locale_less_script = short_locale.getName();
  return true;
}

bool ValidateResource(const icu::Locale locale, const char* path,
                      const char* key) {
  bool result = false;
  UErrorCode status = U_ZERO_ERROR;
  UResourceBundle* bundle = ures_open(path, locale.getName(), &status);
  if (bundle != nullptr && status == U_ZERO_ERROR) {
    if (key == nullptr) {
      result = true;
    } else {
      UResourceBundle* key_bundle =
          ures_getByKey(bundle, key, nullptr, &status);
      result = key_bundle != nullptr && (status == U_ZERO_ERROR);
      ures_close(key_bundle);
    }
  }
  ures_close(bundle);
  if (!result) {
    if ((locale.getCountry()[0] != '\0') && (locale.getScript()[0] != '\0')) {
      // Fallback to try without country.
      std::string without_country(locale.getLanguage());
      without_country = without_country.append("-").append(locale.getScript());
      return ValidateResource(without_country.c_str(), path, key);
    } else if ((locale.getCountry()[0] != '\0') ||
               (locale.getScript()[0] != '\0')) {
      // Fallback to try with only language.
      std::string language(locale.getLanguage());
      return ValidateResource(language.c_str(), path, key);
    }
  }
  return result;
}

}  // namespace

std::set<std::string> Intl::BuildLocaleSet(
    const std::vector<std::string>& icu_available_locales, const char* path,
    const char* validate_key) {
  std::set<std::string> locales;
  for (const std::string& locale : icu_available_locales) {
    if (path != nullptr || validate_key != nullptr) {
      if (!ValidateResource(icu::Locale(locale.c_str()), path, validate_key)) {
        // FIXME(chromium:1215606) Find a beter fix for nb->no fallback
        if (locale != "nb") {
          continue;
        }
        // Try no for nb
        if (!ValidateResource(icu::Locale("no"), path, validate_key)) {
          continue;
        }
      }
    }
    locales.insert(locale);
    std::string shortened_locale;
    if (RemoveLocaleScriptTag(locale, &shortened_locale)) {
      std::replace(shortened_locale.begin(), shortened_locale.end(), '_', '-');
      locales.insert(shortened_locale);
    }
  }
  return locales;
}

Maybe<std::string> Intl::ToLanguageTag(const icu::Locale& locale) {
  UErrorCode status = U_ZERO_ERROR;
  std::string res = locale.toLanguageTag<std::string>(status);
  if (U_FAILURE(status)) {
    return Nothing<std::string>();
  }
  DCHECK(U_SUCCESS(status));
  return Just(res);
}

// See ecma402/#legacy-constructor.
MaybeHandle<Object> Intl::LegacyUnwrapReceiver(Isolate* isolate,
                                               Handle<JSReceiver> receiver,
                                               Handle<JSFunction> constructor,
                                               bool has_initialized_slot) {
  Handle<Object> obj_ordinary_has_instance;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, obj_ordinary_has_instance,
      Object::OrdinaryHasInstance(isolate, constructor, receiver));
  bool ordinary_has_instance =
      Object::BooleanValue(*obj_ordinary_has_instance, isolate);

  // 2. If receiver does not have an [[Initialized...]] internal slot
  //    and ? OrdinaryHasInstance(constructor, receiver) is true, then
  if (!has_initialized_slot && ordinary_has_instance) {
    // 2. a. Let new_receiver be ? Get(receiver, %Intl%.[[FallbackSymbol]]).
    Handle<Object> new_receiver;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, new_receiver,
        JSReceiver::GetProperty(isolate, receiver,
                                isolate->factory()->intl_fallback_symbol()));
    return new_receiver;
  }

  return receiver;
}

namespace {

bool IsTwoLetterLanguage(const std::string& locale) {
  // Two letters, both in range 'a'-'z'...
  return locale.length() == 2 && IsAsciiLower(locale[0]) &&
         IsAsciiLower(locale[1]);
}

bool IsDeprecatedOrLegacyLanguage(const std::string& locale) {
  //  Check if locale is one of the deprecated language tags:
  return locale == "in" || locale == "iw" || locale == "ji" || locale == "jw" ||
         locale == "mo" ||
         //  Check if locale is one of the legacy language tags:
         locale == "sh" || locale == "tl" || locale == "no";
}

bool IsStructurallyValidLanguageTag(const std::string& tag) {
  return JSLocale::StartsWithUnicodeLanguageId(tag);
}

// Canonicalize the locale.
// https://tc39.github.io/ecma402/#sec-canonicalizelanguagetag,
// including type check and structural validity check.
Maybe<std::string> CanonicalizeLanguageTag(Isolate* isolate,
                                           const std::string& locale_in) {
  std::string locale = locale_in;

  if (locale.empty() ||
      !String::IsAscii(locale.data(), static_cast<int>(locale.length()))) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(
            MessageTemplate::kInvalidLanguageTag,
            isolate->factory()->NewStringFromAsciiChecked(locale.c_str())),
        Nothing<std::string>());
  }

  // Optimize for the most common case: a 2-letter language code in the
  // canonical form/lowercase that is not one of the deprecated codes
  // (in, iw, ji, jw). Don't check for ~70 of 3-letter deprecated language
  // codes. Instead, let them be handled by ICU in the slow path. However,
  // fast-track 'fil' (3-letter canonical code).
  if ((IsTwoLetterLanguage(locale) && !IsDeprecatedOrLegacyLanguage(locale)) ||
      locale == "fil") {
    return Just(locale);
  }

  // Because per BCP 47 2.1.1 language tags are case-insensitive, lowercase
  // the input before any more check.
  std::transform(locale.begin(), locale.end(), locale.begin(), ToAsciiLower);

  // // ECMA 402 6.2.3
  // TODO(jshin): uloc_{for,to}TanguageTag can fail even for a structually valid
  // language tag if it's too long (much longer than 100 chars). Even if we
  // allocate a longer buffer, ICU will still fail if it's too long. Either
  // propose to Ecma 402 to put a limit on the locale length or change ICU to
  // handle long locale names better. See
  // https://unicode-org.atlassian.net/browse/ICU-13417
  UErrorCode error = U_ZERO_ERROR;
  // uloc_forLanguageTag checks the structrual validity. If the input BCP47
  // language tag is parsed all the way to the end, it indicates that the input
  // is structurally valid. Due to a couple of bugs, we can't use it
  // without Chromium patches or ICU 62 or earlier.
  icu::Locale icu_locale = icu::Locale::forLanguageTag(locale.c_str(), error);

  if (U_FAILURE(error) || icu_locale.isBogus()) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(
            MessageTemplate::kInvalidLanguageTag,
            isolate->factory()->NewStringFromAsciiChecked(locale.c_str())),
        Nothing<std::string>());
  }

  // Use LocaleBuilder to validate locale.
  icu_locale = icu::LocaleBuilder().setLocale(icu_locale).build(error);
  icu_locale.canonicalize(error);
  if (U_FAILURE(error) || icu_locale.isBogus()) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(
            MessageTemplate::kInvalidLanguageTag,
            isolate->factory()->NewStringFromAsciiChecked(locale.c_str())),
        Nothing<std::string>());
  }
  Maybe<std::string> maybe_to_language_tag = Intl::ToLanguageTag(icu_locale);
  if (maybe_to_language_tag.IsNothing()) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(
            MessageTemplate::kInvalidLanguageTag,
            isolate->factory()->NewStringFromAsciiChecked(locale.c_str())),
        Nothing<std::string>());
  }

  return maybe_to_language_tag;
}

Maybe<std::string> CanonicalizeLanguageTag(Isolate* isolate,
                                           Handle<Object> locale_in) {
  Handle<String> locale_str;
  // This does part of the validity checking spec'ed in CanonicalizeLocaleList:
  // 7c ii. If Type(kValue) is not String or Object, throw a TypeError
  // exception.
  // 7c iii. Let tag be ? ToString(kValue).
  // 7c iv. If IsStructurallyValidLanguageTag(tag) is false, throw a
  // RangeError exception.

  if (IsString(*locale_in)) {
    locale_str = Cast<String>(locale_in);
  } else if (IsJSReceiver(*locale_in)) {
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, locale_str,
                                     Object::ToString(isolate, locale_in),
                                     Nothing<std::string>());
  } else {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NewTypeError(MessageTemplate::kLanguageID),
                                 Nothing<std::string>());
  }
  std::string locale(locale_str->ToCString().get());

  if (!IsStructurallyValidLanguageTag(locale)) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate, NewRangeError(MessageTemplate::kLocaleBadParameters),
        Nothing<std::string>());
  }
  return CanonicalizeLanguageTag(isolate, locale);
}

}  // anonymous namespace

Maybe<std::vector<std::string>> Intl::CanonicalizeLocaleList(
    Isolate* isolate, Handle<Object> locales, bool only_return_one_result) {
  // 1. If locales is undefined, then
  if (IsUndefined(*locales, isolate)) {
    // 1a. Return a new empty List.
    return Just(std::vector<std::string>());
  }
  // 2. Let seen be a new empty List.
  std::vector<std::string> seen;
  // 3. If Type(locales) is String or locales has an [[InitializedLocale]]
  // internal slot,  then
  if (IsJSLocale(*locales)) {
    // Since this value came from JSLocale, which is already went though the
    // CanonializeLanguageTag process once, therefore there are no need to
    // call CanonializeLanguageTag again.
    seen.push_back(JSLocale::ToString(Cast<JSLocale>(locales)));
    return Just(seen);
  }
  if (IsString(*locales)) {
    // 3a. Let O be CreateArrayFromList(« locales »).
    // Instead of creating a one-element array and then iterating over it,
    // we inline the body of the iteration:
    std::string canonicalized_tag;
    if (!CanonicalizeLanguageTag(isolate, locales).To(&canonicalized_tag)) {
      return Nothing<std::vector<std::string>>();
    }
    seen.push_back(canonicalized_tag);
    return Just(seen);
  }
  // 4. Else,
  // 4a. Let O be ? ToObject(locales).
  Handle<JSReceiver> o;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, o,
                                   Object::ToObject(isolate, locales),
                                   Nothing<std::vector<std::string>>());
  // 5. Let len be ? ToLength(? Get(O, "length")).
  Handle<Object> length_obj;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, length_obj,
                                   Object::GetLengthFromArrayLike(isolate, o),
                                   Nothing<std::vector<std::string>>());
  // TODO(jkummerow): Spec violation: strictly speaking, we have to iterate
  // up to 2^53-1 if {length_obj} says so. Since cases above 2^32 probably
  // don't happen in practice (and would be very slow if they do), we'll keep
  // the code simple for now by using a saturating to-uint32 conversion.
  double raw_length = Object::NumberValue(*length_obj);
  uint32_t len =
      raw_length >= kMaxUInt32 ? kMaxUInt32 : static_cast<uint32_t>(raw_length);
  // 6. Let k be 0.
  // 7. Repeat, while k < len
  for (uint32_t k = 0; k < len; k++) {
    // 7a. Let Pk be ToString(k).
    // 7b. Let kPresent be ? HasProperty(O, Pk).
    Lo
```