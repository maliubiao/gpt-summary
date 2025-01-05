Response:
Let's break down the thought process for analyzing the `string_impl.cc` file.

1. **Identify the Core Purpose:** The filename `string_impl.cc` and the `namespace WTF` (Web Template Framework) immediately suggest this file deals with the *implementation* details of strings within the Blink rendering engine. The presence of `StringImpl` as a class name confirms this.

2. **Examine the Header Inclusion:**  The included headers provide valuable clues about the file's responsibilities.
    * `<algorithm>`, `<memory>`: Standard C++ stuff, likely for common operations and memory management.
    * `"base/functional/callback.h"`, `"base/i18n/string_search.h"`, `"base/numerics/safe_conversions.h"`:  Integration with Chromium's base library, indicating more sophisticated string operations and considerations for internationalization and safety.
    * Headers under `third_party/blink/renderer/platform/wtf/`:  These are internal Blink headers related to fundamental types and utilities:
        * `allocator/partitions.h`: Custom memory allocation.
        * `dynamic_annotations.h`, `leak_annotations.h`: Tools for debugging and memory management.
        * `size_assertions.h`: Compile-time checks on object sizes.
        * `static_constructors.h`: Managing the initialization of static objects.
        * `std_lib_extras.h`: Extensions to the standard library.
        * `text/...`: The most important section, pointing to core string-related classes: `AtomicString`, `AtomicStringTable`, `CharacterNames`, `CharacterVisitor`, `StringBuffer`, `StringHash`, `StringToNumber`, `Unicode`, `UnicodeString`.

3. **Scan the Class Definition (`StringImpl`):**  A quick skim reveals important members and methods:
    * `ref_count_`:  Reference counting, crucial for efficient string sharing and memory management.
    * `hash_and_flags_`: Storing hash values and flags (like ASCII properties), suggesting optimizations based on string content.
    * Constructors and destructors (`~StringImpl`).
    * Static methods like `Create`, `CreateStatic`, `empty`, `empty16_bit_`, indicating different ways to create `StringImpl` instances.
    * Methods for common string operations: `Substring`, `LowerASCII`, `UpperASCII`, `FoldCase`, `Trim`, `Replace`, `Find`, `StartsWith`, `EndsWith`, `ToInt`, `ToDouble`, etc.

4. **Categorize Functionality:** Based on the included headers and the methods within `StringImpl`, we can categorize the functionalities:
    * **String Storage and Representation:** How strings are stored in memory (8-bit or 16-bit).
    * **Memory Management:** Reference counting, static string handling, custom allocation.
    * **Basic String Operations:**  Length, access characters, copying.
    * **Case Conversion:** Lowercase, uppercase, case folding.
    * **Trimming and Whitespace Handling:** Removing leading/trailing whitespace, simplifying whitespace.
    * **Searching and Finding:** Finding substrings, characters.
    * **Comparison:** Equality checks (case-sensitive and insensitive).
    * **Prefix and Suffix Checks:** `StartsWith`, `EndsWith`.
    * **Replacement:** Replacing characters or substrings.
    * **Conversion to Numbers:** `ToInt`, `ToDouble`, etc.
    * **Static String Optimization:**  Efficient storage and retrieval of frequently used strings.
    * **Unicode Support:** Handling different character encodings and Unicode operations.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):** Now, consider how these string functionalities relate to the core web technologies:
    * **JavaScript:**  JavaScript heavily relies on strings. Think about:
        * Variable assignment (`let name = "World";`).
        * String manipulation methods (`name.toLowerCase()`, `name.toUpperCase()`, `name.substring()`, `name.replace()`, `name.indexOf()`). The `StringImpl` methods directly underpin these JavaScript string operations.
        * DOM manipulation (e.g., `element.textContent = "New Text";`). The text content is represented by strings.
    * **HTML:**  HTML is structured text. Strings are used for:
        * Tag names (`<div>`, `<p>`). While these might be handled more symbolically in some parts of the engine, their textual representation matters.
        * Attribute values (`<div class="container">`).
        * Text content within elements (`<p>This is text.</p>`).
    * **CSS:**  CSS uses strings for:
        * Selectors (`.container`, `#header`).
        * Property values (`color: blue;`, `font-family: Arial;`).
        * URLs (`background-image: url("image.png");`).

6. **Illustrate with Examples (Hypothetical Inputs and Outputs):** Create simple scenarios to demonstrate the methods:
    * `LowerASCII("HELLO")` -> `"hello"`
    * `StripWhiteSpace("  Hello World  ")` -> `"Hello World"`
    * `Find("abcdefg", "def", 0)` -> `3`

7. **Identify Potential Usage Errors:** Think about common mistakes developers might make when dealing with strings and how the underlying implementation might be sensitive to them:
    * Incorrect indexing (off-by-one errors).
    * Assuming case-sensitivity when it's not desired.
    * Not considering different whitespace characters.
    * Performance issues with excessive string concatenation (although `StringImpl` likely uses optimizations to mitigate this).
    * Encoding issues (though `StringImpl` tries to handle Unicode correctly).

8. **Review and Refine:**  Go through the generated points, ensure they are accurate and clearly explained. Organize the information logically. Add more specific examples if needed. For instance, when discussing static strings, mention the performance benefits. When talking about memory management, highlight the role of reference counting.

This systematic approach, starting from the file's name and gradually delving into the code's structure and functionality, allows for a comprehensive understanding of its role within the larger system and its relevance to web technologies.
这个文件 `blink/renderer/platform/wtf/text/string_impl.cc` 是 Chromium Blink 引擎中负责 **字符串底层实现 (String Implementation)** 的核心文件。它定义了 `StringImpl` 类，这是 Blink 中 `String` 类背后的实际数据结构和操作实现。

以下是 `string_impl.cc` 的主要功能：

**1. 字符串存储和管理:**

* **存储字符串数据:**  `StringImpl` 负责存储实际的字符串字符序列。它支持两种内部表示：
    * **8-bit (LChar):**  用于只包含 ASCII 或 Latin-1 字符的字符串，可以节省内存。
    * **16-bit (UChar):** 用于包含 Unicode 字符的字符串。
* **引用计数:**  `StringImpl` 使用引用计数来管理字符串的生命周期。多个 `String` 对象可以共享同一个 `StringImpl` 实例，只有当最后一个引用被释放时，字符串的内存才会被释放，从而提高效率。
* **静态字符串 (Static Strings):**  为了进一步优化，特别是对于常量字符串，`StringImpl` 支持创建和管理静态字符串。这些字符串在程序运行期间保持不变，可以被高效地共享。`CreateStatic` 函数用于创建这些静态字符串。
* **空字符串:**  提供了全局唯一的空字符串实例 (`empty_`, `empty16_bit_`)，避免重复创建。

**2. 字符串基本操作:**

* **创建和销毁:** 提供了多种 `Create` 方法用于创建 `StringImpl` 实例，可以从不同的数据源 (LChar, UChar 数组等) 创建。`DestroyIfNeeded` 负责在引用计数降为零时释放内存。
* **长度获取:** `length()` 方法返回字符串的字符数。
* **字符访问:**  可以通过下标运算符 `[]` 访问字符串中的单个字符。
* **子串获取:** `Substring` 方法用于提取字符串的一部分。
* **复制:** `CopyTo` 方法将字符串内容复制到提供的缓冲区。

**3. 字符串比较:**

* **相等性比较:** `Equal` 函数用于比较两个 `StringImpl` 对象的内容是否相同。
* **忽略大小写比较:** `DeprecatedEqualIgnoringCase` 和 `EqualIgnoringASCIICase` 函数用于在比较时忽略字符的大小写。

**4. 字符串查找和搜索:**

* **查找字符:** `Find` 方法用于查找字符串中第一次出现指定字符的位置。
* **查找子串:** `Find` 方法也支持查找字符串中第一次出现指定子串的位置。
* **反向查找:** `ReverseFind` 方法从后向前查找字符或子串。
* **判断前缀和后缀:** `StartsWith` 和 `EndsWith` 方法用于检查字符串是否以指定的字符或子串开头或结尾。它们也提供了忽略大小写的版本。

**5. 字符串修改:**

* **大小写转换:** `LowerASCII`, `UpperASCII`, `FoldCase` 方法用于将字符串转换为小写、大写或进行大小写折叠。
* **填充:** `Fill` 方法用指定的字符填充整个字符串。
* **截断:** `Truncate` 方法将字符串截断到指定的长度。
* **去除空白字符:** `StripWhiteSpace` 方法用于去除字符串开头和结尾的空白字符。
* **移除字符:** `RemoveCharacters` 和 `Remove` 方法用于移除字符串中的指定字符或子串。
* **替换字符或子串:** `Replace` 方法用于将字符串中的指定字符或子串替换为新的字符或子串。

**6. 字符串转换:**

* **转换为数字:** `ToInt`, `ToUInt`, `ToDouble`, `ToFloat` 等方法将字符串转换为相应的数字类型。

**7. 字符串属性判断:**

* `ContainsOnlyWhitespaceOrEmpty()`: 检查字符串是否只包含空白字符或为空。

**与 JavaScript, HTML, CSS 的关系：**

`StringImpl` 是 Blink 引擎中字符串的基础，因此与 JavaScript, HTML, CSS 的处理都有密切关系。

**JavaScript:**

* **JavaScript 字符串的底层实现:** 当 JavaScript 代码中创建字符串、进行字符串操作（例如 `toLowerCase()`, `substring()`, `replace()`, `indexOf()` 等）时，Blink 引擎底层会使用 `String` 类，而 `String` 类内部会操作 `StringImpl` 对象。
    * **假设输入:** JavaScript 代码 `const str = "Hello"; const lowerStr = str.toLowerCase();`
    * **逻辑推理:** 当执行 `toLowerCase()` 时，Blink 会获取 `str` 对应的 `StringImpl` 对象，调用其 `LowerASCII` 或 `FoldCase` 方法生成一个新的 `StringImpl` 对象来表示 `"hello"`。
    * **用户或编程常见错误:** 在 JavaScript 中，字符串是不可变的。如果用户错误地认为字符串操作会修改原始字符串，那么在底层实现中，新的 `StringImpl` 对象会被创建，而原始的 `StringImpl` 对象不会被修改。

**HTML:**

* **HTML 内容的表示:** HTML 文档中的文本内容、标签名称、属性值等都以字符串的形式存储和处理。`StringImpl` 用于存储这些 HTML 相关的字符串数据。
    * **假设输入:** HTML 代码 `<div>Example Text</div>`
    * **逻辑推理:** 当 Blink 解析这段 HTML 时，会创建 `StringImpl` 对象来存储 "div"（标签名）和 "Example Text"（文本内容）。
    * **用户或编程常见错误:** 用户在 JavaScript 中尝试修改 HTML 元素的 `textContent` 时，例如 `element.textContent = "New Text";`，Blink 会创建一个新的 `StringImpl` 对象来存储 "New Text"，并更新 DOM 节点的引用。如果用户错误地操作了底层的字符串缓冲区，可能会导致渲染错误或崩溃。

**CSS:**

* **CSS 样式规则的表示:** CSS 样式规则中的选择器、属性名、属性值等都以字符串的形式存在。`StringImpl` 用于存储这些 CSS 相关的字符串数据.
    * **假设输入:** CSS 代码 `.container { color: blue; }`
    * **逻辑推理:** Blink 会创建 `StringImpl` 对象来存储 ".container"（选择器）和 "blue"（颜色值）。
    * **用户或编程常见错误:** 虽然用户通常不会直接操作 CSS 字符串的底层实现，但了解 `StringImpl` 的存在有助于理解浏览器处理 CSS 的方式。例如，在 JavaScript 中获取 CSS 属性值时，返回的是一个 `String` 对象，其底层是由 `StringImpl` 实现的。

**用户或编程常见的使用错误举例:**

* **不正确的索引访问:**  尝试访问超出字符串长度的索引，例如 `string[string.length()]`，会导致越界访问，虽然 `StringImpl` 可能会有边界检查，但这仍然是一个潜在的错误。
    * **假设输入:**  一个长度为 5 的字符串 "abcde"。
    * **错误代码:** `string[5]`
    * **输出:**  可能导致程序崩溃或返回未定义的行为。
* **混淆大小写:** 在比较字符串时，没有考虑到大小写问题，导致比较结果不符合预期。
    * **假设输入:**  两个字符串 "Hello" 和 "hello"。
    * **错误代码:** 使用默认的相等性比较，例如 `string1 == string2`。
    * **输出:** 比较结果为 `false`，因为大小写不同。应该使用 `DeprecatedEqualIgnoringCase` 或 `EqualIgnoringASCIICase` 进行忽略大小写的比较。
* **不正确的空白字符处理:**  没有考虑到不同类型的空白字符（空格、制表符、换行符等），导致字符串处理出现问题。
    * **假设输入:**  字符串 "  Example  \t"。
    * **错误代码:**  仅仅去除空格，而没有考虑到制表符。
    * **输出:**  使用不完善的去除空白字符的方法可能无法完全去除字符串开头和结尾的空白字符。应该使用 `StripWhiteSpace` 方法来处理多种空白字符。

总而言之，`string_impl.cc` 是 Blink 引擎中处理字符串的核心基础设施，它提供了高效、安全、功能丰富的字符串操作，并直接支撑着 JavaScript, HTML, CSS 等 Web 技术中对字符串的处理。理解其功能有助于深入了解浏览器引擎的工作原理。

Prompt: 
```
这是目录为blink/renderer/platform/wtf/text/string_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2001 Dirk Mueller ( mueller@kde.org )
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2013 Apple Inc. All
 * rights reserved.
 * Copyright (C) 2006 Andrew Wellington (proton@wiretapped.net)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/wtf/text/string_impl.h"

#include <algorithm>
#include <memory>

#include "base/functional/callback.h"
#include "base/i18n/string_search.h"
#include "base/numerics/safe_conversions.h"
#include "third_party/blink/renderer/platform/wtf/allocator/partitions.h"
#include "third_party/blink/renderer/platform/wtf/dynamic_annotations.h"
#include "third_party/blink/renderer/platform/wtf/leak_annotations.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"
#include "third_party/blink/renderer/platform/wtf/static_constructors.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string_table.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/character_visitor.h"
#include "third_party/blink/renderer/platform/wtf/text/string_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"
#include "third_party/blink/renderer/platform/wtf/text/string_to_number.h"
#include "third_party/blink/renderer/platform/wtf/text/unicode.h"
#include "third_party/blink/renderer/platform/wtf/text/unicode_string.h"

using std::numeric_limits;

namespace WTF {

namespace {

struct SameSizeAsStringImpl {
#if DCHECK_IS_ON()
  unsigned int ref_count_change_count;
#endif
  int fields[3];
};

ASSERT_SIZE(StringImpl, SameSizeAsStringImpl);

std::u16string ToU16String(const LChar* chars, const wtf_size_t length) {
  std::u16string s;
  s.reserve(length);

  for (wtf_size_t i = 0U; i < length; ++i) {
    s.push_back(chars[i]);
  }

  return s;
}

std::u16string ToU16String(const UChar* chars, const wtf_size_t length) {
  return std::u16string(chars, length);
}

std::u16string ToU16String(const StringView& s) {
  if (s.Is8Bit()) {
    return ToU16String(s.Characters8(), s.length());
  }

  return ToU16String(s.Characters16(), s.length());
}

template <typename DestChar, typename SrcChar>
void CopyAndReplace(base::span<DestChar> dest,
                    base::span<const SrcChar> src,
                    DestChar old_char,
                    DestChar new_char) {
  for (size_t i = 0; i < src.size(); ++i) {
    DestChar ch = src[i];
    if (ch == old_char) {
      ch = new_char;
    }
    dest[i] = ch;
  }
}

}  // namespace

void* StringImpl::operator new(size_t size) {
  DCHECK_EQ(size, sizeof(StringImpl));
  return Partitions::BufferMalloc(size, "WTF::StringImpl");
}

void StringImpl::operator delete(void* ptr) {
  Partitions::BufferFree(ptr);
}

inline StringImpl::~StringImpl() {
  DCHECK(!IsStatic());
}

void StringImpl::DestroyIfNeeded() const {
  if (hash_and_flags_.load(std::memory_order_acquire) & kIsAtomic) {
    // TODO: Remove const_cast
    if (AtomicStringTable::Instance().ReleaseAndRemoveIfNeeded(
            const_cast<StringImpl*>(this))) {
      delete this;
    } else {
      // AtomicStringTable::Add() revived this before we started really
      // killing it.
    }
  } else {
    // This is not necessary but TSAN bots don't like the load in the
    // caller to have relaxed memory order. Adding this check here instead
    // of changing the load memory order to minimize perf impact.
    int ref_count = ref_count_.load(std::memory_order_acquire);
    DCHECK_EQ(ref_count, 1);
    delete this;
  }
}

unsigned StringImpl::ComputeASCIIFlags() const {
  ASCIIStringAttributes ascii_attributes =
      Is8Bit() ? CharacterAttributes(Characters8(), length())
               : CharacterAttributes(Characters16(), length());
  uint32_t new_flags = ASCIIStringAttributesToFlags(ascii_attributes);
  const uint32_t previous_flags =
      hash_and_flags_.fetch_or(new_flags, std::memory_order_relaxed);
  static constexpr uint32_t mask =
      kAsciiPropertyCheckDone | kContainsOnlyAscii | kIsLowerAscii;
  DCHECK((previous_flags & mask) == 0 || (previous_flags & mask) == new_flags);
  return new_flags;
}

#if DCHECK_IS_ON()
std::string StringImpl::AsciiForDebugging() const {
  return String(IsolatedCopy()->Substring(0, 128)).Ascii();
}
#endif

scoped_refptr<StringImpl> StringImpl::CreateUninitialized(
    size_t length,
    base::span<LChar>& data) {
  if (!length) {
    data = {};
    return empty_;
  }
  const wtf_size_t narrowed_length = base::checked_cast<wtf_size_t>(length);

  // Allocate a single buffer large enough to contain the StringImpl
  // struct as well as the data which it contains. This removes one
  // heap allocation from this call.
  StringImpl* string = static_cast<StringImpl*>(Partitions::BufferMalloc(
      AllocationSize<LChar>(narrowed_length), "WTF::StringImpl"));

  // SAFETY: The AllocationSize<LChar>() helper function computes a size that
  // includes `narrowed_length` LChar characters in addition to the size
  // required for the StringImpl.
  data = UNSAFE_BUFFERS(
      base::span(reinterpret_cast<LChar*>(string + 1), narrowed_length));
  return base::AdoptRef(new (string)
                            StringImpl(narrowed_length, kForce8BitConstructor));
}

scoped_refptr<StringImpl> StringImpl::CreateUninitialized(wtf_size_t length,
                                                          LChar*& data) {
  base::span<LChar> data_span;
  auto impl = CreateUninitialized(length, data_span);
  data = data_span.data();
  return impl;
}

scoped_refptr<StringImpl> StringImpl::CreateUninitialized(
    size_t length,
    base::span<UChar>& data) {
  if (!length) {
    data = {};
    return empty_;
  }
  const wtf_size_t narrowed_length = base::checked_cast<wtf_size_t>(length);

  // Allocate a single buffer large enough to contain the StringImpl
  // struct as well as the data which it contains. This removes one
  // heap allocation from this call.
  StringImpl* string = static_cast<StringImpl*>(Partitions::BufferMalloc(
      AllocationSize<UChar>(narrowed_length), "WTF::StringImpl"));

  // SAFETY: The AllocationSize<UChar>() helper function computes a size that
  // includes `narrowed_length` UChar characters in addition to the size
  // required for the StringImpl.
  data = UNSAFE_BUFFERS(
      base::span(reinterpret_cast<UChar*>(string + 1), narrowed_length));
  return base::AdoptRef(new (string) StringImpl(narrowed_length));
}

scoped_refptr<StringImpl> StringImpl::CreateUninitialized(wtf_size_t length,
                                                          UChar*& data) {
  base::span<UChar> data_span;
  auto impl = CreateUninitialized(length, data_span);
  data = data_span.data();
  return impl;
}

static StaticStringsTable& StaticStrings() {
  DEFINE_STATIC_LOCAL(StaticStringsTable, static_strings, ());
  return static_strings;
}

#if DCHECK_IS_ON()
static bool g_allow_creation_of_static_strings = true;
#endif

const StaticStringsTable& StringImpl::AllStaticStrings() {
  return StaticStrings();
}

void StringImpl::FreezeStaticStrings() {
  DCHECK(IsMainThread());

#if DCHECK_IS_ON()
  g_allow_creation_of_static_strings = false;
#endif
}

wtf_size_t StringImpl::highest_static_string_length_ = 0;

DEFINE_GLOBAL(StringImpl, g_global_empty);
DEFINE_GLOBAL(StringImpl, g_global_empty16_bit);
// Callers need the global empty strings to be non-const.
StringImpl* StringImpl::empty_ = const_cast<StringImpl*>(&g_global_empty);
StringImpl* StringImpl::empty16_bit_ =
    const_cast<StringImpl*>(&g_global_empty16_bit);
void StringImpl::InitStatics() {
  new ((void*)empty_) StringImpl(kConstructEmptyString);
  new ((void*)empty16_bit_) StringImpl(kConstructEmptyString16Bit);
  WTF_ANNOTATE_BENIGN_RACE(StringImpl::empty_,
                           "Benign race on the reference counter of a static "
                           "string created by StringImpl::empty");
  WTF_ANNOTATE_BENIGN_RACE(StringImpl::empty16_bit_,
                           "Benign race on the reference counter of a static "
                           "string created by StringImpl::empty16Bit");
}

StringImpl* StringImpl::CreateStatic(const char* string, wtf_size_t length) {
#if DCHECK_IS_ON()
  DCHECK(g_allow_creation_of_static_strings);
#endif
  DCHECK(string);
  DCHECK(length);

  unsigned hash = StringHasher::ComputeHashAndMaskTop8Bits(string, length);

  StaticStringsTable::const_iterator it = StaticStrings().find(hash);
  if (it != StaticStrings().end()) {
    DCHECK(!memcmp(string, it->value + 1, length * sizeof(LChar)));
    return it->value;
  }

  // Allocate a single buffer large enough to contain the StringImpl
  // struct as well as the data which it contains. This removes one
  // heap allocation from this call.
  CHECK_LE(length,
           ((std::numeric_limits<wtf_size_t>::max() - sizeof(StringImpl)) /
            sizeof(LChar)));
  wtf_size_t size = sizeof(StringImpl) + length * sizeof(LChar);

  WTF_INTERNAL_LEAK_SANITIZER_DISABLED_SCOPE;
  StringImpl* impl = static_cast<StringImpl*>(
      Partitions::BufferMalloc(size, "WTF::StringImpl"));

  LChar* data = reinterpret_cast<LChar*>(impl + 1);
  impl = new (impl) StringImpl(length, hash, kStaticString);
  memcpy(data, string, length * sizeof(LChar));
#if DCHECK_IS_ON()
  impl->AssertHashIsCorrect();
#endif

  DCHECK(IsMainThread());
  highest_static_string_length_ =
      std::max(highest_static_string_length_, length);
  StaticStrings().insert(hash, impl);
  WTF_ANNOTATE_BENIGN_RACE(impl,
                           "Benign race on the reference counter of a static "
                           "string created by StringImpl::createStatic");

  return impl;
}

void StringImpl::ReserveStaticStringsCapacityForSize(wtf_size_t size) {
#if DCHECK_IS_ON()
  DCHECK(g_allow_creation_of_static_strings);
#endif
  StaticStrings().ReserveCapacityForSize(size);
}

scoped_refptr<StringImpl> StringImpl::Create(
    base::span<const UChar> utf16_data) {
  if (utf16_data.empty()) {
    return empty_;
  }
  base::span<UChar> string_data;
  scoped_refptr<StringImpl> string =
      CreateUninitialized(utf16_data.size(), string_data);
  string_data.copy_from(utf16_data);
  return string;
}

scoped_refptr<StringImpl> StringImpl::Create(
    base::span<const LChar> latin1_data) {
  if (latin1_data.empty()) {
    return empty_;
  }
  base::span<LChar> string_data;
  scoped_refptr<StringImpl> string =
      CreateUninitialized(latin1_data.size(), string_data);
  string_data.copy_from(latin1_data);
  return string;
}

scoped_refptr<StringImpl> StringImpl::Create(
    base::span<const LChar> characters,
    ASCIIStringAttributes ascii_attributes) {
  scoped_refptr<StringImpl> ret = Create(characters);
  if (!characters.empty()) {
    // If length is 0 then `ret` is empty_ and should not have its
    // attributes calculated or changed.
    uint32_t new_flags = ASCIIStringAttributesToFlags(ascii_attributes);
    ret->hash_and_flags_.fetch_or(new_flags, std::memory_order_relaxed);
  }

  return ret;
}

scoped_refptr<StringImpl> StringImpl::Create8BitIfPossible(
    base::span<const UChar> characters) {
  if (!characters.data() || characters.empty()) {
    return empty_;
  }

  base::span<LChar> data;
  scoped_refptr<StringImpl> string =
      CreateUninitialized(characters.size(), data);

  for (size_t i = 0; i < characters.size(); ++i) {
    const UChar c = characters[i];
    if (c & 0xff00) {
      return Create(characters);
    }
    data[i] = static_cast<LChar>(c);
  }
  return string;
}

bool StringImpl::ContainsOnlyWhitespaceOrEmpty() {
  // FIXME: The definition of whitespace here includes a number of characters
  // that are not whitespace from the point of view of LayoutText; I wonder if
  // that's a problem in practice.
  if (Is8Bit()) {
    for (wtf_size_t i = 0; i < length_; ++i) {
      UChar c = Characters8()[i];
      if (!IsASCIISpace(c))
        return false;
    }

    return true;
  }

  for (wtf_size_t i = 0; i < length_; ++i) {
    UChar c = Characters16()[i];
    if (!IsASCIISpace(c))
      return false;
  }
  return true;
}

scoped_refptr<StringImpl> StringImpl::Substring(wtf_size_t start,
                                                wtf_size_t length) const {
  if (start >= length_)
    return empty_;
  wtf_size_t max_length = length_ - start;
  if (length >= max_length) {
    // RefPtr has trouble dealing with const arguments. It should be updated
    // so this const_cast is not necessary.
    if (!start)
      return const_cast<StringImpl*>(this);
    length = max_length;
  }
  if (Is8Bit())
    return Create(Span8().subspan(start, length));

  return Create(Span16().subspan(start, length));
}

UChar32 StringImpl::CharacterStartingAt(wtf_size_t i) {
  if (Is8Bit())
    return Characters8()[i];
  if (U16_IS_SINGLE(Characters16()[i]))
    return Characters16()[i];
  if (i + 1 < length_ && U16_IS_LEAD(Characters16()[i]) &&
      U16_IS_TRAIL(Characters16()[i + 1]))
    return U16_GET_SUPPLEMENTARY(Characters16()[i], Characters16()[i + 1]);
  return 0;
}

size_t StringImpl::CopyTo(base::span<UChar> buffer, wtf_size_t start) const {
  size_t number_of_characters_to_copy =
      std::min<size_t>(length() - start, buffer.size());
  if (!number_of_characters_to_copy)
    return 0;
  buffer = buffer.first(number_of_characters_to_copy);
  VisitCharacters(StringView(*this, start, number_of_characters_to_copy),
                  [buffer](auto chars) { CopyChars(buffer, chars); });
  return number_of_characters_to_copy;
}

class StringImplAllocator {
 public:
  using ResultStringType = scoped_refptr<StringImpl>;

  template <typename CharType>
  scoped_refptr<StringImpl> Alloc(wtf_size_t length, CharType*& buffer) {
    return StringImpl::CreateUninitialized(length, buffer);
  }

  scoped_refptr<StringImpl> CoerceOriginal(const StringImpl& string) {
    return const_cast<StringImpl*>(&string);
  }
};

scoped_refptr<StringImpl> StringImpl::LowerASCII() {
  return ConvertASCIICase(*this, LowerConverter(), StringImplAllocator());
}

scoped_refptr<StringImpl> StringImpl::UpperASCII() {
  return ConvertASCIICase(*this, UpperConverter(), StringImplAllocator());
}

scoped_refptr<StringImpl> StringImpl::Fill(UChar character) {
  if (!(character & ~0x7F)) {
    base::span<LChar> data;
    scoped_refptr<StringImpl> new_impl = CreateUninitialized(length_, data);
    base::ranges::fill(data, static_cast<LChar>(character));
    return new_impl;
  }
  base::span<UChar> data;
  scoped_refptr<StringImpl> new_impl = CreateUninitialized(length_, data);
  base::ranges::fill(data, character);
  return new_impl;
}

scoped_refptr<StringImpl> StringImpl::FoldCase() {
  CHECK_LE(length_, static_cast<wtf_size_t>(numeric_limits<int32_t>::max()));
  int32_t length = length_;

  if (Is8Bit()) {
    // Do a faster loop for the case where all the characters are ASCII.
    LChar* data;
    scoped_refptr<StringImpl> new_impl = CreateUninitialized(length_, data);
    LChar ored = 0;

    for (int32_t i = 0; i < length; ++i) {
      LChar c = Characters8()[i];
      data[i] = ToASCIILower(c);
      ored |= c;
    }

    if (!(ored & ~0x7F))
      return new_impl;

    // Do a slower implementation for cases that include non-ASCII Latin-1
    // characters.
    for (int32_t i = 0; i < length; ++i)
      data[i] = static_cast<LChar>(unicode::ToLower(Characters8()[i]));

    return new_impl;
  }

  // Do a faster loop for the case where all the characters are ASCII.
  UChar* data;
  scoped_refptr<StringImpl> new_impl = CreateUninitialized(length_, data);
  UChar ored = 0;
  for (int32_t i = 0; i < length; ++i) {
    UChar c = Characters16()[i];
    ored |= c;
    data[i] = ToASCIILower(c);
  }
  if (!(ored & ~0x7F))
    return new_impl;

  // Do a slower implementation for cases that include non-ASCII characters.
  bool error;
  int32_t real_length =
      unicode::FoldCase(data, length, Characters16(), length_, &error);
  if (!error && real_length == length)
    return new_impl;
  new_impl = CreateUninitialized(real_length, data);
  unicode::FoldCase(data, real_length, Characters16(), length_, &error);
  if (error)
    return this;
  return new_impl;
}

scoped_refptr<StringImpl> StringImpl::Truncate(wtf_size_t length) {
  if (length >= length_)
    return this;
  if (Is8Bit())
    return Create(Span8().first(length));
  return Create(Span16().first(length));
}

namespace {

using CharacterRange = std::pair<size_t, size_t>;

template <class UCharPredicate>
inline CharacterRange StrippedMatchedCharactersRange(const StringImpl& impl,
                                                     UCharPredicate predicate) {
  return WTF::VisitCharacters(
      impl, [predicate](auto characters) -> CharacterRange {
        if (characters.empty()) {
          return {0, 0};
        }

        size_t start = 0;
        size_t end = characters.size() - 1;

        // Skip white space from the start.
        while (start <= end && predicate(characters[start])) {
          ++start;
        }

        // String only contains matching characters.
        if (start > end) {
          return {0, 0};
        }

        // Skip white space from the end.
        while (end && predicate(characters[end])) {
          --end;
        }
        return {start, end + 1};
      });
}

}  // namespace

template <class UCharPredicate>
inline scoped_refptr<StringImpl> StringImpl::StripMatchedCharacters(
    UCharPredicate predicate) {
  const auto [start, end] = StrippedMatchedCharactersRange(*this, predicate);
  if (start == end) {
    return empty_;
  }
  if (start == 0 && end == length_) {
    return this;
  }
  if (Is8Bit())
    return Create(Span8().subspan(start, end - start));
  return Create(Span16().subspan(start, end - start));
}

class UCharPredicate final {
  STACK_ALLOCATED();

 public:
  inline UCharPredicate(CharacterMatchFunctionPtr function)
      : function_(function) {}

  inline bool operator()(UChar ch) const { return function_(ch); }

 private:
  const CharacterMatchFunctionPtr function_;
};

class SpaceOrNewlinePredicate final {
  STACK_ALLOCATED();

 public:
  inline bool operator()(UChar ch) const { return IsSpaceOrNewline(ch); }
};

wtf_size_t StringImpl::LengthWithStrippedWhiteSpace() const {
  const auto [start, end] =
      StrippedMatchedCharactersRange(*this, SpaceOrNewlinePredicate());
  return static_cast<wtf_size_t>(end - start);
}

scoped_refptr<StringImpl> StringImpl::StripWhiteSpace() {
  return StripMatchedCharacters(SpaceOrNewlinePredicate());
}

scoped_refptr<StringImpl> StringImpl::StripWhiteSpace(
    IsWhiteSpaceFunctionPtr is_white_space) {
  return StripMatchedCharacters(UCharPredicate(is_white_space));
}

template <typename CharType>
ALWAYS_INLINE scoped_refptr<StringImpl> StringImpl::RemoveCharacters(
    const CharType* characters,
    CharacterMatchFunctionPtr find_match) {
  const CharType* from = characters;
  const CharType* fromend = from + length_;

  // Assume the common case will not remove any characters
  while (from != fromend && !find_match(*from))
    ++from;
  if (from == fromend)
    return this;

  StringBuffer<CharType> data(length_);
  CharType* to = data.Characters();
  wtf_size_t outc = static_cast<wtf_size_t>(from - characters);

  if (outc)
    memcpy(to, characters, outc * sizeof(CharType));

  while (true) {
    while (from != fromend && find_match(*from))
      ++from;
    while (from != fromend && !find_match(*from))
      to[outc++] = *from++;
    if (from == fromend)
      break;
  }

  data.Shrink(outc);

  return data.Release();
}

scoped_refptr<StringImpl> StringImpl::RemoveCharacters(
    CharacterMatchFunctionPtr find_match) {
  if (Is8Bit())
    return RemoveCharacters(Characters8(), find_match);
  return RemoveCharacters(Characters16(), find_match);
}

scoped_refptr<StringImpl> StringImpl::Remove(wtf_size_t start,
                                             wtf_size_t length_to_remove) {
  if (length_to_remove <= 0)
    return this;
  if (start >= length_)
    return this;

  length_to_remove = std::min(length_ - start, length_to_remove);
  wtf_size_t removed_end = start + length_to_remove;

  return VisitCharacters(
      *this, [start, length_to_remove, removed_end](auto chars) {
        using CharType = decltype(chars)::value_type;
        StringBuffer<CharType> buffer(chars.size() - length_to_remove);
        auto [before, after] = buffer.Span().split_at(start);
        CopyChars(before, chars.first(start));
        CopyChars(after, chars.subspan(removed_end));
        return buffer.Release();
      });
}

template <typename CharType, class UCharPredicate>
inline scoped_refptr<StringImpl> StringImpl::SimplifyMatchedCharactersToSpace(
    UCharPredicate predicate,
    StripBehavior strip_behavior) {
  StringBuffer<CharType> data(length_);

  const CharType* from = GetCharacters<CharType>();
  const CharType* fromend = from + length_;
  int outc = 0;
  bool changed_to_space = false;

  CharType* to = data.Characters();

  if (strip_behavior == kStripExtraWhiteSpace) {
    while (true) {
      while (from != fromend && predicate(*from)) {
        if (*from != ' ')
          changed_to_space = true;
        ++from;
      }
      while (from != fromend && !predicate(*from))
        to[outc++] = *from++;
      if (from != fromend)
        to[outc++] = ' ';
      else
        break;
    }

    if (outc > 0 && to[outc - 1] == ' ')
      --outc;
  } else {
    for (; from != fromend; ++from) {
      if (predicate(*from)) {
        if (*from != ' ')
          changed_to_space = true;
        to[outc++] = ' ';
      } else {
        to[outc++] = *from;
      }
    }
  }

  if (static_cast<wtf_size_t>(outc) == length_ && !changed_to_space)
    return this;

  data.Shrink(outc);

  return data.Release();
}

scoped_refptr<StringImpl> StringImpl::SimplifyWhiteSpace(
    StripBehavior strip_behavior) {
  if (Is8Bit())
    return StringImpl::SimplifyMatchedCharactersToSpace<LChar>(
        SpaceOrNewlinePredicate(), strip_behavior);
  return StringImpl::SimplifyMatchedCharactersToSpace<UChar>(
      SpaceOrNewlinePredicate(), strip_behavior);
}

scoped_refptr<StringImpl> StringImpl::SimplifyWhiteSpace(
    IsWhiteSpaceFunctionPtr is_white_space,
    StripBehavior strip_behavior) {
  if (Is8Bit())
    return StringImpl::SimplifyMatchedCharactersToSpace<LChar>(
        UCharPredicate(is_white_space), strip_behavior);
  return StringImpl::SimplifyMatchedCharactersToSpace<UChar>(
      UCharPredicate(is_white_space), strip_behavior);
}

int StringImpl::ToInt(NumberParsingOptions options, bool* ok) const {
  if (Is8Bit())
    return CharactersToInt(Span8(), options, ok);
  return CharactersToInt(Span16(), options, ok);
}

wtf_size_t StringImpl::ToUInt(NumberParsingOptions options, bool* ok) const {
  if (Is8Bit())
    return CharactersToUInt(Span8(), options, ok);
  return CharactersToUInt(Span16(), options, ok);
}

wtf_size_t StringImpl::HexToUIntStrict(bool* ok) {
  constexpr auto kStrict = NumberParsingOptions::Strict();
  if (Is8Bit()) {
    return HexCharactersToUInt(Span8(), kStrict, ok);
  }
  return HexCharactersToUInt(Span16(), kStrict, ok);
}

uint64_t StringImpl::HexToUInt64Strict(bool* ok) {
  constexpr auto kStrict = NumberParsingOptions::Strict();
  if (Is8Bit()) {
    return HexCharactersToUInt64(Span8(), kStrict, ok);
  }
  return HexCharactersToUInt64(Span16(), kStrict, ok);
}

int64_t StringImpl::ToInt64(NumberParsingOptions options, bool* ok) const {
  if (Is8Bit())
    return CharactersToInt64(Span8(), options, ok);
  return CharactersToInt64(Span16(), options, ok);
}

uint64_t StringImpl::ToUInt64(NumberParsingOptions options, bool* ok) const {
  if (Is8Bit())
    return CharactersToUInt64(Span8(), options, ok);
  return CharactersToUInt64(Span16(), options, ok);
}

double StringImpl::ToDouble(bool* ok) {
  if (Is8Bit())
    return CharactersToDouble(Span8(), ok);
  return CharactersToDouble(Span16(), ok);
}

float StringImpl::ToFloat(bool* ok) {
  if (Is8Bit())
    return CharactersToFloat(Span8(), ok);
  return CharactersToFloat(Span16(), ok);
}

// Table is based on ftp://ftp.unicode.org/Public/UNIDATA/CaseFolding.txt
const UChar StringImpl::kLatin1CaseFoldTable[256] = {
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008,
    0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x000e, 0x000f, 0x0010, 0x0011,
    0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017, 0x0018, 0x0019, 0x001a,
    0x001b, 0x001c, 0x001d, 0x001e, 0x001f, 0x0020, 0x0021, 0x0022, 0x0023,
    0x0024, 0x0025, 0x0026, 0x0027, 0x0028, 0x0029, 0x002a, 0x002b, 0x002c,
    0x002d, 0x002e, 0x002f, 0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035,
    0x0036, 0x0037, 0x0038, 0x0039, 0x003a, 0x003b, 0x003c, 0x003d, 0x003e,
    0x003f, 0x0040, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067,
    0x0068, 0x0069, 0x006a, 0x006b, 0x006c, 0x006d, 0x006e, 0x006f, 0x0070,
    0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077, 0x0078, 0x0079,
    0x007a, 0x005b, 0x005c, 0x005d, 0x005e, 0x005f, 0x0060, 0x0061, 0x0062,
    0x0063, 0x0064, 0x0065, 0x0066, 0x0067, 0x0068, 0x0069, 0x006a, 0x006b,
    0x006c, 0x006d, 0x006e, 0x006f, 0x0070, 0x0071, 0x0072, 0x0073, 0x0074,
    0x0075, 0x0076, 0x0077, 0x0078, 0x0079, 0x007a, 0x007b, 0x007c, 0x007d,
    0x007e, 0x007f, 0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086,
    0x0087, 0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x008d, 0x008e, 0x008f,
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097, 0x0098,
    0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f, 0x00a0, 0x00a1,
    0x00a2, 0x00a3, 0x00a4, 0x00a5, 0x00a6, 0x00a7, 0x00a8, 0x00a9, 0x00aa,
    0x00ab, 0x00ac, 0x00ad, 0x00ae, 0x00af, 0x00b0, 0x00b1, 0x00b2, 0x00b3,
    0x00b4, 0x03bc, 0x00b6, 0x00b7, 0x00b8, 0x00b9, 0x00ba, 0x00bb, 0x00bc,
    0x00bd, 0x00be, 0x00bf, 0x00e0, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5,
    0x00e6, 0x00e7, 0x00e8, 0x00e9, 0x00ea, 0x00eb, 0x00ec, 0x00ed, 0x00ee,
    0x00ef, 0x00f0, 0x00f1, 0x00f2, 0x00f3, 0x00f4, 0x00f5, 0x00f6, 0x00d7,
    0x00f8, 0x00f9, 0x00fa, 0x00fb, 0x00fc, 0x00fd, 0x00fe, 0x00df, 0x00e0,
    0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5, 0x00e6, 0x00e7, 0x00e8, 0x00e9,
    0x00ea, 0x00eb, 0x00ec, 0x00ed, 0x00ee, 0x00ef, 0x00f0, 0x00f1, 0x00f2,
    0x00f3, 0x00f4, 0x00f5, 0x00f6, 0x00f7, 0x00f8, 0x00f9, 0x00fa, 0x00fb,
    0x00fc, 0x00fd, 0x00fe, 0x00ff,
};

bool DeprecatedEqualIgnoringCase(const LChar* a,
                                 const LChar* b,
                                 wtf_size_t length) {
  DCHECK_GE(length, 0u);
  if (a == b)
    return true;
  while (length--) {
    if (StringImpl::kLatin1CaseFoldTable[*a++] !=
        StringImpl::kLatin1CaseFoldTable[*b++])
      return false;
  }
  return true;
}

bool DeprecatedEqualIgnoringCase(const UChar* a,
                                 const UChar* b,
                                 wtf_size_t length) {
  DCHECK_GE(length, 0u);
  if (a == b)
    return true;
  return !unicode::Umemcasecmp(a, b, length);
}

bool DeprecatedEqualIgnoringCase(const UChar* a,
                                 const LChar* b,
                                 wtf_size_t length) {
  while (length--) {
    if (unicode::FoldCase(*a++) != StringImpl::kLatin1CaseFoldTable[*b++])
      return false;
  }
  return true;
}

wtf_size_t StringImpl::Find(CharacterMatchFunctionPtr match_function,
                            wtf_size_t start) {
  if (Is8Bit())
    return WTF::Find(Characters8(), length_, match_function, start);
  return WTF::Find(Characters16(), length_, match_function, start);
}

wtf_size_t StringImpl::Find(base::RepeatingCallback<bool(UChar)> match_callback,
                            wtf_size_t index) const {
  if (Is8Bit()) {
    const LChar* characters8 = Characters8();
    while (index < length_) {
      if (match_callback.Run(characters8[index]))
        return index;
      ++index;
    }
    return kNotFound;
  }
  const UChar* characters16 = Characters16();
  while (index < length_) {
    if (match_callback.Run(characters16[index]))
      return index;
    ++index;
  }
  return kNotFound;
}

template <typename SearchCharacterType, typename MatchCharacterType>
ALWAYS_INLINE static wtf_size_t FindInternal(
    base::span<const SearchCharacterType> search,
    base::span<const MatchCharacterType> match,
    wtf_size_t index) {
  // Optimization: keep a running hash of the strings,
  // only call equal() if the hashes match.

  wtf_size_t match_length = base::checked_cast<wtf_size_t>(match.size());
  // delta is the number of additional times to test; delta == 0 means test only
  // once.
  wtf_size_t delta =
      base::checked_cast<wtf_size_t>(search.size() - match.size());

  wtf_size_t search_hash = 0;
  wtf_size_t match_hash = 0;

  for (size_t i = 0; i < match_length; ++i) {
    search_hash += search[i];
    match_hash += match[i];
  }

  wtf_size_t i = 0;
  // keep looping until we match
  while (search_hash != match_hash ||
         search.subspan(i, match_length) != match) {
    if (i == delta)
      return kNotFound;
    search_hash += search[i + match_length];
    search_hash -= search[i];
    ++i;
  }
  return index + i;
}

wtf_size_t StringImpl::Find(const StringView& match_string, wtf_size_t index) {
  if (match_string.IsNull()) [[unlikely]] {
    return kNotFound;
  }

  wtf_size_t match_length = match_string.length();

  // Optimization 1: fast case for strings of length 1.
  if (match_length == 1) {
    if (Is8Bit())
      return WTF::Find(Characters8(), length(), match_string[0], index);
    return WTF::Find(Characters16(), length(), match_string[0], index);
  }

  if (!match_length) [[unlikely]] {
    return std::min(index, length());
  }

  // Check index & matchLength are in range.
  if (index > length())
    return kNotFound;
  wtf_size_t search_length = length() - index;
  if (match_length > search_length)
    return kNotFound;

  if (Is8Bit()) {
    if (match_string.Is8Bit())
      return FindInternal(Span8().subspan(index), match_string.Span8(), index);
    return FindInternal(Span8().subspan(index), match_string.Span16(), index);
  }
  if (match_string.Is8Bit())
    return FindInternal(Span16().subspan(index), match_string.Span8(), index);
  return FindInternal(Span16().subspan(index), match_string.Span16(), index);
}

template <typename SearchCharacterType, typename MatchCharacterType>
ALWAYS_INLINE static wtf_size_t FindIgnoringCaseInternal(
    const SearchCharacterType* search_characters,
    const MatchCharacterType* match_characters,
    wtf_size_t index,
    wtf_size_t search_length,
    wtf_size_t match_length) {
  // delta is the number of additional times to test; delta == 0 means test only
  // once.
  wtf_size_t delta = search_length - match_length;

  wtf_size_t i = 0;
  // keep looping until we match
  while (!DeprecatedEqualIgnoringCase(search_characters + i, match_characters,
                                      match_length)) {
    if (i == delta)
      return kNotFound;
    ++i;
  }
  return index + i;
}

wtf_size_t StringImpl::FindIgnoringCase(const StringView& match_string,
                                        wtf_size_t index) {
  if (match_string.IsNull()) [[unlikely]] {
    return kNotFound;
  }

  wtf_size_t match_length = match_string.length();
  if (!match_length)
    return std::min(index, length());

  // Check index & matchLength are in range.
  if (index > length())
    return kNotFound;
  wtf_size_t search_length = length() - index;
  if (match_length > search_length)
    return kNotFound;

  if (Is8Bit()) {
    if (match_string.Is8Bit())
      return FindIgnoringCaseInternal(Characters8() + index,
                                      match_string.Characters8(), index,
                                      search_length, match_length);
    return FindIgnoringCaseInternal(Characters8() + index,
                                    match_string.Characters16(), index,
                                    search_length, match_length);
  }
  if (match_string.Is8Bit())
    return FindIgnoringCaseInternal(Characters16() + index,
                                    match_string.Characters8(), index,
                                    search_length, match_length);
  return FindIgnoringCaseInternal(Characters16() + index,
                                  match_string.Characters16(), index,
                                  search_length, match_length);
}

template <typename SearchCharacterType, typename MatchCharacterType>
ALWAYS_INLINE static wtf_size_t FindIgnoringASCIICaseInternal(
    const SearchCharacterType* search_characters,
    const MatchCharacterType* match_characters,
    wtf_size_t index,
    wtf_size_t search_length,
    wtf_size_t match_length) {
  // delta is the number of additional times to test; delta == 0 means test only
  // once.
  wtf_size_t delta = search_length - match_length;

  wtf_size_t i = 0;
  // keep looping until we match
  while (!EqualIgnoringASCIICase(search_characters + i, match_characters,
                                 match_length)) {
    if (i == delta)
      return kNotFound;
    ++i;
  }
  return index + i;
}

wtf_size_t StringImpl::FindIgnoringASCIICase(const StringView& match_string,
                                             wtf_size_t index) {
  if (match_string.IsNull()) [[unlikely]] {
    return kNotFound;
  }

  wtf_size_t match_length = match_string.length();
  if (!match_length)
    return std::min(index, length());

  // Check index & matchLength are in range.
  if (index > length())
    return kNotFound;
  wtf_size_t search_length = length() - index;
  if (match_length > search_length)
    return kNotFound;

  if (Is8Bit()) {
    if (match_string.Is8Bit())
      return FindIgnoringASCIICaseInternal(Characters8() + index,
                                           match_string.Characters8(), index,
                                           search_length, match_length);
    return FindIgnoringASCIICaseInternal(Characters8() + index,
                                         match_string.Characters16(), index,
                                         search_length, match_length);
  }
  if (match_string.Is8Bit())
    return FindIgnoringASCIICaseInternal(Characters16() + index,
                                         match_string.Characters8(), index,
                                         search_length, match_length);
  return FindIgnoringASCIICaseInternal(Characters16() + index,
                                       match_string.Characters16(), index,
                                       search_length, match_length);
}

wtf_size_t StringImpl::ReverseFind(UChar c, wtf_size_t index) {
  if (Is8Bit())
    return WTF::ReverseFind(Characters8(), length_, c, index);
  return WTF::ReverseFind(Characters16(), length_, c, index);
}

template <typename SearchCharacterType, typename MatchCharacterType>
ALWAYS_INLINE static wtf_size_t ReverseFindInternal(
    base::span<const SearchCharacterType> search,
    base::span<const MatchCharacterType> match,
    wtf_size_t index) {
  // Optimization: keep a running hash of the strings,
  // only call equal if the hashes match.

  wtf_size_t match_length = base::checked_cast<wtf_size_t>(match.size());
  // delta is the number of additional times to test; delta == 0 means test only
  // once.
  wtf_size_t delta = std::min(
      index, base::checked_cast<wtf_size_t>(search.size() - match_length));

  wtf_size_t search_hash = 0;
  wtf_size_t match_hash = 0;
  for (wtf_size_t i = 0; i < match_length; ++i) {
    search_hash += search[delta + i];
    match_hash += match[i];
  }

  // keep looping until we match
  while (search_hash != match_hash ||
         search.subspan(delta, match_length) != match) {
    if (!delta)
      return kNotFound;
    --delta;
    search_hash -= search[delta + match_length];
    search_hash += search[delta];
  }
  return delta;
}

wtf_size_t StringImpl::ReverseFind(const StringView& match_string,
                                   wtf_size_t index) {
  if (match_string.IsNull()) [[unlikely]] {
    return kNotFound;
  }

  wtf_size_t match_length = match_string.length();
  wtf_size_t our_length = length();
  if (!match_length)
    return std::min(index, our_length);

  // Optimization 1: fast case for strings of length 1.
  if (match_length == 1) {
    if (Is8Bit())
      return WTF::ReverseFind(Characters8(), our_length, match_string[0],
                              index);
    return WTF::ReverseFind(Characters16(), our_length, match_string[0], index);
  }

  // Check index & matchLength are in range.
  if (match_length > our_length)
    return kNotFound;

  if (Is8Bit()) {
    if (match_string.Is8Bit())
      return ReverseFindInternal(Span8(), match_string.Span8(), index);
    return ReverseFindInternal(Span8(), match_string.Span16(), index);
  }
  if (match_string.Is8Bit())
    return ReverseFindInternal(Span16(), match_string.Span8(), index);
  return ReverseFindInternal(Span16(), match_string.Span16(), index);
}

bool StringImpl::StartsWith(UChar character) const {
  return length_ && (*this)[0] == character;
}

bool StringImpl::StartsWith(const StringView& prefix) const {
  if (prefix.length() > length())
    return false;
  if (Is8Bit()) {
    if (prefix.Is8Bit())
      return Equal(Characters8(), prefix.Span8());
    return Equal(Characters8(), prefix.Span16());
  }
  if (prefix.Is8Bit())
    return Equal(Characters16(), prefix.Span8());
  return Equal(Characters16(), prefix.Span16());
}

bool StringImpl::StartsWithIgnoringCase(const StringView& prefix) const {
  if (prefix.length() > length())
    return false;
  if (Is8Bit()) {
    if (prefix.Is8Bit()) {
      return DeprecatedEqualIgnoringCase(Characters8(), prefix.Characters8(),
                                         prefix.length());
    }
    return DeprecatedEqualIgnoringCase(Characters8(), prefix.Characters16(),
                                       prefix.length());
  }
  if (prefix.Is8Bit()) {
    return DeprecatedEqualIgnoringCase(Characters16(), prefix.Characters8(),
                                       prefix.length());
  }
  return DeprecatedEqualIgnoringCase(Characters16(), prefix.Characters16(),
                                     prefix.length());
}

bool StringImpl::StartsWithIgnoringCaseAndAccents(
    const StringView& prefix) const {
  std::u16string s = ToU16String();
  std::u16string p = ::WTF::ToU16String(prefix);
  size_t match_index = 1U;

  if (base::i18n::StringSearchIgnoringCaseAndAccents(
          p, s, &match_index,
          /*match_length=*/nullptr)) {
    return match_index == 0U;
  }

  return false;
}

std::u16string StringImpl::ToU16String() const {
  if (Is8Bit()) {
    return ::WTF::ToU16String(Characters8(), length());
  }

  return ::WTF::ToU16String(Characters16(), length());
}

bool StringImpl::StartsWithIgnoringASCIICase(const StringView& prefix) const {
  if (prefix.length() > length())
    return false;
  if (Is8Bit()) {
    if (prefix.Is8Bit())
      return EqualIgnoringASCIICase(Characters8(), prefix.Characters8(),
                                    prefix.length());
    return EqualIgnoringASCIICase(Characters8(), prefix.Characters16(),
                                  prefix.length());
  }
  if (prefix.Is8Bit())
    return EqualIgnoringASCIICase(Characters16(), prefix.Characters8(),
                                  prefix.length());
  return EqualIgnoringASCIICase(Characters16(), prefix.Characters16(),
                                prefix.length());
}

bool StringImpl::EndsWith(UChar character) const {
  return length_ && (*this)[length_ - 1] == character;
}

bool StringImpl::EndsWith(const StringView& suffix) const {
  if (suffix.length() > length())
    return false;
  wtf_size_t start_offset = length() - suffix.length();
  if (Is8Bit()) {
    if (suffix.Is8Bit())
      return Equal(Characters8() + start_offset, suffix.Span8());
    return Equal(Characters8() + start_offset, suffix.Span16());
  }
  if (suffix.Is8Bit())
    return Equal(Characters16() + start_offset, suffix.Span8());
  return Equal(Characters16() + start_offset, suffix.Span16());
}

bool StringImpl::EndsWithIgnoringCase(const StringView& suffix) const {
  if (suffix.length() > length())
    return false;
  wtf_size_t start_offset = length() - suffix.length();
  if (Is8Bit()) {
    if (suffix.Is8Bit()) {
      return DeprecatedEqualIgnoringCase(Characters8() + start_offset,
                                         suffix.Characters8(), suffix.length());
    }
    return DeprecatedEqualIgnoringCase(Characters8() + start_offset,
                                       suffix.Characters16(), suffix.length());
  }
  if (suffix.Is8Bit()) {
    return DeprecatedEqualIgnoringCase(Characters16() + start_offset,
                                       suffix.Characters8(), suffix.length());
  }
  return DeprecatedEqualIgnoringCase(Characters16() + start_offset,
                                     suffix.Characters16(), suffix.length());
}

bool StringImpl::EndsWithIgnoringASCIICase(const StringView& suffix) const {
  if (suffix.length() > length())
    return false;
  wtf_size_t start_offset = length() - suffix.length();
  if (Is8Bit()) {
    if (suffix.Is8Bit())
      return EqualIgnoringASCIICase(Characters8() + start_offset,
                                    suffix.Characters8(), suffix.length());
    return EqualIgnoringASCIICase(Characters8() + start_offset,
                                  suffix.Characters16(), suffix.length());
  }
  if (suffix.Is8Bit())
    return EqualIgnoringASCIICase(Characters16() + start_offset,
                                  suffix.Characters8(), suffix.length());
  return EqualIgnoringASCIICase(Characters16() + start_offset,
                                suffix.Characters16(), suffix.length());
}

scoped_refptr<StringImpl> StringImpl::Replace(UChar old_c, UChar new_c) {
  if (old_c == new_c)
    return this;

  if (Find(old_c) == kNotFound)
    return this;

  if (Is8Bit()) {
    if (new_c <= 0xff) {
      base::span<LChar> data8;
      scoped_refptr<StringImpl> new_impl = CreateUninitialized(length_, data8);
      CopyAndReplace(data8, Span8(), static_cast<LChar>(old_c),
                     static_cast<LChar>(new_c));
      return new_impl;
    }

    // There is the possibility we need to up convert from 8 to 16 bit,
    // create a 16 bit string for the result.
    base::span<UChar> data16;
    scoped_refptr<StringImpl> new_impl = CreateUninitialized(length_, data16);
    CopyAndReplace(data16, Span8(), old_c, new_c);
    return new_impl;
  }

  base::span<UChar> data16;
  scoped_refptr<StringImpl> new_impl = CreateUninitialized(length_, data16);
  CopyAndReplace(data16, Span16(), old_c, new_c);
  return new_impl;
}

// TODO(esprehn): Passing a null replacement is the same as empty string for
// this method but all others treat null as a no-op. We should choose one
// behavior.
scoped_refptr<StringImpl> StringImpl::Replace(wtf_size_t position,
                                              wtf_size_t length_to_replace,
                                              const StringView& string) {
  position = std::min(position, length());
  length_to_replace = std::min(length_to_replace, length() - position);
  wtf_size_t length_to_insert = string.length();
  if (!length_to_replace && !length_to_insert)
    return this;

  CHECK_LT((length() - length_to_replace),
           (numeric_limits<wtf_size_t>::max() - length_to_insert));

  if (Is8Bit() && (string.IsNull() || string.Is8Bit())) {
    LChar* data;
    scoped_refptr<StringImpl> new_impl = CreateUninitialized(
        length() - length_to_replace + length_to_insert, data);
    memcpy(data, Characters8(), position * sizeof(LChar));
    if (!string.IsNull())
      memcpy(data + position, string.Characters8(),
             length_to_insert * sizeof(LChar));
    memcpy(data + position + length_to_insert,
           Characters8() + position + length_to_replace,
           (length() - position - length_to_replace) * sizeof(LChar));
    return new_impl;
  }
  UChar* data;
  scoped_refptr<StringImpl> new_impl = CreateUninitialized(
      length() - length_to_replace + length_to_insert, data);
  if (Is8Bit())
    for (wtf_size_t i = 0; i < position; ++i)
      data[i] = Characters8()[i];
  else
    memcpy(data, Characters16(), position * sizeof(UChar));
  if (!string.IsNull()) {
    if (string.Is8Bit())
      for (wtf_size_t i = 0; i < length_to_insert; ++i)
        data[i + position] = string.Characters8()[i];
    else
      memcpy(data + position, string.Characters16(),
             length_to_insert * sizeof(UChar));
  }
  if (Is8Bit()) {
    for (wtf_size_t i = 0; i < length() - position - length_to_replace; ++i)
      data[i + position + length_to_insert] =
          Characters8()[i + position + length_to_replace];
  } else {
    memcpy(data + position + length_to_insert,
           Characters16() + position + length_to_replace,
           (length() - position - length_to_replace) * sizeof(UChar));
  }
  return new_impl;
}

scoped_refptr<StringImpl> StringImpl::Replace(UChar pattern,
                                              const StringView& replacement) {
  if (replacement.IsNull())
    return this;
  if (replacement.Is8Bit())
    return Replace(pattern, replacement.Characters8(), replacement.length());
  return Replace(pattern, replacement.Characters16(), replacement.length());
}

scoped_refptr<StringImpl> StringImpl::Replace(UChar pattern,
                                              const LChar* replacement,
                                              wtf_size_t rep_str_length) {
  DCHECK(replacement);

  wtf_size_t src_segment_start = 0;
  wtf_size_t match_count = 0;

  // Count the matches.
  while ((src_segment_start = Find(pattern, src_segment_start)) != kNotFound) {
    ++match_count;
    ++src_segment_start;
  }

  // If we have 0 matches then we don't have to do any more work.
  if (!match_count)
    return this;

  CHECK(!rep_str_length ||
        match_count <= numeric_limits<wtf_size_t>::max() / rep_str_length);

  wtf_size_t replace_size = match_count * rep_str_length;
  wtf_size_t new_size = length_ - match_count;
  CHECK_LT(new_size, (numeric_limits<wtf_size_t>::max() - replace_size));

  new_size += replace_size;

  // Construct the new data.
  wtf_size_t src_segment_end;
  wtf_size_t src_segment_length;
  src_segment_start = 0;
  wtf_size_t dst_offset = 0;

  if (Is8Bit()) {
    LChar* data;
    scoped_refptr<StringImpl> new_impl = CreateUninitialized(new_size, data);

    while ((src_segment_end = Find(pattern, src_segment_start)) != kNotFound) {
      src_segment_length = src_segment_end - src_segment_start;
      memcpy(data + dst_offset, Characters8() + src_segment_start,
             src_segment_length * sizeof(LChar));
      dst_offset += src_segment_length;
      memcpy(data + dst_offset, replacement, rep_str_length * sizeof(LChar));
      dst_offset += rep_str_length;
      src_segment_start = src_segment_end + 1;
    }

    src_segment_length = length_ - src_segment_start;
    memcpy(data + dst_offset, Characters8() + src_segment_start,
           src_segment_length * sizeof(LChar));

    DCHECK_EQ(dst_offset + src_segment_length, new_impl->length());

    return new_impl;
  }

  UChar* data;
  scoped_refptr<StringImpl> new_impl = CreateUninitialized(new_size, data);

  while ((src_segment_end = Find(pattern, src_segment_start)) != kNotFound) {
    src_segment_length = src_segment_end - src_segment_start;
    memcpy(data + dst_offset, Characters16() + src_segment_start,
           src_segment_length * sizeof(UChar));

    dst_offset += src_segment_length;
    for (wtf_size_t i = 0; i < rep_str_length; ++i)
      data[i + dst_offset] = replacement[i];

    dst_offset += rep_str_length;
    src_segment_start = src_segment_end + 1;
  }

  src_segment_length = length_ - src_segment_start;
  memcpy(data + dst_offset, Characters16() + src_segment_start,
         src_segment_length * sizeof(UChar));

  DCHECK_EQ(dst_offset + src_segment_length, new_impl->length());

  return new_impl;
}

scoped_refptr<StringImpl> StringImpl::Replace(UChar pattern,
                                              const UChar* replacement,
                                              wtf_size_t rep_str_length) {
  DCHECK(replacement);

  wtf_size_t src_segment_start = 0;
  wtf_size_t match_count = 0;

  // Count the matches.
  while ((src_segment_start = Find(pattern, src_segment_start)) != kNotFound) {
    ++match_count;
    ++src_segment_start;
  }

  // If we have 0 matches then we don't have to do any more work.
  if (!match_count)
    return this;

  CHECK(!rep_str_length ||
        match_count <= numeric_limits<wtf_size_t>::max() / rep_str_length);

  wtf_size_t replace_size = match_count * rep_str_length;
  wtf_size_t new_size = length_ - match_count;
  CHECK_LT(new_size, (numeric_limits<wtf_size_t>::max() - replace_size));

  new_size += replace_size;

  // Construct the new data.
  wtf_size_t src_segment_end;
  wtf_size_t src_segment_length;
  src_segment_start = 0;
  wtf_size_t dst_offset = 0;

  if (Is8Bit()) {
    UChar* data;
    scoped_refptr<StringImpl> new_impl = CreateUninitialized(new_size, data);

    while ((src_segment_end = Find(pattern, src_segment_start)) != kNotFound) {
      src_segment_length = src_segment_end - src_segment_start;
      for (wtf_size_t i = 0; i < src_segment_length; ++i)
        data[i + dst_offset] = Characters8()[i + src_segment_start];

      dst_offset += src_segment_length;
      memcpy(data + dst_offset, replacement, rep_str_length * sizeof(UChar));

      dst_offset += rep_str_length;
      src_segment_start = src_segment_end + 1;
    }

    src_segment_length = length_ - src_segment_start;
    for (wtf_size_t i = 0; i < src_segment_length; ++i)
      data[i + dst_offset] = Characters8()[i + src_segment_start];

    DCHECK_EQ(dst_offset + src_segment_length, new_impl->length());

    return new_impl;
  }

  UChar* data;
  scoped_refptr<StringImpl> new_impl = CreateUninitialized(new_size, data);

  while ((src_segment_end = Find(pattern, src_segment_start)) != kNotFound) {
    src_segment_length = src_segment_end - src_segment_start;
    memcpy(data + dst_offset, Characters16() + src_segment_start,
           src_segment_length * sizeof(UChar));

    dst_offset += src_segment_length;
    memcpy(data + dst_offset, replacement, rep_str_length * sizeof(UChar));

    dst_offset += rep_str_length;
    src_segment_start = src_segment_end + 1;
  }

  src_segment_length = length_ - src_segment_start;
  memcpy(data + dst_offset, Characters16() + src_segment_start,
         src_segment_length * sizeof(UChar));

  DCHECK_EQ(dst_offset + src_segment_length, new_impl->length());

  return new_impl;
}

scoped_refptr<StringImpl> StringImpl::Replace(const StringView& pattern,
                                              const StringView& replacement) {
  if (pattern.IsNull() || replacement.IsNull())
    return this;

  wtf_size_t pattern_length = pattern.length();
  if (!pattern_length)
    return this;

  wtf_size_t rep_str_length = replacement.length();
  wtf_size_t src_segment_start = 0;
  wtf_size_t match_count = 0;

  // Count the matches.
  while ((src_segment_start = Find(pattern, src_segment_start)) != kNotFound) {
    ++match_count;
    src_segment_start += pattern_length;
  }

  // If we have 0 matches, we don't have to do any more work
  if (!match_count)
    return this;

  wtf_size_t new_size = length_ - match_count * pattern_length;
  CHECK(!rep_str_length ||
        match_count <= numeric_limits<wtf_size_t>::max() / rep_str_length);

  CHECK_LE(new_size,
           (numeric_limits<wtf_size_t>::max() - match_count * rep_str_length));

  new_size += match_count * rep_str_length;

  // Construct the new data
  wtf_size_t src_segment_end;
  wtf_size_t src_segment_length;
  src_segment_start = 0;
  wtf_size_t dst_offset = 0;
  bool src_is_8bit = Is8Bit();
  bool replacement_is_8bit = replacement.Is8Bit();

  // There are 4 cases:
  // 1. This and replacement are both 8 bit.
  // 2. This and replacement are both 16 bit.
  // 3. This is 8 bit and replacement is 16 bit.
  // 4. This is 16 bit and replacement is 8 bit.
  if (src_is_8bit && replacement_is_8bit) {
    // Case 1
    LChar* data;
    scoped_refptr<StringImpl> new_impl = CreateUninitialized(new_size, data);
    while ((src_segment_end = Find(pattern, src_segment_start)) != kNotFound) {
      src_segment_length = src_segment_end - src_segment_start;
      memcpy(data + dst_offset, Characters8() + src_segment_start,
             src_segment_length * sizeof(LChar));
      dst_offset += src_segment_length;
      memcpy(data + dst_offset, replacement.Characters8(),
             rep_str_length * sizeof(LChar));
      dst_offset += rep_str_length;
      src_segment_start = src_segment_end + pattern_length;
    }

    src_segment_length = length_ - src_segment_start;
    memcpy(data + dst_offset, Characters8() + src_segment_start,
           src_segment_length * sizeof(LChar));

    DCHECK_EQ(dst_offset + src_segment_length, new_impl->length());

    return new_impl;
  }

  UChar* data;
  scoped_refptr<StringImpl> new_impl = CreateUninitialized(new_size, data);
  while ((src_segment_end = Find(pattern, src_segment_start)) != kNotFound) {
    src_segment_length = src_segment_end - src_segment_start;
    if (src_is_8bit) {
      // Case 3.
      for (wtf_size_t i = 0; i < src_segment_length; ++i)
        data[i + dst_offset] = Characters8()[i + src_segment_start];
    } else {
      // Case 2 & 4.
      memcpy(data + dst_offset, Characters16() + src_segment_start,
             src_segment_length * sizeof(UChar));
    }
    dst_offset += src_segment_length;
    if (replacement_is_8bit) {
      // Cases 2 & 3.
      for (wtf_size_t i = 0; i < rep_str_length; ++i)
        data[i + dst_offset] = replacement.Characters8()[i];
    } else {
      // Case 4
      memcpy(data + dst_offset, replacement.Characters16(),
             rep_str_length * sizeof(UChar));
    }
    dst_offset += rep_str_length;
    src_segment_start = src_segment_end + pattern_length;
  }

  src_segment_length = length_ - src_segment_start;
  if (src_is_8bit) {
    // Case 3.
    for (wtf_size_t i = 0; i < src_segment_length; ++i)
      data[i + dst_offset] = Characters8()[i + src_segment_start];
  } else {
    // Cases 2 & 4.
    memcpy(data + dst_offset, Characters16() + src_segment_start,
           src_segment_length * sizeof(UChar));
  }

  DCHECK_EQ(dst_offset + src_segment_length, new_impl->length());

  return new_impl;
}

scoped_refptr<StringImpl> StringImpl::UpconvertedString() {
  if (Is8Bit())
    return String::Make16BitFrom8BitSource(Span8()).ReleaseImpl();
  return this;
}

static inline bool StringImplContentEqual(const StringImpl* a,
                                          const StringImpl* b) {
  wtf_size_t a_length = a->length();
  wtf_size_t b_length = b->length();
  if (a_length != b_length)
    return false;

  if (!a_length)
    return true;

  if (a->Is8Bit()) {
    if (b->Is8Bit())
      return Equal(a->Characters8(), b->Span8());

    return Equal(a->Characters8(), b->Span16());
  }

  if (b->Is8Bit())
    return Equal(a->Characters16(), b->Span8());

  return Equal(a->Characters16(), b->Span16());
}

bool Equal(const StringImpl* a, const StringImpl* b) {
  if (a == b)
    return true;
  if (!a || !b)
    return false;
  if (a->IsAtomic() && b->IsAtomic())
    return false;

  return StringImplContentEqual(a, b);
}

template <typename CharType>
inline bool EqualInternal(const StringImpl* a, base::span<const CharType> b) {
  if (!a)
    return !b.data();
  if (!b.data()) {
    return false;
  }

  if (a->length() != b.size()) {
    return false;
  }
  if (a->Is8Bit())
    return Equal(a->Characters8(), b);
  return Equal(a->Characters16(), b);
}

bool Equal(const StringImpl* a, base::span<const LChar> b) {
  return EqualInternal(a, b);
}

bool Equal(const StringImpl* a, base::span<const UChar> b) {
  return EqualInternal(a, b);
}

template <typename StringType>
bool EqualToCString(const StringType* a, const LChar* b) {
  DCHECK(b);
  wtf_size_t length = a->length();

  if (a->Is8Bit()) {
    const LChar* a_ptr = a->Characters8();
    for (wtf_size_t i = 0; i != length; ++i) {
      LChar bc = b[i];
      LChar ac = a_ptr[i];
      if (!bc)
        return false;
      if (ac != bc)
        return false;
    }

    return !b[length];
  }

  const UChar* a_ptr = a->Characters16();
  for (wtf_size_t i = 0; i != length; ++i) {
    LChar bc = b[i];
    if (!bc)
      return false;
    if (a_ptr[i] != bc)
      return false;
  }

  return !b[length];
}

bool EqualToCString(const StringImpl* a, const char* latin1) {
  if (!a) {
    return !latin1;
  }
  return EqualToCString(a, reinterpret_cast<const LChar*>(latin1));
}

bool EqualToCString(const StringView& a, const char* latin1) {
  return EqualToCString(&a, reinterpret_cast<const LChar*>(latin1));
}

bool EqualNonNull(const StringImpl* a, const StringImpl* b) {
  DCHECK(a);
  DCHECK(b);
  if (a == b)
    return true;

  return StringImplContentEqual(a, b);
}

bool EqualIgnoringNullity(StringImpl* a, StringImpl* b) {
  if (!a && b && !b->length())
    return true;
  if (!b && a && !a->length())
    return true;
  return Equal(a, b);
}

template <typename CharacterType1, typename CharacterType2>
int CodeUnitCompareIgnoringASCIICase(wtf_size_t l1,
                                     wtf_size_t l2,
                                     const CharacterType1* c1,
                                     const CharacterType2* c2) {
  const wtf_size_t lmin = l1 < l2 ? l1 : l2;
  wtf_size_t pos = 0;
  while (pos < lmin && ToASCIILower(*c1) == ToASCIILower(*c2)) {
    ++c1;
    ++c2;
    ++pos;
  }

  if (pos < lmin)
    return (ToASCIILower(c1[0]) > ToASCIILower(c2[0])) ? 1 : -1;

  if (l1 == l2)
    return 0;

  return (l1 > l2) ? 1 : -1;
}

template <typename CharacterType>
int CodeUnitCompareIgnoringASCIICase(const StringImpl* string1,
                                     const CharacterType* string2,
                                     wtf_size_t length2) {
  if (!string1)
    return length2 > 0 ? -1 : 0;

  wtf_size_t length1 = string1->length();
  if (!string2)
    return length1 > 0 ? 1 : 0;

  if (string1->Is8Bit()) {
    return CodeUnitCompareIgnoringASCIICase(length1, length2,
                                            string1->Characters8(), string2);
  }
  return CodeUnitCompareIgnoringASCIICase(length1, length2,
                                          string1->Characters16(), string2);
}

int CodeUnitCompareIgnoringASCIICase(const StringImpl* string1,
                                     const LChar* string2) {
  return CodeUnitCompareIgnoringASCIICase(
      string1, string2,
      string2 ? strlen(reinterpret_cast<const char*>(string2)) : 0);
}

int CodeUnitCompareIgnoringASCIICase(const StringImpl* string1,
                                     const StringImpl* string2) {
  if (!string2)
    return string1 && string1->length() > 0 ? 1 : 0;
  return VisitCharacters(*string2, [string1](auto chars) {
    return CodeUnitCompareIgnoringASCIICase(string1, chars.data(),
                                            chars.size());
  });
}

}  // namespace WTF

"""

```