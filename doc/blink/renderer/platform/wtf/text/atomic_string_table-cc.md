Response:
Let's break down the thought process for analyzing this C++ code and generating the explanation.

1. **Understand the Goal:** The request asks for the functionality of the `atomic_string_table.cc` file, its relation to web technologies, examples of usage, potential errors, and logical inference. This means a multi-faceted analysis is needed.

2. **Initial Code Scan (Keywords and Structure):**  Start by quickly scanning the code for important keywords and structural elements. Look for:
    * Class names: `AtomicStringTable`, `UCharBuffer`, `LCharBuffer`
    * Methods: `Add`, `WeakFind`, `Instance`, `ReleaseAndRemoveIfNeeded`, `ComputeHashAndMaskTop8Bits`
    * Data structures: `HashSet`
    * Namespaces: `WTF`
    * Comments: Pay attention to copyright notices and `TODO` comments.
    * Includes: Identify dependencies like `string_hash.h`, `utf8.h`.
    * Preprocessor directives: `#ifdef`, `#pragma` (note the `allow_unsafe_buffers`).

3. **Identify the Core Functionality:** Based on the class name `AtomicStringTable` and key methods like `Add`, the primary function appears to be managing a collection of strings, likely for optimization purposes. The "atomic" part suggests immutability and sharing.

4. **Analyze Key Classes and Methods:**
    * **`AtomicStringTable`:**  The central class. Its `Add` methods are crucial for understanding how strings are added and managed. The `WeakFind` methods suggest lookups. `ReleaseAndRemoveIfNeeded` handles removal. The `Instance()` method indicates it's a singleton.
    * **`UCharBuffer` and `LCharBuffer`:** These seem to be temporary helper classes for creating `StringImpl` objects, handling different character encodings (UTF-16 and Latin-1). The `ComputeHashAndMaskTop8Bits` function is clearly involved in optimizing lookups.
    * **Translators (`UCharBufferTranslator`, `LCharBufferTranslator`, `StringViewLookupTranslator`, `LowercaseLookupTranslator`):**  These are used with the `HashSet` and abstract the process of hashing, comparing, and storing strings, likely to avoid redundant code. The lowercase translator is especially interesting.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):** This is a crucial part of the request. Think about where strings are heavily used in web rendering:
    * **HTML:** Tag names (`div`, `p`), attribute names (`class`, `id`), attribute values.
    * **CSS:** Property names (`color`, `font-size`), selector names (`.class`, `#id`).
    * **JavaScript:** String literals, variable names (though less directly related to this table), property names of objects.

    Hypothesize that this `AtomicStringTable` is used to store these frequently used strings efficiently.

6. **Logical Inference (Hypothetical Inputs and Outputs):**  Consider how the `Add` methods would work.
    * **Input:** A string literal (e.g., `"div"`).
    * **Output:** A pointer to a `StringImpl` object in the table. If the string is already present, the same object is returned; otherwise, a new one is created and added.

    Think about the lowercase lookup:
    * **Input:** An atomic string like `"BackgroundColor"`.
    * **Process:** The `LowercaseLookupTranslator` calculates the hash of `"backgroundcolor"`.
    * **Output:** If `"backgroundcolor"` exists in the table, a pointer to its `StringImpl` is returned.

7. **Identify Potential User/Programming Errors:**
    * **Incorrect encoding:**  Passing the wrong `AtomicStringUCharEncoding` might lead to incorrect string creation or comparisons.
    * **Manual memory management (less likely here):** While the table manages string lifetime, improper handling of related data could cause issues.
    * **Performance implications:** While the table is an optimization, overuse or inefficient use might have performance consequences (though this is less of a *direct* error).
    * **Thread safety issues (addressed by the lock):**  The code uses a lock, highlighting potential concurrency issues if the table wasn't thread-safe.

8. **Structure the Explanation:** Organize the findings logically:
    * Start with a high-level summary of the file's purpose.
    * Detail the key functionalities (adding, finding, removing).
    * Explain the relationship to web technologies with concrete examples.
    * Provide hypothetical input/output scenarios for key methods.
    * Discuss common usage errors.
    * Briefly touch on internal mechanisms (hashing, lookup).

9. **Refine and Elaborate:** Review the generated explanation for clarity and completeness. Add more detail where necessary. For example, explicitly mention the benefits of atomicity (memory savings, faster comparisons).

10. **Consider the Audience:**  The explanation should be understandable to someone familiar with software development concepts but perhaps not intimately with the Blink rendering engine's internals. Avoid overly technical jargon when possible, or explain it clearly.

By following these steps, we can systematically analyze the C++ code and generate a comprehensive and informative explanation that addresses all aspects of the original request. The process involves code reading, understanding data structures and algorithms, connecting code to higher-level concepts, and thinking about potential usage patterns and errors.
这个文件 `atomic_string_table.cc` 定义了 `AtomicStringTable` 类，它在 Chromium 的 Blink 渲染引擎中扮演着非常重要的角色，主要功能是 **高效地存储和管理唯一的、不可变的字符串（称为 "atomic strings"）**。

以下是 `AtomicStringTable` 的主要功能和相关说明：

**主要功能：**

1. **字符串的唯一性 (Uniqueness/Interning):**
   - `AtomicStringTable` 维护了一个所有已添加的原子字符串的集合。
   - 当尝试添加一个新的字符串时，它会首先检查该字符串是否已经存在于表中。
   - 如果存在，则返回对现有字符串的引用，而不是创建一个新的副本。
   - 这被称为字符串驻留 (string interning)。

2. **高效查找 (Efficient Lookup):**
   - 使用 `HashSet` 数据结构来存储字符串，这提供了接近常数时间的查找效率（平均情况下）。
   - 使用哈希值来快速定位可能的匹配项。
   - 提供了多种查找方法，可以根据不同的输入类型（`UChar*`, `LChar*`, `StringView`, `StringImpl*`）和需求（例如，忽略大小写查找）进行查找。

3. **原子性 (Atomicity/Immutability):**
   - 一旦一个字符串被添加到 `AtomicStringTable` 中，它就成为“原子”的，意味着它的内容不会被修改。
   - 这使得可以安全地共享这些字符串的引用，而无需担心数据竞争或意外更改。

4. **内存优化 (Memory Optimization):**
   - 通过确保相同内容的字符串只存储一份，`AtomicStringTable` 显著减少了内存占用，尤其是在处理大量重复字符串的情况下。

5. **快速比较 (Fast Comparison):**
   - 因为相同的字符串在表中总是指向相同的内存地址，所以比较两个原子字符串是否相等只需要比较它们的指针，而不是逐字符比较，这非常快速。

**与 JavaScript, HTML, CSS 的关系 (以及举例说明):**

`AtomicStringTable` 在 Blink 渲染引擎的许多核心功能中都有应用，与 JavaScript, HTML, 和 CSS 的处理密切相关。以下是一些例子：

* **HTML 标签和属性名:**
    - 当浏览器解析 HTML 文档时，像 `<div>`, `<p>`, `<span>`, `class`, `id`, `style` 这样的标签名和属性名会被存储为原子字符串。
    - **举例:** 当解析到 `<div class="container">` 时，字符串 "div" 和 "class" 会被添加到 `AtomicStringTable` (如果尚未存在)。后续遇到相同的标签或属性名时，会直接复用已有的原子字符串。
    - **逻辑推理:**
        - **假设输入:** HTML 字符串片段 `<div id="header">` 和 `<div class="content">`
        - **输出:**  `AtomicStringTable` 中会包含唯一的 "div"、"id" 和 "class" 的 `StringImpl` 对象。尽管 "div" 出现了两次，但只会存储一份。

* **CSS 属性名和选择器:**
    - CSS 属性名（如 `color`, `font-size`, `margin`）和选择器（如 `.container`, `#header`, `p`) 也经常存储为原子字符串。
    - **举例:**  在 CSS 规则 `.container { color: blue; }` 中， ".container" 和 "color" 可能会被存储为原子字符串。
    - **逻辑推理:**
        - **假设输入:** CSS 字符串片段 `.item { color: red; }` 和 `#title { color: blue; }`
        - **输出:** `AtomicStringTable` 中会包含唯一的 ".item"、"color"、"red"（如果它也以某种方式被原子化）、"#title" 和 "blue" 的 `StringImpl` 对象。

* **JavaScript 对象属性名:**
    - JavaScript 对象的属性名（键）在内部也可能使用原子字符串进行优化。
    - **举例:**  当 JavaScript 代码创建对象 `let obj = { name: "John", age: 30 };` 时，属性名 "name" 和 "age" 可能被存储为原子字符串。
    - **逻辑推理:**
        - **假设输入:** JavaScript 代码片段 `let person1 = { name: "Alice" }; let person2 = { name: "Bob" };`
        - **输出:** `AtomicStringTable` 中会包含唯一的 "name" 的 `StringImpl` 对象。

* **事件类型:**
    - 诸如 "click", "mouseover", "keydown" 等事件类型也可能被原子化。

**用户或编程常见的使用错误 (虽然用户通常不直接操作 `AtomicStringTable`):**

由于 `AtomicStringTable` 是 Blink 引擎内部使用的机制，普通用户或 Web 开发者不会直接操作它。然而，理解其原理可以帮助理解 Blink 的性能优化策略。

* **误解字符串的生命周期:** 程序员在使用 Blink 内部的 API 时，可能会错误地管理与原子字符串相关的内存，尽管 `AtomicStringTable` 本身负责管理其内部字符串的生命周期。
* **不必要的字符串复制:**  了解原子字符串的存在可以鼓励开发者避免不必要的字符串复制，因为相同的字符串可以安全地共享。虽然这不是直接的 `AtomicStringTable` 的错误，但理解它可以带来更好的编程实践。
* **性能分析误判:** 在进行性能分析时，如果没有意识到原子字符串的存在，可能会对字符串比较或查找的性能产生错误的理解。实际上，原子字符串的比较非常快。

**代码中的逻辑推理 (示例):**

让我们看一个代码片段中的逻辑推理示例：

```c++
scoped_refptr<StringImpl> AtomicStringTable::Add(
    const UChar* s,
    unsigned length,
    AtomicStringUCharEncoding encoding) {
  if (!s)
    return nullptr;

  if (!length)
    return StringImpl::empty_;

  UCharBuffer buffer(s, length, encoding);
  return AddToStringTable<UCharBuffer, UCharBufferTranslator>(buffer);
}
```

* **假设输入:**
    - `s`: 指向 Unicode 字符串 "hello" 的 `UChar` 数组的指针。
    - `length`: 5
    - `encoding`: `AtomicStringUCharEncoding::kUnknown` (假设，需要根据字符串内容推断)

* **逻辑推理:**
    1. 代码首先检查 `s` 是否为空指针，如果是则返回 `nullptr`。
    2. 然后检查 `length` 是否为 0，如果是则返回表示空字符串的 `StringImpl::empty_`。
    3. 创建一个 `UCharBuffer` 对象，包含字符串数据、长度和编码信息。
    4. 调用 `AddToStringTable`，这是一个模板方法，它会使用 `UCharBufferTranslator` 来计算哈希值、比较字符串，并将字符串添加到 `AtomicStringTable` 的内部 `HashSet` 中。
    5. `UCharBufferTranslator::Equal` 会比较传入的字符串与 `HashSet` 中已存在的 `StringImpl` 对象的内容是否相等。
    6. 如果字符串已存在，则返回对现有 `StringImpl` 的引用。
    7. 如果字符串不存在，则 `UCharBufferTranslator::Store` 会创建一个新的 `StringImpl` 对象，将其添加到 `HashSet` 中，并返回新对象的引用。

* **输出:**
    - 如果 "hello" 已经存在于 `AtomicStringTable` 中，则返回指向现有 "hello" 的 `StringImpl` 对象的 `scoped_refptr`。
    - 如果 "hello" 是第一次添加，则创建一个新的 `StringImpl` 对象，存储在 `AtomicStringTable` 中，并返回指向该新对象的 `scoped_refptr`。

**总结:**

`atomic_string_table.cc` 中定义的 `AtomicStringTable` 是 Blink 渲染引擎中一个核心的优化组件，它通过字符串驻留来减少内存使用并加速字符串比较，这对于高效地处理 HTML、CSS 和 JavaScript 中大量的字符串数据至关重要。虽然开发者通常不直接与之交互，但理解其工作原理有助于更好地理解 Blink 的内部机制和性能优化策略。

### 提示词
```
这是目录为blink/renderer/platform/wtf/text/atomic_string_table.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/wtf/text/atomic_string_table.h"

#include "base/containers/heap_array.h"
#include "base/notreached.h"
#include "third_party/blink/renderer/platform/wtf/text/character_visitor.h"
#include "third_party/blink/renderer/platform/wtf/text/convert_to_8bit_hash_reader.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"
#include "third_party/blink/renderer/platform/wtf/text/utf8.h"

namespace WTF {

namespace {

ALWAYS_INLINE static bool IsOnly8Bit(const UChar* chars, unsigned len) {
  for (unsigned i = 0; i < len; ++i) {
    if ((uint16_t)chars[i] > 255) {
      return false;
    }
  }
  return true;
}

class UCharBuffer {
 public:
  ALWAYS_INLINE static unsigned ComputeHashAndMaskTop8Bits(
      const UChar* chars,
      unsigned len,
      AtomicStringUCharEncoding encoding) {
    if (encoding == AtomicStringUCharEncoding::kIs8Bit ||
        (encoding == AtomicStringUCharEncoding::kUnknown &&
         IsOnly8Bit(chars, len))) {
      // This is a very common case from HTML parsing, so we take
      // the size penalty from inlining.
      return StringHasher::ComputeHashAndMaskTop8BitsInline<
          ConvertTo8BitHashReader>((const char*)chars, len);
    } else {
      return StringHasher::ComputeHashAndMaskTop8Bits((const char*)chars,
                                                      len * 2);
    }
  }

  ALWAYS_INLINE UCharBuffer(const UChar* chars,
                            unsigned len,
                            AtomicStringUCharEncoding encoding)
      : characters_(chars),
        length_(len),
        hash_(ComputeHashAndMaskTop8Bits(chars, len, encoding)),
        encoding_(encoding) {}

  base::span<const UChar> characters() const { return {characters_, length_}; }
  unsigned length() const { return length_; }
  unsigned hash() const { return hash_; }
  AtomicStringUCharEncoding encoding() const { return encoding_; }

  scoped_refptr<StringImpl> CreateStringImpl() const {
    switch (encoding_) {
      case AtomicStringUCharEncoding::kUnknown:
        return StringImpl::Create8BitIfPossible({characters_, length_});
      case AtomicStringUCharEncoding::kIs8Bit:
        return String::Make8BitFrom16BitSource({characters_, length_})
            .ReleaseImpl();
      case AtomicStringUCharEncoding::kIs16Bit:
        return StringImpl::Create({characters_, length_});
    }
  }

 private:
  const UChar* characters_;
  const unsigned length_;
  const unsigned hash_;
  const AtomicStringUCharEncoding encoding_;
};

struct UCharBufferTranslator {
  static unsigned GetHash(const UCharBuffer& buf) { return buf.hash(); }

  static bool Equal(StringImpl* const& str, const UCharBuffer& buf) {
    return WTF::Equal(str, buf.characters());
  }

  static void Store(StringImpl*& location,
                    const UCharBuffer& buf,
                    unsigned hash) {
    location = buf.CreateStringImpl().release();
    location->SetHash(hash);
    location->SetIsAtomic();
  }
};

struct StringViewLookupTranslator {
  static unsigned GetHash(const StringView& buf) {
    StringImpl* shared_impl = buf.SharedImpl();
    if (shared_impl) [[likely]] {
      return shared_impl->GetHash();
    }

    if (buf.Is8Bit()) {
      return StringHasher::ComputeHashAndMaskTop8Bits(
          (const char*)buf.Characters8(), buf.length());
    } else {
      return StringHasher::ComputeHashAndMaskTop8Bits(
          (const char*)buf.Characters16(), buf.length());
    }
  }

  static bool Equal(StringImpl* const& str, const StringView& buf) {
    return *str == buf;
  }
};

// Allows lookups of the ASCII-lowercase version of a string without actually
// allocating memory to store it. Instead, the translator computes the results
// of hash and equality computations as if we had done so. Strings reaching
// these methods are expected to not be lowercase.

// NOTE: Interestingly, the SIMD paths here improve on code size, not just
// on performance.
template <typename CharType>
struct ASCIILowerHashReader {
  static constexpr unsigned kCompressionFactor = 1;
  static constexpr unsigned kExpansionFactor = 1;

  ALWAYS_INLINE static uint64_t Lowercase(CharType ch) {
    return ToASCIILower(ch);
  }

  ALWAYS_INLINE static uint64_t Read64(const uint8_t* ptr) {
    const CharType* p = reinterpret_cast<const CharType*>(ptr);
#if defined(__SSE2__) || defined(__ARM_NEON__)
    CharType b __attribute__((vector_size(8)));
    memcpy(&b, p, sizeof(b));
    b |= (b >= 'A' & b <= 'Z') & 0x20;
    uint64_t ret;
    memcpy(&ret, &b, sizeof(b));
    return ret;
#else
    if constexpr (sizeof(CharType) == 2) {
      return Lowercase(p[0]) | (Lowercase(p[1]) << 16) |
             (Lowercase(p[2]) << 32) | (Lowercase(p[3]) << 48);
    } else {
      return Lowercase(p[0]) | (Lowercase(p[1]) << 8) |
             (Lowercase(p[2]) << 16) | (Lowercase(p[3]) << 24) |
             (Lowercase(p[4]) << 32) | (Lowercase(p[5]) << 40) |
             (Lowercase(p[6]) << 48) | (Lowercase(p[7]) << 56);
    }
#endif
  }
  ALWAYS_INLINE static uint64_t Read32(const uint8_t* ptr) {
    const CharType* p = reinterpret_cast<const CharType*>(ptr);
#if defined(__SSE2__) || defined(__ARM_NEON__)
    CharType b __attribute__((vector_size(4)));
    memcpy(&b, p, sizeof(b));
    b |= (b >= 'A' & b <= 'Z') & 0x20;
    uint32_t ret;
    memcpy(&ret, &b, sizeof(b));
    return ret;
#else
    if constexpr (sizeof(CharType) == 2) {
      return Lowercase(p[0]) | (Lowercase(p[1]) << 16);
    } else {
      return Lowercase(p[0]) | (Lowercase(p[1]) << 8) |
             (Lowercase(p[2]) << 16) | (Lowercase(p[3]) << 24);
    }
#endif
  }

  ALWAYS_INLINE static uint64_t ReadSmall(const uint8_t* p, size_t k) {
    if constexpr (sizeof(CharType) == 2) {
      // This is fine, but the reasoning is a bit subtle. If we get here,
      // we have to be a UTF-16 string, and since ReadSmall can only be called
      // with 1, 2 or 3, it means we must be a UTF-16 string with a single
      // code point (i.e., two bytes). Furthermore, we know that this code point
      // must be above 0xFF, or the HashTranslatorLowercaseBuffer constructor
      // would not have called us. Thus, ToASCIILower() on this code point would
      // do nothing, and this, we should just hash it exactly as PlainHashReader
      // would have done.
      DCHECK_EQ(k, 2u);
      k = 2;
      return (uint64_t{p[0]} << 56) | (uint64_t{p[k >> 1]} << 32) |
             uint64_t{p[k - 1]};
    } else {
      return (Lowercase(p[0]) << 56) | (Lowercase(p[k >> 1]) << 32) |
             Lowercase(p[k - 1]);
    }
  }
};

// Combines ASCIILowerHashReader and ConvertTo8BitHashReader into one.
// This is an obscure case that we only need for completeness,
// so it is fine that it's not all that optimized.
struct ASCIIConvertTo8AndLowerHashReader {
  static constexpr unsigned kCompressionFactor = 2;
  static constexpr unsigned kExpansionFactor = 1;

  static uint64_t Lowercase(uint16_t ch) { return ToASCIILower(ch); }

  static uint64_t Read64(const uint8_t* ptr) {
    const uint16_t* p = reinterpret_cast<const uint16_t*>(ptr);
    return Lowercase(p[0]) | (Lowercase(p[1]) << 8) | (Lowercase(p[2]) << 16) |
           (Lowercase(p[3]) << 24) | (Lowercase(p[4]) << 32) |
           (Lowercase(p[5]) << 40) | (Lowercase(p[6]) << 48) |
           (Lowercase(p[7]) << 56);
  }
  static uint64_t Read32(const uint8_t* ptr) {
    const uint16_t* p = reinterpret_cast<const uint16_t*>(ptr);
    return Lowercase(p[0]) | (Lowercase(p[1]) << 8) | (Lowercase(p[2]) << 16) |
           (Lowercase(p[3]) << 24);
  }
  static uint64_t ReadSmall(const uint8_t* ptr, size_t k) {
    const uint16_t* p = reinterpret_cast<const uint16_t*>(ptr);
    return (Lowercase(p[0]) << 56) | (Lowercase(p[k >> 1]) << 32) |
           Lowercase(p[k - 1]);
  }
};

class HashTranslatorLowercaseBuffer {
 public:
  explicit HashTranslatorLowercaseBuffer(const StringImpl* impl) : impl_(impl) {
    // We expect already lowercase strings to take another path in
    // Element::WeakLowercaseIfNecessary.
    DCHECK(!impl_->IsLowerASCII());
    if (impl_->Is8Bit()) {
      hash_ =
          StringHasher::ComputeHashAndMaskTop8Bits<ASCIILowerHashReader<LChar>>(
              (const char*)impl_->Characters8(), impl_->length());
    } else {
      if (IsOnly8Bit(impl_->Characters16(), impl_->length())) {
        hash_ = StringHasher::ComputeHashAndMaskTop8Bits<
            ASCIIConvertTo8AndLowerHashReader>(
            (const char*)impl_->Characters16(), impl_->length());
      } else {
        hash_ = StringHasher::ComputeHashAndMaskTop8Bits<
            ASCIILowerHashReader<UChar>>((const char*)impl_->Characters16(),
                                         impl_->length() * 2);
      }
    }
  }

  const StringImpl* impl() const { return impl_; }
  unsigned hash() const { return hash_; }

 private:
  const StringImpl* impl_;
  unsigned hash_;
};
struct LowercaseLookupTranslator {
  // Computes the hash that |query| would have if it were first converted to
  // ASCII lowercase.
  static unsigned GetHash(const HashTranslatorLowercaseBuffer& buf) {
    return buf.hash();
  }

  // Returns true if the hashtable |bucket| contains a string which is the ASCII
  // lowercase version of |query|.
  static bool Equal(StringImpl* const& bucket,
                    const HashTranslatorLowercaseBuffer& buf) {
    // This is similar to EqualIgnoringASCIICase, but not the same.
    // In particular, it validates that |bucket| is a lowercase version of
    // |buf.impl()|.
    //
    // Unlike EqualIgnoringASCIICase, it returns false if they are equal
    // ignoring ASCII case but |bucket| contains an uppercase ASCII character.
    //
    // However, similar optimizations are used here as there, so these should
    // have generally similar correctness and performance constraints.
    const StringImpl* query = buf.impl();
    if (bucket->length() != query->length())
      return false;
    if (bucket->Bytes() == query->Bytes() &&
        bucket->Is8Bit() == query->Is8Bit())
      return query->IsLowerASCII();
    return WTF::VisitCharacters(*bucket, [&](auto bch) {
      return WTF::VisitCharacters(*query, [&](auto qch) {
        wtf_size_t len = query->length();
        for (wtf_size_t i = 0; i < len; ++i) {
          if (bch[i] != ToASCIILower(qch[i]))
            return false;
        }
        return true;
      });
    });
  }
};

}  // namespace

AtomicStringTable& AtomicStringTable::Instance() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(AtomicStringTable, table, ());
  return table;
}

AtomicStringTable::AtomicStringTable() {
  base::AutoLock auto_lock(lock_);
  for (StringImpl* string : StringImpl::AllStaticStrings().Values()) {
    DCHECK(string->length());
    AddNoLock(string);
  }
}

void AtomicStringTable::ReserveCapacity(unsigned size) {
  base::AutoLock auto_lock(lock_);
  table_.ReserveCapacityForSize(size);
}

template <typename T, typename HashTranslator>
scoped_refptr<StringImpl> AtomicStringTable::AddToStringTable(const T& value) {
  // Lock not only protects access to the table, it also guarantees
  // mutual exclusion with the refcount decrement on removal.
  base::AutoLock auto_lock(lock_);
  HashSet<StringImpl*>::AddResult add_result =
      table_.AddWithTranslator<HashTranslator>(value);

  // If the string is newly-translated, then we need to adopt it.
  // The boolean in the pair tells us if that is so.
  return add_result.is_new_entry
             ? base::AdoptRef(*add_result.stored_value)
             : base::WrapRefCounted(*add_result.stored_value);
}

scoped_refptr<StringImpl> AtomicStringTable::Add(
    const UChar* s,
    unsigned length,
    AtomicStringUCharEncoding encoding) {
  if (!s)
    return nullptr;

  if (!length)
    return StringImpl::empty_;

  UCharBuffer buffer(s, length, encoding);
  return AddToStringTable<UCharBuffer, UCharBufferTranslator>(buffer);
}

class LCharBuffer {
 public:
  ALWAYS_INLINE LCharBuffer(const LChar* chars, unsigned len)
      : characters_(chars),
        length_(len),
        // This is a common path from V8 strings, so inlining is worth it.
        hash_(StringHasher::ComputeHashAndMaskTop8BitsInline((const char*)chars,
                                                             len)) {}

  base::span<const LChar> characters() const { return {characters_, length_}; }
  unsigned hash() const { return hash_; }

 private:
  const LChar* characters_;
  const unsigned length_;
  const unsigned hash_;
};

struct LCharBufferTranslator {
  static unsigned GetHash(const LCharBuffer& buf) { return buf.hash(); }

  static bool Equal(StringImpl* const& str, const LCharBuffer& buf) {
    return WTF::Equal(str, buf.characters());
  }

  static void Store(StringImpl*& location,
                    const LCharBuffer& buf,
                    unsigned hash) {
    auto string = StringImpl::Create(buf.characters());
    location = string.release();
    location->SetHash(hash);
    location->SetIsAtomic();
  }
};

scoped_refptr<StringImpl> AtomicStringTable::Add(
    const StringView& string_view) {
  if (string_view.IsNull()) {
    return nullptr;
  }

  if (string_view.empty()) {
    return StringImpl::empty_;
  }

  if (string_view.Is8Bit()) {
    LCharBuffer buffer(string_view.Characters8(), string_view.length());
    return AddToStringTable<LCharBuffer, LCharBufferTranslator>(buffer);
  }
  UCharBuffer buffer(string_view.Characters16(), string_view.length(),
                     AtomicStringUCharEncoding::kUnknown);
  return AddToStringTable<UCharBuffer, UCharBufferTranslator>(buffer);
}

scoped_refptr<StringImpl> AtomicStringTable::Add(const LChar* s,
                                                 unsigned length) {
  if (!s)
    return nullptr;

  if (!length)
    return StringImpl::empty_;

  LCharBuffer buffer(s, length);
  return AddToStringTable<LCharBuffer, LCharBufferTranslator>(buffer);
}

StringImpl* AtomicStringTable::AddNoLock(StringImpl* string) {
  auto result = table_.insert(string);
  StringImpl* entry = *result.stored_value;
  if (result.is_new_entry)
    entry->SetIsAtomic();

  DCHECK(!string->IsStatic() || entry->IsStatic());
  return entry;
}

scoped_refptr<StringImpl> AtomicStringTable::Add(StringImpl* string) {
  if (!string->length())
    return StringImpl::empty_;

  // Lock not only protects access to the table, it also guarantess
  // mutual exclusion with the refcount decrement on removal.
  base::AutoLock auto_lock(lock_);
  return base::WrapRefCounted(AddNoLock(string));
}

scoped_refptr<StringImpl> AtomicStringTable::Add(
    scoped_refptr<StringImpl>&& string) {
  if (!string->length())
    return StringImpl::empty_;

  // Lock not only protects access to the table, it also guarantess
  // mutual exclusion with the refcount decrement on removal.
  base::AutoLock auto_lock(lock_);
  StringImpl* entry = AddNoLock(string.get());
  if (entry == string.get())
    return std::move(string);

  return base::WrapRefCounted(entry);
}

scoped_refptr<StringImpl> AtomicStringTable::AddUTF8(
    const uint8_t* characters_start,
    const uint8_t* characters_end) {
  bool seen_non_ascii = false;
  bool seen_non_latin1 = false;
  unsigned utf16_length = unicode::CalculateStringLengthFromUTF8(
      characters_start, characters_end, seen_non_ascii, seen_non_latin1);
  if (!seen_non_ascii) {
    return Add((const LChar*)characters_start, utf16_length);
  }

  auto utf16_buf = base::HeapArray<UChar>::Uninit(utf16_length);
  base::span<const uint8_t> source_buffer(
      reinterpret_cast<const uint8_t*>(characters_start),
      static_cast<size_t>(characters_end - characters_start));
  if (unicode::ConvertUTF8ToUTF16(source_buffer, utf16_buf).status !=
      unicode::kConversionOK) {
    NOTREACHED();
  }

  UCharBuffer buffer(utf16_buf.data(), utf16_buf.size(),
                     seen_non_latin1 ? AtomicStringUCharEncoding::kIs16Bit
                                     : AtomicStringUCharEncoding::kIs8Bit);
  return AddToStringTable<UCharBuffer, UCharBufferTranslator>(buffer);
}

AtomicStringTable::WeakResult AtomicStringTable::WeakFindSlowForTesting(
    const StringView& string) {
  DCHECK(string.length());
  base::AutoLock auto_lock(lock_);
  const auto& it = table_.Find<StringViewLookupTranslator>(string);
  if (it == table_.end())
    return WeakResult();
  return WeakResult(*it);
}

AtomicStringTable::WeakResult AtomicStringTable::WeakFindLowercase(
    const AtomicString& string) {
  DCHECK(!string.empty());
  DCHECK(!string.IsLowerASCII());
  DCHECK(string.length());
  HashTranslatorLowercaseBuffer buffer(string.Impl());
  base::AutoLock auto_lock(lock_);
  const auto& it = table_.Find<LowercaseLookupTranslator>(buffer);
  if (it == table_.end())
    return WeakResult();
  DCHECK(StringView(*it).IsLowerASCII());
  DCHECK(EqualIgnoringASCIICase(*it, string));
  return WeakResult(*it);
}

bool AtomicStringTable::ReleaseAndRemoveIfNeeded(StringImpl* string) {
  DCHECK(string->IsAtomic());
  base::AutoLock auto_lock(lock_);
  // Double check that the refcount is still 1. Because Add() could
  // have added a new reference after the load in StringImpl::Release.
  if (string->ref_count_.fetch_sub(1, std::memory_order_acq_rel) != 1)
    return false;

  auto iterator = table_.find(string);
  CHECK_NE(iterator, table_.end());
  table_.erase(iterator);
  // Indicate that something was removed.
  return true;
}

}  // namespace WTF
```