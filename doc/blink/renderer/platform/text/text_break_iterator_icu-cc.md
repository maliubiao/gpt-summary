Response:
Let's break down the thought process for analyzing the C++ code and answering the user's request.

1. **Understand the Core Request:** The user wants to know the functionality of the `text_break_iterator_icu.cc` file in the Chromium Blink engine. They're also interested in its relation to JavaScript, HTML, CSS, any logical deductions with examples, and common usage errors.

2. **Initial Skim and Keyword Identification:**  Quickly scan the code for key terms and patterns:
    * `BreakIterator`, `icu`, `unicode`, `text`, `line`, `word`, `sentence`, `character`, `cursor`, `locale`. These suggest the file is about segmenting text.
    * `UText`, `UChar`, `LChar`, `String`, `StringView`. These point to different ways of representing text within Blink and interacting with the ICU library.
    * `Pool`, `ThreadSpecific`. This indicates resource management, likely for performance.
    * `AtomicString`. A type of string in Blink.
    * `TextOpenLatin1`, `TextOpenUTF16`. Functions for preparing text for ICU.
    * The copyright notices at the beginning confirm the file's origin and licensing.

3. **Identify the Main Functionality:**  Based on the keywords and the overall structure, the primary purpose of the file is to provide different types of text break iterators using the ICU (International Components for Unicode) library. These iterators are used to find boundaries in text, like the end of words, sentences, or lines.

4. **Map Functionality to Specific Iterators:**  Notice the different functions creating specific types of iterators:
    * `WordBreakIterator`
    * `AcquireLineBreakIterator` (pooled)
    * `GetNonSharedCharacterBreakIterator`
    * `SentenceBreakIterator`
    * `CursorMovementIterator`

5. **Connect to Web Technologies (JavaScript, HTML, CSS):** Think about where text segmentation is relevant in a web browser:
    * **JavaScript:**  JavaScript has methods for manipulating strings, and the browser needs to understand word boundaries for features like text selection, cursor movement, and potentially even spell checking or hyphenation.
    * **HTML:** HTML defines the structure and content of web pages, which is primarily text. The browser needs to break lines of text for proper rendering.
    * **CSS:** CSS controls the visual presentation. Properties like `word-break`, `overflow-wrap`, and text justification directly rely on understanding word and line breaks.

6. **Provide Concrete Examples:** Now, translate the abstract functionality into concrete examples related to the web:
    * **JavaScript:** Text selection, `Intl.Segmenter` (though this example needed a disclaimer about direct usage).
    * **HTML:** Line wrapping within a `<p>` tag.
    * **CSS:**  `word-break: break-all;` causing a long word to break mid-word.

7. **Logical Deductions and Examples:**  Focus on how the code works internally and what the inputs and outputs of the iterators are:
    * **Input:** A string of text.
    * **Output:**  A sequence of integer indices representing the break points.
    * **Assumption:**  The input string has specific characteristics (e.g., spaces between words, punctuation marks at the end of sentences). Demonstrate this with examples.

8. **Common Usage Errors:** Consider how a developer might misuse these iterators or encounter unexpected behavior:
    * **Incorrect Locale:** Using the wrong locale can lead to incorrect segmentation.
    * **String Encoding Issues:**  Assuming the input is always UTF-8 when it might be something else.
    * **Performance:** Creating too many non-pooled iterators might impact performance.

9. **Structure the Answer:** Organize the information logically:
    * Start with a general overview of the file's purpose.
    * List the key functionalities.
    * Explain the connection to JavaScript, HTML, and CSS with examples.
    * Provide logical deduction examples with input and output.
    * Discuss common usage errors.

10. **Refine and Review:**  Read through the answer to ensure clarity, accuracy, and completeness. Make sure the examples are easy to understand and that the technical details are explained without being overly dense. For instance, initially, I might just say "word breaking," but refining it with CSS examples like `word-break` makes it more tangible. Similarly, I need to be careful not to overstate the direct connection to JavaScript methods without proper context (like the `Intl.Segmenter` caveat).

By following this thought process, moving from the general to the specific, and focusing on providing clear examples and explanations, we can effectively answer the user's request and provide a comprehensive understanding of the `text_break_iterator_icu.cc` file.
这个C++源代码文件 `text_break_iterator_icu.cc` 是 Chromium Blink 渲染引擎的一部分，它的主要功能是**提供文本断行（line breaking）、断词（word breaking）、断句（sentence breaking）和字符簇（grapheme cluster）边界判断的功能，并且利用了 ICU (International Components for Unicode) 库来实现这些功能。**

更详细地说，它做了以下事情：

**1. 封装 ICU 的 BreakIterator:**
   - 它使用 ICU 库提供的 `icu::BreakIterator` 类来执行各种文本边界分析。
   - 它为不同类型的边界（行、词、句、字符）创建了相应的 `icu::BreakIterator` 实例。

**2. 提供 C++ 接口供 Blink 其他模块使用:**
   - 它定义了一些 Blink 特有的 C++ 类和函数，例如 `TextBreakIterator`，`PooledBreakIterator`，`NonSharedCharacterBreakIterator` 等，方便 Blink 引擎的其他部分调用文本边界分析功能。
   - 这些接口隐藏了 ICU 库的细节，使得 Blink 的其他模块可以更容易地使用文本断开功能。

**3. 对象池优化 (Line Break Iterator Pool):**
   -  为了提高性能，特别是对于频繁的行断开操作，它实现了一个 `LineBreakIteratorPool`。
   -  这个池维护了一组已经创建好的 `icu::BreakIterator` 对象，可以被重复使用，避免了频繁创建和销毁对象的开销。
   -  它使用线程局部存储 (`WTF::ThreadSpecific`) 来保证每个线程都有自己的对象池。

**4. 处理不同类型的文本数据:**
   -  它提供了处理 8-bit (Latin1) 和 16-bit (UTF-16) 编码字符串的函数，例如 `WordBreakIterator(base::span<const LChar> string)` 和 `WordBreakIterator(base::span<const UChar> string)`。
   -  它内部使用了 `UText` 结构体来统一处理不同格式的文本数据，这是 ICU 提供的用于访问文本的抽象接口。

**5. 处理 Locale (区域设置):**
   -  文本断开规则会因语言和地区而异。这个文件在创建 `icu::BreakIterator` 实例时会考虑当前的区域设置 (`CurrentTextBreakLocaleID()`)，以提供符合语言习惯的断开结果。
   -  它还允许指定特定的 locale，例如在 `AcquireLineBreakIterator` 函数中。

**6. 提供字符簇迭代器:**
   -  `NonSharedCharacterBreakIterator` 提供了迭代文本中字符簇的功能。字符簇是指用户感知的字符，可能由一个或多个 Unicode 码位组成（例如，带有组合字符的字母，或者 Emoji）。

**与 JavaScript, HTML, CSS 的关系:**

这个文件直接参与了浏览器如何解析和渲染网页中的文本，因此与 JavaScript、HTML 和 CSS 的功能都有密切关系。

**JavaScript:**

* **文本选择和光标移动:** 当用户在网页上选择文本或移动光标时，JavaScript 可以触发相应的事件。浏览器需要知道单词、句子和字符的边界，以便正确地进行选择和移动。这个文件提供的断词和字符簇边界判断功能就直接服务于此。
   * **假设输入:** 用户使用鼠标在一段文本上拖动以选择文本。
   * **输出:**  浏览器根据 `TextBreakIterator` 提供的边界信息，高亮显示被选中的单词或字符。
* **`Intl.Segmenter` API (现代 JavaScript API):** 虽然这个文件本身不直接暴露给 JavaScript，但现代 JavaScript 的 `Intl.Segmenter` API 提供了类似的功能，并且在底层实现中可能会使用到类似 ICU 这样的库。
   * **例子:** JavaScript 代码可以使用 `Intl.Segmenter` 来分割文本成单词或句子，这在某些文本处理场景中非常有用。

**HTML:**

* **自动换行:**  当浏览器渲染 HTML 文本时，需要根据容器的宽度自动进行换行。`AcquireLineBreakIterator` 函数提供的断行功能正是用于确定文本应该在哪里换行。
   * **假设输入:**  一个 `<p>` 标签包含一段很长的英文文本，容器宽度有限。
   * **输出:** 浏览器会根据英文的断词规则，在单词之间找到合适的断点进行换行，保证可读性。
* **`<wbr>` 标签:** HTML 中的 `<wbr>` 标签 (Word Break Opportunity) 允许开发者指定文本中可以换行的位置。虽然 `<wbr>` 是显式的断点，但默认的自动换行仍然依赖于 `TextBreakIterator`。

**CSS:**

* **`word-break` 属性:** CSS 的 `word-break` 属性控制浏览器如何在单词内部断行。例如，`word-break: break-all;` 会允许在任意字符之间断行，而 `word-break: keep-all;` 则只允许在空格等自然断点处断行。这个属性的实现依赖于底层的文本断开功能。
   * **例子:** 如果一个很长的 URL 没有空格，使用 `word-break: break-all;` 可以防止它溢出容器。
* **`overflow-wrap` (或 `word-wrap`) 属性:** 这个 CSS 属性也控制着当一个单词太长无法放入容器时，浏览器应该如何处理。`overflow-wrap: break-word;` 会让长单词断开到下一行。
* **`text-align: justify;` 属性:**  为了实现两端对齐的文本，浏览器需要在单词之间插入额外的空格。这需要准确地识别单词的边界，而 `WordBreakIterator` 就提供了这样的功能。

**逻辑推理与假设输入/输出:**

假设我们调用 `WordBreakIterator` 来分割一个英文句子：

* **假设输入:**  一个包含字符串 "This is a test sentence." 的 `base::span<const UChar>`。
* **逻辑推理:**  `WordBreakIterator` 内部会使用 ICU 的单词断开规则，识别出空格和标点符号作为单词的边界。
* **输出:**  调用迭代器的 `next()` 方法会依次返回以下断点的位置索引：
    * 4 (在 "This" 之后)
    * 7 (在 "is" 之后)
    * 9 (在 "a" 之后)
    * 14 (在 "test" 之后)
    * 23 (在 "sentence." 之后)
    * `kTextBreakDone` (表示迭代结束)

**用户或编程常见的使用错误:**

1. **未正确处理 Locale:**  不考虑用户的语言设置，使用默认的断开规则可能会导致不符合用户预期的结果。例如，对于一些亚洲语言，空格不是主要的断词符。
   * **错误示例:**  一个为英文设计的网页，在中文环境下可能无法正确断行或断词。
2. **在多线程环境下不当使用非线程安全的对象:**  虽然 `LineBreakIteratorPool` 尝试使用线程局部存储来提高性能，但直接使用非线程安全的 `icu::BreakIterator` 对象在多线程环境下可能会导致数据竞争和崩溃。
3. **过度创建非共享的迭代器:**  对于某些类型的迭代器（例如字符簇迭代器），如果频繁创建和销毁 `NonSharedCharacterBreakIterator` 对象，可能会带来性能开销。应该尽量复用或使用对象池提供的迭代器。
4. **假设所有文本都是简单的 ASCII:** 没有考虑到 Unicode 字符的复杂性，例如组合字符、Emoji 等，可能导致错误的边界判断。ICU 库能够处理这些复杂的 Unicode 情况，但前提是使用了正确的迭代器和配置。
5. **忘记关闭 `UText` 对象:**  在使用 `UText` 结构体时，应该在不再使用时调用 `utext_close()` 来释放资源，否则可能导致内存泄漏。虽然代码中看起来有 `utext_close(text);`，但在其他使用 `UText` 的场景中需要注意。

总而言之，`text_break_iterator_icu.cc` 文件在 Chromium Blink 引擎中扮演着至关重要的角色，它利用强大的 ICU 库为文本处理提供了基础的边界分析功能，直接影响着网页的排版、文本选择、光标移动等用户体验。理解其功能有助于我们更好地理解浏览器如何处理和渲染互联网上的各种文本内容。

### 提示词
```
这是目录为blink/renderer/platform/text/text_break_iterator_icu.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2006 Lars Knoll <lars@trolltech.com>
 * Copyright (C) 2007, 2011, 2012 Apple Inc. All rights reserved.
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

#include "third_party/blink/renderer/platform/text/text_break_iterator.h"

#include <unicode/rbbi.h>
#include <unicode/ubrk.h>
#include <algorithm>
#include <limits>
#include <memory>
#include <utility>

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/notreached.h"
#include "third_party/blink/renderer/platform/text/icu_error.h"
#include "third_party/blink/renderer/platform/text/text_break_iterator_internal_icu.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string_hash.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/thread_specific.h"

namespace blink {

namespace {

class LineBreakIteratorPool final {
  USING_FAST_MALLOC(LineBreakIteratorPool);

 public:
  static LineBreakIteratorPool& SharedPool() {
    static WTF::ThreadSpecific<LineBreakIteratorPool>* pool =
        new WTF::ThreadSpecific<LineBreakIteratorPool>;
    return **pool;
  }

  LineBreakIteratorPool() = default;
  LineBreakIteratorPool(const LineBreakIteratorPool&) = delete;
  LineBreakIteratorPool& operator=(const LineBreakIteratorPool&) = delete;

  icu::BreakIterator* Take(const AtomicString& locale) {
    icu::BreakIterator* iterator = nullptr;
    for (wtf_size_t i = 0; i < pool_.size(); ++i) {
      if (pool_[i].first == locale) {
        iterator = pool_[i].second;
        pool_.EraseAt(i);
        break;
      }
    }

    if (!iterator) {
      UErrorCode open_status = U_ZERO_ERROR;
      bool locale_is_empty = locale.empty();
      iterator = icu::BreakIterator::createLineInstance(
          locale_is_empty ? icu::Locale(CurrentTextBreakLocaleID())
                          : icu::Locale(locale.Utf8().c_str()),
          open_status);
      // locale comes from a web page and it can be invalid, leading ICU
      // to fail, in which case we fall back to the default locale.
      if (!locale_is_empty && U_FAILURE(open_status)) {
        open_status = U_ZERO_ERROR;
        iterator = icu::BreakIterator::createLineInstance(
            icu::Locale(CurrentTextBreakLocaleID()), open_status);
      }

      if (U_FAILURE(open_status)) {
        DLOG(ERROR) << "icu::BreakIterator construction failed with status "
                    << open_status;
        return nullptr;
      }
    }

    DCHECK(!vended_iterators_.Contains(iterator));
    vended_iterators_.Set(iterator, locale);
    return iterator;
  }

  void Put(icu::BreakIterator* iterator) {
    DCHECK(vended_iterators_.Contains(iterator));

    if (pool_.size() == kCapacity) {
      delete (pool_[0].second);
      pool_.EraseAt(0);
    }

    pool_.push_back(Entry(vended_iterators_.Take(iterator), iterator));
  }

 private:
  static const size_t kCapacity = 4;

  typedef std::pair<AtomicString, icu::BreakIterator*> Entry;
  typedef Vector<Entry, kCapacity> Pool;
  Pool pool_;
  HashMap<icu::BreakIterator*, AtomicString> vended_iterators_;

  friend WTF::ThreadSpecific<
      LineBreakIteratorPool>::operator LineBreakIteratorPool*();
};

enum TextContext { kNoContext, kPriorContext, kPrimaryContext };

constexpr int kTextBufferCapacity = 16;

struct UTextWithBuffer {
  DISALLOW_NEW();
  UText text;
  UChar buffer[kTextBufferCapacity];
};

inline int64_t TextPinIndex(int64_t& index, int64_t limit) {
  if (index < 0) {
    index = 0;
  } else if (index > limit) {
    index = limit;
  }
  return index;
}

inline int64_t TextNativeLength(UText* text) {
  return text->a + text->b;
}

// Relocate pointer from source into destination as required.
void TextFixPointer(const UText* source,
                    UText* destination,
                    const void*& pointer) {
  if (pointer >= source->pExtra &&
      pointer < static_cast<char*>(source->pExtra) + source->extraSize) {
    // Pointer references source extra buffer.
    pointer = static_cast<char*>(destination->pExtra) +
              (static_cast<const char*>(pointer) -
               static_cast<const char*>(source->pExtra));
  } else if (pointer >= source &&
             pointer <
                 reinterpret_cast<const char*>(source) + source->sizeOfStruct) {
    // Pointer references source text structure, but not source extra buffer.
    pointer = reinterpret_cast<char*>(destination) +
              (static_cast<const char*>(pointer) -
               reinterpret_cast<const char*>(source));
  }
}

UText* TextClone(UText* destination,
                 const UText* source,
                 UBool deep,
                 UErrorCode* status) {
  DCHECK(!deep);
  if (U_FAILURE(*status)) {
    return nullptr;
  }
  int32_t extra_size = source->extraSize;
  destination = utext_setup(destination, extra_size, status);
  if (U_FAILURE(*status)) {
    return destination;
  }
  void* extra_new = destination->pExtra;
  int32_t flags = destination->flags;
  int size_to_copy = std::min(source->sizeOfStruct, destination->sizeOfStruct);
  memcpy(destination, source, size_to_copy);
  destination->pExtra = extra_new;
  destination->flags = flags;
  if (extra_size > 0) {
    memcpy(destination->pExtra, source->pExtra, extra_size);
  }
  TextFixPointer(source, destination, destination->context);
  TextFixPointer(source, destination, destination->p);
  TextFixPointer(source, destination, destination->q);
  DCHECK(!destination->r);
  const void* chunk_contents =
      static_cast<const void*>(destination->chunkContents);
  TextFixPointer(source, destination, chunk_contents);
  destination->chunkContents = static_cast<const UChar*>(chunk_contents);
  return destination;
}

int32_t TextExtract(UText*,
                    int64_t,
                    int64_t,
                    UChar*,
                    int32_t,
                    UErrorCode* error_code) {
  // In the present context, this text provider is used only with ICU functions
  // that do not perform an extract operation.
  NOTREACHED();
}

void TextClose(UText* text) {
  text->context = nullptr;
}

inline TextContext TextGetContext(const UText* text,
                                  int64_t native_index,
                                  UBool forward) {
  if (!text->b || native_index > text->b) {
    return kPrimaryContext;
  }
  if (native_index == text->b) {
    return forward ? kPrimaryContext : kPriorContext;
  }
  return kPriorContext;
}

inline TextContext TextLatin1GetCurrentContext(const UText* text) {
  if (!text->chunkContents) {
    return kNoContext;
  }
  return text->chunkContents == text->pExtra ? kPrimaryContext : kPriorContext;
}

void TextLatin1MoveInPrimaryContext(UText* text,
                                    int64_t native_index,
                                    int64_t native_length,
                                    UBool forward) {
  DCHECK_EQ(text->chunkContents, text->pExtra);
  if (forward) {
    DCHECK_GE(native_index, text->b);
    DCHECK_LT(native_index, native_length);
    text->chunkNativeStart = native_index;
    text->chunkNativeLimit = native_index + text->extraSize / sizeof(UChar);
    if (text->chunkNativeLimit > native_length) {
      text->chunkNativeLimit = native_length;
    }
  } else {
    DCHECK_GT(native_index, text->b);
    DCHECK_LE(native_index, native_length);
    text->chunkNativeLimit = native_index;
    text->chunkNativeStart = native_index - text->extraSize / sizeof(UChar);
    if (text->chunkNativeStart < text->b) {
      text->chunkNativeStart = text->b;
    }
  }
  int64_t length = text->chunkNativeLimit - text->chunkNativeStart;
  // Ensure chunk length is well defined if computed length exceeds int32_t
  // range.
  DCHECK_LE(length, std::numeric_limits<int32_t>::max());
  text->chunkLength = length <= std::numeric_limits<int32_t>::max()
                          ? static_cast<int32_t>(length)
                          : 0;
  text->nativeIndexingLimit = text->chunkLength;
  text->chunkOffset = forward ? 0 : text->chunkLength;
  auto source = base::span(
      static_cast<const LChar*>(text->p) + (text->chunkNativeStart - text->b),
      static_cast<unsigned>(text->chunkLength));
  auto dest = base::span(const_cast<UChar*>(text->chunkContents),
                         static_cast<unsigned>(text->chunkLength));
  StringImpl::CopyChars(dest, source);
}

void TextLatin1SwitchToPrimaryContext(UText* text,
                                      int64_t native_index,
                                      int64_t native_length,
                                      UBool forward) {
  DCHECK(!text->chunkContents || text->chunkContents == text->q);
  text->chunkContents = static_cast<const UChar*>(text->pExtra);
  TextLatin1MoveInPrimaryContext(text, native_index, native_length, forward);
}

void TextLatin1MoveInPriorContext(UText* text,
                                  int64_t native_index,
                                  int64_t native_length,
                                  UBool forward) {
  DCHECK_EQ(text->chunkContents, text->q);
  DCHECK(forward ? native_index < text->b : native_index <= text->b);
  DCHECK(forward ? native_index < native_length
                 : native_index <= native_length);
  DCHECK(forward ? native_index < native_length
                 : native_index <= native_length);
  text->chunkNativeStart = 0;
  text->chunkNativeLimit = text->b;
  text->chunkLength = text->b;
  text->nativeIndexingLimit = text->chunkLength;
  int64_t offset = native_index - text->chunkNativeStart;
  // Ensure chunk offset is well defined if computed offset exceeds int32_t
  // range or chunk length.
  DCHECK_LE(offset, std::numeric_limits<int32_t>::max());
  text->chunkOffset = std::min(offset <= std::numeric_limits<int32_t>::max()
                                   ? static_cast<int32_t>(offset)
                                   : 0,
                               text->chunkLength);
}

void TextLatin1SwitchToPriorContext(UText* text,
                                    int64_t native_index,
                                    int64_t native_length,
                                    UBool forward) {
  DCHECK(!text->chunkContents || text->chunkContents == text->pExtra);
  text->chunkContents = static_cast<const UChar*>(text->q);
  TextLatin1MoveInPriorContext(text, native_index, native_length, forward);
}

inline bool TextInChunkOrOutOfRange(UText* text,
                                    int64_t native_index,
                                    int64_t native_length,
                                    UBool forward,
                                    UBool& is_accessible) {
  if (forward) {
    if (native_index >= text->chunkNativeStart &&
        native_index < text->chunkNativeLimit) {
      int64_t offset = native_index - text->chunkNativeStart;
      // Ensure chunk offset is well formed if computed offset exceeds int32_t
      // range.
      DCHECK_LE(offset, std::numeric_limits<int32_t>::max());
      text->chunkOffset = offset <= std::numeric_limits<int32_t>::max()
                              ? static_cast<int32_t>(offset)
                              : 0;
      is_accessible = true;
      return true;
    }
    if (native_index >= native_length &&
        text->chunkNativeLimit == native_length) {
      text->chunkOffset = text->chunkLength;
      is_accessible = false;
      return true;
    }
  } else {
    if (native_index > text->chunkNativeStart &&
        native_index <= text->chunkNativeLimit) {
      int64_t offset = native_index - text->chunkNativeStart;
      // Ensure chunk offset is well formed if computed offset exceeds int32_t
      // range.
      DCHECK_LE(offset, std::numeric_limits<int32_t>::max());
      text->chunkOffset = offset <= std::numeric_limits<int32_t>::max()
                              ? static_cast<int32_t>(offset)
                              : 0;
      is_accessible = true;
      return true;
    }
    if (native_index <= 0 && !text->chunkNativeStart) {
      text->chunkOffset = 0;
      is_accessible = false;
      return true;
    }
  }
  return false;
}

UBool TextLatin1Access(UText* text, int64_t native_index, UBool forward) {
  if (!text->context) {
    return false;
  }
  int64_t native_length = TextNativeLength(text);
  UBool is_accessible;
  if (TextInChunkOrOutOfRange(text, native_index, native_length, forward,
                              is_accessible)) {
    return is_accessible;
  }
  native_index = TextPinIndex(native_index, native_length - 1);
  TextContext current_context = TextLatin1GetCurrentContext(text);
  TextContext new_context = TextGetContext(text, native_index, forward);
  DCHECK_NE(new_context, kNoContext);
  if (new_context == current_context) {
    if (current_context == kPrimaryContext) {
      TextLatin1MoveInPrimaryContext(text, native_index, native_length,
                                     forward);
    } else {
      TextLatin1MoveInPriorContext(text, native_index, native_length, forward);
    }
  } else if (new_context == kPrimaryContext) {
    TextLatin1SwitchToPrimaryContext(text, native_index, native_length,
                                     forward);
  } else {
    DCHECK_EQ(new_context, kPriorContext);
    TextLatin1SwitchToPriorContext(text, native_index, native_length, forward);
  }
  return true;
}

constexpr struct UTextFuncs kTextLatin1Funcs = {
    sizeof(UTextFuncs),
    0,
    0,
    0,
    TextClone,
    TextNativeLength,
    TextLatin1Access,
    TextExtract,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    TextClose,
    nullptr,
    nullptr,
    nullptr,
};

void TextInit(UText* text,
              const UTextFuncs* funcs,
              const void* string,
              unsigned length,
              const UChar* prior_context,
              int prior_context_length) {
  text->pFuncs = funcs;
  text->providerProperties = 1 << UTEXT_PROVIDER_STABLE_CHUNKS;
  text->context = string;
  text->p = string;
  text->a = length;
  text->q = prior_context;
  text->b = prior_context_length;
}

UText* TextOpenLatin1(UTextWithBuffer* ut_with_buffer,
                      base::span<const LChar> string,
                      const UChar* prior_context,
                      int prior_context_length,
                      UErrorCode* status) {
  if (U_FAILURE(*status)) {
    return nullptr;
  }

  if (string.empty() ||
      string.size() >
          static_cast<size_t>(std::numeric_limits<int32_t>::max())) {
    *status = U_ILLEGAL_ARGUMENT_ERROR;
    return nullptr;
  }
  UText* text = utext_setup(&ut_with_buffer->text,
                            sizeof(ut_with_buffer->buffer), status);
  if (U_FAILURE(*status)) {
    DCHECK(!text);
    return nullptr;
  }
  TextInit(text, &kTextLatin1Funcs, string.data(),
           base::checked_cast<unsigned>(string.size()), prior_context,
           prior_context_length);
  return text;
}

inline TextContext TextUTF16GetCurrentContext(const UText* text) {
  if (!text->chunkContents) {
    return kNoContext;
  }
  return text->chunkContents == text->p ? kPrimaryContext : kPriorContext;
}

void TextUTF16MoveInPrimaryContext(UText* text,
                                   int64_t native_index,
                                   int64_t native_length,
                                   UBool forward) {
  DCHECK_EQ(text->chunkContents, text->p);
  DCHECK(forward ? native_index >= text->b : native_index > text->b);
  DCHECK(forward ? native_index < native_length
                 : native_index <= native_length);
  text->chunkNativeStart = text->b;
  text->chunkNativeLimit = native_length;
  int64_t length = text->chunkNativeLimit - text->chunkNativeStart;
  // Ensure chunk length is well defined if computed length exceeds int32_t
  // range.
  DCHECK_LE(length, std::numeric_limits<int32_t>::max());
  text->chunkLength = length <= std::numeric_limits<int32_t>::max()
                          ? static_cast<int32_t>(length)
                          : 0;
  text->nativeIndexingLimit = text->chunkLength;
  int64_t offset = native_index - text->chunkNativeStart;
  // Ensure chunk offset is well defined if computed offset exceeds int32_t
  // range or chunk length.
  DCHECK_LE(offset, std::numeric_limits<int32_t>::max());
  text->chunkOffset = std::min(offset <= std::numeric_limits<int32_t>::max()
                                   ? static_cast<int32_t>(offset)
                                   : 0,
                               text->chunkLength);
}

void TextUTF16SwitchToPrimaryContext(UText* text,
                                     int64_t native_index,
                                     int64_t native_length,
                                     UBool forward) {
  DCHECK(!text->chunkContents || text->chunkContents == text->q);
  text->chunkContents = static_cast<const UChar*>(text->p);
  TextUTF16MoveInPrimaryContext(text, native_index, native_length, forward);
}

void TextUTF16MoveInPriorContext(UText* text,
                                 int64_t native_index,
                                 int64_t native_length,
                                 UBool forward) {
  DCHECK_EQ(text->chunkContents, text->q);
  DCHECK(forward ? native_index < text->b : native_index <= text->b);
  DCHECK(forward ? native_index < native_length
                 : native_index <= native_length);
  DCHECK(forward ? native_index < native_length
                 : native_index <= native_length);
  text->chunkNativeStart = 0;
  text->chunkNativeLimit = text->b;
  text->chunkLength = text->b;
  text->nativeIndexingLimit = text->chunkLength;
  int64_t offset = native_index - text->chunkNativeStart;
  // Ensure chunk offset is well defined if computed offset exceeds
  // int32_t range or chunk length.
  DCHECK_LE(offset, std::numeric_limits<int32_t>::max());
  text->chunkOffset = std::min(offset <= std::numeric_limits<int32_t>::max()
                                   ? static_cast<int32_t>(offset)
                                   : 0,
                               text->chunkLength);
}

void TextUTF16SwitchToPriorContext(UText* text,
                                   int64_t native_index,
                                   int64_t native_length,
                                   UBool forward) {
  DCHECK(!text->chunkContents || text->chunkContents == text->p);
  text->chunkContents = static_cast<const UChar*>(text->q);
  TextUTF16MoveInPriorContext(text, native_index, native_length, forward);
}

UBool TextUTF16Access(UText* text, int64_t native_index, UBool forward) {
  if (!text->context) {
    return false;
  }
  int64_t native_length = TextNativeLength(text);
  UBool is_accessible;
  if (TextInChunkOrOutOfRange(text, native_index, native_length, forward,
                              is_accessible)) {
    return is_accessible;
  }
  native_index = TextPinIndex(native_index, native_length - 1);
  TextContext current_context = TextUTF16GetCurrentContext(text);
  TextContext new_context = TextGetContext(text, native_index, forward);
  DCHECK_NE(new_context, kNoContext);
  if (new_context == current_context) {
    if (current_context == kPrimaryContext) {
      TextUTF16MoveInPrimaryContext(text, native_index, native_length, forward);
    } else {
      TextUTF16MoveInPriorContext(text, native_index, native_length, forward);
    }
  } else if (new_context == kPrimaryContext) {
    TextUTF16SwitchToPrimaryContext(text, native_index, native_length, forward);
  } else {
    DCHECK_EQ(new_context, kPriorContext);
    TextUTF16SwitchToPriorContext(text, native_index, native_length, forward);
  }
  return true;
}

constexpr struct UTextFuncs kTextUTF16Funcs = {
    sizeof(UTextFuncs),
    0,
    0,
    0,
    TextClone,
    TextNativeLength,
    TextUTF16Access,
    TextExtract,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    TextClose,
    nullptr,
    nullptr,
    nullptr,
};

UText* TextOpenUTF16(UText* text,
                     base::span<const UChar> string,
                     const UChar* prior_context,
                     int prior_context_length,
                     UErrorCode* status) {
  if (U_FAILURE(*status)) {
    return nullptr;
  }

  if (string.empty() ||
      string.size() >
          static_cast<size_t>(std::numeric_limits<int32_t>::max())) {
    *status = U_ILLEGAL_ARGUMENT_ERROR;
    return nullptr;
  }

  text = utext_setup(text, 0, status);
  if (U_FAILURE(*status)) {
    DCHECK(!text);
    return nullptr;
  }
  TextInit(text, &kTextUTF16Funcs, string.data(),
           base::checked_cast<unsigned>(string.size()), prior_context,
           prior_context_length);
  return text;
}

constexpr UText g_empty_text = UTEXT_INITIALIZER;

TextBreakIterator* WordBreakIterator(base::span<const LChar> string) {
  UErrorCode error_code = U_ZERO_ERROR;
  static TextBreakIterator* break_iter = nullptr;
  if (!break_iter) {
    break_iter = icu::BreakIterator::createWordInstance(
        icu::Locale(CurrentTextBreakLocaleID()), error_code);
    DCHECK(U_SUCCESS(error_code))
        << "ICU could not open a break iterator: " << u_errorName(error_code)
        << " (" << error_code << ")";
    if (!break_iter) {
      return nullptr;
    }
  }

  UTextWithBuffer text_local;
  text_local.text = g_empty_text;
  text_local.text.extraSize = sizeof(text_local.buffer);
  text_local.text.pExtra = text_local.buffer;

  UErrorCode open_status = U_ZERO_ERROR;
  UText* text = TextOpenLatin1(&text_local, string, nullptr, 0, &open_status);
  if (U_FAILURE(open_status)) {
    DLOG(ERROR) << "textOpenLatin1 failed with status " << open_status;
    return nullptr;
  }

  UErrorCode set_text_status = U_ZERO_ERROR;
  break_iter->setText(text, set_text_status);
  if (U_FAILURE(set_text_status)) {
    DLOG(ERROR) << "BreakIterator::seText failed with status "
                << set_text_status;
  }

  utext_close(text);

  return break_iter;
}

void SetText16(TextBreakIterator* iter, base::span<const UChar> string) {
  UErrorCode error_code = U_ZERO_ERROR;
  UText u_text = UTEXT_INITIALIZER;
  utext_openUChars(&u_text, string.data(), string.size(), &error_code);
  if (U_FAILURE(error_code)) {
    return;
  }
  iter->setText(&u_text, error_code);
}

TextBreakIterator* GetNonSharedCharacterBreakIterator() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(
      ThreadSpecific<std::unique_ptr<TextBreakIterator>>, thread_specific, ());

  std::unique_ptr<TextBreakIterator>& iterator = *thread_specific;

  if (!iterator) {
    ICUError error_code;
    iterator = base::WrapUnique(icu::BreakIterator::createCharacterInstance(
        icu::Locale(CurrentTextBreakLocaleID()), error_code));
    DCHECK(U_SUCCESS(error_code) && iterator)
        << "ICU could not open a break iterator: " << u_errorName(error_code)
        << " (" << error_code << ")";
  }

  DCHECK(iterator);
  return iterator.get();
}

}  // namespace

TextBreakIterator* WordBreakIterator(base::span<const UChar> string) {
  UErrorCode error_code = U_ZERO_ERROR;
  static TextBreakIterator* break_iter = nullptr;
  if (!break_iter) {
    break_iter = icu::BreakIterator::createWordInstance(
        icu::Locale(CurrentTextBreakLocaleID()), error_code);
    DCHECK(U_SUCCESS(error_code))
        << "ICU could not open a break iterator: " << u_errorName(error_code)
        << " (" << error_code << ")";
    if (!break_iter) {
      return nullptr;
    }
  }
  SetText16(break_iter, string);
  return break_iter;
}

TextBreakIterator* WordBreakIterator(const String& string,
                                     wtf_size_t start,
                                     wtf_size_t length) {
  if (string.empty()) {
    return nullptr;
  }
  if (string.Is8Bit()) {
    return WordBreakIterator(string.Span8().subspan(start, length));
  }
  return WordBreakIterator(string.Span16().subspan(start, length));
}

PooledBreakIterator AcquireLineBreakIterator(
    base::span<const LChar> string,
    const AtomicString& locale,
    const UChar* prior_context = nullptr,
    unsigned prior_context_length = 0) {
  PooledBreakIterator iterator{
      LineBreakIteratorPool::SharedPool().Take(locale)};
  if (!iterator) {
    return nullptr;
  }

  UTextWithBuffer text_local;
  text_local.text = g_empty_text;
  text_local.text.extraSize = sizeof(text_local.buffer);
  text_local.text.pExtra = text_local.buffer;

  UErrorCode open_status = U_ZERO_ERROR;
  UText* text = TextOpenLatin1(&text_local, string, prior_context,
                               prior_context_length, &open_status);
  if (U_FAILURE(open_status)) {
    DLOG(ERROR) << "textOpenLatin1 failed with status " << open_status;
    return nullptr;
  }

  UErrorCode set_text_status = U_ZERO_ERROR;
  iterator->setText(text, set_text_status);
  if (U_FAILURE(set_text_status)) {
    DLOG(ERROR) << "ubrk_setUText failed with status " << set_text_status;
    return nullptr;
  }

  utext_close(text);

  return iterator;
}

PooledBreakIterator AcquireLineBreakIterator(
    base::span<const UChar> string,
    const AtomicString& locale,
    const UChar* prior_context = nullptr,
    unsigned prior_context_length = 0) {
  PooledBreakIterator iterator{
      LineBreakIteratorPool::SharedPool().Take(locale)};
  if (!iterator) {
    return nullptr;
  }

  UText text_local = UTEXT_INITIALIZER;

  UErrorCode open_status = U_ZERO_ERROR;
  UText* text = TextOpenUTF16(&text_local, string, prior_context,
                              prior_context_length, &open_status);
  if (U_FAILURE(open_status)) {
    DLOG(ERROR) << "textOpenUTF16 failed with status " << open_status;
    return nullptr;
  }

  UErrorCode set_text_status = U_ZERO_ERROR;
  iterator->setText(text, set_text_status);
  if (U_FAILURE(set_text_status)) {
    DLOG(ERROR) << "ubrk_setUText failed with status " << set_text_status;
    return nullptr;
  }

  utext_close(text);

  return iterator;
}

PooledBreakIterator AcquireLineBreakIterator(StringView string,
                                             const AtomicString& locale) {
  if (string.Is8Bit()) {
    return AcquireLineBreakIterator(string.Span8(), locale);
  }
  return AcquireLineBreakIterator(string.Span16(), locale);
}

void ReturnBreakIteratorToPool::operator()(void* ptr) const {
  TextBreakIterator* iterator = static_cast<TextBreakIterator*>(ptr);
  DCHECK(iterator);
  LineBreakIteratorPool::SharedPool().Put(iterator);
}

NonSharedCharacterBreakIterator::NonSharedCharacterBreakIterator(
    const StringView& string)
    : is_8bit_(true),
      charaters8_(nullptr),
      offset_(0),
      length_(0),
      iterator_(nullptr) {
  if (string.empty()) {
    return;
  }

  is_8bit_ = string.Is8Bit();

  if (is_8bit_) {
    charaters8_ = string.Characters8();
    offset_ = 0;
    length_ = string.length();
    return;
  }

  CreateIteratorForBuffer(string.Span16());
}

NonSharedCharacterBreakIterator::NonSharedCharacterBreakIterator(
    base::span<const UChar> buffer)
    : is_8bit_(false),
      charaters8_(nullptr),
      offset_(0),
      length_(0),
      iterator_(nullptr) {
  CreateIteratorForBuffer(buffer);
}

void NonSharedCharacterBreakIterator::CreateIteratorForBuffer(
    base::span<const UChar> buffer) {
  iterator_ = GetNonSharedCharacterBreakIterator();
  SetText16(iterator_, buffer);
}

NonSharedCharacterBreakIterator::~NonSharedCharacterBreakIterator() {
  if (is_8bit_) {
    return;
  }
}

int NonSharedCharacterBreakIterator::Next() {
  if (!is_8bit_) {
    return iterator_->next();
  }

  if (offset_ >= length_) {
    return kTextBreakDone;
  }

  offset_ += ClusterLengthStartingAt(offset_);
  return offset_;
}

int NonSharedCharacterBreakIterator::Current() {
  if (!is_8bit_) {
    return iterator_->current();
  }
  return offset_;
}

bool NonSharedCharacterBreakIterator::IsBreak(int offset) const {
  if (!is_8bit_) {
    return iterator_->isBoundary(offset);
  }
  return !IsLFAfterCR(offset);
}

int NonSharedCharacterBreakIterator::Preceding(int offset) const {
  if (!is_8bit_) {
    return iterator_->preceding(offset);
  }
  if (offset <= 0) {
    return kTextBreakDone;
  }
  if (IsLFAfterCR(offset)) {
    return offset - 2;
  }
  return offset - 1;
}

int NonSharedCharacterBreakIterator::Following(int offset) const {
  if (!is_8bit_) {
    return iterator_->following(offset);
  }
  if (static_cast<unsigned>(offset) >= length_) {
    return kTextBreakDone;
  }
  return offset + ClusterLengthStartingAt(offset);
}

TextBreakIterator* SentenceBreakIterator(base::span<const UChar> string) {
  UErrorCode open_status = U_ZERO_ERROR;
  static TextBreakIterator* iterator = nullptr;
  if (!iterator) {
    iterator = icu::BreakIterator::createSentenceInstance(
        icu::Locale(CurrentTextBreakLocaleID()), open_status);
    DCHECK(U_SUCCESS(open_status))
        << "ICU could not open a break iterator: " << u_errorName(open_status)
        << " (" << open_status << ")";
    if (!iterator) {
      return nullptr;
    }
  }

  SetText16(iterator, string);
  return iterator;
}

bool IsWordTextBreak(TextBreakIterator* iterator) {
  icu::RuleBasedBreakIterator* rule_based_break_iterator =
      static_cast<icu::RuleBasedBreakIterator*>(iterator);
  int rule_status = rule_based_break_iterator->getRuleStatus();
  return rule_status != UBRK_WORD_NONE;
}

TextBreakIterator* CursorMovementIterator(base::span<const UChar> string) {
  // This rule set is based on character-break iterator rules of ICU 4.0
  // <http://source.icu-project.org/repos/icu/icu/tags/release-4-0/source/data/brkitr/char.txt>.
  // The major differences from the original ones are listed below:
  // * Replaced '[\p{Grapheme_Cluster_Break = SpacingMark}]' with
  //   '[\p{General_Category = Spacing Mark} - $Extend]' for ICU 3.8 or earlier;
  // * Removed rules that prevent a cursor from moving after prepend characters
  //   (Bug 24342);
  // * Added rules that prevent a cursor from moving after virama signs of Indic
  //   languages except Tamil (Bug 15790), and;
  // * Added rules that prevent a cursor from moving before Japanese half-width
  //   katakara voiced marks.
  // * Added rules for regional indicator symbols.
  static const char* const kRules =
      "$CR      = [\\p{Grapheme_Cluster_Break = CR}];"
      "$LF      = [\\p{Grapheme_Cluster_Break = LF}];"
      "$Control = [\\p{Grapheme_Cluster_Break = Control}];"
      "$VoiceMarks = [\\uFF9E\\uFF9F];"  // Japanese half-width katakana voiced
                                         // marks
      "$Extend  = [\\p{Grapheme_Cluster_Break = Extend} $VoiceMarks - [\\u0E30 "
      "\\u0E32 \\u0E45 \\u0EB0 \\u0EB2]];"
      "$SpacingMark = [[\\p{General_Category = Spacing Mark}] - $Extend];"
      "$L       = [\\p{Grapheme_Cluster_Break = L}];"
      "$V       = [\\p{Grapheme_Cluster_Break = V}];"
      "$T       = [\\p{Grapheme_Cluster_Break = T}];"
      "$LV      = [\\p{Grapheme_Cluster_Break = LV}];"
      "$LVT     = [\\p{Grapheme_Cluster_Break = LVT}];"
      "$Hin0    = [\\u0905-\\u0939];"          // Devanagari Letter A,...,Ha
      "$HinV    = \\u094D;"                    // Devanagari Sign Virama
      "$Hin1    = [\\u0915-\\u0939];"          // Devanagari Letter Ka,...,Ha
      "$Ben0    = [\\u0985-\\u09B9];"          // Bengali Letter A,...,Ha
      "$BenV    = \\u09CD;"                    // Bengali Sign Virama
      "$Ben1    = [\\u0995-\\u09B9];"          // Bengali Letter Ka,...,Ha
      "$Pan0    = [\\u0A05-\\u0A39];"          // Gurmukhi Letter A,...,Ha
      "$PanV    = \\u0A4D;"                    // Gurmukhi Sign Virama
      "$Pan1    = [\\u0A15-\\u0A39];"          // Gurmukhi Letter Ka,...,Ha
      "$Guj0    = [\\u0A85-\\u0AB9];"          // Gujarati Letter A,...,Ha
      "$GujV    = \\u0ACD;"                    // Gujarati Sign Virama
      "$Guj1    = [\\u0A95-\\u0AB9];"          // Gujarati Letter Ka,...,Ha
      "$Ori0    = [\\u0B05-\\u0B39];"          // Oriya Letter A,...,Ha
      "$OriV    = \\u0B4D;"                    // Oriya Sign Virama
      "$Ori1    = [\\u0B15-\\u0B39];"          // Oriya Letter Ka,...,Ha
      "$Tel0    = [\\u0C05-\\u0C39];"          // Telugu Letter A,...,Ha
      "$TelV    = \\u0C4D;"                    // Telugu Sign Virama
      "$Tel1    = [\\u0C14-\\u0C39];"          // Telugu Letter Ka,...,Ha
      "$Kan0    = [\\u0C85-\\u0CB9];"          // Kannada Letter A,...,Ha
      "$KanV    = \\u0CCD;"                    // Kannada Sign Virama
      "$Kan1    = [\\u0C95-\\u0CB9];"          // Kannada Letter A,...,Ha
      "$Mal0    = [\\u0D05-\\u0D39];"          // Malayalam Letter A,...,Ha
      "$MalV    = \\u0D4D;"                    // Malayalam Sign Virama
      "$Mal1    = [\\u0D15-\\u0D39];"          // Malayalam Letter A,...,Ha
      "$RI      = [\\U0001F1E6-\\U0001F1FF];"  // Emoji regional indicators
      "!!chain;"
      "!!forward;"
      "$CR $LF;"
      "$L ($L | $V | $LV | $LVT);"
      "($LV | $V) ($V | $T);"
      "($LVT | $T) $T;"
      "[^$Control $CR $LF] $Extend;"
      "[^$Control $CR $LF] $SpacingMark;"
      "$RI $RI / $RI;"
      "$RI $RI;"
      "$Hin0 $HinV $Hin1;"  // Devanagari Virama (forward)
      "$Ben0 $BenV $Ben1;"  // Bengali Virama (forward)
      "$Pan0 $PanV $Pan1;"  // Gurmukhi Virama (forward)
      "$Guj0 $GujV $Guj1;"  // Gujarati Virama (forward)
      "$Ori0 $OriV $Ori1;"  // Oriya Virama (forward)
      "$Tel0 $TelV $Tel1;"  // Telugu Virama (forward)
      "$Kan0 $KanV $Kan1;"  // Kannada Virama (forward)
      "$Mal0 $MalV $Mal1;"  // Malayalam Virama (forward)
      "!!reverse;"
      "$LF $CR;"
      "($L | $V | $LV | $LVT) $L;"
      "($V | $T) ($LV | $V);"
      "$T ($LVT | $T);"
      "$Extend      [^$Control $CR $LF];"
      "$SpacingMark [^$Control $CR $LF];"
      "$RI $RI / $RI $RI;"
      "$RI $RI;"
      "$Hin1 $HinV $Hin0;"  // Devanagari Virama (backward)
      "$Ben1 $BenV $Ben0;"  // Bengali Virama (backward)
      "$Pan1 $PanV $Pan0;"  // Gurmukhi Virama (backward)
      "$Guj1 $GujV $Guj0;"  // Gujarati Virama (backward)
      "$Ori1 $OriV $Ori0;"  // Gujarati Virama (backward)
      "$Tel1 $TelV $Tel0;"  // Telugu Virama (backward)
      "$Kan1 $KanV $Kan0;"  // Kannada Virama (backward)
      "$Mal1 $MalV $Mal0;"  // Malayalam Virama (backward)
      "!!safe_reverse;"
      "!!safe_forward;";

  if (string.empty()) {
    return nullptr;
  }

  DEFINE_THREAD_SAFE_STATIC_LOCAL(
      ThreadSpecific<std::unique_ptr<icu::RuleBasedBreakIterator>>,
      thread_specific, ());

  std::unique_ptr<icu::RuleBasedBreakIterator>& iterator = *thread_specific;

  if (!iterator) {
    UParseError parse_status;
    UErrorCode open_status = U_ZERO_ERROR;
    // break_rules is ASCII. Pick the most efficient UnicodeString ctor.
    iterator = std::make_unique<icu::RuleBasedBreakIterator>(
        icu::UnicodeString(kRules, -1, US_INV), parse_status, open_status);
    DCHECK(U_SUCCESS(open_status))
        << "ICU could not open a break iterator: " << u_errorName(open_status)
        << " (" << open_status << ")";
  }

  SetText16(iterator.get(), string);
  return iterator.get();
}

}  // namespace blink
```