Response:
Let's break down the thought process for analyzing this C++ code and generating the comprehensive answer.

**1. Initial Understanding and Core Functionality:**

The first step is to understand the file's name: `text_searcher_icu.cc`. This immediately suggests its core purpose: searching for text using the ICU (International Components for Unicode) library. The `.cc` extension indicates it's a C++ source file within the Chromium/Blink project.

**2. Examining the Includes:**

The `#include` directives are crucial for identifying dependencies and understanding the context. We see includes like:

* `third_party/blink/renderer/core/editing/iterators/text_searcher_icu.h`:  Confirms this is the implementation of a class declared in the header.
* `<unicode/usearch.h>`: This is the core ICU search API. Knowing this is essential for understanding the underlying mechanism.
* Platform-related headers (`platform/text/...`): Suggests the code interacts with text handling functionalities specific to the platform Blink runs on.
* WTF headers (`wtf/...`):  Indicates usage of Blink's internal utility libraries (like `String`, `Vector`, allocators).

**3. Analyzing Key Classes and Functions:**

The core of the file is the `TextSearcherICU` class. We need to analyze its methods:

* **Constructors and Destructor:**  The presence of a static `AcquireSearcher` and `ReleaseSearcher` hints at a potential optimization or resource management strategy, likely involving reusing a single ICU searcher instance for performance. The `SearcherFactory` inner class reinforces this idea. The destructor calls `ReleaseSearcher`, cleaning up the resource.
* **`SetPattern`:** This method clearly sets the search string (the "pattern"). The handling of `FindOptions` suggests the search can be configured (case-sensitive, whole word). The Kana normalization part indicates special handling for Japanese characters.
* **`SetText`:** This method sets the text to be searched within.
* **`SetOffset`:**  Allows starting the search from a specific position.
* **`NextMatchResult` and `NextMatchResultInternal`:** These are the heart of the search functionality. `usearch_next` is the key ICU function being called here. The internal version seems to do the raw search, while the external one filters results.
* **`ShouldSkipCurrentMatch`:** This suggests the search can have additional filtering criteria, such as "whole word" matching.
* **`IsWholeWordMatch`:**  Implements the logic to determine if a match is a whole word.
* **`IsCorrectKanaMatch`:** Handles specific logic for matching Kana characters.
* **`SetCaseSensitivity`:**  Uses ICU's collation strength to control case sensitivity.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Now we need to link the C++ code to the user-facing web technologies.

* **JavaScript:**  Think about how JavaScript interacts with text searching. The `String.prototype.search()`, `String.prototype.match()`, and regular expressions (`RegExp`) are the primary mechanisms. This C++ code likely powers the underlying implementation of these JavaScript functions in the browser engine.
* **HTML:**  Consider HTML elements that involve text and searching. `<input type="search">` is the most direct example. The browser needs to efficiently search within the text entered by the user. Also, think about "find in page" functionality (Ctrl+F or Cmd+F), which searches within the entire rendered HTML content.
* **CSS:** While CSS doesn't directly initiate searches, properties like `::selection` can be affected by how text is matched. The underlying search mechanism influences what gets highlighted when a user selects text.

**5. Logic and Assumptions (Input/Output):**

Consider how the code might behave with specific inputs. Think about different scenarios:

* **Case-sensitive vs. case-insensitive:**  How does the `SetCaseSensitivity` function affect the outcome?
* **Whole word matching:**  How does `IsWholeWordMatch` work?  What happens if the pattern is part of a larger word?
* **Kana matching:** What are the specific rules for matching Kana characters?

Formulating input/output examples helps clarify the logic.

**6. Common User/Programming Errors:**

Think about mistakes developers or users might make when interacting with features powered by this code:

* **Incorrect regex usage in JavaScript:** If the JavaScript regex engine uses this code, incorrect regex patterns could lead to unexpected search results.
* **Case sensitivity issues:**  Users might expect case-insensitive searches when the default is case-sensitive, or vice-versa.
* **Whole word matching misunderstandings:**  Users might not understand what constitutes a "whole word."

**7. Debugging Clues (User Actions):**

Consider how a user's actions in the browser might lead to this code being executed:

* **Typing in a search bar:** This is a direct trigger.
* **Using "Find in Page" (Ctrl+F):** This is a common scenario.
* **JavaScript code calling search or match methods:**  Developers triggering the functionality programmatically.
* **Text selection:**  While not a direct search, the selection process might involve similar underlying text analysis.

**8. Structuring the Answer:**

Finally, organize the information logically with clear headings and examples. Start with the core functionality, then move to connections with web technologies, logic examples, common errors, and debugging tips. Use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this file just handles simple string searching.
* **Correction:**  The inclusion of ICU and the complexity of the `SetPattern` method (especially Kana normalization) suggest it handles more advanced text searching, including Unicode and locale considerations.
* **Initial thought:** CSS has no direct relation.
* **Correction:**  While not direct, the underlying text matching affects features like `::selection`, so there's an indirect connection.
* **Initial thought:** Focus only on direct function calls from JavaScript.
* **Correction:**  Consider the broader implications for user interactions within the browser, such as "Find in Page."

By following this iterative process of understanding, analyzing, connecting, and refining, we can arrive at a comprehensive and accurate explanation of the `text_searcher_icu.cc` file.
这个文件 `blink/renderer/core/editing/iterators/text_searcher_icu.cc` 是 Chromium Blink 渲染引擎中的一个源代码文件，其主要功能是**使用 ICU (International Components for Unicode) 库来实现文本搜索功能**。  ICU 是一个强大的、被广泛使用的库，用于提供 Unicode 和全球化支持。

以下是它的具体功能和与 JavaScript, HTML, CSS 的关系，以及逻辑推理、使用错误和调试线索的说明：

**功能:**

1. **文本搜索实现:**  该文件实现了 `TextSearcherICU` 类，这个类负责在给定的文本中查找指定的模式（pattern）。它利用 ICU 提供的 `UStringSearch` API 来进行高效的文本搜索。
2. **支持多种搜索选项:**  通过 `FindOptions` 结构，该类支持各种搜索选项，例如：
    * **区分大小写/不区分大小写:**  通过设置 ICU collation strength 来实现。
    * **全字匹配:**  检查匹配结果是否为完整的单词。
3. **Unicode 支持:**  由于使用了 ICU 库，该搜索器能够正确处理各种 Unicode 字符，包括不同语言的文字、特殊符号等。
4. **Kana 匹配优化:**  代码中包含对 Kana 字符（日语假名）的特殊处理，例如进行 NFC 规范化，以提高 Kana 字符的匹配准确性。
5. **性能优化 (SearcherFactory):**  为了提高性能，代码中使用了 `SearcherFactory` 内部类来管理 `UStringSearch` 对象的创建和销毁。可能采用了一种池化的策略，复用 `UStringSearch` 对象，避免频繁创建和销毁带来的开销。

**与 JavaScript, HTML, CSS 的关系:**

这个 C++ 文件直接位于 Blink 渲染引擎的底层，它为浏览器提供核心的文本搜索能力。  当 JavaScript 代码需要进行文本搜索时，最终会调用到类似这样的底层实现。

* **JavaScript:**
    * **`String.prototype.search()`， `String.prototype.match()`，以及正则表达式:**  当 JavaScript 代码中使用这些方法在字符串中查找模式时，Blink 引擎会调用底层的文本搜索实现。`TextSearcherICU` 很可能就是这些功能的幕后英雄。
    * **`window.find()` (查找功能):**  浏览器提供的“查找页面”功能（通常通过 Ctrl+F 或 Cmd+F 触发）在底层也会使用类似的文本搜索机制。

    **举例说明:**
    ```javascript
    const text = "This is a test string with Test in it.";
    const pattern = "test";

    // 使用 String.prototype.search()
    const index = text.search(pattern); // JavaScript 会调用底层搜索功能

    // 使用 String.prototype.match()
    const matches = text.match(pattern); // JavaScript 也会调用底层搜索功能

    // 不区分大小写搜索
    const regex = /test/i;
    const indexIgnoreCase = text.search(regex);

    // 全字匹配 (JavaScript 正则表达式可以实现，但底层可能需要更精细的处理)
    const regexWholeWord = /\btest\b/;
    const matchesWholeWord = text.match(regexWholeWord);
    ```
    在这些 JavaScript 例子中，当引擎执行 `search()` 或 `match()` 时，如果涉及到复杂的 Unicode 字符处理或者特定的搜索选项（如不区分大小写），很可能会依赖于 `TextSearcherICU` 这样的底层实现。

* **HTML:**
    * **`<input type="search">` 元素:** 当用户在搜索输入框中输入文本并提交时，浏览器需要搜索相关的结果。这个过程也会用到文本搜索功能。
    * **内容查找:**  浏览器需要能够在渲染的 HTML 内容中查找用户指定的文本。

    **举例说明:**
    当用户在一个网页的搜索框中输入 "apple" 并点击搜索按钮后，浏览器会获取该输入，并利用底层的文本搜索能力（很可能包括 `TextSearcherICU`）在相关的文档或数据中查找匹配的项。

* **CSS:**
    * **`::selection` 伪元素:**  当用户在网页上选择文本时，浏览器需要确定哪些文本被选中。这涉及到对文本内容的分析，虽然不是直接的搜索，但与文本处理相关。
    * **`content` 属性和文本生成:**  CSS 可能会生成一些文本内容，这些文本内容后续可能会被搜索。

    **举例说明:**
    用户在网页上拖动鼠标选择一段文字时，浏览器需要精确地确定选择的起始和结束位置，这可能需要底层的文本处理和定位能力，与 `TextSearcherICU` 提供的功能在某种程度上是相关的。

**逻辑推理 (假设输入与输出):**

假设我们有以下输入：

* **文本 (text):** `"你好世界，Hello World!"`
* **模式 (pattern):** `"世界"`
* **搜索选项 (options):**  默认选项 (区分大小写，非全字匹配)

**输出:**  `MatchResultICU` 可能会包含以下信息：
* `start`:  2 ( "世界" 在文本中的起始位置，索引从 0 开始)
* `length`: 2 ( "世界" 的长度)

**假设输入与输出 (考虑全字匹配):**

* **文本 (text):** `"这是一个测试案例 test"`
* **模式 (pattern):** `"test"`
* **搜索选项 (options):** 全字匹配

**输出:** `MatchResultICU` 可能会包含以下信息：
* `start`: 7
* `length`: 4

**假设输入与输出 (考虑不区分大小写):**

* **文本 (text):** `"ABCDefg"`
* **模式 (pattern):** `"abc"`
* **搜索选项 (options):** 不区分大小写

**输出:** `MatchResultICU` 可能会包含以下信息：
* `start`: 0
* `length`: 3

**涉及用户或者编程常见的使用错误:**

1. **未正确设置搜索模式或文本:**  如果在调用搜索方法之前没有使用 `SetPattern` 或 `SetText` 设置搜索模式和目标文本，会导致搜索行为不确定或失败。
    * **举例:**  JavaScript 代码中，可能忘记在调用 `search()` 前指定要搜索的字符串。
2. **对全字匹配的误解:**  用户或开发者可能对“全字匹配”的定义有误解。例如，认为 "test" 可以匹配 "testing" 中的 "test"，但实际上全字匹配会要求 "test" 前后都是非字母数字字符或字符串的开头/结尾。
    * **举例:**  在网页的查找功能中，用户勾选了“全字匹配”，但输入的关键词出现在一个单词的中间，导致找不到结果。
3. **忽略大小写设置:**  在需要区分大小写的场景下，没有正确设置搜索选项，导致匹配到不符合预期的结果，反之亦然。
    * **举例:**  JavaScript 正则表达式中忘记添加 `i` 标志进行不区分大小写搜索。
4. **Unicode 字符处理错误:**  对于包含复杂 Unicode 字符的文本，如果底层搜索器没有正确处理，可能会导致匹配失败或不准确。
    * **举例:**  搜索包含组合字符或特殊标点符号的文本时，由于编码或比较方式的问题，可能无法找到预期的结果。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入 URL 并访问网页。**
2. **网页加载完成，包含文本内容。**
3. **用户按下 `Ctrl+F` (或 `Cmd+F` 在 macOS 上) 打开浏览器的查找功能。**
4. **用户在查找框中输入要搜索的文本 (例如 "example")。**
5. **浏览器接收用户输入，并将搜索请求传递给 Blink 渲染引擎。**
6. **Blink 引擎需要执行文本搜索操作。**
7. **JavaScript 代码可能会被调用来处理查找请求，或者浏览器直接调用底层的 C++ 搜索接口。**
8. **最终，`TextSearcherICU` 类及其相关方法会被调用，传入要搜索的文本和模式。**
9. **`usearch_open`, `usearch_setPattern`, `usearch_setText`, `usearch_next` 等 ICU 函数会被调用来执行实际的搜索操作。**
10. **匹配结果会被封装并返回给上层调用者 (JavaScript 或浏览器 UI)。**
11. **浏览器将匹配到的文本在页面上高亮显示，或显示查找结果的数量。**

**调试线索:**

* **如果用户反馈查找功能异常 (例如找不到应该存在的文本)，开发者可以检查以下几点：**
    * **搜索模式是否正确传递:** 检查传递给 `SetPattern` 的字符串是否与用户输入的完全一致。
    * **搜索选项是否正确设置:** 检查 `FindOptions` 是否按照预期设置了区分大小写、全字匹配等选项。
    * **文本内容是否正确:** 确认要搜索的文本内容是否已经被正确加载和传递给 `SetText`。
    * **ICU 库是否正常工作:**  检查 ICU 库的版本和配置，确保其能够正确处理相关的 Unicode 字符。
    * **Kana 匹配逻辑:** 如果搜索涉及日语文本，需要特别关注 Kana 匹配的逻辑是否正确。
* **可以使用断点调试工具，在 `TextSearcherICU` 的关键方法 (如 `NextMatchResultInternal`) 中设置断点，查看搜索过程中的变量值，例如 `match_start`，`result.length` 等，以定位问题。**
* **查看 Chromium 的日志输出，可能会有与文本搜索相关的错误或警告信息。**

总而言之，`blink/renderer/core/editing/iterators/text_searcher_icu.cc` 文件是 Blink 渲染引擎中一个关键的组成部分，它利用 ICU 库提供了强大的文本搜索功能，支撑着浏览器中各种与文本查找相关的特性。 理解其功能和与前端技术的联系，有助于开发者更好地理解浏览器的工作原理，并在遇到相关问题时进行调试和解决。

### 提示词
```
这是目录为blink/renderer/core/editing/iterators/text_searcher_icu.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2012 Apple Inc. All
 * rights reserved.
 * Copyright (C) 2005 Alexey Proskuryakov.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/editing/iterators/text_searcher_icu.h"

#include <unicode/usearch.h>

#include "third_party/blink/renderer/platform/text/character.h"
#include "third_party/blink/renderer/platform/text/text_boundaries.h"
#include "third_party/blink/renderer/platform/text/text_break_iterator_internal_icu.h"
#include "third_party/blink/renderer/platform/text/unicode_utilities.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/utf16.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

UStringSearch* CreateSearcher() {
  // Provide a non-empty pattern and non-empty text so usearch_open will not
  // fail, but it doesn't matter exactly what it is, since we don't perform any
  // searches without setting both the pattern and the text.
  UErrorCode status = U_ZERO_ERROR;
  String search_collator_name =
      CurrentSearchLocaleID() + String("@collation=search");
  UStringSearch* searcher =
      usearch_open(&kNewlineCharacter, 1, &kNewlineCharacter, 1,
                   search_collator_name.Utf8().c_str(), nullptr, &status);
  DCHECK(U_SUCCESS(status)) << status;
  return searcher;
}

class SearcherFactory {
  STACK_ALLOCATED();

 public:
  SearcherFactory(const SearcherFactory&) = delete;
  SearcherFactory& operator=(const SearcherFactory&) = delete;

  // Returns the global instance. If this is called again before calling
  // ReleaseSearcher(), this function crashes.
  static UStringSearch* AcquireSearcher() {
    Instance().Lock();
    return Instance().searcher_;
  }
  // Creates a normal instance. We may create instances multiple times with
  // this function.  A returned pointer should be destructed by
  // ReleaseSearcher().
  static UStringSearch* CreateLocal() { return CreateSearcher(); }

  static void ReleaseSearcher(UStringSearch* searcher) {
    if (searcher == Instance().searcher_) {
      // Leave the static object pointing to valid strings (pattern=target,
      // text=buffer). Otherwise, usearch_reset() will results in
      // 'use-after-free' error.
      UErrorCode status = U_ZERO_ERROR;
      usearch_setPattern(searcher, &kNewlineCharacter, 1, &status);
      DCHECK(U_SUCCESS(status));
      usearch_setText(searcher, &kNewlineCharacter, 1, &status);
      DCHECK(U_SUCCESS(status));
      Instance().Unlock();
    } else {
      usearch_close(searcher);
    }
  }

 private:
  static SearcherFactory& Instance() {
    static SearcherFactory factory(CreateSearcher());
    return factory;
  }

  explicit SearcherFactory(UStringSearch* searcher) : searcher_(searcher) {}

  void Lock() {
#if DCHECK_IS_ON()
    DCHECK(!locked_);
    locked_ = true;
#endif
  }

  void Unlock() {
#if DCHECK_IS_ON()
    DCHECK(locked_);
    locked_ = false;
#endif
  }

  UStringSearch* const searcher_ = nullptr;

#if DCHECK_IS_ON()
  bool locked_ = false;
#endif
};

}  // namespace

static bool IsWholeWordMatch(base::span<const UChar> text,
                             const MatchResultICU& result) {
  const wtf_size_t result_end = result.start + result.length;
  DCHECK_LE(result_end, text.size());
  UChar32 first_character = CodePointAt(text, result.start);

  // Chinese and Japanese lack word boundary marks, and there is no clear
  // agreement on what constitutes a word, so treat the position before any CJK
  // character as a word start.
  if (Character::IsCJKIdeographOrSymbol(first_character))
    return true;

  wtf_size_t word_break_search_start = result_end;
  while (word_break_search_start > result.start) {
    word_break_search_start =
        FindNextWordBackward(text, word_break_search_start);
  }
  if (word_break_search_start != result.start)
    return false;
  return result_end == static_cast<wtf_size_t>(
                           FindWordEndBoundary(text, word_break_search_start));
}

// Grab the single global searcher.
TextSearcherICU::TextSearcherICU()
    : searcher_(SearcherFactory::AcquireSearcher()) {}

TextSearcherICU::TextSearcherICU(ConstructLocalTag)
    : searcher_(SearcherFactory::CreateLocal()) {}

TextSearcherICU::~TextSearcherICU() {
  SearcherFactory::ReleaseSearcher(searcher_);
}

void TextSearcherICU::SetPattern(const StringView& pattern,
                                 FindOptions options) {
  DCHECK_GT(pattern.length(), 0u);
  options_ = options;
  SetCaseSensitivity(!options.IsCaseInsensitive());
  SetPattern(pattern.Span16());
  if (ContainsKanaLetters(pattern.ToString())) {
    normalized_search_text_ = NormalizeCharactersIntoNfc(pattern.Span16());
  }
}

void TextSearcherICU::SetText(base::span<const UChar> text) {
  UErrorCode status = U_ZERO_ERROR;
  usearch_setText(searcher_, text.data(), text.size(), &status);
  DCHECK_EQ(status, U_ZERO_ERROR);
  text_length_ = text.size();
}

void TextSearcherICU::SetOffset(wtf_size_t offset) {
  UErrorCode status = U_ZERO_ERROR;
  usearch_setOffset(searcher_, offset, &status);
  DCHECK_EQ(status, U_ZERO_ERROR);
}

std::optional<MatchResultICU> TextSearcherICU::NextMatchResult() {
  while (std::optional<MatchResultICU> result = NextMatchResultInternal()) {
    if (!ShouldSkipCurrentMatch(*result)) {
      return result;
    }
  }
  return std::nullopt;
}

std::optional<MatchResultICU> TextSearcherICU::NextMatchResultInternal() {
  UErrorCode status = U_ZERO_ERROR;
  const int match_start = usearch_next(searcher_, &status);
  DCHECK(U_SUCCESS(status));

  // TODO(iceman): It is possible to use |usearch_getText| function
  // to retrieve text length and not store it explicitly.
  if (!(match_start >= 0 &&
        static_cast<wtf_size_t>(match_start) < text_length_)) {
    DCHECK_EQ(match_start, USEARCH_DONE);
    return std::nullopt;
  }

  MatchResultICU result = {
      static_cast<wtf_size_t>(match_start),
      base::checked_cast<wtf_size_t>(usearch_getMatchedLength(searcher_))};
  // Might be possible to get zero-length result with some Unicode characters
  // that shouldn't actually match but is matched by ICU such as \u0080.
  if (result.length == 0u) {
    return std::nullopt;
  }
  return result;
}

bool TextSearcherICU::ShouldSkipCurrentMatch(
    const MatchResultICU& result) const {
  int32_t text_length_i32;
  const UChar* text = usearch_getText(searcher_, &text_length_i32);
  unsigned text_length = text_length_i32;
  DCHECK_LE(result.start + result.length, text_length);
  DCHECK_GT(result.length, 0u);
  // SAFETY: Making a span same as the SetText() argument.
  auto text_span = UNSAFE_BUFFERS(base::span<const UChar>(text, text_length));

  if (!normalized_search_text_.empty() &&
      !IsCorrectKanaMatch(text_span, result)) {
    return true;
  }

  return options_.IsWholeWord() && !IsWholeWordMatch(text_span, result);
}

bool TextSearcherICU::IsCorrectKanaMatch(base::span<const UChar> text,
                                         const MatchResultICU& result) const {
  Vector<UChar> normalized_match =
      NormalizeCharactersIntoNfc(text.subspan(result.start, result.length));
  return CheckOnlyKanaLettersInStrings(base::span(normalized_search_text_),
                                       base::span(normalized_match));
}

void TextSearcherICU::SetPattern(base::span<const UChar> pattern) {
  UErrorCode status = U_ZERO_ERROR;
  usearch_setPattern(searcher_, pattern.data(), pattern.size(), &status);
  DCHECK(U_SUCCESS(status));
}

void TextSearcherICU::SetCaseSensitivity(bool case_sensitive) {
  const UCollationStrength strength =
      case_sensitive ? UCOL_TERTIARY : UCOL_PRIMARY;

  UCollator* const collator = usearch_getCollator(searcher_);
  if (ucol_getStrength(collator) == strength)
    return;

  ucol_setStrength(collator, strength);
  usearch_reset(searcher_);
}

}  // namespace blink
```