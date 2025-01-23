Response:
Let's break down the thought process for analyzing this C++ code and fulfilling the prompt's requests.

**1. Initial Code Reading and Goal Identification:**

The first step is always to read through the code to get a general sense of its purpose. Keywords like "break iterator," "grapheme clusters," "line breaking," and the inclusion of Unicode headers (`<unicode/uchar.h>`) immediately suggest this code deals with text segmentation, specifically for purposes related to rendering and layout. The file path `blink/renderer/platform/text/` reinforces this connection to a rendering engine.

**2. Identifying Core Functionality:**

Next, I'd start dissecting the functions provided:

* **`NumGraphemeClusters(const String& string)`:**  The name is self-explanatory. It counts the number of grapheme clusters in a string. The special handling of 8-bit strings (Latin-1) for the simple CR LF case is a detail to note.
* **`GraphemesClusterList(const StringView& text, Vector<unsigned>* graphemes)`:** This function seems to populate a vector with the starting index of each grapheme cluster within the input string.
* **`LengthOfGraphemeCluster(const String& string, unsigned offset)`:**  This calculates the length (in code points) of a single grapheme cluster starting at a given offset. Again, the 8-bit CR LF optimization is present.
* **The block involving `kBreakAllLineBreakClassTable` and related functions (`LineBreakPropertyValue`, `ShouldBreakAfterBreakAll`):** This clearly deals with line breaking rules, specifically for the `word-break: break-all` CSS property. The table structure and the function names suggest a state machine or lookup-based approach.
* **`ShouldKeepAfterKeepAll(UChar last_ch, UChar ch, UChar next_ch)`:** This function appears to implement the logic for the `word-break: keep-all` CSS property, which prevents breaks in certain East Asian contexts.
* **The `LazyLineBreakIterator` class and its methods (especially `NextBreakablePosition`):** This class seems to be the primary mechanism for finding line break opportunities. The template structure, different `LineBreakType` enums (`kNormal`, `kBreakAll`, `kKeepAll`, `kBreakCharacter`, `kPhrase`), and the `BreakSpaceType` enum point to different line-breaking strategies. The "lazy" aspect likely refers to doing more complex break analysis only when necessary.

**3. Connecting to Web Technologies (JavaScript, HTML, CSS):**

This is where the prompt specifically asks for connections.

* **JavaScript:**  JavaScript often interacts with text through string manipulation and the Document Object Model (DOM). The grapheme cluster functions are relevant because JavaScript's string length and indexing operate on code points, not grapheme clusters. This can lead to discrepancies when visually processing text. Line breaking directly affects how text is laid out in web pages, which JavaScript can influence through DOM manipulation and CSS changes.
* **HTML:** HTML provides the structure for text content. The line-breaking logic determines how the browser will wrap lines of text within HTML elements.
* **CSS:**  CSS is the primary way to style text, and the `word-break` property is directly implemented by parts of this code. The different `LineBreakType` values clearly correspond to CSS `word-break` values.

**4. Illustrative Examples and Logical Reasoning:**

To solidify understanding, concrete examples are crucial.

* **Grapheme Clusters:**  Demonstrate how a single visual character might be represented by multiple code points (e.g., combining diacritics).
* **`word-break: break-all`:** Show how this CSS property forces breaks even within words.
* **`word-break: keep-all`:**  Illustrate how this prevents breaks in CJK text.
* **Line Breaking in General:** Demonstrate how different whitespace and punctuation can influence break points.

For logical reasoning, consider the different code paths within functions based on input. For example, the `NumGraphemeClusters` function has a fast path for simple 8-bit strings. The `NextBreakablePosition` function has multiple template specializations based on `LineBreakType` and `BreakSpaceType`.

**5. Identifying Potential User/Programming Errors:**

Think about common mistakes developers might make when working with text and layout:

* **Assuming code point length equals visual character length:**  This is a frequent error when dealing with Unicode.
* **Incorrectly implementing line breaking:**  Manually trying to break lines without using browser APIs or correct algorithms can lead to incorrect wrapping.
* **Misunderstanding `word-break` properties:**  Not knowing the subtle differences between `break-all`, `keep-all`, and `normal` can cause layout issues.

**6. Structuring the Answer:**

Finally, organize the information logically, using clear headings and bullet points to make the answer easy to read and understand. Start with a summary of the file's purpose, then detail the individual functions and their relationships to web technologies. Provide clear examples and address potential errors.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the grapheme functions are only used internally.
* **Correction:**  Realize that JavaScript's string handling differs, making these functions relevant for bridging that gap in understanding character length.
* **Initial thought:** Focus only on the `word-break` properties.
* **Correction:** Expand to include the broader concept of line breaking, how whitespace influences it, and how the browser uses these algorithms for layout.
* **Initial thought:**  Only provide technical descriptions.
* **Correction:** Add user-facing examples (HTML snippets, CSS rules) to make the explanations more concrete.

By following this kind of structured analysis and iterative refinement, one can effectively understand and explain the functionality of a complex piece of code like the `text_break_iterator.cc` file.
这个文件 `blink/renderer/platform/text/text_break_iterator.cc` 是 Chromium Blink 渲染引擎中的一个核心组件，其主要功能是**提供文本分段（Segmentation）的能力，用于确定文本中的断点（Break Points）**。 这些断点对于文本的渲染、编辑以及其他文本处理操作至关重要。

更具体地说，它提供了以下几个方面的功能：

1. **确定字形簇（Grapheme Clusters）的边界：**  字形簇是用户感知到的最小的文本单位，可能由一个或多个 Unicode 码点组成（例如，一个基本字符加上一个或多个组合字符）。 这个文件中的代码能够识别这些字形簇的边界。

2. **确定单词的边界：**  虽然代码中没有显式地包含单词边界迭代器，但它提供的基础能力可以被更高层次的模块用于实现单词边界的识别。

3. **确定行的断点（Line Breaking）：** 这是该文件最核心的功能之一。它实现了复杂的逻辑，用于确定在何处可以安全地将文本分成多行进行显示，考虑了各种因素，例如空格、标点符号、连字符、Unicode 行分隔符属性以及 CSS 的 `word-break` 和 `white-space` 属性的影响。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

该文件的功能与 Web 技术中的 JavaScript、HTML 和 CSS 都有着密切的关系：

* **HTML：**  HTML 定义了网页的结构和内容，其中包括文本内容。`text_break_iterator.cc` 负责处理这些文本内容，确定如何在浏览器中正确地渲染和显示这些文本，包括如何换行。
    * **举例：** 当浏览器解析以下 HTML 代码时：
      ```html
      <p>This is a long sentence that needs to be broken into multiple lines.</p>
      ```
      `text_break_iterator.cc` 会根据默认的行分隔规则（通常基于空格和标点符号）来确定 `p` 元素中的文本应该在哪里换行。

* **CSS：** CSS 用于控制网页的样式，其中与 `text_break_iterator.cc` 最相关的属性是控制文本换行的属性，例如：
    * **`word-break`：**  控制单词内部是否允许断行。该文件中的 `kBreakAllLineBreakClassTable` 以及 `ShouldBreakAfterBreakAll` 函数就直接实现了 `word-break: break-all` 的逻辑。
        * **举例：** 如果 CSS 设置为 `word-break: break-all;`，即使单词很长且没有空格，`text_break_iterator.cc` 也会强制在字符之间断行。假设输入字符串是 "Averylongword"，输出的断点可能在每个字符之后。
    * **`white-space`：**  控制如何处理空白符。不同的值会影响 `text_break_iterator.cc` 如何识别行的断点。例如，`white-space: nowrap;` 会阻止自动换行。
        * **举例：** 如果 CSS 设置为 `white-space: nowrap;`，即使文本内容很长，`text_break_iterator.cc` 也不会找到合适的断点进行换行，导致文本溢出容器。
    * **`overflow-wrap` (或 `word-wrap`)：**  当一个单词太长无法放入容器时，控制是否允许单词内部断行。
        * **举例：** 类似于 `word-break: break-word;` 的效果，当一个很长的单词超出容器宽度时，`text_break_iterator.cc` 会找到一个合适的断点（如果允许的话）在单词内部进行换行。

* **JavaScript：** JavaScript 可以动态地操作 DOM 结构和 CSS 样式，间接地影响 `text_break_iterator.cc` 的行为。此外，JavaScript 可以使用浏览器提供的 API（如 `Intl.Segmenter`）进行文本分段，这些 API 的底层实现可能与 `text_break_iterator.cc` 的功能相似或有交互。
    * **举例：**  JavaScript 可以动态修改元素的 `textContent`，当文本内容改变时，渲染引擎会重新调用 `text_break_iterator.cc` 来确定新的断点。
    * **举例：**  JavaScript 可以通过修改元素的 `style.wordBreak` 属性来改变文本的断行行为，这会影响 `text_break_iterator.cc` 中使用的断行规则。

**逻辑推理、假设输入与输出：**

**假设输入：** 字符串 "Hello world! This is a test."

**默认情况下（`word-break: normal` 或未指定）：**

* **功能：** 确定字形簇边界和行断点。
* **假设输出（行断点）：**  可能在 " " (空格) 处断行。
    * "Hello "
    * "world! "
    * "This is a "
    * "test."

**假设输入：** 字符串 "Thisisalongwordwithoutspaces."，CSS 设置为 `word-break: break-all;`

* **功能：** 强制在字符之间断行。
* **假设输出（行断点）：**
    * "T"
    * "h"
    * "i"
    * "s"
    * "i"
    * "s"
    * "a"
    * "l"
    * "o"
    * "n"
    * "g"
    * "w"
    * "o"
    * "r"
    * "d"
    * "w"
    * "i"
    * "t"
    * "h"
    * "o"
    * "u"
    * "t"
    * "s"
    * "p"
    * "a"
    * "c"
    * "e"
    * "s"
    * "."

**假设输入：**  包含组合字符的字符串 "नमस्ते" (印地语的 "你好")

* **功能：** 识别字形簇。
* **假设输出（字形簇边界）：**  "नमस्ते" 被视为一个字形簇，因为它是一个视觉上的字符单元。迭代器会返回字符串的开始和结束位置作为唯一的字形簇边界。

**用户或编程常见的使用错误：**

1. **错误地假设字符索引等同于字形簇索引：** 程序员可能会错误地使用基于字符索引的方法来处理文本，而没有考虑到组合字符的存在，导致文本处理出现错误。
    * **举例：**  如果 JavaScript 代码使用字符串的 `length` 属性来计算视觉上的字符数量，对于包含组合字符的文本，结果会不准确。`text_break_iterator.cc` 中的 `NumGraphemeClusters` 函数可以提供正确的字形簇数量。

2. **不理解或错误使用 CSS 的文本断行属性：** 开发者可能没有正确地设置 `word-break` 或 `white-space` 属性，导致文本的换行行为不符合预期。
    * **举例：**  希望长单词能在必要时断开，但忘记设置 `word-break: break-word;` 或 `overflow-wrap: break-word;`，导致文本溢出。

3. **在 JavaScript 中手动实现复杂的文本断行逻辑：** 开发者可能尝试自己编写 JavaScript 代码来实现文本断行，而没有利用浏览器内置的、由 `text_break_iterator.cc` 等组件提供的优化过的能力。这可能导致性能问题和对复杂 Unicode 规则处理不当。
    * **举例：**  手动查找空格或特定标点符号进行断行，而没有考虑到更复杂的 Unicode 行分隔符属性或 CSS 规则。

4. **忽略不同语言的断行规则：**  不同的语言有不同的断行习惯。`text_break_iterator.cc` 依赖于底层的 ICU 库来处理这些不同的规则。开发者如果假设所有语言的断行规则都相同，可能会导致显示问题。

总之，`blink/renderer/platform/text/text_break_iterator.cc` 是 Blink 引擎中负责文本分段和确定断点的关键组件，它直接影响着网页文本的渲染效果，并与 HTML 结构、CSS 样式以及 JavaScript 的文本处理能力紧密相关。理解其功能有助于开发者更好地理解和控制网页文本的布局和显示。

### 提示词
```
这是目录为blink/renderer/platform/text/text_break_iterator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * (C) 1999 Lars Knoll (knoll@kde.org)
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2010 Apple Inc. All rights
 * reserved.
 * Copyright (C) 2007-2009 Torch Mobile, Inc.
 * Copyright (C) 2011 Google Inc. All rights reserved.
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
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/text/text_break_iterator.h"

#include <unicode/uchar.h>
#include <unicode/uvernum.h>

#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/break_iterator_data_inline_header.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/ascii_ctype.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/unicode.h"

namespace blink {

unsigned NumGraphemeClusters(const String& string) {
  unsigned string_length = string.length();

  if (!string_length)
    return 0;

  // The only Latin-1 Extended Grapheme Cluster is CR LF
  if (string.Is8Bit() && !string.Contains('\r'))
    return string_length;

  NonSharedCharacterBreakIterator it(string);
  if (!it)
    return string_length;

  unsigned num = 0;
  while (it.Next() != kTextBreakDone)
    ++num;
  return num;
}

void GraphemesClusterList(const StringView& text, Vector<unsigned>* graphemes) {
  const unsigned length = text.length();
  graphemes->resize(length);
  if (!length)
    return;

  NonSharedCharacterBreakIterator it(text);
  int cursor_pos = it.Next();
  unsigned count = 0;
  unsigned pos = 0;
  while (cursor_pos >= 0) {
    for (; pos < static_cast<unsigned>(cursor_pos) && pos < length; ++pos) {
      (*graphemes)[pos] = count;
    }
    cursor_pos = it.Next();
    count++;
  }
}

unsigned LengthOfGraphemeCluster(const String& string, unsigned offset) {
  unsigned string_length = string.length();

  if (string_length - offset <= 1)
    return string_length - offset;

  // The only Latin-1 Extended Grapheme Cluster is CRLF.
  if (string.Is8Bit()) {
    auto* characters = string.Characters8();
    return 1 + (characters[offset] == '\r' && characters[offset + 1] == '\n');
  }

  NonSharedCharacterBreakIterator it(string);
  if (!it)
    return string_length - offset;

  if (it.Following(offset) == kTextBreakDone)
    return string_length - offset;
  return it.Current() - offset;
}

// Pack 8 bits into one byte
#define B(a, b, c, d, e, f, g, h)                                         \
  ((a) | ((b) << 1) | ((c) << 2) | ((d) << 3) | ((e) << 4) | ((f) << 5) | \
   ((g) << 6) | ((h) << 7))

#define BA_LB_COUNT U_LB_COUNT
// Line breaking table for CSS word-break: break-all. This table differs from
// asciiLineBreakTable in:
// - Indices are Line Breaking Classes defined in UAX#14 Unicode Line Breaking
//   Algorithm: http://unicode.org/reports/tr14/#DescriptionOfProperties
// - 1 indicates additional break opportunities. 0 indicates to fallback to
//   normal line break, not "prohibit break."
// clang-format off
static const unsigned char kBreakAllLineBreakClassTable[][BA_LB_COUNT / 8 + 1] = {
    // XX AI AL B2 BA BB BK CB    CL CM CR EX GL HY ID IN    IS LF NS NU OP PO PR QU    SA SG SP SY ZW NL WJ H2    H3 JL JT JV CP CJ HL RI    EB EM ZWJ AK AP AS VF VI
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // XX
    { B(0, 1, 1, 0, 1, 0, 0, 0), B(0, 0, 0, 0, 0, 1, 0, 0), B(0, 0, 0, 1, 1, 0, 1, 0), B(1, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 1, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // AI
    { B(0, 1, 1, 0, 1, 0, 0, 0), B(0, 0, 0, 0, 0, 1, 0, 0), B(0, 0, 0, 1, 1, 0, 1, 0), B(1, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 1, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // AL
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // B2
    { B(0, 1, 1, 0, 1, 0, 0, 0), B(0, 0, 0, 0, 0, 1, 0, 0), B(0, 0, 0, 1, 1, 0, 1, 0), B(1, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 1, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // BA
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // BB
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // BK
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // CB
    { B(0, 1, 1, 0, 1, 0, 0, 0), B(0, 0, 0, 0, 0, 1, 0, 0), B(0, 0, 0, 1, 0, 0, 1, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 1, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // CL
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // CM
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // CR
    { B(0, 1, 1, 0, 1, 0, 0, 0), B(0, 0, 0, 0, 0, 1, 0, 0), B(0, 0, 0, 1, 0, 1, 1, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 1, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // EX
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // GL
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 1, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // HY
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // ID
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // IN
    { B(0, 1, 1, 0, 1, 0, 0, 0), B(0, 0, 0, 0, 0, 1, 0, 0), B(0, 0, 0, 1, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 1, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // IS
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // LF
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // NS
    { B(0, 1, 1, 0, 1, 0, 0, 0), B(0, 0, 0, 0, 0, 1, 0, 0), B(0, 0, 0, 1, 1, 0, 1, 0), B(1, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 1, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // NU
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // OP
    { B(0, 1, 1, 0, 1, 0, 0, 0), B(0, 0, 0, 0, 0, 1, 0, 0), B(0, 0, 0, 1, 0, 1, 1, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 1, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // PO
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 1, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // PR
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // QU
    { B(0, 1, 1, 0, 1, 0, 0, 0), B(0, 0, 0, 0, 0, 1, 0, 0), B(0, 0, 0, 1, 1, 0, 1, 0), B(1, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 1, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // SA
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // SG
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // SP
    { B(0, 1, 1, 0, 1, 0, 0, 0), B(0, 0, 0, 0, 0, 1, 0, 0), B(0, 0, 0, 1, 1, 0, 1, 0), B(1, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 1, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // SY
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // ZW
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // NL
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // WJ
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // H2
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // H3
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // JL
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // JT
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // JV
    { B(0, 1, 1, 0, 1, 0, 0, 0), B(0, 0, 0, 0, 0, 1, 0, 0), B(0, 0, 0, 1, 0, 0, 1, 0), B(1, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 1, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // CP
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // CJ
    { B(0, 1, 1, 0, 1, 0, 0, 0), B(0, 0, 0, 0, 0, 1, 0, 0), B(0, 0, 0, 1, 1, 0, 1, 0), B(1, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 1, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // HL
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // RI
    // Added in ICU 58.
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // EB
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // EM
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // ZWJ
#if U_ICU_VERSION_MAJOR_NUM >= 74
    // Added in ICU 74. https://icu.unicode.org/download/74
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // AK
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // AP
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // AS
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // VF
    { B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0, 0, 0, 0, 0, 0, 0), B(0, 0,  0, 0, 0, 0, 0, 0) }, // VI
#endif  // U_ICU_VERSION_MAJOR_NUM >= 74
};
// clang-format on

#undef B

static_assert(std::size(kBreakAllLineBreakClassTable) == BA_LB_COUNT,
              "breakAllLineBreakClassTable should be consistent");

static inline ULineBreak LineBreakPropertyValue(UChar last_ch, UChar ch) {
  if (ch == '+')  // IE tailors '+' to AL-like class when break-all is enabled.
    return U_LB_ALPHABETIC;
  UChar32 ch32 = U16_IS_LEAD(last_ch) && U16_IS_TRAIL(ch)
                     ? U16_GET_SUPPLEMENTARY(last_ch, ch)
                     : ch;
  return static_cast<ULineBreak>(u_getIntPropertyValue(ch32, UCHAR_LINE_BREAK));
}

static inline bool ShouldBreakAfterBreakAll(ULineBreak last_line_break,
                                            ULineBreak line_break) {
  if (line_break >= 0 && line_break < BA_LB_COUNT && last_line_break >= 0 &&
      last_line_break < BA_LB_COUNT) {
    const unsigned char* table_row =
        kBreakAllLineBreakClassTable[last_line_break];
    return table_row[line_break / 8] & (1 << (line_break % 8));
  }
  return false;
}

// Computes if 'word-break:keep-all' should prevent line break.
// https://drafts.csswg.org/css-text-3/#valdef-word-break-keep-all
// The spec is not very verbose on how this should work. This logic prevents L/M
// general categories and complex line breaking since the spec says "except some
// south east aisans".
// https://github.com/w3c/csswg-drafts/issues/1619
static inline bool ShouldKeepAfterKeepAll(UChar last_ch,
                                          UChar ch,
                                          UChar next_ch) {
  UChar pre_ch = U_MASK(u_charType(ch)) & U_GC_M_MASK ? last_ch : ch;
  return U_MASK(u_charType(pre_ch)) & (U_GC_L_MASK | U_GC_N_MASK) &&
         !WTF::unicode::HasLineBreakingPropertyComplexContext(pre_ch) &&
         U_MASK(u_charType(next_ch)) & (U_GC_L_MASK | U_GC_N_MASK) &&
         !WTF::unicode::HasLineBreakingPropertyComplexContext(next_ch);
}

enum class FastBreakResult : uint8_t { kNoBreak, kCanBreak, kUnknown };

template <typename CharacterType>
struct LazyLineBreakIterator::Context {
  STACK_ALLOCATED();

 public:
  struct ContextChar {
    STACK_ALLOCATED();

   public:
    ContextChar() = default;
    explicit ContextChar(UChar ch) : ch(ch), is_space(IsBreakableSpace(ch)) {}

    UChar ch = 0;
    bool is_space = false;
  };

  Context(const CharacterType* str,
          unsigned len,
          unsigned start_offset,
          unsigned index) {
    DCHECK_GE(index, start_offset);
    CHECK_LE(index, len);
    if (index > start_offset) {
      last = ContextChar(str[index - 1]);
      if (index > start_offset + 1) {
        last_last_ch = str[index - 2];
      }
    }
  }

  bool Fetch(const CharacterType* str, unsigned len, unsigned index) {
    if (index >= len) [[unlikely]] {
      return false;
    }
    current = ContextChar(str[index]);
    return true;
  }

  void Advance(unsigned& index) {
    ++index;
    last_last_ch = last.ch;
    last = current;
  }

  FastBreakResult ShouldBreakFast(bool disable_soft_hyphen) const {
    const UChar last_ch = last.ch;
    const UChar ch = current.ch;
    if (last_ch < kFastLineBreakMinChar || ch < kFastLineBreakMinChar)
        [[unlikely]] {
      return FastBreakResult::kNoBreak;
    }

    // U+002D HYPHEN-MINUS may depend on the context.
    static_assert('-' >= kFastLineBreakMinChar);
    if (last_ch == '-') [[unlikely]] {
      if (ch <= 0x7F) {
        // Up to U+007F is fast-breakable. See `LineBreakData::FillAscii()`.
        if (IsASCIIDigit(ch)) {
          // Don't allow line breaking between '-' and a digit if the '-' may
          // mean a minus sign in the context, while allow breaking in
          // 'ABCD-1234' and '1234-5678' which may be in long URLs.
          return IsASCIIAlphanumeric(last_last_ch) ? FastBreakResult::kCanBreak
                                                   : FastBreakResult::kNoBreak;
        }
      } else if (RuntimeEnabledFeatures::BreakIteratorHyphenMinusEnabled()) {
        // Defer to the Unicode algorithm to take more context into account.
        return FastBreakResult::kUnknown;
      }
    }

    // If both characters are in the fast line break table, use it for enhanced
    // speed. For ASCII characters, it is also for compatibility. The table is
    // generated at the build time, see the `LineBreakData` class.
    if (last_ch <= kFastLineBreakMaxChar && ch <= kFastLineBreakMaxChar) {
      if (!GetFastLineBreak(last_ch, ch)) {
        return FastBreakResult::kNoBreak;
      }
      static_assert(kSoftHyphenCharacter <= kFastLineBreakMaxChar);
      if (disable_soft_hyphen && last_ch == kSoftHyphenCharacter) [[unlikely]] {
        return FastBreakResult::kNoBreak;
      }
      return FastBreakResult::kCanBreak;
    }

    // Otherwise defer to the Unicode algorithm.
    static_assert(kNoBreakSpaceCharacter <= kFastLineBreakMaxChar,
                  "Include NBSP for the performance.");
    return FastBreakResult::kUnknown;
  }

  ContextChar current;
  ContextChar last;
  CharacterType last_last_ch = 0;
};

template <typename CharacterType,
          LineBreakType line_break_type,
          BreakSpaceType break_space>
inline unsigned LazyLineBreakIterator::NextBreakablePosition(
    unsigned pos,
    const CharacterType* str,
    unsigned len) const {
  Context<CharacterType> context(str, len, start_offset_, pos);
  unsigned next_break = 0;
  ULineBreak last_line_break;
  if constexpr (line_break_type == LineBreakType::kBreakAll) {
    last_line_break =
        LineBreakPropertyValue(context.last_last_ch, context.last.ch);
  }
  for (unsigned i = pos; context.Fetch(str, len, i); context.Advance(i)) {
    switch (break_space) {
      case BreakSpaceType::kAfterSpaceRun:
        if (context.current.is_space) {
          continue;
        }
        if (context.last.is_space) {
          return i;
        }
        break;
      case BreakSpaceType::kAfterEverySpace:
        if (context.last.is_space ||
            Character::IsOtherSpaceSeparator(context.last.ch)) {
          return i;
        }
        if ((context.current.is_space ||
             Character::IsOtherSpaceSeparator(context.current.ch)) &&
            i + 1 < len) {
          return i + 1;
        }
        break;
    }

    const FastBreakResult fast_break_result =
        context.ShouldBreakFast(disable_soft_hyphen_);
    if (fast_break_result == FastBreakResult::kCanBreak) {
      return i;
    }

    if constexpr (line_break_type == LineBreakType::kBreakAll) {
      if (!U16_IS_LEAD(context.current.ch)) {
        ULineBreak line_break =
            LineBreakPropertyValue(context.last.ch, context.current.ch);
        if (ShouldBreakAfterBreakAll(last_line_break, line_break)) {
          return i > pos && U16_IS_TRAIL(context.current.ch) ? i - 1 : i;
        }
        if (line_break != U_LB_COMBINING_MARK) {
          last_line_break = line_break;
        }
      }
    } else if constexpr (line_break_type == LineBreakType::kKeepAll) {
      if (ShouldKeepAfterKeepAll(context.last_last_ch, context.last.ch,
                                 context.current.ch)) {
        // word-break:keep-all prevents breaks between East Asian ideographic.
        continue;
      }
    }

    if (fast_break_result == FastBreakResult::kNoBreak) {
      continue;
    }

    if (next_break < i || !next_break) {
      // Don't break if positioned at start of primary context.
      if (i <= start_offset_) [[unlikely]] {
        continue;
      }
      TextBreakIterator* break_iterator = GetIterator();
      if (!break_iterator) [[unlikely]] {
        continue;
      }
      next_break = i - 1;
      for (;;) {
        // Adjust the offset by |start_offset_| because |break_iterator|
        // has text after |start_offset_|.
        DCHECK_GE(next_break, start_offset_);
        const int32_t following = break_iterator->following(
            static_cast<int32_t>(next_break - start_offset_));
        if (following < 0) [[unlikely]] {
          DCHECK_EQ(following, icu::BreakIterator::DONE);
          next_break = len;
          break;
        }
        next_break = following + start_offset_;
        if (disable_soft_hyphen_ && next_break > 0 &&
            str[next_break - 1] == kSoftHyphenCharacter) [[unlikely]] {
          continue;
        }
        break;
      }
    }
    if (i == next_break && !context.last.is_space) {
      return i;
    }
  }

  return len;
}

template <typename CharacterType, LineBreakType lineBreakType>
inline unsigned LazyLineBreakIterator::NextBreakablePosition(
    unsigned pos,
    const CharacterType* str,
    unsigned len) const {
  switch (break_space_) {
    case BreakSpaceType::kAfterSpaceRun:
      return NextBreakablePosition<CharacterType, lineBreakType,
                                   BreakSpaceType::kAfterSpaceRun>(pos, str,
                                                                   len);
    case BreakSpaceType::kAfterEverySpace:
      return NextBreakablePosition<CharacterType, lineBreakType,
                                   BreakSpaceType::kAfterEverySpace>(pos, str,
                                                                     len);
  }
  NOTREACHED();
}

template <LineBreakType lineBreakType>
inline unsigned LazyLineBreakIterator::NextBreakablePosition(
    unsigned pos,
    unsigned len) const {
  if (string_.IsNull()) [[unlikely]] {
    return 0;
  }
  if (string_.Is8Bit()) {
    return NextBreakablePosition<LChar, lineBreakType>(
        pos, string_.Characters8(), len);
  }
  return NextBreakablePosition<UChar, lineBreakType>(
      pos, string_.Characters16(), len);
}

unsigned LazyLineBreakIterator::NextBreakablePositionBreakCharacter(
    unsigned pos) const {
  DCHECK_LE(start_offset_, string_.length());
  NonSharedCharacterBreakIterator iterator(StringView(string_, start_offset_));
  DCHECK_GE(pos, start_offset_);
  pos -= start_offset_;
  // `- 1` because the `Following()` returns the next opportunity after the
  // given `offset`.
  int32_t next =
      iterator.Following(static_cast<int32_t>(pos > 0 ? pos - 1 : 0));
  return next != kTextBreakDone ? next + start_offset_ : string_.length();
}

unsigned LazyLineBreakIterator::NextBreakablePosition(unsigned pos,
                                                      unsigned len) const {
  switch (break_type_) {
    case LineBreakType::kNormal:
    case LineBreakType::kPhrase:
      return NextBreakablePosition<LineBreakType::kNormal>(pos, len);
    case LineBreakType::kBreakAll:
      return NextBreakablePosition<LineBreakType::kBreakAll>(pos, len);
    case LineBreakType::kKeepAll:
      return NextBreakablePosition<LineBreakType::kKeepAll>(pos, len);
    case LineBreakType::kBreakCharacter:
      return NextBreakablePositionBreakCharacter(pos);
  }
  NOTREACHED();
}

unsigned LazyLineBreakIterator::NextBreakOpportunity(unsigned offset) const {
  DCHECK_LE(offset, string_.length());
  return NextBreakablePosition(offset, string_.length());
}

unsigned LazyLineBreakIterator::NextBreakOpportunity(unsigned offset,
                                                     unsigned len) const {
  DCHECK_LE(offset, len);
  DCHECK_LE(len, string_.length());
  return NextBreakablePosition(offset, len);
}

unsigned LazyLineBreakIterator::PreviousBreakOpportunity(unsigned offset,
                                                         unsigned min) const {
  unsigned pos = std::min(offset, string_.length());
  // +2 to ensure at least one code point is included.
  unsigned end = std::min(pos + 2, string_.length());
  while (pos > min) {
    unsigned next_break = NextBreakablePosition(pos, end);
    if (next_break == pos) {
      return next_break;
    }

    // There's no break opportunities at |pos| or after.
    end = pos;
    if (string_.Is8Bit())
      --pos;
    else
      U16_BACK_1(string_.Characters16(), 0, pos);
  }
  return min;
}

std::ostream& operator<<(std::ostream& ostream, LineBreakType line_break_type) {
  switch (line_break_type) {
    case LineBreakType::kNormal:
      return ostream << "Normal";
    case LineBreakType::kBreakAll:
      return ostream << "BreakAll";
    case LineBreakType::kBreakCharacter:
      return ostream << "BreakCharacter";
    case LineBreakType::kKeepAll:
      return ostream << "KeepAll";
    case LineBreakType::kPhrase:
      return ostream << "Phrase";
  }
  NOTREACHED() << "LineBreakType::" << static_cast<int>(line_break_type);
}

std::ostream& operator<<(std::ostream& ostream, BreakSpaceType break_space) {
  switch (break_space) {
    case BreakSpaceType::kAfterSpaceRun:
      return ostream << "kAfterSpaceRun";
    case BreakSpaceType::kAfterEverySpace:
      return ostream << "kAfterEverySpace";
  }
  NOTREACHED() << "BreakSpaceType::" << static_cast<int>(break_space);
}

}  // namespace blink
```