Response:
Let's break down the thought process for analyzing this C++ code.

**1. Initial Understanding of the Request:**

The request asks for the functionality of `visible_units_sentence.cc`, its relationship to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, common errors, and debugging tips.

**2. Core Functionality Identification:**

* **Filename and Directory:** The name `visible_units_sentence.cc` in `blink/renderer/core/editing` strongly suggests it deals with sentence-level operations within the editing functionality of the Blink rendering engine.
* **Includes:** The included headers (`visible_units.h`, `editing_utilities.h`, `ephemeral_range.h`, `text_segments.h`, `visible_position.h`, `text_break_iterator.h`) confirm this. They point to concepts like visible positions, text ranges, and importantly, text segmentation (sentences).
* **Namespace:** The code is within the `blink` namespace, further confirming its part in the Blink engine.
* **Internal Helper Functions:**  The presence of functions like `PreviousSentencePositionInternal`, `StartOfSentenceInternal`, `EndOfSentenceInternal`, and `NextSentencePositionInternal` strongly indicates the core functionalities being implemented. The `Internal` suffix often suggests private helper methods.
* **Key Class: `TextSegments::Finder`:**  This abstract class, and the concrete anonymous classes inheriting from it, are crucial. They define the logic for finding sentence boundaries based on the `TextBreakIterator`.

**3. Detailed Analysis of Internal Functions:**

* **`PreviousSentencePositionInternal`:**
    * Uses `TextSegments::FindBoundaryBackward`.
    * Employs a `Finder` that uses `SentenceBreakIterator->preceding()` to find the start of the previous sentence.
    * Has a detail about skipping spaces between sentences, indicating a specific requirement or edge case.
* **`StartOfSentenceInternal`:**
    * Similar structure to `PreviousSentencePositionInternal`.
    * Uses `SentenceBreakIterator->preceding()`.
    * Handles the case where the beginning of the text is the start of a sentence.
* **`EndOfSentenceInternal`:**
    * Uses `TextSegments::FindBoundaryForward`.
    * Uses `SentenceBreakIterator->following()`.
    * Has logic for handling trailing spaces (`SentenceTrailingSpaceBehavior`), demonstrating flexibility in how sentence ends are defined.
* **`NextSentencePositionInternal`:**
    * Uses `TextSegments::FindBoundaryForward`.
    * Uses `SentenceBreakIterator->following()`.
    * Includes specific logic (`IsImplicitEndOfSentence`) to handle cases where a newline or block boundary signifies the end of a sentence, even if the `SentenceBreakIterator` doesn't explicitly identify it. The comments mentioning specific test files (`extend-by-sentence-002.html`, `move_forward_sentence_empty_line_break.html`) are invaluable for understanding these edge cases.

**4. Public Facing Functions:**

* The functions without the `Internal` suffix (e.g., `EndOfSentence`, `NextSentencePosition`, `StartOfSentencePosition`) are the public API for this module.
* They often come in overloaded versions taking `PositionInFlatTree`, `Position`, and `VisiblePosition` as arguments, providing flexibility for different levels of abstraction.
* Functions like `ExpandEndToSentenceBoundary` and `ExpandRangeToSentenceBoundary` build upon the core sentence boundary finding to manipulate text ranges. The comments with "TODO(editing-dev)" highlight potential areas for future improvement or known issues.

**5. Connecting to Web Technologies:**

* **JavaScript:**  The editing functionalities exposed by this C++ code are likely used by the browser's JavaScript engine to implement text selection, cursor movement, and potentially features like "smart select" or "word jump" that can be triggered by user interaction or JavaScript APIs.
* **HTML:** The code operates on the structure of the HTML document. Sentence boundaries are determined based on the text content within HTML elements. The examples in `NextSentencePositionInternal` (handling `<p>` and `<br>`) directly show this connection.
* **CSS:** While CSS doesn't directly define sentence boundaries, it affects how text is rendered and laid out. This code needs to be aware of how CSS might break lines and handle edge cases where visual breaks might not correspond to sentence breaks.

**6. Logical Reasoning (Assumptions and Outputs):**

For each internal function, consider a simple text snippet and a starting position, then manually trace how the `TextBreakIterator` would likely behave and what the resulting position would be.

* **Example for `StartOfSentenceInternal`:**
    * **Input:** Text: "Hello world. This is a test.", Position: at the 'w' of 'world'.
    * **Reasoning:** The `SentenceBreakIterator` will move backward from 'w' until it finds the beginning of the current sentence, which is before "Hello".
    * **Output:** Position: Before 'H'.

**7. Common Errors and Debugging:**

Think about scenarios where the code might produce unexpected results or where developers might misuse it.

* **Incorrect `SentenceTrailingSpaceBehavior`:** Not understanding when to include or omit trailing spaces can lead to selection or cursor movement issues.
* **Boundary Conditions:** Errors can occur at the beginning or end of the document, or when dealing with empty text nodes or specific HTML structures.
* **Interaction with other editing components:**  Misalignment with other parts of the editing system (e.g., handling of inline elements) could cause problems.

**8. User Interaction and Debugging Clues:**

Trace the steps a user might take that would eventually trigger the execution of this code.

* **Basic Text Editing:** Typing, selecting text with the mouse or keyboard.
* **Advanced Editing Features:** Using keyboard shortcuts for moving by sentence (Ctrl+Up/Down, Option+Up/Down on macOS), double-clicking or triple-clicking to select words or sentences.
* **JavaScript Interactions:**  JavaScript code manipulating the selection or content of an editable element.

**Self-Correction/Refinement During the Process:**

* Initially, one might focus too much on the specific implementation details of `TextBreakIterator`. It's important to step back and understand the *overall purpose* of the file first.
* The comments in the code, especially those mentioning test files, are extremely valuable and should be carefully considered. They often reveal specific edge cases or design decisions.
* Pay attention to the different levels of abstraction (e.g., `PositionInFlatTree` vs. `Position`). Understanding the conversions between these types is crucial.
* The "TODO" comments are a good indicator of potential issues or areas where the code might be incomplete or have known limitations.

By following this structured approach, you can effectively analyze and understand complex source code like this, even without extensive prior knowledge of the specific project. The key is to break down the problem into smaller, manageable parts and to leverage the available information (filenames, includes, comments, function names) to guide your understanding.
好的，让我们来分析一下 `blink/renderer/core/editing/visible_units_sentence.cc` 这个文件。

**文件功能概述:**

这个 C++ 源文件实现了在 Chromium Blink 渲染引擎中，与“句子”这种可见单元相关的操作。它提供了一系列函数，用于在文本内容中定位句子 boundaries（开始和结束），以及移动到下一个或上一个句子的起始位置。这些功能是富文本编辑器的基础，允许用户通过键盘快捷键或程序逻辑进行句子级别的文本操作，例如：

* **句子级别的光标移动:**  允许用户按 Ctrl+Up/Down (或其他快捷键) 将光标移动到上一个或下一个句子的开头或结尾。
* **句子级别的文本选择:**  允许用户快速选择整个句子。
* **文本分析和处理:**  程序可能需要将文本分割成句子进行进一步的分析或处理。

**与 JavaScript, HTML, CSS 的关系:**

这个文件中的 C++ 代码虽然不直接编写 JavaScript, HTML 或 CSS，但它为这些技术提供了底层的能力支撑。

* **JavaScript:**
    * **例 1：用户通过 JavaScript 获取或设置选区 (Selection API)**。当用户使用键盘快捷键（例如 Ctrl+Shift+Up/Down）扩展选区到句子边界时，浏览器内部会调用这个文件中实现的 C++ 函数来确定句子的范围，然后更新 JavaScript 可访问的 `Selection` 对象。
    * **例 2：JavaScript 编辑器库 (如 Quill, ProseMirror) 可能间接地依赖这些功能**。这些库通常会利用浏览器提供的底层编辑 API，而这些 API 又会调用 Blink 引擎中的相应 C++ 代码。
    * **假设输入与输出：**
        * **假设输入 (JavaScript):** 用户在可编辑 `div` 中按下 "Ctrl+Shift+Down" 快捷键，当前光标位置在一个句子的中间。
        * **内部调用:** JavaScript 触发浏览器事件，最终调用到 `visible_units_sentence.cc` 中的某个函数（例如 `EndOfSentence`）。
        * **假设输出 (C++):** 该函数返回当前光标所在句子的结束位置。
        * **结果 (JavaScript):** JavaScript 更新选区，使其扩展到该句子的末尾。

* **HTML:**
    * **HTML 结构决定了文本内容的组织方式，而这直接影响句子边界的判断**。例如，`<p>` 标签定义了一个段落，通常包含多个句子。`visible_units_sentence.cc` 中的代码需要遍历 HTML 结构来定位文本节点，并基于文本内容来识别句子。
    * **例：考虑以下 HTML 片段：**
      ```html
      <p>This is the first sentence. And this is the second.</p>
      ```
      当光标位于 "first" 这个词中间时，`StartOfSentencePosition` 函数会定位到 "This" 之前的位置，而 `EndOfSentencePosition` 会定位到 "sentence." 之后的位置。

* **CSS:**
    * **CSS 影响文本的渲染，但不直接决定句子边界**。CSS 可以控制换行、段落间距等，但逻辑上的句子分割是由标点符号等规则决定的，这部分逻辑在 `visible_units_sentence.cc` 中实现。
    * **需要注意的是，某些 CSS 属性可能会间接影响句子边界的“可见”效果**。例如，`word-break: break-all;` 可能会将一个很长的词语强行断开，但这并不会改变 `visible_units_sentence.cc` 中基于语言规则的句子分割逻辑。

**逻辑推理 (假设输入与输出):**

让我们以 `StartOfSentencePosition` 函数为例进行逻辑推理：

* **假设输入:** 光标位于以下文本中的 "world" 这个词的中间：
  ```
  Hello world. This is another sentence.
  ```
  在 Blink 内部，这会被表示为一个 `PositionInFlatTree` 对象，指向包含 "world" 的文本节点以及该节点内的偏移量。

* **内部处理 (基于代码):**
    1. `StartOfSentencePosition` 调用 `StartOfSentenceInternal`。
    2. `StartOfSentenceInternal` 创建一个匿名的 `Finder` 类，该类继承自 `TextSegments::Finder`。
    3. `Finder::Find` 方法被调用，传入包含 "Hello world. This is another sentence." 的字符串以及光标在 "world" 中的偏移量。
    4. `Find` 方法使用 `SentenceBreakIterator` 来查找给定偏移量之前的句子边界。
    5. `SentenceBreakIterator->preceding(offset)` 方法会回溯，找到句子的起始位置，即 "Hello" 之前的位置。
    6. `Find` 方法返回一个 `Position::Before(result)` 对象，其中 `result` 是句子起始位置的偏移量。

* **假设输出:**  `StartOfSentencePosition` 函数返回一个新的 `PositionInFlatTree` 对象，指向 "Hello" 之前的文本位置。

**用户或编程常见的使用错误:**

1. **不正确的假设句子边界的定义:**  开发者可能会错误地假设句子的结尾总是以句点 `.` 结尾。然而，问号 `?` 和感叹号 `!` 也可以作为句子结尾。`visible_units_sentence.cc` 中使用了 `SentenceBreakIterator`，这是一个考虑了多种语言规则的断句器，可以更准确地识别句子边界。

2. **在非文本节点上调用相关函数:**  这些函数设计用于处理文本内容。如果在非文本节点上调用，可能会导致错误或未定义的行为。

3. **忽略 `SentenceTrailingSpaceBehavior` 参数:**  `EndOfSentence` 函数有一个可选参数 `SentenceTrailingSpaceBehavior`，用于控制是否包含句子末尾的空格。如果开发者没有根据需求正确设置此参数，可能会导致选择或光标移动时包含或遗漏了末尾的空格。

**用户操作如何一步步到达这里 (调试线索):**

假设用户想要在文本编辑器中选中一个句子：

1. **用户操作:** 用户将光标放置在一个句子的中间，然后双击或三击该句子，或者使用键盘快捷键 (例如 Ctrl+Shift+Left/Right 或 Ctrl+Shift+Up/Down)。

2. **浏览器事件处理:** 浏览器接收到鼠标或键盘事件。

3. **事件分发和处理:**  浏览器将事件分发到相应的 HTML 元素。如果该元素是可编辑的 (例如，设置了 `contenteditable` 属性的 `div` 或 `textarea`)，浏览器会启动编辑相关的处理流程。

4. **Blink 渲染引擎介入:**  Blink 渲染引擎的事件处理代码会根据用户的操作类型，调用相应的编辑命令或 API。例如，双击可能会触发一个“选择单词”的操作，而三击或特定的键盘快捷键可能会触发一个“选择句子”的操作。

5. **调用 `VisibleUnits` 相关函数:**  执行“选择句子”操作的代码会调用 `blink/renderer/core/editing/visible_units.h` 中声明的函数，例如 `EndOfSentence` 和 `StartOfSentencePosition`。

6. **`visible_units_sentence.cc` 中的函数执行:**  最终，会调用到 `visible_units_sentence.cc` 中实现的具体函数，例如 `EndOfSentenceInternal` 和 `StartOfSentenceInternal`，来计算句子的起始和结束位置。

7. **更新选区:** 计算出的句子边界信息会被用于更新浏览器的文本选区 (Selection)。

**调试线索:**

* **断点:** 在 `visible_units_sentence.cc` 中设置断点，特别是 `StartOfSentenceInternal`、`EndOfSentenceInternal` 等函数，可以观察函数被调用的时机和参数。
* **日志输出:** 在关键路径上添加日志输出，打印输入的位置信息和计算出的句子边界，可以帮助理解代码的执行流程。
* **查看调用堆栈:** 当程序执行到 `visible_units_sentence.cc` 中的代码时，查看调用堆栈可以追溯用户操作是如何一步步触发到这里的。
* **测试用例:** Chromium 源码中通常会包含大量的测试用例，可以找到与句子选择相关的测试用例，分析其输入和预期输出，帮助理解代码的正确行为。 例如，你提到的注释中提到了 `"move_by_sentence_boundary.html"`，这是一个很好的调试入口。

总而言之，`visible_units_sentence.cc` 是 Blink 引擎中处理句子级别文本操作的关键组件，它为浏览器提供了理解和操作文本句子的能力，这对于富文本编辑器的各种功能至关重要。虽然它本身是 C++ 代码，但其功能直接影响着 JavaScript API 的行为以及用户在 HTML 页面上的编辑体验。

### 提示词
```
这是目录为blink/renderer/core/editing/visible_units_sentence.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009 Apple Inc. All rights
 * reserved.
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

// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/visible_units.h"

#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/text_segments.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/platform/text/text_break_iterator.h"

namespace blink {

namespace {

PositionInFlatTree PreviousSentencePositionInternal(
    const PositionInFlatTree& position) {
  class Finder final : public TextSegments::Finder {
    STACK_ALLOCATED();

   public:
    Position Find(const String text, unsigned passed_offset) final {
      DCHECK_LE(passed_offset, text.length());
      // "move_by_sentence_boundary.html" requires to skip a space characters
      // between sentences.
      const unsigned offset = FindLastNonSpaceCharacter(text, passed_offset);
      TextBreakIterator* iterator = SentenceBreakIterator(text.Span16());
      const int result = iterator->preceding(offset);
      if (result == kTextBreakDone)
        return Position();
      return Position::Before(result);
    }

   private:
    static unsigned FindLastNonSpaceCharacter(const String text,
                                              unsigned passed_offset) {
      for (unsigned offset = passed_offset; offset; --offset) {
        if (text[offset - 1] != ' ')
          return offset;
      }
      return 0;
    }
  } finder;
  return TextSegments::FindBoundaryBackward(position, &finder);
}

PositionInFlatTree StartOfSentenceInternal(const PositionInFlatTree& position) {
  class Finder final : public TextSegments::Finder {
    STACK_ALLOCATED();

   public:
    Position Find(const String text, unsigned passed_offset) final {
      DCHECK_LE(passed_offset, text.length());
      // "move_by_sentence_boundary.html" requires to skip a space characters
      // between sentences.
      const unsigned offset = FindNonSpaceCharacter(text, passed_offset);
      TextBreakIterator* iterator = SentenceBreakIterator(text.Span16());
      const int result = iterator->preceding(offset);
      if (result == kTextBreakDone) {
        if (text.length()) {
          // Block boundaries are also sentence boundaries.
          return Position::Before(0);
        }
        return Position();
      }
      return Position::Before(result);
    }

   private:
    static unsigned FindNonSpaceCharacter(const String text,
                                          unsigned passed_offset) {
      for (unsigned offset = passed_offset; offset; --offset) {
        if (text[offset - 1] != ' ')
          return offset;
      }
      return 0;
    }
  } finder;
  return TextSegments::FindBoundaryBackward(position, &finder);
}

PositionInFlatTree EndOfSentenceInternal(
    const PositionInFlatTree& position,
    SentenceTrailingSpaceBehavior space_behavior =
        SentenceTrailingSpaceBehavior::kIncludeSpace) {
  class Finder final : public TextSegments::Finder {
    STACK_ALLOCATED();

   public:
    explicit Finder(SentenceTrailingSpaceBehavior space_behavior)
        : space_behavior_(space_behavior) {}

    Position Find(const String text, unsigned passed_offset) final {
      DCHECK_LE(passed_offset, text.length());
      TextBreakIterator* iterator = SentenceBreakIterator(text.Span16());
      // "move_by_sentence_boundary.html" requires to skip a space characters
      // between sentences.
      const unsigned offset = FindNonSpaceCharacter(text, passed_offset);
      const int result = iterator->following(offset);
      if (result == kTextBreakDone) {
        if (text.length()) {
          // Block boundaries are also sentence boundaries.
          return Position::After(text.length());
        }
        return Position();
      }
      // If trailing space should be omitted, remove it if present.
      if (space_behavior_ == SentenceTrailingSpaceBehavior::kOmitSpace &&
          result != 0 && text[result - 1] == ' ') {
        return Position::After(result - 2);
      }
      return result == 0 ? Position::Before(0) : Position::After(result - 1);
    }

   private:
    static unsigned FindNonSpaceCharacter(const String text,
                                          unsigned passed_offset) {
      for (unsigned offset = passed_offset; offset < text.length(); ++offset) {
        if (text[offset] != ' ')
          return offset;
      }
      return text.length();
    }

    const SentenceTrailingSpaceBehavior space_behavior_;
  } finder(space_behavior);
  return TextSegments::FindBoundaryForward(position, &finder);
}

PositionInFlatTree NextSentencePositionInternal(
    const PositionInFlatTree& position) {
  class Finder final : public TextSegments::Finder {
    STACK_ALLOCATED();

   private:
    Position Find(const String text, unsigned offset) final {
      DCHECK_LE(offset, text.length());
      if (should_stop_finding_) {
        DCHECK_EQ(offset, 0u);
        return Position::Before(0);
      }
      if (IsImplicitEndOfSentence(text, offset)) {
        // Since each block is separated by newline == end of sentence code,
        // |Find()| will stop at start of next block rater than between blocks.
        should_stop_finding_ = true;
        return Position();
      }
      TextBreakIterator* it = SentenceBreakIterator(text.Span16());
      const int result = it->following(offset);
      if (result == kTextBreakDone)
        return Position();
      return result == 0 ? Position::Before(0) : Position::After(result - 1);
    }

    static bool IsImplicitEndOfSentence(const String text, unsigned offset) {
      DCHECK_LE(offset, text.length());
      if (offset == text.length()) {
        // "extend-by-sentence-002.html" reaches here.
        // Example: <p>abc|</p><p>def</p> => <p>abc</p><p>|def</p>
        return true;
      }
      if (offset + 1 == text.length() && text[offset] == '\n') {
        // "move_forward_sentence_empty_line_break.html" reaches here.
        // foo<div>|<br></div>bar -> foo<div><br></div>|bar
        return true;
      }
      return false;
    }

    bool should_stop_finding_ = false;
  } finder;
  return TextSegments::FindBoundaryForward(position, &finder);
}

}  // namespace

PositionInFlatTreeWithAffinity EndOfSentence(
    const PositionInFlatTree& start,
    SentenceTrailingSpaceBehavior space_behavior) {
  if (start.IsNull())
    return PositionInFlatTreeWithAffinity();
  const PositionInFlatTree result =
      EndOfSentenceInternal(start, space_behavior);
  return AdjustForwardPositionToAvoidCrossingEditingBoundaries(
      PositionInFlatTreeWithAffinity(result), start);
}

PositionWithAffinity EndOfSentence(
    const Position& start,
    SentenceTrailingSpaceBehavior space_behavior) {
  const PositionInFlatTreeWithAffinity result =
      EndOfSentence(ToPositionInFlatTree(start), space_behavior);
  return ToPositionInDOMTreeWithAffinity(result);
}

VisiblePosition EndOfSentence(const VisiblePosition& c,
                              SentenceTrailingSpaceBehavior space_behavior) {
  return CreateVisiblePosition(
      EndOfSentence(c.DeepEquivalent(), space_behavior));
}

VisiblePositionInFlatTree EndOfSentence(
    const VisiblePositionInFlatTree& c,
    SentenceTrailingSpaceBehavior space_behavior) {
  return CreateVisiblePosition(
      EndOfSentence(c.DeepEquivalent(), space_behavior));
}

EphemeralRange ExpandEndToSentenceBoundary(const EphemeralRange& range) {
  DCHECK(range.IsNotNull());
  const Position sentence_end =
      EndOfSentence(range.EndPosition()).GetPosition();
  // TODO(editing-dev): |sentenceEnd < range.endPosition()| is possible,
  // which would trigger a DCHECK in EphemeralRange's constructor if we return
  // it directly. However, this shouldn't happen and needs to be fixed.
  return EphemeralRange(
      range.StartPosition(),
      sentence_end.IsNotNull() && sentence_end > range.EndPosition()
          ? sentence_end
          : range.EndPosition());
}

EphemeralRange ExpandRangeToSentenceBoundary(const EphemeralRange& range) {
  DCHECK(range.IsNotNull());
  const Position sentence_start =
      StartOfSentencePosition(range.StartPosition());
  // TODO(editing-dev): |sentenceStart > range.startPosition()| is possible,
  // which would trigger a DCHECK in EphemeralRange's constructor if we return
  // it directly. However, this shouldn't happen and needs to be fixed.
  return ExpandEndToSentenceBoundary(EphemeralRange(
      sentence_start.IsNotNull() && sentence_start < range.StartPosition()
          ? sentence_start
          : range.StartPosition(),
      range.EndPosition()));
}

// ----

PositionInFlatTree NextSentencePosition(const PositionInFlatTree& start) {
  if (start.IsNull())
    return start;
  const PositionInFlatTree result = NextSentencePositionInternal(start);
  return AdjustForwardPositionToAvoidCrossingEditingBoundaries(
             PositionInFlatTreeWithAffinity(result), start)
      .GetPosition();
}

Position NextSentencePosition(const Position& start) {
  return ToPositionInDOMTree(NextSentencePosition(ToPositionInFlatTree(start)));
}

// ----

PositionInFlatTree PreviousSentencePosition(
    const PositionInFlatTree& position) {
  if (position.IsNull())
    return position;
  const PositionInFlatTree result = PreviousSentencePositionInternal(position);
  return AdjustBackwardPositionToAvoidCrossingEditingBoundaries(
             PositionInFlatTreeWithAffinity(result), position)
      .GetPosition();
}

Position PreviousSentencePosition(const Position& position) {
  return ToPositionInDOMTree(
      PreviousSentencePosition(ToPositionInFlatTree(position)));
}

// ----

PositionInFlatTree StartOfSentencePosition(const PositionInFlatTree& position) {
  if (position.IsNull())
    return position;
  const PositionInFlatTree result = StartOfSentenceInternal(position);
  return AdjustBackwardPositionToAvoidCrossingEditingBoundaries(
             PositionInFlatTreeWithAffinity(result), position)
      .GetPosition();
}

Position StartOfSentencePosition(const Position& position) {
  return ToPositionInDOMTree(
      StartOfSentencePosition(ToPositionInFlatTree(position)));
}

}  // namespace blink
```