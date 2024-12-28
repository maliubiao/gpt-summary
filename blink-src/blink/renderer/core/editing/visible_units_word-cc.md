Response:
Let's break down the thought process for analyzing the `visible_units_word.cc` file.

**1. Initial Understanding - What is the Core Purpose?**

The filename `visible_units_word.cc` immediately suggests it deals with word boundaries and how they are perceived or handled within the Blink rendering engine. The directory `blink/renderer/core/editing` further reinforces that this is related to text editing functionalities.

**2. Deconstructing the File - Key Components:**

* **Copyright and License:** Standard boilerplate, but important for legal reasons and understanding the code's origin.
* **Includes:**  A goldmine of information. Look at the included headers:
    * `visible_units.h`:  This file is part of a larger system dealing with "visible units" (words, lines, etc.).
    * `editing_utilities.h`: Likely contains helper functions for editing operations.
    * `ephemeral_range.h`:  Deals with temporary text ranges, crucial for editing.
    * `iterators/text_iterator.h`:  Provides a way to traverse text content.
    * `text_offset_mapping.h`:  Important for managing the mapping between positions and text offsets, especially when dealing with inline elements.
    * `text_segments.h`:  Likely a mechanism for breaking down text into meaningful segments for analysis.
    * `visible_position.h`:  Represents a visible position in the rendered document.
    * `layout/layout_block_flow.h`:  Deals with the layout of block-level elements, potentially relevant for line breaks and word wrapping.
    * `platform/instrumentation/tracing/trace_event.h`: Used for performance analysis and debugging.
    * `platform/text/character.h`, `text_boundaries.h`, `text_break_iterator.h`:  Fundamental for understanding character properties and performing word breaking.

* **Namespace:** `blink`. Indicates this is part of the Blink rendering engine.
* **Anonymous Namespace:**  The `namespace { ... }` block contains helper functions that are internal to this compilation unit. This is good practice for encapsulation.

* **Key Functions:**  Start identifying the important functions:
    * `EndOfWordPositionInternal`, `NextWordPositionInternal`, `PreviousWordPositionInternal`, `StartOfWordPositionInternal`: These strongly suggest the core functionality is about finding the start and end of words in different directions.
    * `EndOfWordPosition`, `NextWordPosition`, `PreviousWordPosition`, `StartOfWordPosition`:  These look like the public interfaces, potentially wrapping the "Internal" versions.
    * `MiddleOfWordPosition`:  Calculates the middle position within a word.
    * `IsWordBreak`:  A utility function to determine if a character constitutes a word break.

**3. Analyzing Function Logic (High-Level):**

* **Word Boundary Finding:** The "Internal" functions use a `TextSegments::Finder` class. This hints at a pattern: iterate through text segments and use a custom logic (the `Finder`) to determine word boundaries. The `WordBreakIterator` from ICU (International Components for Unicode) is explicitly used, which is a standard way to handle word breaking across different languages and scripts.
* **Platform Differences:** The `PlatformWordBehavior` parameter in `NextWordPositionInternal` suggests platform-specific word breaking behavior (e.g., handling of spaces).
* **Edge Cases:**  Look for handling of empty strings, beginning/end of text, line breaks, and punctuation. The code explicitly handles these.
* **`PositionInFlatTree` vs. `Position`:**  The code uses both `PositionInFlatTree` (representing a position in the flat tree structure used internally by Blink) and `Position` (representing a DOM tree position). Functions often convert between these.
* **`AdjustForwardPositionToAvoidCrossingEditingBoundaries` and `AdjustBackwardPositionToAvoidCrossingEditingBoundaries`:** These functions suggest that word boundary calculations need to respect editing boundaries (e.g., within contenteditable regions).

**4. Connecting to Web Technologies (HTML, CSS, JavaScript):**

* **HTML:** The code directly operates on the text content within HTML elements. The structure of the HTML document (DOM tree) is crucial for how word boundaries are determined, especially with inline elements and line breaks. `contenteditable` is a key attribute that influences the behavior.
* **CSS:** CSS affects how text is rendered, including line breaking and whitespace handling. While this file doesn't directly *implement* CSS parsing, the word boundary calculations must be aware of how CSS can cause text to wrap. The concept of "visible units" is inherently tied to how the text is laid out.
* **JavaScript:** JavaScript interacts with this functionality through the browser's editing APIs (e.g., Selection API, Range API). When a user moves the caret by words (Ctrl+Left/Right arrow), JavaScript triggers actions that ultimately rely on the underlying logic in this C++ file.

**5. Identifying Potential User/Programming Errors:**

Focus on situations where the assumptions of the code might be violated or where incorrect usage could lead to unexpected behavior.

**6. Tracing User Actions:**

Think about the user interactions that would lead to this code being executed. Anything involving text selection and navigation is a likely candidate.

**7. Iterative Refinement:**

After the initial pass, reread the code and your analysis. Look for nuances and details you might have missed. For instance, pay close attention to comments in the code (like the important note about `AbstractInlineTextBox::GetWordBoundariesForText`).

By following these steps, you can systematically analyze a complex C++ file like `visible_units_word.cc` and understand its purpose, its relationship to web technologies, and potential error scenarios. The key is to break the problem down into smaller, manageable parts and to leverage the information available in the code itself (comments, includes, function names).
这个文件 `visible_units_word.cc` 是 Chromium Blink 引擎中负责处理文本编辑时，以“词”为单位进行操作的核心代码。它定义了如何确定一个词的起始和结束位置，以及如何在文本中向前或向后移动一个词。

以下是它的主要功能以及与 JavaScript, HTML, CSS 的关系：

**功能：**

1. **定义词的边界:**  核心功能是定义什么是 "词" 以及如何在文本中识别词的开始和结束。这涉及到复杂的逻辑，需要考虑各种字符类型（字母、数字、标点符号、空格、换行符等）、Unicode 字符属性以及语言规则。
2. **提供以词为单位的移动能力:**  提供了函数，允许在文本中以词为单位移动光标（caret）。这包括：
    * `EndOfWordPosition`: 找到一个位置所在词的末尾。
    * `StartOfWordPosition`: 找到一个位置所在词的开头。
    * `NextWordPosition`: 找到光标之后下一个词的起始位置。
    * `PreviousWordPosition`: 找到光标之前上一个词的起始位置。
    * `MiddleOfWordPosition`: 找到两个位置之间词的中间位置。
3. **处理不同平台的词语行为:**  `NextWordPosition` 函数接受 `PlatformWordBehavior` 参数，这意味着它会考虑不同操作系统或平台的默认词语选择和移动行为。例如，在某些平台上，移动到下一个词会跳过空格，而在其他平台上可能不会。
4. **与编辑边界交互:**  代码中使用了 `AdjustForwardPositionToAvoidCrossingEditingBoundaries` 和 `AdjustBackwardPositionToAvoidCrossingEditingBoundaries` 函数，表明在计算词边界时，会考虑到 `contenteditable` 属性定义的编辑区域，避免跨越这些边界。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**
    * **选择和光标操作:** 当 JavaScript 代码使用 Selection API 或 Range API 来操作文本选择或移动光标时，Blink 引擎最终会调用 `visible_units_word.cc` 中定义的函数来确定词的边界。例如，当用户在 `contenteditable` 的元素中使用 Ctrl+左箭头或 Ctrl+右箭头来按词移动光标时，浏览器会触发相应的事件，JavaScript 可以监听这些事件并调用 Selection API 的方法，最终调用到这里的 C++ 代码。
    * **输入法和富文本编辑器:**  富文本编辑器和复杂的输入法在处理文本输入和光标移动时，也会依赖这些底层的词边界计算逻辑。

    **举例说明:**
    ```javascript
    // 获取当前选区
    const selection = window.getSelection();
    // 光标折叠到选区开始位置
    selection.collapseToStart();
    // 按词向前移动光标
    selection.modify("move", "forward", "word");
    console.log(selection.anchorNode, selection.anchorOffset);
    ```
    在这个例子中，`selection.modify("move", "forward", "word")`  在 Blink 引擎内部会调用 `visible_units_word.cc` 中的 `NextWordPosition` 函数来计算下一个词的起始位置。

* **HTML:**
    * **`contenteditable` 属性:** 当 HTML 元素设置了 `contenteditable` 属性后，用户可以在该元素中编辑文本。在编辑过程中，以词为单位的选择和移动操作会触发 `visible_units_word.cc` 中的代码。
    * **文本内容结构:** HTML 的标签结构会影响词的边界。例如，`<span>`、`<strong>` 等标签可能会将一段文本分割成多个独立的文本节点，`visible_units_word.cc` 需要处理跨越这些节点的词边界。

    **举例说明:**
    ```html
    <div contenteditable="true">
      这是一个 <strong>测试</strong> 文本。
    </div>
    ```
    当光标位于 "这" 和 "是" 之间，然后用户按下 Ctrl+右箭头，`NextWordPosition` 需要能够正确地定位到 "一个" 的起始位置，即使 "测试" 包裹在 `<strong>` 标签中。

* **CSS:**
    * **`word-break` 和 `white-space` 属性:** CSS 的 `word-break` 属性（例如 `break-all`, `keep-all`) 和 `white-space` 属性（例如 `nowrap`, `pre-wrap`) 会影响文本的换行和空格处理，间接地影响了词的边界。`visible_units_word.cc` 中的逻辑需要考虑这些 CSS 属性的影响。例如，如果 `word-break: break-all`，那么即使是一个很长的单词也可能在任意位置被断开，这会影响词的定义。
    * **渲染和布局:** CSS 决定了文本的最终渲染效果和布局，包括行高、字体等等。虽然 `visible_units_word.cc` 主要关注逻辑上的词边界，但最终的词边界需要与渲染结果保持一致。

    **举例说明:**
    ```html
    <div style="word-break: break-all;">
      一个非常非常非常非常非常长的英文单词
    </div>
    ```
    在这种情况下，即使是一个很长的单词，由于 `word-break: break-all` 的设置，也可能被强制断开成多行，`visible_units_word.cc` 在计算词边界时需要考虑到这种断裂。

**逻辑推理 (假设输入与输出):**

假设我们有以下 HTML 内容：

```html
<div>Hello, world! This is a test.</div>
```

并且光标位于 "w" 和 "o" 之间（即 "world" 的 "o" 之前）。

* **假设输入:** 光标位置在 "Hello, w|orld! This is a test."
* **调用函数:** `EndOfWordPosition(currentPosition, kForwardWordIfOnBoundary)`
* **逻辑推理:** 函数会识别出当前位置在 "world" 这个词的内部，并向前找到这个词的末尾，即 "d" 之后的位置。
* **假设输出:** 光标位置会移动到 "Hello, world|! This is a test."

* **假设输入:** 光标位置在 "Hello,| world! This is a test."
* **调用函数:** `NextWordPosition(currentPosition, PlatformWordBehavior::kDefault)`
* **逻辑推理:** 函数会跳过空格，找到下一个词 "world" 的起始位置。
* **假设输出:** 光标位置会移动到 "Hello, |world! This is a test."

**用户或编程常见的使用错误：**

1. **错误地假设词的定义:**  开发者可能会错误地假设词的定义非常简单（例如，空格分隔），而忽略了标点符号、连字符、Unicode 字符等复杂情况。这可能导致在某些情况下，以词为单位的操作行为与预期不符。
2. **没有考虑到平台差异:**  在 JavaScript 中直接操作文本内容时，如果没有意识到不同平台对于词的定义和移动行为可能存在差异，可能会导致跨平台兼容性问题。Blink 引擎在 C++ 层面上处理了这些差异，但开发者在使用 JavaScript API 时也需要有所了解。
3. **在复杂的 HTML 结构中操作:** 当 HTML 结构复杂，包含大量的嵌套标签和特殊字符时，手动计算词的边界可能会非常困难且容易出错。应该依赖浏览器提供的 API 来处理这些情况。
4. **忽略 CSS 的影响:**  没有考虑到 CSS 的 `word-break` 和 `white-space` 属性对词边界的影响，可能会导致在特定样式下，以词为单位的操作行为不符合预期。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在可编辑区域输入文本:** 用户在一个设置了 `contenteditable="true"` 的 HTML 元素中输入文本。
2. **用户进行光标移动操作:** 用户使用键盘上的光标键（例如 Ctrl+左箭头或 Ctrl+右箭头）来按词移动光标。
3. **浏览器事件触发:** 用户的键盘操作会触发浏览器事件（例如 `keydown` 或 `keypress`）。
4. **事件处理和命令执行:** 浏览器或渲染引擎的事件处理机制会捕获这些事件，并识别出用户想要执行“按词移动光标”的操作。
5. **调用编辑命令:** 浏览器会调用相应的编辑命令，例如 `moveWordForward` 或 `moveWordBackward`。
6. **Blink 引擎执行命令:** Blink 引擎接收到这些编辑命令后，会调用 `core/editing/Editor` 或相关的类来处理这些命令。
7. **调用 `VisibleUnits` 相关函数:**  `Editor` 或其他编辑相关的类会调用 `visible_units_word.cc` 中定义的函数（例如 `NextWordPosition` 或 `PreviousWordPosition`）来计算新的光标位置。
8. **计算词边界:**  `visible_units_word.cc` 中的代码会根据当前光标位置、文本内容、可能的 CSS 样式等信息，使用文本断点迭代器（`TextBreakIterator`）来确定词的边界。
9. **更新光标位置:** 计算出的新的光标位置会被传递回 Blink 引擎，最终更新页面上的光标显示。

**调试线索:**

如果需要调试与词边界相关的问题，可以关注以下线索：

* **断点设置:** 在 `visible_units_word.cc` 中相关的函数（例如 `NextWordPositionInternal`, `PreviousWordPositionInternal`）设置断点，查看在执行按词移动光标操作时，这些函数的输入参数和执行流程。
* **检查 `TextBreakIterator` 的行为:** 观察 `WordBreakIterator` 的返回值，了解它是如何识别词边界的。
* **查看文本内容和结构:** 检查当前光标所在位置的文本内容和 HTML 结构，确认是否存在特殊的字符或标签导致词边界的计算出现问题。
* **分析 CSS 样式:** 检查相关的 CSS 样式，特别是 `word-break` 和 `white-space` 属性，确认它们是否影响了词的边界。
* **模拟用户操作:**  在调试环境中模拟用户的操作步骤，例如在特定的文本位置按下 Ctrl+箭头键，观察程序的执行流程。
* **日志输出:**  在关键的代码路径添加日志输出，例如输出当前的字符、断点迭代器的结果等，帮助理解代码的执行过程。

总而言之，`visible_units_word.cc` 是 Blink 引擎中处理文本编辑时以词为单位操作的关键组件，它连接了用户操作、JavaScript API 和底层的文本处理逻辑，确保了在网页上进行文本编辑时的行为符合预期。

Prompt: 
```
这是目录为blink/renderer/core/editing/visible_units_word.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/editing/text_offset_mapping.h"
#include "third_party/blink/renderer/core/editing/text_segments.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/text/character.h"
#include "third_party/blink/renderer/platform/text/text_boundaries.h"
#include "third_party/blink/renderer/platform/text/text_break_iterator.h"

namespace blink {

namespace {

// Helpers used during word movement
static bool IsLineBreak(UChar ch) {
  return ch == kNewlineCharacter || ch == kCarriageReturnCharacter;
}

PositionInFlatTree EndOfWordPositionInternal(const PositionInFlatTree& position,
                                             WordSide side) {
  class Finder final : public TextSegments::Finder {
    STACK_ALLOCATED();

   public:
    Finder(WordSide side) : side_(side) {}

   private:
    Position Find(const String text, unsigned offset) final {
      DCHECK_LE(offset, text.length());
      if (!is_first_time_)
        return FindInternal(text, offset);
      is_first_time_ = false;
      if (side_ == kPreviousWordIfOnBoundary) {
        if (offset == 0)
          return Position::Before(0);
        return FindInternal(text, offset - 1);
      }
      if (offset == text.length())
        return Position::After(offset);
      return FindInternal(text, offset);
    }

    static Position FindInternal(const String text, unsigned offset) {
      DCHECK_LE(offset, text.length());
      TextBreakIterator* it = WordBreakIterator(text.Span16());
      const int result = it->following(offset);
      if (result == kTextBreakDone || result == 0)
        return Position();
      return Position::After(result - 1);
    }

    const WordSide side_;
    bool is_first_time_ = true;
  } finder(side);
  return TextSegments::FindBoundaryForward(position, &finder);
}

// IMPORTANT: If you update the logic of this algorithm, please also update the
// one in `AbstractInlineTextBox::GetWordBoundariesForText`. The word offsets
// computed over there needs to stay in sync with the ones computed here in
// order for screen readers to announce the right words when using caret
// navigation (ctrl + left/right arrow).
PositionInFlatTree NextWordPositionInternal(
    const PositionInFlatTree& position,
    PlatformWordBehavior platform_word_behavior) {
  class Finder final : public TextSegments::Finder {
    STACK_ALLOCATED();

   public:
    Finder(PlatformWordBehavior platform_word_behavior)
        : platform_word_behavior_(platform_word_behavior) {}

   private:
    Position Find(const String text, unsigned offset) final {
      DCHECK_LE(offset, text.length());
      if (!is_first_time_ && static_cast<unsigned>(offset) < text.length()) {
        // These conditions check if we found a valid word break position after
        // another iteration of scanning contents from the position that was
        // passed to this function. Ex: |Hello |World|\n |foo |bar
        // When we are after World|, the first iteration of this loop after call
        // to TextSegments::Finder::find will return empty position as there
        // aren't any meaningful word in that inline_content. In the next
        // iteration of this loop, it fetches the word |foo, so we return the
        // current position as we don't want to skip this valid position by
        // advancing from this position and return |bar instead.
        if (IsWordBreak(text[offset]))
          return SkipWhitespaceIfNeeded(text, offset);
      }
      is_first_time_ = false;
      if (offset == text.length() || text.length() == 0)
        return Position();
      TextBreakIterator* it = WordBreakIterator(text.Span16());
      for (int runner = it->following(offset); runner != kTextBreakDone;
           runner = it->following(runner)) {
        // Move after line break
        if (IsLineBreak(text[runner]))
          return SkipWhitespaceIfNeeded(text, runner);
        // Accumulate punctuation/surrogate pair runs.
        if (static_cast<unsigned>(runner) < text.length() &&
            (WTF::unicode::IsPunct(text[runner]) ||
             U16_IS_SURROGATE(text[runner]))) {
          if (WTF::unicode::IsAlphanumeric(text[runner - 1]))
            return SkipWhitespaceIfNeeded(text, runner);
          continue;
        }
        // We stop searching in the following conditions:
        // 1. When the character preceding the break is
        //    alphanumeric or punctuations or underscore or linebreaks.
        // Only on Windows:
        // 2. When the character preceding the break is a whitespace and
        //    the character following it is an alphanumeric or punctuations
        //    or underscore or linebreaks.
        if (static_cast<unsigned>(runner) < text.length() &&
            IsWordBreak(text[runner - 1]))
          return SkipWhitespaceIfNeeded(text, runner);
        else if (platform_word_behavior_ ==
                     PlatformWordBehavior::kWordSkipSpaces &&
                 static_cast<unsigned>(runner) < text.length() &&
                 IsWhitespace(text[runner - 1]) && IsWordBreak(text[runner]))
          return SkipWhitespaceIfNeeded(text, runner);
      }
      if (text[text.length() - 1] != kNewlineCharacter)
        return Position::After(text.length() - 1);
      return Position();
    }

    Position SkipWhitespaceIfNeeded(const String text, int offset) {
      DCHECK_NE(offset, kTextBreakDone);
      // On Windows next word should skip trailing whitespaces but not line
      // break
      if (platform_word_behavior_ == PlatformWordBehavior::kWordSkipSpaces) {
        for (unsigned runner = static_cast<unsigned>(offset);
             runner < text.length(); ++runner) {
          if (!(IsWhitespace(text[runner]) ||
                WTF::unicode::Direction(text[runner]) ==
                    WTF::unicode::kWhiteSpaceNeutral) ||
              IsLineBreak(text[runner]))
            return Position::Before(runner);
        }
      }
      return Position::Before(offset);
    }

    const PlatformWordBehavior platform_word_behavior_;
    bool is_first_time_ = true;
  } finder(platform_word_behavior);
  return TextSegments::FindBoundaryForward(position, &finder);
}

PositionInFlatTree PreviousWordPositionInternal(
    const PositionInFlatTree& position) {
  class Finder final : public TextSegments::Finder {
    STACK_ALLOCATED();

   private:
    Position Find(const String text, unsigned offset) final {
      DCHECK_LE(offset, text.length());
      if (!is_first_time_ && text.length() > 0 &&
          static_cast<unsigned>(offset) <= text.length()) {
        // These conditions check if we found a valid word break position after
        // another iteration of scanning contents from the position that was
        // passed to this function. Ex: |Hello |World|\n |foo |bar
        // When we are before |foo, the first iteration of this loop after call
        // to TextSegments::Finder::find will return empty position as there
        // aren't any meaningful word in that inline_content. In the next
        // iteration of this loop, it fetches the word World|, so we return the
        // current position as we don't want to skip this valid position by
        // advancing from this position and return |World instead.
        if (IsWordBreak(text[offset - 1]))
          return Position::Before(offset);
      }
      is_first_time_ = false;
      if (!offset || text.length() == 0)
        return Position();
      TextBreakIterator* it = WordBreakIterator(text.Span16());
      int punct_runner = -1;
      for (int runner = it->preceding(offset); runner != kTextBreakDone;
           runner = it->preceding(runner)) {
        // Accumulate punctuation/surrogate pair runs.
        if (static_cast<unsigned>(runner) < text.length() &&
            (WTF::unicode::IsPunct(text[runner]) ||
             U16_IS_SURROGATE(text[runner]))) {
          if (WTF::unicode::IsAlphanumeric(text[runner - 1]))
            return Position::Before(runner);
          punct_runner = runner;
          continue;
        }

        if (punct_runner >= 0)
          return Position::Before(punct_runner);
        // We stop searching when the character following the break is
        // alphanumeric or punctuations or underscore or linebreaks.
        if (static_cast<unsigned>(runner) < text.length() &&
            IsWordBreak(text[runner]))
          return Position::Before(runner);
      }
      return Position::Before(0);
    }
    bool is_first_time_ = true;
  } finder;
  return TextSegments::FindBoundaryBackward(position, &finder);
}

PositionInFlatTree StartOfWordPositionInternal(
    const PositionInFlatTree& position,
    WordSide side) {
  class Finder final : public TextSegments::Finder {
    STACK_ALLOCATED();

   public:
    Finder(WordSide side) : side_(side) {}

   private:
    Position Find(const String text, unsigned offset) final {
      DCHECK_LE(offset, text.length());
      if (!is_first_time_)
        return FindInternal(text, offset);
      is_first_time_ = false;
      if (side_ == kNextWordIfOnBoundary) {
        if (offset == text.length())
          return Position::After(text.length());
        return FindInternal(text, offset + 1);
      }
      if (!offset)
        return Position::Before(offset);
      return FindInternal(text, offset);
    }

    static Position FindInternal(const String text, unsigned offset) {
      DCHECK_LE(offset, text.length());
      TextBreakIterator* it = WordBreakIterator(text.Span16());
      const int result = it->preceding(offset);
      if (result == kTextBreakDone)
        return Position();
      return Position::Before(result);
    }

    const WordSide side_;
    bool is_first_time_ = true;
  } finder(side);
  return TextSegments::FindBoundaryBackward(position, &finder);
}
}  // namespace

PositionInFlatTree EndOfWordPosition(const PositionInFlatTree& start,
                                     WordSide side) {
  return AdjustForwardPositionToAvoidCrossingEditingBoundaries(
             PositionInFlatTreeWithAffinity(
                 EndOfWordPositionInternal(start, side)),
             start)
      .GetPosition();
}

Position EndOfWordPosition(const Position& position, WordSide side) {
  return ToPositionInDOMTree(
      EndOfWordPosition(ToPositionInFlatTree(position), side));
}

// ----
// TODO(editing-dev): Because of word boundary can not be an upstream position,
// we should make this function to return |PositionInFlatTree|.
PositionInFlatTreeWithAffinity NextWordPosition(
    const PositionInFlatTree& start,
    PlatformWordBehavior platform_word_behavior) {
  if (start.IsNull())
    return PositionInFlatTreeWithAffinity();
  const PositionInFlatTree next =
      NextWordPositionInternal(start, platform_word_behavior);
  // Note: The word boundary can not be upstream position.
  const PositionInFlatTreeWithAffinity adjusted =
      AdjustForwardPositionToAvoidCrossingEditingBoundaries(
          PositionInFlatTreeWithAffinity(next), start);
  DCHECK_EQ(adjusted.Affinity(), TextAffinity::kDownstream);
  return adjusted;
}

PositionWithAffinity NextWordPosition(
    const Position& start,
    PlatformWordBehavior platform_word_behavior) {
  const PositionInFlatTreeWithAffinity& next =
      NextWordPosition(ToPositionInFlatTree(start), platform_word_behavior);
  return ToPositionInDOMTreeWithAffinity(next);
}

PositionInFlatTreeWithAffinity PreviousWordPosition(
    const PositionInFlatTree& start) {
  if (start.IsNull())
    return PositionInFlatTreeWithAffinity();
  const PositionInFlatTree prev = PreviousWordPositionInternal(start);
  return AdjustBackwardPositionToAvoidCrossingEditingBoundaries(
      PositionInFlatTreeWithAffinity(prev), start);
}

PositionWithAffinity PreviousWordPosition(const Position& start) {
  const PositionInFlatTreeWithAffinity& prev =
      PreviousWordPosition(ToPositionInFlatTree(start));
  return ToPositionInDOMTreeWithAffinity(prev);
}

PositionInFlatTree StartOfWordPosition(const PositionInFlatTree& position,
                                       WordSide side) {
  const PositionInFlatTree start = StartOfWordPositionInternal(position, side);
  return AdjustBackwardPositionToAvoidCrossingEditingBoundaries(
             PositionInFlatTreeWithAffinity(start), position)
      .GetPosition();
}

Position StartOfWordPosition(const Position& position, WordSide side) {
  return ToPositionInDOMTree(
      StartOfWordPosition(ToPositionInFlatTree(position), side));
}

PositionInFlatTree MiddleOfWordPosition(const PositionInFlatTree& word_start,
                                        const PositionInFlatTree& word_end) {
  if (word_start >= word_end) {
    return PositionInFlatTree(nullptr, 0);
  }
  unsigned middle =
      TextIteratorAlgorithm<EditingInFlatTreeStrategy>::RangeLength(word_start,
                                                                    word_end) /
      2;
  TextOffsetMapping::ForwardRange range =
      TextOffsetMapping::ForwardRangeOf(word_start);
  middle += TextOffsetMapping(*range.begin()).ComputeTextOffset(word_start);
  for (auto inline_contents : range) {
    const TextOffsetMapping mapping(inline_contents);
    unsigned length = mapping.GetText().length();
    if (middle < length) {
      return mapping.GetPositionBefore(middle);
    }
    middle -= length;
  }
  NOTREACHED();
}

Position MiddleOfWordPosition(const Position& word_start,
                              const Position& word_end) {
  return ToPositionInDOMTree(MiddleOfWordPosition(
      ToPositionInFlatTree(word_start), ToPositionInFlatTree(word_end)));
}

bool IsWordBreak(UChar ch) {
  return (WTF::unicode::IsPrintableChar(ch) && !IsWhitespace(ch)) ||
         U16_IS_SURROGATE(ch) || IsLineBreak(ch) || ch == kLowLineCharacter;
}
}  // namespace blink

"""

```