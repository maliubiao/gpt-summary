Response:
Let's break down the thought process for analyzing the provided C++ code and generating the comprehensive explanation.

1. **Understand the Goal:** The primary goal is to analyze the functionality of `TextFragmentFinder.cc` within the Chromium Blink rendering engine, relating it to web technologies (JavaScript, HTML, CSS) and identifying potential user/programming errors.

2. **Initial Code Scan (Keywords and Structure):**  A quick scan reveals important keywords and structures:
    * `TextFragmentFinder`: The central class.
    * `#include`: Includes related files like `TextFragmentSelector.h`, `Document.h`, `Range.h`, `finder/`, etc. This gives clues about the class's dependencies and potential functionalities (finding text, working with DOM ranges, etc.).
    * `namespace blink`:  Confirms it's part of the Blink rendering engine.
    * Private member variables like `selector_`, `document_`, `search_range_`, `potential_match_`, `find_buffer_runner_`, etc. These are the internal data the class uses.
    * Public methods like `FindMatch()`, `Cancel()`, `FindMatchFromPosition()`. These are the main entry points for using the class.
    * Private methods like `FindPrefix()`, `FindTextStart()`, `OnPrefixMatchComplete()`, etc. These likely represent the steps in the matching process.
    * The presence of `AsyncFindBuffer` and `SyncFindBuffer` suggests asynchronous and synchronous search capabilities.

3. **Core Functionality Hypothesis:** Based on the file name and includes, the primary function is likely to find a specific text fragment within a document, guided by a `TextFragmentSelector`.

4. **Dissecting Key Methods:** Now, dive deeper into the crucial methods:
    * **`TextFragmentFinder` Constructor:**  Takes a `TextFragmentSelector`, `Document`, and a `FindBufferRunnerType`. This confirms the dependency on the selector and the choice between asynchronous/synchronous search.
    * **`FindMatch()`:** The starting point for the search. It acquires a display lock, updates layout, and then calls `FindMatchFromPosition`.
    * **`FindMatchFromPosition()`:** Sets up the initial search range and calls `GoToStep(kMatchPrefix)`. This suggests a multi-step matching process.
    * **`GoToStep()` and the `switch` statement:** This is crucial! It reveals the four potential matching steps: `kMatchPrefix`, `kMatchTextStart`, `kMatchTextEnd`, `kMatchSuffix`. This clearly outlines the logic of matching prefixes, the main text, and suffixes.
    * **`FindPrefix()`, `FindTextStart()`, `FindTextEnd()`, `FindSuffix()`:** These methods implement the search logic for each step, using `FindMatchInRange`.
    * **`FindMatchInRange()`:** Delegates the actual text searching to `find_buffer_runner_` (either synchronous or asynchronous).
    * **`On...MatchComplete()` methods:** Handle the results of the `FindMatchInRange` calls, advancing the search to the next step or completing the match.
    * **Helper Functions:** Pay attention to functions like `IsWordBounded()`, `FirstWordBoundaryAfter()`, `NextTextPosition()`, `PreviousTextPosition()`, `IsInSameUninterruptedBlock()`. These provide supporting logic for boundary checks and text navigation.

5. **Relating to Web Technologies:**  Consider how this functionality interacts with JavaScript, HTML, and CSS:
    * **JavaScript:** The most direct link. JavaScript would likely initiate the text fragment finding process, possibly in response to a URL with a text fragment directive (`#:~text=...`). The `TextFragmentFinder` would be invoked from JavaScript through the Blink API.
    * **HTML:** The text being searched exists within the HTML structure. The `TextFragmentFinder` needs to traverse the DOM tree represented by the HTML.
    * **CSS:** While not directly manipulating CSS, the layout updates performed in `FindMatch()` might be influenced by CSS. The concept of "uninterrupted blocks" in `IsInSameUninterruptedBlock()` relates to how elements are rendered on the page, which CSS controls. Highlighting the matched text would also involve CSS styling.

6. **Logical Reasoning and Examples:**  Think about the flow of the matching process and create illustrative examples:
    * **Simple case:** Just `start_text`.
    * **With prefix:** How the prefix helps narrow down the search.
    * **With suffix:** How the suffix further refines the match.
    * **Range match:**  The use of `start_text` and `end_text`.
    * **Word boundaries:** The importance of `word_start_bounded` and `word_end_bounded`.

7. **Identifying Potential Errors:**  Consider how a user or programmer might misuse this functionality:
    * **Incorrect selector:**  Malformed or nonsensical text fragment directives.
    * **Ambiguous selectors:**  Cases where multiple matches are possible.
    * **Dynamic content:** Content changing after the search starts.
    * **Performance:**  Searching very large documents.

8. **Structuring the Explanation:** Organize the findings logically:
    * **Core Functionality:**  A high-level overview.
    * **Detailed Functionality Breakdown:**  Explain the purpose of key methods and the matching steps.
    * **Relationship to Web Technologies:** Provide specific examples.
    * **Logical Reasoning (Input/Output):**  Illustrate the matching process with examples.
    * **Common Errors:**  List potential pitfalls.

9. **Refinement and Review:** Reread the code and the explanation to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For example, initially, I might not have fully grasped the importance of word boundaries, requiring a second look at the `IsWordBounded` function and its usage. Similarly, the asynchronous/synchronous nature of the search warrants careful explanation.
这是 `blink/renderer/core/fragment_directive/text_fragment_finder.cc` 文件的功能列表：

**核心功能：在文档中查找与文本片段选择器匹配的文本片段。**

这个文件的主要目的是实现“滚动到文本片段”功能（Scroll to Text Fragment），允许用户通过 URL 中的特定指令直接滚动到页面中匹配的文本。

**详细功能分解:**

1. **解析文本片段选择器 (TextFragmentSelector):**  该类接收一个 `TextFragmentSelector` 对象作为输入，该对象包含了要查找的文本片段的信息，例如前缀、起始文本、结束文本和后缀。

2. **在文档中进行多步骤搜索:**  `TextFragmentFinder` 使用一种分步搜索策略来定位目标文本片段。这些步骤包括：
    * **查找前缀 (Prefix):**  如果指定了前缀，则首先在文档中查找匹配的前缀。
    * **查找起始文本 (Start Text):**  在找到前缀（如果存在）之后，查找紧随其后的起始文本。
    * **查找结束文本 (End Text):**  如果指定了结束文本，则在找到起始文本之后查找匹配的结束文本，以确定匹配范围的末尾。
    * **查找后缀 (Suffix):**  如果指定了后缀，则在找到起始文本（或结束文本，如果存在）之后查找匹配的后缀。

3. **支持同步和异步查找:**  该类可以使用同步 (`SyncFindBuffer`) 或异步 (`AsyncFindBuffer`) 的查找缓冲区来执行文本搜索。异步查找允许在查找过程中不阻塞主线程，提高用户体验。

4. **考虑词边界:**  在匹配前缀和后缀时，`TextFragmentFinder` 会考虑词边界，确保匹配发生在完整的单词上。这有助于避免误匹配。

5. **处理空格和换行符:**  在确定文本位置时，会忽略空格和换行符。

6. **处理 DOM 结构:**  搜索过程会遍历文档的 DOM 树，以找到匹配的文本片段。

7. **处理查找结果:**  `TextFragmentFinder` 会在找到匹配项或未找到匹配项时通知其客户端（`Client` 接口）。

8. **处理多个可能的匹配项:**  该代码似乎包含处理模糊选择器的逻辑 (标注为 `TODO(crbug.com/919204)`)，这意味着它可能尝试查找所有可能的匹配项。

9. **取消查找:**  提供 `Cancel()` 方法来中止正在进行的查找操作。

**与 JavaScript, HTML, CSS 的关系举例:**

* **JavaScript:**
    * **触发查找:**  当浏览器解析到包含文本片段指令的 URL 时，Blink 引擎会使用 JavaScript API (可能在导航或页面加载过程中) 创建 `TextFragmentSelector` 对象并调用 `TextFragmentFinder` 来执行查找。
    * **API 交互:**  JavaScript 代码可能会监听查找完成的事件，以便进行后续操作，例如滚动到匹配的文本。
    * **示例:**  假设 URL 为 `https://example.com/#:~text=hello`, JavaScript 代码会解析出 `hello` 作为要查找的文本，并传递给 `TextFragmentFinder`。

* **HTML:**
    * **搜索目标:**  `TextFragmentFinder` 遍历 HTML 文档的 DOM 结构，在文本节点中查找匹配的文本片段。
    * **文本内容:**  HTML 内容提供了要搜索的文本数据。
    * **示例:**  在以下 HTML 中：
      ```html
      <p>This is a paragraph containing the word <b>hello</b>.</p>
      ```
      如果 URL 是 `#:~text=paragraph,hello`, `TextFragmentFinder` 将会定位到包含 "hello" 的文本节点。

* **CSS:**
    * **高亮显示:**  一旦找到匹配的文本片段，Blink 引擎可能会应用特定的 CSS 样式来高亮显示该片段，以引起用户的注意。
    * **布局影响:**  虽然 `TextFragmentFinder` 本身不直接操作 CSS，但在 `FindMatch()` 中调用 `document_->UpdateStyleAndLayout()` 表明查找过程可能需要确保文档的布局是最新的，这与 CSS 渲染有关。
    * **示例:**  浏览器可能会默认使用黄色背景或其他高亮样式来显示匹配的文本。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* **HTML 内容:** `<p>The quick brown fox jumps over the lazy dog.</p>`
* **TextFragmentSelector:**
    * `prefix`: "quick brown"
    * `start_text`: "fox"
    * `end_text`: "jumps"
* **操作:** 调用 `FindMatch()`

**预期输出:**

* `TextFragmentFinder` 应该能够定位到 "fox jumps" 这部分文本。
* `OnMatchComplete()` 回调应该被调用，并传递一个包含 "fox jumps" 的 `RangeInFlatTree` 对象。

**假设输入:**

* **HTML 内容:** `<p>This is a test. This is another test.</p>`
* **TextFragmentSelector:**
    * `start_text`: "test"
* **操作:** 调用 `FindMatch()`

**预期输出:**

* 由于 "test" 出现了两次，如果实现了模糊匹配处理，`TextFragmentFinder` 可能会先找到第一个 "test"，然后继续查找找到第二个。
* 最终可能会选择第一个匹配项，或者如果实现了某种优先级规则，可能会选择第二个。  具体的行为取决于模糊匹配的具体实现逻辑。

**用户或编程常见的使用错误举例:**

1. **错误的文本片段指令:** 用户在 URL 中输入的文本片段指令可能拼写错误或格式不正确，导致 `TextFragmentSelector` 无法正确解析，从而导致 `TextFragmentFinder` 找不到匹配项。
    * **示例:** URL 为 `#:~text=helo` 而不是 `#:~text=hello`。

2. **选择器过于宽泛或过于严格:**
    * **过于宽泛:**  如果 `start_text` 非常常见，可能会导致意外匹配到页面中不相关的文本。
        * **示例:**  `#:~text=the` 可能会匹配到页面上很多 "the" 单词。
    * **过于严格:**  如果前缀、起始文本、结束文本和后缀的组合在页面中不存在，则无法找到匹配项。
        * **示例:**  如果页面中只有 "quick brown fox"，而 URL 是 `#:~text=very,quick brown,dog`, 则无法匹配。

3. **动态内容:** 如果页面的内容在 `TextFragmentFinder` 开始查找后发生更改，可能导致找到的匹配项不再是用户期望的或者查找失败。

4. **大小写敏感性 (默认不敏感，但可能引起混淆):**  默认情况下，查找是不区分大小写的。用户可能期望区分大小写，但实际并非如此。

5. **特殊字符处理:**  文本片段指令中包含特殊字符时，需要进行正确的 URL 编码。如果编码不正确，可能会导致 `TextFragmentFinder` 无法正确解析和匹配。

总而言之，`TextFragmentFinder.cc` 是 Chromium Blink 引擎中负责实现“滚动到文本片段”这一重要功能的关键组件，它通过解析文本片段选择器并在文档中执行多步骤搜索来定位目标文本，并与 JavaScript、HTML 和 CSS 等 Web 技术紧密相关。理解其功能有助于开发者更好地利用和调试与文本片段相关的 Web 应用。

Prompt: 
```
这是目录为blink/renderer/core/fragment_directive/text_fragment_finder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fragment_directive/text_fragment_finder.h"

#include <memory>

#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_document_state.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/finder/async_find_buffer.h"
#include "third_party/blink/renderer/core/editing/finder/find_buffer.h"
#include "third_party/blink/renderer/core/editing/finder/find_options.h"
#include "third_party/blink/renderer/core/editing/finder/sync_find_buffer.h"
#include "third_party/blink/renderer/core/editing/iterators/backwards_character_iterator.h"
#include "third_party/blink/renderer/core/editing/iterators/character_iterator.h"
#include "third_party/blink/renderer/core/fragment_directive/text_fragment_selector.h"
#include "third_party/blink/renderer/core/html/list_item_ordinal.h"
#include "third_party/blink/renderer/platform/text/text_boundaries.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

// TODO(crbug/924965): Determine how this should check node boundaries. This
// treats node boundaries as word boundaries, for example "o" is a whole word
// match in "f<i>o</i>o".
// Determines whether the |start| and/or |end| positions of |range| are on a
// word boundaries.
bool IsWordBounded(EphemeralRangeInFlatTree range, bool start, bool end) {
  if (!start && !end)
    return true;

  wtf_size_t start_position = range.StartPosition().OffsetInContainerNode();

  if (start_position != 0 && start) {
    String start_text = range.StartPosition().AnchorNode()->textContent();
    start_text.Ensure16Bit();
    wtf_size_t word_start =
        FindWordStartBoundary(start_text.Span16(), start_position);
    if (word_start != start_position)
      return false;
  }

  wtf_size_t end_position = range.EndPosition().OffsetInContainerNode();
  String end_text = range.EndPosition().AnchorNode()->textContent();

  if (end_position != end_text.length() && end) {
    end_text.Ensure16Bit();
    // We expect end_position to be a word boundary, and FindWordEndBoundary
    // finds the next word boundary, so start from end_position - 1.
    wtf_size_t word_end =
        FindWordEndBoundary(end_text.Span16(), end_position - 1);
    if (word_end != end_position)
      return false;
  }

  return true;
}

PositionInFlatTree FirstWordBoundaryAfter(PositionInFlatTree position) {
  wtf_size_t offset = position.OffsetInContainerNode();
  String text = position.AnchorNode()->textContent();

  if (offset == text.length()) {
    PositionIteratorInFlatTree itr(position);
    if (itr.AtEnd())
      return position;

    itr.Increment();
    return itr.ComputePosition();
  }

  text.Ensure16Bit();
  wtf_size_t word_end = FindWordEndBoundary(text.Span16(), offset);

  PositionInFlatTree end_pos(position.AnchorNode(), word_end);
  PositionIteratorInFlatTree itr(end_pos);
  itr.Increment();
  if (itr.AtEnd())
    return end_pos;
  return itr.ComputePosition();
}

}  // namespace

// static
PositionInFlatTree TextFragmentFinder::NextTextPosition(
    PositionInFlatTree position,
    PositionInFlatTree end_position) {
  const TextIteratorBehavior options =
      TextIteratorBehavior::Builder().SetEmitsSpaceForNbsp(true).Build();
  CharacterIteratorInFlatTree char_it(position, end_position, options);
  for (; char_it.length(); char_it.Advance(1)) {
    if (!IsSpaceOrNewline(char_it.CharacterAt(0)))
      return char_it.StartPosition();
  }

  return end_position;
}

// static
PositionInFlatTree TextFragmentFinder::PreviousTextPosition(
    PositionInFlatTree position,
    PositionInFlatTree max_position) {
  const TextIteratorBehavior options =
      TextIteratorBehavior::Builder().SetEmitsSpaceForNbsp(true).Build();
  BackwardsCharacterIteratorInFlatTree char_it(
      EphemeralRangeInFlatTree(max_position, position), options);

  for (; char_it.length(); char_it.Advance(1)) {
    if (!IsSpaceOrNewline(char_it.CharacterAt(0)))
      return char_it.EndPosition();
  }

  return max_position;
}

void TextFragmentFinder::OnFindMatchInRangeComplete(
    String search_text,
    RangeInFlatTree* search_range,
    bool word_start_bounded,
    bool word_end_bounded,
    const EphemeralRangeInFlatTree& match) {
  // If any of our ranges became invalid, stop the search.
  if (!HasValidRanges()) {
    potential_match_.Clear();
    first_match_.Clear();
    OnMatchComplete();
    return;
  }

  if (match.IsNull() ||
      IsWordBounded(match, word_start_bounded, word_end_bounded)) {
    switch (step_) {
      case kMatchPrefix:
        OnPrefixMatchComplete(match);
        break;
      case kMatchTextStart:
        OnTextStartMatchComplete(match);
        break;
      case kMatchTextEnd:
        OnTextEndMatchComplete(match);
        break;
      case kMatchSuffix:
        OnSuffixMatchComplete(match);
        break;
    }
    return;
  }
  search_range->SetStart(match.EndPosition());
  FindMatchInRange(search_text, search_range, word_start_bounded,
                   word_end_bounded);
}

void TextFragmentFinder::FindMatchInRange(String search_text,
                                          RangeInFlatTree* search_range,
                                          bool word_start_bounded,
                                          bool word_end_bounded) {
  find_buffer_runner_->FindMatchInRange(
      search_range, search_text, FindOptions().SetCaseInsensitive(true),
      WTF::BindOnce(&TextFragmentFinder::OnFindMatchInRangeComplete,
                    WrapWeakPersistent(this), search_text,
                    WrapWeakPersistent(search_range), word_start_bounded,
                    word_end_bounded));
}

void TextFragmentFinder::FindPrefix() {
  search_range_->SetStart(match_range_->StartPosition());
  if (search_range_->IsCollapsed()) {
    OnMatchComplete();
    return;
  }

  if (selector_.Prefix().empty()) {
    GoToStep(kMatchTextStart);
    return;
  }

  FindMatchInRange(selector_.Prefix(), search_range_,
                   /*word_start_bounded=*/true,
                   /*word_end_bounded=*/false);
}

void TextFragmentFinder::OnPrefixMatchComplete(
    EphemeralRangeInFlatTree prefix_match) {
  // No prefix_match in remaining range
  if (prefix_match.IsNull()) {
    OnMatchComplete();
    return;
  }

  // If we iterate again, start searching from the first boundary after the
  // prefix start (since prefix must start at a boundary). Note, we don't
  // advance to the prefix end; this is done since, if this prefix isn't
  // the one we're looking for, the next occurrence might be overlapping
  // with the current one. e.g. If |prefix| is "a a" and our search range
  // currently starts with "a a a b...", the next iteration should start at
  // the second a which is part of the current |prefix_match|.
  match_range_->SetStart(FirstWordBoundaryAfter(prefix_match.StartPosition()));
  SetPrefixMatch(prefix_match);
  GoToStep(kMatchTextStart);
  return;
}

void TextFragmentFinder::FindTextStart() {
  DCHECK(!selector_.Start().empty());

  // The match text need not be bounded at the end. If this is an exact
  // match (i.e. no |end_text|) and we have a suffix then the suffix will
  // be required to end on the word boundary instead. Since we have a
  // prefix, we don't need the match to be word bounded. See
  // https://github.com/WICG/scroll-to-text-fragment/issues/137 for
  // details.
  const bool end_at_word_boundary =
      !selector_.End().empty() || selector_.Suffix().empty();
  if (prefix_match_) {
    search_range_->SetStart(NextTextPosition(prefix_match_->EndPosition(),
                                             match_range_->EndPosition()));
    FindMatchInRange(selector_.Start(), search_range_,
                     /*word_start_bounded=*/false, end_at_word_boundary);
  } else {
    FindMatchInRange(selector_.Start(), search_range_,
                     /*word_start_bounded=*/true, end_at_word_boundary);
  }
}

void TextFragmentFinder::OnTextStartMatchComplete(
    EphemeralRangeInFlatTree potential_match) {
  if (prefix_match_) {
    PositionInFlatTree next_position_after_prefix = NextTextPosition(
        prefix_match_->EndPosition(), match_range_->EndPosition());
    // We found a potential match but it didn't immediately follow the prefix.
    if (!potential_match.IsNull() &&
        potential_match.StartPosition() != next_position_after_prefix) {
      potential_match_.Clear();
      GoToStep(kMatchPrefix);
      return;
    }
  }

  // No start_text match after current prefix_match
  if (potential_match.IsNull()) {
    OnMatchComplete();
    return;
  }
  if (!prefix_match_) {
    match_range_->SetStart(
        FirstWordBoundaryAfter(potential_match.StartPosition()));
  }
  if (!range_end_search_start_) {
    range_end_search_start_ = MakeGarbageCollected<RelocatablePosition>(
        ToPositionInDOMTree(potential_match.EndPosition()));
  } else {
    range_end_search_start_->SetPosition(
        ToPositionInDOMTree(potential_match.EndPosition()));
  }
  SetPotentialMatch(potential_match);
  GoToStep(kMatchTextEnd);
}

void TextFragmentFinder::FindTextEnd() {
  // If we've gotten here, we've found a |prefix| (if one was specified)
  // that's followed by the |start_text|. We'll now try to expand that into
  // a range match if |end_text| is specified.
  if (!selector_.End().empty()) {
    search_range_->SetStart(
        ToPositionInFlatTree(range_end_search_start_->GetPosition()));
    const bool end_at_word_boundary = selector_.Suffix().empty();

    FindMatchInRange(selector_.End(), search_range_,
                     /*word_start_bounded=*/true, end_at_word_boundary);
  } else {
    GoToStep(kMatchSuffix);
  }
}

void TextFragmentFinder::OnTextEndMatchComplete(
    EphemeralRangeInFlatTree text_end_match) {
  if (text_end_match.IsNull()) {
    potential_match_.Clear();
    OnMatchComplete();
    return;
  }

  potential_match_->SetEnd(text_end_match.EndPosition());
  GoToStep(kMatchSuffix);
}

void TextFragmentFinder::FindSuffix() {
  DCHECK(!potential_match_->IsNull());

  if (selector_.Suffix().empty()) {
    OnMatchComplete();
    return;
  }

  // Now we just have to ensure the match is followed by the |suffix|.
  search_range_->SetStart(NextTextPosition(potential_match_->EndPosition(),
                                           match_range_->EndPosition()));
  FindMatchInRange(selector_.Suffix(), search_range_,
                   /*word_start_bounded=*/false, /*word_end_bounded=*/true);
}

void TextFragmentFinder::OnSuffixMatchComplete(
    EphemeralRangeInFlatTree suffix_match) {
  // If no suffix appears in what follows the match, there's no way we can
  // possibly satisfy the constraints so bail.
  if (suffix_match.IsNull()) {
    potential_match_.Clear();
    OnMatchComplete();
    return;
  }

  PositionInFlatTree next_position_after_match = NextTextPosition(
      potential_match_->EndPosition(), match_range_->EndPosition());
  if (suffix_match.StartPosition() == next_position_after_match) {
    OnMatchComplete();
    return;
  }

  // If this is an exact match(e.g. |end_text| is not specified), and we
  // didn't match on suffix, continue searching for a new potential_match
  // from it's start.
  if (selector_.End().empty()) {
    potential_match_.Clear();
    GoToStep(kMatchPrefix);
    return;
  }

  // If this is a range match(e.g. |end_text| is specified), it is possible
  // that we found the correct range start, but not the correct range end.
  // Continue searching for it, without restarting the range start search.
  range_end_search_start_->SetPosition(
      ToPositionInDOMTree(potential_match_->EndPosition()));
  GoToStep(kMatchTextEnd);
}

void TextFragmentFinder::GoToStep(SelectorMatchStep step) {
  step_ = step;
  switch (step_) {
    case kMatchPrefix:
      FindPrefix();
      break;
    case kMatchTextStart:
      FindTextStart();
      break;
    case kMatchTextEnd:
      FindTextEnd();
      break;
    case kMatchSuffix:
      FindSuffix();
      break;
  }
}

// static
bool TextFragmentFinder::IsInSameUninterruptedBlock(
    const PositionInFlatTree& start,
    const PositionInFlatTree& end) {
  Node* start_node = start.ComputeContainerNode();
  Node* end_node = end.ComputeContainerNode();
  if (!start_node || !start_node->GetLayoutObject() || !end_node ||
      !end_node->GetLayoutObject()) {
    return true;
  }
  return FindBuffer::IsInSameUninterruptedBlock(*start_node, *end_node);
}

TextFragmentFinder::TextFragmentFinder(Client& client,
                                       const TextFragmentSelector& selector,
                                       Document* document,
                                       FindBufferRunnerType runner_type)
    : client_(client), selector_(selector), document_(document) {
  DCHECK(!selector_.Start().empty());
  DCHECK(selector_.Type() != TextFragmentSelector::SelectorType::kInvalid);
  if (runner_type == TextFragmentFinder::FindBufferRunnerType::kAsynchronous) {
    find_buffer_runner_ = MakeGarbageCollected<AsyncFindBuffer>();
  } else {
    find_buffer_runner_ = MakeGarbageCollected<SyncFindBuffer>();
  }
}

void TextFragmentFinder::Cancel() {
  if (find_buffer_runner_ && find_buffer_runner_->IsActive())
    find_buffer_runner_->Cancel();
}

void TextFragmentFinder::FindMatch() {
  Cancel();

  auto forced_lock_scope =
      document_->GetDisplayLockDocumentState().GetScopedForceActivatableLocks();
  document_->UpdateStyleAndLayout(DocumentUpdateReason::kFindInPage);

  first_match_.Clear();
  FindMatchFromPosition(PositionInFlatTree::FirstPositionInNode(*document_));
}

void TextFragmentFinder::FindMatchFromPosition(
    PositionInFlatTree search_start) {
  PositionInFlatTree search_end;
  if (document_->documentElement() &&
      document_->documentElement()->lastChild()) {
    search_end = PositionInFlatTree::AfterNode(
        *document_->documentElement()->lastChild());
  } else {
    search_end = PositionInFlatTree::LastPositionInNode(*document_);
  }
  search_range_ =
      MakeGarbageCollected<RangeInFlatTree>(search_start, search_end);
  match_range_ =
      MakeGarbageCollected<RangeInFlatTree>(search_start, search_end);
  potential_match_.Clear();
  prefix_match_.Clear();
  GoToStep(kMatchPrefix);
}

void TextFragmentFinder::OnMatchComplete() {
  if (!potential_match_ && !first_match_) {
    client_.NoMatchFound();
  } else if (potential_match_ && !first_match_) {
    // Continue searching to see if we have an ambiguous selector.
    // TODO(crbug.com/919204): This is temporary and only for measuring
    // ambiguous matching during prototyping.
    first_match_ = potential_match_;
    FindMatchFromPosition(first_match_->EndPosition());
  } else {
    EphemeralRangeInFlatTree potential_match = first_match_->ToEphemeralRange();
    client_.DidFindMatch(*first_match_, !potential_match_);
  }
}

void TextFragmentFinder::Trace(Visitor* visitor) const {
  visitor->Trace(document_);
  visitor->Trace(range_end_search_start_);
  visitor->Trace(potential_match_);
  visitor->Trace(prefix_match_);
  visitor->Trace(first_match_);
  visitor->Trace(search_range_);
  visitor->Trace(match_range_);
  visitor->Trace(find_buffer_runner_);
}

void TextFragmentFinder::SetPotentialMatch(EphemeralRangeInFlatTree range) {
  if (potential_match_) {
    potential_match_->SetStart(range.StartPosition());
    potential_match_->SetEnd(range.EndPosition());
  } else {
    potential_match_ = MakeGarbageCollected<RangeInFlatTree>(
        range.StartPosition(), range.EndPosition());
  }
}

void TextFragmentFinder::SetPrefixMatch(EphemeralRangeInFlatTree range) {
  if (prefix_match_) {
    prefix_match_->SetStart(range.StartPosition());
    prefix_match_->SetEnd(range.EndPosition());
  } else {
    prefix_match_ = MakeGarbageCollected<RangeInFlatTree>(range.StartPosition(),
                                                          range.EndPosition());
  }
}

bool TextFragmentFinder::HasValidRanges() {
  return !((prefix_match_ &&
            (prefix_match_->IsNull() || !prefix_match_->IsConnected())) ||
           (potential_match_ &&
            (potential_match_->IsNull() || !potential_match_->IsConnected())) ||
           (search_range_ &&
            (search_range_->IsNull() || !search_range_->IsConnected())) ||
           (match_range_ &&
            (match_range_->IsNull() || !match_range_->IsConnected())));
}

}  // namespace blink

"""

```