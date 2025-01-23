Response:
Let's break down the thought process for analyzing the `cold_mode_spell_check_requester.cc` file.

**1. Understanding the Goal:**

The request asks for an analysis of the provided C++ source code, specifically focusing on:

* **Functionality:** What does this code *do*?
* **Relationship to Web Technologies:** How does it interact with JavaScript, HTML, and CSS?
* **Logic and Data Flow:** What are the inputs, processing steps, and outputs?
* **Potential User/Developer Errors:**  What mistakes could occur in its use or trigger issues?
* **User Interaction and Debugging:** How does a user end up triggering this code, and how can it be debugged?

**2. Initial Code Scan and Keyword Spotting:**

The first step is a quick read-through of the code, looking for important keywords and concepts. Some immediate observations:

* **Filename:** `cold_mode_spell_check_requester.cc` –  "cold mode" and "spell check" are strong indicators.
* **Includes:**  Headers like `editing/spellcheck/`, `dom/element.h`, `editing/`, `frame/`, and `scheduler/idle_deadline.h` provide context about the areas of Blink this code interacts with. The presence of `idle_deadline.h` suggests this is something that happens in the background or during idle periods.
* **Class Name:** `ColdModeSpellCheckRequester` – Confirms the initial impression.
* **Methods:**  `Invoke`, `RequestFullChecking`, `RequestLocalChecking`, `ClearProgress`, `Deactivate`, `AccumulateTextDeltaAndComputeCheckingType`, `ElementRemoved`. These method names give clues about the class's responsibilities.
* **Constants:** `kColdModeFullCheckingChunkSize`, `kColdModeLocalCheckingSize`, `kRecheckThreshold`. These numeric constants likely define thresholds or sizes related to the spell-checking process.
* **Data Members:** `window_`, `root_editable_`, `remaining_check_range_`, `fully_checked_root_editables_`. These members store the state of the spell-checking process.
* **Usage of Blink Concepts:**  `Element`, `Position`, `EphemeralRange`, `Selection`, `TextIterator`, `SpellCheckRequester`, `LocalDOMWindow`, `LocalFrame`, `IdleDeadline`. These indicate the code operates within the Blink rendering engine.
* **`TRACE_EVENT0`:** This is a logging mechanism used for performance analysis and debugging in Chromium.

**3. Deeper Analysis of Key Methods:**

Now, let's examine the core methods to understand the logic:

* **`Invoke(IdleDeadline* deadline)`:** This is the main entry point, executed during idle time. It checks if there's a focused editable element and then decides whether to perform local or full spell-checking. The `IdleDeadline` parameter is crucial, indicating that this process is designed to be non-blocking and yield to the main thread.
* **`RequestFullChecking(const Element& element_to_check, IdleDeadline* deadline)`:** This method handles the more thorough spell-checking. It divides the editable content into chunks and checks them iteratively, respecting the `IdleDeadline`. It also tracks progress to avoid re-checking already processed content.
* **`RequestLocalChecking(const Element& element_to_check)`:**  This method performs a lighter-weight spell-check around the current cursor position.
* **`AccumulateTextDeltaAndComputeCheckingType(const Element& element_to_check)`:** This is a clever optimization. It tracks changes in the text content of the editable element. If the changes are small, it opts for a local check. If the changes are significant (above `kRecheckThreshold`), it triggers a full re-check. This avoids unnecessary full checks.

**4. Connecting to Web Technologies (HTML, CSS, JavaScript):**

At this stage, we start connecting the C++ code to web technologies:

* **HTML:** The code operates on `Element` objects, which directly correspond to HTML elements like `<textarea>`, `<div contenteditable="true">`, etc. The spell-checking applies to the text content within these elements.
* **CSS:** While the code doesn't directly manipulate CSS, the *rendering* of the spell-checking suggestions (e.g., red underlines) is influenced by CSS. The layout updates triggered by `UpdateStyleAndLayout` are part of the rendering process that includes CSS.
* **JavaScript:** JavaScript interacts with this code indirectly. User actions in the browser (typing, editing) trigger events that can eventually lead to the `Invoke` method being called. JavaScript can also programmatically manipulate the content of editable elements, which would then be picked up by the cold-mode spell checker.

**5. Logical Reasoning and Examples:**

Now, construct examples to illustrate the code's behavior:

* **Assumption:** User types text into a `<textarea>`.
* **Input:** The `Invoke` method is called with an `IdleDeadline`. The `current_focused` element is the `<textarea>`.
* **Processing:** `AccumulateTextDeltaAndComputeCheckingType` determines if it's a new element or if the text changes are small or large. Based on that, either `RequestLocalChecking` or `RequestFullChecking` is called.
* **Output:** Spell-checking requests are sent to the spell-checking service, and eventually, potential spelling errors are highlighted in the `<textarea>`.

**6. Identifying Potential Errors:**

Consider common mistakes:

* **User Error:**  Typing incorrect words (this is the intended use case!).
* **Developer Error:**  Dynamically modifying the DOM in ways that interfere with the tracking of changes in `AccumulateTextDeltaAndComputeCheckingType`. For example, replacing large portions of text programmatically might not be optimally handled by the delta calculation. Incorrectly setting `contenteditable` attributes or not handling focus correctly could also lead to unexpected behavior.

**7. Tracing User Actions and Debugging:**

Think about how a user gets to this code and how a developer might debug it:

* **User Actions:**
    1. User opens a webpage with an editable element.
    2. User focuses on the editable element.
    3. User starts typing or editing text.
    4. The browser's idle task scheduler triggers the `Invoke` method of `ColdModeSpellCheckRequester`.
* **Debugging:**
    * **Logging:** The `TRACE_EVENT0` calls are crucial for performance analysis and can be used to see when `Invoke`, `RequestFullChecking`, and `RequestLocalChecking` are being called.
    * **Breakpoints:** Setting breakpoints in the C++ code within these methods allows developers to step through the logic and inspect the values of variables like `remaining_check_range_`, `last_chunk_index_`, etc.
    * **Chromium Internals:** Developers might use Chromium's internal debugging tools (like `chrome://tracing`) to get a more holistic view of the spell-checking process.

**8. Structuring the Answer:**

Finally, organize the analysis into clear sections based on the original request: functionality, relationship to web technologies, logical reasoning, potential errors, and debugging. Use clear and concise language, providing specific examples where possible. The use of bullet points and code snippets (even if just method names) can improve readability.
好的，我们来分析一下 `blink/renderer/core/editing/spellcheck/cold_mode_spell_check_requester.cc` 文件的功能。

**功能概述:**

`ColdModeSpellCheckRequester` 类负责在浏览器空闲时（cold mode）对用户输入的可编辑区域进行拼写检查。它是一种后台的、非立即触发的拼写检查机制，旨在减轻实时拼写检查的性能压力。其主要功能包括：

1. **延迟拼写检查:**  当用户在可编辑区域输入文本后，不会立即触发拼写检查，而是在浏览器空闲时进行。
2. **分块检查:**  为了避免一次性检查大量文本造成的性能问题，它将可编辑区域的内容分成多个块（chunk）进行检查。
3. **增量检查优化:**  它会跟踪可编辑区域的文本变化，如果变化不大，则进行局部检查；如果变化较大，则重新进行全局检查。
4. **与 `SpellCheckRequester` 协同:** 它依赖于 `SpellCheckRequester` 类来实际发起拼写检查请求。
5. **处理 DOM 变化:**  能够感知可编辑元素的添加和移除，并相应地调整检查状态。

**与 JavaScript, HTML, CSS 的关系:**

这个 C++ 文件虽然本身不包含 JavaScript、HTML 或 CSS 代码，但它与这三者都有密切关系，因为它处理的是用户在网页上可编辑区域的文本内容。

* **HTML:**
    * **目标是 HTML 元素:** `ColdModeSpellCheckRequester` 关注的是页面中可编辑的 HTML 元素，例如 `<textarea>` 标签，或者设置了 `contenteditable="true"` 属性的 `<div>`、`<p>` 等元素。
    * **识别可编辑区域:**  通过检查 DOM 树，找到当前获得焦点的、允许拼写检查的 HTML 元素。
    * **假设输入与输出:**
        * **假设输入:** 用户在一个 `<textarea>` 元素中输入了一段文字 "Thiss is an exmaple."
        * **输出:**  `ColdModeSpellCheckRequester` 会将这段文字（可能分块）传递给拼写检查服务，最终 "Thiss" 和 "exmaple" 可能会被标记为拼写错误，并在用户界面上显示（例如，下划线）。

* **JavaScript:**
    * **间接交互:** JavaScript 可以动态地修改 HTML 结构和内容，包括可编辑区域的内容。这些修改会影响 `ColdModeSpellCheckRequester` 的检查范围和触发时机。
    * **用户操作触发:** 用户在浏览器中的操作（例如在可编辑区域输入、删除、粘贴文本）会触发 JavaScript 事件，这些事件最终会导致浏览器重新渲染和布局，并可能在空闲时触发 `ColdModeSpellCheckRequester` 的 `Invoke` 方法。
    * **假设输入与输出:**
        * **假设输入:**  JavaScript 代码使用 `document.getElementById('myTextarea').value = 'New text with speling errors.';`  来修改一个 `<textarea>` 的内容。
        * **输出:**  在浏览器空闲时，`ColdModeSpellCheckRequester` 会检测到 `myTextarea` 内容的改变，并对其进行拼写检查。

* **CSS:**
    * **呈现拼写错误:** CSS 负责拼写错误标记的视觉呈现，例如红色波浪线。`ColdModeSpellCheckRequester` 负责检测错误，而 CSS 决定如何显示这些错误。
    * **布局影响:**  当拼写检查结果返回并需要在页面上标记错误时，可能会触发浏览器的重新布局和重绘，这与 CSS 的渲染机制有关。
    * **假设输入与输出:**
        * **假设输入:**  `ColdModeSpellCheckRequester` 检测到单词 "misstake" 是拼写错误。
        * **输出:**  浏览器会应用 CSS 样式，例如添加一个红色的 `text-decoration: underline wavy red;` 到 "misstake" 这个单词上。

**逻辑推理 (假设输入与输出):**

假设用户在一个 `<div contenteditable="true">` 元素中进行输入：

1. **用户输入:** 用户输入 "Hello worlld".
2. **`Invoke` 调用:** 在浏览器空闲时，`ColdModeSpellCheckRequester::Invoke` 方法被调用。
3. **获取焦点元素:** `CurrentFocusedEditable` 方法找到当前获得焦点的 `<div>` 元素。
4. **判断检查类型:** `AccumulateTextDeltaAndComputeCheckingType` 方法会检查这个 `<div>` 元素是否之前被完整检查过。
   * **如果之前没有检查过:** 返回 `CheckingType::kFull`。
   * **如果之前检查过:** 它会比较当前文本长度与上次检查时的长度，计算文本变化量。
     * **如果变化量大于 `kRecheckThreshold` (1024):**  返回 `CheckingType::kFull`。
     * **如果变化量小于等于 `kRecheckThreshold`:** 返回 `CheckingType::kLocal`。
5. **发起检查请求:**
   * **`RequestFullChecking` (如果需要全局检查):**
     * 将 `<div>` 的内容分成多个大小为 `kColdModeFullCheckingChunkSize` (16384) 的块。
     * 逐个块调用 `GetSpellCheckRequester().RequestCheckingFor()` 发起拼写检查请求。
   * **`RequestLocalChecking` (如果需要局部检查):**
     * 获取当前光标位置。
     * 在光标前后 `kColdModeLocalCheckingSize / 2` (64) 的范围内选取文本。
     * 调用 `GetSpellCheckRequester().RequestCheckingFor()` 发起拼写检查请求。
6. **拼写检查结果:**  拼写检查服务返回结果，例如 "worlld" 是拼写错误。
7. **UI 更新:** 浏览器根据拼写检查结果，使用 CSS 样式在 "worlld" 下方绘制红色波浪线。

**用户或编程常见的使用错误:**

1. **用户禁用拼写检查:**  用户可以在浏览器设置中禁用拼写检查，这将导致 `ColdModeSpellCheckRequester` 不会执行任何操作。
2. **可编辑属性设置错误:**  开发者可能错误地设置了 HTML 元素的 `contenteditable` 属性，导致某些应该进行拼写检查的区域没有被识别。
3. **动态修改 DOM 导致重复检查:**  如果 JavaScript 代码频繁地、大幅度地修改可编辑区域的内容，可能会导致 `ColdModeSpellCheckRequester` 频繁地进行全局检查，影响性能。开发者应该尽量优化 DOM 操作，避免不必要的重绘和重排。
4. **假设错误示例:**
    * **错误的用户操作:** 用户在浏览器设置中关闭了拼写检查功能。此时，即使在可编辑区域输入错误，也不会有任何拼写提示。
    * **错误的编程操作:**  开发者使用 JavaScript 代码移除了一个可编辑元素，然后又立即将其添加回 DOM 树。这可能导致 `ColdModeSpellCheckRequester` 认为这是一个全新的元素，并重新进行全局检查，即使内容没有改变。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户打开网页:** 用户在浏览器中打开一个包含可编辑元素的网页（例如，一个带有 `<textarea>` 或 `contenteditable` 属性的 `<div>` 的页面）。
2. **用户与可编辑元素交互:**
   * **获取焦点:** 用户点击或使用 Tab 键将焦点移动到可编辑元素上。`ColdModeSpellCheckRequester::CurrentFocusedEditable()` 会检测到这个元素。
   * **输入文本:** 用户在可编辑元素中输入文本。
3. **浏览器事件循环:**  用户的输入操作会触发键盘事件和 `input` 事件等。浏览器会处理这些事件，更新 DOM 结构，并进行渲染。
4. **空闲检测:**  Chromium 的调度器（scheduler）会检测到主线程进入空闲状态。
5. **`IdleDeadline` 回调:**  调度器会调用注册的空闲回调函数，其中就包括 `ColdModeSpellCheckRequester::Invoke` 方法。
6. **执行拼写检查逻辑:** `Invoke` 方法根据当前状态和文本变化情况，决定是否进行全局或局部拼写检查，并调用 `SpellCheckRequester` 发起检查请求。

**调试线索:**

* **断点:** 在 `ColdModeSpellCheckRequester::Invoke`、`RequestFullChecking`、`RequestLocalChecking`、`AccumulateTextDeltaAndComputeCheckingType` 等关键方法中设置断点，可以观察代码的执行流程和变量值。
* **日志:** 可以添加 `DLOG` 或 `TRACE_EVENT` 来输出关键信息，例如当前焦点元素、文本长度、检查类型等。
* **Chromium 追踪工具:** 使用 `chrome://tracing` 可以记录浏览器的运行轨迹，查看 `ColdModeSpellCheckRequester::invoke` 等事件的发生时间和耗时，帮助分析性能问题。
* **检查 `SpellCheckRequester`:** 观察 `SpellCheckRequester` 的相关方法是否被正确调用，以及拼写检查请求是否成功发送和接收。
* **DOM 观察:** 使用浏览器的开发者工具观察 DOM 树的变化，特别是可编辑元素的属性和内容，确认是否符合预期。

总而言之，`ColdModeSpellCheckRequester` 是 Chromium Blink 引擎中一个重要的后台拼写检查模块，它通过在浏览器空闲时进行非侵入式的拼写检查，提升了用户体验，并与 JavaScript、HTML 和 CSS 紧密协作，共同构建了网页的编辑功能。

### 提示词
```
这是目录为blink/renderer/core/editing/spellcheck/cold_mode_spell_check_requester.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/spellcheck/cold_mode_spell_check_requester.h"

#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/iterators/backwards_character_iterator.h"
#include "third_party/blink/renderer/core/editing/iterators/character_iterator.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/spellcheck/spell_check_requester.h"
#include "third_party/blink/renderer/core/editing/spellcheck/spell_checker.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/scheduler/idle_deadline.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"

namespace blink {

namespace {

// in UTF16 code units
const int kColdModeFullCheckingChunkSize = 16384;
const int kColdModeLocalCheckingSize = 128;
const int kRecheckThreshold = 1024;

const int kInvalidChunkIndex = -1;

int TotalTextLength(const Element& root_editable) {
  const EphemeralRange& full_range =
      EphemeralRange::RangeOfContents(root_editable);
  return TextIterator::RangeLength(full_range);
}

}  // namespace

void ColdModeSpellCheckRequester::Trace(Visitor* visitor) const {
  visitor->Trace(window_);
  visitor->Trace(root_editable_);
  visitor->Trace(remaining_check_range_);
  visitor->Trace(fully_checked_root_editables_);
}

ColdModeSpellCheckRequester::ColdModeSpellCheckRequester(LocalDOMWindow& window)
    : window_(window),
      last_chunk_index_(kInvalidChunkIndex),
      needs_more_invocation_for_testing_(false) {}

bool ColdModeSpellCheckRequester::FullyCheckedCurrentRootEditable() const {
  if (needs_more_invocation_for_testing_) {
    needs_more_invocation_for_testing_ = false;
    return false;
  }
  // Note that DOM mutations between cold mode invocations may corrupt the
  // stored states, in which case we also consider checking as finished.
  return !root_editable_ || !remaining_check_range_ ||
         remaining_check_range_->collapsed() ||
         !remaining_check_range_->IsConnected() ||
         !root_editable_->contains(
             remaining_check_range_->commonAncestorContainer());
}

SpellCheckRequester& ColdModeSpellCheckRequester::GetSpellCheckRequester()
    const {
  return window_->GetSpellChecker().GetSpellCheckRequester();
}

const Element* ColdModeSpellCheckRequester::CurrentFocusedEditable() const {
  const Position position =
      window_->GetFrame()->Selection().GetSelectionInDOMTree().Focus();
  if (position.IsNull())
    return nullptr;

  const auto* element = DynamicTo<Element>(HighestEditableRoot(position));
  if (!element || !element->isConnected())
    return nullptr;

  if (!element->IsSpellCheckingEnabled() ||
      !SpellChecker::IsSpellCheckingEnabledAt(position))
    return nullptr;

  return element;
}

void ColdModeSpellCheckRequester::Invoke(IdleDeadline* deadline) {
  TRACE_EVENT0("blink", "ColdModeSpellCheckRequester::invoke");

  // TODO(xiaochengh): Figure out if this has any performance impact.
  window_->document()->UpdateStyleAndLayout(DocumentUpdateReason::kSpellCheck);

  const Element* current_focused = CurrentFocusedEditable();
  if (!current_focused) {
    ClearProgress();
    return;
  }

  switch (AccumulateTextDeltaAndComputeCheckingType(*current_focused)) {
    case CheckingType::kNone:
      return;
    case CheckingType::kLocal:
      return RequestLocalChecking(*current_focused);
    case CheckingType::kFull:
      return RequestFullChecking(*current_focused, deadline);
  }
}

void ColdModeSpellCheckRequester::RequestFullChecking(
    const Element& element_to_check,
    IdleDeadline* deadline) {
  TRACE_EVENT0("blink", "ColdModeSpellCheckRequester::RequestFullChecking");

  if (root_editable_ != &element_to_check) {
    ClearProgress();
    root_editable_ = &element_to_check;
    last_chunk_index_ = 0;
    remaining_check_range_ = Range::Create(root_editable_->GetDocument());
    remaining_check_range_->selectNodeContents(
        const_cast<Element*>(root_editable_.Get()), ASSERT_NO_EXCEPTION);
  }

  while (deadline->timeRemaining() > 0) {
    if (FullyCheckedCurrentRootEditable() || !RequestCheckingForNextChunk()) {
      SetHasFullyCheckedCurrentRootEditable();
      return;
    }
  }
}

void ColdModeSpellCheckRequester::ClearProgress() {
  root_editable_ = nullptr;
  last_chunk_index_ = kInvalidChunkIndex;
  if (!remaining_check_range_)
    return;
  remaining_check_range_->Dispose();
  remaining_check_range_ = nullptr;
}

void ColdModeSpellCheckRequester::Deactivate() {
  ClearProgress();
  fully_checked_root_editables_.clear();
}

void ColdModeSpellCheckRequester::SetHasFullyCheckedCurrentRootEditable() {
  DCHECK(root_editable_);
  DCHECK(!fully_checked_root_editables_.Contains(root_editable_));

  fully_checked_root_editables_.Set(
      root_editable_, FullyCheckedEditableEntry{
                          TotalTextLength(*root_editable_), 0,
                          root_editable_->GetDocument().DomTreeVersion()});
  last_chunk_index_ = kInvalidChunkIndex;
  if (!remaining_check_range_)
    return;
  remaining_check_range_->Dispose();
  remaining_check_range_ = nullptr;
}

bool ColdModeSpellCheckRequester::RequestCheckingForNextChunk() {
  DCHECK(root_editable_);
  DCHECK(!FullyCheckedCurrentRootEditable());

  const EphemeralRange remaining_range(remaining_check_range_);
  const int remaining_length = TextIterator::RangeLength(
      remaining_range,
      // Same behavior used in |CalculateCharacterSubrange()|
      TextIteratorBehavior::EmitsObjectReplacementCharacterBehavior());
  if (remaining_length == 0)
    return false;

  const int chunk_index = last_chunk_index_ + 1;
  const Position chunk_start = remaining_range.StartPosition();
  const Position chunk_end =
      CalculateCharacterSubrange(
          remaining_range, 0,
          std::min(remaining_length, kColdModeFullCheckingChunkSize))
          .EndPosition();

  // Chromium spellchecker requires complete sentences to be checked. However,
  // EndOfSentence() sometimes returns null or out-of-editable positions, which
  // are corrected here.
  const Position extended_end = EndOfSentence(chunk_end).GetPosition();
  const Position check_end =
      extended_end.IsNull() || extended_end < chunk_end
          ? chunk_end
          : std::min(extended_end, remaining_range.EndPosition());
  const EphemeralRange check_range(chunk_start, check_end);

  GetSpellCheckRequester().RequestCheckingFor(check_range, chunk_index);

  last_chunk_index_ = chunk_index;
  remaining_check_range_->setStart(check_range.EndPosition());
  return true;
}

ColdModeSpellCheckRequester::CheckingType
ColdModeSpellCheckRequester::AccumulateTextDeltaAndComputeCheckingType(
    const Element& element_to_check) {
  // Do full checking if we haven't done that before
  auto iter = fully_checked_root_editables_.find(&element_to_check);
  if (iter == fully_checked_root_editables_.end())
    return CheckingType::kFull;

  uint64_t dom_tree_version = element_to_check.GetDocument().DomTreeVersion();

  // Nothing to check, because nothing has changed.
  if (dom_tree_version == iter->value.previous_checked_dom_tree_version) {
    return CheckingType::kNone;
  }
  iter->value.previous_checked_dom_tree_version =
      element_to_check.GetDocument().DomTreeVersion();

  // Compute the amount of text change heuristically. Invoke a full check if
  // the accumulated change is above a threshold; or a local check otherwise.

  int current_text_length = TotalTextLength(element_to_check);
  int delta =
      std::abs(current_text_length - iter->value.previous_checked_length);

  iter->value.accumulated_delta += delta;
  iter->value.previous_checked_length = current_text_length;

  if (iter->value.accumulated_delta > kRecheckThreshold) {
    fully_checked_root_editables_.erase(iter);
    return CheckingType::kFull;
  }

  return CheckingType::kLocal;
}

void ColdModeSpellCheckRequester::RequestLocalChecking(
    const Element& element_to_check) {
  TRACE_EVENT0("blink", "ColdModeSpellCheckRequester::RequestLocalChecking");

  const EphemeralRange& full_range =
      EphemeralRange::RangeOfContents(element_to_check);
  const Position position =
      window_->GetFrame()->Selection().GetSelectionInDOMTree().Focus();
  DCHECK(position.IsNotNull());

  TextIteratorBehavior behavior =
      TextIteratorBehavior::Builder()
          .SetEmitsObjectReplacementCharacter(true)
          .SetEmitsPunctuationForReplacedElements(true)
          .Build();
  BackwardsCharacterIterator backward_iterator(
      EphemeralRange(full_range.StartPosition(), position), behavior);
  if (!backward_iterator.AtEnd())
    backward_iterator.Advance(kColdModeLocalCheckingSize / 2);
  const Position& chunk_start = backward_iterator.EndPosition();
  CharacterIterator forward_iterator(position, full_range.EndPosition(),
                                     behavior);
  if (!forward_iterator.AtEnd())
    forward_iterator.Advance(kColdModeLocalCheckingSize / 2);
  const Position& chunk_end = forward_iterator.EndPosition();
  EphemeralRange checking_range =
      ExpandRangeToSentenceBoundary(EphemeralRange(chunk_start, chunk_end));

  GetSpellCheckRequester().RequestCheckingFor(checking_range);
}

void ColdModeSpellCheckRequester::ElementRemoved(Element* element) {
  if (root_editable_ == element) {
    ClearProgress();
  }
}

}  // namespace blink
```