Response:
The user wants me to analyze the provided C++ code snippet from `text_finder.cc` in the Chromium Blink engine. I need to:

1. **List the functionalities** present in the code.
2. **Identify relationships with web technologies (JavaScript, HTML, CSS)** and provide examples.
3. **Demonstrate logical reasoning** with hypothetical input and output.
4. **Point out potential user or programming errors** with examples.
5. **Explain how a user action leads to this code** as a debugging aid.
6. **Summarize the functionalities** of this first part of the file.

Let's break down the code section by section to address each point.

**Functionalities:**

- Finding text within a document.
- Highlighting found text matches.
- Scrolling to found matches.
- Managing the active match.
- Handling find-in-page requests across frames.
- Interacting with accessibility features.
- Optimizing search performance through asynchronous tasks.
- Managing the visual presentation of find results (tickmarks on the scrollbar).
- Expanding hidden elements like `<details>` and elements with `hidden=until-found` to make matches visible.

**Relationships with JavaScript, HTML, and CSS:**

- **HTML:** The code interacts directly with HTML elements like `<details>`, `<input>`, `<textarea>`, and frame owners (`HTMLFrameOwnerElement`). It expands `<details>` elements to make matches visible, demonstrating interaction with HTML structure. It also interacts with `hidden=until-found` attribute.
- **CSS:** The code implicitly interacts with CSS through layout calculations (`LayoutObject`, `BoundingBox`). The visibility of elements and their layout are crucial for finding and scrolling to matches. The code explicitly deals with `content-visibility: auto`.
- **JavaScript:**  While this specific code is C++, it's part of the browser's rendering engine, which is heavily influenced by JavaScript actions. User interactions triggered by JavaScript, such as initiating a find operation or navigating the page, can lead to this code being executed.

**Logical Reasoning (Hypothetical Input and Output):**

* **Input:** User presses Ctrl+F (or Cmd+F on macOS) and types "example" into the find bar.
* **Processing:** The `TextFinder::Find` function (or `FindInternal`) is called with the search string "example". The code searches through the DOM tree, identifying occurrences of "example".
* **Output:** The first occurrence of "example" is highlighted. The browser may scroll to bring the match into view. Tickmarks are added to the scrollbar to indicate other matches.

**User/Programming Errors:**

* **User Error:**  A user might search for text that is inside a collapsed `<details>` element. Without the logic in this code to expand it, the user might think the search failed.
* **Programming Error:** If the layout information is not up-to-date (e.g., due to asynchronous JavaScript modifications), the `BoundingBox()` calculation might be incorrect, leading to incorrect highlighting or scrolling. The code attempts to mitigate this by forcing layout updates.

**User Operation Leading to This Code (Debugging Clue):**

1. **User presses Ctrl+F (or Cmd+F on macOS).** This action triggers the browser's find-in-page functionality.
2. **The browser's UI displays a find bar.**
3. **The user types a search term into the find bar.**
4. **The user presses Enter or clicks the "Find Next" button.** This initiates a find operation.
5. **The browser's UI (likely implemented in JavaScript) communicates the search request to the rendering engine (Blink).**
6. **The `TextFinder::Find` or `TextFinder::FindInternal` method in `text_finder.cc` is called.** This is where the code snippet's functionality begins.

**Summary of Functionalities (Part 1):**

This first part of `text_finder.cc` focuses on the core logic of finding text within a web page. It includes:

- **Initialization and setup for a new find session.**
- **The main find algorithm (`FindInternal`) which searches for a given string within the document.**
- **Handling wrapping around the document during the search.**
- **Managing the active text match and highlighting it.**
- **Scrolling the active match into view.**
- **Interacting with the display lock mechanism to ensure accurate layout during the search.**
- **Expanding hidden content (like `<details>` elements) to make matches visible.**
- **Basic management of find results and their visual representation.**
- **Interfacing with accessibility features to report find results.**

这是 `blink/renderer/core/editing/finder/text_finder.cc` 文件的第一部分，主要负责在 Chromium Blink 引擎中实现**查找页面内文本**的功能。它的核心职责是接收查找请求，在 DOM 树中搜索匹配的文本，并管理查找结果的呈现和交互。

以下是该部分代码功能的归纳和详细说明：

**核心功能:**

1. **启动和管理查找会话 (Find Session):**
   - `InitNewSession`: 初始化一个新的查找会话，例如当用户首次按下 Ctrl+F 或 Cmd+F 时。它可以重置一些状态，并根据选项决定是否需要定位当前激活的匹配项。
   - `Find`:  是主要的查找入口点，接收查找标识符、搜索文本和查找选项。它会调用 `FindInternal` 执行实际的查找操作。
   - `FindInternal`:  执行实际的文本查找逻辑。它使用 `Editor::FindRangeOfString` 函数在文档中查找匹配的文本范围。它可以处理查找方向、大小写敏感、是否循环查找等选项。

2. **文本查找和匹配:**
   - 使用 `Editor::FindRangeOfString` 函数进行实际的文本查找。
   - 可以处理跨越多个节点的文本匹配。
   - 允许指定查找方向（向前或向后）。
   - 支持大小写敏感或不敏感的查找。
   - 支持在当前帧内循环查找。

3. **匹配结果的管理和高亮:**
   - `active_match_`:  存储当前激活的匹配项的 `Range` 对象。
   - 使用 `DocumentMarker` 在文档中标记找到的文本匹配项，并可以高亮显示激活的匹配项。
   - `SetMarkerActive`:  设置指定匹配项的激活状态，用于高亮显示。
   - `UnmarkAllTextMatches`: 清除所有文本匹配标记。

4. **滚动到匹配项:**
   - `ScrollToVisible`: 将找到的匹配项滚动到可视区域。
   - 考虑了平滑滚动的设置。
   - 可以自动展开被隐藏的元素（如 `<details>`）以使匹配项可见。

5. **跨 Frame 查找的支持:**
   -  代码中涉及到处理父 Frame 和子 Frame 的情况，例如 `AutoExpandSearchableHiddenElementsUpFrameTree` 函数会向上遍历 Frame 树来展开可能包含匹配项的隐藏元素。

6. **与用户交互相关的处理:**
   - 如果用户在上次查找后选择了文本，则下一次查找会从用户选择的位置开始。
   - 在找到匹配项后，可以清除文档的焦点元素，并将当前 Frame 设置为焦点。

7. **异步滚动处理:**
   - 使用 `AnimationFrameTask` 来异步执行滚动操作，以避免阻塞渲染线程。

**与 JavaScript, HTML, CSS 的关系:**

* **HTML:**
    - 代码直接操作 HTML 元素，例如 `HTMLDetailsElement::ExpandDetailsAncestors` 用于展开 `<details>` 元素，这直接影响了 HTML 结构的呈现。
    - 代码还会检查和处理 `hidden=until-found` 属性，这也是 HTML 特性。
    - `HTMLInputElement` 和 `HTMLTextAreaElement` 等元素被提及，用于在找到匹配项后尝试聚焦到可聚焦的元素上。
    - `HTMLFrameOwnerElement` 用于处理跨 Frame 的查找。

    **举例:** 当用户查找的文本位于一个初始状态为折叠的 `<details>` 元素内时，`HTMLDetailsElement::ExpandDetailsAncestors` 会被调用，修改 HTML 结构，展开该元素，从而使匹配项可见。

* **CSS:**
    - 代码通过 `LayoutObject` 和 `BoundingBox()` 获取元素的布局信息，这与 CSS 的渲染密切相关。查找到的文本的位置和大小是由 CSS 样式决定的。
    - `content-visibility: auto` 属性的处理也与 CSS 的渲染优化有关。

    **举例:**  查找到的文本的背景高亮样式（由 `DocumentMarker` 实现）是由 CSS 定义的。`BoundingBox()` 的计算依赖于元素的 CSS 布局。

* **JavaScript:**
    - 虽然这段代码是 C++，但它是 Blink 渲染引擎的一部分，与 JavaScript 紧密协作。用户在页面上执行的 JavaScript 代码可能会动态修改 DOM 结构，而 `TextFinder` 需要能够在这种动态变化的环境中正确地查找文本。
    - JavaScript 可以调用浏览器提供的 API (如 `window.find()`) 来触发页面内的查找功能，最终会调用到 `TextFinder` 中的方法。

    **举例:** 一个 JavaScript 脚本可能会动态地创建一个包含用户要查找的文本的元素。`TextFinder` 必须能够在新的 DOM 结构中找到该文本。

**逻辑推理 (假设输入与输出):**

假设用户在一个包含以下 HTML 的页面中查找 "hello"：

```html
<div>
  <p>This is some text.</p>
  <p>hello world</p>
  <p>Another hello.</p>
</div>
```

**假设输入:**

- `search_text`: "hello"
- `options.forward`: true (向前查找)
- `options.match_case`: false (不区分大小写)

**逻辑推理:**

1. `FindInternal` 被调用，开始在文档中查找 "hello"。
2. 第一个匹配项 "hello world" 中的 "hello" 被找到。
3. `active_match_` 被设置为指向该匹配项的 `Range` 对象。
4. `ScrollToVisible` 被调用，将包含 "hello world" 的段落滚动到可视区域。
5. 对应的文本范围会被标记为匹配项，并高亮显示。

**假设输出:**

- 页面滚动，使包含 "hello world" 的段落可见。
- "hello" 这五个字母在 "hello world" 中被高亮显示。
- 滚动条上可能出现指示其他匹配项的标记。

**用户或编程常见的使用错误:**

* **用户错误:** 用户可能在一个很长的文档中查找一个非常常见的词，导致页面上出现大量的匹配项，可能会影响性能。
* **编程错误:**
    - 如果在查找过程中 DOM 结构发生了显著变化，而 `TextFinder` 没有正确地处理这些变化，可能会导致查找到错误的匹配项或者找不到匹配项。
    - 如果布局信息不正确或过时，`BoundingBox()` 的计算结果可能不准确，导致滚动到错误的位置或高亮不正确。

**用户操作如何一步步的到达这里 (调试线索):**

1. 用户打开一个网页。
2. 用户按下键盘上的 **Ctrl+F** (Windows/Linux) 或 **Cmd+F** (macOS)。
3. 浏览器窗口顶部或底部会出现一个 **查找栏 (Find Bar)**。
4. 用户在查找栏中 **输入要查找的文本**，例如 "example"。
5. 用户按下 **Enter** 键或点击查找栏上的 **“下一个”** 或 **“上一个”** 按钮。
6. 浏览器的 UI 组件捕获到用户的查找请求，并将请求传递给 **Blink 渲染引擎**。
7. 在 Blink 渲染引擎中，负责处理查找功能的模块（即 `blink/renderer/core/editing/finder` 目录下的代码）接收到请求。
8. 具体来说，`TextFinder::Find` 或 `TextFinder::FindInternal` 方法会被调用，开始执行文本查找的逻辑。

**总结 (第一部分功能):**

`blink/renderer/core/editing/finder/text_finder.cc` 的第一部分主要实现了查找页面内文本的核心功能，包括启动和管理查找会话、执行实际的文本查找、管理和高亮匹配结果、以及滚动到匹配项。它还涉及到跨 Frame 查找的支持，并与 HTML、CSS 以及 JavaScript 驱动的用户交互密切相关。这段代码是浏览器查找功能的基础，为用户在网页上快速定位信息提供了支持。

### 提示词
```
这是目录为blink/renderer/core/editing/finder/text_finder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2009 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/editing/finder/text_finder.h"

#include "third_party/blink/public/mojom/input/focus_type.mojom-blink.h"
#include "third_party/blink/public/mojom/scroll/scroll_into_view_params.mojom-blink.h"
#include "third_party/blink/public/platform/web_vector.h"
#include "third_party/blink/public/web/web_frame_widget.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache_base.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_document_state.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/finder/find_in_page_coordinates.h"
#include "third_party/blink/renderer/core/editing/finder/find_options.h"
#include "third_party/blink/renderer/core/editing/finder/find_task_controller.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/find_in_page.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/html/html_details_element.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_shift_tracker.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/text_autosizer.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/scroll/scroll_into_view_util.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/timer.h"

namespace blink {

TextFinder::FindMatch::FindMatch(Range* range, int ordinal)
    : range_(range), ordinal_(ordinal) {}

void TextFinder::FindMatch::Trace(Visitor* visitor) const {
  visitor->Trace(range_);
}

static void AutoExpandSearchableHiddenElementsUpFrameTree(Range* range) {
  const Node& first_node = *range->FirstNode();
  bool needs_layout_shift_allowance = false;

  // If the target text is in a content-visibility:auto subtree, then activate
  // it so we can scroll to it.
  if (DisplayLockUtilities::ActivateFindInPageMatchRangeIfNeeded(
          EphemeralRangeInFlatTree(range))) {
    needs_layout_shift_allowance = true;
  }

  // If the active match is hidden inside a <details> element, then we should
  // expand it so find-in-page can scroll to it.
  if (HTMLDetailsElement::ExpandDetailsAncestors(first_node)) {
    needs_layout_shift_allowance = true;
    UseCounter::Count(first_node.GetDocument(),
                      WebFeature::kAutoExpandedDetailsForFindInPage);
  }

  // If the active match is hidden inside a hidden=until-found element, then we
  // should reveal it so find-in-page can scroll to it.
  if (DisplayLockUtilities::RevealHiddenUntilFoundAncestors(first_node)) {
    needs_layout_shift_allowance = true;
    UseCounter::Count(first_node.GetDocument(),
                      WebFeature::kBeforematchRevealedHiddenMatchable);
    first_node.GetDocument()
        .MarkHasFindInPageBeforematchExpandedHiddenMatchable();
  }

  if (needs_layout_shift_allowance) {
    first_node.GetDocument()
        .GetFrame()
        ->View()
        ->GetLayoutShiftTracker()
        .NotifyFindInPageInput();
  }

  // Also reveal expandables up the frame tree.
  for (Frame *frame = first_node.GetDocument().GetFrame(),
             *parent = frame->Parent();
       frame && parent; frame = parent, parent = parent->Parent()) {
    LocalFrame* local_parent = DynamicTo<LocalFrame>(parent);
    LocalFrame* local_frame = DynamicTo<LocalFrame>(frame);

    if (local_frame && local_parent) {
      // TODO(crbug.com/1250847): Consider replacing the usage of
      // DeprecatedLocalOwner with a virtual function on FrameOwner when
      // implementing this for RemoteFrames.
      HTMLFrameOwnerElement* frame_element =
          local_frame->DeprecatedLocalOwner();
      DCHECK(frame_element);
      bool frame_needs_style_and_layout = false;
      frame_needs_style_and_layout |=
          HTMLDetailsElement::ExpandDetailsAncestors(*frame_element);
      frame_needs_style_and_layout |=
          DisplayLockUtilities::RevealHiddenUntilFoundAncestors(*frame_element);
      if (frame_needs_style_and_layout) {
        frame_element->GetDocument().UpdateStyleAndLayoutForNode(
            frame_element, DocumentUpdateReason::kFindInPage);
        needs_layout_shift_allowance = true;
      }
    } else {
      // TODO(crbug.com/1250847): Implement an IPC signal to expand in parent
      // RemoteFrames.
    }
  }
}

static void ScrollToVisible(Range* match) {
  const EphemeralRangeInFlatTree range(match);
  const Node& first_node = *match->FirstNode();

  // We don't always have a LayoutObject for the node we're trying to scroll to
  // after the async step: crbug.com/1129341
  if (!first_node.GetLayoutObject())
    return;

  Settings* settings = first_node.GetDocument().GetSettings();
  bool smooth_find_enabled =
      settings ? settings->GetSmoothScrollForFindEnabled() : false;
  mojom::blink::ScrollBehavior scroll_behavior =
      smooth_find_enabled ? mojom::blink::ScrollBehavior::kSmooth
                          : mojom::blink::ScrollBehavior::kInstant;
  scroll_into_view_util::ScrollRectToVisible(
      *first_node.GetLayoutObject(), PhysicalRect(match->BoundingBox()),
      scroll_into_view_util::CreateScrollIntoViewParams(
          ScrollAlignment::CenterIfNeeded(), ScrollAlignment::CenterIfNeeded(),
          mojom::blink::ScrollType::kUser,
          true /* make_visible_in_visual_viewport */, scroll_behavior,
          true /* is_for_scroll_sequence */));
  first_node.GetDocument().SetSequentialFocusNavigationStartingPoint(
      const_cast<Node*>(&first_node));
}

void TextFinder::InitNewSession(const mojom::blink::FindOptions& options) {
  should_locate_active_rect_ = false;
  CancelPendingScopingEffort();
  if (!options.find_match) {
    // This gets called in FindInternal if a match is found, but FindInternal
    // doesn't run when find_match is false, so we need to do it here in case
    // there is a match (to get the scoping effort to look for it).
    find_task_controller_->ResetLastFindRequestCompletedWithNoMatches();
  }
}

bool TextFinder::Find(int identifier,
                      const String& search_text,
                      const mojom::blink::FindOptions& options,
                      bool wrap_within_frame,
                      bool* active_now) {
  return FindInternal(identifier, search_text, options, wrap_within_frame,
                      active_now);
}

bool TextFinder::FindInternal(int identifier,
                              const String& search_text,
                              const mojom::blink::FindOptions& options,
                              bool wrap_within_frame,
                              bool* active_now,
                              Range* first_match,
                              bool wrapped_around) {
  // Searching text without forcing DisplayLocks is likely to hit bad layout
  // state, so force them here and update style and layout in order to get good
  // layout state.
  auto forced_activatable_locks = GetFrame()
                                      ->GetDocument()
                                      ->GetDisplayLockDocumentState()
                                      .GetScopedForceActivatableLocks();
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kFindInPage);

  if (options.new_session) {
    // This find-in-page is redone due to the frame finishing loading.
    // If we can, just reuse the old active match;
    if (options.force && active_match_) {
      should_locate_active_rect_ = true;
      return true;
    }
    UnmarkAllTextMatches();
  } else {
    SetMarkerActive(active_match_.Get(), false);
  }
  if (active_match_ &&
      &active_match_->OwnerDocument() != OwnerFrame().GetFrame()->GetDocument())
    active_match_ = nullptr;

  // If the user has selected something since the last Find operation we want
  // to start from there. Otherwise, we start searching from where the last Find
  // operation left off (either a Find or a FindNext operation).
  // TODO(editing-dev): The use of VisibleSelection should be audited. See
  // crbug.com/657237 for details.
  VisibleSelection selection(
      OwnerFrame().GetFrame()->Selection().ComputeVisibleSelectionInDOMTree());
  bool active_selection = !selection.IsNone();
  if (active_selection) {
    active_match_ = CreateRange(FirstEphemeralRangeOf(selection));
    OwnerFrame().GetFrame()->Selection().Clear();
  }

  DCHECK(OwnerFrame().GetFrame());
  DCHECK(OwnerFrame().GetFrame()->View());
  const auto find_options = FindOptions()
                                .SetBackwards(!options.forward)
                                .SetCaseInsensitive(!options.match_case)
                                .SetWrappingAround(wrap_within_frame)
                                .SetStartingInSelection(options.new_session)
                                .SetRubySupported(true);
  active_match_ = Editor::FindRangeOfString(
      *OwnerFrame().GetFrame()->GetDocument(), search_text,
      EphemeralRangeInFlatTree(active_match_.Get()), find_options,
      &wrapped_around);

  if (!active_match_) {
    if (current_active_match_frame_ && options.new_session)
      should_locate_active_rect_ = true;
    // In an existing session the next active match might not be in
    // frame.  In this case we don't want to clear the matches cache.
    if (options.new_session)
      ClearFindMatchesCache();

    InvalidatePaintForTickmarks();
    return false;
  }

  // We don't want to search past the same position twice, so if the new match
  // is past the original one and we have wrapped around, then stop now.
  if (first_match && wrapped_around) {
    if (options.forward) {
      // If the start of the new match has gone past the start of the original
      // match, then stop.
      if (ComparePositions(first_match->StartPosition(),
                           active_match_->StartPosition()) <= 0) {
        return false;
      }
    } else {
      // If the end of the new match has gone before the end of the original
      // match, then stop.
      if (ComparePositions(active_match_->EndPosition(),
                           first_match->EndPosition()) <= 0) {
        return false;
      }
    }
  }

  std::unique_ptr<AsyncScrollContext> scroll_context =
      std::make_unique<AsyncScrollContext>();
  scroll_context->identifier = identifier;
  scroll_context->search_text = search_text;
  scroll_context->options = options;
  // Set new_session to false to make sure that subsequent searches are
  // incremental instead of repeatedly finding the same match.
  scroll_context->options.new_session = false;
  scroll_context->wrap_within_frame = wrap_within_frame;
  scroll_context->range = active_match_.Get();
  scroll_context->first_match = first_match ? first_match : active_match_.Get();
  scroll_context->wrapped_around = wrapped_around;
  if (options.run_synchronously_for_testing) {
    Scroll(std::move(scroll_context));
  } else {
    scroll_task_.Reset(WTF::BindOnce(&TextFinder::Scroll,
                                     WrapWeakPersistent(this),
                                     std::move(scroll_context)));
    GetFrame()->GetDocument()->EnqueueAnimationFrameTask(
        scroll_task_.callback());
  }

  bool was_active_frame = current_active_match_frame_;
  current_active_match_frame_ = true;

  bool is_active = SetMarkerActive(active_match_.Get(), true);
  if (active_now)
    *active_now = is_active;

  // Make sure no node is focused. See http://crbug.com/38700.
  OwnerFrame().GetFrame()->GetDocument()->ClearFocusedElement();

  // Set this frame as focused.
  OwnerFrame().ViewImpl()->SetFocusedFrame(&OwnerFrame());

  if (options.new_session || active_selection || !is_active) {
    // This is either an initial Find operation, a Find-next from a new
    // start point due to a selection, or new matches were found during
    // Find-next due to DOM alteration (that couldn't be set as active), so
    // we set the flag to ask the scoping effort to find the active rect for
    // us and report it back to the UI.
    should_locate_active_rect_ = true;
  } else {
    if (!was_active_frame) {
      if (options.forward)
        active_match_index_ = 0;
      else
        active_match_index_ = find_task_controller_->CurrentMatchCount() - 1;
    } else {
      if (options.forward)
        ++active_match_index_;
      else
        --active_match_index_;

      if (active_match_index_ + 1 > find_task_controller_->CurrentMatchCount())
        active_match_index_ = 0;
      else if (active_match_index_ < 0)
        active_match_index_ = find_task_controller_->CurrentMatchCount() - 1;
    }
    gfx::Rect selection_rect = OwnerFrame().GetFrameView()->ConvertToRootFrame(
        active_match_->BoundingBox());
    ReportFindInPageSelection(selection_rect, active_match_index_ + 1,
                              identifier);
  }

  // We found something, so the result of the previous scoping may be outdated.
  find_task_controller_->ResetLastFindRequestCompletedWithNoMatches();

  return true;
}

void TextFinder::ClearActiveFindMatch() {
  current_active_match_frame_ = false;
  SetMarkerActive(active_match_.Get(), false);
  ResetActiveMatch();
}

LocalFrame* TextFinder::GetFrame() const {
  return OwnerFrame().GetFrame();
}

void TextFinder::SetFindEndstateFocusAndSelection() {
  if (!ActiveMatchFrame())
    return;

  Range* active_match = ActiveMatch();
  if (!active_match)
    return;

  // If the user has set the selection since the match was found, we
  // don't focus anything.
  if (!GetFrame()->Selection().GetSelectionInDOMTree().IsNone())
    return;

  // Need to clean out style and layout state before querying
  // Element::isFocusable().
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kFindInPage);

  // Try to find the first focusable node up the chain, which will, for
  // example, focus links if we have found text within the link.
  Node* node = active_match->FirstNode();
  if (node && node->IsInShadowTree()) {
    if (Node* host = node->OwnerShadowHost()) {
      if (IsA<HTMLInputElement>(*host) || IsA<HTMLTextAreaElement>(*host))
        node = host;
    }
  }
  const EphemeralRange active_match_range(active_match);
  if (node) {
    for (Node& runner : NodeTraversal::InclusiveAncestorsOf(*node)) {
      auto* element = DynamicTo<Element>(runner);
      if (!element)
        continue;
      if (element->IsFocusable()) {
        // Found a focusable parent node. Set the active match as the
        // selection and focus to the focusable node.
        GetFrame()->Selection().SetSelectionAndEndTyping(
            SelectionInDOMTree::Builder()
                .SetBaseAndExtent(active_match_range)
                .Build());
        GetFrame()->GetDocument()->SetFocusedElement(
            element, FocusParams(SelectionBehaviorOnFocus::kNone,
                                 mojom::blink::FocusType::kNone, nullptr));
        return;
      }
    }
  }

  // Iterate over all the nodes in the range until we find a focusable node.
  // This, for example, sets focus to the first link if you search for
  // text and text that is within one or more links.
  for (Node& runner : active_match_range.Nodes()) {
    auto* element = DynamicTo<Element>(runner);
    if (!element)
      continue;
    if (element->IsFocusable()) {
      GetFrame()->GetDocument()->SetFocusedElement(
          element, FocusParams(SelectionBehaviorOnFocus::kNone,
                               mojom::blink::FocusType::kNone, nullptr));
      return;
    }
  }

  // No node related to the active match was focusable, so set the
  // active match as the selection (so that when you end the Find session,
  // you'll have the last thing you found highlighted) and make sure that
  // we have nothing focused (otherwise you might have text selected but
  // a link focused, which is weird).
  GetFrame()->Selection().SetSelectionAndEndTyping(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(active_match_range)
          .Build());
  GetFrame()->GetDocument()->ClearFocusedElement();

  // Finally clear the active match, for two reasons:
  // We just finished the find 'session' and we don't want future (potentially
  // unrelated) find 'sessions' operations to start at the same place.
  // The WebLocalFrameImpl could get reused and the activeMatch could end up
  // pointing to a document that is no longer valid. Keeping an invalid
  // reference around is just asking for trouble.
  ResetActiveMatch();
}

void TextFinder::StopFindingAndClearSelection() {
  CancelPendingScopingEffort();

  // Remove all markers for matches found and turn off the highlighting.
  OwnerFrame().GetFrame()->GetDocument()->Markers().RemoveMarkersOfTypes(
      DocumentMarker::MarkerTypes::TextMatch());
  ClearFindMatchesCache();
  ResetActiveMatch();

  // Let the frame know that we don't want tickmarks anymore.
  InvalidatePaintForTickmarks();

  ReportFindInPageTerminationToAccessibility();
}

void TextFinder::ReportFindInPageTerminationToAccessibility() {
  GetFrame()
      ->GetLocalFrameHostRemote()
      .HandleAccessibilityFindInPageTermination();
}

void TextFinder::ReportFindInPageResultToAccessibility(int identifier) {
  if (!active_match_)
    return;

  auto* ax_object_cache =
      OwnerFrame().GetFrame()->GetDocument()->ExistingAXObjectCache();
  if (!ax_object_cache)
    return;

  Node* start_node = active_match_->startContainer();
  Node* end_node = active_match_->endContainer();
  ax_object_cache->HandleTextMarkerDataAdded(start_node, end_node);

  int32_t start_id = start_node->GetDomNodeId();
  int32_t end_id = end_node->GetDomNodeId();

  auto params = mojom::blink::FindInPageResultAXParams::New(
      identifier, active_match_index_ + 1, start_id,
      active_match_->startOffset(), end_id, active_match_->endOffset());
  GetFrame()->GetLocalFrameHostRemote().HandleAccessibilityFindInPageResult(
      std::move(params));
}

void TextFinder::StartScopingStringMatches(
    int identifier,
    const String& search_text,
    const mojom::blink::FindOptions& options) {
  CancelPendingScopingEffort();

  // This is a brand new search, so we need to reset everything.
  // Scoping is just about to begin.
  scoping_in_progress_ = true;

  // Need to keep the current identifier locally in order to finish the
  // request in case the frame is detached during the process.
  find_request_identifier_ = identifier;

  // Clear highlighting for this frame.
  UnmarkAllTextMatches();

  // Clear the tickmarks and results cache.
  ClearFindMatchesCache();

  // Clear the total match count and increment markers version.
  ResetMatchCount();

  // Clear the counter from last operation.
  next_invalidate_after_ = 0;

  // The view might be null on detached frames.
  LocalFrame* frame = OwnerFrame().GetFrame();
  if (frame && frame->GetPage())
    frame_scoping_ = true;

  find_task_controller_->StartRequest(identifier, search_text, options);
}

void TextFinder::FlushCurrentScopingEffort(int identifier) {
  if (!OwnerFrame().GetFrame() || !OwnerFrame().GetFrame()->GetPage())
    return;

  frame_scoping_ = false;
  IncreaseMatchCount(identifier, 0);
}

void TextFinder::DidFindMatch(int identifier,
                              int current_total_matches,
                              Range* result_range) {
  // Catch a special case where Find found something but doesn't know what
  // the bounding box for it is. In this case we set the first match we find
  // as the active rect.
  bool found_active_match = false;
  if (should_locate_active_rect_) {
    gfx::Rect result_bounds = result_range->BoundingBox();
    gfx::Rect active_selection_rect =
        active_match_.Get() ? active_match_->BoundingBox() : result_bounds;

    // If the Find function found a match it will have stored where the
    // match was found in active_selection_rect_ on the current frame. If we
    // find this rect during scoping it means we have found the active
    // tickmark.
    if (active_selection_rect == result_bounds) {
      // We have found the active tickmark frame.
      current_active_match_frame_ = true;
      found_active_match = true;
      // We also know which tickmark is active now.
      active_match_index_ = current_total_matches - 1;
      // To stop looking for the active tickmark, we set this flag.
      should_locate_active_rect_ = false;

      // Notify browser of new location for the selected rectangle.
      ReportFindInPageSelection(
          OwnerFrame().GetFrameView()->ConvertToRootFrame(result_bounds),
          active_match_index_ + 1, identifier);
    }
  }
  DocumentMarkerController& marker_controller =
      OwnerFrame().GetFrame()->GetDocument()->Markers();
  EphemeralRange ephemeral_result_range(result_range);
  // Scroll() may have added a match marker to this range already.
  if (!marker_controller.FirstMarkerIntersectingEphemeralRange(
          ephemeral_result_range, DocumentMarker::MarkerTypes::TextMatch())) {
    marker_controller.AddTextMatchMarker(
        EphemeralRange(result_range),
        found_active_match ? TextMatchMarker::MatchStatus::kActive
                           : TextMatchMarker::MatchStatus::kInactive);
  }

  find_matches_cache_.push_back(FindMatch(result_range, current_total_matches));
}

void TextFinder::UpdateMatches(int identifier,
                               int found_match_count,
                               bool finished_whole_request) {
  // Let the frame know how many matches we found during this pass.
  IncreaseMatchCount(identifier, found_match_count);

  // If we found anything during this pass, we should redraw. However, we
  // don't want to spam too much if the page is extremely long, so if we
  // reach a certain point we start throttling the redraw requests.
  if (!finished_whole_request)
    InvalidateIfNecessary();
}

void TextFinder::FinishCurrentScopingEffort(int identifier) {
  scoping_in_progress_ = false;
  if (!OwnerFrame().GetFrame())
    return;

  if (!total_match_count_)
    OwnerFrame().GetFrame()->Selection().Clear();

  FlushCurrentScopingEffort(identifier);
  // This frame is done, so show any scrollbar tickmarks we haven't drawn yet.
  InvalidatePaintForTickmarks();
}

void TextFinder::CancelPendingScopingEffort() {
  active_match_index_ = -1;
  scoping_in_progress_ = false;
  find_task_controller_->CancelPendingRequest();
}

void TextFinder::IncreaseMatchCount(int identifier, int count) {
  if (count)
    ++find_match_markers_version_;

  total_match_count_ += count;

  // Update the UI with the latest findings.
  OwnerFrame().GetFindInPage()->ReportFindInPageMatchCount(
      identifier, total_match_count_, !frame_scoping_);
}

void TextFinder::ReportFindInPageSelection(const gfx::Rect& selection_rect,
                                           int active_match_ordinal,
                                           int identifier) {
  // Update the UI with the latest selection rect.
  OwnerFrame().GetFindInPage()->ReportFindInPageSelection(
      identifier, active_match_ordinal, selection_rect,
      false /* final_update */);
  // Update accessibility too, so if the user commits to this query
  // we can move accessibility focus to this result.
  ReportFindInPageResultToAccessibility(identifier);
}

void TextFinder::ResetMatchCount() {
  if (total_match_count_ > 0)
    ++find_match_markers_version_;

  total_match_count_ = 0;
  frame_scoping_ = false;
}

void TextFinder::ClearFindMatchesCache() {
  if (!find_matches_cache_.empty())
    ++find_match_markers_version_;

  find_matches_cache_.clear();
  find_match_rects_are_valid_ = false;
}

void TextFinder::InvalidateFindMatchRects() {
  // Increase version number is required to trigger FindMatchRects update when
  // next find.
  if (!find_matches_cache_.empty())
    ++find_match_markers_version_;

  // For subframes, we need to recalculate the FindMatchRects when the
  // document size of mainframe changed even if the document size of current
  // frame has not changed because Find-in-page coordinates are represented as
  // normalized fractions of the main frame document. So we need to force the
  // FindMatchRects to be updated instead of changing according to the current
  // document size.
  find_match_rects_are_valid_ = false;
}

void TextFinder::UpdateFindMatchRects() {
  gfx::Size current_document_size = OwnerFrame().DocumentSize();
  if (document_size_for_current_find_match_rects_ != current_document_size) {
    document_size_for_current_find_match_rects_ = current_document_size;
    find_match_rects_are_valid_ = false;
  }

  wtf_size_t dead_matches = 0;
  for (FindMatch& match : find_matches_cache_) {
    if (!match.range_->BoundaryPointsValid() ||
        !match.range_->startContainer()->isConnected())
      match.rect_ = gfx::RectF();
    else if (!find_match_rects_are_valid_)
      match.rect_ = FindInPageRectFromRange(EphemeralRange(match.range_.Get()));

    if (match.rect_.IsEmpty())
      ++dead_matches;
  }

  // Remove any invalid matches from the cache.
  if (dead_matches) {
    HeapVector<FindMatch> filtered_matches;
    filtered_matches.reserve(find_matches_cache_.size() - dead_matches);

    for (const FindMatch& match : find_matches_cache_) {
      if (!match.rect_.IsEmpty())
        filtered_matches.push_back(match);
    }

    find_matches_cache_.swap(filtered_matches);
  }

  find_match_rects_are_valid_ = true;
}

#if BUILDFLAG(IS_ANDROID)
gfx::RectF TextFinder::ActiveFindMatchRect() {
  if (!current_active_match_frame_ || !active_match_)
    return gfx::RectF();

  return FindInPageRectFromRange(EphemeralRange(ActiveMatch()));
}

Vector<gfx::RectF> TextFinder::FindMatchRects() {
  UpdateFindMatchRects();

  Vector<gfx::RectF> match_rects;
  match_rects.reserve(match_rects.size() + find_matches_cache_.size());
  for (const FindMatch& match : find_matches_cache_) {
    DCHECK(!match.rect_.IsEmpty());
    match_rects.push_back(match.rect_);
  }

  return match_rects;
}

int TextFinder::SelectNearestFindMatch(const gfx::PointF& point,
                                       gfx::Rect* selection_rect) {
  int index = NearestFindMatch(point, nullptr);
  if (index != -1)
    return SelectFindMatch(static_cast<unsigned>(index), selection_rect);

  return -1;
}

int TextFinder::NearestFindMatch(const gfx::PointF& point,
                                 float* distance_squared) {
  UpdateFindMatchRects();

  int nearest = -1;
  float nearest_distance_squared = FLT_MAX;
  for (wtf_size_t i = 0; i < find_matches_cache_.size(); ++i) {
    DCHECK(!find_matches_cache_[i].rect_.IsEmpty());
    gfx::Vector2dF offset = point - find_matches_cache_[i].rect_.CenterPoint();
    float current_distance_squared = offset.LengthSquared();
    if (current_distance_squared < nearest_distance_squared) {
      nearest = i;
      nearest_distance_squared = current_distance_squared;
    }
  }

  if (distance_squared)
    *distance_squared = nearest_distance_squared;

  return nearest;
}

int TextFinder::SelectFindMatch(unsigned index, gfx::Rect* selection_rect) {
  SECURITY_DCHECK(index < find_matches_cache_.size());

  Range* range = find_matches_cache_[index].range_;
  if (!range->BoundaryPointsValid() || !range->startContainer()->isConnected())
    return -1;

  // Check if the match is already selected.
  if (!current_active_match_frame_ || !active_match_ ||
      !AreRangesEqual(active_match_.Get(), range)) {
    active_match_index_ = find_matches_cache_[index].ordinal_ - 1;

    // Set this frame as the active frame (the one with the active highlight).
    current_active_match_frame_ = true;
    OwnerFrame().ViewImpl()->SetFocusedFrame(&OwnerFrame());

    if (active_match_)
      SetMarkerActive(active_match_.Get(), false);
    active_match_ = range;
    SetMarkerActive(active_match_.Get(), true);

    // Clear any user selection, to make sure Find Next continues on from the
    // match we just activated.
    OwnerFrame().GetFrame()->Selection().Clear();

    // Make sure no node is focused. See http://crbug.com/38700.
    OwnerFrame().GetFrame()->GetDocument()->ClearFocusedElement();
  }

  gfx::Rect active_match_rect;
  gfx::Rect active_match_bounding_box =
      ComputeTextRect(EphemeralRange(active_match_.Get()));

  if (!active_match_bounding_box.IsEmpty()) {
    if (active_match_->FirstNode() &&
        active_match_->FirstNode()->GetLayoutObject()) {
      scroll_into_view_util::ScrollRectToVisible(
          *active_match_->FirstNode()->GetLayoutObject(),
          PhysicalRect(active_match_bounding_box),
          scroll_into_view_util::CreateScrollIntoViewParams(
              ScrollAlignment::CenterIfNeeded(),
              ScrollAlignment::CenterIfNeeded(),
              mojom::blink::ScrollType::kUser));

      // Absolute coordinates are scroll-variant so the bounding box will change
      // if the page is scrolled by ScrollRectToVisible above. Recompute the
      // bounding box so we have the updated location for the zoom below.
      // TODO(bokan): This should really use the return value from
      // ScrollRectToVisible which returns the updated position of the
      // scrolled rect. However, this was recently added and this is a fix
      // that needs to be merged to a release branch.
      // https://crbug.com/823365.
      active_match_bounding_box =
          ComputeTextRect(EphemeralRange(active_match_.Get()));
    }

    // Zoom to the active match.
    active_match_rect = OwnerFrame().GetFrameView()->ConvertToRootFrame(
        active_match_bounding_box);
    OwnerFrame().LocalRoo
```