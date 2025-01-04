Response:
Let's break down the thought process for analyzing this C++ source code file.

1. **Understand the Goal:** The primary request is to understand the functionality of `text_suggestion_controller.cc` within the Chromium Blink rendering engine. This involves identifying its purpose, its interactions with other parts of the system (especially JavaScript, HTML, and CSS), and potential user-facing aspects.

2. **Initial Code Scan (Keywords and Structure):**  The first step is a quick scan of the code for key terms and structural elements. This helps get a high-level overview. Keywords like "suggestion," "spellcheck," "menu," "replace," "delete," "caret," "selection," and "marker" immediately stand out. The `#include` directives reveal dependencies on other Blink components related to editing, frames, and markers. The namespace `blink` confirms its location within the Blink engine.

3. **Identify the Core Responsibility:** Based on the keywords and class name (`TextSuggestionController`), it's clear this class manages text suggestions, likely related to spellchecking, grammar checking, and potentially other forms of text correction or completion.

4. **Deconstruct Function by Function:**  The next step is to analyze each function to understand its specific role. This involves:

    * **Reading the Function Name:**  The name often provides a strong hint about the function's purpose (e.g., `HandlePotentialSuggestionTap`, `ApplySpellCheckSuggestion`, `ShowSuggestionMenu`).
    * **Examining Parameters and Return Type:**  These provide information about the inputs and outputs of the function.
    * **Analyzing the Function Body:** This is where the core logic resides. Look for:
        * **Interactions with other classes/objects:**  Calls to `GetFrame()`, `GetDocument()`, `Selection()`, `Markers()`, `text_suggestion_host_`.
        * **Algorithms and logic:**  Conditions, loops, comparisons, and operations performed on data.
        * **Creation and manipulation of objects:**  Instantiation of `EphemeralRange`, `Position`, `DocumentMarker`, etc.
        * **Calls to platform APIs:**  Interactions with `text_suggestion_host_`, which hints at communication with the browser process.

5. **Identify Interactions with Web Technologies (JavaScript, HTML, CSS):**  This requires understanding how the functionality relates to what web developers and users see.

    * **JavaScript:** Look for actions that might be triggered by JavaScript events (e.g., `tap` or `click` leading to `HandlePotentialSuggestionTap`). Consider how JavaScript might initiate or influence the display of suggestions. The fact that the menu is shown based on user interaction is a strong link.
    * **HTML:**  Consider how the suggestions are applied. The code manipulates the text content within HTML elements. The selection and replacement mechanisms are directly tied to the DOM structure.
    * **CSS:**  Look for styling-related aspects. The code mentions `highlight_color` and uses `LayoutTheme::TapHighlightColor()`, suggesting CSS is involved in visually presenting the suggestions. The `AddActiveSuggestionMarker` function taking color parameters is another strong indicator.

6. **Infer User Actions and Debugging:**  Think about the user's perspective. How does a user trigger the functionality in this code?  This leads to scenarios like tapping on misspelled words or areas with suggestions. For debugging, trace the flow of execution starting from a user action. The function calls provide a path to follow.

7. **Consider Edge Cases and Errors:**  Think about potential issues or mistakes users or developers might make. For example, tapping in the wrong place, or the system failing to retrieve suggestions. The code has checks like `IsAvailable()` and handles cases where no markers are found.

8. **Formulate Hypotheses and Examples:** For areas like logical reasoning, create simple input scenarios and predict the output based on the code's behavior. This helps solidify understanding.

9. **Structure the Explanation:** Organize the findings into logical sections: core functionality, relation to web technologies, logical reasoning, user errors, and debugging. Use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial Assumption Check:** If an initial assumption seems wrong based on later code analysis, revisit and correct it. For example, initially, one might think the controller directly draws the menu, but the `text_suggestion_host_` suggests it delegates this to the browser.
* **Clarifying Ambiguities:** If a piece of code is unclear, look for related code or documentation (if available, which wasn't the case here, so we rely on the surrounding code).
* **Focus on the "Why":**  Don't just describe *what* the code does; try to explain *why* it does it. For example, why check for spaces before deleting?
* **Iterative Refinement:**  The understanding of the code deepens with each pass. Go back and refine earlier interpretations as more information becomes available.

By following this systematic approach, combining code analysis with an understanding of web technologies and user interactions, it's possible to effectively dissect and explain the functionality of a complex source code file like `text_suggestion_controller.cc`.
好的，让我们来分析一下 `blink/renderer/core/editing/suggestion/text_suggestion_controller.cc` 这个文件。

**核心功能:**

`TextSuggestionController` 的主要职责是管理文本建议功能，这通常涉及到以下几个方面：

1. **检测潜在的建议触发:** 监听用户操作（例如触摸或点击），判断是否可能触发显示文本建议菜单。这通常与拼写检查、语法检查或其他类型的文本增强功能相关。
2. **与浏览器进程通信:**  通过 `text_suggestion_host_` 与浏览器进程进行通信，请求显示建议菜单。这涉及使用 Mojo 接口 (`text_suggestion_host_.BindNewPipeAndPassReceiver`).
3. **处理建议:** 接收并处理来自浏览器进程的建议列表。
4. **应用建议:**  当用户选择一个建议时，负责将选定的建议应用到编辑器中，替换掉原来的文本。
5. **删除建议范围:**  允许用户删除被建议标记覆盖的文本范围。
6. **管理建议菜单的生命周期:**  控制建议菜单的显示和关闭。
7. **与文档标记 (Document Markers) 交互:** 使用 `DocumentMarkerController` 来标记可能存在拼写错误、语法错误或建议的文本范围，并在显示建议菜单时使用这些标记。
8. **处理添加到字典的单词:**  响应用户将新单词添加到自定义字典的操作。

**与 JavaScript, HTML, CSS 的关系:**

虽然 `text_suggestion_controller.cc` 是 C++ 代码，但它直接影响用户在网页上与文本交互的体验，因此与 JavaScript、HTML 和 CSS 有着密切的关系：

* **HTML:**
    * **影响文本内容:** 当应用建议或删除建议范围时，最终会修改 HTML 文档中的文本节点内容。
    * **可编辑区域:** 此控制器主要作用于可编辑的 HTML 元素（例如 `<textarea>`，设置了 `contenteditable` 属性的元素）。
    * **示例:** 用户在一个 `contenteditable` 的 `<div>` 中输入 "teh"，拼写检查功能会识别出错误，`TextSuggestionController` 会参与显示 "the" 等建议，当用户选择 "the" 时，`<div>` 的内容会被更新。

* **JavaScript:**
    * **事件触发:** 用户在可编辑区域的点击或触摸操作（可能通过 JavaScript 事件监听）最终会触发 `TextSuggestionController` 的 `HandlePotentialSuggestionTap` 方法。
    * **API 交互 (间接):**  虽然这个 C++ 文件本身不直接执行 JavaScript，但浏览器的渲染引擎会将用户的操作和建议结果反馈给 JavaScript 环境，例如通过 `Selection` API 获取当前选区，或者通过事件通知 JavaScript 建议菜单的状态变化。
    * **示例:**  一个 JavaScript 脚本可能会监听 `input` 事件，并根据用户的输入动态地进行一些处理，而拼写检查和建议功能则会在后台由 `TextSuggestionController` 处理。

* **CSS:**
    * **建议标记的样式:** `TextSuggestionController` 使用 `DocumentMarker` 来标记文本，而这些标记可以通过 CSS 来设置样式，例如拼写错误的红色波浪线，或者建议的下划线颜色。
    * **高亮显示:** 当建议菜单显示时，被建议的文本范围可能会被高亮显示，这个高亮颜色由 `LayoutTheme` 提供，最终通过 CSS 渲染。
    * **示例:**  CSS 规则可能定义了 `.misspelling` 类的元素的 `text-decoration` 属性为红色波浪线，`DocumentMarkerController` 会给拼写错误的文本添加相应的标记，从而应用 CSS 样式。

**逻辑推理 (假设输入与输出):**

假设用户在一个可编辑的 `<textarea>` 中输入了 "wierd"。

* **输入:** 用户在光标位于 "wierd" 的某个位置时，进行了一次点击操作。
* **`HandlePotentialSuggestionTap` 的假设输入:** `caret_position` 指向 "wierd" 中的某个字符。
* **逻辑推理:**
    1. `HandlePotentialSuggestionTap` 被调用。
    2. 代码会检查光标周围的文本范围，并查找是否有相关的 `DocumentMarker` (例如，一个标记 "wierd" 为拼写错误的 `SpellCheckMarker`)。
    3. 如果找到了 `SpellCheckMarker`，并且 `text_suggestion_host_` 尚未绑定，则会建立与浏览器进程的连接。
    4. `text_suggestion_host_->StartSuggestionMenuTimer()` 会启动一个定时器。
* **`SuggestionMenuTimeoutCallback` 的假设输入:** 定时器到期，`max_number_of_suggestions` 例如为 3。
* **逻辑推理:**
    1. `SuggestionMenuTimeoutCallback` 被调用。
    2. 代码再次检查光标周围的 `DocumentMarker`，找到拼写错误的标记。
    3. `ShowSpellCheckMenu` 被调用。
    4. `ShowSpellCheckMenu` 从 `SpellCheckMarker` 中获取建议（假设浏览器进程返回了 "weird"）。
    5. `text_suggestion_host_->ShowSpellCheckSuggestionMenu` 被调用，向浏览器进程发送请求以显示包含 "weird" 建议的菜单。
* **用户操作:** 用户点击了建议菜单中的 "weird"。
* **`ApplySpellCheckSuggestion` 的假设输入:** `suggestion` 为 "weird"。
* **逻辑推理:**
    1. `ApplySpellCheckSuggestion` 被调用。
    2. `ReplaceActiveSuggestionRange` 被调用，使用 "weird" 替换掉 "wierd"。
    3. `OnSuggestionMenuClosed` 被调用，清理相关的 `ActiveSuggestionMarker` 并允许光标显示。
* **输出:** `<textarea>` 中的文本从 "wierd" 变为 "weird"，建议菜单关闭。

**用户或编程常见的使用错误:**

1. **用户操作过快:** 用户可能在建议菜单出现之前就进行了新的输入或移动了光标，导致建议菜单的上下文失效。
2. **网络问题:** 如果与浏览器进程的通信出现问题（例如，`text_suggestion_host_` 连接失败），则无法获取建议。
3. **错误的 Marker 类型:**  如果代码在查找 Marker 时使用了错误的类型，可能无法正确识别需要显示建议的文本范围。例如，查找拼写检查建议时，使用了语法检查的 Marker 类型。
4. **开发者错误地移除了 Marker:**  开发者可能通过 JavaScript 代码错误地移除了 `DocumentMarker`，导致建议功能失效。
5. **可编辑属性配置错误:** 如果 HTML 元素的 `contenteditable` 属性配置不正确，或者被 JavaScript 动态修改导致不可编辑，则建议功能可能无法正常工作。
6. **安全策略限制:**  浏览器的安全策略（例如 Content Security Policy）可能会限制某些功能，从而影响建议功能的正常运行。

**用户操作是如何一步步的到达这里 (作为调试线索):**

假设我们想调试用户点击一个拼写错误的单词后，建议菜单是如何显示的。

1. **用户输入错误:** 用户在可编辑区域（例如 `<textarea>` 或 `contenteditable` 的 `<div>`）中输入了一个拼写错误的单词，例如 "beleive"。
2. **拼写检查标记生成:**  浏览器的拼写检查器（通常在后台运行）识别出 "beleive" 是拼写错误的，并创建一个 `SpellCheckMarker` 对象，标记这个词的范围。`DocumentMarkerController` 负责管理这些标记。
3. **用户点击/触摸:** 用户将光标移动到 "beleive" 上，并进行一次点击或触摸操作。
4. **事件分发:**  浏览器的事件处理机制会将这个点击/触摸事件传递到相应的元素。
5. **`HandlePotentialSuggestionTap` 调用:**  `TextSuggestionController` 监听相关的事件（具体监听方式可能在其他代码中实现，这里假设存在连接），当点击发生在可能存在建议的文本上时，`HandlePotentialSuggestionTap` 方法会被调用，并传入点击位置的 `caret_position`。
6. **查找 Marker:** `HandlePotentialSuggestionTap` 内部会使用 `FirstMarkerIntersectingRange` 或类似的方法，根据 `caret_position` 查找是否存在与点击位置重叠的 `DocumentMarker`，特别是 `SpellCheckMarker`。
7. **启动定时器:** 如果找到相关的 Marker，并且建议菜单没有打开，则会启动一个定时器 (`StartSuggestionMenuTimer`)。
8. **`SuggestionMenuTimeoutCallback` 触发:**  定时器到期后，`SuggestionMenuTimeoutCallback` 被调用。
9. **再次查找 Marker:**  在 `SuggestionMenuTimeoutCallback` 中，会再次查找相关的 Marker。
10. **`ShowSpellCheckMenu` 调用:** 如果找到了拼写检查的 Marker，`ShowSpellCheckMenu` 方法会被调用，传入相关的 Marker 信息。
11. **请求显示菜单:** `ShowSpellCheckMenu` 会构建建议数据，并通过 `text_suggestion_host_->ShowSpellCheckSuggestionMenu` 向浏览器进程发送请求，要求显示包含建议的菜单。
12. **浏览器进程显示菜单:** 浏览器进程接收到请求后，会创建并显示建议菜单，菜单的内容通常包含来自拼写检查器的建议。

通过以上步骤，我们可以看到用户的一个简单的点击操作，是如何逐步引导到 `TextSuggestionController` 的相关方法，并最终触发建议菜单的显示的。在调试过程中，我们可以设置断点在这些关键方法上，观察变量的值，以及方法调用的顺序，从而定位问题。

希望以上分析能够帮助你理解 `text_suggestion_controller.cc` 的功能和作用。

Prompt: 
```
这是目录为blink/renderer/core/editing/suggestion/text_suggestion_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/suggestion/text_suggestion_controller.h"

#include "base/ranges/algorithm.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/markers/spell_check_marker.h"
#include "third_party/blink/renderer/core/editing/markers/suggestion_marker.h"
#include "third_party/blink/renderer/core/editing/markers/suggestion_marker_replacement_scope.h"
#include "third_party/blink/renderer/core/editing/plain_text_range.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/spellcheck/spell_checker.h"
#include "third_party/blink/renderer/core/editing/suggestion/text_suggestion_info.h"
#include "third_party/blink/renderer/core/frame/frame_view.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"

namespace blink {

namespace {

bool ShouldDeleteNextCharacter(const Node& marker_text_node,
                               const DocumentMarker& marker) {
  // If the character immediately following the range to be deleted is a space,
  // delete it if either of these conditions holds:
  // - We're deleting at the beginning of the editable text (to avoid ending up
  //   with a space at the beginning)
  // - The character immediately before the range being deleted is also a space
  //   (to avoid ending up with two adjacent spaces)
  const EphemeralRange next_character_range =
      PlainTextRange(marker.EndOffset(), marker.EndOffset() + 1)
          .CreateRange(*marker_text_node.parentNode());
  // No character immediately following the range (so it can't be a space)
  if (next_character_range.IsNull())
    return false;

  const String next_character_str =
      PlainText(next_character_range, TextIteratorBehavior::Builder().Build());
  const UChar next_character = next_character_str[0];
  // Character immediately following the range is not a space
  if (next_character != kSpaceCharacter &&
      next_character != kNoBreakSpaceCharacter)
    return false;

  // First case: we're deleting at the beginning of the editable text
  if (marker.StartOffset() == 0)
    return true;

  const EphemeralRange prev_character_range =
      PlainTextRange(marker.StartOffset() - 1, marker.StartOffset())
          .CreateRange(*marker_text_node.parentNode());
  // Not at beginning, but there's no character immediately before the range
  // being deleted (so it can't be a space)
  if (prev_character_range.IsNull())
    return false;

  const String prev_character_str =
      PlainText(prev_character_range, TextIteratorBehavior::Builder().Build());
  // Return true if the character immediately before the range is a space, false
  // otherwise
  const UChar prev_character = prev_character_str[0];
  return prev_character == kSpaceCharacter ||
         prev_character == kNoBreakSpaceCharacter;
}

EphemeralRangeInFlatTree ComputeRangeSurroundingCaret(
    const PositionInFlatTree& caret_position) {
  const unsigned position_offset_in_node =
      caret_position.ComputeOffsetInContainerNode();
  auto* text_node = DynamicTo<Text>(caret_position.ComputeContainerNode());
  // If we're in the interior of a text node, we can avoid calling
  // PreviousPositionOf/NextPositionOf for better efficiency.
  if (text_node && position_offset_in_node != 0 &&
      position_offset_in_node != text_node->length()) {
    return EphemeralRangeInFlatTree(
        PositionInFlatTree(text_node, position_offset_in_node - 1),
        PositionInFlatTree(text_node, position_offset_in_node + 1));
  }

  const PositionInFlatTree& previous_position =
      PreviousPositionOf(caret_position, PositionMoveType::kGraphemeCluster);

  const PositionInFlatTree& next_position =
      NextPositionOf(caret_position, PositionMoveType::kGraphemeCluster);

  return EphemeralRangeInFlatTree(
      previous_position.IsNull() ? caret_position : previous_position,
      next_position.IsNull() ? caret_position : next_position);
}

struct SuggestionInfosWithNodeAndHighlightColor {
  STACK_ALLOCATED();

 public:
  Persistent<const Text> text_node;
  Color highlight_color;
  Vector<TextSuggestionInfo> suggestion_infos;
};

SuggestionInfosWithNodeAndHighlightColor ComputeSuggestionInfos(
    const HeapVector<std::pair<Member<const Text>, Member<DocumentMarker>>>&
        node_suggestion_marker_pairs,
    size_t max_number_of_suggestions) {
  // We look at all suggestion markers touching or overlapping the touched
  // location to pull suggestions from. We preferentially draw suggestions from
  // shorter markers first (since we assume they're more specific to the tapped
  // location) until we hit our limit.
  HeapVector<std::pair<Member<const Text>, Member<DocumentMarker>>>
      node_suggestion_marker_pairs_sorted_by_length =
          node_suggestion_marker_pairs;
  std::sort(node_suggestion_marker_pairs_sorted_by_length.begin(),
            node_suggestion_marker_pairs_sorted_by_length.end(),
            [](const std::pair<const Text*, DocumentMarker*>& pair1,
               const std::pair<const Text*, DocumentMarker*>& pair2) {
              const int length1 =
                  pair1.second->EndOffset() - pair1.second->StartOffset();
              const int length2 =
                  pair2.second->EndOffset() - pair2.second->StartOffset();
              return length1 < length2;
            });

  SuggestionInfosWithNodeAndHighlightColor
      suggestion_infos_with_node_and_highlight_color;
  // In theory, a user could tap right before/after the start of a node and we'd
  // want to pull in suggestions from either side of the tap. However, this is
  // an edge case that's unlikely to matter in practice (the user will most
  // likely just tap in the node where they want to apply the suggestions) and
  // it complicates implementation, so we require that all suggestions come
  // from the same text node.
  suggestion_infos_with_node_and_highlight_color.text_node =
      node_suggestion_marker_pairs_sorted_by_length.front().first;

  // The highlight color comes from the shortest suggestion marker touching or
  // intersecting the tapped location. If there's no color set, we use the
  // default text selection color.
  const auto* first_suggestion_marker = To<SuggestionMarker>(
      node_suggestion_marker_pairs_sorted_by_length.front().second.Get());

  suggestion_infos_with_node_and_highlight_color.highlight_color =
      (first_suggestion_marker->SuggestionHighlightColor() ==
       Color::kTransparent)
          ? LayoutTheme::TapHighlightColor()
          : first_suggestion_marker->SuggestionHighlightColor();

  Vector<TextSuggestionInfo>& suggestion_infos =
      suggestion_infos_with_node_and_highlight_color.suggestion_infos;
  for (const std::pair<Member<const Text>, Member<DocumentMarker>>&
           node_marker_pair : node_suggestion_marker_pairs_sorted_by_length) {
    if (node_marker_pair.first !=
        suggestion_infos_with_node_and_highlight_color.text_node)
      continue;

    if (suggestion_infos.size() == max_number_of_suggestions)
      break;

    const auto* marker = To<SuggestionMarker>(node_marker_pair.second.Get());
    const Vector<String>& marker_suggestions = marker->Suggestions();
    for (wtf_size_t suggestion_index = 0;
         suggestion_index < marker_suggestions.size(); ++suggestion_index) {
      const String& suggestion = marker_suggestions[suggestion_index];
      if (suggestion_infos.size() == max_number_of_suggestions)
        break;
      if (base::ranges::any_of(
              suggestion_infos,
              [marker, &suggestion](const TextSuggestionInfo& info) {
                return info.span_start == (int32_t)marker->StartOffset() &&
                       info.span_end == (int32_t)marker->EndOffset() &&
                       info.suggestion == suggestion;
              })) {
        continue;
      }

      TextSuggestionInfo suggestion_info;
      suggestion_info.marker_tag = marker->Tag();
      suggestion_info.suggestion_index = suggestion_index;
      suggestion_info.span_start = marker->StartOffset();
      suggestion_info.span_end = marker->EndOffset();
      suggestion_info.suggestion = suggestion;
      suggestion_infos.push_back(suggestion_info);
    }
  }

  return suggestion_infos_with_node_and_highlight_color;
}

}  // namespace

TextSuggestionController::TextSuggestionController(LocalDOMWindow& window)
    : is_suggestion_menu_open_(false),
      window_(&window),
      text_suggestion_host_(&window) {}

bool TextSuggestionController::IsMenuOpen() const {
  return is_suggestion_menu_open_;
}

void TextSuggestionController::HandlePotentialSuggestionTap(
    const PositionInFlatTree& caret_position) {
  if (!IsAvailable() || GetFrame() != GetDocument().GetFrame()) {
    // TODO(crbug.com/1054955, crbug.com/1409155, crbug.com/1412036): Callsites
    // should not call this function in these conditions.
    return;
  }

  // It's theoretically possible, but extremely unlikely, that the user has
  // managed to tap on some text after TextSuggestionController has told the
  // browser to open the text suggestions menu, but before the browser has
  // actually done so. In this case, we should just ignore the tap.
  if (is_suggestion_menu_open_)
    return;

  const EphemeralRangeInFlatTree& range_to_check =
      ComputeRangeSurroundingCaret(caret_position);

  const std::pair<const Node*, const DocumentMarker*>& node_and_marker =
      FirstMarkerIntersectingRange(
          range_to_check,
          DocumentMarker::MarkerTypes(DocumentMarker::kSpelling |
                                      DocumentMarker::kGrammar |
                                      DocumentMarker::kSuggestion));
  if (!node_and_marker.first)
    return;

  const auto* marker = DynamicTo<SuggestionMarker>(node_and_marker.second);
  if (marker && marker->Suggestions().empty())
    return;

  if (!text_suggestion_host_.is_bound()) {
    GetFrame().GetBrowserInterfaceBroker().GetInterface(
        text_suggestion_host_.BindNewPipeAndPassReceiver(
            GetFrame().GetTaskRunner(TaskType::kMiscPlatformAPI)));
  }

  text_suggestion_host_->StartSuggestionMenuTimer();
}

void TextSuggestionController::Trace(Visitor* visitor) const {
  visitor->Trace(window_);
  visitor->Trace(text_suggestion_host_);
}

void TextSuggestionController::ReplaceActiveSuggestionRange(
    const String& suggestion) {
  const VisibleSelectionInFlatTree& selection =
      GetFrame().Selection().ComputeVisibleSelectionInFlatTree();
  if (selection.IsNone())
    return;

  const EphemeralRangeInFlatTree& range_to_check =
      selection.IsRange() ? selection.ToNormalizedEphemeralRange()
                          : ComputeRangeSurroundingCaret(selection.Start());
  const HeapVector<std::pair<Member<const Text>, Member<DocumentMarker>>>&
      node_marker_pairs =
          GetFrame().GetDocument()->Markers().MarkersIntersectingRange(
              range_to_check, DocumentMarker::MarkerTypes::ActiveSuggestion());

  if (node_marker_pairs.empty())
    return;

  const Text* const marker_text_node = node_marker_pairs.front().first;
  const DocumentMarker* const marker = node_marker_pairs.front().second;

  const EphemeralRange& range_to_replace =
      EphemeralRange(Position(marker_text_node, marker->StartOffset()),
                     Position(marker_text_node, marker->EndOffset()));
  ReplaceRangeWithText(range_to_replace, suggestion);
}

void TextSuggestionController::ApplySpellCheckSuggestion(
    const String& suggestion) {
  ReplaceActiveSuggestionRange(suggestion);
  OnSuggestionMenuClosed();
}

void TextSuggestionController::ApplyTextSuggestion(int32_t marker_tag,
                                                   uint32_t suggestion_index) {
  const VisibleSelectionInFlatTree& selection =
      GetFrame().Selection().ComputeVisibleSelectionInFlatTree();
  if (selection.IsNone()) {
    OnSuggestionMenuClosed();
    return;
  }

  const EphemeralRangeInFlatTree& range_to_check =
      selection.IsRange() ? selection.ToNormalizedEphemeralRange()
                          : ComputeRangeSurroundingCaret(selection.Start());

  const HeapVector<std::pair<Member<const Text>, Member<DocumentMarker>>>&
      node_marker_pairs =
          GetFrame().GetDocument()->Markers().MarkersIntersectingRange(
              range_to_check, DocumentMarker::MarkerTypes::Suggestion());

  const Text* marker_text_node = nullptr;
  SuggestionMarker* marker = nullptr;
  for (const std::pair<Member<const Text>, Member<DocumentMarker>>&
           node_marker_pair : node_marker_pairs) {
    auto* suggestion_marker =
        To<SuggestionMarker>(node_marker_pair.second.Get());
    if (suggestion_marker->Tag() == marker_tag) {
      marker_text_node = node_marker_pair.first;
      marker = suggestion_marker;
      break;
    }
  }

  if (!marker) {
    OnSuggestionMenuClosed();
    return;
  }
  DCHECK(marker_text_node);
  const EphemeralRange& range_to_replace =
      EphemeralRange(Position(marker_text_node, marker->StartOffset()),
                     Position(marker_text_node, marker->EndOffset()));

  const String& replacement = marker->Suggestions()[suggestion_index];
  const String& new_suggestion = PlainText(range_to_replace);

  {
    SuggestionMarkerReplacementScope scope;
    ReplaceRangeWithText(range_to_replace, replacement);
  }

  if (marker->IsMisspelling()) {
    GetFrame().GetDocument()->Markers().RemoveSuggestionMarkerByTag(
        *marker_text_node, marker->Tag());
  } else {
    marker->SetSuggestion(suggestion_index, new_suggestion);
  }

  OnSuggestionMenuClosed();
}

void TextSuggestionController::DeleteActiveSuggestionRange() {
  AttemptToDeleteActiveSuggestionRange();
  OnSuggestionMenuClosed();
}

void TextSuggestionController::OnNewWordAddedToDictionary(const String& word) {
  // Android pops up a dialog to let the user confirm they actually want to add
  // the word to the dictionary; this method gets called as soon as the dialog
  // is shown. So the word isn't actually in the dictionary here, even if the
  // user will end up confirming the dialog, and we shouldn't try to re-run
  // spellcheck here.

  // Note: this actually matches the behavior in native Android text boxes
  GetDocument().Markers().RemoveSpellingMarkersUnderWords(
      Vector<String>({word}));
  OnSuggestionMenuClosed();
}

void TextSuggestionController::OnSuggestionMenuClosed() {
  if (!IsAvailable())
    return;

  GetDocument().Markers().RemoveMarkersOfTypes(
      DocumentMarker::MarkerTypes::ActiveSuggestion());
  GetFrame().Selection().SetCaretEnabled(true);
  is_suggestion_menu_open_ = false;
}

void TextSuggestionController::SuggestionMenuTimeoutCallback(
    size_t max_number_of_suggestions) {
  if (!IsAvailable())
    return;

  const VisibleSelectionInFlatTree& selection =
      GetFrame().Selection().ComputeVisibleSelectionInFlatTree();
  if (selection.IsNone())
    return;

  const EphemeralRangeInFlatTree& range_to_check =
      selection.IsRange() ? selection.ToNormalizedEphemeralRange()
                          : ComputeRangeSurroundingCaret(selection.Start());

  // We can show a menu if the user tapped on either a spellcheck marker or a
  // suggestion marker. Suggestion markers take precedence (we don't even try
  // to draw both underlines, suggestion wins).
  const HeapVector<std::pair<Member<const Text>, Member<DocumentMarker>>>&
      node_suggestion_marker_pairs =
          GetFrame().GetDocument()->Markers().MarkersIntersectingRange(
              range_to_check, DocumentMarker::MarkerTypes::Suggestion());
  if (!node_suggestion_marker_pairs.empty()) {
    ShowSuggestionMenu(node_suggestion_marker_pairs, max_number_of_suggestions);
    return;
  }

  // If we didn't find any suggestion markers, look for spell check markers.
  const HeapVector<std::pair<Member<const Text>, Member<DocumentMarker>>>
      node_spelling_marker_pairs =
          GetFrame().GetDocument()->Markers().MarkersIntersectingRange(
              range_to_check, DocumentMarker::MarkerTypes::Misspelling());
  if (!node_spelling_marker_pairs.empty())
    ShowSpellCheckMenu(node_spelling_marker_pairs.front());

  // If we get here, that means the user tapped on a spellcheck or suggestion
  // marker a few hundred milliseconds ago (to start the double-click timer)
  // but it's gone now. Oh well...
}

void TextSuggestionController::ShowSpellCheckMenu(
    const std::pair<const Text*, DocumentMarker*>& node_spelling_marker_pair) {
  const Text* const marker_text_node = node_spelling_marker_pair.first;
  auto* const marker = To<SpellCheckMarker>(node_spelling_marker_pair.second);

  const EphemeralRange active_suggestion_range =
      EphemeralRange(Position(marker_text_node, marker->StartOffset()),
                     Position(marker_text_node, marker->EndOffset()));
  const String& misspelled_word = PlainText(active_suggestion_range);
  const String& description = marker->Description();

  is_suggestion_menu_open_ = true;
  GetFrame().Selection().SetCaretEnabled(false);
  GetDocument().Markers().AddActiveSuggestionMarker(
      active_suggestion_range, Color::kTransparent,
      ui::mojom::ImeTextSpanThickness::kNone,
      ui::mojom::ImeTextSpanUnderlineStyle::kSolid, Color::kTransparent,
      LayoutTheme::GetTheme().PlatformActiveSpellingMarkerHighlightColor());

  Vector<String> suggestions;
  description.Split('\n', suggestions);

  Vector<mojom::blink::SpellCheckSuggestionPtr> suggestion_ptrs;
  for (const String& suggestion : suggestions) {
    mojom::blink::SpellCheckSuggestionPtr info_ptr(
        mojom::blink::SpellCheckSuggestion::New());
    info_ptr->suggestion = suggestion;
    suggestion_ptrs.push_back(std::move(info_ptr));
  }

  // |FrameSelection::AbsoluteCaretBounds()| requires clean layout.
  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetFrame().GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSpellCheck);
  const gfx::Rect& absolute_bounds =
      GetFrame().Selection().AbsoluteCaretBounds();
  const gfx::Rect& viewport_bounds =
      GetFrame().View()->FrameToViewport(absolute_bounds);

  text_suggestion_host_->ShowSpellCheckSuggestionMenu(
      viewport_bounds.x(), viewport_bounds.bottom(), std::move(misspelled_word),
      std::move(suggestion_ptrs));
}

void TextSuggestionController::ShowSuggestionMenu(
    const HeapVector<std::pair<Member<const Text>, Member<DocumentMarker>>>&
        node_suggestion_marker_pairs,
    size_t max_number_of_suggestions) {
  DCHECK(!node_suggestion_marker_pairs.empty());

  SuggestionInfosWithNodeAndHighlightColor
      suggestion_infos_with_node_and_highlight_color = ComputeSuggestionInfos(
          node_suggestion_marker_pairs, max_number_of_suggestions);

  Vector<TextSuggestionInfo>& suggestion_infos =
      suggestion_infos_with_node_and_highlight_color.suggestion_infos;
  if (suggestion_infos.empty())
    return;

  int span_union_start = suggestion_infos[0].span_start;
  int span_union_end = suggestion_infos[0].span_end;
  for (wtf_size_t i = 1; i < suggestion_infos.size(); ++i) {
    span_union_start =
        std::min(span_union_start, suggestion_infos[i].span_start);
    span_union_end = std::max(span_union_end, suggestion_infos[i].span_end);
  }

  const Text* text_node =
      suggestion_infos_with_node_and_highlight_color.text_node;
  for (TextSuggestionInfo& info : suggestion_infos) {
    const EphemeralRange prefix_range(Position(text_node, span_union_start),
                                      Position(text_node, info.span_start));
    const String& prefix = PlainText(prefix_range);

    const EphemeralRange suffix_range(Position(text_node, info.span_end),
                                      Position(text_node, span_union_end));
    const String& suffix = PlainText(suffix_range);

    info.prefix = prefix;
    info.suffix = suffix;
  }

  const EphemeralRange marker_range(Position(text_node, span_union_start),
                                    Position(text_node, span_union_end));

  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kTransparent, ui::mojom::ImeTextSpanThickness::kThin,
      ui::mojom::ImeTextSpanUnderlineStyle::kSolid, Color::kTransparent,
      suggestion_infos_with_node_and_highlight_color.highlight_color);

  is_suggestion_menu_open_ = true;
  GetFrame().Selection().SetCaretEnabled(false);

  const String& misspelled_word = PlainText(marker_range);
  CallMojoShowTextSuggestionMenu(
      suggestion_infos_with_node_and_highlight_color.suggestion_infos,
      misspelled_word);
}

void TextSuggestionController::CallMojoShowTextSuggestionMenu(
    const Vector<TextSuggestionInfo>& text_suggestion_infos,
    const String& misspelled_word) {
  Vector<mojom::blink::TextSuggestionPtr> suggestion_info_ptrs;
  for (const blink::TextSuggestionInfo& info : text_suggestion_infos) {
    mojom::blink::TextSuggestionPtr info_ptr(
        mojom::blink::TextSuggestion::New());
    info_ptr->marker_tag = info.marker_tag;
    info_ptr->suggestion_index = info.suggestion_index;
    info_ptr->prefix = info.prefix;
    info_ptr->suggestion = info.suggestion;
    info_ptr->suffix = info.suffix;

    suggestion_info_ptrs.push_back(std::move(info_ptr));
  }

  const gfx::Rect& absolute_bounds =
      GetFrame().Selection().AbsoluteCaretBounds();
  const gfx::Rect& viewport_bounds =
      GetFrame().View()->FrameToViewport(absolute_bounds);

  text_suggestion_host_->ShowTextSuggestionMenu(
      viewport_bounds.x(), viewport_bounds.bottom(), misspelled_word,
      std::move(suggestion_info_ptrs));
}

Document& TextSuggestionController::GetDocument() const {
  DCHECK(IsAvailable());
  return *window_->document();
}

bool TextSuggestionController::IsAvailable() const {
  return !window_->IsContextDestroyed();
}

LocalFrame& TextSuggestionController::GetFrame() const {
  DCHECK(window_->GetFrame());
  return *window_->GetFrame();
}

std::pair<const Node*, const DocumentMarker*>
TextSuggestionController::FirstMarkerIntersectingRange(
    const EphemeralRangeInFlatTree& range,
    DocumentMarker::MarkerTypes types) const {
  const Node* const range_start_container =
      range.StartPosition().ComputeContainerNode();
  const unsigned range_start_offset =
      range.StartPosition().ComputeOffsetInContainerNode();
  const Node* const range_end_container =
      range.EndPosition().ComputeContainerNode();
  const unsigned range_end_offset =
      range.EndPosition().ComputeOffsetInContainerNode();

  for (const Node& node : range.Nodes()) {
    auto* text_node = DynamicTo<Text>(node);
    if (!text_node)
      continue;

    const unsigned start_offset =
        node == range_start_container ? range_start_offset : 0;
    const unsigned end_offset =
        node == range_end_container ? range_end_offset : text_node->length();

    const DocumentMarker* const found_marker =
        GetFrame().GetDocument()->Markers().FirstMarkerIntersectingOffsetRange(
            *text_node, start_offset, end_offset, types);
    if (found_marker)
      return std::make_pair(&node, found_marker);
  }

  return {};
}

std::pair<const Node*, const DocumentMarker*>
TextSuggestionController::FirstMarkerTouchingSelection(
    DocumentMarker::MarkerTypes types) const {
  const VisibleSelectionInFlatTree& selection =
      GetFrame().Selection().ComputeVisibleSelectionInFlatTree();
  if (selection.IsNone())
    return {};

  const EphemeralRangeInFlatTree& range_to_check =
      selection.IsRange()
          ? EphemeralRangeInFlatTree(selection.Start(), selection.End())
          : ComputeRangeSurroundingCaret(selection.Start());

  return FirstMarkerIntersectingRange(range_to_check, types);
}

void TextSuggestionController::AttemptToDeleteActiveSuggestionRange() {
  const std::pair<const Node*, const DocumentMarker*>& node_and_marker =
      FirstMarkerTouchingSelection(
          DocumentMarker::MarkerTypes::ActiveSuggestion());
  if (!node_and_marker.first)
    return;

  const Node* const marker_text_node = node_and_marker.first;
  const DocumentMarker* const marker = node_and_marker.second;

  const bool delete_next_char =
      ShouldDeleteNextCharacter(*marker_text_node, *marker);

  const EphemeralRange range_to_delete = EphemeralRange(
      Position(marker_text_node, marker->StartOffset()),
      Position(marker_text_node, marker->EndOffset() + delete_next_char));
  ReplaceRangeWithText(range_to_delete, "");
}

void TextSuggestionController::ReplaceRangeWithText(const EphemeralRange& range,
                                                    const String& replacement) {
  GetFrame().Selection().SetSelectionAndEndTyping(
      SelectionInDOMTree::Builder().SetBaseAndExtent(range).Build());

  InsertTextAndSendInputEventsOfTypeInsertReplacementText(GetFrame(),
                                                          replacement);
}

}  // namespace blink

"""

```