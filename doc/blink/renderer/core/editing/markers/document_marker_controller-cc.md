Response:
The user wants a summary of the functionality of the provided C++ code file, `document_marker_controller.cc`, which is part of the Chromium Blink rendering engine. The summary should cover:

1. **Core Functionality:** What does this code do?
2. **Relationship to Web Technologies:** How does it relate to JavaScript, HTML, and CSS?
3. **Logic and Data Flow:** Provide examples of input and output if logical reasoning is involved.
4. **Common User/Programming Errors:**  Identify potential pitfalls in its use.
5. **User Interaction:** Describe how user actions lead to this code being executed (debugging context).
6. **Overall Summary:** A concise recap of its main purpose.

Let's break down the code to identify these aspects.

**1. Core Functionality Analysis:**

* The code manages "markers" within a document.
* These markers seem to indicate specific ranges of text and have different types (spelling, grammar, text match, composition, suggestion, etc.).
* It provides methods for adding, removing, finding, and querying these markers.
* It handles updating the visual representation (painting) of the document when markers are added or removed.
* It interacts with accessibility features.

**2. Relationship to Web Technologies:**

* **HTML:** Markers are associated with text content within the HTML structure. For example, a spelling marker highlights a misspelled word in the HTML.
* **CSS:** Markers can influence how text is rendered. Composition markers, for instance, might draw underlines with specific colors and styles, reflecting CSS properties. Custom highlight markers directly tie into CSS highlights.
* **JavaScript:** JavaScript can interact with the editing functionalities that use these markers. For instance, a spell-checking feature triggered by JavaScript would use this code to manage the spelling error markers. IME input processed by JavaScript would create composition markers. The Selection API in JavaScript can interact with marked ranges.

**3. Logic and Data Flow (Hypothetical):**

* **Input:**  A user types in an `<input>` field.
* **Processing:**  The IME (Input Method Editor) might generate a "composition" marker as the user types characters that form a word. The `AddCompositionMarker` function would be called.
* **Output:** The text in the input field might be visually underlined with a specific color as defined by the composition marker.

* **Input:** A spell checker identifies an error in the text content.
* **Processing:** The spell checker would call `AddSpellingMarker` with the range of the misspelled word and a description of the error.
* **Output:** The misspelled word might be underlined with a red wavy line.

**4. Common User/Programming Errors:**

* **Incorrect Range Specification:** Providing an invalid or out-of-bounds range when adding a marker could lead to errors or unexpected behavior.
* **Mismatched Marker Types:** Trying to remove a marker with the wrong type.
* **Forgetting to Update Visuals:** While the code handles some invalidation, manually manipulating the DOM without informing the `DocumentMarkerController` could lead to visual inconsistencies.

**5. User Interaction (Debugging Context):**

To reach this code during debugging:

1. **User Types Text:**  If the user is typing in a text field, especially using an IME, the code related to composition markers would be involved. Breakpoints could be set in `AddCompositionMarker`.
2. **Spell Check:**  If the browser's spell checker is active, typing a misspelled word or right-clicking to access spell-checking suggestions would likely trigger the code for spelling markers. Breakpoints in `AddSpellingMarker` or related removal functions could be useful.
3. **Find in Page:** Using the browser's "Find" functionality (Ctrl+F or Cmd+F) would involve the `AddTextMatchMarker` code.
4. **JavaScript Editing:** JavaScript code that programmatically modifies the content of an editable element might also trigger the addition or removal of markers.

**6. Overall Summary (For Part 1):**

The `DocumentMarkerController` in Chromium's Blink engine is responsible for managing various types of markers within a document. These markers visually annotate specific text ranges for purposes like spell-checking, grammar correction, IME composition, text highlighting, and suggestions. It provides the core logic for adding, removing, querying, and rendering these markers, acting as a central hub for document annotation functionality within the rendering engine. It interacts directly with the document's DOM and influences how the content is painted on the screen.
`blink/renderer/core/editing/markers/document_marker_controller.cc` 是 Chromium Blink 引擎中负责管理文档标记（Document Markers）的核心组件。它的主要功能可以归纳为：

**核心功能：文档标记的管理**

1. **存储和组织文档标记:** 该类维护着一个或多个数据结构 (`markers_`) 来存储文档中不同类型的标记。这些标记可能包括拼写错误、语法错误、文本匹配、输入法组合、主动建议、建议、文本片段以及自定义高亮等。
2. **添加标记:** 提供了添加各种类型标记的方法，例如 `AddSpellingMarker`、`AddGrammarMarker`、`AddTextMatchMarker`、`AddCompositionMarker` 等。这些方法接收标记的范围（`EphemeralRange`）以及特定于标记类型的信息（例如拼写错误的描述）。
3. **移除标记:** 提供了移除标记的方法，例如 `RemoveMarkers` 和 `RemoveMarkersInRange`，可以根据范围或迭代器移除指定类型的标记。
4. **查找标记:** 提供了查找特定位置或范围内的标记的方法，例如 `FirstMarkerAroundPosition`、`FirstMarkerIntersectingEphemeralRange`、`MarkersAroundPosition`、`MarkersIntersectingRange` 和 `MarkersFor`。
5. **更新标记:** 虽然代码中没有明显的 "更新" 方法，但通过移除旧标记并添加新标记可以实现更新的效果。某些方法，如 `MoveMarkers`，可以用于在节点分割等操作后移动和调整标记。
6. **管理标记的生命周期:** 负责在文档即将销毁时清理相关的标记数据 (`PrepareForDestruction`)。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **HTML:** 文档标记是应用于 HTML 文档中的文本内容的。例如，当用户在 `<textarea>` 或 `contenteditable` 元素中输入时，拼写或语法错误标记会突出显示 HTML 文本节点中的特定单词或短语。
    *   **举例:** 用户在输入框中输入 "teh"，拼写检查功能可能会调用 `AddSpellingMarker`，将 "teh" 这个词所在的 HTML `Text` 节点的特定偏移量范围标记为拼写错误。
*   **CSS:** 文档标记会影响文本的渲染，特别是通过伪元素（如 `::spelling-error`、`::grammar-error`、`::selection` 等）。标记的存在会触发浏览器应用相应的样式。自定义高亮标记也直接关联到 CSS 自定义高亮 API。
    *   **举例:** 当 `AddGrammarMarker` 被调用时，浏览器可能会在相应的文本下方绘制一个波浪形的蓝色下划线，这是通过 CSS 中针对语法错误的样式定义的。`AddCustomHighlightMarker` 会创建一个与特定 CSS 高亮名称关联的标记，从而应用对应的样式。
*   **JavaScript:** JavaScript 可以通过 Blink 提供的接口间接地影响文档标记。例如：
    *   **输入法 (IME):** 用户使用输入法输入时，JavaScript 处理输入事件可能会触发 `AddCompositionMarker`，用于指示当前正在组合的文本。
    *   **拼写检查/语法检查 API:**  JavaScript 可以调用浏览器提供的 API 来执行拼写或语法检查，这些 API 最终会调用 `DocumentMarkerController` 的方法来添加相应的标记。
    *   **`Selection` API:** JavaScript 可以获取当前选区，而选区本身可以被视为一种特殊的标记。此外，某些类型的标记（如文本匹配标记）可能与用户的选择操作有关。
    *   **`window.find()` 或其他查找功能:** 当用户在页面上执行查找操作时，JavaScript 可能会调用相关方法，最终调用 `AddTextMatchMarker` 来标记匹配的文本。
    *   **自定义高亮 API:** JavaScript 可以使用 `CSS.highlights` API 来创建和管理自定义高亮，这会与 `AddCustomHighlightMarker` 关联。

**逻辑推理、假设输入与输出:**

假设输入：用户在一个可编辑的 `<div>` 中输入 "worng" 这个词。

逻辑推理过程：

1. 输入事件被捕获。
2. 文本内容发生变化。
3. 拼写检查模块（可能是后台服务或本地算法）分析文本内容。
4. 拼写检查模块识别出 "worng" 是一个拼写错误的单词。
5. 拼写检查模块调用 `DocumentMarkerController::AddSpellingMarker`。

输出：

*   `AddSpellingMarker` 方法会接收包含 "worng" 的 `EphemeralRange`，以及一个描述信息（例如 "可能的拼写错误"）。
*   `DocumentMarkerController` 会创建一个 `SpellingMarker` 对象，存储 "worng" 所在的 `Text` 节点以及起始和结束偏移量。
*   浏览器会更新渲染树，将该范围标记为拼写错误，最终在屏幕上可能显示一个红色波浪线下划线。

**涉及用户或编程常见的使用错误:**

1. **范围错误:**  开发者在调用添加标记的方法时，提供的 `EphemeralRange` 超出了文本节点的范围，或者起始偏移量大于结束偏移量。这可能导致断言失败或程序崩溃。
    *   **举例:**  一个文本节点长度为 5，但开发者尝试添加一个起始偏移量为 3，结束偏移量为 10 的标记。
2. **标记类型不匹配:**  尝试使用 `RemoveGrammarMarkers` 去移除一个拼写错误的标记。由于类型不匹配，移除操作不会生效。
3. **忘记更新渲染:** 虽然 `DocumentMarkerController` 会触发一定的渲染更新，但在某些复杂的场景下，手动操作 DOM 后可能需要开发者显式地通知渲染引擎更新，否则标记的显示可能不正确。
4. **在错误的线程调用:** `DocumentMarkerController` 通常运行在渲染线程，如果在其他线程尝试访问或修改其状态，可能会导致线程安全问题。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户在可编辑区域输入文本:** 用户在 `contenteditable` 元素或 `<textarea>` 中输入或修改文本，这可能会触发浏览器的拼写或语法检查功能，从而调用 `AddSpellingMarker` 或 `AddGrammarMarker`。
2. **用户使用输入法:** 用户使用中文、日文等输入法进行输入，输入法编辑器 (IME) 会将正在输入的文本标记为组合状态，这会调用 `AddCompositionMarker`。
3. **用户执行“查找”操作:** 用户按下 `Ctrl+F` 或在菜单中选择“查找”，输入要查找的文本后，浏览器会在页面上标记匹配的文本，这会调用 `AddTextMatchMarker`。
4. **用户与建议交互:** 当某些功能（如自动更正、智能回复等）提供建议时，可能会使用 `AddSuggestionMarker` 或 `AddActiveSuggestionMarker` 来高亮显示建议的文本。
5. **JavaScript 代码操作:** 网页上的 JavaScript 代码（例如富文本编辑器）可能使用 Blink 提供的接口来添加或移除自定义的标记，例如用于代码高亮或协同编辑。
6. **开发者工具调试:** 开发者可能通过开发者工具（例如 Elements 面板）选中特定的文本节点，然后查看与该节点关联的标记信息（如果开发者工具提供了这样的功能）。

**归纳一下它的功能 (第 1 部分):**

`DocumentMarkerController` 的主要功能是**管理和维护文档中各种类型的文本标记**。它负责存储、添加、移除和查询这些标记，并与渲染引擎协同工作，确保这些标记能够正确地反映在用户界面上。它是 Blink 引擎中处理文本注释和增强用户编辑体验的关键组件。

Prompt: 
```
这是目录为blink/renderer/core/editing/markers/document_marker_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2001 Dirk Mueller (mueller@kde.org)
 *           (C) 2006 Alexey Proskuryakov (ap@webkit.org)
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010 Apple Inc. All rights
 * reserved.
 * Copyright (C) 2008, 2009 Torch Mobile Inc. All rights reserved.
 * (http://www.torchmobile.com/)
 * Copyright (C) Research In Motion Limited 2010. All rights reserved.
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

#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"

#include <algorithm>

#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/editing/markers/active_suggestion_marker.h"
#include "third_party/blink/renderer/core/editing/markers/active_suggestion_marker_list_impl.h"
#include "third_party/blink/renderer/core/editing/markers/composition_marker.h"
#include "third_party/blink/renderer/core/editing/markers/composition_marker_list_impl.h"
#include "third_party/blink/renderer/core/editing/markers/custom_highlight_marker.h"
#include "third_party/blink/renderer/core/editing/markers/custom_highlight_marker_list_impl.h"
#include "third_party/blink/renderer/core/editing/markers/grammar_marker.h"
#include "third_party/blink/renderer/core/editing/markers/grammar_marker_list_impl.h"
#include "third_party/blink/renderer/core/editing/markers/sorted_document_marker_list_editor.h"
#include "third_party/blink/renderer/core/editing/markers/spelling_marker.h"
#include "third_party/blink/renderer/core/editing/markers/spelling_marker_list_impl.h"
#include "third_party/blink/renderer/core/editing/markers/suggestion_marker.h"
#include "third_party/blink/renderer/core/editing/markers/suggestion_marker_list_impl.h"
#include "third_party/blink/renderer/core/editing/markers/text_fragment_marker.h"
#include "third_party/blink/renderer/core/editing/markers/text_fragment_marker_list_impl.h"
#include "third_party/blink/renderer/core/editing/markers/text_match_marker.h"
#include "third_party/blink/renderer/core/editing/markers/text_match_marker_list_impl.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/highlight/highlight_style_utils.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/layout_text_fragment.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_hash_set.h"

namespace blink {

namespace {

DocumentMarker::MarkerTypeIndex MarkerTypeToMarkerIndex(
    DocumentMarker::MarkerType type) {
  switch (type) {
    case DocumentMarker::kSpelling:
      return DocumentMarker::kSpellingMarkerIndex;
    case DocumentMarker::kGrammar:
      return DocumentMarker::kGrammarMarkerIndex;
    case DocumentMarker::kTextMatch:
      return DocumentMarker::kTextMatchMarkerIndex;
    case DocumentMarker::kComposition:
      return DocumentMarker::kCompositionMarkerIndex;
    case DocumentMarker::kActiveSuggestion:
      return DocumentMarker::kActiveSuggestionMarkerIndex;
    case DocumentMarker::kSuggestion:
      return DocumentMarker::kSuggestionMarkerIndex;
    case DocumentMarker::kTextFragment:
      return DocumentMarker::kTextFragmentMarkerIndex;
    case DocumentMarker::kCustomHighlight:
      return DocumentMarker::kCustomHighlightMarkerIndex;
  }

  NOTREACHED();
}

DocumentMarkerList* CreateListForType(DocumentMarker::MarkerType type) {
  switch (type) {
    case DocumentMarker::kActiveSuggestion:
      return MakeGarbageCollected<ActiveSuggestionMarkerListImpl>();
    case DocumentMarker::kComposition:
      return MakeGarbageCollected<CompositionMarkerListImpl>();
    case DocumentMarker::kSpelling:
      return MakeGarbageCollected<SpellingMarkerListImpl>();
    case DocumentMarker::kGrammar:
      return MakeGarbageCollected<GrammarMarkerListImpl>();
    case DocumentMarker::kSuggestion:
      return MakeGarbageCollected<SuggestionMarkerListImpl>();
    case DocumentMarker::kTextMatch:
      return MakeGarbageCollected<TextMatchMarkerListImpl>();
    case DocumentMarker::kTextFragment:
      return MakeGarbageCollected<TextFragmentMarkerListImpl>();
    case DocumentMarker::kCustomHighlight:
      return MakeGarbageCollected<CustomHighlightMarkerListImpl>();
  }

  NOTREACHED();
}

void InvalidateVisualOverflowForNode(const Node& node,
                                     DocumentMarker::MarkerType type) {
  LayoutObject* layout_object = node.GetLayoutObject();
  if (!layout_object ||
      !DocumentMarker::MarkerTypes::HighlightPseudos().Intersects(
          DocumentMarker::MarkerTypes(type))) {
    return;
  }
  if (HighlightStyleUtils::ShouldInvalidateVisualOverflow(*layout_object,
                                                          type)) {
    layout_object->InvalidateVisualOverflow();
  }
}

void InvalidatePaintForNode(const Node& node) {
  LayoutObject* layout_object = node.GetLayoutObject();
  if (!layout_object) {
    return;
  }

  layout_object->SetShouldDoFullPaintInvalidation(
      PaintInvalidationReason::kDocumentMarker);

  if (RuntimeEnabledFeatures::PaintHighlightsForFirstLetterEnabled()) {
    // When first-letter css is present, the node only points to remainder.
    // So first letter part would not be invalidated by the above.
    auto* text_layout = DynamicTo<LayoutTextFragment>(layout_object);
    if (text_layout && text_layout->GetFirstLetterPseudoElement()) {
      LayoutText* first_letter_layout = text_layout->GetFirstLetterPart();
      CHECK(first_letter_layout);
      first_letter_layout->SetShouldDoFullPaintInvalidation(
          PaintInvalidationReason::kDocumentMarker);
    }
  }

  // Tell accessibility about the new marker.
  AXObjectCache* ax_object_cache = node.GetDocument().ExistingAXObjectCache();
  if (!ax_object_cache) {
    return;
  }
  // TODO(nektar): Do major refactoring of all AX classes to comply with const
  // correctness.
  Node* non_const_node = &const_cast<Node&>(node);
  ax_object_cache->HandleTextMarkerDataAdded(non_const_node, non_const_node);
}

PositionInFlatTree SearchAroundPositionStart(
    const PositionInFlatTree& position) {
  const PositionInFlatTree start_of_word_or_null =
      StartOfWordPosition(position, kPreviousWordIfOnBoundary);
  return start_of_word_or_null.IsNotNull() ? start_of_word_or_null : position;
}

PositionInFlatTree SearchAroundPositionEnd(const PositionInFlatTree& position) {
  const PositionInFlatTree end_of_word_or_null =
      EndOfWordPosition(position, kNextWordIfOnBoundary);
  return end_of_word_or_null.IsNotNull() ? end_of_word_or_null : position;
}

}  // namespace

bool DocumentMarkerController::PossiblyHasMarkers(
    DocumentMarker::MarkerType type) const {
  return PossiblyHasMarkers(DocumentMarker::MarkerTypes(type));
}

inline bool DocumentMarkerController::PossiblyHasMarkers(
    DocumentMarker::MarkerTypes types) const {
  DCHECK(!markers_.empty() ||
         possibly_existing_marker_types_ == DocumentMarker::MarkerTypes(0));
  return possibly_existing_marker_types_.Intersects(types);
}

bool DocumentMarkerController::HasAnyMarkersForText(const Text& text) const {
  for (const auto& marker_map : markers_) {
    if (marker_map && marker_map->Contains(&text)) {
      return true;
    }
  }
  return false;
}

DocumentMarkerController::DocumentMarkerController(Document& document)
    : document_(&document) {
  markers_.Grow(DocumentMarker::kMarkerTypeIndexesCount);
}

void DocumentMarkerController::AddSpellingMarker(const EphemeralRange& range,
                                                 const String& description) {
  AddMarkerInternal(range, [&description](int start_offset, int end_offset) {
    return MakeGarbageCollected<SpellingMarker>(start_offset, end_offset,
                                                description);
  });
}

void DocumentMarkerController::AddGrammarMarker(const EphemeralRange& range,
                                                const String& description) {
  AddMarkerInternal(range, [&description](int start_offset, int end_offset) {
    return MakeGarbageCollected<GrammarMarker>(start_offset, end_offset,
                                               description);
  });
}

void DocumentMarkerController::AddTextMatchMarker(
    const EphemeralRange& range,
    TextMatchMarker::MatchStatus match_status) {
  DCHECK(!document_->NeedsLayoutTreeUpdate());
  AddMarkerInternal(
      range,
      [match_status](int start_offset, int end_offset) {
        return MakeGarbageCollected<TextMatchMarker>(start_offset, end_offset,
                                                     match_status);
      },
      // Since we've already determined to have a match in the given range (via
      // FindBuffer), we can ignore the display lock for the purposes of finding
      // where to put the marker.
      TextIteratorBehavior::Builder().SetIgnoresDisplayLock(true).Build());
  // Don't invalidate tickmarks here. TextFinder invalidates tickmarks using a
  // throttling algorithm. crbug.com/6819.
}

void DocumentMarkerController::AddCompositionMarker(
    const EphemeralRange& range,
    Color underline_color,
    ui::mojom::ImeTextSpanThickness thickness,
    ui::mojom::ImeTextSpanUnderlineStyle underline_style,
    Color text_color,
    Color background_color) {
  DCHECK(!document_->NeedsLayoutTreeUpdate());
  AddMarkerInternal(range,
                    [underline_color, thickness, underline_style, text_color,
                     background_color](int start_offset, int end_offset) {
                      return MakeGarbageCollected<CompositionMarker>(
                          start_offset, end_offset, underline_color, thickness,
                          underline_style, text_color, background_color);
                    });
}

void DocumentMarkerController::AddActiveSuggestionMarker(
    const EphemeralRange& range,
    Color underline_color,
    ui::mojom::ImeTextSpanThickness thickness,
    ui::mojom::ImeTextSpanUnderlineStyle underline_style,
    Color text_color,
    Color background_color) {
  DCHECK(!document_->NeedsLayoutTreeUpdate());
  AddMarkerInternal(range,
                    [underline_color, thickness, underline_style, text_color,
                     background_color](int start_offset, int end_offset) {
                      return MakeGarbageCollected<ActiveSuggestionMarker>(
                          start_offset, end_offset, underline_color, thickness,
                          underline_style, text_color, background_color);
                    });
}

void DocumentMarkerController::AddSuggestionMarker(
    const EphemeralRange& range,
    const SuggestionMarkerProperties& properties) {
  DCHECK(!document_->NeedsLayoutTreeUpdate());
  AddMarkerInternal(range, [&properties](int start_offset, int end_offset) {
    return MakeGarbageCollected<SuggestionMarker>(start_offset, end_offset,
                                                  properties);
  });
}

void DocumentMarkerController::AddTextFragmentMarker(
    const EphemeralRange& range) {
  DCHECK(!document_->NeedsLayoutTreeUpdate());
  AddMarkerInternal(range, [](int start_offset, int end_offset) {
    return MakeGarbageCollected<TextFragmentMarker>(start_offset, end_offset);
  });
}

void DocumentMarkerController::AddCustomHighlightMarker(
    const EphemeralRange& range,
    const String& highlight_name,
    const Member<Highlight> highlight) {
  DCHECK(!document_->NeedsLayoutTreeUpdate());
  AddMarkerInternal(
      range, [highlight_name, highlight](int start_offset, int end_offset) {
        return MakeGarbageCollected<CustomHighlightMarker>(
            start_offset, end_offset, highlight_name, highlight);
      });
}

void DocumentMarkerController::PrepareForDestruction() {
  for (auto& marker_map : markers_) {
    marker_map.Clear();
  }
  possibly_existing_marker_types_ = DocumentMarker::MarkerTypes();
  SetDocument(nullptr);
}

void DocumentMarkerController::RemoveMarkers(
    TextIterator& marked_text,
    DocumentMarker::MarkerTypes marker_types) {
  for (; !marked_text.AtEnd(); marked_text.Advance()) {
    if (!PossiblyHasMarkers(marker_types)) {
      return;
    }
    const Node& node = marked_text.CurrentContainer();
    auto* text_node = DynamicTo<Text>(node);
    if (!text_node) {
      continue;
    }
    int start_offset = marked_text.StartOffsetInCurrentContainer();
    int end_offset = marked_text.EndOffsetInCurrentContainer();
    for (DocumentMarker::MarkerType type : marker_types) {
      RemoveMarkersInternal(*text_node, start_offset, end_offset - start_offset,
                            type);
    }
  }
}

void DocumentMarkerController::RemoveMarkersInRange(
    const EphemeralRange& range,
    DocumentMarker::MarkerTypes marker_types) {
  DCHECK(!document_->NeedsLayoutTreeUpdate());

  TextIterator marked_text(range.StartPosition(), range.EndPosition());
  DocumentMarkerController::RemoveMarkers(marked_text, marker_types);
}

void DocumentMarkerController::AddMarkerInternal(
    const EphemeralRange& range,
    base::FunctionRef<DocumentMarker*(int, int)> create_marker_from_offsets,
    const TextIteratorBehavior& iterator_behavior) {
  DocumentMarkerGroup* new_marker_group =
      MakeGarbageCollected<DocumentMarkerGroup>();
  for (TextIterator marked_text(range.StartPosition(), range.EndPosition(),
                                iterator_behavior);
       !marked_text.AtEnd(); marked_text.Advance()) {
    const int start_offset_in_current_container =
        marked_text.StartOffsetInCurrentContainer();
    const int end_offset_in_current_container =
        marked_text.EndOffsetInCurrentContainer();

    DCHECK_GE(end_offset_in_current_container,
              start_offset_in_current_container);

    // TODO(editing-dev): TextIterator sometimes emits ranges where the start
    // and end offsets are the same. Investigate if TextIterator should be
    // changed to not do this. See crbug.com/727929
    if (end_offset_in_current_container == start_offset_in_current_container) {
      continue;
    }

    // Ignore text emitted by TextIterator for non-text nodes (e.g. implicit
    // newlines)
    const auto* text_node = DynamicTo<Text>(marked_text.CurrentContainer());
    if (!text_node) {
      continue;
    }

    DocumentMarker* const new_marker = create_marker_from_offsets(
        start_offset_in_current_container, end_offset_in_current_container);
    AddMarkerToNode(*text_node, new_marker);
    new_marker_group->Set(new_marker, text_node);
    marker_groups_.insert(new_marker, new_marker_group);
  }
}

void DocumentMarkerController::AddMarkerToNode(const Text& text,
                                               DocumentMarker* new_marker) {
  DCHECK_GE(text.length(), new_marker->EndOffset());
  possibly_existing_marker_types_ = possibly_existing_marker_types_.Add(
      DocumentMarker::MarkerTypes(new_marker->GetType()));
  SetDocument(document_);

  DocumentMarker::MarkerType new_marker_type = new_marker->GetType();
  const DocumentMarker::MarkerTypeIndex type_index =
      MarkerTypeToMarkerIndex(new_marker_type);
  Member<MarkerMap>& marker_map = markers_[type_index];
  if (!marker_map) {
    marker_map = MakeGarbageCollected<MarkerMap>();
    markers_[type_index] = marker_map;
  }

  MarkerList& markers = marker_map->insert(&text, nullptr).stored_value->value;
  if (!markers) {
    markers = CreateListForType(new_marker_type);
  }
  markers->Add(new_marker);

  InvalidatePaintForNode(text);
  InvalidateVisualOverflowForNode(text, new_marker->GetType());
}

// Moves markers from src_node to dst_node. Markers are moved if their start
// offset is less than length. Markers that run past that point are truncated.
void DocumentMarkerController::MoveMarkers(const Text& src_node,
                                           int length,
                                           const Text& dst_node) {
  if (length <= 0) {
    return;
  }

  if (!PossiblyHasMarkers(DocumentMarker::MarkerTypes::All())) {
    return;
  }

  bool doc_dirty = false;
  for (auto& marker_map : markers_) {
    if (!marker_map) {
      continue;
    }

    DocumentMarkerList* const src_markers = FindMarkers(marker_map, &src_node);
    if (!src_markers) {
      return;
    }
    DCHECK(!src_markers->IsEmpty());

    DocumentMarker::MarkerType type = src_markers->GetMarkers()[0]->GetType();
    auto& dst_marker_entry =
        marker_map->insert(&dst_node, nullptr).stored_value->value;
    if (!dst_marker_entry) {
      dst_marker_entry = CreateListForType(type);
    }
    DocumentMarkerList* const dst_markers = dst_marker_entry;
    DCHECK(src_markers != dst_markers);

    if (src_markers->MoveMarkers(length, dst_markers)) {
      doc_dirty = true;
      InvalidateVisualOverflowForNode(dst_node, type);
      for (const auto& marker : dst_markers->GetMarkers()) {
        auto it = marker_groups_.find(marker);
        if (it != marker_groups_.end())
          it->value->Set(marker, &dst_node);
      }
    }
    // MoveMarkers in a list can remove markers entirely when split across
    // the src and dst, in which case both lists may be empty despite
    // MoveMarkers returning false.
    if (src_markers->IsEmpty()) {
      InvalidateVisualOverflowForNode(src_node, type);
      marker_map->erase(&src_node);
      DidRemoveNodeFromMap(type);
    }
    if (dst_markers->IsEmpty()) {
      marker_map->erase(&dst_node);
      DidRemoveNodeFromMap(type);
    }
  }

  if (!doc_dirty) {
    return;
  }

  InvalidatePaintForNode(dst_node);
}

void DocumentMarkerController::DidRemoveNodeFromMap(
    DocumentMarker::MarkerType type,
    bool clear_document_allowed) {
  DocumentMarker::MarkerTypeIndex type_index = MarkerTypeToMarkerIndex(type);
  if (markers_[type_index]->empty()) {
    markers_[type_index] = nullptr;
    possibly_existing_marker_types_ = possibly_existing_marker_types_.Subtract(
        DocumentMarker::MarkerTypes(type));
  }
  if (clear_document_allowed &&
      possibly_existing_marker_types_ == DocumentMarker::MarkerTypes()) {
    SetDocument(nullptr);
  }
}

void DocumentMarkerController::RemoveMarkersInternal(
    const Text& text,
    unsigned start_offset,
    int length,
    DocumentMarker::MarkerType marker_type) {
  if (length <= 0) {
    return;
  }

  if (!PossiblyHasMarkers(DocumentMarker::MarkerTypes(marker_type))) {
    return;
  }

  MarkerMap* marker_map = markers_[MarkerTypeToMarkerIndex(marker_type)];
  DCHECK(marker_map);

  DocumentMarkerList* const list = FindMarkers(marker_map, &text);
  if (!list) {
    return;
  }

  const unsigned end_offset = start_offset + length;
  for (const Member<DocumentMarker>& marker : list->GetMarkers()) {
    if (marker->EndOffset() > start_offset &&
        marker->StartOffset() < end_offset) {
      auto it = marker_groups_.find(marker);
      if (it != marker_groups_.end()) {
        it->value->Erase(marker);
        marker_groups_.erase(marker);
      }
    }
  }
  if (list->RemoveMarkers(start_offset, length)) {
    InvalidateVisualOverflowForNode(text, marker_type);
    InvalidatePaintForNode(text);
  }
  if (list->IsEmpty()) {
    marker_map->erase(&text);
    DidRemoveNodeFromMap(marker_type);
  }
}

DocumentMarkerList* DocumentMarkerController::FindMarkers(
    const MarkerMap* marker_map,
    const Text* key) const {
  auto it = marker_map->find(key);
  if (it != marker_map->end()) {
    DCHECK(it->value);
    return it->value.Get();
  }
  return nullptr;
}

DocumentMarkerList* DocumentMarkerController::FindMarkersForType(
    DocumentMarker::MarkerType type,
    const Text* key) const {
  const MarkerMap* marker_map = markers_[MarkerTypeToMarkerIndex(type)];
  if (!marker_map) {
    return nullptr;
  }
  return FindMarkers(marker_map, key);
}

DocumentMarker* DocumentMarkerController::FirstMarkerAroundPosition(
    const PositionInFlatTree& position,
    DocumentMarker::MarkerTypes types) {
  if (position.IsNull())
    return nullptr;
  const PositionInFlatTree& start = SearchAroundPositionStart(position);
  const PositionInFlatTree& end = SearchAroundPositionEnd(position);

  if (start > end) {
    // TODO(crbug.com/1114021, crbug.com/40710583): This is unexpected, happens
    // frequently, but no good idea how to diagnose it.
    return nullptr;
  }

  const Node* const start_node = start.ComputeContainerNode();
  const unsigned start_offset = start.ComputeOffsetInContainerNode();
  const Node* const end_node = end.ComputeContainerNode();
  const unsigned end_offset = end.ComputeOffsetInContainerNode();

  for (const Node& node : EphemeralRangeInFlatTree(start, end).Nodes()) {
    auto* text_node = DynamicTo<Text>(node);
    if (!text_node) {
      continue;
    }

    const unsigned start_range_offset = node == start_node ? start_offset : 0;
    const unsigned end_range_offset =
        node == end_node ? end_offset : text_node->length();

    DocumentMarker* const found_marker = FirstMarkerIntersectingOffsetRange(
        *text_node, start_range_offset, end_range_offset, types);
    if (found_marker) {
      return found_marker;
    }
  }

  return nullptr;
}

DocumentMarker* DocumentMarkerController::FirstMarkerIntersectingEphemeralRange(
    const EphemeralRange& range,
    DocumentMarker::MarkerTypes types) {
  if (range.IsNull()) {
    return nullptr;
  }

  if (range.IsCollapsed()) {
    return FirstMarkerAroundPosition(
        ToPositionInFlatTree(range.StartPosition()), types);
  }

  const Node* const start_container =
      range.StartPosition().ComputeContainerNode();
  const Node* const end_container = range.EndPosition().ComputeContainerNode();

  auto* text_node = DynamicTo<Text>(start_container);
  if (!text_node) {
    return nullptr;
  }

  const unsigned start_offset =
      range.StartPosition().ComputeOffsetInContainerNode();
  const unsigned end_offset =
      start_container == end_container
          ? range.EndPosition().ComputeOffsetInContainerNode()
          : text_node->length();

  return FirstMarkerIntersectingOffsetRange(*text_node, start_offset,
                                            end_offset, types);
}

DocumentMarker* DocumentMarkerController::FirstMarkerIntersectingOffsetRange(
    const Text& node,
    unsigned start_offset,
    unsigned end_offset,
    DocumentMarker::MarkerTypes types) {
  if (!PossiblyHasMarkers(types)) {
    return nullptr;
  }

  // Minor optimization: if we have an empty range at a node boundary, it
  // doesn't fall in the interior of any marker.
  if (start_offset == 0 && end_offset == 0) {
    return nullptr;
  }
  const unsigned node_length = node.length();
  if (start_offset == node_length && end_offset == node_length) {
    return nullptr;
  }

  for (DocumentMarker::MarkerType type : types) {
    const DocumentMarkerList* const list = FindMarkersForType(type, &node);
    if (!list) {
      continue;
    }
    DocumentMarker* found_marker =
        list->FirstMarkerIntersectingRange(start_offset, end_offset);
    if (found_marker) {
      return found_marker;
    }
  }

  return nullptr;
}

DocumentMarkerGroup* DocumentMarkerController::FirstMarkerGroupAroundPosition(
    const PositionInFlatTree& position,
    DocumentMarker::MarkerTypes types) {
  return GetMarkerGroupForMarker(FirstMarkerAroundPosition(position, types));
}

DocumentMarkerGroup*
DocumentMarkerController::FirstMarkerGroupIntersectingEphemeralRange(
    const EphemeralRange& range,
    DocumentMarker::MarkerTypes types) {
  return GetMarkerGroupForMarker(
      FirstMarkerIntersectingEphemeralRange(range, types));
}

DocumentMarkerGroup* DocumentMarkerController::GetMarkerGroupForMarker(
    const DocumentMarker* marker) {
  if (marker) {
    auto it = marker_groups_.find(marker);
    if (it != marker_groups_.end()) {
      return it->value.Get();
    }
  }
  return nullptr;
}

HeapVector<std::pair<Member<const Text>, Member<DocumentMarker>>>
DocumentMarkerController::MarkersAroundPosition(
    const PositionInFlatTree& position,
    DocumentMarker::MarkerTypes types) {
  HeapVector<std::pair<Member<const Text>, Member<DocumentMarker>>>
      node_marker_pairs;

  if (position.IsNull()) {
    return node_marker_pairs;
  }

  if (!PossiblyHasMarkers(types)) {
    return node_marker_pairs;
  }

  const PositionInFlatTree& start = SearchAroundPositionStart(position);
  const PositionInFlatTree& end = SearchAroundPositionEnd(position);

  if (start > end) {
    // TODO(crbug.com/1114021, crbug.com/40892570): This is unexpected, happens
    // frequently, but no good idea how to diagnose it.
    return node_marker_pairs;
  }

  const Node* const start_node = start.ComputeContainerNode();
  const unsigned start_offset = start.ComputeOffsetInContainerNode();
  const Node* const end_node = end.ComputeContainerNode();
  const unsigned end_offset = end.ComputeOffsetInContainerNode();

  for (const Node& node : EphemeralRangeInFlatTree(start, end).Nodes()) {
    auto* text_node = DynamicTo<Text>(node);
    if (!text_node) {
      continue;
    }

    const unsigned start_range_offset = node == start_node ? start_offset : 0;
    const unsigned end_range_offset =
        node == end_node ? end_offset : text_node->length();

    // Minor optimization: if we have an empty range at a node boundary, it
    // doesn't fall in the interior of any marker.
    if (start_range_offset == 0 && end_range_offset == 0)
      continue;
    const unsigned node_length = To<CharacterData>(node).length();
    if (start_range_offset == node_length && end_range_offset == node_length)
      continue;

    for (DocumentMarker::MarkerType type : types) {
      const DocumentMarkerList* const list =
          FindMarkersForType(type, text_node);
      if (!list) {
        continue;
      }

      const DocumentMarkerVector& marker_vector =
          list->MarkersIntersectingRange(start_range_offset, end_range_offset);

      for (DocumentMarker* marker : marker_vector)
        node_marker_pairs.push_back(std::make_pair(&To<Text>(node), marker));
    }
  }
  return node_marker_pairs;
}

HeapVector<std::pair<Member<const Text>, Member<DocumentMarker>>>
DocumentMarkerController::MarkersIntersectingRange(
    const EphemeralRangeInFlatTree& range,
    DocumentMarker::MarkerTypes types) {
  HeapVector<std::pair<Member<const Text>, Member<DocumentMarker>>>
      node_marker_pairs;
  if (!PossiblyHasMarkers(types))
    return node_marker_pairs;

  const Node* const range_start_container =
      range.StartPosition().ComputeContainerNode();
  const unsigned range_start_offset =
      range.StartPosition().ComputeOffsetInContainerNode();
  const Node* const range_end_container =
      range.EndPosition().ComputeContainerNode();
  const unsigned range_end_offset =
      range.EndPosition().ComputeOffsetInContainerNode();

  for (Node& node : range.Nodes()) {
    auto* text_node = DynamicTo<Text>(node);
    if (!text_node)
      continue;

    const unsigned start_offset =
        node == range_start_container ? range_start_offset : 0;
    const unsigned max_character_offset = To<CharacterData>(node).length();
    const unsigned end_offset =
        node == range_end_container ? range_end_offset : max_character_offset;

    // Minor optimization: if we have an empty offset range at the boundary
    // of a text node, it doesn't fall into the interior of any marker.
    if (start_offset == 0 && end_offset == 0) {
      continue;
    }
    if (start_offset == max_character_offset && end_offset == 0) {
      continue;
    }

    for (DocumentMarker::MarkerType type : types) {
      const DocumentMarkerList* const list =
          FindMarkersForType(type, text_node);
      if (!list) {
        continue;
      }

      const DocumentMarkerVector& markers_from_this_list =
          list->MarkersIntersectingRange(start_offset, end_offset);
      for (DocumentMarker* marker : markers_from_this_list)
        node_marker_pairs.push_back(std::make_pair(&To<Text>(node), marker));
    }
  }

  return node_marker_pairs;
}

DocumentMarkerVector DocumentMarkerController::MarkersFor(
    const Text& text,
    DocumentMarker::MarkerTypes marker_types) const {
  DocumentMarkerVector result;
  if (!PossiblyHasMarkers(marker_types))
    return result;

  // If requesting a single marker type, make use of the fact
  // that markers are already sorted.
  std::optional<DocumentMarker::MarkerType> lone_marker =
      marker_types.IsOneMarkerType();
  if (lone_marker) {
    DocumentMarkerList* const list = FindMarkersForType(*lone_marker, &text);
    return list ? list->GetMarkers() : result;
  }

  for (DocumentMarker::MarkerType type : marker_types) {
    DocumentMarkerList* const list = FindMarkersForType(type, &text);
    if (!list) {
      continue;
    }

    result.AppendVector(list->GetMarkers());
  }

  std::sort(result.begin(), result.end(),
            [](const Member<DocumentMarker>& marker1,
               const Member<DocumentMarker>& marker2) {
              return marker1->StartOffset() < marker2->StartOffset();
            });
  return result;
}

DocumentMarkerVector DocumentMarkerController::MarkersFor(
    const Text& text,
    DocumentMarker::MarkerType marker_type,
    unsigned start_offset,
    unsigned end_offset) const {
  DocumentMarkerVector result;
  DocumentMarkerList* const list = FindMarkersForType(marker_type, &text);
  return list ? list->MarkersIntersectingRange(start_offset, end_offset)
              : result;
}

DocumentMarkerVector DocumentMarkerController::Markers() const {
  DocumentMarkerVector result;
  for (auto& marker_map : markers_) {
    if (!marker_map) {
      continue;
    }
    for (const auto& node_markers : *marker_map) {
      DocumentMarkerList* list = node_markers.value;
      result.AppendVector(list->GetMarkers());
    }
  }
  std::sort(result.begin(), result.end(),
            [](const Member<DocumentMarker>& marker1,
               const Member<DocumentMarker>& marker2) {
              return marker1->StartOffset() < marker2->StartOffset();
            });
  return result;
}

void DocumentMarkerController::ApplyToMarkersOfType(
    base::FunctionRef<void(const Text&, DocumentMarker*)> func,
    DocumentMarker::MarkerType type) {
  if (!PossiblyHasMarkers(type)) {
    return;
  }
  MarkerMap* marker_map = markers_[MarkerTypeToMarkerIndex(type)];
  DCHECK(marker_map);
  for (auto& node_markers : *marker_map) {
    DocumentMarkerList* list = node_markers.value;
    const HeapVector<Member<DocumentMarker>>& markers = list->GetMarkers();
    for (auto& marker : markers) {
      func(*node_markers.key, marker);
    }
  }
}

void DocumentMarkerController::MergeOverlappingMarkers(
    DocumentMarker::MarkerType type) {
  MarkerMap* marker_map = markers_[MarkerTypeToMarkerIndex(type)];
  if (!marker_map) {
    return;
  }
  for (auto& node_markers : *marker_map) {
    DCHECK(node_markers.value);
    node_markers.value->MergeOverlappingMarkers();
  }
}

DocumentMarkerVector DocumentMarkerController::ComputeMarkersToPaint(
    const Text& text) const {
  DocumentMarker::MarkerTypes excluded_highlight_pseudos =
      DocumentMarker::MarkerTypes::HighlightPseudos();
  DocumentMarkerVector markers_to_paint{};

  // We don't render composition or spelling markers that overlap suggestion
  // markers.
  // Note: DocumentMarkerController::MarkersFor() returns markers sorted by
  // start offset.
  const DocumentMarkerVector
"""


```