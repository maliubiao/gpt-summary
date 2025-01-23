Response:
The user is asking for a summary of the functionality of the provided C++ code snippet, which is part of the Chromium Blink rendering engine. The code is within the `DocumentMarkerController` class and deals with managing and manipulating document markers.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Class:** The code belongs to `DocumentMarkerController`. This immediately suggests its primary responsibility is managing document markers.

2. **Scan for Key Methods:** Look for methods with descriptive names. Methods like `MarkersFor`, `LayoutRectsForTextMatchMarkers`, `InvalidateRectsForTextMatchMarkersInNode`, `RemoveMarkersForNode`, `RemoveSpellingMarkersUnderWords`, `RemoveSuggestionMarkerInRangeOnFinish`, `SetTextMatchMarkersActive`, and `DidUpdateCharacterData` stand out.

3. **Group Functionalities:** Based on the method names, group related functionalities:
    * **Retrieving Markers:** `MarkersFor` suggests retrieving markers based on criteria.
    * **Layout and Painting:**  Methods involving `LayoutRects`, `InvalidatePaint`, and `InvalidateRects` are related to how markers are rendered.
    * **Adding/Removing Markers:** `RemoveMarkersForNode`, `RemoveSpellingMarkersUnderWords`, `RemoveSuggestionMarker...` are clearly about marker management.
    * **Text Match Markers:**  Several methods specifically deal with `TextMatch` markers, suggesting a special handling for them.
    * **Active State:** `SetTextMatchMarkersActive` indicates the ability to change the state of certain markers.
    * **Handling Text Updates:** `DidUpdateCharacterData` shows how the controller reacts to changes in the text content.

4. **Analyze Specific Code Blocks:**  For crucial functions like `PaintMarkers`, carefully examine the logic. In `PaintMarkers`, the code prioritizes suggestion markers and avoids painting other markers that overlap with them. This indicates a conflict resolution mechanism for marker display.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):** Think about how these marker functionalities manifest in web pages.
    * **Spellcheck/Grammar:**  Misspelling and suggestion markers directly relate to browser spellchecking.
    * **Find in Page:** Text match markers are used for the "Find in Page" feature.
    * **Composition/IME:** Composition markers are used during text input, especially with IME.
    * **Custom Highlights:**  The code mentions custom highlight markers, which could be exposed through browser APIs or used internally.
    * **CSS Styling:**  The invalidation methods imply that markers can affect the visual rendering and thus interact with CSS. Pseudo-elements are explicitly mentioned in the code, suggesting a connection to CSS styling of markers.
    * **JavaScript Interaction:** While not directly exposed in this snippet, it's reasonable to assume that JavaScript APIs might exist to trigger actions that result in markers being added or removed (e.g., programmatic spellchecking, implementing custom search).

6. **Identify Potential Errors:** Consider how developers or users might misuse these functionalities. For instance, incorrect assumptions about marker boundaries or the timing of marker updates can lead to rendering glitches.

7. **Trace User Actions:** Think about the user actions that would lead to this code being executed. Typing, using "Find in Page," right-clicking for spellcheck suggestions, and using IME are all relevant actions.

8. **Focus on the Current Snippet (Part 2):** The prompt specifies this is part 2. Review the provided code and identify the primary functions within *this* snippet. This part heavily focuses on removing and invalidating markers, especially text match and suggestion markers, and handling updates to text nodes.

9. **Synthesize and Summarize:** Combine the observations into a concise summary that covers the key functionalities of this specific code segment. Emphasize the removal and invalidation aspects.

10. **Refine and Organize:** Structure the summary logically, using clear language and bullet points for readability. Ensure all aspects of the prompt are addressed. For example, the prompt asks for relationships with web technologies, examples, logical reasoning explanations, error scenarios, and debugging clues.
This部分代码主要负责以下功能，这些功能是 `DocumentMarkerController` 类中处理文档标记的核心逻辑：

**核心功能归纳：**

1. **管理和绘制文档标记 (Painting Markers with Prioritization):**  `PaintMarkers` 函数是本段代码的核心，它负责决定哪些文档标记需要被绘制。它特别关注 `Suggestion` 标记，并确保当存在 `Suggestion` 标记时，与之重叠的 `Composition` 和 `Spelling` 标记不会被绘制。这是一种优先级处理机制，确保用户最相关的建议能够清晰显示。

2. **处理文本匹配标记 (Text Match Markers):**  代码提供了管理和操作文本匹配标记的功能，包括：
    * 检查是否存在文本匹配标记 (`PossiblyHasTextMatchMarkers`).
    * 获取文本匹配标记的布局矩形 (`LayoutRectsForTextMatchMarkers`).
    * 使指定节点或所有节点的文本匹配标记的区域失效 (`InvalidateRectsForTextMatchMarkersInNode`, `InvalidateRectsForAllTextMatchMarkers`).
    * 设置文本匹配标记的激活状态 (`SetTextMatchMarkersActive`).

3. **移除文档标记 (Removing Markers):** 提供了多种移除文档标记的方式：
    * 移除特定节点上的特定类型标记 (`RemoveMarkersForNode`).
    * 移除与特定单词重叠的拼写错误标记 (`RemoveSpellingMarkersUnderWords`).
    * 移除特定范围内的建议标记 (根据完成状态或类型) (`RemoveSuggestionMarkerInRangeOnFinish`, `RemoveSuggestionMarkerByType`).
    * 移除特定类型的建议标记 (`RemoveSuggestionMarkerByType`).
    * 移除具有特定标签的建议标记 (`RemoveSuggestionMarkerByTag`).
    * 移除多种类型的标记 (`RemoveMarkersOfTypes`).
    * 从标记列表中移除标记并清理相关数据 (`RemoveMarkersFromList`).

4. **响应文本内容更新 (Handling Character Data Updates):**  `DidUpdateCharacterData` 函数处理文本节点内容更新的情况，它会移动或移除受文本更改影响的文档标记，并使相关的渲染区域失效。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **JavaScript:** JavaScript 可以通过 Chromium 提供的 API (例如，通过扩展或者内部机制) 来添加、修改或移除文档标记。例如，一个拼写检查的 JavaScript 库可能会调用 Blink 的接口来添加 `Spelling` 类型的标记。
    * **假设输入:** JavaScript 代码调用 API 在文本 "The quick brown fox jumpes over the lazy dog" 的 "jumpes" 处添加一个 `Spelling` 标记。
    * **输出:**  `DocumentMarkerController` 会创建并存储这个标记，并在绘制时将其渲染出来。

* **HTML:** HTML 结构定义了文本内容，而文档标记通常与特定的文本节点相关联。
    * **假设输入:** HTML 中存在 `<p>This is a misspeled word.</p>`。
    * **输出:**  拼写检查功能可能会在 "misspeled" 上添加一个 `Spelling` 标记。

* **CSS:** CSS 可以用来控制文档标记的渲染样式，例如下划线的颜色、样式等。Chromium 内部可能会使用特定的 CSS pseudo-elements 来渲染这些标记。
    * **举例说明:**  拼写错误标记可能会使用红色波浪线下划线渲染，这可以通过 CSS 内部样式或者用户自定义样式来控制。
    * 代码中的 `excluded_highlight_pseudos` 表明在绘制标记时会考虑排除特定的高亮伪类，这与 CSS 的渲染机制有关。

**逻辑推理 (假设输入与输出):**

* **场景：存在一个拼写错误标记和一个重叠的建议标记。**
    * **假设输入:** 文本 "worrd"，有一个 `Spelling` 标记覆盖整个单词，同时有一个 `Suggestion` 标记也覆盖整个单词。
    * **输出:**  在 `PaintMarkers` 函数中，由于存在 `Suggestion` 标记，`Spelling` 标记将被忽略，最终只绘制 `Suggestion` 标记（例如，显示一个建议修改的下拉菜单或高亮）。

* **场景：设置文本匹配标记的激活状态。**
    * **假设输入:** 用户在 "Find in Page" 功能中搜索 "hello"，文本中多个 "hello" 被标记为 `TextMatch`。JavaScript 调用 API 将第二个 "hello" 对应的 `TextMatch` 标记设置为激活状态。
    * **输出:** `SetTextMatchMarkersActive` 函数会将该标记的激活状态设置为 true，并在下次绘制时，该匹配项可能会以不同的样式（例如，更醒目的背景色）显示。

**用户或编程常见的使用错误及举例说明：**

* **错误地假设标记的边界:**  开发者可能错误地认为标记的起始和结束偏移量是绝对的，而没有考虑到文本内容可能发生变化。如果文本内容在标记存在期间被修改，标记的实际位置可能会发生偏移。
    * **举例说明:**  一个自定义高亮功能的开发者在文本 "abcdefg" 的 "cde" 上添加了一个高亮标记。之后，用户在 "b" 和 "c" 之间插入了 "xyz"。开发者如果没有正确处理，高亮标记可能仍然覆盖原来的 "cde"，实际上应该覆盖 "xycde"。`DidUpdateCharacterData` 的作用就是为了处理这类情况。

* **在不正确的时机移除标记:**  在某些情况下，开发者可能会尝试在渲染流程中或者在标记正在被使用时移除它，这可能导致崩溃或者未定义的行为。
    * **举例说明:**  一个拼写检查功能在用户点击建议修改后立即移除了拼写错误标记，但如果渲染线程还在尝试绘制这个标记，可能会发生错误。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户输入文本:** 用户在网页的文本框或可编辑区域输入文本时，可能会触发拼写检查或自动更正功能，从而添加 `Spelling` 或 `Suggestion` 类型的标记。
2. **用户使用 "查找" 功能:** 用户按下 Ctrl+F (或 Cmd+F) 并输入搜索关键词，会导致浏览器在页面上添加 `TextMatch` 类型的标记。
3. **网页 JavaScript 代码执行:** 网页的 JavaScript 代码可能会调用浏览器提供的 API 来添加自定义的文档标记，例如用于实现代码高亮或注释功能。
4. **输入法 (IME) 操作:**  用户在使用输入法输入文本时，会产生 `Composition` 类型的标记，指示当前正在输入的文本段。
5. **用户与建议标记交互:** 用户右键点击拼写错误的单词，浏览器显示建议修改的菜单，这些菜单项与 `Suggestion` 标记相关联。用户选择某个建议会触发移除旧的 `Spelling` 标记并可能添加新的文本。

当这些操作发生时，Blink 引擎会更新文档模型，`DocumentMarkerController` 会相应地添加、移除或更新相关的文档标记。如果涉及到标记的绘制，`PaintMarkers` 函数会被调用来决定哪些标记需要显示。如果涉及到文本内容的修改，`DidUpdateCharacterData` 会被调用来调整标记的位置。

**总结 (针对第2部分代码):**

这部分代码专注于**管理和操作文档标记的生命周期**，特别是**根据优先级规则绘制标记**和**响应文本内容变化来维护标记的正确性**。它提供了添加、查询、移除和更新各种类型文档标记的功能，并处理了不同标记类型之间的交互，例如在存在建议标记时抑制显示重叠的拼写错误标记。此外，它还包含了处理文本匹配标记的特定逻辑，例如高亮显示搜索结果。代码中的方法为 Blink 引擎提供了细粒度的控制，以确保文档标记能够准确、高效地渲染，并与用户的交互和文档的变化保持同步。

### 提示词
```
这是目录为blink/renderer/core/editing/markers/document_marker_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
& suggestion_markers =
      MarkersFor(text, DocumentMarker::MarkerTypes::Suggestion());
  if (suggestion_markers.empty()) {
    // If there are no suggestion markers, we can return early as a minor
    // performance optimization.
    markers_to_paint.AppendVector(MarkersFor(
        text, DocumentMarker::MarkerTypes::AllBut(
                  DocumentMarker::MarkerTypes(DocumentMarker::kSuggestion |
                                              DocumentMarker::kCustomHighlight))
                  .Subtract(excluded_highlight_pseudos)));
    return markers_to_paint;
  }

  const DocumentMarkerVector& markers_overridden_by_suggestion_markers =
      MarkersFor(text,
                 DocumentMarker::MarkerTypes(DocumentMarker::kComposition |
                                             DocumentMarker::kSpelling)
                     .Subtract(excluded_highlight_pseudos));

  Vector<unsigned> suggestion_starts;
  Vector<unsigned> suggestion_ends;
  for (const DocumentMarker* suggestion_marker : suggestion_markers) {
    suggestion_starts.push_back(suggestion_marker->StartOffset());
    suggestion_ends.push_back(suggestion_marker->EndOffset());
  }

  // StartOffsets are already sorted.
  std::sort(suggestion_ends.begin(), suggestion_ends.end());

  unsigned suggestion_starts_index = 0;
  unsigned suggestion_ends_index = 0;
  unsigned number_suggestions_currently_inside = 0;

  for (DocumentMarker* marker : markers_overridden_by_suggestion_markers) {
    while (suggestion_starts_index < suggestion_starts.size() &&
           suggestion_starts[suggestion_starts_index] <=
               marker->StartOffset()) {
      ++suggestion_starts_index;
      ++number_suggestions_currently_inside;
    }
    while (suggestion_ends_index < suggestion_ends.size() &&
           suggestion_ends[suggestion_ends_index] <= marker->StartOffset()) {
      ++suggestion_ends_index;
      --number_suggestions_currently_inside;
    }

    // At this point, number_suggestions_currently_inside should be equal to the
    // number of suggestion markers overlapping the point marker->StartOffset()
    // (marker endpoints don't count as overlapping).

    // Marker is overlapped by a suggestion marker, do not paint.
    if (number_suggestions_currently_inside) {
      continue;
    }

    // Verify that no suggestion marker starts before the current marker ends.
    if (suggestion_starts_index < suggestion_starts.size() &&
        suggestion_starts[suggestion_starts_index] < marker->EndOffset()) {
      continue;
    }

    markers_to_paint.push_back(marker);
  }

  markers_to_paint.AppendVector(suggestion_markers);

  markers_to_paint.AppendVector(MarkersFor(
      text,
      DocumentMarker::MarkerTypes::AllBut(
          DocumentMarker::MarkerTypes(
              DocumentMarker::kComposition | DocumentMarker::kSpelling |
              DocumentMarker::kSuggestion | DocumentMarker::kCustomHighlight))
          .Subtract(excluded_highlight_pseudos)));

  return markers_to_paint;
}

bool DocumentMarkerController::PossiblyHasTextMatchMarkers() const {
  return PossiblyHasMarkers(DocumentMarker::kTextMatch);
}

Vector<gfx::Rect> DocumentMarkerController::LayoutRectsForTextMatchMarkers() {
  DCHECK(!document_->View()->NeedsLayout());
  DCHECK(!document_->NeedsLayoutTreeUpdate());

  Vector<gfx::Rect> result;

  if (!PossiblyHasMarkers(DocumentMarker::kTextMatch)) {
    return result;
  }

  MarkerMap* marker_map =
      markers_[MarkerTypeToMarkerIndex(DocumentMarker::kTextMatch)];
  DCHECK(marker_map);
  MarkerMap::iterator end = marker_map->end();
  for (MarkerMap::iterator node_iterator = marker_map->begin();
       node_iterator != end; ++node_iterator) {
    // inner loop; process each marker in this node
    const Node& node = *node_iterator->key;
    if (!node.isConnected()) {
      continue;
    }
    DocumentMarkerList* const list = node_iterator->value.Get();
    if (!list) {
      continue;
    }
    result.AppendVector(To<TextMatchMarkerListImpl>(list)->LayoutRects(node));
  }

  return result;
}

static void InvalidatePaintForTickmarks(const Node& node) {
  if (LayoutView* layout_view = node.GetDocument().GetLayoutView())
    layout_view->InvalidatePaintForTickmarks();
}

void DocumentMarkerController::InvalidateRectsForTextMatchMarkersInNode(
    const Text& node) {
  if (!PossiblyHasMarkers(DocumentMarker::kTextMatch)) {
    return;
  }

  const DocumentMarkerList* const marker_list =
      FindMarkersForType(DocumentMarker::kTextMatch, &node);
  if (!marker_list) {
    return;
  }

  const HeapVector<Member<DocumentMarker>>& markers_in_list =
      marker_list->GetMarkers();
  for (auto& marker : markers_in_list)
    To<TextMatchMarker>(marker.Get())->Invalidate();

  InvalidatePaintForTickmarks(node);
}

void DocumentMarkerController::InvalidateRectsForAllTextMatchMarkers() {
  if (!PossiblyHasMarkers(DocumentMarker::kTextMatch)) {
    return;
  }

  const MarkerMap* marker_map =
      markers_[MarkerTypeToMarkerIndex(DocumentMarker::kTextMatch)];
  DCHECK(marker_map);

  for (auto& node_markers : *marker_map) {
    const Text& node = *node_markers.key;
    InvalidateRectsForTextMatchMarkersInNode(node);
  }
}

void DocumentMarkerController::Trace(Visitor* visitor) const {
  visitor->Trace(markers_);
  visitor->Trace(marker_groups_);
  visitor->Trace(document_);
  SynchronousMutationObserver::Trace(visitor);
}

void DocumentMarkerController::RemoveMarkersForNode(
    const Text& text,
    DocumentMarker::MarkerTypes marker_types) {
  if (!PossiblyHasMarkers(marker_types)) {
    return;
  }

  for (auto type : marker_types) {
    MarkerMap* marker_map = markers_[MarkerTypeToMarkerIndex(type)];
    if (!marker_map) {
      continue;
    }
    MarkerMap::iterator iterator = marker_map->find(&text);
    if (iterator != marker_map->end()) {
      RemoveMarkersFromList(iterator, type);
    }
  }
}

void DocumentMarkerController::RemoveSpellingMarkersUnderWords(
    const Vector<String>& words) {
  for (DocumentMarker::MarkerType type :
       DocumentMarker::MarkerTypes::Misspelling()) {
    MarkerMap* marker_map = markers_[MarkerTypeToMarkerIndex(type)];
    if (!marker_map) {
      continue;
    }
    HeapHashSet<WeakMember<Text>> nodes_to_remove;
    for (auto& node_markers : *marker_map) {
      const Text& text = *node_markers.key;
      DocumentMarkerList* const list = node_markers.value;
      if (To<SpellCheckMarkerListImpl>(list)->RemoveMarkersUnderWords(
              text.data(), words)) {
        InvalidateVisualOverflowForNode(text, type);
        InvalidatePaintForNode(text);
        if (list->IsEmpty()) {
          nodes_to_remove.insert(node_markers.key);
        }
      }
    }
    if (nodes_to_remove.size()) {
      for (auto node : nodes_to_remove) {
        marker_map->erase(node);
      }
      nodes_to_remove.clear();
      DidRemoveNodeFromMap(type);
    }
  }
}

void DocumentMarkerController::RemoveSuggestionMarkerInRangeOnFinish(
    const EphemeralRangeInFlatTree& range) {
  // MarkersIntersectingRange() might be expensive. In practice, we hope we will
  // only check one node for composing range.
  const HeapVector<std::pair<Member<const Text>, Member<DocumentMarker>>>&
      node_marker_pairs = MarkersIntersectingRange(
          range, DocumentMarker::MarkerTypes::Suggestion());
  MarkerMap* marker_map =
      markers_[MarkerTypeToMarkerIndex(DocumentMarker::kSuggestion)];
  for (const auto& node_marker_pair : node_marker_pairs) {
    auto* suggestion_marker =
        To<SuggestionMarker>(node_marker_pair.second.Get());
    if (suggestion_marker->NeedsRemovalOnFinishComposing()) {
      const Text& text = *node_marker_pair.first;
      DocumentMarkerList* const list = FindMarkers(marker_map, &text);
      // RemoveMarkerByTag() might be expensive. In practice, we have at most
      // one suggestion marker needs to be removed.
      To<SuggestionMarkerListImpl>(list)->RemoveMarkerByTag(
          suggestion_marker->Tag());
      InvalidatePaintForNode(text);
      if (list->IsEmpty()) {
        marker_map->erase(&text);
        DidRemoveNodeFromMap(DocumentMarker::kSuggestion);
      }
    }
  }
}

void DocumentMarkerController::RemoveSuggestionMarkerByType(
    const EphemeralRangeInFlatTree& range,
    const SuggestionMarker::SuggestionType& type) {
  // MarkersIntersectingRange() might be expensive. In practice, we hope we will
  // only check one node for the range.
  const HeapVector<std::pair<Member<const Text>, Member<DocumentMarker>>>&
      node_marker_pairs = MarkersIntersectingRange(
          range, DocumentMarker::MarkerTypes::Suggestion());
  MarkerMap* marker_map =
      markers_[MarkerTypeToMarkerIndex(DocumentMarker::kSuggestion)];
  for (const auto& node_marker_pair : node_marker_pairs) {
    const Text& text = *node_marker_pair.first;
    DocumentMarkerList* const list = FindMarkers(marker_map, &text);
    // RemoveMarkerByType() might be expensive. In practice, we have at most
    // one suggestion marker needs to be removed.
    To<SuggestionMarkerListImpl>(list)->RemoveMarkerByType(type);
    InvalidatePaintForNode(text);
    if (list->IsEmpty()) {
      marker_map->erase(node_marker_pair.first);
      DidRemoveNodeFromMap(DocumentMarker::kSuggestion);
    }
  }
}

void DocumentMarkerController::RemoveSuggestionMarkerByType(
    const SuggestionMarker::SuggestionType& type) {
  if (!PossiblyHasMarkers(DocumentMarker::kSuggestion)) {
    return;
  }
  MarkerMap* marker_map =
      markers_[MarkerTypeToMarkerIndex(DocumentMarker::kSuggestion)];
  DCHECK(marker_map);
  for (const auto& node_markers : *marker_map) {
    DocumentMarkerList* const list = node_markers.value;
    if (To<SuggestionMarkerListImpl>(list)->RemoveMarkerByType(type)) {
      InvalidatePaintForNode(*node_markers.key);
      if (list->IsEmpty()) {
        marker_map->erase(node_markers.key);
        DidRemoveNodeFromMap(DocumentMarker::kSuggestion);
      }
      return;
    }
  }
}

void DocumentMarkerController::RemoveSuggestionMarkerByTag(const Text& text,
                                                           int32_t marker_tag) {
  if (!PossiblyHasMarkers(DocumentMarker::kSuggestion)) {
    return;
  }
  MarkerMap* marker_map =
      markers_[MarkerTypeToMarkerIndex(DocumentMarker::kSuggestion)];
  DCHECK(marker_map);

  DocumentMarkerList* markers = marker_map->at(&text);
  auto* const list = To<SuggestionMarkerListImpl>(markers);
  if (!list->RemoveMarkerByTag(marker_tag)) {
    return;
  }
  if (list->IsEmpty()) {
    marker_map->erase(&text);
    DidRemoveNodeFromMap(DocumentMarker::kSuggestion);
  }
  InvalidatePaintForNode(text);
}

void DocumentMarkerController::RemoveMarkersOfTypes(
    DocumentMarker::MarkerTypes marker_types) {
  if (!PossiblyHasMarkers(marker_types)) {
    return;
  }

  HeapVector<Member<const Text>> nodes_with_markers;
  for (DocumentMarker::MarkerType type : marker_types) {
    MarkerMap* marker_map = markers_[MarkerTypeToMarkerIndex(type)];
    if (!marker_map) {
      continue;
    }
    CopyKeysToVector(*marker_map, nodes_with_markers);
    for (const auto& node : nodes_with_markers) {
      MarkerMap::iterator iterator = marker_map->find(node);
      if (iterator != marker_map->end()) {
        RemoveMarkersFromList(iterator, type);
      }
    }
  }
}

void DocumentMarkerController::RemoveMarkersFromList(
    MarkerMap::iterator iterator,
    DocumentMarker::MarkerType marker_type) {
  DocumentMarkerList* const list = iterator->value.Get();
  list->Clear();

  const Text& node = *iterator->key;
  InvalidateVisualOverflowForNode(node, marker_type);
  InvalidatePaintForNode(node);
  InvalidatePaintForTickmarks(node);

  MarkerMap* marker_map = markers_[MarkerTypeToMarkerIndex(marker_type)];
  marker_map->erase(iterator);
  DidRemoveNodeFromMap(marker_type);
}

bool DocumentMarkerController::SetTextMatchMarkersActive(
    const EphemeralRange& range,
    bool active) {
  if (!PossiblyHasMarkers(DocumentMarker::kTextMatch)) {
    return false;
  }

  DCHECK(!markers_.empty());

  const Node* const start_container =
      range.StartPosition().ComputeContainerNode();
  DCHECK(start_container);
  const Node* const end_container = range.EndPosition().ComputeContainerNode();
  DCHECK(end_container);

  const unsigned container_start_offset =
      range.StartPosition().ComputeOffsetInContainerNode();
  const unsigned container_end_offset =
      range.EndPosition().ComputeOffsetInContainerNode();

  bool marker_found = false;
  for (Node& node : range.Nodes()) {
    auto* text_node = DynamicTo<Text>(node);
    if (!text_node) {
      continue;
    }
    int start_offset = node == start_container ? container_start_offset : 0;
    int end_offset = node == end_container ? container_end_offset : INT_MAX;
    marker_found |=
        SetTextMatchMarkersActive(*text_node, start_offset, end_offset, active);
  }
  return marker_found;
}

bool DocumentMarkerController::SetTextMatchMarkersActive(const Text& text,
                                                         unsigned start_offset,
                                                         unsigned end_offset,
                                                         bool active) {
  DocumentMarkerList* const list =
      FindMarkersForType(DocumentMarker::kTextMatch, &text);
  if (!list) {
    return false;
  }

  bool doc_dirty = To<TextMatchMarkerListImpl>(list)->SetTextMatchMarkersActive(
      start_offset, end_offset, active);

  if (!doc_dirty) {
    return false;
  }
  InvalidatePaintForNode(text);
  return true;
}

#if DCHECK_IS_ON()
void DocumentMarkerController::ShowMarkers() const {
  StringBuilder builder;
  for (DocumentMarker::MarkerType type : DocumentMarker::MarkerTypes::All()) {
    const MarkerMap* marker_map = markers_[MarkerTypeToMarkerIndex(type)];
    if (!marker_map) {
      continue;
    }
    for (auto& node_iterator : *marker_map) {
      const Text* node = node_iterator.key;
      builder.AppendFormat("%p", node);
      DocumentMarkerList* const list = node_iterator.value;
      const HeapVector<Member<DocumentMarker>>& markers_in_list =
          list->GetMarkers();
      for (const DocumentMarker* marker : markers_in_list) {
        bool is_active_match = false;
        if (auto* text_match = DynamicTo<TextMatchMarker>(marker)) {
          is_active_match = text_match->IsActiveMatch();
        }

        builder.AppendFormat(
            " %u:[%u:%u](%d)", static_cast<uint32_t>(marker->GetType()),
            marker->StartOffset(), marker->EndOffset(), is_active_match);
      }
    }
    builder.Append("\n");
  }
  LOG(INFO) << builder.ToString().Utf8();
}
#endif

// SynchronousMutationObserver
void DocumentMarkerController::DidUpdateCharacterData(CharacterData* node,
                                                      unsigned offset,
                                                      unsigned old_length,
                                                      unsigned new_length) {
  if (!PossiblyHasMarkers(DocumentMarker::MarkerTypes::All()))
    return;

  auto* text_node = DynamicTo<Text>(node);
  if (!text_node)
    return;

  bool did_shift_marker = false;
  for (auto& marker_map : markers_) {
    if (!marker_map) {
      continue;
    }
    DocumentMarkerList* const list = FindMarkers(marker_map, text_node);
    if (!list) {
      continue;
    }
    DCHECK(!list->IsEmpty());
    DocumentMarker::MarkerType type = list->GetMarkers()[0]->GetType();
    if (list->ShiftMarkers(node->data(), offset, old_length, new_length)) {
      did_shift_marker = true;
    }
    if (list->IsEmpty()) {
      InvalidateVisualOverflowForNode(*node, type);
      marker_map->erase(text_node);
      DidRemoveNodeFromMap(type, false);
    }
  }

  if (!did_shift_marker)
    return;
  if (!node->GetLayoutObject())
    return;
  InvalidateRectsForTextMatchMarkersInNode(*text_node);
  InvalidatePaintForNode(*node);
}

}  // namespace blink

#if DCHECK_IS_ON()
void ShowDocumentMarkers(const blink::DocumentMarkerController* controller) {
  if (controller)
    controller->ShowMarkers();
}
#endif
```