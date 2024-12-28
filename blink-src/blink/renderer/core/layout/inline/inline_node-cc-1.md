Response:
The user wants to understand the functionality of the `inline_node.cc` file in the Chromium Blink engine. This is the second part of a three-part request, so the focus should be on summarizing the functionality presented in this specific snippet.

Here's a breakdown of the code and its functions:

1. **InlineItem Manipulation:** The code defines methods for copying and splitting `InlineItem` objects, ensuring that the splitting respects character boundaries that might affect rendering (like ligatures or Arabic joining). These methods (`CopyItemAfter`, `CopyItemBefore`, `GetFirstSafeToReuse`, `GetLastSafeToReuse`) are crucial for efficiently handling text modifications and line breaking.

2. **Offset Adjustment:** The `ShiftItem` function adjusts the start and end offsets of an `InlineItem`, which is likely used when text is inserted or deleted.

3. **Item Verification:** The `VerifyItems` function (active in debug builds) checks the consistency of a list of `InlineItem` objects, ensuring that they are ordered correctly and their offsets are valid.

4. **Text Modification with Offset:** The `SetTextWithOffset` function handles in-place text modifications. It attempts to reuse existing `InlineItem` data where possible to avoid unnecessary recalculations. This function interacts with text shaping and layout.

5. **Lazy Initialization of Inline Data:** The `EnsureData` and `ComputeOffsetMappingIfNeeded` methods handle the lazy creation of the `InlineNodeData`, which contains information about the text content and its layout.

6. **Offset Mapping Calculation:** The `ComputeOffsetMapping` function creates a mapping between the original text and any transformed text (e.g., due to CSS `text-transform`). This is important for correctly identifying character positions.

7. **Collecting Inline Items:** The `CollectInlines` function is responsible for traversing the layout tree and building a list of `InlineItem` objects. It handles different types of inline content (text, inline elements) and merges adjacent text nodes where possible. It also handles SVG text specifics.

8. **Finding SVG Text Chunks:** The `FindSvgTextChunks` function identifies and processes individual text chunks within SVG text elements.

9. **Text Segmentation:** The `SegmentText`, `SegmentScriptRuns`, `SegmentFontOrientation`, and `SegmentBidiRuns` functions break down the text into smaller units based on different criteria: bidirectional text runs, script boundaries, font orientation requirements, and Unicode bidirectional algorithm rules.

10. **Text Shaping:** The `ShapeText` function is the core of the text rendering process. It uses a text shaper to convert the text into glyphs, taking into account font features, ligatures, and other rendering details. It attempts to reuse previous shaping results for efficiency. It also handles special cases like list markers.

11. **First-Line Shaping:** The `ShapeTextForFirstLineIfNeeded` function handles the special styling applied to the first line of a text block using the `:first-line` CSS pseudo-element. It reshapes the text if the first-line style differs from the normal style.

**Connecting to Javascript, HTML, and CSS:**

* **HTML:** The structure of the HTML document determines the layout tree that `CollectInlines` traverses. Different HTML tags (like `<span>`, `<a>`, `<svg:text>`) will result in different types of `InlineItem` objects.
* **CSS:** CSS properties like `font-family`, `font-size`, `font-style`, `direction`, `unicode-bidi`, `text-transform`, and `text-orientation` directly influence the behavior of the segmentation and shaping functions. For example, the `direction` and `unicode-bidi` properties control the `SegmentBidiRuns` function. `text-orientation` affects `SegmentFontOrientation`. Font properties are used in `ShapeText`. The `:first-line` CSS pseudo-element triggers `ShapeTextForFirstLineIfNeeded`.
* **Javascript:** While this code doesn't directly execute Javascript, Javascript can manipulate the DOM (adding, removing, or modifying elements and text), which will eventually trigger layout recalculations and the execution of functions in this file. Javascript can also interact with the rendering through APIs like the Canvas API, which might involve similar text shaping logic.

**Logical Reasoning with Assumptions:**

* **Assumption:** When `SetTextWithOffset` is called with a small change within a larger text block.
* **Input:** `layout_text` with existing `InlineItem` data, `new_text` with a minor modification, `diff` object indicating the change range.
* **Output:** The `InlineItem` list in `layout_text` will be updated efficiently, potentially reusing the shape results for the unchanged parts of the text.

* **Assumption:**  A text node contains a word with a ligature (e.g., "fi").
* **Input:**  The text "office", the font supports the "fi" ligature.
* **Output of `ShapeText`:** The `InlineItem` corresponding to "office" will have a `ShapeResult` where the glyphs for "f" and "i" are combined into a single ligature glyph. The `GetFirstSafeToReuse` and `GetLastSafeToReuse` functions will avoid splitting the `InlineItem` in the middle of the ligature.

**Common Usage Errors:**

* **Modifying Text Without Invalidation:**  If Javascript directly modifies the text content of a DOM node without triggering a layout recalculation, the `InlineItem` data might become out of sync with the actual text, leading to rendering errors. The `SetTextWithOffset` function aims to prevent this by updating the `InlineItem` data when text changes are made.
* **Incorrectly Setting CSS Properties:** Setting conflicting or invalid CSS properties related to text (e.g., invalid `direction` or `unicode-bidi` values) can lead to unexpected behavior in the bidirectional text segmentation and rendering.

**Summary of Functionality in This Part:**

This part of `inline_node.cc` focuses on the **efficient management and manipulation of inline text data (`InlineItem`) when the text content of a layout object changes**. It provides mechanisms for:

* **Splitting and copying `InlineItem` objects** while respecting rendering dependencies (like ligatures and complex script joining).
* **Updating `InlineItem` data** when text is modified, attempting to reuse existing information to optimize performance.
* **Calculating mappings between original and transformed text**.
* **Collecting and structuring inline content** into `InlineItem` objects.
* **Segmenting text** into meaningful units for bidirectional rendering, script processing, and font orientation.
* **Shaping text into glyphs**, taking into account font properties and attempting to reuse previous shaping results.
* **Handling special styling for the first line of text**.

这是 `blink/renderer/core/layout/inline/inline_node.cc` 源代码文件的第 2 部分，主要功能是继续处理和优化内联文本的布局和渲染过程。 在此部分，重点在于对 `InlineItem` 进行更细致的操作和优化，以及处理文本内容的修改和分段。

**主要功能归纳：**

1. **`InlineItem` 的精细操作：**
   - 提供了 `CopyItemAfter` 和 `CopyItemBefore` 函数，用于创建 `InlineItem` 的子部分副本。这两个函数特别注意处理复杂文本，例如阿拉伯语连接和字距调整，避免重用可能导致错误渲染的字形。
   - 提供了 `GetFirstSafeToReuse` 和 `GetLastSafeToReuse` 函数，用于确定 `InlineItem` 中可以安全重用的字符范围，这对于文本修改和分段时的性能优化至关重要。这些函数考虑了 OpenType 字体特性，例如 `usMaxContext`，以避免在可能影响字形组合的情况下进行拆分。
   - 提供了 `ShiftItem` 函数，用于调整 `InlineItem` 的起始和结束偏移量，常用于文本插入或删除后更新 `InlineItem` 的位置信息。
   - 提供了 `VerifyItems` 函数（仅在 DCHECK 编译模式下启用），用于验证 `InlineItem` 列表的完整性和一致性，确保 `InlineItem` 的起始和结束偏移量正确，并且与 `ShapeResult` 的信息匹配。

2. **文本修改和 `InlineItem` 的更新：**
   - 提供了 `SetTextWithOffset` 函数，用于在文本内容发生部分修改时，高效地更新 `LayoutText` 对象的 `InlineItem`。该函数尝试重用之前计算的 `InlineItem` 和 `ShapeResult`，避免完全重新计算，提升性能。这个过程涉及到文本转换、偏移量映射和文本分段等多个步骤。

3. **惰性初始化和偏移量映射：**
   - 提供了 `EnsureData` 函数，用于延迟创建 `InlineNodeData` 对象，只有在需要时才进行初始化。
   - 提供了 `ComputeOffsetMappingIfNeeded` 和 `ComputeOffsetMapping` 函数，用于计算文本内容和其在 DOM 树中的偏移量之间的映射关系。这对于处理文本转换（例如 CSS 中的 `text-transform`）非常重要。对于 SVG 文本，还会考虑 `SvgTextChunkOffsets`。

4. **内联元素的收集和处理：**
   - 提供了 `CollectInlines` 函数，用于遍历布局树，收集所有的内联元素和文本节点，并将它们组合成一个单一的文本字符串，并创建相应的 `InlineItem` 对象。该函数还会处理 SVG 文本的特殊情况，例如查找 SVG 文本块。
   - 提供了 `FindSvgTextChunks` 函数，用于在 SVG 文本中查找独立的文本块，这对于 SVG 文本的布局和渲染至关重要。

5. **文本分段（Segmentation）：**
   - 提供了 `SegmentText` 函数，作为文本分段的入口，它会调用其他分段函数。
   - 提供了 `SegmentBidiRuns` 函数，用于根据 Unicode 双向算法 (Bidi) 对文本进行分段，确定文本的书写方向（从左到右或从右到左）。
   - 提供了 `SegmentScriptRuns` 函数，用于根据文本的脚本（例如拉丁文、中文、阿拉伯文）对文本进行分段。这对于应用正确的字体和排版规则至关重要。
   - 提供了 `SegmentFontOrientation` 函数，用于根据文本的 `text-orientation` CSS 属性对文本进行分段，主要用于垂直书写模式。

6. **文本塑形 (Shaping)：**
   - 提供了 `ShapeText` 函数，这是文本渲染的关键步骤。它使用文本塑形器 (Text Shaper) 将文本内容转换为可渲染的字形 (Glyph)。该函数会考虑字体、样式、文本方向等因素，并尝试重用之前的塑形结果以提高性能。它还会处理列表标记等特殊情况。
   - 提供了 `IsNGShapeCacheAllowed` 函数，用于判断是否可以使用 LayoutNG 的形状缓存，以进一步优化文本塑形性能。

7. **首行文本的特殊处理：**
   - 提供了 `ShapeTextForFirstLineIfNeeded` 函数，用于处理 CSS 中 `:first-line` 伪类的样式。如果首行样式与普通样式不同，该函数会重新塑形首行文本。

**与 Javascript, HTML, CSS 的关系举例说明：**

* **HTML:** HTML 的结构决定了 `CollectInlines` 函数遍历的节点类型和顺序。例如，`<span>` 标签会创建一个新的 `InlineItem`，而文本节点也会被转换为 `InlineItem`。
* **CSS:** CSS 的样式属性直接影响文本的分段和塑形。
    * `direction` 和 `unicode-bidi` 属性会影响 `SegmentBidiRuns` 函数的执行，决定文本的书写方向。
    * `font-family`, `font-size`, `font-style` 等字体属性会传递给文本塑形器，影响字形的生成。
    * `text-transform` 属性会在 `SetTextWithOffset` 和 `ShapeTextForFirstLineIfNeeded` 中被考虑，可能需要进行文本转换和重新塑形。
    * `text-orientation` 属性会影响 `SegmentFontOrientation` 函数，特别是在垂直书写模式下。
    * `:first-line` 伪类会触发 `ShapeTextForFirstLineIfNeeded` 函数，对首行文本进行特殊处理。
* **Javascript:** Javascript 可以通过 DOM 操作修改 HTML 结构和文本内容。当文本内容发生变化时，例如通过 `textContent` 或 `innerHTML` 修改，Blink 引擎会调用相关的布局和渲染流程，其中就包括 `SetTextWithOffset` 等函数来更新 `InlineItem` 数据并重新塑形文本。

**逻辑推理的假设输入与输出举例：**

假设有以下 HTML 片段：

```html
<p id="myPara">Hello World</p>
```

并且通过 Javascript 修改了文本内容：

```javascript
document.getElementById('myPara').textContent = 'Hi World';
```

* **假设输入：**
    * 原始 `LayoutText` 对象包含 "Hello World" 的 `InlineItem` 和 `ShapeResult`。
    * `new_text` 为 "Hi World"。
    * `diff` 对象指示从偏移量 0 开始，删除 "ello"，插入 "Hi"。
* **输出（`SetTextWithOffset` 函数）：**
    * 创建新的 `InlineItem` 对象，可能重用 "World" 部分的 `ShapeResult`。
    * 更新 `LayoutText` 对象的内部文本为 "Hi World"。
    * 重新塑形 "Hi" 部分的文本。

**涉及用户或编程常见的使用错误举例：**

* **未触发布局更新的文本修改：** 如果开发者直接修改了底层的文本数据，而没有通知 Blink 引擎进行布局更新，那么 `InlineItem` 和渲染结果可能会与实际文本内容不一致，导致显示错误。Blink 引擎通常会监听 DOM 的变化来触发布局更新，但某些非常规的操作可能会绕过这个机制。
* **错误地设置 CSS 属性导致文本渲染异常：** 例如，将 `direction` 设置为 `rtl`，但没有正确处理双向文本中的嵌入级别，可能导致文本显示顺序混乱。或者，设置了不支持的 `font-family`，导致回退字体显示效果不佳。

**本部分功能的归纳：**

此部分 `inline_node.cc` 的核心功能是 **在文本内容发生变化时，高效地维护和更新内联文本的布局信息 (主要是 `InlineItem`)，并对文本进行精细的分段和塑形，以确保正确的渲染结果并优化性能**。它处理了文本修改、偏移量映射、内联元素的收集、文本分段以及最终的文本塑形等关键步骤，并且特别关注了复杂文本的处理和性能优化策略。

Prompt: 
```
这是目录为blink/renderer/core/layout/inline/inline_node.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
. inserting "A" before "V", and joining in Arabic,
    // we should not reuse first glyph.
    // See http://crbug.com/1199331
    DCHECK_LT(safe_start_offset, item.end_offset_);
    return InlineItem(
        item, safe_start_offset, end_offset,
        item.shape_result_->SubRange(safe_start_offset, end_offset));
  }

  // Returns copy of |item| before |end_offset| (exclusive).
  InlineItem CopyItemBefore(const InlineItem& item, unsigned end_offset) const {
    DCHECK_LT(item.start_offset_, end_offset);
    DCHECK_LE(end_offset, item.end_offset_);
    const unsigned safe_end_offset = GetLastSafeToReuse(item, end_offset);
    const unsigned start_offset = item.start_offset_;
    // Nothing to reuse if no characters are safe to reuse.
    if (safe_end_offset <= start_offset)
      return InlineItem(item, start_offset, end_offset, nullptr);
    // To handle kerning, e.g. "AV", we should not reuse last glyph.
    // See http://crbug.com/1129710
    DCHECK_LT(safe_end_offset, item.end_offset_);
    return InlineItem(
        item, start_offset, safe_end_offset,
        item.shape_result_->SubRange(start_offset, safe_end_offset));
  }

  // See also |GetLastSafeToReuse()|.
  unsigned GetFirstSafeToReuse(const InlineItem& item,
                               unsigned start_offset) const {
    DCHECK_LE(item.start_offset_, start_offset);
    DCHECK_LE(start_offset, item.end_offset_);
    const unsigned end_offset = item.end_offset_;
    // TODO(yosin): It is better to utilize OpenType |usMaxContext|.
    // For font having "fi", |usMaxContext = 2".
    const unsigned max_context = 2;
    const unsigned skip = max_context - 1;
    if (!item.shape_result_ || item.shape_result_->IsAppliedSpacing() ||
        start_offset + skip >= end_offset)
      return end_offset;
    item.shape_result_->EnsurePositionData();
    // Note: Because |CachedNextSafeToBreakOffset()| assumes |start_offset|
    // is always safe to break offset, we try to search after |start_offset|.
    return item.shape_result_->CachedNextSafeToBreakOffset(start_offset + skip);
  }

  // See also |GetFirstSafeToReuse()|.
  unsigned GetLastSafeToReuse(const InlineItem& item,
                              unsigned end_offset) const {
    DCHECK_LT(item.start_offset_, end_offset);
    DCHECK_LE(end_offset, item.end_offset_);
    const unsigned start_offset = item.start_offset_;
    // TODO(yosin): It is better to utilize OpenType |usMaxContext|.
    // For font having "fi", usMaxContext = 2.
    // For Emoji with ZWJ, usMaxContext = 10. (http://crbug.com/1213235)
    const unsigned max_context = data_->text_content.Is8Bit() ? 2 : 10;
    const unsigned skip = max_context - 1;
    if (!item.shape_result_ || item.shape_result_->IsAppliedSpacing() ||
        end_offset <= start_offset + skip)
      return start_offset;
    item.shape_result_->EnsurePositionData();
    // TODO(yosin): It is better to utilize OpenType |usMaxContext|.
    // Note: Because |CachedPreviousSafeToBreakOffset()| assumes |end_offset|
    // is always safe to break offset, we try to search before |end_offset|.
    return item.shape_result_->CachedPreviousSafeToBreakOffset(end_offset -
                                                               skip);
  }

  static void ShiftItem(InlineItem* item, int delta) {
    if (delta == 0)
      return;
    item->start_offset_ = AdjustOffset(item->start_offset_, delta);
    item->end_offset_ = AdjustOffset(item->end_offset_, delta);
    if (!item->shape_result_)
      return;
    item->shape_result_ =
        item->shape_result_->CopyAdjustedOffset(item->start_offset_);
  }

  void VerifyItems(const HeapVector<InlineItem>& items) const {
#if DCHECK_IS_ON()
    if (items.empty())
      return;
    unsigned last_offset = items.front().start_offset_;
    for (const InlineItem& item : items) {
      DCHECK_LE(item.start_offset_, item.end_offset_);
      DCHECK_EQ(last_offset, item.start_offset_);
      last_offset = item.end_offset_;
      if (!item.shape_result_)
        continue;
      DCHECK_LT(item.start_offset_, item.end_offset_);
      DCHECK_EQ(item.shape_result_->StartIndex(), item.start_offset_);
      DCHECK_EQ(item.shape_result_->EndIndex(), item.end_offset_);
    }
    DCHECK_EQ(last_offset,
              block_flow_->GetInlineNodeData()->text_content.length());
#endif
  }

  InlineNodeData* data_ = nullptr;
  LayoutBlockFlow* const block_flow_;
  const LayoutText& layout_text_;
};

// static
bool InlineNode::SetTextWithOffset(LayoutText* layout_text,
                                   String new_text,
                                   const TextDiffRange& diff) {
  if (!layout_text->HasValidInlineItems() ||
      !layout_text->IsInLayoutNGInlineFormattingContext())
    return false;
  const String old_text = layout_text->TransformedText();
  if (diff.offset == 0 && diff.old_size == old_text.length()) {
    // We'll run collect inline items since whole text of |layout_text| is
    // changed.
    return false;
  }

  InlineNodeDataEditor editor(*layout_text);
  InlineNodeData* const previous_data = editor.Prepare();
  if (!previous_data)
    return false;

  // This function runs outside of the layout phase. Prevent purging font cache
  // while shaping.
  FontCachePurgePreventer font_cache_purge_preventer;

  TextOffsetMap offset_map;
  new_text = layout_text->TransformAndSecureText(new_text, offset_map);
  if (!offset_map.IsEmpty()) {
    return false;
  }
  layout_text->SetTextInternal(new_text);
  layout_text->ClearHasNoControlItems();
  layout_text->ClearHasVariableLengthTransform();

  InlineNode node(editor.GetLayoutBlockFlow());
  InlineNodeData* data = node.MutableData();
  data->items.reserve(previous_data->items.size());
  InlineItemsBuilder builder(
      editor.GetLayoutBlockFlow(), &data->items,
      previous_data ? previous_data->text_content : String());
  // TODO(yosin): We should reuse before/after |layout_text| during collecting
  // inline items.
  layout_text->ClearInlineItems();
  CollectInlinesInternal(&builder, previous_data);
  builder.DidFinishCollectInlines(data);
  // Relocates |ShapeResult| in |previous_data| after |offset|+|length|
  editor.Run();
  node.SegmentText(data, nullptr);
  node.ShapeTextIncludingFirstLine(data, &previous_data->text_content,
                                   &previous_data->items);
  node.AssociateItemsWithInlines(data);
  return true;
}

const InlineNodeData& InlineNode::EnsureData() const {
  PrepareLayoutIfNeeded();
  return Data();
}

const OffsetMapping* InlineNode::ComputeOffsetMappingIfNeeded() const {
#if DCHECK_IS_ON()
  DCHECK(!GetLayoutBlockFlow()->GetDocument().NeedsLayoutTreeUpdate() ||
         GetLayoutBlockFlow()->IsInDetachedNonDomTree());
#endif

  InlineNodeData* data = MutableData();
  if (!data->offset_mapping) {
    DCHECK(!data->text_content.IsNull());
    ComputeOffsetMapping(GetLayoutBlockFlow(), data);
  }

  return data->offset_mapping.Get();
}

void InlineNode::ComputeOffsetMapping(LayoutBlockFlow* layout_block_flow,
                                      InlineNodeData* data) {
#if DCHECK_IS_ON()
  DCHECK(!data->offset_mapping);
  DCHECK(!layout_block_flow->GetDocument().NeedsLayoutTreeUpdate() ||
         layout_block_flow->IsInDetachedNonDomTree());
#endif

  const SvgTextChunkOffsets* chunk_offsets = nullptr;
  if (data->svg_node_data_ && data->svg_node_data_->chunk_offsets.size() > 0)
    chunk_offsets = &data->svg_node_data_->chunk_offsets;

  // TODO(xiaochengh): ComputeOffsetMappingIfNeeded() discards the
  // InlineItems and text content built by |builder|, because they are
  // already there in InlineNodeData. For efficiency, we should make
  // |builder| not construct items and text content.
  HeapVector<InlineItem> items;
  ClearCollectionScope<HeapVector<InlineItem>> clear_scope(&items);
  items.reserve(EstimateInlineItemsCount(*layout_block_flow));
  InlineItemsBuilderForOffsetMapping builder(layout_block_flow, &items,
                                             data->text_content, chunk_offsets);
  builder.GetOffsetMappingBuilder().ReserveCapacity(
      EstimateOffsetMappingItemsCount(*layout_block_flow));
  CollectInlinesInternal(&builder, nullptr);

  // For non-NG object, we need the text, and also the inline items to resolve
  // bidi levels. Otherwise |data| already has the text from the pre-layout
  // phase, check they match.
  if (data->text_content.IsNull()) {
    DCHECK(!layout_block_flow->IsLayoutNGObject());
    data->text_content = builder.ToString();
  } else {
    DCHECK(layout_block_flow->IsLayoutNGObject());
  }

  // TODO(xiaochengh): This doesn't compute offset mapping correctly when
  // text-transform CSS property changes text length.
  OffsetMappingBuilder& mapping_builder = builder.GetOffsetMappingBuilder();
  data->offset_mapping = nullptr;
  if (mapping_builder.SetDestinationString(data->text_content)) {
    data->offset_mapping = mapping_builder.Build();
    DCHECK(data->offset_mapping);
  }
}

const OffsetMapping* InlineNode::GetOffsetMapping(
    LayoutBlockFlow* layout_block_flow) {
  DCHECK(!layout_block_flow->GetDocument().NeedsLayoutTreeUpdate());

  if (layout_block_flow->NeedsLayout()) [[unlikely]] {
    // TODO(kojii): This shouldn't happen, but is not easy to fix all cases.
    // Return nullptr so that callers can chose to fail gracefully, or
    // null-deref. crbug.com/946004
    return nullptr;
  }

  InlineNode node(layout_block_flow);
  CHECK(node.IsPrepareLayoutFinished());
  return node.ComputeOffsetMappingIfNeeded();
}

// Depth-first-scan of all LayoutInline and LayoutText nodes that make up this
// InlineNode object. Collects LayoutText items, merging them up into the
// parent LayoutInline where possible, and joining all text content in a single
// string to allow bidi resolution and shaping of the entire block.
void InlineNode::CollectInlines(InlineNodeData* data,
                                InlineNodeData* previous_data) const {
  DCHECK(data->text_content.IsNull());
  DCHECK(data->items.empty());
  LayoutBlockFlow* block = GetLayoutBlockFlow();
  block->WillCollectInlines();

  const SvgTextChunkOffsets* chunk_offsets = nullptr;
  if (block->IsSVGText()) {
    // SVG <text> doesn't support reusing the previous result now.
    previous_data = nullptr;
    data->svg_node_data_ = nullptr;
    // We don't need to find text chunks if the IFC has only 0-1 character
    // because of no Bidi reordering and no ligatures.
    // This is an optimization for perf_tests/svg/France.html.
    const auto* layout_text = DynamicTo<LayoutText>(block->FirstChild());
    bool empty_or_one_char =
        !block->FirstChild() || (layout_text && !layout_text->NextSibling() &&
                                 layout_text->TransformedTextLength() <= 1);
    if (!empty_or_one_char)
      chunk_offsets = FindSvgTextChunks(*block, *data);
  }

  data->items.reserve(EstimateInlineItemsCount(*block));
  InlineItemsBuilder builder(
      block, &data->items,
      previous_data ? previous_data->text_content : String(), chunk_offsets);
  CollectInlinesInternal(&builder, previous_data);
  if (block->IsSVGText() && !data->svg_node_data_) {
    SvgTextLayoutAttributesBuilder svg_attr_builder(*this);
    svg_attr_builder.Build(builder.ToString(), data->items);
    data->svg_node_data_ = svg_attr_builder.CreateSvgInlineNodeData();
  }
  builder.DidFinishCollectInlines(data);

  if (builder.HasUnicodeBidiPlainText()) [[unlikely]] {
    UseCounter::Count(GetDocument(), WebFeature::kUnicodeBidiPlainText);
  }
}

const SvgTextChunkOffsets* InlineNode::FindSvgTextChunks(
    LayoutBlockFlow& block,
    InlineNodeData& data) const {
  TRACE_EVENT0("blink", "InlineNode::FindSvgTextChunks");
  // Build InlineItems and OffsetMapping first.  They are used only by
  // SVGTextLayoutAttributesBuilder, and are discarded because they might
  // be different from final ones.
  HeapVector<InlineItem> items;
  ClearCollectionScope<HeapVector<InlineItem>> clear_scope(&items);
  items.reserve(EstimateInlineItemsCount(block));
  InlineItemsBuilderForOffsetMapping items_builder(&block, &items);
  OffsetMappingBuilder& mapping_builder =
      items_builder.GetOffsetMappingBuilder();
  mapping_builder.ReserveCapacity(EstimateOffsetMappingItemsCount(block));
  CollectInlinesInternal(&items_builder, nullptr);
  String ifc_text_content = items_builder.ToString();

  SvgTextLayoutAttributesBuilder svg_attr_builder(*this);
  svg_attr_builder.Build(ifc_text_content, items);
  data.svg_node_data_ = svg_attr_builder.CreateSvgInlineNodeData();

  // Compute DOM offsets of text chunks.
  CHECK(mapping_builder.SetDestinationString(ifc_text_content));
  OffsetMapping* mapping = mapping_builder.Build();
  StringView ifc_text_view(ifc_text_content);
  for (wtf_size_t i = 0; i < data.svg_node_data_->character_data_list.size();
       ++i) {
    const std::pair<unsigned, SvgCharacterData>& char_data =
        data.svg_node_data_->character_data_list[i];
    if (!char_data.second.anchored_chunk)
      continue;
    unsigned addressable_offset = char_data.first;
    if (addressable_offset == 0u)
      continue;
    unsigned text_content_offset = svg_attr_builder.IfcTextContentOffsetAt(i);
    const auto* unit = mapping->GetLastMappingUnit(text_content_offset);
    DCHECK(unit);
    auto result = data.svg_node_data_->chunk_offsets.insert(
        To<LayoutText>(&unit->GetLayoutObject()), Vector<unsigned>());
    result.stored_value->value.push_back(
        unit->ConvertTextContentToFirstDOMOffset(text_content_offset));
  }
  return data.svg_node_data_->chunk_offsets.size() > 0
             ? &data.svg_node_data_->chunk_offsets
             : nullptr;
}

void InlineNode::SegmentText(InlineNodeData* data,
                             InlineNodeData* previous_data) const {
  SegmentBidiRuns(data);
  SegmentScriptRuns(data, previous_data);
  SegmentFontOrientation(data);
  if (data->segments)
    data->segments->ComputeItemIndex(data->items);
}

// Segment InlineItem by script, Emoji, and orientation using RunSegmenter.
void InlineNode::SegmentScriptRuns(InlineNodeData* data,
                                   InlineNodeData* previous_data) const {
  String& text_content = data->text_content;
  if (text_content.empty()) {
    data->segments = nullptr;
    return;
  }

  if (previous_data && text_content == previous_data->text_content) {
    if (!previous_data->segments) {
      const auto it = base::ranges::find_if(
          previous_data->items,
          [](const auto& item) { return item.Type() == InlineItem::kText; });
      if (it != previous_data->items.end()) {
        unsigned previous_packed_segment = it->segment_data_;
        for (auto& item : data->items) {
          if (item.Type() == InlineItem::kText) {
            item.segment_data_ = previous_packed_segment;
          }
        }
        data->segments = nullptr;
        return;
      }
    } else if (IsHorizontalTypographicMode()) {
      // We can reuse InlineNodeData::segments only in horizontal writing modes
      // because we might update it by SegmentFontOrientation() in vertical
      // writing modes.
      data->segments = std::move(previous_data->segments);
      return;
    }
  }

  if ((text_content.Is8Bit() || !data->HasNonOrc16BitCharacters()) &&
      !data->is_bidi_enabled_) {
    if (data->items.size()) {
      RunSegmenter::RunSegmenterRange range = {
          0u, data->text_content.length(), USCRIPT_LATIN,
          OrientationIterator::kOrientationKeep, FontFallbackPriority::kText};
      InlineItem::SetSegmentData(range, &data->items);
    }
    data->segments = nullptr;
    return;
  }

  // Segment by script and Emoji.
  // Orientation is segmented separately, because it may vary by items.
  text_content.Ensure16Bit();
  RunSegmenter segmenter(text_content.Span16(), FontOrientation::kHorizontal);

  RunSegmenter::RunSegmenterRange range;
  bool consumed = segmenter.Consume(&range);
  DCHECK(consumed);
  if (range.end == text_content.length()) {
    InlineItem::SetSegmentData(range, &data->items);
    data->segments = nullptr;
    return;
  }

  // This node has multiple segments.
  if (!data->segments)
    data->segments = std::make_unique<InlineItemSegments>();
  data->segments->ComputeSegments(&segmenter, &range);
  DCHECK_EQ(range.end, text_content.length());
}

void InlineNode::SegmentFontOrientation(InlineNodeData* data) const {
  // Segment by orientation, only if vertical writing mode and items with
  // 'text-orientation: mixed'.
  if (IsHorizontalTypographicMode()) {
    return;
  }

  HeapVector<InlineItem>& items = data->items;
  if (items.empty())
    return;
  String& text_content = data->text_content;
  text_content.Ensure16Bit();

  // If we don't have |InlineItemSegments| yet, create a segment for the
  // entire content.
  const unsigned capacity = items.size() + text_content.length() / 10;
  InlineItemSegments* segments = data->segments.get();
  if (segments) {
    DCHECK(!data->segments->IsEmpty());
    data->segments->ReserveCapacity(capacity);
    DCHECK_EQ(text_content.length(), data->segments->EndOffset());
  }
  unsigned segment_index = 0;

  for (const InlineItem& item : items) {
    if (item.Type() == InlineItem::kText && item.Length() &&
        item.Style()->GetFont().GetFontDescription().Orientation() ==
            FontOrientation::kVerticalMixed) {
      if (!segments) {
        data->segments = std::make_unique<InlineItemSegments>();
        segments = data->segments.get();
        segments->ReserveCapacity(capacity);
        segments->Append(text_content.length(), item);
        DCHECK_EQ(text_content.length(), data->segments->EndOffset());
      }
      segment_index = segments->AppendMixedFontOrientation(
          text_content, item.StartOffset(), item.EndOffset(), segment_index);
    }
  }
}

// Segment bidi runs by resolving bidi embedding levels.
// http://unicode.org/reports/tr9/#Resolving_Embedding_Levels
void InlineNode::SegmentBidiRuns(InlineNodeData* data) const {
  if (!data->is_bidi_enabled_) {
    data->SetBaseDirection(TextDirection::kLtr);
    return;
  }

  BidiParagraph bidi;
  data->text_content.Ensure16Bit();
  if (!SetParagraphTo(data->text_content, Style(), bidi)) {
    // On failure, give up bidi resolving and reordering.
    data->is_bidi_enabled_ = false;
    data->SetBaseDirection(TextDirection::kLtr);
    return;
  }

  data->SetBaseDirection(bidi.BaseDirection());

  if (bidi.IsUnidirectional() && IsLtr(bidi.BaseDirection())) {
    // All runs are LTR, no need to reorder.
    data->is_bidi_enabled_ = false;
    return;
  }

  HeapVector<InlineItem>& items = data->items;
  unsigned item_index = 0;
  for (unsigned start = 0; start < data->text_content.length();) {
    UBiDiLevel level;
    unsigned end = bidi.GetLogicalRun(start, &level);
    DCHECK_EQ(items[item_index].start_offset_, start);
    item_index = InlineItem::SetBidiLevel(items, item_index, end, level);
    start = end;
  }
#if DCHECK_IS_ON()
  // Check all items have bidi levels, except trailing non-length items.
  // Items that do not create break opportunities such as kOutOfFlowPositioned
  // do not have corresponding characters, and that they do not have bidi level
  // assigned.
  while (item_index < items.size() && !items[item_index].Length())
    item_index++;
  DCHECK_EQ(item_index, items.size());
#endif
}

bool InlineNode::IsNGShapeCacheAllowed(
    const String& text_content,
    const Font* override_font,
    const HeapVector<InlineItem>& items,
    ShapeResultSpacing<String>& spacing) const {
  if (!RuntimeEnabledFeatures::LayoutNGShapeCacheEnabled()) {
    return false;
  }
  // For consistency with similar usages of ShapeCache (e.g. canvas) and in
  // order to avoid caching bugs (e.g. with scripts having Arabic joining)
  // NGShapeCache is only enabled when the IFC is made of a single text item. To
  // be efficient, NGShapeCache only stores entries for short strings and
  // without memory copy, so don't allow it if the text item is too long or if
  // the start/end offsets match a substring. Don't allow it either if a call to
  // ApplySpacing is needed to avoid a costly copy of the ShapeResult in the
  // loop below. Finally, check that the font meet requirements on the font
  // family list to avoid expensive hash key calculations.
  if (items.size() != 1) {
    return false;
  }
  if (text_content.length() > NGShapeCache::kMaxTextLengthOfEntries) {
    return false;
  }
  const InlineItem& single_item = items[0];
  if (!(single_item.Type() == InlineItem::kText &&
        single_item.StartOffset() == 0 &&
        single_item.EndOffset() == text_content.length())) {
    return false;
  }
  const Font& font =
      override_font ? *override_font : single_item.FontWithSvgScaling();
  return !spacing.SetSpacing(font.GetFontDescription());
}

void InlineNode::ShapeText(InlineItemsData* data,
                           const String* previous_text,
                           const HeapVector<InlineItem>* previous_items,
                           const Font* override_font) const {
  TRACE_EVENT0("fonts", "InlineNode::ShapeText");
  base::ScopedClosureRunner scoped_closure_runner(WTF::BindOnce(
      [](base::ElapsedTimer timer, Document* document) {
        if (document) {
          document->MaybeRecordShapeTextElapsedTime(timer.Elapsed());
        }
      },
      base::ElapsedTimer(),
      WrapWeakPersistent(GetLayoutBox() ? &GetLayoutBox()->GetDocument()
                                        : nullptr)));

  const String& text_content = data->text_content;
  HeapVector<InlineItem>* items = &data->items;

  ShapeResultSpacing<String> spacing(text_content, IsSvgText());
  InlineTextAutoSpace auto_space(*data);

  const bool allow_shape_cache =
      IsNGShapeCacheAllowed(text_content, override_font, *items, spacing) &&
      !auto_space.MayApply();

  // Provide full context of the entire node to the shaper.
  ReusingTextShaper shaper(data, previous_items, allow_shape_cache);
  bool is_next_start_of_paragraph = true;

  DCHECK(!data->segments ||
         data->segments->EndOffset() == text_content.length());

  for (unsigned index = 0; index < items->size();) {
    InlineItem& start_item = (*items)[index];
    if (start_item.Type() != InlineItem::kText || !start_item.Length()) {
      index++;
      is_next_start_of_paragraph = start_item.IsForcedLineBreak();
      continue;
    }

    const ComputedStyle& start_style = *start_item.Style();
    const Font& font =
        override_font ? *override_font : start_item.FontWithSvgScaling();
#if DCHECK_IS_ON()
    if (!IsTextCombine()) {
      DCHECK(!override_font);
    } else {
      DCHECK_EQ(font.GetFontDescription().Orientation(),
                FontOrientation::kHorizontal);
      LayoutTextCombine::AssertStyleIsValid(start_style);
      DCHECK(!override_font ||
             font.GetFontDescription().WidthVariant() != kRegularWidth);
    }
#endif
    shaper.SetOptions({
        .is_line_start = is_next_start_of_paragraph,
        .han_kerning_start =
            is_next_start_of_paragraph &&
            ShouldTrimStartOfParagraph(
                font.GetFontDescription().GetTextSpacingTrim()) &&
            Character::MaybeHanKerningOpen(
                text_content[start_item.StartOffset()]),
    });
    is_next_start_of_paragraph = false;
    TextDirection direction = start_item.Direction();
    unsigned end_index = index + 1;
    unsigned end_offset = start_item.EndOffset();

    // Symbol marker is painted as graphics. Create a ShapeResult of space
    // glyphs with the desired size to make it less special for line breaker.
    if (start_item.IsSymbolMarker()) [[unlikely]] {
      LayoutUnit symbol_width = ListMarker::WidthOfSymbol(
          start_style,
          LayoutCounter::ListStyle(start_item.GetLayoutObject(), start_style));
      DCHECK_GE(symbol_width, 0);
      start_item.shape_result_ = ShapeResult::CreateForSpaces(
          &font, direction, start_item.StartOffset(), start_item.Length(),
          symbol_width);
      index++;
      continue;
    }

    // Scan forward until an item is encountered that should trigger a shaping
    // break. This ensures that adjacent text items are shaped together whenever
    // possible as this is required for accurate cross-element shaping.
    unsigned num_text_items = 1;
    for (; end_index < items->size(); end_index++) {
      const InlineItem& item = (*items)[end_index];

      if (item.Type() == InlineItem::kControl) {
        // Do not shape across control characters (line breaks, zero width
        // spaces, etc).
        break;
      }
      if (item.Type() == InlineItem::kText) {
        if (!item.Length())
          continue;
        if (item.TextType() == TextItemType::kSymbolMarker) {
          break;
        }
        if (ShouldBreakShapingBeforeText(item, start_item, start_style, font,
                                         direction)) {
          break;
        }
        // Break shaping at ZWNJ so that it prevents kerning. ZWNJ is always at
        // the beginning of an item for this purpose; see InlineItemsBuilder.
        if (text_content[item.StartOffset()] == kZeroWidthNonJoinerCharacter)
          break;
        end_offset = item.EndOffset();
        num_text_items++;
      } else if (item.Type() == InlineItem::kOpenTag) {
        if (ShouldBreakShapingBeforeBox(item))
          break;
        // Should not have any characters to be opaque to shaping.
        DCHECK_EQ(0u, item.Length());
      } else if (item.Type() == InlineItem::kCloseTag) {
        if (ShouldBreakShapingAfterBox(item))
          break;
        // Should not have any characters to be opaque to shaping.
        DCHECK_EQ(0u, item.Length());
      } else {
        break;
      }
    }

    // Shaping a single item. Skip if the existing results remain valid.
    if (previous_text && end_offset == start_item.EndOffset() &&
        !NeedsShaping(start_item)) {
      if (!IsTextCombine()) [[likely]] {
        DCHECK_EQ(start_item.StartOffset(),
                  start_item.TextShapeResult()->StartIndex());
        DCHECK_EQ(start_item.EndOffset(),
                  start_item.TextShapeResult()->EndIndex());
        index++;
        continue;
      }
    }

    // Results may only be reused if all items in the range remain valid.
    if (previous_text) {
      bool has_valid_shape_results = true;
      for (unsigned item_index = index; item_index < end_index; item_index++) {
        if (NeedsShaping((*items)[item_index])) {
          has_valid_shape_results = false;
          break;
        }
      }

      // When shaping across multiple items checking whether the individual
      // items has valid shape results isn't sufficient as items may have been
      // re-ordered or removed.
      // TODO(layout-dev): It would probably be faster to check for removed or
      // moved items but for now comparing the string itself will do.
      unsigned text_start = start_item.StartOffset();
      DCHECK_GE(end_offset, text_start);
      unsigned text_length = end_offset - text_start;
      if (has_valid_shape_results && previous_text &&
          end_offset <= previous_text->length() &&
          StringView(text_content, text_start, text_length) ==
              StringView(*previous_text, text_start, text_length)) {
        index = end_index;
        continue;
      }
    }

    // Shape each item with the full context of the entire node.
    const ShapeResult* shape_result =
        shaper.Shape(start_item, font, end_offset);

    if (spacing.SetSpacing(font.GetFontDescription())) [[unlikely]] {
      DCHECK(!IsTextCombine()) << GetLayoutBlockFlow();
      DCHECK(!allow_shape_cache);
      // The ShapeResult is actually not a reusable entry of NGShapeCache,
      // so it is safe to mutate it.
      const_cast<ShapeResult*>(shape_result)->ApplySpacing(spacing);
    }

    // If the text is from one item, use the ShapeResult as is.
    if (end_offset == start_item.EndOffset()) {
      start_item.shape_result_ = shape_result;
      DCHECK_EQ(start_item.TextShapeResult()->StartIndex(),
                start_item.StartOffset());
      DCHECK_EQ(start_item.TextShapeResult()->EndIndex(),
                start_item.EndOffset());
      index++;
      continue;
    }

    // If the text is from multiple items, split the ShapeResult to
    // corresponding items.
    DCHECK_GT(num_text_items, 0u);
    // "32" is heuristic, most major sites are up to 8 or so, wikipedia is 21.
    HeapVector<ShapeResult::ShapeRange, 32> text_item_ranges;
    text_item_ranges.ReserveInitialCapacity(num_text_items);
    ClearCollectionScope clear_scope(&text_item_ranges);

    const bool has_ligatures =
        shape_result->NumGlyphs() < shape_result->NumCharacters();
    if (has_ligatures) {
      shape_result->EnsurePositionData();
    }
    for (; index < end_index; index++) {
      InlineItem& item = (*items)[index];
      if (item.Type() != InlineItem::kText || !item.Length()) {
        continue;
      }

      // We don't use SafeToBreak API here because this is not a line break.
      // The ShapeResult is broken into multiple results, but they must look
      // like they were not broken.
      //
      // When multiple code units shape to one glyph, such as ligatures, the
      // item that has its first code unit keeps the glyph.
      ShapeResult* item_result = ShapeResult::CreateEmpty(*shape_result);
      text_item_ranges.emplace_back(item.StartOffset(), item.EndOffset(),
                                    item_result);
      if (has_ligatures && item.EndOffset() < shape_result->EndIndex() &&
          shape_result->CachedNextSafeToBreakOffset(item.EndOffset()) !=
              item.EndOffset()) {
        // Note: We should not reuse `ShapeResult` ends with ligature glyph.
        // e.g. <div>f<span>i</div> to <div>f</div> with ligature "fi".
        // See http://crbug.com/1409702
        item.SetUnsafeToReuseShapeResult();
      }
      item.shape_result_ = item_result;
    }
    DCHECK_EQ(text_item_ranges.size(), num_text_items);
    shape_result->CopyRanges(text_item_ranges.data(), text_item_ranges.size());
  }

  auto_space.ApplyIfNeeded(*data);

#if DCHECK_IS_ON()
  for (const InlineItem& item : *items) {
    if (item.Type() == InlineItem::kText && item.Length()) {
      DCHECK(item.TextShapeResult());
      DCHECK_EQ(item.TextShapeResult()->StartIndex(), item.StartOffset());
      DCHECK_EQ(item.TextShapeResult()->EndIndex(), item.EndOffset());
    }
  }
#endif
}

// Create HeapVector<InlineItem> with :first-line rules applied if needed.
void InlineNode::ShapeTextForFirstLineIfNeeded(InlineNodeData* data) const {
  // First check if the document has any :first-line rules.
  DCHECK(!data->first_line_items_);
  LayoutObject* layout_object = GetLayoutBox();
  if (!layout_object->GetDocument().GetStyleEngine().UsesFirstLineRules())
    return;

  // Check if :first-line rules make any differences in the style.
  const ComputedStyle* block_style = layout_object->Style();
  const ComputedStyle* first_line_style = layout_object->FirstLineStyle();
  if (block_style == first_line_style)
    return;

  auto* first_line_items = MakeGarbageCollected<InlineItemsData>();
  String text_content = data->text_content;
  bool needs_reshape = false;
  if (first_line_style->TextTransform() != block_style->TextTransform()) {
    // TODO(kojii): This logic assumes that text-transform is applied only to
    // ::first-line, and does not work when the base style has text-transform
    // and ::first-line has different text-transform.
    text_content = first_line_style->ApplyTextTransform(text_content);
    if (text_content != data->text_content) {
      // TODO(kojii): When text-transform changes the length, we need to adjust
      // offset in InlineItem, or re-collect inlines. Other classes such as
      // line breaker need to support the scenario too. For now, we force the
      // string to be the same length to prevent them from crashing. This may
      // result in a missing or a duplicate character if the length changes.
      TruncateOrPadText(&text_content, data->text_content.length());
      needs_reshape = true;
    }
  }
  first_line_items->text_content = text_content;

  first_line_items->items.AppendVector(data->items);
  for (auto& item : first_line_items->items) {
    item.SetStyleVariant(StyleVariant::kFirstLine);
  }
  if (data->segments) {
    first_line_items->segments = data->segments->Clone();
  }

  // Re-shape if the font is different.
  if (needs_reshape || FirstLineNeedsReshape(*first_line_style, *block_style))
    ShapeText(first_line_items);

  data->first_line_items_ = first_line_items;
  // The score line breaker can't apply different styles by different line
 
"""


```