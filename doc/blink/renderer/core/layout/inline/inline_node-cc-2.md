Response:
Let's break down the request and the provided code. The goal is to understand the functionality of the `InlineNode` class in Chromium's Blink rendering engine, specifically focusing on its role in layout, and its relationships with JavaScript, HTML, and CSS.

**Mental Sandbox Simulation:**

1. **Core Functionality Identification:**  I'll first scan the code for method names and keywords that suggest the primary responsibilities of `InlineNode`. Terms like `ShapeText`, `Layout`, `ComputeContentSize`, `ComputeMinMaxSizes`, `AssociateItemsWithInlines`, and the context of `blink/renderer/core/layout/inline/` strongly suggest its involvement in the layout process of inline elements.

2. **Data Handling:**  I see `InlineNodeData`, `InlineItem`, `InlineItemsData`. This suggests `InlineNode` manages data related to the inline content, likely broken down into individual items. The interaction with `LayoutObject` further reinforces this, as `LayoutObject` represents the underlying DOM element.

3. **Layout Process:** The `Layout` method is central. It uses an `InlineLayoutAlgorithm`. This indicates `InlineNode` is a key participant in the actual arrangement of inline content within a line. The presence of `ConstraintSpace` and `BreakToken` hints at how layout constraints and line breaking are handled.

4. **Text Shaping:** `ShapeText` is a prominent method. This is likely where the text content is processed to determine glyphs, widths, and other typographical properties, considering font, language, and potentially CSS properties.

5. **Min/Max Content Size:**  The `ComputeMinMaxSizes` and `ComputeContentSize` methods suggest the class is responsible for calculating the intrinsic size requirements of the inline content, which is crucial for layout decisions. The distinction between `MinContent` and `MaxContent` modes is significant.

6. **Sticky Images Quirk:** The `TextContentForStickyImagesQuirk` method highlights a specific browser behavior related to how images affect line breaking in certain quirk modes.

7. **Relationship with JavaScript, HTML, CSS:** I need to connect these functions back to the web platform features they enable.
    * **HTML:** The `LayoutObject` and the presence of tags like `<br>` suggest `InlineNode` works directly with the structure of the HTML document.
    * **CSS:**  The use of `ComputedStyle` in various methods (especially `ComputeMinMaxSizes`) clearly indicates that CSS properties (font, whitespace, etc.) are crucial inputs to the layout calculations.
    * **JavaScript:** While not directly called by JavaScript, the output of `InlineNode`'s calculations (the layout) is what JavaScript interacts with through the DOM and APIs like `getBoundingClientRect`.

8. **Logical Reasoning and Examples:** I need to create hypothetical scenarios to illustrate the inputs and outputs of key functions. For example, how `ShapeText` might process a string based on the applied CSS font. For `ComputeMinMaxSizes`, I can imagine different text content and CSS properties leading to different size calculations.

9. **Common Errors:**  Thinking about common web development mistakes related to inline elements (e.g., very long unbroken strings, interaction of floats with inline content) will help in identifying potential user errors related to this code.

10. **Part 3 Summary:**  Given the context of this being the third part, the summary should focus on the overall role of `InlineNode` in the inline layout process, highlighting its interactions with text, elements, and styling.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes
* 与javascript, html, css的功能有关系，请做出对应的举例说明: Yes
* 做了逻辑推理，请给出假设输入与输出: Yes
* 如果涉及用户或者编程常见的使用错误，请举例说明: Yes
* 这是第3部分，共3部分，请归纳一下它的功能: Yes

Confidence Score: 5/5 - I'm confident I can address all aspects of the request accurately.

Strategizing complete. I will now proceed with generating the response based on these insights.

好的，这是对 `blink/renderer/core/layout/inline/inline_node.cc` 文件功能的归纳总结：

**核心功能：** `InlineNode` 类是 Chromium Blink 引擎中负责处理**内联内容布局**的核心组件。它代表了内联格式化上下文中的一个基本构建块，例如文本节点、内联元素等。其主要职责是计算内联内容的尺寸、确定换行位置、并将内联项目（Inline Items）与其对应的布局对象关联起来。

**具体功能列表及与 JavaScript, HTML, CSS 的关系：**

1. **文本塑形 (Text Shaping):**
   - **功能:** `ShapeText` 方法负责将文本内容转换为可用于渲染的字形（glyphs）。这包括应用字体、处理连字、调整字距等。
   - **与 HTML 的关系:**  它处理 HTML 文本节点中的字符数据。
   - **与 CSS 的关系:**  它会读取和应用 CSS 中与字体相关的属性，如 `font-family`, `font-size`, `font-weight`, `letter-spacing` 等。
   - **举例说明:**
     - **假设输入 (HTML):** `<div>Hello World</div>`  （假设 "Hello World" 是一个 InlineNode）
     - **CSS:** `div { font-family: Arial; font-size: 16px; }`
     - **输出 (逻辑推理):** `ShapeText` 会根据 Arial 字体和 16px 的大小，将 "Hello World" 中的每个字符转换成对应的字形，并计算每个字形的宽度和整体文本的宽度。

2. **首行文本塑形 (Shaping for First Line):**
   - **功能:** `ShapeTextForFirstLineIfNeeded`  方法专门处理应用了 CSS 首行伪类（如 `::first-line`）的文本，可能会采用不同的样式进行塑形。
   - **与 HTML 的关系:** 作用于 HTML 文本节点。
   - **与 CSS 的关系:**  考虑 `::first-line` 伪类中定义的样式。
   - **举例说明:**
     - **假设输入 (HTML):** `<p>This is the first line. And this is the second line.</p>`
     - **CSS:** `p::first-line { font-weight: bold; }`
     - **输出 (逻辑推理):**  `ShapeTextForFirstLineIfNeeded` 会对 "This is the first line." 应用粗体样式进行塑形，而后续行的文本则不会应用。

3. **禁用行分隔符 (Disabling Score Line Break):**
   - **功能:** `DisableScoreLineBreak` 方法用于禁用特定情况下（可能是为了排版特殊符号或防止意外断行）的行分隔符。
   - **与 HTML/CSS 的关系:**  间接影响文本的渲染和换行行为，但没有直接的 HTML 或 CSS 对应关系。
   - **假设输入 (内部状态):**  在处理某些特定字符或布局规则时。
   - **输出 (内部状态):**  影响后续的换行逻辑，阻止在某些位置进行断行。

4. **关联内联项与布局对象 (Associating Items with Inlines):**
   - **功能:** `AssociateItemsWithInlines` 方法将 `InlineItem` 对象（代表内联内容的一部分，如文本片段、内联元素）与它们对应的 `LayoutObject`（代表 DOM 树中的元素）关联起来。这对于后续的布局和渲染至关重要。
   - **与 HTML 的关系:**  将内联项与 HTML 元素（通过 `LayoutObject`）联系起来。
   - **内部逻辑:** 遍历 `InlineItem` 列表，将属于同一个 `LayoutText` 对象的连续 `InlineItem` 组合起来，并设置 `LayoutText` 对象的相关属性，例如是否包含双向文本控制字符。
   - **举例说明:**
     - **假设输入 (Inline Items):**  一系列 `InlineItem`，其中前三个对应于 `<span>Hello</span>` 中的 "Hello"，后两个对应于 `<span>World</span>` 中的 "World"。
     - **输出 (内部状态):**  `<span>` 对应的 `LayoutText` 对象会分别持有指向 "Hello" 和 "World" 对应的 `InlineItem` 的引用。

5. **内联布局 (Inline Layout):**
   - **功能:** `Layout` 方法是执行内联布局的核心。它使用 `InlineLayoutAlgorithm` 来计算内联节点及其子节点的最终位置和尺寸。
   - **与 HTML 的关系:**  负责排列 HTML 中的内联元素和文本。
   - **与 CSS 的关系:**  考虑所有相关的 CSS 属性，如 `width`, `height`, `margin`, `padding`, `line-height`, `vertical-align` 等。
   - **假设输入:**  约束空间 (`ConstraintSpace`)、断点令牌 (`BreakToken`) 等布局上下文信息。
   - **输出:**  布局结果 (`LayoutResult`)，包含内联节点的最终尺寸和位置信息。

6. **处理粘性图片的怪异模式 (Text Content for Sticky Images Quirk):**
   - **功能:** `TextContentForStickyImagesQuirk` 方法处理一种特殊的浏览器怪异模式，在这种模式下，图片周围的换行行为会发生变化。它会创建一个修改后的文本内容，将图片替换为非断行空格，以简化后续的换行逻辑。
   - **与 HTML 的关系:**  涉及到 `<img>` 标签的处理。
   - **与 CSS 的关系:**  与特定怪异模式下的渲染行为有关。
   - **举例说明:**
     - **假设输入 (HTML):** `<td><img src="..."></td>` (在特定的表格布局怪异模式下)
     - **输出 (逻辑推理):**  如果检测到粘性图片怪异模式，并且 `<img>` 标签在 `InlineItemsData` 中，该方法会返回一个新的字符串，其中代表图片的特殊字符（通常是 `U+FFFC OBJECT REPLACEMENT CHARACTER`）被替换为 `U+00A0 NO-BREAK SPACE`。

7. **计算内容尺寸 (Computing Content Size):**
   - **功能:** `ComputeContentSize` 方法计算内联内容的最小内容尺寸（min-content size）和最大内容尺寸（max-content size）。这对于自动布局和弹性布局非常重要。
   - **与 HTML 的关系:**  计算 HTML 内联内容的固有尺寸。
   - **与 CSS 的关系:**  受 CSS 字体、空白处理、`text-indent`、浮动元素等属性的影响。
   - **逻辑推理和假设输入/输出:**
     - **假设输入 (HTML):** `<span>This is a long text</span>`
     - **CSS:** `span { font-size: 16px; }`
     - **输出 (逻辑推理 - Min-Content):**  最小内容尺寸将是所有单词在不换行情况下排列所需的最小宽度，可能类似于 "Thisisalongtext" 的宽度。
     - **输出 (逻辑推理 - Max-Content):** 最大内容尺寸将是所有单词在允许任意换行情况下排列所需的最小宽度，可能类似于 "This is a long text" 的宽度（假设有足够的空间不换行）。

8. **计算最小和最大尺寸 (Computing Min and Max Sizes):**
   - **功能:** `ComputeMinMaxSizes` 方法是计算内联节点最小和最大尺寸的入口点，它会调用 `ComputeContentSize` 来完成计算。
   - **与 HTML/CSS 的关系:** 最终确定内联元素在布局中的尺寸约束。

9. **使用首行样式 (Using First Line Style):**
   - **功能:** `UseFirstLineStyle` 方法检查当前文档是否启用了首行样式的规则（通过 CSS 引擎判断）。
   - **与 CSS 的关系:**  判断是否需要应用 `::first-line` 等伪类的样式。

10. **一致性检查 (Checking Consistency):**
    - **功能:** `CheckConsistency` 方法（仅在 DCHECK 开启时）用于进行内部数据一致性检查，例如确保 `InlineItem` 的样式与其对应的 `LayoutObject` 的样式一致。

11. **SVG 相关数据 (SVG Character Data List, SVG Text Length Range List, SVG Text Path Range List):**
    - **功能:**  这些方法用于获取与 SVG 文本元素相关的特定数据，如字符数据、文本长度范围、文本路径范围等。
    - **与 HTML 的关系:**  处理嵌入在 HTML 中的 SVG 内容。
    - **与 SVG 的关系:**  用于处理 SVG `<text>` 元素及其相关的属性。

12. **调整文本组合垂直样式 (Adjust Font for Text Combine Upright All):**
    - **功能:** `AdjustFontForTextCombineUprightAll` 方法专门处理 `text-combine-upright: all` CSS 属性，用于调整字体以使文本在垂直方向上正确组合。它会尝试使用压缩字体或缩放字体来适应指定的宽度。
    - **与 HTML 的关系:**  影响应用了 `text-combine-upright` 属性的 HTML 元素的渲染。
    - **与 CSS 的关系:**  处理 `text-combine-upright` CSS 属性。

13. **测试所需的塑形 (Needs Shaping for Testing):**
    - **功能:** `NeedsShapingForTesting` 是一个用于测试目的的方法，它简单地调用 `NeedsShaping` 方法来判断一个 `InlineItem` 是否需要进行文本塑形。

**用户或编程常见的使用错误示例：**

1. **长而不换行的文本:**  如果用户在 HTML 中输入了很长的、没有空格或其他断字符的文本，并且没有使用 CSS 进行强制换行（如 `word-break: break-all` 或 `overflow-wrap: break-word`），`InlineNode` 在计算尺寸时可能会生成非常宽的行，导致布局溢出。
   - **假设输入 (HTML):** `<div>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</div>`
   - **错误:** 可能会超出父元素的宽度，导致水平滚动条。

2. **错误的 `text-combine-upright` 用法:**  不正确地使用 `text-combine-upright` 可能会导致文本显示不符合预期，例如字符重叠或显示不全。`InlineNode` 中的相关逻辑会尝试调整字体来适应，但如果配置不当，仍然可能出现问题。
   - **假设输入 (HTML):** `<span style="text-combine-upright: all;">12345</span>`，但父元素宽度不足以容纳组合后的文本。
   - **错误:** 文本可能无法完全显示或显示错乱。

**总结 `InlineNode` 的功能 (作为第 3 部分的总结):**

作为内联布局流程的关键组成部分，`InlineNode` 负责处理内联内容的**核心布局逻辑**。它将 HTML 结构和 CSS 样式转化为实际的渲染信息，包括：

* **文本处理：** 对文本内容进行塑形，考虑字体、样式等因素。
* **尺寸计算：**  确定内联内容的最小和最大固有尺寸，为布局决策提供依据。
* **项目关联：**  将内联内容分解为更小的 `InlineItem` 并与对应的 DOM 元素关联。
* **布局执行：**  使用布局算法来安排内联元素和文本的位置，处理换行等问题。
* **特殊情况处理：**  处理特定的浏览器怪异模式（如粘性图片）和 CSS 特性（如 `text-combine-upright`）。

`InlineNode` 的工作是构建内联格式化上下文的基础，它确保了文本和内联元素能够按照 CSS 规则正确地排列和渲染在页面上。它与 JavaScript、HTML 和 CSS 紧密相关，共同构建了网页的视觉呈现。

Prompt: 
```
这是目录为blink/renderer/core/layout/inline/inline_node.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
 // breaking.
  data->is_score_line_break_disabled_ = true;
}

void InlineNode::ShapeTextIncludingFirstLine(
    InlineNodeData* data,
    const String* previous_text,
    const HeapVector<InlineItem>* previous_items) const {
  ShapeText(data, previous_text, previous_items);
  ShapeTextForFirstLineIfNeeded(data);
}

void InlineNode::AssociateItemsWithInlines(InlineNodeData* data) const {
#if DCHECK_IS_ON()
  HeapHashSet<Member<LayoutObject>> associated_objects;
#endif
  HeapVector<InlineItem>& items = data->items;
  WTF::wtf_size_t size = items.size();
  for (WTF::wtf_size_t i = 0; i != size;) {
    LayoutObject* object = items[i].GetLayoutObject();
    auto* layout_text = DynamicTo<LayoutText>(object);
    if (layout_text && !layout_text->IsBR()) {
#if DCHECK_IS_ON()
      // Items split from a LayoutObject should be consecutive.
      DCHECK(associated_objects.insert(object).is_new_entry);
#endif
      layout_text->ClearHasBidiControlInlineItems();
      bool has_bidi_control = false;
      WTF::wtf_size_t begin = i;
      for (++i; i != size; ++i) {
        auto& item = items[i];
        if (item.GetLayoutObject() != object)
          break;
        if (item.Type() == InlineItem::kBidiControl) {
          has_bidi_control = true;
        }
      }
      layout_text->SetInlineItems(data, begin, i - begin);
      if (has_bidi_control)
        layout_text->SetHasBidiControlInlineItems();
      continue;
    }
    ++i;
  }
}

const LayoutResult* InlineNode::Layout(
    const ConstraintSpace& constraint_space,
    const BreakToken* break_token,
    const ColumnSpannerPath* column_spanner_path,
    InlineChildLayoutContext* context) const {
  PrepareLayoutIfNeeded();

  const auto* inline_break_token = To<InlineBreakToken>(break_token);
  InlineLayoutAlgorithm algorithm(*this, constraint_space, inline_break_token,
                                  column_spanner_path, context);
  return algorithm.Layout();
}

namespace {

template <typename CharType>
String CreateTextContentForStickyImagesQuirk(
    const CharType* text,
    unsigned length,
    base::span<const InlineItem> items) {
  StringBuffer<CharType> buffer(length);
  CharType* characters = buffer.Characters();
  memcpy(characters, text, length * sizeof(CharType));
  for (const InlineItem& item : items) {
    if (item.Type() == InlineItem::kAtomicInline && item.IsImage()) {
      DCHECK_EQ(characters[item.StartOffset()], kObjectReplacementCharacter);
      characters[item.StartOffset()] = kNoBreakSpaceCharacter;
    }
  }
  return buffer.Release();
}

}  // namespace

// The stick images quirk changes the line breaking behavior around images. This
// function returns a text content that has non-breaking spaces for images, so
// that no changes are needed in the line breaking logic.
// https://quirks.spec.whatwg.org/#the-table-cell-width-calculation-quirk
// static
String InlineNode::TextContentForStickyImagesQuirk(
    const InlineItemsData& items_data) {
  const String& text_content = items_data.text_content;
  for (unsigned i = 0; i < items_data.items.size(); ++i) {
    const InlineItem& item = items_data.items[i];
    if (item.Type() == InlineItem::kAtomicInline && item.IsImage()) {
      auto item_span = base::span(items_data.items).subspan(i);
      if (text_content.Is8Bit()) {
        return CreateTextContentForStickyImagesQuirk(
            text_content.Characters8(), text_content.length(), item_span);
      }
      return CreateTextContentForStickyImagesQuirk(
          text_content.Characters16(), text_content.length(), item_span);
    }
  }
  return text_content;
}

static LayoutUnit ComputeContentSize(InlineNode node,
                                     WritingMode container_writing_mode,
                                     const ConstraintSpace& space,
                                     const MinMaxSizesFloatInput& float_input,
                                     LineBreakerMode mode,
                                     LineBreaker::MaxSizeCache* max_size_cache,
                                     std::optional<LayoutUnit>* max_size_out,
                                     bool* depends_on_block_constraints_out) {
  const ComputedStyle& style = node.Style();
  LayoutUnit available_inline_size =
      mode == LineBreakerMode::kMaxContent ? LayoutUnit::Max() : LayoutUnit();

  ExclusionSpace empty_exclusion_space;
  LeadingFloats empty_leading_floats;
  LineLayoutOpportunity line_opportunity(available_inline_size);
  LayoutUnit result;
  LineBreaker line_breaker(
      node, mode, space, line_opportunity, empty_leading_floats,
      /* break_token */ nullptr,
      /* column_spanner_path */ nullptr, &empty_exclusion_space);
  line_breaker.SetIntrinsicSizeOutputs(max_size_cache,
                                       depends_on_block_constraints_out);
  const InlineItemsData& items_data = line_breaker.ItemsData();

  // Computes max-size for floats in inline formatting context.
  class FloatsMaxSize {
    STACK_ALLOCATED();

   public:
    explicit FloatsMaxSize(const MinMaxSizesFloatInput& float_input)
        : floats_inline_size_(float_input.float_left_inline_size +
                              float_input.float_right_inline_size) {
      DCHECK_GE(floats_inline_size_, 0);
    }

    void AddFloat(const ComputedStyle& float_style,
                  const ComputedStyle& style,
                  LayoutUnit float_inline_max_size_with_margin) {
      floating_objects_.push_back(InlineNode::FloatingObject{
          float_style, style, float_inline_max_size_with_margin});
    }

    LayoutUnit ComputeMaxSizeForLine(LayoutUnit line_inline_size,
                                     LayoutUnit max_inline_size) {
      if (floating_objects_.empty())
        return std::max(max_inline_size, line_inline_size);

      EFloat previous_float_type = EFloat::kNone;
      for (const auto& floating_object : floating_objects_) {
        const EClear float_clear =
            floating_object.float_style->Clear(*floating_object.style);

        // If this float clears the previous float we start a new "line".
        // This is subtly different to block layout which will only reset either
        // the left or the right float size trackers.
        if ((previous_float_type == EFloat::kLeft &&
             (float_clear == EClear::kBoth || float_clear == EClear::kLeft)) ||
            (previous_float_type == EFloat::kRight &&
             (float_clear == EClear::kBoth || float_clear == EClear::kRight))) {
          max_inline_size =
              std::max(max_inline_size, line_inline_size + floats_inline_size_);
          floats_inline_size_ = LayoutUnit();
        }

        // When negative margins move the float outside the content area,
        // such float should not affect the content size.
        floats_inline_size_ += floating_object.float_inline_max_size_with_margin
                                   .ClampNegativeToZero();
        previous_float_type =
            floating_object.float_style->Floating(*floating_object.style);
      }
      max_inline_size =
          std::max(max_inline_size, line_inline_size + floats_inline_size_);
      floats_inline_size_ = LayoutUnit();
      floating_objects_.Shrink(0);
      return max_inline_size;
    }

   private:
    LayoutUnit floats_inline_size_;
    HeapVector<InlineNode::FloatingObject, 4> floating_objects_;
  };

  // This struct computes the max size from the line break results for the min
  // size.
  struct MaxSizeFromMinSize {
    STACK_ALLOCATED();

   public:
    using ItemIterator = HeapVector<InlineItem>::const_iterator;

    LayoutUnit position;
    LayoutUnit max_size;
    const InlineItemsData& items_data;
    ItemIterator next_item;
    const LineBreaker::MaxSizeCache& max_size_cache;
    FloatsMaxSize* floats;
    bool is_after_break = true;
    wtf_size_t annotation_nesting_level = 0;

    explicit MaxSizeFromMinSize(const InlineItemsData& items_data,
                                const LineBreaker::MaxSizeCache& max_size_cache,
                                FloatsMaxSize* floats)
        : items_data(items_data),
          next_item(items_data.items.begin()),
          max_size_cache(max_size_cache),
          floats(floats) {}

    // Add all text items up to |end|. The line break results for min size
    // may break text into multiple lines, and may remove trailing spaces. For
    // max size, use the original text widths from InlineItem instead.
    void AddTextUntil(ItemIterator end) {
      for (; next_item != end; ++next_item) {
        if (next_item->Type() == InlineItem::kOpenTag &&
            next_item->GetLayoutObject()->IsInlineRubyText()) {
          ++annotation_nesting_level;
        } else if (next_item->Type() == InlineItem::kCloseTag &&
                   next_item->GetLayoutObject()->IsInlineRubyText()) {
          --annotation_nesting_level;
        } else if (next_item->Type() == InlineItem::kText &&
                   next_item->Length() && annotation_nesting_level == 0) {
          DCHECK(next_item->TextShapeResult());
          const ShapeResult& shape_result = *next_item->TextShapeResult();
          position += shape_result.SnappedWidth().ClampNegativeToZero();
        }
      }
    }

    void ForceLineBreak(const LineInfo& line_info) {
      // Add all text up to the end of the line. There may be spaces that were
      // removed during the line breaking.
      CHECK_LE(line_info.EndItemIndex(), items_data.items.size());
      AddTextUntil(items_data.items.begin() + line_info.EndItemIndex());
      max_size = floats->ComputeMaxSizeForLine(position.ClampNegativeToZero(),
                                               max_size);
      position = LayoutUnit();
      is_after_break = true;
    }

    void AddTabulationCharacters(const InlineItem& item, unsigned length) {
      DCHECK_GE(length, 1u);
      AddTextUntil(items_data.ToItemIterator(item));
      DCHECK(item.Style());
      const ComputedStyle& style = *item.Style();
      const Font& font = style.GetFont();
      const SimpleFontData* font_data = font.PrimaryFont();
      const TabSize& tab_size = style.GetTabSize();
      // Sync with `ShapeResult::CreateForTabulationCharacters()`.
      TextRunLayoutUnit glyph_advance = TextRunLayoutUnit::FromFloatRound(
          font.TabWidth(font_data, tab_size, position));
      InlineLayoutUnit run_advance = glyph_advance;
      DCHECK_GE(length, 1u);
      if (length > 1u) {
        glyph_advance = TextRunLayoutUnit::FromFloatRound(
            font.TabWidth(font_data, tab_size));
        run_advance += glyph_advance.To<InlineLayoutUnit>() * (length - 1);
      }
      position += run_advance.ToCeil<LayoutUnit>().ClampNegativeToZero();
    }

    LayoutUnit Finish(ItemIterator end) {
      AddTextUntil(end);
      return floats->ComputeMaxSizeForLine(position.ClampNegativeToZero(),
                                           max_size);
    }

    void ComputeFromMinSize(const LineInfo& line_info) {
      if (is_after_break) {
        position += line_info.TextIndent();
        is_after_break = false;
      }

      ComputeFromMinSizeInternal(line_info);

      // Compute the forced break after all results were handled, because
      // when close tags appear after a forced break, they are included in
      // the line, and they may have inline sizes. crbug.com/991320.
      if (line_info.HasForcedBreak()) {
        ForceLineBreak(line_info);
      }
    }

    void ComputeFromMinSizeInternal(const LineInfo& line_info) {
      for (const InlineItemResult& result : line_info.Results()) {
        const InlineItem& item = *result.item;
        if (item.Type() == InlineItem::kText) {
          // Text in InlineItemResult may be wrapped and trailing spaces
          // may be removed. Ignore them, but add text later from
          // InlineItem.
          continue;
        }
#if DCHECK_IS_ON()
        if (item.Type() == InlineItem::kBlockInInline) {
          DCHECK(line_info.HasForcedBreak());
        }
#endif
        if (item.Type() == InlineItem::kAtomicInline ||
            item.Type() == InlineItem::kBlockInInline) {
          // The max-size for atomic inlines are cached in |max_size_cache|.
          unsigned item_index = items_data.ToItemIndex(item);
          position += max_size_cache[item_index];
          continue;
        }
        if (item.Type() == InlineItem::kControl) {
          UChar c = items_data.text_content[item.StartOffset()];
#if DCHECK_IS_ON()
          if (c == kNewlineCharacter)
            DCHECK(line_info.HasForcedBreak());
#endif
          // Tabulation characters change the widths by their positions, so
          // their widths for the max size may be different from the widths for
          // the min size. Fall back to 2 pass for now.
          if (c == kTabulationCharacter) {
            AddTabulationCharacters(item, result.Length());
            continue;
          }
        }
        if (result.IsRubyColumn()) {
          ComputeFromMinSizeInternal(result.ruby_column->base_line);
          continue;
        }
        position += result.inline_size;
      }
    }
  };

  if (node.IsInitialLetterBox()) [[unlikely]] {
    LayoutUnit inline_size = LayoutUnit();
    LineInfo line_info;
    do {
      line_breaker.NextLine(&line_info);
      if (line_info.Results().empty())
        break;
      inline_size =
          std::max(CalculateInitialLetterBoxInlineSize(line_info), inline_size);
    } while (!line_breaker.IsFinished());
    return inline_size;
  }

  FloatsMaxSize floats_max_size(float_input);
  bool can_compute_max_size_from_min_size = true;
  MaxSizeFromMinSize max_size_from_min_size(items_data, *max_size_cache,
                                            &floats_max_size);

  LineInfo line_info;
  do {
    line_breaker.NextLine(&line_info);
    if (line_info.Results().empty())
      break;

    LayoutUnit inline_size = line_info.Width();
    for (const InlineItemResult& item_result : line_info.Results()) {
      DCHECK(item_result.item);
      const InlineItem& item = *item_result.item;
      if (item.Type() != InlineItem::kFloating) {
        continue;
      }
      LayoutObject* floating_object = item.GetLayoutObject();
      DCHECK(floating_object && floating_object->IsFloating());

      BlockNode float_node(To<LayoutBox>(floating_object));

      MinMaxConstraintSpaceBuilder builder(space, style, float_node,
                                           /* is_new_fc */ true);
      builder.SetAvailableBlockSize(space.AvailableSize().block_size);
      builder.SetPercentageResolutionBlockSize(
          space.PercentageResolutionBlockSize());
      builder.SetReplacedPercentageResolutionBlockSize(
          space.ReplacedPercentageResolutionBlockSize());
      const auto float_space = builder.ToConstraintSpace();

      const MinMaxSizesResult child_result =
          ComputeMinAndMaxContentContribution(style, float_node, float_space);
      LayoutUnit child_inline_margins =
          ComputeMarginsFor(float_space, float_node.Style(), space).InlineSum();

      if (depends_on_block_constraints_out) {
        *depends_on_block_constraints_out |=
            child_result.depends_on_block_constraints;
      }

      if (mode == LineBreakerMode::kMinContent) {
        result = std::max(result,
                          child_result.sizes.min_size + child_inline_margins);
      }
      floats_max_size.AddFloat(
          float_node.Style(), style,
          child_result.sizes.max_size + child_inline_margins);
    }

    if (mode == LineBreakerMode::kMinContent) {
      result = std::max(result, inline_size);
      can_compute_max_size_from_min_size =
          can_compute_max_size_from_min_size &&
          // `box-decoration-break: clone` clones box decorations to each
          // fragment (line) that we cannot compute max-content from
          // min-content.
          !line_breaker.HasClonedBoxDecorations() &&
          !line_info.MayHaveRubyOverhang();
      if (can_compute_max_size_from_min_size)
        max_size_from_min_size.ComputeFromMinSize(line_info);
    } else {
      result = floats_max_size.ComputeMaxSizeForLine(inline_size, result);
    }
  } while (!line_breaker.IsFinished());

  if (mode == LineBreakerMode::kMinContent &&
      can_compute_max_size_from_min_size) {
    if (node.IsSvgText()) {
      *max_size_out = result;
      return result;
      // The following DCHECK_EQ() doesn't work well for SVG <text> because
      // it has glyph-split InlineItemResults. The sum of InlineItem
      // widths and the sum of InlineItemResult widths can be different.
    }
    *max_size_out = max_size_from_min_size.Finish(items_data.items.end());

#if EXPENSIVE_DCHECKS_ARE_ON()
    // Check the max size matches to the value computed from 2 pass.
    LayoutUnit content_size = ComputeContentSize(
        node, container_writing_mode, space, float_input,
        LineBreakerMode::kMaxContent, max_size_cache, nullptr, nullptr);
    bool values_might_be_saturated =
        (*max_size_out)->MightBeSaturated() || content_size.MightBeSaturated();
    if (!values_might_be_saturated) {
      DCHECK_EQ((*max_size_out)->Round(), content_size.Round())
          << node.GetLayoutBox();
    }
#endif
  }

  return result;
}

MinMaxSizesResult InlineNode::ComputeMinMaxSizes(
    WritingMode container_writing_mode,
    const ConstraintSpace& space,
    const MinMaxSizesFloatInput& float_input) const {
  PrepareLayoutIfNeeded();

  // Compute the max of inline sizes of all line boxes with 0 available inline
  // size. This gives the min-content, the width where lines wrap at every
  // break opportunity.
  LineBreaker::MaxSizeCache max_size_cache;
  MinMaxSizes sizes;
  std::optional<LayoutUnit> max_size;
  bool depends_on_block_constraints = false;
  sizes.min_size =
      ComputeContentSize(*this, container_writing_mode, space, float_input,
                         LineBreakerMode::kMinContent, &max_size_cache,
                         &max_size, &depends_on_block_constraints);
  if (max_size) {
    sizes.max_size = *max_size;
  } else {
    sizes.max_size = ComputeContentSize(
        *this, container_writing_mode, space, float_input,
        LineBreakerMode::kMaxContent, &max_size_cache, nullptr, nullptr);
  }

  // Negative text-indent can make min > max. Ensure min is the minimum size.
  sizes.min_size = std::min(sizes.min_size, sizes.max_size);

  return MinMaxSizesResult(sizes, depends_on_block_constraints);
}

bool InlineNode::UseFirstLineStyle() const {
  return GetLayoutBox() &&
         GetLayoutBox()->GetDocument().GetStyleEngine().UsesFirstLineRules();
}

void InlineNode::CheckConsistency() const {
#if DCHECK_IS_ON()
  const HeapVector<InlineItem>& items = Data().items;
  for (const InlineItem& item : items) {
    DCHECK(!item.GetLayoutObject() || !item.Style() ||
           item.Style() == item.GetLayoutObject()->Style());
  }
#endif
}

const Vector<std::pair<unsigned, SvgCharacterData>>&
InlineNode::SvgCharacterDataList() const {
  DCHECK(IsSvgText());
  return Data().svg_node_data_->character_data_list;
}

const HeapVector<SvgTextContentRange>& InlineNode::SvgTextLengthRangeList()
    const {
  DCHECK(IsSvgText());
  return Data().svg_node_data_->text_length_range_list;
}

const HeapVector<SvgTextContentRange>& InlineNode::SvgTextPathRangeList()
    const {
  DCHECK(IsSvgText());
  return Data().svg_node_data_->text_path_range_list;
}

void InlineNode::AdjustFontForTextCombineUprightAll() const {
  DCHECK(IsTextCombine()) << GetLayoutBlockFlow();
  DCHECK(IsPrepareLayoutFinished()) << GetLayoutBlockFlow();

  const float content_width = CalculateWidthForTextCombine(ItemsData(false));
  if (content_width == 0.0f) [[unlikely]] {
    return;  // See "fast/css/zero-font-size-crash.html".
  }
  auto& text_combine = *To<LayoutTextCombine>(GetLayoutBlockFlow());
  const float desired_width = text_combine.DesiredWidth();
  text_combine.ResetLayout();
  if (desired_width == 0.0f) [[unlikely]] {
    // See http://crbug.com/1342520
    return;
  }
  if (content_width <= desired_width)
    return;

  const Font& font = Style().GetFont();
  FontSelector* const font_selector = font.GetFontSelector();
  FontDescription description = font.GetFontDescription();

  // Try compressed fonts.
  static const std::array<FontWidthVariant, 3> kWidthVariants = {
      kHalfWidth, kThirdWidth, kQuarterWidth};
  for (const auto width_variant : kWidthVariants) {
    description.SetWidthVariant(width_variant);
    Font compressed_font(description, font_selector);
    // TODO(crbug.com/561873): PrimaryFont should not be nullptr.
    if (!compressed_font.PrimaryFont()) {
      continue;
    }
    ShapeText(MutableData(), nullptr, nullptr, &compressed_font);
    if (CalculateWidthForTextCombine(ItemsData(false)) <= desired_width) {
      text_combine.SetCompressedFont(compressed_font);
      return;
    }
  }

  // There is no compressed font to fit within 1em. We use original font with
  // scaling.
  ShapeText(MutableData());
  DCHECK_EQ(content_width, CalculateWidthForTextCombine(ItemsData(false)));
  DCHECK_NE(content_width, 0.0f);
  text_combine.SetScaleX(desired_width / content_width);
}

bool InlineNode::NeedsShapingForTesting(const InlineItem& item) {
  return NeedsShaping(item);
}

String InlineNode::ToString() const {
  return "InlineNode";
}

}  // namespace blink

"""


```