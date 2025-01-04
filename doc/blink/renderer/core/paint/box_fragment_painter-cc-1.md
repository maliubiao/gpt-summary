Response:
The user wants to understand the functionality of the `box_fragment_painter.cc` file in the Chromium Blink rendering engine. This is the second part of a four-part request. I need to:

1. **Summarize the functionality** of the provided code snippet.
2. **Identify connections to web technologies (JavaScript, HTML, CSS)** and provide examples.
3. **Analyze logical reasoning** and provide hypothetical input/output scenarios.
4. **Point out common user/programming errors** related to this code.
5. **Explain how user actions can lead to this code being executed** as a debugging aid.

**Code Analysis (Part 2):**

This part of the `BoxFragmentPainter` focuses on:

- **Painting Inline Content:** Handling the rendering of inline elements and their children within a box fragment.
- **Painting Paginated Content:**  Managing the rendering of content split across multiple pages (like in printing).
- **Painting Block Children:** Rendering block-level elements within a box fragment.
- **Painting Floating Elements:** Handling the rendering of `float` elements.
- **Painting Masks:** Applying visual masks to elements.
- **Painting Box Decoration Backgrounds:** Rendering backgrounds, borders, and shadows of elements.
- **Painting Column Rules:**  Drawing lines between columns in multi-column layouts.

**Plan:**

1. **Summarize core functionalities** observed in this code block.
2. **Relate functionalities to HTML, CSS, and potentially JavaScript interaction** in rendering.
3. **Construct simple scenarios** to illustrate the logic (e.g., how culling works, how background painting is conditional).
4. **Consider common mistakes** that might lead to issues in these painting stages (e.g., incorrect CSS causing layout problems, issues with stacking contexts and z-index).
5. **Describe user actions** that trigger these painting processes (e.g., page load, scrolling, applying styles).
这是 `blink/renderer/core/paint/box_fragment_painter.cc` 文件第二部分代码的功能归纳：

**核心功能： BoxFragment 的内容绘制**

这部分代码主要负责 `BoxFragmentPainter` 类中与绘制 `BoxFragment` 内容相关的逻辑，涵盖了各种类型的子元素和装饰效果的渲染。它根据 `PaintInfo` 中指定的绘制阶段和上下文，决定如何以及何时绘制 `BoxFragment` 的子元素和自身装饰。

**具体功能点:**

* **`PaintInlineChildren(const PaintInfo& paint_info, PhysicalOffset paint_offset)`:**
    * **功能:** 绘制包含内联子元素的 `BoxFragment`。
    * **主要逻辑:**
        * 检查是否需要布局或是否是 MathML 运算符，如果是则跳过绘制。
        * 进行裁剪检测，如果内容不在可视区域内则跳过绘制。
        * 创建内联上下文 (`EnsureInlineContext`)。
        * 遍历内联子元素 (`InlineCursor`)，并根据当前的绘制阶段进行相应的绘制操作。
        * 在前景 (`kForeground`) 阶段，如果需要，会收集 URL 信息用于 PDF 等生成。
        * 在强制颜色模式背景板 (`kForcedColorsModeBackplate`) 阶段，绘制背景板。
        * 调用 `PaintLineBoxChildItems` 绘制实际的内联子元素。
    * **与 Web 技术的关系:**
        * **HTML:**  处理包含文本或其他内联元素的 HTML 结构。
        * **CSS:**  考虑 CSS 的文本样式、颜色、链接等属性。
        * **JavaScript:**  JavaScript 动态修改 HTML 结构或 CSS 样式可能会触发此函数的执行。
    * **假设输入与输出:**
        * **输入:** 一个包含 `<span>` 标签的 `<div>` 元素的 `BoxFragment`，`paint_info` 设置为 `kForeground` 阶段。
        * **输出:** `<span>` 标签中的文本内容会被绘制到屏幕上。
    * **用户/编程常见的使用错误:**
        * CSS 样式导致内联元素重叠或不可见。
        * JavaScript 动态添加大量内联元素可能导致性能问题。

* **`PaintCurrentPageContainer(const PaintInfo& paint_info)`:**
    * **功能:** 绘制分页布局的根 `BoxFragment`（例如，打印预览时的页面容器）。
    * **主要逻辑:**
        * 获取当前页面的 `BoxFragment`。
        * 递归调用 `BoxFragmentPainter::Paint` 绘制页面容器自身。
        * 遍历页面容器的子元素（页面边框、页边距等），并按照 z-index 顺序绘制。
    * **与 Web 技术的关系:**
        * **CSS:**  处理 CSS 的分页属性 (`@page`)，定义页面的大小、边距等。
        * **HTML:**  与包含分页内容的 HTML 结构相关。
    * **假设输入与输出:**
        * **输入:** 一个表示当前打印页面的 `BoxFragment`，`paint_info` 与打印相关。
        * **输出:** 当前页面的边框、页边距等会被绘制出来。

* **`PaintBlockChildren(const PaintInfo& paint_info, PhysicalOffset paint_offset)`:**
    * **功能:** 绘制 `BoxFragment` 的块级子元素。
    * **主要逻辑:**
        * 遍历 `BoxFragment` 的子元素。
        * 跳过自身拥有绘制层或浮动的子元素。
        * 调用 `PaintBlockChild` 绘制其他块级子元素。
    * **与 Web 技术的关系:**
        * **HTML:** 处理 `<div>`, `<p>`, `<h1>` 等块级元素。
        * **CSS:**  考虑块级元素的布局属性 (如 `display: block`)。

* **`PaintBlockChild(...)`:**
    * **功能:** 绘制单个块级子元素。
    * **主要逻辑:**
        * 检查子元素是否可遍历。
        * 如果是 `FragmentainerBox` (用于分栏布局)，则创建一个唯一的标识符并调用 `PaintObject` 进行绘制。
        * 否则，递归调用 `BoxFragmentPainter::Paint` 绘制子元素。
        * 如果子元素不可遍历，则调用 `PaintFragment` 进行绘制。

* **`PaintFloatingItems(const PaintInfo& paint_info, InlineCursor* cursor)`:**
    * **功能:** 绘制内联格式化上下文中的浮动元素。
    * **主要逻辑:** 遍历内联子元素，识别并绘制浮动元素。

* **`PaintFloatingChildren(const PhysicalFragment& container, const PaintInfo& paint_info)`:**
    * **功能:** 绘制包含浮动子元素的 `BoxFragment` 中的浮动元素。
    * **主要逻辑:**
        * 遍历子元素，跳过自身拥有绘制层的子元素。
        * 如果是浮动元素，则调用 `PaintFragment` 进行绘制。
        * 如果是非浮动元素但包含浮动后代，则递归调用 `BoxFragmentPainter::Paint` 或 `PaintFloatingChildren` 进行处理。
        * 特殊处理 selection drag image 阶段。

* **`PaintFloats(const PaintInfo& paint_info)`:**
    * **功能:**  启动浮动元素的绘制流程。

* **`PaintMask(const PaintInfo& paint_info, const PhysicalOffset& paint_offset)`:**
    * **功能:** 绘制元素的遮罩效果。
    * **与 Web 技术的关系:**
        * **CSS:**  对应 CSS 的 `mask` 相关属性。
    * **用户/编程常见的使用错误:**
        * 遮罩路径或图像不正确导致遮罩效果不符合预期。

* **`PaintBoxDecorationBackground(...)`:**
    * **功能:** 绘制元素的背景、边框和阴影等装饰效果。
    * **主要逻辑:**
        * 对于根元素或页面容器，调用专门的 `ViewPainter` 进行绘制。
        * 计算绘制区域。
        * 调用 `PaintBoxDecorationBackgroundWithRect` 执行实际的绘制。
    * **与 Web 技术的关系:**
        * **CSS:**  对应 CSS 的 `background`, `border`, `box-shadow` 等属性。

* **`PaintBoxDecorationBackgroundWithRect(...)`:**
    * **功能:** 使用指定的矩形区域绘制盒子的装饰背景。
    * **主要逻辑:**
        * 处理缓存。
        * 对于固定背景附件 (`background-attachment: fixed`) 进行特殊处理。
        * 调用 `PaintBoxDecorationBackgroundWithDecorationData` 执行绘制。

* **`PaintCompositeBackgroundAttachmentFixed(...)`:**
    * **功能:** 绘制 `background-attachment: fixed` 的背景。
    * **与 Web 技术的关系:**
        * **CSS:**  对应 CSS 的 `background-attachment: fixed` 属性。

* **`PaintBoxDecorationBackgroundWithDecorationData(...)`:**
    * **功能:** 根据提供的装饰数据绘制盒子的背景。
    * **主要逻辑:**
        * 处理缓存。
        * 根据元素类型（`fieldset`, 表格元素等）调用不同的绘制器。
        * 否则，调用 `PaintBoxDecorationBackgroundWithRectImpl` 进行绘制。

* **`PaintBoxDecorationBackgroundWithRectImpl(...)`:**
    * **功能:**  实际执行盒子装饰背景的绘制逻辑。
    * **主要逻辑:**
        * 保存绘图上下文状态。
        * 绘制阴影。
        * 处理出血避免裁剪 (`bleed avoidance clipping`)。
        * 绘制背景颜色和图片。
        * 绘制主题提供的装饰。
        * 绘制内阴影。
        * 绘制边框。

* **`PaintBoxDecorationBackgroundForBlockInInline(...)`:**
    * **功能:**  绘制内联格式化上下文中块级元素的背景。
    * **主要逻辑:** 遍历内联子元素，找到块级元素并绘制其背景。

* **`PaintColumnRules(const PaintInfo& paint_info, const PhysicalOffset& paint_offset)`:**
    * **功能:** 绘制多列布局中列之间的分隔线。
    * **与 Web 技术的关系:**
        * **CSS:**  对应 CSS 的 `column-rule` 相关属性。
    * **用户/编程常见的使用错误:**
        * 列规则的样式、颜色或宽度设置不正确。

**用户操作如何到达这里 (调试线索):**

1. **加载网页:** 当用户打开一个网页时，Blink 渲染引擎开始解析 HTML、CSS 和 JavaScript。
2. **布局计算:** 渲染引擎会根据 HTML 结构和 CSS 样式计算元素的布局信息，生成 LayoutObject 树。
3. **片段化:**  为了优化绘制，LayoutObject 树会被转换为 Fragment 树，其中 `BoxFragment` 是表示盒模型的片段。
4. **绘制准备:**  渲染引擎创建一个 `PaintInfo` 对象，包含当前的绘制阶段、裁剪区域等信息。
5. **调用 `BoxFragmentPainter::Paint`:**  当需要绘制一个 `BoxFragment` 时，会创建 `BoxFragmentPainter` 对象并调用其 `Paint` 方法。
6. **根据绘制阶段调用相应的绘制函数:**  `Paint` 方法会根据 `paint_info.phase` 的值，调用上述不同的绘制函数，例如：
    * **`paint_info.phase == PaintPhase::kForeground`:**  可能会调用 `PaintInlineChildren` 或 `PaintBlockChildren`。
    * **`paint_info.phase == PaintPhase::kBackground`:** 可能会调用 `PaintBoxDecorationBackground`。
    * **用户滚动页面:**  可能触发重绘，从而再次执行这些绘制函数。
    * **CSS 样式更改:**  通过 JavaScript 或 CSS 动态修改样式，会导致重新布局和重绘。
    * **打印网页:**  会触发分页布局和 `PaintCurrentPageContainer` 的调用.

**总结本部分的功能:**

这部分 `BoxFragmentPainter` 的代码专注于 **绘制 `BoxFragment` 的内容和装饰**。它根据元素的类型（内联、块级、浮动）、布局模式（分页、多列）和 CSS 样式，精细地控制着各种视觉元素的渲染过程，包括文本、背景、边框、阴影、遮罩以及多列布局中的分隔线。 这部分代码是 Blink 渲染引擎核心绘制流程的关键组成部分，确保了网页内容的正确呈现。

Prompt: 
```
这是目录为blink/renderer/core/paint/box_fragment_painter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能

"""
gment with inline children, without a paint fragment. See:
  // http://crbug.com/1022545
  if (!items_ || layout_object->NeedsLayout()) {
    return;
  }

  // MathML operators paint text (for example enlarged/stretched) content
  // themselves using MathMLPainter.
  if (box_fragment_.IsMathMLOperator()) [[unlikely]] {
    return;
  }

  // Trying to rule out a null GraphicsContext, see: https://crbug.com/1040298
  CHECK(&paint_info.context);

  // Check if there were contents to be painted and return early if none.
  // The union of |ContentsInkOverflow()| and |LocalRect()| covers the rect to
  // check, in both cases of:
  // 1. Painting non-scrolling contents.
  // 2. Painting scrolling contents.
  // For 1, check with |ContentsInkOverflow()|, except when there is no
  // overflow, in which case check with |LocalRect()|. For 2, check with
  // |ScrollableOverflow()|, but this can be approximiated with
  // |ContentsInkOverflow()|.
  PhysicalRect content_ink_rect = box_fragment_.LocalRect();
  content_ink_rect.Unite(box_fragment_.ContentsInkOverflowRect());
  if (!paint_info.IntersectsCullRect(content_ink_rect, paint_offset)) {
    return;
  }

  DCHECK(items_);
  EnsureInlineContext();
  InlineCursor children(box_fragment_, *items_);
  std::optional<ScopedSVGPaintState> paint_state;
  if (box_fragment_.IsSvgText())
    paint_state.emplace(*box_fragment_.GetLayoutObject(), paint_info);

  PaintInfo child_paint_info(paint_info.ForDescendants());

  // Only paint during the foreground/selection phases.
  if (child_paint_info.phase != PaintPhase::kForeground &&
      child_paint_info.phase != PaintPhase::kForcedColorsModeBackplate &&
      child_paint_info.phase != PaintPhase::kSelectionDragImage &&
      child_paint_info.phase != PaintPhase::kTextClip &&
      child_paint_info.phase != PaintPhase::kMask &&
      child_paint_info.phase != PaintPhase::kDescendantOutlinesOnly &&
      child_paint_info.phase != PaintPhase::kOutline) {
    if (ShouldPaintDescendantBlockBackgrounds(child_paint_info.phase))
        [[unlikely]] {
      // When block-in-inline, block backgrounds need to be painted.
      PaintBoxDecorationBackgroundForBlockInInline(&children, child_paint_info,
                                                   paint_offset);
    }
    return;
  }

  if (child_paint_info.phase == PaintPhase::kForeground &&
      child_paint_info.ShouldAddUrlMetadata()) {
    // TODO(crbug.com/1392701): Avoid walking the LayoutObject tree (which is
    // what AddURLRectsForInlineChildrenRecursively() does). We should walk the
    // fragment tree instead (if we can figure out how to deal with culled
    // inlines - or get rid of them). Walking the LayoutObject tree means that
    // we'll visit every link in the container for each fragment generated,
    // leading to duplicate entries. This is only fine as long as the absolute
    // offsets is the same every time a given link is visited. Otherwise links
    // might end up as unclickable in the resulting PDF. So make sure that the
    // paint offset relative to the first fragment generated by this
    // container. This matches legacy engine behavior.
    PhysicalOffset paint_offset_for_first_fragment =
        paint_offset - OffsetInStitchedFragments(box_fragment_);
    AddURLRectsForInlineChildrenRecursively(*layout_object, child_paint_info,
                                            paint_offset_for_first_fragment);
  }

  // If we have no lines then we have no work to do.
  if (!children)
    return;

  if (child_paint_info.phase == PaintPhase::kForcedColorsModeBackplate &&
      box_fragment_.GetDocument().InForcedColorsMode()) {
    PaintBackplate(&children, child_paint_info, paint_offset);
    return;
  }

  DCHECK(children.HasRoot());
  PaintLineBoxChildItems(&children, child_paint_info, paint_offset);
}

void BoxFragmentPainter::PaintCurrentPageContainer(
    const PaintInfo& paint_info) {
  DCHECK(box_fragment_.IsPaginatedRoot());

  PaintInfo paint_info_for_descendants = paint_info.ForDescendants();
  // The correct page box fragment for the given page has been selected, and
  // that's all that's going to be painted now. The cull rect used during
  // printing is for the paginated content only, in the stitched coordinate
  // system with all the page areas stacked after oneanother. However, no
  // paginated content will be painted here (that's in separate paint layers),
  // only page box decorations and margin fragments.
  paint_info_for_descendants.SetCullRect(CullRect::Infinite());

  PaintInfo paint_info_for_page_container = paint_info_for_descendants;
  // We only want the page container to paint itself and return (and then handle
  // its children on our own here, further below).
  paint_info_for_page_container.SetDescendantPaintingBlocked();

  const PaginationState* pagination_state =
      box_fragment_.GetDocument().View()->GetPaginationState();
  wtf_size_t page_index = pagination_state->CurrentPageIndex();

  const auto& page_container =
      To<PhysicalBoxFragment>(*box_fragment_.Children()[page_index]);
  BoxFragmentPainter(page_container).Paint(paint_info_for_page_container);

  // Paint children of the page container - that is the page border box
  // fragment, and any surrounding page margin boxes. Paint sorted by
  // z-index. We sort a vector of fragment indices, rather than sorting a
  // temporary list of fragments directly, as that would involve oilpan
  // allocations and garbage for no reason.
  //
  // TODO(crbug.com/363031541) Although the page background and borders (and
  // outlines, etc) are painted at the correct time, the paginated document
  // contents (the page areas) will be painted on top of everything, since the
  // document root element, and anything contained by the initial containing
  // block, are separate layers.
  base::span<const PhysicalFragmentLink> children = page_container.Children();
  std::vector<wtf_size_t> indices;
  indices.resize(children.size());
  std::iota(indices.begin(), indices.end(), 0);
  std::stable_sort(
      indices.begin(), indices.end(), [&children](wtf_size_t a, wtf_size_t b) {
        return children[a]->Style().ZIndex() < children[b]->Style().ZIndex();
      });
  for (wtf_size_t index : indices) {
    const PhysicalFragmentLink& child = children[index];
    const auto& child_fragment = To<PhysicalBoxFragment>(*child);
    DCHECK(!child_fragment.HasSelfPaintingLayer());
    BoxFragmentPainter(child_fragment).Paint(paint_info_for_descendants);
  }
}

void BoxFragmentPainter::PaintBlockChildren(const PaintInfo& paint_info,
                                            PhysicalOffset paint_offset) {
  DCHECK(!box_fragment_.IsInlineFormattingContext());
  PaintInfo paint_info_for_descendants = paint_info.ForDescendants();
  for (const PhysicalFragmentLink& child : box_fragment_.Children()) {
    const PhysicalFragment& child_fragment = *child;
    DCHECK(child_fragment.IsBox());
    if (child_fragment.HasSelfPaintingLayer() || child_fragment.IsFloating())
      continue;
    PaintBlockChild(child, paint_info, paint_info_for_descendants,
                    paint_offset);
  }
}

void BoxFragmentPainter::PaintBlockChild(
    const PhysicalFragmentLink& child,
    const PaintInfo& paint_info,
    const PaintInfo& paint_info_for_descendants,
    PhysicalOffset paint_offset) {
  const PhysicalFragment& child_fragment = *child;
  DCHECK(child_fragment.IsBox());
  DCHECK(!child_fragment.HasSelfPaintingLayer());
  DCHECK(!child_fragment.IsFloating());
  const auto& box_child_fragment = To<PhysicalBoxFragment>(child_fragment);
  if (box_child_fragment.CanTraverse()) {
    if (box_child_fragment.IsFragmentainerBox()) {
      // It's normally FragmentData that provides us with the paint offset.
      // FragmentData is (at least currently) associated with a LayoutObject.
      // If we have no LayoutObject, we have no FragmentData, so we need to
      // calculate the offset on our own (which is very simple, anyway).
      // Bypass Paint() and jump directly to PaintObject(), to skip the code
      // that assumes that we have a LayoutObject (and FragmentData).
      PhysicalOffset child_offset = paint_offset + child.offset;

      // This is a fragmentainer, and when a node inside a fragmentation context
      // paints multiple block fragments, we need to distinguish between them
      // somehow, for paint caching to work. Therefore, establish a display item
      // scope here.
      unsigned identifier = FragmentainerUniqueIdentifier(box_child_fragment);
      ScopedDisplayItemFragment scope(paint_info.context, identifier);
      BoxFragmentPainter(box_child_fragment)
          .PaintObject(paint_info, child_offset);
      return;
    }

    BoxFragmentPainter(box_child_fragment).Paint(paint_info_for_descendants);
    return;
  }

  PaintFragment(box_child_fragment, paint_info_for_descendants);
}

void BoxFragmentPainter::PaintFloatingItems(const PaintInfo& paint_info,
                                            InlineCursor* cursor) {
  while (*cursor) {
    const FragmentItem* item = cursor->Current().Item();
    DCHECK(item);
    const PhysicalBoxFragment* child_fragment = item->BoxFragment();
    if (!child_fragment) {
      cursor->MoveToNext();
      continue;
    }
    if (child_fragment->HasSelfPaintingLayer()) {
      cursor->MoveToNextSkippingChildren();
      continue;
    }
    if (child_fragment->IsFloating()) {
      PaintInfo float_paint_info = FloatPaintInfo(paint_info);
      PaintFragment(*child_fragment, float_paint_info);
    } else if (child_fragment->IsBlockInInline() &&
               child_fragment->HasFloatingDescendantsForPaint()) {
      BoxFragmentPainter(*child_fragment).Paint(paint_info);
    }
    DCHECK(child_fragment->IsInlineBox() || !cursor->Current().HasChildren());
    cursor->MoveToNext();
  }
}

void BoxFragmentPainter::PaintFloatingChildren(
    const PhysicalFragment& container,
    const PaintInfo& paint_info) {
  DCHECK(container.HasFloatingDescendantsForPaint());
  const PaintInfo* local_paint_info = &paint_info;
  std::optional<ScopedPaintState> paint_state;
  std::optional<ScopedBoxContentsPaintState> contents_paint_state;
  if (const auto* box = DynamicTo<LayoutBox>(container.GetLayoutObject())) {
    paint_state.emplace(To<PhysicalBoxFragment>(container), paint_info);
    contents_paint_state.emplace(*paint_state, *box);
    local_paint_info = &contents_paint_state->GetPaintInfo();
  }

  DCHECK(container.HasFloatingDescendantsForPaint());

  for (const PhysicalFragmentLink& child : container.Children()) {
    const PhysicalFragment& child_fragment = *child;
    if (child_fragment.HasSelfPaintingLayer())
      continue;

    if (child_fragment.IsFloating()) {
      PaintFragment(To<PhysicalBoxFragment>(child_fragment),
                    FloatPaintInfo(*local_paint_info));
      continue;
    }

    // Any non-floated children which paint atomically shouldn't be traversed.
    if (child_fragment.IsPaintedAtomically())
      continue;

    // The selection paint traversal is special. We will visit all fragments
    // (including floats) in the normal paint traversal. There isn't any point
    // performing the special float traversal here.
    if (local_paint_info->phase == PaintPhase::kSelectionDragImage)
      continue;

    if (!child_fragment.HasFloatingDescendantsForPaint())
      continue;

    if (child_fragment.HasNonVisibleOverflow()) {
      // We need to properly visit this fragment for painting, rather than
      // jumping directly to its children (which is what we normally do when
      // looking for floats), in order to set up the clip rectangle.
      BoxFragmentPainter(To<PhysicalBoxFragment>(child_fragment))
          .Paint(*local_paint_info);
      continue;
    }

    if (child_fragment.IsFragmentainerBox()) {
      // This is a fragmentainer, and when node inside a fragmentation context
      // paints multiple block fragments, we need to distinguish between them
      // somehow, for paint caching to work. Therefore, establish a display item
      // scope here.
      unsigned identifier = FragmentainerUniqueIdentifier(
          To<PhysicalBoxFragment>(child_fragment));
      ScopedDisplayItemFragment scope(paint_info.context, identifier);
      PaintFloatingChildren(child_fragment, *local_paint_info);
    } else {
      PaintFloatingChildren(child_fragment, *local_paint_info);
    }
  }

  // Now process the inline formatting context, if any.
  //
  // TODO(mstensho): Clean up this. Now that floats no longer escape their
  // inline formatting context when fragmented, we should only have to one of
  // these things; either walk the inline items, OR walk the box fragment
  // children (above).
  if (const PhysicalBoxFragment* box =
          DynamicTo<PhysicalBoxFragment>(&container)) {
    if (const FragmentItems* items = box->Items()) {
      InlineCursor cursor(*box, *items);
      PaintFloatingItems(*local_paint_info, &cursor);
      return;
    }
    if (inline_box_cursor_) {
      DCHECK(box->IsInlineBox());
      InlineCursor descendants = inline_box_cursor_->CursorForDescendants();
      PaintFloatingItems(*local_paint_info, &descendants);
      return;
    }
    DCHECK(!box->IsInlineBox());
  }
}

void BoxFragmentPainter::PaintFloats(const PaintInfo& paint_info) {
  DCHECK(GetPhysicalFragment().HasFloatingDescendantsForPaint() ||
         !GetPhysicalFragment().IsInlineFormattingContext());
  PaintFloatingChildren(GetPhysicalFragment(), paint_info);
}

void BoxFragmentPainter::PaintMask(const PaintInfo& paint_info,
                                   const PhysicalOffset& paint_offset) {
  DCHECK_EQ(PaintPhase::kMask, paint_info.phase);
  const PhysicalBoxFragment& physical_box_fragment = GetPhysicalFragment();
  const ComputedStyle& style = physical_box_fragment.Style();
  if (!style.HasMask() || !IsVisibleToPaint(physical_box_fragment, style))
    return;

  if (DrawingRecorder::UseCachedDrawingIfPossible(
          paint_info.context, GetDisplayItemClient(), paint_info.phase))
    return;

  if (physical_box_fragment.IsFieldsetContainer()) {
    FieldsetPainter(box_fragment_).PaintMask(paint_info, paint_offset);
    return;
  }

  DrawingRecorder recorder(paint_info.context, GetDisplayItemClient(),
                           paint_info.phase, VisualRect(paint_offset));
  PhysicalRect paint_rect(paint_offset, box_fragment_.Size());
  // TODO(eae): Switch to LayoutNG version of BoxBackgroundPaintContext.
  BoxBackgroundPaintContext bg_paint_context(
      *static_cast<const LayoutBoxModelObject*>(
          box_fragment_.GetLayoutObject()));
  PaintMaskImages(paint_info, paint_rect, *box_fragment_.GetLayoutObject(),
                  bg_paint_context, box_fragment_.SidesToInclude());
}

// TODO(kojii): This logic is kept in sync with BoxPainter. Not much efforts to
// eliminate LayoutObject dependency were done yet.
void BoxFragmentPainter::PaintBoxDecorationBackground(
    const PaintInfo& paint_info,
    const PhysicalOffset& paint_offset,
    bool suppress_box_decoration_background) {
  // TODO(mstensho): Break dependency on LayoutObject functionality.
  const LayoutObject& layout_object = *box_fragment_.GetLayoutObject();

  if (IsA<LayoutView>(layout_object) ||
      box_fragment_.GetBoxType() == PhysicalFragment::kPageContainer) {
    // The root background has a designated painter. For regular layout, this is
    // the LayoutView. For paginated layout, it's the background of the page box
    // that covers the entire area of a given page.
    ViewPainter(box_fragment_).PaintBoxDecorationBackground(paint_info);
    return;
  }

  PhysicalRect paint_rect;
  const DisplayItemClient* background_client = nullptr;
  std::optional<ScopedBoxContentsPaintState> contents_paint_state;
  gfx::Rect visual_rect;
  if (paint_info.IsPaintingBackgroundInContentsSpace()) {
    // For the case where we are painting the background in the contents space,
    // we need to include the entire overflow rect.
    const LayoutBox& layout_box = To<LayoutBox>(layout_object);
    paint_rect = layout_box.ScrollableOverflowRect();

    contents_paint_state.emplace(paint_info, paint_offset, layout_box,
                                 box_fragment_.GetFragmentData());
    paint_rect.Move(contents_paint_state->PaintOffset());

    // The background painting code assumes that the borders are part of the
    // paintRect so we expand the paintRect by the border size when painting the
    // background into the scrolling contents layer.
    paint_rect.Expand(layout_box.BorderOutsets());

    background_client = &layout_box.GetScrollableArea()
                             ->GetScrollingBackgroundDisplayItemClient();
    visual_rect = layout_box.GetScrollableArea()->ScrollingBackgroundVisualRect(
        paint_offset);
  } else {
    paint_rect.offset = paint_offset;
    paint_rect.size = box_fragment_.Size();
    background_client = &GetDisplayItemClient();
    visual_rect = VisualRect(paint_offset);
  }

  if (!suppress_box_decoration_background &&
      !(paint_info.IsPaintingBackgroundInContentsSpace() &&
        paint_info.ShouldSkipBackground())) {
    PaintBoxDecorationBackgroundWithRect(
        contents_paint_state ? contents_paint_state->GetPaintInfo()
                             : paint_info,
        visual_rect, paint_rect, *background_client);

    Element* element = DynamicTo<Element>(layout_object.GetNode());
    if (element && element->GetRegionCaptureCropId()) {
      paint_info.context.GetPaintController().RecordRegionCaptureData(
          *background_client, *(element->GetRegionCaptureCropId()),
          ToPixelSnappedRect(paint_rect));
    }
  }

  if (ShouldRecordHitTestData(paint_info)) {
    ObjectPainter(layout_object)
        .RecordHitTestData(paint_info, ToPixelSnappedRect(paint_rect),
                           *background_client);
  }

  // Record the scroll hit test after the non-scrolling background so
  // background squashing is not affected. Hit test order would be equivalent
  // if this were immediately before the non-scrolling background.
  if (!paint_info.IsPaintingBackgroundInContentsSpace())
    RecordScrollHitTestData(paint_info, *background_client);
}

void BoxFragmentPainter::PaintBoxDecorationBackgroundWithRect(
    const PaintInfo& paint_info,
    const gfx::Rect& visual_rect,
    const PhysicalRect& paint_rect,
    const DisplayItemClient& background_client) {
  BoxDecorationData box_decoration_data(paint_info, box_fragment_);
  if (!box_decoration_data.ShouldPaint() &&
      (!box_fragment_.IsTable() ||
       !TablePainter(box_fragment_).WillCheckColumnBackgrounds())) {
    return;
  }

  const auto& box = To<LayoutBox>(*box_fragment_.GetLayoutObject());
  std::optional<DisplayItemCacheSkipper> cache_skipper;
  if (RuntimeEnabledFeatures::PaintUnderInvalidationCheckingEnabled() &&
      ShouldSkipPaintUnderInvalidationChecking(box)) {
    cache_skipper.emplace(paint_info.context);
  }

  if (box.CanCompositeBackgroundAttachmentFixed() &&
      BoxBackgroundPaintContext::HasBackgroundFixedToViewport(box)) {
    PaintCompositeBackgroundAttachmentFixed(paint_info, background_client,
                                            box_decoration_data);
    if (box_decoration_data.ShouldPaintBorder()) {
      PaintBoxDecorationBackgroundWithDecorationData(
          paint_info, visual_rect, paint_rect, background_client,
          DisplayItem::kBoxDecorationBackground,
          box_decoration_data.BorderOnly());
    }
  } else {
    PaintBoxDecorationBackgroundWithDecorationData(
        paint_info, visual_rect, paint_rect, background_client,
        DisplayItem::kBoxDecorationBackground, box_decoration_data);
  }
}

void BoxFragmentPainter::PaintCompositeBackgroundAttachmentFixed(
    const PaintInfo& paint_info,
    const DisplayItemClient& background_client,
    const BoxDecorationData& box_decoration_data) {
  const auto& box = To<LayoutBox>(*box_fragment_.GetLayoutObject());
  DCHECK(box.CanCompositeBackgroundAttachmentFixed());
  const FragmentData* fragment_data = box_fragment_.GetFragmentData();
  if (!fragment_data) {
    return;
  }

  // Paint the background-attachment:fixed background in the view's transform
  // space, clipped by BackgroundClip.
  DCHECK(!box_decoration_data.IsPaintingBackgroundInContentsSpace());
  DCHECK(!box_decoration_data.HasAppearance());
  DCHECK(!box_decoration_data.ShouldPaintShadow());
  DCHECK(box_decoration_data.ShouldPaintBackground());
  DCHECK(fragment_data->PaintProperties());
  DCHECK(fragment_data->PaintProperties()->BackgroundClip());
  PropertyTreeStateOrAlias state(
      box.View()->FirstFragment().LocalBorderBoxProperties().Transform(),
      *fragment_data->PaintProperties()->BackgroundClip(),
      paint_info.context.GetPaintController()
          .CurrentPaintChunkProperties()
          .Effect());
  const ScrollableArea* layout_viewport = box.GetFrameView()->LayoutViewport();
  DCHECK(layout_viewport);
  gfx::Rect background_rect(layout_viewport->VisibleContentRect().size());
  ScopedPaintChunkProperties fixed_background_properties(
      paint_info.context.GetPaintController(), state, background_client,
      DisplayItem::kFixedAttachmentBackground);
  PaintBoxDecorationBackgroundWithDecorationData(
      paint_info, background_rect, PhysicalRect(background_rect),
      background_client, DisplayItem::kFixedAttachmentBackground,
      box_decoration_data.BackgroundOnly());
}

void BoxFragmentPainter::PaintBoxDecorationBackgroundWithDecorationData(
    const PaintInfo& paint_info,
    const gfx::Rect& visual_rect,
    const PhysicalRect& paint_rect,
    const DisplayItemClient& background_client,
    DisplayItem::Type display_item_type,
    const BoxDecorationData& box_decoration_data) {
  if (DrawingRecorder::UseCachedDrawingIfPossible(
          paint_info.context, background_client, display_item_type)) {
    return;
  }

  DrawingRecorder recorder(paint_info.context, background_client,
                           display_item_type, visual_rect);

  if (GetPhysicalFragment().IsFieldsetContainer()) {
    FieldsetPainter(box_fragment_)
        .PaintBoxDecorationBackground(paint_info, paint_rect,
                                      box_decoration_data);
  } else if (GetPhysicalFragment().IsTablePart()) {
    if (box_fragment_.IsTableCell()) {
      TableCellPainter(box_fragment_)
          .PaintBoxDecorationBackground(paint_info, paint_rect,
                                        box_decoration_data);
    } else if (box_fragment_.IsTableRow()) {
      TableRowPainter(box_fragment_)
          .PaintBoxDecorationBackground(paint_info, paint_rect,
                                        box_decoration_data);
    } else if (box_fragment_.IsTableSection()) {
      TableSectionPainter(box_fragment_)
          .PaintBoxDecorationBackground(paint_info, paint_rect,
                                        box_decoration_data);
    } else {
      DCHECK(box_fragment_.IsTable());
      TablePainter(box_fragment_)
          .PaintBoxDecorationBackground(paint_info, paint_rect,
                                        box_decoration_data);
    }
  } else {
    PaintBoxDecorationBackgroundWithRectImpl(paint_info, paint_rect,
                                             box_decoration_data);
  }
}

// TODO(kojii): This logic is kept in sync with BoxPainter. Not much efforts to
// eliminate LayoutObject dependency were done yet.
void BoxFragmentPainter::PaintBoxDecorationBackgroundWithRectImpl(
    const PaintInfo& paint_info,
    const PhysicalRect& paint_rect,
    const BoxDecorationData& box_decoration_data) {
  const LayoutObject& layout_object = *box_fragment_.GetLayoutObject();
  const LayoutBox& layout_box = To<LayoutBox>(layout_object);

  const ComputedStyle& style = box_fragment_.Style();

  GraphicsContextStateSaver state_saver(paint_info.context, false);

  if (box_decoration_data.ShouldPaintShadow()) {
    PaintNormalBoxShadow(paint_info, paint_rect, style,
                         box_fragment_.SidesToInclude(),
                         !box_decoration_data.ShouldPaintBackground());
  }

  bool needs_end_layer = false;
  if (!box_decoration_data.IsPaintingBackgroundInContentsSpace() &&
      BleedAvoidanceIsClipping(
          box_decoration_data.GetBackgroundBleedAvoidance())) {
    state_saver.Save();
    FloatRoundedRect border = RoundedBorderGeometry::PixelSnappedRoundedBorder(
        style, paint_rect, box_fragment_.SidesToInclude());
    paint_info.context.ClipRoundedRect(border);

    if (box_decoration_data.GetBackgroundBleedAvoidance() ==
        kBackgroundBleedClipLayer) {
      paint_info.context.BeginLayer();
      needs_end_layer = true;
    }
  }

  gfx::Rect snapped_paint_rect = ToPixelSnappedRect(paint_rect);
  ThemePainter& theme_painter = LayoutTheme::GetTheme().Painter();
  bool theme_painted =
      box_decoration_data.HasAppearance() &&
      !theme_painter.Paint(layout_box, paint_info, snapped_paint_rect);
  if (!theme_painted) {
    if (box_decoration_data.ShouldPaintBackground()) {
      PaintBackground(paint_info, paint_rect,
                      box_decoration_data.BackgroundColor(),
                      box_decoration_data.GetBackgroundBleedAvoidance());
    }
    if (box_decoration_data.HasAppearance()) {
      theme_painter.PaintDecorations(layout_box.GetNode(),
                                     layout_box.GetDocument(), style,
                                     paint_info, snapped_paint_rect);
    }
  }

  if (box_decoration_data.ShouldPaintShadow()) {
    if (layout_box.IsTableCell()) {
      PhysicalRect inner_rect = paint_rect;
      inner_rect.Contract(layout_box.BorderOutsets());
      // PaintInsetBoxShadowWithInnerRect doesn't subtract borders before
      // painting. We have to use it here after subtracting collapsed borders
      // above. PaintInsetBoxShadowWithBorderRect below subtracts the borders
      // specified on the style object, which doesn't account for border
      // collapsing.
      BoxPainterBase::PaintInsetBoxShadowWithInnerRect(paint_info, inner_rect,
                                                       style);
    } else {
      PaintInsetBoxShadowWithBorderRect(paint_info, paint_rect, style,
                                        box_fragment_.SidesToInclude());
    }
  }

  // The theme will tell us whether or not we should also paint the CSS
  // border.
  if (box_decoration_data.ShouldPaintBorder()) {
    if (!theme_painted) {
      theme_painted =
          box_decoration_data.HasAppearance() &&
          !LayoutTheme::GetTheme().Painter().PaintBorderOnly(
              layout_box.GetNode(), style, paint_info, snapped_paint_rect);
    }
    if (!theme_painted) {
      Node* generating_node = layout_object.GeneratingNode();
      const Document& document = layout_object.GetDocument();
      PaintBorder(*box_fragment_.GetLayoutObject(), document, generating_node,
                  paint_info, paint_rect, style,
                  box_decoration_data.GetBackgroundBleedAvoidance(),
                  box_fragment_.SidesToInclude());
    }
  }

  if (needs_end_layer)
    paint_info.context.EndLayer();
}

void BoxFragmentPainter::PaintBoxDecorationBackgroundForBlockInInline(
    InlineCursor* children,
    const PaintInfo& paint_info,
    const PhysicalOffset& paint_offset) {
  while (*children) {
    const FragmentItem* item = children->Current().Item();
    if (const PhysicalLineBoxFragment* line = item->LineBoxFragment()) {
      if (!line->IsBlockInInline()) {
        children->MoveToNextSkippingChildren();
        continue;
      }
    } else if (const PhysicalBoxFragment* fragment = item->BoxFragment()) {
      if (fragment->HasSelfPaintingLayer()) {
        children->MoveToNextSkippingChildren();
        continue;
      }
      if (fragment->IsBlockInInline() && !fragment->IsHiddenForPaint()) {
        PaintBoxItem(*item, *fragment, *children, paint_info, paint_offset);
      }
    }
    children->MoveToNext();
  }
}

void BoxFragmentPainter::PaintColumnRules(const PaintInfo& paint_info,
                                          const PhysicalOffset& paint_offset) {
  const ComputedStyle& style = box_fragment_.Style();
  DCHECK(box_fragment_.IsCSSBox());
  DCHECK(style.HasColumnRule());

  // https://www.w3.org/TR/css-multicol-1/#propdef-column-rule-style
  // interpret column-rule-style as in the collapsing border model
  EBorderStyle rule_style =
      ComputedStyle::CollapsedBorderStyle(style.ColumnRuleStyle());

  if (DrawingRecorder::UseCachedDrawingIfPossible(paint_info.context,
                                                  GetDisplayItemClient(),
                                                  DisplayItem::kColumnRules))
    return;

  DrawingRecorder recorder(paint_info.context, GetDisplayItemClient(),
                           DisplayItem::kColumnRules, gfx::Rect());

  const Color& rule_color =
      LayoutObject::ResolveColor(style, GetCSSPropertyColumnRuleColor());
  LayoutUnit rule_thickness(style.ColumnRuleWidth().GetLegacyValue());

  // Count all the spanners
  int span_count = 0;
  for (const PhysicalFragmentLink& child : box_fragment_.Children()) {
    if (!child->IsColumnBox()) {
      span_count++;
    }
  }

  PhysicalRect previous_column;
  bool past_first_column_in_row = false;
  AutoDarkMode auto_dark_mode(
      PaintAutoDarkMode(style, DarkModeFilter::ElementRole::kBackground));
  for (const PhysicalFragmentLink& child : box_fragment_.Children()) {
    if (!child->IsColumnBox()) {
      // Column spanner. Continue in the next row, if there are 2 columns or
      // more there.
      past_first_column_in_row = false;
      previous_column = PhysicalRect();

      span_count--;
      CHECK_GE(span_count, 0);
      continue;
    }

    PhysicalRect current_column(child.offset, child->Size());
    if (!past_first_column_in_row) {
      // Rules are painted *between* columns. Need to see if we have a second
      // one before painting anything.
      past_first_column_in_row = true;
      previous_column = current_column;
      continue;
    }

    PhysicalRect rule;
    BoxSide box_side;
    if (style.IsHorizontalWritingMode()) {
      LayoutUnit center;
      if (style.IsLeftToRightDirection()) {
        center = (previous_column.X() + current_column.Right()) / 2;
        box_side = BoxSide::kLeft;
      } else {
        center = (current_column.X() + previous_column.Right()) / 2;
        box_side = BoxSide::kRight;
      }

      // Paint column rules as tall as the entire multicol container, but only
      // when we're past all spanners.
      LayoutUnit rule_length;
      if (!span_count) {
        const LayoutUnit column_box_bottom = box_fragment_.Size().height -
                                             box_fragment_.Borders().bottom -
                                             box_fragment_.Padding().bottom -
                                             box_fragment_.OwnerLayoutBox()
                                                 ->ComputeLogicalScrollbars()
                                                 .block_end;
        rule_length = column_box_bottom - previous_column.offset.top;
        // For the case when the border or the padding is included in the
        // multicol container.
        // TODO(layout-dev): Get rid of this clamping, and fix any underlying
        // issues
        rule_length = std::max(rule_length, previous_column.Height());
      } else {
        rule_length = previous_column.Height();
      }

      DCHECK_GE(rule_length, current_column.Height());
      rule.offset.top = previous_column.offset.top;
      rule.size.height = rule_length;
      rule.offset.left = center - rule_thickness / 2;
      rule.size.width = rule_thickness;
    } else {
      // Vertical writing-mode.
      const auto writing_direction = style.GetWritingDirection();
      LayoutUnit center;
      if (writing_direction.InlineEnd() == PhysicalDirection::kDown) {
        // Top to bottom.
        center = (previous_column.Y() + current_column.Bottom()) / 2;
        box_side = BoxSide::kTop;
      } else {
        // Bottom to top.
        center = (current_column.Y() + previous_column.Bottom()) / 2;
        box_side = BoxSide::kBottom;
      }

      LayoutUnit rule_length;
      LayoutUnit rule_left = previous_column.offset.left;
      if (!span_count) {
        if (writing_direction.BlockEnd() == PhysicalDirection::kRight) {
          const LayoutUnit column_box_right = box_fragment_.Size().width -
                                              box_fragment_.Borders().right -
                                              box_fragment_.Padding().right -
                                              box_fragment_.OwnerLayoutBox()
                
"""


```