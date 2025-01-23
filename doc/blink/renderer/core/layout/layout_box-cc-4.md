Response:
My thinking process for analyzing the provided code snippet goes like this:

1. **Identify the Core Subject:** The code is within the `LayoutBox` class in the Blink rendering engine. This immediately tells me the primary focus is on the layout and visual representation of HTML elements.

2. **Break Down by Function:** I go through each function definition within the provided snippet. For each function, I try to understand:
    * **Purpose:** What is the main goal of this function?  What problem does it solve?
    * **Inputs:** What data does the function take in (parameters)?
    * **Outputs:** What data does the function return?  Does it modify any internal state?
    * **Key Operations:** What are the important steps or calculations performed within the function?
    * **Connections to Other Concepts:** How does this function relate to other layout concepts like scrolling, overflow, painting, etc.?

3. **Look for Keywords and Patterns:**  I pay attention to recurring terms and phrases like:
    * `VisualOverflow`:  Indicates the function is likely dealing with how content exceeding the box's boundaries is handled.
    * `ScrollableOverflow`:  Points to the management of scrollbars and the area that can be scrolled.
    * `Fragments`: Suggests handling of elements that are split across multiple regions (like in multi-column layouts or paged media).
    * `PhysicalRect`, `PhysicalSize`, `PhysicalOffset`:  These likely represent concrete pixel-based dimensions and positions.
    * `StyleRef()`:  Indicates interaction with the CSS styling information associated with the element.
    * `Paint`: Suggests operations related to the rendering process.
    * `Anchor`: Points to CSS anchor positioning features.

4. **Infer Relationships with HTML, CSS, and JavaScript:** Based on the function names and the concepts they deal with, I try to connect them back to web technologies:
    * **HTML:** The `LayoutBox` represents an HTML element. Functions dealing with size, position, and overflow directly relate to how HTML content is presented.
    * **CSS:** `StyleRef()` clearly links to CSS properties. Functions managing overflow, clipping, and background painting are all influenced by CSS styles. Anchor positioning is also a CSS feature.
    * **JavaScript:** While this specific code is C++, it's part of the rendering engine that *interprets* and *applies* styles often manipulated by JavaScript. For example, JavaScript can dynamically change CSS properties that affect visual overflow or trigger scrolling.

5. **Identify Logic and Assumptions:** For functions performing calculations or making decisions, I look for the underlying logic. I consider what assumptions are being made about the input data or the state of the element. This helps in constructing potential input/output examples.

6. **Consider Potential Errors:** I think about common mistakes developers might make when using the features these functions implement. For instance, incorrect CSS `overflow` settings could lead to unexpected visual results.

7. **Synthesize and Summarize:**  Finally, I group the functions by their general purpose (e.g., managing visual overflow, handling scrolling, dealing with fragmentation) and create a concise summary of the overall functionality of this part of the `LayoutBox` class. I also explicitly list the relationships with HTML, CSS, and JavaScript, provide examples, and mention common errors.

**Applying this to the given snippet, here's a more detailed breakdown of how I arrived at the answer:**

* **`RecalcScrollableOverflow`:** I see it iterating through layout results and their fragments, checking for child boxes, and using `RecalcFragmentScrollableOverflow`. This clearly relates to calculating the scrollable area based on the content.
* **`AddSelfVisualOverflow` and `AddContentsVisualOverflow`:** The names are self-explanatory. They add to the visual overflow information. The checks for `border_box` and `HasNonVisibleOverflow()` tell me about the conditions under which overflow is considered.
* **`UpdateHasSubpixelVisualEffectOutsets`:** This suggests optimizing rendering for effects that might not align perfectly with pixel boundaries.
* **`SetVisualOverflow` and `ClearVisualOverflow`:** These functions manage the overall visual overflow state. The connection to `OutlinePainter` indicates interaction with how outlines are rendered.
* **`CanUseFragmentsForVisualOverflow` and `CopyVisualOverflowFromFragments`:**  These deal with the complexities of handling visual overflow when an element is fragmented.
* **`HasUnsplittableScrollingOverflow` and `IsMonolithic`:**  These functions determine if a box should be treated as a single unit for layout purposes, which is relevant for things like pagination or avoiding breaks within scrollable areas.
* **`FirstLineHeight`:** This is specific to inline elements and their first line's height.
* **`BorderOutsetsForClipping`:**  This function calculates the area used for clipping content, considering different CSS box models.
* **`VisualOverflowRect`:**  This function combines the self and content overflow to determine the total visual overflow area, considering clipping.
* **`OffsetPoint`, `OffsetLeft`, `OffsetTop`:** These provide the position of the box relative to a parent.
* **`Size` and `ComputeSize`:** These calculate the dimensions of the box, taking into account fragmentation.
* **`LocationContainer`:** This determines the containing block for positioning purposes, with special handling for SVG elements.
* **`GetShapeOutsideInfo` and `GetCustomLayoutChild`:** These relate to more advanced CSS features like shapes and custom layout APIs.
* **`AddCustomLayoutChildIfNeeded` and `ClearCustomLayoutChild`:** These manage the lifecycle of custom layout children.
* **`DebugRect`:** This is likely for internal debugging.
* **`ComputeOverflowClipAxes`:** This determines which axes (horizontal, vertical, or both) should have overflow clipping applied.
* **`MutableForPainting::SavePreviousOverflowData`, `SetPreviousGeometryForLayoutShiftTracking`, `UpdateBackgroundPaintLocation`:** These are related to the rendering pipeline, specifically tracking changes for optimizations and layout shift detection.
* **`RasterEffectOutsetForRasterEffects`:**  Deals with expanding the visual area to accommodate raster effects.
* **`ResolvedDirection`:**  Determines the resolved text direction.
* **`OverrideTickmarks` and `InvalidatePaintForTickmarks`:** These are related to scrollbar tickmarks.
* **`HasInsetBoxShadow` and `BackgroundClipBorderBoxIsEquivalentToPaddingBox`:** These are optimization checks for background painting.
* **`ComputeBackgroundPaintLocation`:**  Determines where the background should be painted based on various factors.
* **`ComputeCanCompositeBackgroundAttachmentFixed`:** Checks conditions for optimizing fixed background attachments.
* **`IsFixedToView`:**  Determines if a fixed-position element is fixed to the viewport.
* **`ComputeStickyConstrainingRect`:** Calculates the constraints for sticky positioning.
* **`GetAnchorPositionScrollData`, `NeedsAnchorPositionScrollAdjustment`, `AnchorPositionScrollAdjustmentAfectedByViewportScrolling`, `AnchorPositionScrollTranslationOffset`:** These are all related to CSS anchor positioning and how it affects scrolling.
* **`ForEachAnchorQueryOnContainer`, `FindTargetAnchor`, `AcceptableImplicitAnchor`:**  These are core parts of the anchor positioning implementation, finding and validating anchor elements.
* **`NonOverflowingScrollRanges`, `OutOfFlowInsetsForGetComputedStyle`, `AccessibilityAnchor`, `DisplayLocksAffectedByAnchors`:** These relate to specific aspects like non-overflowing scroll regions, out-of-flow insets for computed styles, accessibility, and display locks related to anchor positioning.

By methodically examining each function and identifying the key concepts involved, I can build a comprehensive understanding of the code's functionality and its connections to web technologies.
这是 `blink/renderer/core/layout/layout_box.cc` 文件的第五部分，延续了对 `LayoutBox` 类的功能描述。根据提供的代码片段，可以归纳出以下功能：

**核心功能：视觉溢出（Visual Overflow）和滚动溢出（Scrollable Overflow）的管理**

这部分代码主要集中在 `LayoutBox` 如何计算、存储和管理其内容的视觉溢出和可滚动溢出。这对于正确渲染超出元素边界的内容至关重要。

**具体功能点：**

1. **重新计算可滚动溢出 (`RecalcScrollableOverflow`)：**
   - 遍历元素的布局结果 (`layout_results_`) 中的片段 (`PhysicalBoxFragment`)。
   - 如果片段包含子元素，则遍历这些子元素的后布局片段 (`PostLayoutBoxFragment`)，并递归调用子元素的 `RecalcScrollableOverflow` 方法。
   - 调用 `RecalcFragmentScrollableOverflow` 方法处理当前片段的可滚动溢出。
   - **功能:** 确定元素需要滚动才能显示完整内容的区域。
   - **与 HTML/CSS 关系:** 当 HTML 元素的 `overflow` 属性设置为 `auto`、`scroll`、`hidden` 或 `clip` 时，会触发可滚动溢出的计算。例如，一个 `<div>` 元素设置了 `overflow: auto` 并且其内容超出了其设定的宽高，就会产生可滚动溢出。

2. **添加自溢出和内容溢出 (`AddSelfVisualOverflow`, `AddContentsVisualOverflow`)：**
   - 接收一个矩形区域 (`PhysicalRect`)，代表溢出的范围。
   - `AddSelfVisualOverflow` 处理元素自身产生的视觉溢出，例如 `transform` 或 `filter` 导致的溢出。
   - `AddContentsVisualOverflow` 处理元素内容产生的视觉溢出。
   - 会检查溢出矩形是否为空，以及是否包含在元素的 border box 内，以避免不必要的计算。
   - 如果尚未设置视觉溢出模型 (`overflow_`)，则会创建。
   - **功能:** 记录元素及其内容超出其边界的视觉范围。
   - **与 HTML/CSS 关系:** 当元素的内容或视觉效果（如阴影、变换等）超出其 border box 时，会产生视觉溢出。CSS 的 `overflow` 属性会影响如何处理这些溢出。

3. **更新亚像素视觉效果外延 (`UpdateHasSubpixelVisualEffectOutsets`)：**
   - 检查给定的边距 (`PhysicalBoxStrut`) 是否包含非整数值。
   - 如果是，则在视觉溢出模型中标记存在亚像素的视觉效果外延。
   - **功能:** 优化渲染，处理可能由非整数值引起的亚像素级别的视觉效果溢出。
   - **与 CSS 关系:** 当 CSS 属性值（如边距、位置等）使用非整数的像素值时，可能会产生亚像素的视觉效果。

4. **设置视觉溢出 (`SetVisualOverflow`)：**
   - 清除之前的视觉溢出信息 (`ClearVisualOverflow`)。
   - 调用 `AddSelfVisualOverflow` 和 `AddContentsVisualOverflow` 添加新的溢出范围。
   - 计算溢出矩形与元素 border box 的差值，得到外延 (`outsets`)。
   - 调用 `UpdateHasSubpixelVisualEffectOutsets` 更新亚像素信息。
   - 如果元素有轮廓 (`outline`)，则比较外延和轮廓的偏移量，设置 `OutlineMayBeAffectedByDescendants` 标志。
   - **功能:** 集中管理和更新元素的视觉溢出信息。
   - **与 CSS 关系:**  `overflow`, `outline`, `transform`, `filter` 等 CSS 属性的变化会触发视觉溢出的重新计算和设置。

5. **清除视觉溢出 (`ClearVisualOverflow`)：**
   - 重置视觉溢出模型中的 `visual_overflow` 成员。
   - **功能:** 清除之前记录的视觉溢出信息。

6. **判断是否可以使用片段进行视觉溢出计算 (`CanUseFragmentsForVisualOverflow`)：**
   - 检查元素是否没有物理片段 (`PhysicalFragmentCount()`)，以及第一个片段是否可以使用片段进行墨水溢出 (`CanUseFragmentsForInkOverflow`)。
   - **功能:** 确定在元素被分片（例如在多列布局中）的情况下，是否可以使用片段化的信息来计算视觉溢出。

7. **从片段复制视觉溢出信息 (`CopyVisualOverflowFromFragments`, `CopyVisualOverflowFromFragmentsWithoutInvalidations`)：**
   - 用于处理元素被分片的情况，从各个片段的墨水溢出信息中汇总得到整个元素的视觉溢出信息。
   - 如果只有一个片段，则直接使用该片段的溢出信息。
   - 如果有多个片段，则根据书写模式 (`writing-mode`) 将各个片段的溢出范围拼接起来。
   - **功能:** 在分片场景下，准确计算元素的视觉溢出范围。
   - **与 HTML/CSS 关系:**  与 CSS 的多列布局 (`column-*`) 或分页媒体相关。

8. **判断是否存在不可分割的滚动溢出 (`HasUnsplittableScrollingOverflow`)：**
   - 当文档正在打印时，返回 `false`，允许分页。
   - 如果元素是滚动容器 (`IsScrollContainer`)，则返回 `true`。
   - **功能:** 确定是否应该将包含滚动条的元素视为一个整体，避免在分页或分列时将其分割。
   - **与 HTML/CSS 关系:**  与 `overflow: scroll` 或 `overflow: auto` 产生的滚动容器有关，也与打印样式有关。

9. **判断元素是否是不可分割的整体 (`IsMonolithic`)：**
   - 列举了一些应该被视为不可分割的元素类型，例如：
     - 被替换元素 (`ShouldBeConsideredAsReplaced`)
     - 具有不可分割滚动溢出的元素 (`HasUnsplittableScrollingOverflow`)
     - 书写模式的根元素 (`IsWritingModeRoot`)
     - 固定定位元素在打印时 (`IsFixedPositioned() && GetDocument().Printing() && IsA<LayoutView>(Container())`)
     - 应用了内容大小限制 (`ShouldApplySizeContainment`)
     - 框架集 (`IsFrameSet`)
     - 应用了行数限制 (`StyleRef().HasLineClamp()`)
     - 滚动条标记组 (`IsScrollMarkerGroup()`)
   - **功能:**  定义哪些元素在布局和渲染过程中应该被视为一个不可分割的单元。
   - **与 HTML/CSS 关系:**  涉及到各种 CSS 属性和元素类型，影响布局的断行和分片行为。

10. **获取首行高度 (`FirstLineHeight`)：**
    - 对于原子级别的行内元素，返回其高度（水平书写模式）或宽度（垂直书写模式）加上外边距。
    - **功能:** 获取行内元素的首行高度。
    - **与 HTML/CSS 关系:** 与行内元素的渲染和排版有关。

11. **获取用于裁剪的边框外延 (`BorderOutsetsForClipping`)：**
    - 根据 `overflow-clip-margin` CSS 属性计算用于裁剪的边框外延。
    - **功能:** 确定裁剪溢出内容时的边界。
    - **与 CSS 关系:**  与 CSS 属性 `overflow-clip-margin` 相关。

12. **获取视觉溢出矩形 (`VisualOverflowRect`)：**
    - 如果没有设置视觉溢出，则返回元素的 border box 矩形。
    - 考虑 mask 的影响。
    - 如果应用了 `overflow-clip-margin`，则计算裁剪后的溢出矩形。
    - 考虑 `overflow-clip-axes` 属性，只裁剪特定轴上的溢出。
    - **功能:** 获取元素最终的视觉溢出范围，考虑各种影响因素。
    - **与 HTML/CSS 关系:**  与 `overflow`, `mask`, `overflow-clip-margin`, `overflow-clip-axes` 等 CSS 属性密切相关。

**假设输入与输出 (逻辑推理示例)：**

**假设输入：**

```html
<div style="width: 100px; height: 50px; overflow: auto;">
  This is some long text that will overflow the div.
</div>
```

**预期输出 (针对 `RecalcScrollableOverflow`):**

- `RecalcScrollableOverflow` 方法会计算出该 `div` 元素的滚动区域。由于文本内容超出 `100px x 50px` 的范围，输出的 `RecalcScrollableOverflowResult` 将包含一个大于 `100px x 50px` 的矩形，表示需要滚动的区域。

**假设输入：**

```html
<div style="width: 50px; height: 50px; transform: translate(20px, 10px);">
  Content
</div>
```

**预期输出 (针对 `AddSelfVisualOverflow`):**

- 由于 `transform` 属性，元素在视觉上会偏移。`AddSelfVisualOverflow` 方法可能会被调用，并且接收到的 `PhysicalRect` 参数将反映出元素变换后的实际边界，可能会超出其原始 `50px x 50px` 的范围。

**用户或编程常见的使用错误：**

1. **忘记设置 `overflow` 属性导致内容溢出但不显示滚动条：** 用户可能期望内容超出容器时出现滚动条，但如果没有设置 `overflow: auto` 或 `overflow: scroll`，内容会直接溢出，不会出现滚动条。
2. **错误地假设视觉溢出等于滚动溢出：** 视觉溢出包括了由于 `transform`、`filter` 等效果产生的溢出，而滚动溢出是用户可以通过滚动条查看的区域。两者并不总是相同。
3. **在分片元素上错误地计算溢出：**  如果手动计算分片元素的溢出而没有使用 Blink 提供的 `CopyVisualOverflowFromFragments` 等方法，可能会得到不准确的结果，尤其是在处理复杂的书写模式和分片场景时。

**总结：**

这部分 `LayoutBox` 的代码主要负责管理元素的视觉溢出和可滚动溢出。它涉及到计算溢出范围、存储溢出信息以及处理分片元素的情况。这些功能与 HTML 结构和 CSS 样式密切相关，确保了浏览器能够正确地渲染超出元素边界的内容，并为用户提供相应的滚动机制。理解这些功能对于深入了解 Blink 渲染引擎的布局过程至关重要。

### 提示词
```
这是目录为blink/renderer/core/layout/layout_box.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
wPostLayoutScope here.
  PhysicalBoxFragment::AllowPostLayoutScope allow_post_layout_scope;
#endif
  RecalcScrollableOverflowResult result;
  for (auto& layout_result : layout_results_) {
    const auto& fragment =
        To<PhysicalBoxFragment>(layout_result->GetPhysicalFragment());
    if (fragment.HasItems()) {
      for (InlineCursor cursor(fragment); cursor; cursor.MoveToNext()) {
        const PhysicalBoxFragment* child =
            cursor.Current()->PostLayoutBoxFragment();
        if (!child || !child->GetLayoutObject()->IsBox())
          continue;
        result.Unite(
            child->MutableOwnerLayoutBox()->RecalcScrollableOverflow());
      }
    }

    RecalcFragmentScrollableOverflow(result, fragment);
  }

  return result;
}

void LayoutBox::AddSelfVisualOverflow(const PhysicalRect& rect) {
  NOT_DESTROYED();
  if (rect.IsEmpty())
    return;

  PhysicalRect border_box = PhysicalBorderBoxRect();
  if (border_box.Contains(rect))
    return;

  if (!VisualOverflowIsSet()) {
    if (!overflow_)
      overflow_ = MakeGarbageCollected<BoxOverflowModel>();

    overflow_->visual_overflow.emplace(border_box);
  }

  overflow_->visual_overflow->AddSelfVisualOverflow(rect);
}

void LayoutBox::AddContentsVisualOverflow(const PhysicalRect& rect) {
  NOT_DESTROYED();
  if (rect.IsEmpty())
    return;

  // If hasOverflowClip() we always save contents visual overflow because we
  // need it
  // e.g. to determine whether to apply rounded corner clip on contents.
  // Otherwise we save contents visual overflow only if it overflows the border
  // box.
  PhysicalRect border_box = PhysicalBorderBoxRect();
  if (!HasNonVisibleOverflow() && border_box.Contains(rect))
    return;

  if (!VisualOverflowIsSet()) {
    if (!overflow_)
      overflow_ = MakeGarbageCollected<BoxOverflowModel>();

    overflow_->visual_overflow.emplace(border_box);
  }
  overflow_->visual_overflow->AddContentsVisualOverflow(rect);
}

void LayoutBox::UpdateHasSubpixelVisualEffectOutsets(
    const PhysicalBoxStrut& outsets) {
  if (!VisualOverflowIsSet()) {
    return;
  }
  overflow_->visual_overflow->SetHasSubpixelVisualEffectOutsets(
      !outsets.top.IsInteger() || !outsets.right.IsInteger() ||
      !outsets.bottom.IsInteger() || !outsets.left.IsInteger());
}

void LayoutBox::SetVisualOverflow(const PhysicalRect& self,
                                  const PhysicalRect& contents) {
  ClearVisualOverflow();
  AddSelfVisualOverflow(self);
  AddContentsVisualOverflow(contents);
  if (!VisualOverflowIsSet())
    return;

  const PhysicalRect overflow_rect =
      overflow_->visual_overflow->SelfVisualOverflowRect();
  const PhysicalSize box_size = Size();
  const PhysicalBoxStrut outsets(
      -overflow_rect.Y(), overflow_rect.Right() - box_size.width,
      overflow_rect.Bottom() - box_size.height, -overflow_rect.X());
  UpdateHasSubpixelVisualEffectOutsets(outsets);

  // |OutlineMayBeAffectedByDescendants| is set whenever outline style
  // changes. Update to the actual value here.
  const ComputedStyle& style = StyleRef();
  if (style.HasOutline()) {
    const LayoutUnit outline_extent(OutlinePainter::OutlineOutsetExtent(
        style, OutlineInfo::GetFromStyle(style)));
    SetOutlineMayBeAffectedByDescendants(
        outsets.top != outline_extent || outsets.right != outline_extent ||
        outsets.bottom != outline_extent || outsets.left != outline_extent);
  }
}

void LayoutBox::ClearVisualOverflow() {
  NOT_DESTROYED();
  if (overflow_)
    overflow_->visual_overflow.reset();
  // overflow_ will be reset by MutableForPainting::ClearPreviousOverflowData()
  // if we don't need it to store previous overflow data.
}

bool LayoutBox::CanUseFragmentsForVisualOverflow() const {
  NOT_DESTROYED();
  // TODO(crbug.com/1144203): Legacy, or no-fragments-objects such as
  // table-column. What to do with them is TBD.
  if (!PhysicalFragmentCount())
    return false;
  const PhysicalBoxFragment& fragment = *GetPhysicalFragment(0);
  if (!fragment.CanUseFragmentsForInkOverflow())
    return false;
  return true;
}

// Copy visual overflow from |PhysicalFragments()|.
void LayoutBox::CopyVisualOverflowFromFragments() {
  NOT_DESTROYED();
  DCHECK(CanUseFragmentsForVisualOverflow());
  const PhysicalRect previous_visual_overflow =
      VisualOverflowRectAllowingUnset();
  CopyVisualOverflowFromFragmentsWithoutInvalidations();
  const PhysicalRect visual_overflow = VisualOverflowRect();
  if (visual_overflow == previous_visual_overflow)
    return;
  SetShouldCheckForPaintInvalidation();
}

void LayoutBox::CopyVisualOverflowFromFragmentsWithoutInvalidations() {
  NOT_DESTROYED();
  DCHECK(CanUseFragmentsForVisualOverflow());
  if (!PhysicalFragmentCount()) [[unlikely]] {
    DCHECK(IsLayoutTableCol());
    ClearVisualOverflow();
    return;
  }

  if (PhysicalFragmentCount() == 1) {
    const PhysicalBoxFragment& fragment = *GetPhysicalFragment(0);
    DCHECK(fragment.CanUseFragmentsForInkOverflow());
    if (!fragment.HasInkOverflow()) {
      ClearVisualOverflow();
      return;
    }
    SetVisualOverflow(fragment.SelfInkOverflowRect(),
                      fragment.ContentsInkOverflowRect());
    return;
  }

  // When block-fragmented, stitch visual overflows from all fragments.
  const LayoutBlock* cb = ContainingBlock();
  DCHECK(cb);
  const WritingMode writing_mode = cb->StyleRef().GetWritingMode();
  bool has_overflow = false;
  PhysicalRect self_rect;
  PhysicalRect contents_rect;
  const PhysicalBoxFragment* last_fragment = nullptr;
  for (const PhysicalBoxFragment& fragment : PhysicalFragments()) {
    DCHECK(fragment.CanUseFragmentsForInkOverflow());
    if (!fragment.HasInkOverflow()) {
      last_fragment = &fragment;
      continue;
    }
    has_overflow = true;

    PhysicalRect fragment_self_rect = fragment.SelfInkOverflowRect();
    PhysicalRect fragment_contents_rect = fragment.ContentsInkOverflowRect();

    // Stitch this fragment to the bottom of the last one in horizontal
    // writing mode, or to the right in vertical. Flipped blocks is handled
    // later, after the loop.
    if (last_fragment) {
      const BlockBreakToken* break_token = last_fragment->GetBreakToken();
      DCHECK(break_token);
      const LayoutUnit block_offset = break_token->ConsumedBlockSize();
      if (blink::IsHorizontalWritingMode(writing_mode)) {
        fragment_self_rect.offset.top += block_offset;
        fragment_contents_rect.offset.top += block_offset;
      } else {
        fragment_self_rect.offset.left += block_offset;
        fragment_contents_rect.offset.left += block_offset;
      }
    }
    last_fragment = &fragment;

    self_rect.Unite(fragment_self_rect);
    contents_rect.Unite(fragment_contents_rect);

    // The legacy engine doesn't understand our concept of repeated
    // fragments. Stop now. The overflow rectangle will represent the
    // fragment(s) generated under the first repeated root.
    if (fragment.GetBreakToken() && fragment.GetBreakToken()->IsRepeated()) {
      break;
    }
  }

  if (!has_overflow) {
    ClearVisualOverflow();
    return;
  }
  SetVisualOverflow(self_rect, contents_rect);
}

DISABLE_CFI_PERF
bool LayoutBox::HasUnsplittableScrollingOverflow() const {
  NOT_DESTROYED();
  // Fragmenting scrollbars is only problematic in interactive media, e.g.
  // multicol on a screen. If we're printing, which is non-interactive media, we
  // should allow objects with non-visible overflow to be paginated as normally.
  if (GetDocument().Printing())
    return false;

  // Treat any scrollable container as monolithic.
  return IsScrollContainer();
}

bool LayoutBox::IsMonolithic() const {
  NOT_DESTROYED();
  // TODO(almaher): Don't consider a writing mode root monolitic if
  // IsFlexibleBox(). The breakability should be handled at the item
  // level. (Likely same for Table and Grid).
  if (ShouldBeConsideredAsReplaced() || HasUnsplittableScrollingOverflow() ||
      (Parent() && IsWritingModeRoot()) ||
      (IsFixedPositioned() && GetDocument().Printing() &&
       IsA<LayoutView>(Container())) ||
      ShouldApplySizeContainment() || IsFrameSet() ||
      StyleRef().HasLineClamp() || IsScrollMarkerGroup()) {
    return true;
  }

  return false;
}

LayoutUnit LayoutBox::FirstLineHeight() const {
  if (IsAtomicInlineLevel()) {
    return FirstLineStyle()->IsHorizontalWritingMode()
               ? MarginHeight() + Size().height
               : MarginWidth() + Size().width;
  }
  return LayoutUnit();
}

PhysicalBoxStrut LayoutBox::BorderOutsetsForClipping() const {
  auto padding_box = -BorderOutsets();
  if (!ShouldApplyOverflowClipMargin())
    return padding_box;

  PhysicalBoxStrut overflow_clip_margin;
  switch (StyleRef().OverflowClipMargin()->GetReferenceBox()) {
    case StyleOverflowClipMargin::ReferenceBox::kBorderBox:
      break;
    case StyleOverflowClipMargin::ReferenceBox::kPaddingBox:
      overflow_clip_margin = padding_box;
      break;
    case StyleOverflowClipMargin::ReferenceBox::kContentBox:
      overflow_clip_margin = padding_box - PaddingOutsets();
      break;
  }

  return overflow_clip_margin.Inflate(
      StyleRef().OverflowClipMargin()->GetMargin());
}

PhysicalRect LayoutBox::VisualOverflowRect() const {
  NOT_DESTROYED();
  DCHECK(!IsLayoutMultiColumnSet());
  if (!VisualOverflowIsSet())
    return PhysicalBorderBoxRect();

  const PhysicalRect& self_visual_overflow_rect =
      overflow_->visual_overflow->SelfVisualOverflowRect();
  if (HasMask()) {
    return self_visual_overflow_rect;
  }

  const OverflowClipAxes overflow_clip_axes = GetOverflowClipAxes();
  if (ShouldApplyOverflowClipMargin()) {
    // We should apply overflow clip margin only if we clip overflow on both
    // axis.
    DCHECK_EQ(overflow_clip_axes, kOverflowClipBothAxis);
    const PhysicalRect& contents_visual_overflow_rect =
        overflow_->visual_overflow->ContentsVisualOverflowRect();
    if (!contents_visual_overflow_rect.IsEmpty()) {
      PhysicalRect result = PhysicalBorderBoxRect();
      PhysicalBoxStrut outsets = BorderOutsetsForClipping();
      result.ExpandEdges(outsets.top, outsets.right, outsets.bottom,
                         outsets.left);
      result.Intersect(contents_visual_overflow_rect);
      result.Unite(self_visual_overflow_rect);
      return result;
    }
  }

  if (overflow_clip_axes == kOverflowClipBothAxis)
    return self_visual_overflow_rect;

  PhysicalRect result =
      overflow_->visual_overflow->ContentsVisualOverflowRect();
  result.Unite(self_visual_overflow_rect);
  ApplyOverflowClip(overflow_clip_axes, self_visual_overflow_rect, result);
  return result;
}

#if DCHECK_IS_ON()
PhysicalRect LayoutBox::VisualOverflowRectAllowingUnset() const {
  NOT_DESTROYED();
  InkOverflow::ReadUnsetAsNoneScope read_unset_as_none;
  return VisualOverflowRect();
}

void LayoutBox::CheckIsVisualOverflowComputed() const {
  // TODO(crbug.com/1205708): There are still too many failures. Disable the
  // the check for now. Need to investigate the reason.
  return;
  /*
  if (InkOverflow::ReadUnsetAsNoneScope::IsActive())
    return;
  if (!CanUseFragmentsForVisualOverflow())
    return;
  // TODO(crbug.com/1203402): MathML needs some more work.
  if (IsMathML())
    return;
  for (const PhysicalBoxFragment& fragment : PhysicalFragments())
    DCHECK(fragment.IsInkOverflowComputed());
  */
}
#endif

PhysicalOffset LayoutBox::OffsetPoint(const Element* parent) const {
  NOT_DESTROYED();
  return AdjustedPositionRelativeTo(PhysicalLocation(), parent);
}

LayoutUnit LayoutBox::OffsetLeft(const Element* parent) const {
  NOT_DESTROYED();
  return OffsetPoint(parent).left;
}

LayoutUnit LayoutBox::OffsetTop(const Element* parent) const {
  NOT_DESTROYED();
  return OffsetPoint(parent).top;
}

PhysicalSize LayoutBox::Size() const {
  NOT_DESTROYED();
  if (!HasValidCachedGeometry()) {
    // const_cast in order to update the cached value.
    const_cast<LayoutBox*>(this)->SetHasValidCachedGeometry(true);
    const_cast<LayoutBox*>(this)->frame_size_ = ComputeSize();
  }
  return frame_size_;
}

PhysicalSize LayoutBox::ComputeSize() const {
  NOT_DESTROYED();
  const auto& results = GetLayoutResults();
  if (results.size() == 0) {
    return PhysicalSize();
  }
  const auto& first_fragment = results[0]->GetPhysicalFragment();
  if (results.size() == 1u) {
    return first_fragment.Size();
  }
  WritingModeConverter converter(first_fragment.Style().GetWritingDirection());
  const BlockBreakToken* previous_break_token = nullptr;
  LogicalSize size;
  for (const auto& result : results) {
    const auto& physical_fragment =
        To<PhysicalBoxFragment>(result->GetPhysicalFragment());
    LogicalSize fragment_logical_size =
        converter.ToLogical(physical_fragment.Size());
    if (physical_fragment.IsFirstForNode()) {
      // Inline-size will only be set at the first fragment. Subsequent
      // fragments may have different inline-size (either because fragmentainer
      // inline-size is variable, or e.g. because available inline-size is
      // affected by floats). The legacy engine doesn't handle variable
      // inline-size (since it doesn't really understand fragmentation).  This
      // means that things like offsetWidth won't work correctly (since that's
      // still being handled by the legacy engine), but at least layout,
      // painting and hit-testing will be correct.
      size = fragment_logical_size;
    } else {
      DCHECK(previous_break_token);
      size.block_size = fragment_logical_size.block_size +
                        previous_break_token->ConsumedBlockSizeForLegacy();
    }
    previous_break_token = physical_fragment.GetBreakToken();
    // Continue in order to update logical height, unless this fragment is
    // past the block-end of the generating node (happens with overflow) or
    // is a repeated one.
    if (!previous_break_token || previous_break_token->IsRepeated() ||
        previous_break_token->IsAtBlockEnd()) {
      break;
    }
  }
  return converter.ToPhysical(size);
}

LayoutBox* LayoutBox::LocationContainer() const {
  NOT_DESTROYED();
  // Location of a non-root SVG object derived from LayoutBox should not be
  // affected by writing-mode of the containing box (SVGRoot).
  if (IsSVGChild())
    return nullptr;

  // Normally the box's location is relative to its containing box.
  LayoutObject* container = Container();
  while (container && !container->IsBox())
    container = container->Container();
  return To<LayoutBox>(container);
}

ShapeOutsideInfo* LayoutBox::GetShapeOutsideInfo() const {
  NOT_DESTROYED();
  return ShapeOutsideInfo::Info(*this);
}

CustomLayoutChild* LayoutBox::GetCustomLayoutChild() const {
  NOT_DESTROYED();
  DCHECK(rare_data_);
  DCHECK(rare_data_->layout_child_);
  return rare_data_->layout_child_.Get();
}

void LayoutBox::AddCustomLayoutChildIfNeeded() {
  NOT_DESTROYED();
  if (!IsCustomItem())
    return;

  const AtomicString& name = Parent()->StyleRef().DisplayLayoutCustomName();
  LayoutWorklet* worklet = LayoutWorklet::From(*GetDocument().domWindow());
  const CSSLayoutDefinition* definition =
      worklet->Proxy()->FindDefinition(name);

  // If there isn't a definition yet, the web developer defined layout isn't
  // loaded yet (or is invalid). The layout tree will get re-attached when
  // loaded, so don't bother creating a script representation of this node yet.
  if (!definition)
    return;

  EnsureRareData().layout_child_ =
      MakeGarbageCollected<CustomLayoutChild>(*definition, BlockNode(this));
}

void LayoutBox::ClearCustomLayoutChild() {
  NOT_DESTROYED();
  if (!rare_data_)
    return;

  if (rare_data_->layout_child_)
    rare_data_->layout_child_->ClearLayoutNode();

  rare_data_->layout_child_ = nullptr;
}

PhysicalRect LayoutBox::DebugRect() const {
  NOT_DESTROYED();
  return PhysicalRect(PhysicalLocation(), Size());
}

OverflowClipAxes LayoutBox::ComputeOverflowClipAxes() const {
  NOT_DESTROYED();
  if (ShouldApplyPaintContainment() || HasControlClip())
    return kOverflowClipBothAxis;

  if (!RespectsCSSOverflow() || !HasNonVisibleOverflow())
    return kNoOverflowClip;

  if (IsScrollContainer())
    return kOverflowClipBothAxis;
  return (StyleRef().OverflowX() == EOverflow::kVisible ? kNoOverflowClip
                                                        : kOverflowClipX) |
         (StyleRef().OverflowY() == EOverflow::kVisible ? kNoOverflowClip
                                                        : kOverflowClipY);
}

void LayoutBox::MutableForPainting::SavePreviousOverflowData() {
  if (!GetLayoutBox().overflow_)
    GetLayoutBox().overflow_ = MakeGarbageCollected<BoxOverflowModel>();
  auto& previous_overflow = GetLayoutBox().overflow_->previous_overflow_data;
  if (!previous_overflow)
    previous_overflow.emplace();
  previous_overflow->previous_scrollable_overflow_rect =
      GetLayoutBox().ScrollableOverflowRect();
  previous_overflow->previous_visual_overflow_rect =
      GetLayoutBox().VisualOverflowRect();
  previous_overflow->previous_self_visual_overflow_rect =
      GetLayoutBox().SelfVisualOverflowRect();
}

void LayoutBox::MutableForPainting::SetPreviousGeometryForLayoutShiftTracking(
    const PhysicalOffset& paint_offset,
    const PhysicalSize& size,
    const PhysicalRect& visual_overflow_rect) {
  FirstFragment().SetPaintOffset(paint_offset);
  GetLayoutBox().previous_size_ = size;
  if (PhysicalRect(PhysicalOffset(), size).Contains(visual_overflow_rect))
    return;

  if (!GetLayoutBox().overflow_)
    GetLayoutBox().overflow_ = MakeGarbageCollected<BoxOverflowModel>();
  auto& previous_overflow = GetLayoutBox().overflow_->previous_overflow_data;
  if (!previous_overflow)
    previous_overflow.emplace();
  previous_overflow->previous_visual_overflow_rect = visual_overflow_rect;
  // Other previous rects don't matter because they are used for paint
  // invalidation and we always do full paint invalidation on reattachment.
}

void LayoutBox::MutableForPainting::UpdateBackgroundPaintLocation() {
  GetLayoutBox().SetBackgroundPaintLocation(
      GetLayoutBox().ComputeBackgroundPaintLocation());
}

RasterEffectOutset LayoutBox::VisualRectOutsetForRasterEffects() const {
  NOT_DESTROYED();
  // If the box has subpixel visual effect outsets, as the visual effect may be
  // painted along the pixel-snapped border box, the pixels on the anti-aliased
  // edge of the effect may overflow the calculated visual rect. Expand visual
  // rect by one pixel in the case.
  return VisualOverflowIsSet() &&
                 overflow_->visual_overflow->HasSubpixelVisualEffectOutsets()
             ? RasterEffectOutset::kWholePixel
             : RasterEffectOutset::kNone;
}

TextDirection LayoutBox::ResolvedDirection() const {
  NOT_DESTROYED();
  if (IsInline() && IsAtomicInlineLevel() &&
      IsInLayoutNGInlineFormattingContext()) {
    InlineCursor cursor;
    cursor.MoveTo(*this);
    if (cursor) {
      return cursor.Current().ResolvedDirection();
    }
  }
  return StyleRef().Direction();
}

void LayoutBox::OverrideTickmarks(Vector<gfx::Rect> tickmarks) {
  NOT_DESTROYED();
  GetScrollableArea()->SetTickmarksOverride(std::move(tickmarks));
  InvalidatePaintForTickmarks();
}

void LayoutBox::InvalidatePaintForTickmarks() {
  NOT_DESTROYED();
  ScrollableArea* scrollable_area = GetScrollableArea();
  if (!scrollable_area)
    return;
  Scrollbar* scrollbar = scrollable_area->VerticalScrollbar();
  if (!scrollbar)
    return;
  scrollbar->SetNeedsPaintInvalidation(static_cast<ScrollbarPart>(~kThumbPart));
}

static bool HasInsetBoxShadow(const ComputedStyle& style) {
  if (!style.BoxShadow())
    return false;
  for (const ShadowData& shadow : style.BoxShadow()->Shadows()) {
    if (shadow.Style() == ShadowStyle::kInset)
      return true;
  }
  return false;
}

// If all borders and scrollbars are opaque, then background-clip: border-box
// is equivalent to background-clip: padding-box.
bool LayoutBox::BackgroundClipBorderBoxIsEquivalentToPaddingBox() const {
  const auto* scrollable_area = GetScrollableArea();
  if (scrollable_area) {
    if (auto* scrollbar = scrollable_area->HorizontalScrollbar()) {
      if (!scrollbar->IsOverlayScrollbar() && !scrollbar->IsOpaque()) {
        return false;
      }
    }
    if (auto* scrollbar = scrollable_area->VerticalScrollbar()) {
      if (!scrollbar->IsOverlayScrollbar() && !scrollbar->IsOpaque()) {
        return false;
      }
    }
  }

  if (StyleRef().BorderTopWidth() &&
      (!ResolveColor(GetCSSPropertyBorderTopColor()).IsOpaque() ||
       StyleRef().BorderTopStyle() != EBorderStyle::kSolid)) {
    return false;
  }
  if (StyleRef().BorderRightWidth() &&
      (!ResolveColor(GetCSSPropertyBorderRightColor()).IsOpaque() ||
       StyleRef().BorderRightStyle() != EBorderStyle::kSolid)) {
    return false;
  }
  if (StyleRef().BorderBottomWidth() &&
      (!ResolveColor(GetCSSPropertyBorderBottomColor()).IsOpaque() ||
       StyleRef().BorderBottomStyle() != EBorderStyle::kSolid)) {
    return false;
  }
  if (StyleRef().BorderLeftWidth() &&
      (!ResolveColor(GetCSSPropertyBorderLeftColor()).IsOpaque() ||
       StyleRef().BorderLeftStyle() != EBorderStyle::kSolid)) {
    return false;
  }

  if (!StyleRef().IsScrollbarGutterAuto()) {
    return false;
  }

  return true;
}

BackgroundPaintLocation LayoutBox::ComputeBackgroundPaintLocation() const {
  NOT_DESTROYED();
  bool may_have_scrolling_layers_without_scrolling = IsA<LayoutView>(this);
  const auto* scrollable_area = GetScrollableArea();
  bool scrolls_overflow = scrollable_area && scrollable_area->ScrollsOverflow();
  if (!scrolls_overflow && !may_have_scrolling_layers_without_scrolling)
    return kBackgroundPaintInBorderBoxSpace;

  // If we care about LCD text, paint root backgrounds into scrolling contents
  // layer even if style suggests otherwise. (For non-root scrollers, we just
  // avoid compositing - see PLSA::ComputeNeedsCompositedScrolling.)
  if (IsA<LayoutView>(this) &&
      GetDocument().GetSettings()->GetLCDTextPreference() ==
          LCDTextPreference::kStronglyPreferred) {
    return kBackgroundPaintInContentsSpace;
  }

  // Inset box shadow is painted in the scrolling area above the background, and
  // it doesn't scroll, so the background can only be painted in the main layer.
  if (HasInsetBoxShadow(StyleRef()))
    return kBackgroundPaintInBorderBoxSpace;

  // For simplicity, assume any border image can have inset, like the above.
  if (StyleRef().BorderImage().GetImage()) {
    return kBackgroundPaintInBorderBoxSpace;
  }

  // Assume optimistically that the background can be painted in the scrolling
  // contents until we find otherwise.
  BackgroundPaintLocation paint_location = kBackgroundPaintInContentsSpace;

  Color background_color = ResolveColor(GetCSSPropertyBackgroundColor());
  const FillLayer* layer = &(StyleRef().BackgroundLayers());
  for (; layer; layer = layer->Next()) {
    if (layer->Attachment() == EFillAttachment::kLocal)
      continue;

    // The background color is either the only background or it's the
    // bottommost value from the background property (see final-bg-layer in
    // https://drafts.csswg.org/css-backgrounds/#the-background).
    if (!layer->GetImage() && !layer->Next() &&
        !background_color.IsFullyTransparent() &&
        StyleRef().IsScrollbarGutterAuto()) {
      // Solid color layers with an effective background clip of the padding box
      // can be treated as local.
      EFillBox clip = layer->Clip();
      if (clip == EFillBox::kPadding)
        continue;
      // A border box can be treated as a padding box if the border is opaque or
      // there is no border and we don't have custom scrollbars.
      if (clip == EFillBox::kBorder) {
        if (BackgroundClipBorderBoxIsEquivalentToPaddingBox())
          continue;
        // If we have an opaque background color, we can safely paint it into
        // both the scrolling contents layer and the graphics layer to preserve
        // LCD text. The background color is either the only background or
        // behind background-attachment:local images (ensured by previous
        // iterations of the loop). For the latter case, the first paint of the
        // images doesn't matter because it will be covered by the second paint
        // of the opaque color.
        if (background_color.IsOpaque()) {
          paint_location = kBackgroundPaintInBothSpaces;
          continue;
        }
      } else if (clip == EFillBox::kContent &&
                 StyleRef().PaddingTop().IsZero() &&
                 StyleRef().PaddingLeft().IsZero() &&
                 StyleRef().PaddingRight().IsZero() &&
                 StyleRef().PaddingBottom().IsZero()) {
        // A content fill box can be treated as a padding fill box if there is
        // no padding.
        continue;
      }
    }
    return kBackgroundPaintInBorderBoxSpace;
  }

  // It can't paint in the scrolling contents because it has different 3d
  // context than the scrolling contents.
  if (!StyleRef().Preserves3D() && Parent() &&
      Parent()->StyleRef().Preserves3D()) {
    return kBackgroundPaintInBorderBoxSpace;
  }

  return paint_location;
}

bool LayoutBox::ComputeCanCompositeBackgroundAttachmentFixed() const {
  NOT_DESTROYED();
  DCHECK(IsBackgroundAttachmentFixedObject());
  if (GetDocument().GetSettings()->GetLCDTextPreference() ==
      LCDTextPreference::kStronglyPreferred) {
    return false;
  }
  // The fixed attachment background must be the only background layer.
  if (StyleRef().BackgroundLayers().Next() ||
      StyleRef().BackgroundLayers().Clip() == EFillBox::kText) {
    return false;
  }
  // To support box shadow, we'll need to paint the outset and inset box
  // shadows in separate display items in case there are outset box shadow,
  // background, inset box shadow and border in paint order.
  if (StyleRef().BoxShadow()) {
    return false;
  }
  // The theme may paint the background differently for an appearance.
  if (StyleRef().HasEffectiveAppearance()) {
    return false;
  }
  // For now the BackgroundClip paint property node doesn't support rounded
  // corners. If we want to support this, we need to ensure
  // - there is no obvious bleeding issues, and
  // - both the fast path and the slow path of composited rounded clip work.
  if (StyleRef().HasBorderRadius()) {
    return false;
  }
  return true;
}

bool LayoutBox::IsFixedToView(
    const LayoutObject* container_for_fixed_position) const {
  if (!IsFixedPositioned())
    return false;

  const auto* container = container_for_fixed_position;
  if (!container)
    container = Container();
  else
    DCHECK_EQ(container, Container());
  return container->IsLayoutView();
}

PhysicalRect LayoutBox::ComputeStickyConstrainingRect() const {
  NOT_DESTROYED();
  DCHECK(IsScrollContainer());
  PhysicalRect constraining_rect(OverflowClipRect(PhysicalOffset()));
  constraining_rect.Move(PhysicalOffset(-BorderLeft() + PaddingLeft(),
                                        -BorderTop() + PaddingTop()));
  constraining_rect.ContractEdges(LayoutUnit(), PaddingLeft() + PaddingRight(),
                                  PaddingTop() + PaddingBottom(), LayoutUnit());
  return constraining_rect;
}

AnchorPositionScrollData* LayoutBox::GetAnchorPositionScrollData() const {
  if (Element* element = DynamicTo<Element>(GetNode())) {
    return element->GetAnchorPositionScrollData();
  }
  return nullptr;
}

bool LayoutBox::NeedsAnchorPositionScrollAdjustment() const {
  if (auto* data = GetAnchorPositionScrollData()) {
    return data->NeedsScrollAdjustment();
  }
  return false;
}

bool LayoutBox::AnchorPositionScrollAdjustmentAfectedByViewportScrolling()
    const {
  if (auto* data = GetAnchorPositionScrollData()) {
    return data->NeedsScrollAdjustment() &&
           data->IsAffectedByViewportScrolling();
  }
  return false;
}

PhysicalOffset LayoutBox::AnchorPositionScrollTranslationOffset() const {
  if (auto* data = GetAnchorPositionScrollData()) {
    return data->TranslationAsPhysicalOffset();
  }
  return PhysicalOffset();
}

namespace {

template <typename Function>
void ForEachAnchorQueryOnContainer(const LayoutBox& box, Function func) {
  const LayoutObject* container = box.Container();
  if (container->IsLayoutBlock()) {
    for (const PhysicalBoxFragment& fragment :
         To<LayoutBlock>(container)->PhysicalFragments()) {
      if (const PhysicalAnchorQuery* anchor_query = fragment.AnchorQuery()) {
        func(*anchor_query);
      }
    }
    return;
  }

  // Now the container is an inline box that's also an abspos containing block.
  CHECK(container->IsLayoutInline());
  const LayoutInline* inline_container = To<LayoutInline>(container);
  if (!inline_container->HasInlineFragments()) {
    return;
  }
  InlineCursor cursor;
  cursor.MoveTo(*container);
  for (; cursor; cursor.MoveToNextForSameLayoutObject()) {
    if (const PhysicalBoxFragment* fragment = cursor.Current().BoxFragment()) {
      if (const PhysicalAnchorQuery* anchor_query = fragment->AnchorQuery()) {
        func(*anchor_query);
      }
    }
  }
}

#if EXPENSIVE_DCHECKS_ARE_ON()
template <typename Function>
void AssertSameDataOnLayoutResults(
    const LayoutBox::LayoutResultList& layout_results,
    Function func) {
  // When an out-of-flow box is fragmented, the position fallback results on all
  // fragments should be the same.
  for (wtf_size_t i = 1; i < layout_results.size(); ++i) {
    DCHECK(func(layout_results[i]) == func(layout_results[i - 1]));
  }
}

#endif

}  // namespace

const LayoutObject* LayoutBox::FindTargetAnchor(
    const ScopedCSSName& anchor_name) const {
  if (!IsOutOfFlowPositioned()) {
    return nullptr;
  }

  // Go through the already built PhysicalAnchorQuery to avoid tree traversal.
  const LayoutObject* anchor = nullptr;
  auto search_for_anchor = [&](const PhysicalAnchorQuery& anchor_query) {
    if (const LayoutObject* current =
            anchor_query.AnchorLayoutObject(*this, &anchor_name)) {
      if (!anchor ||
          (anchor != current && anchor->IsBeforeInPreOrder(*current))) {
        anchor = current;
      }
    }
  };
  ForEachAnchorQueryOnContainer(*this, search_for_anchor);
  return anchor;
}

const LayoutObject* LayoutBox::AcceptableImplicitAnchor() const {
  if (!IsOutOfFlowPositioned()) {
    return nullptr;
  }
  Element* element = DynamicTo<Element>(GetNode());
  Element* anchor_element =
      element ? element->ImplicitAnchorElement() : nullptr;
  LayoutObject* anchor_layout_object =
      anchor_element ? anchor_element->GetLayoutObject() : nullptr;
  if (!anchor_layout_object) {
    return nullptr;
  }
  // Go through the already built PhysicalAnchorQuery to avoid tree traversal.
  bool is_acceptable_anchor = false;
  auto validate_anchor = [&](const PhysicalAnchorQuery& anchor_query) {
    if (anchor_query.AnchorLayoutObject(*this, anchor_layout_object)) {
      is_acceptable_anchor = true;
    }
  };
  ForEachAnchorQueryOnContainer(*this, validate_anchor);
  return is_acceptable_anchor ? anchor_layout_object : nullptr;
}

const HeapVector<NonOverflowingScrollRange>*
LayoutBox::NonOverflowingScrollRanges() const {
  const auto& layout_results = GetLayoutResults();
  if (layout_results.empty()) {
    return nullptr;
  }
  // We only need to check the first fragment, because when the box is
  // fragmented, position fallback results are duplicated on all fragments.
#if EXPENSIVE_DCHECKS_ARE_ON()
  for (wtf_size_t i = 1; i < layout_results.size(); ++i) {
    DCHECK(base::ValuesEquivalent(
        layout_results[i]->NonOverflowingScrollRanges(),
        layout_results[i - 1]->NonOverflowingScrollRanges()));
  }
#endif
  return layout_results.front()->NonOverflowingScrollRanges();
}

const BoxStrut& LayoutBox::OutOfFlowInsetsForGetComputedStyle() const {
  const auto& layout_results = GetLayoutResults();
  // We should call this function only after the node is laid out.
  CHECK(layout_results.size());
  // We only need to check the first fragment, because when the box is
  // fragmented, insets are duplicated on all fragments.
#if EXPENSIVE_DCHECKS_ARE_ON()
  AssertSameDataOnLayoutResults(layout_results, [](const auto& result) {
    return result->OutOfFlowInsetsForGetComputedStyle();
  });
#endif
  return GetLayoutResults().front()->OutOfFlowInsetsForGetComputedStyle();
}

Element* LayoutBox::AccessibilityAnchor() const {
  const auto& layout_results = GetLayoutResults();
  if (layout_results.empty()) {
    return nullptr;
  }
  return layout_results.front()->AccessibilityAnchor();
}

const HeapHashSet<Member<Element>>* LayoutBox::DisplayLocksAffectedByAnchors()
    const {
  const auto& layout_results = GetLayoutResults();
  if (l
```