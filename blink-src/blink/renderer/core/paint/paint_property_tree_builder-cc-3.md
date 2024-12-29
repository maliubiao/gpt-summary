Response:
The user wants a summary of the functionality of the provided C++ code snippet from `paint_property_tree_builder.cc`. I need to identify the core tasks performed by this code, focusing on its role in building the paint property tree within the Blink rendering engine.

Here's a breakdown of the code's responsibilities, related to the user's requests:

1. **Updating Paint Properties:** The code defines various functions like `UpdateOverflowControlsClip`, `UpdateBackgroundClip`, `UpdateInnerBorderRadiusClip`, `UpdateOverflowClip`, `UpdatePerspective`, `UpdateReplacedContentTransform`, `UpdateScrollAndScrollTranslation`, etc. These functions conditionally update specific paint properties based on the layout object's style and other factors.

2. **Handling Clipping:** Several functions deal with different types of clipping: overflow controls, background, border-radius, and general overflow. These functions calculate the clipping rectangles and update the corresponding `ClipPaintPropertyNode`.

3. **Managing Transforms:** Functions like `UpdatePerspective` and `UpdateReplacedContentTransform` handle the creation and updating of `TransformPaintPropertyNode` to apply transformations like perspective and transforms for replaced content.

4. **Dealing with Scrolling:** `UpdateScrollAndScrollTranslation` and its related functions (`UpdateScrollNode`, `UpdateOverflowControlEffects`, `UpdateScrollTranslation`) manage scroll-related paint properties, including the `ScrollPaintPropertyNode` and the `TransformPaintPropertyNode` for scroll translation.

5. **Handling Out-of-Flow Positioning:** `UpdateOutOfFlowContext` manages the paint context for absolutely and fixed positioned elements.

6. **Managing Isolation:**  `UpdateTransformIsolationNode`, `UpdateEffectIsolationNode`, and `UpdateClipIsolationNode` handle the creation of isolation nodes to create independent stacking contexts.

7. **Updating Paint Offset:** `UpdatePaintOffset` adjusts the paint offset for elements based on their positioning.

8. **Optimizations:** `SetNeedsPaintPropertyUpdateIfNeeded` is about optimizing paint invalidation.

Now, let's connect these functionalities to the user's specific requests:

*   **Function Listing:** I need to list the primary functions and what they achieve.
*   **Relationship to JavaScript, HTML, CSS:**  I need to explain how these C++ functions relate to the rendering of HTML elements styled with CSS, and how JavaScript might trigger changes that lead to this code being executed.
*   **Logical Inference (Input/Output):** I can provide simple examples of CSS properties and how they might influence the output (e.g., `overflow: hidden` leading to overflow clip).
*   **User/Programming Errors:** I can point out common CSS mistakes that might lead to unexpected clipping or scrolling behavior, which this code handles.
*   **User Operation to Reach Here:**  I need to trace back how a user interaction (like scrolling or a style change) might eventually lead to the execution of this C++ code.
*   **Part Summary:** Focus on the core responsibility of the current code snippet within the overall paint property tree building process.

**Overall Plan:**

1. Provide a concise summary of the file's function.
2. Explain the connection to HTML, CSS, and JavaScript with examples.
3. Give illustrative examples of input CSS and potential output (paint property changes).
4. Highlight common user errors in CSS that relate to the functionalities.
5. Describe the user interaction flow that triggers this code.
6. Summarize the specific role of this part of the code within the larger context.
好的，这是 `blink/renderer/core/paint/paint_property_tree_builder.cc` 文件的第 4 部分，主要负责构建和更新**片段（Fragment）级别的绘制属性树节点**。

**本部分的主要功能归纳如下：**

1. **管理各种类型的裁剪 (Clip) 属性节点：**
    *   **溢出控制条裁剪 (`UpdateOverflowControlsClip`)：**  处理滚动条等溢出控制元素的裁剪，确保它们被限制在元素的边框盒内。
    *   **背景裁剪 (`UpdateBackgroundClip`)：**  处理 `background-clip` CSS 属性，根据不同的取值（`content-box`, `padding-box` 等）裁剪元素的背景。
    *   **内圆角裁剪 (`UpdateInnerBorderRadiusClip`)：**  处理带有 `border-radius` 的元素的裁剪，确保内容不会溢出圆角区域。
    *   **溢出裁剪 (`UpdateOverflowClip`)：**  处理 `overflow: hidden`, `scroll`, `auto` 等属性引起的裁剪，限制内容在元素的溢出区域内。
    *   **CSS 裁剪 (`UpdateCssClip`)：**  处理 `clip-path` 或 `clip` 属性定义的裁剪。

2. **管理透视 (Perspective) 变换属性节点 (`UpdatePerspective`)：**
    *   当元素设置了 `perspective` CSS 属性时，创建或更新 `TransformPaintPropertyNode` 来应用 3D 透视效果。

3. **管理替换内容变换属性节点 (`UpdateReplacedContentTransform`)：**
    *   处理像 `<img>`, `<video>`, `<iframe>` 等替换元素的变换，例如 SVG 根元素的变换或嵌入内容的变换。

4. **管理滚动和滚动变换属性节点 (`UpdateScrollAndScrollTranslation`)：**
    *   **滚动属性节点 (`UpdateScrollNode`)：**  为可滚动元素创建或更新 `ScrollPaintPropertyNode`，记录滚动容器的尺寸、内容尺寸、用户是否可滚动等信息。
    *   **滚动效果属性节点 (`UpdateOverflowControlEffects`)：**  为滚动条（特别是覆盖滚动条）创建或更新 `EffectPaintPropertyNode`，用于应用滚动条的视觉效果。
    *   **滚动变换属性节点 (`UpdateScrollTranslation`)：**  创建或更新 `TransformPaintPropertyNode` 来表示滚动的偏移量。

**与 JavaScript, HTML, CSS 功能的关系及举例说明：**

*   **CSS：** 本部分代码的核心职责是根据 CSS 属性的值来构建和更新绘制属性树。
    *   **`overflow: hidden;` (溢出裁剪):**  `UpdateOverflowClip` 函数会计算裁剪矩形，确保超出元素边界的内容被隐藏。
        ```css
        .container {
          width: 100px;
          height: 100px;
          overflow: hidden;
        }
        .content {
          width: 200px;
          height: 200px;
          background-color: red;
        }
        ```
        **假设输入：** 一个 `div` 元素 `.container` 包含一个更大的 `div` 元素 `.content`。`.container` 的 CSS 中设置了 `overflow: hidden;`。
        **输出：** `UpdateOverflowClip` 会创建一个 `ClipPaintPropertyNode`，其裁剪区域大小为 `.container` 的尺寸，`.content` 超出的部分不会被绘制。
    *   **`border-radius: 10px;` (内圆角裁剪):** `UpdateInnerBorderRadiusClip` 函数会计算圆角矩形，作为裁剪区域。
        ```css
        .rounded {
          width: 100px;
          height: 100px;
          border-radius: 10px;
          background-color: blue;
        }
        ```
        **假设输入：** 一个 `div` 元素 `.rounded` 设置了 `border-radius`。
        **输出：** `UpdateInnerBorderRadiusClip` 会创建一个 `ClipPaintPropertyNode`，其裁剪区域是一个带有圆角的矩形。
    *   **`perspective: 300px;` (透视变换):** `UpdatePerspective` 函数会创建 `TransformPaintPropertyNode` 来应用透视变换。
        ```css
        .perspective-container {
          perspective: 300px;
        }
        .transformed {
          transform: rotateX(45deg);
          background-color: green;
        }
        ```
        **假设输入：**  一个父元素 `.perspective-container` 设置了 `perspective`，子元素 `.transformed` 设置了 3D 变换。
        **输出：** `UpdatePerspective` 会在 `.perspective-container` 上创建一个 `TransformPaintPropertyNode`，定义透视效果，影响子元素的 3D 渲染。
    *   **`overflow: scroll;` (滚动):** `UpdateScrollAndScrollTranslation` 相关函数会创建 `ScrollPaintPropertyNode` 和 `TransformPaintPropertyNode`。
        ```css
        .scrollable {
          width: 100px;
          height: 100px;
          overflow: scroll;
        }
        .long-content {
          height: 200px;
          background-color: yellow;
        }
        ```
        **假设输入：** 一个 `div` 元素 `.scrollable` 包含超出其高度的内容，并设置了 `overflow: scroll;`。
        **输出：** `UpdateScrollNode` 会创建一个 `ScrollPaintPropertyNode`，记录 `.scrollable` 的可滚动状态和尺寸。`UpdateScrollTranslation` 会创建一个 `TransformPaintPropertyNode`，其变换会随着用户的滚动而更新。

*   **HTML：** HTML 结构决定了元素的层叠顺序和包含关系，这些信息会被用来确定哪些元素需要应用裁剪或变换。
    *   例如，在一个嵌套的 `div` 结构中，父元素的 `overflow: hidden` 会影响子元素的渲染。

*   **JavaScript：** JavaScript 可以动态修改元素的样式，从而触发绘制属性树的重新构建。
    *   例如，通过 JavaScript 改变元素的 `overflow` 属性，会导致 `UpdateOverflowClip` 函数被调用。
    *   滚动事件 (e.g., `window.scrollTo()`) 会影响滚动变换属性节点的更新。

**用户或编程常见的使用错误举例说明：**

*   **错误地使用 `overflow: hidden` 导致内容被意外裁剪：** 用户可能希望隐藏滚动条，但错误地使用了 `overflow: hidden`，导致部分内容也被裁剪掉。
    ```css
    .container {
      width: 100px;
      height: 100px;
      overflow: hidden; /* 预期隐藏滚动条，但可能裁剪内容 */
    }
    .content {
      width: 120px;
    }
    ```
*   **忘记考虑 `border-radius` 导致的裁剪问题：** 用户可能没有考虑到元素的 `border-radius` 会影响其内部内容的裁剪，导致内容溢出圆角区域或者被意外裁剪。
    ```css
    .rounded-box {
      width: 100px;
      height: 100px;
      border-radius: 20px;
      padding: 10px;
    }
    .inner-content { /* 如果 inner-content 靠近边缘，可能会被圆角裁剪 */
      width: 90px;
      height: 90px;
      background-color: lightgray;
    }
    ```
*   **透视变换的父元素设置不当：** 如果透视变换的父元素没有正确设置，可能会导致 3D 效果不符合预期。
    ```html
    <div class="container">
      <div class="transformed">...</div>
    </div>
    ```
    ```css
    .transformed {
      transform: rotateX(45deg);
    }
    /* 缺少在 .container 上设置 perspective */
    ```

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中加载或访问一个网页。**
2. **浏览器解析 HTML、CSS 和 JavaScript 代码。**
3. **布局 (Layout) 阶段计算出页面上每个元素的位置和大小。**
4. **绘制 (Paint) 阶段开始构建绘制属性树。**
5. **当遍历到需要进行裁剪、应用变换或处理滚动的元素时，会调用 `FragmentPaintPropertyTreeBuilder` 的相应函数。**
    *   例如，如果用户看到一个带有 `overflow: hidden` 的 `div`，布局阶段确定了该 `div` 的几何信息，绘制阶段就会调用 `UpdateOverflowClip` 来创建相应的裁剪节点。
    *   如果用户滚动了一个设置了 `overflow: scroll` 的区域，滚动事件会被浏览器捕获，并触发重新绘制，导致 `UpdateScrollAndScrollTranslation` 相关函数被调用来更新滚动变换。
    *   如果 JavaScript 修改了元素的 `transform` 属性，也会触发重新绘制，并调用相应的变换更新函数。

**这是第 4 部分，共 6 部分，请归纳一下它的功能:**

作为构建绘制属性树的中间环节，**第 4 部分 `FragmentPaintPropertyTreeBuilder` 的主要职责是负责为单个渲染片段 (通常对应一个 HTML 元素或其一部分) 构建和更新各种关键的绘制属性节点，包括裁剪、透视变换和滚动相关的属性。** 它将布局阶段计算出的几何信息和 CSS 样式信息转换为绘制引擎可以理解的绘制属性树结构，为后续的绘制操作提供必要的信息。本部分关注的是更精细化的、基于单个元素或片段的属性设置，为构建完整的绘制属性树打下基础。

Prompt: 
```
这是目录为blink/renderer/core/paint/paint_property_tree_builder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共6部分，请归纳一下它的功能

"""
-overflow/#corner-clipping).
  return object.StyleRef().HasBorderRadius() && object.IsBox() &&
         NeedsOverflowClip(object) && object.ShouldClipOverflowAlongBothAxis();
}

void FragmentPaintPropertyTreeBuilder::UpdateOverflowControlsClip() {
  DCHECK(properties_);

  if (!NeedsPaintPropertyUpdate())
    return;

  if (NeedsOverflowControlsClip()) {
    // Clip overflow controls to the border box rect.
    const auto& clip_rect = PhysicalRect(context_.current.paint_offset,
                                         To<LayoutBox>(object_).Size());
    OnUpdateClip(properties_->UpdateOverflowControlsClip(
        *context_.current.clip,
        ClipPaintPropertyNode::State(*context_.current.transform,
                                     gfx::RectF(clip_rect),
                                     ToSnappedClipRect(clip_rect))));
  } else {
    OnClearClip(properties_->ClearOverflowControlsClip());
  }

  // We don't walk into custom scrollbars in PrePaintTreeWalk because
  // LayoutObjects under custom scrollbars don't support paint properties.
}

static bool NeedsBackgroundClip(const LayoutObject& object) {
  return object.CanCompositeBackgroundAttachmentFixed();
}

void FragmentPaintPropertyTreeBuilder::UpdateBackgroundClip() {
  DCHECK(properties_);

  if (!NeedsPaintPropertyUpdate()) {
    return;
  }

  if (IsMissingActualFragment()) {
    // TODO(crbug.com/1418917): Handle clipping correctly when the ancestor
    // fragment is missing. For now, don't apply any clipping in such
    // situations, since we risk overclipping.
    return;
  }

  if (NeedsBackgroundClip(object_)) {
    DCHECK(!object_.StyleRef().BackgroundLayers().Next());
    const auto& fragment = BoxFragment();
    PhysicalRect clip_rect(context_.current.paint_offset, fragment.Size());
    auto clip = object_.StyleRef().BackgroundLayers().Clip();
    if (clip == EFillBox::kContent || clip == EFillBox::kPadding) {
      PhysicalBoxStrut strut = fragment.Borders();
      if (clip == EFillBox::kContent) {
        strut += fragment.Padding();
      }
      strut.TruncateSides(fragment.SidesToInclude());
      clip_rect.Contract(strut);
    }
    OnUpdateClip(properties_->UpdateBackgroundClip(
        *context_.current.clip,
        ClipPaintPropertyNode::State(*context_.current.transform,
                                     gfx::RectF(clip_rect),
                                     ToSnappedClipRect(clip_rect))));
  } else {
    OnClearClip(properties_->ClearBackgroundClip());
  }

  // BackgroundClip doesn't have descendants, so it doesn't affect the
  // context_.current.affect descendants.clip.
}

static void AdjustRoundedClipForOverflowClipMargin(
    const LayoutBox& box,
    gfx::RectF& layout_clip_rect,
    FloatRoundedRect& paint_clip_rect) {
  const auto& style = box.StyleRef();
  auto overflow_clip_margin = style.OverflowClipMargin();
  if (!overflow_clip_margin || !box.ShouldApplyOverflowClipMargin())
    return;

  // The default rects map to the inner border-radius which is the padding-box.
  // First apply a margin for the reference-box.
  PhysicalBoxStrut outsets;
  switch (overflow_clip_margin->GetReferenceBox()) {
    case StyleOverflowClipMargin::ReferenceBox::kBorderBox:
      outsets = box.BorderOutsets();
      break;
    case StyleOverflowClipMargin::ReferenceBox::kPaddingBox:
      break;
    case StyleOverflowClipMargin::ReferenceBox::kContentBox:
      outsets = -box.PaddingOutsets();
      break;
  }

  outsets.Inflate(overflow_clip_margin->GetMargin());
  layout_clip_rect.Outset(gfx::OutsetsF(outsets));
  paint_clip_rect.OutsetForMarginOrShadow(gfx::OutsetsF(outsets));
}

void FragmentPaintPropertyTreeBuilder::UpdateInnerBorderRadiusClip() {
  DCHECK(properties_);

  if (NeedsPaintPropertyUpdate()) {
    if (IsMissingActualFragment()) {
      // TODO(crbug.com/1418917): Handle clipping correctly when the ancestor
      // fragment is missing. For now, don't apply any clipping in such
      // situations, since we risk overclipping.
      return;
    }
    if (NeedsInnerBorderRadiusClip(object_)) {
      const auto& box = To<LayoutBox>(object_);
      PhysicalRect box_rect(context_.current.paint_offset, box.Size());
      gfx::RectF layout_clip_rect =
          RoundedBorderGeometry::RoundedInnerBorder(box.StyleRef(), box_rect)
              .Rect();
      FloatRoundedRect paint_clip_rect =
          RoundedBorderGeometry::PixelSnappedRoundedInnerBorder(box.StyleRef(),
                                                                box_rect);

      gfx::Vector2dF offset(-OffsetInStitchedFragments(BoxFragment()));
      layout_clip_rect.Offset(offset);
      paint_clip_rect.Move(offset);

      AdjustRoundedClipForOverflowClipMargin(box, layout_clip_rect,
                                             paint_clip_rect);
      ClipPaintPropertyNode::State state(*context_.current.transform,
                                         layout_clip_rect, paint_clip_rect);
      OnUpdateClip(properties_->UpdateInnerBorderRadiusClip(
          *context_.current.clip, std::move(state)));
    } else {
      OnClearClip(properties_->ClearInnerBorderRadiusClip());
    }
  }

  if (auto* border_radius_clip = properties_->InnerBorderRadiusClip())
    context_.current.clip = border_radius_clip;
}

void FragmentPaintPropertyTreeBuilder::UpdateOverflowClip() {
  DCHECK(properties_);

  if (NeedsPaintPropertyUpdate()) {
    if (IsMissingActualFragment()) {
      // TODO(crbug.com/1418917): Handle clipping correctly when the ancestor
      // fragment is missing. For now, don't apply any clipping in such
      // situations, since we risk overclipping.
      return;
    }

    if (NeedsOverflowClip(object_)) {
      ClipPaintPropertyNode::State state(*context_.current.transform,
                                         gfx::RectF(), FloatRoundedRect());

      if (object_.IsLayoutReplaced() &&
          ReplacedElementAlwaysClipsToContentBox(To<LayoutReplaced>(object_))) {
        const auto& replaced = To<LayoutReplaced>(object_);

        // Videos need to be pre-snapped so that they line up with the
        // display_rect and can enable hardware overlays. Adjust the base rect
        // here, before applying padding and corner rounding.
        PhysicalRect content_rect(context_.current.paint_offset,
                                  replaced.Size());
        if (IsA<LayoutVideo>(replaced)) {
          content_rect =
              LayoutReplaced::PreSnappedRectForPersistentSizing(content_rect);
        }
        // LayoutReplaced clips the foreground by rounded content box.
        auto clip_rect =
            RoundedBorderGeometry::PixelSnappedRoundedBorderWithOutsets(
                replaced.StyleRef(), content_rect,
                PhysicalBoxStrut(
                    -(replaced.PaddingTop() + replaced.BorderTop()),
                    -(replaced.PaddingRight() + replaced.BorderRight()),
                    -(replaced.PaddingBottom() + replaced.BorderBottom()),
                    -(replaced.PaddingLeft() + replaced.BorderLeft())));
        if (replaced.IsLayoutEmbeddedContent()) {
          // Embedded objects are always sized to fit the content rect, but they
          // could overflow by 1px due to pre-snapping. Adjust clip rect to
          // match pre-snapped box as a special case.
          clip_rect.SetRect(
              gfx::RectF(clip_rect.Rect().origin(),
                         gfx::SizeF(replaced.ReplacedContentRect().size)));
        }
        // TODO(crbug.com/1248598): Should we use non-snapped clip rect for
        // the first parameter?
        state.SetClipRect(clip_rect.Rect(), clip_rect);
      } else if (object_.IsBox()) {
        const PhysicalBoxFragment& box_fragment = BoxFragment();
        PhysicalRect clip_rect =
            box_fragment.OverflowClipRect(context_.current.paint_offset,
                                          FindPreviousBreakToken(box_fragment));

        if (object_.IsLayoutReplaced()) {
          // TODO(crbug.com/1248598): Should we use non-snapped clip rect for
          // the first parameter?
          auto snapped_rect = ToSnappedClipRect(clip_rect);
          state.SetClipRect(snapped_rect.Rect(), snapped_rect);
        } else {
          state.SetClipRect(gfx::RectF(clip_rect),
                            ToSnappedClipRect(clip_rect));
        }

        state.layout_clip_rect_excluding_overlay_scrollbars =
            FloatClipRect(gfx::RectF(To<LayoutBox>(object_).OverflowClipRect(
                context_.current.paint_offset,
                kExcludeOverlayScrollbarSizeForHitTesting)));
      } else {
        DCHECK(object_.IsSVGViewportContainer());
        const auto& viewport_container =
            To<LayoutSVGViewportContainer>(object_);
        const auto clip_rect =
            viewport_container.LocalToSVGParentTransform().Inverse().MapRect(
                viewport_container.Viewport());
        // TODO(crbug.com/1248598): Should we use non-snapped clip rect for
        // the first parameter?
        state.SetClipRect(clip_rect, FloatRoundedRect(clip_rect));
      }
      OnUpdateClip(properties_->UpdateOverflowClip(*context_.current.clip,
                                                   std::move(state)));
    } else {
      OnClearClip(properties_->ClearOverflowClip());
    }
  }

  if (auto* overflow_clip = properties_->OverflowClip())
    context_.current.clip = overflow_clip;
}

static gfx::PointF PerspectiveOrigin(const LayoutBox& box) {
  const ComputedStyle& style = box.StyleRef();
  // Perspective origin has no effect without perspective.
  DCHECK(style.HasPerspective());
  return PointForLengthPoint(style.PerspectiveOrigin(), gfx::SizeF(box.Size()));
}

static bool NeedsPerspective(const LayoutObject& object) {
  return object.IsBox() && object.StyleRef().HasPerspective();
}

void FragmentPaintPropertyTreeBuilder::UpdatePerspective() {
  DCHECK(properties_);

  if (NeedsPaintPropertyUpdate()) {
    if (NeedsPerspective(object_)) {
      const ComputedStyle& style = object_.StyleRef();
      // The perspective node must not flatten (else nothing will get
      // perspective), but it should still extend the rendering context as
      // most transform nodes do.
      gfx::Transform matrix;
      matrix.ApplyPerspectiveDepth(style.UsedPerspective());
      TransformPaintPropertyNode::State state{
          {matrix,
           gfx::Point3F(PerspectiveOrigin(To<LayoutBox>(object_)) +
                        gfx::Vector2dF(context_.current.paint_offset))}};
      state.flattens_inherited_transform =
          context_.should_flatten_inherited_transform;
      state.rendering_context_id = context_.rendering_context_id;
      OnUpdateTransform(properties_->UpdatePerspective(
          *context_.current.transform, std::move(state)));
    } else {
      OnClearTransform(properties_->ClearPerspective());
    }
  }

  if (properties_->Perspective()) {
    context_.current.transform = properties_->Perspective();
    context_.should_flatten_inherited_transform = false;
  }
}

void FragmentPaintPropertyTreeBuilder::UpdateReplacedContentTransform() {
  DCHECK(properties_);

  if (NeedsPaintPropertyUpdate() && !NeedsReplacedContentTransform(object_)) {
    OnClearTransform(properties_->ClearReplacedContentTransform());
  } else if (NeedsPaintPropertyUpdate()) {
    AffineTransform content_to_parent_space;
    if (object_.IsSVGRoot()) {
      content_to_parent_space =
          SVGRootPainter(To<LayoutSVGRoot>(object_))
              .TransformToPixelSnappedBorderBox(context_.current.paint_offset);
    } else if (object_.IsLayoutEmbeddedContent()) {
      content_to_parent_space =
          To<LayoutEmbeddedContent>(object_).EmbeddedContentTransform();
    }
    if (!content_to_parent_space.IsIdentity()) {
      TransformPaintPropertyNode::State state;
      state.transform_and_origin = {content_to_parent_space.ToTransform()};
      state.flattens_inherited_transform =
          context_.should_flatten_inherited_transform;
      state.rendering_context_id = context_.rendering_context_id;
      OnUpdateTransform(properties_->UpdateReplacedContentTransform(
          *context_.current.transform, std::move(state)));
    } else {
      OnClearTransform(properties_->ClearReplacedContentTransform());
    }
  }

  if (properties_->ReplacedContentTransform()) {
    context_.current.transform = properties_->ReplacedContentTransform();
    context_.should_flatten_inherited_transform = true;
    context_.rendering_context_id = 0;
  }

  if (object_.IsSVGRoot()) {
    // SVG painters don't use paint offset. The paint offset is baked into
    // the transform node instead.
    context_.current.paint_offset = PhysicalOffset();
    context_.current.directly_composited_container_paint_offset_subpixel_delta =
        PhysicalOffset();
  }
}

MainThreadScrollingReasons
FragmentPaintPropertyTreeBuilder::GetMainThreadRepaintReasonsForScroll(
    bool user_scrollable) const {
  DCHECK(IsA<LayoutBox>(object_));
  auto* scrollable_area = To<LayoutBox>(object_).GetScrollableArea();
  DCHECK(scrollable_area);
  MainThreadScrollingReasons reasons = 0;
  if (full_context_.requires_main_thread_for_background_attachment_fixed) {
    reasons |=
        cc::MainThreadScrollingReason::kHasBackgroundAttachmentFixedObjects;
  }
  if (scrollable_area->BackgroundNeedsRepaintOnScroll()) {
    reasons |= cc::MainThreadScrollingReason::kBackgroundNeedsRepaintOnScroll;
  }
  // Use main-thread scrolling if the scroller is not user scrollable
  // because the cull rect is not expanded (see CanExpandForScroll in
  // cull_rect.cc), and the scroller is not registered in
  // LocalFrameView::UserScrollableAreas().
  // TODO(crbug.com/349864862): Even if we expand cull rect,
  // virtual/threaded-prefer-compositing/fast/scroll-behavior/overflow-hidden-*.html
  // will still time out, which will need investigating if we want to improve
  // scroll performance of non-user-scrollable scrollers.
  if (!user_scrollable) {
    reasons |= cc::MainThreadScrollingReason::kPreferNonCompositedScrolling;
  }
  DCHECK(cc::MainThreadScrollingReason::AreRepaintReasons(reasons));
  return reasons;
}

void FragmentPaintPropertyTreeBuilder::UpdateScrollAndScrollTranslation() {
  DCHECK(properties_);

  if (NeedsPaintPropertyUpdate()) {
    if (NeedsScrollAndScrollTranslation(
            object_, full_context_.direct_compositing_reasons)) {
      UpdateScrollNode();
      UpdateOverflowControlEffects();
      UpdateScrollTranslation();
    } else {
      OnClearScroll(properties_->ClearScroll());
      OnClearEffect(properties_->ClearVerticalScrollbarEffect());
      OnClearEffect(properties_->ClearHorizontalScrollbarEffect());
      OnClearEffect(properties_->ClearScrollCornerEffect());
      OnClearTransform(properties_->ClearScrollTranslation());
    }
  }

  if (properties_->Scroll())
    context_.current.scroll = properties_->Scroll();

  if (const auto* scroll_translation = properties_->ScrollTranslation()) {
    context_.current.transform = scroll_translation;
    // See comments for ScrollTranslation in object_paint_properties.h for the
    // reason of adding ScrollOrigin().
    context_.current.paint_offset +=
        PhysicalOffset(To<LayoutBox>(object_).ScrollOrigin());
    // A scroller creates a layout shift root, so we just calculate one scroll
    // offset delta without accumulation.
    context_.current.scroll_offset_to_layout_shift_root_delta =
        scroll_translation->Get2dTranslation() -
        full_context_.old_scroll_offset;
  }
}

void FragmentPaintPropertyTreeBuilder::UpdateScrollNode() {
  DCHECK(NeedsPaintPropertyUpdate());
  DCHECK(NeedsScrollAndScrollTranslation(
      object_, full_context_.direct_compositing_reasons));

  const auto& box = To<LayoutBox>(object_);
  PaintLayerScrollableArea* scrollable_area = box.GetScrollableArea();
  ScrollPaintPropertyNode::State state;

  PhysicalRect clip_rect = box.OverflowClipRect(context_.current.paint_offset);
  state.container_rect = ToPixelSnappedRect(clip_rect);
  state.contents_size =
      scrollable_area->PixelSnappedContentsSize(clip_rect.offset);
  state.overflow_clip_node = properties_->OverflowClip();
  state.user_scrollable_horizontal =
      scrollable_area->UserInputScrollable(kHorizontalScrollbar);
  state.user_scrollable_vertical =
      scrollable_area->UserInputScrollable(kVerticalScrollbar);

  if (!RuntimeEnabledFeatures::UnifiedScrollableAreasEnabled()) {
    if (state.user_scrollable_horizontal || state.user_scrollable_vertical) {
      object_.GetFrameView()->AddUserScrollableArea(*scrollable_area);
    } else {
      object_.GetFrameView()->RemoveUserScrollableArea(*scrollable_area);
    }
  }

  state.composited_scrolling_preference =
      static_cast<CompositedScrollingPreference>(
          full_context_.composited_scrolling_preference);
  state.main_thread_repaint_reasons = GetMainThreadRepaintReasonsForScroll(
      state.user_scrollable_horizontal || state.user_scrollable_vertical);

  state.compositor_element_id = scrollable_area->GetScrollElementId();

  state.overscroll_behavior =
      cc::OverscrollBehavior(static_cast<cc::OverscrollBehavior::Type>(
                                 box.StyleRef().OverscrollBehaviorX()),
                             static_cast<cc::OverscrollBehavior::Type>(
                                 box.StyleRef().OverscrollBehaviorY()));

  if (auto* data = scrollable_area->GetSnapContainerData()) {
    state.snap_container_data = *data;
  }

  OnUpdateScroll(
      properties_->UpdateScroll(*context_.current.scroll, std::move(state)));
}

void FragmentPaintPropertyTreeBuilder::UpdateOverflowControlEffects() {
  DCHECK(NeedsPaintPropertyUpdate());
  DCHECK(NeedsScrollAndScrollTranslation(
      object_, full_context_.direct_compositing_reasons));

  // While in a view transition, page content is painted into a "snapshot"
  // surface by creating a new effect node to force a separate surface.
  // e.g.:
  //    #Root
  //      +--ViewTransitionEffect
  //         +--PageContentEffect
  //            +--...
  // However, frame scrollbars paint after all other content so the paint
  // chunks look like this:
  // [
  //    ...
  //    FrameBackground (effect: ViewTransitionEffect),
  //    PageContent (effect: PageContentEffect),
  //    FrameScrollbar (effect ViewTransitionEffect),
  //    ...
  // ]
  // The non-contiguous node causes the creation of two compositor effect
  // nodes from this one paint effect node which isn't supported by view
  // transitions. Create a separate effect node, a child of the root, for
  // any frame scrollbars so that:
  // 1) they don't cause multiple compositor effect nodes for a view
  //    transition
  // 2) scrollbars aren't captured in the root snapshot.
  bool transition_forces_scrollbar_effect_nodes =
      object_.IsLayoutView() &&
      ViewTransitionUtils::GetTransition(object_.GetDocument());

  // Overflow controls are not clipped by InnerBorderRadiusClip or
  // OverflowClip, so the output clip should skip them.
  const auto* output_clip = context_.current.clip;
  if (const auto* clip_to_skip = properties_->InnerBorderRadiusClip()
                                     ? properties_->InnerBorderRadiusClip()
                                     : properties_->OverflowClip()) {
    output_clip = clip_to_skip->Parent();
  }

  auto* scrollable_area = To<LayoutBox>(object_).GetScrollableArea();
  auto setup_scrollbar_effect_node = [this, scrollable_area,
                                      transition_forces_scrollbar_effect_nodes,
                                      output_clip](
                                         ScrollbarOrientation orientation) {
    Scrollbar* scrollbar = scrollable_area->GetScrollbar(orientation);

    bool scrollbar_is_overlay = scrollbar && scrollbar->IsOverlayScrollbar();

    bool needs_effect_node =
        scrollbar &&
        (transition_forces_scrollbar_effect_nodes || scrollbar_is_overlay);

    if (needs_effect_node) {
      EffectPaintPropertyNode::State effect_state;
      effect_state.local_transform_space = context_.current.transform;
      effect_state.output_clip = output_clip;
      effect_state.compositor_element_id =
          scrollable_area->GetScrollbarElementId(orientation);

      if (scrollbar_is_overlay) {
        effect_state.direct_compositing_reasons =
            CompositingReason::kActiveOpacityAnimation;
      }

      const EffectPaintPropertyNodeOrAlias* parent =
          transition_forces_scrollbar_effect_nodes
              ? &EffectPaintPropertyNode::Root()
              : context_.current_effect;

      PaintPropertyChangeType change_type =
          orientation == ScrollbarOrientation::kHorizontalScrollbar
              ? properties_->UpdateHorizontalScrollbarEffect(
                    *parent, std::move(effect_state))
              : properties_->UpdateVerticalScrollbarEffect(
                    *parent, std::move(effect_state));
      OnUpdateEffect(change_type);
    } else {
      bool result = orientation == ScrollbarOrientation::kHorizontalScrollbar
                        ? properties_->ClearHorizontalScrollbarEffect()
                        : properties_->ClearVerticalScrollbarEffect();
      OnClearEffect(result);
    }
  };

  setup_scrollbar_effect_node(ScrollbarOrientation::kVerticalScrollbar);
  setup_scrollbar_effect_node(ScrollbarOrientation::kHorizontalScrollbar);

  bool has_scroll_corner =
      scrollable_area->HorizontalScrollbar() &&
      scrollable_area->VerticalScrollbar() &&
      !scrollable_area->VerticalScrollbar()->IsOverlayScrollbar();
  DCHECK(!has_scroll_corner ||
         !scrollable_area->HorizontalScrollbar()->IsOverlayScrollbar());

  if (transition_forces_scrollbar_effect_nodes && has_scroll_corner) {
    // The scroll corner needs to paint with the scrollbars during a
    // transition, for the same reason as explained above. Scroll corners
    // are only painted for non-overlay scrollbars.
    EffectPaintPropertyNode::State effect_state;
    effect_state.local_transform_space = context_.current.transform;
    effect_state.output_clip = output_clip;
    effect_state.compositor_element_id =
        scrollable_area->GetScrollCornerElementId();
    OnUpdateEffect(properties_->UpdateScrollCornerEffect(
        EffectPaintPropertyNode::Root(), std::move(effect_state)));
  } else {
    OnClearEffect(properties_->ClearScrollCornerEffect());
  }
}

void FragmentPaintPropertyTreeBuilder::UpdateScrollTranslation() {
  DCHECK(NeedsPaintPropertyUpdate());
  DCHECK(NeedsScrollAndScrollTranslation(
      object_, full_context_.direct_compositing_reasons));

  auto* scrollable_area = To<LayoutBox>(object_).GetScrollableArea();
  gfx::PointF scroll_position = scrollable_area->ScrollPosition();
  TransformPaintPropertyNode::State state{
      {gfx::Transform::MakeTranslation(-scroll_position.OffsetFromOrigin())}};
  if (!scrollable_area->PendingScrollAnchorAdjustment().IsZero()) {
    context_.current.pending_scroll_anchor_adjustment +=
        scrollable_area->PendingScrollAnchorAdjustment();
    scrollable_area->ClearPendingScrollAnchorAdjustment();
  }
  state.flattens_inherited_transform =
      context_.should_flatten_inherited_transform;
  state.rendering_context_id = context_.rendering_context_id;
  state.direct_compositing_reasons =
      full_context_.direct_compositing_reasons &
      CompositingReason::kDirectReasonsForScrollTranslationProperty;
  state.scroll = properties_->Scroll();

  // The scroll translation node always inherits backface visibility, which
  // means if scroll and transform are both present, we will use the
  // transform property tree node to determine visibility of the scrolling
  // contents.
  DCHECK_EQ(state.backface_visibility,
            TransformPaintPropertyNode::BackfaceVisibility::kInherited);

  auto effective_change_type = properties_->UpdateScrollTranslation(
      *context_.current.transform, std::move(state));
  // Even if effective_change_type is kUnchanged, we might still need to
  // DirectlyUpdateScrollOffsetTransform, in case the cc::TransformNode
  // was also updated in LayerTreeHost::ApplyCompositorChanges.
  if (effective_change_type <=
          PaintPropertyChangeType::kChangedOnlySimpleValues &&
      // In platform code, only scroll translations with scroll nodes are
      // treated as scroll translations with overlap testing treatment.
      // A scroll translation without a scroll node (see NeedsScrollNode)
      // needs full PaintArtifactCompositor update on scroll.
      properties_->Scroll()) {
    if (auto* paint_artifact_compositor =
            object_.GetFrameView()->GetPaintArtifactCompositor()) {
      bool updated =
          paint_artifact_compositor->DirectlyUpdateScrollOffsetTransform(
              *properties_->ScrollTranslation());
      if (updated && effective_change_type ==
                         PaintPropertyChangeType::kChangedOnlySimpleValues) {
        effective_change_type =
            PaintPropertyChangeType::kChangedOnlyCompositedValues;
        properties_->ScrollTranslation()->CompositorSimpleValuesUpdated();
      }
    }
  }
  OnUpdateScrollTranslation(effective_change_type);
}

void FragmentPaintPropertyTreeBuilder::UpdateOutOfFlowContext() {
  if (!object_.IsBoxModelObject() && !properties_)
    return;

  if (object_.CanContainAbsolutePositionObjects())
    context_.absolute_position = context_.current;

  if (IsA<LayoutView>(object_)) {
    const auto* initial_fixed_transform = context_.fixed_position.transform;

    context_.fixed_position = context_.current;
    context_.fixed_position.fixed_position_children_fixed_to_root = true;

    // Fixed position transform should not be affected.
    context_.fixed_position.transform = initial_fixed_transform;

    // Scrolling in a fixed position element should chain up through the
    // LayoutView.
    if (properties_->Scroll())
      context_.fixed_position.scroll = properties_->Scroll();
    if (properties_->ScrollTranslation()) {
      // Also undo the ScrollOrigin part in paint offset that was added when
      // ScrollTranslation was updated.
      context_.fixed_position.paint_offset -=
          PhysicalOffset(To<LayoutBox>(object_).ScrollOrigin());
    }
  } else if (object_.CanContainFixedPositionObjects()) {
    context_.fixed_position = context_.current;
    context_.fixed_position.fixed_position_children_fixed_to_root = false;
  } else if (properties_ && properties_->CssClip()) {
    // CSS clip applies to all descendants, even if this object is not a
    // containing block ancestor of the descendant. It is okay for
    // absolute-position descendants because having CSS clip implies being
    // absolute position container. However for fixed-position descendants we
    // need to insert the clip here if we are not a containing block ancestor of
    // them.
    auto* css_clip = properties_->CssClip();

    // Before we actually create anything, check whether in-flow context and
    // fixed-position context has exactly the same clip. Reuse if possible.
    if (context_.fixed_position.clip == css_clip->Parent()) {
      context_.fixed_position.clip = css_clip;
    } else {
      if (NeedsPaintPropertyUpdate()) {
        OnUpdateClip(properties_->UpdateCssClipFixedPosition(
            *context_.fixed_position.clip,
            ClipPaintPropertyNode::State(css_clip->LocalTransformSpace(),
                                         css_clip->LayoutClipRect().Rect(),
                                         css_clip->PaintClipRect())));
      }
      if (properties_->CssClipFixedPosition())
        context_.fixed_position.clip = properties_->CssClipFixedPosition();
      return;
    }
  }

  if (NeedsPaintPropertyUpdate() && properties_)
    OnClearClip(properties_->ClearCssClipFixedPosition());
}

void FragmentPaintPropertyTreeBuilder::UpdateTransformIsolationNode() {
  if (NeedsPaintPropertyUpdate()) {
    if (NeedsIsolationNodes(object_)) {
      OnUpdateTransform(properties_->UpdateTransformIsolationNode(
          *context_.current.transform));
    } else {
      OnClearTransform(properties_->ClearTransformIsolationNode());
    }
  }
  if (properties_->TransformIsolationNode())
    context_.current.transform = properties_->TransformIsolationNode();
}

void FragmentPaintPropertyTreeBuilder::UpdateEffectIsolationNode() {
  if (NeedsPaintPropertyUpdate()) {
    if (NeedsIsolationNodes(object_)) {
      OnUpdateEffect(
          properties_->UpdateEffectIsolationNode(*context_.current_effect));
    } else {
      OnClearEffect(properties_->ClearEffectIsolationNode());
    }
  }
  if (properties_->EffectIsolationNode())
    context_.current_effect = properties_->EffectIsolationNode();
}

void FragmentPaintPropertyTreeBuilder::UpdateClipIsolationNode() {
  if (NeedsPaintPropertyUpdate()) {
    if (NeedsIsolationNodes(object_)) {
      OnUpdateClip(
          properties_->UpdateClipIsolationNode(*context_.current.clip));
    } else {
      OnClearClip(properties_->ClearClipIsolationNode());
    }
  }
  if (properties_->ClipIsolationNode())
    context_.current.clip = properties_->ClipIsolationNode();
}

void FragmentPaintPropertyTreeBuilder::UpdatePaintOffset() {
  if (object_.IsBoxModelObject()) {
    const auto& box_model_object = To<LayoutBoxModelObject>(object_);
    switch (box_model_object.StyleRef().GetPosition()) {
      case EPosition::kStatic:
      case EPosition::kRelative:
        break;
      case EPosition::kAbsolute: {
        DCHECK_EQ(full_context_.container_for_absolute_position,
                  box_model_object.Container());
        SwitchToOOFContext(context_.absolute_position);
        break;
      }
      case EPosition::kSticky:
        break;
      case EPosition::kFixed: {
        DCHECK_EQ(full_context_.container_for_fixed_position,
                  box_model_object.Container());
        SwitchToOOFContext(context_.fixed_position);

        // Fixed-position elements that are fixed to the viewport have a
        // transform above the scroll of the LayoutView. Child content is
        // relative to that transform, and hence the fixed-position element.
        if (context_.fixed_position.fixed_position_children_fixed_to_root)
          context_.current.paint_offset_root = &box_model_object;
        break;
      }
      default:
        NOTREACHED();
    }
  }

  if (const auto* box = DynamicTo<LayoutBox>(&object_)) {
    if (pre_paint_info_) {
      context_.current.paint_offset += pre_paint_info_->paint_offset;

      // Determine whether we're inside block fragmentation or not. OOF
      // descendants need special treatment inside block fragmentation.
      context_.current.is_in_block_fragmentation =
          pre_paint_info_->fragmentainer_is_oof_containing_block &&
          !BoxFragment().IsMonolithic();
    } else {
      // TODO(pdr): Several calls in this function walk back up the tree to
      // calculate containers (e.g., physicalLocation,
      // offsetForInFlowPosition*).  The containing block and other containers
      // can be stored on PaintPropertyTreeBuilderFragmentContext instead of
      // recomputing them.
      context_.current.paint_offset += box->PhysicalLocation();
    }
  }

  context_.current.additional_offset_to_layout_shift_root_delta +=
      context_.pending_additional_offset_to_layout_shift_root_delta;
  context_.pending_additional_offset_to_layout_shift_root_delta =
      PhysicalOffset();
}

void FragmentPaintPropertyTreeBuilder::SetNeedsPaintPropertyUpdateIfNeeded() {
  if (PrePaintDisableSideEffectsScope::IsDisabled()) {
    return;
  }

  if (object_.HasLayer()) {
    PaintLayer* layer = To<LayoutBoxModelObject>(object_).Layer();
    layer->UpdateFilterReferenceBox();
  }

  if (!object_.IsBox())
    return;

  const LayoutBox& box = To<LayoutBox>(object_);

  if (box.IsLayoutReplaced() &&
      box.PreviousPhysicalContentBoxRect() != box.PhysicalContentBoxRect()) {
    box.GetMutableForPainting().SetOnlyThisNeedsPaintPropertyUpdate();
    if (box.IsLayoutEmbeddedContent()) {
      if (const auto* child_view =
              To<LayoutEmbeddedContent>(box).ChildLayoutView()) {
        child_view->GetMutableForPainting()
            .SetOnlyThisNeedsPaintPropertyUpdate();
      }
    }
  }

  // We could check the change of border-box, padding-box or content-box
  // according to background-clip, but checking layout change is much simpler
  // and good enough for the rare cases of NeedsBackgroundClip().
  if (NeedsBackgroundClip(box) && box.ShouldCheckLayoutForPaintInvalidation()) {
    box.GetMutableForPainting().SetOnlyThisNeedsPaintPropertyUpdate();
  }

  // If we reach FragmentPaintPropertyTreeBuilder for an object needing a
  // pending transform upda
"""


```