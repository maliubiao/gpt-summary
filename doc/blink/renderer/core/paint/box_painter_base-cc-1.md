Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `box_painter_base.cc` file in the Chromium Blink rendering engine. I need to identify the key actions and responsibilities of the code, focusing on how it contributes to the painting process. I also need to relate it to web technologies like JavaScript, HTML, and CSS, providing concrete examples. Furthermore, I need to illustrate its behavior with hypothetical inputs and outputs, discuss potential usage errors, and trace how user actions might lead to this code being executed. Finally, since this is part 2 of the request, I should focus on summarizing the functionality covered in *this specific snippet*.

Here's a breakdown of the code's functionality:

1. **Image Drawing:** Functions related to drawing images, including timing information for Largest Contentful Paint (LCP).
2. **Fast-Path Optimization:** Logic for optimizing background painting in simple cases (single color or non-repeating image).
3. **Rounded Borders:** Handling and clipping for elements with rounded borders.
4. **Background Painting:** Core logic for painting background colors and images, including handling tiling, clipping, and blend modes.
5. **Masking:** Support for CSS masking, including luminance masks and SVG masks.
6. **Border Painting:**  Calls out to dedicated border painting logic.
7. **Text as Mask:** A specific painting mode where the text content acts as a mask for the background.
8. **Paint Under-Invalidation Checking:** Logic to conditionally skip checks for harmless repaints, primarily for animated or dynamic content.

Now I'll formulate the summary based on these points.
这是对`blink/renderer/core/paint/box_painter_base.cc`文件功能的归纳总结，主要涵盖了提供的第二部分代码的功能。

**功能归纳：**

这段代码主要负责实现 `BoxPainterBase` 类中关于填充层（Fill Layers）和边框（Border）的绘制逻辑。填充层通常对应于元素的背景颜色和背景图像，而边框则是元素边框的绘制。  它包含了一系列用于优化和处理各种复杂情况的函数。

**核心功能点：**

1. **图像绘制和性能优化:**
    *   `WillDrawImage` 和 `ComputeImagePaintTimingInfo`:  这两个函数用于判断是否绘制背景图像，并计算与图像绘制相关的性能指标，特别是对于Largest Contentful Paint (LCP) 的候选项进行标记。这与CSS中的 `background-image` 属性密切相关，用于优化页面加载性能。
    *   `CanUseBottomLayerFastPath` 和 `PaintFastBottomLayer`: 实现了针对简单背景绘制场景的快速路径优化。如果背景只需要绘制纯色或简单的非重复图像，它可以避免复杂的绘制流程，提高渲染效率。这直接影响浏览器渲染包含简单背景的HTML元素的速度。

2. **背景绘制的核心逻辑:**
    *   `PaintFillLayerBackground`:  负责实际绘制填充层的背景颜色和图像。它处理背景图像的平铺 (`DrawTiledBackground`)、定位以及在需要时与背景颜色进行混合。这与CSS的 `background-color`, `background-image`, `background-repeat`, `background-position` 等属性相关。
    *   `PaintFillLayer`: 作为入口函数，协调填充层的绘制过程。它根据填充层的信息（颜色、图像、裁剪等）选择合适的绘制方式。

3. **圆角边框和裁剪:**
    *   `BackgroundRoundedRectAdjustedForBleedAvoidance`:  处理在避免背景出血时对圆角矩形进行调整。这与CSS的 `border-radius` 属性以及浏览器避免渲染伪影的机制有关。
    *   `RoundedBorderRectForClip`:  计算用于裁剪背景的圆角矩形，确保背景不会溢出元素的指定区域。这与CSS的 `border-radius` 和 `background-clip` 属性相关。

4. **混合模式和遮罩:**
    *   `ShouldApplyBlendOperation` 和 `NeedsMaskLuminanceLayer`:  判断是否应用混合模式 (`background-blend-mode`) 以及是否需要为遮罩创建亮度层 (`mask-mode: luminance`)。这涉及到CSS的混合模式和遮罩属性。
    *   `ScopedMaskLuminanceLayer`:  一个辅助类，用于在绘制遮罩时创建和管理亮度层。
    *   对 SVG 遮罩的处理： 当 `background-image` 或 `mask-image` 引用 SVG `<mask>` 元素时，代码会调用 `SVGMaskPainter::PaintSVGMaskLayer` 进行特殊的绘制处理。

5. **文本作为遮罩:**
    *   `PaintFillLayerTextFillBox`:  处理 `background-clip: text` 的情况，即元素的文本内容作为背景的遮罩。这直接对应CSS的 `background-clip: text` 属性，允许背景只在文本区域可见。

6. **边框绘制:**
    *   `PaintBorder`:  调用 `BoxBorderPainter::PaintBorder` 来绘制元素的边框。如果存在 `border-image`，则优先使用 `NinePieceImagePainter::Paint` 进行绘制。这与CSS的 `border`, `border-style`, `border-width`, `border-color`, 和 `border-image` 等属性相关。

7. **遮罩图像绘制:**
    *   `PaintMaskImages`:  处理 CSS `mask-image` 属性，绘制遮罩图像。

8. **避免非必要的重绘检查:**
    *   `ShouldSkipPaintUnderInvalidationChecking`:  在某些已知情况下，例如动画或特定的UI控件（如滑块），允许跳过不必要的重绘检查，提高性能。

**与 JavaScript, HTML, CSS 的关系举例:**

*   **CSS `background-color: red;`**: 当 HTML 元素应用此样式时，`PaintFillLayer` 和 `PaintFillLayerBackground` 函数会被调用，最终调用 `context.FillRect` 或 `context.FillRoundedRect` 来绘制红色背景。
*   **CSS `background-image: url('image.png');`**:  `WillDrawImage` 会检查图像是否加载完成，`ComputeImagePaintTimingInfo` 可能会标记其为 LCP 候选者。`PaintFillLayerBackground` 会调用 `DrawTiledBackground` 或 `context.DrawImageRRect` 来绘制图像。
*   **CSS `border-radius: 10px;`**:  `RoundedBorderRectForClip` 会计算圆角矩形，`PaintFastBottomLayer` 或 `clip_to_border.emplace` 会根据情况进行绘制或裁剪。
*   **CSS `background-clip: text; color: white; background-image: linear-gradient(to right, red, blue);`**:  `PaintFillLayerTextFillBox` 会被调用。首先，会绘制一个包含线性渐变的背景层。然后，会创建一个遮罩层，并将白色文本绘制到遮罩层中。最后，将背景层与文本遮罩层进行混合，使得背景只在文本区域可见。
*   **HTML `<img src="large-image.jpg">`** 并且该图片是页面的首要内容： `WillDrawImage` 和 `ComputeImagePaintTimingInfo` 会识别该图像作为 LCP 候选者，以便浏览器可以优先加载和渲染它。
*   **JavaScript 动态修改元素的 `style.backgroundColor`**:  这将触发重新布局和重绘，最终可能调用到 `PaintFillLayer` 来更新背景颜色。

**逻辑推理的假设输入与输出:**

**假设输入:**

*   一个 `<div>` 元素，CSS 样式为 `background-color: blue; border-radius: 5px;`。
*   `paint_info` 包含当前绘制的上下文信息。
*   `rect` 描述了 `<div>` 元素的物理尺寸和位置。

**输出:**

*   `PaintFillLayer` 会被调用。
*   由于是简单背景，`CanUseBottomLayerFastPath` 可能返回 `true`。
*   `PaintFastBottomLayer` 会被调用。
*   `RoundedBorderRectForClip` 会计算半径为 5px 的圆角矩形。
*   `context.FillRoundedRect` 会被调用，使用蓝色填充该圆角矩形。

**用户或编程常见的使用错误举例:**

*   **CSS `background-image` 路径错误:** 如果 CSS 中指定的背景图像路径不正确，`fill_layer_info.should_paint_image` 可能是 `false`，或者 `image` 为空，导致背景图像无法显示。开发者在编写 CSS 时可能会拼写错误或路径不正确。
*   **CSS `background-clip: text;` 但文本颜色与背景色相同:** 这会导致文本“消失”，因为背景只在文本区域绘制，但文本颜色与背景色一致，无法区分。开发者可能没有考虑到文本颜色和背景色的对比度。
*   **过度使用复杂的背景效果（例如多层背景、复杂的遮罩）:** 这可能导致性能问题，尤其是在低端设备上。开发者可能没有充分考虑性能影响。

**用户操作如何一步步到达这里（调试线索）:**

1. **用户在浏览器中打开一个网页。**
2. **浏览器解析 HTML 和 CSS，构建 DOM 树和 CSSOM 树。**
3. **浏览器根据 DOM 树和 CSSOM 树构建渲染树（Render Tree 或 Layout Tree）。**
4. **Layout 阶段计算每个元素在页面上的确切位置和大小。**
5. **Paint 阶段遍历渲染树，调用相应的 `paint` 方法来绘制每个元素。**
6. **当需要绘制一个带有背景或边框的元素时，例如一个 `<div>`，`BoxPainter::Paint` 方法会被调用。**
7. **`BoxPainter::Paint` 可能会调用 `BoxPainterBase::PaintFillLayers` 来绘制背景。**
8. **`PaintFillLayers` 遍历元素的背景层，并为每一层调用 `BoxPainterBase::PaintFillLayer`。**
9. **在 `PaintFillLayer` 中，根据背景的复杂程度，可能会调用 `PaintFastBottomLayer` 或 `PaintFillLayerBackground` 等更具体的绘制函数。**
10. 如果元素有圆角，`RoundedBorderRectForClip` 会被调用。
11. 如果使用了 `background-clip: text`，`PaintFillLayerTextFillBox` 会被调用。
12. 如果需要绘制边框，`BoxPainterBase::PaintBorder` 会被调用。

通过调试工具，例如 Chrome DevTools 的 "渲染" 面板，可以查看哪些元素正在重绘，并可以设置断点在 `box_painter_base.cc` 中的相关函数来跟踪绘制流程，从而理解用户操作是如何触发这些代码的执行的。

### 提示词
```
这是目录为blink/renderer/core/paint/box_painter_base.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
ageAutoDarkMode::Disabled(),
      ImagePaintTimingInfo(
          /* image_may_be_lcp_candidate */ false,
          /* report_paint_timing */ false),
      dest_rect, src_rect, SkBlendMode::kSrcOver, kRespectImageOrientation);
  return true;
}

bool WillDrawImage(
    Node* node,
    const Image& image,
    const StyleImage& style_image,
    const PropertyTreeStateOrAlias& current_paint_chunk_properties,
    const gfx::RectF& image_rect) {
  Node* generating_node = GeneratingNode(node);

  //  StyleFetchedImage and StyleImageSet are the only two that could be passed
  //  here that could have a non-null CachedImage.
  if (!generating_node || !style_image.CachedImage() ||
      (!style_image.IsImageResource() && !style_image.IsImageResourceSet())) {
    return false;
  }

  const gfx::Rect enclosing_rect = gfx::ToEnclosingRect(image_rect);

  bool image_may_be_lcp_candidate =
      PaintTimingDetector::NotifyBackgroundImagePaint(
          *generating_node, image, style_image, current_paint_chunk_properties,
          enclosing_rect);

  LocalDOMWindow* window = node->GetDocument().domWindow();
  DCHECK(window);
  ImageElementTiming::From(*window).NotifyBackgroundImagePainted(
      *generating_node, style_image, current_paint_chunk_properties,
      enclosing_rect);
  return image_may_be_lcp_candidate;
}

ImagePaintTimingInfo ComputeImagePaintTimingInfo(Node* node,
                                                 const Image& image,
                                                 const StyleImage& style_image,
                                                 const GraphicsContext& context,
                                                 const gfx::RectF& rect) {
  bool image_may_be_lcp_candidate = WillDrawImage(
      node, image, style_image,
      context.GetPaintController().CurrentPaintChunkProperties(), rect);

  bool report_paint_timing = style_image.IsContentful();

  return ImagePaintTimingInfo(image_may_be_lcp_candidate, report_paint_timing);
}

inline bool CanUseBottomLayerFastPath(
    const BoxPainterBase::FillLayerInfo& info,
    const BoxBackgroundPaintContext& bg_paint_context,
    BackgroundBleedAvoidance bleed_avoidance,
    bool did_adjust_paint_rect) {
  // This should have been checked by the caller already.
  DCHECK(info.should_paint_color || info.should_paint_image);

  // Painting a background image from an ancestor onto a cell is a complex case.
  if (bg_paint_context.CellUsingContainerBackground()) {
    return false;
  }
  // Complex cases not handled on the fast path.
  if (!info.is_bottom_layer || !info.is_border_fill) {
    return false;
  }
  if (info.should_paint_image) {
    // Do not use the fast path for images if we are shrinking the background
    // for bleed avoidance, because this adjusts the border rects in a way that
    // breaks the optimization.
    if (bleed_avoidance == kBackgroundBleedShrinkBackground) {
      return false;
    }
    // Do not use the fast path with images if the dest rect has been adjusted
    // for scrolling backgrounds because correcting the dest rect for scrolling
    // reduces the accuracy of the destination rects.
    if (did_adjust_paint_rect) {
      return false;
    }
    // Avoid image shaders when printing (poorly supported in PDF).
    if (info.is_rounded_fill && info.is_printing) {
      return false;
    }
  }
  return true;
}

inline bool PaintFastBottomLayer(const Document& document,
                                 Node* node,
                                 const ComputedStyle& style,
                                 GraphicsContext& context,
                                 const BoxPainterBase::FillLayerInfo& info,
                                 const PhysicalRect& rect,
                                 const FloatRoundedRect& border_rect,
                                 const BackgroundImageGeometry& geometry,
                                 Image* image,
                                 SkBlendMode composite_op) {
  // Compute the destination rect for painting the color here because we may
  // need it for computing the image painting rect for optimization.
  FloatRoundedRect color_border =
      info.is_rounded_fill ? border_rect
                           : FloatRoundedRect(ToPixelSnappedRect(rect));

  // When the layer has an image, figure out whether it is covered by a single
  // tile. The border for painting images may not be the same as the color due
  // to optimizations for the image painting destination that avoid painting
  // under the border.
  gfx::RectF src_rect;
  FloatRoundedRect image_border;
  if (info.should_paint_image && image) {
    // Compute the dest rect we will be using for images.
    image_border =
        info.is_rounded_fill
            ? color_border
            : FloatRoundedRect(gfx::RectF(geometry.SnappedDestRect()));

    const gfx::RectF& image_rect = image_border.Rect();
    if (!image_rect.IsEmpty()) {
      // We cannot optimize if the tile is too small.
      if (geometry.TileSize().width < image_rect.width() ||
          geometry.TileSize().height < image_rect.height())
        return false;

      // Use FastAndLossyFromRectF when converting the image border rect.
      // At this point it should have been derived from a snapped rectangle, so
      // the conversion from float should be as precise as it can be.
      // If the destination is not a rounded fill, then use the same rectangle
      // as in DrawTiledBackground() to get consistent results.
      const PhysicalRect dest_rect =
          info.is_rounded_fill ? PhysicalRect::FastAndLossyFromRectF(image_rect)
                               : GetSubsetDestRectForImage(geometry, *image);

      std::optional<gfx::RectF> single_tile_src = OptimizeToSingleTileDraw(
          geometry, dest_rect, *image, info.respect_image_orientation);
      if (!single_tile_src)
        return false;
      src_rect = *single_tile_src;
    }
  }

  // At this point we're committed to the fast path: the destination (r)rect
  // fits within a single tile, and we can paint it using direct draw(R)Rect()
  // calls. Furthermore, if an image should be painted, |src_rect| has been
  // updated to account for positioning and size parameters by
  // OptimizeToSingleTileDraw() in the above code block.
  std::optional<RoundedInnerRectClipper> clipper;
  if (info.is_rounded_fill && !color_border.IsRenderable()) {
    // When the rrect is not renderable, we resort to clipping.
    // RoundedInnerRectClipper handles this case via discrete, corner-wise
    // clipping.
    clipper.emplace(context, rect, color_border);
    color_border.SetRadii(FloatRoundedRect::Radii());
    image_border.SetRadii(FloatRoundedRect::Radii());
  }

  // Paint the color if needed.
  if (info.should_paint_color) {
    // Try to paint the background with a paint worklet first in case it will be
    // animated. Otherwise, paint it directly into the context.
    if (!PaintBGColorWithPaintWorklet(document, info, node, style, color_border,
                                      context)) {
      context.FillRoundedRect(
          color_border, info.color,
          PaintAutoDarkMode(style, DarkModeFilter::ElementRole::kBackground));
    }
  }

  // Paint the image if needed.
  if (!info.should_paint_image || src_rect.IsEmpty())
    return true;

  DEVTOOLS_TIMELINE_TRACE_EVENT_WITH_CATEGORIES(
      TRACE_DISABLED_BY_DEFAULT("devtools.timeline"), "PaintImage",
      inspector_paint_image_event::Data, node, *info.image,
      gfx::RectF(image->Rect()), gfx::RectF(image_border.Rect()));

  auto image_auto_dark_mode = ImageClassifierHelper::GetImageAutoDarkMode(
      *document.GetFrame(), style, image_border.Rect(), src_rect);

  Image::ImageClampingMode clamping_mode =
      Image::ImageClampingMode::kClampImageToSourceRect;

  // If the intended snapped background image is the whole tile, do not clamp
  // the source rect. This allows mipmaps and filtering to read beyond the
  // final adjusted source rect even if snapping and scaling means it's subset.
  // However, this detects and preserves clamping to the source rect for sprite
  // sheet background images.
  if (geometry.TileSize().width == geometry.SnappedDestRect().Width() &&
      geometry.TileSize().height == geometry.SnappedDestRect().Height()) {
    clamping_mode = Image::ImageClampingMode::kDoNotClampImageToSourceRect;
  }

  // Since there is no way for the developer to specify decode behavior, use
  // kSync by default
  context.DrawImageRRect(
      *image, Image::kSyncDecode, image_auto_dark_mode,
      ComputeImagePaintTimingInfo(node, *image, *info.image, context,
                                  image_border.Rect()),
      image_border, src_rect, composite_op, info.respect_image_orientation,
      clamping_mode);
  return true;
}

// Inset the background rect by a "safe" amount: 1/2 border-width for opaque
// border styles, 1/6 border-width for double borders.
FloatRoundedRect BackgroundRoundedRectAdjustedForBleedAvoidance(
    const ComputedStyle& style,
    const PhysicalRect& border_rect,
    bool object_has_multiple_boxes,
    PhysicalBoxSides sides_to_include,
    const FloatRoundedRect& background_rounded_rect) {
  // TODO(fmalita): we should be able to fold these parameters into
  // BoxBorderInfo or BoxDecorationData and avoid calling getBorderEdgeInfo
  // redundantly here.
  BorderEdgeArray edges;
  style.GetBorderEdgeInfo(edges, sides_to_include);

  // Use the most conservative inset to avoid mixed-style corner issues.
  float fractional_inset = 1.0f / 2;
  for (auto& edge : edges) {
    if (edge.BorderStyle() == EBorderStyle::kDouble) {
      fractional_inset = 1.0f / 6;
      break;
    }
  }

  auto insets =
      gfx::InsetsF()
          .set_left(edges[static_cast<unsigned>(BoxSide::kLeft)].UsedWidth())
          .set_right(edges[static_cast<unsigned>(BoxSide::kRight)].UsedWidth())
          .set_top(edges[static_cast<unsigned>(BoxSide::kTop)].UsedWidth())
          .set_bottom(
              edges[static_cast<unsigned>(BoxSide::kBottom)].UsedWidth());
  insets.Scale(fractional_inset);
  FloatRoundedRect adjusted_rounded_rect = background_rounded_rect;
  adjusted_rounded_rect.Inset(insets);
  return adjusted_rounded_rect;
}

FloatRoundedRect RoundedBorderRectForClip(
    const ComputedStyle& style,
    const BoxPainterBase::FillLayerInfo& info,
    const FillLayer& bg_layer,
    const PhysicalRect& rect,
    bool object_has_multiple_boxes,
    const PhysicalSize& flow_box_size,
    BackgroundBleedAvoidance bleed_avoidance,
    const PhysicalBoxStrut& border_padding_insets) {
  if (!info.is_rounded_fill)
    return FloatRoundedRect();

  FloatRoundedRect border = RoundedBorderGeometry::PixelSnappedRoundedBorder(
      style, rect, info.sides_to_include);
  if (object_has_multiple_boxes) {
    FloatRoundedRect segment_border =
        RoundedBorderGeometry::PixelSnappedRoundedBorder(
            style,
            PhysicalRect(PhysicalOffset(),
                         PhysicalSize(ToFlooredSize(flow_box_size))),
            info.sides_to_include);
    border.SetRadii(segment_border.GetRadii());
  }

  if (info.is_border_fill &&
      bleed_avoidance == kBackgroundBleedShrinkBackground &&
      !info.is_clipped_with_local_scrolling) {
    border = BackgroundRoundedRectAdjustedForBleedAvoidance(
        style, rect, object_has_multiple_boxes, info.sides_to_include, border);
  }

  // Clip to the padding or content boxes as necessary.
  // Use FastAndLossyFromRectF because we know it has been pixel snapped.
  PhysicalRect border_rect = PhysicalRect::FastAndLossyFromRectF(border.Rect());
  if (bg_layer.Clip() == EFillBox::kFillBox ||
      bg_layer.Clip() == EFillBox::kContent) {
    border = RoundedBorderGeometry::PixelSnappedRoundedBorderWithOutsets(
        style, border_rect, border_padding_insets, info.sides_to_include);
    // Background of 'background-attachment: local' without visible/clip
    // overflow also needs to use inner border which is equivalent to kPadding.
  } else if (bg_layer.Clip() == EFillBox::kPadding ||
             info.is_clipped_with_local_scrolling) {
    border = RoundedBorderGeometry::PixelSnappedRoundedInnerBorder(
        style, border_rect, info.sides_to_include);
  }
  return border;
}

void PaintFillLayerBackground(const Document& document,
                              GraphicsContext& context,
                              const BoxPainterBase::FillLayerInfo& info,
                              Node* node,
                              const ComputedStyle& style,
                              Image* image,
                              SkBlendMode composite_op,
                              const BackgroundImageGeometry& geometry,
                              const PhysicalRect& scrolled_paint_rect) {
  // Paint the color first underneath all images, culled if background image
  // occludes it.
  // TODO(trchen): In the !bgLayer.hasRepeatXY() case, we could improve the
  // culling test by verifying whether the background image covers the entire
  // painting area.
  if (info.should_paint_color) {
    gfx::Rect background_rect = ToPixelSnappedRect(scrolled_paint_rect);
    // Try to paint the background with a paint worklet first in case it will be
    // animated. Otherwise, paint it directly into the context.
    if (!PaintBGColorWithPaintWorklet(document, info, node, style,
                                      FloatRoundedRect(background_rect),
                                      context)) {
      context.FillRect(
          background_rect, info.color,
          PaintAutoDarkMode(style, DarkModeFilter::ElementRole::kBackground));
    }
  }

  // No progressive loading of the background image.
  // NOTE: This method can be called with no image in situations when a bad
  // resource locator is given such as "//:0", so still check for image.
  if (info.should_paint_image && !geometry.SnappedDestRect().IsEmpty() &&
      !geometry.TileSize().IsEmpty() && image) {
    DEVTOOLS_TIMELINE_TRACE_EVENT_WITH_CATEGORIES(
        TRACE_DISABLED_BY_DEFAULT("devtools.timeline"), "PaintImage",
        inspector_paint_image_event::Data, node, *info.image,
        gfx::RectF(image->Rect()), gfx::RectF(scrolled_paint_rect));
    DrawTiledBackground(
        document.GetFrame(), context, style, *image, geometry, composite_op,
        info.respect_image_orientation,
        ComputeImagePaintTimingInfo(node, *image, *info.image, context,
                                    gfx::RectF(geometry.SnappedDestRect())));
  }
}

bool ShouldApplyBlendOperation(const BoxPainterBase::FillLayerInfo& info,
                               const FillLayer& layer) {
  // For a mask layer, don't use the operator if this is the bottom layer.
  return !info.is_bottom_layer || layer.GetType() != EFillLayerType::kMask;
}

bool NeedsMaskLuminanceLayer(const FillLayer& layer) {
  if (layer.GetType() != EFillLayerType::kMask) {
    return false;
  }
  // We only need a luminance layer if the mask-mode is explicitly
  // 'luminance'. A mask-mode of 'match-source' only applies to SVG <mask>
  // references, and that code-path will create a layer if needed in that case.
  return layer.MaskMode() == EFillMaskMode::kLuminance;
}

const StyleMaskSourceImage* ToMaskSourceIfSVGMask(
    const StyleImage& style_image) {
  const auto* mask_source = DynamicTo<StyleMaskSourceImage>(style_image);
  if (!mask_source || !mask_source->HasSVGMask()) {
    return nullptr;
  }
  return mask_source;
}

class ScopedMaskLuminanceLayer {
  STACK_ALLOCATED();

 public:
  ScopedMaskLuminanceLayer(GraphicsContext& context, SkBlendMode composite_op)
      : context_(context) {
    context.BeginLayer(cc::ColorFilter::MakeLuma(), &composite_op);
  }
  ~ScopedMaskLuminanceLayer() { context_.EndLayer(); }

 private:
  GraphicsContext& context_;
};

PhysicalBoxStrut ComputeSnappedBorders(
    const BoxBackgroundPaintContext& bg_paint_context) {
  const PhysicalBoxStrut border_widths = bg_paint_context.BorderOutsets();
  return PhysicalBoxStrut(
      border_widths.top.ToInt(), border_widths.right.ToInt(),
      border_widths.bottom.ToInt(), border_widths.left.ToInt());
}

}  // anonymous namespace

void BoxPainterBase::PaintFillLayer(
    const PaintInfo& paint_info,
    const Color& color,
    const FillLayer& bg_layer,
    const PhysicalRect& rect,
    BackgroundBleedAvoidance bleed_avoidance,
    const BoxBackgroundPaintContext& bg_paint_context,
    bool object_has_multiple_boxes,
    const PhysicalSize& flow_box_size) {
  if (rect.IsEmpty())
    return;

  const FillLayerInfo fill_layer_info =
      GetFillLayerInfo(color, bg_layer, bleed_avoidance,
                       paint_info.IsPaintingBackgroundInContentsSpace());
  // If we're not actually going to paint anything, abort early.
  if (!fill_layer_info.should_paint_image &&
      !fill_layer_info.should_paint_color)
    return;

  if (fill_layer_info.background_forced_to_white &&
      bg_paint_context.ShouldSkipBackgroundIfWhite()) {
    return;
  }

  GraphicsContext& context = paint_info.context;
  GraphicsContextStateSaver clip_with_scrolling_state_saver(
      context, fill_layer_info.is_clipped_with_local_scrolling);
  auto scrolled_paint_rect = rect;
  if (fill_layer_info.is_clipped_with_local_scrolling &&
      !paint_info.IsPaintingBackgroundInContentsSpace()) {
    PhysicalBoxStrut snapped_borders = ComputeSnappedBorders(bg_paint_context);
    snapped_borders.TruncateSides(fill_layer_info.sides_to_include);
    scrolled_paint_rect =
        AdjustRectForScrolledContent(paint_info.context, snapped_borders, rect);
  }
  const auto did_adjust_paint_rect = scrolled_paint_rect != rect;

  scoped_refptr<Image> image;
  BackgroundImageGeometry geometry;
  SkBlendMode composite_op = SkBlendMode::kSrcOver;
  std::optional<ScopedImageRenderingSettings> image_rendering_settings_context;
  std::optional<ScopedMaskLuminanceLayer> mask_luminance_scope;
  if (fill_layer_info.should_paint_image) {
    // Prepare compositing state first so that it's ready in case the layer
    // references an SVG <mask> element.
    if (ShouldApplyBlendOperation(fill_layer_info, bg_layer)) {
      composite_op = WebCoreCompositeToSkiaComposite(bg_layer.Composite(),
                                                     bg_layer.GetBlendMode());
    }

    if (NeedsMaskLuminanceLayer(bg_layer)) {
      mask_luminance_scope.emplace(context, composite_op);
      // The mask luminance layer will apply `composite_op`, so reset it to
      // avoid applying it twice.
      composite_op = SkBlendMode::kSrcOver;
    }

    const ComputedStyle& image_style = bg_paint_context.ImageStyle(style_);

    // If the "image" referenced by the FillLayer is an SVG <mask> reference
    // (and this is a layer for a mask), then repeat, position, clip, origin and
    // size should have no effect.
    if (bg_layer.GetType() == EFillLayerType::kMask) {
      if (const auto* mask_source =
              ToMaskSourceIfSVGMask(*fill_layer_info.image)) {
        const PhysicalRect positioning_area =
            bg_paint_context.ComputePositioningArea(paint_info, bg_layer,
                                                    scrolled_paint_rect);
        const gfx::RectF reference_box(gfx::SizeF(positioning_area.size));
        const float zoom = image_style.EffectiveZoom();

        clip_with_scrolling_state_saver.SaveIfNeeded();
        // Move the origin to the upper-left corner of the positioning area.
        context.Translate(positioning_area.X().ToFloat(),
                          positioning_area.Y().ToFloat());
        SVGMaskPainter::PaintSVGMaskLayer(
            context, *mask_source, bg_paint_context.ImageClient(),
            reference_box, zoom, composite_op,
            bg_layer.MaskMode() == EFillMaskMode::kMatchSource);
        return;
      }
    }
    DCHECK_GE(document_.Lifecycle().GetState(),
              DocumentLifecycle::kPrePaintClean);
    geometry.Calculate(bg_layer, bg_paint_context, scrolled_paint_rect,
                       paint_info);

    image = fill_layer_info.image->GetImage(bg_paint_context.ImageClient(),
                                            document_, image_style,
                                            gfx::SizeF(geometry.TileSize()));

    image_rendering_settings_context.emplace(context,
                                             style_.GetInterpolationQuality(),
                                             style_.GetDynamicRangeLimit());
  }

  const PhysicalBoxStrut border = ComputeSnappedBorders(bg_paint_context);
  const PhysicalBoxStrut padding = bg_paint_context.PaddingOutsets();
  const PhysicalBoxStrut border_padding_insets = -(border + padding);
  FloatRoundedRect border_rect = RoundedBorderRectForClip(
      style_, fill_layer_info, bg_layer, rect, object_has_multiple_boxes,
      flow_box_size, bleed_avoidance, border_padding_insets);

  // Fast path for drawing simple color/image backgrounds.
  if (CanUseBottomLayerFastPath(fill_layer_info, bg_paint_context,
                                bleed_avoidance, did_adjust_paint_rect) &&
      PaintFastBottomLayer(document_, node_, style_, context, fill_layer_info,
                           rect, border_rect, geometry, image.get(),
                           composite_op)) {
    return;
  }

  std::optional<RoundedInnerRectClipper> clip_to_border;
  if (fill_layer_info.is_rounded_fill) {
    DCHECK(!bg_paint_context.CanCompositeBackgroundAttachmentFixed());
    clip_to_border.emplace(context, rect, border_rect);
  }

  EFillBox effective_clip = bg_paint_context.EffectiveClip(bg_layer);

  if (effective_clip == EFillBox::kText) {
    DCHECK(!bg_paint_context.CanCompositeBackgroundAttachmentFixed());
    PaintFillLayerTextFillBox(paint_info, fill_layer_info, image.get(),
                              composite_op, geometry, rect, scrolled_paint_rect,
                              object_has_multiple_boxes);
    return;
  }

  // We use BackgroundClip paint property when CanFastScrollFixedAttachment().
  std::optional<GraphicsContextStateSaver> background_clip_state_saver;
  if (!bg_paint_context.CanCompositeBackgroundAttachmentFixed()) {
    switch (effective_clip) {
      case EFillBox::kFillBox:
      // Spec: For elements with associated CSS layout box, the used values for
      // fill-box compute to content-box.
      // https://drafts.fxtf.org/css-masking/#the-mask-clip
      case EFillBox::kPadding:
      case EFillBox::kContent: {
        if (fill_layer_info.is_rounded_fill) {
          break;
        }

        // Clip to the padding or content boxes as necessary.
        PhysicalBoxStrut outsets = border;
        if (effective_clip == EFillBox::kFillBox ||
            effective_clip == EFillBox::kContent) {
          outsets += padding;
        }
        outsets.TruncateSides(fill_layer_info.sides_to_include);

        PhysicalRect clip_rect = scrolled_paint_rect;
        clip_rect.Contract(outsets);
        background_clip_state_saver.emplace(context);
        context.Clip(ToPixelSnappedRect(clip_rect));
        break;
      }
      case EFillBox::kStrokeBox:
      case EFillBox::kViewBox:
      // Spec: For elements with associated CSS layout box, ... stroke-box and
      // view-box compute to border-box.
      // https://drafts.fxtf.org/css-masking/#the-mask-clip
      case EFillBox::kNoClip:
      case EFillBox::kBorder:
        break;
      case EFillBox::kText:  // fall through
      default:
        NOTREACHED();
    }
  }

  PaintFillLayerBackground(document_, context, fill_layer_info, node_, style_,
                           image.get(), composite_op, geometry,
                           scrolled_paint_rect);
}

void BoxPainterBase::PaintFillLayerTextFillBox(
    const PaintInfo& paint_info,
    const BoxPainterBase::FillLayerInfo& info,
    Image* image,
    SkBlendMode composite_op,
    const BackgroundImageGeometry& geometry,
    const PhysicalRect& rect,
    const PhysicalRect& scrolled_paint_rect,
    bool object_has_multiple_boxes) {
  // First figure out how big the mask has to be. It should be no bigger
  // than what we need to actually render, so we should intersect the dirty
  // rect with the border box of the background.
  gfx::Rect mask_rect = ToPixelSnappedRect(rect);

  GraphicsContext& context = paint_info.context;

  // We draw the background into a separate layer, to be later masked with
  // yet another layer holding the text content.
  GraphicsContextStateSaver background_clip_state_saver(context, false);
  background_clip_state_saver.Save();
  context.Clip(mask_rect);
  context.BeginLayer(composite_op);

  PaintFillLayerBackground(document_, context, info, node_, style_, image,
                           SkBlendMode::kSrcOver, geometry,
                           scrolled_paint_rect);

  // Create the text mask layer and draw the text into the mask. We do this by
  // painting using a special paint phase that signals to InlineTextBoxes that
  // they should just add their contents to the clip.
  context.BeginLayer(SkBlendMode::kDstIn);

  PaintTextClipMask(paint_info, mask_rect, scrolled_paint_rect.offset,
                    object_has_multiple_boxes);

  context.EndLayer();  // Text mask layer.
  context.EndLayer();  // Background layer.
}

void BoxPainterBase::PaintBorder(const ImageResourceObserver& obj,
                                 const Document& document,
                                 Node* node,
                                 const PaintInfo& info,
                                 const PhysicalRect& rect,
                                 const ComputedStyle& style,
                                 BackgroundBleedAvoidance bleed_avoidance,
                                 PhysicalBoxSides sides_to_include) {
  // border-image is not affected by border-radius.
  if (NinePieceImagePainter::Paint(info.context, obj, document, node, rect,
                                   style, style.BorderImage())) {
    return;
  }

  BoxBorderPainter::PaintBorder(info.context, rect, style, bleed_avoidance,
                                sides_to_include);
}

void BoxPainterBase::PaintMaskImages(
    const PaintInfo& paint_info,
    const PhysicalRect& paint_rect,
    const ImageResourceObserver& obj,
    const BoxBackgroundPaintContext& bg_paint_context,
    PhysicalBoxSides sides_to_include) {
  if (!style_.HasMask() || style_.Visibility() != EVisibility::kVisible) {
    return;
  }

  PaintFillLayers(paint_info, Color::kTransparent, style_.MaskLayers(),
                  paint_rect, bg_paint_context);
  NinePieceImagePainter::Paint(paint_info.context, obj, document_, node_,
                               paint_rect, style_, style_.MaskBoxImage(),
                               sides_to_include);
}

bool BoxPainterBase::ShouldSkipPaintUnderInvalidationChecking(
    const LayoutBox& box) {
  DCHECK(RuntimeEnabledFeatures::PaintUnderInvalidationCheckingEnabled());

  // Disable paint under-invalidation checking for cases that under-invalidation
  // is intensional and/or harmless.

  // A box having delayed-invalidation may change before it's actually
  // invalidated. Note that we still report harmless under-invalidation of
  // non-delayed-invalidation animated background, which should be ignored.
  if (box.ShouldDelayFullPaintInvalidation())
    return true;

  // We always paint a MediaSliderPart using the latest data (buffered ranges,
  // current time and duration) which may be different from the cached data.
  if (box.StyleRef().EffectiveAppearance() == kMediaSliderPart)
    return true;

  // We paint an indeterminate progress based on the position calculated from
  // the animation progress. Harmless under-invalidatoin may happen during a
  // paint that is not scheduled for animation.
  if (box.IsProgress() && !To<LayoutProgress>(box).IsDeterminate())
    return true;

  return false;
}

}  // namespace blink
```