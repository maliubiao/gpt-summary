Response:
My thought process for analyzing the `box_painter_base.cc` code and generating the summary involved these steps:

1. **Initial Scan and Keyword Identification:** I started by quickly scanning the included headers and the function names within the provided code snippet. Keywords like "Paint," "Box," "Background," "Border," "Shadow," "FillLayer," "Clip," and the presence of `GraphicsContext` suggested the primary function of this file is related to drawing visual elements on the screen.

2. **Deconstructing the File's Purpose:** Based on the keywords and the file name, I hypothesized that `box_painter_base.cc` provides the fundamental logic for painting the visual aspects of HTML boxes (elements). This includes backgrounds, borders, and shadows. The "base" in the name likely indicates it's a foundational class or set of functions used by other more specialized painting components.

3. **Analyzing Key Functions:**  I focused on the prominent functions and their parameters to understand their specific roles:

    * **`PaintFillLayers`:** This function clearly deals with drawing background layers. The logic involving `FillLayerOcclusionOutputList` hinted at optimization techniques to avoid drawing obscured layers.
    * **`PaintNormalBoxShadow` and `PaintInsetBoxShadow`:** These directly address the rendering of box shadows, distinguishing between normal and inset types. The parameters suggested they take into account border radii and which sides of the box to apply the shadow to.
    * **`CalculateFillLayerOcclusionCulling`:**  This confirms the optimization strategy for background layers by determining which layers are visible and need painting.
    * **`FillLayerInfo` constructor:** This structure seems to encapsulate the necessary information for painting a single background layer, taking into account various CSS properties and rendering contexts (like printing).
    * **`DrawTiledBackground`:**  This function is responsible for handling background images that are set to repeat or tile.
    * **`PaintBGColorWithPaintWorklet`:** This indicates support for a more advanced feature, potentially allowing custom background painting logic through JavaScript (Paint Worklets).

4. **Identifying Relationships with Web Technologies:**  As I analyzed the functions and parameters, I started connecting them to concepts in HTML, CSS, and JavaScript:

    * **HTML:** The "box" concept directly relates to HTML elements, as every element is essentially a rectangular box.
    * **CSS:**  The functions heavily rely on `ComputedStyle`, indicating they interpret and apply CSS properties like `background-color`, `background-image`, `border-radius`, `box-shadow`, `background-repeat`, etc. The parameters and logic directly map to these CSS properties.
    * **JavaScript:** The mention of "Paint Worklets" explicitly links this file to a JavaScript API that allows developers to define custom painting behavior.

5. **Inferring Logic and Potential Issues:**  Based on the function names and logic, I made some inferences about the underlying implementation and potential problems:

    * **Occlusion Culling:** The logic in `CalculateFillLayerOcclusionCulling` aims to improve performance by skipping the rendering of hidden background layers. A potential error could occur if the culling logic is flawed and incorrectly hides visible layers.
    * **Border Radii and Clipping:** The code handles rounded borders, implying potential edge cases or visual artifacts if the clipping or rendering of rounded corners is not precise.
    * **Shadow Rendering:**  The shadow painting functions need to consider the offset, blur, and spread properties of shadows. Incorrect calculations could lead to shadows being positioned or rendered incorrectly.
    * **Background Image Tiling:** The `DrawTiledBackground` function needs to handle different `background-repeat` values correctly. Errors here could result in improperly tiled images.
    * **Print vs. Screen Rendering:** The code handles the `print-color-adjust` property, indicating that rendering might differ for printing versus displaying on the screen.

6. **Constructing Examples and Scenarios:** To illustrate the relationships and potential issues, I created simple examples using HTML and CSS. These examples directly demonstrate how the code in `box_painter_base.cc` would be involved in rendering those elements.

7. **Tracing User Actions to the Code:** I considered how user interactions in a browser could lead to the execution of the code in this file. This involved thinking about the browser's rendering pipeline and the events that trigger layout and paint operations.

8. **Structuring the Output:** Finally, I organized my findings into a clear and structured format, covering the requested aspects: functionality, relationships with web technologies, logical reasoning (with input/output examples), potential errors, and debugging clues. I paid attention to separating the information clearly based on the prompt's requirements.

By following these steps, I could effectively analyze the provided code snippet and generate a comprehensive summary of its functionality and relevance within the Chromium rendering engine. The iterative nature of this process, starting with a broad overview and then drilling down into specifics, was crucial for understanding the complex interactions within the codebase.
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/box_painter_base.h"

#include <optional>

#include "base/containers/adapters.h"
#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/css/background_color_paint_image_generator.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/layout/layout_progress.h"
#include "third_party/blink/renderer/core/paint/background_image_geometry.h"
#include "third_party/blink/renderer/core/paint/box_background_paint_context.h"
#include "third_party/blink/renderer/core/paint/box_border_painter.h"
#include "third_party/blink/renderer/core/paint/nine_piece_image_painter.h"
#include "third_party/blink/renderer/core/paint/paint_auto_dark_mode.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/rounded_border_geometry.h"
#include "third_party/blink/renderer/core/paint/rounded_inner_rect_clipper.h"
#include "third_party/blink/renderer/core/paint/svg_mask_painter.h"
#include "third_party/blink/renderer/core/paint/timing/image_element_timing.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing_detector.h"
#include "third_party/blink/renderer/core/style/border_edge.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/shadow_list.h"
#include "third_party/blink/renderer/core/style/style_fetched_image.h"
#include "third_party/blink/renderer/core/style/style_mask_source_image.h"
#include "third_party/blink/renderer/platform/graphics/bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/draw_looper_builder.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context_state_saver.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_controller.h"
#include "third_party/blink/renderer/platform/graphics/paint_generated_image.h"
#include "third_party/blink/renderer/platform/graphics/scoped_image_rendering_settings.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "ui/gfx/geometry/rect_conversions.h"

namespace blink {

using CompositedPaintStatus = ElementAnimations::CompositedPaintStatus;

void BoxPainterBase::PaintFillLayers(
    const PaintInfo& paint_info,
    const Color& c,
    const FillLayer& fill_layer,
    const PhysicalRect& rect,
    const BoxBackgroundPaintContext& bg_paint_context,
    BackgroundBleedAvoidance bleed) {
  FillLayerOcclusionOutputList reversed_paint_list;
  bool should_draw_background_in_separate_buffer =
      CalculateFillLayerOcclusionCulling(reversed_paint_list, fill_layer);

  // TODO(trchen): We can optimize out isolation group if we have a
  // non-transparent background color and the bottom layer encloses all other
  // layers.
  GraphicsContext& context = paint_info.context;
  if (should_draw_background_in_separate_buffer)
    context.BeginLayer();

  for (auto* const paint : base::Reversed(reversed_paint_list)) {
    PaintFillLayer(paint_info, c, *paint, rect, bleed, bg_paint_context);
  }

  if (should_draw_background_in_separate_buffer)
    context.EndLayer();
}

namespace {

// TODO(crbug.com/682173): We should pass sides_to_include here, and exclude
// the sides that should not be included from the outset.
void ApplySpreadToShadowShape(FloatRoundedRect& shadow_shape, float spread) {
  if (spread == 0)
    return;

  shadow_shape.OutsetForMarginOrShadow(spread);
  shadow_shape.ConstrainRadii();
}

Node* GeneratingNode(Node* node) {
  return node && node->IsPseudoElement() ? node->ParentOrShadowHostNode()
                                         : node;
}

BackgroundColorPaintImageGenerator* GetBackgroundColorPaintImageGenerator(
    const Document& document) {
  if (!RuntimeEnabledFeatures::CompositeBGColorAnimationEnabled())
    return nullptr;

  return document.GetFrame()->GetBackgroundColorPaintImageGenerator();
}

void SetHasNativeBackgroundPainter(Node* node, bool state) {
  Element* element = DynamicTo<Element>(node);
  if (!element)
    return;

  ElementAnimations* element_animations = element->GetElementAnimations();
  DCHECK(element_animations || !state);
  if (element_animations) {
    element_animations->SetCompositedBackgroundColorStatus(
        state ? CompositedPaintStatus::kComposited
              : CompositedPaintStatus::kNotComposited);
  }
}

bool CanCompositeBackgroundColorAnimation(Node* node) {
  Element* element = DynamicTo<Element>(node);
  if (!element)
    return false;

  BackgroundColorPaintImageGenerator* generator =
      GetBackgroundColorPaintImageGenerator(node->GetDocument());
  // The generator can be null in testing environment.
  if (!generator)
    return false;

  Animation* animation = generator->GetAnimationIfCompositable(element);
  if (!animation)
    return false;

  return animation->CheckCanStartAnimationOnCompositor(nullptr) ==
         CompositorAnimations::kNoFailure;
}

CompositedPaintStatus CompositedBackgroundColorStatus(Node* node) {
  Element* element = DynamicTo<Element>(node);
  if (!element)
    return CompositedPaintStatus::kNotComposited;

  ElementAnimations* element_animations = element->GetElementAnimations();
  DCHECK(element_animations);
  return element_animations->CompositedBackgroundColorStatus();
}

void ClipToBorderEdge(GraphicsContext& context,
                      const FloatRoundedRect& border,
                      bool has_border_radius,
                      bool has_opaque_background) {
  FloatRoundedRect rect_to_clip_out = border;

  // If the box is opaque, it is unnecessary to clip it out. However,
  // doing so saves time when painting the shadow. On the other hand, it
  // introduces subpixel gaps along the corners / edges. Those are avoided
  // by insetting the clipping path by one CSS pixel.
  if (has_opaque_background) {
    rect_to_clip_out.Inset(1);
  }

  if (has_border_radius) {
    if (!rect_to_clip_out.IsEmpty()) {
      context.ClipOutRoundedRect(rect_to_clip_out);
    }
  } else {
    if (!rect_to_clip_out.IsEmpty()) {
      context.ClipOut(rect_to_clip_out.Rect());
    }
  }
}

void ClipToSides(GraphicsContext& context,
                 const FloatRoundedRect& border,
                 const ShadowData& shadow,
                 PhysicalBoxSides sides_to_include) {
  // Create a "pseudo-infinite" clip rectangle that should be large enough to
  // contain shadows on all four sides, including blur. Clip to the original
  // box for the sides that are excluded in this fragment.
  gfx::OutsetsF shadow_outsets = shadow.RectOutsets();
  // If an edge is not included, then reset the outset on that edge.
  if (!sides_to_include.left) {
    shadow_outsets.set_left(0);
  }
  if (!sides_to_include.top) {
    shadow_outsets.set_top(0);
  }
  if (!sides_to_include.right) {
    shadow_outsets.set_right(0);
  }
  if (!sides_to_include.bottom) {
    shadow_outsets.set_bottom(0);
  }
  gfx::RectF keep = border.Rect();
  keep.Outset(shadow_outsets);
  context.Clip(keep);
}

void AdjustRectForSideClipping(gfx::RectF& rect,
                               const ShadowData& shadow,
                               PhysicalBoxSides sides_to_include) {
  if (!sides_to_include.left) {
    float extend_by = std::max(shadow.X(), 0.0f) + shadow.Blur();
    rect.Offset(-extend_by, 0);
    rect.set_width(rect.width() + extend_by);
  }
  if (!sides_to_include.top) {
    float extend_by = std::max(shadow.Y(), 0.0f) + shadow.Blur();
    rect.Offset(0, -extend_by);
    rect.set_height(rect.height() + extend_by);
  }
  if (!sides_to_include.right) {
    float shrink_by = std::min(shadow.X(), 0.0f) - shadow.Blur();
    rect.set_width(rect.width() - shrink_by);
  }
  if (!sides_to_include.bottom) {
    float shrink_by = std::min(shadow.Y(), 0.0f) - shadow.Blur();
    rect.set_height(rect.height() - shrink_by);
  }
}

// A box-shadow is always obscured by the box geometry regardless of its color,
// if the shadow has an offset of zero, no blur and no spread. In that case it
// will have no visual effect and can be skipped.
bool ShadowIsFullyObscured(const ShadowData& shadow) {
  return shadow.Offset().IsZero() && shadow.Blur() == 0 && shadow.Spread() == 0;
}

}  // namespace

void BoxPainterBase::PaintNormalBoxShadow(const PaintInfo& info,
                                          const PhysicalRect& paint_rect,
                                          const ComputedStyle& style,
                                          PhysicalBoxSides sides_to_include,
                                          bool background_is_skipped) {
  if (!style.BoxShadow())
    return;
  GraphicsContext& context = info.context;

  FloatRoundedRect border = RoundedBorderGeometry::PixelSnappedRoundedBorder(
      style, paint_rect, sides_to_include);

  bool has_border_radius = style.HasBorderRadius();
  bool has_opaque_background =
      !background_is_skipped &&
      style.VisitedDependentColor(GetCSSPropertyBackgroundColor()).IsOpaque();

  GraphicsContextStateSaver state_saver(context, false);

  const ShadowList* shadow_list = style.BoxShadow();
  for (wtf_size_t i = shadow_list->Shadows().size(); i--;) {
    const ShadowData& shadow = shadow_list->Shadows()[i];
    if (shadow.Style() != ShadowStyle::kNormal)
      continue;
    if (ShadowIsFullyObscured(shadow)) {
      continue;
    }

    Color resolved_shadow_color = shadow.GetColor().Resolve(
        style.VisitedDependentColor(GetCSSPropertyColor()),
        style.UsedColorScheme());
    // DarkModeFilter::ApplyToFlagsIfNeeded does not apply dark mode to the draw
    // looper used for shadows so we need to apply dark mode to the color here.
    const Color shadow_color =
        style.ForceDark()
            ? Color::FromSkColor4f(
                  context.GetDarkModeFilter()->InvertColorIfNeeded(
                      resolved_shadow_color.toSkColor4f(),
                      DarkModeFilter::ElementRole::kBackground))
            : resolved_shadow_color;

    gfx::RectF fill_rect = border.Rect();
    fill_rect.Outset(shadow.Spread());
    if (fill_rect.IsEmpty())
      continue;

    // Save the state and clip, if not already done.
    // The clip does not depend on any shadow-specific properties.
    if (!state_saver.Saved()) {
      state_saver.Save();
      ClipToBorderEdge(context, border, has_border_radius,
                       has_opaque_background);
    }

    // Recompute the shadow shape so that spread isn't applied twice in the
    // border-radius case.
    fill_rect = border.Rect();

    GraphicsContextStateSaver sides_clip_saver(context, false);
    if (!sides_to_include.HasAllSides()) {
      sides_clip_saver.Save();
      ClipToSides(context, border, shadow, sides_to_include);
      AdjustRectForSideClipping(fill_rect, shadow, sides_to_include);
    }

    // Draw only the shadow. If the color of the shadow is transparent we will
    // set an empty draw looper.
    DrawLooperBuilder draw_looper_builder;
    draw_looper_builder.AddShadow(shadow.Offset(), shadow.Blur(), shadow_color,
                                  DrawLooperBuilder::kShadowRespectsTransforms,
                                  DrawLooperBuilder::kShadowIgnoresAlpha);
    context.SetDrawLooper(draw_looper_builder.DetachDrawLooper());

    if (has_border_radius) {
      FloatRoundedRect rounded_fill_rect(fill_rect, border.GetRadii());
      ApplySpreadToShadowShape(rounded_fill_rect, shadow.Spread());
      context.FillRoundedRect(
          rounded_fill_rect, Color::kBlack,
          PaintAutoDarkMode(style, DarkModeFilter::ElementRole::kBackground));
    } else {
      fill_rect.Outset(shadow.Spread());
      context.FillRect(
          fill_rect, Color::kBlack,
          PaintAutoDarkMode(style, DarkModeFilter::ElementRole::kBackground));
    }
  }
}

void BoxPainterBase::PaintInsetBoxShadowWithBorderRect(
    const PaintInfo& info,
    const PhysicalRect& border_rect,
    const ComputedStyle& style,
    PhysicalBoxSides sides_to_include) {
  if (!style.BoxShadow())
    return;
  auto bounds = RoundedBorderGeometry::PixelSnappedRoundedInnerBorder(
      style, border_rect, sides_to_include);
  PaintInsetBoxShadow(info, bounds, style, sides_to_include);
}

void BoxPainterBase::PaintInsetBoxShadowWithInnerRect(
    const PaintInfo& info,
    const PhysicalRect& inner_rect,
    const ComputedStyle& style) {
  if (!style.BoxShadow())
    return;
  auto bounds = RoundedBorderGeometry::PixelSnappedRoundedBorderWithOutsets(
      style, inner_rect, PhysicalBoxStrut());
  PaintInsetBoxShadow(info, bounds, style);
}

namespace {

inline gfx::RectF AreaCastingShadowInHole(const gfx::RectF& hole_rect,
                                          const ShadowData& shadow) {
  gfx::RectF bounds = hole_rect;
  bounds.Outset(shadow.Blur());

  if (shadow.Spread() < 0)
    bounds.Outset(-shadow.Spread());

  gfx::RectF offset_bounds = bounds;
  offset_bounds.Offset(-shadow.Offset());
  return gfx::UnionRects(bounds, offset_bounds);
}

}  // namespace

void BoxPainterBase::PaintInsetBoxShadow(const PaintInfo& info,
                                         const FloatRoundedRect& bounds,
                                         const ComputedStyle& style,
                                         PhysicalBoxSides sides_to_include) {
  GraphicsContext& context = info.context;

  const ShadowList* shadow_list = style.BoxShadow();
  for (wtf_size_t i = shadow_list->Shadows().size(); i--;) {
    const ShadowData& shadow = shadow_list->Shadows()[i];
    if (shadow.Style() != ShadowStyle::kInset)
      continue;
    if (ShadowIsFullyObscured(shadow)) {
      continue;
    }

    Color resolved_shadow_color = shadow.GetColor().Resolve(
        style.VisitedDependentColor(GetCSSPropertyColor()),
        style.UsedColorScheme());
    // DarkModeFilter::ApplyToFlagsIfNeeded does not apply dark mode to the draw
    // looper used for shadows so we need to apply dark mode to the color here.
    const Color& shadow_color =
        style.ForceDark()
            ? Color::FromSkColor4f(
                  context.GetDarkModeFilter()->InvertColorIfNeeded(
                      resolved_shadow_color.toSkColor4f(),
                      DarkModeFilter::ElementRole::kBackground))
            : resolved_shadow_color;

    gfx::RectF inner_rect = bounds.Rect();
    AdjustRectForSideClipping(inner_rect, shadow, sides_to_include);
    FloatRoundedRect inner_rounded_rect(inner_rect, bounds.GetRadii());
    ApplySpreadToShadowShape(inner_rounded_rect, -shadow.Spread());
    if (inner_rounded_rect.IsEmpty()) {
      // |AutoDarkMode::Disabled()| is used because |shadow_color| has already
      // been adjusted for dark mode.
      context.FillRoundedRect(bounds, shadow_color, AutoDarkMode::Disabled());
      continue;
    }
    GraphicsContextStateSaver state_saver(context);
    if (bounds.IsRounded()) {
      context.ClipRoundedRect(bounds);
    } else {
      context.Clip(bounds.Rect());
    }

    DrawLooperBuilder draw_looper_builder;
    draw_looper_builder.AddShadow(shadow.Offset(), shadow.Blur(), shadow_color,
                                  DrawLooperBuilder::kShadowRespectsTransforms,
                                  DrawLooperBuilder::kShadowIgnoresAlpha);
    context.SetDrawLooper(draw_looper_builder.DetachDrawLooper());

    Color fill_color(shadow_color.Red(), shadow_color.Green(),
                     shadow_color.Blue());
    gfx::RectF outer_rect = AreaCastingShadowInHole(bounds.Rect(), shadow);
    // |AutoDarkMode::Disabled()| is used because |fill_color(shadow_color)| has
    // already been adjusted for dark mode.
    context.FillRectWithRoundedHole(outer_rect, inner_rounded_rect, fill_color,
                                    AutoDarkMode::Disabled());
  }
}

bool BoxPainterBase::ShouldForceWhiteBackgroundForPrintEconomy(
    const Document& document,
    const ComputedStyle& style) {
  return document.Printing() &&
         style.PrintColorAdjust() == EPrintColorAdjust::kEconomy &&
         (!document.GetSettings() ||
          !document.GetSettings()->GetShouldPrintBackgrounds());
}

bool BoxPainterBase::CalculateFillLayerOcclusionCulling(
    FillLayerOcclusionOutputList& reversed_paint_list,
    const FillLayer& fill_layer) {
  bool is_non_associative = false;
  for (auto* current_layer = &fill_layer; current_layer;
       current_layer = current_layer->Next()) {
    reversed_paint_list.push_back(current_layer);
    // Stop traversal when an opaque layer is encountered.
    // FIXME : It would be possible for the following occlusion culling test to
    // be more aggressive on layers with no repeat by testing whether the image
    // covers the layout rect. Testing that here would imply duplicating a lot
    // of calculations that are currently done in
    // LayoutBoxModelObject::paintFillLayer. A more efficient solution might be
    // to move the layer recursion into paintFillLayer, or to compute the layer
    // geometry here and pass it down.

    // TODO(trchen): Need to check compositing mode as well.
    if (current_layer->GetBlendMode() != BlendMode::kNormal)
      is_non_associative = true;

    // TODO(trchen): A fill layer cannot paint if the calculated tile size is
    // empty. This occlusion check can be wrong.
    if (current_layer->ClipOccludesNextLayers() &&
        current_layer->ImageOccludesNextLayers(document_, style_)) {
      if (current_layer->Clip() == EFillBox::kBorder)
        is_non_associative = false;
      break;
    }
  }
  return is_non_associative;
}

BoxPainterBase::FillLayerInfo::FillLayerInfo(
    const Document& doc,
    const ComputedStyle& style,
    bool is_scroll_container,
    Color bg_color,
    const FillLayer& layer,
    BackgroundBleedAvoidance bleed_avoidance,
    PhysicalBoxSides sides_to_include,
    bool is_inline,
    bool is_painting_background_in_contents_space)
    : image(layer.GetImage()),
      color(bg_color),
      respect_image_orientation(style.ImageOrientation()),
      sides_to_include(sides_to_include),
      is_bottom_layer(!layer.Next()),
      is_border_fill(layer.Clip() == EFillBox::kStrokeBox ||
                     layer.Clip() == EFillBox::kViewBox ||
                     layer.Clip() == EFillBox::kBorder),
      is_clipped_with_local_scrolling(is_scroll_container &&
                                      layer.Attachment() ==
                                          EFillAttachment::kLocal) {
  // When printing backgrounds is disabled or using economy mode,
  // change existing background colors and images to a solid white background.
  // If there's no bg color or image, leave it untouched to avoid affecting
  // transparency. We don't try to avoid loading the background images,
  // because this style flag is only set when printing, and at that point
  // we've already loaded the background images anyway. (To avoid loading the
  // background images we'd have to do this check when applying styles rather
  // than while layout.)
  if (BoxPainterBase::ShouldForceWhiteBackgroundForPrintEconomy(doc, style)) {
    // Note that we can't reuse this variable below because the bgColor might
    // be changed.
    bool should_paint_background_color =
        is_bottom_layer && !color.IsFullyTransparent();
    if (image || should_paint_background_color) {
      color = Color::kWhite;
      image = nullptr;
      background_forced_to_white = true;
    }
  }

  // Background images are not allowed at the inline level in forced colors
  // mode when forced-color-adjust is auto. This ensures that the inline images
  // are not painted on top of the forced colors mode backplate.
  if (doc.InForcedColorsMode() && is_inline &&
      style.ForcedColorAdjust() == EForcedColorAdjust::kAuto)
    image = nullptr;

  const bool has_rounded_border =
      style.HasBorderRadius() && !sides_to_include.IsEmpty();
  // BorderFillBox radius clipping is taken care of by
  // BackgroundBleedClip{Only,Layer}.
  is_rounded_fill =
      has_rounded_border && !is_painting_background_in_contents_space &&
      (layer.Clip() != EFillBox::kNoClip) &&
      (is_clipped_with_local_scrolling ||
       !(is_border_fill && BleedAvoidanceIsClipping(bleed_avoidance)));

  is_printing = doc.Printing();

  should_paint_image = image && image->CanRender();
  if (should_paint_image) {
    respect_image_orientation =
        image->ForceOrientationIfNecessary(respect_image_orientation);
  }

  bool composite_bgcolor_animation =
      RuntimeEnabledFeatures::CompositeBGColorAnimationEnabled() &&
      style.HasCurrentBackgroundColorAnimation() &&
      layer.GetType() == EFillLayerType::kBackground;
  // When background color animation is running on the compositor thread, we
  // need to trigger repaint even if the background is transparent to collect
  // artifacts in order to run the animation on the compositor.
  should_paint_color =
      is_bottom_layer &&
      (!color.IsFullyTransparent() || composite_bgcolor_animation) &&
      (!should_paint_image || !layer.ImageOccludesNextLayers(doc, style));
  should_paint_color_with_paint_worklet_image =
      should_paint_color && composite_bgcolor_animation;
}

namespace {

gfx::RectF SnapSourceRectIfNearIntegral(const gfx::RectF src_rect) {
  // Round to avoid filtering pulling in neighboring pixels, for the
  // common case of sprite maps, but only if we're close to an integral size.
  // "Close" in this context means we will allow floating point inaccuracy,
  // when converted to layout units, to be at most one LayoutUnit::Epsilon and
  // still snap.
  if (std::abs(std::round(src_rect.x()) - src_rect.x()) <=
          LayoutUnit::Epsilon() &&
      std::abs(std::round(src_rect.y()) - src_rect.y()) <=
          LayoutUnit::Epsilon() &&
      std::abs(std::round(src_rect.right()) - src_rect.right()) <=
          LayoutUnit::Epsilon() &&
      std::abs(std::round(src_rect.bottom()) - src_rect.bottom()) <=
          LayoutUnit::Epsilon()) {
    gfx::Rect rounded_src_rect = gfx::ToRoundedRect(src_rect);
    // If we have snapped the image size to 0, revert the rounding.
    if (rounded_src_rect.IsEmpty())
      return src_rect;
    return gfx::RectF(rounded_src_rect);
  }
  return src_rect;
}

std::optional<gfx::RectF> OptimizeToSingleTileDraw(
    const BackgroundImageGeometry& geometry,
    const PhysicalRect& dest_rect,
    Image& image,
    RespectImageOrientationEnum respect_orientation) {
  const PhysicalRect& snapped_dest = geometry.SnappedDestRect();

  // Phase calculation uses the actual painted location, given by the
  // border-snapped destination rect.
  const PhysicalRect one_tile_rect(
      snapped_dest.offset + geometry.ComputePhase(), geometry.TileSize());

  // We cannot optimize if the tile is misaligned.
  if (!one_tile_rect.Contains(dest_rect))
    return std::nullopt;

  const PhysicalOffset offset_in_tile = dest_rect.offset - one_tile_rect.offset;
  if (!image.HasIntrinsicSize()) {
    // This is a generated image sized according to the tile size so we can use
    // the snapped dest rect directly.
    const PhysicalRect offset_tile(offset_in_tile, snapped_dest.size);
    return gfx::RectF(offset_tile);
  }

  // Compute the image subset, in intrinsic image coordinates, that gets mapped
  // onto the |dest_rect|, when the whole image would be drawn with phase and
  // size given by |one_tile_rect|. Assumes |one_tile_rect| contains
  // |dest_rect|. The location of the requested subset should be the painting
  // snapped location.
  //
  // The size of requested subset should be the unsnapped size so that the
  // computed scale and location in the source image can be correctly
  // determined.
  //
  // image-resolution information is baked into the given parameters, but we
  // need oriented size.
  const gfx::SizeF intrinsic_tile_size = image.SizeAsFloat(respect_orientation);

  // Subset computation needs the same location as was used above, but needs the
  // unsnapped destination size to correctly calculate sprite subsets in the
  // presence of zoom. We rely on the caller to provide a suitable (snapped)
  // size.
  const gfx::SizeF scale(
      geometry.TileSize().width / intrinsic_tile_size.width(),
      geometry.TileSize().height / intrinsic_tile_size.height());
  gfx::RectF visible_src_rect(
      offset_in_tile.left / scale.width(), offset_in_tile.top / scale.height(),
      dest_rect.Width() / scale.width(), dest_rect.Height() / scale.height());

  // Content providers almost always choose source pixels at integer locations,
  // so snap to integers. This is particularly important for sprite maps.
  // Calculation up to this point, in LayoutUnits, can lead to small variations
  // from integer size, so it is safe to round without introducing major issues.
  visible_src_rect = SnapSourceRectIfNearIntegral(visible_src_rect);

  // When respecting image orientation, the drawing code expects the source
  // rect to be in the unrotated image space, but we have computed it here in
  // the rotated space in order to position and size the background. Undo the
  // src rect rotation if necessary.
  if (respect_orientation && !image.HasDefaultOrientation()) {
    visible_src_rect = image.CorrectSrcRectForImageOrientation(
        intrinsic_tile_size, visible_src_rect);
  }
  return visible_src_rect;
}

PhysicalRect GetSubsetDestRectForImage(const BackgroundImageGeometry& geometry,
                                       const Image& image) {
  // Use the snapped size if the image does not have
### 提示词
```
这是目录为blink/renderer/core/paint/box_painter_base.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/box_painter_base.h"

#include <optional>

#include "base/containers/adapters.h"
#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/css/background_color_paint_image_generator.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/layout/layout_progress.h"
#include "third_party/blink/renderer/core/paint/background_image_geometry.h"
#include "third_party/blink/renderer/core/paint/box_background_paint_context.h"
#include "third_party/blink/renderer/core/paint/box_border_painter.h"
#include "third_party/blink/renderer/core/paint/nine_piece_image_painter.h"
#include "third_party/blink/renderer/core/paint/paint_auto_dark_mode.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/rounded_border_geometry.h"
#include "third_party/blink/renderer/core/paint/rounded_inner_rect_clipper.h"
#include "third_party/blink/renderer/core/paint/svg_mask_painter.h"
#include "third_party/blink/renderer/core/paint/timing/image_element_timing.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing_detector.h"
#include "third_party/blink/renderer/core/style/border_edge.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/shadow_list.h"
#include "third_party/blink/renderer/core/style/style_fetched_image.h"
#include "third_party/blink/renderer/core/style/style_mask_source_image.h"
#include "third_party/blink/renderer/platform/graphics/bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/draw_looper_builder.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context_state_saver.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_controller.h"
#include "third_party/blink/renderer/platform/graphics/paint_generated_image.h"
#include "third_party/blink/renderer/platform/graphics/scoped_image_rendering_settings.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "ui/gfx/geometry/rect_conversions.h"

namespace blink {

using CompositedPaintStatus = ElementAnimations::CompositedPaintStatus;

void BoxPainterBase::PaintFillLayers(
    const PaintInfo& paint_info,
    const Color& c,
    const FillLayer& fill_layer,
    const PhysicalRect& rect,
    const BoxBackgroundPaintContext& bg_paint_context,
    BackgroundBleedAvoidance bleed) {
  FillLayerOcclusionOutputList reversed_paint_list;
  bool should_draw_background_in_separate_buffer =
      CalculateFillLayerOcclusionCulling(reversed_paint_list, fill_layer);

  // TODO(trchen): We can optimize out isolation group if we have a
  // non-transparent background color and the bottom layer encloses all other
  // layers.
  GraphicsContext& context = paint_info.context;
  if (should_draw_background_in_separate_buffer)
    context.BeginLayer();

  for (auto* const paint : base::Reversed(reversed_paint_list)) {
    PaintFillLayer(paint_info, c, *paint, rect, bleed, bg_paint_context);
  }

  if (should_draw_background_in_separate_buffer)
    context.EndLayer();
}

namespace {

// TODO(crbug.com/682173): We should pass sides_to_include here, and exclude
// the sides that should not be included from the outset.
void ApplySpreadToShadowShape(FloatRoundedRect& shadow_shape, float spread) {
  if (spread == 0)
    return;

  shadow_shape.OutsetForMarginOrShadow(spread);
  shadow_shape.ConstrainRadii();
}

Node* GeneratingNode(Node* node) {
  return node && node->IsPseudoElement() ? node->ParentOrShadowHostNode()
                                         : node;
}

BackgroundColorPaintImageGenerator* GetBackgroundColorPaintImageGenerator(
    const Document& document) {
  if (!RuntimeEnabledFeatures::CompositeBGColorAnimationEnabled())
    return nullptr;

  return document.GetFrame()->GetBackgroundColorPaintImageGenerator();
}

void SetHasNativeBackgroundPainter(Node* node, bool state) {
  Element* element = DynamicTo<Element>(node);
  if (!element)
    return;

  ElementAnimations* element_animations = element->GetElementAnimations();
  DCHECK(element_animations || !state);
  if (element_animations) {
    element_animations->SetCompositedBackgroundColorStatus(
        state ? CompositedPaintStatus::kComposited
              : CompositedPaintStatus::kNotComposited);
  }
}

bool CanCompositeBackgroundColorAnimation(Node* node) {
  Element* element = DynamicTo<Element>(node);
  if (!element)
    return false;

  BackgroundColorPaintImageGenerator* generator =
      GetBackgroundColorPaintImageGenerator(node->GetDocument());
  // The generator can be null in testing environment.
  if (!generator)
    return false;

  Animation* animation = generator->GetAnimationIfCompositable(element);
  if (!animation)
    return false;

  return animation->CheckCanStartAnimationOnCompositor(nullptr) ==
         CompositorAnimations::kNoFailure;
}

CompositedPaintStatus CompositedBackgroundColorStatus(Node* node) {
  Element* element = DynamicTo<Element>(node);
  if (!element)
    return CompositedPaintStatus::kNotComposited;

  ElementAnimations* element_animations = element->GetElementAnimations();
  DCHECK(element_animations);
  return element_animations->CompositedBackgroundColorStatus();
}

void ClipToBorderEdge(GraphicsContext& context,
                      const FloatRoundedRect& border,
                      bool has_border_radius,
                      bool has_opaque_background) {
  FloatRoundedRect rect_to_clip_out = border;

  // If the box is opaque, it is unnecessary to clip it out. However,
  // doing so saves time when painting the shadow. On the other hand, it
  // introduces subpixel gaps along the corners / edges. Those are avoided
  // by insetting the clipping path by one CSS pixel.
  if (has_opaque_background) {
    rect_to_clip_out.Inset(1);
  }

  if (has_border_radius) {
    if (!rect_to_clip_out.IsEmpty()) {
      context.ClipOutRoundedRect(rect_to_clip_out);
    }
  } else {
    if (!rect_to_clip_out.IsEmpty()) {
      context.ClipOut(rect_to_clip_out.Rect());
    }
  }
}

void ClipToSides(GraphicsContext& context,
                 const FloatRoundedRect& border,
                 const ShadowData& shadow,
                 PhysicalBoxSides sides_to_include) {
  // Create a "pseudo-infinite" clip rectangle that should be large enough to
  // contain shadows on all four sides, including blur. Clip to the original
  // box for the sides that are excluded in this fragment.
  gfx::OutsetsF shadow_outsets = shadow.RectOutsets();
  // If an edge is not included, then reset the outset on that edge.
  if (!sides_to_include.left) {
    shadow_outsets.set_left(0);
  }
  if (!sides_to_include.top) {
    shadow_outsets.set_top(0);
  }
  if (!sides_to_include.right) {
    shadow_outsets.set_right(0);
  }
  if (!sides_to_include.bottom) {
    shadow_outsets.set_bottom(0);
  }
  gfx::RectF keep = border.Rect();
  keep.Outset(shadow_outsets);
  context.Clip(keep);
}

void AdjustRectForSideClipping(gfx::RectF& rect,
                               const ShadowData& shadow,
                               PhysicalBoxSides sides_to_include) {
  if (!sides_to_include.left) {
    float extend_by = std::max(shadow.X(), 0.0f) + shadow.Blur();
    rect.Offset(-extend_by, 0);
    rect.set_width(rect.width() + extend_by);
  }
  if (!sides_to_include.top) {
    float extend_by = std::max(shadow.Y(), 0.0f) + shadow.Blur();
    rect.Offset(0, -extend_by);
    rect.set_height(rect.height() + extend_by);
  }
  if (!sides_to_include.right) {
    float shrink_by = std::min(shadow.X(), 0.0f) - shadow.Blur();
    rect.set_width(rect.width() - shrink_by);
  }
  if (!sides_to_include.bottom) {
    float shrink_by = std::min(shadow.Y(), 0.0f) - shadow.Blur();
    rect.set_height(rect.height() - shrink_by);
  }
}

// A box-shadow is always obscured by the box geometry regardless of its color,
// if the shadow has an offset of zero, no blur and no spread. In that case it
// will have no visual effect and can be skipped.
bool ShadowIsFullyObscured(const ShadowData& shadow) {
  return shadow.Offset().IsZero() && shadow.Blur() == 0 && shadow.Spread() == 0;
}

}  // namespace

void BoxPainterBase::PaintNormalBoxShadow(const PaintInfo& info,
                                          const PhysicalRect& paint_rect,
                                          const ComputedStyle& style,
                                          PhysicalBoxSides sides_to_include,
                                          bool background_is_skipped) {
  if (!style.BoxShadow())
    return;
  GraphicsContext& context = info.context;

  FloatRoundedRect border = RoundedBorderGeometry::PixelSnappedRoundedBorder(
      style, paint_rect, sides_to_include);

  bool has_border_radius = style.HasBorderRadius();
  bool has_opaque_background =
      !background_is_skipped &&
      style.VisitedDependentColor(GetCSSPropertyBackgroundColor()).IsOpaque();

  GraphicsContextStateSaver state_saver(context, false);

  const ShadowList* shadow_list = style.BoxShadow();
  for (wtf_size_t i = shadow_list->Shadows().size(); i--;) {
    const ShadowData& shadow = shadow_list->Shadows()[i];
    if (shadow.Style() != ShadowStyle::kNormal)
      continue;
    if (ShadowIsFullyObscured(shadow)) {
      continue;
    }

    Color resolved_shadow_color = shadow.GetColor().Resolve(
        style.VisitedDependentColor(GetCSSPropertyColor()),
        style.UsedColorScheme());
    // DarkModeFilter::ApplyToFlagsIfNeeded does not apply dark mode to the draw
    // looper used for shadows so we need to apply dark mode to the color here.
    const Color shadow_color =
        style.ForceDark()
            ? Color::FromSkColor4f(
                  context.GetDarkModeFilter()->InvertColorIfNeeded(
                      resolved_shadow_color.toSkColor4f(),
                      DarkModeFilter::ElementRole::kBackground))
            : resolved_shadow_color;

    gfx::RectF fill_rect = border.Rect();
    fill_rect.Outset(shadow.Spread());
    if (fill_rect.IsEmpty())
      continue;

    // Save the state and clip, if not already done.
    // The clip does not depend on any shadow-specific properties.
    if (!state_saver.Saved()) {
      state_saver.Save();
      ClipToBorderEdge(context, border, has_border_radius,
                       has_opaque_background);
    }

    // Recompute the shadow shape so that spread isn't applied twice in the
    // border-radius case.
    fill_rect = border.Rect();

    GraphicsContextStateSaver sides_clip_saver(context, false);
    if (!sides_to_include.HasAllSides()) {
      sides_clip_saver.Save();
      ClipToSides(context, border, shadow, sides_to_include);
      AdjustRectForSideClipping(fill_rect, shadow, sides_to_include);
    }

    // Draw only the shadow. If the color of the shadow is transparent we will
    // set an empty draw looper.
    DrawLooperBuilder draw_looper_builder;
    draw_looper_builder.AddShadow(shadow.Offset(), shadow.Blur(), shadow_color,
                                  DrawLooperBuilder::kShadowRespectsTransforms,
                                  DrawLooperBuilder::kShadowIgnoresAlpha);
    context.SetDrawLooper(draw_looper_builder.DetachDrawLooper());

    if (has_border_radius) {
      FloatRoundedRect rounded_fill_rect(fill_rect, border.GetRadii());
      ApplySpreadToShadowShape(rounded_fill_rect, shadow.Spread());
      context.FillRoundedRect(
          rounded_fill_rect, Color::kBlack,
          PaintAutoDarkMode(style, DarkModeFilter::ElementRole::kBackground));
    } else {
      fill_rect.Outset(shadow.Spread());
      context.FillRect(
          fill_rect, Color::kBlack,
          PaintAutoDarkMode(style, DarkModeFilter::ElementRole::kBackground));
    }
  }
}

void BoxPainterBase::PaintInsetBoxShadowWithBorderRect(
    const PaintInfo& info,
    const PhysicalRect& border_rect,
    const ComputedStyle& style,
    PhysicalBoxSides sides_to_include) {
  if (!style.BoxShadow())
    return;
  auto bounds = RoundedBorderGeometry::PixelSnappedRoundedInnerBorder(
      style, border_rect, sides_to_include);
  PaintInsetBoxShadow(info, bounds, style, sides_to_include);
}

void BoxPainterBase::PaintInsetBoxShadowWithInnerRect(
    const PaintInfo& info,
    const PhysicalRect& inner_rect,
    const ComputedStyle& style) {
  if (!style.BoxShadow())
    return;
  auto bounds = RoundedBorderGeometry::PixelSnappedRoundedBorderWithOutsets(
      style, inner_rect, PhysicalBoxStrut());
  PaintInsetBoxShadow(info, bounds, style);
}

namespace {

inline gfx::RectF AreaCastingShadowInHole(const gfx::RectF& hole_rect,
                                          const ShadowData& shadow) {
  gfx::RectF bounds = hole_rect;
  bounds.Outset(shadow.Blur());

  if (shadow.Spread() < 0)
    bounds.Outset(-shadow.Spread());

  gfx::RectF offset_bounds = bounds;
  offset_bounds.Offset(-shadow.Offset());
  return gfx::UnionRects(bounds, offset_bounds);
}

}  // namespace

void BoxPainterBase::PaintInsetBoxShadow(const PaintInfo& info,
                                         const FloatRoundedRect& bounds,
                                         const ComputedStyle& style,
                                         PhysicalBoxSides sides_to_include) {
  GraphicsContext& context = info.context;

  const ShadowList* shadow_list = style.BoxShadow();
  for (wtf_size_t i = shadow_list->Shadows().size(); i--;) {
    const ShadowData& shadow = shadow_list->Shadows()[i];
    if (shadow.Style() != ShadowStyle::kInset)
      continue;
    if (ShadowIsFullyObscured(shadow)) {
      continue;
    }

    Color resolved_shadow_color = shadow.GetColor().Resolve(
        style.VisitedDependentColor(GetCSSPropertyColor()),
        style.UsedColorScheme());
    // DarkModeFilter::ApplyToFlagsIfNeeded does not apply dark mode to the draw
    // looper used for shadows so we need to apply dark mode to the color here.
    const Color& shadow_color =
        style.ForceDark()
            ? Color::FromSkColor4f(
                  context.GetDarkModeFilter()->InvertColorIfNeeded(
                      resolved_shadow_color.toSkColor4f(),
                      DarkModeFilter::ElementRole::kBackground))
            : resolved_shadow_color;

    gfx::RectF inner_rect = bounds.Rect();
    AdjustRectForSideClipping(inner_rect, shadow, sides_to_include);
    FloatRoundedRect inner_rounded_rect(inner_rect, bounds.GetRadii());
    ApplySpreadToShadowShape(inner_rounded_rect, -shadow.Spread());
    if (inner_rounded_rect.IsEmpty()) {
      // |AutoDarkMode::Disabled()| is used because |shadow_color| has already
      // been adjusted for dark mode.
      context.FillRoundedRect(bounds, shadow_color, AutoDarkMode::Disabled());
      continue;
    }
    GraphicsContextStateSaver state_saver(context);
    if (bounds.IsRounded()) {
      context.ClipRoundedRect(bounds);
    } else {
      context.Clip(bounds.Rect());
    }

    DrawLooperBuilder draw_looper_builder;
    draw_looper_builder.AddShadow(shadow.Offset(), shadow.Blur(), shadow_color,
                                  DrawLooperBuilder::kShadowRespectsTransforms,
                                  DrawLooperBuilder::kShadowIgnoresAlpha);
    context.SetDrawLooper(draw_looper_builder.DetachDrawLooper());

    Color fill_color(shadow_color.Red(), shadow_color.Green(),
                     shadow_color.Blue());
    gfx::RectF outer_rect = AreaCastingShadowInHole(bounds.Rect(), shadow);
    // |AutoDarkMode::Disabled()| is used because |fill_color(shadow_color)| has
    // already been adjusted for dark mode.
    context.FillRectWithRoundedHole(outer_rect, inner_rounded_rect, fill_color,
                                    AutoDarkMode::Disabled());
  }
}

bool BoxPainterBase::ShouldForceWhiteBackgroundForPrintEconomy(
    const Document& document,
    const ComputedStyle& style) {
  return document.Printing() &&
         style.PrintColorAdjust() == EPrintColorAdjust::kEconomy &&
         (!document.GetSettings() ||
          !document.GetSettings()->GetShouldPrintBackgrounds());
}

bool BoxPainterBase::CalculateFillLayerOcclusionCulling(
    FillLayerOcclusionOutputList& reversed_paint_list,
    const FillLayer& fill_layer) {
  bool is_non_associative = false;
  for (auto* current_layer = &fill_layer; current_layer;
       current_layer = current_layer->Next()) {
    reversed_paint_list.push_back(current_layer);
    // Stop traversal when an opaque layer is encountered.
    // FIXME : It would be possible for the following occlusion culling test to
    // be more aggressive on layers with no repeat by testing whether the image
    // covers the layout rect.  Testing that here would imply duplicating a lot
    // of calculations that are currently done in
    // LayoutBoxModelObject::paintFillLayer. A more efficient solution might be
    // to move the layer recursion into paintFillLayer, or to compute the layer
    // geometry here and pass it down.

    // TODO(trchen): Need to check compositing mode as well.
    if (current_layer->GetBlendMode() != BlendMode::kNormal)
      is_non_associative = true;

    // TODO(trchen): A fill layer cannot paint if the calculated tile size is
    // empty.  This occlusion check can be wrong.
    if (current_layer->ClipOccludesNextLayers() &&
        current_layer->ImageOccludesNextLayers(document_, style_)) {
      if (current_layer->Clip() == EFillBox::kBorder)
        is_non_associative = false;
      break;
    }
  }
  return is_non_associative;
}

BoxPainterBase::FillLayerInfo::FillLayerInfo(
    const Document& doc,
    const ComputedStyle& style,
    bool is_scroll_container,
    Color bg_color,
    const FillLayer& layer,
    BackgroundBleedAvoidance bleed_avoidance,
    PhysicalBoxSides sides_to_include,
    bool is_inline,
    bool is_painting_background_in_contents_space)
    : image(layer.GetImage()),
      color(bg_color),
      respect_image_orientation(style.ImageOrientation()),
      sides_to_include(sides_to_include),
      is_bottom_layer(!layer.Next()),
      is_border_fill(layer.Clip() == EFillBox::kStrokeBox ||
                     layer.Clip() == EFillBox::kViewBox ||
                     layer.Clip() == EFillBox::kBorder),
      is_clipped_with_local_scrolling(is_scroll_container &&
                                      layer.Attachment() ==
                                          EFillAttachment::kLocal) {
  // When printing backgrounds is disabled or using economy mode,
  // change existing background colors and images to a solid white background.
  // If there's no bg color or image, leave it untouched to avoid affecting
  // transparency.  We don't try to avoid loading the background images,
  // because this style flag is only set when printing, and at that point
  // we've already loaded the background images anyway. (To avoid loading the
  // background images we'd have to do this check when applying styles rather
  // than while layout.)
  if (BoxPainterBase::ShouldForceWhiteBackgroundForPrintEconomy(doc, style)) {
    // Note that we can't reuse this variable below because the bgColor might
    // be changed.
    bool should_paint_background_color =
        is_bottom_layer && !color.IsFullyTransparent();
    if (image || should_paint_background_color) {
      color = Color::kWhite;
      image = nullptr;
      background_forced_to_white = true;
    }
  }

  // Background images are not allowed at the inline level in forced colors
  // mode when forced-color-adjust is auto. This ensures that the inline images
  // are not painted on top of the forced colors mode backplate.
  if (doc.InForcedColorsMode() && is_inline &&
      style.ForcedColorAdjust() == EForcedColorAdjust::kAuto)
    image = nullptr;

  const bool has_rounded_border =
      style.HasBorderRadius() && !sides_to_include.IsEmpty();
  // BorderFillBox radius clipping is taken care of by
  // BackgroundBleedClip{Only,Layer}.
  is_rounded_fill =
      has_rounded_border && !is_painting_background_in_contents_space &&
      (layer.Clip() != EFillBox::kNoClip) &&
      (is_clipped_with_local_scrolling ||
       !(is_border_fill && BleedAvoidanceIsClipping(bleed_avoidance)));

  is_printing = doc.Printing();

  should_paint_image = image && image->CanRender();
  if (should_paint_image) {
    respect_image_orientation =
        image->ForceOrientationIfNecessary(respect_image_orientation);
  }

  bool composite_bgcolor_animation =
      RuntimeEnabledFeatures::CompositeBGColorAnimationEnabled() &&
      style.HasCurrentBackgroundColorAnimation() &&
      layer.GetType() == EFillLayerType::kBackground;
  // When background color animation is running on the compositor thread, we
  // need to trigger repaint even if the background is transparent to collect
  // artifacts in order to run the animation on the compositor.
  should_paint_color =
      is_bottom_layer &&
      (!color.IsFullyTransparent() || composite_bgcolor_animation) &&
      (!should_paint_image || !layer.ImageOccludesNextLayers(doc, style));
  should_paint_color_with_paint_worklet_image =
      should_paint_color && composite_bgcolor_animation;
}

namespace {

gfx::RectF SnapSourceRectIfNearIntegral(const gfx::RectF src_rect) {
  // Round to avoid filtering pulling in neighboring pixels, for the
  // common case of sprite maps, but only if we're close to an integral size.
  // "Close" in this context means we will allow floating point inaccuracy,
  // when converted to layout units, to be at most one LayoutUnit::Epsilon and
  // still snap.
  if (std::abs(std::round(src_rect.x()) - src_rect.x()) <=
          LayoutUnit::Epsilon() &&
      std::abs(std::round(src_rect.y()) - src_rect.y()) <=
          LayoutUnit::Epsilon() &&
      std::abs(std::round(src_rect.right()) - src_rect.right()) <=
          LayoutUnit::Epsilon() &&
      std::abs(std::round(src_rect.bottom()) - src_rect.bottom()) <=
          LayoutUnit::Epsilon()) {
    gfx::Rect rounded_src_rect = gfx::ToRoundedRect(src_rect);
    // If we have snapped the image size to 0, revert the rounding.
    if (rounded_src_rect.IsEmpty())
      return src_rect;
    return gfx::RectF(rounded_src_rect);
  }
  return src_rect;
}

std::optional<gfx::RectF> OptimizeToSingleTileDraw(
    const BackgroundImageGeometry& geometry,
    const PhysicalRect& dest_rect,
    Image& image,
    RespectImageOrientationEnum respect_orientation) {
  const PhysicalRect& snapped_dest = geometry.SnappedDestRect();

  // Phase calculation uses the actual painted location, given by the
  // border-snapped destination rect.
  const PhysicalRect one_tile_rect(
      snapped_dest.offset + geometry.ComputePhase(), geometry.TileSize());

  // We cannot optimize if the tile is misaligned.
  if (!one_tile_rect.Contains(dest_rect))
    return std::nullopt;

  const PhysicalOffset offset_in_tile = dest_rect.offset - one_tile_rect.offset;
  if (!image.HasIntrinsicSize()) {
    // This is a generated image sized according to the tile size so we can use
    // the snapped dest rect directly.
    const PhysicalRect offset_tile(offset_in_tile, snapped_dest.size);
    return gfx::RectF(offset_tile);
  }

  // Compute the image subset, in intrinsic image coordinates, that gets mapped
  // onto the |dest_rect|, when the whole image would be drawn with phase and
  // size given by |one_tile_rect|. Assumes |one_tile_rect| contains
  // |dest_rect|. The location of the requested subset should be the painting
  // snapped location.
  //
  // The size of requested subset should be the unsnapped size so that the
  // computed scale and location in the source image can be correctly
  // determined.
  //
  // image-resolution information is baked into the given parameters, but we
  // need oriented size.
  const gfx::SizeF intrinsic_tile_size = image.SizeAsFloat(respect_orientation);

  // Subset computation needs the same location as was used above, but needs the
  // unsnapped destination size to correctly calculate sprite subsets in the
  // presence of zoom. We rely on the caller to provide a suitable (snapped)
  // size.
  const gfx::SizeF scale(
      geometry.TileSize().width / intrinsic_tile_size.width(),
      geometry.TileSize().height / intrinsic_tile_size.height());
  gfx::RectF visible_src_rect(
      offset_in_tile.left / scale.width(), offset_in_tile.top / scale.height(),
      dest_rect.Width() / scale.width(), dest_rect.Height() / scale.height());

  // Content providers almost always choose source pixels at integer locations,
  // so snap to integers. This is particularly important for sprite maps.
  // Calculation up to this point, in LayoutUnits, can lead to small variations
  // from integer size, so it is safe to round without introducing major issues.
  visible_src_rect = SnapSourceRectIfNearIntegral(visible_src_rect);

  // When respecting image orientation, the drawing code expects the source
  // rect to be in the unrotated image space, but we have computed it here in
  // the rotated space in order to position and size the background. Undo the
  // src rect rotation if necessary.
  if (respect_orientation && !image.HasDefaultOrientation()) {
    visible_src_rect = image.CorrectSrcRectForImageOrientation(
        intrinsic_tile_size, visible_src_rect);
  }
  return visible_src_rect;
}

PhysicalRect GetSubsetDestRectForImage(const BackgroundImageGeometry& geometry,
                                       const Image& image) {
  // Use the snapped size if the image does not have any intrinsic dimensions,
  // since in that case the image will have been sized according to tile size.
  const PhysicalRect& rect = image.HasIntrinsicSize()
                                 ? geometry.UnsnappedDestRect()
                                 : geometry.SnappedDestRect();
  return {geometry.SnappedDestRect().offset, rect.size};
}

// The unsnapped_subset_size should be the target painting area implied by the
//   content, without any snapping applied. It is necessary to correctly
//   compute the subset of the source image to paint into the destination.
// The snapped_paint_rect should be the target destination for painting into.
// The phase is never snapped.
// The tile_size is the total image size. The mapping from this size
//   to the unsnapped_dest_rect size defines the scaling of the image for
//   sprite computation.
void DrawTiledBackground(LocalFrame* frame,
                         GraphicsContext& context,
                         const ComputedStyle& style,
                         Image& image,
                         const BackgroundImageGeometry& geometry,
                         SkBlendMode op,
                         RespectImageOrientationEnum respect_orientation,
                         ImagePaintTimingInfo paint_timing_info) {
  DCHECK(!geometry.TileSize().IsEmpty());

  const PhysicalRect& snapped_dest = geometry.SnappedDestRect();
  const gfx::RectF dest_rect(snapped_dest);
  // Check and see if a single draw of the image can cover the entire area
  // we are supposed to tile. The dest_rect_for_subset must use the same
  // location that was used in ComputePhaseForBackground and the unsnapped
  // destination rect in order to correctly evaluate the subset size and
  // location in the presence of border snapping and zoom.
  const PhysicalRect dest_rect_for_subset(snapped_dest.offset,
                                          geometry.UnsnappedDestRect().size);
  if (std::optional<gfx::RectF> single_tile_src = OptimizeToSingleTileDraw(
          geometry, dest_rect_for_subset, image, respect_orientation)) {
    auto image_auto_dark_mode = ImageClassifierHelper::GetImageAutoDarkMode(
        *frame, style, dest_rect, *single_tile_src);
    context.DrawImage(image, Image::kSyncDecode, image_auto_dark_mode,
                      paint_timing_info, dest_rect, &*single_tile_src, op,
                      respect_orientation);
    return;
  }

  // At this point we have decided to tile the image to fill the dest rect.

  // Use the intrinsic size of the image if it has one, otherwise force the
  // generated image to be the tile size.
  // image-resolution information is baked into the given parameters, but we
  // need oriented size. That requires explicitly applying orientation here.
  Image::SizeConfig size_config;
  size_config.apply_orientation = respect_orientation;
  const gfx::SizeF intrinsic_tile_size =
      image.SizeWithConfigAsFloat(size_config);

  // Note that this tile rect uses the image's pre-scaled size.
  ImageTilingInfo tiling_info;
  tiling_info.image_rect.set_size(intrinsic_tile_size);
  tiling_info.phase =
      gfx::PointF(snapped_dest.offset + geometry.ComputePhase());
  tiling_info.spacing = gfx::SizeF(geometry.SpaceSize());

  // Farther down the pipeline we will use the scaled tile size to determine
  // which dimensions to clamp or repeat in. We do not want to repeat when the
  // tile size rounds to match the dest in a given dimension, to avoid having
  // a single row or column repeated when the developer almost certainly
  // intended the image to not repeat (this generally occurs under zoom).
  //
  // So detect when we do not want to repeat and set the scale to round the
  // values in that dimension.
  const PhysicalSize tile_dest_diff = geometry.TileSize() - snapped_dest.size;
  const LayoutUnit ref_tile_width = tile_dest_diff.width.Abs() <= 0.5f
                                        ? snapped_dest.Width()
                                        : geometry.TileSize().width;
  const LayoutUnit ref_tile_height = tile_dest_diff.height.Abs() <= 0.5f
                                         ? snapped_dest.Height()
                                         : geometry.TileSize().height;
  tiling_info.scale = {ref_tile_width / tiling_info.image_rect.width(),
                       ref_tile_height / tiling_info.image_rect.height()};

  auto image_auto_dark_mode = ImageClassifierHelper::GetImageAutoDarkMode(
      *frame, style, dest_rect, tiling_info.image_rect);
  // This call takes the unscaled image, applies the given scale, and paints
  // it into the snapped_dest_rect using phase from one_tile_rect and the
  // given repeat spacing. Note the phase is already scaled.
  context.DrawImageTiled(image, dest_rect, tiling_info, image_auto_dark_mode,
                         paint_timing_info, op, respect_orientation);
}

scoped_refptr<Image> GetBGColorPaintWorkletImage(const Document& document,
                                                 Node* node,
                                                 const gfx::SizeF& image_size) {
  BackgroundColorPaintImageGenerator* generator =
      GetBackgroundColorPaintImageGenerator(document);
  // The generator can be null in testing environment.
  if (!generator)
    return nullptr;

  return generator->Paint(image_size, node);
}

// Returns true if the background color was painted by the paint worklet.
bool PaintBGColorWithPaintWorklet(const Document& document,
                                  const BoxPainterBase::FillLayerInfo& info,
                                  Node* node,
                                  const ComputedStyle& style,
                                  const FloatRoundedRect& dest_rect,
                                  GraphicsContext& context) {
  if (!info.should_paint_color_with_paint_worklet_image)
    return false;

  CompositedPaintStatus status = CompositedBackgroundColorStatus(node);

  switch (status) {
    case CompositedPaintStatus::kNoAnimation:
    case CompositedPaintStatus::kNotComposited:
      // Once an animation has been downgraded to run on the main thread, it
      // cannot restart on the compositor without a pending animation update.
      return false;

    case CompositedPaintStatus::kNeedsRepaint:
    case CompositedPaintStatus::kComposited:
      if (CanCompositeBackgroundColorAnimation(node)) {
        SetHasNativeBackgroundPainter(node, true);
      } else {
        SetHasNativeBackgroundPainter(node, false);
        return false;
      }
  }

  scoped_refptr<Image> paint_worklet_image =
      GetBGColorPaintWorkletImage(document, node, dest_rect.Rect().size());
  if (!paint_worklet_image)
    return false;
  gfx::RectF src_rect(dest_rect.Rect().size());
  context.DrawImageRRect(
      *paint_worklet_image, Image::kSyncDecode, Im
```