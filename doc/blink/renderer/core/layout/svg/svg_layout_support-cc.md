Response:
Let's break down the thought process for analyzing the given C++ code snippet.

1. **Understand the Goal:** The request asks for the functionalities of `svg_layout_support.cc`, its relation to web technologies (JavaScript, HTML, CSS), and examples of logic, errors, etc. The key is to extract the *purpose* of the code, not just a mechanical listing of functions.

2. **Initial Scan for Keywords and Concepts:**  A quick scan reveals terms like "SVG," "layout," "transform," "visual rect," "clip," "mask," "stroke," "text," and "hit test."  This immediately tells us the file deals with the layout and rendering of SVG elements within the Blink engine.

3. **Examine Included Headers:** The `#include` directives are crucial. They tell us about the dependencies and the types of operations the file performs.
    * `svg_layout_support.h`:  Self-explanatory, likely contains the declarations for the functions defined in this file.
    * `transform_state.h`: Indicates the code deals with coordinate transformations.
    * `hit_test_location.h`: Suggests involvement in determining what's under the cursor.
    * `layout_svg_inline_text.h`, `layout_svg_resource_clipper.h`, etc.:  Highlights specific SVG element types and layout mechanisms.
    * `svg_resources.h`:  Implies the management and usage of SVG resources like gradients, filters, etc.
    * `css_mask_painter.h`, `outline_painter.h`: Relates to visual effects applied using CSS.
    * `paint_layer.h`: Connects to the compositing and rendering layers in the browser.
    * `svg_element.h`, `svg_length_functions.h`: Deals with the SVG DOM and length calculations.
    * `stroke_data.h`: Focuses on how strokes (outlines) are handled.
    * Other platform and utility headers provide foundational support.

4. **Analyze Namespaces and Classes:** The code is within the `blink` namespace, further confirming its role in the Blink engine. The core class is `SVGLayoutSupport`.

5. **Dissect Key Functions and Their Logic:**  This is the most important step. Go through the prominent functions and understand their purpose.

    * **`LocalVisualRect`:** Calculates the visual bounding box of an SVG element in its local coordinate system. It considers visibility and outlines.
    * **`VisualRectInAncestorSpace` and `MapToVisualRectInAncestorSpace`:**  Crucial for translating coordinates between different SVG elements and the containing HTML document. They handle transformations and clipping. The inclusion of filter mapping is notable.
    * **`MapLocalToAncestor` and `MapAncestorToLocal`:**  Lower-level coordinate mapping functions, specifically handling the SVG root boundary.
    * **`IsOverflowHidden`:** Determines if overflow content should be clipped.
    * **`AdjustWithClipPathAndMask`:**  Applies SVG clipping paths and CSS masks to adjust the visible area.
    * **`ExtendTextBBoxWithStroke` and `ComputeVisualRectForText`:** Handles the visual bounds of SVG text, including strokes and text shadows.
    * **`ResolveSVGDashArray` and `ApplyStrokeStyleToStrokeData`:**  Deals with the styling of SVG strokes, including dashed lines.
    * **`IsLayoutableTextNode`:** Checks if a text node is handled by SVG layout.
    * **`WillIsolateBlendingDescendantsForStyle` and related functions:** Concerns compositing and how blending effects are isolated.
    * **`SubtreeContentTransformScope`:** A utility class for temporarily applying transformations to a subtree.
    * **`CalculateScreenFontSizeScalingFactor`:**  Calculates a scaling factor based on transformations, although it's marked as a "FIXME" indicating potential issues.
    * **`FindClosestLayoutSVGText` and related functions:**  Implements a hit-testing mechanism to find the closest SVG text element to a given point.

6. **Identify Relationships with Web Technologies:**

    * **HTML:** SVG is embedded in HTML. The coordinate mapping functions are essential for positioning SVG elements within the HTML layout. The handling of the `LayoutSVGRoot` at the SVG/HTML boundary is a direct connection.
    * **CSS:**  Many functions directly use `ComputedStyle` to access CSS properties (e.g., `visibility`, `overflow`, `clip-path`, `mask`, `stroke-*`, `text-shadow`). The `OutlinePainter` and `CSSMaskPainter` interactions are further links.
    * **JavaScript:** While the C++ code doesn't *directly* interact with JavaScript, its functionality enables the rendering and interactivity of SVG elements that are often manipulated by JavaScript. For example, JavaScript might change the `transform` attribute, and this C++ code is responsible for applying that transformation during layout. Hit testing is also crucial for JavaScript event handling on SVG elements.

7. **Construct Examples and Scenarios:**  Think about how the different functions would be used in practical web development.

    * **Logic/Transformation:**  Imagine an SVG group (`<g>`) with a `transform` attribute. The `MapLocalToAncestor` function would be used to calculate the position of elements within that group relative to the main SVG canvas or even the HTML document.
    * **User/Programming Errors:** Consider common mistakes developers make with SVG, such as incorrect units in `stroke-width`, leading to unexpected rendering. Or, using `overflow: hidden` on an SVG element and expecting it to clip child elements in a certain way.
    * **Assumptions:** Focus on what the functions assume about their input. For example, coordinate mapping functions assume the existence of a valid transformation matrix.

8. **Structure the Output:** Organize the information logically with clear headings and bullet points. Start with a summary of the file's purpose, then detail the functionalities, web technology connections, examples, and potential errors.

9. **Refine and Review:** Read through the generated explanation and ensure clarity, accuracy, and completeness. Check for any missing connections or misinterpretations. For example, initially, I might focus too much on individual functions. The review step helps to synthesize the information and see the bigger picture of how these functions work together. Also, ensure the examples are concrete and easy to understand.
This C++ source file, `svg_layout_support.cc`, part of the Chromium Blink rendering engine, provides a collection of utility functions and logic specifically designed to support the layout of Scalable Vector Graphics (SVG) content within a web page. It acts as a bridge between the general layout mechanisms of Blink and the specific requirements of SVG.

Here's a breakdown of its functionalities:

**Core Functionalities Related to SVG Layout:**

* **Coordinate Transformations:**  A significant portion of the code deals with transforming coordinates between different SVG elements and their ancestors, including the root SVG element and potentially containing HTML elements. This is crucial for correctly positioning and rendering SVG shapes and text.
    * **`LocalVisualRect`:** Calculates the visual bounding box of an SVG element in its own local coordinate system, considering visibility and outlines.
    * **`VisualRectInAncestorSpace` and `MapToVisualRectInAncestorSpace`:**  Determines the visual bounding box of an SVG element in the coordinate space of an ancestor element. This handles the cumulative effect of transformations applied up the SVG tree.
    * **`MapLocalToAncestor`:**  Transforms a point or rectangle from the local coordinate system of an SVG element to the coordinate system of an ancestor.
    * **`MapAncestorToLocal`:**  Performs the inverse transformation, mapping from an ancestor's coordinate system to the local coordinate system.
    * **`DeprecatedCalculateTransformToLayer`:** Calculates the transformation from an SVG element to its containing paint layer. (Note: The "Deprecated" prefix suggests this might be in the process of being phased out or replaced).
* **Clipping and Masking:**  The code handles how SVG `clipPath` elements and CSS `mask` properties affect the visible area of SVG elements.
    * **`AdjustWithClipPathAndMask`:**  Intersects the visual rectangle of an object with the bounding boxes defined by its `clip-path` and `mask` properties.
* **Stroke Handling:**  Functions related to the rendering of strokes (outlines) on SVG shapes and text.
    * **`ExtendTextBBoxWithStroke`:**  Calculates the bounding box of SVG text, taking into account the stroke width.
    * **`ApplyStrokeStyleToStrokeData`:**  Applies the stroke-related CSS properties (width, line cap, line join, miter limit, dash array, dash offset) to a `StrokeData` object, which is used for actual rendering.
    * **`ResolveSVGDashArray`:**  Converts the SVG dash array values (which can be lengths relative to the viewport) into concrete pixel values.
* **Text Layout Support:**  Specific handling for SVG text elements.
    * **`ComputeVisualRectForText`:** Calculates the visual rectangle for SVG text, including strokes and text shadows.
    * **`IsLayoutableTextNode`:**  Determines if a given text node should be handled by the SVG layout system.
    * **`FindClosestLayoutSVGText`:**  Implements logic to find the closest SVG text element to a given point. This is likely used for features like text selection or cursor placement within SVG text.
* **Overflow Handling:** Determines if the overflow content of an SVG element should be hidden.
    * **`IsOverflowHidden`:** Checks if the `overflow-x` or `overflow-y` CSS properties are set to `hidden`, `clip`, or `scroll`.
* **Blending and Isolation:** Functions related to how blending effects are applied to SVG content, including creating isolated groups for blending.
    * **`WillIsolateBlendingDescendantsForStyle` and `WillIsolateBlendingDescendantsForObject`:** Determine if a blending context needs to be created for an SVG element based on its styles and type.
    * **`IsIsolationRequired`:** Checks if blending isolation is actually needed for a given object.
* **Subtree Content Transformation:**  Allows for temporarily applying a transformation to all descendants of an SVG element.
    * **`SubtreeContentTransformScope`:** A class to manage the temporary application of a content transformation.
    * **`CalculateScreenFontSizeScalingFactor`:** Calculates a scaling factor based on the current transformation, likely used for adjusting font sizes to screen resolution.
* **Hit Testing Support:** The `FindClosestLayoutSVGText` function contributes to hit testing within SVG content.

**Relationship with JavaScript, HTML, and CSS:**

This file is deeply intertwined with the rendering of web content defined by HTML, styled by CSS, and potentially manipulated by JavaScript.

* **HTML:** SVG is often embedded within HTML using the `<svg>` tag. This file's coordinate transformation logic is essential for positioning SVG elements correctly within the overall HTML page layout. The concept of the `LayoutSVGRoot` highlights the boundary between HTML and SVG rendering.
    * **Example:** When an SVG element with a specific `x` and `y` attribute is placed inside a `<div>`, this file's functions ensure it's rendered at the correct location relative to the `<div>`.
* **CSS:**  Many of the functionalities in this file directly rely on CSS properties applied to SVG elements.
    * **Example:** The `ApplyStrokeStyleToStrokeData` function reads CSS properties like `stroke`, `stroke-width`, `stroke-linecap`, `stroke-linejoin`, `stroke-dasharray`, and `stroke-dashoffset` to determine how the outline of an SVG shape should be rendered.
    * **Example:** The `AdjustWithClipPathAndMask` function uses the `clip-path` and `mask` CSS properties to control the visibility of SVG elements.
    * **Example:** The `IsOverflowHidden` function checks the `overflow-x` and `overflow-y` CSS properties.
* **JavaScript:** While this C++ file doesn't directly execute JavaScript, its functionality is crucial for making SVG interactive and dynamic, which is often achieved through JavaScript.
    * **Example:** When JavaScript modifies the `transform` attribute of an SVG element (e.g., using `element.setAttribute('transform', 'translate(10, 20)')`), the layout engine, using functions from this file, recalculates the element's position and rendering based on the new transformation.
    * **Example:** JavaScript event listeners on SVG elements rely on accurate hit testing, which is supported by functions like `FindClosestLayoutSVGText`.
    * **Example:** JavaScript might animate SVG properties like `stroke-dashoffset`, and this file's functions ensure those changes are reflected in the rendered output.

**Logic Inference (Hypothetical Input and Output):**

Let's consider the `MapLocalToAncestor` function:

**Hypothetical Input:**

* `object`: A `LayoutSVGPath` object representing a `<path>` element.
* `ancestor`: A `LayoutSVGRoot` object representing the root `<svg>` element.
* `transform_state`: An initial `TransformState` object (potentially an identity matrix).
* `flags`:  `MapCoordinatesFlags::kNone`.

**Assumptions:**

* The `<path>` element has a `transform` attribute, e.g., `transform="translate(50, 50)"`.
* The root `<svg>` element itself might also have a `transform` (though less common).

**Logical Steps within `MapLocalToAncestor` (simplified):**

1. Apply the local transformation of the `LayoutSVGPath` to `transform_state`. This would involve multiplying the current `transform_state` matrix by the `translate(50, 50)` transformation.
2. If the parent of the `LayoutSVGPath` has a transformation, apply that as well.
3. If the parent is a `LayoutSVGRoot`, apply the `LocalToBorderBoxTransform` of the root.
4. Recursively call `MapLocalToAncestor` on the parent until the `ancestor` is reached.

**Hypothetical Output:**

The `transform_state` object will be updated to contain the combined transformation matrix that maps coordinates from the local coordinate system of the `<path>` element to the coordinate system of the root `<svg>` element. If the root had no additional transformation, the final matrix would effectively be the `translate(50, 50)` transformation.

**User or Programming Common Usage Errors:**

* **Incorrect Units in SVG Attributes/CSS:**
    * **Example:**  Setting `stroke-width: 10` without specifying units in a context where the default unit is not pixels can lead to unexpected stroke sizes. The `ValueForLength` function (used internally) handles unit conversions, but incorrect units in the source will still result in incorrect calculations.
* **Misunderstanding SVG Coordinate Systems:**
    * **Example:** Applying a transformation to a group (`<g>`) and expecting it to affect the absolute position of elements inside the group without considering the group's own coordinate system. This file's functions are designed to handle these nested transformations correctly, but misunderstanding the concept can lead to unexpected layout.
* **Incorrect Use of `overflow` on SVG Elements:**
    * **Example:** Assuming `overflow: hidden` on an inline SVG element will clip content like it does on block-level HTML elements. SVG's overflow behavior can be more nuanced, and improper use might not produce the desired clipping effect.
* **Forgetting Transformations Accumulate:**
    * **Example:** Applying multiple transformations to an element or its ancestors without realizing their effects are cumulative. This can lead to elements being positioned far from their intended location. The coordinate mapping functions in this file are crucial for understanding how these transformations combine.
* **Z-Index Issues with Stacked SVG Elements:** While not directly handled in this file, misunderstanding how `z-index` interacts with SVG elements and their stacking context can lead to rendering problems. This file contributes to the correct positioning of elements within their stacking context.

In summary, `svg_layout_support.cc` is a foundational piece of the Blink rendering engine responsible for the correct layout and rendering of SVG content. It handles the complexities of SVG coordinate systems, transformations, clipping, masking, and styling, ensuring that SVG elements are displayed accurately within web pages. Its functionalities are essential for the seamless integration of SVG with HTML, CSS, and JavaScript.

### 提示词
```
这是目录为blink/renderer/core/layout/svg/svg_layout_support.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2007, 2008 Rob Buis <buis@kde.org>
 * Copyright (C) 2007 Nikolas Zimmermann <zimmermann@kde.org>
 * Copyright (C) 2007 Eric Seidel <eric@webkit.org>
 * Copyright (C) 2009 Google, Inc.  All rights reserved.
 * Copyright (C) 2009 Dirk Schulze <krit@webkit.org>
 * Copyright (C) Research In Motion Limited 2009-2010. All rights reserved.
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
 */

#include "third_party/blink/renderer/core/layout/svg/svg_layout_support.h"

#include "third_party/blink/renderer/core/layout/geometry/transform_state.h"
#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_inline_text.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_resource_clipper.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_resource_masker.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_root.h"
#include "third_party/blink/renderer/core/layout/svg/svg_resources.h"
#include "third_party/blink/renderer/core/paint/css_mask_painter.h"
#include "third_party/blink/renderer/core/paint/outline_painter.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/svg/svg_element.h"
#include "third_party/blink/renderer/core/svg/svg_length_functions.h"
#include "third_party/blink/renderer/platform/graphics/stroke_data.h"
#include "third_party/blink/renderer/platform/heap/collection_support/clear_collection_scope.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "ui/gfx/geometry/rect_conversions.h"

namespace blink {

namespace {

AffineTransform DeprecatedCalculateTransformToLayer(
    const LayoutObject* layout_object) {
  AffineTransform transform;
  while (layout_object) {
    transform = layout_object->LocalToSVGParentTransform() * transform;
    if (layout_object->IsSVGRoot())
      break;
    layout_object = layout_object->Parent();
  }

  // Continue walking up the layer tree, accumulating CSS transforms.
  PaintLayer* layer = layout_object ? layout_object->EnclosingLayer() : nullptr;
  while (layer) {
    if (gfx::Transform* layer_transform = layer->Transform())
      transform = AffineTransform::FromTransform(*layer_transform) * transform;
    layer = layer->Parent();
  }

  return transform;
}

}  // namespace

struct SearchCandidate {
  DISALLOW_NEW();

  SearchCandidate()
      : layout_object(nullptr), distance(std::numeric_limits<double>::max()) {}
  SearchCandidate(LayoutObject* layout_object, double distance)
      : layout_object(layout_object), distance(distance) {}
  void Trace(Visitor* visitor) const { visitor->Trace(layout_object); }

  Member<LayoutObject> layout_object;
  double distance;
};

gfx::RectF SVGLayoutSupport::LocalVisualRect(const LayoutObject& object) {
  // For LayoutSVGRoot, use LayoutSVGRoot::localVisualRect() instead.
  DCHECK(!object.IsSVGRoot());

  // Return early for any cases where we don't actually paint
  if (object.StyleRef().Visibility() != EVisibility::kVisible &&
      !object.EnclosingLayer()->HasVisibleContent()) {
    return gfx::RectF();
  }

  gfx::RectF visual_rect = object.VisualRectInLocalSVGCoordinates();
  if (int outset = OutlinePainter::OutlineOutsetExtent(
          object.StyleRef(),
          LayoutObject::OutlineInfo::GetUnzoomedFromStyle(object.StyleRef()))) {
    visual_rect.Outset(outset);
  }
  return visual_rect;
}

PhysicalRect SVGLayoutSupport::VisualRectInAncestorSpace(
    const LayoutObject& object,
    const LayoutBoxModelObject& ancestor,
    VisualRectFlags flags) {
  PhysicalRect rect;
  MapToVisualRectInAncestorSpace(object, &ancestor, LocalVisualRect(object),
                                 rect, flags);
  return rect;
}

static gfx::RectF MapToSVGRootIncludingFilter(
    const LayoutObject& object,
    const gfx::RectF& local_visual_rect) {
  DCHECK(object.IsSVGChild());

  gfx::RectF visual_rect = local_visual_rect;
  const LayoutObject* parent = &object;
  for (; !parent->IsSVGRoot(); parent = parent->Parent()) {
    const ComputedStyle& style = parent->StyleRef();
    if (style.HasFilter())
      visual_rect = style.Filter().MapRect(visual_rect);
    visual_rect = parent->LocalToSVGParentTransform().MapRect(visual_rect);
  }

  return To<LayoutSVGRoot>(*parent).LocalToBorderBoxTransform().MapRect(
      visual_rect);
}

static const LayoutSVGRoot& ComputeTransformToSVGRoot(
    const LayoutObject& object,
    AffineTransform& root_border_box_transform,
    bool* filter_skipped) {
  DCHECK(object.IsSVGChild());

  const LayoutObject* parent = &object;
  for (; !parent->IsSVGRoot(); parent = parent->Parent()) {
    if (filter_skipped && parent->StyleRef().HasFilter())
      *filter_skipped = true;
    root_border_box_transform.PostConcat(parent->LocalToSVGParentTransform());
  }

  const auto& svg_root = To<LayoutSVGRoot>(*parent);
  root_border_box_transform.PostConcat(svg_root.LocalToBorderBoxTransform());
  return svg_root;
}

bool SVGLayoutSupport::MapToVisualRectInAncestorSpace(
    const LayoutObject& object,
    const LayoutBoxModelObject* ancestor,
    const gfx::RectF& local_visual_rect,
    PhysicalRect& result_rect,
    VisualRectFlags visual_rect_flags) {
  AffineTransform root_border_box_transform;
  bool filter_skipped = false;
  const LayoutSVGRoot& svg_root = ComputeTransformToSVGRoot(
      object, root_border_box_transform, &filter_skipped);

  gfx::RectF adjusted_rect;
  if (filter_skipped)
    adjusted_rect = MapToSVGRootIncludingFilter(object, local_visual_rect);
  else
    adjusted_rect = root_border_box_transform.MapRect(local_visual_rect);

  if (adjusted_rect.IsEmpty()) {
    result_rect = PhysicalRect();
  } else {
    // Use ToEnclosingRect because we cannot properly apply subpixel offset of
    // the SVGRoot since we don't know the desired subpixel accumulation at this
    // point.
    result_rect = PhysicalRect(gfx::ToEnclosingRect(adjusted_rect));
  }

  // Apply initial viewport clip.
  if (svg_root.ClipsToContentBox()) {
    PhysicalRect clip_rect(svg_root.OverflowClipRect(PhysicalOffset()));
    if (visual_rect_flags & kEdgeInclusive) {
      if (!result_rect.InclusiveIntersect(clip_rect))
        return false;
    } else {
      result_rect.Intersect(clip_rect);
    }
  }
  return svg_root.MapToVisualRectInAncestorSpace(ancestor, result_rect,
                                                 visual_rect_flags);
}

void SVGLayoutSupport::MapLocalToAncestor(const LayoutObject* object,
                                          const LayoutBoxModelObject* ancestor,
                                          TransformState& transform_state,
                                          MapCoordinatesFlags flags) {
  if (object == ancestor) {
    return;
  }
  transform_state.ApplyTransform(object->LocalToSVGParentTransform());

  LayoutObject* parent = object->Parent();

  // At the SVG/HTML boundary (aka LayoutSVGRoot), we apply the
  // localToBorderBoxTransform to map an element from SVG viewport coordinates
  // to CSS box coordinates.
  // LayoutSVGRoot's mapLocalToAncestor method expects CSS box coordinates.
  if (auto* svg_root = DynamicTo<LayoutSVGRoot>(*parent)) {
    transform_state.ApplyTransform(svg_root->LocalToBorderBoxTransform());
  }

  parent->MapLocalToAncestor(ancestor, transform_state, flags);
}

void SVGLayoutSupport::MapAncestorToLocal(const LayoutObject& object,
                                          const LayoutBoxModelObject* ancestor,
                                          TransformState& transform_state,
                                          MapCoordinatesFlags flags) {
  // |object| is either a LayoutSVGModelObject or a LayoutSVGBlock here. In
  // the former case, |object| can never be an ancestor while in the latter
  // the caller is responsible for doing the ancestor check. Because of this,
  // computing the transform to the SVG root is always what we want to do here.
  DCHECK_NE(ancestor, &object);
  DCHECK(object.IsSVGContainer() || object.IsSVGShape() ||
         object.IsSVGImage() || object.IsSVGForeignObject());
  AffineTransform local_to_svg_root;
  const LayoutSVGRoot& svg_root =
      ComputeTransformToSVGRoot(object, local_to_svg_root, nullptr);

  svg_root.MapAncestorToLocal(ancestor, transform_state, flags);

  transform_state.ApplyTransform(local_to_svg_root);
}

bool SVGLayoutSupport::IsOverflowHidden(const LayoutObject& object) {
  // LayoutSVGRoot should never query for overflow state - it should always clip
  // itself to the initial viewport size.
  DCHECK(!object.IsDocumentElement());
  return IsOverflowHidden(object.StyleRef());
}

bool SVGLayoutSupport::IsOverflowHidden(const ComputedStyle& style) {
  return style.OverflowX() == EOverflow::kHidden ||
         style.OverflowX() == EOverflow::kClip ||
         style.OverflowX() == EOverflow::kScroll;
}

void SVGLayoutSupport::AdjustWithClipPathAndMask(
    const LayoutObject& layout_object,
    const gfx::RectF& object_bounding_box,
    gfx::RectF& visual_rect) {
  SVGResourceClient* client = SVGResources::GetClient(layout_object);
  if (!client)
    return;
  const ComputedStyle& style = layout_object.StyleRef();
  if (LayoutSVGResourceClipper* clipper =
          GetSVGResourceAsType(*client, style.ClipPath()))
    visual_rect.Intersect(clipper->ResourceBoundingBox(object_bounding_box));
  if (auto mask_bbox =
          CSSMaskPainter::MaskBoundingBox(layout_object, PhysicalOffset())) {
    visual_rect.Intersect(*mask_bbox);
  }
}

gfx::RectF SVGLayoutSupport::ExtendTextBBoxWithStroke(
    const LayoutObject& layout_object,
    const gfx::RectF& text_bounds) {
  DCHECK(layout_object.IsSVGText() || layout_object.IsSVGInline());
  gfx::RectF bounds = text_bounds;
  const ComputedStyle& style = layout_object.StyleRef();
  if (style.HasStroke()) {
    const SVGViewportResolver viewport_resolver(layout_object);
    // TODO(fs): This approximation doesn't appear to be conservative enough
    // since while text (usually?) won't have caps it could have joins and thus
    // miters.
    bounds.Outset(ValueForLength(style.StrokeWidth(), viewport_resolver));
  }
  return bounds;
}

gfx::RectF SVGLayoutSupport::ComputeVisualRectForText(
    const LayoutObject& layout_object,
    const gfx::RectF& text_bounds) {
  DCHECK(layout_object.IsSVGText() || layout_object.IsSVGInline());
  gfx::RectF visual_rect = ExtendTextBBoxWithStroke(layout_object, text_bounds);
  if (const ShadowList* text_shadow = layout_object.StyleRef().TextShadow())
    text_shadow->AdjustRectForShadow(visual_rect);
  return visual_rect;
}

DashArray SVGLayoutSupport::ResolveSVGDashArray(
    const SVGDashArray& svg_dash_array,
    const ComputedStyle& style,
    const SVGViewportResolver& viewport_resolver) {
  DashArray dash_array;
  for (const Length& dash_length : svg_dash_array.data) {
    dash_array.push_back(ValueForLength(dash_length, viewport_resolver, style));
  }
  return dash_array;
}

void SVGLayoutSupport::ApplyStrokeStyleToStrokeData(StrokeData& stroke_data,
                                                    const ComputedStyle& style,
                                                    const LayoutObject& object,
                                                    float dash_scale_factor) {
  DCHECK(object.GetNode());
  DCHECK(object.GetNode()->IsSVGElement());

  const SVGViewportResolver viewport_resolver(object);
  stroke_data.SetThickness(
      ValueForLength(style.StrokeWidth(), viewport_resolver));
  stroke_data.SetLineCap(style.CapStyle());
  stroke_data.SetLineJoin(style.JoinStyle());
  stroke_data.SetMiterLimit(style.StrokeMiterLimit());

  DashArray dash_array =
      ResolveSVGDashArray(*style.StrokeDashArray(), style, viewport_resolver);
  float dash_offset =
      ValueForLength(style.StrokeDashOffset(), viewport_resolver, style);
  // Apply scaling from 'pathLength'.
  if (dash_scale_factor != 1) {
    DCHECK_GE(dash_scale_factor, 0);
    dash_offset *= dash_scale_factor;
    for (auto& dash_item : dash_array)
      dash_item *= dash_scale_factor;
  }
  stroke_data.SetLineDash(dash_array, dash_offset);
}

bool SVGLayoutSupport::IsLayoutableTextNode(const LayoutObject* object) {
  DCHECK(object->IsText());
  // <br> is marked as text, but is not handled by the SVG layout code-path.
  const auto* svg_inline_text = DynamicTo<LayoutSVGInlineText>(object);
  return svg_inline_text && !svg_inline_text->HasEmptyText();
}

bool SVGLayoutSupport::WillIsolateBlendingDescendantsForStyle(
    const ComputedStyle& style) {
  return style.HasGroupingProperty(style.BoxReflect());
}

bool SVGLayoutSupport::WillIsolateBlendingDescendantsForObject(
    const LayoutObject* object) {
  if (object->IsSVGHiddenContainer())
    return false;
  if (!object->IsSVGRoot() && !object->IsSVGContainer())
    return false;
  return WillIsolateBlendingDescendantsForStyle(object->StyleRef());
}

bool SVGLayoutSupport::IsIsolationRequired(const LayoutObject* object) {
  return WillIsolateBlendingDescendantsForObject(object) &&
         object->HasNonIsolatedBlendingDescendants();
}

AffineTransform SubtreeContentTransformScope::current_content_transformation_;

SubtreeContentTransformScope::SubtreeContentTransformScope(
    const AffineTransform& subtree_content_transformation)
    : saved_content_transformation_(current_content_transformation_) {
  current_content_transformation_.PostConcat(subtree_content_transformation);
}

SubtreeContentTransformScope::~SubtreeContentTransformScope() {
  current_content_transformation_ = saved_content_transformation_;
}

float SVGLayoutSupport::CalculateScreenFontSizeScalingFactor(
    const LayoutObject* layout_object) {
  DCHECK(layout_object);

  // FIXME: trying to compute a device space transform at record time is wrong.
  // All clients should be updated to avoid relying on this information, and the
  // method should be removed.
  AffineTransform ctm =
      DeprecatedCalculateTransformToLayer(layout_object) *
      SubtreeContentTransformScope::CurrentContentTransformation();

  return ClampTo<float>(sqrt((ctm.XScaleSquared() + ctm.YScaleSquared()) / 2));
}

static inline bool CompareCandidateDistance(const SearchCandidate& r1,
                                            const SearchCandidate& r2) {
  return r1.distance < r2.distance;
}

static inline double DistanceToChildLayoutObject(LayoutObject* child,
                                                 const gfx::PointF& point) {
  const AffineTransform& local_to_parent_transform =
      child->LocalToSVGParentTransform();
  if (!local_to_parent_transform.IsInvertible())
    return std::numeric_limits<float>::max();
  gfx::PointF child_local_point =
      local_to_parent_transform.Inverse().MapPoint(point);
  return (child->ObjectBoundingBox().ClosestPoint(child_local_point) -
          child_local_point)
      .LengthSquared();
}

static SearchCandidate SearchTreeForFindClosestLayoutSVGText(
    const LayoutObject* layout_object,
    const gfx::PointF& point) {
  // Try to find the closest LayoutSVGText.
  SearchCandidate closest_text;
  HeapVector<SearchCandidate> candidates;
  ClearCollectionScope<HeapVector<SearchCandidate>> scope(&candidates);

  // Find the closest LayoutSVGText on this tree level, and also collect any
  // containers that could contain LayoutSVGTexts that are closer.
  for (LayoutObject* child = layout_object->SlowLastChild(); child;
       child = child->PreviousSibling()) {
    if (child->IsSVGText()) {
      double distance = DistanceToChildLayoutObject(child, point);
      if (distance >= closest_text.distance)
        continue;
      closest_text.layout_object = child;
      closest_text.distance = distance;
      continue;
    }

    if (child->IsSVGContainer() && !layout_object->IsSVGHiddenContainer()) {
      double distance = DistanceToChildLayoutObject(child, point);
      if (distance > closest_text.distance)
        continue;
      candidates.push_back(SearchCandidate(child, distance));
    }
  }

  // If a LayoutSVGText was found and there are no potentially closer sub-trees,
  // just return |closestText|.
  if (closest_text.layout_object && candidates.empty())
    return closest_text;

  std::stable_sort(candidates.begin(), candidates.end(),
                   CompareCandidateDistance);

  // Find the closest LayoutSVGText in the sub-trees in |candidates|.
  // If a LayoutSVGText is found that is strictly closer than any previous
  // candidate, then end the search.
  for (const SearchCandidate& search_candidate : candidates) {
    if (closest_text.distance < search_candidate.distance)
      break;
    LayoutObject* candidate_layout_object = search_candidate.layout_object;
    gfx::PointF candidate_local_point =
        candidate_layout_object->LocalToSVGParentTransform().Inverse().MapPoint(
            point);

    SearchCandidate candidate_text = SearchTreeForFindClosestLayoutSVGText(
        candidate_layout_object, candidate_local_point);

    if (candidate_text.distance < closest_text.distance)
      closest_text = candidate_text;
  }

  return closest_text;
}

LayoutObject* SVGLayoutSupport::FindClosestLayoutSVGText(
    const LayoutObject* layout_object,
    const gfx::PointF& point) {
  return SearchTreeForFindClosestLayoutSVGText(layout_object, point)
      .layout_object;
}

}  // namespace blink

WTF_ALLOW_CLEAR_UNUSED_SLOTS_WITH_MEM_FUNCTIONS(blink::SearchCandidate)
```