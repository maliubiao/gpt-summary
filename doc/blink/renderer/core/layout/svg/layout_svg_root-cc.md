Response:
Let's break down the thought process for analyzing the `LayoutSVGRoot.cc` file and generating the detailed explanation.

**1. Understanding the Goal:**

The request asks for a comprehensive overview of the `LayoutSVGRoot.cc` file, specifically focusing on:

* **Functionality:** What does this file *do*?
* **Relationship with Web Technologies (HTML, CSS, JavaScript):** How does it interact with the core web standards?
* **Logical Reasoning (Hypothetical Inputs/Outputs):**  Can we illustrate its behavior with examples?
* **Common User/Programming Errors:** What mistakes are possible when dealing with the concepts implemented in this file?

**2. Initial Skim and Identifying Key Concepts:**

The first step is to read through the code, even without deeply understanding every line. Look for keywords and familiar concepts. The included headers (`#include`) provide strong clues. I see:

* `layout/`: This strongly suggests responsibility for calculating the position and size of elements on the page.
* `svg/`: Clearly related to Scalable Vector Graphics.
* `LayoutReplaced`:  Inheritance, indicating it's a specific type of replaced element layout.
* `SVGElement`, `SVGSVGElement`:  Direct interaction with SVG DOM elements.
* `IntrinsicSizingInfo`:  Dealing with how the element's size is determined inherently.
* `LocalToBorderBoxTransform`: Handling transformations and coordinate systems.
* `HitTest`: Determining what element is clicked or interacted with.
* `Paint`:  How the element is drawn on the screen.
* `StyleDidChange`: Responding to changes in CSS styles.

This initial scan gives me a good high-level understanding. It's about laying out the root `<svg>` element and managing its properties and interactions.

**3. Deeper Dive into Functionality (Method by Method):**

Now, go through each method in the class `LayoutSVGRoot` and try to understand its purpose.

* **Constructor/Destructor:** Basic object lifecycle management.
* **`Trace`:** For debugging and memory management. Less relevant to the core functionality from a user perspective.
* **`UnscaledIntrinsicSizingInfo`, `ComputeIntrinsicSizingInfo`:**  Clearly related to calculating the default or inherent size of the SVG. Pay attention to `viewBox`.
* **`IsEmbeddedThroughSVGImage`, `IsEmbeddedThroughFrameContainingSVGDocument`:**  Checking the context in which the SVG is used (inline `<svg>` vs. `<image>` or `<iframe>`). This is crucial for understanding how sizing and behavior might differ.
* **`LogicalSizeScaleFactorForPercentageLengths`:** Handling how percentage-based sizes within the SVG are interpreted, especially with zooming.
* **`LayoutRoot`:**  The core layout method. Notice the use of `SVGTransformChange`, indicating recalculating transformations. The interaction with `PaintLayer` is important.
* **`RecalcVisualOverflow`, `ComputeContentsVisualOverflow`:**  Determining the area that the SVG's content occupies, including potential overflow.
* **`PaintReplaced`:**  The actual drawing of the SVG content.
* **`WillBeDestroyed`:** Cleanup operations.
* **`IntrinsicSizeIsFontMetricsDependent`, `StyleChangeAffectsIntrinsicSize`, `IntrinsicSizingInfoChanged`:** Handling how changes in font size and style affect the SVG's intrinsic size and how to notify parent elements.
* **`StyleDidChange`:**  Responding to CSS changes, including transformations and triggering layout updates.
* **`IsChildAllowed`, `AddChild`, `RemoveChild`:** Managing the children of the SVG element and tracking properties like blending.
* **`HasNonIsolatedBlendingDescendants`, `DescendantIsolationRequirementsChanged`:**  Related to compositing and how blending effects are handled.
* **`InsertedIntoTree`, `WillBeRemovedFromTree`:** Lifecycle events related to adding/removing the SVG from the DOM.
* **`PositionForPoint`:**  Crucial for event handling (like mouse clicks) within the SVG, taking transformations into account.
* **`BuildLocalToBorderBoxTransform`, `LocalToSVGParentTransform`:**  Core methods for calculating coordinate transformations.
* **`ViewBoxRect`, `ViewportSize`:**  Getting information about the SVG's visible area.
* **`MapLocalToAncestor`:**  Mapping coordinates to parent elements.
* **`HitTestChildren`, `IsInSelfHitTestingPhase`, `IntersectChildren`:**  Detailed hit-testing logic, handling different phases.
* **`AddSvgTextDescendant`, `RemoveSvgTextDescendant`:**  Tracking text elements within the SVG.
* **`LayerTypeRequired`:**  Determining if a dedicated paint layer is needed (important for performance and compositing).
* **`ComputeOverflowClipAxes`:**  Deciding how the SVG's content should be clipped if it overflows.

**4. Connecting to Web Technologies:**

As I understand each method's functionality, I explicitly think about how it relates to HTML, CSS, and JavaScript:

* **HTML:** The `<svg>` tag itself is the primary connection. The file handles the layout and rendering of elements within this tag.
* **CSS:** CSS properties like `width`, `height`, `overflow`, `transform`, `zoom`, and blending modes directly influence the logic in this file. The `StyleDidChange` method handles these changes.
* **JavaScript:** JavaScript can manipulate the SVG DOM (e.g., changing attributes, adding/removing elements), which in turn triggers layout and paint updates handled by this code. Event listeners in JavaScript interact with the hit-testing mechanisms.

**5. Crafting Examples and Explanations:**

With a solid understanding of the code, I can now create meaningful examples:

* **Intrinsic Sizing:**  Show how the `width` and `height` attributes and the `viewBox` influence the initial size.
* **Embedding:** Illustrate the difference in behavior when an SVG is used as an `<img>` versus inline.
* **Transformations:**  Demonstrate how CSS `transform` affects the coordinate system.
* **Hit Testing:**  Explain how clicks are routed to the correct SVG elements, even with transformations.
* **Overflow:** Show how the `overflow` property works on the root SVG.
* **Common Errors:**  Think about typical mistakes developers make with SVGs, like incorrect `viewBox` settings or misunderstanding coordinate systems.

**6. Logical Reasoning (Hypothetical Inputs/Outputs):**

For each key function, consider a simple input and predict the output. For example:

* **Input (CSS):** `svg { width: 100px; height: 50px; }`  **Output:** The `ComputeIntrinsicSizingInfo` will likely return a size close to 100x50, possibly adjusted by zoom.
* **Input (User Action):** Clicking on a specific shape inside the SVG. **Output:** The `HitTestChildren` and related methods will identify the clicked element.

**7. Review and Refine:**

Finally, reread the explanation and ensure it's clear, accurate, and addresses all aspects of the original request. Use clear and concise language. Organize the information logically.

By following this detailed process, moving from a high-level understanding to specific function analysis and then connecting it back to web technologies and practical examples, a comprehensive and accurate explanation can be generated.
This file, `layout_svg_root.cc`, within the Chromium Blink engine, is responsible for the **layout and rendering of the root `<svg>` element**. Think of it as the main controller for positioning and displaying all the SVG content within a given `<svg>` tag.

Here's a breakdown of its key functionalities:

**Core Responsibilities:**

* **Managing the Layout of the Root SVG:**  It determines the size and position of the root `<svg>` element itself within its containing environment (e.g., a webpage). This involves considering attributes like `width`, `height`, and how the SVG is embedded (inline, as an image, or in an iframe).
* **Handling Intrinsic Sizing:** It calculates the default or "intrinsic" size of the SVG if no explicit width or height is provided. This can be based on the `viewBox` attribute or the dimensions of its content.
* **Applying Transformations:** It manages transformations applied to the root SVG, such as scaling, translation, and rotation, often driven by CSS `transform` properties.
* **Coordinate System Management:** It plays a crucial role in establishing and managing the SVG's coordinate system, including the mapping between the SVG's internal coordinates and the coordinates of the surrounding webpage. This is essential for accurate rendering and hit-testing.
* **Hit Testing:** It's involved in determining which SVG element is targeted when a user interacts with the SVG (e.g., clicks, hovers). It needs to account for the transformations applied to the SVG and its elements.
* **Painting:**  It orchestrates the painting process for the entire SVG, delegating the rendering of individual shapes and elements to other parts of the rendering engine.
* **Handling Overflow:** It determines how the SVG content should be handled if it exceeds the bounds of the root `<svg>` element, respecting the `overflow` CSS property (or default behavior).
* **Responding to Style Changes:** It reacts to changes in CSS styles that affect the root SVG, triggering re-layout and re-painting as needed.
* **Managing Compositing:** It participates in the compositing process, which involves deciding which parts of the SVG should be rendered in separate layers for performance optimization, especially when dealing with effects like blending and masking.

**Relationship with JavaScript, HTML, and CSS:**

`LayoutSVGRoot.cc` acts as a bridge between the declarative nature of HTML and CSS and the dynamic possibilities of JavaScript.

* **HTML:**
    * **Example:** When the browser encounters an `<svg>` tag in the HTML, it creates a corresponding `LayoutSVGRoot` object to manage its layout.
    * **Functionality:** The `LayoutSVGRoot` reads attributes from the `<svg>` tag like `width`, `height`, and `viewBox` to determine its initial size and coordinate system.
    * **Example:**  If you have `<svg width="200" height="100">...</svg>`, the `LayoutSVGRoot` will initially try to allocate a space of 200x100 pixels for the SVG.

* **CSS:**
    * **Example:**  CSS properties applied to the `<svg>` element directly influence the behavior of `LayoutSVGRoot`.
    * **Functionality:**
        * `width` and `height`: CSS can override the HTML attributes, and `LayoutSVGRoot` will respect these CSS values during layout.
        * `transform`: CSS `transform` properties (e.g., `scale`, `rotate`, `translate`) are used by `LayoutSVGRoot` to apply transformations to the SVG's coordinate system.
        * `overflow`:  The `overflow` property on the `<svg>` element dictates how content that exceeds its bounds is handled (e.g., hidden, scrollable). `LayoutSVGRoot` uses this information to determine clipping behavior.
        * `zoom`: The CSS `zoom` property affects the scaling of the SVG, which `LayoutSVGRoot` takes into account.
        * Blending modes (`mix-blend-mode`, `isolation`): These CSS properties on the root SVG or its descendants are considered when `LayoutSVGRoot` determines if compositing layers are needed.
    * **Example:** If you have `svg { transform: rotate(45deg); }`, the `LayoutSVGRoot` will apply a 45-degree rotation to the entire SVG content during rendering. The `StyleDidChange` method in `LayoutSVGRoot` would be triggered by this CSS change.

* **JavaScript:**
    * **Example:** JavaScript can dynamically manipulate the attributes of the `<svg>` element or its children, triggering layout updates handled by `LayoutSVGRoot`.
    * **Functionality:**
        * Changing attributes like `width`, `height`, or `viewBox` via JavaScript will cause `LayoutSVGRoot` to recalculate the layout.
        * JavaScript can trigger animations that involve transformations, and `LayoutSVGRoot` will update the rendering accordingly.
        * JavaScript event listeners attached to elements within the SVG rely on the hit-testing logic implemented in `LayoutSVGRoot` to determine which element was interacted with.
    * **Example:** If a JavaScript function changes the `viewBox` attribute of the `<svg>` element, `LayoutSVGRoot` will re-establish the SVG's coordinate system based on the new `viewBox`.

**Logical Reasoning (Hypothetical Input & Output):**

Let's consider a simple scenario:

**Hypothetical Input (HTML):**

```html
<div style="width: 300px; height: 200px;">
  <svg id="mySvg" viewBox="0 0 100 50" style="width: 100%; height: 100%;">
    <rect x="10" y="10" width="80" height="30" fill="red" />
  </svg>
</div>
```

**Hypothetical Assumptions:**

* The containing `div` has a fixed width of 300px and height of 200px.
* The `<svg>` element has `width: 100%; height: 100%`, meaning it should take up the full dimensions of its parent.
* The `viewBox` is "0 0 100 50", defining the user coordinate system of the SVG.

**Logical Reasoning by `LayoutSVGRoot`:**

1. **Initial Size:** The `LayoutSVGRoot` for `#mySvg` will determine its initial size based on the CSS `width: 100%` and `height: 100%`. This means the SVG will have a physical size of 300px x 200px.
2. **Coordinate System Mapping:** The `viewBox="0 0 100 50"` tells `LayoutSVGRoot` that the internal SVG drawing area ranges from 0 to 100 in the x-direction and 0 to 50 in the y-direction.
3. **Scaling:** Since the physical size is 300x200 and the `viewBox` defines a logical size of 100x50, `LayoutSVGRoot` will calculate a scaling factor to map the logical coordinates to the physical pixels. In this case, the scaling factor would be 3 in the x-direction (300/100) and 4 in the y-direction (200/50).
4. **Layout of Child Elements:**  When laying out the `<rect>`, the `LayoutSVGRoot` (or related layout objects for SVG elements) will interpret the `x`, `y`, `width`, and `height` attributes in the context of the `viewBox`'s coordinate system. So, the rectangle with `x="10"`, `y="10"`, `width="80"`, and `height="30"` in the SVG's logical units will be rendered in the physical space, taking the scaling factor into account.

**Hypothetical Output (Rendering):**

The red rectangle will be drawn within the 300x200 pixel area of the SVG. Its top-left corner will be at approximately (30px, 40px) in physical pixels (10 * 3, 10 * 4), and its dimensions will be approximately 240px x 120px (80 * 3, 30 * 4).

**User and Programming Common Usage Errors:**

* **Incorrect `viewBox` settings:**  Setting the `viewBox` incorrectly can lead to unexpected scaling or cropping of the SVG content. For instance, if the aspect ratio of the `viewBox` doesn't match the aspect ratio of the SVG's dimensions, the content might be stretched or compressed.
    * **Example:** `<svg width="200" height="100" viewBox="0 0 50 50">...</svg>` will cause the SVG content to be stretched horizontally because the `viewBox` defines a square area while the SVG element is rectangular.
* **Misunderstanding coordinate systems:** Developers might struggle with the difference between the SVG's user coordinate system (defined by `viewBox`) and the physical pixel coordinates. Applying transformations without understanding the current coordinate system can lead to unexpected results.
    * **Example:** Applying a CSS `transform: translate(10px, 10px)` to an SVG without considering the `viewBox` might not move the content by 10 logical units but by 10 physical pixels, which could be a different amount depending on the scaling.
* **Forgetting to set `width` and `height` on the `<svg>` element:** If `width` and `height` are not explicitly set (either as HTML attributes or CSS properties), the SVG might render with a default size (often 300x150), which might not be the desired behavior.
* **Incorrectly assuming pixel units within SVG:**  Units within SVG attributes (like `x`, `y`, `width`, `height` of shapes) are generally in the user coordinate system defined by the `viewBox`, not necessarily physical pixels, unless specific units like "px" are used.
* **Over-reliance on CSS zoom without considering SVG's inherent scaling:**  Using CSS `zoom` on an SVG can sometimes interact unexpectedly with the scaling defined by the `viewBox`. It's important to understand how these two mechanisms interact.
* **Not understanding how `overflow` works on the root SVG:**  Developers might expect `overflow: hidden` on the root SVG to clip content in the same way it works on regular HTML elements, but the behavior can be slightly different due to the SVG's coordinate system.

In summary, `layout_svg_root.cc` is a fundamental component in Blink for correctly positioning, sizing, transforming, and rendering the core `<svg>` element and managing its interaction with the browser's rendering pipeline. Understanding its role is crucial for web developers working with SVG.

Prompt: 
```
这是目录为blink/renderer/core/layout/svg/layout_svg_root.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2004, 2005, 2007 Nikolas Zimmermann <zimmermann@kde.org>
 * Copyright (C) 2004, 2005, 2007, 2008, 2009 Rob Buis <buis@kde.org>
 * Copyright (C) 2007 Eric Seidel <eric@webkit.org>
 * Copyright (C) 2009 Google, Inc.
 * Copyright (C) Research In Motion Limited 2011. All rights reserved.
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

#include "third_party/blink/renderer/core/layout/svg/layout_svg_root.h"

#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/frame/frame_owner.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/intrinsic_sizing_info.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_resource_container.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_text.h"
#include "third_party/blink/renderer/core/layout/svg/svg_layout_info.h"
#include "third_party/blink/renderer/core/layout/svg/svg_layout_support.h"
#include "third_party/blink/renderer/core/layout/svg/svg_resources.h"
#include "third_party/blink/renderer/core/layout/svg/transform_helper.h"
#include "third_party/blink/renderer/core/layout/svg/transformed_hit_test_location.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/paint/compositing/compositing_reason_finder.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/svg_root_painter.h"
#include "third_party/blink/renderer/core/svg/graphics/svg_image.h"
#include "third_party/blink/renderer/core/svg/svg_animated_length.h"
#include "third_party/blink/renderer/core/svg/svg_animated_rect.h"
#include "third_party/blink/renderer/core/svg/svg_element.h"
#include "third_party/blink/renderer/core/svg/svg_svg_element.h"
#include "third_party/blink/renderer/platform/geometry/length_functions.h"

namespace blink {

LayoutSVGRoot::LayoutSVGRoot(SVGElement* node)
    : LayoutReplaced(node),
      needs_transform_update_(true),
      has_non_isolated_blending_descendants_(false),
      has_non_isolated_blending_descendants_dirty_(false) {}

LayoutSVGRoot::~LayoutSVGRoot() = default;

void LayoutSVGRoot::Trace(Visitor* visitor) const {
  visitor->Trace(content_);
  visitor->Trace(text_set_);
  LayoutReplaced::Trace(visitor);
}

void LayoutSVGRoot::UnscaledIntrinsicSizingInfo(
    const SVGRect* override_viewbox,
    IntrinsicSizingInfo& intrinsic_sizing_info) const {
  NOT_DESTROYED();
  // https://www.w3.org/TR/SVG/coords.html#IntrinsicSizing

  auto* svg = To<SVGSVGElement>(GetNode());
  DCHECK(svg);

  std::optional<float> intrinsic_width = svg->IntrinsicWidth();
  std::optional<float> intrinsic_height = svg->IntrinsicHeight();
  intrinsic_sizing_info.size =
      gfx::SizeF(intrinsic_width.value_or(0), intrinsic_height.value_or(0));
  intrinsic_sizing_info.has_width = intrinsic_width.has_value();
  intrinsic_sizing_info.has_height = intrinsic_height.has_value();

  if (!intrinsic_sizing_info.size.IsEmpty()) {
    intrinsic_sizing_info.aspect_ratio = intrinsic_sizing_info.size;
  } else {
    const SVGRect& view_box =
        override_viewbox ? *override_viewbox : svg->CurrentViewBox();
    const gfx::SizeF view_box_size = view_box.Rect().size();
    if (!view_box_size.IsEmpty()) {
      // The viewBox can only yield an intrinsic ratio, not an intrinsic size.
      intrinsic_sizing_info.aspect_ratio = view_box_size;
    }
  }
}

void LayoutSVGRoot::ComputeIntrinsicSizingInfo(
    IntrinsicSizingInfo& intrinsic_sizing_info) const {
  NOT_DESTROYED();
  DCHECK(!ShouldApplySizeContainment());
  UnscaledIntrinsicSizingInfo(intrinsic_sizing_info);

  intrinsic_sizing_info.size.Scale(StyleRef().EffectiveZoom());
}

bool LayoutSVGRoot::IsEmbeddedThroughSVGImage() const {
  NOT_DESTROYED();
  return SVGImage::IsInSVGImage(To<SVGSVGElement>(GetNode()));
}

bool LayoutSVGRoot::IsEmbeddedThroughFrameContainingSVGDocument() const {
  NOT_DESTROYED();
  if (!IsDocumentElement() || !GetNode()) {
    return false;
  }

  LocalFrame* frame = GetNode()->GetDocument().GetFrame();
  if (!frame || !frame->GetDocument()->IsSVGDocument())
    return false;

  if (frame->Owner() && frame->Owner()->IsRemote())
    return true;

  // If our frame has an owner layoutObject, we're embedded through eg.
  // object/embed/iframe, but we only negotiate if we're in an SVG document
  // inside a embedded object (object/embed).
  LayoutObject* owner_layout_object = frame->OwnerLayoutObject();
  return owner_layout_object && owner_layout_object->IsEmbeddedObject();
}

double LayoutSVGRoot::LogicalSizeScaleFactorForPercentageLengths() const {
  NOT_DESTROYED();
  CHECK(IsDocumentElement());
  if (!GetDocument().IsInOutermostMainFrame() ||
      GetDocument().GetLayoutView()->ShouldUsePaginatedLayout()) {
    return 1;
  }
  // This will return the zoom factor which is different from the typical usage
  // of "zoom factor" in blink (e.g., |LocalFrame::LayoutZoomFactor()|) which
  // includes CSS zoom and the device scale factor (if use-zoom-for-dsf is
  // enabled). For this special-case, we only want to include the user's zoom
  // factor, as all other types of zoom should not scale a percentage-sized svg.
  return GetFrame()->GetChromeClient().UserZoomFactor(GetFrame());
}

void LayoutSVGRoot::LayoutRoot(const PhysicalRect& content_rect) {
  NOT_DESTROYED();
  DCHECK(NeedsLayout());

  base::AutoReset<const PhysicalSize*> reset(&new_content_size_,
                                             &content_rect.size, nullptr);

  const PhysicalSize old_content_size = PhysicalContentBoxSize();

  // Whether we have a self-painting layer depends on whether there are
  // compositing descendants (see: |HasCompositingDescendants()| which is called
  // from |PaintLayer::UpdateSelfPaintingLayer()|). We cannot do this update in
  // StyleDidChange because descendants have not yet run StyleDidChange, so we
  // don't know their compositing reasons yet. A layout is scheduled when
  // |HasCompositingDescendants()| changes to ensure this is run.
  if (Layer())
    Layer()->UpdateSelfPaintingLayer();

  // The local-to-border-box transform is a function with the following as
  // input:
  //
  //  * effective zoom
  //  * contentWidth/Height
  //  * viewBox
  //  * border + padding
  //  * currentTranslate
  //  * currentScale
  //
  // Which means that |transformChange| will notice a change to the scale from
  // any of these.
  SVGTransformChange transform_change =
      BuildLocalToBorderBoxTransform(content_rect);

  // The scale factor from the local-to-border-box transform is all that our
  // scale-dependent descendants care about.
  const bool screen_scale_factor_changed =
      transform_change == SVGTransformChange::kFull;

  // selfNeedsLayout() will cover changes to one (or more) of viewBox,
  // current{Scale,Translate}, decorations and 'overflow'.
  const bool viewport_may_have_changed =
      SelfNeedsFullLayout() || old_content_size != content_rect.size;

  SVGLayoutInfo layout_info;
  layout_info.scale_factor_changed = screen_scale_factor_changed;
  layout_info.viewport_changed = viewport_may_have_changed;

  const SVGLayoutResult content_result = content_.Layout(layout_info);

  // Boundaries affects the mask clip. (Other resources handled elsewhere.)
  if (content_result.bounds_changed) {
    SetNeedsPaintPropertyUpdate();
  }
  needs_transform_update_ = false;

  // The scale of one or more of the SVG elements may have changed, content
  // (the entire SVG) could have moved or new content may have been exposed, so
  // mark the entire subtree as needing paint invalidation checking.
  if (transform_change != SVGTransformChange::kNone ||
      viewport_may_have_changed) {
    SetSubtreeShouldCheckForPaintInvalidation();
    SetNeedsPaintPropertyUpdate();
    if (Layer())
      Layer()->SetNeedsCompositingInputsUpdate();
  }
}

void LayoutSVGRoot::RecalcVisualOverflow() {
  NOT_DESTROYED();
  LayoutReplaced::RecalcVisualOverflow();
  if (!ClipsToContentBox())
    AddContentsVisualOverflow(ComputeContentsVisualOverflow());
}

PhysicalRect LayoutSVGRoot::ComputeContentsVisualOverflow() const {
  NOT_DESTROYED();
  gfx::RectF content_visual_rect = VisualRectInLocalSVGCoordinates();
  content_visual_rect =
      local_to_border_box_transform_.MapRect(content_visual_rect);
  // Condition the visual overflow rect to avoid being clipped/culled
  // out if it is huge. This may sacrifice overflow, but usually only
  // overflow that would never be seen anyway.
  // To condition, we intersect with something that we oftentimes
  // consider to be "infinity".
  return Intersection(PhysicalRect::EnclosingRect(content_visual_rect),
                      PhysicalRect(InfiniteIntRect()));
}

void LayoutSVGRoot::PaintReplaced(const PaintInfo& paint_info,
                                  const PhysicalOffset& paint_offset) const {
  NOT_DESTROYED();
  if (ChildPaintBlockedByDisplayLock())
    return;
  SVGRootPainter(*this).PaintReplaced(paint_info, paint_offset);
}

void LayoutSVGRoot::WillBeDestroyed() {
  NOT_DESTROYED();
  SVGResources::ClearEffects(*this);
  LayoutReplaced::WillBeDestroyed();
}

bool LayoutSVGRoot::IntrinsicSizeIsFontMetricsDependent() const {
  NOT_DESTROYED();
  const auto& svg = To<SVGSVGElement>(*GetNode());
  return svg.width()->CurrentValue()->IsFontRelative() ||
         svg.height()->CurrentValue()->IsFontRelative();
}

bool LayoutSVGRoot::StyleChangeAffectsIntrinsicSize(
    const ComputedStyle& old_style) const {
  NOT_DESTROYED();
  const ComputedStyle& style = StyleRef();
  // If the writing mode changed from a horizontal mode to a vertical
  // mode, or vice versa, then our intrinsic dimensions will have
  // changed.
  if (old_style.IsHorizontalWritingMode() != style.IsHorizontalWritingMode())
    return true;
  // If our intrinsic dimensions depend on font metrics (by using 'em', 'ex' or
  // any other font-relative unit), any changes to the font may change said
  // dimensions.
  if (IntrinsicSizeIsFontMetricsDependent() &&
      old_style.GetFont() != style.GetFont())
    return true;
  return false;
}

void LayoutSVGRoot::IntrinsicSizingInfoChanged() {
  NOT_DESTROYED();
  SetIntrinsicLogicalWidthsDirty();

  // TODO(fs): Merge with IntrinsicSizeChanged()? (from LayoutReplaced)
  // Ignore changes to intrinsic dimensions if the <svg> is not in an SVG
  // document, or not embedded in a way that supports/allows size negotiation.
  if (!IsEmbeddedThroughFrameContainingSVGDocument())
    return;
  DCHECK(GetFrame()->Owner());
  GetFrame()->Owner()->IntrinsicSizingInfoChanged();
}

void LayoutSVGRoot::StyleDidChange(StyleDifference diff,
                                   const ComputedStyle* old_style) {
  NOT_DESTROYED();
  LayoutReplaced::StyleDidChange(diff, old_style);

  if (old_style && StyleChangeAffectsIntrinsicSize(*old_style))
    IntrinsicSizingInfoChanged();

  SVGResources::UpdateEffects(*this, diff, old_style);

  if (diff.TransformChanged()) {
    for (auto& svg_text : text_set_) {
      svg_text->SetNeedsLayout(layout_invalidation_reason::kStyleChange,
                               kMarkContainerChain);
      svg_text->SetNeedsTextMetricsUpdate();
    }
  }

  if (!Parent())
    return;
  if (diff.HasDifference())
    LayoutSVGResourceContainer::StyleChanged(*this, diff);
}

bool LayoutSVGRoot::IsChildAllowed(LayoutObject* child,
                                   const ComputedStyle&) const {
  NOT_DESTROYED();
  return SVGContentContainer::IsChildAllowed(*child);
}

void LayoutSVGRoot::AddChild(LayoutObject* child, LayoutObject* before_child) {
  NOT_DESTROYED();
  LayoutReplaced::AddChild(child, before_child);

  bool should_isolate_descendants =
      (child->IsBlendingAllowed() && child->StyleRef().HasBlendMode()) ||
      child->HasNonIsolatedBlendingDescendants();
  if (should_isolate_descendants)
    DescendantIsolationRequirementsChanged(kDescendantIsolationRequired);
}

void LayoutSVGRoot::RemoveChild(LayoutObject* child) {
  NOT_DESTROYED();
  LayoutReplaced::RemoveChild(child);

  content_.MarkBoundsDirtyFromRemovedChild();

  bool had_non_isolated_descendants =
      (child->IsBlendingAllowed() && child->StyleRef().HasBlendMode()) ||
      child->HasNonIsolatedBlendingDescendants();
  if (had_non_isolated_descendants)
    DescendantIsolationRequirementsChanged(kDescendantIsolationNeedsUpdate);
}

bool LayoutSVGRoot::HasNonIsolatedBlendingDescendants() const {
  NOT_DESTROYED();
  if (has_non_isolated_blending_descendants_dirty_) {
    has_non_isolated_blending_descendants_ =
        content_.ComputeHasNonIsolatedBlendingDescendants();
    has_non_isolated_blending_descendants_dirty_ = false;
  }
  return has_non_isolated_blending_descendants_;
}

void LayoutSVGRoot::DescendantIsolationRequirementsChanged(
    DescendantIsolationState state) {
  NOT_DESTROYED();
  switch (state) {
    case kDescendantIsolationRequired:
      has_non_isolated_blending_descendants_ = true;
      has_non_isolated_blending_descendants_dirty_ = false;
      break;
    case kDescendantIsolationNeedsUpdate:
      has_non_isolated_blending_descendants_dirty_ = true;
      break;
  }
  SetNeedsPaintPropertyUpdate();
  if (Layer())
    Layer()->SetNeedsCompositingInputsUpdate();
}

void LayoutSVGRoot::InsertedIntoTree() {
  NOT_DESTROYED();
  LayoutReplaced::InsertedIntoTree();
  LayoutSVGResourceContainer::MarkForLayoutAndParentResourceInvalidation(*this,
                                                                         false);
  if (StyleRef().HasSVGEffect())
    SetNeedsPaintPropertyUpdate();
}

void LayoutSVGRoot::WillBeRemovedFromTree() {
  NOT_DESTROYED();
  LayoutSVGResourceContainer::MarkForLayoutAndParentResourceInvalidation(*this,
                                                                         false);
  if (StyleRef().HasSVGEffect())
    SetNeedsPaintPropertyUpdate();
  LayoutReplaced::WillBeRemovedFromTree();
}

PositionWithAffinity LayoutSVGRoot::PositionForPoint(
    const PhysicalOffset& point) const {
  NOT_DESTROYED();
  gfx::PointF absolute_point(point);
  absolute_point =
      local_to_border_box_transform_.Inverse().MapPoint(absolute_point);
  LayoutObject* closest_descendant =
      SVGLayoutSupport::FindClosestLayoutSVGText(this, absolute_point);

  if (!closest_descendant)
    return LayoutReplaced::PositionForPoint(point);

  LayoutObject* layout_object = closest_descendant;
  AffineTransform transform = layout_object->LocalToSVGParentTransform();
  PhysicalOffset location = To<LayoutBox>(layout_object)->PhysicalLocation();
  transform.Translate(location.left, location.top);
  while (layout_object) {
    layout_object = layout_object->Parent();
    if (layout_object->IsSVGRoot())
      break;
    transform = layout_object->LocalToSVGParentTransform() * transform;
  }

  absolute_point = transform.Inverse().MapPoint(absolute_point);

  return closest_descendant->PositionForPoint(
      PhysicalOffset::FromPointFRound(absolute_point));
}

// LayoutBox methods will expect coordinates w/o any transforms in coordinates
// relative to our borderBox origin.  This method gives us exactly that.
SVGTransformChange LayoutSVGRoot::BuildLocalToBorderBoxTransform(
    const PhysicalRect& content_rect) {
  NOT_DESTROYED();
  SVGTransformChangeDetector change_detector(local_to_border_box_transform_);
  auto* svg = To<SVGSVGElement>(GetNode());
  DCHECK(svg);
  float scale = StyleRef().EffectiveZoom();
  gfx::SizeF content_size(content_rect.size.width / scale,
                          content_rect.size.height / scale);
  local_to_border_box_transform_ = svg->ViewBoxToViewTransform(content_size);

  gfx::Vector2dF translate = svg->CurrentTranslate();
  AffineTransform view_to_border_box_transform(
      scale, 0, 0, scale, content_rect.offset.left + translate.x(),
      content_rect.offset.top + translate.y());
  view_to_border_box_transform.Scale(svg->currentScale());
  local_to_border_box_transform_.PostConcat(view_to_border_box_transform);
  return change_detector.ComputeChange(local_to_border_box_transform_);
}

AffineTransform LayoutSVGRoot::LocalToSVGParentTransform() const {
  NOT_DESTROYED();
  PhysicalOffset location = PhysicalLocation();
  return AffineTransform::Translation(RoundToInt(location.left),
                                      RoundToInt(location.top)) *
         local_to_border_box_transform_;
}

gfx::RectF LayoutSVGRoot::ViewBoxRect() const {
  return To<SVGSVGElement>(*GetNode()).CurrentViewBoxRect();
}

gfx::SizeF LayoutSVGRoot::ViewportSize() const {
  const PhysicalSize& viewport_size =
      new_content_size_ ? *new_content_size_ : PhysicalContentBoxSize();
  const float zoom = StyleRef().EffectiveZoom();
  return gfx::SizeF(viewport_size.width / zoom, viewport_size.height / zoom);
}

// This method expects local CSS box coordinates.
// Callers with local SVG viewport coordinates should first apply the
// localToBorderBoxTransform to convert from SVG viewport coordinates to local
// CSS box coordinates.
void LayoutSVGRoot::MapLocalToAncestor(const LayoutBoxModelObject* ancestor,
                                       TransformState& transform_state,
                                       MapCoordinatesFlags mode) const {
  NOT_DESTROYED();
  LayoutReplaced::MapLocalToAncestor(ancestor, transform_state, mode);
}

bool LayoutSVGRoot::HitTestChildren(HitTestResult& result,
                                    const HitTestLocation& hit_test_location,
                                    const PhysicalOffset& accumulated_offset,
                                    HitTestPhase phase) {
  NOT_DESTROYED();
  HitTestLocation local_border_box_location(hit_test_location,
                                            -accumulated_offset);
  TransformedHitTestLocation local_location(local_border_box_location,
                                            LocalToBorderBoxTransform());
  if (!local_location) {
    return false;
  }
  return content_.HitTest(result, *local_location, phase);
}

bool LayoutSVGRoot::IsInSelfHitTestingPhase(HitTestPhase phase) const {
  // Only hit-test the root <svg> container during the background
  // phase. (Hit-testing during the foreground phase would make us miss for
  // instance backgrounds of children inside <foreignObject>.)
  return phase == HitTestPhase::kSelfBlockBackground;
}

void LayoutSVGRoot::IntersectChildren(HitTestResult& result,
                                      const HitTestLocation& location) const {
  content_.HitTest(result, location, HitTestPhase::kForeground);
}

void LayoutSVGRoot::AddSvgTextDescendant(LayoutSVGText& svg_text) {
  NOT_DESTROYED();
  DCHECK(!text_set_.Contains(&svg_text));
  text_set_.insert(&svg_text);
}

void LayoutSVGRoot::RemoveSvgTextDescendant(LayoutSVGText& svg_text) {
  NOT_DESTROYED();
  DCHECK(text_set_.Contains(&svg_text));
  text_set_.erase(&svg_text);
}

PaintLayerType LayoutSVGRoot::LayerTypeRequired() const {
  NOT_DESTROYED();
  auto layer_type_required = LayoutReplaced::LayerTypeRequired();
  if (layer_type_required == kNoPaintLayer) {
    // Force a paint layer so the parent layer will know if there are
    // non-isolated descendants with blend mode.
    layer_type_required = kForcedPaintLayer;
  }
  return layer_type_required;
}

OverflowClipAxes LayoutSVGRoot::ComputeOverflowClipAxes() const {
  NOT_DESTROYED();

  // svg document roots are always clipped. When the svg is stand-alone
  // (isDocumentElement() == true) the viewport clipping should always be
  // applied, noting that the window scrollbars should be hidden if
  // overflow=hidden.
  if (IsDocumentElement())
    return kOverflowClipBothAxis;

  // Use the default code-path which computes overflow based on `overflow`,
  // `overflow-clip-margin` and paint containment if all these properties are
  // respected on svg elements similar to other replaced elements.
  if (RespectsCSSOverflow())
    return LayoutReplaced::ComputeOverflowClipAxes();

  // the outermost svg is clipped if auto.
  if (StyleRef().OverflowX() == EOverflow::kHidden ||
      StyleRef().OverflowX() == EOverflow::kAuto ||
      StyleRef().OverflowX() == EOverflow::kScroll ||
      StyleRef().OverflowX() == EOverflow::kClip)
    return kOverflowClipBothAxis;

  return LayoutReplaced::ComputeOverflowClipAxes();
}

}  // namespace blink

"""

```