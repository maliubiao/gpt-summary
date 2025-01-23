Response:
Let's break down the thought process for analyzing the `view_painter.cc` file.

**1. Understanding the Goal:**

The request asks for the functionalities of this file, its relation to web technologies (JavaScript, HTML, CSS), examples, logic reasoning, potential errors, and debugging context. The core is to understand *what this code does* within the larger Blink rendering engine.

**2. Initial Code Scan - Identifying Key Concepts:**

The first step is to quickly scan the `#include` directives and the class/method names. This gives a high-level overview:

* **Includes:**  Keywords like `frame`, `layout`, `paint`, `graphics`, `view_transition` stand out. This immediately suggests this file is involved in the rendering pipeline, specifically dealing with how views (likely representing browser windows/frames) are painted. The inclusion of `view_transition` indicates involvement with visual transitions between states.
* **Class Name:** `ViewPainter` strongly suggests its primary purpose is *painting* something related to a *view*.
* **Method Names:**  `PaintRootGroup`, `PaintBoxDecorationBackground`, `PaintRootElementGroup` are significant. They point to distinct stages or types of painting operations. The naming suggests a hierarchical structure in how elements are painted.
* **Namespace:** `blink` confirms this is within the Chromium/Blink rendering engine.

**3. Analyzing Key Methods (Functionality):**

Now, delve into the key methods identified in the scan.

* **`PaintRootGroup`:** The comments clearly state this handles painting the "infinite canvas" behind the main frame's root element. It deals with the `BaseBackgroundColor` and the handling of printing scenarios (transparent background for white). This connects directly to CSS's `background-color` property and how the browser's default background is managed.

* **`PaintBoxDecorationBackground`:** This is more complex. The code checks for visibility, pagination, and then handles painting the background of the `LayoutView`. Crucially, it mentions `HitTestOpaquenessEnabled`, hinting at how rendering interacts with event handling. The logic for painting in "contents space" and handling scrollable overflow is important. The connection to CSS is clear: `background-color`, `background-image`, etc. The inclusion of `ViewTransitionUtils` links it to visual transitions.

* **`PaintRootElementGroup`:**  This method focuses on painting the background of the root element (usually `<html>`). It addresses the special cases for HTML and XHTML documents where the root element's background might be painted differently. The interaction with `GeometryMapper` to handle transforms is key. The code also deals with print economy mode. This method directly implements the rendering of the root element's background as defined by CSS.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

With the functionalities understood, the connections to web technologies become clearer:

* **HTML:** The structure of the document, the existence of the root element (`<html>`), and the concept of frames are all fundamental to HTML. `ViewPainter` directly renders the visual representation of this HTML structure.
* **CSS:**  The most direct link. `background-color`, `background-image`, `visibility`, and other box decoration properties are the primary drivers for what `ViewPainter` draws. The handling of transforms, clipping, and blend modes also ties into CSS features.
* **JavaScript:**  While `ViewPainter` doesn't *directly* execute JavaScript, JavaScript can manipulate the DOM and CSS styles, which in turn trigger repaints and involve `ViewPainter`. For example, changing an element's `backgroundColor` via JavaScript would eventually lead to `ViewPainter` being called. View Transitions, which are often initiated by JavaScript, are explicitly mentioned in the code.

**5. Examples and Logic Reasoning:**

* **CSS Example:**  Choosing a simple example like setting the `background-color` of the `body` demonstrates the direct link between CSS and the code's functionality.
* **Logic Reasoning:**  Focusing on the `PaintRootGroup`'s handling of printing and the default white background provides a concrete example of conditional logic. The input (printing mode, white background) and output (transparent background) illustrate this.

**6. User/Programming Errors:**

Thinking about how developers might misuse or misunderstand CSS properties in a way that manifests in rendering issues is the key here. For instance, assuming the root background always covers the entire viewport (when it might be clipped) or misunderstanding how stacking contexts and transforms affect background painting are good examples.

**7. Debugging Context:**

Consider the developer's perspective. How would they end up looking at this code?  Common debugging scenarios involve visual glitches, unexpected background behavior, or performance issues related to painting. Tracing the rendering pipeline from a user action (like scrolling or a page load) leading to this specific file is the core idea.

**8. Iteration and Refinement:**

After the initial analysis, review and refine the explanations. Ensure the examples are clear and the connections to web technologies are explicitly stated. For instance, initially, the explanation for JavaScript's role might be too vague. Making it more specific by mentioning DOM manipulation and triggering repaints strengthens the explanation.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This just paints backgrounds."  **Correction:** Realize it's more nuanced, handling different layers, transforms, and interactions with other rendering components.
* **Vague Link to JavaScript:** Initially, the link to JS might be something like "JS can change styles." **Refinement:** Be more specific about *how* JS changes styles and *what the consequence* is for the rendering pipeline (triggering repaints).
* **Overlooking edge cases:** Initially, might focus only on basic background colors. **Correction:**  Consider more complex scenarios like background images, clipping, and transforms.
* **Not explaining *why* certain checks are done:**  For example, the special handling for printing. **Refinement:** Explain the rationale (e.g., assuming white paper).

By following these steps, combining code analysis with an understanding of web technologies and debugging practices, one can effectively analyze and explain the functionality of a complex source code file like `view_painter.cc`.
This C++ source code file, `view_painter.cc`, located within the Blink rendering engine, is responsible for **painting the background of the main view or frame of a web page**. It handles how the background color and images are rendered for the root element (usually `<html>` or `<body>`) and the overall document canvas.

Here's a breakdown of its functionalities and relationships:

**Core Functionalities:**

1. **Painting the Root Group Background:**
   - `PaintRootGroup`: This function paints the "infinite canvas" behind the root element of the main frame.
   - It considers the `BaseBackgroundColor` set on the `LocalFrameView`.
   - It handles special cases for printing, where the background might be left transparent if the `BaseBackgroundColor` is white.
   - It respects the `ShouldClearDocumentBackground` setting to decide whether to clear the canvas before painting.

2. **Painting Box Decoration Background (for the View):**
   - `PaintBoxDecorationBackground`: This is the primary function for painting the background of the `LayoutView`.
   - It checks for visibility and if the view is paginated (in which case background painting is handled differently for individual pages).
   - It determines if hit-testing data, region capture data, or scroll hit-test data needs to be recorded during the painting process.
   - It calculates the `background_rect`, which encompasses the visible content and potentially the entire document area (especially during printing).
   - It handles cases where the root element's background needs to be painted in a separate paint chunk due to properties like `clip-path`, `filter`, `blend-mode`, or `opacity`.
   - It calls `PaintRootElementGroup` to handle the actual painting of the root element's background.

3. **Painting the Root Element Group Background:**
   - `PaintRootElementGroup`: This function specifically paints the background of the root element (e.g., `<html>`).
   - It considers the root element's `background-color` and `background-image` styles.
   - It handles the case where the user agent defines a `BaseBackgroundColor`.
   - It takes into account print economy mode, where the background might be forced to white.
   - It uses `GeometryMapper` to handle transformations applied to the root element when painting the background.
   - It uses `BoxBackgroundPaintContext` and `BoxModelObjectPainter` to perform the actual drawing of background layers (colors and images).
   - It optimizes by potentially using separate paint layers for performance reasons (e.g., when there are blending effects).

**Relationship with JavaScript, HTML, and CSS:**

This file is a crucial part of the rendering pipeline that translates the information from HTML and CSS into visual pixels on the screen. JavaScript can indirectly influence this file by modifying the DOM and CSS styles.

**Examples:**

* **HTML:** The presence of `<html>` or `<body>` elements in the HTML structure determines which element's background will be painted by `PaintRootElementGroup`.
* **CSS:**
    - The CSS `background-color` property of the `html` or `body` element directly determines the `root_element_background_color` used in `PaintRootElementGroup`.
    ```css
    body {
      background-color: lightblue;
    }
    ```
    - The CSS `background-image` property will cause `BoxModelObjectPainter::PaintFillLayer` to be called to render the image.
    ```css
    html {
      background-image: url("background.png");
    }
    ```
    - The `visibility: hidden` CSS property on the root element would cause `PaintBoxDecorationBackground` to return early, preventing any background painting.
    - CSS transformations (e.g., `transform: rotate(45deg)`) on the root element will be handled by the `GeometryMapper` in `PaintRootElementGroup` to correctly position the background.
* **JavaScript:**
    - JavaScript code that changes the `backgroundColor` of the `document.body` will trigger a repaint, eventually leading to `ViewPainter` being invoked to update the background.
    ```javascript
    document.body.style.backgroundColor = 'yellow';
    ```
    - JavaScript that dynamically adds or removes CSS classes affecting background properties will also trigger repaints handled by this file.
    - JavaScript animations that manipulate CSS transform properties on the root element will require `ViewPainter` to repaint the background with the updated transformation.

**Logic Reasoning (Hypothetical):**

**Assumption:** The `document.body` element has `background-color: red;` and the browser window is scrolled down.

**Input to `PaintBoxDecorationBackground`:**
- `paint_info`: Contains information about the current paint context, including the clip rectangle.
- `box_fragment_`: Represents the `LayoutView`'s physical fragment.

**Reasoning within `PaintBoxDecorationBackground`:**
1. The function checks if the view is visible (assuming it is).
2. It determines that it's not a paginated root.
3. It calculates the `background_rect`. Since the window is scrolled, this rect might extend beyond the visible viewport to cover the entire document.
4. It calls `PaintRootElementGroup`.

**Input to `PaintRootElementGroup`:**
- `paint_info`: Same as above.
- `pixel_snapped_background_rect`: The pixel-snapped version of `background_rect`.
- `background_paint_state`:  Represents the property tree state for background painting.

**Reasoning within `PaintRootElementGroup`:**
1. It retrieves the computed style of the root element (`document.body`).
2. It gets the `root_element_background_color`, which is `red`.
3. It determines that there is no `BaseBackgroundColor` to consider (or it's transparent).
4. It calls `context.FillRect` with the `paint_rect` and the `red` color to draw the background.

**Output:** The background of the viewport (and potentially the scrolled-out area) will be painted with the color red.

**User or Programming Common Usage Errors:**

1. **Assuming Root Background Always Fills the Viewport:** Developers might assume that setting the `background-color` on the `html` element always covers the entire viewport. However, if the `body` element has a different background color and a height that fills the viewport, the `body`'s background will be visible.

   ```html
   <!DOCTYPE html>
   <html>
   <head>
   <style>
     html { background-color: blue; }
     body { height: 100vh; background-color: red; }
   </style>
   </head>
   <body></body>
   </html>
   ```
   In this case, the user might expect the entire background to be blue, but it will be red because the `body`'s background is painted on top.

2. **Misunderstanding Stacking Contexts and Background Painting:** When elements have `z-index` and create stacking contexts, their backgrounds are painted within their own context. A developer might incorrectly assume the root background will always be behind everything.

3. **Performance Issues with Complex Backgrounds:** Using large background images or complex background gradients can lead to performance issues during painting. This file is responsible for executing those painting operations, and inefficient CSS can lead to slowdowns.

**User Operation Steps to Reach Here (Debugging Clues):**

Let's say a user reports that the background color of a website is not showing up correctly. Here's how the rendering process and debugging might lead to `view_painter.cc`:

1. **User Action:** The user opens a web page in Chrome, scrolls the page, or resizes the browser window.
2. **Layout Calculation:** Blink's layout engine calculates the positions and sizes of elements based on the HTML and CSS. This involves the `LayoutView` and `LayoutBox` objects.
3. **Paint Invalidation:**  The layout changes (due to scrolling, resizing, or dynamic content updates) mark regions of the screen as needing to be repainted.
4. **Paint Tree Traversal:** Blink's paint system traverses the paint tree, which is a representation of the visual structure of the page.
5. **`ViewPainter` Invocation:** When the paint traversal reaches the `LayoutView` (representing the main frame), the `ViewPainter::Paint` method (or one of its related methods like `PaintBoxDecorationBackground`) is called.
6. **Execution within `view_painter.cc`:** The code within `view_painter.cc` then executes, determining how to paint the background based on the computed styles and other factors.

**Debugging Steps for a Developer:**

1. **Inspect Element:** Using Chrome DevTools, the developer inspects the `<html>` or `<body>` element and examines its computed styles, particularly the background-related properties.
2. **Check for Overlapping Elements:** The developer verifies if other elements are positioned on top of the root element, potentially obscuring its background.
3. **Look for CSS Errors:** The developer checks for any CSS syntax errors or logical issues in the background styles.
4. **Examine Paint Layers:** Using the "Layers" tab in DevTools, the developer can see how the page is composed of different paint layers and identify if the root element's background is on the expected layer.
5. **Performance Profiling:** If there are performance concerns, the developer can use the "Performance" tab to record a timeline and analyze the paint events, potentially identifying bottlenecks in the background painting process.
6. **Source Code Inspection (as a last resort):** If the issue is complex and not easily diagnosed, a Chromium developer might need to delve into the Blink source code, including `view_painter.cc`, to understand the exact logic behind the background painting. They might set breakpoints or add logging statements to trace the execution flow and inspect the values of relevant variables.

In summary, `view_painter.cc` is a fundamental component responsible for the visual foundation of a webpage, rendering the background as dictated by HTML and CSS, and it plays a key role in the overall rendering performance and user experience.

### 提示词
```
这是目录为blink/renderer/core/paint/view_painter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/view_painter.h"

#include "base/containers/adapters.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/pagination_utils.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/paint/box_background_paint_context.h"
#include "third_party/blink/renderer/core/paint/box_decoration_data.h"
#include "third_party/blink/renderer/core/paint/box_model_object_painter.h"
#include "third_party/blink/renderer/core/paint/box_painter.h"
#include "third_party/blink/renderer/core/paint/object_painter.h"
#include "third_party/blink/renderer/core/paint/paint_auto_dark_mode.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/view_transition/view_transition.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_utils.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/graphics/paint/geometry_mapper.h"
#include "third_party/blink/renderer/platform/graphics/paint/scoped_paint_chunk_properties.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

// Behind the root element of the main frame of the page, there is an infinite
// canvas. This is by default white, but it can be overridden by
// BaseBackgroundColor on the LocalFrameView.
// https://drafts.fxtf.org/compositing/#rootgroup
void ViewPainter::PaintRootGroup(const PaintInfo& paint_info,
                                 const gfx::Rect& pixel_snapped_background_rect,
                                 const Document& document,
                                 const DisplayItemClient& client,
                                 const PropertyTreeStateOrAlias& state) {
  const LayoutView& layout_view = GetLayoutView();
  if (!layout_view.GetFrameView()->ShouldPaintBaseBackgroundColor()) {
    return;
  }

  Color base_background_color =
      layout_view.GetFrameView()->BaseBackgroundColor();
  if (document.Printing() && base_background_color == Color::kWhite) {
    // Leave a transparent background, assuming the paper or the PDF viewer
    // background is white by default. This allows further customization of the
    // background, e.g. in the case of https://crbug.com/498892.
    return;
  }

  bool should_clear_canvas =
      document.GetSettings() &&
      document.GetSettings()->GetShouldClearDocumentBackground();

  ScopedPaintChunkProperties frame_view_background_state(
      paint_info.context.GetPaintController(), state, client,
      DisplayItem::kDocumentRootBackdrop);
  GraphicsContext& context = paint_info.context;
  if (!DrawingRecorder::UseCachedDrawingIfPossible(
          context, client, DisplayItem::kDocumentRootBackdrop)) {
    DrawingRecorder recorder(context, client,
                             DisplayItem::kDocumentRootBackdrop,
                             pixel_snapped_background_rect);
    context.FillRect(
        pixel_snapped_background_rect, base_background_color,
        PaintAutoDarkMode(box_fragment_.Style(),
                          DarkModeFilter::ElementRole::kBackground),
        should_clear_canvas ? SkBlendMode::kSrc : SkBlendMode::kSrcOver);
  }
}

void ViewPainter::PaintBoxDecorationBackground(const PaintInfo& paint_info) {
  if (box_fragment_.Style().Visibility() != EVisibility::kVisible) {
    return;
  }

  if (box_fragment_.IsPaginatedRoot()) {
    // When paginated, the background is painted for each individual page. The
    // @page background is painted for the kPageContainer. The root view
    // fragment itself paints no background.
    return;
  }

  const LayoutView& layout_view = GetLayoutView();
  bool painting_background_in_contents_space =
      paint_info.IsPaintingBackgroundInContentsSpace();
  bool paints_hit_test_data =
      (RuntimeEnabledFeatures::HitTestOpaquenessEnabled() &&
       painting_background_in_contents_space) ||
      ObjectPainter(layout_view).ShouldRecordSpecialHitTestData(paint_info);

  Element* element = DynamicTo<Element>(layout_view.GetNode());
  bool paints_region_capture_data =
      element && element->GetRegionCaptureCropId() &&
      // TODO(wangxianzhu): This is to avoid the side-effect of
      // HitTestOpaqueness on region capture data. Verify if the side-effect
      // really matters.
      !(painting_background_in_contents_space &&
        paint_info.ShouldSkipBackground());
  bool paints_scroll_hit_test =
      !painting_background_in_contents_space &&
      layout_view.FirstFragment().PaintProperties()->Scroll();
  bool is_represented_via_pseudo_elements = [&layout_view]() {
    if (auto* transition =
            ViewTransitionUtils::GetTransition(layout_view.GetDocument())) {
      return transition->IsRepresentedViaPseudoElements(layout_view);
    }
    return false;
  }();
  if (!layout_view.HasBoxDecorationBackground() && !paints_hit_test_data &&
      !paints_scroll_hit_test && !paints_region_capture_data &&
      !is_represented_via_pseudo_elements) {
    return;
  }

  // The background rect always includes at least the visible content size.
  PhysicalRect background_rect(BackgroundRect());

  const Document& document = layout_view.GetDocument();

  // When printing or painting a preview, paint the entire unclipped scrolling
  // content area.
  if (document.IsPrintingOrPaintingPreview() ||
      !layout_view.GetFrameView()->GetFrame().ClipsContent()) {
    background_rect.Unite(layout_view.DocumentRect());
  }

  const DisplayItemClient* background_client = &layout_view;

  if (painting_background_in_contents_space) {
    // Scrollable overflow, combined with the visible content size.
    auto document_rect = layout_view.DocumentRect();
    // DocumentRect is relative to ScrollOrigin. Add ScrollOrigin to let it be
    // in the space of ContentsProperties(). See ScrollTranslation in
    // object_paint_properties.h for details.
    document_rect.Move(PhysicalOffset(layout_view.ScrollOrigin()));
    background_rect.Unite(document_rect);
    background_client = &layout_view.GetScrollableArea()
                             ->GetScrollingBackgroundDisplayItemClient();
  }

  gfx::Rect pixel_snapped_background_rect = ToPixelSnappedRect(background_rect);

  auto root_element_background_painting_state =
      layout_view.FirstFragment().ContentsProperties();

  std::optional<ScopedPaintChunkProperties> scoped_properties;

  bool painted_separate_backdrop = false;
  bool painted_separate_effect = false;

  bool should_apply_root_background_behavior =
      document.IsHTMLDocument() || document.IsXHTMLDocument();

  bool should_paint_background = !paint_info.ShouldSkipBackground() &&
                                 (layout_view.HasBoxDecorationBackground() ||
                                  is_represented_via_pseudo_elements);

  LayoutObject* root_object = nullptr;
  if (auto* document_element = document.documentElement())
    root_object = document_element->GetLayoutObject();

  // For HTML and XHTML documents, the root element may paint in a different
  // clip, effect or transform state than the LayoutView. For
  // example, the HTML element may have a clip-path, filter, blend-mode,
  // or opacity.  (However, we should ignore differences in transform.)
  //
  // In these cases, we should paint the background of the root element in
  // its LocalBorderBoxProperties() state, as part of the Root Element Group
  // [1]. In addition, for the main frame of the page, we also need to paint the
  // default backdrop color in the Root Group [2]. The Root Group paints in
  // the scrolling space of the LayoutView (i.e. its ContentsProperties()).
  //
  // [1] https://drafts.fxtf.org/compositing/#pagebackdrop
  // [2] https://drafts.fxtf.org/compositing/#rootgroup
  if (should_paint_background && painting_background_in_contents_space &&
      should_apply_root_background_behavior && root_object) {
    auto document_element_state =
        root_object->FirstFragment().LocalBorderBoxProperties();
    document_element_state.SetTransform(
        root_object->FirstFragment().PreTransform());

    // As an optimization, only paint a separate PaintChunk for the
    // root group if its property tree state differs from root element
    // group's. Otherwise we can usually avoid both a separate
    // PaintChunk and a BeginLayer/EndLayer.
    if (document_element_state != root_element_background_painting_state) {
      if (&document_element_state.Effect() !=
          &root_element_background_painting_state.Effect())
        painted_separate_effect = true;

      root_element_background_painting_state = document_element_state;
      PaintRootGroup(paint_info, pixel_snapped_background_rect, document,
                     *background_client,
                     layout_view.FirstFragment().ContentsProperties());
      painted_separate_backdrop = true;
    }
  }

  if (painting_background_in_contents_space) {
    scoped_properties.emplace(paint_info.context.GetPaintController(),
                              root_element_background_painting_state,
                              *background_client,
                              DisplayItem::kDocumentBackground);
  }

  if (should_paint_background) {
    PaintRootElementGroup(paint_info, pixel_snapped_background_rect,
                          root_element_background_painting_state,
                          *background_client, painted_separate_backdrop,
                          painted_separate_effect);
  }
  if (paints_hit_test_data) {
    ObjectPainter(layout_view)
        .RecordHitTestData(paint_info, pixel_snapped_background_rect,
                           *background_client);
  }

  if (paints_region_capture_data) {
    BoxPainter(layout_view)
        .RecordRegionCaptureData(paint_info,
                                 PhysicalRect(pixel_snapped_background_rect),
                                 *background_client);
  }

  // Record the scroll hit test after the non-scrolling background so
  // background squashing is not affected. Hit test order would be equivalent
  // if this were immediately before the non-scrolling background.
  if (paints_scroll_hit_test) {
    DCHECK(!painting_background_in_contents_space);

    // The root never fragments. In paged media page fragments are inserted
    // under the LayoutView, but the LayoutView itself never fragments.
    DCHECK(!layout_view.IsFragmented());

    BoxPainter(layout_view)
        .RecordScrollHitTestData(paint_info, *background_client,
                                 &layout_view.FirstFragment());
  }
}

// This function handles background painting for the LayoutView.
// View background painting is special in the following ways:
// 1. The view paints background for the root element, the background
//    positioning respects the positioning (but not transform) of the root
//    element. However, this method assumes that there is already a
//    PaintChunk being recorded with the LocalBorderBoxProperties of the
//    root element. Therefore the transform of the root element
//    are applied via PaintChunksToCcLayer, and not via the display list of the
//    PaintChunk itself.
// 2. CSS background-clip is ignored, the background layers always expand to
//    cover the whole canvas.
// 3. The main frame is also responsible for painting the user-agent-defined
//    base background color. Conceptually it should be painted by the embedder
//    but painting it here allows culling and pre-blending optimization when
//    possible.
void ViewPainter::PaintRootElementGroup(
    const PaintInfo& paint_info,
    const gfx::Rect& pixel_snapped_background_rect,
    const PropertyTreeStateOrAlias& background_paint_state,
    const DisplayItemClient& background_client,
    bool painted_separate_backdrop,
    bool painted_separate_effect) {
  GraphicsContext& context = paint_info.context;
  if (DrawingRecorder::UseCachedDrawingIfPossible(
          context, background_client, DisplayItem::kDocumentBackground)) {
    return;
  }
  DrawingRecorder recorder(context, background_client,
                           DisplayItem::kDocumentBackground,
                           pixel_snapped_background_rect);

  const LayoutView& layout_view = GetLayoutView();
  const Document& document = layout_view.GetDocument();
  const LocalFrameView& frame_view = *layout_view.GetFrameView();
  const ComputedStyle& style = box_fragment_.Style();
  bool paints_base_background =
      frame_view.ShouldPaintBaseBackgroundColor() &&
      !frame_view.BaseBackgroundColor().IsFullyTransparent();
  Color base_background_color =
      paints_base_background ? frame_view.BaseBackgroundColor() : Color();
  if (document.Printing() && base_background_color == Color::kWhite) {
    // Leave a transparent background, assuming the paper or the PDF viewer
    // background is white by default. This allows further customization of the
    // background, e.g. in the case of https://crbug.com/498892.
    base_background_color = Color();
    paints_base_background = false;
  }

  Color root_element_background_color =
      style.VisitedDependentColor(GetCSSPropertyBackgroundColor());

  const LayoutObject* root_object =
      document.documentElement() ? document.documentElement()->GetLayoutObject()
                                 : nullptr;

  // Special handling for print economy mode.
  bool force_background_to_white =
      BoxModelObjectPainter::ShouldForceWhiteBackgroundForPrintEconomy(document,
                                                                       style);
  if (force_background_to_white) {
    // Leave a transparent background, assuming the paper or the PDF viewer
    // background is white by default. This allows further customization of the
    // background, e.g. in the case of https://crbug.com/498892.
    return;
  }

  AutoDarkMode auto_dark_mode(
      PaintAutoDarkMode(style, DarkModeFilter::ElementRole::kBackground));

  // Compute the enclosing rect of the view, in root element space.
  //
  // For background colors we can simply paint the document rect in the default
  // space. However, for background image, the root element paint offset (but
  // not transforms) apply. The strategy is to issue draw commands in the root
  // element's local space, which requires mapping the document background rect.
  bool background_renderable = true;
  gfx::Rect paint_rect = pixel_snapped_background_rect;
  // Offset for BackgroundImageGeometry to offset the image's origin. This makes
  // background tiling start at the root element's origin instead of the view.
  // This is different from the offset for painting, which is in |paint_rect|.
  PhysicalOffset background_image_offset;
  if (!root_object || !root_object->IsBox()) {
    background_renderable = false;
  } else {
    const auto& view_contents_state =
        layout_view.FirstFragment().ContentsProperties();
    if (view_contents_state != background_paint_state) {
      GeometryMapper::SourceToDestinationRect(
          view_contents_state.Transform(), background_paint_state.Transform(),
          paint_rect);
      if (paint_rect.IsEmpty())
        background_renderable = false;
      // With transforms, paint offset is encoded in paint property nodes but we
      // can use the |paint_rect|'s adjusted location as the offset from the
      // view to the root element.
      background_image_offset = PhysicalOffset(paint_rect.origin());
    } else {
      background_image_offset = -root_object->FirstFragment().PaintOffset();
    }

    if (box_fragment_.GetBoxType() == PhysicalFragment::kPageContainer) {
      // Background image origin is at the border box edge. A page container
      // fragment covers the entire page box. Add the offset to the page border
      // box fragment, to get past the margins.
      background_image_offset -= GetPageBorderBoxLink(box_fragment_).offset;
    }
  }

  bool should_clear_canvas =
      paints_base_background &&
      (document.GetSettings() &&
       document.GetSettings()->GetShouldClearDocumentBackground());

  if (!background_renderable) {
    if (!painted_separate_backdrop) {
      if (!base_background_color.IsFullyTransparent()) {
        context.FillRect(
            pixel_snapped_background_rect, base_background_color,
            auto_dark_mode,
            should_clear_canvas ? SkBlendMode::kSrc : SkBlendMode::kSrcOver);
      } else if (should_clear_canvas) {
        context.FillRect(pixel_snapped_background_rect, Color(), auto_dark_mode,
                         SkBlendMode::kClear);
      }
    }
    return;
  }

  recorder.UniteVisualRect(paint_rect);

  BoxPainterBase::FillLayerOcclusionOutputList reversed_paint_list;
  bool should_draw_background_in_separate_buffer =
      BoxModelObjectPainter(layout_view)
          .CalculateFillLayerOcclusionCulling(reversed_paint_list,
                                              style.BackgroundLayers());
  DCHECK(reversed_paint_list.size());

  if (painted_separate_effect) {
    should_draw_background_in_separate_buffer = true;
  } else {
    // If the root background color is opaque, isolation group can be skipped
    // because the canvas will be cleared by root background color.
    if (root_element_background_color.IsOpaque()) {
      should_draw_background_in_separate_buffer = false;
    }

    // We are going to clear the canvas with transparent pixels, isolation group
    // can be skipped.
    if (base_background_color.IsFullyTransparent() && should_clear_canvas) {
      should_draw_background_in_separate_buffer = false;
    }
  }

  // Only use BeginLayer if not only we should draw in a separate buffer, but
  // we also didn't paint a separate backdrop. Separate backdrops are always
  // painted when there is any effect on the root element, such as a blend
  // mode. An extra BeginLayer will result in incorrect blend isolation if
  // it is added on top of any effect on the root element.
  if (should_draw_background_in_separate_buffer && !painted_separate_effect) {
    if (!base_background_color.IsFullyTransparent()) {
      context.FillRect(
          paint_rect, base_background_color, auto_dark_mode,
          should_clear_canvas ? SkBlendMode::kSrc : SkBlendMode::kSrcOver);
    }
    context.BeginLayer();
  }

  Color combined_background_color =
      should_draw_background_in_separate_buffer
          ? root_element_background_color
          : base_background_color.Blend(root_element_background_color);

  if (combined_background_color != frame_view.BaseBackgroundColor())
    context.GetPaintController().SetFirstPainted();

  if (!combined_background_color.IsFullyTransparent()) {
    context.FillRect(
        paint_rect, combined_background_color, auto_dark_mode,
        (should_draw_background_in_separate_buffer || should_clear_canvas)
            ? SkBlendMode::kSrc
            : SkBlendMode::kSrcOver);
  } else if (should_clear_canvas &&
             !should_draw_background_in_separate_buffer) {
    context.FillRect(paint_rect, Color(), auto_dark_mode, SkBlendMode::kClear);
  }

  BoxBackgroundPaintContext bg_paint_context(layout_view, &box_fragment_,
                                             background_image_offset);
  BoxModelObjectPainter box_model_painter(layout_view);
  for (const auto* fill_layer : base::Reversed(reversed_paint_list)) {
    box_model_painter.PaintFillLayer(paint_info, Color(), *fill_layer,
                                     PhysicalRect(paint_rect),
                                     kBackgroundBleedNone, bg_paint_context);
  }

  if (should_draw_background_in_separate_buffer && !painted_separate_effect)
    context.EndLayer();
}

const LayoutView& ViewPainter::GetLayoutView() const {
  return *box_fragment_.GetLayoutObject()->View();
}

PhysicalRect ViewPainter::BackgroundRect() const {
  if (box_fragment_.GetBoxType() == PhysicalFragment::kPageContainer) {
    return box_fragment_.LocalRect();
  }
  return GetLayoutView().BackgroundRect();
}

}  // namespace blink
```