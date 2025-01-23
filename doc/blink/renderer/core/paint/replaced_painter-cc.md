Response:
Let's break down the thought process for analyzing the provided C++ source code and generating the comprehensive response.

**1. Initial Understanding and Goal:**

The primary goal is to understand the purpose of the `replaced_painter.cc` file within the Chromium Blink rendering engine. The request asks for its functionalities, relationships with web technologies (HTML, CSS, JavaScript), logical reasoning examples, common usage errors, and debugging tips.

**2. Core Functionality - Deconstructing the Code:**

* **Identify the Class:** The core of the file is the `ReplacedPainter` class. This immediately tells us it deals with painting elements that are "replaced."
* **What are "Replaced Elements"?**  Prior knowledge or a quick search reveals that replaced elements are things like `<img>`, `<video>`, `<canvas>`, `<iframe>`, `<object>`, etc. Their content is rendered by an external resource or agent, not directly by the browser's layout engine in the same way as regular HTML elements.
* **Key Methods:** The `Paint` method is the most crucial. Analyze its steps:
    * `ScopedPaintState`:  Manages the painting context.
    * `ShouldPaint`: A common pattern to determine if painting is necessary.
    * `PaintBoxDecorationBackground`: Handles backgrounds, borders, and shadows.
    * `PaintMask`: Deals with masking effects.
    * `layout_replaced_.PaintReplaced(...)`:  This is the core call to actually render the *content* of the replaced element. The `ReplacedPainter` itself *doesn't* render the image, video, etc. It orchestrates the painting around it.
    * `ScrollableAreaPainter`:  Handles scrollbars and resizers.
    * `SelectionBoundsRecorder`: Draws selection highlights.
* **Helper Classes and Structures:** Note the usage of `ScopedReplacedContentPaintState`, `BoxDecorationData`, `BoxPainter`, `ObjectPainter`, `ThemePainter`, etc. These reveal different aspects of the painting process.
* **Key Data Structures:**  Look for members like `layout_replaced_`. This signifies that the painter operates on a `LayoutReplaced` object, which is the layout representation of a replaced element.
* **Namespace and Includes:**  The `blink` namespace and the included headers (`<optional>`, `"base/metrics/histogram_macros.h"`, various `renderer/core/...` and `renderer/platform/...` headers) provide context about the environment and dependencies. Metrics tracking (`UMA_HISTOGRAM_COUNTS_100000`) is also important.

**3. Connecting to Web Technologies:**

* **HTML:**  The very concept of "replaced elements" comes from HTML. Examples: `<img>`, `<video>`, `<canvas>`.
* **CSS:**  CSS properties like `background-color`, `border`, `box-shadow`, `mask`, `visibility`, `object-fit`, `object-position`, `overflow`, and `resize` directly influence how `ReplacedPainter` works.
* **JavaScript:** JavaScript can dynamically change the attributes of replaced elements (e.g., `img.src`, `video.play()`), modify their styles, or even create them. This indirectly triggers the painting process handled by `ReplacedPainter`.

**4. Logical Reasoning (Hypothetical Inputs and Outputs):**

Think about specific scenarios:

* **Simple Image:**  Input: `<img>` tag. Output:  The image is drawn within its bounds.
* **Image with Border:** Input: `<img>` with CSS `border: 1px solid black;`. Output: The image is drawn with a black border.
* **Hidden Video:** Input: `<video>` with CSS `visibility: hidden;`. Output: The video is likely not painted (checked by `ShouldPaint`).
* **Canvas Drawing:** Input: `<canvas>` with JavaScript drawing on it. Output: The drawn content of the canvas is rendered.

**5. Common Usage Errors:**

Consider what developers might do wrong that would involve the rendering of replaced elements:

* **Incorrect Paths:**  Trying to load an image with a broken URL. The `ReplacedPainter` will still attempt to paint the element, but the content will be missing (often a broken image icon).
* **CSS Issues:** Setting `display: none;` on a replaced element. It won't be painted. Incorrectly sized or positioned replaced elements leading to unexpected layout.
* **JavaScript Errors:**  JavaScript failing to load or manipulate the content of a replaced element (e.g., a canvas).

**6. Debugging Clues (How to Reach This Code):**

Think about the chain of events:

1. **User Action:** User opens a web page, scrolls, resizes the window, interacts with the page.
2. **HTML Parsing and Layout:** The browser parses the HTML and builds the DOM tree. Layout objects are created, including `LayoutReplaced` for replaced elements.
3. **Style Calculation:** CSS is parsed, and computed styles are applied to the layout objects.
4. **Painting Initiation:** When the browser needs to render or re-render the page (or parts of it), the painting process begins.
5. **`Paint` Method Call:**  The `Paint` method of `ReplacedPainter` is called specifically for `LayoutReplaced` objects.

**7. Structuring the Response:**

Organize the information logically:

* **Overview:** Start with a concise summary of the file's purpose.
* **Functionalities:**  List the key actions performed by the code.
* **Relationship to Web Technologies:** Explain the connections to HTML, CSS, and JavaScript with concrete examples.
* **Logical Reasoning:** Provide the hypothetical input/output scenarios.
* **Common Usage Errors:**  Give practical examples of developer mistakes.
* **Debugging:**  Outline the user actions and browser processes that lead to this code being executed.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe the `ReplacedPainter` directly fetches image data. **Correction:** The code shows it interacts with `LayoutReplaced` and `PaintInfo`, suggesting its role is more about the *painting process* around the content, not the content loading itself.
* **Consider edge cases:** What about SVG images?  The code includes `<layout/svg/layout_svg_root.h>`, indicating support for SVG replaced elements.
* **Emphasize the "why":** Don't just list features. Explain *why* those features are necessary for rendering replaced elements correctly.

By following these steps, iterating through the code and considering the broader context of web rendering, one can arrive at a comprehensive and accurate understanding of the `replaced_painter.cc` file's role.
好的，我们来详细分析一下 `blink/renderer/core/paint/replaced_painter.cc` 这个文件。

**功能概述**

`replaced_painter.cc` 文件是 Chromium Blink 渲染引擎中负责绘制“被替换元素”（Replaced Elements）的类 `ReplacedPainter` 的实现。被替换元素是指其内容的渲染不由 CSS 视觉格式化模型控制的元素。 常见的被替换元素包括：

* `<img>` (图像)
* `<video>` (视频)
* `<audio>` (音频)
* `<canvas>` (画布)
* `<iframe>` (内联框架)
* `<object>` (外部资源)
* `<embed>` (嵌入内容)
* 表单控件如 `<input type="image">`

`ReplacedPainter` 的主要职责是：

1. **控制被替换元素的绘制流程**:  它决定了在哪个绘制阶段（背景、前景、遮罩等）绘制被替换元素的哪些部分。
2. **绘制背景和边框**:  类似于其他块级元素，被替换元素也可以有背景颜色、背景图片和边框。`ReplacedPainter` 负责调用相应的绘制逻辑来绘制这些装饰。
3. **绘制被替换元素的内容**:  它会调用 `LayoutReplaced::PaintReplaced()` 方法，这部分逻辑会根据具体的被替换元素类型进行实际内容的绘制。例如，对于 `<img>` 元素，这可能会涉及到从解码后的图像数据绘制。
4. **处理遮罩 (Masking)**: 如果被替换元素应用了 CSS 遮罩，`ReplacedPainter` 负责应用这些遮罩效果。
5. **处理选中效果**: 当被替换元素被选中时，`ReplacedPainter` 会绘制相应的选中高亮。
6. **处理滚动条和调整大小控件**: 对于可以调整大小的被替换元素（如某些 `<object>` 或 `<iframe>`），`ReplacedPainter` 负责绘制调整大小的控件。
7. **性能优化**:  代码中包含一些性能优化的考虑，例如使用缓存的绘制项 (Display Items) 来避免重复绘制。
8. **移动端友好性检查**:  会参与到移动端友好性检查的过程中，通知检查器关于被替换元素的绘制情况。

**与 JavaScript, HTML, CSS 的关系及举例说明**

`ReplacedPainter` 的工作是网页渲染过程中的一部分，与 JavaScript, HTML, CSS 紧密相关：

* **HTML**: HTML 定义了页面结构，包括哪些元素是被替换元素。`ReplacedPainter` 作用于这些在 HTML 中声明的被替换元素。
    * **例子**: 当 HTML 中存在 `<img src="image.png">` 时，渲染引擎会创建一个 `LayoutReplaced` 对象来表示这个图像，并最终由 `ReplacedPainter` 负责绘制该图像。
* **CSS**: CSS 决定了被替换元素的样式，包括背景、边框、大小、位置、遮罩效果等。`ReplacedPainter` 会读取这些 CSS 属性来指导绘制。
    * **例子**:
        * `img { width: 200px; height: 150px; border: 1px solid black; background-color: lightblue; }` -  `ReplacedPainter` 会根据这些 CSS 属性设置图像的尺寸、绘制黑色边框和浅蓝色背景。
        * `img { mask-image: url(mask.png); }` - `ReplacedPainter` 会应用 `mask.png` 作为图像的遮罩。
        * `video { object-fit: cover; }` -  虽然 `ReplacedPainter` 主要负责外围的绘制，但其调用的 `LayoutReplaced::PaintReplaced()` 逻辑会受到类似 `object-fit` 和 `object-position` 等 CSS 属性的影响，以决定如何调整视频内容的大小和位置。
* **JavaScript**: JavaScript 可以动态地操作 HTML 结构和 CSS 样式，从而间接地影响 `ReplacedPainter` 的行为。
    * **例子**:
        * `document.getElementById('myImage').src = 'new_image.jpg';` -  JavaScript 修改了 `<img>` 元素的 `src` 属性，导致浏览器需要重新获取并绘制新的图像，`ReplacedPainter` 会参与到这个重绘过程中。
        * `element.style.backgroundColor = 'red';` - JavaScript 修改了被替换元素的背景色，`ReplacedPainter` 在下一次绘制时会使用新的背景色。
        * 使用 `<canvas>` 元素并通过 JavaScript 进行绘制，`ReplacedPainter` 负责绘制这个画布元素，而画布上的具体内容是由 JavaScript 代码绘制的。

**逻辑推理示例 (假设输入与输出)**

假设我们有以下 HTML 和 CSS：

```html
<div id="container">
  <img id="myImage" src="example.png" style="border-radius: 10px;">
</div>
```

**假设输入**:

* `LayoutReplaced` 对象对应于 `id="myImage"` 的 `<img>` 元素。
* CSS 样式指定了 `border-radius: 10px;`。
* 绘制阶段为 `PaintPhase::kForeground` (前景绘制)。
* `example.png` 图片已成功加载。

**逻辑推理与输出**:

1. `ReplacedPainter::Paint()` 方法被调用，传入与 `myImage` 相关的 `PaintInfo`。
2. `ShouldPaint()` 方法会检查元素是否可见且在裁剪区域内，假设条件满足。
3. `ShouldPaintBoxDecorationBackground()` 方法会根据元素是否有背景或边框等决定是否需要绘制背景，由于有 `border-radius`，通常会绘制背景。
4. `PaintBoxDecorationBackground()` 方法会被调用，它会计算圆角矩形的形状。
5. `PaintBoxDecorationBackgroundWithRect()` 方法会使用 `GraphicsContext::ClipRoundedRect()` 来裁剪绘制区域，确保背景和边框绘制在圆角内。
6. 接着，`LayoutReplaced::PaintReplaced()` 方法会被调用，实际绘制 `example.png` 的内容。这个绘制会受到前面设置的裁剪区域的影响，图像的角会被裁剪成圆角。
7. 如果元素被选中，并且绘制阶段是 `PaintPhase::kForeground`，则可能会绘制选中高亮。

**预期输出**: `example.png` 图片会以圆角矩形的形式绘制在页面上。

**用户或编程常见的使用错误及举例说明**

1. **错误的图片路径**: 用户在 HTML 中指定了不存在的图片路径。
    * **现象**: 浏览器会显示一个“图片无法加载”的占位符，而不是预期的图片。
    * **调试线索**:  虽然 `ReplacedPainter` 会被调用来绘制 `<img>` 元素，但 `LayoutReplaced::PaintReplaced()` 在尝试绘制图片内容时会失败，因为它找不到指定的资源。开发者可以通过浏览器的开发者工具查看网络请求来发现 404 错误。

2. **CSS 样式导致被替换元素不可见**:  开发者使用 CSS 隐藏了被替换元素。
    * **例子**: `img { display: none; }` 或 `img { visibility: hidden; }`
    * **现象**: 元素不会显示在页面上。
    * **调试线索**: `ReplacedPainter::ShouldPaint()` 方法会检查元素的 `visibility` 属性，如果为 `EVisibility::kHidden`，则会直接返回 `false`，阻止后续的绘制操作。开发者可以通过检查元素的计算样式来确认是否被隐藏。

3. **错误的遮罩路径或格式**:  开发者使用了无效的遮罩图片路径或不支持的遮罩图片格式。
    * **现象**: 遮罩效果无法正确应用，可能看不到遮罩，或者出现其他渲染错误。
    * **调试线索**:  `ReplacedPainter::PaintMask()` 会尝试加载和应用遮罩图片。如果加载失败，遮罩效果可能不会生效。开发者可以通过检查网络请求和控制台错误来排查遮罩问题。

4. **尺寸和定位问题**: CSS 样式设置不当导致被替换元素显示不正确的大小或位置。
    * **例子**:  `img { width: 50%; }` 在某些布局下可能导致图片超出父容器。
    * **现象**: 图片可能变形、溢出或与其他元素重叠。
    * **调试线索**:  `ReplacedPainter` 会根据 `LayoutReplaced` 对象提供的尺寸和位置信息进行绘制。开发者可以使用开发者工具检查元素的布局信息和计算样式，确认尺寸和定位是否符合预期。

**用户操作是如何一步步到达这里，作为调试线索**

1. **用户在浏览器中打开一个包含被替换元素的网页**: 例如，访问一个包含 `<img>` 标签的网页。
2. **HTML 解析和 DOM 构建**: 浏览器解析 HTML 代码，构建 DOM 树，其中包含了 `<img>` 元素对应的节点。
3. **样式计算**: 浏览器解析 CSS 样式，并计算应用于 `<img>` 元素的最终样式。
4. **布局 (Layout)**: 渲染引擎根据 DOM 树和计算样式创建布局树，对于 `<img>` 元素，会创建一个 `LayoutReplaced` 对象，并确定其在页面上的位置和大小。
5. **绘制 (Paint)**: 当浏览器需要渲染页面时，会遍历布局树进行绘制。当遇到 `LayoutReplaced` 对象时，会创建并调用 `ReplacedPainter` 对象。
6. **`ReplacedPainter::Paint()` 被调用**:  `PaintInfo` 对象包含了当前绘制阶段和其他相关信息。
7. **后续的绘制流程**: `ReplacedPainter` 根据当前的绘制阶段和元素的样式，逐步调用各种绘制方法，例如绘制背景、边框、遮罩，并最终调用 `LayoutReplaced::PaintReplaced()` 来绘制元素的内容。

**作为调试线索**:

* 如果页面上的图片没有显示出来，或者显示不正确，开发者可以设置断点在 `ReplacedPainter::Paint()` 方法中，查看 `PaintInfo` 的状态、`layout_replaced_` 对象的信息（如尺寸、位置、样式），以及中间的计算结果，从而定位问题所在。
* 检查 `ShouldPaint()` 的返回值可以确定元素是否因为不可见或其他原因被跳过绘制。
* 检查 `PaintBoxDecorationBackground()` 中的绘制逻辑可以排查背景和边框相关的问题。
* 如果是图片内容本身的问题，可能需要进一步调试 `LayoutReplaced::PaintReplaced()` 相关的代码。

希望这个详细的分析能够帮助你理解 `replaced_painter.cc` 文件的功能和作用。

### 提示词
```
这是目录为blink/renderer/core/paint/replaced_painter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/paint/replaced_painter.h"

#include <optional>

#include "base/metrics/histogram_macros.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/highlight/highlight_style_utils.h"
#include "third_party/blink/renderer/core/layout/layout_replaced.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_root.h"
#include "third_party/blink/renderer/core/mobile_metrics/mobile_friendliness_checker.h"
#include "third_party/blink/renderer/core/paint/box_background_paint_context.h"
#include "third_party/blink/renderer/core/paint/box_decoration_data.h"
#include "third_party/blink/renderer/core/paint/box_model_object_painter.h"
#include "third_party/blink/renderer/core/paint/box_painter.h"
#include "third_party/blink/renderer/core/paint/box_painter_base.h"
#include "third_party/blink/renderer/core/paint/object_painter.h"
#include "third_party/blink/renderer/core/paint/paint_auto_dark_mode.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/paint/rounded_border_geometry.h"
#include "third_party/blink/renderer/core/paint/scoped_paint_state.h"
#include "third_party/blink/renderer/core/paint/scrollable_area_painter.h"
#include "third_party/blink/renderer/core/paint/selection_bounds_recorder.h"
#include "third_party/blink/renderer/core/paint/theme_painter.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context_state_saver.h"
#include "third_party/blink/renderer/platform/graphics/paint/display_item_cache_skipper.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/graphics/paint/scoped_paint_chunk_properties.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"

namespace blink {

namespace {

// Adjusts cull rect and paint chunk properties of the input ScopedPaintState
// for ReplacedContentTransform if needed.
class ScopedReplacedContentPaintState : public ScopedPaintState {
 public:
  ScopedReplacedContentPaintState(const ScopedPaintState& input,
                                  const LayoutReplaced& replaced);

 private:
  std::optional<MobileFriendlinessChecker::IgnoreBeyondViewportScope>
      mf_ignore_scope_;
};

ScopedReplacedContentPaintState::ScopedReplacedContentPaintState(
    const ScopedPaintState& input,
    const LayoutReplaced& replaced)
    : ScopedPaintState(input) {
  if (!fragment_to_paint_)
    return;

  if (input_paint_info_.phase == PaintPhase::kForeground) {
    if (auto* mf_checker =
            MobileFriendlinessChecker::From(replaced.GetDocument())) {
      PhysicalRect content_rect = replaced.ReplacedContentRect();
      content_rect.Move(paint_offset_);
      content_rect.Intersect(PhysicalRect(GetPaintInfo().GetCullRect().Rect()));
      mf_checker->NotifyPaintReplaced(content_rect,
                                      GetPaintInfo()
                                          .context.GetPaintController()
                                          .CurrentPaintChunkProperties()
                                          .Transform());
      mf_ignore_scope_.emplace(*mf_checker);
    }
  }

  const auto* paint_properties = fragment_to_paint_->PaintProperties();
  if (!paint_properties)
    return;

  auto new_properties = input_paint_info_.context.GetPaintController()
                            .CurrentPaintChunkProperties();
  bool property_changed = false;

  const auto* content_transform = paint_properties->ReplacedContentTransform();
  if (content_transform) {
    new_properties.SetTransform(*content_transform);
    adjusted_paint_info_.emplace(input_paint_info_);
    adjusted_paint_info_->TransformCullRect(*content_transform);
    property_changed = true;
  }

  if (const auto* clip = paint_properties->OverflowClip()) {
    new_properties.SetClip(*clip);
    property_changed = true;
  }

  if (property_changed) {
    chunk_properties_.emplace(input_paint_info_.context.GetPaintController(),
                              new_properties, replaced,
                              input_paint_info_.DisplayItemTypeForClipping());
  }
}

}  // anonymous namespace

bool ReplacedPainter::ShouldPaintBoxDecorationBackground(
    const PaintInfo& paint_info) {
  // LayoutFrameSet paints everything in the foreground phase.
  if (layout_replaced_.IsLayoutEmbeddedContent() &&
      layout_replaced_.Parent()->IsFrameSet()) {
    return paint_info.phase == PaintPhase::kForeground;
  }
  return ShouldPaintSelfBlockBackground(paint_info.phase);
}

void ReplacedPainter::Paint(const PaintInfo& paint_info) {
  ScopedPaintState paint_state(layout_replaced_, paint_info);
  if (!ShouldPaint(paint_state))
    return;

  const auto& local_paint_info = paint_state.GetPaintInfo();
  auto paint_offset = paint_state.PaintOffset();
  PhysicalRect border_rect(paint_offset, layout_replaced_.Size());

  if (ShouldPaintBoxDecorationBackground(local_paint_info)) {
    bool should_paint_background = false;
    if (RuntimeEnabledFeatures::HitTestOpaquenessEnabled() &&
        // TODO(crbug.com/1477914): Without this condition, scaled canvas
        // would become pixelated on Linux.
        !layout_replaced_.IsCanvas()) {
      should_paint_background = true;
    } else if (layout_replaced_.HasBoxDecorationBackground()) {
      should_paint_background = true;
    } else if (layout_replaced_.HasEffectiveAllowedTouchAction() ||
               layout_replaced_.InsideBlockingWheelEventHandler()) {
      should_paint_background = true;
    } else {
      Element* element = DynamicTo<Element>(layout_replaced_.GetNode());
      if (element && element->GetRegionCaptureCropId()) {
        should_paint_background = true;
      }
    }
    if (should_paint_background) {
      PaintBoxDecorationBackground(local_paint_info, paint_offset);
    }

    // We're done. We don't bother painting any children.
    if (layout_replaced_.DrawsBackgroundOntoContentLayer() ||
        local_paint_info.phase == PaintPhase::kSelfBlockBackgroundOnly) {
      return;
    }
  }

  if (local_paint_info.phase == PaintPhase::kMask) {
    PaintMask(local_paint_info, paint_offset);
    return;
  }

  if (ShouldPaintSelfOutline(local_paint_info.phase)) {
    ObjectPainter(layout_replaced_)
        .PaintOutline(local_paint_info, paint_offset);
    return;
  }

  if (local_paint_info.phase != PaintPhase::kForeground &&
      local_paint_info.phase != PaintPhase::kSelectionDragImage &&
      (!layout_replaced_.CanHaveChildren() || layout_replaced_.IsCanvas())) {
    return;
  }

  if (local_paint_info.phase == PaintPhase::kSelectionDragImage &&
      !layout_replaced_.IsSelected())
    return;

  bool has_clip =
      layout_replaced_.FirstFragment().PaintProperties() &&
      layout_replaced_.FirstFragment().PaintProperties()->OverflowClip();
  if (!has_clip || !layout_replaced_.PhysicalContentBoxRect().IsEmpty()) {
    ScopedReplacedContentPaintState content_paint_state(paint_state,
                                                        layout_replaced_);
    layout_replaced_.PaintReplaced(content_paint_state.GetPaintInfo(),
                                   content_paint_state.PaintOffset());
    MeasureOverflowMetrics();
  }

  if (layout_replaced_.StyleRef().Visibility() == EVisibility::kVisible &&
      layout_replaced_.CanResize()) {
    auto* scrollable_area = layout_replaced_.GetScrollableArea();
    DCHECK(scrollable_area);
    if (!scrollable_area->HasLayerForScrollCorner()) {
      ScrollableAreaPainter(*scrollable_area)
          .PaintResizer(local_paint_info.context, paint_offset,
                        local_paint_info.GetCullRect());
    }
    // Otherwise the resizer will be painted by the scroll corner layer.
  }

  // The selection tint never gets clipped by border-radius rounding, since we
  // want it to run right up to the edges of surrounding content.
  bool draw_selection_tint =
      local_paint_info.phase == PaintPhase::kForeground &&
      layout_replaced_.IsSelected() && layout_replaced_.CanBeSelectionLeaf() &&
      !layout_replaced_.GetDocument().Printing();
  if (!draw_selection_tint)
    return;

  std::optional<SelectionBoundsRecorder> selection_recorder;
  const FrameSelection& frame_selection =
      layout_replaced_.GetFrame()->Selection();
  SelectionState selection_state = layout_replaced_.GetSelectionState();
  if (SelectionBoundsRecorder::ShouldRecordSelection(frame_selection,
                                                     selection_state)) {
    PhysicalRect selection_rect = layout_replaced_.LocalSelectionVisualRect();
    selection_rect.Move(paint_offset);
    const ComputedStyle& style = layout_replaced_.StyleRef();
    selection_recorder.emplace(selection_state, selection_rect,
                               local_paint_info.context.GetPaintController(),
                               style.Direction(), style.GetWritingMode(),
                               layout_replaced_);
  }

  if (!DrawingRecorder::UseCachedDrawingIfPossible(
          local_paint_info.context, layout_replaced_,
          DisplayItem::kSelectionTint)) {
    PhysicalRect selection_painting_rect =
        layout_replaced_.LocalSelectionVisualRect();
    selection_painting_rect.Move(paint_offset);
    gfx::Rect selection_painting_int_rect =
        ToPixelSnappedRect(selection_painting_rect);

    DrawingRecorder recorder(local_paint_info.context, layout_replaced_,
                             DisplayItem::kSelectionTint,
                             selection_painting_int_rect);
    Color selection_bg = HighlightStyleUtils::HighlightBackgroundColor(
        layout_replaced_.GetDocument(), layout_replaced_.StyleRef(),
        layout_replaced_.GetNode(), std::nullopt, kPseudoIdSelection,
        SearchTextIsActiveMatch::kNo);
    local_paint_info.context.FillRect(
        selection_painting_int_rect, selection_bg,
        PaintAutoDarkMode(layout_replaced_.StyleRef(),
                          DarkModeFilter::ElementRole::kBackground));
  }
}

bool ReplacedPainter::ShouldPaint(const ScopedPaintState& paint_state) const {
  const auto& paint_info = paint_state.GetPaintInfo();
  if (paint_info.phase != PaintPhase::kForeground &&
      paint_info.phase != PaintPhase::kForcedColorsModeBackplate &&
      !ShouldPaintSelfOutline(paint_info.phase) &&
      paint_info.phase != PaintPhase::kSelectionDragImage &&
      paint_info.phase != PaintPhase::kMask &&
      !ShouldPaintSelfBlockBackground(paint_info.phase))
    return false;

  if (layout_replaced_.IsTruncated())
    return false;

  // If we're invisible or haven't received a layout yet, just bail.
  // But if it's an SVG root, there can be children, so we'll check visibility
  // later.
  if (!layout_replaced_.IsSVGRoot() &&
      layout_replaced_.StyleRef().Visibility() != EVisibility::kVisible) {
    return false;
  }

  PhysicalRect local_rect = layout_replaced_.VisualOverflowRect();
  local_rect.Unite(layout_replaced_.LocalSelectionVisualRect());
  if (!paint_state.LocalRectIntersectsCullRect(local_rect))
    return false;

  return true;
}

void ReplacedPainter::MeasureOverflowMetrics() const {
  if (!layout_replaced_.BelongsToElementChangingOverflowBehaviour() ||
      layout_replaced_.ClipsToContentBox() ||
      !layout_replaced_.HasVisualOverflow()) {
    return;
  }

  auto overflow_size = layout_replaced_.VisualOverflowRect().size;
  auto overflow_area = overflow_size.width * overflow_size.height;

  auto content_size = layout_replaced_.Size();
  auto content_area = content_size.width * content_size.height;

  DCHECK_GE(overflow_area, content_area);
  if (overflow_area == content_area)
    return;

  const float device_pixel_ratio =
      layout_replaced_.GetDocument().DevicePixelRatio();
  const int overflow_outside_content_rect =
      (overflow_area - content_area).ToInt() / pow(device_pixel_ratio, 2);
  UMA_HISTOGRAM_COUNTS_100000(
      "Blink.Overflow.ReplacedElementAreaOutsideContentRect",
      overflow_outside_content_rect);

  UseCounter::Count(layout_replaced_.GetDocument(),
                    WebFeature::kReplacedElementPaintedWithOverflow);
  constexpr int kMaxContentBreakageHeuristic = 5000;
  if (overflow_outside_content_rect > kMaxContentBreakageHeuristic) {
    UseCounter::Count(layout_replaced_.GetDocument(),
                      WebFeature::kReplacedElementPaintedWithLargeOverflow);
  }
}

void ReplacedPainter::PaintBoxDecorationBackground(
    const PaintInfo& paint_info,
    const PhysicalOffset& paint_offset) {
  const ComputedStyle& style = layout_replaced_.StyleRef();
  if (style.Visibility() != EVisibility::kVisible) {
    return;
  }

  PhysicalRect paint_rect;
  const DisplayItemClient* background_client = nullptr;
  std::optional<ScopedBoxContentsPaintState> contents_paint_state;
  bool painting_background_in_contents_space =
      paint_info.IsPaintingBackgroundInContentsSpace();
  gfx::Rect visual_rect;
  if (painting_background_in_contents_space) {
    // For the case where we are painting the background in the contents space,
    // we need to include the entire overflow rect.
    paint_rect = layout_replaced_.ScrollableOverflowRect();
    contents_paint_state.emplace(paint_info, paint_offset, layout_replaced_,
                                 paint_info.FragmentDataOverride());
    paint_rect.Move(contents_paint_state->PaintOffset());

    // The background painting code assumes that the borders are part of the
    // paint_rect so we expand the paint_rect by the border size when painting
    // the background into the scrolling contents layer.
    paint_rect.Expand(layout_replaced_.BorderOutsets());

    background_client = &layout_replaced_.GetScrollableArea()
                             ->GetScrollingBackgroundDisplayItemClient();
    visual_rect =
        layout_replaced_.GetScrollableArea()->ScrollingBackgroundVisualRect(
            paint_offset);
  } else {
    paint_rect = layout_replaced_.PhysicalBorderBoxRect();
    paint_rect.Move(paint_offset);
    background_client = &layout_replaced_;
    visual_rect = BoxPainter(layout_replaced_).VisualRect(paint_offset);
  }

  if (layout_replaced_.HasBoxDecorationBackground() &&
      !layout_replaced_.DrawsBackgroundOntoContentLayer()) {
    PaintBoxDecorationBackgroundWithRect(
        contents_paint_state ? contents_paint_state->GetPaintInfo()
                             : paint_info,
        visual_rect, paint_rect, *background_client);
  }

  ObjectPainter(layout_replaced_)
      .RecordHitTestData(paint_info, ToPixelSnappedRect(paint_rect),
                         *background_client);
  BoxPainter(layout_replaced_)
      .RecordRegionCaptureData(paint_info, paint_rect, *background_client);

  // Record the scroll hit test after the non-scrolling background so
  // background squashing is not affected. Hit test order would be equivalent
  // if this were immediately before the non-scrolling background.
  if (!painting_background_in_contents_space) {
    BoxPainter(layout_replaced_)
        .RecordScrollHitTestData(paint_info, *background_client,
                                 paint_info.FragmentDataOverride());
  }
}

void ReplacedPainter::PaintBoxDecorationBackgroundWithRect(
    const PaintInfo& paint_info,
    const gfx::Rect& visual_rect,
    const PhysicalRect& paint_rect,
    const DisplayItemClient& background_client) {
  const ComputedStyle& style = layout_replaced_.StyleRef();

  std::optional<DisplayItemCacheSkipper> cache_skipper;
  if (RuntimeEnabledFeatures::PaintUnderInvalidationCheckingEnabled() &&
      BoxPainterBase::ShouldSkipPaintUnderInvalidationChecking(
          layout_replaced_)) {
    cache_skipper.emplace(paint_info.context);
  }

  BoxDecorationData box_decoration_data(paint_info, layout_replaced_);
  if (!box_decoration_data.ShouldPaint()) {
    return;
  }

  if (DrawingRecorder::UseCachedDrawingIfPossible(
          paint_info.context, background_client,
          DisplayItem::kBoxDecorationBackground)) {
    return;
  }

  DrawingRecorder recorder(paint_info.context, background_client,
                           DisplayItem::kBoxDecorationBackground, visual_rect);
  GraphicsContextStateSaver state_saver(paint_info.context, false);

  bool needs_end_layer = false;
  // FIXME: Should eventually give the theme control over whether the box
  // shadow should paint, since controls could have custom shadows of their
  // own.
  if (box_decoration_data.ShouldPaintShadow()) {
    BoxPainterBase::PaintNormalBoxShadow(
        paint_info, paint_rect, style, PhysicalBoxSides(),
        !box_decoration_data.ShouldPaintBackground());
  }

  if (BleedAvoidanceIsClipping(
          box_decoration_data.GetBackgroundBleedAvoidance())) {
    state_saver.Save();
    FloatRoundedRect border =
        RoundedBorderGeometry::PixelSnappedRoundedBorder(style, paint_rect);
    paint_info.context.ClipRoundedRect(border);

    if (box_decoration_data.GetBackgroundBleedAvoidance() ==
        kBackgroundBleedClipLayer) {
      paint_info.context.BeginLayer();
      needs_end_layer = true;
    }
  }

  // If we have a native theme appearance, paint that before painting our
  // background.  The theme will tell us whether or not we should also paint the
  // CSS background.
  gfx::Rect snapped_paint_rect = ToPixelSnappedRect(paint_rect);
  ThemePainter& theme_painter = LayoutTheme::GetTheme().Painter();
  bool theme_painted =
      box_decoration_data.HasAppearance() &&
      !theme_painter.Paint(layout_replaced_, paint_info, snapped_paint_rect);
  if (!theme_painted) {
    if (box_decoration_data.ShouldPaintBackground()) {
      PaintBackground(paint_info, paint_rect,
                      box_decoration_data.BackgroundColor(),
                      box_decoration_data.GetBackgroundBleedAvoidance());
    }
    if (box_decoration_data.HasAppearance()) {
      theme_painter.PaintDecorations(layout_replaced_.GetNode(),
                                     layout_replaced_.GetDocument(), style,
                                     paint_info, snapped_paint_rect);
    }
  }

  if (box_decoration_data.ShouldPaintShadow()) {
    BoxPainterBase::PaintInsetBoxShadowWithBorderRect(paint_info, paint_rect,
                                                      style);
  }

  // The theme will tell us whether or not we should also paint the CSS
  // border.
  if (box_decoration_data.ShouldPaintBorder()) {
    if (!theme_painted) {
      theme_painted =
          box_decoration_data.HasAppearance() &&
          !theme_painter.PaintBorderOnly(layout_replaced_.GetNode(), style,
                                         paint_info, snapped_paint_rect);
    }
    if (!theme_painted) {
      BoxPainterBase::PaintBorder(
          layout_replaced_, layout_replaced_.GetDocument(),
          layout_replaced_.GeneratingNode(), paint_info, paint_rect, style,
          box_decoration_data.GetBackgroundBleedAvoidance());
    }
  }

  if (needs_end_layer) {
    paint_info.context.EndLayer();
  }
}

void ReplacedPainter::PaintBackground(
    const PaintInfo& paint_info,
    const PhysicalRect& paint_rect,
    const Color& background_color,
    BackgroundBleedAvoidance bleed_avoidance) {
  if (layout_replaced_.BackgroundTransfersToView()) {
    return;
  }
  if (layout_replaced_.BackgroundIsKnownToBeObscured()) {
    return;
  }
  BoxModelObjectPainter box_model_painter(layout_replaced_);
  BoxBackgroundPaintContext bg_paint_context(layout_replaced_);
  box_model_painter.PaintFillLayers(
      paint_info, background_color,
      layout_replaced_.StyleRef().BackgroundLayers(), paint_rect,
      bg_paint_context, bleed_avoidance);
}

void ReplacedPainter::PaintMask(const PaintInfo& paint_info,
                                const PhysicalOffset& paint_offset) {
  DCHECK_EQ(PaintPhase::kMask, paint_info.phase);

  if (!layout_replaced_.HasMask() ||
      layout_replaced_.StyleRef().Visibility() != EVisibility::kVisible) {
    return;
  }

  if (DrawingRecorder::UseCachedDrawingIfPossible(
          paint_info.context, layout_replaced_, paint_info.phase)) {
    return;
  }

  PhysicalRect paint_rect(paint_offset, layout_replaced_.Size());
  BoxDrawingRecorder recorder(paint_info.context, layout_replaced_,
                              paint_info.phase, paint_offset);
  PaintMaskImages(paint_info, paint_rect);
}

void ReplacedPainter::PaintMaskImages(const PaintInfo& paint_info,
                                      const PhysicalRect& paint_rect) {
  // For mask images legacy layout painting handles multi-line boxes by giving
  // the full width of the element, not the current line box, thereby clipping
  // the offending edges.
  BoxModelObjectPainter painter(layout_replaced_);
  BoxBackgroundPaintContext bg_paint_context(layout_replaced_);
  painter.PaintMaskImages(paint_info, paint_rect, layout_replaced_,
                          bg_paint_context, PhysicalBoxSides());
}

}  // namespace blink
```