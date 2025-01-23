Response:
The user wants me to analyze the provided C++ code snippet from Chromium's Blink rendering engine. Specifically, they want to understand the functionality of `view_transition_style_tracker.cc`. I need to identify its purpose, explain its relationships with web technologies (JavaScript, HTML, CSS), provide examples of logical reasoning with input/output, highlight potential user/programmer errors, and summarize its functions based on the provided first part of the file.

Here's a breakdown of how to address each point:

1. **Functionality:**  Scan the code for key data structures, methods, and concepts. The file deals with tracking styles and properties related to view transitions. Look for things like:
    *  Data structures storing element information (like `element_data_map_`).
    *  Methods for adding and processing transition elements (`AddTransitionElement`, `AddTransitionElementsFromCSS`).
    *  Logic for capturing and comparing styles.
    *  Handling of pseudo-elements related to view transitions.
    *  Interactions with the layout and paint systems.

2. **Relationships with JavaScript, HTML, CSS:** Identify how the C++ code interacts with these web technologies.
    * **CSS:** The code heavily references CSS properties (`CSSPropertyID`), parses CSS values, and interacts with the style system. The `view-transition-name` property is a key connection point.
    * **HTML:** The code operates on `Element` objects and traverses the DOM tree. The `view-transition-name` attribute on HTML elements is crucial.
    * **JavaScript:** While this specific file doesn't show direct JavaScript interaction, the view transition API itself is triggered by JavaScript. The C++ code provides the underlying mechanism for the API.

3. **Logical Reasoning (Input/Output):**  Think about specific scenarios and how the code would react.
    * **Input:** An HTML element with `style="view-transition-name: my-element;"`.
    * **Output:** The `ViewTransitionStyleTracker` would store information about this element, associating the name "my-element" with the element.
    * **Input:** Two elements with the same `view-transition-name`.
    * **Output:** The code detects this duplicate and logs a console error.

4. **User/Programmer Errors:**  Identify common mistakes developers might make.
    *  Using the same `view-transition-name` for multiple elements when intending separate transitions.
    *  Incorrectly setting up CSS styles that interfere with the transition.

5. **Summary of Functionality:** Condense the findings into a concise description of the file's purpose based on the provided code.

**Pre-computation/Pre-analysis:**

* **Core Concept:** View Transitions involve capturing the state of elements before and after a change, then animating the differences. This file seems to be responsible for the "before" part - identifying and capturing the necessary information.
* **Key Data Structure:** `element_data_map_` likely stores the captured information for each element involved in the transition, indexed by the `view-transition-name`.
* **Key Methods:**  `AddTransitionElement` and `AddTransitionElementsFromCSS` are central to identifying which elements participate in the transition.
* **Pseudo-elements:** The code explicitly creates and manages pseudo-elements like `::view-transition-old` and `::view-transition-new`, which are crucial for rendering the transitional states.

By following these steps and considering the pre-analysis, I can generate a comprehensive and accurate answer.
这是 `blink/renderer/core/view_transition/view_transition_style_tracker.cc` 文件的第一部分，它主要负责 **追踪和管理参与视图过渡的元素的样式信息**。更具体地说，它的功能可以归纳为以下几点：

**核心功能：**

1. **识别参与视图过渡的元素：**
   - 通过解析 CSS 样式中的 `view-transition-name` 属性来识别需要进行视图过渡的元素。
   -  `AddTransitionElement` 和 `AddTransitionElementsFromCSS` 方法用于查找并记录这些元素。

2. **存储元素的初始状态：**
   -  在视图过渡开始前，捕获这些元素的关键样式属性，例如 `opacity`、`transform`、`clip-path` 等，用于后续的动画。
   -  `element_data_map_` 数据结构用于存储每个被追踪元素的相关信息。

3. **管理视图过渡相关的伪元素：**
   - 创建和管理与视图过渡相关的伪元素，例如 `::view-transition-image-pair`、`::view-transition-old` 和 `::view-transition-new`。
   - `ImageWrapperPseudoElement` 类是用于管理图像相关的伪元素的。

4. **处理 `view-transition-group`：**
   - 识别并记录元素的包含组信息，以便在过渡中进行分组和动画。

5. **处理自动命名 (auto-name)：**
   -  当 `view-transition-name` 设置为 `auto` 时，生成唯一的名称。

**与 JavaScript, HTML, CSS 的关系和举例说明：**

* **CSS:**
    - **功能关系：** 该文件直接解析和利用 CSS 的 `view-transition-name` 属性来确定哪些元素参与过渡。同时，它还捕获和存储元素的各种 CSS 属性值。
    - **举例说明：**
        ```css
        .element-to-transition {
          view-transition-name: my-element;
        }
        ```
        当浏览器解析到这段 CSS 时，`ViewTransitionStyleTracker` 会识别出带有 `view-transition-name: my-element;` 的 HTML 元素，并开始追踪它的样式信息。

* **HTML:**
    - **功能关系：** 该文件操作的是 HTML 元素，通过 `view-transition-name` 属性或者自动命名机制与特定的 HTML 元素关联起来。
    - **举例说明：**
        ```html
        <div class="element-to-transition">This will transition</div>
        ```
        这个 HTML `div` 元素因为应用了带有 `view-transition-name` 的 CSS 类，会被 `ViewTransitionStyleTracker` 识别。

* **JavaScript:**
    - **功能关系：** 虽然这个文件本身是 C++ 代码，但它为 JavaScript 发起的视图过渡 API 提供了底层的支持。JavaScript 通过 API 触发视图过渡，而 `ViewTransitionStyleTracker` 负责收集和管理过渡所需的样式信息。
    - **举例说明：** (虽然代码中没有直接体现，但可以理解为幕后工作) 当 JavaScript 代码调用 `document.startViewTransition(...)` 时，浏览器会调用 Blink 引擎的相关代码，其中就包括使用 `ViewTransitionStyleTracker` 来捕获当前状态的元素样式。

**逻辑推理 (假设输入与输出):**

假设输入一个包含以下 HTML 和 CSS 的页面：

```html
<!DOCTYPE html>
<html>
<head>
<style>
  .box {
    view-transition-name: box-element;
    width: 100px;
    height: 100px;
    background-color: red;
  }
</style>
</head>
<body>
  <div class="box"></div>
</body>
</html>
```

在视图过渡开始时，`ViewTransitionStyleTracker` 会执行以下逻辑：

1. **输入：** 浏览器开始处理视图过渡。
2. **查找：** `AddTransitionElementsFromCSS` 方法会被调用，遍历 DOM 树。
3. **匹配：** 当遇到带有 CSS 类 `box` 的 `div` 元素时，会检查其 `view-transition-name` 属性。
4. **存储：**  `view-transition-name` 的值为 `box-element`，`ViewTransitionStyleTracker` 会在 `element_data_map_` 中创建一个条目，键为 `"box-element"`，值包含该 `div` 元素当前的样式信息，例如 `width: 100px`, `height: 100px`, `background-color: red`。
5. **输出：**  `element_data_map_` 中会包含类似如下的信息（简化表示）：
   ```
   {
     "box-element": {
       element: [指向该 div 元素的指针],
       captured_css_properties: {
         "width": "100px",
         "height": "100px",
         "background-color": "red",
         // ... 其他捕获的属性
       }
     }
   }
   ```

**用户或者编程常见的使用错误 (举例说明):**

1. **重复使用 `view-transition-name`：**
   - **错误：**  如果两个不同的元素使用了相同的 `view-transition-name`，`ViewTransitionStyleTracker` 会发出警告，因为这会导致在过渡中将这两个元素视为同一个元素，可能产生意想不到的动画效果。
   - **例子：**
     ```html
     <div style="view-transition-name: item1;">Item 1</div>
     <div style="view-transition-name: item1;">Item 2</div>
     ```
     `ViewTransitionStyleTracker` 会记录一个错误，提示 "Unexpected duplicate view-transition-name: item1"。

2. **在不支持视图过渡的浏览器中使用：**
   - **错误：**  如果在不支持视图过渡 API 的浏览器中使用 `view-transition-name`，这些属性会被忽略，不会产生过渡效果。
   - **例子：** 在较旧的浏览器中，即使设置了 `view-transition-name`，也不会触发视图过渡。

**功能归纳 (基于第 1 部分):**

`blink/renderer/core/view_transition/view_transition_style_tracker.cc` 文件的第一部分主要负责 **在视图过渡的初始阶段，识别页面中需要参与过渡的元素，并捕获这些元素在过渡开始前的样式信息**。它通过解析 CSS 的 `view-transition-name` 属性来实现元素的识别，并将捕获的信息存储起来，为后续的动画处理做准备。此外，它还涉及到管理与视图过渡相关的伪元素和处理 `view-transition-group` 属性。

### 提示词
```
这是目录为blink/renderer/core/view_transition/view_transition_style_tracker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/view_transition/view_transition_style_tracker.h"

#include <limits>
#include <unordered_map>

#include "base/check.h"
#include "base/containers/contains.h"
#include "base/not_fatal_until.h"
#include "components/viz/common/view_transition_element_resource_id.h"
#include "third_party/blink/public/resources/grit/blink_resources.h"
#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/animation/property_handle.h"
#include "third_party/blink/renderer/core/css/css_default_style_sheets.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/properties/computed_style_utils.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_document_state.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/frame/browser_controls.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/page_scale_constraints_set.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/layout/geometry/box_strut.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_rect.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/layout_view_transition_root.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/paint/clip_path_clipper.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_paint_order_iterator.h"
#include "third_party/blink/renderer/core/resize_observer/resize_observer_entry.h"
#include "third_party/blink/renderer/core/resize_observer/resize_observer_size.h"
#include "third_party/blink/renderer/core/scroll/scrollable_area.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/style/shape_clip_path_operation.h"
#include "third_party/blink/renderer/core/style/style_view_transition_group.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_content_element.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_pseudo_element_base.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_style_builder.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_supplement.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_transition_element.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_utils.h"
#include "third_party/blink/renderer/platform/data_resource_helper.h"
#include "third_party/blink/renderer/platform/graphics/graphics_types.h"
#include "third_party/blink/renderer/platform/graphics/paint/geometry_mapper.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/widget/frame_widget.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "ui/display/screen_info.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/rect_conversions.h"
#include "ui/gfx/geometry/size_conversions.h"
#include "ui/gfx/geometry/transform.h"
#include "ui/gfx/geometry/vector2d_f.h"

namespace blink {
namespace {

const char* kDuplicateTagBaseError =
    "Unexpected duplicate view-transition-name: ";

CSSPropertyID kPropertiesToCapture[] = {
    CSSPropertyID::kBackdropFilter, CSSPropertyID::kColorScheme,
    CSSPropertyID::kMixBlendMode,   CSSPropertyID::kTextOrientation,
    CSSPropertyID::kWritingMode,
};

CSSPropertyID kLayeredCaptureProperties[] = {
    CSSPropertyID::kBackground,
    CSSPropertyID::kBorderBottom,
    CSSPropertyID::kBorderImage,
    CSSPropertyID::kBorderLeft,
    CSSPropertyID::kBorderRadius,
    CSSPropertyID::kBorderRight,
    CSSPropertyID::kBorderTop,
    CSSPropertyID::kBoxShadow,
    CSSPropertyID::kBoxSizing,
    CSSPropertyID::kClipPath,
    CSSPropertyID::kContain,
    CSSPropertyID::kFilter,
    // Deliberately capturing the shorthand, to include all the mask-related
    // properties.
    CSSPropertyID::kMask,
    CSSPropertyID::kOpacity,
    CSSPropertyID::kOutline,
    CSSPropertyID::kOverflow,
    CSSPropertyID::kOverflowClipMargin,
    CSSPropertyID::kPadding,
};

CSSPropertyID kPropertiesToAnimate[] = {
    CSSPropertyID::kBackdropFilter, CSSPropertyID::kOpacity,
    CSSPropertyID::kBorderLeft,     CSSPropertyID::kBackground,
    CSSPropertyID::kBorderRadius,   CSSPropertyID::kBoxShadow,
    CSSPropertyID::kBorderRight,    CSSPropertyID::kBorderBottom,
    CSSPropertyID::kClipPath,       CSSPropertyID::kFilter,
    CSSPropertyID::kMask,           CSSPropertyID::kBorderTop,
    CSSPropertyID::kOutline,        CSSPropertyID::kBorderImage,
    CSSPropertyID::kPadding,
};

template <typename K, typename V>
class FlatMapBuilder {
 public:
  explicit FlatMapBuilder(size_t reserve = 0) { data_.reserve(reserve); }

  template <typename... Args>
  void Insert(Args&&... args) {
    data_.emplace_back(std::forward<Args>(args)...);
  }

  base::flat_map<K, V> Finish() && {
    return base::flat_map<K, V>(std::move(data_));
  }

 private:
  std::vector<std::pair<K, V>> data_
      ALLOW_DISCOURAGED_TYPE("flat_map underlying type");
};

#define FOR_EACH_CSS_PROPERTY(OP) \
  OP(BackdropFilter)              \
  OP(Background)                  \
  OP(BorderBottom)                \
  OP(BorderImage)                 \
  OP(BorderLeft)                  \
  OP(BorderRadius)                \
  OP(BorderRight)                 \
  OP(BorderTop)                   \
  OP(BoxShadow)                   \
  OP(BoxSizing)                   \
  OP(ClipPath)                    \
  OP(ColorScheme)                 \
  OP(Contain)                     \
  OP(Filter)                      \
  OP(Mask)                        \
  OP(MixBlendMode)                \
  OP(Opacity)                     \
  OP(Outline)                     \
  OP(Overflow)                    \
  OP(OverflowClipMargin)          \
  OP(Padding)                     \
  OP(TextOrientation)             \
  OP(WritingMode)

mojom::blink::ViewTransitionPropertyId ToTranstionPropertyId(CSSPropertyID id) {
#define TO_TRANSITION_PROPERTY_ID(id) \
  case CSSPropertyID::k##id:          \
    return mojom::blink::ViewTransitionPropertyId::k##id;
  switch (id) {
    FOR_EACH_CSS_PROPERTY(TO_TRANSITION_PROPERTY_ID)
    default:
      NOTREACHED() << "Unknown id " << static_cast<uint32_t>(id);
  }
}

CSSPropertyID FromTransitionPropertyId(
    mojom::blink::ViewTransitionPropertyId id) {
#define FROM_TRANSITION_PROPERTY_ID(id)               \
  case mojom::blink::ViewTransitionPropertyId::k##id: \
    return CSSPropertyID::k##id;
  switch (id) { FOR_EACH_CSS_PROPERTY(FROM_TRANSITION_PROPERTY_ID) }
  return CSSPropertyID::kInvalid;
}

const String& StaticUAStyles() {
  DEFINE_STATIC_LOCAL(
      String, kStaticUAStyles,
      (UncompressResourceAsASCIIString(IDR_UASTYLE_TRANSITION_CSS)));
  return kStaticUAStyles;
}

const String& AnimationUAStyles() {
  DEFINE_STATIC_LOCAL(
      String, kAnimationUAStyles,
      (UncompressResourceAsASCIIString(IDR_UASTYLE_TRANSITION_ANIMATIONS_CSS)));
  return kAnimationUAStyles;
}

// Computes and returns the start offset for element's painting in horizontal or
// vertical direction.
// `start` and `end` denote the offset where the element's ink overflow
// rectangle start and end for a particular direction, relative to the element's
// border box.
// `snapshot_root_dimension` is the length of the snapshot root in the same
// direction.
// `max_capture_size` denotes the maximum bounds we can capture for an element.
float ComputeStartForSide(float start,
                          float end,
                          int snapshot_root_dimension,
                          int max_capture_size) {
  DCHECK_GT((end - start), max_capture_size)
      << "Side must be larger than max texture size";
  DCHECK_GE(max_capture_size, snapshot_root_dimension)
      << "Snapshot root bounds must be a subset of max texture size";
  // In all comments below, | and _ denote the edges for the snapshot root and
  // * denote the edges of the element being captured.

  // This is for the following cases:
  //  ____________
  // |            |
  // |  ******    |
  // |__*____*____|
  //    *    *
  //    ******
  //
  // The element starts after the left edge horizontally or after the top edge
  // vertically and is partially onscreen.
  //  ____________
  // |            |
  // |            |
  // |____________|
  //
  //    ******
  //    *    *
  //    ******
  //
  // The element starts after the left edge horizontally or after the top edge
  // vertically and is completely offscreen.
  //
  // For both these cases, start painting from the left or top edge.
  if (start > 0) {
    return start;
  }

  // This is for the following cases:
  //    ******
  //  __*____*____
  // |  *    *    |
  // |  ******    |
  // |____________|
  //
  // The element ends before the right edge horizontally or before the bottom
  // edge vertically and is partially onscreen.
  //
  //    ******
  //    *    *
  //    ******
  //  ____________
  // |            |
  // |            |
  // |____________|
  //
  // The element ends before the right edge horizontally or before the bottom
  // edge vertically and is completely offscreen.
  //
  // For both these cases, start painting from the right or bottom edge.
  if (end < snapshot_root_dimension) {
    return end - max_capture_size;
  }

  // This is for the following case:
  //    ******
  //  __*____*____
  // |  *    *    |
  // |  *    *    |
  // |__*____*____|
  //    *    *
  //    ******
  //
  // The element covers the complete snapshot root horizontally or vertically
  // and is partially offscreen on both sides.
  //
  // Capture the element's intersection with the snapshot root, inflating it by
  // the remaining margin on both sides. If a side doesn't consume the margin
  // completely, give the remaining capacity to the other side.
  const float delta_to_distribute_per_side =
      (max_capture_size - snapshot_root_dimension) / 2;
  const float delta_on_end_side = end - snapshot_root_dimension;
  const float delta_for_start_side =
      delta_to_distribute_per_side +
      std::max(0.f, (delta_to_distribute_per_side - delta_on_end_side));
  return std::max(start, -delta_for_start_side);
}

// Computes the subset of an element's `ink_overflow_rect_in_border_box_space`
// that should be painted. The return value is relative to the element's border
// box.
// Returns null if the complete ink overflow rect should be painted.
std::optional<gfx::RectF> ComputeCaptureRect(
    const int max_capture_size,
    const PhysicalRect& ink_overflow_rect_in_border_box_space,
    const gfx::Transform& element_to_snapshot_root,
    const gfx::Size& snapshot_root_size) {
  if (ink_overflow_rect_in_border_box_space.Width() <= max_capture_size &&
      ink_overflow_rect_in_border_box_space.Height() <= max_capture_size) {
    return std::nullopt;
  }

  // Compute the matrix to map the element's ink overflow rectangle to snapshot
  // root's coordinate space. This is required to figure out which subset of the
  // element to paint based on its position in the viewport.
  // If the transform is not invertible, fallback to painting from the element's
  // ink overflow rectangle's origin.
  gfx::Transform snapshot_root_to_element;
  if (!element_to_snapshot_root.GetInverse(&snapshot_root_to_element)) {
    gfx::SizeF size(ink_overflow_rect_in_border_box_space.size);
    size.SetToMin(gfx::SizeF(max_capture_size, max_capture_size));
    return gfx::RectF(gfx::PointF(ink_overflow_rect_in_border_box_space.offset),
                      size);
  }

  const gfx::RectF ink_overflow_rect_in_snapshot_root_space =
      element_to_snapshot_root.MapRect(
          gfx::RectF(ink_overflow_rect_in_border_box_space));
  gfx::RectF captured_ink_overflow_subrect_in_snapshot_root_space =
      ink_overflow_rect_in_snapshot_root_space;

  if (ink_overflow_rect_in_snapshot_root_space.width() > max_capture_size) {
    captured_ink_overflow_subrect_in_snapshot_root_space.set_x(
        ComputeStartForSide(ink_overflow_rect_in_snapshot_root_space.x(),
                            ink_overflow_rect_in_snapshot_root_space.right(),
                            snapshot_root_size.width(), max_capture_size));
    captured_ink_overflow_subrect_in_snapshot_root_space.set_width(
        max_capture_size);
  }

  if (ink_overflow_rect_in_snapshot_root_space.height() > max_capture_size) {
    captured_ink_overflow_subrect_in_snapshot_root_space.set_y(
        ComputeStartForSide(ink_overflow_rect_in_snapshot_root_space.y(),
                            ink_overflow_rect_in_snapshot_root_space.bottom(),
                            snapshot_root_size.height(), max_capture_size));
    captured_ink_overflow_subrect_in_snapshot_root_space.set_height(
        max_capture_size);
  }

  return snapshot_root_to_element.MapRect(
      captured_ink_overflow_subrect_in_snapshot_root_space);
}

int ComputeMaxCaptureSize(Document& document,
                          std::optional<int> max_texture_size,
                          const gfx::Size& snapshot_root_size) {
  // If the max texture size is not known yet, use the size of the snapshot
  // root.
  if (!max_texture_size) {
    return std::max(snapshot_root_size.width(), snapshot_root_size.height());
  }

  // The snapshot root corresponds to the maximum screen bounds so we should be
  // able to allocate a buffer of that size. However, Chrome Android's scaling
  // behavior of the position-fixed viewport means the snapshot root may
  // actually be larger than the screen bounds, though it gets scaled down by
  // the page-scale-factor in the compositor. Since this maximum is applied to
  // layout-generated bounds, project it into layout-space by using the minimum
  // possible scale (which is how the position-fixed viewport size is
  // computed).
  const float min_page_scale_factor = document.GetPage()
                                          ->GetPageScaleConstraintsSet()
                                          .FinalConstraints()
                                          .minimum_scale;
  const int max_texture_size_in_layout =
      static_cast<int>(std::ceil(*max_texture_size / min_page_scale_factor));

  LOG_IF(WARNING, snapshot_root_size.width() > max_texture_size_in_layout ||
                      snapshot_root_size.height() > max_texture_size_in_layout)
      << "root snapshot does not fit within max texture size";

  // While we can render up to the max texture size, that would significantly
  // add to the memory overhead. So limit to up to a viewport worth of
  // additional content.
  const int max_bounds_based_on_viewport =
      2 * std::max(snapshot_root_size.width(), snapshot_root_size.height());

  return std::min(max_bounds_based_on_viewport, max_texture_size_in_layout);
}

gfx::Transform ComputeViewportTransform(const LayoutObject& object) {
  DCHECK(object.HasLayer());
  DCHECK(!object.IsLayoutView());

  auto& first_fragment = object.FirstFragment();
  DCHECK(ToRoundedPoint(first_fragment.PaintOffset()).IsOrigin())
      << first_fragment.PaintOffset();
  auto paint_properties = first_fragment.LocalBorderBoxProperties();

  auto& root_fragment = object.GetDocument().GetLayoutView()->FirstFragment();
  const auto& root_properties = root_fragment.LocalBorderBoxProperties();

  auto transform = GeometryMapper::SourceToDestinationProjection(
      paint_properties.Transform(), root_properties.Transform());
  if (auto* layout_inline = DynamicTo<LayoutInline>(object)) {
    // The paint_properties we get from
    // `first_fragment.LocalBorderBoxProperties()` correspond to the origin of
    // the inline's container's border-box. So the transform from GeometryMapper
    // maps a point from the viewport to the container's border-box origin. We
    // need the extra translation to map from container's border box origin to
    // inline's border box origin.
    transform.Translate(
        gfx::Vector2dF(layout_inline->PhysicalLinesBoundingBox().offset));
  }

  if (!transform.HasPerspective()) {
    transform.Round2dTranslationComponents();
  }

  return transform;
}

gfx::Transform ConvertFromTopLeftToCenter(
    const gfx::Transform& transform_from_top_left,
    const PhysicalSize& box_size) {
  gfx::Transform transform_from_center;
  transform_from_center.Translate(-box_size.width / 2, -box_size.height / 2);
  transform_from_center.PreConcat(transform_from_top_left);
  transform_from_center.Translate(box_size.width / 2, box_size.height / 2);

  return transform_from_center;
}

float DevicePixelRatioFromDocument(Document& document) {
  // Prefer to use the effective zoom. This should be the case in most
  // situations, unless the transition is being started before first layout
  // where documentElement gets a layout object.
  if (document.documentElement() &&
      document.documentElement()->GetLayoutObject()) {
    return document.documentElement()
        ->GetLayoutObject()
        ->StyleRef()
        .EffectiveZoom();
  }

  if (!document.GetPage() || !document.GetFrame()) {
    return 0.f;
  }
  return document.GetPage()
      ->GetChromeClient()
      .GetScreenInfo(*document.GetFrame())
      .device_scale_factor;
}

Vector<AtomicString> GetDocumentScopedClassList(Element* element) {
  auto class_list = element->ComputedStyleRef().ViewTransitionClass();
  if (!class_list || class_list->GetNames().empty() ||
      class_list->GetNames().front()->GetTreeScope() !=
          element->GetDocument().GetTreeScope()) {
    return Vector<AtomicString>();
  }
  Vector<AtomicString> result;
  result.ReserveInitialCapacity(class_list->GetNames().size());
  for (const auto& scoped_name : class_list->GetNames()) {
    CHECK(scoped_name->GetTreeScope() == element->GetDocument().GetTreeScope());
    result.emplace_back(scoped_name->GetName());
  }

  return result;
}

}  // namespace

class ViewTransitionStyleTracker::ImageWrapperPseudoElement
    : public ViewTransitionPseudoElementBase {
 public:
  ImageWrapperPseudoElement(Element* parent,
                            PseudoId pseudo_id,
                            const AtomicString& view_transition_name,
                            const ViewTransitionStyleTracker* style_tracker)
      : ViewTransitionPseudoElementBase(parent,
                                        pseudo_id,
                                        view_transition_name,
                                        style_tracker) {}

  ~ImageWrapperPseudoElement() override = default;

 private:
  bool CanGeneratePseudoElement(PseudoId pseudo_id) const override {
    if (!ViewTransitionPseudoElementBase::CanGeneratePseudoElement(pseudo_id)) {
      return false;
    }

    // If we're being called with a name, we must have a tracking for this name.
    auto it = style_tracker_->element_data_map_.find(view_transition_name());
    CHECK(it != style_tracker_->element_data_map_.end());
    const auto& element_data = it->value;

    if (pseudo_id == kPseudoIdViewTransitionOld) {
      return element_data->old_snapshot_id.IsValid();
    } else if (pseudo_id == kPseudoIdViewTransitionNew) {
      return element_data->new_snapshot_id.IsValid();
    }

    // Image wrapper pseudo-elements can only generate old/new image
    // pseudo-elements.
    return false;
  }
};

ViewTransitionStyleTracker::ViewTransitionStyleTracker(
    Document& document,
    const blink::ViewTransitionToken& transition_token)
    : document_(document),
      transition_token_(transition_token),
      device_pixel_ratio_(DevicePixelRatioFromDocument(document)) {}

ViewTransitionStyleTracker::ViewTransitionStyleTracker(
    Document& document,
    ViewTransitionState transition_state)
    : document_(document),
      state_(State::kCaptured),
      transition_token_(transition_state.transition_token),
      deserialized_(true) {
  auto* supplement = ViewTransitionSupplement::FromIfExists(document);
  CHECK(supplement);
  supplement->InitializeResourceIdSequence(
      transition_state.next_element_resource_id);

  device_pixel_ratio_ = transition_state.device_pixel_ratio;
  captured_name_count_ = static_cast<int>(transition_state.elements.size());
  snapshot_root_layout_size_at_capture_ =
      transition_state.snapshot_root_size_at_capture;

  VectorOf<AtomicString> transition_names;
  transition_names.ReserveInitialCapacity(captured_name_count_);
  for (const auto& transition_state_element : transition_state.elements) {
    auto name =
        AtomicString::FromUTF8(transition_state_element.tag_name.c_str());
    transition_names.push_back(name);

    DCHECK(!element_data_map_.Contains(name));
    auto* element_data = MakeGarbageCollected<ElementData>();

    element_data->container_properties = ContainerProperties{
        PhysicalRect::EnclosingRect(
            transition_state_element
                .border_box_rect_in_enclosing_layer_css_space),
        transition_state_element.viewport_matrix,
        transition_state_element.layered_box_properties
            ? std::make_optional(ContainerProperties::BoxGeometry{
                  .content_box = PhysicalRect::EnclosingRect(
                      transition_state_element.layered_box_properties
                          ->content_box),
                  .padding_box = PhysicalRect::EnclosingRect(
                      transition_state_element.layered_box_properties
                          ->padding_box),
                  .box_sizing =
                      transition_state_element.layered_box_properties
                                  ->box_sizing ==
                              mojom::blink::ViewTransitionElementBoxSizing::
                                  kContentBox
                          ? EBoxSizing::kContentBox
                          : EBoxSizing::kBorderBox})
            : std::nullopt};
    element_data->old_snapshot_id = transition_state_element.snapshot_id;

    element_data->element_index = transition_state_element.paint_order;
    set_element_sequence_id_ = std::max(set_element_sequence_id_,
                                        transition_state_element.paint_order);

    element_data->visual_overflow_rect_in_layout_space =
        PhysicalRect::EnclosingRect(
            transition_state_element.overflow_rect_in_layout_space);
    element_data->captured_rect_in_layout_space =
        transition_state_element.captured_rect_in_layout_space;

    CHECK_LE(
        transition_state_element.captured_css_properties.size(),
        std::size(kPropertiesToCapture) + std::size(kLayeredCaptureProperties));

    FlatMapBuilder<CSSPropertyID, String> css_property_builder(
        transition_state_element.captured_css_properties.size());
    for (const auto& [id, value] :
         transition_state_element.captured_css_properties) {
      css_property_builder.Insert(FromTransitionPropertyId(id),
                                  String::FromUTF8(value));
    }
    element_data->captured_css_properties =
        std::move(css_property_builder).Finish();

    for (const auto& class_name : transition_state_element.class_list) {
      element_data->class_list.push_back(
          AtomicString::FromUTF8(class_name.c_str()));
    }

    element_data->containing_group_name =
        transition_state_element.containing_group_name.empty()
            ? AtomicString()
            : AtomicString::FromUTF8(
                  transition_state_element.containing_group_name.c_str());
    element_data->CacheStateForOldSnapshot();

    element_data_map_.insert(name, std::move(element_data));
  }

  // Re-create the layer to display the old Document's cached content until the
  // new Document is render-blocked. This is conceptually the same layer as on
  // the ViewTransition on the old Document since it uses the same resource ID.
  if (transition_state.subframe_snapshot_id.IsValid()) {
    subframe_snapshot_layer_ = cc::ViewTransitionContentLayer::Create(
        transition_state.subframe_snapshot_id, /*is_live_content_layer=*/false);
  }

  // The aim of this flag is to serialize/deserialize SPA state using MPA
  // machinery. The intent is to use SPA tests to test MPA implementation as
  // well. To that end, if the flag is enabled we should invalidate styles and
  // clear the view transition names, because the "true" MPA implementation
  // would not have any style or names set.
  if (RuntimeEnabledFeatures::SerializeViewTransitionStateInSPAEnabled()) {
    InvalidateHitTestingCache();
    InvalidateStyle();
    document_->GetStyleEngine().SetViewTransitionNames({});
  }
}

ViewTransitionStyleTracker::~ViewTransitionStyleTracker() {
  if (!RuntimeEnabledFeatures::SerializeViewTransitionStateInSPAEnabled()) {
    CHECK_EQ(state_, State::kFinished);
  }
}

void ViewTransitionStyleTracker::AddConsoleError(
    String message,
    Vector<DOMNodeId> related_nodes) {
  auto* console_message = MakeGarbageCollected<ConsoleMessage>(
      mojom::blink::ConsoleMessageSource::kRendering,
      mojom::blink::ConsoleMessageLevel::kError, std::move(message));
  console_message->SetNodes(document_->GetFrame(), std::move(related_nodes));
  document_->AddConsoleMessage(console_message);
}

void ViewTransitionStyleTracker::AddTransitionElement(
    Element* element,
    const AtomicString& name,
    const AtomicString& nearest_containing_group,
    const AtomicString& nearest_group_with_contain) {
  DCHECK(element);

  // Insert an empty hash set for the element if it doesn't exist, or get it if
  // it does.
  auto& value = pending_transition_element_names_
                    .insert(element, HashSet<std::pair<AtomicString, int>>())
                    .stored_value->value;

  if (nearest_containing_group) {
    group_state_map_.Set(name, AncestorGroupNames{
                                   nearest_containing_group,
                                   nearest_group_with_contain,
                               });
  }
  // Find the existing name if one is there. If it is there, do nothing.
  if (base::Contains(value, name, &std::pair<AtomicString, int>::first))
    return;
  // Otherwise, insert a new sequence id with this name. We'll use the sequence
  // to sort later.
  value.insert(std::make_pair(name, set_element_sequence_id_));
  ++set_element_sequence_id_;
}

bool ViewTransitionStyleTracker::MatchForOnlyChild(
    PseudoId pseudo_id,
    const AtomicString& view_transition_name) const {
  switch (pseudo_id) {
    case kPseudoIdViewTransition:
      DCHECK(!view_transition_name);
      return false;

    case kPseudoIdViewTransitionGroup: {
      DCHECK(view_transition_name);
      DCHECK(element_data_map_.Contains(view_transition_name));

      return element_data_map_.size() == 1;
    }

    case kPseudoIdViewTransitionImagePair:
      DCHECK(view_transition_name);
      return true;

    case kPseudoIdViewTransitionOld: {
      DCHECK(view_transition_name);

      auto it = element_data_map_.find(view_transition_name);
      CHECK(it != element_data_map_.end(), base::NotFatalUntil::M130);
      const auto& element_data = it->value;
      return !element_data->new_snapshot_id.IsValid();
    }

    case kPseudoIdViewTransitionNew: {
      DCHECK(view_transition_name);

      auto it = element_data_map_.find(view_transition_name);
      CHECK(it != element_data_map_.end(), base::NotFatalUntil::M130);
      const auto& element_data = it->value;
      return !element_data->old_snapshot_id.IsValid();
    }

    default:
      NOTREACHED();
  }
}

void ViewTransitionStyleTracker::AddTransitionElementsFromCSS() {
  DCHECK(document_ && document_->View());

  // We need our paint layers, and z-order lists which is done during
  // compositing inputs update.
  DCHECK_GE(document_->Lifecycle().GetState(),
            DocumentLifecycle::kCompositingInputsClean);

  Vector<AtomicString> containing_group_stack;

  AddTransitionElementsFromCSSRecursive(
      document_->GetLayoutView()->PaintingLayer(), document_.Get(),
      containing_group_stack, /*nearest_group_with_contain=*/g_null_atom);
}

AtomicString ViewTransitionStyleTracker::GenerateAutoName(
    Element& element,
    const TreeScope* scope) {
  // The flag should be checked much earlier than this, in the CSS parser.
  CHECK(RuntimeEnabledFeatures::CSSViewTransitionAutoNameEnabled());
  if (element.HasID() && scope && *scope == element.GetTreeScope()) {
    return element.GetIdAttribute();
  }
  StringBuilder builder;
  builder.Append("-ua-auto-");
  if (token_.is_zero()) {
    token_ = base::Token::CreateRandom();
  }
  builder.Append(token_.ToString().c_str());
  builder.Append("-");
  builder.AppendNumber(element.GetDomNodeId());
  return builder.ToAtomicString();
}

void ViewTransitionStyleTracker::AddTransitionElementsFromCSSRecursive(
    PaintLayer* root,
    const TreeScope* tree_scope,
    Vector<AtomicString>& containing_group_stack,
    const AtomicString& nearest_group_with_contain) {
  // We want to call AddTransitionElements in the order in which
  // PaintLayerPaintOrderIterator would cause us to paint the elements.
  // Specifically, parents are added before their children, and lower z-index
  // children are added before higher z-index children. Given that, what we
  // need to do is to first add `root`'s element, and then recurse using the
  // PaintLayerPaintOrderIterator which will return values in the correct
  // z-index order.
  //
  // Note that the order of calls to AddTransitionElement determines the DOM
  // order of pseudo-elements constructed to represent the transition elements,
  // which by default will also represent the paint order of the pseudo-elements
  // (unless changed by something like z-index on the pseudo-elements).
  auto& root_object = root->GetLayoutObject();
  auto& root_style = root_object.StyleRef();

  const auto& view_transition_name = root_style.ViewTransitionName();
  AtomicString current_name;
  if (view_transition_name && !root_object.IsFragmented()) {
    auto* node = root_object.GetNode();
    DCHECK(node);
    DCHECK(node->IsElementNode());

    // ATM this will be null if the scope of the view-transition-name comes from
    // e.g. devtools.
    auto* relevant_tree_scope =
        RuntimeEnabledFeatures::ViewTransitionTreeScopedNamesEnabled()
            ? view_transition_name->GetTreeScope()
            : &node->GetTreeScope();

    if (relevant_tree_scope == tree_scope || !relevant_tree_scope) {
      current_name = view_transition_name->IsAuto()
                         ? GenerateAutoName(*To<Element>(node), tree_scope)
                         : view_transition_name->CustomName();
      AddTransitionElement(DynamicTo<Element>(node), current_name,
                           containing_group_stack.empty()
                               ? g_null_atom
                               : containing_group_stack.back(),
                           nearest_group_with_contain);
    }
  }

  if (root_object.ChildPaintBlockedByDisplayLock())
    return;

  if (current_name) {
    containing_group_stack.push_back(current_name);
  }

  // Even if tree scopes don't match, we process children since light slotted
  // children can have outer tree scope.
  PaintLayerPaintOrderIterator child_iterator(root, kAllChildren);
  while (auto* child = child_iterator.Next()) {
    AddTransitionElementsFromCSSRecursive(
        child, tree_scope, containing_group_stack,
        root_style.ViewTransitionGroup().IsNormal() ? nearest_group_with_contain
                                                    : current_name);
  }

  if (current_name) {
    containing_group_stack.pop_back();
  }
}

bool ViewTransitionStyleTracker::FlattenAndVerifyElements(
    VectorOf<Element>& elements,
    VectorOf<AtomicString>& transiti
```