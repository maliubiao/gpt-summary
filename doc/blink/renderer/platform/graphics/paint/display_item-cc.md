Response:
My thinking process to analyze the `display_item.cc` file goes like this:

1. **Understand the Core Purpose:** The file name `display_item.cc` within the `paint` directory strongly suggests that this file defines a fundamental unit of the rendering pipeline responsible for representing something to be drawn on the screen. The presence of `#include` directives for `DrawingDisplayItem`, `ForeignLayerDisplayItem`, and `ScrollbarDisplayItem` hints at a base class and derived classes for different types of display items.

2. **Identify Key Data Structures:** I look for classes and structs. The `DisplayItem` class is clearly the central focus. The `SameSizeAsDisplayItem` struct, although used for size assertion, gives clues about the basic data members of `DisplayItem`: a pointer/ID, a rectangle, and a couple of integers. The `DisplayItem::Id` nested class represents a unique identifier.

3. **Analyze Member Functions:**  I go through each function, trying to understand its role:
    * **`Destruct()`:**  Handles deallocation, crucial for memory management. The use of `DynamicTo` implies polymorphism and different destruction logic for derived classes.
    * **`EqualsForUnderInvalidation()`:**  This function's name and the `PaintUnderInvalidationCheckingEnabled()` check suggest it's used to determine if a display item has changed in a way that requires repainting during an invalidation process. The checks on `client_id_`, `type_`, `fragment_`, `raster_effect_outset_`, `draws_content_`, and `visual_rect_` indicate the attributes that contribute to the identity and rendering characteristics of a display item. The special handling for empty `visual_rect_` and `DrawingDisplayItem`s not drawing content reveals optimizations or specific conditions. The recursive calls to `EqualsForUnderInvalidationImpl` in derived classes confirm the polymorphic nature.
    * **Debug String Functions (`PaintPhaseAsDebugString`, `SpecialDrawingTypeAsDebugString`, `DrawingTypeAsDebugString`, `ForeignLayerTypeAsDebugString`, `TypeAsDebugString`):** These are clearly for debugging and logging. They provide human-readable names for different display item types and paint phases. The macros `PAINT_PHASE_BASED_DEBUG_STRINGS`, `DEBUG_STRING_CASE`, and `DEFAULT_CASE` simplify the definition of these debug strings.
    * **`AsDebugString()` and `PropertiesAsJSON()`:** These functions are for generating string representations of `DisplayItem` objects, either in a pretty-printed format or as JSON. This is useful for debugging, logging, and potentially for communication between different parts of the rendering engine.
    * **`IdAsString()` and `Id::ToString()`:** These functions are for generating string representations of the `DisplayItem::Id`. The different versions suggest context-dependent information may be included (e.g., using `PaintArtifact`).
    * **Overloaded `operator<<`:** These overloads allow `DisplayItem`, `DisplayItem::Type`, and `DisplayItem::Id` to be easily printed to an output stream, which is heavily used in debugging and logging.

4. **Identify Relationships to Web Technologies (JavaScript, HTML, CSS):**  Now I connect the dots to how `DisplayItem` relates to the front-end:
    * **HTML Structure:** The hierarchical nature of the DOM (Document Object Model) is reflected in how display items are organized and painted. Each HTML element might correspond to one or more display items.
    * **CSS Styling:** CSS properties dictate how elements are rendered. `DisplayItem` stores information like `visual_rect_` (influenced by layout), and different `DisplayItem::Type` values correspond to different CSS effects (e.g., background colors, borders, shadows, transforms, clipping). The paint phases directly relate to the order in which different visual aspects are drawn, influenced by CSS `z-index` and stacking contexts.
    * **JavaScript Interaction:** JavaScript can trigger changes to the DOM and CSS, which in turn necessitate updates to the display list and repainting. The invalidation mechanism, using `EqualsForUnderInvalidation()`, is crucial for efficiently handling these updates. The `ForeignLayerDisplayItem` types directly relate to embedded content like `<canvas>`, `<video>`, and plugins, often manipulated by JavaScript.

5. **Infer Logical Reasoning and Assumptions:**
    * **Assumption:** The code assumes that efficient comparison of display items is essential for optimizing repainting. This is evidenced by the `EqualsForUnderInvalidation()` function and the associated debug checks.
    * **Input/Output for `EqualsForUnderInvalidation()`:**
        * **Input:** Two `DisplayItem` objects.
        * **Output:** `true` if the items are considered equivalent for under-invalidation purposes, `false` otherwise. The specific conditions checked highlight what constitutes a relevant change for repainting.
    * **Input/Output for Debug String Functions:**
        * **Input:** A `DisplayItem::Type` or a paint phase integer.
        * **Output:** A human-readable string describing the type or phase.

6. **Consider Potential Usage Errors:**  I think about how developers might misuse the concepts represented by this code, even if they don't directly interact with `display_item.cc`.
    * **Incorrectly invalidating regions:**  If the invalidation logic is flawed or not precise enough, it can lead to unnecessary repainting, impacting performance.
    * **Modifying properties that affect `EqualsForUnderInvalidation()` without triggering an update:**  This could lead to visual inconsistencies as the rendering engine might not repaint when necessary.
    * **Misunderstanding paint phases:**  While developers don't directly set paint phases, understanding the concept is crucial for understanding how layering and rendering order work in web pages. Issues with `z-index` or stacking contexts often boil down to misunderstandings of paint phases.

7. **Structure the Output:** Finally, I organize my findings into the requested categories: functionality, relationship to web technologies (with examples), logical reasoning (with input/output), and potential usage errors. I use clear and concise language, providing specific examples where applicable. I also try to maintain a logical flow in the explanation.
这个文件 `blink/renderer/platform/graphics/paint/display_item.cc` 定义了 Blink 渲染引擎中用于表示绘制操作的基本单元 `DisplayItem` 类及其相关功能。 `DisplayItem` 是渲染过程中生成的一个指令，它描述了在特定区域绘制特定内容的方式。可以将它理解为渲染引擎的“绘图指令”。

以下是该文件的主要功能：

**1. 定义 `DisplayItem` 类及其子类:**

* **`DisplayItem` (抽象基类):**  定义了所有显示项的通用接口和数据成员，例如：
    * `client_id_`:  一个标识符，用于关联 `DisplayItem` 与其对应的渲染对象。
    * `type_`:  一个枚举值，表示 `DisplayItem` 的具体类型（例如，绘制矩形、绘制文本、绘制图片等）。
    * `visual_rect_`:  `DisplayItem` 在屏幕上的可见区域。
    * `fragment_`:  一个用于区分同一类型但不同实例的标记。
    * `raster_effect_outset_`:  与栅格化效果相关的外延。
    * `draws_content_`:  指示该 `DisplayItem` 是否实际绘制内容。
* **子类 (具体显示项类型):**
    * **`DrawingDisplayItem`:** 表示需要进行实际绘制操作的显示项，例如绘制背景、边框、文本、图片等。
    * **`ForeignLayerDisplayItem`:** 表示需要合成到单独层的显示项，例如 `<canvas>` 元素、`<video>` 元素、插件等。
    * **`ScrollbarDisplayItem`:**  表示滚动条的显示项。

**2. 提供 `DisplayItem` 的创建和销毁机制:**

* `Destruct()`:  一个虚函数，用于安全地销毁不同类型的 `DisplayItem` 对象。它会根据 `DisplayItem` 的实际类型调用相应的析构函数。

**3. 支持 `DisplayItem` 的比较和无效化检查:**

* `EqualsForUnderInvalidation()`:  用于判断两个 `DisplayItem` 对象是否在“欠无效化”的上下文中被认为是相等的。这在渲染优化中非常重要，可以避免不必要的重绘。  它会比较 `client_id_`、`type_`、`fragment_`、`raster_effect_outset_`、`draws_content_` 和 `visual_rect_` 等关键属性。对于 `DrawingDisplayItem` 和 `ForeignLayerDisplayItem`，还会调用其各自的 `EqualsForUnderInvalidationImpl()` 方法进行更细致的比较。

**4. 提供 `DisplayItem` 的调试信息输出:**

* `TypeAsDebugString()`:  返回 `DisplayItem` 类型的可读字符串表示。
* `AsDebugString()`:  返回 `DisplayItem` 对象的详细属性的 JSON 字符串表示。
* `IdAsString()`:  返回 `DisplayItem` 的 ID 字符串表示。
* `PropertiesAsJSON()`:  将 `DisplayItem` 的属性添加到 JSON 对象中。
* 重载的 `operator<<`:  允许将 `DisplayItem` 对象及其类型和 ID 输出到输出流，方便调试。

**与 JavaScript, HTML, CSS 的关系及举例:**

`DisplayItem` 是 Blink 渲染引擎内部的核心概念，它直接由 HTML 结构和 CSS 样式驱动，并且在 JavaScript 操作 DOM 和 CSSOM 后会发生变化。

* **HTML:** HTML 结构定义了页面上的元素。每个需要渲染的 HTML 元素（以及其产生的匿名盒模型）都会生成一系列的 `DisplayItem` 对象。
    * **例子:**  一个 `<div>` 元素会生成 `DisplayItem` 来绘制其背景色 (如果 CSS 中设置了 `background-color`)，边框 (如果设置了 `border`)，以及包含的内容的 `DisplayItem`。
* **CSS:** CSS 样式决定了元素的渲染方式。不同的 CSS 属性会生成不同类型的 `DisplayItem`。
    * **例子:**
        * `background-image: url(...)` 会生成一个用于绘制背景图片的 `DrawingDisplayItem`。
        * `border: 1px solid black` 会生成一个用于绘制边框的 `DrawingDisplayItem`。
        * `transform: rotate(45deg)` 可能会生成一个 `SVGTransformDisplayItem` 或影响后续 `DrawingDisplayItem` 的绘制上下文。
        * `position: fixed` 可能会导致元素的内容被绘制在一个 `ForeignLayerDisplayItem` 中，以便在滚动时保持固定位置。
        * `<canvas>` 元素会生成一个 `ForeignLayerCanvasDisplayItem`。
* **JavaScript:** JavaScript 可以通过修改 DOM 结构和 CSS 样式来间接地影响 `DisplayItem` 的生成和更新。
    * **例子:**
        * JavaScript 使用 `document.createElement()` 创建一个新的 DOM 元素，渲染引擎会为这个新元素生成相应的 `DisplayItem`。
        * JavaScript 使用 `element.style.backgroundColor = 'red'` 修改元素的背景色，会导致与该元素相关的背景绘制 `DisplayItem` 被更新。
        * JavaScript 操作 Canvas API 会直接影响 `ForeignLayerCanvasDisplayItem` 的绘制内容。

**逻辑推理与假设输入/输出 (以 `EqualsForUnderInvalidation` 为例):**

**假设输入:** 两个 `DisplayItem` 对象，`item1` 和 `item2`。

**逻辑推理:**

1. **首先比较基本属性:** 比较 `item1.client_id_` 是否等于 `item2.client_id_`，`item1.type_` 是否等于 `item2.type_`，`item1.fragment_` 是否等于 `item2.fragment_`，`item1.raster_effect_outset_` 是否等于 `item2.raster_effect_outset_`，以及 `item1.draws_content_` 是否等于 `item2.draws_content_`。如果任何一个不相等，则返回 `false`。
2. **比较可视区域:** 比较 `item1.visual_rect_` 是否等于 `item2.visual_rect_`。
    * **特殊情况 1:** 如果两个可视区域都为空，则认为相等，继续后续检查。
    * **特殊情况 2:** 如果 `item1` 是 `DrawingDisplayItem` 且不绘制内容 (`draws_content_` 为 `false`)，则忽略可视区域的差异，继续后续检查。
3. **根据类型进行更细致的比较:**
    * 如果 `item1` 是 `DrawingDisplayItem`，则调用 `item1.EqualsForUnderInvalidationImpl(item2 的 DrawingDisplayItem 版本)` 进行比较。
    * 如果 `item1` 是 `ForeignLayerDisplayItem`，则调用 `item1.EqualsForUnderInvalidationImpl(item2 的 ForeignLayerDisplayItem 版本)` 进行比较。
    * 如果 `item1` 是 `ScrollbarDisplayItem`，则调用 `item1.EqualsForUnderInvalidationImpl(item2 的 ScrollbarDisplayItem 版本)` 进行比较。

**假设输出:**

* **输入:**
    * `item1`: `DrawingDisplayItem`，`client_id_ = 0x123`, `type_ = kBoxDecorationBackground`, `visual_rect_ = {0, 0, 100, 100}`, `draws_content_ = true`.
    * `item2`: `DrawingDisplayItem`，`client_id_ = 0x123`, `type_ = kBoxDecorationBackground`, `visual_rect_ = {0, 0, 100, 100}`, `draws_content_ = true`.
* **输出:** `true` (所有关键属性都相同)

* **输入:**
    * `item1`: `DrawingDisplayItem`，`client_id_ = 0x123`, `type_ = kBoxDecorationBackground`, `visual_rect_ = {0, 0, 100, 100}`.
    * `item2`: `DrawingDisplayItem`，`client_id_ = 0x123`, `type_ = kBoxDecorationBackground`, `visual_rect_ = {50, 50, 100, 100}`.
* **输出:** `false` (可视区域不同)

* **输入:**
    * `item1`: `DrawingDisplayItem`，`client_id_ = 0x123`, `type_ = kText`, `visual_rect_ = {0, 0, 50, 10}`.
    * `item2`: `DrawingDisplayItem`，`client_id_ = 0x123`, `type_ = kText`, `visual_rect_ = {0, 0, 60, 10}`.
    * **假设** `DrawingDisplayItem` 的 `EqualsForUnderInvalidationImpl` 比较文本内容和样式，如果内容和样式相同，则认为相等。
* **输出:**  取决于 `DrawingDisplayItem` 的具体实现，如果文本内容和样式相同，可能为 `true`，否则为 `false`。

**用户或编程常见的使用错误 (虽然开发者通常不直接操作 `DisplayItem`):**

虽然前端开发者通常不直接操作 `DisplayItem` 对象，但理解其概念有助于避免一些性能问题和渲染错误。

* **过度使用 JavaScript 操作样式:** 频繁地通过 JavaScript 修改元素的样式会导致大量的 `DisplayItem` 更新和重新生成，可能导致页面卡顿和性能下降。应该尽量批量更新样式或使用 CSS 动画和过渡。
* **不理解 CSS 的渲染层叠 (stacking contexts):**  错误地使用 `z-index` 和 `position: relative/absolute/fixed` 可能会创建不必要的渲染层，导致生成更多的 `ForeignLayerDisplayItem`，增加合成开销。
* **触发不必要的重绘 (repaints):**  修改某些 CSS 属性（例如，布局相关的属性）会触发更大范围的重绘，可能涉及到多个 `DisplayItem` 的更新。了解哪些 CSS 属性会触发重绘，哪些会触发回流 (reflow)，有助于优化性能。
* **不必要地使用 `will-change`:**  `will-change` 属性可以提示浏览器提前优化某些元素的渲染，但过度使用可能会消耗更多内存。理解其原理并谨慎使用。

总而言之，`display_item.cc` 定义了 Blink 渲染引擎中用于表示绘制操作的核心数据结构，它与 HTML 结构、CSS 样式和 JavaScript 操作密切相关，是理解浏览器渲染原理的重要组成部分。

### 提示词
```
这是目录为blink/renderer/platform/graphics/paint/display_item.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/paint/display_item.h"

#include <cinttypes>

#include "third_party/blink/renderer/platform/graphics/paint/drawing_display_item.h"
#include "third_party/blink/renderer/platform/graphics/paint/foreign_layer_display_item.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_artifact.h"
#include "third_party/blink/renderer/platform/graphics/paint/scrollbar_display_item.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"

namespace blink {

struct SameSizeAsDisplayItem {
  uintptr_t pointer_as_id;
  gfx::Rect rect;
  uint32_t i1;
  uint32_t i2;
};
ASSERT_SIZE(DisplayItem, SameSizeAsDisplayItem);

void DisplayItem::Destruct() {
  if (IsTombstone())
    return;
  if (auto* drawing = DynamicTo<DrawingDisplayItem>(this)) {
    drawing->~DrawingDisplayItem();
  } else if (auto* foreign_layer = DynamicTo<ForeignLayerDisplayItem>(this)) {
    foreign_layer->~ForeignLayerDisplayItem();
  } else {
    To<ScrollbarDisplayItem>(this)->~ScrollbarDisplayItem();
  }
}

bool DisplayItem::EqualsForUnderInvalidation(const DisplayItem& other) const {
  DCHECK(RuntimeEnabledFeatures::PaintUnderInvalidationCheckingEnabled());
  SECURITY_CHECK(!IsTombstone());
  if (client_id_ != other.client_id_ || type_ != other.type_ ||
      fragment_ != other.fragment_ ||
      raster_effect_outset_ != other.raster_effect_outset_ ||
      draws_content_ != other.draws_content_)
    return false;

  if (visual_rect_ != other.visual_rect_ &&
      // Change of empty visual rect doesn't matter.
      (visual_rect_.IsEmpty() && other.visual_rect_.IsEmpty()) &&
      // Visual rect of a DrawingDisplayItem not drawing content doesn't matter.
      (!IsDrawing() || draws_content_))
    return false;

  if (auto* drawing = DynamicTo<DrawingDisplayItem>(this)) {
    return drawing->EqualsForUnderInvalidationImpl(
        To<DrawingDisplayItem>(other));
  }
  if (auto* foreign_layer = DynamicTo<ForeignLayerDisplayItem>(this)) {
    return foreign_layer->EqualsForUnderInvalidationImpl(
        To<ForeignLayerDisplayItem>(other));
  }
  return To<ScrollbarDisplayItem>(this)->EqualsForUnderInvalidationImpl(
      To<ScrollbarDisplayItem>(other));
}

#if DCHECK_IS_ON()

static WTF::String PaintPhaseAsDebugString(int paint_phase) {
  // Must be kept in sync with PaintPhase.
  switch (paint_phase) {
    case 0:
      return "PaintPhaseBlockBackground";
    case 1:
      return "PaintPhaseSelfBlockBackgroundOnly";
    case 2:
      return "PaintPhaseDescendantBlockBackgroundsOnly";
    case 3:
      return "PaintPhaseForcedColorsModeBackplate";
    case 4:
      return "PaintPhaseFloat";
    case 5:
      return "PaintPhaseForeground";
    case 6:
      return "PaintPhaseOutline";
    case 7:
      return "PaintPhaseSelfOutlineOnly";
    case 8:
      return "PaintPhaseDescendantOutlinesOnly";
    case 9:
      return "PaintPhaseOverlayOverflowControls";
    case 10:
      return "PaintPhaseSelection";
    case 11:
      return "PaintPhaseTextClip";
    case DisplayItem::kPaintPhaseMax:
      return "PaintPhaseMask";
    default:
      NOTREACHED();
  }
}

#define PAINT_PHASE_BASED_DEBUG_STRINGS(Category)          \
  if (type >= DisplayItem::k##Category##PaintPhaseFirst && \
      type <= DisplayItem::k##Category##PaintPhaseLast)    \
    return #Category + PaintPhaseAsDebugString(            \
                           type - DisplayItem::k##Category##PaintPhaseFirst);

#define DEBUG_STRING_CASE(DisplayItemName) \
  case DisplayItem::k##DisplayItemName:    \
    return #DisplayItemName

#define DEFAULT_CASE \
  default:           \
    NOTREACHED();

static WTF::String SpecialDrawingTypeAsDebugString(DisplayItem::Type type) {
  switch (type) {
    DEBUG_STRING_CASE(BoxDecorationBackground);
    DEBUG_STRING_CASE(FixedAttachmentBackground);
    DEBUG_STRING_CASE(Caret);
    DEBUG_STRING_CASE(CapsLockIndicator);
    DEBUG_STRING_CASE(ColumnRules);
    DEBUG_STRING_CASE(DocumentRootBackdrop);
    DEBUG_STRING_CASE(DocumentBackground);
    DEBUG_STRING_CASE(DragCaret);
    DEBUG_STRING_CASE(ForcedColorsModeBackplate);
    DEBUG_STRING_CASE(SVGImage);
    DEBUG_STRING_CASE(ImageAreaFocusRing);
    DEBUG_STRING_CASE(OverflowControls);
    DEBUG_STRING_CASE(FrameOverlay);
    DEBUG_STRING_CASE(PrintedContentDestinationLocations);
    DEBUG_STRING_CASE(PrintedContentPDFURLRect);
    DEBUG_STRING_CASE(ReflectionMask);
    DEBUG_STRING_CASE(Resizer);
    DEBUG_STRING_CASE(SVGClip);
    DEBUG_STRING_CASE(SVGMask);
    DEBUG_STRING_CASE(ScrollbarThumb);
    DEBUG_STRING_CASE(ScrollbarTickmarks);
    DEBUG_STRING_CASE(ScrollbarTrackAndButtons);
    DEBUG_STRING_CASE(ScrollCorner);
    DEBUG_STRING_CASE(SelectionTint);
    DEBUG_STRING_CASE(TableCollapsedBorders);
    DEBUG_STRING_CASE(WebPlugin);

    DEFAULT_CASE;
  }
}

static WTF::String DrawingTypeAsDebugString(DisplayItem::Type type) {
  PAINT_PHASE_BASED_DEBUG_STRINGS(Drawing);
  return "Drawing" + SpecialDrawingTypeAsDebugString(type);
}

static String ForeignLayerTypeAsDebugString(DisplayItem::Type type) {
  switch (type) {
    DEBUG_STRING_CASE(ForeignLayerCanvas);
    DEBUG_STRING_CASE(ForeignLayerDevToolsOverlay);
    DEBUG_STRING_CASE(ForeignLayerPlugin);
    DEBUG_STRING_CASE(ForeignLayerVideo);
    DEBUG_STRING_CASE(ForeignLayerRemoteFrame);
    DEBUG_STRING_CASE(ForeignLayerLinkHighlight);
    DEBUG_STRING_CASE(ForeignLayerViewportScroll);
    DEBUG_STRING_CASE(ForeignLayerViewportScrollbar);
    DEBUG_STRING_CASE(ForeignLayerViewTransitionContent);
    DEFAULT_CASE;
  }
}

WTF::String DisplayItem::TypeAsDebugString(Type type) {
  if (IsDrawingType(type))
    return DrawingTypeAsDebugString(type);

  if (IsForeignLayerType(type))
    return ForeignLayerTypeAsDebugString(type);

  PAINT_PHASE_BASED_DEBUG_STRINGS(Clip);
  PAINT_PHASE_BASED_DEBUG_STRINGS(Scroll);
  PAINT_PHASE_BASED_DEBUG_STRINGS(SVGTransform);
  PAINT_PHASE_BASED_DEBUG_STRINGS(SVGEffect);

  switch (type) {
    DEBUG_STRING_CASE(HitTest);
    DEBUG_STRING_CASE(WebPluginHitTest);
    DEBUG_STRING_CASE(RegionCapture);
    DEBUG_STRING_CASE(ScrollHitTest);
    DEBUG_STRING_CASE(ResizerScrollHitTest);
    DEBUG_STRING_CASE(ScrollbarHitTest);
    DEBUG_STRING_CASE(LayerChunk);
    DEBUG_STRING_CASE(LayerChunkForeground);
    DEBUG_STRING_CASE(ScrollbarHorizontal);
    DEBUG_STRING_CASE(ScrollbarVertical);
    DEBUG_STRING_CASE(UninitializedType);
    DEFAULT_CASE;
  }
}

String DisplayItem::AsDebugString(const PaintArtifact& paint_artifact) const {
  auto json = std::make_unique<JSONObject>();
  PropertiesAsJSON(*json, paint_artifact);
  return json->ToPrettyJSONString();
}

String DisplayItem::IdAsString(const PaintArtifact& paint_artifact) const {
  if (IsSubsequenceTombstone())
    return "SUBSEQUENCE TOMBSTONE";
  if (IsTombstone())
    return "TOMBSTONE " + paint_artifact.IdAsString(GetId());
  return paint_artifact.IdAsString(GetId());
}

void DisplayItem::PropertiesAsJSON(JSONObject& json,
                                   const PaintArtifact& paint_artifact) const {
  json.SetString("id", IdAsString(paint_artifact));
  if (IsSubsequenceTombstone()) {
    return;
  }
  json.SetString("invalidation",
                 PaintInvalidationReasonToString(GetPaintInvalidationReason()));
  json.SetString("visualRect", String(VisualRect().ToString()));
  if (GetRasterEffectOutset() != RasterEffectOutset::kNone) {
    json.SetDouble(
        "outset",
        GetRasterEffectOutset() == RasterEffectOutset::kHalfPixel ? 0.5 : 1);
  }

  if (IsTombstone())
    return;
  if (auto* drawing = DynamicTo<DrawingDisplayItem>(this)) {
    drawing->PropertiesAsJSONImpl(json);
  } else if (auto* foreign_layer = DynamicTo<ForeignLayerDisplayItem>(this)) {
    foreign_layer->PropertiesAsJSONImpl(json);
  } else {
    To<ScrollbarDisplayItem>(this)->PropertiesAsJSONImpl(json);
  }
}

#endif  // DCHECK_IS_ON()

String DisplayItem::Id::ToString() const {
#if DCHECK_IS_ON()
  return String::Format("%p:%s:%d", reinterpret_cast<void*>(client_id),
                        DisplayItem::TypeAsDebugString(type).Utf8().data(),
                        fragment);
#else
  return String::Format("%p:%d:%d", reinterpret_cast<void*>(client_id),
                        static_cast<int>(type), fragment);
#endif
}

String DisplayItem::Id::ToString(const PaintArtifact& paint_artifact) const {
  return paint_artifact.IdAsString(*this);
}

std::ostream& operator<<(std::ostream& os, DisplayItem::Type type) {
#if DCHECK_IS_ON()
  return os << DisplayItem::TypeAsDebugString(type).Utf8();
#else
  return os << static_cast<int>(type);
#endif
}

std::ostream& operator<<(std::ostream& os, const DisplayItem::Id& id) {
  return os << id.ToString().Utf8();
}

std::ostream& operator<<(std::ostream& os, const DisplayItem& item) {
  return os << "{\"id\": " << item.GetId() << "}";
}

}  // namespace blink
```