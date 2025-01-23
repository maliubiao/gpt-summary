Response:
The user wants a summary of the provided C++ code. I need to identify the main purpose of the `PendingLayer` class and its key functionalities. The code interacts with Chromium's compositing system, so understanding that relationship is important. I also need to look for connections to web technologies like JavaScript, HTML, and CSS and provide examples if they exist. The prompt also asks for examples of logical reasoning with inputs and outputs, and common usage errors. Finally, I need to summarize the overall functionality.

Here's a plan:

1. **Identify the core purpose of `PendingLayer`**: Based on the file path and code, it seems related to managing layers before they become actual composited layers.
2. **List key functionalities**: Analyze the methods and data members to understand what the class does (e.g., managing bounds, merging, updating properties).
3. **Find connections to web technologies**:  Look for concepts that map to HTML (structure), CSS (styling), and JavaScript (interaction/dynamic changes).
4. **Create logical reasoning examples**:  Think about how the methods would work with specific input data and what the expected output would be.
5. **Identify common usage errors**: Consider how a developer might misuse this class or related concepts.
6. **Summarize the functionality**:  Condense the findings into a concise overview.
```
功能列举:
```
1. **表示一个待处理的图层 (Pending Layer):**  `PendingLayer` 类表示一个在 Blink 渲染引擎中尚未完全创建和提交到合成器线程的图层。它存储了创建最终合成图层所需的信息。

2. **管理图层的几何属性:**
   - `bounds_`: 存储图层的边界矩形。
   - `rect_known_to_be_opaque_`: 存储图层中已知为不透明的矩形区域。
   - `LayerOffset()`: 计算图层在父图层中的偏移量，会根据是否是纯色图层进行不同的处理以优化性能。
   - `LayerBounds()`: 计算图层的边界尺寸，也会根据是否是纯色图层进行不同的处理。
   - `MapRectKnownToBeOpaque()`: 将已知不透明的矩形区域映射到新的属性树状态下。

3. **管理图层的内容信息:**
   - `chunks_`:  包含用于绘制图层内容的 `PaintChunk` 对象的集合。`PaintChunk` 描述了绘制操作和相关的属性。
   - `draws_content_`:  指示图层是否绘制内容。
   - `has_text_`: 指示图层是否包含文本。
   - `text_known_to_be_on_opaque_background_`: 指示图层中的文本是否已知绘制在不透明的背景上。
   - `solid_color_chunk_index_`: 如果图层是纯色图层，则存储对应的 `PaintChunk` 的索引。
   - `IsSolidColor()`: 判断图层是否是纯色图层。
   - `GetSolidColor()`: 获取纯色图层的颜色。

4. **管理图层的属性树状态:**
   - `property_tree_state_`: 存储图层相关的属性树状态，包括变换、裁剪、效果等信息。
   - `Upcast()`:  将图层的属性树状态更新到父节点的属性树状态。
   - `PropertyTreeStateChanged()`: 检查图层的属性树状态是否发生了变化。

5. **支持图层的合并和复用:**
   - `Matches()`: 判断当前待处理图层是否与旧的待处理图层匹配。
   - `CanMerge()`: 判断当前待处理图层是否可以与另一个待处理图层合并。
   - `Merge()`: 将当前待处理图层与另一个待处理图层合并。
   - `CanUpcastWith()`: 检查当前图层是否可以提升到与另一个图层相同的属性树状态。
   - `CanMergeWithDecompositedBlendMode()`: 检查是否可以与具有分解混合模式的图层合并。

6. **处理命中测试 (Hit Testing):**
   - `hit_test_opaqueness_`:  存储图层的命中测试不透明度。
   - `UpdateCcLayerHitTestOpaqueness()`: 更新合成器图层的命中测试不透明度。

7. **处理滚动相关的图层:**
   - `non_composited_scroll_translations_`: 存储非合成滚动转换的信息。
   - `ScrollTranslationForScrollHitTestLayer()`: 获取滚动命中测试图层的滚动转换节点。
   - `UpdateScrollHitTestLayer()`: 更新滚动命中测试图层的属性。
   - `UpdateScrollbarLayer()`: 更新滚动条图层的属性。

8. **处理外来图层 (Foreign Layer):**
   - `UpdateForeignLayer()`: 更新外来图层的属性。

9. **处理内容图层 (Content Layer) 和纯色图层 (Solid Color Layer):**
   - `UpdateContentLayer()`: 更新内容图层的属性。
   - `UpdateSolidColorLayer()`: 更新纯色图层的属性。
   - `UsesSolidColorLayer()`: 判断是否可以使用纯色图层进行优化。

10. **处理变换的分解 (Decompose Transforms):**
    - `offset_of_decomposited_transforms_`: 存储已分解的变换偏移量。
    - `change_of_decomposited_transforms_`: 存储已分解变换的更改类型。
    - `DecompositeTransforms()`:  尝试将某些变换操作转移到父图层，以优化性能。

11. **与其他合成器组件交互:**
    - `UpdateCompositedLayer()`:  根据图层的类型更新底层的 `cc::Layer` 对象。
    - `UpdateCompositedLayerForRepaint()`:  在重绘时更新合成器图层。
    - 与 `cc::Layer`, `cc::SolidColorLayer`, `cc::PictureLayer`, `cc::ScrollbarLayerBase` 等合成器线程的类进行交互。

12. **调试和序列化:**
    - `ToJSON()`: 将 `PendingLayer` 对象序列化为 JSON 格式，用于调试。
    - `DebugName()`: 获取图层的调试名称。
    - `OwnerNodeId()`: 获取拥有该图层的 DOM 节点的 ID。
    - `operator<<`:  重载输出运算符，方便打印 `PendingLayer` 对象的信息。

```
与 javascript, html, css 的功能关系举例:
```
1. **HTML 结构:** `PendingLayer` 最终对应于渲染后的 HTML 元素在合成器线程中的表示。例如，一个 `<div>` 元素可能会对应一个或多个 `PendingLayer`（例如，如果它有背景色、边框或需要合成的特性）。`OwnerNodeId()` 方法可以追溯到对应的 HTML 元素。

2. **CSS 样式:** CSS 样式决定了 `PendingLayer` 的各种属性：
   - **几何属性:** `bounds_` 反映了元素的位置和大小，这受到 CSS 的 `width`, `height`, `top`, `left`, `margin`, `padding` 等属性的影响。
   - **背景和颜色:** CSS 的 `background-color` 属性会影响 `solid_color_chunk_index_` 和 `GetSolidColor()`。如果元素设置了纯色背景，`PendingLayer` 可能会优化为使用 `cc::SolidColorLayer`。
   - **透明度和不透明度:** CSS 的 `opacity` 属性会影响 `hit_test_opaqueness_` 和 `rect_known_to_be_opaque_`。
   - **变换 (Transforms):** CSS 的 `transform` 属性会影响 `property_tree_state_` 中的变换信息，`DecompositeTransforms()` 方法会尝试优化这些变换。
   - **裁剪 (Clip):** CSS 的 `clip-path` 或 `overflow: hidden` 等属性会影响 `property_tree_state_` 中的裁剪信息。
   - **效果 (Effects):** CSS 的 `filter`，`backdrop-filter`，`mix-blend-mode` 等属性会影响 `property_tree_state_` 中的效果信息。具有需要合成的滤镜效果的元素会创建自己的合成层。
   - **滚动 (Scrolling):**  当 HTML 元素可以滚动时（例如，`overflow: auto` 或 `scroll`），会涉及到滚动条图层和滚动命中测试图层，`UpdateScrollbarLayer()` 和 `UpdateScrollHitTestLayer()` 就与此相关。

3. **JavaScript 交互:** JavaScript 可以动态地修改 HTML 结构和 CSS 样式，这些修改最终会反映到 `PendingLayer` 的更新上：
   - 当 JavaScript 修改元素的几何属性或样式时，渲染引擎会重新布局和重绘，并创建或更新相应的 `PendingLayer`。
   - JavaScript 可以通过 `element.style.transform` 等方式直接操作元素的变换，这会影响 `PendingLayer` 的变换属性。
   - JavaScript 动画和过渡效果也会导致 `PendingLayer` 属性的动态变化。

**举例说明:**

假设有以下 HTML 和 CSS:

```html
<div id="box" style="width: 100px; height: 100px; background-color: red; transform: translateX(50px);"></div>
```

- **HTML:**  `<div>` 元素会对应一个 `PendingLayer`。 `OwnerNodeId()` 可以获取到该 `<div>` 元素的 ID。
- **CSS:**
    - `width: 100px; height: 100px;` 会影响 `PendingLayer` 的 `bounds_` 属性。
    - `background-color: red;`  可能会导致 `PendingLayer` 的 `solid_color_chunk_index_` 被设置，并且 `GetSolidColor()` 返回红色。如果满足纯色图层的条件，可能会使用 `cc::SolidColorLayer`。
    - `transform: translateX(50px);` 会影响 `PendingLayer` 的 `property_tree_state_` 中的变换信息。`DecomposeTransforms()` 可能会尝试将这个平移变换分解到父图层。
- **JavaScript:**
    - 如果 JavaScript 执行 `document.getElementById('box').style.backgroundColor = 'blue';`，那么对应的 `PendingLayer` 在下次更新时，其 `GetSolidColor()` 的返回值会变为蓝色。
    - 如果 JavaScript 执行动画 `element.animate([{ transform: 'translateX(50px)' }, { transform: 'translateX(100px)' }], { duration: 1000 });`，那么在动画的每一帧，`PendingLayer` 的变换属性都会更新。

```
逻辑推理的假设输入与输出:
```
**场景:** 判断两个 `PendingLayer` 是否可以合并 (`CanMerge` 方法)。

**假设输入:**

- **`pending_layer1` (当前图层):**
    - `bounds_`: `{0, 0, 100, 100}`
    - `rect_known_to_be_opaque_`: `{0, 0, 100, 100}`
    - `text_known_to_be_on_opaque_background_`: `true`
    - `property_tree_state_`: (假设为一个没有特殊变换或效果的初始状态)
    - `draws_content_`: `true`
    - `is_solid_color`: `false`
    - `hit_test_opaqueness_`: `kOpaque`

- **`pending_layer2` (访客图层):**
    - `bounds_`: `{100, 0, 100, 100}`
    - `rect_known_to_be_opaque_`: `{100, 0, 100, 100}`
    - `text_known_to_be_on_opaque_background_`: `true`
    - `property_tree_state_`: (假设为一个没有特殊变换或效果的初始状态)
    - `draws_content_`: `true`
    - `is_solid_color`: `false`
    - `hit_test_opaqueness_`: `kOpaque`

- `lcd_text_preference`: `LCDTextPreference::kStronglyPreferred`
- `is_composited_scroll`: (假设返回 `false`)

**预期输出:**

- `merged_bounds`: `{0, 0, 200, 100}` (两个矩形的并集)
- `merged_state`: (与输入的状态相同，因为两个图层的属性树状态可以兼容)
- `merged_rect_known_to_be_opaque`: `{0, 0, 200, 100}` (两个不透明矩形的并集)
- `merged_text_known_to_be_on_opaque_background`: `true` (两个图层的文本都在不透明背景上)
- `merged_solid_color_chunk_index`: `kNotFound` (都不是纯色图层)
- `merged_hit_test_opaqueness`: `kOpaque` (合并后的区域也是不透明的)
- `CanMerge` 的返回值: `true`

**解释:** 在这个简单的例子中，两个相邻且都完全不透明的图层可以合并，合并后的区域覆盖了两个图层，并且仍然是不透明的。

**假设输入 (场景 2，无法合并):**

- **`pending_layer1`:**  (与上面相同)
- **`pending_layer2`:**
    - `bounds_`: `{200, 0, 10, 10}` (非常小的矩形，与第一个图层距离较远)
    - ... (其他属性保持不变)

**预期输出:**

- 由于合并后的稀疏度超过了 `kMergeSparsityAreaTolerance`，`CanMerge` 的返回值将为 `false`。其他的输出参数可能未定义或保持其初始状态。

```
涉及用户或者编程常见的使用错误举例:
```
1. **假设图层始终存在:** 开发者可能会在异步操作中假设 `PendingLayer` 对应的合成器图层已经创建并准备就绪，但实际上 `PendingLayer` 只是一个中间状态。直接访问或操作尚未提交的合成器图层可能会导致空指针或未定义的行为。

2. **不理解图层合并的条件:** 开发者可能会错误地期望两个在视觉上相邻的元素总是会被合并成一个合成层。但是，图层合并有严格的条件（例如，属性树状态的兼容性、稀疏度限制等）。如果这些条件不满足，即使视觉上相邻，也会创建独立的合成层，这可能会导致性能问题。

3. **过度依赖 `IsSolidColor()` 的判断:** 开发者可能会假设，只要设置了 `background-color`，对应的 `PendingLayer` 就一定是纯色图层。然而，一些复杂的背景效果（例如，渐变背景、背景图片）或特定的属性组合可能会阻止优化为纯色图层。

4. **在不合适的时机修改属性:**  `PendingLayer` 的属性通常由渲染引擎在特定的阶段管理。开发者不应该尝试直接修改 `PendingLayer` 的内部状态，这可能会导致数据不一致或崩溃。应该通过修改 DOM 结构或 CSS 样式来触发渲染引擎的更新。

5. **忽略命中测试不透明度的影响:**  开发者可能没有意识到 `hit_test_opaqueness_` 对事件处理的影响。如果一个图层被错误地标记为不透明，它可能会意外地阻止下层元素的事件响应。反之，如果本应不透明的区域被标记为透明，可能会导致事件穿透。

```
功能归纳:
```
`blink::PendingLayer` 类是 Chromium Blink 渲染引擎中用于表示和管理待处理合成图层的核心组件。它存储了创建最终合成器图层所需的各种信息，包括几何属性、内容信息和属性树状态。`PendingLayer` 负责处理图层的创建、更新、合并和优化，并与合成器线程的 `cc::Layer` 等类进行交互。它的主要功能是为高效的图层合成做准备，确保渲染性能和用户体验。它在渲染流水线中扮演着至关重要的角色，连接了布局、绘制和合成阶段。

### 提示词
```
这是目录为blink/renderer/platform/graphics/compositing/pending_layer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/compositing/pending_layer.h"

#include "base/containers/adapters.h"
#include "cc/layers/scrollbar_layer_base.h"
#include "cc/layers/solid_color_layer.h"
#include "third_party/blink/renderer/platform/geometry/geometry_as_json.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_chunks_to_cc_layer.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_display_item.h"
#include "third_party/blink/renderer/platform/graphics/paint/foreign_layer_display_item.h"
#include "third_party/blink/renderer/platform/graphics/paint/geometry_mapper.h"
#include "third_party/blink/renderer/platform/graphics/paint/scroll_paint_property_node.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_hash_map.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_hash_set.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "ui/gfx/color_utils.h"
#include "ui/gfx/geometry/rect_conversions.h"
#include "ui/gfx/geometry/size_conversions.h"
#include "ui/gfx/geometry/vector2d_conversions.h"

namespace blink {

namespace {

// Snap |bounds| if within floating-point numeric limits of an integral rect.
void PreserveNearIntegralBounds(gfx::RectF& bounds) {
  constexpr float kTolerance = 1e-3f;
  if (std::abs(std::round(bounds.x()) - bounds.x()) <= kTolerance &&
      std::abs(std::round(bounds.y()) - bounds.y()) <= kTolerance &&
      std::abs(std::round(bounds.right()) - bounds.right()) <= kTolerance &&
      std::abs(std::round(bounds.bottom()) - bounds.bottom()) <= kTolerance) {
    bounds = gfx::RectF(gfx::ToRoundedRect(bounds));
  }
}

}  // anonymous namespace

PendingLayer::PendingLayer(const PaintArtifact& artifact,
                           const PaintChunk& first_chunk,
                           CompositingType compositing_type)
    : bounds_(first_chunk.bounds),
      rect_known_to_be_opaque_(first_chunk.rect_known_to_be_opaque),
      has_text_(first_chunk.has_text),
      draws_content_(first_chunk.DrawsContent()),
      text_known_to_be_on_opaque_background_(
          first_chunk.text_known_to_be_on_opaque_background),
      solid_color_chunk_index_(
          first_chunk.background_color.is_solid_color ? 0 : kNotFound),
      chunks_(artifact, first_chunk),
      property_tree_state_(first_chunk.properties.Unalias()),
      compositing_type_(compositing_type),
      hit_test_opaqueness_(first_chunk.hit_test_opaqueness) {
  DCHECK(!ChunkRequiresOwnLayer() || first_chunk.size() <= 1u);
  // Though text_known_to_be_on_opaque_background is only meaningful when
  // has_text is true, we expect text_known_to_be_on_opaque_background to be
  // true when !has_text to simplify code.
  DCHECK(has_text_ || text_known_to_be_on_opaque_background_);
  if (const std::optional<gfx::RectF>& visibility_limit =
          GeometryMapper::VisibilityLimit(GetPropertyTreeState())) {
    bounds_.Intersect(*visibility_limit);
    if (bounds_.IsEmpty()) {
      draws_content_ = false;
    }
  }
  rect_known_to_be_opaque_.Intersect(bounds_);
  if (compositing_type == kOther && first_chunk.hit_test_data &&
      first_chunk.hit_test_data->scroll_translation) {
    non_composited_scroll_translations_.push_back(
        first_chunk.hit_test_data->scroll_translation.Get());
  }
}

void PendingLayer::Trace(Visitor* visitor) const {
  visitor->Trace(chunks_);
  visitor->Trace(property_tree_state_);
  visitor->Trace(non_composited_scroll_translations_);
  visitor->Trace(content_layer_client_);
}

gfx::Vector2dF PendingLayer::LayerOffset() const {
  // The solid color layer optimization is important for performance. Snapping
  // the location could make the solid color drawings not cover the entire
  // cc::Layer which would make the layer non-solid-color.
  if (IsSolidColor()) {
    return bounds_.OffsetFromOrigin();
  }
  // Otherwise return integral offset to reduce chance of additional blurriness.
  // TODO(crbug.com/1414915): This expansion may harm performance because
  // opaque layers becomes non-opaque. We can avoid this when we support
  // subpixel raster translation for render surfaces. We have already supported
  // that for cc::PictureLayerImpls.
  return gfx::Vector2dF(gfx::ToFlooredVector2d(bounds_.OffsetFromOrigin()));
}

gfx::Size PendingLayer::LayerBounds() const {
  // Because solid color layers do not adjust their location (see:
  // |PendingLayer::LayerOffset()|), we only expand their size here.
  if (IsSolidColor()) {
    return gfx::ToCeiledSize(bounds_.size());
  }
  return gfx::ToEnclosingRect(bounds_).size();
}

gfx::RectF PendingLayer::MapRectKnownToBeOpaque(
    const PropertyTreeState& new_state,
    const FloatClipRect& mapped_layer_bounds) const {
  if (!mapped_layer_bounds.IsTight()) {
    return gfx::RectF();
  }
  if (rect_known_to_be_opaque_.IsEmpty()) {
    return gfx::RectF();
  }
  if (rect_known_to_be_opaque_ == bounds_) {
    return mapped_layer_bounds.Rect();
  }
  FloatClipRect float_clip_rect(rect_known_to_be_opaque_);
  GeometryMapper::LocalToAncestorVisualRect(GetPropertyTreeState(), new_state,
                                            float_clip_rect);
  float_clip_rect.Rect().Intersect(mapped_layer_bounds.Rect());
  DCHECK(float_clip_rect.IsTight());
  return float_clip_rect.Rect();
}

std::unique_ptr<JSONObject> PendingLayer::ToJSON() const {
  std::unique_ptr<JSONObject> result = std::make_unique<JSONObject>();
  result->SetString("debug_name", DebugName());
  result->SetArray("bounds", RectAsJSONArray(bounds_));
  result->SetArray("rect_known_to_be_opaque",
                   RectAsJSONArray(rect_known_to_be_opaque_));
  result->SetBoolean("text_known_to_be_on_opaque_background",
                     text_known_to_be_on_opaque_background_);
  result->SetString("property_tree_state", GetPropertyTreeState().ToString());
  result->SetArray("offset_of_decomposited_transforms",
                   VectorAsJSONArray(offset_of_decomposited_transforms_));
  result->SetArray("paint_chunks", chunks_.ToJSON());
  result->SetBoolean("draws_content", DrawsContent());
  result->SetBoolean("is_solid_color", IsSolidColor());
  result->SetString("hit_test_opaqueness",
                    cc::HitTestOpaquenessToString(hit_test_opaqueness_));
  return result;
}

String PendingLayer::DebugName() const {
  return Chunks().GetPaintArtifact().ClientDebugName(
      FirstPaintChunk().id.client_id);
}

DOMNodeId PendingLayer::OwnerNodeId() const {
  return Chunks().GetPaintArtifact().ClientOwnerNodeId(
      FirstPaintChunk().id.client_id);
}

std::ostream& operator<<(std::ostream& os, const PendingLayer& layer) {
  return os << layer.ToJSON()->ToPrettyJSONString().Utf8();
}

void PendingLayer::Upcast(const PropertyTreeState& new_state) {
  DCHECK(!ChunkRequiresOwnLayer());
  DCHECK_EQ(&new_state.Effect(),
            property_tree_state_.Effect().UnaliasedParent());

  if (property_tree_state_.Effect().BlendMode() != SkBlendMode::kSrcOver)
    has_decomposited_blend_mode_ = true;

  FloatClipRect float_clip_rect(bounds_);
  GeometryMapper::LocalToAncestorVisualRect(GetPropertyTreeState(), new_state,
                                            float_clip_rect);
  // The order of the following two statements is important because
  // MapRectKnownToBeOpaque() needs to know the original bounds_.
  rect_known_to_be_opaque_ = MapRectKnownToBeOpaque(new_state, float_clip_rect);
  bounds_ = float_clip_rect.Rect();

  property_tree_state_ = new_state;
  solid_color_chunk_index_ = kNotFound;
}

const PaintChunk& PendingLayer::FirstPaintChunk() const {
  return chunks_[0];
}

const DisplayItem& PendingLayer::FirstDisplayItem() const {
  return *chunks_.begin().DisplayItems().begin();
}

bool PendingLayer::Matches(const PendingLayer& old_pending_layer) const {
  if (ChunkRequiresOwnLayer() != old_pending_layer.ChunkRequiresOwnLayer())
    return false;
  if (ChunkRequiresOwnLayer() &&
      compositing_type_ != old_pending_layer.compositing_type_)
    return false;
  return FirstPaintChunk().Matches(old_pending_layer.FirstPaintChunk());
}

// We will only allow merging if
// merged_area - (home_area + guest_area) <= kMergeSparsityAreaTolerance
static constexpr float kMergeSparsityAreaTolerance = 10000;

bool PendingLayer::CanMerge(
    const PendingLayer& guest,
    LCDTextPreference lcd_text_preference,
    IsCompositedScrollFunction is_composited_scroll,
    gfx::RectF& merged_bounds,
    PropertyTreeState& merged_state,
    gfx::RectF& merged_rect_known_to_be_opaque,
    bool& merged_text_known_to_be_on_opaque_background,
    wtf_size_t& merged_solid_color_chunk_index,
    cc::HitTestOpaqueness& merged_hit_test_opaqueness) const {
  std::optional<PropertyTreeState> optional_merged_state =
      CanUpcastWith(guest, guest.GetPropertyTreeState(), is_composited_scroll);
  if (!optional_merged_state) {
    return false;
  }

  merged_state = *optional_merged_state;
  const std::optional<gfx::RectF>& merged_visibility_limit =
      GeometryMapper::VisibilityLimit(merged_state);
  merged_solid_color_chunk_index = kNotFound;

  // If the current bounds and known-to-be-opaque area already cover the entire
  // visible area of the merged state, and the current state is already equal
  // to the merged state, we can merge the guest immediately without needing to
  // update any bounds at all. This simple merge fast-path avoids the cost of
  // mapping the visual rects, below.
  if (!guest.has_decomposited_blend_mode_ && merged_visibility_limit &&
      *merged_visibility_limit == bounds_ &&
      merged_state == property_tree_state_ &&
      rect_known_to_be_opaque_ == bounds_) {
    merged_bounds = merged_rect_known_to_be_opaque = bounds_;
    merged_text_known_to_be_on_opaque_background = true;
    if (!guest.draws_content_) {
      merged_solid_color_chunk_index = solid_color_chunk_index_;
    }
    merged_hit_test_opaqueness = cc::UnionHitTestOpaqueness(
        gfx::ToRoundedRect(bounds_), hit_test_opaqueness_,
        gfx::ToRoundedRect(guest.bounds_), guest.hit_test_opaqueness_);
    return true;
  }

  FloatClipRect new_home_bounds(bounds_);
  GeometryMapper::LocalToAncestorVisualRect(GetPropertyTreeState(),
                                            merged_state, new_home_bounds);
  if (merged_visibility_limit) {
    new_home_bounds.Rect().Intersect(*merged_visibility_limit);
  }
  FloatClipRect new_guest_bounds(guest.bounds_);
  GeometryMapper::LocalToAncestorVisualRect(guest.GetPropertyTreeState(),
                                            merged_state, new_guest_bounds);
  if (merged_visibility_limit) {
    new_guest_bounds.Rect().Intersect(*merged_visibility_limit);
  }

  merged_bounds =
      gfx::UnionRects(new_home_bounds.Rect(), new_guest_bounds.Rect());

  // If guest.has_decomposited_blend_mode_ is true, this function must merge
  // unconditionally and return because the decomposited blend mode requires
  // the merge. See PaintArtifactCompositor::DecompositeEffect().
  // Also in the case, the conditions returning false below are unlikely to
  // apply because
  // - the src and dest layers are unlikely to be far away (sparse),
  // - the blend mode may make the merged layer not opaque,
  // - LCD text will be disabled with exotic blend mode.
  if (!guest.has_decomposited_blend_mode_) {
    float sum_area = new_home_bounds.Rect().size().GetArea() +
                     new_guest_bounds.Rect().size().GetArea();
    if (merged_bounds.size().GetArea() - sum_area >
        kMergeSparsityAreaTolerance) {
      return false;
    }

    gfx::RectF home_rect_known_to_be_opaque =
        MapRectKnownToBeOpaque(merged_state, new_home_bounds);
    gfx::RectF guest_rect_known_to_be_opaque =
        guest.MapRectKnownToBeOpaque(merged_state, new_guest_bounds);
    merged_rect_known_to_be_opaque = gfx::MaximumCoveredRect(
        home_rect_known_to_be_opaque, guest_rect_known_to_be_opaque);
    merged_text_known_to_be_on_opaque_background =
        text_known_to_be_on_opaque_background_;
    if (text_known_to_be_on_opaque_background_ !=
        guest.text_known_to_be_on_opaque_background_) {
      if (!text_known_to_be_on_opaque_background_) {
        if (merged_rect_known_to_be_opaque.Contains(new_home_bounds.Rect())) {
          merged_text_known_to_be_on_opaque_background = true;
        }
      } else if (!guest.text_known_to_be_on_opaque_background_) {
        if (!merged_rect_known_to_be_opaque.Contains(new_guest_bounds.Rect())) {
          merged_text_known_to_be_on_opaque_background = false;
        }
      }
    }
    if (lcd_text_preference == LCDTextPreference::kStronglyPreferred &&
        !merged_text_known_to_be_on_opaque_background) {
      if (has_text_ && text_known_to_be_on_opaque_background_) {
        return false;
      }
      if (guest.has_text_ && guest.text_known_to_be_on_opaque_background_) {
        return false;
      }
    }
    if (IsSolidColor() && new_home_bounds.IsTight() && !guest.draws_content_ &&
        new_home_bounds.Rect() == merged_bounds) {
      // Home's solid color fills the merged layer, and is the only drawing.
      merged_solid_color_chunk_index = solid_color_chunk_index_;
    } else if (guest.IsSolidColor() && new_guest_bounds.IsTight() &&
               new_guest_bounds.Rect() == merged_bounds &&
               (!draws_content_ || guest.GetSolidColor().isOpaque())) {
      // Guest's solid color fills the merged layer, and is the only drawing or
      // obscures all home's drawing.
      merged_solid_color_chunk_index =
          chunks_.size() + guest.solid_color_chunk_index_;
    }
  }

  cc::HitTestOpaqueness home_hit_test_opaqueness = hit_test_opaqueness_;
  if (home_hit_test_opaqueness == cc::HitTestOpaqueness::kOpaque &&
      !new_home_bounds.IsTight()) {
    home_hit_test_opaqueness = cc::HitTestOpaqueness::kMixed;
  }
  cc::HitTestOpaqueness guest_hit_test_opaqueness = guest.hit_test_opaqueness_;
  if (guest_hit_test_opaqueness == cc::HitTestOpaqueness::kOpaque &&
      !new_guest_bounds.IsTight()) {
    guest_hit_test_opaqueness = cc::HitTestOpaqueness::kMixed;
  }
  merged_hit_test_opaqueness = cc::UnionHitTestOpaqueness(
      gfx::ToRoundedRect(new_home_bounds.Rect()), home_hit_test_opaqueness,
      gfx::ToRoundedRect(new_guest_bounds.Rect()), guest_hit_test_opaqueness);

  // GeometryMapper::LocalToAncestorVisualRect can introduce floating-point
  // error to the bounds. Integral bounds are important for reducing
  // blurriness (see: PendingLayer::LayerOffset) so preserve that here.
  PreserveNearIntegralBounds(merged_bounds);
  PreserveNearIntegralBounds(merged_rect_known_to_be_opaque);
  return true;
}

bool PendingLayer::Merge(const PendingLayer& guest,
                         LCDTextPreference lcd_text_preference,
                         IsCompositedScrollFunction is_composited_scroll) {
  gfx::RectF merged_bounds;
  PropertyTreeState merged_state(PropertyTreeState::kUninitialized);
  gfx::RectF merged_rect_known_to_be_opaque;
  bool merged_text_known_to_be_on_opaque_background = false;
  wtf_size_t merged_solid_color_chunk_index = kNotFound;
  cc::HitTestOpaqueness merged_hit_test_opaqueness =
      cc::HitTestOpaqueness::kMixed;

  if (!CanMerge(guest, lcd_text_preference, is_composited_scroll, merged_bounds,
                merged_state, merged_rect_known_to_be_opaque,
                merged_text_known_to_be_on_opaque_background,
                merged_solid_color_chunk_index, merged_hit_test_opaqueness)) {
    return false;
  }

  chunks_.Merge(guest.Chunks());
  bounds_ = merged_bounds;
  if (property_tree_state_ != merged_state) {
    property_tree_state_ = merged_state;
  }
  draws_content_ |= guest.draws_content_;
  rect_known_to_be_opaque_ = merged_rect_known_to_be_opaque;
  text_known_to_be_on_opaque_background_ =
      merged_text_known_to_be_on_opaque_background;
  has_text_ |= guest.has_text_;
  solid_color_chunk_index_ = merged_solid_color_chunk_index;
  change_of_decomposited_transforms_ = std::max(
      ChangeOfDecompositedTransforms(), guest.ChangeOfDecompositedTransforms());
  hit_test_opaqueness_ = merged_hit_test_opaqueness;
  non_composited_scroll_translations_.AppendVector(
      guest.non_composited_scroll_translations_);
  return true;
}

std::optional<PropertyTreeState> PendingLayer::CanUpcastWith(
    const PendingLayer& guest,
    const PropertyTreeState& guest_state,
    IsCompositedScrollFunction is_composited_scroll) const {
  DCHECK_EQ(&Chunks().GetPaintArtifact(), &guest.Chunks().GetPaintArtifact());
  if (ChunkRequiresOwnLayer() || guest.ChunkRequiresOwnLayer()) {
    return std::nullopt;
  }
  if (&GetPropertyTreeState().Effect() != &guest_state.Effect()) {
    return std::nullopt;
  }
  std::optional<PropertyTreeState> result =
      GetPropertyTreeState().CanUpcastWith(guest_state, is_composited_scroll);
  if (!result || !RuntimeEnabledFeatures::HitTestOpaquenessEnabled()) {
    return result;
  }

  // In HitTestOpaqueness, additionally check scroll translations to ensure
  // they will be covered by the MainThreadScrollHitTestRegion of the merged
  // layer if either of the scroll translations is not composited.
  const auto& home_scroll_translation =
      property_tree_state_.Transform().NearestScrollTranslationNode();
  const auto& guest_scroll_translation =
      guest.property_tree_state_.Transform().NearestScrollTranslationNode();
  if (&home_scroll_translation == &guest_scroll_translation) {
    return result;
  }
  const auto& lca_scroll_translation =
      result->Transform().NearestScrollTranslationNode();
  if ((&guest_scroll_translation == &lca_scroll_translation ||
       non_composited_scroll_translations_.Contains(
           &guest_scroll_translation)) &&
      (&home_scroll_translation == &lca_scroll_translation ||
       guest.non_composited_scroll_translations_.Contains(
           &home_scroll_translation))) {
    return result;
  }
  return std::nullopt;
}

bool PendingLayer::CanMergeWithDecompositedBlendMode(
    const PendingLayer& guest,
    const PropertyTreeState& upcast_state,
    IsCompositedScrollFunction is_composited_scroll) const {
  return CanUpcastWith(guest, upcast_state, is_composited_scroll).has_value();
}

const TransformPaintPropertyNode&
PendingLayer::ScrollTranslationForScrollHitTestLayer() const {
  DCHECK_EQ(GetCompositingType(), kScrollHitTestLayer);
  DCHECK_EQ(1u, Chunks().size());
  const auto& paint_chunk = FirstPaintChunk();
  DCHECK(paint_chunk.hit_test_data);
  DCHECK(paint_chunk.hit_test_data->scroll_translation);
  DCHECK(paint_chunk.hit_test_data->scroll_translation->ScrollNode());
  return *paint_chunk.hit_test_data->scroll_translation;
}

bool PendingLayer::PropertyTreeStateChanged(
    const PendingLayer* old_pending_layer) const {
  if (!old_pending_layer ||
      old_pending_layer->property_tree_state_ != property_tree_state_)
    return true;

  auto change = PaintPropertyChangeType::kChangedOnlyNonRerasterValues;
  if (change_of_decomposited_transforms_ >= change)
    return true;

  return GetPropertyTreeState().ChangedToRoot(change);
}

bool PendingLayer::MightOverlap(const PendingLayer& other) const {
  return GeometryMapper::MightOverlapForCompositing(
      bounds_, GetPropertyTreeState(), other.bounds_,
      other.GetPropertyTreeState());
}

// Walk the pending layer list and build up a table of transform nodes that
// can be de-composited (replaced with offset_to_transform_parent). A
// transform node can be de-composited if:
//  1. It is not the root transform node.
//  2. It is a 2d translation only.
//  3. The transform is not used for scrolling - its ScrollNode() is nullptr.
//  4. The transform is not a StickyTranslation node.
//  5. It has no direct compositing reasons, other than k3DTransform. Note
//     that if it has a k3DTransform reason, check #2 above ensures that it
//     isn't really 3D.
//  6. It has FlattensInheritedTransform matching that of its direct parent.
//  7. It has backface visibility matching its direct parent.
//  8. No clips have local_transform_space referring to this transform node.
//  9. No effects have local_transform_space referring to this transform node.
//  10. All child transform nodes are also able to be de-composited.
// This algorithm should be O(t+c+e) where t,c,e are the number of transform,
// clip, and effect nodes in the full tree.
void PendingLayer::DecompositeTransforms(PendingLayers& pending_layers) {
  HeapHashMap<Member<const TransformPaintPropertyNode>, bool>
      can_be_decomposited;
  HeapHashSet<Member<const PaintPropertyNode>> clips_and_effects_seen;
  for (const PendingLayer& pending_layer : pending_layers) {
    const auto& property_state = pending_layer.GetPropertyTreeState();

    // Lambda to handle marking a transform node false, and walking up all
    // true parents and marking them false as well. This also handles
    // inserting transform_node if it isn't in the map, and keeps track of
    // clips or effects.
    auto mark_not_decompositable =
        [&can_be_decomposited](
            const TransformPaintPropertyNode& transform_node) {
          for (const auto* node = &transform_node; node && !node->IsRoot();
               node = node->UnaliasedParent()) {
            auto result = can_be_decomposited.insert(node, false);
            if (!result.is_new_entry) {
              if (!result.stored_value->value)
                break;
              result.stored_value->value = false;
            }
          }
        };

    // Add the transform and all transform parents to the map.
    for (const auto* node = &property_state.Transform();
         !node->IsRoot() && !can_be_decomposited.Contains(node);
         node = &node->Parent()->Unalias()) {
      if (!node->IsIdentityOr2dTranslation() || node->ScrollNode() ||
          node->HasDirectCompositingReasonsOtherThan3dTransform() ||
          !node->FlattensInheritedTransformSameAsParent() ||
          !node->BackfaceVisibilitySameAsParent()) {
        mark_not_decompositable(*node);
        break;
      }
      DCHECK(!node->GetStickyConstraint());
      DCHECK(!node->GetAnchorPositionScrollData());
      DCHECK(!node->IsAffectedByOuterViewportBoundsDelta());
      can_be_decomposited.insert(node, true);
    }

    // Add clips and effects, and their parents, that we haven't already seen.
    for (const auto* node = &property_state.Clip();
         !node->IsRoot() && !clips_and_effects_seen.Contains(node);
         node = &node->Parent()->Unalias()) {
      clips_and_effects_seen.insert(node);
      mark_not_decompositable(node->LocalTransformSpace().Unalias());
    }
    for (const auto* node = &property_state.Effect();
         !node->IsRoot() && !clips_and_effects_seen.Contains(node);
         node = &node->Parent()->Unalias()) {
      clips_and_effects_seen.insert(node);
      mark_not_decompositable(node->LocalTransformSpace().Unalias());
    }

    if (pending_layer.GetCompositingType() == kScrollHitTestLayer) {
      // The scroll translation node of a scroll hit test layer may not be
      // referenced by any pending layer's property tree state. Disallow
      // decomposition of it (and its ancestors).
      mark_not_decompositable(
          pending_layer.ScrollTranslationForScrollHitTestLayer());
    }
  }

  // Now, for any transform nodes that can be de-composited, re-map their
  // transform to point to the correct parent, and set the
  // offset_to_transform_parent.
  for (PendingLayer& pending_layer : pending_layers) {
    const auto* transform = &pending_layer.GetPropertyTreeState().Transform();
    while (!transform->IsRoot() && can_be_decomposited.at(transform)) {
      pending_layer.offset_of_decomposited_transforms_ +=
          transform->Get2dTranslation();
      pending_layer.change_of_decomposited_transforms_ =
          std::max(pending_layer.ChangeOfDecompositedTransforms(),
                   transform->NodeChanged());
      transform = &transform->Parent()->Unalias();
    }
    pending_layer.property_tree_state_.SetTransform(*transform);
    pending_layer.bounds_.Offset(
        pending_layer.OffsetOfDecompositedTransforms());
    pending_layer.rect_known_to_be_opaque_.Offset(
        pending_layer.OffsetOfDecompositedTransforms());
  }
}

void PendingLayer::UpdateForeignLayer() {
  DCHECK_EQ(compositing_type_, PendingLayer::kForeignLayer);

  // UpdateTouchActionRects() depends on the layer's offset, but when the
  // layer's offset changes, we do not call SetNeedsUpdate() (this is an
  // optimization because the update would only cause an extra commit) This is
  // only OK if the ForeignLayer doesn't have hit test data.
  DCHECK(!FirstPaintChunk().hit_test_data);
  const auto& foreign_layer_display_item =
      To<ForeignLayerDisplayItem>(FirstDisplayItem());

  gfx::Vector2dF layer_offset(
      foreign_layer_display_item.VisualRect().OffsetFromOrigin());
  cc_layer_ = foreign_layer_display_item.GetLayer();
  cc_layer_->SetOffsetToTransformParent(layer_offset +
                                        offset_of_decomposited_transforms_);
}

void PendingLayer::UpdateScrollHitTestLayer(PendingLayer* old_pending_layer) {
  DCHECK_EQ(compositing_type_, kScrollHitTestLayer);

  // We shouldn't decomposite scroll transform nodes.
  DCHECK_EQ(gfx::Vector2dF(), offset_of_decomposited_transforms_);

  const auto& scroll_node =
      *ScrollTranslationForScrollHitTestLayer().ScrollNode();

  DCHECK(!cc_layer_);
  if (old_pending_layer)
    cc_layer_ = std::move(old_pending_layer->cc_layer_);

  if (cc_layer_) {
    DCHECK_EQ(cc_layer_->element_id(), scroll_node.GetCompositorElementId());
  } else {
    cc_layer_ = cc::Layer::Create();
    cc_layer_->SetElementId(scroll_node.GetCompositorElementId());
  }

  UpdateCcLayerHitTestOpaqueness();

  cc_layer_->SetOffsetToTransformParent(
      gfx::Vector2dF(scroll_node.ContainerRect().OffsetFromOrigin()));
  // TODO(pdr): The scroll layer's bounds are currently set to the clipped
  // container bounds but this does not include the border. We may want to
  // change this behavior to make non-composited and composited hit testing
  // match (see: crbug.com/753124). To do this, use
  // |scroll_hit_test->scroll_container_bounds|. Set the layer's bounds equal
  // to the container because the scroll layer does not scroll.
  cc_layer_->SetBounds(scroll_node.ContainerRect().size());

  if (scroll_node.NodeChanged() != PaintPropertyChangeType::kUnchanged) {
    cc_layer_->SetNeedsPushProperties();
    cc_layer_->SetNeedsCommit();
  }
}

void PendingLayer::UpdateScrollbarLayer(PendingLayer* old_pending_layer) {
  DCHECK_EQ(compositing_type_, kScrollbarLayer);

  const auto& item = FirstDisplayItem();
  DCHECK(item.IsScrollbar());

  const auto& scrollbar_item = To<ScrollbarDisplayItem>(item);
  scoped_refptr<cc::ScrollbarLayerBase> scrollbar_layer;
  if (old_pending_layer) {
    scrollbar_layer = static_cast<cc::ScrollbarLayerBase*>(
        std::move(old_pending_layer->cc_layer_).get());
  }

  scrollbar_layer = scrollbar_item.CreateOrReuseLayer(
      scrollbar_layer.get(), offset_of_decomposited_transforms_);
  DCHECK(!cc_layer_);
  cc_layer_ = std::move(scrollbar_layer);
}

void PendingLayer::UpdateContentLayer(PendingLayer* old_pending_layer,
                                      bool tracks_raster_invalidations) {
  DCHECK(!ChunkRequiresOwnLayer());
  DCHECK(!cc_layer_);
  DCHECK(!content_layer_client_);
  DCHECK(!UsesSolidColorLayer());
  if (old_pending_layer) {
    content_layer_client_ = std::move(old_pending_layer->content_layer_client_);
  }
  if (!content_layer_client_) {
    content_layer_client_ = MakeGarbageCollected<ContentLayerClientImpl>();
    content_layer_client_->GetRasterInvalidator().SetTracksRasterInvalidations(
        tracks_raster_invalidations);
  }
  content_layer_client_->UpdateCcPictureLayer(*this);
}

void PendingLayer::UpdateSolidColorLayer(PendingLayer* old_pending_layer) {
  DCHECK(!ChunkRequiresOwnLayer());
  DCHECK(!cc_layer_);
  DCHECK(!content_layer_client_);
  DCHECK(UsesSolidColorLayer());
  if (old_pending_layer) {
    cc_layer_ = std::move(old_pending_layer->cc_layer_);
  }
  if (!cc_layer_) {
    cc_layer_ = cc::SolidColorLayer::Create();
  }
  cc_layer_->SetOffsetToTransformParent(LayerOffset());
  cc_layer_->SetBounds(LayerBounds());
  UpdateCcLayerHitTestOpaqueness();
  cc_layer_->SetBackgroundColor(GetSolidColor());
  cc_layer_->SetIsDrawable(draws_content_);
}

bool PendingLayer::UsesSolidColorLayer() const {
  if (!IsSolidColor()) {
    return false;
  }
  // We need a PictureLayer for the backdrop filter mask.
  if (property_tree_state_.Effect()
          .RequiresCompositingForBackdropFilterMask()) {
    return false;
  }
#if BUILDFLAG(IS_MAC)
  // TODO(crbug.com/922899): Additionally, on Mac, we require that the color is
  // opaque due to the bug. Remove this condition once that bug is fixed.
  if (GetSolidColor().fA != 1.0f) {
    return false;
  }
#endif  // BUILDFLAG(IS_MAC)
  return true;
}

SkColor4f PendingLayer::GetSolidColor() const {
  CHECK_NE(solid_color_chunk_index_, kNotFound);
  DCHECK(chunks_[solid_color_chunk_index_].background_color.is_solid_color);
  return chunks_[solid_color_chunk_index_].background_color.color;
}

void PendingLayer::UpdateCompositedLayer(PendingLayer* old_pending_layer,
                                         cc::LayerSelection& layer_selection,
                                         bool tracks_raster_invalidations,
                                         cc::LayerTreeHost* layer_tree_host) {
  // This is used during PaintArifactCompositor::CollectPendingLayers() only.
  non_composited_scroll_translations_.clear();

  switch (compositing_type_) {
    case PendingLayer::kForeignLayer:
      UpdateForeignLayer();
      break;
    case PendingLayer::kScrollHitTestLayer:
      UpdateScrollHitTestLayer(old_pending_layer);
      break;
    case PendingLayer::kScrollbarLayer:
      UpdateScrollbarLayer(old_pending_layer);
      break;
    default:
      DCHECK(!ChunkRequiresOwnLayer());
      if (UsesSolidColorLayer()) {
        UpdateSolidColorLayer(old_pending_layer);
      } else {
        UpdateContentLayer(old_pending_layer, tracks_raster_invalidations);
      }
      break;
  }

  cc::Layer& layer = CcLayer();
  layer.SetLayerTreeHost(layer_tree_host);

  UpdateLayerProperties(layer_selection, /*selection_only=*/false);

  if (!layer.subtree_property_changed() &&
      PropertyTreeStateChanged(old_pending_layer)) {
    layer.SetSubtreePropertyChanged();
  }
}

void PendingLayer::UpdateCcLayerHitTestOpaqueness() const {
  if (RuntimeEnabledFeatures::HitTestOpaquenessEnabled()) {
    CcLayer().SetHitTestOpaqueness(GetHitTestOpaqueness());
  } else {
    CcLayer().SetHitTestable(true);
  }
}

void PendingLayer::UpdateCompositedLayerForRepaint(
    const PaintArtifact& repainted_artifact,
    cc::LayerSelection& layer_selection) {
  // Essentially replace the paint chunks of the pending layer with the
  // repainted chunks in |repainted_artifact|. The pending layer's paint
  // chunks (a |PaintChunkSubset|) actually store indices to |PaintChunk|s
  // in a |PaintArtifact|. In repaint updates, chunks are not added,
  // removed, or re-ordered, so we can simply swap in a repainted
  // |PaintArtifact| instead of copying |PaintChunk|s individually.
  const PaintArtifact& old_artifact = Chunks().GetPaintArtifact();
  DCHECK_EQ(old_artifact.GetPaintChunks().size(),
            repainted_artifact.GetPaintChunks().size());
  SetPaintArtifact(repainted_artifact);

  bool chunks_unchanged = true;
  for (const auto& chunk : Chunks()) {
    if (!chunk.is_moved_from_cached_subsequence) {
      chunks_unchanged = false;
      break;
    }
  }

  if (!ChunkRequiresOwnLayer()) {
    if (UsesSolidColorLayer()) {
      DCHECK(cc_layer_);
      if (!chunks_unchanged) {
        cc_layer_->SetBackgroundColor(GetSolidColor());
      }
    } else {
      DCHECK(content_layer_client_);
      // Checking |chunks_unchanged| is an optimization to avoid the expensive
      // call to |UpdateCcPictureLayer| when no repainting occurs for this
      // PendingLayer.
      if (chunks_unchanged) {
        // See RasterInvalidator::SetOldPaintArtifact() for the reason for this.
        content_layer_client_->GetRasterInvalidator().SetOldPaintArtifact(
            Chunks().GetPaintArtifact());
      } else {
        content_layer_client_->UpdateCcPictureLayer(*this);
      }
    }
  }

  UpdateLayerPr
```