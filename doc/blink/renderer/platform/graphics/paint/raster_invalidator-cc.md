Response:
My thinking process to analyze the `RasterInvalidator.cc` file went through these stages:

1. **Understand the Core Purpose:** The name "RasterInvalidator" strongly suggests its primary function is to manage and track when parts of the rendered output (raster) need to be redrawn or invalidated. The context within the Blink rendering engine further reinforces this.

2. **Identify Key Data Structures:** I scanned the class members to understand the data it holds. The presence of `old_paint_artifact_`, `current_paint_artifact_`, and `old_paint_chunks_info_` immediately suggests a comparison between previous and current rendering states. `layer_state_`, `layer_offset_`, and `layer_bounds_` point to the context of the invalidation – a specific layer. `tracking_` hinted at debugging or tracking capabilities.

3. **Analyze Key Methods:**  I focused on the public and prominent methods to decipher the workflow:
    * `SetTracksRasterInvalidations`:  Clearly controls whether invalidations are tracked.
    * `GenerateRasterInvalidations`:  This is the core logic. The method signature takes `new_chunks` as input and likely compares them to the old ones.
    * `AddRasterInvalidation`:  This is the action – marking a region for invalidation.
    * `IncrementallyInvalidateChunk`: A more targeted invalidation approach.
    * `Generate`: The main entry point, orchestrating the invalidation process.
    * Methods like `MatchNewChunkToOldChunk`, `ChunkPropertiesChanged` suggest the comparison logic.

4. **Infer Relationships to Rendering Concepts:** I connected the data and methods to core rendering concepts:
    * **Paint Artifacts/Chunks:**  These represent the recorded painting operations. Invalidating them means re-executing those operations.
    * **Layers:**  Rasterization happens on layers. The `RasterInvalidator` operates within the context of a layer.
    * **Display Items:**  The individual drawing commands within a chunk.
    * **Property Trees:**  CSS properties that affect rendering. Changes in these properties can trigger invalidation.
    * **Transforms, Clips, Effects:**  These are specific properties that often lead to raster invalidation.

5. **Map to Web Technologies (HTML, CSS, JavaScript):**  I considered how changes in these technologies would trigger the `RasterInvalidator`:
    * **HTML Structure Changes:**  Adding, removing, or reordering elements can change the paint order and the structure of paint chunks.
    * **CSS Property Changes:** Modifying styles (e.g., `color`, `background-color`, `transform`, `opacity`) directly affects how elements are painted. This is a major trigger for invalidation.
    * **JavaScript Animations/Interactions:**  Dynamic changes driven by JavaScript (e.g., using `requestAnimationFrame`, event handlers) often lead to CSS property changes or structural modifications, thus triggering raster invalidation.
    * **Scrolling:** The visual changes during scrolling need to be tracked and invalidated.

6. **Consider Edge Cases and Optimizations:** The code mentions "caching" and "incremental invalidation."  This suggests an effort to optimize rendering by avoiding full redraws whenever possible. The tolerances for transform changes indicate a strategy to avoid unnecessary invalidations for minor changes.

7. **Identify Potential Usage Errors:** I thought about common mistakes developers might make that could relate to raster invalidation:
    * **Forcing Layout/Reflow:**  While not directly related to *using* the `RasterInvalidator`, triggering excessive layout can lead to more invalidations.
    * **Direct DOM Manipulation:**  Inefficient DOM manipulation can cause more extensive repaints.
    * **Complex CSS Transitions/Animations:** While visually appealing, they can lead to frequent raster invalidations if not handled carefully.

8. **Construct Examples and Hypothetical Scenarios:**  To solidify my understanding, I created concrete examples of how changes in HTML, CSS, and JavaScript could trigger different types of invalidation (full, incremental, appearance, disappearance). I also imagined input and output scenarios for the `GenerateRasterInvalidations` method.

9. **Structure the Explanation:**  Finally, I organized my findings into a clear and logical format, covering the core functionalities, relationships to web technologies, examples, logical inferences, and potential usage errors. I aimed for a comprehensive yet easy-to-understand explanation.

Essentially, my process involved a combination of code analysis, understanding of rendering principles, and connecting the implementation details to the broader context of web development. The goal was to go beyond just describing what the code *does* and explain *why* it does it and how it fits into the larger picture.
文件 `raster_invalidator.cc` 的主要功能是**跟踪和生成渲染无效化 (raster invalidations)**。当页面内容或样式发生变化时，浏览器需要重新绘制受影响的部分。`RasterInvalidator` 负责识别这些需要重新绘制的区域，并记录下来，以便后续的渲染流程可以高效地进行。

更具体地说，它的功能包括：

1. **比较新旧渲染状态 (Paint Artifacts):**  它维护了前一个渲染帧的 `PaintArtifact` (`old_paint_artifact_`) 和当前渲染帧的 `PaintArtifact` (`current_paint_artifact_`)。 `PaintArtifact` 包含了渲染所需的绘制指令和信息。通过比较这两个 `PaintArtifact`，它可以找出发生变化的部分。

2. **管理 Paint Chunks:**  `PaintArtifact` 被分割成多个 `PaintChunk`，每个 `PaintChunk` 代表页面的一部分内容及其绘制信息。 `RasterInvalidator` 跟踪这些 `PaintChunk` 的变化，例如出现、消失、属性变化、顺序变化等。

3. **确定无效化原因 (PaintInvalidationReason):**  它会判断触发无效化的具体原因，例如：
    * `kChunkAppeared`: 新增了 `PaintChunk`。
    * `kChunkDisappeared`: 移除了 `PaintChunk`。
    * `kPaintProperty`:  `PaintChunk` 的绘制属性（例如 transform, clip, effect）发生了变化。
    * `kIncremental`: `PaintChunk` 的边界发生了变化，但内容和属性没有根本性改变，可以进行增量重绘。
    * `kScrollControl`: 滚动条需要更新。
    * `kFullLayer`: 整个图层需要重绘。
    * `kChunkUncacheable`: `PaintChunk` 由于某些原因无法被缓存。

4. **生成无效化区域:**  根据 `PaintChunk` 的变化及其边界，它会计算出需要在屏幕上重新绘制的矩形区域 (gfx::Rect)。

5. **跟踪无效化信息 (RasterInvalidationTracking):**  它可以选择性地跟踪生成的无效化信息，用于调试和性能分析。这包括记录哪些客户端 ID 触发了哪些区域的无效化以及无效化的原因。

6. **处理图层偏移和状态变化:** 它会考虑图层的偏移 (`layer_offset_`) 和状态 (`layer_state_`) 的变化，这些变化也会影响渲染的有效性。

**与 JavaScript, HTML, CSS 的功能关系及举例说明:**

`RasterInvalidator` 的工作是响应由 HTML 结构、CSS 样式以及 JavaScript 交互引起的变化。

* **HTML:**
    * **例子:**  当 JavaScript 通过 DOM API (`appendChild`, `removeChild`, `insertBefore`) 修改 HTML 结构时，会导致新增或删除 DOM 元素，进而可能导致新增或删除 `PaintChunk`。`RasterInvalidator` 会识别出这些变化，并将新出现的区域标记为需要重绘 (`kChunkAppeared`)，或将消失的区域标记为不再需要绘制 (`kChunkDisappeared`)。
    * **假设输入:**  JavaScript 执行 `document.getElementById('container').appendChild(newElement);`
    * **可能输出:**  `RasterInvalidator` 识别到 `newElement` 对应的 `PaintChunk` 是新出现的，生成一个包含该 `PaintChunk` 边界的无效化区域，并标记原因为 `kChunkAppeared`。

* **CSS:**
    * **例子:**  当 CSS 属性发生变化时，例如修改元素的 `background-color`、`width`、`height`、`transform`、`opacity` 等，都会影响元素的绘制。
        * 修改颜色或尺寸可能导致整个 `PaintChunk` 的重绘 (`kPaintProperty`)。
        * 修改 `transform` 可能导致 `PaintChunk` 的位置或形状发生变化，如果只是位置的微小变化，可能触发增量重绘 (`kIncremental`)。
    * **假设输入:**  JavaScript 执行 `document.getElementById('box').style.backgroundColor = 'red';`
    * **可能输出:**  `RasterInvalidator` 比较新旧 `PaintChunk` 的属性，发现背景色变化，生成一个包含该 `PaintChunk` 边界的无效化区域，并标记原因为 `kPaintProperty`。

* **JavaScript:**
    * **例子:**  JavaScript 可以通过动画 (如 CSS transitions/animations, `requestAnimationFrame`) 动态地修改元素的 CSS 属性，或者直接操作 Canvas 等进行绘制。这些动态变化都会触发 `RasterInvalidator` 的工作。
        * 一个 CSS `transition` 使得一个元素的 `transform` 属性随时间变化，`RasterInvalidator` 会在每一帧识别出 `transform` 的变化，并生成相应的无效化区域。
    * **假设输入:**  一个 CSS transition 使得一个元素的 `left` 属性从 10px 变化到 100px。
    * **可能输出:**  在 transition 的每一帧，`RasterInvalidator` 会比较元素 `PaintChunk` 的位置，并生成增量无效化区域 (`kIncremental`) 来反映元素位置的变化。

**逻辑推理的假设输入与输出:**

假设我们有以下简单的场景：

* **初始状态:** 一个 `div` 元素，背景色为蓝色，位于 (10, 10)，大小为 100x100。
* **变化:** JavaScript 将该 `div` 的背景色改为红色。

**假设输入 (在 `GenerateRasterInvalidations` 方法中):**

* `new_chunks`: 包含新的 `div` 的 `PaintChunk` 信息，背景色为红色。
* `old_chunks`: 包含旧的 `div` 的 `PaintChunk` 信息，背景色为蓝色。
* `layer_offset_or_state_changed`: false (假设图层的偏移和状态没有变化)。
* `layer_effect_changed`: false (假设图层的效果没有变化)。

**逻辑推理过程:**

1. `RasterInvalidator` 会比较新旧 `PaintChunk`。
2. 它会发现 `PaintChunk` 的属性（主要是背景色）发生了变化。
3. `ChunkPropertiesChanged` 方法会被调用，并返回 `PaintInvalidationReason::kPaintProperty`。
4. 由于是 `kPaintProperty`，`GenerateRasterInvalidations` 会调用 `AddRasterInvalidation`，传入旧 `PaintChunk` 的边界和新 `PaintChunk` 的边界（在这个简单例子中相同）。

**可能输出:**

* `AddRasterInvalidation` 被调用，参数可能如下：
    * `rect`: `gfx::Rect(10, 10, 100, 100)` (div 的边界)。
    * `client_id`:  与该 `div` 元素关联的客户端 ID。
    * `reason`: `PaintInvalidationReason::kPaintProperty`.
    * `old_or_new`: `kClientIsNew`.

**涉及用户或编程常见的使用错误及举例说明:**

虽然开发者不会直接使用 `RasterInvalidator` API，但一些常见的编程实践会影响它的效率，导致不必要的或过多的重绘：

1. **频繁地、小幅度地修改样式:**
   * **错误示例:** 使用 JavaScript 每隔很短的时间修改元素的 `left` 属性几个像素来实现动画效果。
   * **说明:**  这会导致 `RasterInvalidator` 频繁地生成小的无效化区域，虽然逻辑正确，但会消耗更多的资源。更推荐使用 CSS transitions/animations 或 `requestAnimationFrame` 来进行更高效的动画。

2. **在循环中强制同步布局 (Layout/Reflow):**
   * **错误示例:**
     ```javascript
     for (let i = 0; i < elements.length; i++) {
       elements[i].style.width = i * 10 + 'px';
       // 强制浏览器立即计算布局，可能触发多次重绘
       elements[i].offsetWidth;
     }
     ```
   * **说明:**  读取某些布局相关的属性（如 `offsetWidth`, `offsetHeight`）会强制浏览器立即进行布局计算，如果在循环中频繁进行，会导致多次不必要的布局和重绘，`RasterInvalidator` 会针对每次布局后的变化生成无效化。应该尽量批量修改样式，然后让浏览器在合适的时机进行布局。

3. **不必要地操作隐藏元素或不可见区域:**
   * **错误示例:**  修改一个 `display: none` 或 `visibility: hidden` 的元素的样式。
   * **说明:**  虽然这些修改在元素可见之前不会直接导致屏幕上的变化，但 `RasterInvalidator` 仍然可能会跟踪这些变化。虽然现代浏览器对此做了一些优化，但避免不必要的操作仍然是好的实践。

4. **过度使用复杂的 CSS 选择器:**
   * **说明:**  复杂的 CSS 选择器可能会降低样式计算的效率，虽然这不直接是 `RasterInvalidator` 的问题，但更慢的样式计算可能导致更频繁的重绘发生。

总结来说，`raster_invalidator.cc` 是 Blink 渲染引擎中负责跟踪和生成渲染无效化的核心组件。它通过比较新旧渲染状态，识别出需要重绘的区域和原因，从而指导后续的渲染流程。它的工作与 JavaScript, HTML, CSS 的动态变化紧密相关，任何影响页面视觉呈现的修改都会触发它的工作。理解它的功能有助于开发者编写更高效的 web 应用，避免不必要的重绘操作。

### 提示词
```
这是目录为blink/renderer/platform/graphics/paint/raster_invalidator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/paint/raster_invalidator.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "third_party/blink/renderer/platform/graphics/compositing/paint_chunks_to_cc_layer.h"
#include "third_party/blink/renderer/platform/graphics/paint/display_item_raster_invalidator.h"
#include "third_party/blink/renderer/platform/graphics/paint/geometry_mapper.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_artifact.h"
#include "ui/gfx/geometry/skia_conversions.h"

namespace blink {

void RasterInvalidator::Trace(Visitor* visitor) const {
  visitor->Trace(layer_state_);
  visitor->Trace(current_paint_artifact_);
  visitor->Trace(old_paint_artifact_);
  visitor->Trace(tracking_);
}

void RasterInvalidator::SetTracksRasterInvalidations(bool should_track) {
  if (should_track) {
    if (!tracking_) {
      tracking_ = MakeGarbageCollected<RasterInvalidationTracking>();
    }
    tracking_->ClearInvalidations();
  } else if (!RasterInvalidationTracking::ShouldAlwaysTrack()) {
    tracking_ = nullptr;
  } else if (tracking_) {
    tracking_->ClearInvalidations();
  }
}

const PaintChunk& RasterInvalidator::GetOldChunk(wtf_size_t index) const {
  DCHECK(old_paint_artifact_);
  const auto& old_chunk_info = old_paint_chunks_info_[index];
  const auto& old_chunk =
      old_paint_artifact_
          ->GetPaintChunks()[old_chunk_info.index_in_paint_artifact];
#if DCHECK_IS_ON()
  DCHECK_EQ(old_chunk.id, old_chunk_info.id);
#endif
  return old_chunk;
}

wtf_size_t RasterInvalidator::MatchNewChunkToOldChunk(
    const PaintChunk& new_chunk,
    wtf_size_t old_index) const {
  if (!new_chunk.CanMatchOldChunk())
    return kNotFound;

  for (wtf_size_t i = old_index; i < old_paint_chunks_info_.size(); i++) {
    if (new_chunk.Matches(GetOldChunk(i)))
      return i;
  }
  return kNotFound;
}

PaintInvalidationReason RasterInvalidator::ChunkPropertiesChanged(
    const PaintChunk& new_chunk,
    const PaintChunk& old_chunk,
    const PaintChunkInfo& new_chunk_info,
    const PaintChunkInfo& old_chunk_info,
    const PropertyTreeState& layer_state,
    const float absolute_translation_tolerance,
    const float other_transform_tolerance) const {
  if (new_chunk.effectively_invisible != old_chunk.effectively_invisible)
    return PaintInvalidationReason::kPaintProperty;

  // Special case for transform changes because we may create or delete some
  // transform nodes when no raster invalidation is needed. For example, when
  // a composited layer previously not transformed now gets transformed.
  // Check for real accumulated transform change instead.
  if (!new_chunk_info.chunk_to_layer_transform.ApproximatelyEqual(
          old_chunk_info.chunk_to_layer_transform,
          absolute_translation_tolerance, other_transform_tolerance,
          other_transform_tolerance)) {
    return PaintInvalidationReason::kPaintProperty;
  }

  // Treat the chunk property as changed if the effect node pointer is
  // different, or the effect node's value changed between the layer state and
  // the chunk state.
  const auto& new_chunk_state = new_chunk.properties;
  bool clip_node_is_different = false;
  bool effect_node_is_different = false;
  if (!new_chunk.is_moved_from_cached_subsequence) {
    clip_node_is_different =
        &new_chunk_state.Clip() != &old_chunk.properties.Clip();
    effect_node_is_different =
        &new_chunk_state.Effect() != &old_chunk.properties.Effect();
  }
  if (effect_node_is_different ||
      new_chunk_state.Effect().Changed(
          PaintPropertyChangeType::kChangedOnlySimpleValues, layer_state,
          &new_chunk_state.Transform())) {
    return PaintInvalidationReason::kPaintProperty;
  }

  // Check for accumulated clip rect change, if the clip rects are tight.
  if (new_chunk_info.chunk_to_layer_clip.IsTight() &&
      old_chunk_info.chunk_to_layer_clip.IsTight()) {
    gfx::RectF new_clip_rect = new_chunk_info.chunk_to_layer_clip.Rect();
    gfx::RectF old_clip_rect = old_chunk_info.chunk_to_layer_clip.Rect();
    if (new_clip_rect == old_clip_rect)
      return PaintInvalidationReason::kNone;
    // Ignore differences out of the current layer bounds.
    gfx::RectF new_clip_in_layer_bounds = ClipByLayerBounds(new_clip_rect);
    gfx::RectF old_clip_in_layer_bounds = ClipByLayerBounds(old_clip_rect);
    if (new_clip_in_layer_bounds == old_clip_in_layer_bounds)
      return PaintInvalidationReason::kNone;

    // Clip changed and may have visual effect, so we need raster invalidation.
    if (!new_clip_in_layer_bounds.Contains(
            gfx::RectF(new_chunk_info.bounds_in_layer)) ||
        !old_clip_in_layer_bounds.Contains(
            gfx::RectF(old_chunk_info.bounds_in_layer))) {
      // If the chunk is not fully covered by the clip rect, we have to do full
      // invalidation instead of incremental because the delta parts of the
      // layer bounds may not cover all changes caused by the clip change.
      // This can happen because of pixel snapping, raster effect outset, etc.
      return PaintInvalidationReason::kPaintProperty;
    }
    // Otherwise we just invalidate the delta parts of the layer bounds.
    return PaintInvalidationReason::kIncremental;
  }

  // Otherwise treat the chunk property as changed if the clip node pointer is
  // different, or the clip node's value changed between the layer state and the
  // chunk state.
  if (clip_node_is_different ||
      new_chunk_state.Clip().Changed(
          PaintPropertyChangeType::kChangedOnlySimpleValues, layer_state,
          &new_chunk_state.Transform()))
    return PaintInvalidationReason::kPaintProperty;

  return PaintInvalidationReason::kNone;
}

static bool ShouldSkipForRasterInvalidation(
    const PaintChunkIterator& chunk_it) {
  if (!chunk_it->DrawsContent())
    return true;

  // Foreign layers take care of raster invalidation by themselves.
  if (DisplayItem::IsForeignLayerType(chunk_it->id.type))
    return true;

  return false;
}

static bool ScrollbarNeedsUpdateDisplay(const PaintChunkIterator& chunk_it) {
  if (chunk_it->size() != 1) {
    return false;
  }
  if (auto* scrollbar =
          DynamicTo<ScrollbarDisplayItem>(*chunk_it.DisplayItems().begin())) {
    return scrollbar->NeedsUpdateDisplay();
  }
  return false;
}

// Generates raster invalidations by checking changes (appearing, disappearing,
// reordering, property changes) of chunks. The logic is similar to
// PaintController::GenerateRasterInvalidations(). The complexity is between
// O(n) and O(m*n) where m and n are the numbers of old and new chunks,
// respectively. Normally both m and n are small numbers. The best case is that
// all old chunks have matching new chunks in the same order. The worst case is
// that no matching chunks except the first one (which always matches otherwise
// we won't reuse the RasterInvalidator), which is rare. In
// common cases that most of the chunks can be matched in-order, the complexity
// is slightly larger than O(n).
void RasterInvalidator::GenerateRasterInvalidations(
    const PaintChunkSubset& new_chunks,
    bool layer_offset_or_state_changed,
    bool layer_effect_changed,
    Vector<PaintChunkInfo>& new_chunks_info) {
  ChunkToLayerMapper mapper(PropertyTreeState(layer_state_), layer_offset_);
  Vector<bool> old_chunks_matched;
  old_chunks_matched.resize(old_paint_chunks_info_.size());
  wtf_size_t old_index = 0;

  const float absolute_translation_tolerance = 1e-2f;
  const float other_transform_tolerance = 1e-4f;

  for (auto it = new_chunks.begin(); it != new_chunks.end(); ++it) {
    if (ShouldSkipForRasterInvalidation(it))
      continue;

    const auto& new_chunk = *it;
    auto matched_old_index = MatchNewChunkToOldChunk(new_chunk, old_index);
    if (matched_old_index == kNotFound) {
      // The new chunk doesn't match any old chunk.
      mapper.SwitchToChunk(new_chunk);
      auto& new_chunk_info = new_chunks_info.emplace_back(*this, mapper, it);
      AddRasterInvalidation(
          new_chunk_info.bounds_in_layer, new_chunk.id.client_id,
          new_chunk.is_cacheable ? PaintInvalidationReason::kChunkAppeared
                                 : PaintInvalidationReason::kChunkUncacheable,
          kClientIsNew);
      continue;
    }

    DCHECK(!old_chunks_matched[matched_old_index]);
    old_chunks_matched[matched_old_index] = true;

    auto& old_chunk_info = old_paint_chunks_info_[matched_old_index];
    const auto& old_chunk = GetOldChunk(matched_old_index);
    // Clip the old chunk bounds by the new layer bounds.
    old_chunk_info.bounds_in_layer =
        ClipByLayerBounds(old_chunk_info.bounds_in_layer);

    auto reason = PaintInvalidationReason::kNone;
    if (ScrollbarNeedsUpdateDisplay(it)) {
      reason = PaintInvalidationReason::kScrollControl;
    }

    // No need to invalidate if the chunk is moved from cached subsequence and
    // its paint properties didn't change relative to the layer.
    if (!layer_offset_or_state_changed &&
        reason == PaintInvalidationReason::kNone &&
        new_chunk.is_moved_from_cached_subsequence &&
        !new_chunk.properties.Changed(
            PaintPropertyChangeType::kChangedOnlySimpleValues,
            PropertyTreeState(layer_state_))) {
      new_chunks_info.emplace_back(old_chunk_info, it);
    } else {
      mapper.SwitchToChunk(new_chunk);
      auto& new_chunk_info = new_chunks_info.emplace_back(*this, mapper, it);

      if (reason == PaintInvalidationReason::kNone) {
        if (layer_effect_changed) {
          // Because of DecompositeEffect, the layer's effect may have changed
          // even if the chunk's didn't.
          reason = PaintInvalidationReason::kPaintProperty;
        } else {
          reason = ChunkPropertiesChanged(
              new_chunk, old_chunk, new_chunk_info, old_chunk_info,
              PropertyTreeState(layer_state_), absolute_translation_tolerance,
              other_transform_tolerance);
        }
      }

      if (IsFullPaintInvalidationReason(reason)) {
        // Invalidate both old and new bounds of the chunk if the chunk's paint
        // properties changed, or is moved backward and may expose area that was
        // previously covered by it.
        AddRasterInvalidation(old_chunk_info.bounds_in_layer,
                              new_chunk.id.client_id, reason, kClientIsNew);
        if (old_chunk_info.bounds_in_layer != new_chunk_info.bounds_in_layer) {
          AddRasterInvalidation(new_chunk_info.bounds_in_layer,
                                new_chunk.id.client_id, reason, kClientIsNew);
        }
        // Ignore the display item raster invalidations because we have fully
        // invalidated the chunk.
      } else {
        // We may have ignored tiny changes of transform, in which case we
        // should use the old chunk_to_layer_transform for later comparison to
        // correctly invalidate animating transform in tiny increments when the
        // accumulated change exceeds the tolerance.
        new_chunk_info.chunk_to_layer_transform =
            old_chunk_info.chunk_to_layer_transform;

        if (reason == PaintInvalidationReason::kIncremental) {
          IncrementallyInvalidateChunk(old_chunk_info, new_chunk_info,
                                       new_chunk.id.client_id);
        }

        if (&new_chunks.GetPaintArtifact() != old_paint_artifact_ &&
            !new_chunk.is_moved_from_cached_subsequence) {
          DisplayItemRasterInvalidator(
              *this,
              old_paint_artifact_->DisplayItemsInChunk(
                  old_chunk_info.index_in_paint_artifact),
              it.DisplayItems(), mapper)
              .Generate();
        }
      }
    }

    old_index = matched_old_index + 1;
  }

  // Invalidate remaining unmatched (disappeared or uncacheable) old chunks.
  for (wtf_size_t i = 0; i < old_paint_chunks_info_.size(); ++i) {
    if (old_chunks_matched[i])
      continue;

    const auto& old_chunk = GetOldChunk(i);
    auto reason = old_chunk.is_cacheable
                      ? PaintInvalidationReason::kChunkDisappeared
                      : PaintInvalidationReason::kChunkUncacheable;
    AddRasterInvalidation(old_paint_chunks_info_[i].bounds_in_layer,
                          old_chunk.id.client_id, reason, kClientIsOld);
  }
}

void RasterInvalidator::IncrementallyInvalidateChunk(
    const PaintChunkInfo& old_chunk_info,
    const PaintChunkInfo& new_chunk_info,
    DisplayItemClientId client_id) {
  SkRegion diff(gfx::RectToSkIRect(old_chunk_info.bounds_in_layer));
  diff.op(gfx::RectToSkIRect(new_chunk_info.bounds_in_layer),
          SkRegion::kXOR_Op);
  for (SkRegion::Iterator it(diff); !it.done(); it.next()) {
    AddRasterInvalidation(gfx::SkIRectToRect(it.rect()), client_id,
                          PaintInvalidationReason::kIncremental, kClientIsNew);
  }
}

void RasterInvalidator::TrackRasterInvalidation(const gfx::Rect& rect,
                                                DisplayItemClientId client_id,
                                                PaintInvalidationReason reason,
                                                ClientIsOldOrNew old_or_new) {
  DCHECK(tracking_);
  String debug_name = old_or_new == kClientIsOld
                          ? old_paint_artifact_->ClientDebugName(client_id)
                          : current_paint_artifact_->ClientDebugName(client_id);
  tracking_->AddInvalidation(client_id, debug_name, rect, reason);
}

RasterInvalidationTracking& RasterInvalidator::EnsureTracking() {
  if (!tracking_) {
    tracking_ = MakeGarbageCollected<RasterInvalidationTracking>();
  }
  return *tracking_;
}

void RasterInvalidator::Generate(
    const PaintChunkSubset& new_chunks,
    const gfx::Vector2dF& layer_offset,
    const gfx::Size& layer_bounds,
    const PropertyTreeState& layer_state) {
  if (RasterInvalidationTracking::ShouldAlwaysTrack())
    EnsureTracking();

  bool layer_offset_or_state_changed =
      layer_offset_ != layer_offset || layer_state_ != layer_state;
  bool layer_effect_changed = &layer_state_.Effect() != &layer_state.Effect();
  bool layer_bounds_was_empty = layer_bounds_.IsEmpty();
  layer_offset_ = layer_offset;
  layer_bounds_ = layer_bounds;
  layer_state_ = layer_state;
  current_paint_artifact_ = &new_chunks.GetPaintArtifact();

  Vector<PaintChunkInfo> new_chunks_info;
  new_chunks_info.reserve(new_chunks.size());

  if (layer_bounds_was_empty || layer_bounds_.IsEmpty()) {
    // Fast path if either the old bounds or the new bounds is empty. We still
    // need to update new_chunks_info for the next cycle.
    ChunkToLayerMapper mapper(layer_state, layer_offset);
    for (auto it = new_chunks.begin(); it != new_chunks.end(); ++it) {
      if (ShouldSkipForRasterInvalidation(it))
        continue;
      mapper.SwitchToChunk(*it);
      new_chunks_info.emplace_back(*this, mapper, it);
    }

    if (!layer_bounds.IsEmpty() && !new_chunks.IsEmpty()) {
      AddRasterInvalidation(gfx::Rect(layer_bounds),
                            new_chunks.begin()->id.client_id,
                            PaintInvalidationReason::kFullLayer, kClientIsNew);
    }
  } else {
    GenerateRasterInvalidations(new_chunks, layer_offset_or_state_changed,
                                layer_effect_changed, new_chunks_info);
  }

  old_paint_chunks_info_ = std::move(new_chunks_info);
  old_paint_artifact_ = &new_chunks.GetPaintArtifact();
  current_paint_artifact_ = nullptr;
}

void RasterInvalidator::SetOldPaintArtifact(
    const PaintArtifact& old_paint_artifact) {
  old_paint_artifact_ = &old_paint_artifact;
}

size_t RasterInvalidator::ApproximateUnsharedMemoryUsage() const {
  return sizeof(*this) +
         old_paint_chunks_info_.capacity() * sizeof(PaintChunkInfo);
}

void RasterInvalidator::ClearOldStates() {
  old_paint_artifact_ = nullptr;
  old_paint_chunks_info_.clear();
  layer_offset_ = gfx::Vector2dF();
  layer_bounds_ = gfx::Size();
}

}  // namespace blink
```