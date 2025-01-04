Response:
The user wants to understand the functionality of the provided C++ code snippet from the Chromium Blink engine. This is the second part of the file `paint_chunks_to_cc_layer.cc`.

To address the request, I will:

1. **Summarize the functions:**  Describe the purpose of each function and class within the provided code.
2. **Relate to web technologies:** Explain how the code interacts with JavaScript, HTML, and CSS, providing examples where applicable.
3. **Illustrate logic with examples:**  Demonstrate the code's behavior with hypothetical inputs and outputs.
4. **Highlight potential errors:** Point out common mistakes users or programmers might make in relation to the code's functionality.
5. **Provide a final summary:** Condense the overall purpose of this code snippet.
这是 `blink/renderer/platform/graphics/compositing/paint_chunks_to_cc_layer.cc` 文件的第二部分，主要负责将 `PaintChunk` 数据结构转换为 `cc::DisplayItemList` 或 `PaintRecord`，并更新相关的图层属性。

以下是其功能的详细列举和说明：

**核心功能：将 PaintChunks 转换为 Compositor 内容**

* **`ConversionContext` 类:**  这是一个模板类，负责在将 `PaintChunk` 转换为 `cc::DisplayItemList` 或 `PaintRecord` 的过程中维护状态。它跟踪当前的变换、裁剪、特效等属性，并负责生成相应的 compositor 操作。
    * **`StartTransform()`, `EndTransform()`:**  处理变换属性的开始和结束，生成 `cc::SaveOp`、`cc::RestoreOp` 和 `cc::TranslateOp`/`cc::ConcatOp`。
    * **`StartClip()`, `EndClip()`:** 处理裁剪属性的开始和结束，生成 `cc::PushPropertiesOp` 和 `cc::PopPropertiesOp`，包含 `cc::ClipNode::Id`。
    * **`StartEffect()`, `EndEffect()`:** 处理特效属性的开始和结束，生成 `cc::PushPropertiesOp` 和 `cc::PopPropertiesOp`，包含 `cc::EffectNode::Id`。
    * **`SwitchToTransform()`, `SwitchToClip()`, `SwitchToEffect()`:** 比较目标属性和当前属性，如果需要则开始新的属性，返回一个 `ScrollTranslationAction` 用于处理滚动。
    * **`EmitDrawScrollingContentsOp()`:**  当遇到需要单独 compositor 图层处理的滚动内容时，将该部分 `PaintChunk` 递归地转换为一个新的 `cc::DisplayItemList`，并生成 `cc::DrawScrollingContentsOp`。
    * **`ComputeScrollTranslationAction()`:**  判断是否需要开始或结束一个滚动转换，用于处理嵌套滚动容器。
    * **`HasDrawing()`:**  判断一个 `PaintChunk` 是否包含实际绘制内容，用于优化跳过空 `PaintChunk`。
    * **`Convert()`:**  遍历 `PaintChunk` 迭代器，根据 `PaintChunk` 的属性和包含的 `DisplayItem`，生成对应的 compositor 操作。它处理变换、裁剪、特效和滚动，并将绘制命令转换为 `cc::DrawRecordOp`。
* **`PaintChunksToCcLayer::ConvertInto()`:**  将 `PaintChunkSubset` 转换为 `cc::DisplayItemList`。它创建 `ConversionContext` 实例并调用 `Convert()` 方法。可以进行无效化检查。
* **`PaintChunksToCcLayer::Convert()`:** 将 `PaintChunkSubset` 转换为 `PaintRecord`。它创建一个基于 `PaintOpBufferExt` 的 `ConversionContext` 实例并调用 `Convert()` 方法。

**图层属性更新**

* **`LayerPropertiesUpdater` 类:**  负责根据 `PaintChunk` 中的信息更新 `cc::Layer` 的属性，例如触摸动作区域、滚动事件区域、主线程滚动命中测试区域、非复合滚动命中测试矩形和图层选择信息。
    * **`Update()`:**  遍历 `PaintChunk`，调用其他方法更新各种图层属性。
    * **`ShouldDisableCursorControl()`:**  判断是否需要禁用光标控制，与横向可滚动区域有关。
    * **`UpdateTouchActionRegion()`:**  根据 `HitTestData` 中的信息更新图层的触摸动作区域。
    * **`UpdateWheelEventRegion()`:** 根据 `HitTestData` 中的信息更新图层的滚轮事件区域。
    * **`UpdateScrollHitTestData()`:** 根据 `HitTestData` 中的信息更新图层的滚动命中测试信息，包括复合滚动和非复合滚动。
    * **`AddNonCompositedScroll()`:**  记录非复合滚动的信息。
    * **`TopNonCompositedScroll()`:** 找到顶级的非复合滚动节点。
    * **`UpdatePreviousNonCompositedScrolls()`:**  更新之前遇到的非复合滚动的信息，以处理重叠情况。
    * **`UpdateForNonCompositedScrollbar()`:**  处理非复合滚动条的命中测试区域。
    * **`UpdateRegionCaptureData()`:**  处理区域捕获数据。
    * **`MapSelectionBoundPoint()`, `PaintedSelectionBoundToLayerSelectionBound()`, `UpdateLayerSelection()`:** 处理图层选择相关信息。
* **`PaintChunksToCcLayer::UpdateLayerProperties()`:**  创建 `LayerPropertiesUpdater` 实例并调用 `Update()` 方法来更新 `cc::Layer` 的属性。

**与 JavaScript, HTML, CSS 的关系及举例**

* **CSS 盒模型和布局:** `PaintChunk` 的生成基于渲染树的布局信息，而渲染树是由 HTML 和 CSS 构建的。`ConversionContext` 中处理的变换、裁剪、特效等属性直接对应 CSS 的 `transform`、`clip-path`、`opacity`、`filter` 等属性。
    * **例子 (CSS Transform):**  如果一个 HTML 元素应用了 `transform: translate(10px, 20px); rotate(45deg);`，那么在遍历到与该元素相关的 `PaintChunk` 时，`StartTransform()` 会被调用，并可能生成一个包含平移和旋转的 `cc::ConcatOp`。
* **CSS 滚动:** 代码中大量涉及滚动处理，特别是 `EmitDrawScrollingContentsOp()` 和 `ComputeScrollTranslationAction()`。这与 CSS 的 `overflow: auto/scroll` 属性创建滚动容器密切相关。
    * **例子 (CSS Overflow):**  如果一个 `div` 元素设置了 `overflow: auto;` 并且内容超出边界，该 `div` 会创建一个滚动容器。当处理该 `div` 的 `PaintChunk` 时，`EmitDrawScrollingContentsOp()` 可能会被调用，将其滚动内容单独渲染到一个 compositor 图层上。
* **CSS 裁剪:**  CSS 的 `clip-path` 属性会影响 `ConversionContext` 中 `StartClip()` 和 `EndClip()` 的行为。
    * **例子 (CSS Clip-path):**  如果一个元素设置了 `clip-path: polygon(0 0, 100px 0, 100px 100px, 0 100px);`，`StartClip()` 会生成一个包含该多边形裁剪区域的 `cc::PushPropertiesOp`。
* **CSS 滤镜和特效:**  CSS 的 `filter` 属性（例如 `blur()`, `grayscale()`）会影响 `ConversionContext` 中 `StartEffect()` 和 `EndEffect()` 的行为。
    * **例子 (CSS Filter):**  如果一个图片设置了 `filter: blur(5px);`，`StartEffect()` 会生成一个包含模糊滤镜效果的 `cc::PushPropertiesOp`。
* **事件处理 (JavaScript):**  `LayerPropertiesUpdater` 中更新的触摸动作区域 (`touch_action_region_`) 和滚轮事件区域 (`wheel_event_region_`) 会影响浏览器如何将触摸和滚轮事件分发到不同的 compositor 图层，最终影响 JavaScript 事件处理的触发。
    * **例子 (Touch Action):**  如果一个区域设置了 `touch-action: pan-y;`，`UpdateTouchActionRegion()` 会将该信息记录到图层属性中，告知 compositor 只允许垂直方向的滑动。
* **选择 (Selection):** `LayerPropertiesUpdater` 中处理的图层选择信息 (`layer_selection_`) 对应用户在网页上选中文本或元素的操作，这通常通过鼠标或触摸手势触发，并与 JavaScript 的 Selection API 相关。

**逻辑推理的假设输入与输出**

假设有以下简化的 `PaintChunk`:

```
PaintChunk {
  drawable_bounds: Rect(0, 0, 100, 100),
  properties: PropertyTreeState {
    transform: TransformPaintPropertyNode { /* Identity */ },
    clip: ClipPaintPropertyNode { /* No Clip */ },
    effect: EffectPaintPropertyNode { /* No Effect */ }
  },
  display_items: [
    DrawingDisplayItem {
      visual_rect: Rect(10, 10, 80, 80),
      paint_record: PaintRecord { /* Contains drawing commands */ }
    }
  ]
}
```

当 `ConversionContext` 的 `Convert()` 方法处理这个 `PaintChunk` 时，假设 `result_` 是一个 `cc::DisplayItemList`：

* **输入:** 上述 `PaintChunk`。
* **输出:** `cc::DisplayItemList` 会包含以下操作：
    * `cc::StartPaintOp`
    * `cc::DrawRecordOp` (包含 `PaintRecord` 中的绘制命令)
    * `cc::EndPaintOfUnpairedOp` (带有 `visual_rect: Rect(10, 10, 80, 80)`)

再假设有另一个 `PaintChunk`，它在一个应用了 CSS `transform: translate(50px, 50px);` 的元素内：

```
PaintChunk {
  drawable_bounds: Rect(0, 0, 50, 50),
  properties: PropertyTreeState {
    transform: TransformPaintPropertyNode { /* Translation by 50, 50 */ },
    // ... 其他属性
  },
  // ...
}
```

* **输入:** 上述带有变换的 `PaintChunk`。
* **输出:** `cc::DisplayItemList` 会包含：
    * `cc::StartPaintOp`
    * `cc::SaveOp`
    * `cc::TranslateOp(50, 50)`
    * ... (该 `PaintChunk` 中 `DisplayItem` 对应的绘制操作)
    * `cc::RestoreOp`
    * `cc::EndPaintOfPairedEndOp`

**用户或编程常见的使用错误**

* **在没有调用 `StartTransform()` 的情况下调用 `EndTransform()`:** 这会导致程序错误，因为 `previous_transform_` 为空。代码中通过 `if (!previous_transform_) return;` 进行了保护。
* **错误地管理 `PaintChunk` 的生命周期:**  `PaintChunksToCcLayer` 接收的是 `PaintChunkSubset` 的引用，需要确保在转换过程中 `PaintChunk` 数据的有效性。
* **在更新图层属性时，提供的 `PropertyTreeState` 与实际渲染树状态不一致:** 这会导致图层属性更新不准确，例如触摸事件可能无法正确分发。
* **没有正确处理嵌套的滚动容器:** 复杂的滚动嵌套可能导致 `ComputeScrollTranslationAction()` 的逻辑变得复杂，需要仔细处理开始和结束滚动转换的时机。

**归纳其功能**

总而言之，`blink/renderer/platform/graphics/compositing/paint_chunks_to_cc_layer.cc` 的这部分代码的主要功能是：

1. **将中间表示 `PaintChunk` 转换为 compositor 可以理解的绘制指令 (`cc::DisplayItemList` 或 `PaintRecord`)。**
2. **根据 `PaintChunk` 中的信息更新 compositor 图层 (`cc::Layer`) 的属性，以便 compositor 正确处理用户交互和渲染优化。**

它充当了 Blink 渲染引擎中一个关键的转换桥梁，将渲染流水线中后期的绘制信息转化为最终在屏幕上呈现的内容。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/compositing/paint_chunks_to_cc_layer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
 gfx::Transform projection = TargetToCurrentProjection(target_transform);
  if (projection.IsIdentity()) {
    return {};
  }

  result_.StartPaint();
  push<cc::SaveOp>();
  if (projection.IsIdentityOr2dTranslation()) {
    gfx::Vector2dF translation = projection.To2dTranslation();
    push<cc::TranslateOp>(translation.x(), translation.y());
  } else {
    push<cc::ConcatOp>(gfx::TransformToSkM44(projection));
  }
  result_.EndPaintOfPairedBegin();
  previous_transform_ = current_transform_;
  current_transform_ = &target_transform;
  return {};
}

template <typename Result>
void ConversionContext<Result>::EndTransform() {
  if (!previous_transform_)
    return;

  result_.StartPaint();
  push<cc::RestoreOp>();
  result_.EndPaintOfPairedEnd();
  current_transform_ = previous_transform_;
  previous_transform_ = nullptr;
}

template <>
void ConversionContext<cc::DisplayItemList>::EmitDrawScrollingContentsOp(
    PaintChunkIterator& chunk_it,
    PaintChunkIterator end_chunk,
    const TransformPaintPropertyNode& scroll_translation) {
  CHECK(RuntimeEnabledFeatures::RasterInducingScrollEnabled());
  CHECK(scroll_translation.ScrollNode());
  DCHECK_EQ(previous_transform_, nullptr);

  // Switch to the parent of the scroll translation in the current context.
  auto action = SwitchToTransform(*scroll_translation.UnaliasedParent());
  // This should not need to switch to any other scroll translation.
  CHECK(!action);

  // The scrolling contents will be recorded into this DisplayItemList as if
  // the scrolling contents creates a layer.
  auto scrolling_contents_list = base::MakeRefCounted<cc::DisplayItemList>();
  ConversionContext<cc::DisplayItemList>(
      PropertyTreeState(scroll_translation, *current_clip_, *current_effect_),
      gfx::Vector2dF(), *scrolling_contents_list, &state_stack_)
      .Convert(chunk_it, end_chunk);

  EndTransform();
  scrolling_contents_list->Finalize();

  gfx::Rect visual_rect = chunk_to_layer_mapper_.MapVisualRectFromState(
      InfiniteIntRect(),
      PropertyTreeState(scroll_translation,
                        *scroll_translation.ScrollNode()->OverflowClipNode(),
                        // The effect state doesn't matter.
                        chunk_to_layer_mapper_.LayerState().Effect()));
  result_.PushDrawScrollingContentsOp(
      scroll_translation.ScrollNode()->GetCompositorElementId(),
      std::move(scrolling_contents_list), visual_rect);
}

template <>
ScrollTranslationAction
ConversionContext<cc::DisplayItemList>::ComputeScrollTranslationAction(
    const TransformPaintPropertyNode& target_transform) const {
  if (!RuntimeEnabledFeatures::RasterInducingScrollEnabled()) {
    return {};
  }

  const auto& target_scroll_translation =
      target_transform.NearestScrollTranslationNode();
  if (&target_scroll_translation == current_scroll_translation_) {
    return {};
  }

  const auto& chunk_scroll_translation = chunk_to_layer_mapper_.ChunkState()
                                             .Transform()
                                             .NearestScrollTranslationNode();
  // In most real-world cases, target_scroll_translation equals
  // chunk_scroll_translation. In less common cases, chunk_scroll_translation
  // is deeper than target_scroll_translation (e.g. when a chunk enters
  // multiple levels of scrolling states). In very rare case for a
  // non-composited fixed-attachment background, target_scroll_translation of
  // the background clip is deeper than chunk_scroll_translation, and we
  // should emit a transform operation for the clip to avoid infinite loop of
  // starting (by the transform of the clip) and ending (by the chunk
  // transform) empty DrawScrollingContentsOps.
  if (!target_scroll_translation.IsAncestorOf(chunk_scroll_translation)) {
    return {};
  }

  if (current_scroll_translation_ ==
      target_scroll_translation.ParentScrollTranslationNode()) {
    // We need to enter a new level of scroll translation. If a PaintChunk
    // enters multiple levels of scroll translations at once, this function
    // will be called for each level of overflow clip before it's called for
    // the scrolling contents, so we only need to check one level of scroll
    // translation here.
    return {ScrollTranslationAction::kStart, &target_scroll_translation};
  }

  DCHECK(target_scroll_translation.IsAncestorOf(*current_scroll_translation_));
  return {ScrollTranslationAction::kEnd};
}

template <typename Result>
bool ConversionContext<Result>::HasDrawing(
    PaintChunkIterator chunk_it,
    const PropertyTreeState& chunk_state) const {
  // If we have an empty paint chunk, then we would prefer ignoring it.
  // However, a reference filter can generate visible effect from invisible
  // source, and we need to emit paint operations for it.
  if (&chunk_state.Effect() != current_effect_) {
    return true;
  }
  DisplayItemRange items = chunk_it.DisplayItems();
  if (items.size() == 0) {
    return false;
  }
  if (items.size() > 1) {
    // Assume the chunk has drawing if it has more than one display items.
    return true;
  }
  if (auto* drawing = DynamicTo<DrawingDisplayItem>(*items.begin())) {
    if (drawing->GetPaintRecord().empty() &&
        // See can_ignore_record in Convert()'s inner loop.
        &chunk_state.Effect() == &EffectPaintPropertyNode::Root()) {
      return false;
    }
  }
  return true;
}

template <typename Result>
void ConversionContext<Result>::Convert(PaintChunkIterator& chunk_it,
                                        PaintChunkIterator end_chunk,
                                        const gfx::Rect* additional_cull_rect) {
  for (; chunk_it != end_chunk; ++chunk_it) {
    const auto& chunk = *chunk_it;
    if (chunk.effectively_invisible) {
      continue;
    }

    PropertyTreeState chunk_state = chunk.properties.Unalias();
    if (!HasDrawing(chunk_it, chunk_state)) {
      continue;
    }

    TranslateForLayerOffsetOnce();
    chunk_to_layer_mapper_.SwitchToChunkWithState(chunk, chunk_state);

    if (additional_cull_rect) {
      gfx::Rect chunk_visual_rect =
          chunk_to_layer_mapper_.MapVisualRect(chunk.drawable_bounds);
      if (additional_cull_rect &&
          !additional_cull_rect->Intersects(chunk_visual_rect)) {
        continue;
      }
    }

    ScrollTranslationAction action = SwitchToEffect(chunk_state.Effect());
    if (!action) {
      action = SwitchToClip(chunk_state.Clip());
    }
    if (!action) {
      action = SwitchToTransform(chunk_state.Transform());
    }
    if (action.type == ScrollTranslationAction::kStart) {
      CHECK(action.scroll_translation_to_start);
      EmitDrawScrollingContentsOp(chunk_it, end_chunk,
                                  *action.scroll_translation_to_start);
      // Now chunk_it points to the last chunk in the scrolling contents.
      // We need to continue with the chunk in the next loop in case switching
      // to the chunk state hasn't finished in EmitDrawScrollingContentsOp.
      // The following line neutralize the ++chunk_it in the `for` statement.
      --chunk_it;
      continue;
    }
    if (action.type == ScrollTranslationAction::kEnd) {
      if (outer_state_stack_) {
        // Return to the calling EmitDrawScrollingContentsOp().
        return;
      } else {
        // TODO(crbug.com/40558824): This can happen when we encounter a
        // clip hierarchy issue. We have to continue.
      }
    }

    for (const auto& item : chunk_it.DisplayItems()) {
      PaintRecord record;
      if (auto* scrollbar = DynamicTo<ScrollbarDisplayItem>(item)) {
        record = scrollbar->Paint();
      } else if (auto* drawing = DynamicTo<DrawingDisplayItem>(item)) {
        record = drawing->GetPaintRecord();
      } else {
        continue;
      }

      // If we have an empty paint record, then we would prefer ignoring it.
      // However, if we also have a non-root effect, the empty paint record
      // might be for a mask with empty content which should make the masked
      // content fully invisible. We need to "draw" this record to ensure that
      // the effect has correct visual rect.
      bool can_ignore_record =
          &chunk_state.Effect() == &EffectPaintPropertyNode::Root();
      if (record.empty() && can_ignore_record) {
        continue;
      }

      gfx::Rect visual_rect =
          chunk_to_layer_mapper_.MapVisualRect(item.VisualRect());
      if (additional_cull_rect && can_ignore_record &&
          !additional_cull_rect->Intersects(visual_rect)) {
        continue;
      }

      result_.StartPaint();
      if (!record.empty()) {
        push<cc::DrawRecordOp>(std::move(record));
      }
      result_.EndPaintOfUnpaired(visual_rect);
    }

    // Most effects apply to drawable contents only. Reference filters are
    // exceptions, for which we have already added the chunk bounds mapped
    // through the filter to the bounds of the effect in StartEffect().
    UpdateEffectBounds(gfx::RectF(chunk.drawable_bounds),
                       chunk_state.Transform());
  }
}

}  // unnamed namespace

void PaintChunksToCcLayer::ConvertInto(
    const PaintChunkSubset& chunks,
    const PropertyTreeState& layer_state,
    const gfx::Vector2dF& layer_offset,
    RasterUnderInvalidationCheckingParams* under_invalidation_checking_params,
    cc::DisplayItemList& cc_list) {
  ConversionContext(layer_state, layer_offset, cc_list).Convert(chunks);
  if (under_invalidation_checking_params) {
    auto& params = *under_invalidation_checking_params;
    PaintRecorder recorder;
    recorder.beginRecording();
    // Create a complete cloned list for under-invalidation checking. We can't
    // use cc_list because it is not finalized yet.
    PaintOpBufferExt buffer;
    ConversionContext(layer_state, layer_offset, buffer).Convert(chunks);
    recorder.getRecordingCanvas()->drawPicture(buffer.ReleaseAsRecord());
    params.tracking.CheckUnderInvalidations(params.debug_name,
                                            recorder.finishRecordingAsPicture(),
                                            params.interest_rect);
    auto under_invalidation_record = params.tracking.UnderInvalidationRecord();
    if (!under_invalidation_record.empty()) {
      cc_list.StartPaint();
      cc_list.push<cc::DrawRecordOp>(std::move(under_invalidation_record));
      cc_list.EndPaintOfUnpaired(params.interest_rect);
    }
  }
}

PaintRecord PaintChunksToCcLayer::Convert(const PaintChunkSubset& chunks,
                                          const PropertyTreeState& layer_state,
                                          const gfx::Rect* cull_rect) {
  PaintOpBufferExt buffer;
  ConversionContext(layer_state, gfx::Vector2dF(), buffer)
      .Convert(chunks, cull_rect);
  return buffer.ReleaseAsRecord();
}

namespace {

struct NonCompositedScroll {
  DISALLOW_NEW();

 public:
  Member<const TransformPaintPropertyNode> scroll_translation;
  // The hit-testable rect of the scroller in the layer space.
  gfx::Rect layer_hit_test_rect;
  // Accumulated hit test opaqueness of a) the scroller itself and b)
  // contents after the scroller intersecting layer_hit_test_rect.
  // If it's kMixed, scroll in some areas in the layer can't reliably scroll
  // `scroll_translation`.
  cc::HitTestOpaqueness hit_test_opaqueness;

  void Trace(Visitor* visitor) const { visitor->Trace(scroll_translation); }
};

class LayerPropertiesUpdater {
  STACK_ALLOCATED();

 public:
  LayerPropertiesUpdater(cc::Layer& layer,
                         const PropertyTreeState& layer_state,
                         const PaintChunkSubset& chunks,
                         cc::LayerSelection& layer_selection,
                         bool selection_only)
      : chunk_to_layer_mapper_(layer_state, layer.offset_to_transform_parent()),
        layer_(layer),
        chunks_(chunks),
        layer_selection_(layer_selection),
        selection_only_(selection_only),
        layer_scroll_translation_(
            layer_state.Transform().NearestScrollTranslationNode()) {}

  void Update();

 private:
  TouchAction ShouldDisableCursorControl();
  void UpdateTouchActionRegion(const HitTestData&);
  void UpdateWheelEventRegion(const HitTestData&);

  void UpdateScrollHitTestData(const PaintChunk&);
  void AddNonCompositedScroll(const PaintChunk&);
  const TransformPaintPropertyNode& TopNonCompositedScroll(
      const TransformPaintPropertyNode&) const;
  void UpdatePreviousNonCompositedScrolls(const PaintChunk&);

  void UpdateForNonCompositedScrollbar(const ScrollbarDisplayItem&);
  void UpdateRegionCaptureData(const RegionCaptureData&);
  gfx::Point MapSelectionBoundPoint(const gfx::Point&) const;
  cc::LayerSelectionBound PaintedSelectionBoundToLayerSelectionBound(
      const PaintedSelectionBound&) const;
  void UpdateLayerSelection(const LayerSelectionData&);

  ChunkToLayerMapper chunk_to_layer_mapper_;
  cc::Layer& layer_;
  const PaintChunkSubset& chunks_;
  cc::LayerSelection& layer_selection_;
  bool selection_only_;
  const TransformPaintPropertyNode& layer_scroll_translation_;

  cc::TouchActionRegion touch_action_region_;
  TouchAction last_disable_cursor_control_ = TouchAction::kNone;
  const ScrollPaintPropertyNode* last_disable_cursor_control_scroll_ = nullptr;

  cc::Region wheel_event_region_;
  cc::Region main_thread_scroll_hit_test_region_;
  viz::RegionCaptureBounds capture_bounds_;

  // Top-level (i.e., non-nested) non-composited scrolls. Nested non-composited
  // scrollers will force the containing top non-composited scroller to hit test
  // on the main thread, to avoid the complexity and cost of mapping the scroll
  // hit test rect of nested scroller to the layer space, especially when the
  // parent scroller scrolls. TODO(crbug.com/359279553): Investigate if we can
  // optimize this.
  HeapVector<NonCompositedScroll, 4> top_non_composited_scrolls_;
};

TouchAction LayerPropertiesUpdater::ShouldDisableCursorControl() {
  const auto* scroll_node = chunk_to_layer_mapper_.ChunkState()
                                .Transform()
                                .NearestScrollTranslationNode()
                                .ScrollNode();
  if (scroll_node == last_disable_cursor_control_scroll_) {
    return last_disable_cursor_control_;
  }

  last_disable_cursor_control_scroll_ = scroll_node;
  // If the element has an horizontal scrollable ancestor (including itself), we
  // need to disable cursor control by setting the bit kInternalPanXScrolls.
  last_disable_cursor_control_ = TouchAction::kNone;
  // TODO(input-dev): Consider to share the code with
  // ThreadedInputHandler::FindNodeToLatch.
  for (; scroll_node; scroll_node = scroll_node->Parent()) {
    if (scroll_node->UserScrollableHorizontal() &&
        scroll_node->ContainerRect().width() <
            scroll_node->ContentsRect().width()) {
      last_disable_cursor_control_ = TouchAction::kInternalPanXScrolls;
      break;
    }
    // If it is not kAuto, scroll can't propagate, so break here.
    if (scroll_node->OverscrollBehaviorX() !=
        cc::OverscrollBehavior::Type::kAuto) {
      break;
    }
  }
  return last_disable_cursor_control_;
}

void LayerPropertiesUpdater::UpdateTouchActionRegion(
    const HitTestData& hit_test_data) {
  if (hit_test_data.touch_action_rects.empty()) {
    return;
  }

  for (const auto& touch_action_rect : hit_test_data.touch_action_rects) {
    gfx::Rect rect =
        chunk_to_layer_mapper_.MapVisualRect(touch_action_rect.rect);
    if (rect.IsEmpty()) {
      continue;
    }
    TouchAction touch_action = touch_action_rect.allowed_touch_action;
    if ((touch_action & TouchAction::kPanX) != TouchAction::kNone) {
      touch_action |= ShouldDisableCursorControl();
    }
    touch_action_region_.Union(touch_action, rect);
  }
}

void LayerPropertiesUpdater::UpdateWheelEventRegion(
    const HitTestData& hit_test_data) {
  for (const auto& wheel_event_rect : hit_test_data.wheel_event_rects) {
    wheel_event_region_.Union(
        chunk_to_layer_mapper_.MapVisualRect(wheel_event_rect));
  }
}

void LayerPropertiesUpdater::UpdateScrollHitTestData(const PaintChunk& chunk) {
  const HitTestData& hit_test_data = *chunk.hit_test_data;
  if (hit_test_data.scroll_hit_test_rect.IsEmpty()) {
    return;
  }

  // A scroll hit test rect contributes to the non-fast scrollable region if
  // - the scroll_translation pointer is null, or
  // - the scroll node is not composited.
  if (const auto scroll_translation = hit_test_data.scroll_translation) {
    const auto* scroll_node = scroll_translation->ScrollNode();
    DCHECK(scroll_node);
    // TODO(crbug.com/1230615): Remove this when we fix the root cause.
    if (!scroll_node) {
      return;
    }

    auto scroll_element_id = scroll_node->GetCompositorElementId();
    auto& scroll_tree =
        layer_.layer_tree_host()->property_trees()->scroll_tree_mutable();
    if (hit_test_data.scrolling_contents_cull_rect.Contains(
            scroll_node->ContentsRect())) {
      scroll_tree.ClearScrollingContentsCullRect(scroll_element_id);
    } else {
      scroll_tree.SetScrollingContentsCullRect(
          scroll_element_id, hit_test_data.scrolling_contents_cull_rect);
    }

    if (layer_.element_id() == scroll_element_id) {
      // layer_ is the composited layer of the scroll hit test chunk.
      return;
    }
  }

  if (RuntimeEnabledFeatures::FastNonCompositedScrollHitTestEnabled() &&
      hit_test_data.scroll_translation) {
    CHECK_EQ(chunk.id.type, DisplayItem::Type::kScrollHitTest);
    AddNonCompositedScroll(chunk);
    return;
  }

  gfx::Rect rect =
      chunk_to_layer_mapper_.MapVisualRect(hit_test_data.scroll_hit_test_rect);
  if (rect.IsEmpty()) {
    return;
  }
  main_thread_scroll_hit_test_region_.Union(rect);

  // The scroll hit test rect of scrollbar or resizer also contributes to the
  // touch action region.
  if (chunk.id.type == DisplayItem::Type::kScrollbarHitTest ||
      chunk.id.type == DisplayItem::Type::kResizerScrollHitTest) {
    touch_action_region_.Union(TouchAction::kNone, rect);
  }
}

const TransformPaintPropertyNode&
LayerPropertiesUpdater::TopNonCompositedScroll(
    const TransformPaintPropertyNode& scroll_translation) const {
  const auto* node = &scroll_translation;
  do {
    const auto* parent = node->ParentScrollTranslationNode();
    if (parent == &layer_scroll_translation_) {
      return *node;
    }
    node = parent;
  } while (node);
  // TODO(crbug.com/40558824): Abnormal hierarchy.
  return scroll_translation;
}

void LayerPropertiesUpdater::AddNonCompositedScroll(const PaintChunk& chunk) {
  DCHECK(RuntimeEnabledFeatures::FastNonCompositedScrollHitTestEnabled());
  const auto& scroll_translation = *chunk.hit_test_data->scroll_translation;
  const auto& top_scroll = TopNonCompositedScroll(scroll_translation);
  if (&top_scroll == &scroll_translation) {
    auto hit_test_opaqueness = chunk.hit_test_opaqueness;
    if (hit_test_opaqueness == cc::HitTestOpaqueness::kOpaque &&
        !chunk_to_layer_mapper_.ClipRect().IsTight()) {
      hit_test_opaqueness = cc::HitTestOpaqueness::kMixed;
    }
    top_non_composited_scrolls_.emplace_back(
        &scroll_translation,
        chunk_to_layer_mapper_.MapVisualRect(
            chunk.hit_test_data->scroll_hit_test_rect),
        hit_test_opaqueness);
  } else {
    // A top non-composited scroller with nested non-composited scrollers is
    // forced to be non-fast.
    for (auto& scroll : top_non_composited_scrolls_) {
      if (scroll.scroll_translation == &top_scroll) {
        scroll.hit_test_opaqueness = cc::HitTestOpaqueness::kMixed;
        break;
      }
    }
  }
}

// Updates hit_test_opaqueness on previous non-composited scrollers to be
// HitTestOpaqueness::kMixed if the chunk is hit testable and overlaps.
// Hit tests in these cases cannot be handled on the compositor thread.
void LayerPropertiesUpdater::UpdatePreviousNonCompositedScrolls(
    const PaintChunk& chunk) {
  if (top_non_composited_scrolls_.empty()) {
    return;
  }
  DCHECK(RuntimeEnabledFeatures::FastNonCompositedScrollHitTestEnabled());

  if (chunk.hit_test_data && chunk.hit_test_data->scroll_translation) {
    // ScrollHitTest has been handled in AddNonCompositedScroll().
    return;
  }

  if (chunk.hit_test_opaqueness == cc::HitTestOpaqueness::kTransparent) {
    return;
  }

  const auto* scroll_translation =
      &chunk.properties.Transform().Unalias().NearestScrollTranslationNode();
  if (scroll_translation == &layer_scroll_translation_) {
    // The new chunk is not scrollable in the layer. Any previous scroller
    // intersecting with the new chunk will need main thread hit test.
    gfx::Rect chunk_hit_test_rect =
        chunk_to_layer_mapper_.MapVisualRect(chunk.bounds);
    for (auto& previous_scroll : base::Reversed(top_non_composited_scrolls_)) {
      if (previous_scroll.layer_hit_test_rect.Intersects(chunk_hit_test_rect)) {
        previous_scroll.hit_test_opaqueness = cc::HitTestOpaqueness::kMixed;
      }
      if (previous_scroll.layer_hit_test_rect.Contains(chunk_hit_test_rect)) {
        break;
      }
    }
    return;
  }

  const auto& top_scroll = TopNonCompositedScroll(*scroll_translation);
  if (&top_scroll != scroll_translation) {
    // The chunk is under a nested non-composited scroller. We should have
    // forced or will force the top scroll to be non-fast, so we don't need
    // to do anything here.
    return;
  }
  // The chunk is in the scrolling contents of a top non-composited scroller.
  // Find the scroller. Normally the loop runs only one iteration, unless the
  // scrolling contents of the scroller interlace with other scrollers.
  NonCompositedScroll* non_composited_scroll = nullptr;
  for (auto& previous_scroll : base::Reversed(top_non_composited_scrolls_)) {
    if (previous_scroll.scroll_translation == scroll_translation) {
      non_composited_scroll = &previous_scroll;
      break;
    }
  }
  if (!non_composited_scroll) {
    // The chunk appears before the ScrollHitTest chunk of top_scroll.
    // The chunk's hit-test status doesn't matter because it will be covered
    // by the future ScrollHitTest.
    return;
  }
  if (non_composited_scroll->hit_test_opaqueness ==
      cc::HitTestOpaqueness::kTransparent) {
    // non_composited_scroll has pointer-events:none but the chunk is
    // hit-testable.
    non_composited_scroll->hit_test_opaqueness = cc::HitTestOpaqueness::kMixed;
  }
  if (non_composited_scroll->hit_test_opaqueness ==
      cc::HitTestOpaqueness::kMixed) {
    // non_composited_scroll will generate a rect in
    // main_thread_scroll_hit_test_region_ which will disable all fast scroll
    // in the area, so no need to check overlap with other scrollers.
    return;
  }

  // Assume the chunk can appear anywhere in non_composited_scroll, so use
  // non_composited_scroll->layer_hit_test_rect to check overlap.
  const gfx::Rect& hit_test_rect = non_composited_scroll->layer_hit_test_rect;
  // This is the same as the loop under '== &layer_scroll_translation_` but
  // stops at scroll_translation. Normally this loop is no-op, unless the
  // scrolling contents of the scroller interlace with other scrollers
  // (which will be tested overlap with the hit_test_rect).
  for (auto& previous_scroll : base::Reversed(top_non_composited_scrolls_)) {
    if (previous_scroll.scroll_translation == scroll_translation) {
      break;
    }
    if (previous_scroll.layer_hit_test_rect.Intersects(hit_test_rect)) {
      previous_scroll.hit_test_opaqueness = cc::HitTestOpaqueness::kMixed;
    }
    if (previous_scroll.layer_hit_test_rect.Contains(hit_test_rect)) {
      break;
    }
  }
}

const ScrollbarDisplayItem* NonCompositedScrollbarDisplayItem(
    PaintChunkIterator chunk_it,
    const cc::Layer& layer) {
  if (chunk_it->size() != 1) {
    return nullptr;
  }
  const auto* scrollbar =
      DynamicTo<ScrollbarDisplayItem>(*chunk_it.DisplayItems().begin());
  if (!scrollbar) {
    return nullptr;
  }
  if (scrollbar->ElementId() == layer.element_id()) {
    // layer_ is the composited layer of the scrollbar.
    return nullptr;
  }
  return scrollbar;
}

void LayerPropertiesUpdater::UpdateForNonCompositedScrollbar(
    const ScrollbarDisplayItem& scrollbar) {
  // A non-composited scrollbar contributes to the non-fast scrolling region
  // and the touch action region.
  gfx::Rect rect = chunk_to_layer_mapper_.MapVisualRect(scrollbar.VisualRect());
  if (rect.IsEmpty()) {
    return;
  }
  main_thread_scroll_hit_test_region_.Union(rect);
  touch_action_region_.Union(TouchAction::kNone, rect);
}

void LayerPropertiesUpdater::UpdateRegionCaptureData(
    const RegionCaptureData& region_capture_data) {
  for (const std::pair<RegionCaptureCropId, gfx::Rect>& pair :
       region_capture_data.map) {
    capture_bounds_.Set(pair.first.value(),
                        chunk_to_layer_mapper_.MapVisualRect(pair.second));
  }
}

gfx::Point LayerPropertiesUpdater::MapSelectionBoundPoint(
    const gfx::Point& point) const {
  return gfx::ToRoundedPoint(
      chunk_to_layer_mapper_.Transform().MapPoint(gfx::PointF(point)));
}

cc::LayerSelectionBound
LayerPropertiesUpdater::PaintedSelectionBoundToLayerSelectionBound(
    const PaintedSelectionBound& bound) const {
  cc::LayerSelectionBound layer_bound;
  layer_bound.type = bound.type;
  layer_bound.hidden = bound.hidden;
  layer_bound.edge_start = MapSelectionBoundPoint(bound.edge_start);
  layer_bound.edge_end = MapSelectionBoundPoint(bound.edge_end);
  return layer_bound;
}

void LayerPropertiesUpdater::UpdateLayerSelection(
    const LayerSelectionData& layer_selection_data) {
  if (layer_selection_data.start) {
    layer_selection_.start =
        PaintedSelectionBoundToLayerSelectionBound(*layer_selection_data.start);
    layer_selection_.start.layer_id = layer_.id();
  }

  if (layer_selection_data.end) {
    layer_selection_.end =
        PaintedSelectionBoundToLayerSelectionBound(*layer_selection_data.end);
    layer_selection_.end.layer_id = layer_.id();
  }
}

void LayerPropertiesUpdater::Update() {
  bool any_selection_was_painted = false;
  for (auto it = chunks_.begin(); it != chunks_.end(); ++it) {
    const PaintChunk& chunk = *it;
    const auto* non_composited_scrollbar =
        NonCompositedScrollbarDisplayItem(it, layer_);
    if ((!selection_only_ &&
         (chunk.hit_test_data || non_composited_scrollbar ||
          chunk.region_capture_data || !top_non_composited_scrolls_.empty())) ||
        chunk.layer_selection_data) {
      chunk_to_layer_mapper_.SwitchToChunk(chunk);
    }
    if (!selection_only_) {
      if (chunk.hit_test_data) {
        UpdateTouchActionRegion(*chunk.hit_test_data);
        UpdateWheelEventRegion(*chunk.hit_test_data);
        UpdateScrollHitTestData(chunk);
      }
      UpdatePreviousNonCompositedScrolls(chunk);
      if (non_composited_scrollbar) {
        UpdateForNonCompositedScrollbar(*non_composited_scrollbar);
      }
      if (chunk.region_capture_data) {
        UpdateRegionCaptureData(*chunk.region_capture_data);
      }
    }
    if (chunk.layer_selection_data) {
      any_selection_was_painted |=
          chunk.layer_selection_data->any_selection_was_painted;
      UpdateLayerSelection(*chunk.layer_selection_data);
    }
  }

  if (!selection_only_) {
    layer_.SetTouchActionRegion(std::move(touch_action_region_));
    layer_.SetWheelEventRegion(std::move(wheel_event_region_));
    layer_.SetCaptureBounds(std::move(capture_bounds_));

    std::vector<cc::ScrollHitTestRect> non_composited_scroll_hit_test_rects;
    for (const auto& scroll : top_non_composited_scrolls_) {
      if (scroll.hit_test_opaqueness == cc::HitTestOpaqueness::kMixed) {
        main_thread_scroll_hit_test_region_.Union(scroll.layer_hit_test_rect);
      } else if (scroll.hit_test_opaqueness == cc::HitTestOpaqueness::kOpaque) {
        non_composited_scroll_hit_test_rects.emplace_back(
            scroll.scroll_translation->ScrollNode()->GetCompositorElementId(),
            scroll.layer_hit_test_rect);
      }
    }
    layer_.SetMainThreadScrollHitTestRegion(
        std::move(main_thread_scroll_hit_test_region_));
    layer_.SetNonCompositedScrollHitTestRects(
        std::move(non_composited_scroll_hit_test_rects));
  }

  if (any_selection_was_painted) {
    // If any selection was painted, but we didn't see the start or end bound
    // recorded, it could have been outside of the painting cull rect thus
    // invisible. Mark the bound as such if this is the case.
    if (layer_selection_.start.type == gfx::SelectionBound::EMPTY) {
      layer_selection_.start.type = gfx::SelectionBound::LEFT;
      layer_selection_.start.hidden = true;
    }

    if (layer_selection_.end.type == gfx::SelectionBound::EMPTY) {
      layer_selection_.end.type = gfx::SelectionBound::RIGHT;
      layer_selection_.end.hidden = true;
    }
  }
}

}  // namespace

void PaintChunksToCcLayer::UpdateLayerProperties(
    cc::Layer& layer,
    const PropertyTreeState& layer_state,
    const PaintChunkSubset& chunks,
    cc::LayerSelection& layer_selection,
    bool selection_only) {
  LayerPropertiesUpdater(layer, layer_state, chunks, layer_selection,
                         selection_only)
      .Update();
}

}  // namespace blink

WTF_ALLOW_MOVE_INIT_AND_COMPARE_WITH_MEM_FUNCTIONS(blink::StateEntry)
WTF_ALLOW_MOVE_INIT_AND_COMPARE_WITH_MEM_FUNCTIONS(blink::EffectBoundsInfo)
WTF_ALLOW_MOVE_INIT_AND_COMPARE_WITH_MEM_FUNCTIONS(blink::NonCompositedScroll)

"""


```