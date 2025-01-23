Response:
The user wants a summary of the functionalities of the provided C++ code snippet from the Chromium Blink engine. The code is part of the `LayoutBox` class and deals with managing layout results and cached information related to the layout process.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The code primarily manages `LayoutResult` objects, which represent the outcome of the layout process for a `LayoutBox`. This involves storing, updating, and invalidating these results.

2. **Analyze the key methods:** Go through each method and understand its role:
    * `CacheLayoutResult`:  Caches layout results, potentially clearing old cached data. Handles differences between layout and measure results.
    * `SetLayoutResult`:  A main entry point for setting layout results. Manages replacing or appending results, handles fragmentation, and finalizes results.
    * `AppendLayoutResult`:  Adds a new layout result.
    * `ReplaceLayoutResult`:  Replaces an existing layout result, handling potential fragment changes and invalidations.
    * `FinalizeLayoutResults`:  Performs post-layout tasks, especially for inline formatting contexts.
    * `RebuildFragmentTreeSpine`: Updates the fragment tree structure.
    * `ShrinkLayoutResults`: Removes older layout results.
    * `InvalidateCachedGeometry`:  Marks cached geometry as invalid.
    * `InvalidateItems`:  Invalidates display items associated with a layout result.
    * `GetCachedLayoutResult`, `GetCachedMeasureResult`, `GetSingleCachedLayoutResult`, `GetSingleCachedMeasureResultForTesting`, `GetLayoutResult`: Retrieve cached or stored layout results.
    * `PhysicalFragmentList::Iterator::operator*`, `PhysicalFragmentList::front`, `PhysicalFragmentList::back`: Access methods for fragments within layout results.
    * `FragmentDataFromPhysicalFragment`: Retrieves fragment data.
    * `SetSpannerPlaceholder`, `ClearSpannerPlaceholder`: Manage placeholder elements for multicolumn layouts.
    * `InflateVisualRectForFilterUnderContainer`, `MapToVisualRectInAncestorSpaceInternal`, `InflateVisualRectForFilter`: Methods for adjusting visual rectangles based on filters and transformations.
    * `SkipContainingBlockForPercentHeightCalculation`, `ContainingBlockLogicalHeightForPositioned`: Determine the containing block for height calculations, considering different positioning schemes.
    * `LocalCaretRect`: Calculates the position and size of the text input caret.
    * `PositionForPointInFragments`: Determines the document position for a given point within fragmented content.
    * `ShouldBeConsideredAsReplaced`: Checks if the element should be treated as a replaced element (like images or form controls).
    * `IsCustomItem`: Checks if the element is an item within a `LayoutCustom` object.
    * `ComputeVisualEffectOverflowOutsets`: Calculates the overflow caused by visual effects like outlines.
    * `HasTopOverflow`, `HasLeftOverflow`: Determine if there's overflow in specific directions.
    * `SetScrollableOverflowFromLayoutResults`: Calculates and sets the scrollable overflow based on layout results.
    * `RecalcScrollableOverflowNG`, `RecalcChildScrollableOverflowNG`: Recalculate scrollable overflow using the NG layout engine.

3. **Identify relationships with web technologies:** Consider how these functionalities relate to JavaScript, HTML, and CSS:
    * **HTML Structure:** The layout process is directly influenced by the HTML structure. The code manages layout results for `LayoutBox` objects, which correspond to HTML elements.
    * **CSS Styling:** CSS properties determine the layout (size, position, etc.). The code uses `ComputedStyle` to factor in CSS rules. Fragmentation, handled by this code, is influenced by CSS properties like `break-inside`, `column-count`, etc. Visual effects controlled by CSS (filters, outlines) are also considered.
    * **JavaScript Interaction:** While this C++ code doesn't directly execute JavaScript, the layout it produces affects how JavaScript interacts with the page. For instance, JavaScript calculations of element positions or sizes rely on the layout. User interactions triggered by JavaScript might necessitate layout recalculations.

4. **Infer logical reasoning and examples:**  Consider scenarios and provide illustrative input/output examples where applicable:
    * **Caching:** If a box's layout hasn't changed, the cached result can be reused, saving computation. Input: A `LayoutBox` with stable properties. Output: The previously calculated `LayoutResult` is retrieved.
    * **Fragmentation:** When content is split across pages or columns, multiple `LayoutResult` objects are created and managed. Input: A long block of text within a multicolumn container. Output: Multiple `LayoutResult` objects, each representing a fragment.
    * **Visual Effects:** Filters and outlines can affect the visual bounds of an element. Input: A `div` with a CSS `filter`. Output: The `InflateVisualRectForFilter` methods adjust the visual rectangle accordingly.

5. **Consider common errors:** Think about situations where developers might make mistakes that relate to these functionalities:
    * **Incorrectly assuming cached layout:**  Developers might assume a layout is stable when it's not, leading to unexpected behavior if they rely on stale cached values (although this is more of an internal engine concern).
    * **Not considering fragmentation:**  JavaScript code that calculates positions might not account for fragmentation, leading to errors when elements are split across fragments.
    * **Overlooking visual effects:**  Calculations of element boundaries might be inaccurate if visual effects like filters are not considered.

6. **Synthesize the information into a concise summary:**  Group related functionalities and express them in clear, understandable language. Emphasize the core role of managing layout results, handling fragmentation, and considering CSS and visual effects.

7. **Address the "part 4 of 6" instruction:** Acknowledge that this is part of a larger file and that the focus is on the provided snippet's functions.

By following these steps, we can generate a comprehensive and accurate explanation of the code snippet's functionality and its relationship to web technologies.
这是 `blink/renderer/core/layout/layout_box.cc` 文件的第 4 部分，主要关注于 `LayoutBox` 类中 **管理和操作布局结果 (LayoutResult) 以及相关的缓存机制** 的功能。

**核心功能归纳:**

* **管理布局结果 (`LayoutResult`) 的生命周期:**
    * **存储和更新:** 提供方法 (`SetLayoutResult`, `AppendLayoutResult`, `ReplaceLayoutResult`) 来存储、添加和替换 `LayoutResult` 对象，这些对象包含了布局计算后的信息，如盒子的位置和尺寸。
    * **处理分片 (Fragmentation):**  代码考虑了布局对象可能被分片成多个部分（例如，跨页、跨列），并能管理这些分片的布局结果。
    * **清理和收缩:** 提供方法 (`ShrinkLayoutResults`) 在需要时移除旧的或不再需要的布局结果，以节省内存。
    * **最终化处理:**  `FinalizeLayoutResults`  在所有分片的布局结果都生成后执行最终的处理，特别是对于创建了行内格式化上下文的盒子。

* **实现布局结果的缓存机制:**
    * **`measure_cache_`:** 使用 `measure_cache_` 来缓存 "measure pass" 的结果。 Measure pass 是在完整的布局之前执行的预先计算，用于估计盒子的尺寸。
    * **缓存策略:**  代码会在特定条件下清理缓存，例如在布局发生变化时。
    * **获取缓存结果:** 提供方法 (`GetCachedLayoutResult`, `GetCachedMeasureResult`) 从缓存中检索布局或 measure pass 的结果，以避免重复计算。

* **维护布局的有效性:**
    * **失效缓存:** 当布局发生变化时，通过 `InvalidateCachedGeometry` 方法将缓存的几何信息标记为无效，强制在下次需要时重新计算。
    * **失效显示项 (`DisplayItem`):**  `InvalidateItems` 方法用于失效与布局结果关联的显示项，确保渲染时使用最新的信息。

* **支持复杂布局特性:**
    * **处理列跨越 (`Column Spanner`):** 代码中包含处理列跨越元素的逻辑，确保布局的正确性，并避免访问过时的分片信息。
    * **处理绝对定位和固定定位 (`Out-of-flow Positioning`):**  虽然这部分代码没有直接体现，但布局结果的管理是支持这些定位方式的基础。
    * **处理视觉效果 (`Filters`, `Outlines`):**  `InflateVisualRectForFilter` 等方法用于调整元素的视觉边界，以考虑 CSS 滤镜等视觉效果的影响。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **HTML:** `LayoutBox` 对象对应于 HTML 元素。这部分代码管理着每个 HTML 元素经过布局计算后的结果。例如，如果一个 `<div>` 元素的内容改变了，相关的 `LayoutResult` 可能需要更新。
* **CSS:** CSS 样式（如 `width`, `height`, `display`, `position`, `break-inside`, `column-count`, `filter`, `outline` 等）直接影响布局的结果。 这部分代码在计算和管理布局结果时会考虑这些样式。
    * **示例（CSS Fragmentation）：**  如果一个 `<div>` 设置了 `column-count: 2;`，`LayoutBox` 会创建多个 `LayoutResult` 对象，每个对应一个列中的内容分片。 代码中的逻辑会处理这些分片的存储和更新。
    * **示例（CSS Filters）：** 如果一个 `<img>` 元素应用了 CSS 滤镜，`InflateVisualRectForFilter` 方法会调整该元素在布局中的视觉矩形大小，以便包含滤镜效果的影响。
* **JavaScript:** JavaScript 可以读取和修改 DOM 结构和 CSS 样式，这些操作可能会导致布局的重新计算。 这部分代码确保了当布局需要重新计算时，相关的缓存会被失效，以便获取最新的布局结果。
    * **假设输入：** JavaScript 代码修改了一个 `<div>` 元素的 `width` 样式。
    * **逻辑推理：**  Blink 引擎会检测到样式变化，并将该 `<div>` 的 `LayoutBox` 标记为需要重新布局。这部分代码管理的缓存会失效，确保下次渲染时使用新的布局结果。
    * **输出：**  当浏览器重新渲染页面时，会触发布局过程，并生成新的 `LayoutResult` 对象。

**用户或编程常见的使用错误举例说明:**

这部分代码主要在 Blink 引擎内部使用，普通 Web 开发者不会直接与之交互。然而，理解其功能可以帮助理解一些与性能相关的概念：

* **过度依赖强制同步布局 (Forced Synchronous Layout):**  如果在 JavaScript 中频繁地读取会导致布局计算的属性（例如 `offsetWidth`, `offsetHeight`）后立即修改样式，可能会导致浏览器反复进行布局计算，降低性能。理解布局结果的缓存机制可以帮助开发者意识到这种操作的潜在性能问题。

**总结:**

这部分代码在 `LayoutBox` 类中扮演着至关重要的角色，它负责高效地管理和缓存布局计算的结果，处理布局分片等复杂场景，并确保布局信息的有效性。这对于浏览器的性能至关重要，因为它避免了对相同内容进行重复的布局计算，并支持各种复杂的 CSS 布局特性。

### 提示词
```
这是目录为blink/renderer/core/layout/layout_box.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
measure_cache_->Clear();
      }
    }
  }

  // If we're about to cache a layout result that is different than the measure
  // result, mark the measure result's fragment as no longer having valid
  // children. It can still be used to query information about this box's
  // fragment from the measure pass, but children might be out of sync with the
  // latest version of the tree.
  if (measure_cache_) {
    measure_cache_->SetFragmentChildrenInvalid(result);
  }

  SetLayoutResult(result, index);
}

void LayoutBox::SetLayoutResult(const LayoutResult* result, wtf_size_t index) {
  NOT_DESTROYED();
  DCHECK_EQ(result->Status(), LayoutResult::kSuccess);
  const auto& box_fragment =
      To<PhysicalBoxFragment>(result->GetPhysicalFragment());

  if (index != WTF::kNotFound && layout_results_.size() > index) {
    if (layout_results_.size() > index + 1) {
      // If we have reached the end, remove surplus results from previous
      // layout.
      //
      // Note: When an OOF is fragmented, we wait to lay it out at the
      // fragmentation context root. If the OOF lives above a column spanner,
      // though, we may lay it out early to make sure the OOF contributes to the
      // correct column block-size. Thus, if an item broke as a result of a
      // spanner, remove subsequent sibling items so that OOFs don't try to
      // access old fragments.
      //
      // Additionally, if an outer multicol has a spanner break, we may try
      // to access old fragments of the inner multicol if it hasn't completed
      // layout yet. Remove subsequent multicol fragments to avoid OOFs from
      // trying to access old fragments.
      //
      // TODO(layout-dev): Other solutions to handling interactions between OOFs
      // and spanner breaks may need to be considered.
      if (!box_fragment.GetBreakToken() ||
          box_fragment.GetBreakToken()->IsCausedByColumnSpanner() ||
          box_fragment.IsFragmentationContextRoot()) {
        // Before forgetting any old fragments and their items, we need to clear
        // associations.
        if (box_fragment.IsInlineFormattingContext())
          FragmentItems::ClearAssociatedFragments(this);
        ShrinkLayoutResults(index + 1);
      }
    }
    ReplaceLayoutResult(std::move(result), index);
    return;
  }

  DCHECK(index == layout_results_.size() || index == kNotFound);
  AppendLayoutResult(result);

  if (!box_fragment.GetBreakToken()) {
    FinalizeLayoutResults();
  }
}

void LayoutBox::AppendLayoutResult(const LayoutResult* result) {
  const auto& fragment = To<PhysicalBoxFragment>(result->GetPhysicalFragment());
  // |layout_results_| is particularly critical when side effects are disabled.
  DCHECK(!DisableLayoutSideEffectsScope::IsDisabled());
  layout_results_.push_back(std::move(result));
  InvalidateCachedGeometry();
  CheckDidAddFragment(*this, fragment);
}

void LayoutBox::ReplaceLayoutResult(const LayoutResult* result,
                                    wtf_size_t index) {
  NOT_DESTROYED();
  DCHECK_LE(index, layout_results_.size());
  const LayoutResult* old_result = layout_results_[index];
  if (old_result == result)
    return;
  const auto& fragment = To<PhysicalBoxFragment>(result->GetPhysicalFragment());
  const auto& old_fragment = old_result->GetPhysicalFragment();
  bool got_new_fragment = &old_fragment != &fragment;
  if (got_new_fragment) {
    if (HasFragmentItems()) {
      if (!index)
        InvalidateItems(*old_result);
      FragmentItems::ClearAssociatedFragments(this);
    }
    // We are about to replace a fragment, and the size may have changed. The
    // inline-size and total stitched block-size may still remain unchanged,
    // though, and pre-paint can only detect changes in the total stitched
    // size. So this is our last chance to detect any size changes at the
    // fragment itself. Only do this if we're fragmented, though. Otherwise
    // leave it to pre-paint to figure out if invalidation is really required,
    // since it's fine to just check the stitched sizes when not fragmented.
    // Unconditionally requiring full paint invalidation at size changes may be
    // unnecessary and expensive.
    if (layout_results_.size() > 1 && fragment.Size() != old_fragment.Size()) {
      SetShouldDoFullPaintInvalidation();
    }
  }
  // |layout_results_| is particularly critical when side effects are disabled.
  DCHECK(!DisableLayoutSideEffectsScope::IsDisabled());
  layout_results_[index] = std::move(result);
  InvalidateCachedGeometry();
  CheckDidAddFragment(*this, fragment, index);

  if (got_new_fragment && !fragment.GetBreakToken()) {
    // If this is the last result, the results vector better agree on that.
    DCHECK_EQ(index, layout_results_.size() - 1);

    FinalizeLayoutResults();
  }
}

void LayoutBox::FinalizeLayoutResults() {
  DCHECK(!layout_results_.empty());
  DCHECK(!layout_results_.back()->GetPhysicalFragment().GetBreakToken());
#if EXPENSIVE_DCHECKS_ARE_ON()
  CheckMayHaveFragmentItems();
#endif
  // If we've added all the results we were going to, and the node establishes
  // an inline formatting context, we have some finalization to do.
  if (HasFragmentItems()) {
    FragmentItems::FinalizeAfterLayout(layout_results_,
                                       *To<LayoutBlockFlow>(this));
  }
}

void LayoutBox::RebuildFragmentTreeSpine() {
  DCHECK(PhysicalFragmentCount());
  SCOPED_BLINK_UMA_HISTOGRAM_TIMER_HIGHRES(
      "Blink.Layout.RebuildFragmentTreeSpine");
  // If this box has an associated layout-result, rebuild the spine of the
  // fragment-tree to ensure consistency.
  LayoutBox* container = this;
  while (container && container->PhysicalFragmentCount() &&
         !container->NeedsLayout()) {
    for (auto& result : container->layout_results_)
      result = LayoutResult::CloneWithPostLayoutFragments(*result);
    container = container->ContainingNGBox();
  }

  if (container && container->NeedsLayout()) {
    // We stopped walking upwards because this container needs layout. This
    // typically means that updating the associated layout results is waste of
    // time, since we're probably going to lay it out anyway. However, in some
    // cases the container is going to hit the cache and therefore not perform
    // actual layout. If this happens, we need to update the layout results at
    // that point.
    container->SetHasBrokenSpine();
  }
}

void LayoutBox::ShrinkLayoutResults(wtf_size_t results_to_keep) {
  NOT_DESTROYED();
  DCHECK_GE(layout_results_.size(), results_to_keep);
  // Invalidate if inline |DisplayItemClient|s will be destroyed.
  for (wtf_size_t i = results_to_keep; i < layout_results_.size(); i++)
    InvalidateItems(*layout_results_[i]);
  // |layout_results_| is particularly critical when side effects are disabled.
  DCHECK(!DisableLayoutSideEffectsScope::IsDisabled());
  layout_results_.Shrink(results_to_keep);
  InvalidateCachedGeometry();
}

#if EXPENSIVE_DCHECKS_ARE_ON()
void LayoutBox::CheckMayHaveFragmentItems() const {
  NOT_DESTROYED();
  if (!MayHaveFragmentItems()) {
    DCHECK(!PhysicalFragments().SlowHasFragmentItems());
  }
}
#endif

void LayoutBox::InvalidateCachedGeometry() {
  NOT_DESTROYED();
  SetHasValidCachedGeometry(false);
  if (auto* block_flow = DynamicTo<LayoutBlockFlow>(this)) {
    if (auto* flow_thread = block_flow->MultiColumnFlowThread()) {
      flow_thread->SetHasValidCachedGeometry(false);
      for (auto* sibling = flow_thread->NextSiblingBox(); sibling;
           sibling = sibling->NextSiblingBox()) {
        sibling->SetHasValidCachedGeometry(false);
      }
    }
  }
}

// static
void LayoutBox::InvalidateItems(const LayoutResult& result) {
  // Invalidate if inline |DisplayItemClient|s will be destroyed.
  const auto& box_fragment =
      To<PhysicalBoxFragment>(result.GetPhysicalFragment());
  if (!box_fragment.HasItems())
    return;
  ObjectPaintInvalidator(*box_fragment.GetLayoutObject())
      .SlowSetPaintingLayerNeedsRepaint();
}

const LayoutResult* LayoutBox::GetCachedLayoutResult(
    const BlockBreakToken* break_token) const {
  NOT_DESTROYED();
  wtf_size_t index = FragmentIndex(break_token);
  if (index >= layout_results_.size())
    return nullptr;
  const LayoutResult* result = layout_results_[index];
  DCHECK(!result->GetPhysicalFragment().IsLayoutObjectDestroyedOrMoved() ||
         BeingDestroyed());
  return result;
}

const LayoutResult* LayoutBox::GetCachedMeasureResult(
    const ConstraintSpace& space,
    std::optional<FragmentGeometry>* fragment_geometry) const {
  NOT_DESTROYED();
  if (!measure_cache_) {
    return nullptr;
  }

  // If we've already had an actual layout pass, and the node fragmented, we
  // cannot reliably re-use the measure result. What we want to avoid here is
  // simplified layout inside a measure-result, as that would descend into a
  // fragment subtree generated by actual (fragmented) layout, which is
  // invalid. But it seems safer to stop such attempts here, so that we don't
  // hand out results that may cause problems if we end up with simplified
  // layout inside.
  if (!layout_results_.empty()) {
    const PhysicalBoxFragment* first_fragment = GetPhysicalFragment(0);
    if (first_fragment->GetBreakToken()) {
      return nullptr;
    }
  }

  return measure_cache_
             ? measure_cache_->Find(BlockNode(const_cast<LayoutBox*>(this)),
                                    space, fragment_geometry)
             : nullptr;
}

const LayoutResult* LayoutBox::GetSingleCachedLayoutResult() const {
  DCHECK_LE(layout_results_.size(), 1u);
  return GetCachedLayoutResult(nullptr);
}

const LayoutResult* LayoutBox::GetSingleCachedMeasureResultForTesting() const {
  return measure_cache_ ? measure_cache_->GetLastForTesting() : nullptr;
}

const LayoutResult* LayoutBox::GetLayoutResult(wtf_size_t i) const {
  NOT_DESTROYED();
  return layout_results_[i].Get();
}

const PhysicalBoxFragment&
LayoutBox::PhysicalFragmentList::Iterator::operator*() const {
  return To<PhysicalBoxFragment>((*iterator_)->GetPhysicalFragment());
}

const PhysicalBoxFragment& LayoutBox::PhysicalFragmentList::front() const {
  return To<PhysicalBoxFragment>(
      layout_results_.front()->GetPhysicalFragment());
}

const PhysicalBoxFragment& LayoutBox::PhysicalFragmentList::back() const {
  return To<PhysicalBoxFragment>(layout_results_.back()->GetPhysicalFragment());
}

const FragmentData* LayoutBox::FragmentDataFromPhysicalFragment(
    const PhysicalBoxFragment& physical_fragment) const {
  NOT_DESTROYED();
  return &FragmentList().at(BoxFragmentIndex(physical_fragment));
}

void LayoutBox::SetSpannerPlaceholder(
    LayoutMultiColumnSpannerPlaceholder& placeholder) {
  NOT_DESTROYED();
  // Not expected to change directly from one spanner to another.
  CHECK(!rare_data_ || !rare_data_->spanner_placeholder_);
  EnsureRareData().spanner_placeholder_ = &placeholder;
}

void LayoutBox::ClearSpannerPlaceholder() {
  NOT_DESTROYED();
  if (!rare_data_)
    return;
  rare_data_->spanner_placeholder_ = nullptr;
}

void LayoutBox::InflateVisualRectForFilterUnderContainer(
    TransformState& transform_state,
    const LayoutObject& container,
    const LayoutBoxModelObject* ancestor_to_stop_at) const {
  NOT_DESTROYED();
  transform_state.Flatten();
  // Apply visual overflow caused by reflections and filters defined on objects
  // between this object and container (not included) or ancestorToStopAt
  // (included).
  PhysicalOffset offset_from_container = OffsetFromContainer(&container);
  transform_state.Move(offset_from_container);
  for (LayoutObject* parent = Parent(); parent && parent != container;
       parent = parent->Parent()) {
    if (parent->IsBox()) {
      // Convert rect into coordinate space of parent to apply parent's
      // reflection and filter.
      PhysicalOffset parent_offset = parent->OffsetFromAncestor(&container);
      transform_state.Move(-parent_offset);
      To<LayoutBox>(parent)->InflateVisualRectForFilter(transform_state);
      transform_state.Move(parent_offset);
    }
    if (parent == ancestor_to_stop_at)
      break;
  }
  transform_state.Move(-offset_from_container);
}

bool LayoutBox::MapToVisualRectInAncestorSpaceInternal(
    const LayoutBoxModelObject* ancestor,
    TransformState& transform_state,
    VisualRectFlags visual_rect_flags) const {
  NOT_DESTROYED();

  if (ancestor == this)
    return true;

  if (!(visual_rect_flags & kIgnoreFilters)) {
    InflateVisualRectForFilter(transform_state);
  }

  AncestorSkipInfo skip_info(ancestor, true);
  LayoutObject* container = Container(&skip_info);
  if (!container)
    return true;

  PhysicalOffset container_offset;
  if (auto* box = DynamicTo<LayoutBox>(container)) {
    container_offset += PhysicalLocation(box);
  } else {
    container_offset += PhysicalLocation();
  }

  if (IsStickyPositioned()) {
    container_offset += StickyPositionOffset();
  } else if (NeedsAnchorPositionScrollAdjustment()) [[unlikely]] {
    container_offset += AnchorPositionScrollTranslationOffset();
  }

  if (skip_info.FilterSkipped() && !(visual_rect_flags & kIgnoreFilters)) {
    InflateVisualRectForFilterUnderContainer(transform_state, *container,
                                             ancestor);
  }

  if (!MapVisualRectToContainer(container, container_offset, ancestor,
                                visual_rect_flags, transform_state))
    return false;

  if (skip_info.AncestorSkipped()) {
    bool preserve3D = container->StyleRef().Preserves3D();
    TransformState::TransformAccumulation accumulation =
        preserve3D ? TransformState::kAccumulateTransform
                   : TransformState::kFlattenTransform;

    // If the ancestor is below the container, then we need to map the rect into
    // ancestor's coordinates.
    PhysicalOffset ancestor_container_offset =
        ancestor->OffsetFromAncestor(container);
    transform_state.Move(-ancestor_container_offset, accumulation);
    return true;
  }

  if (IsFixedPositioned() && container == ancestor && container->IsLayoutView())
    transform_state.Move(To<LayoutView>(container)->OffsetForFixedPosition());

  return container->MapToVisualRectInAncestorSpaceInternal(
      ancestor, transform_state, visual_rect_flags);
}

void LayoutBox::InflateVisualRectForFilter(
    TransformState& transform_state) const {
  NOT_DESTROYED();
  if (!Layer() || !Layer()->PaintsWithFilters())
    return;

  transform_state.Flatten();
  PhysicalRect rect = PhysicalRect::EnclosingRect(
      transform_state.LastPlanarQuad().BoundingBox());
  transform_state.SetQuad(
      gfx::QuadF(gfx::RectF(Layer()->MapRectForFilter(rect))));
}

bool LayoutBox::SkipContainingBlockForPercentHeightCalculation(
    const LayoutBox* containing_block) {
  const bool in_quirks_mode = containing_block->GetDocument().InQuirksMode();
  // Anonymous blocks should not impede percentage resolution on a child.
  // Examples of such anonymous blocks are blocks wrapped around inlines that
  // have block siblings (from the CSS spec) and multicol flow threads (an
  // implementation detail). Another implementation detail, ruby columns, create
  // anonymous inline-blocks, so skip those too. All other types of anonymous
  // objects, such as table-cells, will be treated just as if they were
  // non-anonymous.
  if (containing_block->IsAnonymous()) {
    if (!in_quirks_mode && containing_block->Parent() &&
        containing_block->Parent()->IsFieldset()) {
      return false;
    }
    EDisplay display = containing_block->StyleRef().Display();
    return display == EDisplay::kBlock || display == EDisplay::kInlineBlock ||
           display == EDisplay::kFlowRoot;
  }

  // For quirks mode, we skip most auto-height containing blocks when computing
  // percentages.
  if (!in_quirks_mode ||
      !containing_block->StyleRef().LogicalHeight().HasAuto()) {
    return false;
  }

  const Node* node = containing_block->GetNode();
  if (node->IsInUserAgentShadowRoot()) [[unlikely]] {
    const Element* host = node->OwnerShadowHost();
    if (const auto* input = DynamicTo<HTMLInputElement>(host)) {
      // In web_tests/fast/forms/range/range-thumb-height-percentage.html, a
      // percent height for the slider thumb element should refer to the height
      // of the INPUT box.
      if (input->FormControlType() == FormControlType::kInputRange) {
        return true;
      }
    }
  }

  return !containing_block->IsLayoutReplaced() &&
         !containing_block->IsTableCell() &&
         !containing_block->IsOutOfFlowPositioned() &&
         !containing_block->IsLayoutGrid() &&
         !containing_block->IsFlexibleBox() &&
         !containing_block->IsLayoutCustom();
}

LayoutUnit LayoutBox::ContainingBlockLogicalHeightForPositioned(
    const LayoutBoxModelObject* containing_block) const {
  NOT_DESTROYED();

  // Use viewport as container for top-level fixed-position elements.
  const auto* view = DynamicTo<LayoutView>(containing_block);
  if (StyleRef().GetPosition() == EPosition::kFixed && view &&
      !GetDocument().Printing()) {
    if (LocalFrameView* frame_view = view->GetFrameView()) {
      // Don't use visibleContentRect since the PaintLayer's size has not been
      // set yet.
      gfx::Size viewport_size =
          frame_view->LayoutViewport()->ExcludeScrollbars(frame_view->Size());
      return LayoutUnit(containing_block->IsHorizontalWritingMode()
                            ? viewport_size.height()
                            : viewport_size.width());
    }
  }

  if (containing_block->IsBox())
    return To<LayoutBox>(containing_block)->ClientLogicalHeight();

  DCHECK(containing_block->IsLayoutInline());
  DCHECK(containing_block->CanContainOutOfFlowPositionedElement(
      StyleRef().GetPosition()));

  const auto* flow = To<LayoutInline>(containing_block);
  // If the containing block is empty, return a height of 0.
  if (!flow->HasInlineFragments())
    return LayoutUnit();

  LayoutUnit height_result;
  auto bounding_box_size = flow->PhysicalLinesBoundingBox().size;
  if (containing_block->IsHorizontalWritingMode())
    height_result = bounding_box_size.height;
  else
    height_result = bounding_box_size.width;
  height_result -= (containing_block->BorderBlockStart() +
                    containing_block->BorderBlockEnd());
  return height_result;
}

PhysicalRect LayoutBox::LocalCaretRect(int caret_offset) const {
  NOT_DESTROYED();
  // VisiblePositions at offsets inside containers either a) refer to the
  // positions before/after those containers (tables and select elements) or
  // b) refer to the position inside an empty block.
  // They never refer to children.
  // FIXME: Paint the carets inside empty blocks differently than the carets
  // before/after elements.
  LayoutUnit caret_width = GetFrameView()->CaretWidth();
  LogicalSize size(LogicalWidth(), LogicalHeight());

  LayoutUnit caret_block_size = size.block_size;
  // If height of box is smaller than font height, use the latter one,
  // otherwise the caret might become invisible.
  //
  // Also, if the box is not an atomic inline-level element, always use the font
  // height. This prevents the "big caret" bug described in:
  // <rdar://problem/3777804> Deleting all content in a document can result in
  // giant tall-as-window insertion point
  //
  // FIXME: ignoring :first-line, missing good reason to take care of
  const SimpleFontData* font_data = StyleRef().GetFont().PrimaryFont();
  LayoutUnit font_height =
      LayoutUnit(font_data ? font_data->GetFontMetrics().Height() : 0);
  if (font_height > size.block_size || (!IsAtomicInlineLevel() && !IsTable())) {
    caret_block_size = font_height;
  }

  // FIXME: Border/padding should be added for all elements but this workaround
  // is needed because we use offsets inside an "atomic" element to represent
  // positions before and after the element in deprecated editing offsets.
  bool apply_border_padding =
      GetNode() &&
      !(EditingIgnoresContent(*GetNode()) || IsDisplayInsideTable(GetNode()));

  if (RuntimeEnabledFeatures::SidewaysWritingModesEnabled()) {
    WritingDirectionMode writing_direction = Style()->GetWritingDirection();
    LogicalOffset offset;
    LayoutUnit content_inline_size = size.inline_size;
    if (apply_border_padding) {
      BoxStrut border_padding = (BorderOutsets() + PaddingOutsets())
                                    .ConvertToLogical(writing_direction);
      offset.inline_offset = border_padding.inline_start;
      offset.block_offset = border_padding.block_start;
      content_inline_size -= border_padding.InlineSum();
    }
    if (caret_offset) {
      offset.inline_offset += content_inline_size - caret_width;
    }

    LogicalRect rect(offset, LogicalSize(caret_width, caret_block_size));
    return WritingModeConverter(writing_direction, Size()).ToPhysical(rect);
  }
  const bool is_horizontal = IsHorizontalWritingMode();
  PhysicalOffset offset = PhysicalLocation();
  PhysicalRect rect(offset, is_horizontal
                                ? PhysicalSize(caret_width, caret_block_size)
                                : PhysicalSize(caret_block_size, caret_width));
  bool ltr = StyleRef().IsLeftToRightDirection();

  if ((!caret_offset) ^ ltr) {
    rect.Move(
        is_horizontal
            ? PhysicalOffset(size.inline_size - caret_width, LayoutUnit())
            : PhysicalOffset(LayoutUnit(), size.inline_size - caret_width));
  }

  // Move to local coords
  rect.Move(-offset);

  if (apply_border_padding) {
    rect.SetX(rect.X() + BorderLeft() + PaddingLeft());
    rect.SetY(rect.Y() + PaddingTop() + BorderTop());
  }

  return rect;
}

PositionWithAffinity LayoutBox::PositionForPointInFragments(
    const PhysicalOffset& target) const {
  NOT_DESTROYED();
  DCHECK_GE(GetDocument().Lifecycle().GetState(),
            DocumentLifecycle::kPrePaintClean);
  DCHECK_GT(PhysicalFragmentCount(), 0u);

  if (PhysicalFragmentCount() == 1) {
    const PhysicalBoxFragment* fragment = GetPhysicalFragment(0);
    return fragment->PositionForPoint(target);
  }

  // When |this| is block fragmented, find the closest fragment.
  const PhysicalBoxFragment* closest_fragment = nullptr;
  PhysicalOffset closest_fragment_offset;
  LayoutUnit shortest_square_distance = LayoutUnit::Max();
  for (const PhysicalBoxFragment& fragment : PhysicalFragments()) {
    // If |fragment| contains |target|, call its |PositionForPoint|.
    const PhysicalOffset fragment_offset = fragment.OffsetFromOwnerLayoutBox();
    const PhysicalSize distance =
        PhysicalRect(fragment_offset, fragment.Size()).DistanceAsSize(target);
    if (distance.IsZero())
      return fragment.PositionForPoint(target - fragment_offset);

    // Otherwise find the closest fragment.
    const LayoutUnit square_distance =
        distance.width * distance.width + distance.height * distance.height;
    if (square_distance < shortest_square_distance || !closest_fragment) {
      shortest_square_distance = square_distance;
      closest_fragment = &fragment;
      closest_fragment_offset = fragment_offset;
    }
  }
  DCHECK(closest_fragment);
  return closest_fragment->PositionForPoint(target - closest_fragment_offset);
}

DISABLE_CFI_PERF
bool LayoutBox::ShouldBeConsideredAsReplaced() const {
  NOT_DESTROYED();
  if (IsAtomicInlineLevel())
    return true;
  // We need to detect all types of objects that should be treated as replaced.
  // Callers of this method will use the result for various things, such as
  // determining how to size the object, or whether it needs to avoid adjacent
  // floats, just like objects that establish a new formatting context.
  // IsAtomicInlineLevel() will not catch all the cases. Objects may be
  // block-level and still replaced, and we cannot deduce this from the
  // LayoutObject type. Checkboxes and radio buttons are such examples. We need
  // to check the Element type. This also applies to images, since we may have
  // created a block-flow LayoutObject for the ALT text (which still counts as
  // replaced).
  auto* element = DynamicTo<Element>(GetNode());
  if (!element)
    return false;
  if (element->IsFormControlElement()) {
    // Form control elements are generally replaced objects. Fieldsets are not,
    // though. A fieldset is (almost) a regular block container, and should be
    // treated as such.
    return !IsA<HTMLFieldSetElement>(element);
  }
  return IsA<HTMLImageElement>(element);
}

// Children of LayoutCustom object's are only considered "items" when it has a
// loaded algorithm.
bool LayoutBox::IsCustomItem() const {
  NOT_DESTROYED();
  auto* parent_layout_box = DynamicTo<LayoutCustom>(Parent());
  return parent_layout_box && parent_layout_box->IsLoaded();
}

PhysicalBoxStrut LayoutBox::ComputeVisualEffectOverflowOutsets() {
  NOT_DESTROYED();
  const ComputedStyle& style = StyleRef();
  DCHECK(style.HasVisualOverflowingEffect());

  PhysicalBoxStrut outsets = style.BoxDecorationOutsets();

  if (style.HasOutline()) {
    OutlineInfo info;
    Vector<PhysicalRect> outline_rects =
        OutlineRects(&info, PhysicalOffset(),
                     style.OutlineRectsShouldIncludeBlockInkOverflow());
    PhysicalRect rect = UnionRect(outline_rects);
    bool outline_affected = rect.size != Size();
    SetOutlineMayBeAffectedByDescendants(outline_affected);
    rect.Inflate(LayoutUnit(OutlinePainter::OutlineOutsetExtent(style, info)));
    outsets.Unite(PhysicalBoxStrut(-rect.Y(), rect.Right() - Size().width,
                                   rect.Bottom() - Size().height, -rect.X()));
  }

  return outsets;
}

bool LayoutBox::HasTopOverflow() const {
  NOT_DESTROYED();
  // Early-return for the major case.
  if (IsHorizontalWritingMode()) {
    return false;
  }
  switch (StyleRef().GetWritingMode()) {
    case WritingMode::kHorizontalTb:
      return false;
    case WritingMode::kSidewaysLr:
      return StyleRef().IsLeftToRightDirection();
    case WritingMode::kVerticalLr:
    case WritingMode::kVerticalRl:
    case WritingMode::kSidewaysRl:
      return !StyleRef().IsLeftToRightDirection();
  }
}

bool LayoutBox::HasLeftOverflow() const {
  NOT_DESTROYED();
  // Early-return for the major case.
  if (IsHorizontalWritingMode()) {
    return !StyleRef().IsLeftToRightDirection();
  }
  switch (StyleRef().GetWritingMode()) {
    case WritingMode::kHorizontalTb:
      return !StyleRef().IsLeftToRightDirection();
    case WritingMode::kVerticalLr:
    case WritingMode::kSidewaysLr:
      return false;
    case WritingMode::kVerticalRl:
    case WritingMode::kSidewaysRl:
      return true;
  }
}

void LayoutBox::SetScrollableOverflowFromLayoutResults() {
  NOT_DESTROYED();
  ClearSelfNeedsScrollableOverflowRecalc();
  ClearChildNeedsScrollableOverflowRecalc();
  if (overflow_) {
    overflow_->scrollable_overflow.reset();
  }

  if (IsLayoutReplaced()) {
    return;
  }

  const WritingMode writing_mode = StyleRef().GetWritingMode();
  std::optional<PhysicalRect> scrollable_overflow;
  LayoutUnit consumed_block_size;
  LayoutUnit fragment_width_sum;

  // Iterate over all the fragments and unite their individual
  // scrollable-overflow to determine the final scrollable-overflow.
  for (const auto& layout_result : layout_results_) {
    const auto& fragment =
        To<PhysicalBoxFragment>(layout_result->GetPhysicalFragment());

    // In order to correctly unite the overflow, we need to shift an individual
    // fragment's scrollable-overflow by previously consumed block-size so far.
    PhysicalOffset offset_adjust;
    switch (writing_mode) {
      case WritingMode::kHorizontalTb:
        offset_adjust = {LayoutUnit(), consumed_block_size};
        break;
      case WritingMode::kVerticalRl:
      case WritingMode::kSidewaysRl:
        // For flipped-blocks writing-modes, we build the total overflow rect
        // from right-to-left (adding with negative offsets). At the end we
        // need to make the origin relative to the LHS, so we add the total
        // fragment width.
        fragment_width_sum += fragment.Size().width;
        offset_adjust = {-fragment.Size().width - consumed_block_size,
                         LayoutUnit()};
        break;
      case WritingMode::kVerticalLr:
      case WritingMode::kSidewaysLr:
        offset_adjust = {consumed_block_size, LayoutUnit()};
        break;
      default:
        NOTREACHED();
    }

    PhysicalRect fragment_scrollable_overflow = fragment.ScrollableOverflow();
    fragment_scrollable_overflow.offset += offset_adjust;

    // If we are the first fragment just set the scrollable-overflow.
    if (!scrollable_overflow) {
      scrollable_overflow = fragment_scrollable_overflow;
    } else {
      scrollable_overflow->UniteEvenIfEmpty(fragment_scrollable_overflow);
    }

    if (const auto* break_token = fragment.GetBreakToken()) {
      // The legacy engine doesn't understand our concept of repeated
      // fragments. Stop now. The overflow rectangle will represent the
      // fragment(s) generated under the first repeated root.
      if (break_token->IsRepeated())
        break;
      consumed_block_size = break_token->ConsumedBlockSize();
    }
  }

  if (!scrollable_overflow) {
    return;
  }

  if (IsFlippedBlocksWritingMode(writing_mode)) {
    scrollable_overflow->offset.left += fragment_width_sum;
  }

  if (scrollable_overflow->IsEmpty() ||
      PhysicalPaddingBoxRect().Contains(*scrollable_overflow)) {
    return;
  }

  DCHECK(!ScrollableOverflowIsSet());
  if (!overflow_)
    overflow_ = MakeGarbageCollected<BoxOverflowModel>();
  overflow_->scrollable_overflow.emplace(*scrollable_overflow);
}

RecalcScrollableOverflowResult LayoutBox::RecalcScrollableOverflowNG() {
  NOT_DESTROYED();

  RecalcScrollableOverflowResult child_result;
  // Don't attempt to rebuild the fragment tree or recalculate
  // scrollable-overflow, layout will do this for us.
  if (NeedsLayout())
    return RecalcScrollableOverflowResult();

  if (ChildNeedsScrollableOverflowRecalc()) {
    child_result = RecalcChildScrollableOverflowNG();
  }

  bool should_recalculate_scrollable_overflow =
      SelfNeedsScrollableOverflowRecalc() ||
      child_result.scrollable_overflow_changed;
  bool rebuild_fragment_tree = child_result.rebuild_fragment_tree;
  bool scrollable_overflow_changed = false;

  if (rebuild_fragment_tree || should_recalculate_scrollable_overflow) {
    for (auto& layout_result : layout_results_) {
      const auto& fragment =
          To<PhysicalBoxFragment>(layout_result->GetPhysicalFragment());
      std::optional<PhysicalRect> scrollable_overflow;

      // Recalculate our scrollable-overflow if a child had its
      // scrollable-overflow changed, or if we are marked as dirty.
      if (should_recalculate_scrollable_overflow) {
        const PhysicalRect old_scrollable_overflow =
            fragment.ScrollableOverflow();
        const bool has_block_fragmentation =
            layout_result->GetConstraintSpaceForCaching()
                .HasBlockFragmentation();
#if DCHECK_IS_ON()
        PhysicalBoxFragment::AllowPostLayoutScope allow_post_layout_scope;
#endif
        const PhysicalRect new_scrollable_overflow =
            ScrollableOverflowCalculator::
                RecalculateScrollableOverflowForFragment(
                    fragment, has_block_fragmentation);

        // Set the appropriate flags if the scrollable-overflow changed.
        if (old_scrollable_overflow != new_scrollable_overflow) {
          scrollable_overflow = new_scrollable_overflow;
          scrollable_overflow_changed = true;
          rebuild_fragment_tree = true;
        }
      }

      if (scrollable_overflow) {
        fragment.GetMutableForStyleRecalc().SetScrollableOverflow(
            *scrollable_overflow);
      }
    }
    SetScrollableOverflowFromLayoutResults();
  }

  if (scrollable_overflow_changed && IsScrollContainer()) {
    Layer()->GetScrollableArea()->UpdateAfterOverflowRecalc();
  }

  // Only indicate to our parent that our scrollable overflow changed if we
  // have:
  //  - No layout containment applied.
  //  - No clipping (in both axes).
  scrollable_overflow_changed = scrollable_overflow_changed &&
                                !ShouldApplyLayoutContainment() &&
                                !ShouldClipOverflowAlongBothAxis();

  return {scrollable_overflow_changed, rebuild_fragment_tree};
}

RecalcScrollableOverflowResult LayoutBox::RecalcChildScrollableOverflowNG() {
  NOT_DESTROYED();
  DCHECK(ChildNeedsScrollableOverflowRecalc());
  ClearChildNeedsScrollableOverflowRecalc();

#if DCHECK_IS_ON()
  // We use PostLayout methods to navigate the fragment tree and reach the
  // corresponding LayoutObjects, so we need to use Allo
```