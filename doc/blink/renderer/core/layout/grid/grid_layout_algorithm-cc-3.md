Response:
The user wants me to summarize the functionality of the provided C++ code snippet from `grid_layout_algorithm.cc`. This is part 4 of 6. I need to:

1. **Identify the main purpose of the code:** This involves analyzing the function names, variable names, and comments.
2. **Explain its relation to web technologies:**  Connect the C++ logic to concepts in HTML, CSS, and JavaScript if applicable. Provide concrete examples.
3. **Illustrate logical reasoning:** If the code performs calculations or conditional logic, provide hypothetical inputs and the expected outputs.
4. **Point out potential usage errors:**  Highlight common mistakes developers might make when dealing with related CSS or HTML.
5. **Synthesize the functionality:**  Provide a concise summary of what the code does.

**Analysis of the Code Snippet:**

The code primarily deals with distributing extra space among grid tracks (represented as "sets"). It has functions like:

* `GrowthPotentialForSet`: Calculates how much a grid track can grow.
* `AreEqual`: Compares floating-point numbers with tolerance.
* `DistributeExtraSpaceToSets`: The core function for distributing extra space, with a templated version for equal and weighted distribution.
* `DistributeExtraSpaceToSetsEqually`: Distributes extra space equally.
* `DistributeExtraSpaceToWeightedSets`: Distributes extra space based on flex factors.
* `IncreaseTrackSizesToAccommodateGridItems`:  Increases track sizes to fit grid items, considering their contributions.
* `ResolveIntrinsicTrackSizes`: Resolves the sizes of tracks based on the intrinsic sizes of the items within them.
* `MaximizeTracks`:  Distributes remaining free space to tracks.
* `StretchAutoTracks`: Distributes free space to auto-sized tracks.
* `ExpandFlexibleTracks`:  Handles the distribution of space to flexible tracks (`fr` units).

The code uses concepts like "base size," "growth limit," "flex factor," and "fit-content limit," which directly correspond to CSS Grid Layout properties.

**Connections to Web Technologies:**

* **CSS Grid Layout:** The entire code snippet is dedicated to the implementation of the CSS Grid Layout algorithm. Functions directly manipulate track sizes based on CSS properties.
* **`fr` unit:** The `ExpandFlexibleTracks` function specifically deals with the `fr` unit, a flexible length unit in CSS Grid.
* **`fit-content()`:** The `GrowthPotentialForSet` function mentions the `'fit-content'` argument, which is a CSS function for sizing grid tracks.
* **`min-content`, `max-content`:** The `ResolveIntrinsicTrackSizes` function uses `GridItemContributionType` enum values like `kForIntrinsicMinimums`, `kForContentBasedMinimums`, etc., which relate to the `min-content` and `max-content` keywords in CSS.
* **`justify-content`, `align-content`:** The `StretchAutoTracks` function references `Style().JustifyContent()` and `Style().AlignContent()`, demonstrating the connection to CSS properties that control the alignment of grid tracks within the container.

**Logical Reasoning and Assumptions:**

The `DistributeExtraSpaceToSets` function makes decisions based on whether the distribution is equal or weighted (using flex factors). It iterates through the "sets" (grid tracks) and calculates how much each should grow based on available space and its properties. The sorting based on `GrowthPotentialForSet` is a key logical step to ensure fair distribution up to limits.

**User/Programming Errors:**

A common mistake is to misunderstand how `fr` units work. If the content within a flexible track is larger than the space allocated by the `fr` unit, the content will overflow unless `minmax()` is used to set a minimum size. Another error is to not understand the difference between `min-content`, `max-content`, and `auto` when sizing tracks, leading to unexpected layout behavior.

**Part 4 Summary:**

This part of the `grid_layout_algorithm.cc` file focuses on the core logic for distributing available space among the tracks of a CSS Grid layout. It includes functions to calculate the growth potential of tracks and to distribute extra space either equally or based on the flex factors of the tracks. It also contains the logic for increasing track sizes to accommodate the content of grid items, handling different contribution types (minimums, maximums). The ultimate goal is to determine the final sizes of the grid tracks based on the defined CSS grid properties and the content within the grid items.
这是 `blink/renderer/core/layout/grid/grid_layout_algorithm.cc` 文件的第 4 部分，主要功能是 **在确定了 Grid 布局的初始 track 大小后，根据剩余空间和 grid item 的内容来调整 track 的大小，最终确定 track 的最终大小。**  这部分包含了处理 track 伸缩和分配剩余空间的关键算法。

以下是对其功能的详细列举和说明：

**核心功能：**

1. **`GrowthPotentialForSet`:**  计算一个 Grid Track Set（一组相邻的相同类型的 track）的增长潜力。这取决于该 Set 的类型（用于基本大小、增长限制或剩余空间）以及是否有 `fit-content` 的限制。
    * **假设输入:** 一个 `GridSet` 对象，指定 `GridItemContributionType`。
    * **输出:** `LayoutUnit` 表示该 Set 的增长潜力，如果潜力无限则返回 `kIndefiniteSize`。

2. **`DistributeExtraSpaceToSets` (模板函数)：**  核心的分配额外空间函数。它根据 `is_equal_distribution` 模板参数决定是否平均分配或根据 flex factor 加权分配额外空间给一组 Grid Track Set。
    * **与 CSS 的关系:**  这直接关联到 CSS Grid 中剩余空间的分配。如果 Grid 容器有额外的空间，这个函数负责将这些空间分配给各个 track。
    * **HTML 示例:**  一个 Grid 容器设置了 `grid-template-columns: 1fr 1fr;`，并且容器宽度大于两个 track 的内容宽度之和，那么 `DistributeExtraSpaceToSets` 会将剩余空间分配给这两个 flex track。
    * **CSS 示例:**
        ```css
        .grid-container {
          display: grid;
          grid-template-columns: 100px auto 1fr; /* 'auto' 和 'fr' 会参与空间分配 */
          width: 500px;
        }
        ```
    * **假设输入:** 额外空间 `extra_space`，flex factor 总和 `flex_factor_sum`，`GridItemContributionType`，需要增长的 Set 的指针向量 `sets_to_grow`，以及可能需要增长超出限制的 Set 的指针向量 `sets_to_grow_beyond_limit`。
    * **输出:**  修改 `sets_to_grow` 中每个 Set 的 `item_incurred_increase` 属性，表示该 Set 分配到的额外增长量。

3. **`DistributeExtraSpaceToSetsEqually`:**  一个便捷函数，调用 `DistributeExtraSpaceToSets` 并设置 `is_equal_distribution` 为 `true`，用于将额外空间平均分配给 track。
    * **与 CSS 的关系:**  这对应于没有 flex track 或者需要平均分配剩余空间的情况。例如，如果所有 track 的大小都是像素值，那么剩余空间会被平均分配（取决于 `justify-content` 和 `align-content` 的设置）。

4. **`DistributeExtraSpaceToWeightedSets`:**  另一个便捷函数，调用 `DistributeExtraSpaceToSets` 并设置 `is_equal_distribution` 为 `false`，用于根据 flex factor ( `fr` 单位) 的比例分配额外空间。
    * **与 CSS 的关系:**  这直接对应于 CSS Grid 中使用 `fr` 单位来定义 track 大小的情况。
    * **HTML 示例:**  一个 Grid 容器设置了 `grid-template-columns: 1fr 2fr;`，剩余空间会按照 1:2 的比例分配给这两个 track。

5. **`IncreaseTrackSizesToAccommodateGridItems`:**  核心函数，用于根据 Grid Item 的大小来增加 Track 的大小。它会遍历 Grid Item，计算它们对 Track 的贡献，并使用 `DistributeExtraSpaceToSets` 来分配所需的额外空间。
    * **与 CSS 的关系:** 这反映了 Grid Item 内容影响 Track 大小的机制。例如，一个内容很长的 Item 会导致其所在的 Track 变大。
    * **假设输入:** 一组 Grid Item 的迭代器范围，`GridSizingSubtree`，是否跨越 flex track 的标志，尺寸约束，`GridItemContributionType`，以及 `GridSizingTrackCollection` 对象。
    * **输出:**  修改 `track_collection` 中相关 Track Set 的 `planned_increase` 和实际大小，以容纳 Grid Item。

6. **`ResolveIntrinsicTrackSizes`:**  解决 Grid 布局中 intrinsic track 大小的问题。它会考虑 Grid Item 的最小和最大内容尺寸，以及它们如何影响 Track 的大小。
    * **与 CSS 的关系:**  这与 CSS Grid 中使用 `min-content`、`max-content` 和 `auto` 关键字定义 track 大小有关。
    * **用户常见错误:**  不理解 `min-content` 和 `max-content` 的区别，导致布局尺寸不符合预期。例如，一个 track 被设置为 `min-content`，但其包含的文本很长且不允许换行，可能会导致内容溢出。
    * **编程常见错误:**  在 JavaScript 中动态改变 Grid Item 的内容，而没有重新触发布局计算，可能导致布局不更新。
    * **假设输入:** `GridSizingSubtree`，track 方向，尺寸约束。
    * **输出:**  更新 `track_collection` 中 Track 的大小，使其能够容纳 Grid Item 的 intrinsic 大小。

7. **`MaximizeTracks`:**  在所有 intrinsic 大小都确定后，将剩余的自由空间分配给 Track，使其尽可能填充 Grid 容器。
    * **与 CSS 的关系:**  这对应于 `justify-content: stretch` 和 `align-content: stretch` 的默认行为，或者当剩余空间没有被其他对齐方式使用时。
    * **假设输入:** 尺寸约束，`GridSizingTrackCollection` 对象。
    * **输出:**  增加 `track_collection` 中 Track 的基本大小，以填充剩余空间。

8. **`StretchAutoTracks`:**  将剩余的自由空间分配给 `max-width/height: auto` 的 Track。
    * **与 CSS 的关系:**  当 track 的最大尺寸设置为 `auto` 时，它们会尝试填充剩余空间。这与 `justify-content` 和 `align-content` 的 `stretch` 值相关。
    * **用户常见错误:**  误以为设置了 `width: auto` 的 Grid Item 会像 block 元素一样填充其所在的 track，但实际上 Grid Track 的 `auto` 大小取决于其内容和剩余空间。

9. **`ExpandFlexibleTracks`:**  处理 flex track (使用 `fr` 单位定义的 track) 的扩展。它会计算 `fr` 单位的大小，并根据 flex factor 分配剩余空间。
    * **与 CSS 的关系:**  这是 CSS Grid 布局中 `fr` 单位的核心实现逻辑。
    * **用户常见错误:**  不理解 `fr` 单位是如何分配剩余空间的，导致在不同屏幕尺寸下布局表现不一致。 例如，如果只设置了 `grid-template-columns: 1fr;`，那么这个 track 会占用所有可用的水平空间。

**功能归纳：**

这部分代码实现了 CSS Grid 布局算法中 **调整和扩展 track 大小** 的关键步骤。它负责：

* **根据 Grid Item 的内容，增加 Track 的大小以容纳内容。**
* **将 Grid 容器的剩余空间分配给 Track，包括平均分配和根据 flex factor 加权分配。**
* **处理 `auto` 大小的 Track 的伸缩。**
* **计算和应用 `fr` 单位的大小。**

总而言之，这部分代码确保了 Grid 布局能够根据内容和可用空间，正确地计算和设置每个 Track 的最终大小，从而实现灵活且强大的布局功能。

### 提示词
```
这是目录为blink/renderer/core/layout/grid/grid_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
' until it reaches the limit specified as the 'fit-content'
      // argument, after which it is treated as having a fixed sizing function
      // of that argument (with a growth potential of zero).
      if (set.fit_content_limit != kIndefiniteSize) {
        LayoutUnit growth_potential = set.fit_content_limit -
                                      DefiniteGrowthLimit(set) -
                                      set.item_incurred_increase;
        return growth_potential.ClampNegativeToZero();
      }
      // Otherwise, this set has infinite growth potential.
      return kIndefiniteSize;
    }
    case GridItemContributionType::kForFreeSpace: {
      LayoutUnit growth_limit = set.GrowthLimit();
      DCHECK_NE(growth_limit, kIndefiniteSize);
      return growth_limit - set.BaseSize();
    }
  }
}

template <typename T>
bool AreEqual(T a, T b) {
  return a == b;
}

template <>
bool AreEqual<float>(float a, float b) {
  return std::abs(a - b) < kFloatEpsilon;
}

// Follow the definitions from https://drafts.csswg.org/css-grid-2/#extra-space;
// notice that this method replaces the notion of "tracks" with "sets".
template <bool is_equal_distribution>
void DistributeExtraSpaceToSets(LayoutUnit extra_space,
                                float flex_factor_sum,
                                GridItemContributionType contribution_type,
                                GridSetPtrVector* sets_to_grow,
                                GridSetPtrVector* sets_to_grow_beyond_limit) {
  DCHECK(extra_space && sets_to_grow);

  if (extra_space == kIndefiniteSize) {
    // Infinite extra space should only happen when distributing free space at
    // the maximize tracks step; in such case, we can simplify this method by
    // "filling" every track base size up to their growth limit.
    DCHECK_EQ(contribution_type, GridItemContributionType::kForFreeSpace);
    for (auto* set : *sets_to_grow) {
      set->item_incurred_increase =
          GrowthPotentialForSet(*set, contribution_type);
    }
    return;
  }

  DCHECK_GT(extra_space, 0);
#if DCHECK_IS_ON()
  if (IsDistributionForGrowthLimits(contribution_type))
    DCHECK_EQ(sets_to_grow, sets_to_grow_beyond_limit);
#endif

  wtf_size_t growable_track_count = 0;
  for (auto* set : *sets_to_grow) {
    set->item_incurred_increase = LayoutUnit();

    // From the first note in https://drafts.csswg.org/css-grid-2/#extra-space:
    //   If the affected size was a growth limit and the track is not marked
    //   "infinitely growable", then each item-incurred increase will be zero.
    //
    // When distributing space to growth limits, we need to increase each track
    // up to its 'fit-content' limit. However, because of the note above, first
    // we should only grow tracks marked as "infinitely growable" up to limits
    // and then grow all affected tracks beyond limits.
    //
    // We can correctly resolve every scenario by doing a single sort of
    // |sets_to_grow|, purposely ignoring the "infinitely growable" flag, then
    // filtering out sets that won't take a share of the extra space at each
    // step; for base sizes this is not required, but if there are no tracks
    // with growth potential > 0, we can optimize by not sorting the sets.
    if (GrowthPotentialForSet(*set, contribution_type))
      growable_track_count += set->track_count;
  }

  using ShareRatioType =
      typename std::conditional<is_equal_distribution, wtf_size_t, float>::type;
  DCHECK(is_equal_distribution ||
         !AreEqual<ShareRatioType>(flex_factor_sum, 0));
  ShareRatioType share_ratio_sum =
      is_equal_distribution ? growable_track_count : flex_factor_sum;
  const bool is_flex_factor_sum_overflowing_limits =
      share_ratio_sum >= std::numeric_limits<wtf_size_t>::max();

  // We will sort the tracks by growth potential in non-decreasing order to
  // distribute space up to limits; notice that if we start distributing space
  // equally among all tracks we will eventually reach the limit of a track or
  // run out of space to distribute. If the former scenario happens, it should
  // be easy to see that the group of tracks that will reach its limit first
  // will be that with the least growth potential. Otherwise, if tracks in such
  // group does not reach their limit, every upcoming track with greater growth
  // potential must be able to increase its size by the same amount.
  if (growable_track_count ||
      IsDistributionForGrowthLimits(contribution_type)) {
    auto CompareSetsByGrowthPotential =
        [contribution_type](const GridSet* lhs, const GridSet* rhs) {
          auto growth_potential_lhs = GrowthPotentialForSet(
              *lhs, contribution_type, InfinitelyGrowableBehavior::kIgnore);
          auto growth_potential_rhs = GrowthPotentialForSet(
              *rhs, contribution_type, InfinitelyGrowableBehavior::kIgnore);

          if (growth_potential_lhs == kIndefiniteSize ||
              growth_potential_rhs == kIndefiniteSize) {
            // At this point we know that there is at least one set with
            // infinite growth potential; if |a| has a definite value, then |b|
            // must have infinite growth potential, and thus, |a| < |b|.
            return growth_potential_lhs != kIndefiniteSize;
          }
          // Straightforward comparison of definite growth potentials.
          return growth_potential_lhs < growth_potential_rhs;
        };

    // Only sort for equal distributions; since the growth potential of any
    // flexible set is infinite, they don't require comparing.
    if (AreEqual<float>(flex_factor_sum, 0)) {
      DCHECK(is_equal_distribution);
      std::sort(sets_to_grow->begin(), sets_to_grow->end(),
                CompareSetsByGrowthPotential);
    }
  }

  auto ExtraSpaceShare = [&](const GridSet& set,
                             LayoutUnit growth_potential) -> LayoutUnit {
    DCHECK(growth_potential >= 0 || growth_potential == kIndefiniteSize);

    // If this set won't take a share of the extra space, e.g. has zero growth
    // potential, exit so that this set is filtered out of |share_ratio_sum|.
    if (!growth_potential)
      return LayoutUnit();

    wtf_size_t set_track_count = set.track_count;
    DCHECK_LE(set_track_count, growable_track_count);

    ShareRatioType set_share_ratio =
        is_equal_distribution ? set_track_count : set.FlexFactor();

    // Since |share_ratio_sum| can be greater than the wtf_size_t limit, cap the
    // value of |set_share_ratio| to prevent overflows.
    if (set_share_ratio > share_ratio_sum) {
      DCHECK(is_flex_factor_sum_overflowing_limits);
      set_share_ratio = share_ratio_sum;
    }

    LayoutUnit extra_space_share;
    if (AreEqual(set_share_ratio, share_ratio_sum)) {
      // If this set's share ratio and the remaining ratio sum are the same, it
      // means that this set will receive all of the remaining space. Hence, we
      // can optimize a little by directly using the extra space as this set's
      // share and break early by decreasing the remaining growable track count
      // to 0 (even if there are further growable tracks, since the share ratio
      // sum will be reduced to 0, their space share will also be 0).
      set_track_count = growable_track_count;
      extra_space_share = extra_space;
    } else {
      DCHECK(!AreEqual<ShareRatioType>(share_ratio_sum, 0));
      DCHECK_LT(set_share_ratio, share_ratio_sum);

      extra_space_share = LayoutUnit::FromRawValue(
          (extra_space.RawValue() * set_share_ratio) / share_ratio_sum);
    }

    if (growth_potential != kIndefiniteSize)
      extra_space_share = std::min(extra_space_share, growth_potential);
    DCHECK_LE(extra_space_share, extra_space);

    growable_track_count -= set_track_count;
    share_ratio_sum -= set_share_ratio;
    extra_space -= extra_space_share;
    return extra_space_share;
  };

  // Distribute space up to limits:
  //   - For base sizes, grow the base size up to the growth limit.
  //   - For growth limits, the only case where a growth limit should grow at
  //   this step is when its set has already been marked "infinitely growable".
  //   Increase the growth limit up to the 'fit-content' argument (if any); note
  //   that these arguments could prevent this step to fulfill the entirety of
  //   the extra space and further distribution would be needed.
  for (auto* set : *sets_to_grow) {
    // Break early if there are no further tracks to grow.
    if (!growable_track_count)
      break;
    set->item_incurred_increase =
        ExtraSpaceShare(*set, GrowthPotentialForSet(*set, contribution_type));
  }

  // Distribute space beyond limits:
  //   - For base sizes, every affected track can grow indefinitely.
  //   - For growth limits, grow tracks up to their 'fit-content' argument.
  if (sets_to_grow_beyond_limit && extra_space) {
#if DCHECK_IS_ON()
    // We expect |sets_to_grow_beyond_limit| to be ordered by growth potential
    // for the following section of the algorithm to work.
    //
    // For base sizes, since going beyond limits should only happen after we
    // grow every track up to their growth limits, it should be easy to see that
    // every growth potential is now zero, so they're already ordered.
    //
    // Now let's consider growth limits: we forced the sets to be sorted by
    // growth potential ignoring the "infinitely growable" flag, meaning that
    // ultimately they will be sorted by remaining space to their 'fit-content'
    // parameter (if it exists, infinite otherwise). If we ended up here, we
    // must have filled the sets marked as "infinitely growable" up to their
    // 'fit-content' parameter; therefore, if we only consider sets with
    // remaining space to their 'fit-content' limit in the following
    // distribution step, they should still be ordered.
    LayoutUnit previous_growable_potential;
    for (auto* set : *sets_to_grow_beyond_limit) {
      LayoutUnit growth_potential = GrowthPotentialForSet(
          *set, contribution_type, InfinitelyGrowableBehavior::kIgnore);
      if (growth_potential) {
        if (previous_growable_potential == kIndefiniteSize) {
          DCHECK_EQ(growth_potential, kIndefiniteSize);
        } else {
          DCHECK(growth_potential >= previous_growable_potential ||
                 growth_potential == kIndefiniteSize);
        }
        previous_growable_potential = growth_potential;
      }
    }
#endif

    auto BeyondLimitsGrowthPotential =
        [contribution_type](const GridSet& set) -> LayoutUnit {
      // For growth limits, ignore the "infinitely growable" flag and grow all
      // affected tracks up to their 'fit-content' argument (note that
      // |GrowthPotentialForSet| already accounts for it).
      return !IsDistributionForGrowthLimits(contribution_type)
                 ? kIndefiniteSize
                 : GrowthPotentialForSet(set, contribution_type,
                                         InfinitelyGrowableBehavior::kIgnore);
    };

    // If we reached this point, we must have exhausted every growable track up
    // to their limits, meaning |growable_track_count| should be 0 and we need
    // to recompute it considering their 'fit-content' limits instead.
    DCHECK_EQ(growable_track_count, 0u);

    for (auto* set : *sets_to_grow_beyond_limit) {
      if (BeyondLimitsGrowthPotential(*set))
        growable_track_count += set->track_count;
    }

    // In |IncreaseTrackSizesToAccommodateGridItems| we guaranteed that, when
    // dealing with flexible tracks, there shouldn't be any set to grow beyond
    // limits. Thus, the only way to reach the section below is when we are
    // distributing space equally among sets.
    DCHECK(is_equal_distribution);
    share_ratio_sum = growable_track_count;

    for (auto* set : *sets_to_grow_beyond_limit) {
      // Break early if there are no further tracks to grow.
      if (!growable_track_count)
        break;
      set->item_incurred_increase +=
          ExtraSpaceShare(*set, BeyondLimitsGrowthPotential(*set));
    }
  }
}

void DistributeExtraSpaceToSetsEqually(
    LayoutUnit extra_space,
    GridItemContributionType contribution_type,
    GridSetPtrVector* sets_to_grow,
    GridSetPtrVector* sets_to_grow_beyond_limit = nullptr) {
  DistributeExtraSpaceToSets</* is_equal_distribution */ true>(
      extra_space, /* flex_factor_sum */ 0, contribution_type, sets_to_grow,
      sets_to_grow_beyond_limit);
}

void DistributeExtraSpaceToWeightedSets(
    LayoutUnit extra_space,
    float flex_factor_sum,
    GridItemContributionType contribution_type,
    GridSetPtrVector* sets_to_grow) {
  DistributeExtraSpaceToSets</* is_equal_distribution */ false>(
      extra_space, flex_factor_sum, contribution_type, sets_to_grow,
      /* sets_to_grow_beyond_limit */ nullptr);
}

}  // namespace

void GridLayoutAlgorithm::IncreaseTrackSizesToAccommodateGridItems(
    GridItemDataPtrVector::iterator group_begin,
    GridItemDataPtrVector::iterator group_end,
    const GridSizingSubtree& sizing_subtree,
    bool is_group_spanning_flex_track,
    SizingConstraint sizing_constraint,
    GridItemContributionType contribution_type,
    GridSizingTrackCollection* track_collection) const {
  DCHECK(track_collection);
  const auto track_direction = track_collection->Direction();

  for (auto set_iterator = track_collection->GetSetIterator();
       !set_iterator.IsAtEnd(); set_iterator.MoveToNextSet()) {
    set_iterator.CurrentSet().planned_increase = kIndefiniteSize;
  }

  GridSetPtrVector sets_to_grow;
  GridSetPtrVector sets_to_grow_beyond_limit;

  while (group_begin != group_end) {
    GridItemData& grid_item = **(group_begin++);
    DCHECK(grid_item.IsSpanningIntrinsicTrack(track_direction));

    sets_to_grow.Shrink(0);
    sets_to_grow_beyond_limit.Shrink(0);

    ClampedFloat flex_factor_sum = 0;
    LayoutUnit spanned_tracks_size = track_collection->GutterSize() *
                                     (grid_item.SpanSize(track_direction) - 1);
    for (auto set_iterator =
             GetSetIteratorForItem(grid_item, *track_collection);
         !set_iterator.IsAtEnd(); set_iterator.MoveToNextSet()) {
      auto& current_set = set_iterator.CurrentSet();

      spanned_tracks_size +=
          AffectedSizeForContribution(current_set, contribution_type);

      if (is_group_spanning_flex_track &&
          !current_set.track_size.HasFlexMaxTrackBreadth()) {
        // From https://drafts.csswg.org/css-grid-2/#algo-spanning-flex-items:
        //   Distributing space only to flexible tracks (i.e. treating all other
        //   tracks as having a fixed sizing function).
        continue;
      }

      if (IsContributionAppliedToSet(current_set, contribution_type)) {
        if (current_set.planned_increase == kIndefiniteSize)
          current_set.planned_increase = LayoutUnit();

        if (is_group_spanning_flex_track)
          flex_factor_sum += current_set.FlexFactor();

        sets_to_grow.push_back(&current_set);
        if (ShouldUsedSizeGrowBeyondLimit(current_set, contribution_type))
          sets_to_grow_beyond_limit.push_back(&current_set);
      }
    }

    if (sets_to_grow.empty())
      continue;

    // Subtract the corresponding size (base size or growth limit) of every
    // spanned track from the grid item's size contribution to find the item's
    // remaining size contribution. For infinite growth limits, substitute with
    // the track's base size. This is the space to distribute, floor it at zero.
    LayoutUnit extra_space = ContributionSizeForGridItem(
        sizing_subtree, contribution_type, track_direction, sizing_constraint,
        &grid_item);
    extra_space = (extra_space - spanned_tracks_size).ClampNegativeToZero();

    if (!extra_space)
      continue;

    // From https://drafts.csswg.org/css-grid-2/#algo-spanning-flex-items:
    //   If the sum of the flexible sizing functions of all flexible tracks
    //   spanned by the item is greater than zero, distributing space to such
    //   tracks according to the ratios of their flexible sizing functions
    //   rather than distributing space equally.
    if (!is_group_spanning_flex_track || AreEqual<float>(flex_factor_sum, 0)) {
      DistributeExtraSpaceToSetsEqually(
          extra_space, contribution_type, &sets_to_grow,
          sets_to_grow_beyond_limit.empty() ? &sets_to_grow
                                            : &sets_to_grow_beyond_limit);
    } else {
      // 'fr' units are only allowed as a maximum in track definitions, meaning
      // that no set has an intrinsic max track sizing function that would allow
      // it to grow beyond limits (see |ShouldUsedSizeGrowBeyondLimit|).
      DCHECK(sets_to_grow_beyond_limit.empty());
      DistributeExtraSpaceToWeightedSets(extra_space, flex_factor_sum,
                                         contribution_type, &sets_to_grow);
    }

    // For each affected track, if the track's item-incurred increase is larger
    // than its planned increase, set the planned increase to that value.
    for (auto* set : sets_to_grow) {
      DCHECK_NE(set->item_incurred_increase, kIndefiniteSize);
      DCHECK_NE(set->planned_increase, kIndefiniteSize);
      set->planned_increase =
          std::max(set->item_incurred_increase, set->planned_increase);
    }
  }

  for (auto set_iterator = track_collection->GetSetIterator();
       !set_iterator.IsAtEnd(); set_iterator.MoveToNextSet()) {
    GrowAffectedSizeByPlannedIncrease(contribution_type,
                                      &set_iterator.CurrentSet());
  }
}

// https://drafts.csswg.org/css-grid-2/#algo-content
void GridLayoutAlgorithm::ResolveIntrinsicTrackSizes(
    const GridSizingSubtree& sizing_subtree,
    GridTrackSizingDirection track_direction,
    SizingConstraint sizing_constraint) const {
  auto& grid_items = sizing_subtree.GetGridItems();
  auto& track_collection = sizing_subtree.SizingCollection(track_direction);

  GridItemDataPtrVector reordered_grid_items;
  reordered_grid_items.ReserveInitialCapacity(grid_items.Size());

  for (auto& grid_item : grid_items.IncludeSubgriddedItems()) {
    if (!grid_item.IsSpanningIntrinsicTrack(track_direction)) {
      continue;
    }

    if (grid_item.MustConsiderGridItemsForSizing(track_direction)) {
      // A subgrid should accommodate its extra margins in the subgridded axis
      // since it might not have children on its edges to account for them.
      DCHECK(grid_item.IsSubgrid());

      const bool is_for_columns_in_subgrid =
          RelativeDirectionInSubgrid(track_direction, grid_item) == kForColumns;

      const auto& subgrid_layout_data =
          sizing_subtree.SubgridSizingSubtree(grid_item).LayoutData();
      const auto& subgrid_track_collection = is_for_columns_in_subgrid
                                                 ? subgrid_layout_data.Columns()
                                                 : subgrid_layout_data.Rows();

      auto start_extra_margin = subgrid_track_collection.StartExtraMargin();
      auto end_extra_margin = subgrid_track_collection.EndExtraMargin();

      if (grid_item.IsOppositeDirectionInRootGrid(track_direction)) {
        std::swap(start_extra_margin, end_extra_margin);
      }

      AccomodateSubgridExtraMargins(start_extra_margin, end_extra_margin,
                                    grid_item.SetIndices(track_direction),
                                    &track_collection);

    } else if (grid_item.IsConsideredForSizing(track_direction)) {
      reordered_grid_items.emplace_back(&grid_item);
    }
  }

  // Reorder grid items to process them as follows:
  //   - First, consider items spanning a single non-flexible track.
  //   - Next, consider items with span size of 2 not spanning a flexible track.
  //   - Repeat incrementally for items with greater span sizes until all items
  //   not spanning a flexible track have been considered.
  //   - Finally, consider all items spanning a flexible track.
  auto CompareGridItemsForIntrinsicTrackResolution =
      [track_direction](GridItemData* lhs, GridItemData* rhs) -> bool {
    if (lhs->IsSpanningFlexibleTrack(track_direction) ||
        rhs->IsSpanningFlexibleTrack(track_direction)) {
      // Ignore span sizes if one of the items spans a track with a flexible
      // sizing function; items not spanning such tracks should come first.
      return !lhs->IsSpanningFlexibleTrack(track_direction);
    }
    return lhs->SpanSize(track_direction) < rhs->SpanSize(track_direction);
  };
  std::sort(reordered_grid_items.begin(), reordered_grid_items.end(),
            CompareGridItemsForIntrinsicTrackResolution);

  auto current_group_begin = reordered_grid_items.begin();

  // First, process the items that don't span a flexible track.
  while (current_group_begin != reordered_grid_items.end() &&
         !(*current_group_begin)->IsSpanningFlexibleTrack(track_direction)) {
    // Each iteration considers all items with the same span size.
    wtf_size_t current_group_span_size =
        (*current_group_begin)->SpanSize(track_direction);

    auto current_group_end = current_group_begin;
    do {
      DCHECK(!(*current_group_end)->IsSpanningFlexibleTrack(track_direction));
      ++current_group_end;
    } while (current_group_end != reordered_grid_items.end() &&
             !(*current_group_end)->IsSpanningFlexibleTrack(track_direction) &&
             (*current_group_end)->SpanSize(track_direction) ==
                 current_group_span_size);

    IncreaseTrackSizesToAccommodateGridItems(
        current_group_begin, current_group_end, sizing_subtree,
        /* is_group_spanning_flex_track */ false, sizing_constraint,
        GridItemContributionType::kForIntrinsicMinimums, &track_collection);
    IncreaseTrackSizesToAccommodateGridItems(
        current_group_begin, current_group_end, sizing_subtree,
        /* is_group_spanning_flex_track */ false, sizing_constraint,
        GridItemContributionType::kForContentBasedMinimums, &track_collection);
    IncreaseTrackSizesToAccommodateGridItems(
        current_group_begin, current_group_end, sizing_subtree,
        /* is_group_spanning_flex_track */ false, sizing_constraint,
        GridItemContributionType::kForMaxContentMinimums, &track_collection);
    IncreaseTrackSizesToAccommodateGridItems(
        current_group_begin, current_group_end, sizing_subtree,
        /* is_group_spanning_flex_track */ false, sizing_constraint,
        GridItemContributionType::kForIntrinsicMaximums, &track_collection);
    IncreaseTrackSizesToAccommodateGridItems(
        current_group_begin, current_group_end, sizing_subtree,
        /* is_group_spanning_flex_track */ false, sizing_constraint,
        GridItemContributionType::kForMaxContentMaximums, &track_collection);

    // Move to the next group with greater span size.
    current_group_begin = current_group_end;
  }

  // From https://drafts.csswg.org/css-grid-2/#algo-spanning-flex-items:
  //   Increase sizes to accommodate spanning items crossing flexible tracks:
  //   Next, repeat the previous step instead considering (together, rather than
  //   grouped by span size) all items that do span a track with a flexible
  //   sizing function...
#if DCHECK_IS_ON()
  // Every grid item of the remaining group should span a flexible track.
  for (auto it = current_group_begin; it != reordered_grid_items.end(); ++it) {
    DCHECK((*it)->IsSpanningFlexibleTrack(track_direction));
  }
#endif

  // Now, process items spanning flexible tracks (if any).
  if (current_group_begin != reordered_grid_items.end()) {
    // We can safely skip contributions for maximums since a <flex> definition
    // does not have an intrinsic max track sizing function.
    IncreaseTrackSizesToAccommodateGridItems(
        current_group_begin, reordered_grid_items.end(), sizing_subtree,
        /* is_group_spanning_flex_track */ true, sizing_constraint,
        GridItemContributionType::kForIntrinsicMinimums, &track_collection);
    IncreaseTrackSizesToAccommodateGridItems(
        current_group_begin, reordered_grid_items.end(), sizing_subtree,
        /* is_group_spanning_flex_track */ true, sizing_constraint,
        GridItemContributionType::kForContentBasedMinimums, &track_collection);
    IncreaseTrackSizesToAccommodateGridItems(
        current_group_begin, reordered_grid_items.end(), sizing_subtree,
        /* is_group_spanning_flex_track */ true, sizing_constraint,
        GridItemContributionType::kForMaxContentMinimums, &track_collection);
  }
}

// https://drafts.csswg.org/css-grid-2/#algo-grow-tracks
void GridLayoutAlgorithm::MaximizeTracks(
    SizingConstraint sizing_constraint,
    GridSizingTrackCollection* track_collection) const {
  const LayoutUnit free_space =
      DetermineFreeSpace(sizing_constraint, *track_collection);
  if (!free_space)
    return;

  GridSetPtrVector sets_to_grow;
  sets_to_grow.ReserveInitialCapacity(track_collection->GetSetCount());
  for (auto set_iterator = track_collection->GetSetIterator();
       !set_iterator.IsAtEnd(); set_iterator.MoveToNextSet()) {
    sets_to_grow.push_back(&set_iterator.CurrentSet());
  }

  DistributeExtraSpaceToSetsEqually(
      free_space, GridItemContributionType::kForFreeSpace, &sets_to_grow);

  for (auto* set : sets_to_grow)
    set->IncreaseBaseSize(set->BaseSize() + set->item_incurred_increase);

  // TODO(ethavar): If this would cause the grid to be larger than the grid
  // container’s inner size as limited by its 'max-width/height', then redo this
  // step, treating the available grid space as equal to the grid container’s
  // inner size when it’s sized to its 'max-width/height'.
}

// https://drafts.csswg.org/css-grid-2/#algo-stretch
void GridLayoutAlgorithm::StretchAutoTracks(
    SizingConstraint sizing_constraint,
    GridSizingTrackCollection* track_collection) const {
  const auto track_direction = track_collection->Direction();

  // Stretching auto tracks should only occur if we have a "stretch" (or
  // default) content distribution.
  const auto& content_alignment = (track_direction == kForColumns)
                                      ? Style().JustifyContent()
                                      : Style().AlignContent();

  if (content_alignment.Distribution() != ContentDistributionType::kStretch &&
      (content_alignment.Distribution() != ContentDistributionType::kDefault ||
       content_alignment.GetPosition() != ContentPosition::kNormal)) {
    return;
  }

  // Expand tracks that have an 'auto' max track sizing function by dividing any
  // remaining positive, definite free space equally amongst them.
  GridSetPtrVector sets_to_grow;
  for (auto set_iterator = track_collection->GetSetIterator();
       !set_iterator.IsAtEnd(); set_iterator.MoveToNextSet()) {
    auto& set = set_iterator.CurrentSet();
    if (set.track_size.HasAutoMaxTrackBreadth() &&
        !set.track_size.IsFitContent()) {
      sets_to_grow.push_back(&set);
    }
  }

  if (sets_to_grow.empty())
    return;

  LayoutUnit free_space =
      DetermineFreeSpace(sizing_constraint, *track_collection);

  // If the free space is indefinite, but the grid container has a definite
  // min-width/height, use that size to calculate the free space for this step
  // instead.
  if (free_space == kIndefiniteSize) {
    free_space = (track_direction == kForColumns)
                     ? grid_min_available_size_.inline_size
                     : grid_min_available_size_.block_size;

    DCHECK_NE(free_space, kIndefiniteSize);
    free_space -= track_collection->TotalTrackSize();
  }

  if (free_space <= 0)
    return;

  DistributeExtraSpaceToSetsEqually(free_space,
                                    GridItemContributionType::kForFreeSpace,
                                    &sets_to_grow, &sets_to_grow);
  for (auto* set : sets_to_grow)
    set->IncreaseBaseSize(set->BaseSize() + set->item_incurred_increase);
}

// https://drafts.csswg.org/css-grid-2/#algo-flex-tracks
void GridLayoutAlgorithm::ExpandFlexibleTracks(
    const GridSizingSubtree& sizing_subtree,
    GridTrackSizingDirection track_direction,
    SizingConstraint sizing_constraint) const {
  auto& track_collection = sizing_subtree.SizingCollection(track_direction);
  const LayoutUnit free_space =
      DetermineFreeSpace(sizing_constraint, track_collection);

  // If the free space is zero or if sizing the grid container under a
  // min-content constraint, the used flex fraction is zero.
  if (!free_space)
    return;

  // https://drafts.csswg.org/css-grid-2/#algo-find-fr-size
  GridSetPtrVector flexible_sets;
  auto FindFrSize = [&](SetIterator set_iterator,
                        LayoutUnit leftover_space) -> float {
    ClampedFloat flex_factor_sum = 0;
    wtf_size_t total_track_count = 0;
    flexible_sets.Shrink(0);

    while (!set_iterator.IsAtEnd()) {
      auto& set = set_iterator.CurrentSet();
      if (set.track_size.HasFlexMaxTrackBreadth() &&
          !AreEqual<float>(set.FlexFactor(), 0)) {
        flex_factor_sum += set.FlexFactor();
        flexible_sets.push_back(&set);
      } else {
        leftover_space -= set.BaseSize();
      }
      total_track_count += set.track_count;
      set_iterator.MoveToNextSet();
    }

    // Remove the gutters between spanned tracks.
    leftover_space -= track_collection.GutterSize() * (total_track_count - 1);

    if (leftover_space < 0 || flexible_sets.empty())
      return 0;

    // From css-grid-2 spec: "If the product of the hypothetical fr size and
    // a flexible track’s flex factor is less than the track’s base size,
    // restart this algorithm treating all such tracks as inflexible."
    //
    // We will process the same algorithm a bit different; since we define the
    // hypothetical fr size as the leftover space divided by the flex factor
    // sum, we can reinterpret the statement above as follows:
    //
    //   (leftover space / flex factor sum) * flexible set's flex factor <
    //       flexible set's base size
    //
    // Reordering the terms of such expression we get:
    //
    //   leftover space / flex factor sum <
    //       flexible set's base size / flexible set's flex factor
    //
    // The term on the right is constant for every flexible set, while the term
    // on the left changes whenever we restart the algorithm treating some of
    // those sets as inflexible. Note that, if the expression above is false for
    // a given set, any other set with a lesser (base size / flex factor) ratio
    // will also fail such expression.
    //
    // Based on this observation, we can process the sets in non-increasing
    // ratio, when the current set does not fulfill the expression, no further
    // set will fulfill it either (and we can return the hypothetical fr size).
    // Otherwise, determine which sets should be treated as inflexible, exclude
    // them from the leftover space and flex factor sum computation, and keep
    // checking the condition for sets with lesser ratios.
    auto CompareSetsByBaseSizeFlexFactorRatio = [](GridSet* lhs,
                                                   GridSet* rhs) -> bool {
      // Avoid divisions by reordering the terms of the comparison.
      return lhs->BaseSize().RawValue() * rhs->FlexFactor() >
             rhs->BaseSize().RawValue() * lhs->FlexFactor();
    };
    std::sort(flexible_sets.begin(), flexible_sets.end(),
              CompareSetsByBaseSizeFlexFactorRatio);

    auto current_set = flexible_sets.begin();
    while (leftover_space > 0 && current_set != flexible_sets.end()) {
      flex_factor_sum = base::ClampMax(flex_factor_sum, 1);

      auto next_set = current_set;
      while (next_set != flexible_sets.end() &&
             (*next_set)->FlexFactor() * leftover_space.RawValue() <
                 (*next_set)->BaseSize().RawValue() * flex_factor_sum) {
        ++next_set;
      }

      // Any upcoming flexible set will receive a share of free space of at
      // least their base size; return the current hypothetical fr size.
      if (current_set == next_set) {
        DCHECK(!AreEqual<float>(flex_factor_sum, 0));
        return leftover_space.RawValue() / flex_factor_sum;
      }

      // Otherwise, treat all those sets that does not receive a share of free
      // space of at least their base size as inflexible, effectively excluding
      // them from the leftover space and flex factor sum computation.
      for (auto it = current_set; it != next_set; ++it) {
        flex_factor_sum -= (*it)->FlexFactor();
        leftover_space -= (*it)->BaseSize();
      }
      current_set = next_set;
    }
    return 0;
  };

  float fr_size = 0;
  if (free_space != kIndefiniteSize) {
    // Otherwise, if the
```