Response:
The user wants a summary of the C++ source code file `grid_track_collection.cc`. I need to identify the main functionalities provided by this file. It seems to deal with the layout of grid tracks in the Blink rendering engine. I should focus on the classes and their methods, and highlight any connections to CSS grid layout concepts.

**Plan:**

1. Identify the main classes: `GridTrackCollectionBase`, `GridRange`, `GridRangeBuilder`, `GridSet`, `GridLayoutTrackCollection`.
2. For each class, list its purpose and key methods.
3. Analyze the relationships between the classes.
4. Connect the functionalities to CSS grid concepts like grid lines, tracks, repeaters, subgrids, etc.
5. Look for examples of how these functionalities might be used in rendering.
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/grid/grid_track_collection.h"

#include "base/check.h"
#include "third_party/blink/renderer/core/layout/grid/grid_line_resolver.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"

namespace blink {

struct SameSizeAsGridRange {
  wtf_size_t members[6];
  wtf_size_t bitfields;
};

ASSERT_SIZE(GridRange, SameSizeAsGridRange);

wtf_size_t GridTrackCollectionBase::RangeEndLine(wtf_size_t range_index) const {
  return RangeStartLine(range_index) + RangeTrackCount(range_index);
}

wtf_size_t GridTrackCollectionBase::RangeIndexFromGridLine(
    wtf_size_t grid_line) const {
  wtf_size_t upper = RangeCount();
  DCHECK_GT(upper, 0u);

  const wtf_size_t last_grid_line =
      RangeStartLine(upper - 1) + RangeTrackCount(upper - 1);
  DCHECK_LT(grid_line, last_grid_line);

  // Do a binary search on the ranges.
  wtf_size_t lower = 0;
  while (lower < upper) {
    const wtf_size_t center = (lower + upper) >> 1;
    const wtf_size_t start_line = RangeStartLine(center);

    if (grid_line < start_line)
      upper = center;
    else if (grid_line < start_line + RangeTrackCount(center))
      return center;
    else
      lower = center + 1;
  }
  return lower;
}

bool GridRange::IsCollapsed() const {
  return properties.HasProperty(TrackSpanProperties::kIsCollapsed);
}

bool GridRange::IsImplicit() const {
  return properties.HasProperty(TrackSpanProperties::kIsImplicit);
}

void GridRange::SetIsCollapsed() {
  properties.SetProperty(TrackSpanProperties::kIsCollapsed);
}

void GridRange::SetIsImplicit() {
  properties.SetProperty(TrackSpanProperties::kIsImplicit);
}

GridRangeBuilder::GridRangeBuilder(const ComputedStyle& grid_style,
                                   const GridLineResolver& line_resolver,
                                   GridTrackSizingDirection track_direction,
                                   wtf_size_t start_offset)
    : auto_repetitions_(line_resolver.AutoRepetitions(track_direction)),
      start_offset_(start_offset),
      must_sort_grid_lines_(false),
      explicit_tracks_((track_direction == kForColumns)
                           ? grid_style.GridTemplateColumns().track_list
                           : grid_style.GridTemplateRows().track_list),
      implicit_tracks_((track_direction == kForColumns)
                           ? grid_style.GridAutoColumns()
                           : grid_style.GridAutoRows()) {
  // The implicit track list should have only one repeater, if any.
  DCHECK_LE(implicit_tracks_.RepeaterCount(), 1u);
  DCHECK_NE(auto_repetitions_, kNotFound);

  const wtf_size_t repeater_count = explicit_tracks_.RepeaterCount();

  // Add extra capacity for the extra lines needed for named grids.
  start_lines_.ReserveInitialCapacity(repeater_count + 1);
  end_lines_.ReserveInitialCapacity(repeater_count + 1);

  wtf_size_t current_repeater_start_line = start_offset_;
  for (wtf_size_t i = 0; i < repeater_count; ++i) {
    const wtf_size_t repeater_track_count =
        explicit_tracks_.RepeatCount(i, auto_repetitions_) *
        explicit_tracks_.RepeatSize(i);

    // Subgrids can have zero auto repetitions.
    if (explicit_tracks_.IsSubgriddedAxis() && repeater_track_count == 0) {
      continue;
    }

    DCHECK_NE(repeater_track_count, 0u);
    start_lines_.emplace_back(current_repeater_start_line);
    current_repeater_start_line += repeater_track_count;
    end_lines_.emplace_back(current_repeater_start_line);
  }

  // There is a special scenario where named grid areas can be specified through
  // the "grid-template" property with no specified explicit grid; such case is
  // tricky because the computed value of "grid-template-columns" is expected to
  // return the computed size of columns from the named grid areas.
  //
  // In order to guarantee that such columns are included, if the last repeater
  // from the explicit grid ended before the end of the named grid area, add an
  // extra repeater to fulfill the named grid area's span.
  wtf_size_t named_grid_area_end_line = start_offset_;
  if (const auto& grid_template_areas = grid_style.GridTemplateAreas()) {
    named_grid_area_end_line += (track_direction == kForColumns)
                                    ? grid_template_areas->column_count
                                    : grid_template_areas->row_count;
  }

  if (current_repeater_start_line < named_grid_area_end_line) {
    start_lines_.emplace_back(current_repeater_start_line);
    end_lines_.emplace_back(named_grid_area_end_line);
  }
}

void GridRangeBuilder::EnsureTrackCoverage(
    wtf_size_t start_line,
    wtf_size_t span_length,
    wtf_size_t* grid_item_start_range_index,
    wtf_size_t* grid_item_end_range_index) {
  DCHECK_NE(start_line, kNotFound);
  DCHECK_NE(span_length, kNotFound);
  DCHECK(grid_item_start_range_index && grid_item_end_range_index);

  must_sort_grid_lines_ = true;
  start_lines_.emplace_back(start_line, grid_item_start_range_index);
  end_lines_.emplace_back(start_line + span_length, grid_item_end_range_index);
}

GridRangeVector GridRangeBuilder::FinalizeRanges() {
  DCHECK_EQ(start_lines_.size(), end_lines_.size());

  // Sort start and ending tracks from low to high.
  if (must_sort_grid_lines_) {
    auto CompareTrackBoundaries = [](const TrackBoundaryToRangePair& a,
                                     const TrackBoundaryToRangePair& b) {
      return a.grid_line < b.grid_line;
    };
    std::sort(start_lines_.begin(), start_lines_.end(), CompareTrackBoundaries);
    std::sort(end_lines_.begin(), end_lines_.end(), CompareTrackBoundaries);
    must_sort_grid_lines_ = false;
  }

  const wtf_size_t explicit_repeater_count = explicit_tracks_.RepeaterCount();
  const wtf_size_t grid_line_count = start_lines_.size();

  GridRangeVector ranges;
  bool is_in_auto_fit_range = false;

  wtf_size_t current_explicit_grid_line = start_offset_;
  wtf_size_t current_explicit_repeater_index = kNotFound;
  wtf_size_t current_range_start_line = 0;
  wtf_size_t current_set_index = 0;
  wtf_size_t open_items_or_repeaters = 0;

  // If the explicit grid is not empty, |start_offset_| is the translated index
  // of the first track in |explicit_tracks_|; otherwise, the next repeater
  // does not exist, fallback to |kNotFound|.
  wtf_size_t next_explicit_repeater_start =
      explicit_repeater_count ? start_offset_ : kNotFound;

  // Index of the start/end line we are currently processing.
  wtf_size_t start_line_index = 0;
  wtf_size_t end_line_index = 0;

  while (true) {
    // Identify starting tracks index.
    while (start_line_index < grid_line_count &&
           current_range_start_line >=
               start_lines_[start_line_index].grid_line) {
      ++start_line_index;
      ++open_items_or_repeaters;
    }

    // Identify ending tracks index.
    while (end_line_index < grid_line_count &&
           current_range_start_line >= end_lines_[end_line_index].grid_line) {
      ++end_line_index;
      --open_items_or_repeaters;
      DCHECK_GE(open_items_or_repeaters, 0u);
    }

    if (end_line_index >= grid_line_count)
      break;

    // Determine the next starting and ending track index.
    const wtf_size_t next_start_line =
        (start_line_index < grid_line_count)
            ? start_lines_[start_line_index].grid_line
            : kNotFound;
    const wtf_size_t next_end_line = end_lines_[end_line_index].grid_line;
    DCHECK(next_start_line != kNotFound || next_end_line < next_start_line);

    // Move to the start of the next explicit repeater.
    while (current_range_start_line == next_explicit_repeater_start) {
      current_explicit_grid_line = next_explicit_repeater_start;

      // No next repeater, break and use implicit grid tracks.
      if (++current_explicit_repeater_index == explicit_repeater_count) {
        current_explicit_repeater_index = kNotFound;
        is_in_auto_fit_range = false;
        break;
      }

      is_in_auto_fit_range =
          explicit_tracks_.RepeatType(current_explicit_repeater_index) ==
          NGGridTrackRepeater::RepeatType::kAutoFit;
      next_explicit_repeater_start +=
          explicit_tracks_.RepeatSize(current_explicit_repeater_index) *
          explicit_tracks_.RepeatCount(current_explicit_repeater_index,
                                       auto_repetitions_);
    }

    // Compute this range's begin set index, start line, and track count.
    GridRange range;
    wtf_size_t current_repeater_size = 1;
    range.start_line = current_range_start_line;
    range.track_count =
        std::min(next_start_line, next_end_line) - current_range_start_line;
    DCHECK_GT(range.track_count, 0u);

    // Compute current repeater's index, size, and offset.
    // TODO(ethavar): Simplify this logic.
    range.begin_set_index = current_set_index;
    if (explicit_tracks_.IsSubgriddedAxis()) {
      // Subgridded axis specified on standalone grid, use 'auto'.
      range.repeater_index = kNotFound;
      range.repeater_offset = 0u;
    } else if (current_explicit_repeater_index != kNotFound) {
      current_repeater_size =
          explicit_tracks_.RepeatSize(current_explicit_repeater_index);

      // This range is contained within a repeater of the explicit grid; at this
      // point, |current_explicit_grid_line| should be set to the start line of
      // such repeater.
      range.repeater_index = current_explicit_repeater_index;
      range.repeater_offset =
          (current_range_start_line - current_explicit_grid_line) %
          current_repeater_size;
    } else {
      range.SetIsImplicit();
      if (!implicit_tracks_.RepeaterCount()) {
        // No specified implicit grid tracks, use 'auto'.
        range.repeater_index = kNotFound;
        range.repeater_offset = 0u;
      } else {
        current_repeater_size = implicit_tracks_.RepeatSize(0);

        // Otherwise, use the only repeater for implicit grid tracks.
        // There are 2 scenarios we want to cover here:
        //   1. At this point, we should not have reached any explicit repeater,
        //   since |current_explicit_grid_line| was initialized as the start
        //   line of the first explicit repeater (e.g. |start_offset_|), it can
        //   be used to determine the offset of ranges preceding the explicit
        //   grid; the last implicit grid track before the explicit grid
        //   receives the last specified size, and so on backwards.
        //
        //   2. This range is located after any repeater in |explicit_tracks_|,
        //   meaning it was defined with indices beyond the explicit grid.
        //   We should have set |current_explicit_grid_line| to the last line
        //   of the explicit grid at this point, use it to compute the offset of
        //   following implicit tracks; the first track after the explicit grid
        //   receives the first specified size, and so on forwards.
        //
        // Note that for both scenarios we can use the following formula:
        //   (current_range_start_line - current_explicit_grid_line) %
        //   current_repeater_size
        // The expression below is equivalent, but uses some modular arithmetic
        // properties to avoid |wtf_size_t| underflow in scenario 1.
        range.repeater_index = 0;
        range.repeater_offset =
            (current_range_start_line + current_repeater_size -
             current_explicit_grid_line % current_repeater_size) %
            current_repeater_size;
      }
    }

    // Cache range-start indices to avoid having to recompute them later.
    // Loop backwards to find all other entries with the same track number. The
    // |start_line_index| will always land 1 position after duplicate entries.
    // Walk back to cache all duplicates until we are at the start of the vector
    // or we have gone over all duplicate entries.
    if (start_line_index != 0) {
      DCHECK_LE(start_line_index, grid_line_count);
      for (wtf_size_t line_index = start_line_index - 1;
           start_lines_[line_index].grid_line == range.start_line;
           --line_index) {
        if (start_lines_[line_index].grid_item_range_index_to_cache) {
          *start_lines_[line_index].grid_item_range_index_to_cache =
              ranges.size();
        }
        // This is needed here to avoid underflow.
        if (!line_index)
          break;
      }
    }

    // Cache range-end indices to avoid having to recompute them later. The
    // |end_line_index| will always land at the start of duplicate entries.
    // Cache all duplicate entries by walking forwards until we are at the end
    // of the vector or we have gone over all duplicate entries.
    const wtf_size_t end_line = range.start_line + range.track_count;
    for (wtf_size_t line_index = end_line_index;
         line_index < grid_line_count &&
         end_lines_[line_index].grid_line == end_line;
         ++line_index) {
      if (end_lines_[line_index].grid_item_range_index_to_cache)
        *end_lines_[line_index].grid_item_range_index_to_cache = ranges.size();
    }

    if (is_in_auto_fit_range && open_items_or_repeaters == 1) {
      range.SetIsCollapsed();
      range.set_count = 0;
    } else {
      // If this is a non-collapsed range, the number of sets in this range is
      // the number of track definitions in the current repeater clamped by the
      // track count if it's less than the repeater's size.
      range.set_count = std::min(current_repeater_size, range.track_count);
      DCHECK_GT(range.set_count, 0u);
    }

    current_range_start_line += range.track_count;
    current_set_index += range.set_count;
    ranges.emplace_back(std::move(range));
  }

#if DCHECK_IS_ON()
  // We must have exhausted all start and end indices.
  DCHECK_EQ(start_line_index, grid_line_count);
  DCHECK_EQ(end_line_index, grid_line_count);
  DCHECK_EQ(open_items_or_repeaters, 0u);

  // If we exhausted the end indices, then we must have already exhausted the
  // repeaters, or are located at the end of the last repeater.
  if (current_explicit_repeater_index != kNotFound) {
    DCHECK_EQ(current_explicit_repeater_index, explicit_repeater_count - 1);
    DCHECK_EQ(current_range_start_line, next_explicit_repeater_start);
  }
#endif
  return ranges;
}

GridRangeBuilder::GridRangeBuilder(const NGGridTrackList& explicit_tracks,
                                   const NGGridTrackList& implicit_tracks,
                                   wtf_size_t auto_repetitions)
    : auto_repetitions_(auto_repetitions),
      start_offset_(0),
      must_sort_grid_lines_(false),
      explicit_tracks_(explicit_tracks),
      implicit_tracks_(implicit_tracks) {
  const wtf_size_t repeater_count = explicit_tracks_.RepeaterCount();

  wtf_size_t current_repeater_start_line = 0;
  for (wtf_size_t i = 0; i < repeater_count; ++i) {
    const wtf_size_t repeater_track_count =
        explicit_tracks_.RepeatCount(i, auto_repetitions_) *
        explicit_tracks_.RepeatSize(i);
    DCHECK_NE(repeater_track_count, 0u);

    start_lines_.emplace_back(current_repeater_start_line);
    current_repeater_start_line += repeater_track_count;
    end_lines_.emplace_back(current_repeater_start_line);
  }
}

GridSet::GridSet(wtf_size_t track_count,
                 const GridTrackSize& track_definition,
                 bool is_available_size_indefinite)
    : track_count(track_count),
      track_size(track_definition),
      fit_content_limit(kIndefiniteSize) {
  if (track_size.IsFitContent()) {
    // Argument for 'fit-content' is a <percentage> that couldn't be resolved to
    // a definite <length>, normalize to 'minmax(auto, max-content)'.
    if (is_available_size_indefinite &&
        track_size.FitContentTrackBreadth().HasPercent()) {
      track_size = GridTrackSize(Length::Auto(), Length::MaxContent());
    }
  } else {
    // Normalize |track_size| into a |kMinMaxTrackSizing| type; follow the
    // definitions from https://drafts.csswg.org/css-grid-2/#algo-terms.
    const auto normalized_min_track_sizing_function =
        ((is_available_size_indefinite &&
          track_size.MinTrackBreadth().HasPercent()) ||
         track_size.HasFlexMinTrackBreadth())
            ? Length::Auto()
            : track_size.MinTrackBreadth();

    const auto normalized_max_track_sizing_function =
        (is_available_size_indefinite &&
         track_size.MaxTrackBreadth().HasPercent())
            ? Length::Auto()
            : track_size.MaxTrackBreadth();

    track_size = GridTrackSize(normalized_min_track_sizing_function,
                               normalized_max_track_sizing_function);
  }
  DCHECK(track_size.GetType() == kFitContentTrackSizing ||
         track_size.GetType() == kMinMaxTrackSizing);
}

float GridSet::FlexFactor() const {
  DCHECK(track_size.HasFlexMaxTrackBreadth());
  return track_size.MaxTrackBreadth().GetFloatValue() * track_count;
}

LayoutUnit GridSet::BaseSize() const {
  DCHECK(!IsGrowthLimitLessThanBaseSize());
  return base_size;
}

LayoutUnit GridSet::GrowthLimit() const {
  DCHECK(!IsGrowthLimitLessThanBaseSize());
  return growth_limit;
}

void GridSet::InitBaseSize(LayoutUnit new_base_size) {
  DCHECK_NE(new_base_size, kIndefiniteSize);
  base_size = new_base_size;
  EnsureGrowthLimitIsNotLessThanBaseSize();
}

void GridSet::IncreaseBaseSize(LayoutUnit new_base_size) {
  // Expect base size to always grow monotonically.
  DCHECK_NE(new_base_size, kIndefiniteSize);
  DCHECK_LE(base_size, new_base_size);
  base_size = new_base_size;
  EnsureGrowthLimitIsNotLessThanBaseSize();
}

void GridSet::IncreaseGrowthLimit(LayoutUnit new_growth_limit) {
  // Growth limit is initialized as infinity; expect it to change from infinity
  // to a definite value and then to always grow monotonically.
  DCHECK_NE(new_growth_limit, kIndefiniteSize);
  DCHECK(!IsGrowthLimitLessThanBaseSize() &&
         (growth_limit == kIndefiniteSize || growth_limit <= new_growth_limit));
  growth_limit = new_growth_limit;
}

void GridSet::EnsureGrowthLimitIsNotLessThanBaseSize() {
  if (IsGrowthLimitLessThanBaseSize())
    growth_limit = base_size;
}

bool GridSet::IsGrowthLimitLessThanBaseSize() const {
  return growth_limit != kIndefiniteSize && growth_limit < base_size;
}

bool GridLayoutTrackCollection::operator==(
    const GridLayoutTrackCollection& other) const {
  return gutter_size_ == other.gutter_size_ &&
         track_direction_ == other.track_direction_ &&
         accumulated_gutter_size_delta_ ==
             other.accumulated_gutter_size_delta_ &&
         accumulated_start_extra_margin_ ==
             other.accumulated_start_extra_margin_ &&
         accumulated_end_extra_margin_ == other.accumulated_end_extra_margin_ &&
         baselines_.has_value() == other.baselines_.has_value() &&
         (!baselines_ || (baselines_->major == other.baselines_->major &&
                          baselines_->minor == other.baselines_->minor)) &&
         last_indefinite_index_ == other.last_indefinite_index_ &&
         ranges_ == other.ranges_ && sets_geometry_ == other.sets_geometry_;
}

wtf_size_t GridLayoutTrackCollection::RangeStartLine(
    wtf_size_t range_index) const {
  DCHECK_LT(range_index, ranges_.size());
  return ranges_[range_index].start_line;
}

wtf_size_t GridLayoutTrackCollection::RangeTrackCount(
    wtf_size_t range_index) const {
  DCHECK_LT(range_index, ranges_.size());
  return ranges_[range_index].track_count;
}

wtf_size_t GridLayoutTrackCollection::RangeSetCount(
    wtf_size_t range_index) const {
  DCHECK_LT(range_index, ranges_.size());
  return ranges_[range_index].set_count;
}

wtf_size_t GridLayoutTrackCollection::RangeBeginSetIndex(
    wtf_size_t range_index) const {
  DCHECK_LT(range_index, ranges_.size());
  return ranges_[range_index].begin_set_index;
}

TrackSpanProperties GridLayoutTrackCollection::RangeProperties(
    wtf_size_t range_index) const {
  DCHECK_LT(range_index, ranges_.size());
  return ranges_[range_index].properties;
}

wtf_size_t GridLayoutTrackCollection::EndLineOfImplicitGrid() const {
  if (ranges_.empty())
    return 0;
  const auto& last_range = ranges_.back();
  return last_range.start_line + last_range.track_count;
}

bool GridLayoutTrackCollection::IsGridLineWithinImplicitGrid(
    wtf_size_t grid_line) const {
  DCHECK_NE(grid_line, kNotFound);
  return grid_line <= EndLineOfImplicitGrid();
}

wtf_size_t GridLayoutTrackCollection::GetSetCount() const {
  if (ranges_.empty())
    return 0;
  const auto& last_range = ranges_.back();
  return last_range.begin_set_index + last_range.set_count;
}

LayoutUnit GridLayoutTrackCollection::GetSetOffset(wtf_size_t set_index) const {
  DCHECK_LT(set_index, sets_geometry_.size());
  return sets_geometry_[set_index].offset;
}

wtf_size_t GridLayoutTrackCollection::GetSetTrackCount(
    wtf_size_t set_index) const {
  DCHECK_LT(set_index + 1, sets_geometry_.size());
  return sets_geometry_[set_index + 1].track_count;
}

LayoutUnit GridLayoutTrackCollection::StartExtraMargin(
    wtf_size_t set_index) const {
  return set_index ? accumulated_gutter_size_delta_ / 2
                   : accumulated_start_extra_margin_;
}

LayoutUnit GridLayoutTrackCollection::EndExtraMargin(
    wtf_size_t set_index) const {
  return (set_index < sets_geometry_.size() - 1)
             ? accumulated_gutter_size_delta_ / 2
             : accumulated_end_extra_margin_;
}

LayoutUnit GridLayoutTrackCollection::MajorBaseline(
    wtf_size_t set_index) const {
  if (!baselines_) {
    return LayoutUnit::Min();
  }

  DCHECK_LT(set_index, baselines_->major.size());
  return baselines_->major[set_index];
}

LayoutUnit GridLayoutTrackCollection::MinorBaseline(
    wtf_size_t set_index) const {
  if (!baselines_) {
    return LayoutUnit::Min();
  }

  DCHECK_LT(set_index, baselines_->minor.size());
  return baselines_->minor[set_index];
}

void GridLayoutTrackCollection::AdjustSetOffsets(wtf_size_t set_index,
                                                 LayoutUnit delta) {
  DCHECK_LT(set_index, sets_geometry_.size());
  for (wtf_size_t i = set_index; i < sets_geometry_.size(); ++i)
    sets_geometry_[i].offset += delta;
}

LayoutUnit GridLayoutTrackCollection::ComputeSetSpanSize() const {
  return ComputeSetSpanSize(0, GetSetCount());
}

LayoutUnit GridLayoutTrackCollection::ComputeSetSpanSize(
    wtf_size_t begin_set_index,
    wtf_size_t end_set_index) const {
  DCHECK_LE(begin_set_index, end_set_index);
  DCHECK_LT(end_set_index, sets_geometry_.size());

  if (begin_set_index == end_set_index)
    return LayoutUnit();

  if (IsSpanningIndefiniteSet(begin_set_index, end_set_index))
    return kIndefiniteSize;

  // While the set offsets are guaranteed to be in non-decreasing order, if an
  // extra margin is larger than any of the offsets or the gutter size saturates
  // the end offset, the following difference may become negative.
  return (GetSetOffset(end_set_index) - gutter_size_ -
          GetSetOffset(begin_set_index))
      .ClampNegativeToZero();
}

bool GridLayoutTrackCollection::IsSpanningIndefiniteSet(
    wtf_size_t begin_set_index,
    wtf_size_t end_set_index) const {
  if (last_indefinite_index_.empty()) {
    return false;
  }

  DCHECK_LT(begin_set_index, end_set_index);
  DCHECK_LT(end_set_index, last_indefinite_index_.size());
  const wtf_size_t last_indefinite_index =
      last_indefinite_index_[end_set_index];

  return last_indefinite_index != kNotFound &&
         begin_set_index <= last_indefinite_index;
}

GridLayoutTrackCollection
GridLayoutTrackCollection::CreateSubgridTrackCollection(
    wtf_size_t begin_range_index,
    wtf_size_t end_range_index,
    LayoutUnit subgrid_gutter_size,
    const BoxStrut& subgrid_margin,
    const BoxStrut& subgrid_border_scrollbar_padding,
    GridTrackSizingDirection subgrid_track_direction,
    bool is_opposite_direction_in_root_grid) const {
  DCHECK_LE(begin_range_index, end_range_index);
  DCHECK_LT(end_range_index, ranges_.size());

  GridLayoutTrackCollection subgrid_track_collection(subgrid_track_direction);

  const wtf_size_t begin_set_index = ranges_[begin_range_index].begin_set_index;
  const wtf_size_t end_set_index = ranges_[end_range_index].begin_set_index +
                                   ranges_[end_range_index].set_count;

  DCHECK_LT(end_set_index, sets_geometry_.size());
  DCHECK_LT(begin_set_index, end_set_index);

  // Copy and translate the ranges in the subgrid's span.
  {
    auto& subgrid_properties = subgrid_track_collection.properties_;
    auto& subgrid_ranges = subgrid_track_collection.ranges_;

    const wtf_size_t range_count = end_range_index - begin_range_index;
    wtf_size_t current_begin_set_index = 0;
    wtf_size_t current_start_line = 0;

    subgrid_ranges.ReserveInitialCapacity(range_count + 1);

    for (wtf_size_t i = 0; i <= range_count; ++i) {
      // Opposite direction subgrids need to iterate backwards.
      const wtf_size_t current_index = is_opposite_direction_in_root_grid
                                           ? end_range_index - i
                                           : begin_range_index + i;

      auto& subgrid_translated_range =
          subgrid_ranges.emplace_back(ranges_[current_index]);
      subgrid_translated_range.begin_set_index = current_begin_set_index;
      current_begin_set_index += subgrid_translated_range.set_count;

      subgrid_translated_range.start_line = current_start_line;
      current_start_line += subgrid_translated_range.track_count;

      subgrid_properties |= subgrid_translated_range.properties;
    }
  }

  const wtf_size_t set_span_size = end_set_index - begin_set_index;

  // Copy the sets geometry and adjust its offsets to accommodate the subgrid's
  // margin, border, scrollbar, padding, and gutter size.
  const auto subgrid_gutter_size_delta = subgrid_gutter_size - gutter_size_;

  const bool is_for_columns = subgrid_track_direction == kForColumns;
  const auto subgrid_margin_start =
      is_for_columns ? subgrid_margin.inline_start : subgrid_margin.block_start;

  const auto subgrid_border_scrollbar_padding_start =
      is_for_columns ? subgrid_border_scrollbar_padding.inline_start
                     : subgrid_border_scrollbar_padding.block_start;

  const auto subgrid_margin_border_scrollbar_padding_start =
      subgrid_margin_start + subgrid_border_scrollbar_padding_start;
  const auto subgrid_margin_border_scrollbar_padding_end =
      is_for_columns ? subgrid_margin.inline_end +
                           subgrid_border_scrollbar_padding.inline_end
                     : subgrid_margin.block_end +
                           subgrid_border_scrollbar_padding.block_end;

  // Accumulate the extra margin from the spanned sets in the parent track
  // collection and this subgrid's margins and gutter size delta.
  {
    subgrid_track_collection.accumulated_gutter_size_delta_ =
        subgrid_gutter_size_delta + accumulated
Prompt: 
```
这是目录为blink/renderer/core/layout/grid/grid_track_collection.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/grid/grid_track_collection.h"

#include "base/check.h"
#include "third_party/blink/renderer/core/layout/grid/grid_line_resolver.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"

namespace blink {

struct SameSizeAsGridRange {
  wtf_size_t members[6];
  wtf_size_t bitfields;
};

ASSERT_SIZE(GridRange, SameSizeAsGridRange);

wtf_size_t GridTrackCollectionBase::RangeEndLine(wtf_size_t range_index) const {
  return RangeStartLine(range_index) + RangeTrackCount(range_index);
}

wtf_size_t GridTrackCollectionBase::RangeIndexFromGridLine(
    wtf_size_t grid_line) const {
  wtf_size_t upper = RangeCount();
  DCHECK_GT(upper, 0u);

  const wtf_size_t last_grid_line =
      RangeStartLine(upper - 1) + RangeTrackCount(upper - 1);
  DCHECK_LT(grid_line, last_grid_line);

  // Do a binary search on the ranges.
  wtf_size_t lower = 0;
  while (lower < upper) {
    const wtf_size_t center = (lower + upper) >> 1;
    const wtf_size_t start_line = RangeStartLine(center);

    if (grid_line < start_line)
      upper = center;
    else if (grid_line < start_line + RangeTrackCount(center))
      return center;
    else
      lower = center + 1;
  }
  return lower;
}

bool GridRange::IsCollapsed() const {
  return properties.HasProperty(TrackSpanProperties::kIsCollapsed);
}

bool GridRange::IsImplicit() const {
  return properties.HasProperty(TrackSpanProperties::kIsImplicit);
}

void GridRange::SetIsCollapsed() {
  properties.SetProperty(TrackSpanProperties::kIsCollapsed);
}

void GridRange::SetIsImplicit() {
  properties.SetProperty(TrackSpanProperties::kIsImplicit);
}

GridRangeBuilder::GridRangeBuilder(const ComputedStyle& grid_style,
                                   const GridLineResolver& line_resolver,
                                   GridTrackSizingDirection track_direction,
                                   wtf_size_t start_offset)
    : auto_repetitions_(line_resolver.AutoRepetitions(track_direction)),
      start_offset_(start_offset),
      must_sort_grid_lines_(false),
      explicit_tracks_((track_direction == kForColumns)
                           ? grid_style.GridTemplateColumns().track_list
                           : grid_style.GridTemplateRows().track_list),
      implicit_tracks_((track_direction == kForColumns)
                           ? grid_style.GridAutoColumns()
                           : grid_style.GridAutoRows()) {
  // The implicit track list should have only one repeater, if any.
  DCHECK_LE(implicit_tracks_.RepeaterCount(), 1u);
  DCHECK_NE(auto_repetitions_, kNotFound);

  const wtf_size_t repeater_count = explicit_tracks_.RepeaterCount();

  // Add extra capacity for the extra lines needed for named grids.
  start_lines_.ReserveInitialCapacity(repeater_count + 1);
  end_lines_.ReserveInitialCapacity(repeater_count + 1);

  wtf_size_t current_repeater_start_line = start_offset_;
  for (wtf_size_t i = 0; i < repeater_count; ++i) {
    const wtf_size_t repeater_track_count =
        explicit_tracks_.RepeatCount(i, auto_repetitions_) *
        explicit_tracks_.RepeatSize(i);

    // Subgrids can have zero auto repetitions.
    if (explicit_tracks_.IsSubgriddedAxis() && repeater_track_count == 0) {
      continue;
    }

    DCHECK_NE(repeater_track_count, 0u);
    start_lines_.emplace_back(current_repeater_start_line);
    current_repeater_start_line += repeater_track_count;
    end_lines_.emplace_back(current_repeater_start_line);
  }

  // There is a special scenario where named grid areas can be specified through
  // the "grid-template" property with no specified explicit grid; such case is
  // tricky because the computed value of "grid-template-columns" is expected to
  // return the computed size of columns from the named grid areas.
  //
  // In order to guarantee that such columns are included, if the last repeater
  // from the explicit grid ended before the end of the named grid area, add an
  // extra repeater to fulfill the named grid area's span.
  wtf_size_t named_grid_area_end_line = start_offset_;
  if (const auto& grid_template_areas = grid_style.GridTemplateAreas()) {
    named_grid_area_end_line += (track_direction == kForColumns)
                                    ? grid_template_areas->column_count
                                    : grid_template_areas->row_count;
  }

  if (current_repeater_start_line < named_grid_area_end_line) {
    start_lines_.emplace_back(current_repeater_start_line);
    end_lines_.emplace_back(named_grid_area_end_line);
  }
}

void GridRangeBuilder::EnsureTrackCoverage(
    wtf_size_t start_line,
    wtf_size_t span_length,
    wtf_size_t* grid_item_start_range_index,
    wtf_size_t* grid_item_end_range_index) {
  DCHECK_NE(start_line, kNotFound);
  DCHECK_NE(span_length, kNotFound);
  DCHECK(grid_item_start_range_index && grid_item_end_range_index);

  must_sort_grid_lines_ = true;
  start_lines_.emplace_back(start_line, grid_item_start_range_index);
  end_lines_.emplace_back(start_line + span_length, grid_item_end_range_index);
}

GridRangeVector GridRangeBuilder::FinalizeRanges() {
  DCHECK_EQ(start_lines_.size(), end_lines_.size());

  // Sort start and ending tracks from low to high.
  if (must_sort_grid_lines_) {
    auto CompareTrackBoundaries = [](const TrackBoundaryToRangePair& a,
                                     const TrackBoundaryToRangePair& b) {
      return a.grid_line < b.grid_line;
    };
    std::sort(start_lines_.begin(), start_lines_.end(), CompareTrackBoundaries);
    std::sort(end_lines_.begin(), end_lines_.end(), CompareTrackBoundaries);
    must_sort_grid_lines_ = false;
  }

  const wtf_size_t explicit_repeater_count = explicit_tracks_.RepeaterCount();
  const wtf_size_t grid_line_count = start_lines_.size();

  GridRangeVector ranges;
  bool is_in_auto_fit_range = false;

  wtf_size_t current_explicit_grid_line = start_offset_;
  wtf_size_t current_explicit_repeater_index = kNotFound;
  wtf_size_t current_range_start_line = 0;
  wtf_size_t current_set_index = 0;
  wtf_size_t open_items_or_repeaters = 0;

  // If the explicit grid is not empty, |start_offset_| is the translated index
  // of the first track in |explicit_tracks_|; otherwise, the next repeater
  // does not exist, fallback to |kNotFound|.
  wtf_size_t next_explicit_repeater_start =
      explicit_repeater_count ? start_offset_ : kNotFound;

  // Index of the start/end line we are currently processing.
  wtf_size_t start_line_index = 0;
  wtf_size_t end_line_index = 0;

  while (true) {
    // Identify starting tracks index.
    while (start_line_index < grid_line_count &&
           current_range_start_line >=
               start_lines_[start_line_index].grid_line) {
      ++start_line_index;
      ++open_items_or_repeaters;
    }

    // Identify ending tracks index.
    while (end_line_index < grid_line_count &&
           current_range_start_line >= end_lines_[end_line_index].grid_line) {
      ++end_line_index;
      --open_items_or_repeaters;
      DCHECK_GE(open_items_or_repeaters, 0u);
    }

    if (end_line_index >= grid_line_count)
      break;

    // Determine the next starting and ending track index.
    const wtf_size_t next_start_line =
        (start_line_index < grid_line_count)
            ? start_lines_[start_line_index].grid_line
            : kNotFound;
    const wtf_size_t next_end_line = end_lines_[end_line_index].grid_line;
    DCHECK(next_start_line != kNotFound || next_end_line < next_start_line);

    // Move to the start of the next explicit repeater.
    while (current_range_start_line == next_explicit_repeater_start) {
      current_explicit_grid_line = next_explicit_repeater_start;

      // No next repeater, break and use implicit grid tracks.
      if (++current_explicit_repeater_index == explicit_repeater_count) {
        current_explicit_repeater_index = kNotFound;
        is_in_auto_fit_range = false;
        break;
      }

      is_in_auto_fit_range =
          explicit_tracks_.RepeatType(current_explicit_repeater_index) ==
          NGGridTrackRepeater::RepeatType::kAutoFit;
      next_explicit_repeater_start +=
          explicit_tracks_.RepeatSize(current_explicit_repeater_index) *
          explicit_tracks_.RepeatCount(current_explicit_repeater_index,
                                       auto_repetitions_);
    }

    // Compute this range's begin set index, start line, and track count.
    GridRange range;
    wtf_size_t current_repeater_size = 1;
    range.start_line = current_range_start_line;
    range.track_count =
        std::min(next_start_line, next_end_line) - current_range_start_line;
    DCHECK_GT(range.track_count, 0u);

    // Compute current repeater's index, size, and offset.
    // TODO(ethavar): Simplify this logic.
    range.begin_set_index = current_set_index;
    if (explicit_tracks_.IsSubgriddedAxis()) {
      // Subgridded axis specified on standalone grid, use 'auto'.
      range.repeater_index = kNotFound;
      range.repeater_offset = 0u;
    } else if (current_explicit_repeater_index != kNotFound) {
      current_repeater_size =
          explicit_tracks_.RepeatSize(current_explicit_repeater_index);

      // This range is contained within a repeater of the explicit grid; at this
      // point, |current_explicit_grid_line| should be set to the start line of
      // such repeater.
      range.repeater_index = current_explicit_repeater_index;
      range.repeater_offset =
          (current_range_start_line - current_explicit_grid_line) %
          current_repeater_size;
    } else {
      range.SetIsImplicit();
      if (!implicit_tracks_.RepeaterCount()) {
        // No specified implicit grid tracks, use 'auto'.
        range.repeater_index = kNotFound;
        range.repeater_offset = 0u;
      } else {
        current_repeater_size = implicit_tracks_.RepeatSize(0);

        // Otherwise, use the only repeater for implicit grid tracks.
        // There are 2 scenarios we want to cover here:
        //   1. At this point, we should not have reached any explicit repeater,
        //   since |current_explicit_grid_line| was initialized as the start
        //   line of the first explicit repeater (e.g. |start_offset_|), it can
        //   be used to determine the offset of ranges preceding the explicit
        //   grid; the last implicit grid track before the explicit grid
        //   receives the last specified size, and so on backwards.
        //
        //   2. This range is located after any repeater in |explicit_tracks_|,
        //   meaning it was defined with indices beyond the explicit grid.
        //   We should have set |current_explicit_grid_line| to the last line
        //   of the explicit grid at this point, use it to compute the offset of
        //   following implicit tracks; the first track after the explicit grid
        //   receives the first specified size, and so on forwards.
        //
        // Note that for both scenarios we can use the following formula:
        //   (current_range_start_line - current_explicit_grid_line) %
        //   current_repeater_size
        // The expression below is equivalent, but uses some modular arithmetic
        // properties to avoid |wtf_size_t| underflow in scenario 1.
        range.repeater_index = 0;
        range.repeater_offset =
            (current_range_start_line + current_repeater_size -
             current_explicit_grid_line % current_repeater_size) %
            current_repeater_size;
      }
    }

    // Cache range-start indices to avoid having to recompute them later.
    // Loop backwards to find all other entries with the same track number. The
    // |start_line_index| will always land 1 position after duplicate entries.
    // Walk back to cache all duplicates until we are at the start of the vector
    // or we have gone over all duplicate entries.
    if (start_line_index != 0) {
      DCHECK_LE(start_line_index, grid_line_count);
      for (wtf_size_t line_index = start_line_index - 1;
           start_lines_[line_index].grid_line == range.start_line;
           --line_index) {
        if (start_lines_[line_index].grid_item_range_index_to_cache) {
          *start_lines_[line_index].grid_item_range_index_to_cache =
              ranges.size();
        }
        // This is needed here to avoid underflow.
        if (!line_index)
          break;
      }
    }

    // Cache range-end indices to avoid having to recompute them later. The
    // |end_line_index| will always land at the start of duplicate entries.
    // Cache all duplicate entries by walking forwards until we are at the end
    // of the vector or we have gone over all duplicate entries.
    const wtf_size_t end_line = range.start_line + range.track_count;
    for (wtf_size_t line_index = end_line_index;
         line_index < grid_line_count &&
         end_lines_[line_index].grid_line == end_line;
         ++line_index) {
      if (end_lines_[line_index].grid_item_range_index_to_cache)
        *end_lines_[line_index].grid_item_range_index_to_cache = ranges.size();
    }

    if (is_in_auto_fit_range && open_items_or_repeaters == 1) {
      range.SetIsCollapsed();
      range.set_count = 0;
    } else {
      // If this is a non-collapsed range, the number of sets in this range is
      // the number of track definitions in the current repeater clamped by the
      // track count if it's less than the repeater's size.
      range.set_count = std::min(current_repeater_size, range.track_count);
      DCHECK_GT(range.set_count, 0u);
    }

    current_range_start_line += range.track_count;
    current_set_index += range.set_count;
    ranges.emplace_back(std::move(range));
  }

#if DCHECK_IS_ON()
  // We must have exhausted all start and end indices.
  DCHECK_EQ(start_line_index, grid_line_count);
  DCHECK_EQ(end_line_index, grid_line_count);
  DCHECK_EQ(open_items_or_repeaters, 0u);

  // If we exhausted the end indices, then we must have already exhausted the
  // repeaters, or are located at the end of the last repeater.
  if (current_explicit_repeater_index != kNotFound) {
    DCHECK_EQ(current_explicit_repeater_index, explicit_repeater_count - 1);
    DCHECK_EQ(current_range_start_line, next_explicit_repeater_start);
  }
#endif
  return ranges;
}

GridRangeBuilder::GridRangeBuilder(const NGGridTrackList& explicit_tracks,
                                   const NGGridTrackList& implicit_tracks,
                                   wtf_size_t auto_repetitions)
    : auto_repetitions_(auto_repetitions),
      start_offset_(0),
      must_sort_grid_lines_(false),
      explicit_tracks_(explicit_tracks),
      implicit_tracks_(implicit_tracks) {
  const wtf_size_t repeater_count = explicit_tracks_.RepeaterCount();

  wtf_size_t current_repeater_start_line = 0;
  for (wtf_size_t i = 0; i < repeater_count; ++i) {
    const wtf_size_t repeater_track_count =
        explicit_tracks_.RepeatCount(i, auto_repetitions_) *
        explicit_tracks_.RepeatSize(i);
    DCHECK_NE(repeater_track_count, 0u);

    start_lines_.emplace_back(current_repeater_start_line);
    current_repeater_start_line += repeater_track_count;
    end_lines_.emplace_back(current_repeater_start_line);
  }
}

GridSet::GridSet(wtf_size_t track_count,
                 const GridTrackSize& track_definition,
                 bool is_available_size_indefinite)
    : track_count(track_count),
      track_size(track_definition),
      fit_content_limit(kIndefiniteSize) {
  if (track_size.IsFitContent()) {
    // Argument for 'fit-content' is a <percentage> that couldn't be resolved to
    // a definite <length>, normalize to 'minmax(auto, max-content)'.
    if (is_available_size_indefinite &&
        track_size.FitContentTrackBreadth().HasPercent()) {
      track_size = GridTrackSize(Length::Auto(), Length::MaxContent());
    }
  } else {
    // Normalize |track_size| into a |kMinMaxTrackSizing| type; follow the
    // definitions from https://drafts.csswg.org/css-grid-2/#algo-terms.
    const auto normalized_min_track_sizing_function =
        ((is_available_size_indefinite &&
          track_size.MinTrackBreadth().HasPercent()) ||
         track_size.HasFlexMinTrackBreadth())
            ? Length::Auto()
            : track_size.MinTrackBreadth();

    const auto normalized_max_track_sizing_function =
        (is_available_size_indefinite &&
         track_size.MaxTrackBreadth().HasPercent())
            ? Length::Auto()
            : track_size.MaxTrackBreadth();

    track_size = GridTrackSize(normalized_min_track_sizing_function,
                               normalized_max_track_sizing_function);
  }
  DCHECK(track_size.GetType() == kFitContentTrackSizing ||
         track_size.GetType() == kMinMaxTrackSizing);
}

float GridSet::FlexFactor() const {
  DCHECK(track_size.HasFlexMaxTrackBreadth());
  return track_size.MaxTrackBreadth().GetFloatValue() * track_count;
}

LayoutUnit GridSet::BaseSize() const {
  DCHECK(!IsGrowthLimitLessThanBaseSize());
  return base_size;
}

LayoutUnit GridSet::GrowthLimit() const {
  DCHECK(!IsGrowthLimitLessThanBaseSize());
  return growth_limit;
}

void GridSet::InitBaseSize(LayoutUnit new_base_size) {
  DCHECK_NE(new_base_size, kIndefiniteSize);
  base_size = new_base_size;
  EnsureGrowthLimitIsNotLessThanBaseSize();
}

void GridSet::IncreaseBaseSize(LayoutUnit new_base_size) {
  // Expect base size to always grow monotonically.
  DCHECK_NE(new_base_size, kIndefiniteSize);
  DCHECK_LE(base_size, new_base_size);
  base_size = new_base_size;
  EnsureGrowthLimitIsNotLessThanBaseSize();
}

void GridSet::IncreaseGrowthLimit(LayoutUnit new_growth_limit) {
  // Growth limit is initialized as infinity; expect it to change from infinity
  // to a definite value and then to always grow monotonically.
  DCHECK_NE(new_growth_limit, kIndefiniteSize);
  DCHECK(!IsGrowthLimitLessThanBaseSize() &&
         (growth_limit == kIndefiniteSize || growth_limit <= new_growth_limit));
  growth_limit = new_growth_limit;
}

void GridSet::EnsureGrowthLimitIsNotLessThanBaseSize() {
  if (IsGrowthLimitLessThanBaseSize())
    growth_limit = base_size;
}

bool GridSet::IsGrowthLimitLessThanBaseSize() const {
  return growth_limit != kIndefiniteSize && growth_limit < base_size;
}

bool GridLayoutTrackCollection::operator==(
    const GridLayoutTrackCollection& other) const {
  return gutter_size_ == other.gutter_size_ &&
         track_direction_ == other.track_direction_ &&
         accumulated_gutter_size_delta_ ==
             other.accumulated_gutter_size_delta_ &&
         accumulated_start_extra_margin_ ==
             other.accumulated_start_extra_margin_ &&
         accumulated_end_extra_margin_ == other.accumulated_end_extra_margin_ &&
         baselines_.has_value() == other.baselines_.has_value() &&
         (!baselines_ || (baselines_->major == other.baselines_->major &&
                          baselines_->minor == other.baselines_->minor)) &&
         last_indefinite_index_ == other.last_indefinite_index_ &&
         ranges_ == other.ranges_ && sets_geometry_ == other.sets_geometry_;
}

wtf_size_t GridLayoutTrackCollection::RangeStartLine(
    wtf_size_t range_index) const {
  DCHECK_LT(range_index, ranges_.size());
  return ranges_[range_index].start_line;
}

wtf_size_t GridLayoutTrackCollection::RangeTrackCount(
    wtf_size_t range_index) const {
  DCHECK_LT(range_index, ranges_.size());
  return ranges_[range_index].track_count;
}

wtf_size_t GridLayoutTrackCollection::RangeSetCount(
    wtf_size_t range_index) const {
  DCHECK_LT(range_index, ranges_.size());
  return ranges_[range_index].set_count;
}

wtf_size_t GridLayoutTrackCollection::RangeBeginSetIndex(
    wtf_size_t range_index) const {
  DCHECK_LT(range_index, ranges_.size());
  return ranges_[range_index].begin_set_index;
}

TrackSpanProperties GridLayoutTrackCollection::RangeProperties(
    wtf_size_t range_index) const {
  DCHECK_LT(range_index, ranges_.size());
  return ranges_[range_index].properties;
}

wtf_size_t GridLayoutTrackCollection::EndLineOfImplicitGrid() const {
  if (ranges_.empty())
    return 0;
  const auto& last_range = ranges_.back();
  return last_range.start_line + last_range.track_count;
}

bool GridLayoutTrackCollection::IsGridLineWithinImplicitGrid(
    wtf_size_t grid_line) const {
  DCHECK_NE(grid_line, kNotFound);
  return grid_line <= EndLineOfImplicitGrid();
}

wtf_size_t GridLayoutTrackCollection::GetSetCount() const {
  if (ranges_.empty())
    return 0;
  const auto& last_range = ranges_.back();
  return last_range.begin_set_index + last_range.set_count;
}

LayoutUnit GridLayoutTrackCollection::GetSetOffset(wtf_size_t set_index) const {
  DCHECK_LT(set_index, sets_geometry_.size());
  return sets_geometry_[set_index].offset;
}

wtf_size_t GridLayoutTrackCollection::GetSetTrackCount(
    wtf_size_t set_index) const {
  DCHECK_LT(set_index + 1, sets_geometry_.size());
  return sets_geometry_[set_index + 1].track_count;
}

LayoutUnit GridLayoutTrackCollection::StartExtraMargin(
    wtf_size_t set_index) const {
  return set_index ? accumulated_gutter_size_delta_ / 2
                   : accumulated_start_extra_margin_;
}

LayoutUnit GridLayoutTrackCollection::EndExtraMargin(
    wtf_size_t set_index) const {
  return (set_index < sets_geometry_.size() - 1)
             ? accumulated_gutter_size_delta_ / 2
             : accumulated_end_extra_margin_;
}

LayoutUnit GridLayoutTrackCollection::MajorBaseline(
    wtf_size_t set_index) const {
  if (!baselines_) {
    return LayoutUnit::Min();
  }

  DCHECK_LT(set_index, baselines_->major.size());
  return baselines_->major[set_index];
}

LayoutUnit GridLayoutTrackCollection::MinorBaseline(
    wtf_size_t set_index) const {
  if (!baselines_) {
    return LayoutUnit::Min();
  }

  DCHECK_LT(set_index, baselines_->minor.size());
  return baselines_->minor[set_index];
}

void GridLayoutTrackCollection::AdjustSetOffsets(wtf_size_t set_index,
                                                 LayoutUnit delta) {
  DCHECK_LT(set_index, sets_geometry_.size());
  for (wtf_size_t i = set_index; i < sets_geometry_.size(); ++i)
    sets_geometry_[i].offset += delta;
}

LayoutUnit GridLayoutTrackCollection::ComputeSetSpanSize() const {
  return ComputeSetSpanSize(0, GetSetCount());
}

LayoutUnit GridLayoutTrackCollection::ComputeSetSpanSize(
    wtf_size_t begin_set_index,
    wtf_size_t end_set_index) const {
  DCHECK_LE(begin_set_index, end_set_index);
  DCHECK_LT(end_set_index, sets_geometry_.size());

  if (begin_set_index == end_set_index)
    return LayoutUnit();

  if (IsSpanningIndefiniteSet(begin_set_index, end_set_index))
    return kIndefiniteSize;

  // While the set offsets are guaranteed to be in non-decreasing order, if an
  // extra margin is larger than any of the offsets or the gutter size saturates
  // the end offset, the following difference may become negative.
  return (GetSetOffset(end_set_index) - gutter_size_ -
          GetSetOffset(begin_set_index))
      .ClampNegativeToZero();
}

bool GridLayoutTrackCollection::IsSpanningIndefiniteSet(
    wtf_size_t begin_set_index,
    wtf_size_t end_set_index) const {
  if (last_indefinite_index_.empty()) {
    return false;
  }

  DCHECK_LT(begin_set_index, end_set_index);
  DCHECK_LT(end_set_index, last_indefinite_index_.size());
  const wtf_size_t last_indefinite_index =
      last_indefinite_index_[end_set_index];

  return last_indefinite_index != kNotFound &&
         begin_set_index <= last_indefinite_index;
}

GridLayoutTrackCollection
GridLayoutTrackCollection::CreateSubgridTrackCollection(
    wtf_size_t begin_range_index,
    wtf_size_t end_range_index,
    LayoutUnit subgrid_gutter_size,
    const BoxStrut& subgrid_margin,
    const BoxStrut& subgrid_border_scrollbar_padding,
    GridTrackSizingDirection subgrid_track_direction,
    bool is_opposite_direction_in_root_grid) const {
  DCHECK_LE(begin_range_index, end_range_index);
  DCHECK_LT(end_range_index, ranges_.size());

  GridLayoutTrackCollection subgrid_track_collection(subgrid_track_direction);

  const wtf_size_t begin_set_index = ranges_[begin_range_index].begin_set_index;
  const wtf_size_t end_set_index = ranges_[end_range_index].begin_set_index +
                                   ranges_[end_range_index].set_count;

  DCHECK_LT(end_set_index, sets_geometry_.size());
  DCHECK_LT(begin_set_index, end_set_index);

  // Copy and translate the ranges in the subgrid's span.
  {
    auto& subgrid_properties = subgrid_track_collection.properties_;
    auto& subgrid_ranges = subgrid_track_collection.ranges_;

    const wtf_size_t range_count = end_range_index - begin_range_index;
    wtf_size_t current_begin_set_index = 0;
    wtf_size_t current_start_line = 0;

    subgrid_ranges.ReserveInitialCapacity(range_count + 1);

    for (wtf_size_t i = 0; i <= range_count; ++i) {
      // Opposite direction subgrids need to iterate backwards.
      const wtf_size_t current_index = is_opposite_direction_in_root_grid
                                           ? end_range_index - i
                                           : begin_range_index + i;

      auto& subgrid_translated_range =
          subgrid_ranges.emplace_back(ranges_[current_index]);
      subgrid_translated_range.begin_set_index = current_begin_set_index;
      current_begin_set_index += subgrid_translated_range.set_count;

      subgrid_translated_range.start_line = current_start_line;
      current_start_line += subgrid_translated_range.track_count;

      subgrid_properties |= subgrid_translated_range.properties;
    }
  }

  const wtf_size_t set_span_size = end_set_index - begin_set_index;

  // Copy the sets geometry and adjust its offsets to accommodate the subgrid's
  // margin, border, scrollbar, padding, and gutter size.
  const auto subgrid_gutter_size_delta = subgrid_gutter_size - gutter_size_;

  const bool is_for_columns = subgrid_track_direction == kForColumns;
  const auto subgrid_margin_start =
      is_for_columns ? subgrid_margin.inline_start : subgrid_margin.block_start;

  const auto subgrid_border_scrollbar_padding_start =
      is_for_columns ? subgrid_border_scrollbar_padding.inline_start
                     : subgrid_border_scrollbar_padding.block_start;

  const auto subgrid_margin_border_scrollbar_padding_start =
      subgrid_margin_start + subgrid_border_scrollbar_padding_start;
  const auto subgrid_margin_border_scrollbar_padding_end =
      is_for_columns ? subgrid_margin.inline_end +
                           subgrid_border_scrollbar_padding.inline_end
                     : subgrid_margin.block_end +
                           subgrid_border_scrollbar_padding.block_end;

  // Accumulate the extra margin from the spanned sets in the parent track
  // collection and this subgrid's margins and gutter size delta.
  {
    subgrid_track_collection.accumulated_gutter_size_delta_ =
        subgrid_gutter_size_delta + accumulated_gutter_size_delta_;

    auto& subgrid_sets_geometry = subgrid_track_collection.sets_geometry_;
    subgrid_sets_geometry.ReserveInitialCapacity(set_span_size + 1);
    subgrid_sets_geometry.emplace_back(
        /* offset */ subgrid_border_scrollbar_padding_start);

    // Opposite direction subgrids adjust extra margin from the opposite side.
    subgrid_track_collection.accumulated_start_extra_margin_ =
        subgrid_margin_border_scrollbar_padding_start +
        (is_opposite_direction_in_root_grid
             ? EndExtraMargin(end_set_index)
             : StartExtraMargin(begin_set_index));

    subgrid_track_collection.accumulated_end_extra_margin_ =
        subgrid_margin_border_scrollbar_padding_end +
        (is_opposite_direction_in_root_grid ? StartExtraMargin(begin_set_index)
                                            : EndExtraMargin(end_set_index));

    // Opposite direction subgrids iterate backwards.
    const wtf_size_t first_set_index =
        is_opposite_direction_in_root_grid ? end_set_index : begin_set_index;
    LayoutUnit first_set_offset = sets_geometry_[first_set_index].offset;

    if (is_opposite_direction_in_root_grid) {
      first_set_offset -= subgrid_margin_start;
    } else {
      first_set_offset += subgrid_margin_start;
    }

    for (wtf_size_t i = 1; i < set_span_size; ++i) {
      // Opposite direction subgrids need to iterate backwards.
      const wtf_size_t current_index = is_opposite_direction_in_root_grid
                                           ? end_set_index - i
                                           : begin_set_index + i;
      auto& set =
          subgrid_sets_geometry.emplace_back(sets_geometry_[current_index]);
      if (is_opposite_direction_in_root_grid) {
        set.offset = first_set_offset - set.offset;

        // Opposite direction subgrids take their offset from the current index,
        // but their track counts from the subsequent index.
        const wtf_size_t next_index = current_index + 1;
        DCHECK_LT(next_index, sets_geometry_.size());
        set.track_count = sets_geometry_[next_index].track_count;
      } else {
        set.offset -= first_set_offset;
      }
      DCHECK_GT(set.track_count, 0U);
      set.offset += subgrid_gutter_size_delta / 2;
    }
    const wtf_size_t last_set_index =
        is_opposite_direction_in_root_grid ? begin_set_index : end_set_index;
    auto& last_set =
        subgrid_sets_geometry.emplace_back(sets_geometry_[last_set_index]);

    if (is_opposite_direction_in_root_grid) {
      last_set.offset = first_set_offset - last_set.offset;
      // Opposite direction subgrids take their offset from the current index,
      // but their track counts from the subsequent index.
      const wtf_size_t next_index = last_set_index + 1;
      DCHECK_LT(next_index, sets_geometry_.size());
      last_set.track_count = sets_geometry_[next_index].track_count;
    } else {
      last_set.offset -= first_set_offset;
    }
    last_set.offset +=
        subgrid_gutter_size_delta - subgrid_margin_border_scrollbar_padding_end;
    DCHECK_GT(last_set.track_count, 0U);
  }

  // Copy the last indefinite indices in the subgrid's span.
  if (!last_indefinite_index_.empty()) {
    auto& subgrid_last_indefinite_index =
        subgrid_track_collection.last_indefinite_index_;

    subgrid_last_indefinite_index.ReserveInitialCapacity(set_span_size + 1);
    subgrid_last_indefinite_index.push_back(kNotFound);

    wtf_size_t last_indefinite_index = kNotFound;
    for (wtf_size_t i = 0; i < set_span_size; ++i) {
      // Opposite direction subgrids need to iterate backwards.
      const wtf_size_t current_index = is_opposite_direction_in_root_grid
                                           ? end_set_index - i - 1
                                           : begin_set_index + i;

      DCHECK_LT(current_index + 1, last_indefinite_index_.size());

      // Map the last indefinite index from the parent track collection by
      // looking for a change in subsequent entries.
      if (last_indefinite_index_[current_index + 1] !=
          last_indefinite_index_[current_index]) {
        last_indefinite_index = i;
      }
      subgrid_last_indefinite_index.push_back(last_indefinite_index);
    }
  }

  // Copy the major and minor baselines in the subgrid's span.
  if (baselines_ && !baselines_->major.empty()) {
    DCHECK_LE(end_set_index, baselines_->major.size());
    DCHECK_LE(end_set_index, baselines_->minor.size());

    Baselines subgrid_baselines;
    subgrid_baselines.major.ReserveInitialCapacity(set_span_size);
    subgrid_baselines.minor.ReserveInitialCapacity(set_span_size);

    // Adjust the baselines to accommodate the subgrid extra margins.
    for (wtf_size_t i = 0; i < set_span_size; ++i) {
      LayoutUnit major_adjust =
          (i == 0) ? subgrid_margin_border_scrollbar_padding_start
                   : subgrid_gutter_size_delta / 2;
      LayoutUnit minor_adjust =
          (i == set_span_size - 1) ? subgrid_margin_border_scrollbar_padding_end
                                   : subgrid_gutter_size_delta / 2;
      if (is_opposite_direction_in_root_grid) {
        std::swap(major_adjust, minor_adjust);
      }
      const wtf_size_t current_index = is_opposite_direction_in_root_grid
                                           ? end_set_index - i - 1
                                           : begin_set_index + i;
      subgrid_baselines.major.emplace_back(baselines_->major[current_index] -
                                           major_adjust);
      subgrid_baselines.minor.emplace_back(baselines_->minor[current_index] -
                                           minor_adjust);
 
"""


```