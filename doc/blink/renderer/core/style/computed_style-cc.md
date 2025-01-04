Response:
The user is asking for a summary of the functionality of the `computed_style.cc` file in the Chromium Blink rendering engine, along with specific examples related to JavaScript, HTML, and CSS. I need to analyze the provided code snippet and identify its key responsibilities.

Here's a breakdown of the thought process:

1. **Identify the Core Purpose:** The file name `computed_style.cc` and the class `ComputedStyle` strongly suggest this file is responsible for managing the final, computed style of an element after applying all relevant CSS rules.

2. **Analyze Includes:** The included header files offer valuable clues about the functionalities involved.
    * `computed_style.h`, `computed_style_constants.h`, `computed_style_initial_values.h`: These likely define the structure, constants, and initial values for the `ComputedStyle` class.
    * `css/...`:  Includes related to CSS properties, values, and the CSSOM (CSS Object Model). This confirms the file's connection to CSS.
    * `dom/document.h`: Suggests interaction with the DOM (Document Object Model).
    * `layout/...`: Indicates involvement in the layout process.
    * `paint/...`: Points to responsibilities related to painting and rendering.
    * `animation/...`:  Shows support for CSS animations and transitions.
    * `style/...`: Implies interactions with other styling components.

3. **Examine Key Code Sections:**
    * **Copyright and License:** Standard licensing information.
    * **Includes:** Already analyzed.
    * **`ASSERT_SIZE`:**  A safety check to ensure the size of the `ComputedStyle` object remains consistent, likely important for performance and memory management.
    * **Caching Mechanisms (`cached_data_`, `pseudo_element_styles_`, `variable_names_`):** Indicates that `ComputedStyle` stores and manages cached styling information for performance optimization. This is crucial for avoiding redundant style calculations.
    * **`GetInitialStyleSingleton` and `GetInitialStyleForImgSingleton`:**  Provides access to default or initial styles. This is important for elements that don't have explicitly defined styles.
    * **Constructors:**  Different constructors allow for creating `ComputedStyle` objects in various ways.
    * **`PseudoElementStylesEqual`:** A function to compare the styles of pseudo-elements.
    * **`DiffAffectsContainerQueries` and `DiffAffectsScrollAnimations`:** Functions checking for style changes that impact container queries and scroll-driven animations, respectively.
    * **`NeedsReattachLayoutTree`:**  A critical function that determines if changes in computed style necessitate a re-layout of the DOM tree. This directly links `ComputedStyle` to the layout process.
    * **`ComputeDifference` and `ComputeDifferenceIgnoringInheritedFirstLineStyle`:**  Functions to calculate the difference between two `ComputedStyle` objects, crucial for optimizing updates and repaints.
    * **`ResolvedAlignSelf`, `ResolvedJustifySelf`, `ResolvedAlignContent`, `ResolvedJustifyContent`:** Functions to resolve the final values of alignment properties based on parent styles and other factors.
    * **`operator==`:** Defines how to compare two `ComputedStyle` objects for equality.
    * **`HighlightPseudoElementStylesDependOn...` and `HighlightPseudoElementStylesHaveVariableReferences`:**  Functions to check if highlight pseudo-element styles depend on specific units or variables.
    * **`GetCachedPseudoElementStyle`, `AddCachedPseudoElementStyle`, `ReplaceCachedPseudoElementStyle`, `ClearCachedPseudoElementStyles`:** Functions for managing the cached styles of pseudo-elements.
    * **`GetBaseComputedStyle` and `GetBaseImportantSet`:**  Likely related to style inheritance and cascading.
    * **`InheritedEqual`, `IndependentInheritedEqual`, `NonIndependentInheritedEqual`, `NonInheritedEqual`, `InheritedDataShared`:** Functions to compare different aspects of the `ComputedStyle` object, crucial for change detection.
    * **`VisualInvalidationDiff`:**  Calculates the differences that require visual invalidation (repainting).

4. **Relate to JavaScript, HTML, and CSS:**
    * **CSS:** The entire purpose of `ComputedStyle` is to manage the final CSS styles applied to an element. Examples include how CSS properties like `display`, `color`, `font-size`, layout properties (flexbox, grid), and pseudo-elements are handled.
    * **HTML:** `ComputedStyle` is associated with HTML elements. The code mentions specific HTML elements like `img`, `legend`, `progress`, `body`, `html`, and `li`. The computed style determines how these elements are rendered.
    * **JavaScript:** JavaScript can access and modify the computed style of an element through the `getComputedStyle()` method. The `ComputedStyle` class is the underlying data structure that holds this information. Changes made via JavaScript can trigger updates to the `ComputedStyle`.

5. **Identify Logical Reasoning:** The `ComputeDifference` and related functions demonstrate logical reasoning. They take two `ComputedStyle` objects as input and output a `Difference` enum, effectively classifying the type and impact of the style changes. The `NeedsReattachLayoutTree` function uses conditional logic to determine if a more significant layout update is required.

6. **Consider User/Programming Errors:** Incorrectly setting CSS properties or using invalid values can lead to unexpected computed styles. For instance, setting `display: none` will result in a computed style where the element is not rendered. Programmers might also make errors when manipulating styles via JavaScript, leading to inconsistencies.

7. **Formulate the Summary:** Combine the observations to create a concise summary of the file's functionality. Emphasize its central role in determining the final style of an element.

By following this thought process, I can arrive at a comprehensive and accurate summary of the `computed_style.cc` file's purpose and its relationship with web technologies.
```cpp
/*
 * Copyright (C) 1999 Antti Koivisto (koivisto@kde.org)
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010 Apple Inc. All rights
 * reserved.
 * Copyright (C) 2011 Adobe Systems Incorporated. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB. If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#include "third_party/blink/renderer/core/style/computed_style.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "base/memory/values_equivalent.h"
#include "base/metrics/histogram_functions.h"
#include "base/numerics/clamped_math.h"
#include "base/ranges/algorithm.h"
#include "build/build_config.h"
#include "cc/input/overscroll_behavior.h"
#include "cc/paint/paint_flags.h"
#include "third_party/blink/public/mojom/css/preferred_color_scheme.mojom-blink.h"
#include "third_party/blink/renderer/core/animation/css/css_animation_data.h"
#include "third_party/blink/renderer/core/animation/css/css_transition_data.h"
#include "third_party/blink/renderer/core/css/css_paint_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_property_equality.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/properties/computed_style_utils.h"
#include "third_party/blink/renderer/core/css/properties/css_property.h"
#include "third_party/blink/renderer/core/css/properties/longhand.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/forms/html_legend_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/html/html_li_element.h"
#include "third_party/blink/renderer/core/html/html_progress_element.h"
#include "third_party/blink/renderer/core/layout/custom/layout_worklet.h"
#include "third_party/blink/renderer/core/layout/layout_block.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"
#include "third_party/blink/renderer/core/layout/map_coordinates_flags.h"
#include "third_party/blink/renderer/core/layout/text_autosizer.h"
#include "third_party/blink/renderer/core/paint/compositing/compositing_reason_finder.h"
#include "third_party/blink/renderer/core/style/applied_text_decoration.h"
#include "third_party/blink/renderer/core/style/basic_shapes.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/style/computed_style_initial_values.h"
#include "third_party/blink/renderer/core/style/content_data.h"
#include "third_party/blink/renderer/core/style/coord_box_offset_path_operation.h"
#include "third_party/blink/renderer/core/style/cursor_data.h"
#include "third_party/blink/renderer/core/style/reference_offset_path_operation.h"
#include "third_party/blink/renderer/core/style/shadow_list.h"
#include "third_party/blink/renderer/core/style/shape_offset_path_operation.h"
#include "third_party/blink/renderer/core/style/style_difference.h"
#include "third_party/blink/renderer/core/style/style_fetched_image.h"
#include "third_party/blink/renderer/core/style/style_generated_image.h"
#include "third_party/blink/renderer/core/style/style_image.h"
#include "third_party/blink/renderer/core/style/style_inherited_variables.h"
#include "third_party/blink/renderer/core/style/style_non_inherited_variables.h"
#include "third_party/blink/renderer/core/style/style_ray.h"
#include "third_party/blink/renderer/core/svg/svg_element.h"
#include "third_party/blink/renderer/core/svg/svg_geometry_element.h"
#include "third_party/blink/renderer/core/svg/svg_length_functions.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/fonts/font_selector.h"
#include "third_party/blink/renderer/platform/geometry/length_functions.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/path.h"
#include "third_party/blink/renderer/platform/text/capitalize.h"
#include "third_party/blink/renderer/platform/text/character.h"
#include "third_party/blink/renderer/platform/text/quotes_data.h"
#include "third_party/blink/renderer/platform/transforms/rotate_transform_operation.h"
#include "third_party/blink/renderer/platform/transforms/scale_transform_operation.h"
#include "third_party/blink/renderer/platform/transforms/translate_transform_operation.h"
#include "third_party/blink/renderer/platform/wtf/assertions.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"
#include "third_party/blink/renderer/platform/wtf/text/case_map.h"
#include "third_party/blink/renderer/platform/wtf/text/math_transform.h"
#include "third_party/blink/renderer/platform/wtf/text/text_offset_map.h"
#include "third_party/blink/renderer/platform/wtf/thread_specific.h"
#include "ui/base/ui_base_features.h"
#include "ui/gfx/geometry/point_f.h"

namespace blink {

// Since different compilers/architectures pack ComputedStyle differently,
// re-create the same structure for an accurate size comparison.
//
// Keep a separate struct for ComputedStyleBase so that we can recreate the
// inheritance structure. Make sure the fields have the same access specifiers
// as in the "real" class since it can affect the layout. Reference the fields
// so that they are not seen as unused (-Wunused-private-field).
struct SameSizeAsComputedStyleBase
    : public GarbageCollected<SameSizeAsComputedStyleBase> {
  SameSizeAsComputedStyleBase() {
    base::debug::Alias(&pointers);
    base::debug::Alias(&bitfields);
  }

 private:
  Member<void*> pointers[10];
  unsigned bitfields[5];
};

struct SameSizeAsComputedStyle : public SameSizeAsComputedStyleBase {
  SameSizeAsComputedStyle() { base::debug::Alias(&own_ptrs); }

 private:
  Member<void*> own_ptrs[1];
};

// If this assert fails, it means that size of ComputedStyle has changed. Please
// check that you really *do* want to increase the size of ComputedStyle, then
// update the SameSizeAsComputedStyle struct to match the updated storage of
// ComputedStyle.
ASSERT_SIZE(ComputedStyle, SameSizeAsComputedStyle);

StyleCachedData& ComputedStyle::EnsureCachedData() const {
  if (!cached_data_) {
    cached_data_ = MakeGarbageCollected<StyleCachedData>();
  }
  return *cached_data_;
}

bool ComputedStyle::HasCachedPseudoElementStyles() const {
  return cached_data_ && cached_data_->pseudo_element_styles_ &&
         cached_data_->pseudo_element_styles_->size();
}

PseudoElementStyleCache* ComputedStyle::GetPseudoElementStyleCache() const {
  if (cached_data_) {
    return cached_data_->pseudo_element_styles_.Get();
  }
  return nullptr;
}

PseudoElementStyleCache& ComputedStyle::EnsurePseudoElementStyleCache() const {
  if (!cached_data_ || !cached_data_->pseudo_element_styles_) {
    EnsureCachedData().pseudo_element_styles_ =
        MakeGarbageCollected<PseudoElementStyleCache>();
  }
  return *cached_data_->pseudo_element_styles_;
}

const ComputedStyle* ComputedStyle::GetInitialStyleSingleton() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(
      ThreadSpecific<Persistent<const ComputedStyle>>,
      thread_specific_initial_style, ());
  Persistent<const ComputedStyle>& persistent = *thread_specific_initial_style;
  if (!persistent) [[unlikely]] {
    persistent = MakeGarbageCollected<ComputedStyle>(PassKey());
    LEAK_SANITIZER_IGNORE_OBJECT(&persistent);
  }
  return persistent.Get();
}

namespace {

const ComputedStyle* BuildInitialStyleForImg(
    const ComputedStyle& initial_style) {
  // This matches the img {} declarations in html.css to avoid copy-on-write
  // when only UA styles apply for these properties. See crbug.com/1369454
  // for details.
  ComputedStyleBuilder builder(initial_style);
  builder.SetOverflowX(EOverflow::kClip);
  builder.SetOverflowY(EOverflow::kClip);
  builder.SetOverflowClipMargin(StyleOverflowClipMargin::CreateContent());
  return builder.TakeStyle();
}

}  // namespace

const ComputedStyle* ComputedStyle::GetInitialStyleForImgSingleton() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(
      ThreadSpecific<Persistent<const ComputedStyle>>,
      thread_specific_initial_style, ());
  Persistent<const ComputedStyle>& persistent = *thread_specific_initial_style;
  if (!persistent) [[unlikely]] {
    persistent = BuildInitialStyleForImg(*GetInitialStyleSingleton());
    LEAK_SANITIZER_IGNORE_OBJECT(&persistent);
  }
  return persistent.Get();
}

Vector<AtomicString>* ComputedStyle::GetVariableNamesCache() const {
  if (cached_data_) {
    return cached_data_->variable_names_.get();
  }
  return nullptr;
}

Vector<AtomicString>& ComputedStyle::EnsureVariableNamesCache() const {
  if (!cached_data_ || !cached_data_->variable_names_) {
    EnsureCachedData().variable_names_ =
        std::make_unique<Vector<AtomicString>>();
  }
  return *cached_data_->variable_names_;
}

ALWAYS_INLINE ComputedStyle::ComputedStyle() = default;

ALWAYS_INLINE ComputedStyle::ComputedStyle(const ComputedStyle& initial_style)
    : ComputedStyleBase(initial_style) {}

ALWAYS_INLINE ComputedStyle::ComputedStyle(const ComputedStyleBuilder& builder)
    : ComputedStyleBase(builder) {}

ALWAYS_INLINE ComputedStyle::ComputedStyle(PassKey key) : ComputedStyle() {}

ALWAYS_INLINE ComputedStyle::ComputedStyle(BuilderPassKey key,
                                           const ComputedStyle& initial_style)
    : ComputedStyle(initial_style) {}

ALWAYS_INLINE ComputedStyle::ComputedStyle(BuilderPassKey key,
                                           const ComputedStyleBuilder& builder)
    : ComputedStyle(builder) {}

static bool PseudoElementStylesEqual(const ComputedStyle& old_style,
                                     const ComputedStyle& new_style) {
  if (!old_style.HasAnyPseudoElementStyles() &&
      !new_style.HasAnyPseudoElementStyles()) {
    return true;
  }
  for (PseudoId pseudo_id = kFirstPublicPseudoId;
       pseudo_id <= kLastTrackedPublicPseudoId;
       pseudo_id = static_cast<PseudoId>(pseudo_id + 1)) {
    if (!old_style.HasPseudoElementStyle(pseudo_id) &&
        !new_style.HasPseudoElementStyle(pseudo_id)) {
      continue;
    }
    // Highlight pseudo styles are stored in StyleHighlightData, and compared
    // like any other inherited field, yielding Difference::kInherited.
    if (UsesHighlightPseudoInheritance(pseudo_id)) {
      continue;
    }
    const ComputedStyle* new_pseudo_style =
        new_style.GetCachedPseudoElementStyle(pseudo_id);
    if (!new_pseudo_style) {
      return false;
    }
    const ComputedStyle* old_pseudo_style =
        old_style.GetCachedPseudoElementStyle(pseudo_id);
    if (old_pseudo_style && *old_pseudo_style != *new_pseudo_style) {
      return false;
    }
  }
  return true;
}

static bool DiffAffectsContainerQueries(const ComputedStyle& old_style,
                                        const ComputedStyle& new_style) {
  if (!old_style.IsContainerForSizeContainerQueries() &&
      !new_style.IsContainerForSizeContainerQueries() &&
      !old_style.IsContainerForScrollStateContainerQueries() &&
      !new_style.IsContainerForScrollStateContainerQueries()) {
    return false;
  }
  if (!base::ValuesEquivalent(old_style.ContainerName(),
                              new_style.ContainerName()) ||
      (old_style.ContainerType() != new_style.ContainerType())) {
    return true;
  }
  if (new_style.Display() != old_style.Display()) {
    if (new_style.Display() == EDisplay::kNone ||
        new_style.Display() == EDisplay::kContents) {
      return true;
    }
  }
  return false;
}

static bool DiffAffectsScrollAnimations(const ComputedStyle& old_style,
                                        const ComputedStyle& new_style) {
  if (!base::ValuesEquivalent(old_style.ScrollTimelineName(),
                              new_style.ScrollTimelineName()) ||
      (old_style.ScrollTimelineAxis() != new_style.ScrollTimelineAxis())) {
    return true;
  }
  if (!base::ValuesEquivalent(old_style.ViewTimelineName(),
                              new_style.ViewTimelineName()) ||
      (old_style.ViewTimelineAxis() != new_style.ViewTimelineAxis()) ||
      (old_style.ViewTimelineInset() != new_style.ViewTimelineInset())) {
    return true;
  }
  if (!base::ValuesEquivalent(old_style.TimelineScope(),
                              new_style.TimelineScope())) {
    return true;
  }
  return false;
}

bool ComputedStyle::NeedsReattachLayoutTree(const Element& element,
                                            const ComputedStyle* old_style,
                                            const ComputedStyle* new_style) {
  if (old_style == new_style) {
    return false;
  }
  if (!old_style || !new_style) {
    return true;
  }
  if (old_style->Display() != new_style->Display()) {
    return true;
  }
  if (old_style->HasPseudoElementStyle(kPseudoIdFirstLetter) !=
      new_style->HasPseudoElementStyle(kPseudoIdFirstLetter)) {
    return true;
  }
  if (!old_style->ContentDataEquivalent(*new_style)) {
    return true;
  }
  if (old_style->HasTextCombine() != new_style->HasTextCombine()) {
    return true;
  }
  if (!old_style->ScrollMarkerGroupEqual(*new_style)) {
    return true;
  }
  // line-clamping is currently only handled by LayoutDeprecatedFlexibleBox,
  // so that if line-clamping changes then the LayoutObject needs to be
  // recreated.
  if (old_style->IsDeprecatedFlexboxUsingFlexLayout() !=
      new_style->IsDeprecatedFlexboxUsingFlexLayout()) {
    return true;
  }
  // We need to perform a reattach if a "display: layout(foo)" has changed to a
  // "display: layout(bar)". This is because one custom layout could be
  // registered and the other may not, affecting the box-tree construction.
  if (old_style->DisplayLayoutCustomName() !=
      new_style->DisplayLayoutCustomName()) {
    return true;
  }
  if (old_style->HasEffectiveAppearance() !=
          new_style->HasEffectiveAppearance() &&
      IsA<HTMLProgressElement>(element)) {
    // HTMLProgressElement::CreateLayoutObject creates different LayoutObjects
    // based on appearance.
    return true;
  }

  // LayoutObject tree structure for <legend> depends on whether it's a
  // rendered legend or not.
  if (IsA<HTMLLegendElement>(element) &&
      (old_style->IsFloating() != new_style->IsFloating() ||
       old_style->HasOutOfFlowPosition() != new_style->HasOutOfFlowPosition()))
      [[unlikely]] {
    return true;
  }

  // We use LayoutTextCombine only for vertical writing mode.
  if (new_style->HasTextCombine() && old_style->IsHorizontalWritingMode() !=
                                         new_style->IsHorizontalWritingMode()) {
    DCHECK_EQ(old_style->HasTextCombine(), new_style->HasTextCombine());
    return true;
  }

  // LayoutNG needs an anonymous inline wrapper if ::first-line is applied.
  // Also see |LayoutBlockFlow::NeedsAnonymousInlineWrapper()|.
  if (new_style->HasPseudoElementStyle(kPseudoIdFirstLine) &&
      !old_style->HasPseudoElementStyle(kPseudoIdFirstLine)) {
    return true;
  }

  if (old_style->Overlay() != new_style->Overlay()) {
    return true;
  }
  if (old_style->ListStylePosition() != new_style->ListStylePosition()) {
    return true;
  }
  return false;
}

ComputedStyle::Difference ComputedStyle::ComputeDifference(
    const ComputedStyle* old_style,
    const ComputedStyle* new_style) {
  if (old_style == new_style) {
    return Difference::kEqual;
  }
  if (!old_style || !new_style) {
    return Difference::kInherited;
  }

  // For inline elements, the new computed first line style will be |new_style|
  // inheriting from the parent's first line style. If |new_style| is different
  // from |old_style|'s cached inherited first line style, the new computed
  // first line style may be different from the old even if |new_style| and
  // |old_style| equal. Especially if the difference is on inherited properties,
  // we need to propagate the difference to descendants.
  // See external/wpt/css/css-pseudo/first-line-change-inline-color*.html.
  auto inherited_first_line_style_diff = Difference::kEqual;
  if (const ComputedStyle* cached_inherited_first_line_style =
          old_style->GetCachedPseudoElementStyle(kPseudoIdFirstLineInherited)) {
    DCHECK(
        !new_style->GetCachedPseudoElementStyle(kPseudoIdFirstLineInherited));
    inherited_first_line_style_diff =
        ComputeDifferenceIgnoringInheritedFirstLineStyle(
            *cached_inherited_first_line_style, *new_style);
  }
  return std::max(
      inherited_first_line_style_diff,
      ComputeDifferenceIgnoringInheritedFirstLineStyle(*old_style, *new_style));
}

ComputedStyle::Difference
ComputedStyle::ComputeDifferenceIgnoringInheritedFirstLineStyle(
    const ComputedStyle& old_style,
    const ComputedStyle& new_style) {
  DCHECK_NE(&old_style, &new_style);
  if (DiffAffectsScrollAnimations(old_style, new_style)) {
    return Difference::kDescendantAffecting;
  }
  if (old_style.Display() != new_style.Display() &&
      (old_style.BlockifiesChildren() != new_style.BlockifiesChildren() ||
       old_style.InlinifiesChildren() != new_style.InlinifiesChildren())) {
    return Difference::kDescendantAffecting;
  }
  // TODO(crbug.com/1213888): Only recalc affected descendants.
  if (DiffAffectsContainerQueries(old_style, new_style)) {
    return Difference::kDescendantAffecting;
  }
  if (!old_style.NonIndependentInheritedEqual(new_style)) {
    return Difference::kInherited;
  }
  if (old_style.JustifyItems() != new_style.JustifyItems()) {
    return Difference::kInherited;
  }
  if (old_style.AppliedTextDecorations() !=
      new_style.AppliedTextDecorations()) {
    return Difference::kInherited;
  }
  bool non_inherited_equal = old_style.NonInheritedEqual(new_style);
  if (!non_inherited_equal && old_style.ChildHasExplicitInheritance()) {
    return Difference::kInherited;
  }
  bool variables_independent =
      !old_style.HasVariableReference() && !old_style.HasVariableDeclaration();
  bool inherited_variables_equal = old_style.InheritedVariablesEqual(new_style);
  if (!inherited_variables_equal && !variables_independent) {
    return Difference::kInherited;
  }
  if (!old_style.IndependentInheritedEqual(new_style) ||
      !inherited_variables_equal) {
    return Difference::kIndependentInherited;
  }
  if (non_inherited_equal) {
    DCHECK(old_style == new_style);
    if (PseudoElementStylesEqual(old_style, new_style)) {
      return Difference::kEqual;
    }
    return Difference::kPseudoElementStyle;
  }
  if (new_style.HasAnyPseudoElementStyles() ||
      old_style.HasAnyPseudoElementStyles()) {
    return Difference::kPseudoElementStyle;
  }
  if (old_style.Display() != new_style.Display() &&
      (new_style.IsDisplayListItem() || old_style.IsDisplayListItem())) {
    return Difference::kPseudoElementStyle;
  }
  return Difference::kNonInherited;
}

StyleSelfAlignmentData ResolvedSelfAlignment(
    const StyleSelfAlignmentData& value,
    const StyleSelfAlignmentData& normal_value_behavior,
    bool has_out_of_flow_position) {
  if (value.GetPosition() == ItemPosition::kLegacy ||
      value.GetPosition() == ItemPosition::kNormal ||
      value.GetPosition() == ItemPosition::kAuto) {
    return normal_value_behavior;
  }
  if (!has_out_of_flow_position &&
      value.GetPosition() == ItemPosition::kAnchorCenter) {
    return {ItemPosition::kCenter, value.Overflow(), value.PositionType()};
  }
  return value;
}

StyleSelfAlignmentData ComputedStyle::ResolvedAlignSelf(
    const StyleSelfAlignmentData& normal_value_behavior,
    const ComputedStyle* parent_style) const {
  // We will return the behaviour of 'normal' value if needed, which is specific
  // of each layout model.
  if (!parent_style || AlignSelf().GetPosition() != ItemPosition::kAuto) {
    return ResolvedSelfAlignment(AlignSelf(), normal_value_behavior,
                                 HasOutOfFlowPosition());
  }

  // The 'auto' keyword computes to the parent's align-items computed value.
  return ResolvedSelfAlignment(parent_style->AlignItems(),
                               normal_value_behavior, HasOutOfFlowPosition());
}

StyleSelfAlignmentData ComputedStyle::ResolvedJustifySelf(
    const StyleSelfAlignmentData& normal_value_behavior,
    const ComputedStyle* parent_style) const {
  // We will return the behaviour of 'normal' value if needed, which is specific
  // of each layout model.
  if (!parent_style || JustifySelf().GetPosition() != ItemPosition::kAuto) {
    return ResolvedSelfAlignment(JustifySelf(), normal_value_behavior,
                                 HasOutOfFlowPosition());
  }

  // The auto keyword computes to the parent's justify-items computed value.
  return ResolvedSelfAlignment(parent_style->JustifyItems(),
                               normal_value_behavior, HasOutOfFlowPosition());
}

StyleContentAlignmentData ResolvedContentAlignment(
    const StyleContentAlignmentData& value,
    const StyleContentAlignmentData& normal_behaviour) {
  return (value.GetPosition() == ContentPosition::kNormal &&
          value.Distribution() == ContentDistributionType::kDefault)
             ? normal_behaviour
             : value;
}

StyleContentAlignmentData ComputedStyle::ResolvedAlignContent(
    const StyleContentAlignmentData& normal_behaviour) const {
  // We will return the behaviour of 'normal' value if needed, which is specific
  // of each layout model.
  return ResolvedContentAlignment(AlignContent(), normal_behaviour);
}

StyleContentAlignmentData ComputedStyle::ResolvedJustifyContent(
    const StyleContentAlignmentData& normal_behaviour) const {
  // We will return the behaviour of 'normal' value if needed, which is specific
  // of each layout model.
  return ResolvedContentAlignment(JustifyContent(), normal_behaviour);
}

static inline ContentPosition ResolvedContentAlignmentPosition(
    const StyleContentAlignmentData& value,
    const StyleContentAlignmentData& normal_value_behavior) {
  return (value.GetPosition() == ContentPosition::kNormal &&
          value.Distribution() == ContentDistributionType::kDefault)
             ? normal_value_behavior.GetPosition()
             : value.GetPosition();
}

static inline ContentDistributionType ResolvedContentAlignmentDistribution(
    const StyleContentAlignmentData& value,
    const StyleContentAlignmentData& normal_value_behavior) {
  return (value.GetPosition() == ContentPosition::kNormal &&
          value.Distribution() == ContentDistributionType::kDefault)
             ? normal_value_behavior.Distribution()
             : value.Distribution();
}

ContentPosition ComputedStyle::ResolvedJustifyContentPosition(
    const StyleContentAlignmentData& normal_value_behavior) const {
  return ResolvedContentAlignmentPosition(JustifyContent(),
                                          normal_value_behavior);
}

ContentDistributionType ComputedStyle::ResolvedJustifyContentDistribution(
    const StyleContentAlignmentData& normal_value_behavior) const {
  return ResolvedContentAlignmentDistribution(JustifyContent(),
                                              normal_value_behavior);
}

ContentPosition ComputedStyle::ResolvedAlignContentPosition(
    const StyleContentAlignmentData& normal_value_behavior) const {
  return ResolvedContentAlignmentPosition(AlignContent(),
                                          normal_value_behavior);
}

ContentDistributionType ComputedStyle::ResolvedAlignContentDistribution(
    const StyleContentAlignmentData& normal_value_behavior) const {
  return ResolvedContentAlignmentDistribution(AlignContent(),
                                              normal_value_behavior);
}

bool ComputedStyle::operator==(const ComputedStyle& o) const {
  return InheritedEqual(o) && NonInheritedEqual(
Prompt: 
```
这是目录为blink/renderer/core/style/computed_style.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 1999 Antti Koivisto (koivisto@kde.org)
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010 Apple Inc. All rights
 * reserved.
 * Copyright (C) 2011 Adobe Systems Incorporated. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#include "third_party/blink/renderer/core/style/computed_style.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "base/memory/values_equivalent.h"
#include "base/metrics/histogram_functions.h"
#include "base/numerics/clamped_math.h"
#include "base/ranges/algorithm.h"
#include "build/build_config.h"
#include "cc/input/overscroll_behavior.h"
#include "cc/paint/paint_flags.h"
#include "third_party/blink/public/mojom/css/preferred_color_scheme.mojom-blink.h"
#include "third_party/blink/renderer/core/animation/css/css_animation_data.h"
#include "third_party/blink/renderer/core/animation/css/css_transition_data.h"
#include "third_party/blink/renderer/core/css/css_paint_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_property_equality.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/properties/computed_style_utils.h"
#include "third_party/blink/renderer/core/css/properties/css_property.h"
#include "third_party/blink/renderer/core/css/properties/longhand.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/forms/html_legend_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/html/html_li_element.h"
#include "third_party/blink/renderer/core/html/html_progress_element.h"
#include "third_party/blink/renderer/core/layout/custom/layout_worklet.h"
#include "third_party/blink/renderer/core/layout/layout_block.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"
#include "third_party/blink/renderer/core/layout/map_coordinates_flags.h"
#include "third_party/blink/renderer/core/layout/text_autosizer.h"
#include "third_party/blink/renderer/core/paint/compositing/compositing_reason_finder.h"
#include "third_party/blink/renderer/core/style/applied_text_decoration.h"
#include "third_party/blink/renderer/core/style/basic_shapes.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/style/computed_style_initial_values.h"
#include "third_party/blink/renderer/core/style/content_data.h"
#include "third_party/blink/renderer/core/style/coord_box_offset_path_operation.h"
#include "third_party/blink/renderer/core/style/cursor_data.h"
#include "third_party/blink/renderer/core/style/reference_offset_path_operation.h"
#include "third_party/blink/renderer/core/style/shadow_list.h"
#include "third_party/blink/renderer/core/style/shape_offset_path_operation.h"
#include "third_party/blink/renderer/core/style/style_difference.h"
#include "third_party/blink/renderer/core/style/style_fetched_image.h"
#include "third_party/blink/renderer/core/style/style_generated_image.h"
#include "third_party/blink/renderer/core/style/style_image.h"
#include "third_party/blink/renderer/core/style/style_inherited_variables.h"
#include "third_party/blink/renderer/core/style/style_non_inherited_variables.h"
#include "third_party/blink/renderer/core/style/style_ray.h"
#include "third_party/blink/renderer/core/svg/svg_element.h"
#include "third_party/blink/renderer/core/svg/svg_geometry_element.h"
#include "third_party/blink/renderer/core/svg/svg_length_functions.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/fonts/font_selector.h"
#include "third_party/blink/renderer/platform/geometry/length_functions.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/path.h"
#include "third_party/blink/renderer/platform/text/capitalize.h"
#include "third_party/blink/renderer/platform/text/character.h"
#include "third_party/blink/renderer/platform/text/quotes_data.h"
#include "third_party/blink/renderer/platform/transforms/rotate_transform_operation.h"
#include "third_party/blink/renderer/platform/transforms/scale_transform_operation.h"
#include "third_party/blink/renderer/platform/transforms/translate_transform_operation.h"
#include "third_party/blink/renderer/platform/wtf/assertions.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"
#include "third_party/blink/renderer/platform/wtf/text/case_map.h"
#include "third_party/blink/renderer/platform/wtf/text/math_transform.h"
#include "third_party/blink/renderer/platform/wtf/text/text_offset_map.h"
#include "third_party/blink/renderer/platform/wtf/thread_specific.h"
#include "ui/base/ui_base_features.h"
#include "ui/gfx/geometry/point_f.h"

namespace blink {

// Since different compilers/architectures pack ComputedStyle differently,
// re-create the same structure for an accurate size comparison.
//
// Keep a separate struct for ComputedStyleBase so that we can recreate the
// inheritance structure. Make sure the fields have the same access specifiers
// as in the "real" class since it can affect the layout. Reference the fields
// so that they are not seen as unused (-Wunused-private-field).
struct SameSizeAsComputedStyleBase
    : public GarbageCollected<SameSizeAsComputedStyleBase> {
  SameSizeAsComputedStyleBase() {
    base::debug::Alias(&pointers);
    base::debug::Alias(&bitfields);
  }

 private:
  Member<void*> pointers[10];
  unsigned bitfields[5];
};

struct SameSizeAsComputedStyle : public SameSizeAsComputedStyleBase {
  SameSizeAsComputedStyle() { base::debug::Alias(&own_ptrs); }

 private:
  Member<void*> own_ptrs[1];
};

// If this assert fails, it means that size of ComputedStyle has changed. Please
// check that you really *do* want to increase the size of ComputedStyle, then
// update the SameSizeAsComputedStyle struct to match the updated storage of
// ComputedStyle.
ASSERT_SIZE(ComputedStyle, SameSizeAsComputedStyle);

StyleCachedData& ComputedStyle::EnsureCachedData() const {
  if (!cached_data_) {
    cached_data_ = MakeGarbageCollected<StyleCachedData>();
  }
  return *cached_data_;
}

bool ComputedStyle::HasCachedPseudoElementStyles() const {
  return cached_data_ && cached_data_->pseudo_element_styles_ &&
         cached_data_->pseudo_element_styles_->size();
}

PseudoElementStyleCache* ComputedStyle::GetPseudoElementStyleCache() const {
  if (cached_data_) {
    return cached_data_->pseudo_element_styles_.Get();
  }
  return nullptr;
}

PseudoElementStyleCache& ComputedStyle::EnsurePseudoElementStyleCache() const {
  if (!cached_data_ || !cached_data_->pseudo_element_styles_) {
    EnsureCachedData().pseudo_element_styles_ =
        MakeGarbageCollected<PseudoElementStyleCache>();
  }
  return *cached_data_->pseudo_element_styles_;
}

const ComputedStyle* ComputedStyle::GetInitialStyleSingleton() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(
      ThreadSpecific<Persistent<const ComputedStyle>>,
      thread_specific_initial_style, ());
  Persistent<const ComputedStyle>& persistent = *thread_specific_initial_style;
  if (!persistent) [[unlikely]] {
    persistent = MakeGarbageCollected<ComputedStyle>(PassKey());
    LEAK_SANITIZER_IGNORE_OBJECT(&persistent);
  }
  return persistent.Get();
}

namespace {

const ComputedStyle* BuildInitialStyleForImg(
    const ComputedStyle& initial_style) {
  // This matches the img {} declarations in html.css to avoid copy-on-write
  // when only UA styles apply for these properties. See crbug.com/1369454
  // for details.
  ComputedStyleBuilder builder(initial_style);
  builder.SetOverflowX(EOverflow::kClip);
  builder.SetOverflowY(EOverflow::kClip);
  builder.SetOverflowClipMargin(StyleOverflowClipMargin::CreateContent());
  return builder.TakeStyle();
}

}  // namespace

const ComputedStyle* ComputedStyle::GetInitialStyleForImgSingleton() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(
      ThreadSpecific<Persistent<const ComputedStyle>>,
      thread_specific_initial_style, ());
  Persistent<const ComputedStyle>& persistent = *thread_specific_initial_style;
  if (!persistent) [[unlikely]] {
    persistent = BuildInitialStyleForImg(*GetInitialStyleSingleton());
    LEAK_SANITIZER_IGNORE_OBJECT(&persistent);
  }
  return persistent.Get();
}

Vector<AtomicString>* ComputedStyle::GetVariableNamesCache() const {
  if (cached_data_) {
    return cached_data_->variable_names_.get();
  }
  return nullptr;
}

Vector<AtomicString>& ComputedStyle::EnsureVariableNamesCache() const {
  if (!cached_data_ || !cached_data_->variable_names_) {
    EnsureCachedData().variable_names_ =
        std::make_unique<Vector<AtomicString>>();
  }
  return *cached_data_->variable_names_;
}

ALWAYS_INLINE ComputedStyle::ComputedStyle() = default;

ALWAYS_INLINE ComputedStyle::ComputedStyle(const ComputedStyle& initial_style)
    : ComputedStyleBase(initial_style) {}

ALWAYS_INLINE ComputedStyle::ComputedStyle(const ComputedStyleBuilder& builder)
    : ComputedStyleBase(builder) {}

ALWAYS_INLINE ComputedStyle::ComputedStyle(PassKey key) : ComputedStyle() {}

ALWAYS_INLINE ComputedStyle::ComputedStyle(BuilderPassKey key,
                                           const ComputedStyle& initial_style)
    : ComputedStyle(initial_style) {}

ALWAYS_INLINE ComputedStyle::ComputedStyle(BuilderPassKey key,
                                           const ComputedStyleBuilder& builder)
    : ComputedStyle(builder) {}

static bool PseudoElementStylesEqual(const ComputedStyle& old_style,
                                     const ComputedStyle& new_style) {
  if (!old_style.HasAnyPseudoElementStyles() &&
      !new_style.HasAnyPseudoElementStyles()) {
    return true;
  }
  for (PseudoId pseudo_id = kFirstPublicPseudoId;
       pseudo_id <= kLastTrackedPublicPseudoId;
       pseudo_id = static_cast<PseudoId>(pseudo_id + 1)) {
    if (!old_style.HasPseudoElementStyle(pseudo_id) &&
        !new_style.HasPseudoElementStyle(pseudo_id)) {
      continue;
    }
    // Highlight pseudo styles are stored in StyleHighlightData, and compared
    // like any other inherited field, yielding Difference::kInherited.
    if (UsesHighlightPseudoInheritance(pseudo_id)) {
      continue;
    }
    const ComputedStyle* new_pseudo_style =
        new_style.GetCachedPseudoElementStyle(pseudo_id);
    if (!new_pseudo_style) {
      return false;
    }
    const ComputedStyle* old_pseudo_style =
        old_style.GetCachedPseudoElementStyle(pseudo_id);
    if (old_pseudo_style && *old_pseudo_style != *new_pseudo_style) {
      return false;
    }
  }
  return true;
}

static bool DiffAffectsContainerQueries(const ComputedStyle& old_style,
                                        const ComputedStyle& new_style) {
  if (!old_style.IsContainerForSizeContainerQueries() &&
      !new_style.IsContainerForSizeContainerQueries() &&
      !old_style.IsContainerForScrollStateContainerQueries() &&
      !new_style.IsContainerForScrollStateContainerQueries()) {
    return false;
  }
  if (!base::ValuesEquivalent(old_style.ContainerName(),
                              new_style.ContainerName()) ||
      (old_style.ContainerType() != new_style.ContainerType())) {
    return true;
  }
  if (new_style.Display() != old_style.Display()) {
    if (new_style.Display() == EDisplay::kNone ||
        new_style.Display() == EDisplay::kContents) {
      return true;
    }
  }
  return false;
}

static bool DiffAffectsScrollAnimations(const ComputedStyle& old_style,
                                        const ComputedStyle& new_style) {
  if (!base::ValuesEquivalent(old_style.ScrollTimelineName(),
                              new_style.ScrollTimelineName()) ||
      (old_style.ScrollTimelineAxis() != new_style.ScrollTimelineAxis())) {
    return true;
  }
  if (!base::ValuesEquivalent(old_style.ViewTimelineName(),
                              new_style.ViewTimelineName()) ||
      (old_style.ViewTimelineAxis() != new_style.ViewTimelineAxis()) ||
      (old_style.ViewTimelineInset() != new_style.ViewTimelineInset())) {
    return true;
  }
  if (!base::ValuesEquivalent(old_style.TimelineScope(),
                              new_style.TimelineScope())) {
    return true;
  }
  return false;
}

bool ComputedStyle::NeedsReattachLayoutTree(const Element& element,
                                            const ComputedStyle* old_style,
                                            const ComputedStyle* new_style) {
  if (old_style == new_style) {
    return false;
  }
  if (!old_style || !new_style) {
    return true;
  }
  if (old_style->Display() != new_style->Display()) {
    return true;
  }
  if (old_style->HasPseudoElementStyle(kPseudoIdFirstLetter) !=
      new_style->HasPseudoElementStyle(kPseudoIdFirstLetter)) {
    return true;
  }
  if (!old_style->ContentDataEquivalent(*new_style)) {
    return true;
  }
  if (old_style->HasTextCombine() != new_style->HasTextCombine()) {
    return true;
  }
  if (!old_style->ScrollMarkerGroupEqual(*new_style)) {
    return true;
  }
  // line-clamping is currently only handled by LayoutDeprecatedFlexibleBox,
  // so that if line-clamping changes then the LayoutObject needs to be
  // recreated.
  if (old_style->IsDeprecatedFlexboxUsingFlexLayout() !=
      new_style->IsDeprecatedFlexboxUsingFlexLayout()) {
    return true;
  }
  // We need to perform a reattach if a "display: layout(foo)" has changed to a
  // "display: layout(bar)". This is because one custom layout could be
  // registered and the other may not, affecting the box-tree construction.
  if (old_style->DisplayLayoutCustomName() !=
      new_style->DisplayLayoutCustomName()) {
    return true;
  }
  if (old_style->HasEffectiveAppearance() !=
          new_style->HasEffectiveAppearance() &&
      IsA<HTMLProgressElement>(element)) {
    // HTMLProgressElement::CreateLayoutObject creates different LayoutObjects
    // based on appearance.
    return true;
  }

  // LayoutObject tree structure for <legend> depends on whether it's a
  // rendered legend or not.
  if (IsA<HTMLLegendElement>(element) &&
      (old_style->IsFloating() != new_style->IsFloating() ||
       old_style->HasOutOfFlowPosition() != new_style->HasOutOfFlowPosition()))
      [[unlikely]] {
    return true;
  }

  // We use LayoutTextCombine only for vertical writing mode.
  if (new_style->HasTextCombine() && old_style->IsHorizontalWritingMode() !=
                                         new_style->IsHorizontalWritingMode()) {
    DCHECK_EQ(old_style->HasTextCombine(), new_style->HasTextCombine());
    return true;
  }

  // LayoutNG needs an anonymous inline wrapper if ::first-line is applied.
  // Also see |LayoutBlockFlow::NeedsAnonymousInlineWrapper()|.
  if (new_style->HasPseudoElementStyle(kPseudoIdFirstLine) &&
      !old_style->HasPseudoElementStyle(kPseudoIdFirstLine)) {
    return true;
  }

  if (old_style->Overlay() != new_style->Overlay()) {
    return true;
  }
  if (old_style->ListStylePosition() != new_style->ListStylePosition()) {
    return true;
  }
  return false;
}

ComputedStyle::Difference ComputedStyle::ComputeDifference(
    const ComputedStyle* old_style,
    const ComputedStyle* new_style) {
  if (old_style == new_style) {
    return Difference::kEqual;
  }
  if (!old_style || !new_style) {
    return Difference::kInherited;
  }

  // For inline elements, the new computed first line style will be |new_style|
  // inheriting from the parent's first line style. If |new_style| is different
  // from |old_style|'s cached inherited first line style, the new computed
  // first line style may be different from the old even if |new_style| and
  // |old_style| equal. Especially if the difference is on inherited properties,
  // we need to propagate the difference to descendants.
  // See external/wpt/css/css-pseudo/first-line-change-inline-color*.html.
  auto inherited_first_line_style_diff = Difference::kEqual;
  if (const ComputedStyle* cached_inherited_first_line_style =
          old_style->GetCachedPseudoElementStyle(kPseudoIdFirstLineInherited)) {
    DCHECK(
        !new_style->GetCachedPseudoElementStyle(kPseudoIdFirstLineInherited));
    inherited_first_line_style_diff =
        ComputeDifferenceIgnoringInheritedFirstLineStyle(
            *cached_inherited_first_line_style, *new_style);
  }
  return std::max(
      inherited_first_line_style_diff,
      ComputeDifferenceIgnoringInheritedFirstLineStyle(*old_style, *new_style));
}

ComputedStyle::Difference
ComputedStyle::ComputeDifferenceIgnoringInheritedFirstLineStyle(
    const ComputedStyle& old_style,
    const ComputedStyle& new_style) {
  DCHECK_NE(&old_style, &new_style);
  if (DiffAffectsScrollAnimations(old_style, new_style)) {
    return Difference::kDescendantAffecting;
  }
  if (old_style.Display() != new_style.Display() &&
      (old_style.BlockifiesChildren() != new_style.BlockifiesChildren() ||
       old_style.InlinifiesChildren() != new_style.InlinifiesChildren())) {
    return Difference::kDescendantAffecting;
  }
  // TODO(crbug.com/1213888): Only recalc affected descendants.
  if (DiffAffectsContainerQueries(old_style, new_style)) {
    return Difference::kDescendantAffecting;
  }
  if (!old_style.NonIndependentInheritedEqual(new_style)) {
    return Difference::kInherited;
  }
  if (old_style.JustifyItems() != new_style.JustifyItems()) {
    return Difference::kInherited;
  }
  if (old_style.AppliedTextDecorations() !=
      new_style.AppliedTextDecorations()) {
    return Difference::kInherited;
  }
  bool non_inherited_equal = old_style.NonInheritedEqual(new_style);
  if (!non_inherited_equal && old_style.ChildHasExplicitInheritance()) {
    return Difference::kInherited;
  }
  bool variables_independent =
      !old_style.HasVariableReference() && !old_style.HasVariableDeclaration();
  bool inherited_variables_equal = old_style.InheritedVariablesEqual(new_style);
  if (!inherited_variables_equal && !variables_independent) {
    return Difference::kInherited;
  }
  if (!old_style.IndependentInheritedEqual(new_style) ||
      !inherited_variables_equal) {
    return Difference::kIndependentInherited;
  }
  if (non_inherited_equal) {
    DCHECK(old_style == new_style);
    if (PseudoElementStylesEqual(old_style, new_style)) {
      return Difference::kEqual;
    }
    return Difference::kPseudoElementStyle;
  }
  if (new_style.HasAnyPseudoElementStyles() ||
      old_style.HasAnyPseudoElementStyles()) {
    return Difference::kPseudoElementStyle;
  }
  if (old_style.Display() != new_style.Display() &&
      (new_style.IsDisplayListItem() || old_style.IsDisplayListItem())) {
    return Difference::kPseudoElementStyle;
  }
  return Difference::kNonInherited;
}

StyleSelfAlignmentData ResolvedSelfAlignment(
    const StyleSelfAlignmentData& value,
    const StyleSelfAlignmentData& normal_value_behavior,
    bool has_out_of_flow_position) {
  if (value.GetPosition() == ItemPosition::kLegacy ||
      value.GetPosition() == ItemPosition::kNormal ||
      value.GetPosition() == ItemPosition::kAuto) {
    return normal_value_behavior;
  }
  if (!has_out_of_flow_position &&
      value.GetPosition() == ItemPosition::kAnchorCenter) {
    return {ItemPosition::kCenter, value.Overflow(), value.PositionType()};
  }
  return value;
}

StyleSelfAlignmentData ComputedStyle::ResolvedAlignSelf(
    const StyleSelfAlignmentData& normal_value_behavior,
    const ComputedStyle* parent_style) const {
  // We will return the behaviour of 'normal' value if needed, which is specific
  // of each layout model.
  if (!parent_style || AlignSelf().GetPosition() != ItemPosition::kAuto) {
    return ResolvedSelfAlignment(AlignSelf(), normal_value_behavior,
                                 HasOutOfFlowPosition());
  }

  // The 'auto' keyword computes to the parent's align-items computed value.
  return ResolvedSelfAlignment(parent_style->AlignItems(),
                               normal_value_behavior, HasOutOfFlowPosition());
}

StyleSelfAlignmentData ComputedStyle::ResolvedJustifySelf(
    const StyleSelfAlignmentData& normal_value_behavior,
    const ComputedStyle* parent_style) const {
  // We will return the behaviour of 'normal' value if needed, which is specific
  // of each layout model.
  if (!parent_style || JustifySelf().GetPosition() != ItemPosition::kAuto) {
    return ResolvedSelfAlignment(JustifySelf(), normal_value_behavior,
                                 HasOutOfFlowPosition());
  }

  // The auto keyword computes to the parent's justify-items computed value.
  return ResolvedSelfAlignment(parent_style->JustifyItems(),
                               normal_value_behavior, HasOutOfFlowPosition());
}

StyleContentAlignmentData ResolvedContentAlignment(
    const StyleContentAlignmentData& value,
    const StyleContentAlignmentData& normal_behaviour) {
  return (value.GetPosition() == ContentPosition::kNormal &&
          value.Distribution() == ContentDistributionType::kDefault)
             ? normal_behaviour
             : value;
}

StyleContentAlignmentData ComputedStyle::ResolvedAlignContent(
    const StyleContentAlignmentData& normal_behaviour) const {
  // We will return the behaviour of 'normal' value if needed, which is specific
  // of each layout model.
  return ResolvedContentAlignment(AlignContent(), normal_behaviour);
}

StyleContentAlignmentData ComputedStyle::ResolvedJustifyContent(
    const StyleContentAlignmentData& normal_behaviour) const {
  // We will return the behaviour of 'normal' value if needed, which is specific
  // of each layout model.
  return ResolvedContentAlignment(JustifyContent(), normal_behaviour);
}

static inline ContentPosition ResolvedContentAlignmentPosition(
    const StyleContentAlignmentData& value,
    const StyleContentAlignmentData& normal_value_behavior) {
  return (value.GetPosition() == ContentPosition::kNormal &&
          value.Distribution() == ContentDistributionType::kDefault)
             ? normal_value_behavior.GetPosition()
             : value.GetPosition();
}

static inline ContentDistributionType ResolvedContentAlignmentDistribution(
    const StyleContentAlignmentData& value,
    const StyleContentAlignmentData& normal_value_behavior) {
  return (value.GetPosition() == ContentPosition::kNormal &&
          value.Distribution() == ContentDistributionType::kDefault)
             ? normal_value_behavior.Distribution()
             : value.Distribution();
}

ContentPosition ComputedStyle::ResolvedJustifyContentPosition(
    const StyleContentAlignmentData& normal_value_behavior) const {
  return ResolvedContentAlignmentPosition(JustifyContent(),
                                          normal_value_behavior);
}

ContentDistributionType ComputedStyle::ResolvedJustifyContentDistribution(
    const StyleContentAlignmentData& normal_value_behavior) const {
  return ResolvedContentAlignmentDistribution(JustifyContent(),
                                              normal_value_behavior);
}

ContentPosition ComputedStyle::ResolvedAlignContentPosition(
    const StyleContentAlignmentData& normal_value_behavior) const {
  return ResolvedContentAlignmentPosition(AlignContent(),
                                          normal_value_behavior);
}

ContentDistributionType ComputedStyle::ResolvedAlignContentDistribution(
    const StyleContentAlignmentData& normal_value_behavior) const {
  return ResolvedContentAlignmentDistribution(AlignContent(),
                                              normal_value_behavior);
}

bool ComputedStyle::operator==(const ComputedStyle& o) const {
  return InheritedEqual(o) && NonInheritedEqual(o) &&
         InheritedVariablesEqual(o);
}

bool ComputedStyle::HighlightPseudoElementStylesDependOnRelativeUnits() const {
  const StyleHighlightData& highlight_data = HighlightData();
  if (highlight_data.Selection() &&
      highlight_data.Selection()->HasAnyRelativeUnits()) {
    return true;
  }
  if (highlight_data.TargetText() &&
      highlight_data.TargetText()->HasAnyRelativeUnits()) {
    return true;
  }
  if (highlight_data.SpellingError() &&
      highlight_data.SpellingError()->HasAnyRelativeUnits()) {
    return true;
  }
  if (highlight_data.GrammarError() &&
      highlight_data.GrammarError()->HasAnyRelativeUnits()) {
    return true;
  }
  const CustomHighlightsStyleMap& custom_highlights =
      highlight_data.CustomHighlights();
  for (auto custom_highlight : custom_highlights) {
    if (custom_highlight.value->HasAnyRelativeUnits()) {
      return true;
    }
  }

  return false;
}

bool ComputedStyle::HighlightPseudoElementStylesDependOnContainerUnits() const {
  const StyleHighlightData& highlight_data = HighlightData();
  if (highlight_data.Selection() &&
      highlight_data.Selection()->HasContainerRelativeUnits()) {
    return true;
  }
  if (highlight_data.TargetText() &&
      highlight_data.TargetText()->HasContainerRelativeUnits()) {
    return true;
  }
  if (highlight_data.SpellingError() &&
      highlight_data.SpellingError()->HasContainerRelativeUnits()) {
    return true;
  }
  if (highlight_data.GrammarError() &&
      highlight_data.GrammarError()->HasContainerRelativeUnits()) {
    return true;
  }
  const CustomHighlightsStyleMap& custom_highlights =
      highlight_data.CustomHighlights();
  for (auto custom_highlight : custom_highlights) {
    if (custom_highlight.value->HasContainerRelativeUnits()) {
      return true;
    }
  }

  return false;
}

bool ComputedStyle::HighlightPseudoElementStylesDependOnViewportUnits() const {
  const StyleHighlightData& highlight_data = HighlightData();
  if (highlight_data.Selection() &&
      highlight_data.Selection()->HasViewportUnits()) {
    return true;
  }
  if (highlight_data.TargetText() &&
      highlight_data.TargetText()->HasViewportUnits()) {
    return true;
  }
  if (highlight_data.SpellingError() &&
      highlight_data.SpellingError()->HasViewportUnits()) {
    return true;
  }
  if (highlight_data.GrammarError() &&
      highlight_data.GrammarError()->HasViewportUnits()) {
    return true;
  }
  const CustomHighlightsStyleMap& custom_highlights =
      highlight_data.CustomHighlights();
  for (auto custom_highlight : custom_highlights) {
    if (custom_highlight.value->HasViewportUnits()) {
      return true;
    }
  }

  return false;
}

bool ComputedStyle::HighlightPseudoElementStylesHaveVariableReferences() const {
  const StyleHighlightData& highlight_data = HighlightData();
  if (highlight_data.Selection() &&
      highlight_data.Selection()->HasVariableReference()) {
    return true;
  }
  if (highlight_data.TargetText() &&
      highlight_data.TargetText()->HasVariableReference()) {
    return true;
  }
  if (highlight_data.SpellingError() &&
      highlight_data.SpellingError()->HasVariableReference()) {
    return true;
  }
  if (highlight_data.GrammarError() &&
      highlight_data.GrammarError()->HasVariableReference()) {
    return true;
  }
  const CustomHighlightsStyleMap& custom_highlights =
      highlight_data.CustomHighlights();
  for (auto custom_highlight : custom_highlights) {
    if (custom_highlight.value->HasVariableReference()) {
      return true;
    }
  }

  return false;
}

const ComputedStyle* ComputedStyle::GetCachedPseudoElementStyle(
    PseudoId pseudo_id,
    const AtomicString& pseudo_argument) const {
  if (!HasCachedPseudoElementStyles()) {
    return nullptr;
  }

  for (const auto& pseudo_style : *GetPseudoElementStyleCache()) {
    if (pseudo_style->StyleType() == pseudo_id &&
        (!PseudoElementHasArguments(pseudo_id) ||
         pseudo_style->PseudoArgument() == pseudo_argument)) {
      return pseudo_style.Get();
    }
  }

  return nullptr;
}

const ComputedStyle* ComputedStyle::AddCachedPseudoElementStyle(
    const ComputedStyle* pseudo,
    PseudoId pseudo_id,
    const AtomicString& pseudo_argument) const {
  DCHECK(pseudo);

  // Confirm that the styles being cached are for the (PseudoId,argument) that
  // the caller intended (and presumably had checked was not present).
  DCHECK_EQ(static_cast<unsigned>(pseudo->StyleType()),
            static_cast<unsigned>(pseudo_id));
  DCHECK_EQ(pseudo->PseudoArgument(), pseudo_argument);

  // The pseudo style cache assumes that only one entry will be added for any
  // any given (PseudoId,argument). Adding more than one entry is a bug, even
  // if the styles being cached are equal.
  DCHECK(!GetCachedPseudoElementStyle(pseudo->StyleType(),
                                      pseudo->PseudoArgument()));

  const ComputedStyle* result = pseudo;

  EnsurePseudoElementStyleCache().push_back(std::move(pseudo));

  return result;
}

const ComputedStyle* ComputedStyle::ReplaceCachedPseudoElementStyle(
    const ComputedStyle* pseudo_style,
    PseudoId pseudo_id,
    const AtomicString& pseudo_argument) const {
  DCHECK(pseudo_style->StyleType() != kPseudoIdNone &&
         pseudo_style->StyleType() != kPseudoIdFirstLineInherited);
  if (HasCachedPseudoElementStyles()) {
    for (auto& cached_style : *GetPseudoElementStyleCache()) {
      if (cached_style->StyleType() == pseudo_id &&
          (!PseudoElementHasArguments(pseudo_id) ||
           cached_style->PseudoArgument() == pseudo_argument)) {
        SECURITY_CHECK(cached_style->IsEnsuredInDisplayNone());
        cached_style = pseudo_style;
        return pseudo_style;
      }
    }
  }
  return AddCachedPseudoElementStyle(pseudo_style, pseudo_id, pseudo_argument);
}

void ComputedStyle::ClearCachedPseudoElementStyles() const {
  if (cached_data_ && cached_data_->pseudo_element_styles_) {
    cached_data_->pseudo_element_styles_->clear();
  }
}

const ComputedStyle* ComputedStyle::GetBaseComputedStyle() const {
  if (StyleBaseData* base_data = BaseData()) {
    return base_data->GetBaseComputedStyle();
  }
  return nullptr;
}

const CSSBitset* ComputedStyle::GetBaseImportantSet() const {
  if (StyleBaseData* base_data = BaseData()) {
    return base_data->GetBaseImportantSet();
  }
  return nullptr;
}

bool ComputedStyle::InheritedEqual(const ComputedStyle& other) const {
  return IndependentInheritedEqual(other) &&
         NonIndependentInheritedEqual(other);
}

bool ComputedStyle::IndependentInheritedEqual(
    const ComputedStyle& other) const {
  return ComputedStyleBase::IndependentInheritedEqual(other);
}

bool ComputedStyle::NonIndependentInheritedEqual(
    const ComputedStyle& other) const {
  return ComputedStyleBase::NonIndependentInheritedEqual(other);
}

bool ComputedStyle::NonInheritedEqual(const ComputedStyle& other) const {
  // compare everything except the pseudoStyle pointer
  return ComputedStyleBase::NonInheritedEqual(other);
}

bool ComputedStyle::InheritedDataShared(const ComputedStyle& other) const {
  // We use a by-value check that is a bit more expensive than
  // pointer comparison, but yields many more full MPC hits,
  // so it generally makes up for it.
  return ComputedStyleBase::InheritedDataShared(other);
}

StyleDifference ComputedStyle::VisualInvalidationDiff(
    const Document& document,
    const ComputedStyle& other) const {
  StyleDifference diff;
  uint64_t field_diff = FieldInvalidationDiff(*this, other);

  if ((field_diff & kReshape) || ShouldWrapLine() != other.ShouldWrapLine()) {
    diff.SetNeedsReshape();
    diff.SetNeedsFullLayout();
    diff.SetNeedsNormalPaintInvalidation();
  }

  if (IsStackingContextWithoutContainment() !=
      other.IsStackingContextWithoutContainment()) {
    diff.SetNeedsFu
"""


```