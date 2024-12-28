Response:
My thinking process for summarizing the functionality of `layout_box.cc` went something like this:

1. **Understand the Context:** The prompt clearly states this is a Chromium Blink engine source file related to layout. The path `blink/renderer/core/layout/` confirms this. The file name `layout_box.cc` strongly suggests it's the core implementation for the `LayoutBox` class, a fundamental building block of the layout engine.

2. **Scan the Includes:**  The included headers provide a wealth of information about the file's responsibilities. I looked for recurring themes and key areas:
    * **Layout Primitives:** `LayoutObject`, `LayoutBlock`, `LayoutInline`, `BoxFragment`, `ConstraintSpace`. These confirm the file deals with the basic building blocks of the layout tree and the process of laying out content.
    * **CSS Properties:** Includes related to CSS properties like `longhands.h`, `ComputedStyle`, `ShapeValue`. This indicates the file is involved in applying CSS rules and their effects on layout.
    * **DOM Interaction:**  Includes like `Document`, `Element`, `HTMLElement`, and specific HTML element headers (e.g., `HTMLInputElement`, `HTMLDivElement`) suggest interaction with the Document Object Model.
    * **Scrolling:** `ScrollSnapData`, `AutoscrollController`, `PaintLayerScrollableArea`. This points to the file's involvement in handling scrolling and related features.
    * **Painting:** `PaintLayer`, `BoxPaintInvalidator`, `OutlinePainter`. This suggests the file has a role in determining how elements are painted on the screen, though not the actual painting itself.
    * **Editing:** `EditingUtilities`, `InputMethodController`. This indicates involvement with text editing within the layout context.
    * **Geometry:**  `PhysicalOffset`, `PhysicalRect`, `FloatRoundedRect`. This is expected for a layout-related file, as it needs to deal with the positioning and sizing of elements.
    * **Custom Layout:** `CustomLayoutChild`, `LayoutCustom`, `LayoutWorklet`. This indicates support for CSS Custom Layout API.

3. **Analyze the Code Structure (High-Level):** I looked for key class definitions (specifically `LayoutBox`) and major function groups. The copyright notices and license information are less relevant for functional summarization.

4. **Focus on the `LayoutBox` Class:** The file name itself highlights this class. I looked for the declaration and its methods. The presence of methods like `InsertedIntoTree`, `WillBeRemovedFromTree`, `StyleWillChange`, `StyleDidChange`, and the destructor `~LayoutBox` strongly suggests this class manages the lifecycle and style updates of layout boxes.

5. **Examine Key Methods and Data Members:**  I paid close attention to methods that appeared to have significant responsibilities:
    * **Lifecycle Methods:**  `InsertedIntoTree`, `WillBeRemovedFromTree`, `WillBeDestroyed`. These manage the integration and removal of layout boxes within the layout tree.
    * **Style Handling:** `StyleWillChange`, `StyleDidChange`. These are crucial for reacting to changes in CSS styles and triggering necessary layout and paint updates.
    * **Layout-Related Methods:**  While the provided snippet doesn't contain the core layout calculation logic, the presence of includes for `BoxFragment`, `ConstraintSpace`, and mentions of intrinsic sizes indicates the `LayoutBox` class *participates* in the layout process.
    * **Scrolling Related Methods:** The presence of methods interacting with `PaintLayerScrollableArea` suggests management of scrollable areas.
    * **Painting Related Methods:** `LayerTypeRequired` and interactions with `PaintLayer` indicate control over paint layer creation and properties.

6. **Identify Relationships to Web Technologies:** Based on the includes and code snippets, I connected the functionality to JavaScript, HTML, and CSS:
    * **HTML:** The file directly deals with HTML elements and their layout representations.
    * **CSS:**  The file heavily relies on `ComputedStyle` and responds to CSS property changes, directly influencing how elements are rendered based on CSS rules.
    * **JavaScript:** While the snippet doesn't show direct JavaScript interaction, the mention of events and the overall function of the layout engine in rendering web pages implies an indirect relationship. JavaScript can manipulate the DOM and CSS, which in turn triggers the functionality within this file.

7. **Infer Logical Reasoning and Assumptions:** I considered how the code would behave based on certain inputs:
    * **Assumption:** When CSS properties change, the `StyleWillChange` and `StyleDidChange` methods are triggered.
    * **Output:** This triggers re-layout or re-painting, ensuring the visual representation matches the updated styles.
    * **Assumption:** When an element is added or removed from the DOM, `InsertedIntoTree` and `WillBeRemovedFromTree` are called.
    * **Output:** This ensures the layout tree is updated to reflect the DOM structure.

8. **Identify Potential User/Programming Errors:** I considered common mistakes developers might make that would involve this code:
    * Incorrect CSS leading to unexpected layout.
    * JavaScript manipulations causing layout thrashing.

9. **Synthesize the Summary:**  Based on the above steps, I formulated a summary that covers the key functionalities, relationships to web technologies, logical reasoning, and potential errors. I organized the summary into logical sections for clarity.

10. **Address the "Part 1 of 6" Instruction:**  I made sure the summary focused specifically on the content provided in the first part and avoided speculating about the content of the remaining parts. The explicit request was to summarize *this* part.

Essentially, I adopted a detective-like approach, piecing together clues from the code (includes, class names, method names) and my understanding of web technologies to deduce the purpose and functionality of the `layout_box.cc` file. The key was to move from the specific details in the code to a more general understanding of its role in the Blink rendering engine.
```
这是目录为blink/renderer/core/layout/layout_box.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能
"""
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2005 Allan Sandfeld Jensen (kde@carewolf.com)
 *           (C) 2005, 2006 Samuel Weinig (sam.weinig@gmail.com)
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Apple Inc.
 *               All rights reserved.
 * Copyright (C) 2013 Adobe Systems Incorporated. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB. If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#include "third_party/blink/renderer/core/layout/layout_box.h"

#include <math.h>

#include <algorithm>
#include <utility>

#include "base/memory/values_equivalent.h"
#include "cc/input/scroll_snap_data.h"
#include "third_party/blink/public/platform/web_theme_engine.h"
#include "third_party/blink/public/strings/grit/blink_strings.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/scroll_marker_group_pseudo_element.h"
#include "third_party/blink/renderer/core/dom/scroll_marker_pseudo_element.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/forms/html_button_element.h"
#include "third_party/blink/renderer/core/html/forms/html_field_set_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_legend_element.h"
#include "third_party/blink/renderer/core/html/forms/html_opt_group_element.h"
#include "third_party/blink/renderer/core/html/forms/html_option_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_frame_element_base.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_utils.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/layout/anchor_position_scroll_data.h"
#include "third_party/blink/renderer/core/layout/box_fragment_builder.h"
#include "third_party/blink/renderer/core/layout/constraint_space.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/custom/custom_layout_child.h"
#include "third_party/blink/renderer/core/layout/custom/layout_custom.h"
#include "third_party/blink/renderer/core/layout/custom/layout_worklet.h"
#include "third_party/blink/renderer/core/layout/custom/layout_worklet_global_scope_proxy.h"
#include "third_party/blink/renderer/core/layout/custom_scrollbar.h"
#include "third_party/blink/renderer/core/layout/disable_layout_side_effects_scope.h"
#include "third_party/blink/renderer/core/layout/forms/layout_fieldset.h"
#include "third_party/blink/renderer/core/layout/forms/layout_text_control.h"
#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/geometry/box_strut.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_offset.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_rect.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_multi_column_flow_thread.h"
#include "third_party/blink/renderer/core/layout/layout_multi_column_spanner_placeholder.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_object_inlines.h"
#include "third_party/blink/renderer/core/layout/layout_result.h"
#include "third_party/blink/renderer/core/layout/layout_utils.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/legacy_layout_tree_walking.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/logical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/measure_cache.h"
#include "third_party/blink/renderer/core/layout/shapes/shape_outside_info.h"
#include "third_party/blink/renderer/core/layout/table/layout_table.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_cell.h"
#include "third_party/blink/renderer/core/layout/text_utils.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource_content.h"
#include "third_party/blink/renderer/core/page/autoscroll_controller.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/box_paint_invalidator.h"
#include "third_party/blink/renderer/core/paint/object_paint_invalidator.h"
#include "third_party/blink/renderer/core/paint/outline_painter.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/paint/rounded_border_geometry.h"
#include "third_party/blink/renderer/core/resize_observer/resize_observer_size.h"
#include "third_party/blink/renderer/core/scroll/scroll_into_view_util.h"
#include "third_party/blink/renderer/core/style/computed_style_base_constants.h"
#include "third_party/blink/renderer/core/style/shadow_list.h"
#include "third_party/blink/renderer/core/style/style_overflow_clip_margin.h"
#include "third_party/blink/renderer/platform/geometry/float_rounded_rect.h"
#include "third_party/blink/renderer/platform/geometry/length_functions.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/platform_locale.h"
#include "third_party/blink/renderer/platform/theme/web_theme_engine_helper.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"
#include "ui/gfx/geometry/quad_f.h"
#include "ui/gfx/geometry/rect_conversions.h"

namespace blink {

using mojom::blink::FormControlType;

// Used by flexible boxes when flexing this element and by table cells.
typedef WTF::HashMap<const LayoutBox*, LayoutUnit> OverrideSizeMap;

// Size of border belt for autoscroll. When mouse pointer in border belt,
// autoscroll is started.
static const int kAutoscrollBeltSize = 20;
static const unsigned kBackgroundObscurationTestMaxDepth = 4;

struct SameSizeAsLayoutBox : public LayoutBoxModelObject {
  LayoutPoint frame_location_;
  PhysicalSize frame_size_;
  PhysicalSize previous_size;
  MinMaxSizes intrinsic_logical_widths;
  Member<void*> min_max_sizes_cache;
  Member<void*> cache;
  HeapVector<Member<const LayoutResult>, 1> layout_results;
  wtf_size_t first_fragment_item_index_;
  Member<void*> members[2];
};

ASSERT_SIZE(LayoutBox, SameSizeAsLayoutBox);

namespace {

LayoutUnit TextAreaIntrinsicInlineSize(const HTMLTextAreaElement& textarea,
                                       const LayoutBox& box) {
  // Always add the scrollbar thickness for 'overflow:auto'.
  const auto& style = box.StyleRef();
  int scrollbar_thickness = 0;
  if (style.OverflowBlockDirection() == EOverflow::kScroll ||
      style.OverflowBlockDirection() == EOverflow::kAuto) {
    scrollbar_thickness = layout_text_control::ScrollbarThickness(box);
  }

  return LayoutUnit(ceilf(layout_text_control::GetAvgCharWidth(style) *
                          textarea.cols())) +
         scrollbar_thickness;
}

LayoutUnit TextFieldIntrinsicInlineSize(const HTMLInputElement& input,
                                        const LayoutBox& box) {
  int factor;
  const bool includes_decoration = input.SizeShouldIncludeDecoration(factor);
  if (factor <= 0)
    factor = 20;

  const float char_width = layout_text_control::GetAvgCharWidth(box.StyleRef());
  float float_result = char_width * factor;

  float max_char_width = 0.f;
  const Font& font = box.StyleRef().GetFont();
  if (layout_text_control::HasValidAvgCharWidth(font)) {
    max_char_width = font.PrimaryFont()->MaxCharWidth();
  }

  // For text inputs, IE adds some extra width.
  if (max_char_width > char_width)
    float_result += max_char_width - char_width;

  LayoutUnit result(ceilf(float_result));
  if (includes_decoration) {
    const auto* spin_button =
        To<HTMLElement>(input.UserAgentShadowRoot()->getElementById(
            shadow_element_names::kIdSpinButton));
    if (LayoutBox* spin_box =
            spin_button ? spin_button->GetLayoutBox() : nullptr) {
      const Length& logical_width = spin_box->StyleRef().LogicalWidth();
      result += spin_box->BorderAndPaddingInlineSize();
      // Since the width of spin_box is not calculated yet,
      // spin_box->LogicalWidth() returns 0. Use the computed logical
      // width instead.
      if (logical_width.IsPercent()) {
        if (logical_width.Value() != 100.f) {
          result +=
              result * logical_width.Value() / (100 - logical_width.Value());
        }
      } else {
        result += logical_width.Value();
      }
    }
  }
  return result;
}

LayoutUnit TextAreaIntrinsicBlockSize(const HTMLTextAreaElement& textarea,
                                      const LayoutBox& box) {
  // Only add the scrollbar thickness for 'overflow: scroll'.
  int scrollbar_thickness = 0;
  if (box.StyleRef().OverflowInlineDirection() == EOverflow::kScroll) {
    scrollbar_thickness = layout_text_control::ScrollbarThickness(box);
  }

  const auto* inner_editor = textarea.InnerEditorElement();
  const LayoutUnit line_height =
      inner_editor && inner_editor->GetLayoutBox()
          ? inner_editor->GetLayoutBox()->FirstLineHeight()
          : box.FirstLineHeight();

  return line_height * textarea.rows() + scrollbar_thickness;
}

LayoutUnit TextFieldIntrinsicBlockSize(const HTMLInputElement& input,
                                       const LayoutBox& box) {
  const auto* inner_editor = input.InnerEditorElement();
  // inner_editor's LayoutBox can be nullptr because web authors can set
  // display:none to ::-webkit-textfield-decoration-container element.
  const LayoutBox& target_box = (inner_editor && inner_editor->GetLayoutBox())
                                    ? *inner_editor->GetLayoutBox()
                                    : box;
  return target_box.FirstLineHeight();
}

LayoutUnit FileUploadControlIntrinsicInlineSize(const HTMLInputElement& input,
                                                const LayoutBox& box) {
  // This should match to margin-inline-end of ::-webkit-file-upload-button UA
  // style.
  constexpr int kAfterButtonSpacing = 4;
  // Figure out how big the filename space needs to be for a given number of
  // characters (using "0" as the nominal character).
  constexpr int kDefaultWidthNumChars = 34;
  constexpr UChar kCharacter = '0';
  const String character_as_string = String(base::span_from_ref(kCharacter));
  const float min_default_label_width =
      kDefaultWidthNumChars *
      ComputeTextWidth(character_as_string, box.StyleRef());

  const String label =
      input.GetLocale().QueryString(IDS_FORM_FILE_NO_FILE_LABEL);
  float default_label_width = ComputeTextWidth(label, box.StyleRef());
  if (HTMLInputElement* button = input.UploadButton()) {
    if (auto* button_box = button->GetLayoutBox()) {
      const ComputedStyle& button_style = button_box->StyleRef();
      WritingMode mode = button_style.GetWritingMode();
      ConstraintSpaceBuilder builder(mode, button_style.GetWritingDirection(),
                                     /* is_new_fc */ true);
      LayoutUnit max = BlockNode(button_box)
                           .ComputeMinMaxSizes(mode, SizeType::kIntrinsic,
                                               builder.ToConstraintSpace())
                           .sizes.max_size;
      default_label_width +=
          max + (kAfterButtonSpacing * box.StyleRef().EffectiveZoom());
    }
  }
  return LayoutUnit(
      ceilf(std::max(min_default_label_width, default_label_width)));
}

LayoutUnit SliderIntrinsicInlineSize(const LayoutBox& box) {
  constexpr int kDefaultTrackLength = 129;
  return LayoutUnit(kDefaultTrackLength * box.StyleRef().EffectiveZoom());
}

LogicalSize ThemePartIntrinsicSize(const LayoutBox& box,
                                   WebThemeEngine::Part part) {
  const auto& style = box.StyleRef();
  PhysicalSize size(
      WebThemeEngineHelper::GetNativeThemeEngine()->GetSize(part));
  size.Scale(style.EffectiveZoom());
  return size.ConvertToLogical(style.GetWritingMode());
}

LayoutUnit ListBoxDefaultItemHeight(const LayoutBox& box) {
  constexpr int kDefaultPaddingBottom = 1;

  const SimpleFontData* font_data = box.StyleRef().GetFont().PrimaryFont();
  if (!font_data)
    return LayoutUnit();
  return LayoutUnit(font_data->GetFontMetrics().Height() +
                    kDefaultPaddingBottom);
}

// TODO(crbug.com/1040826): This function is written in LayoutObject API
// so that this works in both of the legacy layout and LayoutNG. We
// should have LayoutNG-specific code.
LayoutUnit ListBoxItemBlockSize(const HTMLSelectElement& select,
                                const LayoutBox& box) {
  const auto& items = select.GetListItems();
  if (items.empty() || box.ShouldApplySizeContainment())
    return ListBoxDefaultItemHeight(box);

  LayoutUnit max_block_size;
  for (Element* element : items) {
    if (auto* optgroup = DynamicTo<HTMLOptGroupElement>(element))
      element = &optgroup->OptGroupLabelElement();
    LayoutUnit item_block_size;
    if (auto* layout_box = element->GetLayoutBox()) {
      item_block_size = box.StyleRef().IsHorizontalWritingMode()
                            ? layout_box->Size().height
                            : layout_box->Size().width;
    } else {
      item_block_size = ListBoxDefaultItemHeight(box);
    }
    max_block_size = std::max(max_block_size, item_block_size);
  }
  return max_block_size;
}

LayoutUnit MenuListIntrinsicInlineSize(const HTMLSelectElement& select,
                                       const LayoutBox& box) {
  const ComputedStyle& style = box.StyleRef();
  float max_option_width = 0;
  if (!box.ShouldApplySizeContainment()) {
    for (auto* const option : select.GetOptionList()) {
      String text =
          style.ApplyTextTransform(option->TextIndentedToRespectGroupLabel());
      // We apply SELECT's style, not OPTION's style because max_option_width is
      // used to determine intrinsic width of the menulist box.
      max_option_width =
          std::max(max_option_width, ComputeTextWidth(text, style));
    }
  }

  LayoutTheme& theme = LayoutTheme::GetTheme();
  int paddings = theme.PopupInternalPaddingStart(style) +
                 theme.PopupInternalPaddingEnd(box.GetFrame(), style);
  return LayoutUnit(ceilf(max_option_width)) + LayoutUnit(paddings);
}

LayoutUnit MenuListIntrinsicBlockSize(const HTMLSelectElement& select,
                                      const LayoutBox& box) {
  if (!box.StyleRef().HasEffectiveAppearance())
    return kIndefiniteSize;
  const SimpleFontData* font_data = box.StyleRef().GetFont().PrimaryFont();
  DCHECK(font_data);
  const LayoutBox* inner_box = select.InnerElement().GetLayoutBox();
  return (font_data ? font_data->GetFontMetrics().Height() : 0) +
         (inner_box ? inner_box->BorderAndPaddingBlockSize() : LayoutUnit());
}

#if DCHECK_IS_ON()
void CheckDidAddFragment(const LayoutBox& box,
                         const PhysicalBoxFragment& new_fragment,
                         wtf_size_t new_fragment_index = kNotFound) {
  // If |HasFragmentItems|, |ChildrenInline()| should be true.
  // |HasFragmentItems| uses this condition to optimize .
  if (new_fragment.HasItems())
    DCHECK(box.ChildrenInline());

  wtf_size_t index = 0;
  for (const PhysicalBoxFragment& fragment : box.PhysicalFragments()) {
    DCHECK_EQ(fragment.IsFirstForNode(), index == 0);
    if (const FragmentItems* fragment_items = fragment.Items()) {
      fragment_items->CheckAllItemsAreValid();
    }
    // Don't check past the fragment just added. Those entries may be invalid at
    // this point.
    if (index == new_fragment_index)
      break;
    ++index;
  }
}
#else
inline void CheckDidAddFragment(const LayoutBox& box,
                                const PhysicalBoxFragment& fragment,
                                wtf_size_t new_fragment_index = kNotFound) {}
#endif

// Applies the overflow clip to |result|. For any axis that is clipped, |result|
// is reset to |no_overflow_rect|. If neither axis is clipped, nothing is
// changed.
void ApplyOverflowClip(OverflowClipAxes overflow_clip_axes,
                       const PhysicalRect& no_overflow_rect,
                       PhysicalRect& result) {
  if (overflow_clip_axes & kOverflowClipX) {
    result.SetX(no_overflow_rect.X());
    result.SetWidth(no_overflow_rect.Width());
  }
  if (overflow_clip_axes & kOverflowClipY) {
    result.SetY(no_overflow_rect.Y());
    result.SetHeight(no_overflow_rect.Height());
  }
}

int HypotheticalScrollbarThickness(const LayoutBox& box,
                                   ScrollbarOrientation scrollbar_orientation,
                                   bool should_include_overlay_thickness) {
  box.CheckIsNotDestroyed();

  if (PaintLayerScrollableArea* scrollable_area = box.GetScrollableArea()) {
    return scrollable_area->HypotheticalScrollbarThickness(
        scrollbar_orientation, should_include_overlay_thickness);
  } else {
    Page* page = box.GetFrame()->GetPage();
    ScrollbarTheme& theme = page->GetScrollbarTheme();

    if (theme.UsesOverlayScrollbars() && !should_include_overlay_thickness) {
      return 0;
    } else {
      ChromeClient& chrome_client = page->GetChromeClient();
      Document& document = box.GetDocument();
      float scale_from_dip =
          chrome_client.WindowToViewportScalar(document.GetFrame(), 1.0f);
      return theme.ScrollbarThickness(scale_from_dip,
                                      box.StyleRef().UsedScrollbarWidth());
    }
  }
}

void RecalcFragmentScrollableOverflow(RecalcScrollableOverflowResult& result,
                                      const PhysicalFragment& fragment) {
  for (const auto& child : fragment.PostLayoutChildren()) {
    if (child->GetLayoutObject()) {
      if (const auto* box = DynamicTo<PhysicalBoxFragment>(child.get())) {
        if (LayoutBox* owner_box = box->MutableOwnerLayoutBox())
          result.Unite(owner_box->RecalcScrollableOverflow());
      }
    } else {
      // We enter this branch when the |child| is a fragmentainer.
      RecalcFragmentScrollableOverflow(result, *child.get());
    }
  }
}

// Returns the logical offset in the LocationContainer() coordination system,
// and its WritingMode.
std::tuple<LogicalOffset, WritingMode> LogicalLocation(const LayoutBox& box) {
  LayoutBox* container = box.LocationContainer();
  WritingMode writing_mode = container->StyleRef().GetWritingMode();
  WritingModeConverter converter({writing_mode, TextDirection::kLtr},
                                 PhysicalSize(container->Size()));
  return {converter.ToLogical(box.PhysicalLocation(), PhysicalSize(box.Size())),
          writing_mode};
}

}  // namespace

LayoutBoxRareData::LayoutBoxRareData()
    : spanner_placeholder_(nullptr),
      // TODO(rego): We should store these based on physical direction.
      has_override_containing_block_content_logical_width_(false),
      has_previous_content_box_rect_(false) {}

void LayoutBoxRareData::Trace(Visitor* visitor) const {
  visitor->Trace(spanner_placeholder_);
  visitor->Trace(layout_child_);
}

LayoutBox::LayoutBox(ContainerNode* node) : LayoutBoxModelObject(node) {
  if (blink::IsA<HTMLLegendElement>(node))
    SetIsHTMLLegendElement();
}

void LayoutBox::Trace(Visitor* visitor) const {
  visitor->Trace(min_max_sizes_cache_);
  visitor->Trace(measure_cache_);
  visitor->Trace(layout_results_);
  visitor->Trace(overflow_);
  visitor->Trace(rare_data_);
  LayoutBoxModelObject::Trace(visitor);
}

LayoutBox::~LayoutBox() = default;

PaintLayerType LayoutBox::LayerTypeRequired() const {
  NOT_DESTROYED();
  if (IsStacked() || HasHiddenBackface() ||
      (StyleRef().SpecifiesColumns() && !IsLayoutNGObject()))
    return kNormalPaintLayer;

  if (HasNonVisibleOverflow() && !IsLayoutReplaced()) {
    return kOverflowClipPaintLayer;
  }

  return kNoPaintLayer;
}

void LayoutBox::WillBeDestroyed() {
  NOT_DESTROYED();
  ClearOverrideContainingBlockContentSize();

  ShapeOutsideInfo::RemoveInfo(*this);

  if (!DocumentBeingDestroyed()) {
    DisassociatePhysicalFragments();
  }

  if (Style() && StyleRef().HasOutOfFlowPosition()) {
    if (auto* display_locks = DisplayLocksAffectedByAnchors()) {
      NotifyContainingDisplayLocksForAnchorPositioning(display_locks, nullptr);
    }
  }

  LayoutBoxModelObject::WillBeDestroyed();
}

void LayoutBox::DisassociatePhysicalFragments() {
  if (FirstInlineFragmentItemIndex()) {
    FragmentItems::LayoutObjectWillBeDestroyed(*this);
    ClearFirstInlineFragmentItemIndex();
  }
  if (measure_cache_) {
    measure_cache_->LayoutObjectWillBeDestroyed();
  }
  for (auto result : layout_results_)
    result->GetPhysicalFragment().LayoutObjectWillBeDestroyed();
}

void LayoutBox::InsertedIntoTree() {
  NOT_DESTROYED();
  LayoutBoxModelObject::InsertedIntoTree();
  AddCustomLayoutChildIfNeeded();
}

void LayoutBox::WillBeRemovedFromTree() {
  NOT_DESTROYED();
  ClearCustomLayoutChild();
  LayoutBoxModelObject::WillBeRemovedFromTree();
}

void LayoutBox::StyleWillChange(StyleDifference diff
Prompt: 
```
这是目录为blink/renderer/core/layout/layout_box.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2005 Allan Sandfeld Jensen (kde@carewolf.com)
 *           (C) 2005, 2006 Samuel Weinig (sam.weinig@gmail.com)
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Apple Inc.
 *               All rights reserved.
 * Copyright (C) 2013 Adobe Systems Incorporated. All rights reserved.
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

#include "third_party/blink/renderer/core/layout/layout_box.h"

#include <math.h>

#include <algorithm>
#include <utility>

#include "base/memory/values_equivalent.h"
#include "cc/input/scroll_snap_data.h"
#include "third_party/blink/public/platform/web_theme_engine.h"
#include "third_party/blink/public/strings/grit/blink_strings.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/scroll_marker_group_pseudo_element.h"
#include "third_party/blink/renderer/core/dom/scroll_marker_pseudo_element.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/forms/html_button_element.h"
#include "third_party/blink/renderer/core/html/forms/html_field_set_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_legend_element.h"
#include "third_party/blink/renderer/core/html/forms/html_opt_group_element.h"
#include "third_party/blink/renderer/core/html/forms/html_option_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_frame_element_base.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_utils.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/layout/anchor_position_scroll_data.h"
#include "third_party/blink/renderer/core/layout/box_fragment_builder.h"
#include "third_party/blink/renderer/core/layout/constraint_space.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/custom/custom_layout_child.h"
#include "third_party/blink/renderer/core/layout/custom/layout_custom.h"
#include "third_party/blink/renderer/core/layout/custom/layout_worklet.h"
#include "third_party/blink/renderer/core/layout/custom/layout_worklet_global_scope_proxy.h"
#include "third_party/blink/renderer/core/layout/custom_scrollbar.h"
#include "third_party/blink/renderer/core/layout/disable_layout_side_effects_scope.h"
#include "third_party/blink/renderer/core/layout/forms/layout_fieldset.h"
#include "third_party/blink/renderer/core/layout/forms/layout_text_control.h"
#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/geometry/box_strut.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_offset.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_rect.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_multi_column_flow_thread.h"
#include "third_party/blink/renderer/core/layout/layout_multi_column_spanner_placeholder.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_object_inlines.h"
#include "third_party/blink/renderer/core/layout/layout_result.h"
#include "third_party/blink/renderer/core/layout/layout_utils.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/legacy_layout_tree_walking.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/logical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/measure_cache.h"
#include "third_party/blink/renderer/core/layout/shapes/shape_outside_info.h"
#include "third_party/blink/renderer/core/layout/table/layout_table.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_cell.h"
#include "third_party/blink/renderer/core/layout/text_utils.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource_content.h"
#include "third_party/blink/renderer/core/page/autoscroll_controller.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/box_paint_invalidator.h"
#include "third_party/blink/renderer/core/paint/object_paint_invalidator.h"
#include "third_party/blink/renderer/core/paint/outline_painter.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/paint/rounded_border_geometry.h"
#include "third_party/blink/renderer/core/resize_observer/resize_observer_size.h"
#include "third_party/blink/renderer/core/scroll/scroll_into_view_util.h"
#include "third_party/blink/renderer/core/style/computed_style_base_constants.h"
#include "third_party/blink/renderer/core/style/shadow_list.h"
#include "third_party/blink/renderer/core/style/style_overflow_clip_margin.h"
#include "third_party/blink/renderer/platform/geometry/float_rounded_rect.h"
#include "third_party/blink/renderer/platform/geometry/length_functions.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/platform_locale.h"
#include "third_party/blink/renderer/platform/theme/web_theme_engine_helper.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"
#include "ui/gfx/geometry/quad_f.h"
#include "ui/gfx/geometry/rect_conversions.h"

namespace blink {

using mojom::blink::FormControlType;

// Used by flexible boxes when flexing this element and by table cells.
typedef WTF::HashMap<const LayoutBox*, LayoutUnit> OverrideSizeMap;

// Size of border belt for autoscroll. When mouse pointer in border belt,
// autoscroll is started.
static const int kAutoscrollBeltSize = 20;
static const unsigned kBackgroundObscurationTestMaxDepth = 4;

struct SameSizeAsLayoutBox : public LayoutBoxModelObject {
  LayoutPoint frame_location_;
  PhysicalSize frame_size_;
  PhysicalSize previous_size;
  MinMaxSizes intrinsic_logical_widths;
  Member<void*> min_max_sizes_cache;
  Member<void*> cache;
  HeapVector<Member<const LayoutResult>, 1> layout_results;
  wtf_size_t first_fragment_item_index_;
  Member<void*> members[2];
};

ASSERT_SIZE(LayoutBox, SameSizeAsLayoutBox);

namespace {

LayoutUnit TextAreaIntrinsicInlineSize(const HTMLTextAreaElement& textarea,
                                       const LayoutBox& box) {
  // Always add the scrollbar thickness for 'overflow:auto'.
  const auto& style = box.StyleRef();
  int scrollbar_thickness = 0;
  if (style.OverflowBlockDirection() == EOverflow::kScroll ||
      style.OverflowBlockDirection() == EOverflow::kAuto) {
    scrollbar_thickness = layout_text_control::ScrollbarThickness(box);
  }

  return LayoutUnit(ceilf(layout_text_control::GetAvgCharWidth(style) *
                          textarea.cols())) +
         scrollbar_thickness;
}

LayoutUnit TextFieldIntrinsicInlineSize(const HTMLInputElement& input,
                                        const LayoutBox& box) {
  int factor;
  const bool includes_decoration = input.SizeShouldIncludeDecoration(factor);
  if (factor <= 0)
    factor = 20;

  const float char_width = layout_text_control::GetAvgCharWidth(box.StyleRef());
  float float_result = char_width * factor;

  float max_char_width = 0.f;
  const Font& font = box.StyleRef().GetFont();
  if (layout_text_control::HasValidAvgCharWidth(font)) {
    max_char_width = font.PrimaryFont()->MaxCharWidth();
  }

  // For text inputs, IE adds some extra width.
  if (max_char_width > char_width)
    float_result += max_char_width - char_width;

  LayoutUnit result(ceilf(float_result));
  if (includes_decoration) {
    const auto* spin_button =
        To<HTMLElement>(input.UserAgentShadowRoot()->getElementById(
            shadow_element_names::kIdSpinButton));
    if (LayoutBox* spin_box =
            spin_button ? spin_button->GetLayoutBox() : nullptr) {
      const Length& logical_width = spin_box->StyleRef().LogicalWidth();
      result += spin_box->BorderAndPaddingInlineSize();
      // Since the width of spin_box is not calculated yet,
      // spin_box->LogicalWidth() returns 0. Use the computed logical
      // width instead.
      if (logical_width.IsPercent()) {
        if (logical_width.Value() != 100.f) {
          result +=
              result * logical_width.Value() / (100 - logical_width.Value());
        }
      } else {
        result += logical_width.Value();
      }
    }
  }
  return result;
}

LayoutUnit TextAreaIntrinsicBlockSize(const HTMLTextAreaElement& textarea,
                                      const LayoutBox& box) {
  // Only add the scrollbar thickness for 'overflow: scroll'.
  int scrollbar_thickness = 0;
  if (box.StyleRef().OverflowInlineDirection() == EOverflow::kScroll) {
    scrollbar_thickness = layout_text_control::ScrollbarThickness(box);
  }

  const auto* inner_editor = textarea.InnerEditorElement();
  const LayoutUnit line_height =
      inner_editor && inner_editor->GetLayoutBox()
          ? inner_editor->GetLayoutBox()->FirstLineHeight()
          : box.FirstLineHeight();

  return line_height * textarea.rows() + scrollbar_thickness;
}

LayoutUnit TextFieldIntrinsicBlockSize(const HTMLInputElement& input,
                                       const LayoutBox& box) {
  const auto* inner_editor = input.InnerEditorElement();
  // inner_editor's LayoutBox can be nullptr because web authors can set
  // display:none to ::-webkit-textfield-decoration-container element.
  const LayoutBox& target_box = (inner_editor && inner_editor->GetLayoutBox())
                                    ? *inner_editor->GetLayoutBox()
                                    : box;
  return target_box.FirstLineHeight();
}

LayoutUnit FileUploadControlIntrinsicInlineSize(const HTMLInputElement& input,
                                                const LayoutBox& box) {
  // This should match to margin-inline-end of ::-webkit-file-upload-button UA
  // style.
  constexpr int kAfterButtonSpacing = 4;
  // Figure out how big the filename space needs to be for a given number of
  // characters (using "0" as the nominal character).
  constexpr int kDefaultWidthNumChars = 34;
  constexpr UChar kCharacter = '0';
  const String character_as_string = String(base::span_from_ref(kCharacter));
  const float min_default_label_width =
      kDefaultWidthNumChars *
      ComputeTextWidth(character_as_string, box.StyleRef());

  const String label =
      input.GetLocale().QueryString(IDS_FORM_FILE_NO_FILE_LABEL);
  float default_label_width = ComputeTextWidth(label, box.StyleRef());
  if (HTMLInputElement* button = input.UploadButton()) {
    if (auto* button_box = button->GetLayoutBox()) {
      const ComputedStyle& button_style = button_box->StyleRef();
      WritingMode mode = button_style.GetWritingMode();
      ConstraintSpaceBuilder builder(mode, button_style.GetWritingDirection(),
                                     /* is_new_fc */ true);
      LayoutUnit max = BlockNode(button_box)
                           .ComputeMinMaxSizes(mode, SizeType::kIntrinsic,
                                               builder.ToConstraintSpace())
                           .sizes.max_size;
      default_label_width +=
          max + (kAfterButtonSpacing * box.StyleRef().EffectiveZoom());
    }
  }
  return LayoutUnit(
      ceilf(std::max(min_default_label_width, default_label_width)));
}

LayoutUnit SliderIntrinsicInlineSize(const LayoutBox& box) {
  constexpr int kDefaultTrackLength = 129;
  return LayoutUnit(kDefaultTrackLength * box.StyleRef().EffectiveZoom());
}

LogicalSize ThemePartIntrinsicSize(const LayoutBox& box,
                                   WebThemeEngine::Part part) {
  const auto& style = box.StyleRef();
  PhysicalSize size(
      WebThemeEngineHelper::GetNativeThemeEngine()->GetSize(part));
  size.Scale(style.EffectiveZoom());
  return size.ConvertToLogical(style.GetWritingMode());
}

LayoutUnit ListBoxDefaultItemHeight(const LayoutBox& box) {
  constexpr int kDefaultPaddingBottom = 1;

  const SimpleFontData* font_data = box.StyleRef().GetFont().PrimaryFont();
  if (!font_data)
    return LayoutUnit();
  return LayoutUnit(font_data->GetFontMetrics().Height() +
                    kDefaultPaddingBottom);
}

// TODO(crbug.com/1040826): This function is written in LayoutObject API
// so that this works in both of the legacy layout and LayoutNG. We
// should have LayoutNG-specific code.
LayoutUnit ListBoxItemBlockSize(const HTMLSelectElement& select,
                                const LayoutBox& box) {
  const auto& items = select.GetListItems();
  if (items.empty() || box.ShouldApplySizeContainment())
    return ListBoxDefaultItemHeight(box);

  LayoutUnit max_block_size;
  for (Element* element : items) {
    if (auto* optgroup = DynamicTo<HTMLOptGroupElement>(element))
      element = &optgroup->OptGroupLabelElement();
    LayoutUnit item_block_size;
    if (auto* layout_box = element->GetLayoutBox()) {
      item_block_size = box.StyleRef().IsHorizontalWritingMode()
                            ? layout_box->Size().height
                            : layout_box->Size().width;
    } else {
      item_block_size = ListBoxDefaultItemHeight(box);
    }
    max_block_size = std::max(max_block_size, item_block_size);
  }
  return max_block_size;
}

LayoutUnit MenuListIntrinsicInlineSize(const HTMLSelectElement& select,
                                       const LayoutBox& box) {
  const ComputedStyle& style = box.StyleRef();
  float max_option_width = 0;
  if (!box.ShouldApplySizeContainment()) {
    for (auto* const option : select.GetOptionList()) {
      String text =
          style.ApplyTextTransform(option->TextIndentedToRespectGroupLabel());
      // We apply SELECT's style, not OPTION's style because max_option_width is
      // used to determine intrinsic width of the menulist box.
      max_option_width =
          std::max(max_option_width, ComputeTextWidth(text, style));
    }
  }

  LayoutTheme& theme = LayoutTheme::GetTheme();
  int paddings = theme.PopupInternalPaddingStart(style) +
                 theme.PopupInternalPaddingEnd(box.GetFrame(), style);
  return LayoutUnit(ceilf(max_option_width)) + LayoutUnit(paddings);
}

LayoutUnit MenuListIntrinsicBlockSize(const HTMLSelectElement& select,
                                      const LayoutBox& box) {
  if (!box.StyleRef().HasEffectiveAppearance())
    return kIndefiniteSize;
  const SimpleFontData* font_data = box.StyleRef().GetFont().PrimaryFont();
  DCHECK(font_data);
  const LayoutBox* inner_box = select.InnerElement().GetLayoutBox();
  return (font_data ? font_data->GetFontMetrics().Height() : 0) +
         (inner_box ? inner_box->BorderAndPaddingBlockSize() : LayoutUnit());
}

#if DCHECK_IS_ON()
void CheckDidAddFragment(const LayoutBox& box,
                         const PhysicalBoxFragment& new_fragment,
                         wtf_size_t new_fragment_index = kNotFound) {
  // If |HasFragmentItems|, |ChildrenInline()| should be true.
  // |HasFragmentItems| uses this condition to optimize .
  if (new_fragment.HasItems())
    DCHECK(box.ChildrenInline());

  wtf_size_t index = 0;
  for (const PhysicalBoxFragment& fragment : box.PhysicalFragments()) {
    DCHECK_EQ(fragment.IsFirstForNode(), index == 0);
    if (const FragmentItems* fragment_items = fragment.Items()) {
      fragment_items->CheckAllItemsAreValid();
    }
    // Don't check past the fragment just added. Those entries may be invalid at
    // this point.
    if (index == new_fragment_index)
      break;
    ++index;
  }
}
#else
inline void CheckDidAddFragment(const LayoutBox& box,
                                const PhysicalBoxFragment& fragment,
                                wtf_size_t new_fragment_index = kNotFound) {}
#endif

// Applies the overflow clip to |result|. For any axis that is clipped, |result|
// is reset to |no_overflow_rect|. If neither axis is clipped, nothing is
// changed.
void ApplyOverflowClip(OverflowClipAxes overflow_clip_axes,
                       const PhysicalRect& no_overflow_rect,
                       PhysicalRect& result) {
  if (overflow_clip_axes & kOverflowClipX) {
    result.SetX(no_overflow_rect.X());
    result.SetWidth(no_overflow_rect.Width());
  }
  if (overflow_clip_axes & kOverflowClipY) {
    result.SetY(no_overflow_rect.Y());
    result.SetHeight(no_overflow_rect.Height());
  }
}

int HypotheticalScrollbarThickness(const LayoutBox& box,
                                   ScrollbarOrientation scrollbar_orientation,
                                   bool should_include_overlay_thickness) {
  box.CheckIsNotDestroyed();

  if (PaintLayerScrollableArea* scrollable_area = box.GetScrollableArea()) {
    return scrollable_area->HypotheticalScrollbarThickness(
        scrollbar_orientation, should_include_overlay_thickness);
  } else {
    Page* page = box.GetFrame()->GetPage();
    ScrollbarTheme& theme = page->GetScrollbarTheme();

    if (theme.UsesOverlayScrollbars() && !should_include_overlay_thickness) {
      return 0;
    } else {
      ChromeClient& chrome_client = page->GetChromeClient();
      Document& document = box.GetDocument();
      float scale_from_dip =
          chrome_client.WindowToViewportScalar(document.GetFrame(), 1.0f);
      return theme.ScrollbarThickness(scale_from_dip,
                                      box.StyleRef().UsedScrollbarWidth());
    }
  }
}

void RecalcFragmentScrollableOverflow(RecalcScrollableOverflowResult& result,
                                      const PhysicalFragment& fragment) {
  for (const auto& child : fragment.PostLayoutChildren()) {
    if (child->GetLayoutObject()) {
      if (const auto* box = DynamicTo<PhysicalBoxFragment>(child.get())) {
        if (LayoutBox* owner_box = box->MutableOwnerLayoutBox())
          result.Unite(owner_box->RecalcScrollableOverflow());
      }
    } else {
      // We enter this branch when the |child| is a fragmentainer.
      RecalcFragmentScrollableOverflow(result, *child.get());
    }
  }
}

// Returns the logical offset in the LocationContainer() coordination system,
// and its WritingMode.
std::tuple<LogicalOffset, WritingMode> LogicalLocation(const LayoutBox& box) {
  LayoutBox* container = box.LocationContainer();
  WritingMode writing_mode = container->StyleRef().GetWritingMode();
  WritingModeConverter converter({writing_mode, TextDirection::kLtr},
                                 PhysicalSize(container->Size()));
  return {converter.ToLogical(box.PhysicalLocation(), PhysicalSize(box.Size())),
          writing_mode};
}

}  // namespace

LayoutBoxRareData::LayoutBoxRareData()
    : spanner_placeholder_(nullptr),
      // TODO(rego): We should store these based on physical direction.
      has_override_containing_block_content_logical_width_(false),
      has_previous_content_box_rect_(false) {}

void LayoutBoxRareData::Trace(Visitor* visitor) const {
  visitor->Trace(spanner_placeholder_);
  visitor->Trace(layout_child_);
}

LayoutBox::LayoutBox(ContainerNode* node) : LayoutBoxModelObject(node) {
  if (blink::IsA<HTMLLegendElement>(node))
    SetIsHTMLLegendElement();
}

void LayoutBox::Trace(Visitor* visitor) const {
  visitor->Trace(min_max_sizes_cache_);
  visitor->Trace(measure_cache_);
  visitor->Trace(layout_results_);
  visitor->Trace(overflow_);
  visitor->Trace(rare_data_);
  LayoutBoxModelObject::Trace(visitor);
}

LayoutBox::~LayoutBox() = default;

PaintLayerType LayoutBox::LayerTypeRequired() const {
  NOT_DESTROYED();
  if (IsStacked() || HasHiddenBackface() ||
      (StyleRef().SpecifiesColumns() && !IsLayoutNGObject()))
    return kNormalPaintLayer;

  if (HasNonVisibleOverflow() && !IsLayoutReplaced()) {
    return kOverflowClipPaintLayer;
  }

  return kNoPaintLayer;
}

void LayoutBox::WillBeDestroyed() {
  NOT_DESTROYED();
  ClearOverrideContainingBlockContentSize();

  ShapeOutsideInfo::RemoveInfo(*this);

  if (!DocumentBeingDestroyed()) {
    DisassociatePhysicalFragments();
  }

  if (Style() && StyleRef().HasOutOfFlowPosition()) {
    if (auto* display_locks = DisplayLocksAffectedByAnchors()) {
      NotifyContainingDisplayLocksForAnchorPositioning(display_locks, nullptr);
    }
  }

  LayoutBoxModelObject::WillBeDestroyed();
}

void LayoutBox::DisassociatePhysicalFragments() {
  if (FirstInlineFragmentItemIndex()) {
    FragmentItems::LayoutObjectWillBeDestroyed(*this);
    ClearFirstInlineFragmentItemIndex();
  }
  if (measure_cache_) {
    measure_cache_->LayoutObjectWillBeDestroyed();
  }
  for (auto result : layout_results_)
    result->GetPhysicalFragment().LayoutObjectWillBeDestroyed();
}

void LayoutBox::InsertedIntoTree() {
  NOT_DESTROYED();
  LayoutBoxModelObject::InsertedIntoTree();
  AddCustomLayoutChildIfNeeded();
}

void LayoutBox::WillBeRemovedFromTree() {
  NOT_DESTROYED();
  ClearCustomLayoutChild();
  LayoutBoxModelObject::WillBeRemovedFromTree();
}

void LayoutBox::StyleWillChange(StyleDifference diff,
                                const ComputedStyle& new_style) {
  NOT_DESTROYED();
  const ComputedStyle* old_style = Style();
  if (old_style) {
    if (IsDocumentElement() || IsBody()) {
      // The background of the root element or the body element could propagate
      // up to the canvas. Just dirty the entire canvas when our style changes
      // substantially.
      if (diff.NeedsNormalPaintInvalidation() || diff.NeedsLayout()) {
        View()->SetShouldDoFullPaintInvalidation();
      }
    }

    // When a layout hint happens and an object's position style changes, we
    // have to do a layout to dirty the layout tree using the old position
    // value now.
    if (diff.NeedsFullLayout() && Parent()) {
      bool will_move_out_of_ifc = false;
      if (old_style->GetPosition() != new_style.GetPosition()) {
        if (!old_style->HasOutOfFlowPosition() &&
            new_style.HasOutOfFlowPosition()) {
          // We're about to go out of flow. Before that takes place, we need to
          // mark the current containing block chain for preferred widths
          // recalculation.
          SetNeedsLayoutAndIntrinsicWidthsRecalc(
              layout_invalidation_reason::kStyleChange);

          // Grid placement is different for out-of-flow elements, so if the
          // containing block is a grid, dirty the grid's placement. The
          // converse (going from out of flow to in flow) is handled in
          // LayoutBox::UpdateGridPositionAfterStyleChange.
          LayoutBlock* containing_block = ContainingBlock();
          if (containing_block && containing_block->IsLayoutGrid()) {
            containing_block->SetGridPlacementDirty(true);
          }

          // Out of flow are not part of |FragmentItems|, and that further
          // changes including destruction cannot be tracked. We need to mark it
          // is moved out from this IFC.
          will_move_out_of_ifc = true;
        } else {
          MarkContainerChainForLayout();
        }

        if (old_style->GetPosition() == EPosition::kStatic) {
          SetShouldDoFullPaintInvalidation();
        } else if (new_style.HasOutOfFlowPosition()) {
          Parent()->SetChildNeedsLayout();
        }
      }

      bool will_become_inflow = false;
      if ((old_style->IsFloating() || old_style->HasOutOfFlowPosition()) &&
          !new_style.IsFloating() && !new_style.HasOutOfFlowPosition()) {
        // As a float or OOF, this object may have been part of an inline
        // formatting context, but that's definitely no longer the case.
        will_become_inflow = true;
        will_move_out_of_ifc = true;
      }

      if (will_move_out_of_ifc && FirstInlineFragmentItemIndex()) {
        FragmentItems::LayoutObjectWillBeMoved(*this);
        ClearFirstInlineFragmentItemIndex();
      }
      if (will_become_inflow)
        SetIsInLayoutNGInlineFormattingContext(false);
    }
    // FIXME: This branch runs when !oldStyle, which means that layout was never
    // called so what's the point in invalidating the whole view that we never
    // painted?
  } else if (IsBody()) {
    View()->SetShouldDoFullPaintInvalidation();
  }

  LayoutBoxModelObject::StyleWillChange(diff, new_style);
}

void LayoutBox::StyleDidChange(StyleDifference diff,
                               const ComputedStyle* old_style) {
  NOT_DESTROYED();
  LayoutBoxModelObject::StyleDidChange(diff, old_style);

  // Reflection works through PaintLayer. Some child classes e.g. LayoutSVGBlock
  // don't create layers and ignore reflections.
  if (HasReflection() && !HasLayer())
    SetHasReflection(false);

  if (auto* parent_flow_block = DynamicTo<LayoutBlockFlow>(Parent())) {
    if (IsFloatingOrOutOfFlowPositioned() && old_style &&
        !old_style->IsFloating() && !old_style->HasOutOfFlowPosition()) {
      // Note that |parent_flow_block| may have been destroyed after this call.
      parent_flow_block->ChildBecameFloatingOrOutOfFlow(this);
    }
  }

  SetOverflowClipAxes(ComputeOverflowClipAxes());

  // If our zoom factor changes and we have a defined scrollLeft/Top, we need to
  // adjust that value into the new zoomed coordinate space.  Note that the new
  // scroll offset may be outside the normal min/max range of the scrollable
  // area, which is weird but OK, because the scrollable area will update its
  // min/max in updateAfterLayout().
  const ComputedStyle& new_style = StyleRef();
  if (IsScrollContainer() && old_style &&
      old_style->EffectiveZoom() != new_style.EffectiveZoom()) {
    PaintLayerScrollableArea* scrollable_area = GetScrollableArea();
    DCHECK(scrollable_area);
    // We use GetScrollOffset() rather than ScrollPosition(), because scroll
    // offset is the distance from the beginning of flow for the box, which is
    // the dimension we want to preserve.
    ScrollOffset offset = scrollable_area->GetScrollOffset();
    if (!offset.IsZero()) {
      offset.Scale(new_style.EffectiveZoom() / old_style->EffectiveZoom());
      scrollable_area->SetScrollOffsetUnconditionally(offset);
    }
  }

  if (old_style && old_style->IsScrollContainer() != IsScrollContainer()) {
    if (auto* layer = EnclosingLayer())
      layer->ScrollContainerStatusChanged();
  }

  UpdateShapeOutsideInfoAfterStyleChange(*Style(), old_style);
  UpdateGridPositionAfterStyleChange(old_style);

  if (old_style) {
    // Regular column content (i.e. non-spanners) have a hook into the flow
    // thread machinery before (StyleWillChange()) and after (here in
    // StyleDidChange()) the style has changed. Column spanners, on the other
    // hand, only have a hook here. The LayoutMultiColumnSpannerPlaceholder code
    // will do all the necessary things, including removing it as a spanner, if
    // it should no longer be one. Therefore, make sure that we skip
    // FlowThreadDescendantStyleDidChange() in such cases, as that might trigger
    // a duplicate flow thread insertion notification, if the spanner no longer
    // is a spanner.
    if (LayoutMultiColumnSpannerPlaceholder* placeholder =
            SpannerPlaceholder()) {
      placeholder->LayoutObjectInFlowThreadStyleDidChange(old_style);
    }

    UpdateScrollSnapMappingAfterStyleChange(*old_style);

    if (ShouldClipOverflowAlongEitherAxis()) {
      // The overflow clip paint property depends on border sizes through
      // overflowClipRect(), and border radii, so we update properties on
      // border size or radii change.
      //
      // For some controls, it depends on paddings.
      if (!old_style->BorderSizeEquals(new_style) ||
          diff.BorderRadiusChanged() ||
          (HasControlClip() && !old_style->PaddingEqual(new_style))) {
        SetNeedsPaintPropertyUpdate();
      }
    }

    if (old_style->OverscrollBehaviorX() != new_style.OverscrollBehaviorX() ||
        old_style->OverscrollBehaviorY() != new_style.OverscrollBehaviorY()) {
      SetNeedsPaintPropertyUpdate();
    }

    if (old_style->OverflowX() != new_style.OverflowX() ||
        old_style->OverflowY() != new_style.OverflowY()) {
      SetNeedsPaintPropertyUpdate();
    }

    if (old_style->OverflowClipMargin() != new_style.OverflowClipMargin())
      SetNeedsPaintPropertyUpdate();

    if (IsInLayoutNGInlineFormattingContext() && IsAtomicInlineLevel() &&
        old_style->Direction() != new_style.Direction()) {
      SetNeedsCollectInlines();
    }

    if (IsBackgroundAttachmentFixedObject() &&
        new_style.BackgroundLayers().Clip() !=
            old_style->BackgroundLayers().Clip()) {
      SetNeedsPaintPropertyUpdate();
    }
  }

  // Update the script style map, from the new computed style.
  if (IsCustomItem())
    GetCustomLayoutChild()->styleMap()->UpdateStyle(GetDocument(), StyleRef());

  // Non-atomic inlines should be LayoutInline or LayoutText, not LayoutBox.
  DCHECK(!IsInline() || IsAtomicInlineLevel());
}

void LayoutBox::UpdateShapeOutsideInfoAfterStyleChange(
    const ComputedStyle& style,
    const ComputedStyle* old_style) {
  NOT_DESTROYED();
  const ShapeValue* shape_outside = style.ShapeOutside();
  const ShapeValue* old_shape_outside =
      old_style ? old_style->ShapeOutside()
                : ComputedStyleInitialValues::InitialShapeOutside();

  const Length& shape_margin = style.ShapeMargin();
  const Length& old_shape_margin =
      old_style ? old_style->ShapeMargin()
                : ComputedStyleInitialValues::InitialShapeMargin();

  float shape_image_threshold = style.ShapeImageThreshold();
  float old_shape_image_threshold =
      old_style ? old_style->ShapeImageThreshold()
                : ComputedStyleInitialValues::InitialShapeImageThreshold();

  // FIXME: A future optimization would do a deep comparison for equality. (bug
  // 100811)
  if (shape_outside == old_shape_outside && shape_margin == old_shape_margin &&
      shape_image_threshold == old_shape_image_threshold)
    return;

  if (!shape_outside)
    ShapeOutsideInfo::RemoveInfo(*this);
  else
    ShapeOutsideInfo::EnsureInfo(*this).MarkShapeAsDirty();

  if (!IsFloating()) {
    return;
  }

  if (shape_outside || shape_outside != old_shape_outside) {
    if (auto* containing_block = ContainingBlock()) {
      containing_block->SetChildNeedsLayout();
    }
  }
"""


```