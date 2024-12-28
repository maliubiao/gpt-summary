Response:
My thinking process to answer the request about `layout_theme.cc` goes like this:

1. **Understand the Core Request:** The user wants to know the functionality of `layout_theme.cc`, particularly its relationship with HTML, CSS, and JavaScript, along with examples of logical reasoning, user errors, and a summary of its purpose. Crucially, they specified "Part 1 of 2," indicating they want an initial overview based on the provided code snippet.

2. **Initial Code Scan and Keywords:** I'll quickly scan the code for prominent keywords and include files. This gives me immediate clues about the file's responsibilities. I see includes like:
    * `layout_theme.h`, `layout_theme_mobile.h`:  This confirms it's part of a theme system.
    * HTML elements (`HTMLButtonElement`, `HTMLInputElement`, etc.):  Indicates it deals with the rendering and styling of HTML form controls and other elements.
    * CSS (`css_value_keywords.h`, `ComputedStyleBuilder`):  Shows involvement in CSS styling.
    * `javascript/`: While not directly included, the interaction with the DOM and styling implies JavaScript's influence on the rendered output.
    * `build_config.h`: Suggests platform-specific considerations.
    * `ui/base/ui_base_features.h`, `ui/native_theme/native_theme.h`: Points to integration with the underlying operating system's theme.

3. **Deconstruct the Functionality (Based on the Code):** I'll go through the code more systematically, function by function (or groups of related functions), and try to deduce their purpose:

    * **Licensing Header:**  Acknowledge the licensing information.
    * **Includes:** Note the key includes and their implications (as done in step 2).
    * **`AutoAppearanceFor()`:** This function maps HTML elements to specific "ControlParts." This is fundamental for determining the default rendering of form controls.
    * **`ResetBorder()` and `ResetPadding()`:**  These utility functions suggest the theme has the ability to override or reset default browser styling for specific elements.
    * **`SystemAccentColorAllowed()`:** This hints at handling system-wide accent colors.
    * **`LayoutTheme::GetTheme()`:** This is the central entry point for accessing the appropriate theme (either the mobile or the native one). This suggests a strategy for adapting rendering based on the platform or settings.
    * **`AdjustAppearanceWithAuthorStyle()` and `AdjustAppearanceWithElementType()`:** These functions determine the final "ControlPart" based on both default behavior and author-provided CSS styles. This highlights the interaction between the browser's default theme and custom styling. The logic involving `kAutoPart` and specific element types is crucial for understanding how the theme resolves different appearance values.
    * **`AdjustStyle()`:**  This is the main function that applies theme-specific styling. It adjusts the `ComputedStyleBuilder` based on the element and its appearance. The logic of forcing `display` values is significant.
    * **`ExtraDefaultStyleSheet()` and `ExtraFullscreenStyleSheet()`:** This indicates the theme can inject additional CSS rules.
    * **Color-related functions (`ActiveSelectionBackgroundColor`, `InactiveSelectionForegroundColor`, etc.):**  These functions define the colors used for selections, list boxes, and other UI elements. The platform-specific implementations (prefixed with `Platform`) are important.
    * **`IsControlStyled()`:** This function determines if an element's appearance is being controlled by author styles (e.g., background or border).
    * **`ShouldDrawDefaultFocusRing()`:**  This controls whether the default focus outline should be displayed.
    * **`AdjustCheckboxStyle()`, `AdjustRadioStyle()`, `AdjustButtonStyle()`, etc.:** These are specific functions for adjusting the styling of individual form controls. The resetting of padding and border is noteworthy.
    * **`AdjustSliderContainerStyle()` and `AdjustSliderThumbStyle()`:** These deal with the specific styling of slider elements, including touch actions and writing modes.
    * **`PlatformColorsDidChange()` and `ColorSchemeDidChange()`:** These functions indicate the theme reacts to system-level color changes.
    * **`SetCaretBlinkInterval()` and `CaretBlinkInterval()`:**  This deals with the behavior of the text input caret.
    * **`SystemColor()` and `DefaultSystemColor()`:** These functions handle the retrieval of system-defined colors, considering dark/light themes and feature flags. The deprecation notes are important.
    * **`SystemColorFromColorProvider()` and `SystemHighlightFromColorProvider()`:** These are related to using a `ui::ColorProvider`, likely for more modern theming mechanisms.
    * **`PlatformTextSearchHighlightColor()` and `PlatformTextSearchColor()`:** These define the colors for text search highlighting.
    * **`TapHighlightColor()`:** Deals with the highlight shown on touch interactions.
    * **`SetCustomFocusRingColor()` and `FocusRingColor()`:** Allows setting a custom focus ring color.
    * **`DelegatesMenuListRendering()` and `SetDelegatesMenuListRenderingForTesting()`:** Indicates the possibility of delegating menu list rendering to a different mechanism.
    * **`DisplayNameForFile()`:**  Provides a way to get a displayable name for a file.
    * **`SupportsCalendarPicker()`:**  Checks if a calendar picker is supported for a given input type.

4. **Categorize and Summarize Functionality:** I'll group the deduced functionalities into logical categories:

    * **Theme Management:**  Loading the correct theme (mobile or native).
    * **Default Appearance:** Defining the initial look of form controls.
    * **CSS Styling Integration:** Applying and adjusting styles based on CSS rules.
    * **Platform Integration:** Adapting to the underlying operating system's theme and settings.
    * **Specific Control Styling:**  Customizing the appearance of individual form elements.
    * **Accessibility:**  Handling focus rings.
    * **Text Handling:**  Managing selection colors and caret behavior.
    * **Search Highlighting:** Defining colors for text search.
    * **Input Enhancements:** Supporting calendar pickers.

5. **Address Specific Requirements:**

    * **Relationship with JavaScript, HTML, CSS:**  Explain how the theme interacts with these technologies. HTML provides the structure, CSS the styling, and JavaScript can dynamically modify the DOM and CSS, which the theme then interprets.
    * **Examples:** Provide concrete examples of how the theme affects the rendering of specific HTML elements and how CSS can override the default theme styles.
    * **Logical Reasoning (Hypothetical Input/Output):**  Create a simple scenario to illustrate how the theme determines the appearance of an element based on its type and applied CSS.
    * **User/Programming Errors:**  Think about common mistakes developers might make when trying to style form controls and how the theme might behave in those cases.
    * **Summary of Functionality:**  Provide a concise overview of the file's purpose based on the identified functionalities.

6. **Structure the Answer:** Organize the information logically with clear headings and bullet points to make it easy to read and understand.

7. **Review and Refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness, addressing all aspects of the original request. Ensure the language is appropriate and avoid overly technical jargon where possible. Since it's "Part 1," focus on the broader functionalities evident from the code snippet without delving into implementation details that might be in Part 2.

By following these steps, I can generate a comprehensive and accurate answer that addresses all the user's requirements based on the provided code snippet of `layout_theme.cc`.
```
这是目录为blink/renderer/core/layout/layout_theme.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

基于提供的代码片段，`blink/renderer/core/layout/layout_theme.cc` 文件的主要功能是：

**核心功能：管理和应用用户界面控件（特别是表单控件）的主题样式。**

更具体地说，它负责：

1. **定义默认控件外观:**  为各种HTML表单控件（如按钮、输入框、下拉列表等）定义平台默认的外观样式。这包括边框、背景、内边距等。`AutoAppearanceFor` 函数根据元素类型返回默认的 `ControlPart` 枚举值，这个枚举值决定了控件的基本视觉呈现。

   * **例子 (HTML/CSS关系):** 当浏览器渲染一个 `<input type="checkbox">` 元素时，`AutoAppearanceFor` 会返回 `kCheckboxPart`。  `LayoutTheme` 会根据这个 `ControlPart` 应用默认的复选框样式。  CSS 可以通过 `appearance` 属性来修改这个默认外观，例如 `appearance: none;` 可以移除默认样式。

2. **处理作者样式和元素类型的影响:**  当开发者使用CSS的 `appearance` 属性或者浏览器遇到特定的HTML元素时，这个文件中的函数（如 `AdjustAppearanceWithAuthorStyle` 和 `AdjustAppearanceWithElementType`) 决定最终应用于控件的 `ControlPart`。 这涉及到优先级和覆盖逻辑。

   * **例子 (HTML/CSS关系):**  如果一个 `<select>` 元素没有应用任何 `appearance` 样式，`AutoAppearanceFor` 会根据其是否使用 `multiple` 属性返回 `kMenulistPart` 或 `kListboxPart`。  如果开发者设置了 `appearance: menulist-button;`，`AdjustAppearanceWithAuthorStyle` 会将其转换为 `kMenulistButtonPart`。

3. **调整控件的样式属性:**  `AdjustStyle` 函数是核心，它根据确定的 `ControlPart` 调用相应的调整函数（如 `AdjustCheckboxStyle`, `AdjustButtonStyle`, `AdjustMenuListStyle` 等）来修改 `ComputedStyleBuilder`，从而影响最终的渲染样式。

   * **例子 (CSS关系):**  `AdjustCheckboxStyle` 函数会重置复选框的 `padding` 和 `border` 属性，因为这些属性在某些浏览器上可能不被默认支持或呈现不一致。这确保了 Blink 引擎对这些控件的默认处理方式。

4. **提供平台相关的颜色和样式:**  文件中定义了许多与平台相关的颜色（如选择背景色、前景色）和样式，这些样式会根据操作系统或用户设置而变化。  例如，`ActiveSelectionBackgroundColor` 和 `InactiveSelectionBackgroundColor` 定义了选中文字的背景颜色。

5. **处理焦点环:** `ShouldDrawDefaultFocusRing` 函数决定是否绘制默认的焦点环，这对于可访问性很重要。

6. **处理系统颜色:** `SystemColor` 和 `DefaultSystemColor` 函数用于获取操作系统定义的一些颜色值，例如按钮面颜色、文本颜色等，允许网页元素融入系统主题。

   * **例子 (CSS关系):** 可以使用 CSS 系统颜色关键字，如 `canvas`, `canvastext`, `buttonface` 等，这些关键字的值会通过 `SystemColor` 函数获取。

7. **处理触摸操作:** 对于某些控件（如滑块），会设置默认的触摸操作行为 (`TouchAction`)。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **HTML:**  `layout_theme.cc` 负责渲染各种 HTML 元素，特别是表单控件。它根据 HTML 元素的类型（例如 `<button>`, `<input type="text">`）来决定应用哪些默认样式。
* **CSS:**  CSS 的 `appearance` 属性直接影响 `layout_theme.cc` 的行为。开发者可以通过 CSS 修改或重置默认的控件外观。此外，CSS 的系统颜色关键字也与 `layout_theme.cc` 中的 `SystemColor` 函数紧密相关。
* **JavaScript:**  JavaScript 可以动态地创建、修改 HTML 元素和它们的 CSS 样式。  当 JavaScript 修改一个表单元素的类型或应用 `appearance` 样式时，`layout_theme.cc` 的逻辑会相应地更新元素的渲染。例如，JavaScript 可以动态地改变一个输入框的 `type` 属性，从而触发 `layout_theme.cc` 应用不同的默认样式。

**逻辑推理（假设输入与输出）:**

* **假设输入:** 一个未设置任何 CSS 样式的 `<input type="range">` 元素被添加到 DOM 中。
* **逻辑推理:** `AutoAppearanceFor` 函数会识别出这是一个 range 输入框，返回 `kSliderHorizontalPart`。 `AdjustStyle` 函数会被调用，并进一步调用 `AdjustSliderContainerStyle` 和 `AdjustSliderThumbStyle` 等函数，根据平台设置默认的滑块轨道和滑块按钮的样式（例如，边框、背景色、尺寸）。
* **输出:** 浏览器会渲染出一个具有平台默认样式的水平滑块。

**用户或编程常见的使用错误举例说明:**

* **错误:**  开发者尝试使用 `appearance: checkbox;` 来强制一个 `<div>` 元素看起来像复选框，但没有使用 JavaScript 添加相应的交互逻辑。
* **后果:** 虽然 `layout_theme.cc` 可能会应用类似复选框的视觉样式，但该 `<div>` 元素不会具有复选框的内置行为（例如，选中/未选中状态的切换）。这是因为 `layout_theme.cc` 主要负责视觉呈现，而元素的行为通常由浏览器内置逻辑和 JavaScript 控制。

**归纳一下它的功能 (Part 1):**

`layout_theme.cc` 的主要职责是定义和管理 Chromium Blink 引擎中用户界面控件的默认视觉主题。它通过识别 HTML 元素类型、处理 CSS 的 `appearance` 属性，并提供平台相关的颜色和样式，来确保控件在不同操作系统和浏览器设置下具有一致且符合平台规范的外观。  它充当了 HTML 结构和最终渲染样式之间的桥梁，尤其在处理表单控件的默认样式方面起着核心作用。这个文件是 Blink 引擎渲染表单控件的基础，并允许开发者通过 CSS 进行定制。
```
Prompt: 
```
这是目录为blink/renderer/core/layout/layout_theme.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
/**
 * This file is part of the theme implementation for form controls in WebCore.
 *
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010, 2012 Apple Computer, Inc.
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
 */

#include "third_party/blink/renderer/core/layout/layout_theme.h"

#include "build/build_config.h"
#include "third_party/blink/public/strings/grit/blink_strings.h"
#include "third_party/blink/public/web/blink.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/fileapi/file.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/forms/html_button_element.h"
#include "third_party/blink/renderer/core/html/forms/html_data_list_element.h"
#include "third_party/blink/renderer/core/html/forms/html_data_list_options_collection.h"
#include "third_party/blink/renderer/core/html/forms/html_form_control_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_option_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/html/forms/spin_button_element.h"
#include "third_party/blink/renderer/core/html/forms/text_control_inner_elements.h"
#include "third_party/blink/renderer/core/html/html_collection.h"
#include "third_party/blink/renderer/core/html/html_meter_element.h"
#include "third_party/blink/renderer/core/html/html_progress_element.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_utils.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_theme_font_provider.h"
#include "third_party/blink/renderer/core/layout/layout_theme_mobile.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/computed_style_initial_values.h"
#include "third_party/blink/renderer/platform/file_metadata.h"
#include "third_party/blink/renderer/platform/fonts/font_selector.h"
#include "third_party/blink/renderer/platform/graphics/touch_action.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/writing_mode.h"
#include "third_party/blink/renderer/platform/theme/web_theme_engine_helper.h"
#include "third_party/blink/renderer/platform/web_test_support.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "ui/base/ui_base_features.h"
#include "ui/native_theme/native_theme.h"

// The methods in this file are shared by all themes on every platform.

namespace blink {

using mojom::blink::FormControlType;

namespace {

// This function should match to the user-agent stylesheet.
ControlPart AutoAppearanceFor(const Element& element) {
  if (IsA<HTMLButtonElement>(element))
    return kButtonPart;
  if (IsA<HTMLMeterElement>(element))
    return kMeterPart;
  if (IsA<HTMLProgressElement>(element))
    return kProgressBarPart;
  if (IsA<HTMLTextAreaElement>(element))
    return kTextAreaPart;
  if (IsA<SpinButtonElement>(element))
    return kInnerSpinButtonPart;
  if (const auto* select = DynamicTo<HTMLSelectElement>(element))
    return select->UsesMenuList() ? kMenulistPart : kListboxPart;

  if (const auto* input = DynamicTo<HTMLInputElement>(element))
    return input->AutoAppearance();

  if (element.IsInUserAgentShadowRoot()) {
    const AtomicString& id_value =
        element.FastGetAttribute(html_names::kIdAttr);
    if (id_value == shadow_element_names::kIdSliderThumb)
      return kSliderThumbHorizontalPart;
    if (id_value == shadow_element_names::kIdSearchClearButton ||
        id_value == shadow_element_names::kIdClearButton)
      return kSearchFieldCancelButtonPart;

    // Slider container elements and -webkit-meter-inner-element don't have IDs.
    if (IsSliderContainer(element))
      return kSliderHorizontalPart;
    if (element.ShadowPseudoId() ==
        shadow_element_names::kPseudoMeterInnerElement)
      return kMeterPart;
  }
  return kNoControlPart;
}

void ResetBorder(ComputedStyleBuilder& builder) {
  builder.ResetBorderImage();
  builder.ResetBorderTopStyle();
  builder.ResetBorderTopWidth();
  builder.ResetBorderTopColor();
  builder.ResetBorderRightStyle();
  builder.ResetBorderRightWidth();
  builder.ResetBorderRightColor();
  builder.ResetBorderBottomStyle();
  builder.ResetBorderBottomWidth();
  builder.ResetBorderBottomColor();
  builder.ResetBorderLeftStyle();
  builder.ResetBorderLeftWidth();
  builder.ResetBorderLeftColor();
  builder.ResetBorderTopLeftRadius();
  builder.ResetBorderTopRightRadius();
  builder.ResetBorderBottomLeftRadius();
  builder.ResetBorderBottomRightRadius();
}

void ResetPadding(ComputedStyleBuilder& builder) {
  builder.ResetPaddingTop();
  builder.ResetPaddingRight();
  builder.ResetPaddingBottom();
  builder.ResetPaddingLeft();
}

bool SystemAccentColorAllowed() {
  return RuntimeEnabledFeatures::CSSSystemAccentColorEnabled() ||
         RuntimeEnabledFeatures::CSSAccentColorKeywordEnabled();
}

}  // namespace

LayoutTheme& LayoutTheme::GetTheme() {
  if (RuntimeEnabledFeatures::MobileLayoutThemeEnabled()) {
    DEFINE_STATIC_REF(LayoutTheme, layout_theme_mobile,
                      (LayoutThemeMobile::Create()));
    return *layout_theme_mobile;
  }
  return NativeTheme();
}

LayoutTheme::LayoutTheme() : has_custom_focus_ring_color_(false) {
}

ControlPart LayoutTheme::AdjustAppearanceWithAuthorStyle(
    ControlPart part,
    const ComputedStyleBuilder& builder) {
  if (IsControlStyled(part, builder))
    return part == kMenulistPart ? kMenulistButtonPart : kNoControlPart;
  return part;
}

ControlPart LayoutTheme::AdjustAppearanceWithElementType(
    const ComputedStyleBuilder& builder,
    const Element* element) {
  ControlPart part = builder.EffectiveAppearance();
  if (!element)
    return kNoControlPart;

  ControlPart auto_appearance = AutoAppearanceFor(*element);
  if (part == auto_appearance)
    return part;

  switch (part) {
    // No restrictions.
    case kNoControlPart:
    case kMediaSliderPart:
    case kMediaSliderThumbPart:
    case kMediaVolumeSliderPart:
    case kMediaVolumeSliderThumbPart:
    case kMediaControlPart:
      return part;
    case kBaseSelectPart:
      CHECK(RuntimeEnabledFeatures::CustomizableSelectEnabled());
      return IsA<HTMLSelectElement>(element) ||
                     HTMLSelectElement::IsPopoverForAppearanceBase(element)
                 ? part
                 : auto_appearance;

    // Aliases of 'auto'.
    // https://drafts.csswg.org/css-ui-4/#typedef-appearance-compat-auto
    case kAutoPart:
    case kCheckboxPart:
    case kRadioPart:
    case kPushButtonPart:
    case kSquareButtonPart:
    case kInnerSpinButtonPart:
    case kListboxPart:
    case kMenulistPart:
    case kMeterPart:
    case kProgressBarPart:
    case kSliderHorizontalPart:
    case kSliderThumbHorizontalPart:
    case kSearchFieldPart:
    case kSearchFieldCancelButtonPart:
    case kTextAreaPart:
      return auto_appearance;

      // The following keywords should work well for some element types
      // even if their default appearances are different from the keywords.

    case kButtonPart:
      return (auto_appearance == kPushButtonPart ||
              auto_appearance == kSquareButtonPart)
                 ? part
                 : auto_appearance;

    case kMenulistButtonPart:
      return auto_appearance == kMenulistPart ? part : auto_appearance;

    case kSliderVerticalPart:
      return auto_appearance == kSliderHorizontalPart ? part : auto_appearance;

    case kSliderThumbVerticalPart:
      return auto_appearance == kSliderThumbHorizontalPart ? part
                                                           : auto_appearance;

    case kTextFieldPart:
      if (const auto* input_element = DynamicTo<HTMLInputElement>(*element);
          input_element &&
          input_element->FormControlType() == FormControlType::kInputSearch) {
        return part;
      }
      return auto_appearance;
  }

  return part;
}

void LayoutTheme::AdjustStyle(const Element* element,
                              ComputedStyleBuilder& builder) {
  ControlPart original_part = builder.Appearance();
  builder.SetEffectiveAppearance(original_part);
  if (original_part == ControlPart::kNoControlPart)
    return;

  // Force inline and table display styles to be inline-block (except for table-
  // which is block)
  if (builder.Display() == EDisplay::kInline ||
      builder.Display() == EDisplay::kInlineTable ||
      builder.Display() == EDisplay::kTableRowGroup ||
      builder.Display() == EDisplay::kTableHeaderGroup ||
      builder.Display() == EDisplay::kTableFooterGroup ||
      builder.Display() == EDisplay::kTableRow ||
      builder.Display() == EDisplay::kTableColumnGroup ||
      builder.Display() == EDisplay::kTableColumn ||
      builder.Display() == EDisplay::kTableCell ||
      builder.Display() == EDisplay::kTableCaption)
    builder.SetDisplay(EDisplay::kInlineBlock);
  else if (builder.Display() == EDisplay::kListItem ||
           builder.Display() == EDisplay::kTable)
    builder.SetDisplay(EDisplay::kBlock);

  ControlPart part = AdjustAppearanceWithAuthorStyle(
      AdjustAppearanceWithElementType(builder, element), builder);
  builder.SetEffectiveAppearance(part);
  DCHECK_NE(part, kAutoPart);
  if (part == kNoControlPart)
    return;
  DCHECK(element);
  // After this point, a Node must be non-null Element if
  // EffectiveAppearance() != kNoControlPart.

  AdjustControlPartStyle(builder);

  // Call the appropriate style adjustment method based off the appearance
  // value.
  switch (part) {
    case kMenulistPart:
      return AdjustMenuListStyle(builder);
    case kMenulistButtonPart:
      return AdjustMenuListButtonStyle(builder);
    case kSliderThumbHorizontalPart:
    case kSliderThumbVerticalPart:
      return AdjustSliderThumbStyle(builder);
    case kSearchFieldCancelButtonPart:
      return AdjustSearchFieldCancelButtonStyle(builder);
    default:
      break;
  }

  if (IsSliderContainer(*element))
    AdjustSliderContainerStyle(*element, builder);
}

String LayoutTheme::ExtraDefaultStyleSheet() {
  // If you want to add something depending on a runtime flag here,
  // please consider using `@supports blink-feature(flag-name)` in a
  // stylesheet resource file.
  return "@namespace 'http://www.w3.org/1999/xhtml';\n";
}

String LayoutTheme::ExtraFullscreenStyleSheet() {
  return String();
}

Color LayoutTheme::ActiveSelectionBackgroundColor(
    mojom::blink::ColorScheme color_scheme) const {
  Color color = PlatformActiveSelectionBackgroundColor(color_scheme);
#if BUILDFLAG(IS_MAC)
  // BlendWithWhite() darkens Mac system colors too much.
  // Apply .8 (204/255) alpha instead, same as Safari.
  if (color_scheme == mojom::blink::ColorScheme::kDark)
    return Color(color.Red(), color.Green(), color.Blue(), 204);
#endif
  return color.BlendWithWhite();
}

Color LayoutTheme::InactiveSelectionBackgroundColor(
    mojom::blink::ColorScheme color_scheme) const {
  return PlatformInactiveSelectionBackgroundColor(color_scheme)
      .BlendWithWhite();
}

Color LayoutTheme::ActiveSelectionForegroundColor(
    mojom::blink::ColorScheme color_scheme) const {
  return PlatformActiveSelectionForegroundColor(color_scheme);
}

Color LayoutTheme::InactiveSelectionForegroundColor(
    mojom::blink::ColorScheme color_scheme) const {
  return PlatformInactiveSelectionForegroundColor(color_scheme);
}

Color LayoutTheme::ActiveListBoxSelectionBackgroundColor(
    mojom::blink::ColorScheme color_scheme) const {
  return PlatformActiveListBoxSelectionBackgroundColor(color_scheme);
}

Color LayoutTheme::InactiveListBoxSelectionBackgroundColor(
    mojom::blink::ColorScheme color_scheme) const {
  return PlatformInactiveListBoxSelectionBackgroundColor(color_scheme);
}

Color LayoutTheme::ActiveListBoxSelectionForegroundColor(
    mojom::blink::ColorScheme color_scheme) const {
  return PlatformActiveListBoxSelectionForegroundColor(color_scheme);
}

Color LayoutTheme::InactiveListBoxSelectionForegroundColor(
    mojom::blink::ColorScheme color_scheme) const {
  return PlatformInactiveListBoxSelectionForegroundColor(color_scheme);
}

Color LayoutTheme::PlatformSpellingMarkerUnderlineColor() const {
  return Color(255, 0, 0);
}

Color LayoutTheme::PlatformGrammarMarkerUnderlineColor() const {
  return Color(192, 192, 192);
}

Color LayoutTheme::PlatformActiveSpellingMarkerHighlightColor() const {
  return Color(255, 0, 0, 102);
}

Color LayoutTheme::PlatformActiveSelectionBackgroundColor(
    mojom::blink::ColorScheme color_scheme) const {
  // Use a blue color by default if the platform theme doesn't define anything.
  return Color(0, 0, 255);
}

Color LayoutTheme::PlatformActiveSelectionForegroundColor(
    mojom::blink::ColorScheme color_scheme) const {
  // Use a white color by default if the platform theme doesn't define anything.
  return Color::kWhite;
}

Color LayoutTheme::PlatformInactiveSelectionBackgroundColor(
    mojom::blink::ColorScheme color_scheme) const {
  // Use a grey color by default if the platform theme doesn't define anything.
  // This color matches Firefox's inactive color.
  return Color(176, 176, 176);
}

Color LayoutTheme::PlatformInactiveSelectionForegroundColor(
    mojom::blink::ColorScheme color_scheme) const {
  // Use a black color by default.
  return Color::kBlack;
}

Color LayoutTheme::PlatformActiveListBoxSelectionBackgroundColor(
    mojom::blink::ColorScheme color_scheme) const {
  return PlatformActiveSelectionBackgroundColor(color_scheme);
}

Color LayoutTheme::PlatformActiveListBoxSelectionForegroundColor(
    mojom::blink::ColorScheme color_scheme) const {
  return PlatformActiveSelectionForegroundColor(color_scheme);
}

Color LayoutTheme::PlatformInactiveListBoxSelectionBackgroundColor(
    mojom::blink::ColorScheme color_scheme) const {
  return PlatformInactiveSelectionBackgroundColor(color_scheme);
}

Color LayoutTheme::PlatformInactiveListBoxSelectionForegroundColor(
    mojom::blink::ColorScheme color_scheme) const {
  return PlatformInactiveSelectionForegroundColor(color_scheme);
}

bool LayoutTheme::IsControlStyled(ControlPart part,
                                  const ComputedStyleBuilder& builder) const {
  switch (part) {
    case kPushButtonPart:
    case kSquareButtonPart:
    case kButtonPart:
    case kProgressBarPart:
      return builder.HasAuthorBackground() || builder.HasAuthorBorder();

    case kMeterPart:
      return RuntimeEnabledFeatures::MeterDevolveAppearanceEnabled() &&
             (builder.HasAuthorBackground() || builder.HasAuthorBorder());

    case kMenulistPart:
    case kSearchFieldPart:
    case kTextAreaPart:
    case kTextFieldPart:
      return builder.HasAuthorBackground() || builder.HasAuthorBorder() ||
             builder.BoxShadow();

    default:
      return false;
  }
}

bool LayoutTheme::ShouldDrawDefaultFocusRing(const Node* node,
                                             const ComputedStyle& style) const {
  if (!node)
    return true;
  if (!style.HasEffectiveAppearance() && !node->IsLink())
    return true;
  // We can't use LayoutTheme::isFocused because outline:auto might be
  // specified to non-:focus rulesets.
  if (node->IsFocused() && !node->ShouldHaveFocusAppearance())
    return false;
  return true;
}

void LayoutTheme::AdjustCheckboxStyle(ComputedStyleBuilder& builder) const {
  // padding - not honored by WinIE, needs to be removed.
  ResetPadding(builder);

  // border - honored by WinIE, but looks terrible (just paints in the control
  // box and turns off the Windows XP theme) for now, we will not honor it.
  ResetBorder(builder);

  builder.SetShouldIgnoreOverflowPropertyForInlineBlockBaseline();
  builder.SetInlineBlockBaselineEdge(EInlineBlockBaselineEdge::kBorderBox);
}

void LayoutTheme::AdjustRadioStyle(ComputedStyleBuilder& builder) const {
  // padding - not honored by WinIE, needs to be removed.
  ResetPadding(builder);

  // border - honored by WinIE, but looks terrible (just paints in the control
  // box and turns off the Windows XP theme) for now, we will not honor it.
  ResetBorder(builder);

  builder.SetShouldIgnoreOverflowPropertyForInlineBlockBaseline();
  builder.SetInlineBlockBaselineEdge(EInlineBlockBaselineEdge::kBorderBox);
}

void LayoutTheme::AdjustButtonStyle(ComputedStyleBuilder&) const {}

void LayoutTheme::AdjustInnerSpinButtonStyle(ComputedStyleBuilder&) const {}

void LayoutTheme::AdjustMenuListStyle(ComputedStyleBuilder& builder) const {
  // Menulists should have visible overflow
  // https://bugs.webkit.org/show_bug.cgi?id=21287
  builder.SetOverflowX(EOverflow::kVisible);
  builder.SetOverflowY(EOverflow::kVisible);
}

void LayoutTheme::AdjustMenuListButtonStyle(ComputedStyleBuilder&) const {}

void LayoutTheme::AdjustSliderContainerStyle(
    const Element& element,
    ComputedStyleBuilder& builder) const {
  DCHECK(IsSliderContainer(element));

  if (!IsHorizontalWritingMode(builder.GetWritingMode())) {
    builder.SetTouchAction(TouchAction::kPanX);
  } else if (RuntimeEnabledFeatures::
                 NonStandardAppearanceValueSliderVerticalEnabled() &&
             builder.EffectiveAppearance() == kSliderVerticalPart) {
    builder.SetTouchAction(TouchAction::kPanX);
    builder.SetWritingMode(WritingMode::kVerticalRl);
    // It's always in RTL because the slider value increases up even in LTR.
    builder.SetDirection(TextDirection::kRtl);
  } else {
    builder.SetTouchAction(TouchAction::kPanY);
    builder.SetWritingMode(WritingMode::kHorizontalTb);
    if (To<HTMLInputElement>(element.OwnerShadowHost())->DataList()) {
      builder.SetAlignSelf(StyleSelfAlignmentData(ItemPosition::kCenter,
                                                  OverflowAlignment::kUnsafe));
    }
  }
  builder.SetEffectiveAppearance(kNoControlPart);
}

void LayoutTheme::AdjustSliderThumbStyle(ComputedStyleBuilder& builder) const {
  AdjustSliderThumbSize(builder);
}

void LayoutTheme::AdjustSliderThumbSize(ComputedStyleBuilder&) const {}

void LayoutTheme::AdjustSearchFieldCancelButtonStyle(
    ComputedStyleBuilder&) const {}

void LayoutTheme::PlatformColorsDidChange() {
  Page::PlatformColorsChanged();
}

void LayoutTheme::ColorSchemeDidChange() {
  Page::ColorSchemeChanged();
}

void LayoutTheme::SetCaretBlinkInterval(base::TimeDelta interval) {
  caret_blink_interval_ = interval;
}

base::TimeDelta LayoutTheme::CaretBlinkInterval() const {
  // Disable the blinking caret in web test mode, as it introduces
  // a race condition for the pixel tests. http://b/1198440
  return WebTestSupport::IsRunningWebTest() ? base::TimeDelta()
                                            : caret_blink_interval_;
}

Color LayoutTheme::SystemColor(CSSValueID css_value_id,
                               mojom::blink::ColorScheme color_scheme,
                               const ui::ColorProvider* color_provider,
                               bool is_in_web_app_scope) const {
  if (color_provider && !WebTestSupport::IsRunningWebTest()) {
    return SystemColorFromColorProvider(css_value_id, color_scheme,
                                        color_provider, is_in_web_app_scope);
  }
  return DefaultSystemColor(css_value_id, color_scheme, color_provider,
                            is_in_web_app_scope);
}

Color LayoutTheme::DefaultSystemColor(CSSValueID css_value_id,
                                      mojom::blink::ColorScheme color_scheme,
                                      const ui::ColorProvider* color_provider,
                                      bool is_in_web_app_scope) const {
  // The source for the deprecations commented on below is
  // https://www.w3.org/TR/css-color-4/#deprecated-system-colors.

  switch (css_value_id) {
    case CSSValueID::kAccentcolor:
      return RuntimeEnabledFeatures::CSSAccentColorKeywordEnabled()
                 ? GetAccentColorOrDefault(color_scheme, is_in_web_app_scope)
                 : Color();
    case CSSValueID::kAccentcolortext:
      return RuntimeEnabledFeatures::CSSAccentColorKeywordEnabled()
                 ? GetAccentColorText(color_scheme, is_in_web_app_scope)
                 : Color();
    case CSSValueID::kActivetext:
      return Color::FromRGBA32(0xFFFF0000);
    case CSSValueID::kButtonborder:
    // The following system colors were deprecated to default to ButtonBorder.
    case CSSValueID::kActiveborder:
    case CSSValueID::kInactiveborder:
    case CSSValueID::kThreeddarkshadow:
    case CSSValueID::kThreedhighlight:
    case CSSValueID::kThreedlightshadow:
    case CSSValueID::kThreedshadow:
    case CSSValueID::kWindowframe:
      return color_scheme == mojom::blink::ColorScheme::kDark
                 ? Color::FromRGBA32(0xFF6B6B6B)
                 : Color::FromRGBA32(0xFF767676);
    case CSSValueID::kButtonface:
    // The following system colors were deprecated to default to ButtonFace.
    case CSSValueID::kButtonhighlight:
    case CSSValueID::kButtonshadow:
    case CSSValueID::kThreedface:
      return color_scheme == mojom::blink::ColorScheme::kDark
                 ? Color::FromRGBA32(0xFF6B6B6B)
                 : Color::FromRGBA32(0xFFEFEFEF);
    case CSSValueID::kButtontext:
      return color_scheme == mojom::blink::ColorScheme::kDark
                 ? Color::FromRGBA32(0xFFFFFFFF)
                 : Color::FromRGBA32(0xFF000000);
    case CSSValueID::kCanvas:
    // The following system colors were deprecated to default to Canvas.
    case CSSValueID::kAppworkspace:
    case CSSValueID::kBackground:
    case CSSValueID::kInactivecaption:
    case CSSValueID::kInfobackground:
    case CSSValueID::kMenu:
    case CSSValueID::kScrollbar:
    case CSSValueID::kWindow:
      return color_scheme == mojom::blink::ColorScheme::kDark
                 ? Color::FromRGBA32(0xFF121212)
                 : Color::FromRGBA32(0xFFFFFFFF);
    case CSSValueID::kCanvastext:
    // The following system colors were deprecated to default to CanvasText.
    case CSSValueID::kActivecaption:
    case CSSValueID::kCaptiontext:
    case CSSValueID::kInfotext:
    case CSSValueID::kMenutext:
    case CSSValueID::kWindowtext:
      return color_scheme == mojom::blink::ColorScheme::kDark
                 ? Color::FromRGBA32(0xFFFFFFFF)
                 : Color::FromRGBA32(0xFF000000);

    case CSSValueID::kField:
      return color_scheme == mojom::blink::ColorScheme::kDark
                 ? Color::FromRGBA32(0xFF3B3B3B)
                 : Color::FromRGBA32(0xFFFFFFFF);
    case CSSValueID::kFieldtext:
      return color_scheme == mojom::blink::ColorScheme::kDark
                 ? Color::FromRGBA32(0xFFFFFFFF)
                 : Color::FromRGBA32(0xFF000000);
    case CSSValueID::kGraytext:
    // The following system color was deprecated to default to GrayText.
    case CSSValueID::kInactivecaptiontext:
      return Color::FromRGBA32(0xFF808080);
    case CSSValueID::kHighlight:
      return ActiveSelectionBackgroundColor(color_scheme);
    case CSSValueID::kHighlighttext:
      return ActiveSelectionForegroundColor(color_scheme);
    case CSSValueID::kLinktext:
      return color_scheme == mojom::blink::ColorScheme::kDark
                 ? Color::FromRGBA32(0xFF9E9EFF)
                 : Color::FromRGBA32(0xFF0000EE);
    case CSSValueID::kMark:
      return Color::FromRGBA32(0xFFFFFF00);
    case CSSValueID::kMarktext:
      return Color::FromRGBA32(0xFF000000);
    case CSSValueID::kText:
      return color_scheme == mojom::blink::ColorScheme::kDark
                 ? Color::FromRGBA32(0xFFFFFFFF)
                 : Color::FromRGBA32(0xFF000000);
    case CSSValueID::kVisitedtext:
      return color_scheme == mojom::blink::ColorScheme::kDark
                  ? Color::FromRGBA32(0xFFD0ADF0)
                  : Color::FromRGBA32(0xFF551A8B);
    case CSSValueID::kSelecteditem:
    case CSSValueID::kInternalActiveListBoxSelection:
      return ActiveListBoxSelectionBackgroundColor(color_scheme);
    case CSSValueID::kSelecteditemtext:
    case CSSValueID::kInternalActiveListBoxSelectionText:
      return ActiveListBoxSelectionForegroundColor(color_scheme);
    case CSSValueID::kInternalInactiveListBoxSelection:
      return InactiveListBoxSelectionBackgroundColor(color_scheme);
    case CSSValueID::kInternalInactiveListBoxSelectionText:
      return InactiveListBoxSelectionForegroundColor(color_scheme);
    case CSSValueID::kInternalSpellingErrorColor:
      return PlatformSpellingMarkerUnderlineColor();
    case CSSValueID::kInternalGrammarErrorColor:
      return PlatformGrammarMarkerUnderlineColor();
    case CSSValueID::kInternalSearchColor:
      return PlatformTextSearchHighlightColor(/* active_match */ false,
                                              /* in_forced_colors */ false,
                                              color_scheme, color_provider,
                                              is_in_web_app_scope);
    case CSSValueID::kInternalSearchTextColor:
      return PlatformTextSearchColor(/* active_match */ false,
                                     /* in_forced_colors */ false, color_scheme,
                                     color_provider, is_in_web_app_scope);
    case CSSValueID::kInternalCurrentSearchColor:
      return PlatformTextSearchHighlightColor(/* active_match */ true,
                                              /* in_forced_colors */ false,
                                              color_scheme, color_provider,
                                              is_in_web_app_scope);
    case CSSValueID::kInternalCurrentSearchTextColor:
      return PlatformTextSearchColor(/* active_match */ true,
                                     /* in_forced_colors */ false, color_scheme,
                                     color_provider, is_in_web_app_scope);
    default:
      break;
  }
  DUMP_WILL_BE_NOTREACHED()
      << GetCSSValueName(css_value_id) << " is not a recognized system color";
  return Color();
}

Color LayoutTheme::SystemColorFromColorProvider(
    CSSValueID css_value_id,
    mojom::blink::ColorScheme color_scheme,
    const ui::ColorProvider* color_provider,
    bool is_in_web_app_scope) const {
  SkColor system_theme_color;
  switch (css_value_id) {
    case CSSValueID::kActivetext:
    case CSSValueID::kLinktext:
    case CSSValueID::kVisitedtext:
      system_theme_color =
          color_provider->GetColor(ui::kColorCssSystemHotlight);
      break;
    case CSSValueID::kButtonface:
    case CSSValueID::kButtonhighlight:
    case CSSValueID::kButtonshadow:
    case CSSValueID::kThreedface:
      system_theme_color = color_provider->GetColor(ui::kColorCssSystemBtnFace);
      break;
    case CSSValueID::kButtonborder:
    case CSSValueID::kButtontext:
    // Deprecated colors, see DefaultSystemColor().
    case CSSValueID::kActiveborder:
    case CSSValueID::kInactiveborder:
    case CSSValueID::kThreeddarkshadow:
    case CSSValueID::kThreedhighlight:
    case CSSValueID::kThreedlightshadow:
    case CSSValueID::kThreedshadow:
    case CSSValueID::kWindowframe:
      system_theme_color = color_provider->GetColor(ui::kColorCssSystemBtnText);
      break;
    case CSSValueID::kGraytext:
      system_theme_color =
          color_provider->GetColor(ui::kColorCssSystemGrayText);
      break;
    case CSSValueID::kHighlight:
      return SystemHighlightFromColorProvider(color_scheme, color_provider);
    case CSSValueID::kHighlighttext:
      system_theme_color =
          color_provider->GetColor(ui::kColorCssSystemHighlightText);
      break;
    case CSSValueID::kCanvas:
    case CSSValueID::kField:
    // Deprecated colors, see DefaultSystemColor().
    case CSSValueID::kAppworkspace:
    case CSSValueID::kBackground:
    case CSSValueID::kInactivecaption:
    case CSSValueID::kInfobackground:
    case CSSValueID::kMenu:
    case CSSValueID::kScrollbar:
    case CSSValueID::kWindow:
      system_theme_color = color_provider->GetColor(ui::kColorCssSystemWindow);
      break;
    case CSSValueID::kCanvastext:
    case CSSValueID::kFieldtext:
    // Deprecated colors, see DefaultSystemColor().
    case CSSValueID::kActivecaption:
    case CSSValueID::kCaptiontext:
    case CSSValueID::kInfotext:
    case CSSValueID::kMenutext:
    case CSSValueID::kWindowtext:
      system_theme_color =
          color_provider->GetColor(ui::kColorCssSystemWindowText);
      break;
    default:
      return DefaultSystemColor(css_value_id, color_scheme, color_provider,
                                is_in_web_app_scope);
  }

  return Color::FromSkColor(system_theme_color);
}

Color LayoutTheme::SystemHighlightFromColorProvider(
    mojom::blink::ColorScheme color_scheme,
    const ui::ColorProvider* color_provider) const {
  SkColor system_highlight_color =
      color_provider->GetColor(ui::kColorCssSystemHighlight);
  return Color::FromSkColor(system_highlight_color).BlendWithWhite();
}

Color LayoutTheme::PlatformTextSearchHighlightColor(
    bool active_match,
    bool in_forced_colors,
    mojom::blink::ColorScheme color_scheme,
    const ui::ColorProvider* color_provider,
    bool is_in_web_app_scope) const {
  if (active_match) {
    if (in_forced_colors) {
      return GetTheme().SystemColor(CSSValueID::kHighlight, color_scheme,
                                    color_provider, is_in_web_app_scope);
    }
    return Color(255, 150, 50);  // Orange.
  }
  return Color(255, 255, 0);  // Yellow.
}

Color LayoutTheme::PlatformTextSearchColor(
    bool active_match,
    bool in_forced_colors,
    mojom::blink::ColorScheme color_scheme,
    const ui::ColorProvider* color_provider,
    bool is_in_web_app_scope) const {
  if (in_forced_colors && active_match) {
    return GetTheme().SystemColor(CSSValueID::kHighlighttext, color_scheme,
                                  color_provider, is_in_web_app_scope);
  }
  return Color::kBlack;
}

Color LayoutTheme::TapHighlightColor() {
  return GetTheme().PlatformTapHighlightColor();
}

void LayoutTheme::SetCustomFocusRingColor(const Color& c) {
  const bool changed =
      !has_custom_focus_ring_color_ || custom_focus_ring_color_ != c;
  custom_focus_ring_color_ = c;
  has_custom_focus_ring_color_ = true;
  if (changed) {
    Page::PlatformColorsChanged();
  }
}

Color LayoutTheme::FocusRingColor(
    mojom::blink::ColorScheme color_scheme) const {
  return has_custom_focus_ring_color_ ? custom_focus_ring_color_
                                      : GetTheme().PlatformFocusRingColor();
}

bool LayoutTheme::DelegatesMenuListRendering() const {
  return delegates_menu_list_rendering_;
}

void LayoutTheme::SetDelegatesMenuListRenderingForTesting(bool flag) {
  delegates_menu_list_rendering_ = flag;
}

String LayoutTheme::DisplayNameForFile(const File& file) const {
  return file.name();
}

bool LayoutTheme::SupportsCalendarPicker(InputType::Type type) const {
  DCHECK(RuntimeEnabledFeatures::InputMultipleFieldsUIEnabled());
  return type == InputType::Type::kTime || type == InputType::Type::kDate ||
         type == InputType::Type::kDateTimeLocal ||
         type == InputType::Type::kMonth || type == InputType::Type::kWeek;
}

void LayoutTheme
"""


```