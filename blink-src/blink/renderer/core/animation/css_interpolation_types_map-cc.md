Response:
Let's break down the thought process for analyzing the `css_interpolation_types_map.cc` file.

1. **Understand the Goal:** The request asks for the file's functionality, its relationship to web technologies (JS, HTML, CSS), examples, logical reasoning, and common usage errors.

2. **Initial Scan and Keywords:** Quickly scan the file for key terms. "Interpolation," "CSS," "Animation," "Property," "Type," and the included header files stand out. This immediately suggests the file is related to how CSS property values change smoothly during animations and transitions.

3. **Identify the Core Data Structure:** Notice the class `CSSInterpolationTypesMap`. The name itself is very descriptive. It seems to be a map (or dictionary) that associates CSS properties with their interpolation types.

4. **Examine the `Get` Method:** This is the central method. Its purpose is clearly to retrieve the appropriate `InterpolationTypes` for a given `PropertyHandle`.

5. **Analyze the Logic within `Get`:**
    * **Caching:** The use of static local variables (`all_applicable_types_map`, `reduce_motion_applicable_types_map`) suggests caching to improve performance. The maps store already computed interpolation types for properties.
    * **Custom Properties:**  The code explicitly handles CSS custom properties (variables). It checks the `PropertyRegistry` for registered interpolation types. This indicates that the behavior of animating custom properties can be defined.
    * **`reduce-motion`:** The `document_.ShouldForceReduceMotion()` check is important. It signifies accessibility considerations, where animations might be disabled or simplified.
    * **Switch Statement:** The large `switch` statement based on `css_property.PropertyID()` is crucial. This is where specific interpolation types are assigned to standard CSS properties. Each `case` corresponds to a different CSS property like `width`, `color`, `transform`, etc.
    * **Interpolation Type Classes:**  The `std::make_unique<CSS...InterpolationType>` lines are the core of the logic. They instantiate specific classes responsible for handling the interpolation of a particular property type. For example, `CSSLengthInterpolationType` handles the smooth change of length values.
    * **`CSSDefaultInterpolationType`:** The inclusion of this type as a fallback is important. It suggests a default behavior if a more specific interpolation type isn't defined or applicable.

6. **Connect to Web Technologies:**
    * **CSS:** The file directly deals with CSS properties and their animation. This is the most obvious connection.
    * **JavaScript:**  JavaScript is often used to trigger CSS animations and transitions. Therefore, this file plays a role in *how* those animations are performed when initiated by JavaScript. Examples would involve setting CSS properties or using the Web Animations API.
    * **HTML:** HTML elements are styled with CSS. The animations defined in CSS (and handled by this code) directly affect the visual presentation of HTML elements.

7. **Logical Reasoning (Input/Output):**  Consider what happens when the `Get` method is called.
    * **Input:** A `PropertyHandle` representing a CSS property (e.g., `width`, `--my-color`).
    * **Output:** A `const InterpolationTypes&`, which is a collection of objects responsible for handling the interpolation of that property.

8. **Common Usage Errors (Developer Perspective):**  Think about what mistakes a web developer might make that could relate to this code. Misunderstanding how specific properties animate, not considering `reduce-motion`, or expecting unsupported properties to animate smoothly are potential issues.

9. **`CreateInterpolationTypesForCSSSyntax` Method:**  This method is separate but related. It's used for custom properties defined using `@property`. It parses the syntax definition of the custom property to determine the appropriate interpolation types.

10. **Structure the Answer:**  Organize the findings into clear sections as requested: Functionality, Relationship to Web Technologies, Examples, Logical Reasoning, and Common Usage Errors. Use clear and concise language.

11. **Refine and Elaborate:**  Review the answer for clarity and completeness. Add details where necessary. For example, explain *why* caching is used or how `reduce-motion` affects animations. Ensure the examples are practical and illustrate the points effectively.

**Self-Correction/Refinement during the process:**

* **Initial Thought:**  Maybe this file is just about parsing CSS animation definitions.
* **Correction:**  No, it's more about the *how* of interpolation – the smooth transitions between values. Parsing might happen elsewhere.
* **Initial Thought:** The `switch` statement looks like a simple mapping.
* **Correction:** It's more than that. It involves instantiating specific *classes* that implement the interpolation logic, tailored to the property type (length, color, transform, etc.).
* **Initial Thought:**  The custom property handling seems complex.
* **Clarification:** The separation of the `Get` method for standard properties and the `CreateInterpolationTypesForCSSSyntax` for custom properties makes sense. Custom properties have more dynamic definitions.

By following these steps, combining code analysis with an understanding of web development concepts, and iteratively refining the understanding, one can effectively analyze the provided source code and generate a comprehensive answer.
这个文件 `css_interpolation_types_map.cc` 在 Chromium Blink 引擎中扮演着至关重要的角色，它主要负责**维护和提供 CSS 属性的插值类型信息**，以便在 CSS 动画和过渡效果中能够平滑地在属性值之间进行过渡。

更具体地说，它的功能可以概括为：

1. **存储 CSS 属性与插值类型之间的映射关系:**  它是一个中心化的注册表，记录了哪些 CSS 属性可以进行动画或过渡，以及应该使用哪种特定的插值算法来进行这些动画。例如，对于 `width` 属性，它可能映射到 `CSSLengthInterpolationType`，这意味着宽度值的变化会按照长度单位进行平滑插值。

2. **提供获取属性插值类型的方法:**  `CSSInterpolationTypesMap` 类提供了一个 `Get` 方法，该方法接收一个 `PropertyHandle` (代表一个 CSS 属性) 作为输入，并返回一个 `InterpolationTypes` 对象。`InterpolationTypes` 对象包含了一个或多个可用于该属性的插值类型。之所以可能返回多个插值类型，是因为某些 CSS 属性可能有多种插值方式，例如 `line-height` 可以作为长度或数字进行插值。

3. **处理自定义 CSS 属性的插值:**  对于使用 `@property` 注册的自定义 CSS 属性，该文件也负责根据其语法定义来创建相应的插值类型。`CreateInterpolationTypesForCSSSyntax` 方法用于此目的。

4. **考虑 `reduce-motion` 用户设置:**  代码中会检查文档是否设置了 `reduce-motion`（减少动画）偏好。如果设置了，某些动画可能会被禁用或使用更简单的插值方式，以提高可访问性。

5. **依赖 `PropertyRegistry`:**  它依赖于 `PropertyRegistry` 来获取 CSS 属性的元数据信息。

**它与 javascript, html, css 的功能关系以及举例说明：**

* **CSS:** 这是该文件最直接相关的部分。它定义了如何对不同的 CSS 属性进行动画处理。
    * **例子:** 当你在 CSS 中定义一个过渡效果，例如：
      ```css
      .element {
        width: 100px;
        transition: width 1s ease-in-out;
      }
      .element:hover {
        width: 200px;
      }
      ```
      当鼠标悬停在 `.element` 上时，`css_interpolation_types_map.cc` 中的逻辑会查找 `width` 属性对应的插值类型（很可能是 `CSSLengthInterpolationType`），并使用该类型提供的算法来平滑地将宽度从 `100px` 变化到 `200px`。

    * **例子 (自定义属性):** 如果你使用 `@property` 定义了一个自定义属性：
      ```css
      @property --my-color {
        syntax: '<color>';
        inherits: false;
        initial-value: red;
      }

      .element {
        background-color: var(--my-color);
        transition: --my-color 1s;
      }

      .element:hover {
        --my-color: blue;
      }
      ```
      `css_interpolation_types_map.cc` 中的 `CreateInterpolationTypesForCSSSyntax` 方法会根据 `<color>` 语法创建一个 `CSSColorInterpolationType` 的实例，用于平滑地在 `red` 和 `blue` 之间过渡。

* **JavaScript:** JavaScript 可以通过修改 CSS 属性或使用 Web Animations API 来触发动画和过渡。
    * **例子:** 使用 JavaScript 修改 CSS 属性：
      ```javascript
      const element = document.querySelector('.element');
      element.style.width = '200px'; // 如果有 transition 定义，会触发过渡
      ```
      当 JavaScript 改变元素的 `width` 属性时，Blink 引擎会使用 `css_interpolation_types_map.cc` 中定义的插值类型来执行过渡动画。

    * **例子:** 使用 Web Animations API：
      ```javascript
      const element = document.querySelector('.element');
      element.animate({
        width: ['100px', '200px']
      }, {
        duration: 1000,
        easing: 'ease-in-out'
      });
      ```
      Web Animations API 也会依赖 `css_interpolation_types_map.cc` 来确定如何插值 `width` 属性的值。

* **HTML:** HTML 元素是 CSS 样式应用的目标。动画和过渡效果最终会渲染到 HTML 元素上。
    * **关系:**  HTML 结构提供了应用 CSS 样式的上下文，而 CSS 样式中的动画和过渡声明会触发 `css_interpolation_types_map.cc` 中定义的插值逻辑。

**逻辑推理与假设输入/输出：**

假设输入一个 `PropertyHandle` 代表 CSS 属性 `opacity`。

* **假设输入:** `PropertyHandle(CSSPropertyID::kOpacity)`
* **逻辑推理:** `Get` 方法会查找到 `CSSPropertyID::kOpacity` 的 `case` 分支。
* **输出:** 返回的 `InterpolationTypes` 对象将包含一个 `CSSNumberInterpolationType` 的实例，因为 `opacity` 属性的值是一个介于 0 和 1 之间的数字。

假设输入一个 `PropertyHandle` 代表 CSS 属性 `background-color`。

* **假设输入:** `PropertyHandle(CSSPropertyID::kBackgroundColor)`
* **逻辑推理:** `Get` 方法会查找到 `CSSPropertyID::kBackgroundColor` 的 `case` 分支。
* **输出:** 返回的 `InterpolationTypes` 对象将包含一个 `CSSColorInterpolationType` 的实例，因为 `background-color` 属性的值是一个颜色。

假设输入一个 `PropertyHandle` 代表一个使用 `@property` 定义的自定义属性 `--my-font-size`，其 `syntax` 为 `<length>`.

* **假设输入:** `PropertyHandle(AtomicString("--my-font-size"))`
* **逻辑推理:**  由于是自定义属性，会检查 `PropertyRegistry`。假设已注册，`CreateInterpolationTypesForCSSSyntax` 会根据 `<length>` 语法创建插值类型。
* **输出:** 返回的 `InterpolationTypes` 对象将包含一个 `CSSCustomLengthInterpolationType` 的实例。

**用户或编程常见的使用错误：**

1. **尝试动画不可动画的属性:**  CSS 中并非所有属性都支持动画。如果尝试对一个在 `css_interpolation_types_map.cc` 中没有对应插值类型的属性进行动画，通常不会产生平滑过渡效果，而是会立即跳到最终值。
    * **例子:** 尝试动画 `display` 属性的常见错误（虽然可以使用关键帧动画，但直接过渡通常不生效）。

2. **假设所有数值属性都以相同方式插值:**  即使两个属性都是数值类型，它们的插值方式也可能不同。例如，`opacity` 的插值是简单的线性插值，而角度或长度的插值会考虑单位。
    * **例子:**  错误地认为角度的插值和普通数字的插值方式完全一样，可能导致旋转动画出现意外。

3. **忽略 `reduce-motion` 设置:**  开发者可能没有考虑到用户启用了 `reduce-motion` 设置，导致他们的精细动画在某些用户那里被简化或禁用，影响用户体验。应该确保动画在 `reduce-motion` 模式下也能提供合理的体验。

4. **自定义属性语法定义错误:**  在使用 `@property` 定义自定义属性时，如果 `syntax` 定义不正确或者与实际使用的值不符，可能导致无法进行平滑插值或者出现其他意外行为。
    * **例子:** 定义 `@property --my-size { syntax: '<color>'; ... }`，但实际使用时赋予长度值，会导致插值失败。

5. **期望复杂类型属性的完美插值:**  对于像 `box-shadow` 或 `transform` 这样的复杂属性，其插值逻辑可能比较复杂，并且存在一些限制。例如，`transform` 的插值要求变换函数的类型和顺序匹配。如果起始和结束状态的 `transform` 值结构差异过大，可能无法实现预期的平滑过渡。

总而言之，`css_interpolation_types_map.cc` 是 Blink 引擎中实现 CSS 动画和过渡效果的关键组件，它确保了各种 CSS 属性能够以符合其语义的方式进行平滑过渡，并考虑了用户可访问性设置和自定义属性的支持。理解其功能有助于开发者更好地掌握 CSS 动画的原理，避免常见的错误。

Prompt: 
```
这是目录为blink/renderer/core/animation/css_interpolation_types_map.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/animation/css_interpolation_types_map.h"

#include <memory>
#include <utility>

#include "third_party/blink/renderer/core/animation/css_angle_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_aspect_ratio_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_basic_shape_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_border_image_length_box_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_clip_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_color_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_content_visibility_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_custom_length_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_custom_list_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_custom_transform_function_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_custom_transform_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_default_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_display_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_dynamic_range_limit_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_filter_list_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_font_palette_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_font_size_adjust_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_font_size_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_font_stretch_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_font_style_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_font_variation_settings_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_font_weight_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_grid_template_property_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_image_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_image_list_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_image_slice_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_intrinsic_length_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_length_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_length_list_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_length_pair_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_number_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_offset_rotate_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_overlay_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_paint_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_path_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_percentage_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_position_axis_list_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_position_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_ray_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_resolution_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_rotate_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_scale_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_scrollbar_color_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_shadow_list_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_size_list_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_text_indent_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_time_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_transform_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_transform_origin_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_translate_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_var_cycle_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_visibility_interpolation_type.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/css_syntax_definition.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/properties/css_property.h"
#include "third_party/blink/renderer/core/css/property_registry.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

CSSInterpolationTypesMap::CSSInterpolationTypesMap(
    const PropertyRegistry* registry,
    const Document& document)
    : document_(document), registry_(registry) {}

static const PropertyRegistration* GetRegistration(
    const PropertyRegistry* registry,
    const PropertyHandle& property) {
  DCHECK(property.IsCSSCustomProperty());
  if (!registry) {
    return nullptr;
  }
  return registry->Registration(property.CustomPropertyName());
}

const InterpolationTypes& CSSInterpolationTypesMap::Get(
    const PropertyHandle& property) const {
  using ApplicableTypesMap =
      HashMap<PropertyHandle, std::unique_ptr<const InterpolationTypes>>;
  DEFINE_STATIC_LOCAL(ApplicableTypesMap, all_applicable_types_map, ());

  DEFINE_STATIC_LOCAL(ApplicableTypesMap, reduce_motion_applicable_types_map,
                      ());

  // Custom property interpolation types may change over time so don't trust the
  // applicable_types_map without checking the registry. Also since the static
  // map is shared between documents, the registered type may be different in
  // the different documents.
  if (registry_ && property.IsCSSCustomProperty()) {
    if (const auto* registration = GetRegistration(registry_, property))
      return registration->GetInterpolationTypes();
  }
  bool reduce_motion = document_.ShouldForceReduceMotion();

  ApplicableTypesMap& applicable_types_map =
      reduce_motion ? reduce_motion_applicable_types_map
                    : all_applicable_types_map;

  auto entry = applicable_types_map.find(property);
  if (entry != applicable_types_map.end())
    return *entry->value;

  std::unique_ptr<InterpolationTypes> applicable_types =
      std::make_unique<InterpolationTypes>();

  const CSSProperty& css_property = property.IsCSSProperty()
                                        ? property.GetCSSProperty()
                                        : property.PresentationAttribute();
  // We treat presentation attributes identically to their CSS property
  // equivalents when interpolating.
  PropertyHandle used_property =
      property.IsCSSProperty() ? property : PropertyHandle(css_property);

  if (!reduce_motion) {
    switch (css_property.PropertyID()) {
      case CSSPropertyID::kBaselineShift:
      case CSSPropertyID::kBorderBottomWidth:
      case CSSPropertyID::kBorderLeftWidth:
      case CSSPropertyID::kBorderRightWidth:
      case CSSPropertyID::kBorderTopWidth:
      case CSSPropertyID::kBottom:
      case CSSPropertyID::kCx:
      case CSSPropertyID::kCy:
      case CSSPropertyID::kFlexBasis:
      case CSSPropertyID::kHeight:
      case CSSPropertyID::kLeft:
      case CSSPropertyID::kLetterSpacing:
      case CSSPropertyID::kMarginBottom:
      case CSSPropertyID::kMarginLeft:
      case CSSPropertyID::kMarginRight:
      case CSSPropertyID::kMarginTop:
      case CSSPropertyID::kMaxHeight:
      case CSSPropertyID::kMaxWidth:
      case CSSPropertyID::kMinHeight:
      case CSSPropertyID::kMinWidth:
      case CSSPropertyID::kOffsetDistance:
      case CSSPropertyID::kOutlineOffset:
      case CSSPropertyID::kOutlineWidth:
      case CSSPropertyID::kPaddingBottom:
      case CSSPropertyID::kPaddingLeft:
      case CSSPropertyID::kPaddingRight:
      case CSSPropertyID::kPaddingTop:
      case CSSPropertyID::kPerspective:
      case CSSPropertyID::kR:
      case CSSPropertyID::kRight:
      case CSSPropertyID::kRx:
      case CSSPropertyID::kRy:
      case CSSPropertyID::kShapeMargin:
      case CSSPropertyID::kStrokeDashoffset:
      case CSSPropertyID::kStrokeWidth:
      case CSSPropertyID::kTextDecorationThickness:
      case CSSPropertyID::kTextUnderlineOffset:
      case CSSPropertyID::kTop:
      case CSSPropertyID::kVerticalAlign:
      case CSSPropertyID::kWebkitBorderHorizontalSpacing:
      case CSSPropertyID::kWebkitBorderVerticalSpacing:
      case CSSPropertyID::kColumnGap:
      case CSSPropertyID::kRowGap:
      case CSSPropertyID::kColumnRuleWidth:
      case CSSPropertyID::kColumnWidth:
      case CSSPropertyID::kWebkitPerspectiveOriginX:
      case CSSPropertyID::kWebkitPerspectiveOriginY:
      case CSSPropertyID::kWebkitTransformOriginX:
      case CSSPropertyID::kWebkitTransformOriginY:
      case CSSPropertyID::kWebkitTransformOriginZ:
      case CSSPropertyID::kWidth:
      case CSSPropertyID::kWordSpacing:
      case CSSPropertyID::kX:
      case CSSPropertyID::kY:
        applicable_types->push_back(
            std::make_unique<CSSLengthInterpolationType>(used_property));
        break;
      case CSSPropertyID::kAspectRatio:
        applicable_types->push_back(
            std::make_unique<CSSAspectRatioInterpolationType>(used_property));
        break;
      case CSSPropertyID::kGridTemplateColumns:
      case CSSPropertyID::kGridTemplateRows:
        applicable_types->push_back(
            std::make_unique<CSSGridTemplatePropertyInterpolationType>(
                used_property));
        break;
      case CSSPropertyID::kContainIntrinsicWidth:
      case CSSPropertyID::kContainIntrinsicHeight:
        applicable_types->push_back(
            std::make_unique<CSSIntrinsicLengthInterpolationType>(
                used_property));
        break;
      case CSSPropertyID::kDynamicRangeLimit:
        if (RuntimeEnabledFeatures::CSSDynamicRangeLimitEnabled()) {
          applicable_types->push_back(
              std::make_unique<CSSDynamicRangeLimitInterpolationType>(
                  used_property));
        }
        break;
      case CSSPropertyID::kFlexGrow:
      case CSSPropertyID::kFlexShrink:
      case CSSPropertyID::kFillOpacity:
      case CSSPropertyID::kFloodOpacity:
      case CSSPropertyID::kOpacity:
      case CSSPropertyID::kOrder:
      case CSSPropertyID::kOrphans:
      case CSSPropertyID::kShapeImageThreshold:
      case CSSPropertyID::kStopOpacity:
      case CSSPropertyID::kStrokeMiterlimit:
      case CSSPropertyID::kStrokeOpacity:
      case CSSPropertyID::kColumnCount:
      case CSSPropertyID::kTextSizeAdjust:
      case CSSPropertyID::kWidows:
      case CSSPropertyID::kZIndex:
        applicable_types->push_back(
            std::make_unique<CSSNumberInterpolationType>(used_property));
        break;
      case CSSPropertyID::kLineHeight:
      case CSSPropertyID::kTabSize:
        applicable_types->push_back(
            std::make_unique<CSSLengthInterpolationType>(used_property));
        applicable_types->push_back(
            std::make_unique<CSSNumberInterpolationType>(used_property));
        break;
      case CSSPropertyID::kPopoverShowDelay:
      case CSSPropertyID::kPopoverHideDelay:
        applicable_types->push_back(
            std::make_unique<CSSTimeInterpolationType>(used_property));
        break;
      case CSSPropertyID::kAccentColor:
      case CSSPropertyID::kBackgroundColor:
      case CSSPropertyID::kBorderBottomColor:
      case CSSPropertyID::kBorderLeftColor:
      case CSSPropertyID::kBorderRightColor:
      case CSSPropertyID::kBorderTopColor:
      case CSSPropertyID::kCaretColor:
      case CSSPropertyID::kColor:
      case CSSPropertyID::kFloodColor:
      case CSSPropertyID::kLightingColor:
      case CSSPropertyID::kOutlineColor:
      case CSSPropertyID::kStopColor:
      case CSSPropertyID::kTextDecorationColor:
      case CSSPropertyID::kTextEmphasisColor:
      case CSSPropertyID::kColumnRuleColor:
      case CSSPropertyID::kWebkitTextStrokeColor:
        applicable_types->push_back(
            std::make_unique<CSSColorInterpolationType>(used_property));
        break;
      case CSSPropertyID::kFill:
      case CSSPropertyID::kStroke:
        applicable_types->push_back(
            std::make_unique<CSSPaintInterpolationType>(used_property));
        break;
      case CSSPropertyID::kOffsetPath:
        applicable_types->push_back(
            std::make_unique<CSSBasicShapeInterpolationType>(used_property));
        applicable_types->push_back(
            std::make_unique<CSSRayInterpolationType>(used_property));
        [[fallthrough]];
      case CSSPropertyID::kD:
        applicable_types->push_back(
            std::make_unique<CSSPathInterpolationType>(used_property));
        break;
      case CSSPropertyID::kBoxShadow:
      case CSSPropertyID::kTextShadow:
        applicable_types->push_back(
            std::make_unique<CSSShadowListInterpolationType>(used_property));
        break;
      case CSSPropertyID::kBorderImageSource:
      case CSSPropertyID::kListStyleImage:
      case CSSPropertyID::kWebkitMaskBoxImageSource:
        applicable_types->push_back(
            std::make_unique<CSSImageInterpolationType>(used_property));
        break;
      case CSSPropertyID::kBackgroundImage:
        applicable_types->push_back(
            std::make_unique<CSSImageListInterpolationType>(used_property));
        break;
      case CSSPropertyID::kStrokeDasharray:
        applicable_types->push_back(
            std::make_unique<CSSLengthListInterpolationType>(used_property));
        break;
      case CSSPropertyID::kFontWeight:
        applicable_types->push_back(
            std::make_unique<CSSFontWeightInterpolationType>(used_property));
        break;
      case CSSPropertyID::kFontStretch:
        applicable_types->push_back(
            std::make_unique<CSSFontStretchInterpolationType>(used_property));
        break;
      case CSSPropertyID::kFontStyle:
        applicable_types->push_back(
            std::make_unique<CSSFontStyleInterpolationType>(used_property));
        break;
      case CSSPropertyID::kFontVariationSettings:
        applicable_types->push_back(
            std::make_unique<CSSFontVariationSettingsInterpolationType>(
                used_property));
        break;
      case blink::CSSPropertyID::kFontPalette:
        applicable_types->push_back(
            std::make_unique<CSSFontPaletteInterpolationType>(used_property));
        break;
      case CSSPropertyID::kVisibility:
        applicable_types->push_back(
            std::make_unique<CSSVisibilityInterpolationType>(used_property));
        break;
      case CSSPropertyID::kClip:
        applicable_types->push_back(
            std::make_unique<CSSClipInterpolationType>(used_property));
        break;
      case CSSPropertyID::kOffsetRotate:
        applicable_types->push_back(
            std::make_unique<CSSOffsetRotateInterpolationType>(used_property));
        break;
      case CSSPropertyID::kBackgroundPositionX:
      case CSSPropertyID::kBackgroundPositionY:
      case CSSPropertyID::kWebkitMaskPositionX:
      case CSSPropertyID::kWebkitMaskPositionY:
        applicable_types->push_back(
            std::make_unique<CSSPositionAxisListInterpolationType>(
                used_property));
        break;
      case CSSPropertyID::kObjectPosition:
      case CSSPropertyID::kOffsetAnchor:
      case CSSPropertyID::kOffsetPosition:
      case CSSPropertyID::kPerspectiveOrigin:
        applicable_types->push_back(
            std::make_unique<CSSPositionInterpolationType>(used_property));
        break;
      case CSSPropertyID::kBorderBottomLeftRadius:
      case CSSPropertyID::kBorderBottomRightRadius:
      case CSSPropertyID::kBorderTopLeftRadius:
      case CSSPropertyID::kBorderTopRightRadius:
        applicable_types->push_back(
            std::make_unique<CSSLengthPairInterpolationType>(used_property));
        break;
      case CSSPropertyID::kTranslate:
        applicable_types->push_back(
            std::make_unique<CSSTranslateInterpolationType>(used_property));
        break;
      case CSSPropertyID::kTransformOrigin:
        applicable_types->push_back(
            std::make_unique<CSSTransformOriginInterpolationType>(
                used_property));
        break;
      case CSSPropertyID::kBackgroundSize:
      case CSSPropertyID::kMaskSize:
        applicable_types->push_back(
            std::make_unique<CSSSizeListInterpolationType>(used_property));
        break;
      case CSSPropertyID::kBorderImageOutset:
      case CSSPropertyID::kBorderImageWidth:
      case CSSPropertyID::kWebkitMaskBoxImageOutset:
      case CSSPropertyID::kWebkitMaskBoxImageWidth:
        applicable_types->push_back(
            std::make_unique<CSSBorderImageLengthBoxInterpolationType>(
                used_property));
        break;
      case CSSPropertyID::kScale:
        applicable_types->push_back(
            std::make_unique<CSSScaleInterpolationType>(used_property));
        break;
      case CSSPropertyID::kFontSize:
        applicable_types->push_back(
            std::make_unique<CSSFontSizeInterpolationType>(used_property));
        break;
      case CSSPropertyID::kFontSizeAdjust:
        applicable_types->push_back(
            std::make_unique<CSSFontSizeAdjustInterpolationType>(
                used_property));
        break;
      case CSSPropertyID::kTextIndent:
        applicable_types->push_back(
            std::make_unique<CSSTextIndentInterpolationType>(used_property));
        break;
      case CSSPropertyID::kBorderImageSlice:
      case CSSPropertyID::kWebkitMaskBoxImageSlice:
        applicable_types->push_back(
            std::make_unique<CSSImageSliceInterpolationType>(used_property));
        break;
      case CSSPropertyID::kClipPath:
        applicable_types->push_back(
            std::make_unique<CSSBasicShapeInterpolationType>(used_property));
        applicable_types->push_back(
            std::make_unique<CSSPathInterpolationType>(used_property));
        break;
      case CSSPropertyID::kShapeOutside:
        applicable_types->push_back(
            std::make_unique<CSSBasicShapeInterpolationType>(used_property));
        break;
      case CSSPropertyID::kRotate:
        applicable_types->push_back(
            std::make_unique<CSSRotateInterpolationType>(used_property));
        break;
      case CSSPropertyID::kBackdropFilter:
      case CSSPropertyID::kFilter:
        applicable_types->push_back(
            std::make_unique<CSSFilterListInterpolationType>(used_property));
        break;
      case CSSPropertyID::kTransform:
        applicable_types->push_back(
            std::make_unique<CSSTransformInterpolationType>(used_property));
        break;
      case CSSPropertyID::kVariable:
        DCHECK_EQ(GetRegistration(registry_, property), nullptr);
        break;
      case CSSPropertyID::kObjectViewBox:
        applicable_types->push_back(
            std::make_unique<CSSBasicShapeInterpolationType>(used_property));
        break;
      case CSSPropertyID::kDisplay:
        applicable_types->push_back(
            std::make_unique<CSSDisplayInterpolationType>(used_property));
        break;
      case CSSPropertyID::kContentVisibility:
        applicable_types->push_back(
            std::make_unique<CSSContentVisibilityInterpolationType>(
                used_property));
        break;
      case CSSPropertyID::kOverlay:
        applicable_types->push_back(
            std::make_unique<CSSOverlayInterpolationType>(used_property));
        break;
      case CSSPropertyID::kScrollbarColor:
        applicable_types->push_back(
            std::make_unique<CSSScrollbarColorInterpolationType>(
                used_property));
        break;
      default:
        DCHECK(!css_property.IsInterpolable());
        break;
    }
  }

  applicable_types->push_back(
      std::make_unique<CSSDefaultInterpolationType>(used_property));

  auto add_result =
      applicable_types_map.insert(property, std::move(applicable_types));
  return *add_result.stored_value->value;
}

size_t CSSInterpolationTypesMap::Version() const {
  return registry_ ? registry_->Version() : 0;
}

static std::unique_ptr<CSSInterpolationType>
CreateInterpolationTypeForCSSSyntax(const CSSSyntaxComponent syntax,
                                    PropertyHandle property,
                                    const PropertyRegistration& registration) {
  switch (syntax.GetType()) {
    case CSSSyntaxType::kAngle:
      return std::make_unique<CSSAngleInterpolationType>(property,
                                                         &registration);
    case CSSSyntaxType::kColor:
      return std::make_unique<CSSColorInterpolationType>(property,
                                                         &registration);
    case CSSSyntaxType::kLength:
      return std::make_unique<CSSCustomLengthInterpolationType>(property,
                                                                &registration);
    case CSSSyntaxType::kLengthPercentage:
      return std::make_unique<CSSLengthInterpolationType>(property,
                                                          &registration);
    case CSSSyntaxType::kPercentage:
      return std::make_unique<CSSPercentageInterpolationType>(property,
                                                              &registration);
    case CSSSyntaxType::kNumber:
      return std::make_unique<CSSNumberInterpolationType>(property,
                                                          &registration);
    case CSSSyntaxType::kResolution:
      return std::make_unique<CSSResolutionInterpolationType>(property,
                                                              &registration);
    case CSSSyntaxType::kTime:
      return std::make_unique<CSSTimeInterpolationType>(property,
                                                        &registration);
    case CSSSyntaxType::kImage:
      // TODO(andruud): Implement smooth interpolation for gradients.
      return nullptr;
    case CSSSyntaxType::kInteger:
      return std::make_unique<CSSNumberInterpolationType>(property,
                                                          &registration, true);
    case CSSSyntaxType::kTransformFunction:
      if (!syntax.IsRepeatable() ||
          syntax.GetRepeat() == CSSSyntaxRepeat::kCommaSeparated) {
        // <transform-function> needs an interpolation type different from
        // <transform-function>+ and <transform-list> as it can only use a
        // single function representation for interpolation and composition.
        return std::make_unique<CSSCustomTransformFunctionInterpolationType>(
            property, &registration);
      }
      [[fallthrough]];
    case CSSSyntaxType::kTransformList:
      return std::make_unique<CSSCustomTransformInterpolationType>(
          property, &registration);
    case CSSSyntaxType::kCustomIdent:
    case CSSSyntaxType::kIdent:
    case CSSSyntaxType::kTokenStream:
    case CSSSyntaxType::kUrl:
      // Smooth interpolation not supported for these types.
      return nullptr;
    case CSSSyntaxType::kString:
      // Smooth interpolation not supported for <string> type.
      DCHECK(RuntimeEnabledFeatures::CSSAtPropertyStringSyntaxEnabled());
      return nullptr;
    default:
      NOTREACHED();
  }
}

InterpolationTypes
CSSInterpolationTypesMap::CreateInterpolationTypesForCSSSyntax(
    const AtomicString& property_name,
    const CSSSyntaxDefinition& definition,
    const PropertyRegistration& registration) {
  PropertyHandle property(property_name);
  InterpolationTypes result;

  // All custom properties may encounter var() dependency cycles.
  result.push_back(
      std::make_unique<CSSVarCycleInterpolationType>(property, registration));

  for (const CSSSyntaxComponent& component : definition.Components()) {
    std::unique_ptr<CSSInterpolationType> interpolation_type =
        CreateInterpolationTypeForCSSSyntax(component, property, registration);

    if (!interpolation_type)
      continue;

    if (component.IsRepeatable() &&
        (component.GetType() != CSSSyntaxType::kTransformFunction ||
         component.GetRepeat() != CSSSyntaxRepeat::kSpaceSeparated)) {
      interpolation_type = std::make_unique<CSSCustomListInterpolationType>(
          property, &registration, std::move(interpolation_type),
          component.GetType(), component.GetRepeat());
    }

    result.push_back(std::move(interpolation_type));
  }
  result.push_back(std::make_unique<CSSDefaultInterpolationType>(property));
  return result;
}

}  // namespace blink

"""

```