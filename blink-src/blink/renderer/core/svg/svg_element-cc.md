Response:
The user wants a summary of the functionality of the provided C++ source code file (`svg_element.cc`). They are also interested in the file's relationship with JavaScript, HTML, and CSS. I should provide examples to illustrate these relationships, logical reasoning with input/output examples, common user errors, and a debugging path leading to this file. Finally, I need to summarize the file's overall function for this first part of the request.

Here's a breakdown of the file's responsibilities based on the included headers and the provided code:

1. **Core SVG Element Representation:** This file defines the `SVGElement` class, which is a fundamental building block for representing SVG elements in the Blink rendering engine.

2. **SVG Attributes and Properties:** It handles the parsing and management of SVG attributes, including their connection to CSS properties and animation.

3. **Animation Support:** The file integrates with Blink's animation system, including both SMIL and Web Animations, allowing SVG attributes to be animated.

4. **Styling and Rendering:** It plays a role in how SVG elements are styled using CSS and ultimately rendered on the screen.

5. **DOM Integration:** The file interacts with the Document Object Model (DOM), handling events, and managing the relationships between SVG elements.

6. **`use` Element Instantiation:** The code manages instances of SVG elements created via the `<use>` element.

7. **Error Handling:** It includes basic error reporting for SVG attribute parsing.

8. **Relative Length Handling:** It manages elements with relative lengths, ensuring proper layout invalidation when viewport sizes change.

**Relationship with JavaScript, HTML, and CSS:**

*   **JavaScript:**  JavaScript can interact with SVG elements through the DOM API, setting attributes, adding event listeners, and triggering animations. This file likely contains logic that is exposed to JavaScript.
*   **HTML:** SVG elements are often embedded within HTML documents. This file handles the integration of SVG into the HTML structure.
*   **CSS:** CSS is used to style SVG elements. This file handles the connection between SVG attributes and CSS properties.

**Logical Reasoning, User Errors, and Debugging:** These will require more specific context within the full file content. I'll need to make reasonable assumptions based on the provided code snippet.

**Summary for Part 1:** This file implements the core functionality of the `SVGElement` class in the Blink rendering engine. It manages SVG attributes, connects them to CSS properties, supports animations, integrates with the DOM, handles `<use>` element instances, and deals with elements using relative lengths. It's a crucial component for rendering SVG content within a web browser.
这是 `blink/renderer/core/svg/svg_element.cc` 文件的第一部分，它定义了 Blink 渲染引擎中 `SVGElement` 类的核心功能。根据提供的代码，我们可以归纳出以下主要功能：

**核心功能：**

1. **SVG 元素基类定义：**  `SVGElement` 类是所有 SVG 元素的基类。它继承自 `Element` 类，并添加了 SVG 特有的行为和属性管理。

2. **SVG 特有数据存储：**  通过 `svg_rare_data_` 成员和 `SVGElementRareData` 类，存储了 SVG 元素不常用的数据，例如 SMIL 动画状态、实例信息等，这样做可以优化内存使用。

3. **CSS 样式集成：**
    *   处理 SVG 属性到 CSS 属性的映射，例如 `fill` 属性对应 CSS 的 `fill` 属性。
    *   处理通过属性设置样式，并影响元素的渲染。
    *   支持 `class` 属性的动画。
    *   提供了方法 `CssPropertyIdForSVGAttributeName` 来查找 SVG 属性对应的 CSS 属性 ID。
    *   涉及到 Presentation Attribute 的样式处理，并带有缓存机制优化 URL 相关的属性 (如 `fill`, `clip-path`)。

4. **动画支持（SMIL 和 Web Animations）：**
    *   集成了 Blink 的动画系统，支持 SMIL (Synchronized Multimedia Integration Language) 动画和 Web Animations API。
    *   提供了 `SetWebAnimationsPending`、`ApplyActiveWebAnimations` 等方法来处理 Web Animations。
    *   提供了 `GetSMILAnimations` 和 `EnsureSMILAnimations` 来管理 SMIL 动画。
    *   支持通过 `SetAnimatedAttribute` 和 `ClearAnimatedAttribute` 方法直接设置和清除动画值。
    *   处理 `animateMotion` 动画产生的变换效果。

5. **DOM 操作集成：**
    *   处理元素插入 (`InsertedInto`) 和移除 (`RemovedFrom`) DOM 树时的操作，例如更新相对长度信息、管理 `use` 元素的实例。
    *   处理子节点变化 (`ChildrenChanged`) 时需要执行的操作。

6. **`use` 元素实例管理：**
    *   提供了 `AddInstance` 和 `RemoveInstance` 方法来管理通过 `<use>` 元素创建的 SVG 元素实例。
    *   `InstancesForElement` 方法返回当前元素的所有实例。
    *   `CorrespondingElement` 和 `GeneratingUseElement` 用于获取关联的原始元素或 `<use>` 元素。

7. **相对长度单位处理：**
    *   管理包含相对长度单位的元素，并在父元素尺寸变化时触发子元素的重新布局。
    *   `UpdateRelativeLengthsInformation` 和 `InvalidateRelativeLengthClients` 方法用于更新和失效相对长度信息。

8. **错误报告：**  提供了 `ReportAttributeParsingError` 方法，用于在解析 SVG 属性时报告错误。

9. **标题信息：**  `title()` 方法用于获取 SVG 元素的标题，优先从 `<use>` 元素的 host 获取，否则查找自身的 `<title>` 子元素。

10. **视口 (Viewport) 管理：** 提供了 `IsOutermostSVGSVGElement` 和 `viewportElement` 方法来判断元素是否是最外层的 `<svg>` 元素以及获取其视口元素。

11. **变换 (Transform) 处理：**
    *   提供了 `LocalCoordinateSpaceTransform` 和 `CalculateTransform` 方法来计算元素的变换矩阵。
    *   支持 `animateMotion` 动画产生的变换效果 (`ApplyMotionTransform`)。

**与 JavaScript, HTML, CSS 的关系举例说明：**

*   **JavaScript:**
    *   **假设输入：** JavaScript 代码使用 `element.setAttribute('fill', 'red')` 来设置 SVG 元素的填充颜色。
    *   **输出：** `SVGElement::ParseAttribute` 方法会被调用，最终可能会调用到 `AddPropertyToPresentationAttributeStyleWithCache` 将 `fill: red;` 添加到元素的样式中。
    *   **假设输入：** JavaScript 代码使用 Web Animations API 对 SVG 元素的 `opacity` 属性进行动画，例如：
        ```javascript
        element.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 1000 });
        ```
    *   **输出：** `SVGElement::SetWebAnimationsPending` 会被调用，标记元素有待处理的 Web Animations，之后 `SVGElement::ApplyActiveWebAnimations` 会根据动画效果更新元素的属性。

*   **HTML:**
    *   **举例：**  SVG 代码嵌入到 HTML 中，例如：
        ```html
        <!DOCTYPE html>
        <html>
        <body>
        <svg width="100" height="100">
          <circle cx="50" cy="50" r="40" fill="blue" />
        </svg>
        </body>
        </html>
        ```
    *   **说明：** 当浏览器解析这段 HTML 时，会创建对应的 `SVGElement` 对象（例如 `SVGCircleElement`，继承自 `SVGElement`），`SVGElement` 的相关方法会被调用来处理这些 SVG 元素。

*   **CSS:**
    *   **举例：** CSS 规则应用于 SVG 元素：
        ```css
        circle {
          stroke: black;
          stroke-width: 2;
        }
        ```
    *   **说明：** 样式解析器会将这些 CSS 属性与对应的 SVG 元素关联起来。`SVGElement` 中的逻辑会处理这些样式，并可能通过 `CssPropertyIdForSVGAttributeName` 将 CSS 属性映射回 SVG 属性（虽然这里是 CSS 设置 SVG 属性的样式）。
    *   **假设输入：**  SVG 元素的 `fill` 属性通过 CSS 设置为 `url(#gradient)`。
    *   **输出：** `AddPropertyToPresentationAttributeStyleWithCache` 方法会被调用，并且由于 `fill` 属性是 URL 类型，可能会利用缓存来避免重复解析 URL。

**逻辑推理的假设输入与输出：**

*   **假设输入：**  一个 `<circle>` 元素通过 `<use>` 元素被多次引用。
*   **输出：**  原始的 `<circle>` 元素会通过 `EnsureSVGRareData()->ElementInstances()` 记录所有 `<use>` 元素创建的实例，每个实例都是一个独立的 `SVGElement` 对象，但共享某些属性信息。

**用户或编程常见的使用错误举例说明：**

*   **错误：**  在 JavaScript 中尝试直接修改通过 `<use>` 元素实例化的元素的某些“定义性”属性，例如 `cx`，期望影响所有实例。
*   **说明：**  由于实例的属性可能来源于原始元素或 `<use>` 元素的属性，直接修改实例的某些属性可能不会生效或产生意想不到的结果。开发者应该修改原始元素或 `<use>` 元素的属性来影响所有实例。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户加载包含 SVG 的网页：** 用户在浏览器中打开一个包含 SVG 内容的网页。
2. **浏览器解析 HTML 和 SVG：** 浏览器开始解析 HTML，遇到 `<svg>` 标签及其子元素时，会创建相应的 `SVGElement` 对象。
3. **样式计算：** 浏览器解析 CSS，并将 CSS 规则应用到 SVG 元素上，这会涉及到 `SVGElement` 中处理 CSS 相关的逻辑。
4. **JavaScript 交互 (可选)：** 如果网页包含 JavaScript 代码，JavaScript 可能会操作 SVG 元素，例如修改属性、添加动画等，这会触发 `SVGElement` 的相关方法。
5. **动画触发 (可选)：** 如果 SVG 中定义了 SMIL 动画或通过 Web Animations API 添加了动画，动画引擎会更新 SVG 元素的属性，这会调用 `SVGElement` 中处理动画的方法。
6. **渲染：**  最终，渲染引擎会根据 SVG 元素的属性和样式信息来绘制 SVG 图形。在渲染过程中，可能需要计算元素的变换矩阵，这会调用 `SVGElement::CalculateTransform` 等方法。
7. **`use` 元素实例化：** 如果 SVG 中包含 `<use>` 元素，当浏览器处理到该元素时，会创建目标元素的实例，这会调用 `SVGElement::AddInstance` 等方法。

**总结：**

`blink/renderer/core/svg/svg_element.cc` 文件的第一部分定义了 `SVGElement` 类的核心结构和功能，它是 Blink 渲染引擎中处理 SVG 元素的基础。它负责管理 SVG 元素的属性、样式、动画，并与 DOM 和 JavaScript 进行交互。该文件是理解 Blink 如何渲染和处理 SVG 内容的关键入口点之一。

Prompt: 
```
这是目录为blink/renderer/core/svg/svg_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2004, 2005, 2006, 2007, 2008 Nikolas Zimmermann
 * <zimmermann@kde.org>
 * Copyright (C) 2004, 2005, 2006, 2008 Rob Buis <buis@kde.org>
 * Copyright (C) 2008 Apple Inc. All rights reserved.
 * Copyright (C) 2008 Alp Toker <alp@atoker.com>
 * Copyright (C) 2009 Cameron McCormack <cam@mcc.id.au>
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

#include "third_party/blink/renderer/core/svg/svg_element.h"

#include "base/auto_reset.h"
#include "third_party/blink/renderer/bindings/core/v8/js_event_handler_for_content_attribute.h"
#include "third_party/blink/renderer/core/animation/document_animations.h"
#include "third_party/blink/renderer/core/animation/effect_stack.h"
#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/animation/invalidatable_interpolation.h"
#include "third_party/blink/renderer/core/animation/keyframe_effect.h"
#include "third_party/blink/renderer/core/animation/svg_interpolation_environment.h"
#include "third_party/blink/renderer/core/animation/svg_interpolation_types_map.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/post_style_update_scope.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/add_event_listener_options_resolved.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/events/simulated_click_options.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_resource_container.h"
#include "third_party/blink/renderer/core/layout/svg/transform_helper.h"
#include "third_party/blink/renderer/core/svg/animation/element_smil_animations.h"
#include "third_party/blink/renderer/core/svg/properties/svg_animated_property.h"
#include "third_party/blink/renderer/core/svg/properties/svg_property.h"
#include "third_party/blink/renderer/core/svg/svg_animated_string.h"
#include "third_party/blink/renderer/core/svg/svg_document_extensions.h"
#include "third_party/blink/renderer/core/svg/svg_element_rare_data.h"
#include "third_party/blink/renderer/core/svg/svg_foreign_object_element.h"
#include "third_party/blink/renderer/core/svg/svg_graphics_element.h"
#include "third_party/blink/renderer/core/svg/svg_image_element.h"
#include "third_party/blink/renderer/core/svg/svg_resource.h"
#include "third_party/blink/renderer/core/svg/svg_svg_element.h"
#include "third_party/blink/renderer/core/svg/svg_symbol_element.h"
#include "third_party/blink/renderer/core/svg/svg_title_element.h"
#include "third_party/blink/renderer/core/svg/svg_tree_scope_resources.h"
#include "third_party/blink/renderer/core/svg/svg_use_element.h"
#include "third_party/blink/renderer/core/svg_names.h"
#include "third_party/blink/renderer/core/xml_names.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/threading.h"

namespace blink {

SVGElement::SVGElement(const QualifiedName& tag_name,
                       Document& document,
                       ConstructionType construction_type)
    : Element(tag_name, &document, construction_type),
      svg_rare_data_(nullptr),
      class_name_(
          MakeGarbageCollected<SVGAnimatedString>(this,
                                                  html_names::kClassAttr)) {
  SetHasCustomStyleCallbacks();
}

SVGElement::~SVGElement() {
  DCHECK(isConnected() || !HasRelativeLengths());
}

void SVGElement::DetachLayoutTree(bool performing_reattach) {
  Element::DetachLayoutTree(performing_reattach);
  // To avoid a noncollectable Blink GC reference cycle, we must clear the
  // ComputedStyle here. See http://crbug.com/878032#c11
  if (HasSVGRareData())
    SvgRareData()->ClearOverriddenComputedStyle();
}

void SVGElement::WillRecalcStyle(const StyleRecalcChange change) {
  if (!HasSVGRareData())
    return;
  // If the style changes because of a regular property change (not induced by
  // SMIL animations themselves) reset the "computed style without SMIL style
  // properties", so the base value change gets reflected.
  if (change.ShouldRecalcStyleFor(*this))
    SvgRareData()->SetNeedsOverrideComputedStyleUpdate();
}

SVGElementRareData* SVGElement::EnsureSVGRareData() {
  if (!svg_rare_data_)
    svg_rare_data_ = MakeGarbageCollected<SVGElementRareData>();
  return svg_rare_data_.Get();
}

bool SVGElement::IsOutermostSVGSVGElement() const {
  if (!IsA<SVGSVGElement>(*this))
    return false;

  // Element may not be in the document, pretend we're outermost for viewport(),
  // getCTM(), etc.
  if (!parentNode())
    return true;

  // We act like an outermost SVG element, if we're a direct child of a
  // <foreignObject> element.
  if (IsA<SVGForeignObjectElement>(*parentNode()))
    return true;

  // If we're living in a shadow tree, we're a <svg> element that got created as
  // replacement for a <symbol> element or a cloned <svg> element in the
  // referenced tree. In that case we're always an inner <svg> element.
  if (InUseShadowTree() && ParentOrShadowHostElement() &&
      ParentOrShadowHostElement()->IsSVGElement())
    return false;

  // This is true whenever this is the outermost SVG, even if there are HTML
  // elements outside it
  return !parentNode()->IsSVGElement();
}

void SVGElement::ReportAttributeParsingError(SVGParsingError error,
                                             const QualifiedName& name,
                                             const AtomicString& value) {
  if (error == SVGParseStatus::kNoError)
    return;
  // Don't report any errors on attribute removal.
  if (value.IsNull())
    return;
  GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
      mojom::ConsoleMessageSource::kRendering,
      mojom::ConsoleMessageLevel::kError,
      "Error: " + error.Format(tagName(), name, value)));
}

String SVGElement::title() const {
  // According to spec, we should not return titles when hovering over root
  // <svg> elements imported as a standalone document(those <title> elements
  // are the title of the document, not a tooltip) so we instantly return.
  if (IsA<SVGSVGElement>(*this) && this == GetDocument().documentElement())
    return String();

  if (InUseShadowTree()) {
    String use_title(OwnerShadowHost()->title());
    if (!use_title.empty())
      return use_title;
  }

  // If we aren't an instance in a <use> or the <use> title was not found, then
  // find the first <title> child of this element.
  // If a title child was found, return the text contents.
  if (Element* title_element = Traversal<SVGTitleElement>::FirstChild(*this))
    return title_element->innerText();

  // Otherwise return a null/empty string.
  return String();
}

void SVGElement::SetWebAnimationsPending() {
  GetDocument().AccessSVGExtensions().AddWebAnimationsPendingSVGElement(*this);
  EnsureSVGRareData()->SetWebAnimatedAttributesDirty(true);
}

static bool IsSVGAttributeHandle(const PropertyHandle& property_handle) {
  return property_handle.IsSVGAttribute();
}

void SVGElement::ApplyActiveWebAnimations() {
  ActiveInterpolationsMap active_interpolations_map =
      EffectStack::ActiveInterpolations(
          &GetElementAnimations()->GetEffectStack(), nullptr, nullptr,
          KeyframeEffect::kDefaultPriority, IsSVGAttributeHandle);
  for (auto& entry : active_interpolations_map) {
    const QualifiedName& attribute = entry.key.SvgAttribute();
    SVGInterpolationTypesMap map;
    SVGInterpolationEnvironment environment(
        map, *this, PropertyFromAttribute(attribute)->BaseValueBase());
    InvalidatableInterpolation::ApplyStack(*entry.value, environment);
  }
  if (!HasSVGRareData())
    return;
  SvgRareData()->SetWebAnimatedAttributesDirty(false);
}

template <typename T>
static void ForSelfAndInstances(SVGElement* element, T callback) {
  callback(element);
  for (SVGElement* instance : element->InstancesForElement())
    callback(instance);
}

void SVGElement::SetWebAnimatedAttribute(const QualifiedName& attribute,
                                         SVGPropertyBase* value) {
  SetAnimatedAttribute(attribute, value);
  EnsureSVGRareData()->WebAnimatedAttributes().insert(attribute);
}

void SVGElement::ClearWebAnimatedAttributes() {
  if (!HasSVGRareData())
    return;
  HashSet<QualifiedName>& animated_attributes =
      SvgRareData()->WebAnimatedAttributes();
  for (const QualifiedName& attribute : animated_attributes)
    ClearAnimatedAttribute(attribute);
  animated_attributes.clear();
}

ElementSMILAnimations* SVGElement::GetSMILAnimations() const {
  if (!HasSVGRareData())
    return nullptr;
  return SvgRareData()->GetSMILAnimations();
}

ElementSMILAnimations& SVGElement::EnsureSMILAnimations() {
  return EnsureSVGRareData()->EnsureSMILAnimations();
}

void SVGElement::SetAnimatedAttribute(const QualifiedName& attribute,
                                      SVGPropertyBase* value) {
  // When animating the 'class' attribute we need to have our own
  // unique element data since we'll be altering the active class
  // names for the element.
  if (attribute == html_names::kClassAttr)
    EnsureUniqueElementData();

  ForSelfAndInstances(this, [&attribute, &value](SVGElement* element) {
    if (SVGAnimatedPropertyBase* animated_property =
            element->PropertyFromAttribute(attribute)) {
      animated_property->SetAnimatedValue(value);
      element->SvgAttributeChanged({*animated_property, attribute,
                                    AttributeModificationReason::kDirectly});
    }
  });
}

void SVGElement::ClearAnimatedAttribute(const QualifiedName& attribute) {
  ForSelfAndInstances(this, [&attribute](SVGElement* element) {
    if (SVGAnimatedPropertyBase* animated_property =
            element->PropertyFromAttribute(attribute)) {
      animated_property->SetAnimatedValue(nullptr);
      element->SvgAttributeChanged({*animated_property, attribute,
                                    AttributeModificationReason::kDirectly});
    }
  });
}

void SVGElement::SetAnimatedMotionTransform(
    const AffineTransform& motion_transform) {
  ForSelfAndInstances(this, [&motion_transform](SVGElement* element) {
    AffineTransform* transform = element->AnimateMotionTransform();
    DCHECK(transform);
    *transform = motion_transform;
    if (LayoutObject* layout_object = element->GetLayoutObject()) {
      layout_object->SetNeedsTransformUpdate();
      // The transform paint property relies on the SVG transform value.
      layout_object->SetNeedsPaintPropertyUpdate();
      MarkForLayoutAndParentResourceInvalidation(*layout_object);
    }
  });
}

void SVGElement::ClearAnimatedMotionTransform() {
  SetAnimatedMotionTransform(AffineTransform());
}

bool SVGElement::HasNonCSSPropertyAnimations() const {
  if (HasSVGRareData() && !SvgRareData()->WebAnimatedAttributes().empty())
    return true;
  if (GetSMILAnimations() && GetSMILAnimations()->HasAnimations())
    return true;
  return false;
}

AffineTransform SVGElement::LocalCoordinateSpaceTransform(CTMScope) const {
  // To be overridden by SVGTransformableElement (or as special case
  // SVGTextElement and SVGPatternElement)
  return AffineTransform();
}

bool SVGElement::HasTransform(
    ApplyMotionTransformTag apply_motion_transform) const {
  return (GetLayoutObject() && GetLayoutObject()->HasTransform()) ||
         (apply_motion_transform == kIncludeMotionTransform &&
          HasMotionTransform());
}

AffineTransform SVGElement::CalculateTransform(
    ApplyMotionTransformTag apply_motion_transform) const {
  const LayoutObject* layout_object = GetLayoutObject();

  AffineTransform matrix;
  if (layout_object && layout_object->HasTransform()) {
    const gfx::RectF reference_box =
        TransformHelper::ComputeReferenceBox(*layout_object);
    matrix = TransformHelper::ComputeTransform(
        GetDocument(), layout_object->StyleRef(), reference_box,
        ComputedStyle::kIncludeTransformOrigin);
  }

  // Apply any "motion transform" contribution if requested (and existing.)
  if (apply_motion_transform == kIncludeMotionTransform) {
    ApplyMotionTransform(matrix);
  }
  return matrix;
}

void SVGElement::ApplyMotionTransform(AffineTransform& matrix) const {
  if (HasSVGRareData()) {
    matrix.PostConcat(*SvgRareData()->AnimateMotionTransform());
  }
}

Node::InsertionNotificationRequest SVGElement::InsertedInto(
    ContainerNode& root_parent) {
  Element::InsertedInto(root_parent);
  HideNonce();
  UpdateRelativeLengthsInformation();
  return kInsertionDone;
}

void SVGElement::RemovedFrom(ContainerNode& root_parent) {
  bool was_in_document = root_parent.isConnected();
  auto* root_parent_svg_element = DynamicTo<SVGElement>(
      root_parent.IsShadowRoot() ? root_parent.ParentOrShadowHostElement()
                                 : &root_parent);

  if (was_in_document && HasRelativeLengths()) {
    // The root of the subtree being removed should take itself out from its
    // parent's relative length set. For the other nodes in the subtree we don't
    // need to do anything: they will get their own removedFrom() notification
    // and just clear their sets.
    if (root_parent_svg_element && !ParentOrShadowHostElement()) {
      DCHECK(root_parent_svg_element->elements_with_relative_lengths_.Contains(
          this));
      root_parent_svg_element->UpdateRelativeLengthsInformation(false, this);
    }

    elements_with_relative_lengths_.clear();
  }

  DCHECK(
      !root_parent_svg_element ||
      !root_parent_svg_element->elements_with_relative_lengths_.Contains(this));

  Element::RemovedFrom(root_parent);

  if (was_in_document) {
    if (SVGElement* corresponding_element =
            HasSVGRareData() ? SvgRareData()->CorrespondingElement()
                             : nullptr) {
      corresponding_element->RemoveInstance(this);
      SvgRareData()->SetCorrespondingElement(nullptr);
    }
    RemoveAllIncomingReferences();
  }

  InvalidateInstances();
}

void SVGElement::ChildrenChanged(const ChildrenChange& change) {
  Element::ChildrenChanged(change);

  // Invalidate all instances associated with us.
  InvalidateInstances();
}

CSSPropertyID SVGElement::CssPropertyIdForSVGAttributeName(
    const ExecutionContext* execution_context,
    const QualifiedName& attr_name) {
  if (!attr_name.NamespaceURI().IsNull())
    return CSSPropertyID::kInvalid;

  static HashMap<StringImpl*, CSSPropertyID>* property_name_to_id_map = nullptr;
  if (!property_name_to_id_map) {
    property_name_to_id_map = new HashMap<StringImpl*, CSSPropertyID>;
    // This is a list of all base CSS and SVG CSS properties which are exposed
    // as SVG XML attributes
    const auto attr_names = std::to_array<const QualifiedName*>({
        &svg_names::kAlignmentBaselineAttr,
        &svg_names::kBaselineShiftAttr,
        &svg_names::kBufferedRenderingAttr,
        &svg_names::kClipAttr,
        &svg_names::kClipPathAttr,
        &svg_names::kClipRuleAttr,
        &svg_names::kColorAttr,
        &svg_names::kColorInterpolationAttr,
        &svg_names::kColorInterpolationFiltersAttr,
        &svg_names::kColorRenderingAttr,
        &svg_names::kCursorAttr,
        &svg_names::kDirectionAttr,
        &svg_names::kDisplayAttr,
        &svg_names::kDominantBaselineAttr,
        &svg_names::kFillAttr,
        &svg_names::kFillOpacityAttr,
        &svg_names::kFillRuleAttr,
        &svg_names::kFilterAttr,
        &svg_names::kFloodColorAttr,
        &svg_names::kFloodOpacityAttr,
        &svg_names::kFontFamilyAttr,
        &svg_names::kFontSizeAttr,
        &svg_names::kFontStretchAttr,
        &svg_names::kFontStyleAttr,
        &svg_names::kFontVariantAttr,
        &svg_names::kFontWeightAttr,
        &svg_names::kImageRenderingAttr,
        &svg_names::kLetterSpacingAttr,
        &svg_names::kLightingColorAttr,
        &svg_names::kMarkerEndAttr,
        &svg_names::kMarkerMidAttr,
        &svg_names::kMarkerStartAttr,
        &svg_names::kMaskAttr,
        &svg_names::kMaskTypeAttr,
        &svg_names::kOpacityAttr,
        &svg_names::kOverflowAttr,
        &svg_names::kPaintOrderAttr,
        &svg_names::kPointerEventsAttr,
        &svg_names::kShapeRenderingAttr,
        &svg_names::kStopColorAttr,
        &svg_names::kStopOpacityAttr,
        &svg_names::kStrokeAttr,
        &svg_names::kStrokeDasharrayAttr,
        &svg_names::kStrokeDashoffsetAttr,
        &svg_names::kStrokeLinecapAttr,
        &svg_names::kStrokeLinejoinAttr,
        &svg_names::kStrokeMiterlimitAttr,
        &svg_names::kStrokeOpacityAttr,
        &svg_names::kStrokeWidthAttr,
        &svg_names::kTextAnchorAttr,
        &svg_names::kTextDecorationAttr,
        &svg_names::kTextRenderingAttr,
        &svg_names::kTransformOriginAttr,
        &svg_names::kUnicodeBidiAttr,
        &svg_names::kVectorEffectAttr,
        &svg_names::kVisibilityAttr,
        &svg_names::kWordSpacingAttr,
        &svg_names::kWritingModeAttr,
    });
    for (const auto* qname : attr_names) {
      CSSPropertyID property_id =
          CssPropertyID(execution_context, qname->LocalName());
      DCHECK_GT(property_id, CSSPropertyID::kInvalid);
      property_name_to_id_map->Set(qname->LocalName().Impl(), property_id);
    }
  }

  auto it = property_name_to_id_map->find(attr_name.LocalName().Impl());
  if (it == property_name_to_id_map->end())
    return CSSPropertyID::kInvalid;
  return it->value;
}

void SVGElement::UpdateRelativeLengthsInformation(
    bool client_has_relative_lengths,
    SVGElement* client_element) {
  DCHECK(client_element);

  // Through an unfortunate chain of events, we can end up calling this while a
  // subtree is being removed, and before the subtree has been properly
  // "disconnected". Hence check the entire ancestor chain to avoid propagating
  // relative length clients up into ancestors that have already been
  // disconnected.
  // If we're not yet in a document, this function will be called again from
  // insertedInto(). Do nothing now.
  for (Node* current_node = this; current_node;
       current_node = current_node->ParentOrShadowHostNode()) {
    if (!current_node->isConnected())
      return;
  }

  // An element wants to notify us that its own relative lengths state changed.
  // Register it in the relative length map, and register us in the parent
  // relative length map.  Register the parent in the grandparents map, etc.
  // Repeat procedure until the root of the SVG tree.
  for (Element* current_node = this; current_node;
       current_node = current_node->ParentOrShadowHostElement()) {
    auto* current_element = DynamicTo<SVGElement>(current_node);
    if (!current_element)
      break;

#if DCHECK_IS_ON()
    DCHECK(!current_element->in_relative_length_clients_invalidation_);
#endif

    bool had_relative_lengths = current_element->HasRelativeLengths();
    if (client_has_relative_lengths)
      current_element->elements_with_relative_lengths_.insert(client_element);
    else
      current_element->elements_with_relative_lengths_.erase(client_element);

    // If the relative length state hasn't changed, we can stop propagating the
    // notification.
    if (had_relative_lengths == current_element->HasRelativeLengths())
      return;

    client_element = current_element;
    client_has_relative_lengths = client_element->HasRelativeLengths();
  }

  // Register root SVG elements for top level viewport change notifications.
  if (auto* svg = DynamicTo<SVGSVGElement>(*client_element)) {
    SVGDocumentExtensions& svg_extensions = GetDocument().AccessSVGExtensions();
    if (client_element->HasRelativeLengths())
      svg_extensions.AddSVGRootWithRelativeLengthDescendents(svg);
    else
      svg_extensions.RemoveSVGRootWithRelativeLengthDescendents(svg);
  }
}

void SVGElement::InvalidateRelativeLengthClients() {
  if (!isConnected())
    return;

#if DCHECK_IS_ON()
  DCHECK(!in_relative_length_clients_invalidation_);
  base::AutoReset<bool> in_relative_length_clients_invalidation_change(
      &in_relative_length_clients_invalidation_, true);
#endif

  if (LayoutObject* layout_object = GetLayoutObject()) {
    if (HasRelativeLengths() && layout_object->IsSVGResourceContainer()) {
      auto* resource_container = To<LayoutSVGResourceContainer>(layout_object);
      resource_container->SetNeedsLayoutAndFullPaintInvalidation(
          layout_invalidation_reason::kSizeChanged);
      resource_container->InvalidateCache();
    } else if (SelfHasRelativeLengths()) {
      layout_object->SetNeedsLayoutAndFullPaintInvalidation(
          layout_invalidation_reason::kUnknown, kMarkContainerChain);
    }
  }

  for (SVGElement* element : elements_with_relative_lengths_) {
    if (element != this)
      element->InvalidateRelativeLengthClients();
  }
}

SVGSVGElement* SVGElement::ownerSVGElement() const {
  ContainerNode* n = ParentOrShadowHostNode();
  while (n) {
    if (auto* svg_svg_element = DynamicTo<SVGSVGElement>(n))
      return svg_svg_element;

    n = n->ParentOrShadowHostNode();
  }

  return nullptr;
}

SVGElement* SVGElement::viewportElement() const {
  // This function needs shadow tree support - as LayoutSVGContainer uses this
  // function to determine the "overflow" property. <use> on <symbol> wouldn't
  // work otherwhise.
  ContainerNode* n = ParentOrShadowHostNode();
  while (n) {
    if (IsA<SVGSVGElement>(*n) || IsA<SVGImageElement>(*n) ||
        IsA<SVGSymbolElement>(*n))
      return To<SVGElement>(n);

    n = n->ParentOrShadowHostNode();
  }

  return nullptr;
}

void SVGElement::AddInstance(SVGElement* instance) {
  DCHECK(instance);
  DCHECK(instance->InUseShadowTree());

  HeapHashSet<WeakMember<SVGElement>>& instances =
      EnsureSVGRareData()->ElementInstances();
  DCHECK(!instances.Contains(instance));

  instances.insert(instance);
}

void SVGElement::RemoveInstance(SVGElement* instance) {
  DCHECK(instance);
  // Called during instance->RemovedFrom() after removal from shadow tree
  DCHECK(!instance->isConnected());

  HeapHashSet<WeakMember<SVGElement>>& instances =
      SvgRareData()->ElementInstances();

  instances.erase(instance);
}

static HeapHashSet<WeakMember<SVGElement>>& EmptyInstances() {
  DEFINE_STATIC_LOCAL(
      Persistent<HeapHashSet<WeakMember<SVGElement>>>, empty_instances,
      (MakeGarbageCollected<HeapHashSet<WeakMember<SVGElement>>>()));
  return *empty_instances;
}

const HeapHashSet<WeakMember<SVGElement>>& SVGElement::InstancesForElement()
    const {
  if (!HasSVGRareData())
    return EmptyInstances();
  return SvgRareData()->ElementInstances();
}

SVGElement* SVGElement::CorrespondingElement() const {
  DCHECK(!HasSVGRareData() || !SvgRareData()->CorrespondingElement() ||
         ContainingShadowRoot());
  return HasSVGRareData() ? SvgRareData()->CorrespondingElement() : nullptr;
}

SVGUseElement* SVGElement::GeneratingUseElement() const {
  if (ShadowRoot* root = ContainingShadowRoot()) {
    return DynamicTo<SVGUseElement>(root->host());
  }
  return nullptr;
}

SVGResourceTarget& SVGElement::EnsureResourceTarget() {
  return EnsureSVGRareData()->EnsureResourceTarget(*this);
}

bool SVGElement::IsResourceTarget() const {
  return HasSVGRareData() && SvgRareData()->HasResourceTarget();
}

void SVGElement::SetCorrespondingElement(SVGElement* corresponding_element) {
  EnsureSVGRareData()->SetCorrespondingElement(corresponding_element);
}

bool SVGElement::InUseShadowTree() const {
  return GeneratingUseElement();
}

void SVGElement::ParseAttribute(const AttributeModificationParams& params) {
  // SVGElement and HTMLElement are handling "nonce" the same way.
  if (params.name == html_names::kNonceAttr) {
    if (params.new_value != g_empty_atom)
      setNonce(params.new_value);
  } else if (params.name == svg_names::kLangAttr) {
    LangAttributeChanged();
  }

  const AtomicString& event_name =
      HTMLElement::EventNameForAttributeName(params.name);
  if (!event_name.IsNull()) {
    SetAttributeEventListener(
        event_name, JSEventHandlerForContentAttribute::Create(
                        GetExecutionContext(), params.name, params.new_value));
    return;
  }

  Element::ParseAttribute(params);
}

using AttributeToPropertyTypeMap = HashMap<QualifiedName, AnimatedPropertyType>;
AnimatedPropertyType SVGElement::AnimatedPropertyTypeForCSSAttribute(
    const QualifiedName& attribute_name) {
  DEFINE_STATIC_LOCAL(AttributeToPropertyTypeMap, css_property_map, ());

  if (css_property_map.empty()) {
    // Fill the map for the first use.
    struct AttrToTypeEntry {
      const QualifiedName& attr = g_null_name;
      const AnimatedPropertyType prop_type;
    };
    const auto attr_to_types = std::to_array<const AttrToTypeEntry>({
        {svg_names::kAlignmentBaselineAttr, kAnimatedString},
        {svg_names::kBaselineShiftAttr, kAnimatedString},
        {svg_names::kBufferedRenderingAttr, kAnimatedString},
        {svg_names::kClipPathAttr, kAnimatedString},
        {svg_names::kClipRuleAttr, kAnimatedString},
        {svg_names::kColorAttr, kAnimatedColor},
        {svg_names::kColorInterpolationAttr, kAnimatedString},
        {svg_names::kColorInterpolationFiltersAttr, kAnimatedString},
        {svg_names::kColorRenderingAttr, kAnimatedString},
        {svg_names::kCursorAttr, kAnimatedString},
        {svg_names::kDisplayAttr, kAnimatedString},
        {svg_names::kDominantBaselineAttr, kAnimatedString},
        {svg_names::kFillAttr, kAnimatedColor},
        {svg_names::kFillOpacityAttr, kAnimatedNumber},
        {svg_names::kFillRuleAttr, kAnimatedString},
        {svg_names::kFilterAttr, kAnimatedString},
        {svg_names::kFloodColorAttr, kAnimatedColor},
        {svg_names::kFloodOpacityAttr, kAnimatedNumber},
        {svg_names::kFontFamilyAttr, kAnimatedString},
        {svg_names::kFontSizeAttr, kAnimatedLength},
        {svg_names::kFontStretchAttr, kAnimatedString},
        {svg_names::kFontStyleAttr, kAnimatedString},
        {svg_names::kFontVariantAttr, kAnimatedString},
        {svg_names::kFontWeightAttr, kAnimatedString},
        {svg_names::kImageRenderingAttr, kAnimatedString},
        {svg_names::kLetterSpacingAttr, kAnimatedLength},
        {svg_names::kLightingColorAttr, kAnimatedColor},
        {svg_names::kMarkerEndAttr, kAnimatedString},
        {svg_names::kMarkerMidAttr, kAnimatedString},
        {svg_names::kMarkerStartAttr, kAnimatedString},
        {svg_names::kMaskAttr, kAnimatedString},
        {svg_names::kMaskTypeAttr, kAnimatedString},
        {svg_names::kOpacityAttr, kAnimatedNumber},
        {svg_names::kOverflowAttr, kAnimatedString},
        {svg_names::kPaintOrderAttr, kAnimatedString},
        {svg_names::kPointerEventsAttr, kAnimatedString},
        {svg_names::kShapeRenderingAttr, kAnimatedString},
        {svg_names::kStopColorAttr, kAnimatedColor},
        {svg_names::kStopOpacityAttr, kAnimatedNumber},
        {svg_names::kStrokeAttr, kAnimatedColor},
        {svg_names::kStrokeDasharrayAttr, kAnimatedLengthList},
        {svg_names::kStrokeDashoffsetAttr, kAnimatedLength},
        {svg_names::kStrokeLinecapAttr, kAnimatedString},
        {svg_names::kStrokeLinejoinAttr, kAnimatedString},
        {svg_names::kStrokeMiterlimitAttr, kAnimatedNumber},
        {svg_names::kStrokeOpacityAttr, kAnimatedNumber},
        {svg_names::kStrokeWidthAttr, kAnimatedLength},
        {svg_names::kTextAnchorAttr, kAnimatedString},
        {svg_names::kTextDecorationAttr, kAnimatedString},
        {svg_names::kTextRenderingAttr, kAnimatedString},
        {svg_names::kVectorEffectAttr, kAnimatedString},
        {svg_names::kVisibilityAttr, kAnimatedString},
        {svg_names::kWordSpacingAttr, kAnimatedLength},
    });
    for (const auto& item : attr_to_types) {
      css_property_map.Set(item.attr, item.prop_type);
    }
  }
  auto it = css_property_map.find(attribute_name);
  if (it == css_property_map.end())
    return kAnimatedUnknown;
  return it->value;
}

SVGAnimatedPropertyBase* SVGElement::PropertyFromAttribute(
    const QualifiedName& attribute_name) const {
  if (attribute_name == html_names::kClassAttr) {
    return class_name_.Get();
  } else {
    return nullptr;
  }
}

bool SVGElement::IsAnimatableCSSProperty(const QualifiedName& attr_name) {
  return AnimatedPropertyTypeForCSSAttribute(attr_name) != kAnimatedUnknown;
}

bool SVGElement::IsPresentationAttribute(const QualifiedName& name) const {
  return name.Matches(xml_names::kLangAttr) || name == svg_names::kLangAttr;
}

namespace {

bool ProbablyUrlFunction(const AtomicString& value) {
  return value.length() > 5 && value.Is8Bit() &&
         memcmp(value.Characters8(), "url(", 4) == 0;
}

bool UseCSSURIValueCacheForProperty(CSSPropertyID property_id) {
  return property_id == CSSPropertyID::kFill ||
         property_id == CSSPropertyID::kClipPath;
}

}  // namespace

void SVGElement::AddPropertyToPresentationAttributeStyleWithCache(
    MutableCSSPropertyValueSet* style,
    CSSPropertyID property_id,
    const AtomicString& value) {
  if (UseCSSURIValueCacheForProperty(property_id) &&
      ProbablyUrlFunction(value)) {
    // Cache CSSURIValue objects for a given attribute value string. If other
    // presentation attributes change repeatedly while the fill or clip-path
    // stay the same, we still recreate the presentation attribute style for
    // the mentioned attributes/properties. Cache them to avoid expensive url
    // parsing and resolution.
    StyleEngine& engine = GetDocument().GetStyleEngine();
    if (const CSSValue* cached_value =
            engine.GetCachedFillOrClipPathURIValue(value)) {
      AddPropertyToPresentationAttributeStyle(style, property_id,
                                              *cached_value);
    } else {
      AddPropertyToPresentationAttributeStyle(style, property_id, value);
      if (unsigned count = style->PropertyCount()) {
        // Cache the value if it was added.
        CSSPropertyValueSet::PropertyReference last_decl =
            style->PropertyAt(--count);
        if (last_decl.Id() == property_id) {
          engine.AddCachedFillOrClipPathURIValue(value, last_decl.Value());
        }
      }
    }
  } else {
    AddPropertyToPresentationAttributeStyle(style, property_id, value);
  }
}

void SVGElement::CollectStyleForPresentationAttribute(
    const QualifiedName& name,
    const AtomicString& value,
    MutableCSSPropertyValueSet* style) {
  CSSPropertyID property_id =
      CssPropertyIdForSVGAttributeName(GetExecutionContext(), name);
  if (property_id > CSSPropertyID::kInvalid) {
    AddPropertyToPresentationAttributeStyleWithCache(style, property_id, value);
    return;
  }
  SVGAnimatedPropertyBase* property = PropertyFromAttribute(name);
  if (property && property->HasPresentationAttributeMapping()) {
    if (const CSSValue* css_value = property->CssValue()) {
      AddPropertyToPresentationAttributeStyle(style, property->CssPropertyId(),
                                              *css_value);
    }
    return;
  }
  if (name.Matches(xml_names::kLa
"""


```