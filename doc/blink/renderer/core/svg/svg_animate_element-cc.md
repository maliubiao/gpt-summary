Response:
Let's break down the thought process for analyzing the `svg_animate_element.cc` file.

**1. Understanding the Core Purpose:**

The file name itself, `svg_animate_element.cc`, strongly suggests this code deals with the `<animate>` SVG element. The `.cc` extension indicates it's a C++ source file, part of the Blink rendering engine. Therefore, the primary function is likely to implement the behavior and logic of the `<animate>` tag within a web browser.

**2. Identifying Key Concepts:**

Reading the header comments and included files provides valuable clues:

* **SMIL Animation:** The comments mention "SMIL" (Synchronized Multimedia Integration Language), an older XML-based language for multimedia presentations, including SVG animation. This tells us the file implements SMIL animation features for the `<animate>` element.
* **CSS, HTML, JavaScript:**  The inclusion of headers like `css_property_value_set.h`, `document.h`, and the mention of JavaScript URLs within attributes indicate interactions with these web technologies.
* **SVG Properties:** The inclusion of various `svg_*.h` files (e.g., `svg_animated_color.h`, `svg_length.h`) points to the core function of animating SVG properties.
* **Blink Renderer:** The file path `blink/renderer/core/svg/` clearly positions this within the Blink rendering engine.

**3. Analyzing the Code Structure (Top-Down):**

* **Copyright Notice:** Standard copyright and licensing information, not directly relevant to functionality but important for legal context.
* **Includes:** These are crucial. They reveal the dependencies and the areas of Blink the `SVGAnimateElement` interacts with. Note the different categories: CSS, DOM, Execution Context, SVG animation specifics, SVG property types, and platform-level utilities.
* **Namespace:** `namespace blink { ... }` indicates this code belongs to the Blink project.
* **Unnamed Namespace:** The `namespace { ... }` block contains helper functions that are only used within this file, promoting modularity. The `ComputeCSSPropertyValue` and `PropertyValueType` functions stand out as likely dealing with CSS interactions.
* **`SVGAnimateElement` Class Definition:** This is the central part of the file.

**4. Deconstructing the `SVGAnimateElement` Class:**

* **Constructors/Destructor:**  Standard class lifecycle management.
* **`IsSVGAnimationAttributeSettingJavaScriptURL`:**  A security check to prevent malicious JavaScript execution via animation attributes.
* **`InsertedInto`, `RemovedFrom`:** DOM lifecycle methods, showing how the animation element is integrated into and removed from the document tree. The `SetAttributeName` call here is interesting – it suggests initialization logic.
* **`ParseAttribute`:** Handles changes to attributes of the `<animate>` element, triggering updates.
* **`ResolveTargetProperty`, `ClearTargetProperty`, `UpdateTargetProperty`:**  Logic for identifying the SVG property being animated. This is a core function.
* **`HasValidAnimation`:** Checks if the animation is configured correctly.
* **`CreatePropertyForAttributeAnimation`, `CreateUnderlyingValueForAttributeAnimation`, `CreatePropertyForCSSAnimation`:** Different pathways for creating property objects depending on whether it's a direct SVG attribute or a CSS property being animated. This highlights the two ways animation can work.
* **`ParseValue`:** A central point for converting string values from attributes into internal SVG property representations.
* **`AdjustForInheritance`:** Handles the `inherit` keyword for CSS properties.
* **`DiscreteSelectValue`:** A utility for discrete animation modes.
* **`CalculateAnimationValue`:** The heart of the animation logic, calculating the animated value at a given point in time. It considers animation mode, easing, and repeat counts.
* **`CalculateAnimationMode`, `CalculateToAtEndOfDurationValue`, `CalculateFromAndToValues`, `CalculateFromAndByValues`:** Methods for parsing and interpreting the animation parameters from the attributes.
* **`CreateUnderlyingValueForAnimation`, `CreateAnimationValue`, `ClearAnimationValue`:**  Managing the internal representation of the animated value.
* **`ApplyResultsToTarget`:** Applies the calculated animated value to the target element, either as an SVG attribute or a CSS property.
* **`AnimatedPropertyTypeSupportsAddition`:** Determines if a property can be animated using additive animation.
* **`CalculateDistance`:** Used for paced animation.
* **`WillChangeAnimatedType`, `DidChangeAnimatedType`, `WillChangeAnimationTarget`, `DidChangeAnimationTarget`:** Lifecycle methods for managing the animation state. The calls to `RegisterAnimation` and `UnregisterAnimation` are key for activating and deactivating the animation.
* **`SetAttributeName`, `SetAttributeType`:**  Setters for specific attributes, triggering updates.
* **`Trace`:** Used for garbage collection.

**5. Connecting to Web Technologies:**

* **JavaScript:**  The `IsSVGAnimationAttributeSettingJavaScriptURL` method is a direct link. JavaScript can dynamically modify attributes of the `<animate>` element, and this code needs to be aware of potential security issues.
* **HTML:** The `<animate>` tag itself is an HTML element within the SVG namespace. The code processes this element as it's parsed and rendered by the browser.
* **CSS:**  The file extensively deals with CSS properties. `<animate>` can animate CSS properties, and functions like `ComputeCSSPropertyValue`, `CreatePropertyForCSSAnimation`, and `ApplyResultsToTarget` handle this interaction.

**6. Inferring Logic and Scenarios:**

Based on the function names and code:

* **Input:**  An SVG document with an `<animate>` element, defining attributes like `attributeName`, `from`, `to`, `dur`, etc.
* **Output:**  Changes to the target SVG element's attributes or CSS properties over time, creating animation.

**7. Identifying Potential Errors:**

* **Incorrect Attribute Names:**  Specifying a non-existent or misspelled `attributeName`.
* **Invalid Values:** Providing values for `from`, `to`, or `values` that don't match the data type of the animated property.
* **Conflicting Attributes:**  Using combinations of attributes that are mutually exclusive or lead to undefined behavior.
* **Animating Non-Animatable Properties:** Trying to animate properties that the `<animate>` element doesn't support.

**8. Tracing User Operations:**

* A user creates an SVG file with an `<animate>` element.
* The browser parses the HTML and encounters the `<svg>` and `<animate>` tags.
* The Blink rendering engine creates an `SVGAnimateElement` object.
* The browser may fetch external resources (if the SVG is loaded from a URL).
* The layout engine determines the initial layout of the SVG.
* When the animation starts (based on `begin` time or document load), the `SVGAnimateElement` calculates the animated values over time.
* The `ApplyResultsToTarget` method updates the target element's properties, triggering a repaint of the affected area on the screen.
* Developer tools can inspect the element and its animated properties, providing debugging information.

By following these steps, we can gain a comprehensive understanding of the `svg_animate_element.cc` file's role and how it fits within the larger web ecosystem. The process involves code analysis, understanding related concepts, and reasoning about potential scenarios and errors.
This C++ source file, `svg_animate_element.cc`, within the Chromium Blink rendering engine, is responsible for implementing the behavior of the `<animate>` SVG element. The `<animate>` element is a fundamental building block for creating animations within Scalable Vector Graphics (SVG) by changing the values of attributes or CSS properties of other SVG elements over time.

Here's a breakdown of its functionality, its relationship with JavaScript, HTML, and CSS, along with examples, logical reasoning, potential errors, and debugging clues:

**Functionality of `svg_animate_element.cc`:**

1. **Parsing and Processing `<animate>` Attributes:**
   - It handles the parsing of attributes specific to the `<animate>` element, such as `attributeName`, `attributeType`, `from`, `to`, `by`, `values`, `dur`, `begin`, `end`, `fill`, `repeatCount`, `repeatDur`, `calcMode`, `keyTimes`, and `keySplines`.
   - It determines the type of property being animated (e.g., a number, a length, a color, a string).
   - It differentiates between animating SVG attributes directly (attributeType="XML" or auto) and animating CSS properties (attributeType="CSS").

2. **Calculating Animated Values:**
   - It implements the logic to calculate the intermediate values of the animated property based on the specified timing and pacing functions (e.g., linear, discrete, spline).
   - It handles different animation modes like `from-to`, `from-by`, `by`, and `values`.
   - It considers the `begin`, `end`, `dur`, `repeatCount`, and `repeatDur` attributes to determine when and how many times the animation should play.

3. **Applying Animated Values to the Target Element:**
   - It identifies the target SVG element to be animated based on the implicit targeting rules (the parent element).
   - It updates the corresponding attribute or CSS property of the target element with the calculated animated value at each animation frame.

4. **Handling Inheritance for CSS Animations:**
   - When animating CSS properties, it needs to consider CSS inheritance. The code might retrieve the computed style of the parent element to handle the `inherit` keyword in animation values.

5. **Managing Animation State:**
   - It integrates with the browser's animation system to schedule and manage the animation lifecycle (start, pause, resume, end).
   - It registers and unregisters animations when the `<animate>` element is added to or removed from the DOM, or when its relevant attributes change.

**Relationship with JavaScript, HTML, and CSS:**

* **HTML:** The `<animate>` element is defined within the SVG specification, which is often embedded within HTML documents. This file handles the runtime behavior of that HTML element.

   ```html
   <svg width="200" height="200">
     <rect id="myRect" width="100" height="100" fill="red">
       <animate attributeName="x" from="0" to="100" dur="2s" repeatCount="indefinite"/>
     </rect>
   </svg>
   ```
   In this example, `svg_animate_element.cc` would be responsible for reading the attributes of the `<animate>` element and modifying the `x` attribute of the `<rect>` element over time.

* **JavaScript:** JavaScript can interact with `<animate>` elements in several ways:
    - **Modifying Attributes:** JavaScript can change the attributes of the `<animate>` element dynamically, causing the animation to restart or change its behavior.
      ```javascript
      const animateElement = document.querySelector('animate');
      animateElement.setAttribute('to', '50'); // Change the target x position
      ```
      `svg_animate_element.cc` would react to these changes and update the animation accordingly.
    - **Controlling Animation Playback:**  Methods like `beginElement()`, `endElement()`, `pauseElement()`, and `unpauseElement()` (though these are often implemented in a more general animation controller) can be used to control the animation's state. While this file might not directly implement these methods, it plays a role in how those controls affect the animation.
    - **Accessing Animated Values:** JavaScript can potentially access the currently animated value of a property, although this is less common for direct `<animate>` manipulation and more relevant for more complex JavaScript animation libraries.

* **CSS:** `<animate>` can animate CSS properties directly when `attributeType="CSS"`.

   ```html
   <svg width="200" height="200">
     <rect id="myRect" width="100" height="100" style="fill: red;">
       <animate attributeName="fill" attributeType="CSS" from="red" to="blue" dur="2s" repeatCount="indefinite"/>
     </rect>
   </svg>
   ```
   Here, `svg_animate_element.cc` would interact with the CSS style system to change the `fill` property of the rectangle. The `ComputeCSSPropertyValue` function in the code snippet suggests fetching the base CSS value.

**Logical Reasoning (Hypothetical Input and Output):**

**Scenario 1: Simple Attribute Animation**

* **Input (HTML):**
  ```html
  <svg width="100" height="100">
    <circle id="myCircle" cx="50" cy="50" r="40" fill="green">
      <animate attributeName="cx" from="10" to="90" dur="1s"/>
    </circle>
  </svg>
  ```
* **Processing in `svg_animate_element.cc`:**
    1. The parser creates an `SVGAnimateElement` object for the `<animate>` tag.
    2. It reads the `attributeName="cx"`, `from="10"`, `to="90"`, and `dur="1s"` attributes.
    3. It identifies the target element (`myCircle`).
    4. It determines the property type of `cx` (likely a number).
    5. Over the duration of 1 second, it calculates intermediate values for `cx`, linearly interpolating between 10 and 90.
    6. It updates the `cx` attribute of the `myCircle` element at each animation frame.
* **Output (Visual):** The green circle will smoothly move horizontally from x-coordinate 10 to 90 over 1 second.

**Scenario 2: CSS Property Animation with Inheritance**

* **Input (HTML):**
  ```html
  <svg style="fill: black;">
    <rect width="50" height="50">
      <animate attributeName="fill" attributeType="CSS" from="inherit" to="red" dur="1s"/>
    </rect>
  </svg>
  ```
* **Processing in `svg_animate_element.cc`:**
    1. The parser creates an `SVGAnimateElement`.
    2. It reads `attributeName="fill"`, `attributeType="CSS"`, `from="inherit"`, `to="red"`, and `dur="1s"`.
    3. It identifies the target `<rect>`.
    4. Because `from="inherit"`, the `ComputeCSSPropertyValue` function is likely used to fetch the computed `fill` value of the parent `<svg>` (which is "black").
    5. The animation interpolates the `fill` CSS property from "black" to "red" over 1 second.
* **Output (Visual):** The rectangle's color will smoothly transition from black to red over 1 second.

**Common User or Programming Errors:**

1. **Incorrect `attributeName`:** Specifying an attribute that doesn't exist on the target element or is misspelled. The animation might not have any effect, and the browser's developer console might show warnings or errors.
   ```html
   <animate attributeName="wrongAttribute" from="0" to="100" dur="1s"/>
   ```

2. **Invalid `from`, `to`, or `values`:** Providing values that are not compatible with the data type of the animated attribute. For example, trying to animate the `fill` attribute (which expects a color) with numerical values.
   ```html
   <animate attributeName="fill" from="0" to="100" dur="1s"/>
   ```

3. **Mixing `attributeType` and Attribute Names:**  Trying to animate a CSS property without setting `attributeType="CSS"`. The animation might not work as expected, or the browser might interpret it as an attempt to animate an SVG attribute with that name.

4. **Conflicting Timing Attributes:** Providing contradictory values for `begin`, `end`, and `dur` that make it impossible to determine when the animation should play.

5. **Animating Non-Animatable Attributes:** Attempting to animate attributes that the SVG specification doesn't allow to be animated with `<animate>`.

**User Operations Leading to this Code (Debugging Clues):**

Imagine a developer is debugging an SVG animation that isn't working correctly. Here's how they might end up examining this code:

1. **Initial Observation:** The animation on a webpage isn't behaving as expected. Perhaps an element isn't moving, its color isn't changing, or the timing is off.

2. **Inspect Element in Developer Tools:** The developer opens the browser's developer tools and inspects the SVG element with the failing animation. They examine the attributes of the `<animate>` element to ensure they are correctly specified.

3. **Look for Console Errors/Warnings:** The developer checks the browser's console for any error messages or warnings related to the SVG or animation. These messages might point to issues with attribute syntax or invalid values.

4. **Breakpoint in JavaScript (if any):** If JavaScript is involved in manipulating the animation, the developer might set breakpoints in their JavaScript code to see if the attributes are being set correctly.

5. **Delving into Browser Internals (Advanced):** If the issue isn't apparent from the above steps, a developer with more in-depth knowledge of the browser's rendering engine might suspect a bug or unexpected behavior in the SVG animation implementation.

6. **Searching for Relevant Code:** They might search the Chromium source code for files related to SVG animation, such as `svg_animate_element.cc`. They might be looking for the specific code that handles the problematic attribute or animation behavior.

7. **Setting Breakpoints in C++ Code:** Using a debugger, a Chromium developer could set breakpoints within the `svg_animate_element.cc` file (e.g., in the `ParseAttribute`, `CalculateAnimationValue`, or `ApplyResultsToTarget` functions) to step through the code and understand how the animation is being processed.

8. **Analyzing Function Calls and Data Flow:** By examining the values of variables and the sequence of function calls, the developer can pinpoint where the animation logic is going wrong. They might discover that an attribute is being parsed incorrectly, the animated value calculation is flawed, or the update to the target element is failing.

In essence, the journey to examining `svg_animate_element.cc` is often driven by a need to understand the low-level implementation of SVG animations when high-level debugging methods aren't sufficient to diagnose a problem. This file represents a crucial part of the browser's ability to bring SVG animations to life.

### 提示词
```
这是目录为blink/renderer/core/svg/svg_animate_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2004, 2005 Nikolas Zimmermann <zimmermann@kde.org>
 * Copyright (C) 2004, 2005, 2006 Rob Buis <buis@kde.org>
 * Copyright (C) 2008 Apple Inc. All rights reserved.
 * Copyright (C) Research In Motion Limited 2011. All rights reserved.
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

#include "third_party/blink/renderer/core/svg/svg_animate_element.h"

#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/qualified_name.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/svg/animation/smil_animation_effect_parameters.h"
#include "third_party/blink/renderer/core/svg/animation/smil_animation_value.h"
#include "third_party/blink/renderer/core/svg/properties/svg_animated_property.h"
#include "third_party/blink/renderer/core/svg/properties/svg_property.h"
#include "third_party/blink/renderer/core/svg/svg_angle.h"
#include "third_party/blink/renderer/core/svg/svg_animated_color.h"
#include "third_party/blink/renderer/core/svg/svg_boolean.h"
#include "third_party/blink/renderer/core/svg/svg_integer.h"
#include "third_party/blink/renderer/core/svg/svg_integer_optional_integer.h"
#include "third_party/blink/renderer/core/svg/svg_length.h"
#include "third_party/blink/renderer/core/svg/svg_length_list.h"
#include "third_party/blink/renderer/core/svg/svg_number.h"
#include "third_party/blink/renderer/core/svg/svg_number_list.h"
#include "third_party/blink/renderer/core/svg/svg_number_optional_number.h"
#include "third_party/blink/renderer/core/svg/svg_path.h"
#include "third_party/blink/renderer/core/svg/svg_point_list.h"
#include "third_party/blink/renderer/core/svg/svg_preserve_aspect_ratio.h"
#include "third_party/blink/renderer/core/svg/svg_rect.h"
#include "third_party/blink/renderer/core/svg/svg_script_element.h"
#include "third_party/blink/renderer/core/svg/svg_set_element.h"
#include "third_party/blink/renderer/core/svg/svg_string.h"
#include "third_party/blink/renderer/core/xlink_names.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

namespace {

String ComputeCSSPropertyValue(SVGElement* element, CSSPropertyID id) {
  DCHECK(element);
  // TODO(fs): StyleEngine doesn't support document without a frame.
  // Refer to comment in Element::computedStyle.
  DCHECK(element->InActiveDocument());

  element->GetDocument().UpdateStyleAndLayoutTreeForElement(
      element, DocumentUpdateReason::kSMILAnimation);

  // Don't include any properties resulting from CSS Transitions/Animations or
  // SMIL animations, as we want to retrieve the "base value".
  const ComputedStyle* style = element->BaseComputedStyleForSMIL();
  if (!style)
    return "";
  const CSSValue* value = CSSProperty::Get(id).CSSValueFromComputedStyle(
      *style, element->GetLayoutObject(), false, CSSValuePhase::kResolvedValue);
  return value ? value->CssText() : "";
}

AnimatedPropertyValueType PropertyValueType(const QualifiedName& attribute_name,
                                            const String& value) {
  DEFINE_STATIC_LOCAL(const AtomicString, inherit, ("inherit"));
  if (value.empty() || value != inherit ||
      !SVGElement::IsAnimatableCSSProperty(attribute_name))
    return kRegularPropertyValue;
  return kInheritValue;
}

QualifiedName ConstructQualifiedName(const SVGElement& svg_element,
                                     const AtomicString& attribute_name) {
  if (attribute_name.empty())
    return AnyQName();
  if (!attribute_name.Contains(':'))
    return QualifiedName(attribute_name);

  AtomicString prefix;
  AtomicString local_name;
  if (!Document::ParseQualifiedName(attribute_name, prefix, local_name,
                                    IGNORE_EXCEPTION_FOR_TESTING))
    return AnyQName();

  const AtomicString& namespace_uri = svg_element.lookupNamespaceURI(prefix);
  if (namespace_uri.empty())
    return AnyQName();

  QualifiedName resolved_attr_name(g_null_atom, local_name, namespace_uri);
  // "Animation elements treat attributeName='xlink:href' as being an alias
  // for targetting the 'href' attribute."
  // https://svgwg.org/svg2-draft/types.html#__svg__SVGURIReference__href
  if (resolved_attr_name == xlink_names::kHrefAttr)
    return svg_names::kHrefAttr;
  return resolved_attr_name;
}

}  // unnamed namespace

SVGAnimateElement::SVGAnimateElement(Document& document)
    : SVGAnimateElement(svg_names::kAnimateTag, document) {}

SVGAnimateElement::SVGAnimateElement(const QualifiedName& tag_name,
                                     Document& document)
    : SVGAnimationElement(tag_name, document),
      attribute_name_(AnyQName()),
      type_(kAnimatedUnknown),
      css_property_id_(CSSPropertyID::kInvalid),
      from_property_value_type_(kRegularPropertyValue),
      to_property_value_type_(kRegularPropertyValue),
      attribute_type_(kAttributeTypeAuto) {}

SVGAnimateElement::~SVGAnimateElement() = default;

bool SVGAnimateElement::IsSVGAnimationAttributeSettingJavaScriptURL(
    const Attribute& attribute) const {
  if ((attribute.GetName() == svg_names::kFromAttr ||
       attribute.GetName() == svg_names::kToAttr) &&
      AttributeValueIsJavaScriptURL(attribute))
    return true;

  if (attribute.GetName() == svg_names::kValuesAttr) {
    Vector<String> parts;
    if (!ParseValues(attribute.Value(), parts)) {
      // Assume the worst.
      return true;
    }
    for (const auto& part : parts) {
      if (ProtocolIsJavaScript(part))
        return true;
    }
  }

  return SVGSMILElement::IsSVGAnimationAttributeSettingJavaScriptURL(attribute);
}

Node::InsertionNotificationRequest SVGAnimateElement::InsertedInto(
    ContainerNode& root_parent) {
  SVGAnimationElement::InsertedInto(root_parent);
  if (root_parent.isConnected()) {
    SetAttributeName(ConstructQualifiedName(
        *this, FastGetAttribute(svg_names::kAttributeNameAttr)));
  }
  return kInsertionDone;
}

void SVGAnimateElement::RemovedFrom(ContainerNode& root_parent) {
  if (root_parent.isConnected())
    SetAttributeName(AnyQName());
  SVGAnimationElement::RemovedFrom(root_parent);
}

void SVGAnimateElement::ParseAttribute(
    const AttributeModificationParams& params) {
  if (params.name == svg_names::kAttributeTypeAttr) {
    SetAttributeType(params.new_value);
    return;
  }
  if (params.name == svg_names::kAttributeNameAttr) {
    SetAttributeName(ConstructQualifiedName(*this, params.new_value));
    return;
  }
  SVGAnimationElement::ParseAttribute(params);
}

void SVGAnimateElement::ResolveTargetProperty() {
  DCHECK(targetElement());
  target_property_ = targetElement()->PropertyFromAttribute(AttributeName());
  if (target_property_) {
    type_ = target_property_->GetType();
    css_property_id_ = target_property_->CssPropertyId();

    // Only <animateTransform> is allowed to animate AnimatedTransformList.
    // http://www.w3.org/TR/SVG/animate.html#AnimationAttributesAndProperties
    if (type_ == kAnimatedTransformList) {
      type_ = kAnimatedUnknown;
      css_property_id_ = CSSPropertyID::kInvalid;
    }
  } else {
    type_ = SVGElement::AnimatedPropertyTypeForCSSAttribute(AttributeName());
    css_property_id_ =
        type_ != kAnimatedUnknown
            ? CssPropertyID(targetElement()->GetExecutionContext(),
                            AttributeName().LocalName())
            : CSSPropertyID::kInvalid;
  }
  // Disallow <script> targets here for now to prevent unpleasantries. This
  // also disallows the perfectly "valid" animation of 'className' on said
  // element. If SVGScriptElement.href is transitioned off of SVGAnimatedHref,
  // this can be removed.
  if (IsA<SVGScriptElement>(*targetElement())) {
    type_ = kAnimatedUnknown;
    css_property_id_ = CSSPropertyID::kInvalid;
  }
  DCHECK(type_ != kAnimatedPoint && type_ != kAnimatedStringList &&
         type_ != kAnimatedTransform && type_ != kAnimatedTransformList);
}

void SVGAnimateElement::ClearTargetProperty() {
  target_property_ = nullptr;
  type_ = kAnimatedUnknown;
  css_property_id_ = CSSPropertyID::kInvalid;
}

void SVGAnimateElement::UpdateTargetProperty() {
  if (targetElement()) {
    ResolveTargetProperty();
  } else {
    ClearTargetProperty();
  }
}

bool SVGAnimateElement::HasValidAnimation() const {
  if (type_ == kAnimatedUnknown)
    return false;
  // Always animate CSS properties using the ApplyCSSAnimation code path,
  // regardless of the attributeType value.
  // If attributeType="CSS" and attributeName doesn't point to a CSS property,
  // ignore the animation.
  return IsAnimatingCSSProperty() || GetAttributeType() != kAttributeTypeCSS;
}

SVGPropertyBase* SVGAnimateElement::CreatePropertyForAttributeAnimation(
    const String& value) const {
  // SVG DOM animVal animation code-path.
  // TransformList must be animated via <animateTransform>, and its
  // {from,by,to} attribute values needs to be parsed w.r.t. its "type"
  // attribute. Spec:
  // http://www.w3.org/TR/SVG/single-page.html#animate-AnimateTransformElement
  DCHECK_NE(type_, kAnimatedTransformList);
  DCHECK(target_property_);
  return target_property_->BaseValueBase().CloneForAnimation(value);
}

SVGPropertyBase* SVGAnimateElement::CreateUnderlyingValueForAttributeAnimation()
    const {
  // SVG DOM animVal animation code-path.
  DCHECK_NE(type_, kAnimatedTransformList);
  DCHECK(target_property_);
  const SVGPropertyBase& base_value = target_property_->BaseValueBase();
  switch (base_value.GetType()) {
    case kAnimatedAngle:
      return To<SVGAngle>(base_value).Clone();
    case kAnimatedBoolean:
      return To<SVGBoolean>(base_value).Clone();
    case kAnimatedEnumeration:
      return To<SVGEnumeration>(base_value).Clone();
    case kAnimatedInteger:
      return To<SVGInteger>(base_value).Clone();
    case kAnimatedIntegerOptionalInteger:
      return To<SVGIntegerOptionalInteger>(base_value).Clone();
    case kAnimatedLength:
      return To<SVGLength>(base_value).Clone();
    case kAnimatedLengthList:
      return To<SVGLengthList>(base_value).Clone();
    case kAnimatedNumber:
      return To<SVGNumber>(base_value).Clone();
    case kAnimatedNumberList:
      return To<SVGNumberList>(base_value).Clone();
    case kAnimatedNumberOptionalNumber:
      return To<SVGNumberOptionalNumber>(base_value).Clone();
    case kAnimatedPath:
      return To<SVGPath>(base_value).Clone();
    case kAnimatedPoints:
      return To<SVGPointList>(base_value).Clone();
    case kAnimatedPreserveAspectRatio:
      return To<SVGPreserveAspectRatio>(base_value).Clone();
    case kAnimatedRect:
      return To<SVGRect>(base_value).Clone();
    case kAnimatedString:
      return To<SVGString>(base_value).Clone();

    // The following are either not animated or are not animated as
    // attributeType=XML. <animateTransform> handles the transform-list case.
    case kAnimatedUnknown:
    case kAnimatedColor:
    case kAnimatedPoint:
    case kAnimatedStringList:
    case kAnimatedTransform:
    case kAnimatedTransformList:
    default:
      NOTREACHED();
  }
}

SVGPropertyBase* SVGAnimateElement::CreatePropertyForCSSAnimation(
    const String& value) const {
  // CSS properties animation code-path.
  // Create a basic instance of the corresponding SVG property.
  // The instance will not have full context info. (e.g. SVGLengthMode)
  switch (type_) {
    case kAnimatedColor:
      return MakeGarbageCollected<SVGColorProperty>(value);
    case kAnimatedNumber: {
      auto* property = MakeGarbageCollected<SVGNumber>();
      property->SetValueAsString(value);
      return property;
    }
    case kAnimatedLength: {
      auto* property = MakeGarbageCollected<SVGLength>();
      property->SetValueAsString(value);
      return property;
    }
    case kAnimatedLengthList: {
      auto* property = MakeGarbageCollected<SVGLengthList>();
      property->SetValueAsString(value);
      return property;
    }
    case kAnimatedString: {
      auto* property = MakeGarbageCollected<SVGString>();
      property->SetValueAsString(value);
      return property;
    }
    // These types don't appear in the table in
    // SVGElement::animatedPropertyTypeForCSSAttribute() and thus don't need
    // support.
    case kAnimatedAngle:
    case kAnimatedBoolean:
    case kAnimatedEnumeration:
    case kAnimatedInteger:
    case kAnimatedIntegerOptionalInteger:
    case kAnimatedNumberList:
    case kAnimatedNumberOptionalNumber:
    case kAnimatedPath:
    case kAnimatedPoint:
    case kAnimatedPoints:
    case kAnimatedPreserveAspectRatio:
    case kAnimatedRect:
    case kAnimatedStringList:
    case kAnimatedTransform:
    case kAnimatedTransformList:
    case kAnimatedUnknown:
      break;
    default:
      break;
  }
  NOTREACHED();
}

SVGPropertyBase* SVGAnimateElement::ParseValue(const String& value) const {
  if (IsAnimatingSVGDom())
    return CreatePropertyForAttributeAnimation(value);
  DCHECK(IsAnimatingCSSProperty());
  return CreatePropertyForCSSAnimation(value);
}

SVGPropertyBase* SVGAnimateElement::AdjustForInheritance(
    SVGPropertyBase* property_value,
    AnimatedPropertyValueType value_type) const {
  if (value_type != kInheritValue)
    return property_value;
  DCHECK(IsAnimatingCSSProperty());
  // TODO(fs): At the moment the computed style gets returned as a String and
  // needs to get parsed again. In the future we might want to work with the
  // value type directly to avoid the String parsing.
  DCHECK(targetElement());
  Element* parent = targetElement()->parentElement();
  auto* svg_parent = DynamicTo<SVGElement>(parent);
  if (!svg_parent)
    return property_value;
  // Replace 'inherit' by its computed property value.
  String value = ComputeCSSPropertyValue(svg_parent, css_property_id_);
  return CreatePropertyForCSSAnimation(value);
}

static SVGPropertyBase* DiscreteSelectValue(AnimationMode animation_mode,
                                            float percentage,
                                            SVGPropertyBase* from,
                                            SVGPropertyBase* to) {
  if (((animation_mode == kFromToAnimation || animation_mode == kToAnimation) &&
       percentage > 0.5) ||
      percentage == 1) {
    return to;
  }
  return from;
}

void SVGAnimateElement::CalculateAnimationValue(
    SMILAnimationValue& animation_value,
    float percentage,
    unsigned repeat_count) const {
  DCHECK(targetElement());
  DCHECK(percentage >= 0 && percentage <= 1);
  DCHECK_NE(type_, kAnimatedUnknown);
  DCHECK(from_property_);
  DCHECK_EQ(from_property_->GetType(), type_);
  DCHECK(to_property_);

  DCHECK(animation_value.property_value);
  DCHECK_EQ(animation_value.property_value->GetType(), type_);

  // The semantics of the 'set' element is that it always (and only) sets the
  // 'to' value. (It is also always set as a 'to' animation and will thus never
  // be additive or cumulative.)
  if (IsA<SVGSetElement>(*this))
    percentage = 1;

  if (GetCalcMode() == kCalcModeDiscrete)
    percentage = percentage < 0.5 ? 0 : 1;

  // Values-animation accumulates using the last values entry corresponding to
  // the end of duration time.
  SVGPropertyBase* animated_value = animation_value.property_value;
  SVGPropertyBase* to_at_end_of_duration_value =
      to_at_end_of_duration_property_ ? to_at_end_of_duration_property_
                                      : to_property_;
  SVGPropertyBase* from_value = GetAnimationMode() == kToAnimation
                                    ? animated_value
                                    : from_property_.Get();
  SVGPropertyBase* to_value = to_property_;

  // Apply CSS inheritance rules.
  from_value = AdjustForInheritance(from_value, from_property_value_type_);
  to_value = AdjustForInheritance(to_value, to_property_value_type_);

  // If the animated type can only be animated discretely, then do that here,
  // replacing |result_element|s animated value.
  if (!AnimatedPropertyTypeSupportsAddition()) {
    animation_value.property_value = DiscreteSelectValue(
        GetAnimationMode(), percentage, from_value, to_value);
    return;
  }

  SMILAnimationEffectParameters parameters = ComputeEffectParameters();
  animated_value->CalculateAnimatedValue(
      parameters, percentage, repeat_count, from_value, to_value,
      to_at_end_of_duration_value, targetElement());
}

AnimationMode SVGAnimateElement::CalculateAnimationMode() {
  AnimationMode animation_mode = SVGAnimationElement::CalculateAnimationMode();
  if (animation_mode == kByAnimation || animation_mode == kFromByAnimation) {
    // by/from-by animation may only be used with attributes that support addition
    // (e.g. most numeric attributes).
    if (!AnimatedPropertyTypeSupportsAddition()) {
      return kNoAnimation;
    }
  }
  return animation_mode;
}

bool SVGAnimateElement::CalculateToAtEndOfDurationValue(
    const String& to_at_end_of_duration_string) {
  if (to_at_end_of_duration_string.empty())
    return false;
  to_at_end_of_duration_property_ = ParseValue(to_at_end_of_duration_string);
  return true;
}

void SVGAnimateElement::CalculateFromAndToValues(const String& from_string,
                                                 const String& to_string) {
  DCHECK(targetElement());
  from_property_ = ParseValue(from_string);
  from_property_value_type_ = PropertyValueType(AttributeName(), from_string);
  to_property_ = ParseValue(to_string);
  to_property_value_type_ = PropertyValueType(AttributeName(), to_string);
}

void SVGAnimateElement::CalculateFromAndByValues(const String& from_string,
                                                 const String& by_string) {
  DCHECK(targetElement());
  DCHECK(GetAnimationMode() == kByAnimation ||
         GetAnimationMode() == kFromByAnimation);
  DCHECK(AnimatedPropertyTypeSupportsAddition());
  DCHECK(!IsA<SVGSetElement>(*this));

  from_property_ = ParseValue(from_string);
  from_property_value_type_ = PropertyValueType(AttributeName(), from_string);
  to_property_ = ParseValue(by_string);
  to_property_value_type_ = PropertyValueType(AttributeName(), by_string);
  to_property_->Add(from_property_, targetElement());
}

SVGPropertyBase* SVGAnimateElement::CreateUnderlyingValueForAnimation() const {
  DCHECK(targetElement());
  if (IsAnimatingSVGDom()) {
    // SVG DOM animVal animation code-path.
    return CreateUnderlyingValueForAttributeAnimation();
  }
  DCHECK(IsAnimatingCSSProperty());
  // Presentation attributes that have an SVG DOM representation should use
  // the "SVG DOM" code-path (above.)
  DCHECK(SVGElement::IsAnimatableCSSProperty(AttributeName()));

  // CSS properties animation code-path.
  String base_value =
      ComputeCSSPropertyValue(targetElement(), css_property_id_);
  return CreatePropertyForCSSAnimation(base_value);
}

SMILAnimationValue SVGAnimateElement::CreateAnimationValue() const {
  SMILAnimationValue animation_value;
  animation_value.property_value = CreateUnderlyingValueForAnimation();
  return animation_value;
}

void SVGAnimateElement::ClearAnimationValue() {
  SVGElement* target_element = targetElement();
  DCHECK(target_element);

  // CSS properties animation code-path.
  if (IsAnimatingCSSProperty()) {
    MutableCSSPropertyValueSet* property_set =
        target_element->EnsureAnimatedSMILStyleProperties();
    if (property_set->RemoveProperty(css_property_id_)) {
      target_element->SetNeedsStyleRecalc(
          kLocalStyleChange,
          StyleChangeReasonForTracing::Create(style_change_reason::kAnimation));
    }
  }
  // SVG DOM animVal animation code-path.
  if (IsAnimatingSVGDom())
    target_element->ClearAnimatedAttribute(AttributeName());
}

void SVGAnimateElement::ApplyResultsToTarget(
    const SMILAnimationValue& animation_value) {
  DCHECK(animation_value.property_value);
  DCHECK(targetElement());
  DCHECK_NE(type_, kAnimatedUnknown);

  // We do update the style and the animation property independent of each
  // other.
  SVGElement* target_element = targetElement();
  SVGPropertyBase* animated_value = animation_value.property_value;

  // CSS properties animation code-path.
  if (IsAnimatingCSSProperty()) {
    // Convert the result of the animation to a String and apply it as CSS
    // property on the target_element.
    MutableCSSPropertyValueSet* properties =
        target_element->EnsureAnimatedSMILStyleProperties();
    auto animated_value_string = animated_value->ValueAsString();
    auto& document = target_element->GetDocument();
    auto set_result = properties->ParseAndSetProperty(
        css_property_id_, animated_value_string, false,
        document.GetExecutionContext()->GetSecureContextMode(),
        document.ElementSheet().Contents());
    if (set_result >= MutableCSSPropertyValueSet::kModifiedExisting) {
      target_element->SetNeedsStyleRecalc(
          kLocalStyleChange,
          StyleChangeReasonForTracing::Create(style_change_reason::kAnimation));
    }
  }
  // SVG DOM animVal animation code-path.
  if (IsAnimatingSVGDom())
    target_element->SetAnimatedAttribute(AttributeName(), animated_value);
}

bool SVGAnimateElement::AnimatedPropertyTypeSupportsAddition() const {
  DCHECK(targetElement());
  // http://www.w3.org/TR/SVG/animate.html#AnimationAttributesAndProperties.
  switch (type_) {
    case kAnimatedBoolean:
    case kAnimatedEnumeration:
    case kAnimatedPreserveAspectRatio:
    case kAnimatedString:
    case kAnimatedUnknown:
      return false;
    default:
      return true;
  }
}

float SVGAnimateElement::CalculateDistance(const String& from_string,
                                           const String& to_string) {
  DCHECK(targetElement());
  // FIXME: A return value of float is not enough to support paced animations on
  // lists.
  SVGPropertyBase* from_value = ParseValue(from_string);
  SVGPropertyBase* to_value = ParseValue(to_string);
  return from_value->CalculateDistance(to_value, targetElement());
}

void SVGAnimateElement::WillChangeAnimatedType() {
  UnregisterAnimation(attribute_name_);
  from_property_.Clear();
  to_property_.Clear();
  to_at_end_of_duration_property_.Clear();
}

void SVGAnimateElement::DidChangeAnimatedType() {
  UpdateTargetProperty();
  RegisterAnimation(attribute_name_);
}

void SVGAnimateElement::WillChangeAnimationTarget() {
  SVGAnimationElement::WillChangeAnimationTarget();
  WillChangeAnimatedType();
}

void SVGAnimateElement::DidChangeAnimationTarget() {
  DidChangeAnimatedType();
  SVGAnimationElement::DidChangeAnimationTarget();
}

void SVGAnimateElement::SetAttributeName(const QualifiedName& attribute_name) {
  if (attribute_name == attribute_name_)
    return;
  WillChangeAnimatedType();
  attribute_name_ = attribute_name;
  DidChangeAnimatedType();
  AnimationAttributeChanged();
}

void SVGAnimateElement::SetAttributeType(
    const AtomicString& attribute_type_string) {
  AttributeType attribute_type = kAttributeTypeAuto;
  if (attribute_type_string == "CSS")
    attribute_type = kAttributeTypeCSS;
  else if (attribute_type_string == "XML")
    attribute_type = kAttributeTypeXML;
  if (attribute_type == attribute_type_)
    return;
  WillChangeAnimatedType();
  attribute_type_ = attribute_type;
  DidChangeAnimatedType();
  AnimationAttributeChanged();
}

void SVGAnimateElement::Trace(Visitor* visitor) const {
  visitor->Trace(from_property_);
  visitor->Trace(to_property_);
  visitor->Trace(to_at_end_of_duration_property_);
  visitor->Trace(target_property_);
  SVGAnimationElement::Trace(visitor);
}

}  // namespace blink
```