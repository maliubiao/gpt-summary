Response:
Let's break down the thought process for analyzing this `SVGPatternElement.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relationships with web technologies (JavaScript, HTML, CSS), logical deductions with examples, common user/programming errors, and a debugging context.

2. **Initial Skim and Keyword Identification:**  A quick read-through highlights key terms and concepts: `SVGPatternElement`, `pattern`, `fill`, `stroke`, `xlink:href`, `viewBox`, `preserveAspectRatio`, `transform`, `units`, `contentUnits`. These immediately suggest the file deals with defining reusable graphic patterns in SVG.

3. **Deconstruct the Code -  Sections and their Purpose:**  I'll go through the code section by section, trying to understand the purpose of each part.

    * **Copyright and License:**  Standard boilerplate, indicating the open-source nature and licensing terms. Not directly functional but important for legal reasons.

    * **Includes:** These are crucial for understanding dependencies. I see includes for:
        * Core DOM elements (`ElementTraversal`, `IdTargetObserver`).
        * Layout-related classes (`LayoutSVGResourcePattern`). This links the element to the rendering process.
        * SVG attribute classes (`SVGAnimatedLength`, `SVGAnimatedPreserveAspectRatio`, etc.). This reveals how the element's properties are managed and animated.
        * Base classes (`SVGElement`, `SVGURIReference`, `SVGTests`, `SVGFitToViewBox`). This tells me `SVGPatternElement` inherits functionality and attributes from these classes.
        * Platform utilities (`AffineTransform`). This suggests the element deals with geometric transformations.

    * **Constructor (`SVGPatternElement::SVGPatternElement`):** This initializes the object. It creates and associates `SVGAnimatedLength` and `SVGAnimatedEnumeration` objects for attributes like `x`, `y`, `width`, `height`, `patternTransform`, `patternUnits`, and `patternContentUnits`. The default values hint at the initial state of these properties.

    * **`Trace` Method:** This is part of the Blink garbage collection system. It lists member variables that need to be tracked for memory management.

    * **`BuildPendingResource` and `ClearResourceReferences`:** These methods deal with managing references to other resources, especially via the `xlink:href` attribute. The `IdTargetObserver` is used to watch for changes in the referenced element.

    * **`SvgAttributeChanged`:** This is a crucial method. It's called when an attribute of the `<pattern>` element changes. It handles:
        * Updating presentation attributes for transforms.
        * Invalidating the pattern's layout if relevant attributes change (triggering a re-render).
        * Handling URI references (for `xlink:href`).
        * Delegating to the base class for other attribute changes.

    * **`InsertedInto` and `RemovedFrom`:** These lifecycle methods handle what happens when the `<pattern>` element is added to or removed from the DOM tree. They call `BuildPendingResource` and `ClearResourceReferences` accordingly.

    * **`ChildrenChanged`:** This method invalidates the pattern when its content changes.

    * **`InvalidatePattern` and `InvalidateDependentPatterns`:** These methods trigger a re-rendering of the pattern and any elements that use this pattern.

    * **`CreateLayoutObject`:** This is where the connection to the rendering engine is made. It creates a `LayoutSVGResourcePattern` object, which is responsible for the visual representation of the pattern.

    * **`SetPatternAttributes`:** A helper function to copy attribute values from an `SVGPatternElement` to a `PatternAttributes` structure.

    * **`ReferencedElement`:**  Handles resolving the target of the `xlink:href` attribute.

    * **`CollectPatternAttributes`:** This is a core function. It walks up the chain of referenced patterns (via `xlink:href`) to collect all relevant attributes, handling inheritance and overrides. Cycle detection is implemented to prevent infinite loops.

    * **`LocalCoordinateSpaceTransform`:** Returns the transformation matrix applied to the pattern.

    * **`SelfHasRelativeLengths`:** Checks if any of the length attributes (`x`, `y`, `width`, `height`) are relative (e.g., percentages).

    * **`PropertyFromAttribute`:**  Allows accessing the underlying `SVGAnimatedPropertyBase` objects for various attributes.

    * **`SynchronizeAllSVGAttributes`:**  Ensures the animated attribute values are up-to-date.

    * **`CollectExtraStyleForPresentationAttribute`:**  Adds style information based on attributes.

4. **Identify Key Functionalities:** Based on the code analysis, I can now summarize the key functions:
    * Defining the geometry and visual content of an SVG pattern.
    * Handling attributes related to position, size, transformations, and tiling.
    * Supporting inheritance and overriding of pattern attributes through `xlink:href`.
    * Integrating with the Blink rendering engine.
    * Managing resources and dependencies.
    * Responding to attribute and content changes.

5. **Relate to Web Technologies (HTML, CSS, JavaScript):**

    * **HTML:** The `<pattern>` element is defined in SVG, which is often embedded within HTML.
    * **CSS:**  The `fill` and `stroke` properties in CSS can reference SVG patterns defined using the `<pattern>` element's ID. The `patternUnits` and `patternContentUnits` influence how the pattern scales with the filled/stroked object.
    * **JavaScript:** JavaScript can manipulate the attributes of the `<pattern>` element (e.g., using `setAttribute`) to dynamically change the pattern's appearance. Event listeners could be attached to trigger pattern updates.

6. **Logical Deductions and Examples:** I'll create simple scenarios to illustrate how the code behaves:

    * **Basic Pattern:**  A simple pattern with defined width, height, and content.
    * **`xlink:href`:**  Demonstrate attribute inheritance and overriding.
    * **Units:** Show the difference between `userSpaceOnUse` and `objectBoundingBox`.
    * **Transformations:** Illustrate how `patternTransform` affects the pattern's rendering.

7. **Common Errors:** Think about what developers might do wrong when using `<pattern>`:
    * Forgetting to define width and height.
    * Incorrectly using units.
    * Creating circular `xlink:href` references.
    * Not understanding how transformations are applied.

8. **Debugging Context:**  Imagine a scenario where a pattern isn't rendering correctly. I'll trace the steps that might lead to this file being involved in the debugging process:
    * Inspecting the element in DevTools.
    * Checking the computed styles.
    * Setting breakpoints in `SvgAttributeChanged` or `CollectPatternAttributes`.

9. **Structure and Refine:** Finally, organize the information logically, providing clear explanations and examples. Ensure the language is precise and avoids jargon where possible. Review and refine the examples to ensure they are easy to understand and directly illustrate the concepts. Make sure the explanation flows well and addresses all parts of the original request.
This C++ source code file, `blink/renderer/core/svg/svg_pattern_element.cc`, defines the implementation for the `SVGPatternElement` class within the Blink rendering engine. This class represents the `<pattern>` SVG element. Let's break down its functionality:

**Core Functionality of `SVGPatternElement`:**

1. **Represents the `<pattern>` SVG Element:**  The primary purpose is to model the behavior and attributes of the `<pattern>` element as defined in the SVG specification. This element allows you to define a reusable graphical template that can be used to fill or stroke other SVG shapes.

2. **Manages Pattern Attributes:** The class holds and manages the various attributes associated with a `<pattern>` element, including:
   - **Position and Size:** `x`, `y`, `width`, `height` (using `SVGAnimatedLength` for potential animation).
   - **Transformation:** `patternTransform` (using `SVGAnimatedTransformList` for potential animation of transformations).
   - **Tiling Units:** `patternUnits` (specifying whether the tiling is relative to the user space or the object bounding box).
   - **Content Units:** `patternContentUnits` (specifying the coordinate system for the contents of the `<pattern>` element).
   - **`viewBox` and `preserveAspectRatio`:** Inherited from `SVGFitToViewBox`, controlling how the pattern's content is scaled and positioned within its defined rectangle.
   - **`xlink:href`:** Inherited from `SVGURIReference`, allowing the pattern to inherit attributes from another `<pattern>` element.

3. **Handles Attribute Changes:**  The `SvgAttributeChanged` method is crucial. It's invoked when any attribute of the `<pattern>` element is modified (either via the DOM or CSS). It performs actions like:
   - Updating internal representations of the attributes.
   - Invalidating the pattern's rendering cache (`InvalidatePattern`) to ensure the changes are reflected visually.
   - Handling changes to the `xlink:href` attribute by resolving the referenced pattern.

4. **Integrates with the Rendering Pipeline:**
   - **`CreateLayoutObject`:** This method creates a `LayoutSVGResourcePattern` object. This layout object is responsible for the actual rendering of the pattern when it's used to fill or stroke another SVG element.
   - **`InvalidatePattern`:**  This method signals to the layout object that the pattern needs to be re-rendered.
   - **`CollectPatternAttributes`:** This method gathers all the relevant attributes of the pattern, including those inherited from referenced patterns. This information is used by the layout object during rendering.

5. **Supports Inheritance via `xlink:href`:** The code handles the case where a `<pattern>` element refers to another `<pattern>` using `xlink:href`. It recursively collects attributes, allowing for a chain of pattern definitions.

6. **Manages Resource References:**  The `BuildPendingResource` and `ClearResourceReferences` methods are responsible for tracking dependencies between patterns (via `xlink:href`). This ensures that when a referenced pattern changes, the patterns that depend on it are also updated.

**Relationship with JavaScript, HTML, and CSS:**

* **HTML:** The `<pattern>` element is defined within SVG, which is often embedded directly within HTML using the `<svg>` tag. The attributes of the `<pattern>` element are set using standard HTML attribute syntax within the SVG markup.

   ```html
   <svg>
     <defs>
       <pattern id="myPattern" x="0" y="0" width="10" height="10" patternUnits="userSpaceOnUse">
         <circle cx="5" cy="5" r="4" fill="red"/>
       </pattern>
     </defs>
     <rect x="10" y="10" width="100" height="100" fill="url(#myPattern)"/>
   </svg>
   ```

* **CSS:**  The `fill` and `stroke` properties in CSS can reference a `<pattern>` element by its `id`. This is done using the `url()` function.

   ```css
   rect {
     fill: url(#myPattern);
   }
   ```

* **JavaScript:** JavaScript can interact with the `<pattern>` element through the DOM API:
   - **Accessing Attributes:**  JavaScript can get and set the attributes of the `<pattern>` element using methods like `getAttribute()` and `setAttribute()`.
   - **Modifying Content:** JavaScript can add, remove, or modify the child elements within the `<pattern>` element, which define the pattern's visual content.
   - **Listening for Events:** While less common directly on `<pattern>` elements, events could theoretically be attached.
   - **Animating Attributes:** JavaScript can be used to animate the attributes of the `<pattern>` element, and the `SVGAnimatedLength` and `SVGAnimatedTransformList` classes in this file are designed to handle such animations.

**Example Scenarios and Logical Deductions:**

**Scenario 1: Basic Pattern**

**Hypothetical Input (HTML):**

```html
<svg>
  <defs>
    <pattern id="dots" width="10" height="10" patternUnits="userSpaceOnUse">
      <circle cx="5" cy="5" r="2" fill="blue"/>
    </pattern>
  </defs>
  <rect x="0" y="0" width="50" height="50" fill="url(#dots)"/>
</svg>
```

**Logical Deduction:**

1. The browser parses the HTML and creates an `SVGPatternElement` object for the `<pattern>` tag with `id="dots"`.
2. The `width` and `height` attributes are set to 10. `patternUnits` is set to `userSpaceOnUse`.
3. When the `<rect>` is rendered, its `fill` attribute references the `dots` pattern.
4. The rendering engine uses the `LayoutSVGResourcePattern` associated with the `SVGPatternElement` to tile the blue circle across the `rect`.
5. **Output:** A 50x50 rectangle filled with a repeating pattern of blue dots, each dot centered within a 10x10 unit square in the user coordinate system.

**Scenario 2: Pattern Inheritance with `xlink:href`**

**Hypothetical Input (HTML):**

```html
<svg>
  <defs>
    <pattern id="baseDots" width="10" height="10" patternUnits="userSpaceOnUse">
      <circle cx="5" cy="5" r="2" fill="blue"/>
    </pattern>
    <pattern id="redDots" xlink:href="#baseDots" fill="red"/>
  </defs>
  <rect x="0" y="0" width="50" height="50" fill="url(#redDots)"/>
</svg>
```

**Logical Deduction:**

1. Two `SVGPatternElement` objects are created: `baseDots` and `redDots`.
2. `redDots` has an `xlink:href` attribute pointing to `baseDots`.
3. When `CollectPatternAttributes` is called for `redDots`, it first retrieves the attributes from `baseDots` (width, height, patternUnits, and the `<circle>` element).
4. Then, it applies the attributes of `redDots`. In this case, `redDots` doesn't have `width`, `height`, or `patternUnits` defined, so it inherits those from `baseDots`. However, `redDots` might have its own content (though not in this example) or style attributes. If `redDots` *did* have a `fill` attribute *on the `<pattern>` element itself* (which is technically valid but less common than styling the pattern's contents), it would override anything from the base. **Important Note:**  The `fill="red"` in the example is *incorrectly placed* on the `<pattern>` element. The `fill` should be on the *contents* of the pattern. Let's correct the example for clarity:

```html
<svg>
  <defs>
    <pattern id="baseDots" width="10" height="10" patternUnits="userSpaceOnUse">
      <circle cx="5" cy="5" r="2" fill="blue"/>
    </pattern>
    <pattern id="redDots" xlink:href="#baseDots">
      <circle cx="5" cy="5" r="2" fill="red"/>
    </pattern>
  </defs>
  <rect x="0" y="0" width="50" height="50" fill="url(#redDots)"/>
</svg>
```

Now the deduction is: `redDots` inherits `width`, `height`, and `patternUnits` from `baseDots`, but its content is a red circle.

5. **Output:** A 50x50 rectangle filled with a repeating pattern of **red** dots.

**Common User or Programming Errors:**

1. **Missing `width` and `height` on `<pattern>`:** If `width` or `height` are not specified, the pattern might not be visible or might render unexpectedly, as the browser won't know the dimensions of the tile to repeat.

   ```html
   <pattern id="brokenPattern">
     <circle cx="5" cy="5" r="2" fill="green"/>
   </pattern>
   ```

   **Consequence:** The pattern might not tile correctly or at all.

2. **Incorrect `patternUnits` or `patternContentUnits`:**  Misunderstanding the difference between `userSpaceOnUse` and `objectBoundingBox` can lead to patterns that don't scale or position correctly with the objects they fill.

   - `userSpaceOnUse`: Coordinates in the pattern are absolute in the SVG document's user coordinate system.
   - `objectBoundingBox`: Coordinates are relative to the bounding box of the object being filled (values range from 0 to 1).

   **Example of Error:**  Expecting a pattern defined with `patternUnits="objectBoundingBox"` to have pixel dimensions.

3. **Circular `xlink:href` references:** If pattern A references pattern B, and pattern B references pattern A (directly or indirectly), this creates an infinite loop. The browser needs to detect and handle this to prevent crashes or hangs. The `CollectPatternAttributes` method includes logic to detect such cycles.

4. **Forgetting to define content within the `<pattern>`:** A `<pattern>` element with no child elements will result in a transparent or empty fill.

5. **Applying transformations incorrectly:** Applying `patternTransform` can be confusing if the user doesn't understand how transformations accumulate.

**User Operation Steps to Reach This Code (Debugging Context):**

Let's say a web developer is creating an SVG with a pattern that isn't rendering correctly. Here's how they might end up investigating the `SVGPatternElement.cc` file:

1. **Create an SVG with a `<pattern>` element in their HTML.**

2. **Observe the incorrect rendering in the browser.**  The pattern might be missing, distorted, or not tiling as expected.

3. **Open the browser's developer tools (e.g., Chrome DevTools).**

4. **Inspect the relevant SVG element that uses the pattern (e.g., a `<rect>`).** They'll see the `fill` property referencing the pattern.

5. **Inspect the `<pattern>` element itself.** They might look at its attributes and the content within it.

6. **If the issue is complex, they might suspect a bug in the browser's rendering engine.**

7. **If they are familiar with Chromium's architecture, or if a more experienced developer is helping, they might realize the issue could be related to how the `<pattern>` element is handled internally.**

8. **They might search the Chromium source code for files related to `<pattern>` or `SVGPatternElement`.** This would lead them to `blink/renderer/core/svg/svg_pattern_element.cc`.

9. **To debug further, they might:**
   - **Set breakpoints within `SVGPatternElement.cc`:** Using a debugger, they could set breakpoints in methods like `SvgAttributeChanged`, `CollectPatternAttributes`, or `CreateLayoutObject` to step through the code and see how the pattern's attributes are being processed.
   - **Examine the values of member variables:** They could inspect the values of attributes like `x_`, `y_`, `width_`, `height_`, `pattern_units_`, etc., to see if they are being set correctly.
   - **Trace the execution flow:** They could follow the call stack to understand how the rendering engine arrives at the `SVGPatternElement` code.
   - **Look at the creation of the `LayoutSVGResourcePattern` object:** They could investigate if the layout object is being created with the correct parameters.

By examining the code in `SVGPatternElement.cc`, developers can gain a deeper understanding of how the browser interprets and renders SVG patterns, helping them diagnose and fix rendering issues. The comments and structure of the code itself are valuable debugging aids.

### 提示词
```
这是目录为blink/renderer/core/svg/svg_pattern_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2004, 2005, 2006, 2007, 2008 Nikolas Zimmermann
 * <zimmermann@kde.org>
 * Copyright (C) 2004, 2005, 2006, 2007 Rob Buis <buis@kde.org>
 * Copyright (C) Research In Motion Limited 2010. All rights reserved.
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

#include "third_party/blink/renderer/core/svg/svg_pattern_element.h"

#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/id_target_observer.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_resource_pattern.h"
#include "third_party/blink/renderer/core/svg/pattern_attributes.h"
#include "third_party/blink/renderer/core/svg/svg_animated_length.h"
#include "third_party/blink/renderer/core/svg/svg_animated_preserve_aspect_ratio.h"
#include "third_party/blink/renderer/core/svg/svg_animated_rect.h"
#include "third_party/blink/renderer/core/svg/svg_animated_transform_list.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/transforms/affine_transform.h"

namespace blink {

SVGPatternElement::SVGPatternElement(Document& document)
    : SVGElement(svg_names::kPatternTag, document),
      SVGURIReference(this),
      SVGTests(this),
      SVGFitToViewBox(this),
      x_(MakeGarbageCollected<SVGAnimatedLength>(
          this,
          svg_names::kXAttr,
          SVGLengthMode::kWidth,
          SVGLength::Initial::kUnitlessZero)),
      y_(MakeGarbageCollected<SVGAnimatedLength>(
          this,
          svg_names::kYAttr,
          SVGLengthMode::kHeight,
          SVGLength::Initial::kUnitlessZero)),
      width_(MakeGarbageCollected<SVGAnimatedLength>(
          this,
          svg_names::kWidthAttr,
          SVGLengthMode::kWidth,
          SVGLength::Initial::kUnitlessZero)),
      height_(MakeGarbageCollected<SVGAnimatedLength>(
          this,
          svg_names::kHeightAttr,
          SVGLengthMode::kHeight,
          SVGLength::Initial::kUnitlessZero)),
      pattern_transform_(MakeGarbageCollected<SVGAnimatedTransformList>(
          this,
          svg_names::kPatternTransformAttr,
          CSSPropertyID::kTransform)),
      pattern_units_(MakeGarbageCollected<
                     SVGAnimatedEnumeration<SVGUnitTypes::SVGUnitType>>(
          this,
          svg_names::kPatternUnitsAttr,
          SVGUnitTypes::kSvgUnitTypeObjectboundingbox)),
      pattern_content_units_(MakeGarbageCollected<
                             SVGAnimatedEnumeration<SVGUnitTypes::SVGUnitType>>(
          this,
          svg_names::kPatternContentUnitsAttr,
          SVGUnitTypes::kSvgUnitTypeUserspaceonuse)) {}

void SVGPatternElement::Trace(Visitor* visitor) const {
  visitor->Trace(x_);
  visitor->Trace(y_);
  visitor->Trace(width_);
  visitor->Trace(height_);
  visitor->Trace(pattern_transform_);
  visitor->Trace(pattern_units_);
  visitor->Trace(pattern_content_units_);
  visitor->Trace(target_id_observer_);
  SVGElement::Trace(visitor);
  SVGURIReference::Trace(visitor);
  SVGTests::Trace(visitor);
  SVGFitToViewBox::Trace(visitor);
}

void SVGPatternElement::BuildPendingResource() {
  ClearResourceReferences();
  if (!isConnected())
    return;
  Element* target = ObserveTarget(target_id_observer_, *this);
  if (auto* pattern = DynamicTo<SVGPatternElement>(target))
    AddReferenceTo(pattern);

  InvalidatePattern();
}

void SVGPatternElement::ClearResourceReferences() {
  UnobserveTarget(target_id_observer_);
  RemoveAllOutgoingReferences();
}

void SVGPatternElement::SvgAttributeChanged(
    const SvgAttributeChangedParams& params) {
  const QualifiedName& attr_name = params.name;
  bool is_length_attr =
      attr_name == svg_names::kXAttr || attr_name == svg_names::kYAttr ||
      attr_name == svg_names::kWidthAttr || attr_name == svg_names::kHeightAttr;

  if (attr_name == svg_names::kPatternTransformAttr) {
    UpdatePresentationAttributeStyle(*pattern_transform_);
  }

  if (is_length_attr || attr_name == svg_names::kPatternUnitsAttr ||
      attr_name == svg_names::kPatternContentUnitsAttr ||
      attr_name == svg_names::kPatternTransformAttr ||
      SVGFitToViewBox::IsKnownAttribute(attr_name) ||
      SVGTests::IsKnownAttribute(attr_name)) {
    if (is_length_attr)
      UpdateRelativeLengthsInformation();

    InvalidatePattern();
    return;
  }

  if (SVGURIReference::IsKnownAttribute(attr_name)) {
    BuildPendingResource();
    return;
  }

  SVGElement::SvgAttributeChanged(params);
}

Node::InsertionNotificationRequest SVGPatternElement::InsertedInto(
    ContainerNode& root_parent) {
  SVGElement::InsertedInto(root_parent);
  if (root_parent.isConnected())
    BuildPendingResource();
  return kInsertionDone;
}

void SVGPatternElement::RemovedFrom(ContainerNode& root_parent) {
  SVGElement::RemovedFrom(root_parent);
  if (root_parent.isConnected())
    ClearResourceReferences();
}

void SVGPatternElement::ChildrenChanged(const ChildrenChange& change) {
  SVGElement::ChildrenChanged(change);

  if (!change.ByParser())
    InvalidatePattern();
}

void SVGPatternElement::InvalidatePattern() {
  if (auto* layout_object = To<LayoutSVGResourceContainer>(GetLayoutObject()))
    layout_object->InvalidateCache();
}

void SVGPatternElement::InvalidateDependentPatterns() {
  NotifyIncomingReferences([](SVGElement& element) {
    if (auto* pattern = DynamicTo<SVGPatternElement>(element)) {
      pattern->InvalidatePattern();
    }
  });
}

LayoutObject* SVGPatternElement::CreateLayoutObject(const ComputedStyle&) {
  return MakeGarbageCollected<LayoutSVGResourcePattern>(this);
}

static void SetPatternAttributes(const SVGPatternElement& element,
                                 PatternAttributes& attributes) {
  if (!attributes.HasX() && element.x()->IsSpecified())
    attributes.SetX(element.x()->CurrentValue());

  if (!attributes.HasY() && element.y()->IsSpecified())
    attributes.SetY(element.y()->CurrentValue());

  if (!attributes.HasWidth() && element.width()->IsSpecified())
    attributes.SetWidth(element.width()->CurrentValue());

  if (!attributes.HasHeight() && element.height()->IsSpecified())
    attributes.SetHeight(element.height()->CurrentValue());

  if (!attributes.HasViewBox() && element.HasValidViewBox())
    attributes.SetViewBox(element.viewBox()->CurrentValue()->Rect());

  if (!attributes.HasPreserveAspectRatio() &&
      element.preserveAspectRatio()->IsSpecified()) {
    attributes.SetPreserveAspectRatio(
        element.preserveAspectRatio()->CurrentValue());
  }

  if (!attributes.HasPatternUnits() && element.patternUnits()->IsSpecified()) {
    attributes.SetPatternUnits(element.patternUnits()->CurrentEnumValue());
  }

  if (!attributes.HasPatternContentUnits() &&
      element.patternContentUnits()->IsSpecified()) {
    attributes.SetPatternContentUnits(
        element.patternContentUnits()->CurrentEnumValue());
  }

  if (!attributes.HasPatternTransform() &&
      element.HasTransform(SVGElement::kExcludeMotionTransform)) {
    attributes.SetPatternTransform(
        element.CalculateTransform(SVGElement::kExcludeMotionTransform));
  }

  if (!attributes.HasPatternContentElement() &&
      ElementTraversal::FirstWithin(element))
    attributes.SetPatternContentElement(element);
}

const SVGPatternElement* SVGPatternElement::ReferencedElement() const {
  return DynamicTo<SVGPatternElement>(
      TargetElementFromIRIString(HrefString(), GetTreeScope()));
}

PatternAttributes SVGPatternElement::CollectPatternAttributes() const {
  HeapHashSet<Member<const SVGPatternElement>> processed_patterns;
  const SVGPatternElement* current = this;

  PatternAttributes attributes;
  while (true) {
    SetPatternAttributes(*current, attributes);
    processed_patterns.insert(current);

    // If (xlink:)href links to another SVGPatternElement, allow attributes
    // from that element to override values this pattern didn't set.
    current = current->ReferencedElement();

    // Ignore the referenced pattern element if it is not attached.
    if (!current || !current->GetLayoutObject())
      break;
    // Cycle detection.
    if (processed_patterns.Contains(current))
      break;
  }

  // Fill out any ("complex") empty fields with values from this element (where
  // these values should equal the initial values).
  if (!attributes.HasX()) {
    attributes.SetX(x()->CurrentValue());
  }
  if (!attributes.HasY()) {
    attributes.SetY(y()->CurrentValue());
  }
  if (!attributes.HasWidth()) {
    attributes.SetWidth(width()->CurrentValue());
  }
  if (!attributes.HasHeight()) {
    attributes.SetHeight(height()->CurrentValue());
  }
  if (!attributes.HasPreserveAspectRatio()) {
    attributes.SetPreserveAspectRatio(preserveAspectRatio()->CurrentValue());
  }
  DCHECK(attributes.X());
  DCHECK(attributes.Y());
  DCHECK(attributes.Width());
  DCHECK(attributes.Height());
  DCHECK(attributes.PreserveAspectRatio());
  return attributes;
}

AffineTransform SVGPatternElement::LocalCoordinateSpaceTransform(
    CTMScope) const {
  return CalculateTransform(SVGElement::kExcludeMotionTransform);
}

bool SVGPatternElement::SelfHasRelativeLengths() const {
  return x_->CurrentValue()->IsRelative() || y_->CurrentValue()->IsRelative() ||
         width_->CurrentValue()->IsRelative() ||
         height_->CurrentValue()->IsRelative();
}

SVGAnimatedPropertyBase* SVGPatternElement::PropertyFromAttribute(
    const QualifiedName& attribute_name) const {
  if (attribute_name == svg_names::kXAttr) {
    return x_.Get();
  } else if (attribute_name == svg_names::kYAttr) {
    return y_.Get();
  } else if (attribute_name == svg_names::kWidthAttr) {
    return width_.Get();
  } else if (attribute_name == svg_names::kHeightAttr) {
    return height_.Get();
  } else if (attribute_name == svg_names::kPatternTransformAttr) {
    return pattern_transform_.Get();
  } else if (attribute_name == svg_names::kPatternUnitsAttr) {
    return pattern_units_.Get();
  } else if (attribute_name == svg_names::kPatternContentUnitsAttr) {
    return pattern_content_units_.Get();
  } else {
    SVGAnimatedPropertyBase* ret;
    if (ret = SVGURIReference::PropertyFromAttribute(attribute_name); ret) {
      return ret;
    }
    if (ret = SVGFitToViewBox::PropertyFromAttribute(attribute_name); ret) {
      return ret;
    }
    if (ret = SVGTests::PropertyFromAttribute(attribute_name); ret) {
      return ret;
    }
    return SVGElement::PropertyFromAttribute(attribute_name);
  }
}

void SVGPatternElement::SynchronizeAllSVGAttributes() const {
  SVGAnimatedPropertyBase* attrs[]{x_.Get(),
                                   y_.Get(),
                                   width_.Get(),
                                   height_.Get(),
                                   pattern_transform_.Get(),
                                   pattern_units_.Get(),
                                   pattern_content_units_.Get()};
  SynchronizeListOfSVGAttributes(attrs);
  SVGURIReference::SynchronizeAllSVGAttributes();
  SVGTests::SynchronizeAllSVGAttributes();
  SVGFitToViewBox::SynchronizeAllSVGAttributes();
  SVGElement::SynchronizeAllSVGAttributes();
}

void SVGPatternElement::CollectExtraStyleForPresentationAttribute(
    MutableCSSPropertyValueSet* style) {
  AddAnimatedPropertyToPresentationAttributeStyle(*pattern_transform_, style);
  SVGElement::CollectExtraStyleForPresentationAttribute(style);
}

}  // namespace blink
```