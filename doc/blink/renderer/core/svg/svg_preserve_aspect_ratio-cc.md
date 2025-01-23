Response:
Let's break down the thought process for analyzing the `SVGPreserveAspectRatio.cc` file.

1. **Understand the Goal:** The request asks for a comprehensive analysis of the file, including its functionality, relationships with web technologies, logic examples, common errors, and debugging context.

2. **Initial Reading and Core Functionality Identification:**
   - Quickly read through the code, paying attention to class names, method names, and included headers.
   - The class name `SVGPreserveAspectRatio` immediately suggests it deals with the `preserveAspectRatio` attribute in SVG.
   - The methods like `ParseInternal`, `SetValueAsString`, `TransformRect`, and `ComputeTransform` confirm this. They indicate parsing the attribute's string value and applying transformations based on it.

3. **Deconstruct the Functionality (Method by Method):**

   - **Constructor and `SetDefault`:**  These initialize the object with default values (`xMidYMid meet`).
   - **`Clone`:** Creates a copy of the object. This is a standard pattern for objects that might be modified.
   - **`ParseInternal` (and its public wrappers `Parse` and `SetValueAsString`):** This is the core of parsing the `preserveAspectRatio` string.
     - Identify the grammar it's trying to parse: `none` or `<align> [<meetOrSlice>]`.
     - Notice the detailed logic for parsing the `<align>` part (e.g., "xMinYMin", "xMidYMax").
     - Observe the handling of `<meetOrSlice>` ("meet" or "slice").
     - Understand that parsing involves iterating through the string and setting the internal `align_` and `meet_or_slice_` members.
     - Recognize the error handling using `SVGParsingError`.
   - **`TransformRect`:** Modifies a destination rectangle (`dest_rect`) based on the `preserveAspectRatio` settings, considering a source rectangle (`src_rect`). This is about fitting the content within a given area. The logic involves comparing aspect ratios and adjusting dimensions and positions based on the `align` and `meetOrSlice` values.
   - **`ComputeTransform`:** Calculates an `AffineTransform` that can be applied to the SVG content. This is the more general form of `TransformRect`, producing a transformation matrix. It handles the "none" case separately and then applies different scaling and translation based on the `align` and `meetOrSlice` values.
   - **`ValueAsString`:**  Converts the internal state back into the string representation of the `preserveAspectRatio` attribute.
   - **`Add`, `CalculateAnimatedValue`, `CalculateDistance`:** These methods have `NOTREACHED()`, indicating that `preserveAspectRatio` doesn't directly support SMIL animation in the same way as other SVG properties.

4. **Relate to Web Technologies (HTML, CSS, JavaScript):**

   - **HTML:** The `preserveAspectRatio` attribute is directly used in SVG elements like `<svg>`, `<image>`, `<view>`, etc. Provide examples.
   - **CSS:** While you can't directly set `preserveAspectRatio` using CSS, CSS properties like `object-fit` and `object-position` on replaced elements (like `<img>` or `<video>`) provide similar functionality for HTML content, illustrating the broader concept. Mentioning CSS properties that *interact* with SVG (like styling SVG elements) is also relevant.
   - **JavaScript:** JavaScript can get and set the `preserveAspectRatio` attribute of SVG elements using the DOM API. Provide an example showing how to manipulate the attribute.

5. **Illustrate with Logic Examples (Input/Output):**

   - Choose a few representative `preserveAspectRatio` values and explain how `TransformRect` or `ComputeTransform` would behave with example input rectangles/viewports. Focus on showing how `align` and `meetOrSlice` affect the output.

6. **Identify Common User/Programming Errors:**

   - Focus on mistakes users might make when writing the `preserveAspectRatio` attribute in their SVG. This includes typos, invalid combinations, and misunderstanding the effects of `meet` vs. `slice`.
   - For programming errors, consider cases where developers might manipulate the attribute incorrectly via JavaScript or misunderstand how the transformations are applied.

7. **Provide Debugging Clues (User Operations):**

   - Think about how a user's actions in a browser could lead to this code being executed. This involves rendering SVG content on a webpage.
   - Describe the sequence of events: HTML parsing, encountering an SVG element with `preserveAspectRatio`, Blink rendering the SVG, and this code being called to calculate the necessary transformations. Mention DevTools as a way to inspect the attribute.

8. **Structure and Refine:** Organize the information logically with clear headings and explanations. Use bullet points and code examples to enhance readability. Ensure that the explanation of each point is concise and addresses the specific aspect of the request. For example, when explaining the function of `ParseInternal`, explicitly mention that it parses the string and sets internal state.

9. **Self-Critique and Review:**  Read through the entire response to ensure accuracy, clarity, and completeness. Did I address all parts of the prompt? Are my examples clear and correct? Is the language easy to understand?  For instance, initially, I might have focused too heavily on the code details. Reviewing the prompt reminds me to also emphasize the user and web technology connections.
This C++ source file, `svg_preserve_aspect_ratio.cc`, within the Chromium Blink rendering engine is responsible for **parsing, storing, and applying the `preserveAspectRatio` attribute of SVG elements.**

Here's a breakdown of its functionalities:

**Core Functionality:**

1. **Parsing the `preserveAspectRatio` Attribute:**
   - The primary function is to take a string value representing the `preserveAspectRatio` attribute (e.g., `"xMidYMid meet"`, `"none"`) and parse it into internal data structures.
   - It identifies two key components:
     - **`align`:**  Determines how the SVG's intrinsic aspect ratio is aligned within the viewport. Possible values include `none`, `xMinYMin`, `xMidYMin`, `xMaxYMin`, `xMinYMid`, `xMidYMid`, `xMaxYMid`, `xMinYMax`, `xMidYMax`, `xMaxYMax`.
     - **`meetOrSlice`:** Determines how the SVG's aspect ratio is fitted to the viewport. Possible values are `meet` (ensures the entire SVG is visible, potentially with empty space) and `slice` (fills the entire viewport, potentially clipping parts of the SVG).
   - The `ParseInternal` function handles the low-level parsing logic, iterating through the string and identifying the keywords. It supports both `LChar` and `UChar` string types.
   - `SetValueAsString` provides a public interface to set the `preserveAspectRatio` based on a `String`.

2. **Storing the Parsed Values:**
   - The `SVGPreserveAspectRatio` class has member variables (`align_` and `meet_or_slice_`) to store the parsed `align` and `meetOrSlice` values as enumerated types.

3. **Applying the `preserveAspectRatio` Transformation:**
   - The file provides two main functions for applying the `preserveAspectRatio`:
     - **`TransformRect`:** Takes a destination rectangle (`dest_rect`) representing the viewport and a source rectangle (`src_rect`) representing the SVG's intrinsic bounds. It modifies the `dest_rect` to reflect how the SVG content should be positioned and scaled within the viewport according to the `preserveAspectRatio` settings.
     - **`ComputeTransform`:** Calculates an `AffineTransform` matrix that represents the transformation needed to map the SVG's coordinate system to the viewport according to the `preserveAspectRatio` settings. This transform can then be applied to the SVG content during rendering.

4. **Providing a String Representation:**
   - The `ValueAsString` function converts the internal `align_` and `meet_or_slice_` values back into a string representation of the `preserveAspectRatio` attribute.

**Relationship with JavaScript, HTML, and CSS:**

* **HTML:** The `preserveAspectRatio` attribute is directly used within SVG elements in HTML. For example:

   ```html
   <svg width="200" height="100" viewBox="0 0 100 50" preserveAspectRatio="xMinYMin meet">
     <rect width="100" height="50" fill="red" />
   </svg>
   ```

   In this example, `preserveAspectRatio="xMinYMin meet"` tells the browser to:
   - Align the minimum X of the SVG's viewBox with the minimum X of the viewport.
   - Align the minimum Y of the SVG's viewBox with the minimum Y of the viewport.
   - Scale the SVG uniformly so that the entire viewBox is visible within the viewport (using `meet`).

* **JavaScript:** JavaScript can access and manipulate the `preserveAspectRatio` attribute of SVG elements through the DOM API.

   ```javascript
   const svgElement = document.querySelector('svg');
   console.log(svgElement.preserveAspectRatio.baseVal.valueAsString); // Get the current value

   svgElement.setAttribute('preserveAspectRatio', 'xMaxYMax slice'); // Set a new value
   ```

   When JavaScript sets the attribute, the parsing logic in `svg_preserve_aspect_ratio.cc` is invoked to interpret the new value.

* **CSS:** While CSS doesn't directly define the `preserveAspectRatio` attribute, CSS properties like `object-fit` and `object-position` on replaced elements (like `<img>` or `<video>`) provide similar functionality for HTML content. There isn't a direct CSS equivalent for SVG's `preserveAspectRatio`. However, CSS transformations can be used in conjunction with SVG to achieve similar visual effects, though the underlying mechanism is different.

**Logical Reasoning with Assumptions (Input/Output):**

**Assumption:** We have an SVG element with `viewBox="0 0 100 50"` (intrinsic width 100, height 50) and a viewport of width 200 and height 100.

**Example 1:**

* **Input `preserveAspectRatio` String:** `"xMidYMid meet"`
* **Parsing Logic:** `ParseInternal` would parse this into `align_ = kSvgPreserveaspectratioXmidymid` and `meet_or_slice_ = kSvgMeetorsliceMeet`.
* **`TransformRect` Logic (Conceptual):** The function would calculate that the SVG's aspect ratio (100/50 = 2) is different from the viewport's aspect ratio (200/100 = 2). Since they are equal, no scaling is strictly needed to fit while preserving aspect ratio. However, the alignment needs to be applied. The center of the SVG's viewBox will be aligned with the center of the viewport.
* **Conceptual Output of `TransformRect` (Modification of `dest_rect`):** The `dest_rect` might remain largely unchanged in terms of size, but its position might be adjusted to center the content.
* **Conceptual Output of `ComputeTransform`:** An `AffineTransform` matrix would be generated that essentially scales by 1 and translates to center the SVG within the viewport.

**Example 2:**

* **Input `preserveAspectRatio` String:** `"xMinYMin slice"`
* **Parsing Logic:** `ParseInternal` would parse this into `align_ = kSvgPreserveaspectratioXminymin` and `meet_or_slice_ = kSvgMeetorsliceSlice`.
* **`TransformRect` Logic (Conceptual):** The function would determine that the viewport is wider than the SVG's aspect ratio would dictate if we tried to fit the whole thing. With `slice`, the SVG will be scaled to fill the entire viewport, potentially clipping the right and bottom edges. The top-left corner of the SVG's viewBox will be aligned with the top-left corner of the viewport.
* **Conceptual Output of `TransformRect` (Modification of `src_rect`):** The `src_rect` (representing the portion of the SVG to render) would be adjusted. Its width might remain 100, but its height would be scaled up, and its `y` coordinate might become negative to represent the clipped portion.
* **Conceptual Output of `ComputeTransform`:** An `AffineTransform` matrix would be generated that scales the SVG up to fill the viewport and translates it so the top-left corners align.

**User or Programming Common Usage Errors:**

1. **Typographical Errors in the Attribute Value:**
   - **Example:** `preserveAspectRatio="xMinYMin  mett"` (misspelling "meet").
   - **Outcome:** The parsing logic in `ParseInternal` would likely fail or result in default values being used. The SVG might not render as expected.

2. **Using Invalid Combinations:**
   - **Example:** `preserveAspectRatio="none meet"` (using "meet" or "slice" with "none" is redundant and usually ignored).
   - **Outcome:** The parser might handle this gracefully by ignoring the redundant part, or it might be considered an error depending on strictness.

3. **Misunderstanding `meet` vs. `slice`:**
   - **User Scenario:** A user wants the entire SVG to be visible without any cropping but uses `slice`.
   - **Outcome:** The SVG will be scaled to fill the viewport, potentially cropping parts of the image.

4. **Incorrectly Manipulating the Attribute with JavaScript:**
   - **Example:** Setting the attribute to an empty string (`svgElement.setAttribute('preserveAspectRatio', '');`).
   - **Outcome:** The parsing logic might handle an empty string by setting default values, but it could lead to unexpected rendering behavior if the developer intended a different outcome.

5. **Not Understanding the `viewBox` Attribute's Importance:**
   - The `preserveAspectRatio` attribute works in conjunction with the `viewBox` attribute. If `viewBox` is not defined or is incorrectly defined, `preserveAspectRatio` might not have the intended effect.

**User Operation Steps to Reach This Code (Debugging Clues):**

1. **User Creates or Loads an HTML Page:** The user navigates to a webpage in Chromium that contains an SVG element.
2. **SVG Element with `preserveAspectRatio` is Encountered:** The HTML parser encounters an SVG element with the `preserveAspectRatio` attribute set.
3. **Blink's Rendering Engine Processes the SVG:** The Blink rendering engine starts processing the SVG element to determine how to render it.
4. **`SVGPreserveAspectRatio::SetValueAsString` is Called:**  When the rendering engine processes the `preserveAspectRatio` attribute, it will likely call `SetValueAsString` (or a similar entry point) in this `svg_preserve_aspect_ratio.cc` file, passing the attribute's string value.
5. **Parsing Occurs:** The `ParseInternal` function is invoked to parse the string value into the internal `align_` and `meet_or_slice_` members.
6. **Layout and Transformation Calculation:** During the layout phase, when the browser needs to determine the size and position of the SVG content within its container, the `TransformRect` or `ComputeTransform` function will be called.
   - `TransformRect` might be used in simpler layout scenarios.
   - `ComputeTransform` is used when a transformation matrix needs to be applied, which is common in more complex rendering pipelines.
7. **Rendering:** Finally, the calculated transformation (from `ComputeTransform`) or the adjusted rectangle (from `TransformRect`) is used to render the SVG content on the screen.

**As a debugger, you might:**

- Set breakpoints within `ParseInternal` to inspect the parsing process and see how the string value is being interpreted.
- Set breakpoints in `TransformRect` or `ComputeTransform` to understand how the transformations are being calculated based on the parsed `align_` and `meet_or_slice_` values.
- Use Chromium's DevTools to inspect the computed styles of the SVG element and see the effect of the `preserveAspectRatio` attribute.
- Examine the `viewBox` attribute to ensure it's correctly defined, as it's crucial for `preserveAspectRatio` to work as expected.

This file plays a vital role in ensuring that SVG content is rendered correctly and predictably across different viewport sizes while maintaining its intended aspect ratio, as specified by the author.

### 提示词
```
这是目录为blink/renderer/core/svg/svg_preserve_aspect_ratio.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2004, 2005, 2008 Nikolas Zimmermann <zimmermann@kde.org>
 * Copyright (C) 2004, 2005, 2006, 2007 Rob Buis <buis@kde.org>
 * Copyright (C) 2010 Dirk Schulze <krit@webkit.org>
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

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/svg/svg_preserve_aspect_ratio.h"

#include "base/notreached.h"
#include "third_party/blink/renderer/core/svg/svg_parser_utilities.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/transforms/affine_transform.h"
#include "third_party/blink/renderer/platform/wtf/text/character_visitor.h"
#include "third_party/blink/renderer/platform/wtf/text/parsing_utilities.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "ui/gfx/geometry/rect_f.h"

namespace blink {

SVGPreserveAspectRatio::SVGPreserveAspectRatio() {
  SetDefault();
}

void SVGPreserveAspectRatio::SetDefault() {
  align_ = kSvgPreserveaspectratioXmidymid;
  meet_or_slice_ = kSvgMeetorsliceMeet;
}

SVGPreserveAspectRatio* SVGPreserveAspectRatio::Clone() const {
  auto* preserve_aspect_ratio = MakeGarbageCollected<SVGPreserveAspectRatio>();

  preserve_aspect_ratio->align_ = align_;
  preserve_aspect_ratio->meet_or_slice_ = meet_or_slice_;

  return preserve_aspect_ratio;
}

template <typename CharType>
SVGParsingError SVGPreserveAspectRatio::ParseInternal(const CharType*& ptr,
                                                      const CharType* end,
                                                      bool validate) {
  SVGPreserveAspectRatioType align = kSvgPreserveaspectratioXmidymid;
  SVGMeetOrSliceType meet_or_slice = kSvgMeetorsliceMeet;

  SetAlign(align);
  SetMeetOrSlice(meet_or_slice);

  const CharType* start = ptr;
  if (!SkipOptionalSVGSpaces(ptr, end))
    return SVGParsingError(SVGParseStatus::kExpectedEnumeration, ptr - start);

  if (*ptr == 'n') {
    if (!SkipToken(ptr, end, "none"))
      return SVGParsingError(SVGParseStatus::kExpectedEnumeration, ptr - start);
    align = kSvgPreserveaspectratioNone;
    SkipOptionalSVGSpaces(ptr, end);
  } else if (*ptr == 'x') {
    if ((end - ptr) < 8)
      return SVGParsingError(SVGParseStatus::kExpectedEnumeration, ptr - start);
    if (ptr[1] != 'M' || ptr[4] != 'Y' || ptr[5] != 'M')
      return SVGParsingError(SVGParseStatus::kExpectedEnumeration, ptr - start);
    if (ptr[2] == 'i') {
      if (ptr[3] == 'n') {
        if (ptr[6] == 'i') {
          if (ptr[7] == 'n')
            align = kSvgPreserveaspectratioXminymin;
          else if (ptr[7] == 'd')
            align = kSvgPreserveaspectratioXminymid;
          else
            return SVGParsingError(SVGParseStatus::kExpectedEnumeration,
                                   ptr - start);
        } else if (ptr[6] == 'a' && ptr[7] == 'x') {
          align = kSvgPreserveaspectratioXminymax;
        } else {
          return SVGParsingError(SVGParseStatus::kExpectedEnumeration,
                                 ptr - start);
        }
      } else if (ptr[3] == 'd') {
        if (ptr[6] == 'i') {
          if (ptr[7] == 'n')
            align = kSvgPreserveaspectratioXmidymin;
          else if (ptr[7] == 'd')
            align = kSvgPreserveaspectratioXmidymid;
          else
            return SVGParsingError(SVGParseStatus::kExpectedEnumeration,
                                   ptr - start);
        } else if (ptr[6] == 'a' && ptr[7] == 'x') {
          align = kSvgPreserveaspectratioXmidymax;
        } else {
          return SVGParsingError(SVGParseStatus::kExpectedEnumeration,
                                 ptr - start);
        }
      } else {
        return SVGParsingError(SVGParseStatus::kExpectedEnumeration,
                               ptr - start);
      }
    } else if (ptr[2] == 'a' && ptr[3] == 'x') {
      if (ptr[6] == 'i') {
        if (ptr[7] == 'n')
          align = kSvgPreserveaspectratioXmaxymin;
        else if (ptr[7] == 'd')
          align = kSvgPreserveaspectratioXmaxymid;
        else
          return SVGParsingError(SVGParseStatus::kExpectedEnumeration,
                                 ptr - start);
      } else if (ptr[6] == 'a' && ptr[7] == 'x') {
        align = kSvgPreserveaspectratioXmaxymax;
      } else {
        return SVGParsingError(SVGParseStatus::kExpectedEnumeration,
                               ptr - start);
      }
    } else {
      return SVGParsingError(SVGParseStatus::kExpectedEnumeration, ptr - start);
    }
    ptr += 8;
    SkipOptionalSVGSpaces(ptr, end);
  } else {
    return SVGParsingError(SVGParseStatus::kExpectedEnumeration, ptr - start);
  }

  if (ptr < end) {
    if (*ptr == 'm') {
      if (!SkipToken(ptr, end, "meet"))
        return SVGParsingError(SVGParseStatus::kExpectedEnumeration,
                               ptr - start);
      SkipOptionalSVGSpaces(ptr, end);
    } else if (*ptr == 's') {
      if (!SkipToken(ptr, end, "slice"))
        return SVGParsingError(SVGParseStatus::kExpectedEnumeration,
                               ptr - start);
      SkipOptionalSVGSpaces(ptr, end);
      if (align != kSvgPreserveaspectratioNone)
        meet_or_slice = kSvgMeetorsliceSlice;
    }
  }

  if (end != ptr && validate)
    return SVGParsingError(SVGParseStatus::kTrailingGarbage, ptr - start);

  SetAlign(align);
  SetMeetOrSlice(meet_or_slice);

  return SVGParseStatus::kNoError;
}

SVGParsingError SVGPreserveAspectRatio::SetValueAsString(const String& string) {
  SetDefault();

  if (string.empty())
    return SVGParseStatus::kNoError;

  return WTF::VisitCharacters(string, [&](auto chars) {
    const auto* start = chars.data();
    return ParseInternal(start, start + chars.size(), true);
  });
}

bool SVGPreserveAspectRatio::Parse(const LChar*& ptr,
                                   const LChar* end,
                                   bool validate) {
  return ParseInternal(ptr, end, validate) == SVGParseStatus::kNoError;
}

bool SVGPreserveAspectRatio::Parse(const UChar*& ptr,
                                   const UChar* end,
                                   bool validate) {
  return ParseInternal(ptr, end, validate) == SVGParseStatus::kNoError;
}

void SVGPreserveAspectRatio::TransformRect(gfx::RectF& dest_rect,
                                           gfx::RectF& src_rect) const {
  if (align_ == kSvgPreserveaspectratioNone)
    return;

  gfx::SizeF image_size = src_rect.size();
  float orig_dest_width = dest_rect.width();
  float orig_dest_height = dest_rect.height();
  switch (meet_or_slice_) {
    case SVGPreserveAspectRatio::kSvgMeetorsliceUnknown:
      break;
    case SVGPreserveAspectRatio::kSvgMeetorsliceMeet: {
      float width_to_height_multiplier = src_rect.height() / src_rect.width();
      if (orig_dest_height > orig_dest_width * width_to_height_multiplier) {
        dest_rect.set_height(orig_dest_width * width_to_height_multiplier);
        switch (align_) {
          case SVGPreserveAspectRatio::kSvgPreserveaspectratioXminymid:
          case SVGPreserveAspectRatio::kSvgPreserveaspectratioXmidymid:
          case SVGPreserveAspectRatio::kSvgPreserveaspectratioXmaxymid:
            dest_rect.set_y(dest_rect.y() + orig_dest_height / 2 -
                            dest_rect.height() / 2);
            break;
          case SVGPreserveAspectRatio::kSvgPreserveaspectratioXminymax:
          case SVGPreserveAspectRatio::kSvgPreserveaspectratioXmidymax:
          case SVGPreserveAspectRatio::kSvgPreserveaspectratioXmaxymax:
            dest_rect.set_y(dest_rect.y() + orig_dest_height -
                            dest_rect.height());
            break;
          default:
            break;
        }
      }
      if (orig_dest_width > orig_dest_height / width_to_height_multiplier) {
        dest_rect.set_width(orig_dest_height / width_to_height_multiplier);
        switch (align_) {
          case SVGPreserveAspectRatio::kSvgPreserveaspectratioXmidymin:
          case SVGPreserveAspectRatio::kSvgPreserveaspectratioXmidymid:
          case SVGPreserveAspectRatio::kSvgPreserveaspectratioXmidymax:
            dest_rect.set_x(dest_rect.x() + orig_dest_width / 2 -
                            dest_rect.width() / 2);
            break;
          case SVGPreserveAspectRatio::kSvgPreserveaspectratioXmaxymin:
          case SVGPreserveAspectRatio::kSvgPreserveaspectratioXmaxymid:
          case SVGPreserveAspectRatio::kSvgPreserveaspectratioXmaxymax:
            dest_rect.set_x(dest_rect.x() + orig_dest_width -
                            dest_rect.width());
            break;
          default:
            break;
        }
      }
      break;
    }
    case SVGPreserveAspectRatio::kSvgMeetorsliceSlice: {
      float width_to_height_multiplier = src_rect.height() / src_rect.width();
      // If the destination height is less than the height of the image we'll be
      // drawing.
      if (orig_dest_height < orig_dest_width * width_to_height_multiplier) {
        float dest_to_src_multiplier = src_rect.width() / dest_rect.width();
        src_rect.set_height(dest_rect.height() * dest_to_src_multiplier);
        switch (align_) {
          case SVGPreserveAspectRatio::kSvgPreserveaspectratioXminymid:
          case SVGPreserveAspectRatio::kSvgPreserveaspectratioXmidymid:
          case SVGPreserveAspectRatio::kSvgPreserveaspectratioXmaxymid:
            src_rect.set_y(src_rect.y() + image_size.height() / 2 -
                           src_rect.height() / 2);
            break;
          case SVGPreserveAspectRatio::kSvgPreserveaspectratioXminymax:
          case SVGPreserveAspectRatio::kSvgPreserveaspectratioXmidymax:
          case SVGPreserveAspectRatio::kSvgPreserveaspectratioXmaxymax:
            src_rect.set_y(src_rect.y() + image_size.height() -
                           src_rect.height());
            break;
          default:
            break;
        }
      }
      // If the destination width is less than the width of the image we'll be
      // drawing.
      if (orig_dest_width < orig_dest_height / width_to_height_multiplier) {
        float dest_to_src_multiplier = src_rect.height() / dest_rect.height();
        src_rect.set_width(dest_rect.width() * dest_to_src_multiplier);
        switch (align_) {
          case SVGPreserveAspectRatio::kSvgPreserveaspectratioXmidymin:
          case SVGPreserveAspectRatio::kSvgPreserveaspectratioXmidymid:
          case SVGPreserveAspectRatio::kSvgPreserveaspectratioXmidymax:
            src_rect.set_x(src_rect.x() + image_size.width() / 2 -
                           src_rect.width() / 2);
            break;
          case SVGPreserveAspectRatio::kSvgPreserveaspectratioXmaxymin:
          case SVGPreserveAspectRatio::kSvgPreserveaspectratioXmaxymid:
          case SVGPreserveAspectRatio::kSvgPreserveaspectratioXmaxymax:
            src_rect.set_x(src_rect.x() + image_size.width() -
                           src_rect.width());
            break;
          default:
            break;
        }
      }
      break;
    }
  }
}

AffineTransform SVGPreserveAspectRatio::ComputeTransform(
    const gfx::RectF& view_box,
    const gfx::SizeF& viewport_size) const {
  DCHECK(!view_box.IsEmpty());
  DCHECK(!viewport_size.IsEmpty());
  DCHECK_NE(align_, kSvgPreserveaspectratioUnknown);

  double extended_logical_x = view_box.x();
  double extended_logical_y = view_box.y();
  double extended_logical_width = view_box.width();
  double extended_logical_height = view_box.height();
  double extended_physical_width = viewport_size.width();
  double extended_physical_height = viewport_size.height();

  AffineTransform transform;
  if (align_ == kSvgPreserveaspectratioNone) {
    transform.ScaleNonUniform(
        extended_physical_width / extended_logical_width,
        extended_physical_height / extended_logical_height);
    transform.Translate(-extended_logical_x, -extended_logical_y);
    return transform;
  }

  double logical_ratio = extended_logical_width / extended_logical_height;
  double physical_ratio = extended_physical_width / extended_physical_height;
  if ((logical_ratio < physical_ratio &&
       (meet_or_slice_ == kSvgMeetorsliceMeet)) ||
      (logical_ratio >= physical_ratio &&
       (meet_or_slice_ == kSvgMeetorsliceSlice))) {
    transform.ScaleNonUniform(
        extended_physical_height / extended_logical_height,
        extended_physical_height / extended_logical_height);

    if (align_ == kSvgPreserveaspectratioXminymin ||
        align_ == kSvgPreserveaspectratioXminymid ||
        align_ == kSvgPreserveaspectratioXminymax)
      transform.Translate(-extended_logical_x, -extended_logical_y);
    else if (align_ == kSvgPreserveaspectratioXmidymin ||
             align_ == kSvgPreserveaspectratioXmidymid ||
             align_ == kSvgPreserveaspectratioXmidymax)
      transform.Translate(-extended_logical_x - (extended_logical_width -
                                                 extended_physical_width *
                                                     extended_logical_height /
                                                     extended_physical_height) /
                                                    2,
                          -extended_logical_y);
    else
      transform.Translate(-extended_logical_x - (extended_logical_width -
                                                 extended_physical_width *
                                                     extended_logical_height /
                                                     extended_physical_height),
                          -extended_logical_y);

    return transform;
  }

  transform.ScaleNonUniform(extended_physical_width / extended_logical_width,
                            extended_physical_width / extended_logical_width);

  if (align_ == kSvgPreserveaspectratioXminymin ||
      align_ == kSvgPreserveaspectratioXmidymin ||
      align_ == kSvgPreserveaspectratioXmaxymin)
    transform.Translate(-extended_logical_x, -extended_logical_y);
  else if (align_ == kSvgPreserveaspectratioXminymid ||
           align_ == kSvgPreserveaspectratioXmidymid ||
           align_ == kSvgPreserveaspectratioXmaxymid)
    transform.Translate(-extended_logical_x,
                        -extended_logical_y -
                            (extended_logical_height -
                             extended_physical_height * extended_logical_width /
                                 extended_physical_width) /
                                2);
  else
    transform.Translate(-extended_logical_x,
                        -extended_logical_y -
                            (extended_logical_height -
                             extended_physical_height * extended_logical_width /
                                 extended_physical_width));

  return transform;
}

String SVGPreserveAspectRatio::ValueAsString() const {
  StringBuilder builder;

  const char* align_string = "";
  switch (align_) {
    case kSvgPreserveaspectratioNone:
      align_string = "none";
      break;
    case kSvgPreserveaspectratioXminymin:
      align_string = "xMinYMin";
      break;
    case kSvgPreserveaspectratioXmidymin:
      align_string = "xMidYMin";
      break;
    case kSvgPreserveaspectratioXmaxymin:
      align_string = "xMaxYMin";
      break;
    case kSvgPreserveaspectratioXminymid:
      align_string = "xMinYMid";
      break;
    case kSvgPreserveaspectratioXmidymid:
      align_string = "xMidYMid";
      break;
    case kSvgPreserveaspectratioXmaxymid:
      align_string = "xMaxYMid";
      break;
    case kSvgPreserveaspectratioXminymax:
      align_string = "xMinYMax";
      break;
    case kSvgPreserveaspectratioXmidymax:
      align_string = "xMidYMax";
      break;
    case kSvgPreserveaspectratioXmaxymax:
      align_string = "xMaxYMax";
      break;
    case kSvgPreserveaspectratioUnknown:
      align_string = "unknown";
      break;
  }
  builder.Append(align_string);

  const char* meet_or_slice_string = "";
  switch (meet_or_slice_) {
    default:
    case kSvgMeetorsliceUnknown:
      break;
    case kSvgMeetorsliceMeet:
      meet_or_slice_string = " meet";
      break;
    case kSvgMeetorsliceSlice:
      meet_or_slice_string = " slice";
      break;
  }
  builder.Append(meet_or_slice_string);
  return builder.ToString();
}

void SVGPreserveAspectRatio::Add(const SVGPropertyBase* other,
                                 const SVGElement*) {
  NOTREACHED();
}

void SVGPreserveAspectRatio::CalculateAnimatedValue(
    const SMILAnimationEffectParameters&,
    float percentage,
    unsigned repeat_count,
    const SVGPropertyBase* from_value,
    const SVGPropertyBase* to_value,
    const SVGPropertyBase*,
    const SVGElement*) {
  NOTREACHED();
}

float SVGPreserveAspectRatio::CalculateDistance(
    const SVGPropertyBase* to_value,
    const SVGElement* context_element) const {
  // No paced animations for SVGPreserveAspectRatio.
  return -1;
}

}  // namespace blink
```