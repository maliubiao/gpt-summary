Response:
Let's break down the thought process for analyzing this C++ code file.

**1. Initial Understanding of the Request:**

The request asks for a functional analysis of `viewport_description.cc`, including its relation to JavaScript/HTML/CSS, logical reasoning, potential errors, and debugging tips. The core task is to understand *what* this code does and *why* it matters in a browser context.

**2. High-Level Code Overview (Skimming):**

First, quickly scan the code to identify key elements:

* **Includes:**  Notice headers like `viewport_description.h`, `document.h`, `local_frame.h`, `settings.h`, `visual_viewport.h`, and `page.h`. This immediately suggests the file is deeply involved in the rendering pipeline, particularly concerning how the page's viewport is determined and managed.
* **Namespace:** The code is within the `blink` namespace, confirming it's part of the Blink rendering engine.
* **Constants:**  `kValueAuto` and `kValueExtendToZoom` are used, hinting at special values for viewport properties.
* **Functions:**  Identify the core functions: `ResolveViewportLength`, `Resolve`, and `ReportMobilePageStats`. These are likely the primary actions performed by this file.
* **Comments:** Pay attention to the copyright information and any descriptive comments (though this file doesn't have many detailed in-code comments explaining the *why*).
* **Histogram Macro:** The `UMA_HISTOGRAM_ENUMERATION` macro suggests this code collects usage statistics.

**3. Deeper Dive into Core Functions:**

* **`ResolveViewportLength`:**  The name suggests it converts various length units (pixels, percentages, `device-width`, `device-height`, `auto`, `extend-to-zoom`) into concrete pixel values based on the initial viewport size. The `Direction` enum indicates it handles both horizontal and vertical dimensions. *Key insight: This function is responsible for translating abstract viewport length specifications into actual pixel values.*
* **`Resolve`:** This is the most complex function. It takes the initial viewport size and a legacy fallback width as input and returns `PageScaleConstraints`. This return type strongly suggests this function calculates the final viewport settings like initial scale, minimum/maximum scale, and layout size. Notice the handling of `min-width`, `max-width`, `min-height`, `max-height`, `zoom`, `min-zoom`, `max-zoom`, and `user-zoom`. The logic involves resolving conflicts and constraints between these values. The "legacy viewport type" handling is important. *Key insight: This function is the core logic for determining the final viewport configuration based on various inputs, including meta tags.*
* **`ReportMobilePageStats`:** This function seems to collect metrics about the type of viewport configuration used on a page. It checks if a viewport meta tag is present, its type, and records this information using the `UMA_HISTOGRAM_ENUMERATION` macro. *Key insight: This function is for telemetry, helping understand how developers are configuring viewports.*

**4. Connecting to JavaScript/HTML/CSS:**

* **HTML:** The viewport meta tag (`<meta name="viewport" ...>`) is the primary link. The attributes within this tag (`width`, `initial-scale`, `minimum-scale`, `maximum-scale`, `user-scalable`) directly correspond to the parameters being processed in the C++ code.
* **CSS:** While not directly parsing CSS, the resulting viewport dimensions and scaling impact how CSS layouts are rendered. Media queries, which rely on viewport dimensions, are affected by the calculations performed here.
* **JavaScript:** JavaScript can interact with the viewport through properties like `window.innerWidth`, `window.innerHeight`, `document.documentElement.clientWidth`, etc. The C++ code sets the foundation for these values. JavaScript can also programmatically modify viewport properties (though typically through setting meta tags).

**5. Logical Reasoning and Examples:**

Think about scenarios and how the code would behave:

* **Scenario: `width=device-width`:** `ResolveViewportLength` would return `initial_viewport_size.width()`. `Resolve` would likely use this value to set the layout width.
* **Scenario: `initial-scale=2.0`:** `Resolve` would set `result.initial_scale` to 2.0.
* **Scenario: Conflicting values (e.g., `width=500`, `max-width=300`):**  The `CompareIgnoringAuto` function and the `std::min`/`std::max` usage in `Resolve` would ensure constraints are respected.

**6. Identifying Potential Errors:**

Focus on common developer mistakes:

* **Conflicting viewport settings:**  Setting contradictory values in the meta tag can lead to unexpected behavior, and the code attempts to resolve these conflicts.
* **Incorrect unit usage:** Using incorrect units or mixing units improperly in viewport properties.
* **Misunderstanding `device-width` and `width` in pixels:**  Developers might not understand the difference and how they interact.

**7. Debugging Clues and User Operations:**

Trace back how a user's actions lead to this code being executed:

1. **User enters a URL or clicks a link.**
2. **The browser's network stack fetches the HTML.**
3. **The HTML parser encounters the `<meta name="viewport" ...>` tag.**
4. **Blink's HTML parser extracts the attributes and their values.**
5. **This information is used to create a `ViewportDescription` object.**
6. **The `Resolve` function in `viewport_description.cc` is called to calculate the final viewport constraints.**
7. **These constraints are then used by the layout engine to render the page.**

**8. Structure and Refinement:**

Organize the findings into clear categories as requested by the prompt. Use headings and bullet points for readability. Ensure examples are concrete and illustrate the points being made.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file *directly* renders the viewport.
* **Correction:**  Realize it *calculates* the viewport properties that are *then* used by other rendering components.
* **Initial thought:** Focus heavily on the `ReportMobilePageStats`.
* **Correction:** Recognize that `Resolve` is the core functional unit and spend more time analyzing it.
* **Initial thought:**  Overcomplicate the explanations.
* **Correction:**  Simplify the language and provide clear, concise explanations.

By following this structured approach, moving from a high-level understanding to detailed analysis, and considering the context of the browser rendering pipeline, a comprehensive and accurate response can be generated.
好的，我们来详细分析一下 `blink/renderer/core/page/viewport_description.cc` 这个 Chromium Blink 引擎的源代码文件。

**文件功能概述**

`viewport_description.cc` 文件的核心功能是**解析和处理 HTML 文档中指定的视口（Viewport）元数据（Meta Data）**，并将其转化为浏览器渲染引擎可以理解和使用的视口约束条件。简单来说，它负责理解开发者通过 `<meta name="viewport" ...>` 标签表达的意图，例如页面的初始缩放比例、最小/最大缩放比例、宽度和高度等，并将其转化为实际的数值。

**与 Javascript, HTML, CSS 的关系及举例说明**

这个文件直接关联 HTML 的 `<meta name="viewport">` 标签，并间接地影响 JavaScript 和 CSS 的行为：

* **HTML (直接关联):**
    * **功能:**  `viewport_description.cc` 的主要输入来源就是 HTML 文档中的 `<meta name="viewport" content="...">` 标签。它会解析 `content` 属性中的各种键值对，例如 `width=device-width`, `initial-scale=1.0`, `maximum-scale=5.0` 等。
    * **举例:**
        ```html
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Viewport Example</title>
        </head>
        <body>
            <p>This page uses a viewport meta tag.</p>
        </body>
        </html>
        ```
        当浏览器解析到这个 `<meta>` 标签时，`viewport_description.cc` 中的代码会被调用，解析 `content` 属性，提取出 `width` 和 `initial-scale` 的值。

* **JavaScript (间接影响):**
    * **功能:**  通过 `viewport_description.cc` 计算出的视口约束会影响 JavaScript 中关于页面尺寸和缩放的 API，例如 `window.innerWidth`, `window.innerHeight`, `window.devicePixelRatio` 等。
    * **举例:**  如果 HTML 中设置了 `<meta name="viewport" content="width=500">`，那么 `viewport_description.cc` 会将视口宽度解析为 500 像素。这会导致 `window.innerWidth` 在初始加载时返回接近 500 的值（可能会因为滚动条等因素略有偏差）。如果用户进行了缩放，`window.innerWidth` 的值会随之变化，但其初始状态是由视口元数据决定的。

* **CSS (间接影响):**
    * **功能:** 视口的宽度和缩放比例直接影响 CSS 布局的计算和渲染。例如，使用 `vw` 和 `vh` 单位时，其值取决于视口的尺寸。媒体查询（Media Queries）也依赖于视口的宽度、高度和设备像素比等信息，而这些信息的初始值受到视口元数据的影响。
    * **举例:**
        ```html
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="viewport" content="width=device-width">
            <title>CSS Viewport Example</title>
            <style>
                body {
                    background-color: lightblue;
                }
                @media (max-width: 600px) {
                    body {
                        background-color: lightgreen;
                    }
                }
            </style>
        </head>
        <body>
            <p>This page uses a viewport meta tag and CSS media queries.</p>
        </body>
        </html>
        ```
        如果设备的屏幕宽度小于 600 像素，并且 HTML 中设置了 `width=device-width`，那么 `viewport_description.cc` 会将视口宽度设置为设备宽度，从而触发 CSS 媒体查询，将背景颜色设置为浅绿色。

**逻辑推理 (假设输入与输出)**

假设 HTML 中有以下视口元数据：

**假设输入:** `<meta name="viewport" content="width=device-width, initial-scale=0.5, maximum-scale=2.0, user-scalable=no">`

**逻辑推理过程 (部分):**

1. **解析 `width`:** `width=device-width` 会被 `ResolveViewportLength` 函数解析，根据设备的实际宽度返回一个像素值（假设设备宽度为 1080px，则返回 1080）。
2. **解析 `initial-scale`:** `initial-scale=0.5` 会被解析为初始缩放比例 0.5。
3. **解析 `maximum-scale`:** `maximum-scale=2.0` 会被解析为最大缩放比例 2.0。
4. **解析 `user-scalable`:** `user-scalable=no` 会被解析为不允许用户手动缩放。
5. **`Resolve` 函数计算:**  `Resolve` 函数会综合这些解析出的值，并结合初始视口大小等信息，计算出最终的 `PageScaleConstraints` 对象。

**假设输出 (部分 PageScaleConstraints 的成员):**

* `initial_scale`: 0.5
* `maximum_scale`: 2.0
* `minimum_scale`: 0.5  (因为 `user-scalable=no`，最小缩放会被锁定为初始缩放)
* `layout_size.width()`: 1080 (假设设备宽度)
* `user_zoom`: false

**用户或编程常见的使用错误及举例说明**

1. **设置冲突的视口属性:**
    * **错误示例:** `<meta name="viewport" content="width=500, initial-scale=1.0, width=device-width">`
    * **说明:**  这里 `width` 属性被设置了两次，浏览器需要决定哪个值生效，不同的浏览器可能处理方式不同，导致不一致的行为。

2. **错误理解 `width` 属性的值:**
    * **错误示例:** `<meta name="viewport" content="width=320">` 在高分辨率设备上可能导致页面初始时看起来非常小，因为视口被限制为 320 像素。开发者可能期望的是逻辑像素而不是设备像素。
    * **正确做法:** 通常使用 `width=device-width` 来适应不同设备的屏幕宽度。

3. **忘记设置必要的视口属性:**
    * **错误示例:**  只设置了 `width`，而没有设置 `initial-scale`。
    * **说明:** 在移动设备上，如果没有设置 `initial-scale`，浏览器可能会使用其默认的缩放比例，导致页面看起来不符合预期。建议同时设置 `width=device-width` 和 `initial-scale=1.0`。

4. **过度限制用户缩放:**
    * **错误示例:** `<meta name="viewport" content="maximum-scale=1.0, user-scalable=no">`
    * **说明:**  完全禁用用户缩放会降低可访问性，对于有视觉障碍的用户来说非常不友好。除非有非常特殊的需求，否则应该允许用户进行一定程度的缩放。

**用户操作如何一步步到达这里 (作为调试线索)**

当你调试一个与页面视口相关的 bug 时，可以按照以下步骤思考用户操作如何触发 `viewport_description.cc` 中的代码：

1. **用户在浏览器中打开一个网页。**
2. **浏览器开始解析 HTML 文档。**
3. **HTML 解析器遇到 `<meta name="viewport" ...>` 标签。**
4. **Blink 渲染引擎的 HTML 解析器（位于 `blink/renderer/core/html` 目录下的一些文件）会识别出这是一个视口元数据标签。**
5. **解析器会将 `content` 属性的值传递给专门处理视口元数据的模块，其中就包括 `viewport_description.cc` 中的代码。**
6. **`viewport_description.cc` 中的函数（例如 `Resolve`）会被调用，解析 `content` 属性中的键值对，并计算出最终的视口约束。**
7. **计算出的视口约束会被传递给布局引擎（Layout Engine），用于确定页面的初始布局和渲染。**
8. **如果用户随后进行了缩放操作，或者页面通过 JavaScript 修改了视口属性，可能会触发重新计算视口约束，但初始的视口设置是由 `viewport_description.cc` 决定的。**

**调试线索:**

* **检查 HTML 源代码:**  确保 `<meta name="viewport">` 标签存在，并且 `content` 属性的值是预期的。
* **使用开发者工具:**  在 Chrome 浏览器的开发者工具中，可以查看渲染的视口大小和设备像素比等信息，这可以帮助你验证 `viewport_description.cc` 的计算结果是否正确。
* **断点调试:**  如果你需要深入了解 `viewport_description.cc` 的内部运作，可以在相关的函数（例如 `Resolve`, `ResolveViewportLength`) 中设置断点，查看解析过程中的变量值。
* **搜索 Blink 源代码:**  如果你怀疑某个特定的视口属性解析有问题，可以搜索 Blink 源代码中对该属性的处理逻辑，找到 `viewport_description.cc` 中对应的代码段。

总而言之，`viewport_description.cc` 是 Blink 渲染引擎中一个至关重要的组件，它负责理解网页开发者对视口的配置，并将这些配置转化为浏览器可以执行的渲染指令，直接影响着网页在不同设备上的呈现效果和用户体验。理解其工作原理对于开发响应式网页和调试相关问题至关重要。

### 提示词
```
这是目录为blink/renderer/core/page/viewport_description.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2001 Dirk Mueller (mueller@kde.org)
 *           (C) 2006 Alexey Proskuryakov (ap@webkit.org)
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2011 Apple Inc. All rights
 * reserved.
 * Copyright (C) 2008 Torch Mobile Inc. All rights reserved.
 * (http://www.torchmobile.com/)
 * Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies)
 * Copyright (C) 2012-2013 Intel Corporation. All rights reserved.
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

#include "third_party/blink/renderer/core/page/viewport_description.h"

#include "base/metrics/histogram_macros.h"
#include "build/build_config.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"

namespace blink {

static const float& CompareIgnoringAuto(const float& value1,
                                        const float& value2,
                                        const float& (*compare)(const float&,
                                                                const float&)) {
  if (value1 == ViewportDescription::kValueAuto)
    return value2;

  if (value2 == ViewportDescription::kValueAuto)
    return value1;

  return compare(value1, value2);
}

static void RecordViewportTypeMetric(
    ViewportDescription::ViewportUMAType type) {
  UMA_HISTOGRAM_ENUMERATION("Viewport.MetaTagType", type);
}

float ViewportDescription::ResolveViewportLength(
    const Length& length,
    const gfx::SizeF& initial_viewport_size,
    Direction direction) {
  if (length.IsAuto())
    return ViewportDescription::kValueAuto;

  if (length.IsFixed())
    return length.GetFloatValue();

  if (length.IsExtendToZoom())
    return ViewportDescription::kValueExtendToZoom;

  if (length.IsPercent() && direction == Direction::kHorizontal)
    return initial_viewport_size.width() * length.GetFloatValue() / 100.0f;

  if (length.IsPercent() && direction == Direction::kVertical)
    return initial_viewport_size.height() * length.GetFloatValue() / 100.0f;

  if (length.IsDeviceWidth())
    return initial_viewport_size.width();

  if (length.IsDeviceHeight())
    return initial_viewport_size.height();

  NOTREACHED();
}

PageScaleConstraints ViewportDescription::Resolve(
    const gfx::SizeF& initial_viewport_size,
    const Length& legacy_fallback_width) const {
  float result_width = kValueAuto;

  Length copy_max_width = max_width;
  Length copy_min_width = min_width;
  // In case the width (used for min- and max-width) is undefined.
  if (IsLegacyViewportType() && max_width.IsAuto()) {
    // The width viewport META property is translated into 'width' descriptors,
    // setting the 'min' value to 'extend-to-zoom' and the 'max' value to the
    // intended length.  In case the UA-defines a min-width, use that as length.
    if (zoom == ViewportDescription::kValueAuto) {
      copy_min_width = Length::ExtendToZoom();
      copy_max_width = legacy_fallback_width;
    } else if (max_height.IsAuto()) {
      copy_min_width = Length::ExtendToZoom();
      copy_max_width = Length::ExtendToZoom();
    }
  }

  float result_max_width = ResolveViewportLength(
      copy_max_width, initial_viewport_size, Direction::kHorizontal);
  float result_min_width = ResolveViewportLength(
      copy_min_width, initial_viewport_size, Direction::kHorizontal);

  float result_height = kValueAuto;
  float result_max_height = ResolveViewportLength(
      max_height, initial_viewport_size, Direction::kVertical);
  float result_min_height = ResolveViewportLength(
      min_height, initial_viewport_size, Direction::kVertical);

  float result_zoom = zoom;
  float result_min_zoom = min_zoom;
  float result_max_zoom = max_zoom;
  bool result_user_zoom = user_zoom;

  // Resolve min-zoom and max-zoom values.
  if (result_min_zoom != ViewportDescription::kValueAuto &&
      result_max_zoom != ViewportDescription::kValueAuto)
    result_max_zoom = std::max(result_min_zoom, result_max_zoom);

  // Constrain zoom value to the [min-zoom, max-zoom] range.
  if (result_zoom != ViewportDescription::kValueAuto)
    result_zoom = CompareIgnoringAuto(
        result_min_zoom,
        CompareIgnoringAuto(result_max_zoom, result_zoom, std::min), std::max);

  float extend_zoom =
      CompareIgnoringAuto(result_zoom, result_max_zoom, std::min);

  // Resolve non-"auto" lengths to pixel lengths.
  if (extend_zoom == ViewportDescription::kValueAuto) {
    if (result_max_width == ViewportDescription::kValueExtendToZoom)
      result_max_width = ViewportDescription::kValueAuto;

    if (result_max_height == ViewportDescription::kValueExtendToZoom)
      result_max_height = ViewportDescription::kValueAuto;

    if (result_min_width == ViewportDescription::kValueExtendToZoom)
      result_min_width = result_max_width;

    if (result_min_height == ViewportDescription::kValueExtendToZoom)
      result_min_height = result_max_height;
  } else {
    float extend_width = initial_viewport_size.width() / extend_zoom;
    float extend_height = initial_viewport_size.height() / extend_zoom;

    if (result_max_width == ViewportDescription::kValueExtendToZoom)
      result_max_width = extend_width;

    if (result_max_height == ViewportDescription::kValueExtendToZoom)
      result_max_height = extend_height;

    if (result_min_width == ViewportDescription::kValueExtendToZoom)
      result_min_width =
          CompareIgnoringAuto(extend_width, result_max_width, std::max);

    if (result_min_height == ViewportDescription::kValueExtendToZoom)
      result_min_height =
          CompareIgnoringAuto(extend_height, result_max_height, std::max);
  }

  // Resolve initial width from min/max descriptors.
  if (result_min_width != ViewportDescription::kValueAuto ||
      result_max_width != ViewportDescription::kValueAuto)
    result_width = CompareIgnoringAuto(
        result_min_width,
        CompareIgnoringAuto(result_max_width, initial_viewport_size.width(),
                            std::min),
        std::max);

  // Resolve initial height from min/max descriptors.
  if (result_min_height != ViewportDescription::kValueAuto ||
      result_max_height != ViewportDescription::kValueAuto)
    result_height = CompareIgnoringAuto(
        result_min_height,
        CompareIgnoringAuto(result_max_height, initial_viewport_size.height(),
                            std::min),
        std::max);

  // Resolve width value.
  if (result_width == ViewportDescription::kValueAuto) {
    if (result_height == ViewportDescription::kValueAuto ||
        !initial_viewport_size.height()) {
      result_width = initial_viewport_size.width();
    } else {
      result_width = result_height * (initial_viewport_size.width() /
                                      initial_viewport_size.height());
    }
  }

  // Resolve height value.
  if (result_height == ViewportDescription::kValueAuto) {
    if (!initial_viewport_size.width()) {
      result_height = initial_viewport_size.height();
    } else {
      result_height = result_width * initial_viewport_size.height() /
                      initial_viewport_size.width();
    }
  }

  // Resolve initial-scale value.
  if (result_zoom == ViewportDescription::kValueAuto) {
    if (result_width != ViewportDescription::kValueAuto && result_width > 0)
      result_zoom = initial_viewport_size.width() / result_width;
    if (result_height != ViewportDescription::kValueAuto && result_height > 0) {
      // if 'auto', the initial-scale will be negative here and thus ignored.
      result_zoom = std::max<float>(
          result_zoom, initial_viewport_size.height() / result_height);
    }

    // Reconstrain zoom value to the [min-zoom, max-zoom] range.
    result_zoom = CompareIgnoringAuto(
        result_min_zoom,
        CompareIgnoringAuto(result_max_zoom, result_zoom, std::min), std::max);
  }

  // If user-scalable = no, lock the min/max scale to the computed initial
  // scale.
  if (!result_user_zoom)
    result_min_zoom = result_max_zoom = result_zoom;

  // Only set initialScale to a value if it was explicitly set.
  if (zoom == ViewportDescription::kValueAuto)
    result_zoom = ViewportDescription::kValueAuto;

  PageScaleConstraints result;
  result.minimum_scale = result_min_zoom;
  result.maximum_scale = result_max_zoom;
  result.initial_scale = result_zoom;
  result.layout_size.set_width(result_width);
  result.layout_size.set_height(result_height);
  return result;
}

void ViewportDescription::ReportMobilePageStats(
    const LocalFrame* main_frame) const {
  if (!main_frame || !main_frame->GetPage() || !main_frame->View() ||
      !main_frame->GetDocument())
    return;

  if (!main_frame->GetSettings() ||
      !main_frame->GetSettings()->GetViewportEnabled())
    return;

  // Avoid chrome:// pages like the new-tab page (on Android new tab is
  // non-http).
  if (!main_frame->GetDocument()->Url().ProtocolIsInHTTPFamily())
    return;

  if (!IsSpecifiedByAuthor()) {
    RecordViewportTypeMetric(main_frame->GetDocument()->IsMobileDocument()
                                 ? ViewportUMAType::kXhtmlMobileProfile
                                 : ViewportUMAType::kNoViewportTag);
    return;
  }

  if (IsMetaViewportType()) {
    if (max_width.IsFixed()) {
      RecordViewportTypeMetric(ViewportUMAType::kConstantWidth);
    } else if (max_width.IsDeviceWidth() || max_width.IsExtendToZoom()) {
      RecordViewportTypeMetric(ViewportUMAType::kDeviceWidth);
    } else {
      // Overflow bucket for cases we may be unaware of.
      RecordViewportTypeMetric(ViewportUMAType::kMetaWidthOther);
    }
  } else if (type == ViewportDescription::kHandheldFriendlyMeta) {
    RecordViewportTypeMetric(ViewportUMAType::kMetaHandheldFriendly);
  } else if (type == ViewportDescription::kMobileOptimizedMeta) {
    RecordViewportTypeMetric(ViewportUMAType::kMetaMobileOptimized);
  }
}

}  // namespace blink
```