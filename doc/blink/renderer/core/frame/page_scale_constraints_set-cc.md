Response:
Let's break down the thought process for analyzing this C++ file.

1. **Understand the Goal:** The request asks for the functionality of `PageScaleConstraintsSet.cc`, its relation to web technologies (JavaScript, HTML, CSS), logical reasoning, and common errors.

2. **Initial Skim and Keyword Identification:**  Quickly read through the code, looking for keywords and class names that hint at its purpose. "PageScaleConstraints," "viewport," "zoom," "initial scale," "minimum scale," "maximum scale," "layout size," "user agent," "fullscreen,"  "settings," "content size," and  "containing block size" are all strong indicators. The file path `blink/renderer/core/frame/` also points towards core browser rendering functionality.

3. **Identify the Core Data Structure:** The class `PageScaleConstraintsSet` is central. It holds various `PageScaleConstraints` objects (`default_constraints_`, `page_defined_constraints_`, `user_agent_constraints_`, `fullscreen_constraints_`). This immediately suggests its role is to manage and combine different sources of constraints on page scaling.

4. **Analyze the Methods:**  Go through each method and understand its individual purpose:
    * **Constructor:** Initializes with default constraints and a pointer to the `Page`.
    * **`SetDefaultConstraints`, `SetPageDefinedConstraints`, `SetUserAgentConstraints`, `SetFullscreenConstraints`:**  These clearly set the different sources of constraints. The `constraints_dirty_ = true;` in each of these is a key detail – it signals that the combined constraints need recalculation.
    * **`ComputeConstraintsStack`:** This method combines the individual constraint sets, applying overrides in a specific order (default, page-defined, user-agent, fullscreen). This defines the *priority* of different constraint sources.
    * **`ComputeFinalConstraints`:** Calls `ComputeConstraintsStack` and then `AdjustFinalConstraintsToContentsSize`. This indicates a two-stage process: first combine the raw constraints, then adjust based on content.
    * **`AdjustFinalConstraintsToContentsSize`:**  Deals with the `shrink-to-fit` setting and resolves "auto" initial scale. This links to CSS viewport meta tags.
    * **`SetNeedsReset`:** Flags that a reset of the page scale is needed.
    * **`DidChangeContentsSize`:**  Reacts to changes in the document's content size, potentially triggering a reset based on initial scale and `shrink-to-fit`.
    * **`DidChangeInitialContainingBlockSize`:**  Handles changes to the viewport size.
    * **`GetLayoutSize`:** Returns the calculated layout size based on the final constraints.
    * **`AdjustForAndroidWebViewQuirks`:** This is a more complex method dealing with Android-specific viewport behaviors and compatibility. Keywords like "target-densitydpi," "wide viewport," and "overview mode" are strong clues.

5. **Connect to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:** The `<meta name="viewport">` tag is the primary way HTML defines page scaling constraints. The methods dealing with `ViewportDescription` directly relate to parsing and processing this tag.
    * **CSS:** The `shrink-to-fit` setting (mentioned in `AdjustFinalConstraintsToContentsSize`) is a CSS concept. The calculated layout size influences how CSS layout is performed.
    * **JavaScript:** While this C++ code doesn't directly execute JavaScript, JavaScript can *indirectly* influence these constraints. For example, JavaScript can dynamically modify the viewport meta tag or trigger reflows that change content size, thus indirectly invoking methods in this class.

6. **Logical Reasoning (Hypothetical Inputs and Outputs):** Think about how the methods would behave with specific inputs. For example:
    * **Input:** A viewport meta tag with `initial-scale=2.0`, `minimum-scale=1.0`.
    * **Output:**  `page_defined_constraints_` would be populated with these values. `ComputeFinalConstraints` would likely result in `final_constraints_.initial_scale` being 2.0, and `final_constraints_.minimum_scale` being 1.0, unless overridden by user-agent or fullscreen settings.
    * **Input:** A large image is loaded, increasing `contents_size`. `page_scale_factor` is at its minimum. `initial_scale` is lower than the new minimum required.
    * **Output:** `DidChangeContentsSize` would detect this and potentially call `SetNeedsReset(true)`, triggering a recalculation of the page scale.

7. **Common Usage Errors:** Consider how developers might misuse the features that these constraints control:
    * **Conflicting viewport settings:** Setting `user-scalable=no` while also setting a very small `maximum-scale`.
    * **Ignoring device diversity:** Setting fixed viewport widths that don't adapt to different screen sizes.
    * **Misunderstanding `initial-scale`:**  Thinking it's a zoom level rather than a ratio between the device-independent pixels and the initial layout viewport.

8. **Structure the Answer:** Organize the findings into clear sections: Functionality, Relationship to Web Technologies, Logical Reasoning, and Common Errors. Use clear and concise language. Provide specific examples where possible.

9. **Review and Refine:** Read through the answer to ensure accuracy, clarity, and completeness. Check for any logical inconsistencies or areas that could be explained better. For instance, initially, I might have just said "handles viewport settings," but refining it to specifically mention the `<meta name="viewport">` tag makes the explanation much stronger. Similarly, clarifying the order of constraint overriding is crucial.

This detailed thought process allows for a comprehensive understanding of the code's purpose and its place within the larger web development ecosystem. The key is to dissect the code systematically, understand the individual components, and then connect them to the broader context of web standards and browser behavior.
这个文件 `page_scale_constraints_set.cc` 的主要功能是**管理和计算页面的缩放约束**。它负责维护一个由不同来源定义的缩放限制集合，并最终确定适用于当前页面的实际缩放约束。

以下是更详细的功能点：

**核心功能：**

1. **存储不同来源的缩放约束：**
   - **默认约束 (default_constraints_)：**  浏览器或引擎设置的默认缩放限制。
   - **页面定义约束 (page_defined_constraints_)：**  通过 HTML `<meta name="viewport">` 标签定义的约束。
   - **用户代理约束 (user_agent_constraints_)：**  浏览器自身基于用户设置或设备特性施加的约束。
   - **全屏约束 (fullscreen_constraints_)：**  当页面进入全屏模式时应用的约束。

2. **计算最终的缩放约束 (final_constraints_)：**
   - 通过 `ComputeConstraintsStack()` 方法，按照优先级顺序合并上述不同来源的约束。优先级顺序是：默认约束 < 页面定义约束 < 用户代理约束 < 全屏约束。这意味着后定义的约束会覆盖先定义的约束。
   - `ComputeFinalConstraints()` 方法会调用 `ComputeConstraintsStack()` 并进一步调用 `AdjustFinalConstraintsToContentsSize()` 来根据页面内容大小进行调整。

3. **根据内容大小调整最终约束：**
   - `AdjustFinalConstraintsToContentsSize()` 方法会考虑 `shrink-to-fit` 设置，如果启用，则会调整最大和最小缩放比例以适应内容宽度。
   - 它还会解析 `initial-scale=auto` 的情况，计算合适的初始缩放比例。

4. **响应页面状态变化：**
   - **`SetNeedsReset(bool needs_reset)`:**  标记是否需要重置页面缩放。
   - **`DidChangeContentsSize(gfx::Size contents_size, int vertical_scrollbar_width, float page_scale_factor)`:**  当页面内容大小发生变化时被调用，例如加载了新的图片或文本。它会根据内容变化和当前的缩放因子来判断是否需要重置缩放。
   - **`DidChangeInitialContainingBlockSize(const gfx::Size& size)`:** 当视口（initial containing block）大小变化时被调用。

5. **处理 Android WebView 特定的行为：**
   - **`AdjustForAndroidWebViewQuirks(...)`:**  包含一系列针对 Android WebView 的特殊处理逻辑，以兼容一些历史遗留问题和特定行为，例如 `target-densitydpi`、`wide viewport` 等。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个 C++ 文件直接负责解析和应用 HTML `<meta name="viewport">` 标签中定义的缩放约束，因此与 HTML 关系密切。它也间接地影响 CSS 的布局和渲染，因为缩放比例会影响元素的尺寸和位置。虽然它不直接执行 JavaScript 代码，但 JavaScript 可以通过修改 DOM (例如动态添加 `<meta>` 标签) 来间接影响这里的约束。

**HTML 举例：**

```html
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=2.0, user-scalable=no">
</head>
<body>
  <!-- 页面内容 -->
</body>
</html>
```

在这个例子中，`page_scale_constraints_set.cc` 会解析 `content` 属性中的值，并将它们应用于 `page_defined_constraints_`。

* `width=device-width` 会设置布局视口的宽度等于设备的宽度。
* `initial-scale=1.0` 会设置初始缩放比例为 1.0。
* `maximum-scale=2.0` 会设置最大缩放比例为 2.0。
* `user-scalable=no` 会禁用用户的缩放操作。

**CSS 举例：**

CSS 中的 `@viewport` 规则是另一种定义视口属性的方式，虽然在 Blink 中，`<meta name="viewport">` 更常见且优先级更高。  `AdjustFinalConstraintsToContentsSize()` 方法中提到的 `shrink-to-fit` 属性也与 CSS 有关，它影响是否将视口内容缩小以适应屏幕。

**JavaScript 举例：**

JavaScript 可以动态修改 `<meta name="viewport">` 标签的 `content` 属性，从而间接影响 `page_scale_constraints_set.cc` 的行为。

```javascript
// 获取 viewport meta 标签
const viewportMeta = document.querySelector('meta[name="viewport"]');

// 修改 initial-scale
viewportMeta.setAttribute('content', 'initial-scale=0.5');
```

这段 JavaScript 代码会修改页面的初始缩放比例，`page_scale_constraints_set.cc` 在后续的处理中会读取并应用这个新的值。

**逻辑推理（假设输入与输出）：**

**假设输入：**

1. **默认约束：** `minimum_scale=0.5`, `initial_scale=1.0`, `maximum_scale=3.0`
2. **页面定义约束 (来自 `<meta name="viewport">`)：** `minimum-scale=0.8`, `maximum-scale=2.0`
3. **用户代理约束：**  无
4. **全屏约束：**  无

**逻辑推理过程：**

`ComputeConstraintsStack()` 方法会按顺序应用约束：

1. 从 `default_constraints_` 开始：`minimum_scale=0.5`, `initial_scale=1.0`, `maximum_scale=3.0`
2. 应用 `page_defined_constraints_`，覆盖部分值：
   - `minimum_scale` 被覆盖为 `0.8`
   - `maximum_scale` 被覆盖为 `2.0`
   - `initial_scale` 保持 `1.0` (因为页面定义中没有明确设置)
3. `user_agent_constraints_` 和 `fullscreen_constraints_` 为空，不影响结果。

**预期输出 (ComputeConstraintsStack() 的结果)：**

`minimum_scale=0.8`, `initial_scale=1.0`, `maximum_scale=2.0`

**假设输入 (DidChangeContentsSize):**

1. `last_contents_width_ = 1000` 像素
2. 新的 `contents_size.width() = 1200` 像素
3. `page_scale_factor = FinalConstraints().minimum_scale` (假设当前缩放比例等于最小缩放比例)
4. `ComputeConstraintsStack().initial_scale = 0.5` (假设计算出的初始缩放比例小于当前最小缩放比例)

**逻辑推理过程：**

`DidChangeContentsSize` 方法会检查：

* `contents_size.width() > last_contents_width_` (1200 > 1000，成立)
* `page_scale_factor == FinalConstraints().minimum_scale` (成立)
* `ComputeConstraintsStack().initial_scale < FinalConstraints().minimum_scale` (0.5 < 当前最小缩放比例，假设成立)

**预期输出：**

`SetNeedsReset(true)` 会被调用，因为内容宽度增加，当前缩放比例为最小值，且理想的初始缩放比例更小，需要重置以适应新的内容。

**用户或编程常见的使用错误举例：**

1. **在 `<meta name="viewport">` 中设置冲突的属性：**
   ```html
   <meta name="viewport" content="width=500, initial-scale=1.0">
   ```
   这里同时设置了固定的宽度 `width=500` 和初始缩放 `initial-scale=1.0`，可能会导致在不同设备上显示效果不一致。建议使用 `width=device-width` 与 `initial-scale` 配合使用。

2. **误解 `user-scalable=no` 的影响：**
   ```html
   <meta name="viewport" content="user-scalable=no">
   ```
   禁用用户缩放可能会影响可访问性，特别是对于有视觉障碍的用户。应谨慎使用。

3. **过度依赖 `initial-scale` 而忽略了响应式设计：**
   ```html
   <meta name="viewport" content="initial-scale=0.5">
   ```
   虽然可以设置初始缩放，但更好的做法是结合 CSS 媒体查询等技术实现响应式布局，使页面能够适应不同屏幕尺寸，而不是依赖固定的初始缩放。

4. **在 JavaScript 中错误地修改 `viewport` 元数据：**
   ```javascript
   document.querySelector('meta[name="viewport"]').content = 'width=1000';
   ```
   直接覆盖 `content` 属性可能会意外删除或覆盖其他重要的视口设置。建议更精确地修改单个属性，或者使用 `setAttribute` 方法。

总之，`page_scale_constraints_set.cc` 是 Blink 引擎中负责管理和计算页面缩放约束的关键模块，它直接关系到开发者如何通过 HTML 和间接地通过 JavaScript 控制页面的缩放行为，并最终影响用户在不同设备上的浏览体验。理解其功能有助于开发者更好地控制页面的视口和缩放，避免常见的错误配置。

### 提示词
```
这是目录为blink/renderer/core/frame/page_scale_constraints_set.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/frame/page_scale_constraints_set.h"

#include <algorithm>
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/platform/geometry/length.h"
#include "ui/gfx/geometry/size_conversions.h"

namespace blink {

PageScaleConstraintsSet::PageScaleConstraintsSet(Page* page)
    : default_constraints_(-1, 1, 1),
      final_constraints_(ComputeConstraintsStack()),
      page_(page),
      last_contents_width_(0),
      last_vertical_scrollbar_width_(0),
      needs_reset_(false),
      constraints_dirty_(false) {}

void PageScaleConstraintsSet::Trace(Visitor* visitor) const {
  visitor->Trace(page_);
}

void PageScaleConstraintsSet::SetDefaultConstraints(
    const PageScaleConstraints& default_constraints) {
  default_constraints_ = default_constraints;
  constraints_dirty_ = true;
}

const PageScaleConstraints& PageScaleConstraintsSet::DefaultConstraints()
    const {
  return default_constraints_;
}

void PageScaleConstraintsSet::UpdatePageDefinedConstraints(
    const ViewportDescription& description,
    const Length& legacy_fallback_width) {
  page_defined_constraints_ =
      description.Resolve(gfx::SizeF(icb_size_), legacy_fallback_width);

  constraints_dirty_ = true;
}

void PageScaleConstraintsSet::ClearPageDefinedConstraints() {
  page_defined_constraints_ = PageScaleConstraints();
  constraints_dirty_ = true;
}

void PageScaleConstraintsSet::SetUserAgentConstraints(
    const PageScaleConstraints& user_agent_constraints) {
  user_agent_constraints_ = user_agent_constraints;
  constraints_dirty_ = true;
}

void PageScaleConstraintsSet::SetFullscreenConstraints(
    const PageScaleConstraints& fullscreen_constraints) {
  fullscreen_constraints_ = fullscreen_constraints;
  constraints_dirty_ = true;
}

PageScaleConstraints PageScaleConstraintsSet::ComputeConstraintsStack() const {
  PageScaleConstraints constraints = DefaultConstraints();
  constraints.OverrideWith(page_defined_constraints_);
  constraints.OverrideWith(user_agent_constraints_);
  constraints.OverrideWith(fullscreen_constraints_);
  return constraints;
}

void PageScaleConstraintsSet::ComputeFinalConstraints() {
  final_constraints_ = ComputeConstraintsStack();
  AdjustFinalConstraintsToContentsSize();
  constraints_dirty_ = false;
}

void PageScaleConstraintsSet::AdjustFinalConstraintsToContentsSize() {
  if (page_->GetSettings().GetShrinksViewportContentToFit()) {
    final_constraints_.FitToContentsWidth(
        last_contents_width_,
        icb_size_.width() - last_vertical_scrollbar_width_);
  }

  final_constraints_.ResolveAutoInitialScale();
}

void PageScaleConstraintsSet::SetNeedsReset(bool needs_reset) {
  needs_reset_ = needs_reset;
  if (needs_reset)
    constraints_dirty_ = true;
}

void PageScaleConstraintsSet::DidChangeContentsSize(
    gfx::Size contents_size,
    int vertical_scrollbar_width,
    float page_scale_factor) {
  // If a large fixed-width element expanded the size of the document late in
  // loading and our initial scale is not set (or set to be less than the last
  // minimum scale), reset the page scale factor to the new initial scale.
  if (contents_size.width() > last_contents_width_ &&
      page_scale_factor == FinalConstraints().minimum_scale &&
      ComputeConstraintsStack().initial_scale <
          FinalConstraints().minimum_scale)
    SetNeedsReset(true);

  constraints_dirty_ = true;
  last_vertical_scrollbar_width_ = vertical_scrollbar_width;
  last_contents_width_ = contents_size.width();
}

static float ComputeDeprecatedTargetDensityDPIFactor(
    const ViewportDescription& description) {
  if (description.deprecated_target_density_dpi ==
      ViewportDescription::kValueDeviceDPI)
    return 1.0f;

  float target_dpi = -1.0f;
  if (description.deprecated_target_density_dpi ==
      ViewportDescription::kValueLowDPI)
    target_dpi = 120.0f;
  else if (description.deprecated_target_density_dpi ==
           ViewportDescription::kValueMediumDPI)
    target_dpi = 160.0f;
  else if (description.deprecated_target_density_dpi ==
           ViewportDescription::kValueHighDPI)
    target_dpi = 240.0f;
  else if (description.deprecated_target_density_dpi !=
           ViewportDescription::kValueAuto)
    target_dpi = description.deprecated_target_density_dpi;
  return target_dpi > 0 ? 160.0f / target_dpi : 1.0f;
}

static float GetLayoutWidthForNonWideViewport(const gfx::Size& device_size,
                                              float initial_scale) {
  return initial_scale == -1 ? device_size.width()
                             : device_size.width() / initial_scale;
}

static float ComputeHeightByAspectRatio(float width,
                                        const gfx::Size& device_size) {
  return width * device_size.height() / device_size.width();
}

void PageScaleConstraintsSet::DidChangeInitialContainingBlockSize(
    const gfx::Size& size) {
  if (icb_size_ == size)
    return;

  icb_size_ = size;
  constraints_dirty_ = true;
}

gfx::Size PageScaleConstraintsSet::GetLayoutSize() const {
  return gfx::ToFlooredSize(ComputeConstraintsStack().layout_size);
}

void PageScaleConstraintsSet::AdjustForAndroidWebViewQuirks(
    const ViewportDescription& description,
    int layout_fallback_width,
    bool support_target_density_dpi,
    bool wide_viewport_quirk_enabled,
    bool use_wide_viewport,
    bool load_with_overview_mode,
    bool non_user_scalable_quirk_enabled) {
  if (!support_target_density_dpi && !wide_viewport_quirk_enabled &&
      load_with_overview_mode && !non_user_scalable_quirk_enabled)
    return;

  const float old_initial_scale = page_defined_constraints_.initial_scale;
  if (!load_with_overview_mode) {
    bool reset_initial_scale = false;
    if (description.zoom == -1) {
      if (description.max_width.IsAuto() ||
          description.max_width.IsExtendToZoom())
        reset_initial_scale = true;
      if (use_wide_viewport || description.max_width.IsDeviceWidth())
        reset_initial_scale = true;
    }
    if (reset_initial_scale)
      page_defined_constraints_.initial_scale = 1.0f;
  }

  float adjusted_layout_size_width =
      page_defined_constraints_.layout_size.width();
  float adjusted_layout_size_height =
      page_defined_constraints_.layout_size.height();
  float target_density_dpi_factor = 1.0f;

  if (support_target_density_dpi) {
    target_density_dpi_factor =
        ComputeDeprecatedTargetDensityDPIFactor(description);
    if (page_defined_constraints_.initial_scale != -1)
      page_defined_constraints_.initial_scale *= target_density_dpi_factor;
    if (page_defined_constraints_.minimum_scale != -1)
      page_defined_constraints_.minimum_scale *= target_density_dpi_factor;
    if (page_defined_constraints_.maximum_scale != -1)
      page_defined_constraints_.maximum_scale *= target_density_dpi_factor;
    if (wide_viewport_quirk_enabled &&
        (!use_wide_viewport || description.max_width.IsDeviceWidth())) {
      adjusted_layout_size_width /= target_density_dpi_factor;
      adjusted_layout_size_height /= target_density_dpi_factor;
    }
  }

  if (wide_viewport_quirk_enabled) {
    if (use_wide_viewport &&
        (description.max_width.IsAuto() ||
         description.max_width.IsExtendToZoom()) &&
        description.zoom != 1.0f) {
      if (layout_fallback_width)
        adjusted_layout_size_width = layout_fallback_width;
      adjusted_layout_size_height =
          ComputeHeightByAspectRatio(adjusted_layout_size_width, icb_size_);
    } else if (!use_wide_viewport) {
      const float non_wide_scale =
          description.zoom < 1 && !description.max_width.IsDeviceWidth() &&
                  !description.max_width.IsDeviceHeight()
              ? -1
              : old_initial_scale;
      adjusted_layout_size_width =
          GetLayoutWidthForNonWideViewport(icb_size_, non_wide_scale) /
          target_density_dpi_factor;
      float new_initial_scale = target_density_dpi_factor;
      if (user_agent_constraints_.initial_scale != -1 &&
          (description.max_width.IsDeviceWidth() ||
           ((description.max_width.IsAuto() ||
             description.max_width.IsExtendToZoom()) &&
            description.zoom == -1))) {
        adjusted_layout_size_width /= user_agent_constraints_.initial_scale;
        new_initial_scale = user_agent_constraints_.initial_scale;
      }
      adjusted_layout_size_height =
          ComputeHeightByAspectRatio(adjusted_layout_size_width, icb_size_);
      if (description.zoom < 1) {
        page_defined_constraints_.initial_scale = new_initial_scale;
        if (page_defined_constraints_.minimum_scale != -1)
          page_defined_constraints_.minimum_scale =
              std::min<float>(page_defined_constraints_.minimum_scale,
                              page_defined_constraints_.initial_scale);
        if (page_defined_constraints_.maximum_scale != -1)
          page_defined_constraints_.maximum_scale =
              std::max<float>(page_defined_constraints_.maximum_scale,
                              page_defined_constraints_.initial_scale);
      }
    }
  }

  if (non_user_scalable_quirk_enabled && !description.user_zoom) {
    page_defined_constraints_.initial_scale = target_density_dpi_factor;
    page_defined_constraints_.minimum_scale =
        page_defined_constraints_.initial_scale;
    page_defined_constraints_.maximum_scale =
        page_defined_constraints_.initial_scale;
    if (description.max_width.IsAuto() ||
        description.max_width.IsExtendToZoom() ||
        description.max_width.IsDeviceWidth()) {
      adjusted_layout_size_width =
          icb_size_.width() / target_density_dpi_factor;
      adjusted_layout_size_height =
          ComputeHeightByAspectRatio(adjusted_layout_size_width, icb_size_);
    }
  }

  page_defined_constraints_.layout_size.set_width(adjusted_layout_size_width);
  page_defined_constraints_.layout_size.set_height(adjusted_layout_size_height);
}

}  // namespace blink
```