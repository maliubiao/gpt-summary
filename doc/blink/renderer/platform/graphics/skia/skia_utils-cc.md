Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Understanding - The File's Purpose:**

The first thing to do is read the introductory comment block. It immediately tells us this is `skia_utils.cc` within the Blink rendering engine, specifically dealing with Skia. Skia is a 2D graphics library. The name "utils" strongly suggests this file contains helper functions for working with Skia.

**2. Examining Includes:**

Next, look at the included header files. This provides valuable clues about the functionalities within.

* `"third_party/blink/renderer/platform/graphics/skia/skia_utils.h"`:  This is the header file for the current source file, meaning it likely declares the functions we'll be analyzing.
* `<algorithm>`, `<cmath>`: Standard C++ libraries for common algorithms and math functions. This suggests the file will be performing calculations.
* `"base/numerics/safe_conversions.h"`: Indicates a focus on safe type conversions, potentially preventing overflow or other numeric errors.
* `"build/build_config.h"`:  Likely used for platform-specific code adjustments (though not directly visible in this snippet).
* `"cc/paint/paint_flags.h"`:  `cc` usually refers to Chromium Compositor. `PaintFlags` are used to configure how drawing operations are performed (e.g., antialiasing, color, stroke width). This strongly links the file to rendering.
* `"partition_alloc/partition_alloc.h"`:  Indicates memory management, suggesting the file might be involved in allocating resources for graphics.
* `"third_party/blink/renderer/platform/graphics/graphics_context.h"`: `GraphicsContext` is a core abstraction in Blink for drawing. This confirms the file is deeply involved in rendering.
* `"third_party/blink/renderer/platform/wtf/allocator/partitions.h"`: Another indication of custom memory management within Blink.
* `"third_party/skia/include/core/SkColorSpace.h"`: Directly related to Skia's color management.
* `"third_party/skia/modules/skcms/skcms.h"`:  Deals with Skia Color Management System, confirming a focus on color.
* `"ui/base/ui_base_features.h"`: Suggests UI-related features might influence the behavior.

**3. Analyzing Individual Functions (The Core Logic):**

Go through each function, understand its purpose, and look for connections to web technologies:

* **`WebCoreCompositeToSkiaComposite` and `WebCoreBlendModeToSkBlendMode`:**  These functions clearly translate Blink's `CompositeOperator` and `BlendMode` enums (used in CSS) to Skia's `SkBlendMode`. This is a direct bridge between web styling and the underlying graphics library.

* **`CompositeAndBlendOpsFromSkBlendMode`:** The reverse of the previous functions, translating Skia's blend modes back to Blink's representations.

* **`AffineTransformToSkMatrix` and `AffineTransformToSkM44`:** These functions convert Blink's `AffineTransform` (used for 2D transformations in CSS) to Skia's matrix representations (`SkMatrix` and `SkM44`). This is essential for implementing CSS transforms.

* **`NearlyIntegral`:**  A simple utility to check if a float is close to an integer. This likely relates to pixel alignment and avoiding blurry rendering.

* **`IsValidImageSize`:** Checks if an image size is valid, considering maximum dimensions and area. This is important for security and preventing excessive memory usage.

* **`InterpolationQuality ComputeInterpolationQuality`:** This is a crucial function. It decides the level of image smoothing (interpolation) based on source and destination sizes, and whether the image is fully loaded. This directly impacts how scaled images appear on the web page. The comments within the function provide valuable insights into the reasoning behind the different interpolation levels.

* **`ScaleAlpha`:** Modifies the alpha (transparency) component of a Skia color. This is used for implementing opacity in CSS.

* **`ApproximatelyEqualSkColorSpaces`:** Compares Skia color spaces for approximate equality. This is relevant for color management and ensuring consistent color rendering.

* **`PaintFlagsForFocusRing`, `DrawPlatformFocusRing` (overloads):**  These functions are responsible for drawing focus rings (visual indicators for keyboard navigation). This is a core accessibility feature in web browsers. The use of `cc::PaintFlags` links it to the compositor.

* **`TryAllocateSkData`:**  Attempts to allocate memory for Skia data using Blink's custom memory allocator. This highlights memory management related to graphics resources.

**4. Identifying Relationships with JavaScript, HTML, and CSS:**

As you analyze each function, think about how it connects to web technologies:

* **CSS:**  `CompositeOperator`, `BlendMode`, `transform` (using `AffineTransform`), `opacity`, image scaling (`width`, `height` properties), focus outlines (`:focus` styles).
* **HTML:** `<img>` tags (image rendering), `<canvas>` (direct drawing using JavaScript).
* **JavaScript:** Can manipulate the DOM and CSS styles, triggering the rendering logic that uses these Skia utilities. Canvas API directly interacts with graphics contexts.

**5. Logical Reasoning (Hypothetical Input/Output):**

For functions like `WebCoreCompositeToSkiaComposite` or `AffineTransformToSkMatrix`, it's straightforward to provide example inputs and expected outputs. For more complex functions like `ComputeInterpolationQuality`, you need to consider the different conditions and how they affect the output.

**6. Identifying Potential User/Programming Errors:**

Think about how developers might misuse the functionalities or encounter issues:

* **Incorrect Blend Modes/Composite Operators:** Using the wrong blend mode can lead to unexpected visual results.
* **Large Image Sizes:** Not being mindful of image dimensions can cause performance problems or even crashes due to memory limits.
* **Excessive Resizing:**  Continuously resizing large images can be computationally expensive.
* **Color Space Mismatches:** While the code attempts to handle color spaces, developers might encounter issues if color profiles are not correctly managed.
* **Memory Leaks (though less likely with `TryAllocateSkData`'s smart pointer):**  In general graphics programming, failing to release resources can be a problem. The use of `SkData::MakeWithProc` with a custom deallocator helps mitigate this.

**7. Structuring the Output:**

Organize your findings clearly:

* **Overall Functionality:** Start with a high-level summary.
* **Detailed Function Breakdown:** Describe each function's purpose and arguments.
* **Relationships to Web Technologies:**  Clearly link the functions to JavaScript, HTML, and CSS with concrete examples.
* **Logical Reasoning (Examples):** Provide input/output examples for key functions.
* **Common Errors:** List potential mistakes developers might make.

By following these steps, you can effectively analyze and understand the functionality of a C++ source file within a complex project like Chromium. The key is to combine code examination with knowledge of the surrounding system and related technologies.
这个文件 `blink/renderer/platform/graphics/skia/skia_utils.cc` 的主要功能是提供一组实用工具函数，用于在 Blink 渲染引擎中使用 Skia 图形库。它充当了 Blink 的图形抽象层和 Skia API 之间的桥梁，方便 Blink 代码使用 Skia 的功能进行绘制操作。

以下是该文件的具体功能列表：

**1. Composite Operator 和 Blend Mode 的转换：**

*   **`WebCoreCompositeToSkiaComposite(CompositeOperator op, BlendMode blend_mode)`:**  将 Blink 内部使用的 `CompositeOperator` 枚举（例如 `kCompositeSourceOver`, `kCompositeCopy`）和 `BlendMode` 枚举（例如 `kNormal`, `kMultiply`）转换为 Skia 对应的 `SkBlendMode` 枚举。
    *   **关系：** 这直接关系到 CSS 的 `mix-blend-mode` 和 `background-blend-mode` 属性，以及一些 Canvas API 中涉及合成操作的参数。
    *   **举例：**
        *   **假设输入：** `op = kCompositeSourceOver`, `blend_mode = BlendMode::kMultiply`
        *   **输出：** `SkBlendMode::kMultiply`
        *   **假设输入：** `op = kCompositeCopy`, `blend_mode = BlendMode::kNormal`
        *   **输出：** `SkBlendMode::kSrc`

*   **`WebCoreBlendModeToSkBlendMode(BlendMode blend_mode)`:** 将 Blink 的 `BlendMode` 枚举转换为 Skia 的 `SkBlendMode` 枚举。
    *   **关系：** 同上，与 CSS 的混合模式相关。

*   **`CompositeAndBlendOpsFromSkBlendMode(SkBlendMode sk_blend_mode)`:**  将 Skia 的 `SkBlendMode` 枚举转换回 Blink 的 `CompositeOperator` 和 `BlendMode` 的组合。
    *   **关系：** 这在某些反向操作或需要将 Skia 的结果映射回 Blink 内部表示时使用。
    *   **举例：**
        *   **假设输入：** `sk_blend_mode = SkBlendMode::kScreen`
        *   **输出：** `std::make_pair(kCompositeSourceOver, BlendMode::kScreen)`
        *   **假设输入：** `sk_blend_mode = SkBlendMode::kSrcCopy`
        *   **输出：** `std::make_pair(kCompositeCopy, BlendMode::kNormal)`

**2. 坐标变换的转换：**

*   **`AffineTransformToSkMatrix(const AffineTransform& source)`:** 将 Blink 的 `AffineTransform` 对象（用于 2D 变换）转换为 Skia 的 `SkMatrix` 对象。
    *   **关系：** 这与 CSS 的 `transform` 属性密切相关。`transform` 属性可以实现旋转、缩放、平移和倾斜等效果，这些效果在底层会转换为矩阵运算。
    *   **举例：**
        *   **假设输入：** 一个表示旋转 45 度的 `AffineTransform`。
        *   **输出：** 对应的 Skia `SkMatrix`，可以应用于 Skia 的绘制操作来实现旋转。

*   **`AffineTransformToSkM44(const AffineTransform& source)`:** 将 Blink 的 `AffineTransform` 对象转换为 Skia 的 `SkM44` 对象 (4x4 矩阵)。虽然 `AffineTransform` 本身是 2D 的，但在某些上下文中可能需要将其表示为 4x4 矩阵。
    *   **关系：** 同样与 CSS 的 `transform` 相关，尤其是在某些 3D 上下文中（虽然 `AffineTransform` 本身是 2D 的，但可能在更复杂的变换流水线中使用）。

**3. 数值和尺寸的实用函数：**

*   **`NearlyIntegral(float value)`:**  判断一个浮点数是否接近整数。
    *   **关系：** 这可能用于优化绘制，例如在某些情况下，如果尺寸接近整数像素，可以避免一些抗锯齿操作。
    *   **假设输入：** `3.000001f`
    *   **输出：** `true`
    *   **假设输入：** `3.1f`
    *   **输出：** `false`

*   **`IsValidImageSize(const gfx::Size& size)`:** 检查给定的图像尺寸是否有效，例如是否为空，是否过大以至于可能导致内存问题。
    *   **关系：** 这与 HTML 的 `<img>` 标签以及 Canvas API 中加载和绘制图像有关。浏览器需要防止加载过大的图像导致崩溃或性能问题。
    *   **用户/编程常见错误：** 加载或尝试绘制尺寸非常大的图片，可能导致内存溢出或渲染卡顿。

*   **`InterpolationQuality ComputeInterpolationQuality(float src_width, float src_height, float dest_width, float dest_height, bool is_data_complete)`:**  根据源图像和目标图像的尺寸以及图像数据是否加载完成，计算合适的插值质量。这决定了图像缩放时的平滑程度。
    *   **关系：**  直接影响 `<img>` 标签和 Canvas 中图像缩放的视觉效果。浏览器会根据缩放比例和图像完整性选择不同的插值算法。
    *   **假设输入：** `src_width = 100`, `src_height = 100`, `dest_width = 200`, `dest_height = 200`, `is_data_complete = true`
    *   **输出：**  `kInterpolationDefault` (假设默认质量)
    *   **假设输入：** `src_width = 100`, `src_height = 100`, `dest_width = 101`, `dest_height = 101`, `is_data_complete = true`
    *   **输出：** `kInterpolationNone` (对于小幅度的缩放可能不进行插值)
    *   **用户/编程常见错误：**  在 HTML 或 CSS 中使用非常小的源图像并将其放大很多倍，可能导致图像模糊。`ComputeInterpolationQuality` 尝试根据情况选择合适的插值，但过度放大仍然会损失细节。

**4. 颜色处理：**

*   **`ScaleAlpha(SkColor color, float alpha)`:**  调整 Skia 颜色的 alpha (透明度) 分量。
    *   **关系：**  与 CSS 的 `opacity` 属性以及颜色的 alpha 值（例如 `rgba()`）相关。
    *   **假设输入：** `color = SkColorSetARGB(255, 255, 0, 0)` (红色), `alpha = 0.5f`
    *   **输出：** `SkColorSetARGB(128, 255, 0, 0)` (半透明红色)

*   **`ApproximatelyEqualSkColorSpaces(sk_sp<SkColorSpace> src_color_space, sk_sp<SkColorSpace> dst_color_space)`:**  判断两个 Skia 色彩空间是否近似相等。
    *   **关系：**  与 CSS 的色彩管理相关，例如 `color-profile` 属性。浏览器需要处理不同色彩空间之间的转换，并判断色彩空间是否足够接近，从而避免不必要的转换。

**5. 绘制辅助函数：**

*   **`PaintFlagsForFocusRing(SkColor4f color, float width)`:** 创建用于绘制焦点环的 Skia `PaintFlags` 对象，设置抗锯齿、描边样式、颜色和描边宽度。
    *   **关系：**  与 HTML 元素获得焦点时的视觉反馈有关，例如通过键盘导航时的焦点轮廓。

*   **`DrawPlatformFocusRing(const SkRRect& rrect, cc::PaintCanvas* canvas, SkColor4f color, float width)`** 和 **`DrawPlatformFocusRing(const SkPath& path, cc::PaintCanvas* canvas, SkColor4f color, float width, float corner_radius)`:**  在给定的画布上绘制平台风格的焦点环，可以绘制圆角矩形或任意路径的焦点环。
    *   **关系：**  与可访问性相关，帮助用户了解当前哪个元素获得了焦点。

**6. 内存管理：**

*   **`TryAllocateSkData(size_t size)`:** 尝试分配 Skia 数据 ( `SkData` ) 的内存，使用 Blink 的分区分配器。如果分配失败则返回 `nullptr`。
    *   **关系：**  这与处理图像、字体等需要大量内存的图形资源有关。使用分区分配器可以提高内存管理的效率和安全性。
    *   **用户/编程常见错误：**  没有检查 `TryAllocateSkData` 的返回值，直接使用可能为 `nullptr` 的指针，导致程序崩溃。

**总结来说，`skia_utils.cc` 是一个关键的桥梁文件，它封装了 Skia 的底层 API，并提供了 Blink 更易于使用的接口。它直接参与了网页内容的渲染过程，包括图像绘制、变换、混合模式、色彩管理以及焦点反馈等，与 JavaScript、HTML 和 CSS 的功能都有着紧密的联系。**

### 提示词
```
这是目录为blink/renderer/platform/graphics/skia/skia_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (c) 2006,2007,2008, Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/platform/graphics/skia/skia_utils.h"

#include <algorithm>
#include <cmath>

#include "base/numerics/safe_conversions.h"
#include "build/build_config.h"
#include "cc/paint/paint_flags.h"
#include "partition_alloc/partition_alloc.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/wtf/allocator/partitions.h"
#include "third_party/skia/include/core/SkColorSpace.h"
#include "third_party/skia/modules/skcms/skcms.h"
#include "ui/base/ui_base_features.h"

namespace blink {

SkBlendMode WebCoreCompositeToSkiaComposite(CompositeOperator op,
                                            BlendMode blend_mode) {
  if (blend_mode != BlendMode::kNormal) {
    DCHECK(op == kCompositeSourceOver);
    return WebCoreBlendModeToSkBlendMode(blend_mode);
  }

  switch (op) {
    case kCompositeClear:
      return SkBlendMode::kClear;
    case kCompositeCopy:
      return SkBlendMode::kSrc;
    case kCompositeSourceOver:
      return SkBlendMode::kSrcOver;
    case kCompositeSourceIn:
      return SkBlendMode::kSrcIn;
    case kCompositeSourceOut:
      return SkBlendMode::kSrcOut;
    case kCompositeSourceAtop:
      return SkBlendMode::kSrcATop;
    case kCompositeDestinationOver:
      return SkBlendMode::kDstOver;
    case kCompositeDestinationIn:
      return SkBlendMode::kDstIn;
    case kCompositeDestinationOut:
      return SkBlendMode::kDstOut;
    case kCompositeDestinationAtop:
      return SkBlendMode::kDstATop;
    case kCompositeXOR:
      return SkBlendMode::kXor;
    case kCompositePlusLighter:
      return SkBlendMode::kPlus;
  }

  NOTREACHED();
}

SkBlendMode WebCoreBlendModeToSkBlendMode(BlendMode blend_mode) {
  switch (blend_mode) {
    case BlendMode::kNormal:
      return SkBlendMode::kSrcOver;
    case BlendMode::kMultiply:
      return SkBlendMode::kMultiply;
    case BlendMode::kScreen:
      return SkBlendMode::kScreen;
    case BlendMode::kOverlay:
      return SkBlendMode::kOverlay;
    case BlendMode::kDarken:
      return SkBlendMode::kDarken;
    case BlendMode::kLighten:
      return SkBlendMode::kLighten;
    case BlendMode::kColorDodge:
      return SkBlendMode::kColorDodge;
    case BlendMode::kColorBurn:
      return SkBlendMode::kColorBurn;
    case BlendMode::kHardLight:
      return SkBlendMode::kHardLight;
    case BlendMode::kSoftLight:
      return SkBlendMode::kSoftLight;
    case BlendMode::kDifference:
      return SkBlendMode::kDifference;
    case BlendMode::kExclusion:
      return SkBlendMode::kExclusion;
    case BlendMode::kHue:
      return SkBlendMode::kHue;
    case BlendMode::kSaturation:
      return SkBlendMode::kSaturation;
    case BlendMode::kColor:
      return SkBlendMode::kColor;
    case BlendMode::kLuminosity:
      return SkBlendMode::kLuminosity;
    case BlendMode::kPlusLighter:
      return SkBlendMode::kPlus;
  }

  NOTREACHED();
}

std::pair<CompositeOperator, BlendMode> CompositeAndBlendOpsFromSkBlendMode(
    SkBlendMode sk_blend_mode) {
  CompositeOperator composite_op = kCompositeSourceOver;
  BlendMode blend_mode = BlendMode::kNormal;
  switch (sk_blend_mode) {
    // The following are SkBlendMode values that map to CompositeOperators.
    case SkBlendMode::kClear:
      composite_op = kCompositeClear;
      break;
    case SkBlendMode::kSrc:
      composite_op = kCompositeCopy;
      break;
    case SkBlendMode::kSrcOver:
      composite_op = kCompositeSourceOver;
      break;
    case SkBlendMode::kDstOver:
      composite_op = kCompositeDestinationOver;
      break;
    case SkBlendMode::kSrcIn:
      composite_op = kCompositeSourceIn;
      break;
    case SkBlendMode::kDstIn:
      composite_op = kCompositeDestinationIn;
      break;
    case SkBlendMode::kSrcOut:
      composite_op = kCompositeSourceOut;
      break;
    case SkBlendMode::kDstOut:
      composite_op = kCompositeDestinationOut;
      break;
    case SkBlendMode::kSrcATop:
      composite_op = kCompositeSourceAtop;
      break;
    case SkBlendMode::kDstATop:
      composite_op = kCompositeDestinationAtop;
      break;
    case SkBlendMode::kXor:
      composite_op = kCompositeXOR;
      break;
    case SkBlendMode::kPlus:
      composite_op = kCompositePlusLighter;
      break;

    // The following are SkBlendMode values that map to BlendModes.
    case SkBlendMode::kScreen:
      blend_mode = BlendMode::kScreen;
      break;
    case SkBlendMode::kOverlay:
      blend_mode = BlendMode::kOverlay;
      break;
    case SkBlendMode::kDarken:
      blend_mode = BlendMode::kDarken;
      break;
    case SkBlendMode::kLighten:
      blend_mode = BlendMode::kLighten;
      break;
    case SkBlendMode::kColorDodge:
      blend_mode = BlendMode::kColorDodge;
      break;
    case SkBlendMode::kColorBurn:
      blend_mode = BlendMode::kColorBurn;
      break;
    case SkBlendMode::kHardLight:
      blend_mode = BlendMode::kHardLight;
      break;
    case SkBlendMode::kSoftLight:
      blend_mode = BlendMode::kSoftLight;
      break;
    case SkBlendMode::kDifference:
      blend_mode = BlendMode::kDifference;
      break;
    case SkBlendMode::kExclusion:
      blend_mode = BlendMode::kExclusion;
      break;
    case SkBlendMode::kMultiply:
      blend_mode = BlendMode::kMultiply;
      break;
    case SkBlendMode::kHue:
      blend_mode = BlendMode::kHue;
      break;
    case SkBlendMode::kSaturation:
      blend_mode = BlendMode::kSaturation;
      break;
    case SkBlendMode::kColor:
      blend_mode = BlendMode::kColor;
      break;
    case SkBlendMode::kLuminosity:
      blend_mode = BlendMode::kLuminosity;
      break;

    // We don't handle other SkBlendModes.
    default:
      break;
  }
  return std::make_pair(composite_op, blend_mode);
}

SkMatrix AffineTransformToSkMatrix(const AffineTransform& source) {
  // SkMatrices are 3x3, so they have a concept of "perspective" in the bottom
  // row. blink::AffineTransform is a 2x3 matrix that can encode 2d rotations,
  // skew and translation, but has no perspective. Those parameters are set to
  // zero here. i.e.:

  //   INPUT           OUTPUT
  // | a c e |       | a c e |
  // | b d f | ----> | b d f |
  //                 | 0 0 1 |

  SkMatrix result;

  result.setScaleX(WebCoreDoubleToSkScalar(source.A()));
  result.setSkewX(WebCoreDoubleToSkScalar(source.C()));
  result.setTranslateX(WebCoreDoubleToSkScalar(source.E()));

  result.setScaleY(WebCoreDoubleToSkScalar(source.D()));
  result.setSkewY(WebCoreDoubleToSkScalar(source.B()));
  result.setTranslateY(WebCoreDoubleToSkScalar(source.F()));

  result.setPerspX(0);
  result.setPerspY(0);
  result.set(SkMatrix::kMPersp2, SK_Scalar1);

  return result;
}

SkM44 AffineTransformToSkM44(const AffineTransform& source) {
  //   INPUT           OUTPUT
  // | a c e |       | a c 0 e |
  // | b d f | ----> | b d 0 f |
  //                 | 0 0 1 0 |
  //                 | 0 0 0 1 |
  SkScalar a = WebCoreDoubleToSkScalar(source.A());
  SkScalar b = WebCoreDoubleToSkScalar(source.B());
  SkScalar c = WebCoreDoubleToSkScalar(source.C());
  SkScalar d = WebCoreDoubleToSkScalar(source.D());
  SkScalar e = WebCoreDoubleToSkScalar(source.E());
  SkScalar f = WebCoreDoubleToSkScalar(source.F());
  return SkM44(a, c, 0, e,   // row 0
               b, d, 0, f,   // row 1
               0, 0, 1, 0,   // row 2
               0, 0, 0, 1);  // row 3
}

bool NearlyIntegral(float value) {
  return fabs(value - floorf(value)) < std::numeric_limits<float>::epsilon();
}

bool IsValidImageSize(const gfx::Size& size) {
  if (size.IsEmpty())
    return false;
  base::CheckedNumeric<int> area = size.GetCheckedArea();
  if (!area.IsValid() || area.ValueOrDie() > kMaxCanvasArea)
    return false;
  if (size.width() > kMaxSkiaDim || size.height() > kMaxSkiaDim)
    return false;
  return true;
}

InterpolationQuality ComputeInterpolationQuality(float src_width,
                                                 float src_height,
                                                 float dest_width,
                                                 float dest_height,
                                                 bool is_data_complete) {
  // The percent change below which we will not resample. This usually means
  // an off-by-one error on the web page, and just doing nearest neighbor
  // sampling is usually good enough.
  const float kFractionalChangeThreshold = 0.025f;

  // Images smaller than this in either direction are considered "small" and
  // are not resampled ever (see below).
  const int kSmallImageSizeThreshold = 8;

  // The amount an image can be stretched in a single direction before we
  // say that it is being stretched so much that it must be a line or
  // background that doesn't need resampling.
  const float kLargeStretch = 3.0f;

  // Figure out if we should resample this image. We try to prune out some
  // common cases where resampling won't give us anything, since it is much
  // slower than drawing stretched.
  float diff_width = fabs(dest_width - src_width);
  float diff_height = fabs(dest_height - src_height);
  bool width_nearly_equal = diff_width < std::numeric_limits<float>::epsilon();
  bool height_nearly_equal =
      diff_height < std::numeric_limits<float>::epsilon();
  // We don't need to resample if the source and destination are the same.
  if (width_nearly_equal && height_nearly_equal)
    return kInterpolationNone;

  if (src_width <= kSmallImageSizeThreshold ||
      src_height <= kSmallImageSizeThreshold ||
      dest_width <= kSmallImageSizeThreshold ||
      dest_height <= kSmallImageSizeThreshold) {
    // Small image detected.

    // Resample in the case where the new size would be non-integral.
    // This can cause noticeable breaks in repeating patterns, except
    // when the source image is only one pixel wide in that dimension.
    if ((!NearlyIntegral(dest_width) &&
         src_width > 1 + std::numeric_limits<float>::epsilon()) ||
        (!NearlyIntegral(dest_height) &&
         src_height > 1 + std::numeric_limits<float>::epsilon()))
      return kInterpolationLow;

    // Otherwise, don't resample small images. These are often used for
    // borders and rules (think 1x1 images used to make lines).
    return kInterpolationNone;
  }

  if (src_height * kLargeStretch <= dest_height ||
      src_width * kLargeStretch <= dest_width) {
    // Large image detected.

    // Don't resample if it is being stretched a lot in only one direction.
    // This is trying to catch cases where somebody has created a border
    // (which might be large) and then is stretching it to fill some part
    // of the page.
    if (width_nearly_equal || height_nearly_equal)
      return kInterpolationNone;

    // The image is growing a lot and in more than one direction. Resampling
    // is slow and doesn't give us very much when growing a lot.
    return kInterpolationLow;
  }

  if ((diff_width / src_width < kFractionalChangeThreshold) &&
      (diff_height / src_height < kFractionalChangeThreshold)) {
    // It is disappointingly common on the web for image sizes to be off by
    // one or two pixels. We don't bother resampling if the size difference
    // is a small fraction of the original size.
    return kInterpolationNone;
  }

  // When the image is not yet done loading, use linear. We don't cache the
  // partially resampled images, and as they come in incrementally, it causes
  // us to have to resample the whole thing every time.
  if (!is_data_complete)
    return kInterpolationLow;

  // Everything else gets resampled at default quality.
  return GetDefaultInterpolationQuality();
}

SkColor ScaleAlpha(SkColor color, float alpha) {
  const auto clamped_alpha = std::max(0.0f, std::min(1.0f, alpha));
  const auto rounded_alpha =
      base::ClampRound<U8CPU>(SkColorGetA(color) * clamped_alpha);

  return SkColorSetA(color, rounded_alpha);
}

bool ApproximatelyEqualSkColorSpaces(sk_sp<SkColorSpace> src_color_space,
                                     sk_sp<SkColorSpace> dst_color_space) {
  if ((!src_color_space && dst_color_space) ||
      (src_color_space && !dst_color_space))
    return false;
  if (!src_color_space && !dst_color_space)
    return true;
  skcms_ICCProfile src_profile, dst_profile;
  src_color_space->toProfile(&src_profile);
  dst_color_space->toProfile(&dst_profile);
  return skcms_ApproximatelyEqualProfiles(&src_profile, &dst_profile);
}

static cc::PaintFlags PaintFlagsForFocusRing(SkColor4f color, float width) {
  cc::PaintFlags flags;
  flags.setAntiAlias(true);
  flags.setStyle(cc::PaintFlags::kStroke_Style);
  flags.setColor(color);
  flags.setStrokeWidth(width);
  return flags;
}

void DrawPlatformFocusRing(const SkRRect& rrect,
                           cc::PaintCanvas* canvas,
                           SkColor4f color,
                           float width) {
  canvas->drawRRect(rrect, PaintFlagsForFocusRing(color, width));
}

void DrawPlatformFocusRing(const SkPath& path,
                           cc::PaintCanvas* canvas,
                           SkColor4f color,
                           float width,
                           float corner_radius) {
  cc::PaintFlags path_flags = PaintFlagsForFocusRing(color, width);
  if (corner_radius) {
    path_flags.setPathEffect(cc::PathEffect::MakeCorner(corner_radius));
  }
  canvas->drawPath(path, path_flags);
}

sk_sp<SkData> TryAllocateSkData(size_t size) {
  void* buffer =
      WTF::Partitions::BufferPartition()
          ->AllocInline<partition_alloc::AllocFlags::kReturnNull |
                        partition_alloc::AllocFlags::kZeroFill>(size, "SkData");
  if (!buffer)
    return nullptr;
  return SkData::MakeWithProc(
      buffer, size,
      [](const void* buffer, void* context) {
        WTF::Partitions::BufferPartition()->Free(const_cast<void*>(buffer));
      },
      /*context=*/nullptr);
}

}  // namespace blink
```