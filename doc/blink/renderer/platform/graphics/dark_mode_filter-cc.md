Response:
Let's break down the thought process for analyzing the `dark_mode_filter.cc` file.

**1. Understanding the Goal:**

The fundamental goal is to understand the purpose and functionality of this specific source code file within the Chromium Blink rendering engine. The request also asks for connections to web technologies (HTML, CSS, JavaScript), logical reasoning examples, and common usage errors.

**2. Initial Code Scan and Keyword Spotting:**

I started by quickly scanning the code, looking for key terms and patterns:

* **`DarkModeFilter`:**  This is the central class. Immediately, I know it's about applying some kind of filtering related to dark mode.
* **`settings`:** The constructor takes `DarkModeSettings`, suggesting configurable behavior.
* **`InvertColor`:**  This appears frequently, hinting at color inversion as a core function.
* **`AdjustDarkenColor`:**  Suggests adjustments to make colors darker, likely with considerations for contrast.
* **`ApplyFilterToImage`:**  Clearly deals with applying dark mode to images.
* **`GenerateImageFilter`:**  Indicates the creation of color filters, likely for images.
* **`cc::ColorFilter` and `cc::PaintFlags`:** These are Chromium Compositor concepts, signifying integration with the rendering pipeline.
* **`SkColor`, `SkBitmap`, `SkPixmap`:**  These are Skia graphics library types, revealing the underlying graphics manipulation.
* **`kMaxCacheSize`, `DarkModeInvertedColorCache`, `DarkModeImageCache`:** Caching is used, likely for performance optimization.
* **`ElementRole`:**  Different types of elements (border, background, etc.) are treated differently, implying nuanced dark mode application.
* **`DarkModeImagePolicy`:**  Different strategies for handling images in dark mode.
* **`switches::kEnableRasterSideDarkModeForImages`:** A command-line switch, indicating a feature flag.
* **`IsBitmapImage()`:**  Image type checking, suggesting different handling for different image formats.
* **`AsSkBitmapForCurrentFrame()`:**  Decoding images, which can be performance-intensive.
* **`DarkModeColorClassifier`, `DarkModeImageClassifier`:**  Components responsible for deciding whether to apply dark mode to specific elements or images.

**3. Identifying Core Functionalities (High-Level):**

From the keyword spotting and initial scan, I could deduce the primary functionalities:

* **Color Inversion:**  A fundamental part of making things "dark."
* **Image Filtering:** Applying dark mode to images.
* **Caching:**  Optimizing performance by storing results of color inversions and image filters.
* **Configuration:**  Using `DarkModeSettings` to control behavior.
* **Element-Specific Handling:**  Applying dark mode differently based on the role of the element (border, background, etc.).
* **Integration with Chromium Rendering:** Using `cc::ColorFilter` and `cc::PaintFlags` for applying effects during rendering.

**4. Delving Deeper into Specific Functionalities:**

I then went back through the code to understand the details of each functionality:

* **Color Inversion (`InvertColorIfNeeded`):**  It checks `ShouldApplyToColor` based on `ElementRole` and uses a cache to avoid redundant computations. It interacts with `DarkModeColorFilter`.
* **Image Filtering (`ApplyFilterToImage`):**  It has different paths:
    * **`kFilterAll`:** Applies a general filter.
    * **Raster-side:**  Sets a flag for later processing in the compositor.
    * **Blink-side:**  Retrieves or generates a color filter using caching and the `DarkModeImageClassifier`.
* **Element Roles:**  The `ElementRole` enum and the `ShouldApplyToColor` function are crucial for deciding which elements get dark mode applied. The classifiers (`DarkModeColorClassifier`) make these decisions.
* **Contrast Adjustment (`AdjustDarkenColor`):** Addresses issues with low contrast after darkening, especially for borders and selections.

**5. Connecting to Web Technologies (HTML, CSS, JavaScript):**

This required thinking about how the rendering engine interacts with web content:

* **CSS:**  The most direct connection. CSS styles (colors, backgrounds, borders) are the *input* to this code. Dark mode aims to modify how these styles are rendered.
* **HTML:** The structure of the page. The `ElementRole` concept directly relates to HTML elements (e.g., a `<div>` might have a border, background color, or text content).
* **JavaScript:** Less direct, but JavaScript can manipulate the DOM and CSS styles, indirectly influencing how this filter operates. JavaScript could also trigger image loading.

**6. Formulating Examples and Logical Reasoning:**

For logical reasoning, I focused on the conditional logic within the functions:

* **`ShouldApplyFilterToImage`:**  The different `DarkModeImagePolicy` values lead to different outcomes.
* **`ShouldUseRasterSidePath`:** The feature flag and image type determine the path.
* **`InvertColorIfNeeded`:**  The `ShouldApplyToColor` check is the logical condition.

For examples, I tried to make them concrete:

* **CSS Color:** Show how a CSS color value might be inverted.
* **Image:**  Illustrate how different `DarkModeImagePolicy` settings affect image rendering.

**7. Identifying Common Usage Errors (From a Developer Perspective):**

Since this is Blink code, the "user" is more of a Chromium developer or someone working on the rendering engine. Common errors might involve:

* **Incorrect Settings:**  Misconfiguring `DarkModeSettings`.
* **Cache Issues:**  Problems with the caching logic leading to stale or incorrect results.
* **Performance Problems:**  Not considering the performance implications of synchronous image decoding.
* **Incorrect Element Roles:**  Misclassifying elements leading to unexpected dark mode application.

**8. Structuring the Answer:**

Finally, I organized the information into the requested categories: Functionality, Relationships to Web Technologies, Logical Reasoning, and Common Errors, providing clear explanations and examples for each. I made sure to use the terminology present in the code to demonstrate understanding.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This just inverts colors."  **Correction:**  Realized it's more nuanced, with classifiers, caching, and different handling for images and element types.
* **Focusing too much on low-level Skia details:** **Correction:** Shifted focus to the higher-level functionality and how it relates to the web.
* **Not enough concrete examples:** **Correction:** Added specific examples with CSS color values and image policies.
* **Overlooking the "user" perspective:** **Correction:**  Clarified that the "user" in this context is more likely a Chromium developer.

By following this iterative process of scanning, understanding, connecting, and refining, I was able to construct a comprehensive and accurate answer to the request.
好的，让我们来分析一下 `blink/renderer/platform/graphics/dark_mode_filter.cc` 这个文件。

**文件功能概述：**

`DarkModeFilter.cc` 文件在 Chromium Blink 渲染引擎中负责实现暗黑模式 (Dark Mode) 的核心过滤逻辑。它的主要功能是：

1. **颜色反转（或调整）：**  根据配置策略，对页面元素（如文本、背景、边框等）的颜色进行反转或调整，使其在暗黑模式下更易于阅读和观看。
2. **图像处理：**  决定是否以及如何对图像应用暗黑模式滤镜。这可能包括对整个图像进行反色，或者通过图像分类器判断图像内容（例如，照片通常不应该反色）来智能地应用滤镜。
3. **缓存机制：**  为了提高性能，该文件实现了颜色反转结果和图像处理结果的缓存，避免重复计算。
4. **对比度调整：**  在暗黑模式下，某些颜色反转后可能导致对比度过低，该文件包含调整逻辑以确保必要的对比度，例如针对边框和选中状态。
5. **与渲染流程集成：**  该文件生成的滤镜会通过 `cc::PaintFlags` 传递给 Chromium 的合成器 (Compositor) 进行渲染。
6. **配置管理：**  通过 `DarkModeSettings` 对象来控制暗黑模式的行为，例如图像处理策略。

**与 JavaScript, HTML, CSS 的关系：**

`DarkModeFilter.cc` 位于渲染引擎的底层，它的工作是对渲染过程中的颜色和图像进行处理，以实现最终的暗黑模式效果。它与 JavaScript, HTML, CSS 的关系体现在：

* **CSS：**  CSS 样式是 `DarkModeFilter` 的主要输入来源。例如，当 CSS 定义了元素的背景颜色、文本颜色或边框颜色时，`DarkModeFilter` 会接收到这些颜色值，并根据暗黑模式的策略进行处理。
    * **举例：**  如果一个 `<div>` 元素在 CSS 中定义了 `background-color: white; color: black;`，在启用暗黑模式后，`DarkModeFilter` 可能会将背景颜色反转为接近黑色，文本颜色反转为接近白色。

* **HTML：** HTML 定义了页面的结构和元素。`DarkModeFilter` 需要识别不同类型的 HTML 元素（例如，文本节点、图像元素、SVG 元素）以便应用不同的暗黑模式处理策略。例如，它可能会对图像元素采取与普通文本元素不同的处理方式。
    * **举例：**  对于一个 `<img>` 标签，`DarkModeFilter` 会根据 `DarkModeImagePolicy` 决定是否应用滤镜。

* **JavaScript：** JavaScript 可以动态地修改 HTML 结构和 CSS 样式。这些修改最终会影响 `DarkModeFilter` 的处理。例如，JavaScript 动态改变了元素的背景颜色，那么 `DarkModeFilter` 会对新的颜色值进行处理。
    * **举例：**  一个 JavaScript 脚本可能根据用户的偏好设置动态地切换页面的 CSS 类，从而启用或禁用暗黑模式。`DarkModeFilter` 会根据当前是否启用了暗黑模式来进行颜色和图像的过滤。

**逻辑推理举例：**

假设输入一个浅色背景和一个深色文本的场景：

**假设输入：**

* **元素类型：** `ElementRole::kForeground` (文本) 和 `ElementRole::kBackground`
* **原始颜色：**
    * 文本颜色 (`color`): `SkColor4f{0.0f, 0.0f, 0.0f, 1.0f}` (黑色)
    * 背景颜色 (`contrast_background`): `SkColor4f{1.0f, 1.0f, 1.0f, 1.0f}` (白色)
* **暗黑模式已启用。**

**处理过程（简化）：**

1. `InvertColorIfNeeded(color, ElementRole::kForeground)` 被调用。
2. `ShouldApplyToColor` 函数根据 `ElementRole::kForeground` 和 `immutable_.foreground_classifier` 判断是否需要反转颜色。假设分类器认为需要反转。
3. `inverted_color_cache_->GetInvertedColor` 被调用，尝试从缓存中获取反转后的颜色。
4. 如果缓存未命中，`immutable_.color_filter->InvertColor(color)` 会被调用，计算反转后的颜色，例如接近白色。
5. 反转后的颜色会被存入缓存。
6. 类似的流程会处理背景颜色，将其反转为接近黑色。

**输出：**

* **反转后的文本颜色：**  接近白色
* **反转后的背景颜色：**  接近黑色

**假设输入一个图像的场景：**

**假设输入：**

* **图像类型：** `Image` 对象，`IsBitmapImage()` 返回 `true`。
* **暗黑模式图像策略：** `DarkModeImagePolicy::kFilterSmart`
* **图像内容：**  一个包含风景的照片。

**处理过程（简化）：**

1. `ApplyFilterToImage(image, flags, src)` 被调用。
2. 由于 `GetDarkModeImagePolicy()` 返回 `kFilterSmart`，并且 `ShouldUseRasterSidePath(image)` 返回 `false` (假设未启用 Raster-side 暗黑模式)，则进入 Blink-side 处理路径。
3. `GetDarkModeFilterForImageOnMainThread` 被调用。
4. `image->GetDarkModeImageCache()->Exists(rounded_src)` 检查缓存中是否存在针对该图像区域的滤镜。
5. 如果缓存未命中：
    * `image->AsSkBitmapForCurrentFrame()` 获取图像的位图数据。
    * `immutable_.image_classifier->Classify(pixmap, rounded_src)` 调用图像分类器判断是否应该对该图像应用滤镜。由于是风景照片，分类器可能返回 `DarkModeResult::kDoNotApplyFilter`。
6. 如果分类器决定不应用滤镜，则 `GenerateImageFilter` 返回 `nullptr`。
7. `ApplyFilterToImage` 中，由于 `color_filter` 为空，所以不会设置 `flags->setColorFilter`。

**输出：**

* 图像不会被应用暗黑模式滤镜，保持原始颜色。

**用户或编程常见的使用错误举例：**

1. **误用 `ElementRole`：**  在调用 `InvertColorIfNeeded` 或 `ShouldApplyToColor` 时，如果传入了错误的 `ElementRole`，可能导致暗黑模式应用不正确。例如，将一个背景颜色误认为是文本颜色进行处理。

    ```c++
    // 错误示例：将背景颜色当作前景颜色处理
    SkColor4f bg_color = GetBackgroundColor();
    filter->InvertColorIfNeeded(bg_color, DarkModeFilter::ElementRole::kForeground);
    ```

2. **未考虑缓存：**  在开发或调试暗黑模式功能时，如果没有正确地清理缓存，可能会遇到预期之外的行为，因为缓存中可能存在旧的处理结果。

    ```c++
    // 例如，在测试中可能需要手动清除缓存
    // filter->inverted_color_cache_->Clear(); // 假设有公开的清除方法
    ```

3. **假设所有颜色都需要反转：**  `DarkModeFilter` 的设计目标是智能地应用暗黑模式，而不是简单地反转所有颜色。如果开发者假设所有颜色都需要反转，可能会导致对不需要反转的元素（例如，已经很深的颜色）也进行了反转，从而产生不好的视觉效果。

4. **Raster-side 和 Blink-side 暗黑模式的混淆：**  该文件提到了 Raster-side 暗黑模式，这是一种在 GPU 栅格化阶段应用暗黑模式的技术。如果开发者混淆了这两种模式的工作原理和适用场景，可能会导致配置错误或预期之外的行为。例如，错误地假设 Blink-side 的缓存机制对 Raster-side 也有效。

5. **图像分类器的误判：**  图像分类器虽然可以智能地判断是否需要对图像应用滤镜，但仍然可能存在误判的情况。例如，某些图标可能被误认为照片而没有应用滤镜，或者某些浅色背景的图像被错误地应用了反色。开发者需要了解图像分类器的局限性，并可能需要根据具体情况进行调整或提供额外的处理逻辑。

总而言之，`blink/renderer/platform/graphics/dark_mode_filter.cc` 文件是 Blink 渲染引擎中实现暗黑模式的核心组件，它通过颜色反转、图像处理和缓存等机制，将浅色主题的网页转换为适合在暗光环境下浏览的深色主题，并与 CSS 样式、HTML 结构以及 JavaScript 动态修改密切相关。理解其功能和使用方式对于开发和调试 Chromium 的暗黑模式功能至关重要。

### 提示词
```
这是目录为blink/renderer/platform/graphics/dark_mode_filter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/dark_mode_filter.h"

#include <cmath>
#include <optional>

#include "base/check_op.h"
#include "base/command_line.h"
#include "base/containers/lru_cache.h"
#include "base/notreached.h"
#include "third_party/blink/public/common/switches.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/graphics/dark_mode_color_classifier.h"
#include "third_party/blink/renderer/platform/graphics/dark_mode_color_filter.h"
#include "third_party/blink/renderer/platform/graphics/dark_mode_image_cache.h"
#include "third_party/blink/renderer/platform/graphics/dark_mode_image_classifier.h"
#include "third_party/blink/renderer/platform/graphics/image.h"
#include "third_party/blink/renderer/platform/wtf/hash_functions.h"
#include "third_party/skia/include/core/SkBitmap.h"
#include "third_party/skia/include/core/SkColor.h"
#include "third_party/skia/include/core/SkColorFilter.h"
#include "third_party/skia/include/core/SkPixmap.h"
#include "third_party/skia/include/core/SkRect.h"
#include "third_party/skia/include/core/SkRefCnt.h"
#include "ui/gfx/color_utils.h"

namespace blink {

namespace {

const size_t kMaxCacheSize = 1024u;
constexpr SkColor SK_ColorDark = SkColorSetARGB(0xFF, 0x12, 0x12, 0x12);

bool IsRasterSideDarkModeForImagesEnabled() {
  static bool enabled = base::CommandLine::ForCurrentProcess()->HasSwitch(
      switches::kEnableRasterSideDarkModeForImages);
  return enabled;
}

bool ShouldUseRasterSidePath(Image* image) {
  DCHECK(image);

  // Raster-side path is not enabled.
  if (!IsRasterSideDarkModeForImagesEnabled())
    return false;

  // Raster-side path is only supported for bitmap images.
  return image->IsBitmapImage();
}

sk_sp<cc::ColorFilter> GetDarkModeFilterForImageOnMainThread(
    DarkModeFilter* filter,
    Image* image,
    const SkIRect& rounded_src) {
  sk_sp<cc::ColorFilter> color_filter;
  DarkModeImageCache* cache = image->GetDarkModeImageCache();
  DCHECK(cache);
  if (cache->Exists(rounded_src)) {
    color_filter = cache->Get(rounded_src);
  } else {
    // Performance warning: Calling AsSkBitmapForCurrentFrame() will
    // synchronously decode image.
    SkBitmap bitmap =
        image->AsSkBitmapForCurrentFrame(kDoNotRespectImageOrientation);
    SkPixmap pixmap;
    bitmap.peekPixels(&pixmap);
    color_filter = filter->GenerateImageFilter(pixmap, rounded_src);

    // Using blink side dark mode for images, it is hard to implement
    // caching mechanism for partially loaded bitmap image content, as
    // content id for the image frame being rendered gets decided during
    // rastering only. So caching of dark mode result will be deferred until
    // default frame is completely received. This will help get correct
    // classification results for incremental content received for the given
    // image.
    if (!image->IsBitmapImage() || image->CurrentFrameIsComplete())
      cache->Add(rounded_src, color_filter);
  }
  return color_filter;
}

}  // namespace

// DarkModeInvertedColorCache - Implements cache for inverted colors.
class DarkModeInvertedColorCache {
 public:
  DarkModeInvertedColorCache() : cache_(kMaxCacheSize) {}
  ~DarkModeInvertedColorCache() = default;

  SkColor4f GetInvertedColor(DarkModeColorFilter* filter, SkColor4f color) {
    SkColor key = color.toSkColor();
    auto it = cache_.Get(key);
    if (it != cache_.end())
      return it->second;

    SkColor4f inverted_color = filter->InvertColor(color);
    cache_.Put(key, inverted_color);
    return inverted_color;
  }

  void Clear() { cache_.Clear(); }

  size_t size() { return cache_.size(); }

 private:
  base::HashingLRUCache<SkColor, SkColor4f> cache_;
};

DarkModeFilter::DarkModeFilter(const DarkModeSettings& settings)
    : immutable_(settings),
      inverted_color_cache_(new DarkModeInvertedColorCache()) {}

DarkModeFilter::~DarkModeFilter() {}

DarkModeFilter::ImmutableData::ImmutableData(const DarkModeSettings& settings)
    : settings(settings),
      foreground_classifier(nullptr),
      background_classifier(nullptr),
      image_classifier(nullptr),
      color_filter(nullptr),
      image_filter(nullptr) {
  color_filter = DarkModeColorFilter::FromSettings(settings);
  if (!color_filter)
    return;

  image_filter = color_filter->ToColorFilter();

  foreground_classifier =
      DarkModeColorClassifier::MakeForegroundColorClassifier(settings);
  background_classifier =
      DarkModeColorClassifier::MakeBackgroundColorClassifier(settings);
  image_classifier = std::make_unique<DarkModeImageClassifier>(
      settings.image_classifier_policy);
}

DarkModeImagePolicy DarkModeFilter::GetDarkModeImagePolicy() const {
  return immutable_.settings.image_policy;
}

// Heuristic to maintain contrast for borders and selections (see:
// crbug.com/1263545,crbug.com/1298969)
SkColor4f DarkModeFilter::AdjustDarkenColor(
    const SkColor4f& color,
    DarkModeFilter::ElementRole role,
    const SkColor4f& contrast_background) {
  const SkColor4f& background = [&contrast_background]() {
    if (contrast_background == SkColors::kTransparent)
      return SkColor4f::FromColor(SK_ColorDark);
    else
      return contrast_background;
  }();

  switch (role) {
    case ElementRole::kBorder: {
      if (color == SkColor4f{0.0f, 0.0f, 0.0f, color.fA})
        return color;

      if (color_utils::GetContrastRatio(color, background) <
          color_utils::kMinimumReadableContrastRatio)
        return color;

      return AdjustDarkenColor(Color::FromSkColor4f(color).Dark().toSkColor4f(),
                               role, background);
    }
    case ElementRole::kSelection: {
      if (!immutable_.color_filter)
        return color;

      return immutable_.color_filter->AdjustColorForHigherConstrast(
          color, background, color_utils::kMinimumVisibleContrastRatio);
    }
    default:
      return color;
  }
  NOTREACHED();
}

SkColor4f DarkModeFilter::InvertColorIfNeeded(
    const SkColor4f& color,
    ElementRole role,
    const SkColor4f& contrast_background) {
  return AdjustDarkenColor(
      InvertColorIfNeeded(color, role), role,
      InvertColorIfNeeded(contrast_background, ElementRole::kBackground));
}

SkColor4f DarkModeFilter::InvertColorIfNeeded(const SkColor4f& color,
                                              ElementRole role) {
  if (!immutable_.color_filter)
    return color;

  if (ShouldApplyToColor(color, role)) {
    return inverted_color_cache_->GetInvertedColor(
        immutable_.color_filter.get(), color);
  }

  return color;
}

void DarkModeFilter::ApplyFilterToImage(Image* image,
                                        cc::PaintFlags* flags,
                                        const SkRect& src) {
  DCHECK(image);
  DCHECK(flags);
  DCHECK_NE(GetDarkModeImagePolicy(), DarkModeImagePolicy::kFilterNone);

  if (GetDarkModeImagePolicy() == DarkModeImagePolicy::kFilterAll) {
    flags->setColorFilter(GetImageFilter());
    return;
  }

  // Raster-side dark mode path - Just set the dark mode on flags and dark
  // mode will be applied at compositor side during rasterization.
  if (ShouldUseRasterSidePath(image)) {
    flags->setUseDarkModeForImage(true);
    return;
  }

  // Blink-side dark mode path - Apply dark mode to images in main thread
  // only. If the result is not cached, calling this path is expensive and
  // will block main thread.
  sk_sp<cc::ColorFilter> color_filter =
      GetDarkModeFilterForImageOnMainThread(this, image, src.roundOut());
  if (color_filter)
    flags->setColorFilter(std::move(color_filter));
}

bool DarkModeFilter::ShouldApplyFilterToImage(ImageType type) const {
  DarkModeImagePolicy image_policy = GetDarkModeImagePolicy();
  if (image_policy == DarkModeImagePolicy::kFilterNone)
    return false;
  if (image_policy == DarkModeImagePolicy::kFilterAll)
    return true;

  // kIcon: Do not consider images being drawn into bigger rect as these
  // images are not meant for icons or representing smaller widgets. These
  // images are considered as photos which should be untouched.
  // kSeparator: Images being drawn from very smaller |src| rect, i.e. one of
  // the dimensions is very small, can be used for the border around the content
  // or showing separator. Consider these images irrespective of size of the
  // rect being drawn to. Classifying them will not be too costly.
  return type == ImageType::kIcon || type == ImageType::kSeparator;
}

sk_sp<cc::ColorFilter> DarkModeFilter::GenerateImageFilter(
    const SkPixmap& pixmap,
    const SkIRect& src) const {
  DCHECK(immutable_.settings.image_policy == DarkModeImagePolicy::kFilterSmart);
  DCHECK(immutable_.image_filter);

  return (immutable_.image_classifier->Classify(pixmap, src) ==
          DarkModeResult::kApplyFilter)
             ? immutable_.image_filter
             : nullptr;
}

sk_sp<cc::ColorFilter> DarkModeFilter::GetImageFilter() const {
  DCHECK(immutable_.image_filter);
  return immutable_.image_filter;
}

std::optional<cc::PaintFlags> DarkModeFilter::ApplyToFlagsIfNeeded(
    const cc::PaintFlags& flags,
    ElementRole role,
    SkColor4f contrast_background) {
  if (!immutable_.color_filter || flags.HasShader())
    return std::nullopt;

  cc::PaintFlags dark_mode_flags = flags;
  SkColor4f flags_color = flags.getColor4f();
  if (ShouldApplyToColor(flags_color, role)) {
    flags_color = inverted_color_cache_->GetInvertedColor(
        immutable_.color_filter.get(), flags_color);
  }
  dark_mode_flags.setColor(AdjustDarkenColor(
      flags_color, role,
      InvertColorIfNeeded(contrast_background, ElementRole::kBackground)));

  return std::make_optional<cc::PaintFlags>(std::move(dark_mode_flags));
}

bool DarkModeFilter::ShouldApplyToColor(const SkColor4f& color,
                                        ElementRole role) {
  switch (role) {
    case ElementRole::kBorder:
    case ElementRole::kSVG:
    case ElementRole::kForeground:
    case ElementRole::kListSymbol:
      DCHECK(immutable_.foreground_classifier);
      return immutable_.foreground_classifier->ShouldInvertColor(
                 color.toSkColor()) == DarkModeResult::kApplyFilter;
    case ElementRole::kBackground:
    case ElementRole::kSelection:
      DCHECK(immutable_.background_classifier);
      return immutable_.background_classifier->ShouldInvertColor(
                 color.toSkColor()) == DarkModeResult::kApplyFilter;
    default:
      return false;
  }
  NOTREACHED();
}

size_t DarkModeFilter::GetInvertedColorCacheSizeForTesting() {
  return inverted_color_cache_->size();
}

}  // namespace blink
```