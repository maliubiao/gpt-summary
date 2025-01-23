Response:
Let's break down the thought process for analyzing the `style_fetched_image.cc` file.

1. **Understand the Context:** The first step is always to understand where this file fits within the larger Chromium/Blink project. The path `blink/renderer/core/style/` immediately tells us it's part of the styling engine within the rendering core. The name `style_fetched_image` strongly suggests it deals with images that are fetched from a network or cache and used in styling.

2. **Identify the Core Purpose:**  Reading the initial comments and the class declaration (`class StyleFetchedImage`) gives a high-level understanding. It manages an `ImageResourceContent`, which represents the actual image data. The constructor takes parameters like `is_lazyload_possibly_deferred`, `origin_clean`, and `url`, further reinforcing its role in handling externally loaded images within the styling process.

3. **Analyze Member Variables:** Examining the private member variables provides more details about the class's responsibilities:
    * `image_`:  A pointer to `ImageResourceContent`, the core image data.
    * `document_`:  A pointer to the `Document`, crucial for context and interactions with the DOM.
    * `url_`: The URL of the image.
    * `override_image_resolution_`:  Allows overriding the image's natural resolution.
    * `origin_clean_`, `is_ad_related_`: Metadata about the image's origin and purpose, likely for security or tracking.
    * `is_lazyload_possibly_deferred_`:  Indicates whether the image loading might be deferred for performance.

4. **Go Through the Public Methods:**  This is where the specific functionalities are revealed. For each method, consider:
    * **What it does:**  A brief description of its action.
    * **Parameters and Return Type:**  What information does it need, and what does it provide?
    * **Relationship to other concepts:**  How does this method relate to HTML, CSS, or JavaScript?
    * **Potential side effects or important implications.**

   * **Key Methods and their Implications:**
      * `IsEqual()`:  Important for efficient style updates and caching.
      * `Data()`:  Provides access to the raw image data.
      * `ImageScaleFactor()`:  Handles different pixel densities and overrides. Directly related to responsive design and CSS `image-set`.
      * `CssValue()`: Creates a `CSSImageValue`, linking the fetched image to the CSS representation.
      * `CanRender()`, `IsLoaded()`, `IsLoading()`, `ErrorOccurred()`:  State management of the image loading process. Important for rendering logic and potential error handling.
      * `ImageSize()`, `GetNaturalSizingInfo()`, `HasIntrinsicSize()`: Crucial for layout calculations and how the image occupies space on the page. Directly related to CSS sizing properties.
      * `AddClient()`, `RemoveClient()`:  Manages observers that need to be notified of image loading events.
      * `ImageNotifyFinished()`:  Handles actions when an image finishes loading, potentially triggering JavaScript events and performance measurements.
      * `GetImage()`:  Retrieves the actual `Image` object, potentially with transformations based on context (like SVG scaling).
      * `LoadDeferredImage()`:  Implements lazy loading, a performance optimization technique.

5. **Identify Connections to Web Technologies:** While analyzing methods, actively look for relationships to HTML, CSS, and JavaScript:
    * **HTML:** The image itself is often loaded due to an `<img>` tag or as a background image in CSS. Lazy loading is often tied to the `loading="lazy"` attribute.
    * **CSS:**  The class is deeply intertwined with CSS. It creates `CSSImageValue`, handles image scaling (related to `image-set`, `srcset`), and provides sizing information used in layout (affected by `width`, `height`, `object-fit`, etc.).
    * **JavaScript:** The `ImageNotifyFinished()` method can trigger JavaScript events (through `ImageElementTiming`), and JavaScript can interact with image loading states.

6. **Look for Logic and Assumptions:** Analyze conditional statements and data transformations. For example, the `ImageScaleFactor()` method checks for an override and then for a device pixel ratio header. This reveals an order of precedence in how image scaling is determined.

7. **Consider Potential Errors and Usage Issues:** Think about common mistakes developers might make when dealing with images on the web:
    * Incorrect image paths.
    * Missing CORS headers for cross-origin images.
    * Performance issues with large, unoptimized images.
    * Not handling image loading errors gracefully.
    * Incorrectly using lazy loading.

8. **Structure the Output:** Organize the findings logically, starting with a summary of the file's purpose, then detailing its functionalities, connections to web technologies, and potential issues. Use clear and concise language with examples where appropriate.

9. **Refine and Review:**  Read through the analysis to ensure accuracy, clarity, and completeness. Check for any jargon that needs explanation.

**Self-Correction/Refinement Example During the Process:**

Initially, I might just say "handles image loading." But upon closer inspection of methods like `IsAccessAllowed` and the constructor parameters `origin_clean`, I'd refine that to include the aspect of security and cross-origin resource sharing (CORS). Similarly, just noting `ImageSize()` isn't enough; recognizing its connection to CSS layout and properties like `object-fit` adds more depth. The initial description of `CSSValue()` might be too simplistic; realizing it's the bridge between the internal representation and the CSS syntax is a key refinement.
`blink/renderer/core/style/style_fetched_image.cc` 文件是 Chromium Blink 渲染引擎中的一个核心组件，其主要功能是**管理通过网络或缓存获取的图像资源，并在 CSS 样式系统中使用这些图像。**  它充当了图像资源（`ImageResourceContent`）和 CSS 样式表示（`StyleImage` 的子类）之间的桥梁。

以下是该文件的主要功能列表：

**核心功能:**

1. **封装和管理图像资源:**
   - 持有一个指向 `ImageResourceContent` 对象的指针，该对象负责实际的图像加载、解码和缓存。
   - 维护图像的 URL、是否允许跨域访问、是否与广告相关等元数据。
   - 监听 `ImageResourceContent` 的状态变化（加载完成、出错等）。

2. **提供 CSS 样式系统所需的图像信息:**
   - 实现 `StyleImage` 接口，为 CSS 样式系统提供关于图像的信息，例如：
     - 图像是否已加载 (`IsLoaded`)
     - 图像是否正在加载 (`IsLoading`)
     - 图像加载是否出错 (`ErrorOccurred`)
     - 图像的原始大小 (`ImageSize`) 和自然大小 (`GetNaturalSizingInfo`)
     - 图像的缩放因子 (`ImageScaleFactor`)
     - 是否可以渲染图像 (`CanRender`)
     - 生成代表该图像的 CSS 值 (`CssValue`)

3. **处理图像的缩放和分辨率:**
   - 考虑设备像素比率和可能的覆盖分辨率 (`override_image_resolution_`) 来调整图像的显示大小。
   - 提供 `ApplyImageResolution` 方法来应用分辨率调整。

4. **支持 SVG 图像的特殊处理:**
   - 对于 SVG 图像，会考虑其 `viewBox` 等属性来计算尺寸。
   - 使用 `SVGImageForContainer` 类来处理 SVG 图像的尺寸和渲染。

5. **支持延迟加载 (Lazy Loading):**
   - 通过 `is_lazyload_possibly_deferred_` 标记来处理可能延迟加载的图像。
   - 提供 `LoadDeferredImage` 方法来触发延迟加载。

6. **通知观察者图像加载完成:**
   - 在图像加载完成后，会通知相关的观察者，例如用于性能监控的 `ImageElementTiming`。

**与 JavaScript, HTML, CSS 的关系以及举例说明:**

这个文件在 Blink 渲染引擎中扮演着至关重要的角色，连接了 HTML 中引用的图像资源和 CSS 样式。

**1. 与 CSS 的关系:**

* **背景图片 (background-image):**  当 CSS 规则中设置了 `background-image: url("image.png")` 时，Blink 会解析这个 URL，并创建一个 `StyleFetchedImage` 对象来管理这个图像资源。`StyleFetchedImage::CssValue()` 方法会生成一个 `CSSImageValue` 对象，该对象被 CSS 样式系统用来表示这个背景图片。

   ```html
   <!-- HTML -->
   <div style="background-image: url('my-image.jpg'); width: 200px; height: 100px;"></div>
   ```

   在这个例子中，`StyleFetchedImage` 负责加载 `my-image.jpg`，并为 CSS 样式系统提供其尺寸，以便正确地在 `div` 元素中绘制背景图片。 `ImageSize()` 和 `GetNaturalSizingInfo()` 等方法会被调用来确定图像的尺寸，这会影响背景图片的定位和缩放方式 (例如 `background-size`, `background-repeat`)。

* **`<img>` 标签的 `src` 属性:** 虽然 `<img>` 标签主要由其他类处理（例如 `HTMLImageElement`），但当浏览器需要获取 `src` 属性指向的图像资源时，也会使用类似的机制来加载和管理图像。 `StyleFetchedImage` 提供的功能，例如图像加载状态、尺寸等，也会间接地影响 `<img>` 标签的渲染。

* **CSS 函数 (image()):** CSS 的 `image()` 函数允许使用更复杂的图像引用方式，例如指定备用图像或图像片段。 `StyleFetchedImage` 同样可以用来管理通过 `image()` 函数引用的图像资源。

* **`image-set`:**  `StyleFetchedImage::ImageScaleFactor()` 方法与 CSS 的 `image-set` 属性密切相关。`image-set` 允许为不同的设备像素比率提供不同的图像资源。 `ImageScaleFactor()` 负责确定当前应该使用哪个分辨率的图像。

**2. 与 HTML 的关系:**

* **`<img>` 标签:**  如前所述，尽管不是直接管理 `<img>` 标签的类，但当解析到 `<img>` 标签的 `src` 属性时，会触发图像资源的加载，并可能创建 `StyleFetchedImage` 对象来管理这个过程。
* **`<link rel="preload" as="image">`:**  使用 preload 预加载图像资源时，可能会创建 `StyleFetchedImage` 对象，以便在需要时快速使用这些图像。

**3. 与 JavaScript 的关系:**

* **JavaScript 操作 CSS 样式:** JavaScript 可以通过 DOM API 修改元素的 CSS 样式，例如设置 `element.style.backgroundImage = "url('new-image.png')"`. 当 JavaScript 这样做时，Blink 引擎会创建新的 `StyleFetchedImage` 对象来管理新的图像资源。
* **JavaScript 监听图像加载事件:** JavaScript 可以使用 `<img>` 元素的 `onload` 和 `onerror` 事件来监听图像的加载状态。  虽然 `StyleFetchedImage` 本身不直接触发这些事件，但它管理着图像的加载过程，其内部状态的改变最终会反映到这些事件上。
* **Performance API (例如 `PerformanceObserver`):**  `StyleFetchedImage::ImageNotifyFinished()` 方法会通知 `ImageElementTiming`，而 `ImageElementTiming` 可以与 Performance API 集成，用于记录图像加载的时间，从而让 JavaScript 可以监控页面性能。

**逻辑推理的假设输入与输出:**

**假设输入:**

1. **CSS 规则:** `div { background-image: url("example.png"); width: 100px; height: 100px; }`
2. **`example.png` 的实际尺寸:** 200px x 150px
3. **设备像素比率:** 2

**逻辑推理和输出:**

* **输入 `example.png` 的 URL:**  `StyleFetchedImage` 会接收到 "example.png" 的 URL。
* **加载图像:**  `StyleFetchedImage` 会触发 `ImageResourceContent` 开始加载 "example.png"。
* **获取图像尺寸:**  当图像加载完成后，`StyleFetchedImage::ImageSize()` 会被调用。
* **考虑设备像素比率:** 由于设备像素比率为 2，并且假设没有 `override_image_resolution_`，`ImageScaleFactor()` 会返回 2。
* **计算显示尺寸:**  如果 CSS 中没有指定 `background-size`，那么背景图片的默认显示尺寸可能会受到原始尺寸和容器尺寸的影响。在这种情况下，可能需要进行缩放以适应 100px x 100px 的 `div`。
* **输出到渲染引擎:**  `StyleFetchedImage` 会将图像数据和相关信息传递给渲染引擎，以便在 `div` 中绘制背景图片。

**用户或编程常见的使用错误举例:**

1. **错误的图片路径:**  如果 CSS 中 `background-image` 的 URL 指向一个不存在的图片，`StyleFetchedImage` 会检测到加载错误 (`ErrorOccurred()` 返回 true)。这将导致背景图片无法显示。

   ```css
   /* 错误：图片路径不存在 */
   div { background-image: url("non-existent-image.jpg"); }
   ```

2. **CORS 问题:**  如果图片资源位于不同的域名下，并且服务器没有设置正确的 CORS 头信息 (`Access-Control-Allow-Origin`)，浏览器会阻止跨域访问。 `StyleFetchedImage::IsAccessAllowed()` 会返回 false，即使图片可能已经加载完成。

   ```html
   <!-- HTML，图片位于不同的域名 example.com 下 -->
   <img src="https://example.com/image.png">
   ```

   如果 `example.com` 的服务器没有设置允许当前域访问的 CORS 头，图片将无法正常显示。

3. **大型未优化图片导致性能问题:**  使用过大的图片会消耗大量的内存和带宽，导致页面加载缓慢。 `StyleFetchedImage` 负责管理这些图像，但它本身并不会自动优化图片。 开发者需要负责提供优化过的图片。

4. **不正确的 `background-size` 使用:**  如果 `background-size` 设置不当，可能会导致图片变形或显示不全。`StyleFetchedImage` 提供的图像尺寸信息是正确渲染的基础，但开发者需要正确使用 CSS 属性来控制背景图片的显示方式。

5. **懒加载配置错误:**  如果开发者尝试使用 JavaScript 实现懒加载，但与浏览器内置的懒加载机制冲突，或者配置不正确，可能会导致图片无法按预期加载。 `StyleFetchedImage` 中的懒加载支持需要与其他部分的逻辑协同工作。

总而言之，`blink/renderer/core/style/style_fetched_image.cc` 是 Blink 渲染引擎中处理图像资源的核心组件，它连接了图像数据和 CSS 样式系统，负责加载、管理、并提供图像的相关信息，以便浏览器能够正确地渲染网页。 开发者在使用 HTML、CSS 和 JavaScript 操作图像时，其背后的图像加载和管理逻辑都与这个文件息息相关。

### 提示词
```
这是目录为blink/renderer/core/style/style_fetched_image.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2000 Lars Knoll (knoll@kde.org)
 *           (C) 2000 Antti Koivisto (koivisto@kde.org)
 *           (C) 2000 Dirk Mueller (mueller@kde.org)
 * Copyright (C) 2003, 2005, 2006, 2007, 2008 Apple Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/style/style_fetched_image.h"

#include "third_party/blink/renderer/core/css/css_image_value.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource_content.h"
#include "third_party/blink/renderer/core/paint/timing/image_element_timing.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/svg/graphics/svg_image_for_container.h"
#include "third_party/blink/renderer/platform/graphics/bitmap_image.h"

namespace blink {

StyleFetchedImage::StyleFetchedImage(ImageResourceContent* image,
                                     const Document& document,
                                     bool is_lazyload_possibly_deferred,
                                     bool origin_clean,
                                     bool is_ad_related,
                                     const KURL& url,
                                     const float override_image_resolution)
    : document_(document),
      url_(url),
      override_image_resolution_(override_image_resolution),
      origin_clean_(origin_clean),
      is_ad_related_(is_ad_related) {
  is_image_resource_ = true;
  is_lazyload_possibly_deferred_ = is_lazyload_possibly_deferred;

  image_ = image;
  image_->AddObserver(this);
  // ResourceFetcher is not determined from StyleFetchedImage and it is
  // impossible to send a request for refetching.
  image_->SetNotRefetchableDataFromDiskCache();
}

StyleFetchedImage::~StyleFetchedImage() = default;

void StyleFetchedImage::Prefinalize() {
  image_->DidRemoveObserver();
  image_ = nullptr;
}

bool StyleFetchedImage::IsEqual(const StyleImage& other) const {
  if (other.IsPendingImage()) {
    // Ignore pending status when comparing; as long as the values are
    // equal, the same, the images should be considered equal, too.
    return base::ValuesEquivalent(CssValue(), other.CssValue());
  }
  if (!other.IsImageResource()) {
    return false;
  }

  const auto& other_image = To<StyleFetchedImage>(other);

  return image_ == other_image.image_ && url_ == other_image.url_ &&
         EqualResolutions(override_image_resolution_,
                          other_image.override_image_resolution_);
}

WrappedImagePtr StyleFetchedImage::Data() const {
  return image_.Get();
}

float StyleFetchedImage::ImageScaleFactor() const {
  if (override_image_resolution_ > 0.0f) {
    return override_image_resolution_;
  }

  if (image_->HasDevicePixelRatioHeaderValue()) {
    return image_->DevicePixelRatioHeaderValue();
  }

  return 1.0f;
}

ImageResourceContent* StyleFetchedImage::CachedImage() const {
  return image_.Get();
}

CSSValue* StyleFetchedImage::CssValue() const {
  return MakeGarbageCollected<CSSImageValue>(
      CSSUrlData(AtomicString(url_.GetString()), url_, Referrer(),
                 origin_clean_ ? OriginClean::kTrue : OriginClean::kFalse,
                 is_ad_related_),
      const_cast<StyleFetchedImage*>(this));
}

CSSValue* StyleFetchedImage::ComputedCSSValue(const ComputedStyle&,
                                              bool allow_visited_style,
                                              CSSValuePhase value_phase) const {
  return CssValue();
}

bool StyleFetchedImage::CanRender() const {
  return !image_->ErrorOccurred() && !image_->GetImage()->IsNull();
}

bool StyleFetchedImage::IsLoaded() const {
  return image_->IsLoaded();
}

bool StyleFetchedImage::IsLoading() const {
  return image_->IsLoading();
}

bool StyleFetchedImage::ErrorOccurred() const {
  return image_->ErrorOccurred();
}

bool StyleFetchedImage::IsAccessAllowed(String& failing_url) const {
  DCHECK(image_->IsLoaded());
  if (image_->IsAccessAllowed()) {
    return true;
  }
  failing_url = image_->Url().ElidedString();
  return false;
}

float StyleFetchedImage::ApplyImageResolution(float multiplier) const {
  const Image& image = *image_->GetImage();
  if (image.IsBitmapImage() && override_image_resolution_ > 0.0f) {
    multiplier /= override_image_resolution_;
  } else if (image_->HasDevicePixelRatioHeaderValue()) {
    multiplier /= image_->DevicePixelRatioHeaderValue();
  }
  return multiplier;
}

gfx::SizeF StyleFetchedImage::ImageSize(
    float multiplier,
    const gfx::SizeF& default_object_size,
    RespectImageOrientationEnum respect_orientation) const {
  multiplier = ApplyImageResolution(multiplier);

  Image& image = *image_->GetImage();
  gfx::SizeF size;
  if (auto* svg_image = DynamicTo<SVGImage>(image)) {
    const SVGImageViewInfo* view_info =
        SVGImageForContainer::CreateViewInfo(*svg_image, url_);
    const gfx::SizeF unzoomed_default_object_size =
        gfx::ScaleSize(default_object_size, 1 / multiplier);
    size = SVGImageForContainer::ConcreteObjectSize(
        *svg_image, view_info, unzoomed_default_object_size);
  } else {
    size = gfx::SizeF(
        image.Size(ForceOrientationIfNecessary(respect_orientation)));
  }
  return ApplyZoom(size, multiplier);
}

IntrinsicSizingInfo StyleFetchedImage::GetNaturalSizingInfo(
    float multiplier,
    RespectImageOrientationEnum respect_orientation) const {
  Image& image = *image_->GetImage();
  IntrinsicSizingInfo intrinsic_sizing_info;
  if (auto* svg_image = DynamicTo<SVGImage>(image)) {
    const SVGImageViewInfo* view_info =
        SVGImageForContainer::CreateViewInfo(*svg_image, url_);
    if (!SVGImageForContainer::GetNaturalDimensions(*svg_image, view_info,
                                                    intrinsic_sizing_info)) {
      intrinsic_sizing_info = IntrinsicSizingInfo::None();
    }
  } else {
    gfx::SizeF size(
        image.Size(ForceOrientationIfNecessary(respect_orientation)));
    intrinsic_sizing_info.size = size;
    intrinsic_sizing_info.aspect_ratio = size;
  }

  multiplier = ApplyImageResolution(multiplier);
  intrinsic_sizing_info.size =
      ApplyZoom(intrinsic_sizing_info.size, multiplier);
  return intrinsic_sizing_info;
}

bool StyleFetchedImage::HasIntrinsicSize() const {
  Image& image = *image_->GetImage();
  if (auto* svg_image = DynamicTo<SVGImage>(image)) {
    IntrinsicSizingInfo intrinsic_sizing_info;
    const SVGImageViewInfo* view_info =
        SVGImageForContainer::CreateViewInfo(*svg_image, url_);
    if (!SVGImageForContainer::GetNaturalDimensions(*svg_image, view_info,
                                                    intrinsic_sizing_info)) {
      return false;
    }
    return !intrinsic_sizing_info.IsNone();
  }
  return image.HasIntrinsicSize();
}

void StyleFetchedImage::AddClient(ImageResourceObserver* observer) {
  image_->AddObserver(observer);
}

void StyleFetchedImage::RemoveClient(ImageResourceObserver* observer) {
  image_->RemoveObserver(observer);
}

void StyleFetchedImage::ImageNotifyFinished(ImageResourceContent*) {
  if (!document_) {
    return;
  }

  if (image_ && image_->HasImage()) {
    Image& image = *image_->GetImage();

    if (auto* svg_image = DynamicTo<SVGImage>(image)) {
      // Check that the SVGImage has completed loading (i.e the 'load' event
      // has been dispatched in the SVG document).
      svg_image->CheckLoaded();
      svg_image->UpdateUseCounters(*document_);
      svg_image->MaybeRecordSvgImageProcessingTime(*document_);
    }
    image_->RecordDecodedImageType(document_->GetExecutionContext());
  }

  if (LocalDOMWindow* window = document_->domWindow()) {
    ImageElementTiming::From(*window).NotifyBackgroundImageFinished(this);
  }

  // Oilpan: do not prolong the Document's lifetime.
  document_.Clear();
}

scoped_refptr<Image> StyleFetchedImage::GetImage(
    const ImageResourceObserver&,
    const Document& document,
    const ComputedStyle& style,
    const gfx::SizeF& target_size) const {
  Image* image = image_->GetImage();
  auto* svg_image = DynamicTo<SVGImage>(image);
  if (!svg_image) {
    return image;
  }
  const SVGImageViewInfo* view_info =
      SVGImageForContainer::CreateViewInfo(*svg_image, url_);
  return SVGImageForContainer::Create(
      *svg_image, target_size, style.EffectiveZoom(), view_info,
      document.GetStyleEngine().ResolveColorSchemeForEmbedding(&style));
}

bool StyleFetchedImage::KnownToBeOpaque(const Document&,
                                        const ComputedStyle&) const {
  return image_->GetImage()->CurrentFrameKnownToBeOpaque();
}

void StyleFetchedImage::LoadDeferredImage(const Document& document) {
  DCHECK(is_lazyload_possibly_deferred_);
  is_lazyload_possibly_deferred_ = false;
  document_ = &document;
  image_->LoadDeferredImage(document_->Fetcher());
}

RespectImageOrientationEnum StyleFetchedImage::ForceOrientationIfNecessary(
    RespectImageOrientationEnum default_orientation) const {
  // SVG Images don't have orientation and assert on loading when
  // IsAccessAllowed is called.
  if (image_->GetImage()->IsSVGImage()) {
    return default_orientation;
  }
  // Cross-origin images must always respect orientation to prevent
  // potentially private data leakage.
  if (!image_->IsAccessAllowed()) {
    return kRespectImageOrientation;
  }
  return default_orientation;
}

bool StyleFetchedImage::GetImageAnimationPolicy(
    mojom::blink::ImageAnimationPolicy& policy) {
  if (!document_ || !document_->GetSettings()) {
    return false;
  }
  policy = document_->GetSettings()->GetImageAnimationPolicy();
  return true;
}

void StyleFetchedImage::Trace(Visitor* visitor) const {
  visitor->Trace(image_);
  visitor->Trace(document_);
  StyleImage::Trace(visitor);
  ImageResourceObserver::Trace(visitor);
}

}  // namespace blink
```