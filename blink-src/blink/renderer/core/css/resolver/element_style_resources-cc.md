Response:
Let's break down the thought process to answer the user's request about `element_style_resources.cc`.

1. **Understand the Core Request:** The user wants to know the *functionality* of the file, its relationship to web technologies (JavaScript, HTML, CSS), examples, potential errors, and how one might end up debugging it.

2. **Initial Scan for Keywords and Includes:**  Look at the `#include` directives and the overall structure. This immediately reveals key areas:
    * **CSS:**  `css_crossfade_value.h`, `css_gradient_value.h`, `css_image_value.h`, `css_paint_value.h`, `css_property_names.h`, `css_uri_value.h`. This strongly suggests a connection to CSS processing.
    * **DOM:** `document.h`, `element.h`, `tree_scope.h`. Indicates interaction with the Document Object Model.
    * **Style:** `computed_style.h`, `content_data.h`, `cursor_data.h`, `fill_layer.h`, `style_image.h`, etc. This is a central theme – managing styles.
    * **Loading/Fetching:** `lazy_image_helper.h`, `resource_fetcher.h`. Points to how external resources are handled.
    * **SVG:** `svg_tree_scope_resources.h`. Indicates SVG support.

3. **Identify Key Classes and Methods:**  The file defines the `ElementStyleResources` class and a nested `StyleImageLoader`. This suggests two main actors in the process. The methods within these classes (e.g., `IsPending`, `CachedStyleImage`, `GetStyleImage`, `LoadPendingImages`, `LoadPendingSVGResources`) are clues to the specific actions being performed.

4. **Formulate a High-Level Functionality Summary:** Based on the includes and class names, the file likely deals with resolving and loading resources (images, SVG) referenced in CSS styles applied to an HTML element. It seems to handle caching, pending states, and different types of CSS values (images, gradients, cross-fades).

5. **Connect to Web Technologies (HTML, CSS, JavaScript):**

    * **CSS:** This is the most direct connection. The file processes CSS values for properties like `background-image`, `content`, `cursor`, `mask-image`, etc. Think about how CSS selectors target HTML elements and apply styles.
    * **HTML:** The `Element& element_` member indicates a direct link to HTML elements. The styles being resolved are applied *to* these elements.
    * **JavaScript:** While the file itself isn't JavaScript, JavaScript often manipulates the DOM and CSS styles. Changes made through JavaScript (e.g., setting `element.style.backgroundImage`) can trigger the logic in this file.

6. **Develop Concrete Examples:** For each web technology connection, come up with short, illustrative code snippets:

    * **CSS:** Show how different CSS properties reference image URLs, gradients, and `paint()` functions.
    * **HTML:** Demonstrate a simple HTML structure where CSS is applied to elements.
    * **JavaScript:**  Show how JavaScript can modify styles that would be processed by this file.

7. **Consider Logic and Data Flow (Hypothetical Input/Output):**

    * **Input:** A CSS property with a resource (e.g., `background-image: url("image.png")`).
    * **Processing:** The `ElementStyleResources` would identify the resource, check its cache status, potentially initiate a load, and create a `StyleImage` object.
    * **Output:** A `StyleImage` object (or a `StylePendingImage` if loading) associated with the element's style.

8. **Identify Potential User/Programming Errors:** Think about common mistakes developers make related to CSS resources:

    * **Incorrect URLs:** Leading to 404 errors.
    * **CORS issues:** When accessing resources from different origins.
    * **Missing resources:** Forgetting to include an image file.
    * **Typos in CSS properties or values.**

9. **Outline Debugging Scenarios:** How would a developer end up looking at this code?

    * **Visual issues:** Images not loading, incorrect rendering.
    * **Performance problems:** Slow loading of resources.
    * **Crashes:**  Although less frequent in this specific file, issues in related resource loading could lead here.
    * **Specific CSS features not working:**  Investigating why a certain image or mask isn't being applied correctly.
    * **Following the call stack:**  When debugging a style-related problem, the execution might lead into this file.

10. **Structure the Answer:** Organize the information logically, using headings and bullet points for clarity. Start with the overall functionality, then delve into specific aspects, examples, and debugging.

11. **Refine and Elaborate:** Review the answer for completeness and accuracy. Add details where necessary. For example, explain the role of the `StyleImageLoader` class more explicitly. Ensure the examples are clear and easy to understand.

By following this systematic approach, considering the code's purpose, its interactions with web technologies, and potential issues, a comprehensive and helpful answer can be constructed.
这个文件 `element_style_resources.cc` 是 Chromium Blink 引擎中负责**管理和加载与特定 HTML 元素相关的 CSS 样式资源**的关键组件。它主要处理以下功能：

**1. 解析和管理 CSS 资源：**

* **识别 CSS 值中的资源引用：**  当解析 CSS 样式时，该文件负责识别可能需要加载外部资源的 CSS 属性值，例如 `background-image`, `content`, `cursor`, `mask-image`, `clip-path` 等。这些值可能包含 URL（指向图片、SVG 文件等）或函数调用（如 `url()`, `image-set()`, `paint()`, `cross-fade()`, `linear-gradient()` 等）。
* **创建资源对象：**  根据识别出的资源类型，创建相应的内部表示对象，例如 `StyleImage` (用于图片), `StyleGeneratedImage` (用于渐变), `StylePendingImage` (用于正在加载中的图片), `SVGResource` (用于 SVG 文件)。
* **缓存资源：**  管理已加载的资源缓存，避免重复加载相同的资源，提高性能。
* **处理不同类型的 CSS 值：**  针对不同类型的 CSS 值（例如 `CSSImageValue`, `CSSGradientValue`, `CSSPaintValue`, `CSSCrossfadeValue`, `CSSImageSetValue`），提供特定的处理逻辑来提取和加载资源。

**2. 异步加载资源：**

* **处理待加载状态：**  对于需要异步加载的资源（例如图片），该文件会标记这些资源为“待加载”状态 (`StylePendingImage`)，并在资源加载完成后更新状态。
* **触发资源加载：**  与资源加载器 (ResourceFetcher) 交互，发起网络请求来获取外部资源。
* **处理跨域请求：**  考虑跨域资源请求 (CORS) 的情况，设置合适的请求头。
* **处理懒加载：**  对于某些可以懒加载的资源（例如 `background-image`），会配合 `LazyImageHelper` 进行管理。

**3. 与 HTML, CSS, JavaScript 的关系：**

* **CSS：** 该文件是 CSS 样式解析和应用流程中的核心环节。它直接处理 CSS 属性值，并根据这些值加载相应的资源。
    * **例子：** 当浏览器解析到以下 CSS 规则时：
        ```css
        .my-element {
          background-image: url("image.png");
          mask-image: url("mask.svg");
          cursor: url("custom_cursor.cur"), auto;
        }
        ```
        `element_style_resources.cc` 会识别 `background-image`, `mask-image`, `cursor` 属性中的 URL，并尝试加载 `image.png`, `mask.svg`, 和 `custom_cursor.cur`。
* **HTML：** 该文件处理的是应用于 HTML 元素的 CSS 样式。它接收一个 `Element` 对象作为输入，并根据该元素应用的样式加载资源。
    * **例子：**  考虑以下 HTML 结构：
        ```html
        <div class="my-element"></div>
        ```
        当浏览器渲染这个 `div` 元素时，会查找应用于它的 CSS 规则（如上面的例子），然后 `element_style_resources.cc` 会处理这些规则中引用的资源。
* **JavaScript：** JavaScript 可以动态修改元素的样式，这些修改可能会触发 `element_style_resources.cc` 的工作。
    * **例子：**  以下 JavaScript 代码会改变元素的背景图片：
        ```javascript
        const element = document.querySelector('.my-element');
        element.style.backgroundImage = 'url("new_image.jpg")';
        ```
        这个操作会导致 `element_style_resources.cc` 尝试加载 `new_image.jpg`。

**4. 逻辑推理 (假设输入与输出)：**

**假设输入：**

* 一个 `Element` 对象，表示一个 HTML `<div>` 元素。
* 该元素的 `ComputedStyle` 对象，其中 `background-image` 属性的值为 `url("my-bg.png")`， `mask-image` 属性的值为 `image-set(url("small.png") 1x, url("large.png") 2x)`.

**输出：**

* `element_style_resources.cc` 会创建一个 `StyleImage` 对象来表示 `my-bg.png`。
* 它会创建一个 `StyleImageSet` 对象来表示 `image-set()`，该对象会包含针对不同设备像素比率的 `StyleImage` 对象（分别对应 `small.png` 和 `large.png`）。
* 如果资源尚未加载，会创建 `StylePendingImage` 对象，并触发 `my-bg.png`, `small.png`, 和 `large.png` 的加载。

**5. 用户或编程常见的使用错误：**

* **拼写错误的 URL：** 用户在 CSS 中指定的图片或 SVG 文件的 URL 拼写错误，导致资源加载失败。浏览器通常会在控制台中显示 404 错误。
    * **例子：** `background-image: url("mispelled_image.png");`
* **CORS 配置错误：**  尝试加载来自不同域名的资源，但目标服务器没有正确配置 CORS 头，导致浏览器阻止加载。
    * **例子：**  在 CSS 中引用了另一个域名下的图片，但该服务器没有设置 `Access-Control-Allow-Origin` 头。
* **资源文件不存在：**  CSS 中引用的图片或 SVG 文件实际上不存在于服务器上，导致 404 错误。
* **使用了不支持的 CSS 图片类型或函数：**  虽然该文件处理多种图片类型，但仍然可能存在不支持的情况。
* **在 `paint()` 函数中使用了错误的 Painter 名称：** 如果 CSS 中使用了 `paint()` 函数，但指定的 Painter 名称在渲染引擎中不存在，则会导致错误。

**6. 用户操作如何一步步地到达这里（调试线索）：**

假设用户发现一个网页上的背景图片没有显示出来。以下是可能的调试步骤，最终可能会涉及到 `element_style_resources.cc`：

1. **用户打开网页，发现背景图片缺失。**
2. **用户打开浏览器的开发者工具 (DevTools)。**
3. **用户检查元素的样式 (Elements 面板)。**
4. **用户找到应用了 `background-image` 属性的元素。**
5. **用户查看 `background-image` 属性的值，确认 URL 是否正确。**
6. **用户可以查看 "Network" 面板，检查该 URL 的资源加载状态。** 如果状态码是 404，则说明资源不存在或 URL 错误。如果状态码是其他错误（例如 CORS 相关），则问题可能在于服务器配置。
7. **如果 Network 面板显示资源请求被发起，但最终失败，开发者可能会怀疑资源加载过程中的某个环节出了问题。**
8. **在 Chromium 的源代码中，如果开发者想深入了解 CSS 资源是如何被加载的，他们可能会追踪 `background-image` 属性的处理流程。** 这会涉及到 CSS 样式解析器，样式计算，最终会到达 `element_style_resources.cc` 中的相关函数，例如 `GetStyleImage` 或 `LoadPendingImages`。
9. **开发者可能会设置断点在 `element_style_resources.cc` 中，观察 `StyleImageLoader` 如何处理 `background-image` 的 URL，以及如何创建和加载 `StyleImage` 对象。**
10. **如果怀疑是跨域问题，开发者可能会查看 `CrossOriginAttributeValue` 的值，以及资源加载器是如何处理跨域请求的。**
11. **如果使用了 `image-set()`，开发者可能会检查 `ResolveImageSet` 函数，了解它是如何根据设备像素比率选择合适的图片的。**

总而言之，`element_style_resources.cc` 是 Blink 引擎中一个核心的 CSS 资源管理模块，它负责连接 CSS 样式定义和实际的资源加载，是理解和调试网页样式相关问题的关键部分。

Prompt: 
```
这是目录为blink/renderer/core/css/resolver/element_style_resources.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011 Apple Inc.
 * All rights reserved.
 * Copyright (C) 2013 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/css/resolver/element_style_resources.h"

#include "third_party/blink/renderer/core/css/css_crossfade_value.h"
#include "third_party/blink/renderer/core/css/css_gradient_value.h"
#include "third_party/blink/renderer/core/css/css_image_set_option_value.h"
#include "third_party/blink/renderer/core/css/css_image_set_value.h"
#include "third_party/blink/renderer/core/css/css_image_value.h"
#include "third_party/blink/renderer/core/css/css_paint_value.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/css_to_length_conversion_data.h"
#include "third_party/blink/renderer/core/css/css_uri_value.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/tree_scope.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/loader/lazy_image_helper.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/content_data.h"
#include "third_party/blink/renderer/core/style/cursor_data.h"
#include "third_party/blink/renderer/core/style/fill_layer.h"
#include "third_party/blink/renderer/core/style/filter_operation.h"
#include "third_party/blink/renderer/core/style/reference_clip_path_operation.h"
#include "third_party/blink/renderer/core/style/style_crossfade_image.h"
#include "third_party/blink/renderer/core/style/style_fetched_image.h"
#include "third_party/blink/renderer/core/style/style_generated_image.h"
#include "third_party/blink/renderer/core/style/style_image.h"
#include "third_party/blink/renderer/core/style/style_image_set.h"
#include "third_party/blink/renderer/core/style/style_mask_source_image.h"
#include "third_party/blink/renderer/core/style/style_pending_image.h"
#include "third_party/blink/renderer/core/style/style_svg_resource.h"
#include "third_party/blink/renderer/core/svg/svg_tree_scope_resources.h"
#include "third_party/blink/renderer/platform/geometry/length.h"
#include "third_party/blink/renderer/platform/loader/fetch/cross_origin_attribute_value.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_parameters.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"

namespace blink {

namespace {

class StyleImageLoader {
  STACK_ALLOCATED();

 public:
  using ContainerSizes = CSSToLengthConversionData::ContainerSizes;

  StyleImageLoader(Document& document,
                   ComputedStyleBuilder& builder,
                   const PreCachedContainerSizes& pre_cached_container_sizes,
                   float device_scale_factor)
      : document_(document),
        builder_(builder),
        pre_cached_container_sizes_(pre_cached_container_sizes),
        device_scale_factor_(device_scale_factor) {}

  StyleImage* Load(CSSValue&,
                   FetchParameters::ImageRequestBehavior =
                       FetchParameters::ImageRequestBehavior::kNone,
                   CrossOriginAttributeValue = kCrossOriginAttributeNotSet,
                   const float override_image_resolution = 0.0f);

 private:
  StyleImage* CrossfadeArgument(CSSValue&, CrossOriginAttributeValue);
  StyleImage* ResolveImageSet(CSSImageSetValue& image_set_value,
                              FetchParameters::ImageRequestBehavior,
                              CrossOriginAttributeValue);

  Document& document_;
  ComputedStyleBuilder& builder_;
  const PreCachedContainerSizes& pre_cached_container_sizes_;
  const float device_scale_factor_;
};

StyleImage* StyleImageLoader::Load(
    CSSValue& value,
    FetchParameters::ImageRequestBehavior image_request_behavior,
    CrossOriginAttributeValue cross_origin,
    const float override_image_resolution) {
  if (auto* image_value = DynamicTo<CSSImageValue>(value)) {
    return image_value->CacheImage(document_, image_request_behavior,
                                   cross_origin, override_image_resolution);
  }

  if (auto* paint_value = DynamicTo<CSSPaintValue>(value)) {
    auto* image = MakeGarbageCollected<StyleGeneratedImage>(*paint_value,
                                                            ContainerSizes());
    builder_.AddPaintImage(image);
    return image;
  }

  if (auto* crossfade_value = DynamicTo<cssvalue::CSSCrossfadeValue>(value)) {
    HeapVector<Member<StyleImage>> style_images;
    for (const auto& [image, percentage] :
         crossfade_value->GetImagesAndPercentages()) {
      style_images.push_back(CrossfadeArgument(*image, cross_origin));
    }
    return MakeGarbageCollected<StyleCrossfadeImage>(*crossfade_value,
                                                     std::move(style_images));
  }

  if (auto* image_gradient_value =
          DynamicTo<cssvalue::CSSGradientValue>(value)) {
    const ContainerSizes& container_sizes =
        image_gradient_value->IsUsingContainerRelativeUnits()
            ? pre_cached_container_sizes_.Get()
            : ContainerSizes();
    return MakeGarbageCollected<StyleGeneratedImage>(*image_gradient_value,
                                                     container_sizes);
  }

  if (auto* image_set_value = DynamicTo<CSSImageSetValue>(value)) {
    StyleImage* style_image =
        ResolveImageSet(*image_set_value, image_request_behavior, cross_origin);
    return image_set_value->CacheImage(
        style_image, device_scale_factor_,
        style_image ? style_image->IsOriginClean() : true);
  }

  NOTREACHED();
}

StyleImage* StyleImageLoader::CrossfadeArgument(
    CSSValue& value,
    CrossOriginAttributeValue cross_origin) {
  // TODO(crbug.com/614906): For some reason we allow 'none' as an argument to
  // -webkit-cross-fade() - the unprefixed cross-fade() function does however
  // not accept 'none'. Map 'none' to a null StyleImage.
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kNone);
    return nullptr;
  }
  // Reject paint() functions. They make assumptions about the client (being
  // a LayoutObject) that we can't meet with the current implementation.
  if (IsA<CSSPaintValue>(value)) {
    return nullptr;
  }
  return Load(value, FetchParameters::ImageRequestBehavior::kNone,
              cross_origin);
}

StyleImage* StyleImageLoader::ResolveImageSet(
    CSSImageSetValue& image_set_value,
    FetchParameters::ImageRequestBehavior image_request_behavior,
    CrossOriginAttributeValue cross_origin) {
  const CSSImageSetOptionValue* option =
      image_set_value.GetBestOption(device_scale_factor_);
  if (!option) {
    return nullptr;
  }
  CSSValue& image_value = option->GetImage();
  // Artificially reject types that are not "supported".
  if (!IsA<CSSImageValue>(image_value) &&
      !IsA<cssvalue::CSSGradientValue>(image_value)) {
    return nullptr;
  }
  return Load(image_value, image_request_behavior, cross_origin,
              option->ComputedResolution());
}

}  // namespace

const PreCachedContainerSizes::ContainerSizes& PreCachedContainerSizes::Get()
    const {
  if (!cache_) {
    if (conversion_data_) {
      cache_ = conversion_data_->PreCachedContainerSizesCopy();
    } else {
      cache_ = ContainerSizes();
    }
  }
  return *cache_;
}

ElementStyleResources::ElementStyleResources(Element& element,
                                             float device_scale_factor)
    : element_(element), device_scale_factor_(device_scale_factor) {}

bool ElementStyleResources::IsPending(const CSSValue& value) const {
  if (auto* img_value = DynamicTo<CSSImageValue>(value)) {
    return img_value->IsCachePending();
  }

  // paint(...) is always treated as pending because it needs to call
  // AddPaintImage() on the ComputedStyle.
  if (IsA<CSSPaintValue>(value)) {
    return true;
  }

  // cross-fade(...) is always treated as pending (to avoid adding more complex
  // recursion).
  if (IsA<cssvalue::CSSCrossfadeValue>(value)) {
    return true;
  }

  // Gradient functions are never pending.
  if (IsA<cssvalue::CSSGradientValue>(value)) {
    return false;
  }

  if (auto* img_set_value = DynamicTo<CSSImageSetValue>(value)) {
    return img_set_value->IsCachePending(device_scale_factor_);
  }

  NOTREACHED();
}

StyleImage* ElementStyleResources::CachedStyleImage(
    const CSSValue& value) const {
  DCHECK(!IsPending(value));
  if (auto* img_value = DynamicTo<CSSImageValue>(value)) {
    img_value->RestoreCachedResourceIfNeeded(element_.GetDocument());
    return img_value->CachedImage();
  }

  // Gradient functions are never pending (but don't cache StyleImages).
  if (auto* gradient_value = DynamicTo<cssvalue::CSSGradientValue>(value)) {
    using ContainerSizes = CSSToLengthConversionData::ContainerSizes;
    const ContainerSizes& container_sizes =
        gradient_value->IsUsingContainerRelativeUnits()
            ? pre_cached_container_sizes_.Get()
            : ContainerSizes();
    return MakeGarbageCollected<StyleGeneratedImage>(*gradient_value,
                                                     container_sizes);
  }

  if (auto* img_set_value = DynamicTo<CSSImageSetValue>(value)) {
    return img_set_value->CachedImage(device_scale_factor_);
  }

  NOTREACHED();
}

StyleImage* ElementStyleResources::GetStyleImage(CSSPropertyID property,
                                                 const CSSValue& value) {
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kNone);
    return nullptr;
  }
  if (IsPending(value)) {
    pending_image_properties_.insert(property);
    return MakeGarbageCollected<StylePendingImage>(value);
  }
  return CachedStyleImage(value);
}

static bool AllowExternalResources(CSSPropertyID property) {
  if (RuntimeEnabledFeatures::SvgExternalResourcesEnabled()) {
    if (property == CSSPropertyID::kClipPath ||
        property == CSSPropertyID::kFill ||
        property == CSSPropertyID::kMarkerEnd ||
        property == CSSPropertyID::kMarkerMid ||
        property == CSSPropertyID::kMarkerStart ||
        property == CSSPropertyID::kStroke) {
      return true;
    }
  }
  return property == CSSPropertyID::kBackdropFilter ||
         property == CSSPropertyID::kFilter;
}

SVGResource* ElementStyleResources::GetSVGResourceFromValue(
    CSSPropertyID property,
    const cssvalue::CSSURIValue& value) {
  if (value.IsLocal(element_.GetDocument())) {
    SVGTreeScopeResources& tree_scope_resources =
        element_.OriginatingTreeScope().EnsureSVGTreeScopedResources();
    return tree_scope_resources.ResourceForId(
        value.NormalizedFragmentIdentifier());
  }
  if (AllowExternalResources(property)) {
    pending_svg_resource_properties_.insert(property);
    return value.EnsureResourceReference();
  }
  return nullptr;
}

static void LoadResourcesForFilter(
    FilterOperations::FilterOperationVector& filter_operations,
    Document& document) {
  for (const auto& filter_operation : filter_operations) {
    auto* reference_operation =
        DynamicTo<ReferenceFilterOperation>(filter_operation.Get());
    if (!reference_operation) {
      continue;
    }
    if (SVGResource* resource = reference_operation->Resource()) {
      resource->Load(document, kCrossOriginAttributeNotSet);
    }
  }
}

static SVGResource* GetSVGResourceOrNull(StyleSVGResource* style_resource) {
  return style_resource ? style_resource->Resource() : nullptr;
}

static SVGResource* GetSingleSVGResource(CSSPropertyID property,
                                         ComputedStyleBuilder& builder) {
  CHECK(RuntimeEnabledFeatures::SvgExternalResourcesEnabled());
  switch (property) {
    case CSSPropertyID::kClipPath: {
      auto* reference_clip =
          DynamicTo<ReferenceClipPathOperation>(builder.MutableClipPath());
      return reference_clip ? reference_clip->Resource() : nullptr;
    }
    case CSSPropertyID::kFill:
      return GetSVGResourceOrNull(builder.FillPaint().Resource());
    case CSSPropertyID::kMarkerEnd:
      return GetSVGResourceOrNull(builder.MarkerEndResource());
    case CSSPropertyID::kMarkerMid:
      return GetSVGResourceOrNull(builder.MarkerMidResource());
    case CSSPropertyID::kMarkerStart:
      return GetSVGResourceOrNull(builder.MarkerStartResource());
    case CSSPropertyID::kStroke:
      return GetSVGResourceOrNull(builder.StrokePaint().Resource());
    default:
      NOTREACHED();
  }
}

void ElementStyleResources::LoadPendingSVGResources(
    ComputedStyleBuilder& builder) {
  Document& document = element_.GetDocument();
  for (CSSPropertyID property : pending_svg_resource_properties_) {
    switch (property) {
      case CSSPropertyID::kBackdropFilter:
        LoadResourcesForFilter(builder.MutableBackdropFilterOperations(),
                               document);
        break;
      case CSSPropertyID::kFilter:
        LoadResourcesForFilter(builder.MutableFilterOperations(), document);
        break;
      case CSSPropertyID::kClipPath:
      case CSSPropertyID::kFill:
      case CSSPropertyID::kMarkerEnd:
      case CSSPropertyID::kMarkerMid:
      case CSSPropertyID::kMarkerStart:
      case CSSPropertyID::kStroke:
        if (SVGResource* resource = GetSingleSVGResource(property, builder)) {
          resource->Load(document, kCrossOriginAttributeAnonymous);
        }
        break;
      default:
        NOTREACHED();
    }
  }
}

static CSSValue* PendingCssValue(StyleImage* style_image) {
  if (auto* pending_image = DynamicTo<StylePendingImage>(style_image)) {
    return pending_image->CssValue();
  }
  return nullptr;
}

StyleImage* ElementStyleResources::LoadMaskSource(CSSValue& pending_value) {
  auto* image_value = DynamicTo<CSSImageValue>(pending_value);
  if (!image_value) {
    return nullptr;
  }
  if (image_value->IsLocal(element_.GetDocument())) {
    SVGTreeScopeResources& tree_scope_resources =
        element_.OriginatingTreeScope().EnsureSVGTreeScopedResources();
    SVGResource* resource = tree_scope_resources.ResourceForId(
        image_value->NormalizedFragmentIdentifier());
    return MakeGarbageCollected<StyleMaskSourceImage>(resource, image_value);
  }
  StyleImage* image = image_value->CacheImage(
      element_.GetDocument(), FetchParameters::ImageRequestBehavior::kNone,
      kCrossOriginAttributeAnonymous);
  return MakeGarbageCollected<StyleMaskSourceImage>(
      To<StyleFetchedImage>(image), image_value->EnsureSVGResource(),
      image_value);
}

void ElementStyleResources::LoadPendingImages(ComputedStyleBuilder& builder) {
  // We must loop over the properties and then look at the style to see if
  // a pending image exists, and only load that image. For example:
  //
  // <style>
  //    div { background-image: url(a.png); }
  //    div { background-image: url(b.png); }
  //    div { background-image: none; }
  // </style>
  // <div></div>
  //
  // We call styleImage() for both a.png and b.png adding the
  // CSSPropertyID::kBackgroundImage property to the pending_image_properties_
  // set, then we null out the background image because of the "none".
  //
  // If we eagerly loaded the images we'd fetch a.png, even though it's not
  // used. If we didn't null check below we'd crash since the none actually
  // removed all background images.
  StyleImageLoader loader(element_.GetDocument(), builder,
                          pre_cached_container_sizes_, device_scale_factor_);
  for (CSSPropertyID property : pending_image_properties_) {
    switch (property) {
      case CSSPropertyID::kBackgroundImage: {
        for (FillLayer* background_layer = &builder.AccessBackgroundLayers();
             background_layer; background_layer = background_layer->Next()) {
          if (auto* pending_value =
                  PendingCssValue(background_layer->GetImage())) {
            FetchParameters::ImageRequestBehavior image_request_behavior =
                FetchParameters::ImageRequestBehavior::kNone;
            StyleImage* new_image =
                loader.Load(*pending_value, image_request_behavior);
            if (new_image && new_image->IsLazyloadPossiblyDeferred()) {
              LazyImageHelper::StartMonitoring(&element_);
            }
            background_layer->SetImage(new_image);
          }
        }
        break;
      }
      case CSSPropertyID::kContent: {
        for (ContentData* content_data =
                 const_cast<ContentData*>(builder.GetContentData());
             content_data; content_data = content_data->Next()) {
          if (auto* image_content =
                  DynamicTo<ImageContentData>(*content_data)) {
            if (auto* pending_value =
                    PendingCssValue(image_content->GetImage())) {
              image_content->SetImage(loader.Load(*pending_value));
            }
          }
        }
        break;
      }
      case CSSPropertyID::kCursor: {
        if (CursorList* cursor_list = builder.Cursors()) {
          for (CursorData& cursor : *cursor_list) {
            if (auto* pending_value = PendingCssValue(cursor.GetImage())) {
              cursor.SetImage(loader.Load(*pending_value));
            }
          }
        }
        break;
      }
      case CSSPropertyID::kListStyleImage: {
        if (auto* pending_value = PendingCssValue(builder.ListStyleImage())) {
          builder.SetListStyleImage(loader.Load(*pending_value));
        }
        break;
      }
      case CSSPropertyID::kBorderImageSource: {
        if (auto* pending_value =
                PendingCssValue(builder.BorderImage().GetImage())) {
          builder.SetBorderImageSource(loader.Load(*pending_value));
        }
        break;
      }
      case CSSPropertyID::kWebkitBoxReflect: {
        if (StyleReflection* reflection = builder.BoxReflect()) {
          const NinePieceImage& mask_image = reflection->Mask();
          if (auto* pending_value = PendingCssValue(mask_image.GetImage())) {
            StyleImage* loaded_image = loader.Load(*pending_value);
            reflection->SetMask(NinePieceImage(
                loaded_image, mask_image.ImageSlices(), mask_image.Fill(),
                mask_image.BorderSlices(), mask_image.Outset(),
                mask_image.HorizontalRule(), mask_image.VerticalRule()));
          }
        }
        break;
      }
      case CSSPropertyID::kWebkitMaskBoxImageSource: {
        if (auto* pending_value =
                PendingCssValue(builder.MaskBoxImageSource())) {
          builder.SetMaskBoxImageSource(loader.Load(*pending_value));
        }
        break;
      }
      case CSSPropertyID::kMaskImage: {
        for (FillLayer* mask_layer = &builder.AccessMaskLayers(); mask_layer;
             mask_layer = mask_layer->Next()) {
          if (auto* pending_value = PendingCssValue(mask_layer->GetImage())) {
            StyleImage* image = LoadMaskSource(*pending_value);
            if (!image) {
              image = loader.Load(*pending_value,
                                  FetchParameters::ImageRequestBehavior::kNone,
                                  kCrossOriginAttributeAnonymous);
            }
            mask_layer->SetImage(image);
          }
        }
        break;
      }
      case CSSPropertyID::kShapeOutside:
        if (ShapeValue* shape_value = builder.ShapeOutside()) {
          if (auto* pending_value = PendingCssValue(shape_value->GetImage())) {
            shape_value->SetImage(loader.Load(
                *pending_value, FetchParameters::ImageRequestBehavior::kNone,
                kCrossOriginAttributeAnonymous));
          }
        }
        break;
      default:
        NOTREACHED();
    }
  }
}

void ElementStyleResources::LoadPendingResources(
    ComputedStyleBuilder& builder) {
  LoadPendingImages(builder);
  LoadPendingSVGResources(builder);
}

void ElementStyleResources::UpdateLengthConversionData(
    const CSSToLengthConversionData* conversion_data) {
  pre_cached_container_sizes_ = PreCachedContainerSizes(conversion_data);
}

}  // namespace blink

"""

```