Response:
Let's break down the thought process for analyzing this C++ file and generating the explanation.

**1. Initial Understanding of the Request:**

The request asks for a comprehensive analysis of a specific Chromium Blink engine source file, `svg_fe_image_element.cc`. It wants to know its function, its relationship to web technologies (JavaScript, HTML, CSS), examples of its behavior, potential user errors, and debugging clues.

**2. High-Level Overview of the File:**

The first step is to quickly scan the code and its imports. Key observations include:

* **Filename:** `svg_fe_image_element.cc` immediately suggests it's related to the `<feImage>` SVG filter primitive.
* **Includes:**  The included headers provide crucial context:
    * `svg_fe_image_element.h`: Likely the corresponding header file defining the `SVGFEImageElement` class.
    * `dom/document.h`, `dom/id_target_observer.h`: Indicates interaction with the DOM.
    * `execution_context/execution_context.h`:  Involves the runtime environment of the browser.
    * `loader/resource/image_resource_content.h`:  Deals with fetching and managing image resources.
    * `svg/graphics/filters/svg_fe_image.h`: The core logic for the `<feImage>` filter effect.
    * `svg/svg_animated_preserve_aspect_ratio.h`, `svg/svg_preserve_aspect_ratio.h`: Handling the `preserveAspectRatio` attribute.
    * `svg/svg_filter_element.h`: Its parent element within the SVG filter structure.
    * `svg_names.h`: Defines constants for SVG element and attribute names.
    * `platform/graphics/image.h`: Represents image data.
    * `platform/loader/fetch/...`:  Deals with network requests for resources.

* **Class Definition:** `class SVGFEImageElement : public SVGFilterPrimitiveStandardAttributes, public SVGURIReference, public ImageResourceObserver` reveals its inheritance structure and key responsibilities. It inherits from:
    * `SVGFilterPrimitiveStandardAttributes`:  Provides common attributes for SVG filter primitives.
    * `SVGURIReference`:  Handles the `xlink:href` attribute for referencing resources.
    * `ImageResourceObserver`: Allows it to be notified about the loading status of images.

**3. Functionality Breakdown (Line by Line or Block by Block):**

Next, analyze the key methods of the `SVGFEImageElement` class:

* **Constructor & Destructor:** Standard setup and cleanup. Note the initialization of `preserve_aspect_ratio_`.
* **`Trace()`:** Used for garbage collection. Not directly related to the functional logic for web developers.
* **`CurrentFrameHasSingleSecurityOrigin()`:** Security check related to cross-origin image access.
* **`ClearResourceReferences()`:**  Releases resources (images, observers).
* **`FetchImageResource()`:**  Initiates the loading of an image from a URL specified in the `xlink:href` attribute. Pay attention to the `ResourceLoaderOptions` and `FetchParameters`.
* **`ClearImageResource()`:** Stops observing the image resource and releases the reference.
* **`Dispose()`:**  Similar to `ClearImageResource` but potentially called during object destruction.
* **`BuildPendingResource()`:**  The central logic for determining what resource to load (image URL or a reference to an in-document element) based on the `xlink:href`. It also handles observing target elements within the SVG document.
* **`SvgAttributeChanged()`:**  Handles changes to SVG attributes, triggering resource loading or invalidation.
* **`InsertedInto()` & `RemovedFrom()`:** Lifecycle methods called when the element is added or removed from the DOM. They manage resource loading and cleanup.
* **`ImageNotifyFinished()`:** Called when an image has finished loading (or failed). Triggers potential re-rendering of the filter.
* **`TargetElement()`:**  Resolves the target element referenced by the `xlink:href` if it's an in-document reference.
* **`Build()`:**  The core function that creates the actual `FEImage` filter effect used by the graphics rendering pipeline. It takes either a loaded `Image` or a target `SVGElement` as input.
* **`TaintsOrigin()`:**  Determines if using this filter primitive could introduce cross-origin security issues.
* **`PropertyFromAttribute()`:**  Provides access to animated properties (like `preserveAspectRatio`).
* **`SynchronizeAllSVGAttributes()`:**  Ensures attribute values are up-to-date.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **HTML:** The `<feImage>` element itself is defined in HTML within an SVG `<filter>` element. The `xlink:href` attribute is a key connection point.
* **JavaScript:** JavaScript can manipulate the `xlink:href` attribute of the `<feImage>` element, triggering the resource loading logic in this C++ file. JavaScript can also dynamically create and append `<feImage>` elements.
* **CSS:** While CSS doesn't directly control the inner workings of `<feImage>`, CSS can be used to apply the SVG filter that contains the `<feImage>` element to other HTML elements.

**5. Examples and Scenarios:**

Based on the code analysis, construct concrete examples illustrating the functionality:

* **Loading an image from a URL:** A simple case demonstrating the `FetchImageResource()` path.
* **Referencing an in-document SVG element:** Demonstrating the `ObserveTarget()` and `TargetElement()` paths.
* **`preserveAspectRatio` attribute:** Showing how this attribute affects the image rendering.

**6. User and Programming Errors:**

Think about common mistakes developers might make:

* **Incorrect `xlink:href`:**  Typos, broken links, or referencing non-existent elements.
* **Cross-origin issues:** Trying to load images from domains without proper CORS headers.
* **Circular dependencies:**  An `<feImage>` referencing itself (though the code might have safeguards).

**7. Debugging Clues and User Actions:**

Trace how a user interaction leads to this code being executed:

* A user loads a web page containing an SVG filter with an `<feImage>` element.
* The browser parses the HTML and encounters the `<feImage>`.
* Blink creates an `SVGFEImageElement` object.
* The browser fetches the image resource specified in `xlink:href`.
* The `ImageNotifyFinished()` method is called when the image loads.
* The filter is applied and rendered.

**8. Structuring the Explanation:**

Organize the findings logically, starting with the core functionality and then branching out to related concepts, examples, and potential issues. Use clear and concise language. Use headings and bullet points for readability.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Focus only on image loading.
* **Correction:** Realize the `<feImage>` can also reference other SVG elements, requiring attention to the target observing logic.
* **Initial thought:** Describe individual methods in isolation.
* **Correction:**  Explain how the methods interact and the overall flow of resource loading and filter creation.
* **Initial thought:**  Provide only code snippets for examples.
* **Correction:**  Create more complete HTML/SVG examples for better understanding.

By following these steps, the detailed and comprehensive explanation can be generated. The process involves understanding the code's structure, its purpose, its interactions with other parts of the browser engine, and how it relates to the web development concepts that developers use.
这个C++源代码文件 `blink/renderer/core/svg/svg_fe_image_element.cc` 实现了 Chromium Blink 引擎中用于处理 SVG `<feImage>` 滤镜原语的功能。`<feImage>` 允许在 SVG 滤镜效果中使用外部图像或另一个 SVG 元素作为输入。

以下是它的主要功能：

**1. 表示和管理 `<feImage>` 元素:**

* 该文件定义了 `SVGFEImageElement` 类，该类继承自 `SVGFilterPrimitiveStandardAttributes` (提供通用滤镜原语属性) 和 `SVGURIReference` (处理 URI 引用，如 `xlink:href`) 以及 `ImageResourceObserver` (用于观察图像资源加载状态)。
* 它负责解析和存储 `<feImage>` 元素的属性，例如 `x`, `y`, `width`, `height` 以及关键的 `xlink:href` 属性。

**2. 处理 `xlink:href` 属性:**

* `SVGFEImageElement` 使用 `SVGURIReference` 基类来处理 `xlink:href` 属性。
* `BuildPendingResource()` 方法是关键，它根据 `xlink:href` 的值来决定要加载的内容：
    * **如果 `xlink:href` 指向一个外部图像 URL:** 它会使用 `FetchImageResource()` 方法异步加载图像资源。
    * **如果 `xlink:href` 指向文档内部的另一个 SVG 元素 (通过 ID 选择器):** 它会使用 `ObserveTarget()` 方法来观察该目标元素的变化。

**3. 异步加载外部图像:**

* `FetchImageResource()` 方法使用 Blink 的资源加载机制 (`ResourceFetcher`) 来获取外部图像。
* 它创建 `ImageResourceContent` 对象来管理加载的图像数据。
* 作为 `ImageResourceObserver`，`SVGFEImageElement` 可以接收图像加载完成或失败的通知 (`ImageNotifyFinished()`)。

**4. 观察目标 SVG 元素:**

* 如果 `xlink:href` 指向一个内部 SVG 元素，`ObserveTarget()` 会建立一个观察者 (`target_id_observer_`) 来监听目标元素的变化。
* 当目标元素发生改变（例如，它的内容或属性发生变化）时，`SVGFEImageElement` 会收到通知并进行必要的更新，例如重新渲染滤镜效果。

**5. 创建和管理滤镜效果:**

* `Build()` 方法是核心，它在需要时创建一个 `FEImage` 滤镜效果对象。
* `FEImage` 对象是实际执行图像或 SVG 元素到滤镜管道的转换的类。
* `Build()` 方法会根据 `xlink:href` 的内容来选择创建 `FEImage` 的方式：
    * 如果加载了外部图像，它会传递 `Image` 对象给 `FEImage`。
    * 如果引用了内部 SVG 元素，它会传递目标 `SVGElement` 给 `FEImage`。
* `preserveAspectRatio` 属性也会被传递给 `FEImage`，以控制图像或 SVG 元素在滤镜区域内的缩放和对齐方式。

**6. 处理 `preserveAspectRatio` 属性:**

* `preserve_aspect_ratio_` 成员变量存储了 `<feImage>` 元素的 `preserveAspectRatio` 属性的动画值。
* `SvgAttributeChanged()` 方法会处理 `preserveAspectRatio` 属性的变化，并触发滤镜的重新渲染。

**7. 生命周期管理:**

* `InsertedInto()` 和 `RemovedFrom()` 方法处理元素添加到 DOM 或从 DOM 移除时的逻辑，例如启动或停止资源加载和观察。
* `ClearResourceReferences()` 方法在元素不再需要时清理资源引用，例如取消图像加载和解除目标元素的观察。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML:**  `<feImage>` 元素是 SVG 规范定义的一部分，直接在 HTML 中使用 SVG 标签时出现。例如：

```html
<svg>
  <filter id="myFilter">
    <feImage xlink:href="image.png" result="image"/>
    <feGaussianBlur in="image" stdDeviation="5" result="blur"/>
    <feBlend in="SourceGraphic" in2="blur" mode="normal"/>
  </filter>
  <rect width="200" height="200" fill="red" filter="url(#myFilter)"/>
</svg>
```

在这个例子中，`<feImage>` 使用 `xlink:href` 引用了一个名为 `image.png` 的外部图像。

* **JavaScript:** JavaScript 可以动态地创建、修改和删除 `<feImage>` 元素及其属性。例如，可以使用 JavaScript 修改 `xlink:href` 属性来动态切换滤镜使用的图像或 SVG 元素。

```javascript
const feImage = document.createElementNS('http://www.w3.org/2000/svg', 'feImage');
feImage.setAttributeNS('http://www.w3.org/1999/xlink', 'href', 'another_image.png');
document.getElementById('myFilter').appendChild(feImage);
```

* **CSS:** CSS 可以通过 `filter` 属性来应用包含 `<feImage>` 的 SVG 滤镜到 HTML 元素。CSS 无法直接控制 `<feImage>` 元素的内部行为，但可以通过影响应用了滤镜的元素来间接影响其视觉效果。

```css
.my-element {
  filter: url(#myFilter);
}
```

**逻辑推理的假设输入与输出:**

**假设输入 1:**

```html
<svg>
  <filter id="imageFilter">
    <feImage xlink:href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg==" result="embeddedImage"/>
    <feGaussianBlur in="embeddedImage" stdDeviation="2" result="blurredImage"/>
    <feBlend in="SourceGraphic" in2="blurredImage" mode="multiply"/>
  </filter>
  <rect width="100" height="100" fill="blue" filter="url(#imageFilter)"/>
</svg>
```

**输出 1:**

* `SVGFEImageElement` 会解析 `xlink:href` 属性，识别出这是一个 data URI 形式的嵌入式图像。
* Blink 可能会直接解码 data URI 并将其作为图像数据使用，而不会发起网络请求。
* `Build()` 方法会创建一个 `FEImage` 对象，并将解码后的图像数据传递给它。
* 最终，蓝色矩形会应用一个使用该嵌入式图像作为输入的模糊滤镜效果。

**假设输入 2:**

```html
<svg>
  <symbol id="mySymbol">
    <circle cx="10" cy="10" r="5" fill="green"/>
  </symbol>
  <filter id="symbolFilter">
    <feImage xlink:href="#mySymbol" result="symbolImage"/>
    <feColorMatrix in="symbolImage" type="matrix" values="1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 0.5 0"/>
  </filter>
  <rect width="50" height="50" fill="yellow" filter="url(#symbolFilter)"/>
</svg>
```

**输出 2:**

* `SVGFEImageElement` 会解析 `xlink:href` 属性，识别出它指向一个 ID 为 `mySymbol` 的内部 SVG 元素。
* `BuildPendingResource()` 会调用 `ObserveTarget()` 来观察 ID 为 `mySymbol` 的元素。
* `Build()` 方法会创建一个 `FEImage` 对象，并将 `mySymbol` 元素作为输入传递给它。
* 最终，黄色矩形会应用一个使用 `mySymbol` 内容的滤镜效果，这里是一个半透明的绿色圆圈。

**用户或编程常见的使用错误：**

1. **`xlink:href` 指向不存在的资源或元素:**
   * **用户操作:** 在 HTML 中编写 SVG 代码，`<feImage>` 的 `xlink:href` 属性指向一个拼写错误的图像文件名或一个不存在的内部 SVG 元素的 ID。
   * **调试线索:**  浏览器控制台可能会显示资源加载失败的错误（对于外部图像）或找不到目标元素的警告（对于内部引用）。`SVGFEImageElement::BuildPendingResource()` 中 `ObserveTarget()` 返回 `nullptr` 或 `FetchImageResource()` 加载失败会是调试的关键点。

2. **跨域问题 (CORS) 导致图像加载失败:**
   * **用户操作:** `<feImage>` 的 `xlink:href` 属性指向另一个域名的图像，但该域名服务器没有设置允许跨域访问的 CORS 头。
   * **调试线索:** 浏览器控制台会显示 CORS 相关的错误信息。`SVGFEImageElement::FetchImageResource()` 尝试加载资源，但 `cached_image_->ErrorOccurred()` 会返回 `true`。`TaintsOrigin()` 方法在这种情况下也会返回 `true`。

3. **循环引用:**
   * **用户操作:**  `<feImage>` 的 `xlink:href` 属性指向包含该 `<feImage>` 元素的父元素或祖先元素，可能导致无限循环或未定义的行为。
   * **调试线索:**  Blink 引擎可能会有机制来检测和阻止这种循环引用，但如果发生，可能会导致性能问题或渲染错误。需要检查 `BuildPendingResource()` 中的逻辑，确保不会建立指向自身或祖先的引用。

4. **使用了不支持的图像格式:**
   * **用户操作:** `<feImage>` 的 `xlink:href` 属性指向浏览器不支持解码的图像格式。
   * **调试线索:** 图像加载可能成功，但解码会失败。`cached_image_->GetImage()` 可能返回空指针或一个表示解码错误的图像对象。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设开发者正在调试一个网页，该网页使用了包含 `<feImage>` 元素的 SVG 滤镜，并且发现滤镜效果没有按预期工作。以下是可能的调试步骤以及如何到达 `svg_fe_image_element.cc` 文件：

1. **开发者在浏览器中加载包含 SVG 滤镜的 HTML 页面。**
2. **浏览器解析 HTML，遇到 `<svg>` 和 `<filter>` 元素，并创建相应的 Blink 引擎对象。**
3. **当解析到 `<feImage>` 元素时，Blink 会创建 `SVGFEImageElement` 对象。**
4. **`SVGFEImageElement` 的构造函数被调用。**
5. **根据 `xlink:href` 属性的值，`BuildPendingResource()` 方法被调用。**
   * **如果 `xlink:href` 是外部 URL:** `FetchImageResource()` 被调用，尝试加载图像。开发者可能会在网络面板中查看请求状态。
   * **如果 `xlink:href` 是内部引用:** `ObserveTarget()` 被调用，尝试找到目标元素。开发者可能会在 Elements 面板中检查目标元素是否存在以及其 ID 是否正确。
6. **如果图像加载完成 (`ImageNotifyFinished()`) 或目标元素发生变化 (`SvgAttributeChanged()`),  `Build()` 方法会被调用来创建或更新 `FEImage` 滤镜效果。**
7. **如果滤镜效果没有正确渲染，开发者可能会使用浏览器的开发者工具检查以下内容：**
   * **Elements 面板:** 查看 `<feImage>` 元素的属性值是否正确，特别是 `xlink:href` 和 `preserveAspectRatio`。
   * **Network 面板:** 检查图像资源是否成功加载，是否存在 CORS 问题。
   * **Console 面板:** 查看是否有错误或警告信息，例如资源加载失败或找不到目标元素。
8. **如果开发者需要深入了解 Blink 引擎的内部行为，他们可能会设置断点在 `svg_fe_image_element.cc` 的关键方法中，例如：**
   * `SVGFEImageElement::BuildPendingResource()`:  检查 `xlink:href` 的解析和资源加载/观察的逻辑。
   * `SVGFEImageElement::FetchImageResource()`:  查看资源请求的创建和发送。
   * `SVGFEImageElement::ImageNotifyFinished()`:  确认图像加载是否成功。
   * `SVGFEImageElement::Build()`:  检查 `FEImage` 对象的创建和参数传递。
9. **通过单步调试，开发者可以跟踪代码的执行流程，查看变量的值，并理解 `SVGFEImageElement` 如何处理 `<feImage>` 元素及其属性，从而找到问题所在。** 例如，他们可能会发现 `HrefString()` 返回了错误的 URL，或者 `TargetElementFromIRIString()` 没有找到预期的目标元素。

总而言之，`blink/renderer/core/svg/svg_fe_image_element.cc` 文件是 Chromium Blink 引擎中处理 SVG `<feImage>` 元素的核心，负责加载外部图像或引用内部 SVG 元素，并将其转化为滤镜管道中可以使用的 `FEImage` 对象。 理解这个文件的功能对于调试涉及 `<feImage>` 的 SVG 滤镜问题至关重要。

### 提示词
```
这是目录为blink/renderer/core/svg/svg_fe_image_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2004, 2005, 2007 Nikolas Zimmermann <zimmermann@kde.org>
 * Copyright (C) 2004, 2005 Rob Buis <buis@kde.org>
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

#include "third_party/blink/renderer/core/svg/svg_fe_image_element.h"

#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/id_target_observer.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource_content.h"
#include "third_party/blink/renderer/core/svg/graphics/filters/svg_fe_image.h"
#include "third_party/blink/renderer/core/svg/svg_animated_preserve_aspect_ratio.h"
#include "third_party/blink/renderer/core/svg/svg_filter_element.h"
#include "third_party/blink/renderer/core/svg/svg_preserve_aspect_ratio.h"
#include "third_party/blink/renderer/core/svg_names.h"
#include "third_party/blink/renderer/platform/graphics/image.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_parameters.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"

namespace blink {

SVGFEImageElement::SVGFEImageElement(Document& document)
    : SVGFilterPrimitiveStandardAttributes(svg_names::kFEImageTag, document),
      SVGURIReference(this),
      preserve_aspect_ratio_(
          MakeGarbageCollected<SVGAnimatedPreserveAspectRatio>(
              this,
              svg_names::kPreserveAspectRatioAttr)) {}

SVGFEImageElement::~SVGFEImageElement() = default;

void SVGFEImageElement::Trace(Visitor* visitor) const {
  visitor->Trace(preserve_aspect_ratio_);
  visitor->Trace(cached_image_);
  visitor->Trace(target_id_observer_);
  SVGFilterPrimitiveStandardAttributes::Trace(visitor);
  SVGURIReference::Trace(visitor);
  ImageResourceObserver::Trace(visitor);
}

bool SVGFEImageElement::CurrentFrameHasSingleSecurityOrigin() const {
  if (cached_image_) {
    if (Image* image = cached_image_->GetImage())
      return image->CurrentFrameHasSingleSecurityOrigin();
  }
  return true;
}

void SVGFEImageElement::ClearResourceReferences() {
  ClearImageResource();
  UnobserveTarget(target_id_observer_);
  RemoveAllOutgoingReferences();
}

void SVGFEImageElement::FetchImageResource() {
  if (!GetExecutionContext())
    return;

  ResourceLoaderOptions options(GetExecutionContext()->GetCurrentWorld());
  options.initiator_info.name = localName();
  FetchParameters params(
      ResourceRequest(GetDocument().CompleteURL(HrefString())), options);
  cached_image_ = ImageResourceContent::Fetch(params, GetDocument().Fetcher());
  if (cached_image_)
    cached_image_->AddObserver(this);
}

void SVGFEImageElement::ClearImageResource() {
  if (!cached_image_)
    return;
  cached_image_->RemoveObserver(this);
  cached_image_ = nullptr;
}

void SVGFEImageElement::Dispose() {
  if (!cached_image_)
    return;
  cached_image_->DidRemoveObserver();
  cached_image_ = nullptr;
}

void SVGFEImageElement::BuildPendingResource() {
  ClearResourceReferences();
  if (!isConnected())
    return;

  Element* target = ObserveTarget(target_id_observer_, *this);
  if (!target) {
    if (!SVGURLReferenceResolver(HrefString(), GetDocument()).IsLocal())
      FetchImageResource();
  } else if (auto* svg_element = DynamicTo<SVGElement>(target)) {
    // Register us with the target in the dependencies map. Any change of
    // hrefElement that leads to relayout/repainting now informs us, so we can
    // react to it.
    AddReferenceTo(svg_element);
  }

  Invalidate();
}

void SVGFEImageElement::SvgAttributeChanged(
    const SvgAttributeChangedParams& params) {
  const QualifiedName& attr_name = params.name;
  if (attr_name == svg_names::kPreserveAspectRatioAttr) {
    Invalidate();
    return;
  }

  if (SVGURIReference::IsKnownAttribute(attr_name)) {
    BuildPendingResource();
    return;
  }

  SVGFilterPrimitiveStandardAttributes::SvgAttributeChanged(params);
}

Node::InsertionNotificationRequest SVGFEImageElement::InsertedInto(
    ContainerNode& root_parent) {
  SVGFilterPrimitiveStandardAttributes::InsertedInto(root_parent);
  BuildPendingResource();
  return kInsertionDone;
}

void SVGFEImageElement::RemovedFrom(ContainerNode& root_parent) {
  SVGFilterPrimitiveStandardAttributes::RemovedFrom(root_parent);
  if (root_parent.isConnected())
    ClearResourceReferences();
}

void SVGFEImageElement::ImageNotifyFinished(ImageResourceContent*) {
  if (!isConnected())
    return;

  Element* parent = parentElement();
  if (!parent || !IsA<SVGFilterElement>(parent) || !parent->GetLayoutObject())
    return;

  if (LayoutObject* layout_object = GetLayoutObject())
    MarkForLayoutAndParentResourceInvalidation(*layout_object);
}

const SVGElement* SVGFEImageElement::TargetElement() const {
  if (cached_image_)
    return nullptr;
  return DynamicTo<SVGElement>(
      TargetElementFromIRIString(HrefString(), GetTreeScope()));
}

FilterEffect* SVGFEImageElement::Build(SVGFilterBuilder*, Filter* filter) {
  if (cached_image_) {
    // Don't use the broken image icon on image loading errors.
    scoped_refptr<Image> image =
        cached_image_->ErrorOccurred() ? nullptr : cached_image_->GetImage();
    return MakeGarbageCollected<FEImage>(
        filter, image, preserve_aspect_ratio_->CurrentValue());
  }
  return MakeGarbageCollected<FEImage>(filter, TargetElement(),
                                       preserve_aspect_ratio_->CurrentValue());
}

bool SVGFEImageElement::TaintsOrigin() const {
  // We always consider a 'href' that references a local element as tainting.
  return !cached_image_ || !cached_image_->IsAccessAllowed();
}

SVGAnimatedPropertyBase* SVGFEImageElement::PropertyFromAttribute(
    const QualifiedName& attribute_name) const {
  if (attribute_name == svg_names::kPreserveAspectRatioAttr) {
    return preserve_aspect_ratio_.Get();
  } else {
    SVGAnimatedPropertyBase* ret =
        SVGURIReference::PropertyFromAttribute(attribute_name);
    if (ret) {
      return ret;
    } else {
      return SVGFilterPrimitiveStandardAttributes::PropertyFromAttribute(
          attribute_name);
    }
  }
}

void SVGFEImageElement::SynchronizeAllSVGAttributes() const {
  SVGAnimatedPropertyBase* attrs[]{preserve_aspect_ratio_.Get()};
  SynchronizeListOfSVGAttributes(attrs);
  SVGURIReference::SynchronizeAllSVGAttributes();
  SVGFilterPrimitiveStandardAttributes::SynchronizeAllSVGAttributes();
}

}  // namespace blink
```