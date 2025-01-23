Response:
Let's break down the thought process for analyzing this C++ source code and generating the detailed explanation.

1. **Initial Understanding of the File's Purpose:**

   - The file name `image_resource_content.cc` in the `blink/renderer/core/loader/resource/` directory strongly suggests it deals with the *content* of image resources within the Blink rendering engine. The `.cc` extension confirms it's a C++ source file.

2. **Core Class Identification:**

   - The code immediately introduces the `ImageResourceContent` class. This is the central entity we need to understand.

3. **Key Dependencies and Relationships (Scanning Includes):**

   - The `#include` directives are crucial for understanding how this class interacts with other parts of the Blink engine. I'd scan these and think about what each included header represents:
     - `image_resource.h`: Likely the "owner" or manager of `ImageResourceContent`.
     - `image_resource_info.h`:  Information *about* the image resource (URL, response headers, etc.).
     - `image_resource_observer.h`:  Mechanisms for other parts of the engine to be notified about changes to the image content.
     - `svg_image.h`, `bitmap_image.h`: Concrete image types that `ImageResourceContent` can hold.
     - `resource_load_timing.h`, `resource_response.h`: Network-related data about the image load.
     - `shared_buffer.h`:  How the raw image data is stored.
     - Other utility/platform headers.

4. **Dissecting the `ImageResourceContent` Class:**

   - **Member Variables:**  I'd look at the private members first:
     - `image_`: A `scoped_refptr<blink::Image>` – holds the actual decoded image data (either a `BitmapImage` or `SVGImage`). The `scoped_refptr` means it's reference-counted for memory management.
     - `info_`: A pointer to `ImageResourceInfo` – confirms that `ImageResourceContent` relies on a separate object for metadata.
     - `observers_`, `finished_observers_`: Sets of `ImageResourceObserver`s – important for the notification mechanism.
     - `content_status_`: An enum (`ResourceStatus`) tracking the loading state of the image.
     - Other flags like `is_broken_`, `size_available_`, `device_pixel_ratio_header_value_`.

   - **Public Methods:**  These define the functionality of the class:
     - Constructors (`ImageResourceContent`, `CreateLoaded`, `Fetch`): How `ImageResourceContent` instances are created.
     - `SetImageResourceInfo`:  Setting the associated metadata.
     - `AddObserver`, `RemoveObserver`: Managing the notification system.
     - `UpdateImage`:  The core method for receiving and processing image data.
     - `GetImage`, `IntrinsicSize`: Accessing the image data and its properties.
     - `NotifyObservers`: Triggering notifications.
     - Methods related to animation (`DoResetAnimation`, `ShouldPauseAnimation`, `UpdateImageAnimationPolicy`).
     - Methods for accessing metadata (`Url`, `GetResponse`, etc.).
     - Methods related to error handling (`ErrorOccurred`, `LoadFailedOrCanceled`).

5. **Relating to Web Technologies (JavaScript, HTML, CSS):**

   - **HTML:**  The most direct connection is through the `<img>` tag. When the browser encounters an `<img>` tag, it needs to fetch and display the image. `ImageResourceContent` is involved in handling the fetched image data.
   - **CSS:** CSS properties like `background-image`, `content` (for generated content), and even some animation properties trigger image loading. `ImageResourceContent` plays the same role here as with `<img>` tags.
   - **JavaScript:** JavaScript can manipulate images in various ways:
     - Dynamically creating `<img>` elements.
     - Setting the `src` attribute of image elements.
     - Using the Canvas API, which can draw images.
     - Fetching images using `XMLHttpRequest` or `fetch`. While `ImageResourceContent` itself might not be directly exposed to JS, it's part of the underlying mechanism that handles these requests.

6. **Logical Reasoning and Hypothetical Scenarios:**

   - **Input:**  Think about the data that `ImageResourceContent` processes: raw image bytes (via `SharedBuffer`), HTTP headers (`ResourceResponse`), and signals from the network.
   - **Processing:**  The key logic is in `UpdateImage`, where it takes the raw data, passes it to the appropriate `blink::Image` subclass for decoding, and then notifies observers.
   - **Output:**  The "output" isn't a direct return value in many cases, but rather the side effects:  the image is decoded and ready to be rendered, and observers are notified, leading to repaints.

7. **Identifying Common User/Programming Errors:**

   - **Incorrect Image URLs:** If the `src` attribute is wrong, the fetch will fail, and `ImageResourceContent` might end up in an error state.
   - **CORS Issues:**  If a website tries to load an image from a different origin without proper CORS headers, the load might be blocked. `ImageResourceContent` would receive an error.
   - **Large Images:**  While not strictly an "error," very large images can cause performance problems, potentially leading to out-of-memory issues or slow rendering.
   - **Unsupported Image Formats:** If the browser doesn't support the image format, `ImageResourceContent` would likely trigger a decode error.

8. **Tracing User Actions:**

   - Start with a simple user action: typing a URL in the address bar and pressing Enter.
   - The browser parses the HTML, finds an `<img>` tag, and initiates a network request for the image source.
   - The networking stack fetches the image data and headers.
   - This data is passed to the Blink rendering engine.
   - Somewhere in the Blink pipeline, an `ImageResource` is created.
   - `ImageResourceContent` is associated with the `ImageResource`.
   - As image data arrives, `UpdateImage` is called.
   - Observers (like the rendering pipeline) are notified, eventually leading to the image being drawn on the screen.

9. **Refinement and Structure:**

   - Organize the information logically: start with the core functionality, then discuss relationships, web technology connections, error scenarios, and finally, debugging aspects.
   - Use clear headings and bullet points to improve readability.
   - Provide concrete examples to illustrate abstract concepts.
   - Ensure the language is accessible to someone with a basic understanding of web development concepts.

This iterative process of reading the code, identifying key components, understanding relationships, and then connecting it to higher-level web concepts is crucial for generating a comprehensive and helpful explanation.
好的，让我们来详细分析一下 `blink/renderer/core/loader/resource/image_resource_content.cc` 这个文件。

**文件功能概述:**

`ImageResourceContent.cc` 文件定义了 `ImageResourceContent` 类，这个类在 Chromium Blink 渲染引擎中负责管理和处理图像资源的内容数据。它的主要职责包括：

1. **存储和管理图像数据:**  它持有实际的图像数据，这些数据通常以解码后的 `blink::Image` 对象的形式存在，可以是 `BitmapImage`（位图图像）或 `SVGImage`（矢量图像）。
2. **维护图像加载状态:** 跟踪图像资源的加载、解码、错误等状态。
3. **管理观察者:**  允许其他 Blink 组件（例如，渲染对象、CSS 引擎等）注册为观察者，以便在图像内容发生变化时得到通知。
4. **处理图像数据的更新:**  接收从网络或其他来源加载的图像数据，并更新内部的 `blink::Image` 对象。
5. **提供图像信息:**  提供关于图像的各种信息，例如尺寸、MIME 类型、加载时间等。
6. **控制图像动画:**  对动画图像进行控制，例如暂停、重置动画。
7. **处理设备像素比:**  考虑 HTTP 头部中 `Content-DPR` (Device Pixel Ratio) 的值，以支持不同设备上的高清图像显示。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`ImageResourceContent` 位于 Blink 渲染引擎的核心，与前端技术紧密相关。它在幕后支撑着网页中图像的显示和交互：

* **HTML `<image>` 标签和相关属性:**
    * 当浏览器解析到 `<image src="image.png">` 这样的 HTML 代码时，会触发图像资源的加载。
    * `ImageResourceContent` 负责接收并处理 `image.png` 的数据。
    * HTML 属性如 `srcset` 和 `sizes` 会影响浏览器如何选择和加载不同尺寸的图像，而 `ImageResourceContent` 需要处理这些选择后的图像数据。
    * **假设输入:** HTML 中包含 `<img src="my-image.jpg">`。
    * **输出:** `ImageResourceContent` 会创建一个 `BitmapImage` 对象来存储 `my-image.jpg` 的解码后数据。

* **CSS `background-image` 和其他图像相关的 CSS 属性:**
    * CSS 可以通过 `background-image: url('bg.png')` 来设置元素的背景图像。
    * `ImageResourceContent` 同样负责加载和管理 `bg.png` 的内容。
    * CSS 属性如 `image-set` 允许指定不同分辨率的背景图，`ImageResourceContent` 需要处理这些不同版本的图像。
    * **假设输入:** CSS 中定义了 `.element { background-image: url('pattern.gif'); }`。
    * **输出:** `ImageResourceContent` 会创建一个 `BitmapImage` 对象来存储 `pattern.gif` 的解码后数据，并可能处理其动画。

* **JavaScript 操作图像:**
    * JavaScript 可以通过 `Image()` 构造函数动态创建图像对象，并设置其 `src` 属性。
    * JavaScript 可以通过 Canvas API 绘制图像。Canvas API 的 `drawImage()` 方法会用到由 `ImageResourceContent` 管理的图像数据。
    * JavaScript 可以通过 Fetch API 或 XMLHttpRequest 加载图像资源，这些请求最终也会由 Blink 的资源加载机制处理，涉及到 `ImageResourceContent`。
    * **假设输入:** JavaScript 代码 `const img = new Image(); img.src = 'dynamic.png';`。
    * **输出:** 当 `dynamic.png` 加载完成后，`ImageResourceContent` 会创建一个 `BitmapImage` 对象，并且可以通过 JavaScript 的 `img` 对象访问到图像的属性。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  `ImageResourceContent` 接收到一个 JPEG 图像的 `SharedBuffer` 数据，并且 HTTP 响应头部的 `Content-Type` 是 `image/jpeg`。
* **输出:** `ImageResourceContent` 会创建一个 `BitmapImage` 对象，使用 JPEG 解码器来解码 `SharedBuffer` 中的数据，并将解码后的像素数据存储在 `BitmapImage` 中。

* **假设输入:**  `ImageResourceContent` 已经加载了一个 GIF 动画，并且有多个观察者（例如，页面上的多个 `<img>` 标签正在显示相同的 GIF）。
* **输出:** 当 GIF 动画的帧发生变化时，`ImageResourceContent` 会通知所有注册的观察者，导致这些 `<img>` 标签上的 GIF 动画同步更新。

**用户或编程常见的使用错误举例:**

1. **错误的图像 URL:**
   * **用户操作:** 在 HTML 中输入一个不存在或错误的图像 URL，例如 `<img src="not-found.jpg">`。
   * **`ImageResourceContent` 行为:**  资源加载会失败，`ImageResourceContent` 的状态会变为错误状态 (`ResourceStatus::kLoadError`)，并且会通知观察者加载失败，可能导致页面上显示 broken image 图标。

2. **CORS (跨域资源共享) 问题:**
   * **用户操作:** 网页尝试加载来自不同域名但服务器没有设置正确 CORS 头的图像。
   * **`ImageResourceContent` 行为:**  浏览器会阻止跨域加载，`ImageResourceContent` 的状态也会变为错误状态 (`ResourceStatus::kLoadError`)。

3. **加载过大的图像导致性能问题:**
   * **用户操作:**  网页引用了分辨率非常高的图像，或者未优化的图像。
   * **`ImageResourceContent` 行为:**  解码和渲染大图像会消耗大量内存和 CPU 资源，可能导致页面卡顿或崩溃。虽然 `ImageResourceContent` 本身不直接阻止加载，但它会持有这些大的图像数据。

4. **不支持的图像格式:**
   * **用户操作:**  网页尝试加载浏览器不支持的图像格式，例如一些特定的 WebP 变种或 AVIF 版本。
   * **`ImageResourceContent` 行为:** 解码过程会失败，`ImageResourceContent` 的状态会变为解码错误状态 (`ResourceStatus::kDecodeError`)。

**用户操作如何一步步到达这里 (作为调试线索):**

假设开发者需要调试一个网页中图像加载不出来的问题：

1. **用户在浏览器地址栏输入网址并回车，或者点击一个包含图像的链接。**
2. **浏览器开始解析 HTML 页面。**
3. **当解析到 `<img>` 标签或 CSS 中定义的背景图像时，Blink 引擎会创建一个 `ImageResource` 对象来负责加载该图像。**
4. **`ImageResource` 对象会创建一个 `ImageResourceContent` 对象来管理图像的内容数据。**
5. **网络线程发起 HTTP 请求去获取图像数据。**
6. **接收到图像数据后，数据会被存储在一个 `SharedBuffer` 中。**
7. **`ImageResourceContent` 的 `UpdateImage()` 方法会被调用，传入 `SharedBuffer` 和加载状态。**
8. **`UpdateImage()` 方法会根据图像的 MIME 类型创建 `BitmapImage` 或 `SVGImage` 对象，并尝试解码数据。**
9. **如果解码成功，`ImageResourceContent` 会通知所有注册的观察者（例如，渲染对象），以便更新页面的显示。**
10. **如果加载或解码失败，`ImageResourceContent` 会将状态设置为错误，并通知观察者显示错误占位符或不显示图像。**

**调试线索:**

* **查看 Network 面板:** 开发者可以查看浏览器开发者工具的 Network 面板，确认图像请求的状态码（例如，200 OK 表示成功，404 Not Found 表示找不到资源）和响应头部的 `Content-Type`。
* **断点调试 `ImageResourceContent.cc`:**  开发者可以在 `ImageResourceContent::UpdateImage()`、`ImageResourceContent::NotifyObservers()` 等关键方法设置断点，查看图像数据的接收和处理过程，以及观察者的通知情况。
* **检查控制台错误信息:** 如果图像加载失败，浏览器控制台可能会输出相关的错误信息，例如 CORS 错误或解码错误。
* **使用 Blink 内部的调试工具:** Blink 引擎内部有一些调试工具和日志可以帮助开发者更深入地了解资源加载过程。

总而言之，`ImageResourceContent.cc` 是 Blink 渲染引擎中处理图像内容的核心组件，它连接了网络加载、图像解码、渲染显示等多个环节，并与前端技术（HTML, CSS, JavaScript）密切相关，共同支撑着网页上图像的呈现。

### 提示词
```
这是目录为blink/renderer/core/loader/resource/image_resource_content.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/loader/resource/image_resource_content.h"

#include <memory>

#include "base/auto_reset.h"
#include "base/metrics/histogram_macros.h"
#include "base/not_fatal_until.h"
#include "base/time/time.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource_info.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource_observer.h"
#include "third_party/blink/renderer/core/svg/graphics/svg_image.h"
#include "third_party/blink/renderer/platform/graphics/bitmap_image.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_load_timing.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/network/mime/mime_type_registry.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "ui/gfx/geometry/size.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

class NullImageResourceInfo final
    : public GarbageCollected<NullImageResourceInfo>,
      public ImageResourceInfo {
 public:
  NullImageResourceInfo() = default;

  void Trace(Visitor* visitor) const override {
    ImageResourceInfo::Trace(visitor);
  }

 private:
  const KURL& Url() const override { return url_; }
  base::TimeTicks LoadResponseEnd() const override { return base::TimeTicks(); }
  base::TimeTicks LoadStart() const override { return base::TimeTicks(); }
  base::TimeTicks LoadEnd() const override { return base::TimeTicks(); }
  base::TimeTicks DiscoveryTime() const override { return base::TimeTicks(); }
  const ResourceResponse& GetResponse() const override { return response_; }
  bool IsCacheValidator() const override { return false; }
  bool IsAccessAllowed(
      DoesCurrentFrameHaveSingleSecurityOrigin) const override {
    return true;
  }
  bool HasCacheControlNoStoreHeader() const override { return false; }
  std::optional<ResourceError> GetResourceError() const override {
    return std::nullopt;
  }

  void SetDecodedSize(size_t) override {}
  void WillAddClientOrObserver() override {}
  void DidRemoveClientOrObserver() override {}
  void EmulateLoadStartedForInspector(
      ResourceFetcher*,
      const AtomicString& initiator_name) override {}

  void LoadDeferredImage(ResourceFetcher* fetcher) override {}

  bool IsAdResource() const override { return false; }

  const HashSet<String>* GetUnsupportedImageMimeTypes() const override {
    return nullptr;
  }

  std::optional<WebURLRequest::Priority> RequestPriority() const override {
    return std::nullopt;
  }

  const KURL url_;
  const ResourceResponse response_;
};

}  // namespace

ImageResourceContent::ImageResourceContent(scoped_refptr<blink::Image> image)
    : image_(std::move(image)) {
  DEFINE_STATIC_LOCAL(Persistent<NullImageResourceInfo>, null_info,
                      (MakeGarbageCollected<NullImageResourceInfo>()));
  info_ = null_info;
}

ImageResourceContent* ImageResourceContent::CreateLoaded(
    scoped_refptr<blink::Image> image) {
  DCHECK(image);
  ImageResourceContent* content =
      MakeGarbageCollected<ImageResourceContent>(std::move(image));
  content->content_status_ = ResourceStatus::kCached;
  return content;
}

ImageResourceContent* ImageResourceContent::Fetch(FetchParameters& params,
                                                  ResourceFetcher* fetcher) {
  // TODO(hiroshige): Remove direct references to ImageResource by making
  // the dependencies around ImageResource and ImageResourceContent cleaner.
  ImageResource* resource = ImageResource::Fetch(params, fetcher);
  if (!resource)
    return nullptr;

  return resource->GetContent();
}

void ImageResourceContent::SetImageResourceInfo(ImageResourceInfo* info) {
  info_ = info;
}

void ImageResourceContent::Trace(Visitor* visitor) const {
  visitor->Trace(info_);
  visitor->Trace(observers_);
  visitor->Trace(finished_observers_);
  ImageObserver::Trace(visitor);
  MediaTiming::Trace(visitor);
}

void ImageResourceContent::HandleObserverFinished(
    ImageResourceObserver* observer) {
  {
    ProhibitAddRemoveObserverInScope prohibit_add_remove_observer_in_scope(
        this);
    auto it = observers_.find(observer);
    if (it != observers_.end()) {
      observers_.erase(it);
      finished_observers_.insert(observer);
    }
  }
  observer->ImageNotifyFinished(this);
  UpdateImageAnimationPolicy();
}

void ImageResourceContent::AddObserver(ImageResourceObserver* observer) {
  CHECK(!is_add_remove_observer_prohibited_);

  info_->WillAddClientOrObserver();

  {
    ProhibitAddRemoveObserverInScope prohibit_add_remove_observer_in_scope(
        this);
    observers_.insert(observer);
  }

  if (info_->IsCacheValidator())
    return;

  if (image_ && !image_->IsNull()) {
    observer->ImageChanged(this, CanDeferInvalidation::kNo);
  }

  if (IsSufficientContentLoadedForPaint() && observers_.Contains(observer))
    HandleObserverFinished(observer);
}

void ImageResourceContent::RemoveObserver(ImageResourceObserver* observer) {
  DCHECK(observer);
  CHECK(!is_add_remove_observer_prohibited_);
  ProhibitAddRemoveObserverInScope prohibit_add_remove_observer_in_scope(this);

  auto it = observers_.find(observer);
  bool fully_erased;
  if (it != observers_.end()) {
    fully_erased = observers_.erase(it) && finished_observers_.find(observer) ==
                                               finished_observers_.end();
  } else {
    it = finished_observers_.find(observer);
    CHECK(it != finished_observers_.end(), base::NotFatalUntil::M130);
    fully_erased = finished_observers_.erase(it);
  }
  DidRemoveObserver();
  if (fully_erased)
    observer->NotifyImageFullyRemoved(this);
}

void ImageResourceContent::DidRemoveObserver() {
  info_->DidRemoveClientOrObserver();
}

static void PriorityFromObserver(
    const ImageResourceObserver* observer,
    ResourcePriority& priority,
    ResourcePriority& priority_excluding_image_loader) {
  ResourcePriority next_priority = observer->ComputeResourcePriority();
  if (next_priority.is_lcp_resource) {
    // Mark the resource as predicted LCP despite its visibility.
    priority.is_lcp_resource = true;
    priority_excluding_image_loader.is_lcp_resource = true;
  }

  if (next_priority.visibility == ResourcePriority::kNotVisible)
    return;

  priority.visibility = ResourcePriority::kVisible;
  priority.intra_priority_value += next_priority.intra_priority_value;

  if (next_priority.source != ResourcePriority::Source::kImageLoader) {
    priority_excluding_image_loader.visibility = ResourcePriority::kVisible;
    priority_excluding_image_loader.intra_priority_value +=
        next_priority.intra_priority_value;
  }
}

std::pair<ResourcePriority, ResourcePriority>
ImageResourceContent::PriorityFromObservers() const {
  ProhibitAddRemoveObserverInScope prohibit_add_remove_observer_in_scope(this);
  ResourcePriority priority;
  ResourcePriority priority_excluding_image_loader;

  for (const auto& it : finished_observers_)
    PriorityFromObserver(it.key, priority, priority_excluding_image_loader);
  for (const auto& it : observers_)
    PriorityFromObserver(it.key, priority, priority_excluding_image_loader);

  return std::make_pair(priority, priority_excluding_image_loader);
}

std::optional<WebURLRequest::Priority> ImageResourceContent::RequestPriority()
    const {
  return info_->RequestPriority();
}

void ImageResourceContent::DestroyDecodedData() {
  if (!image_)
    return;
  CHECK(!ErrorOccurred());
  image_->DestroyDecodedData();
}

void ImageResourceContent::DoResetAnimation() {
  if (image_)
    image_->ResetAnimation();
}

scoped_refptr<const SharedBuffer> ImageResourceContent::ResourceBuffer() const {
  if (image_)
    return image_->Data();
  return nullptr;
}

bool ImageResourceContent::ShouldUpdateImageImmediately() const {
  // If we don't have the size available yet, then update immediately since
  // we need to know the image size as soon as possible. Likewise for
  // animated images, update right away since we shouldn't throttle animated
  // images.
  return size_available_ == Image::kSizeUnavailable ||
         (image_ && image_->MaybeAnimated());
}

blink::Image* ImageResourceContent::GetImage() const {
  if (!image_ || ErrorOccurred())
    return Image::NullImage();

  return image_.get();
}

gfx::Size ImageResourceContent::IntrinsicSize(
    RespectImageOrientationEnum should_respect_image_orientation) const {
  if (!image_)
    return gfx::Size();
  RespectImageOrientationEnum respect_orientation =
      ForceOrientationIfNecessary(should_respect_image_orientation);
  return image_->Size(respect_orientation);
}

RespectImageOrientationEnum ImageResourceContent::ForceOrientationIfNecessary(
    RespectImageOrientationEnum default_orientation) const {
  if (image_ && image_->IsBitmapImage() && !IsAccessAllowed())
    return kRespectImageOrientation;
  return default_orientation;
}

void ImageResourceContent::NotifyObservers(
    NotifyFinishOption notifying_finish_option,
    CanDeferInvalidation defer) {
  {
    HeapVector<Member<ImageResourceObserver>> finished_observers_as_vector;
    {
      ProhibitAddRemoveObserverInScope prohibit_add_remove_observer_in_scope(
          this);
      CopyToVector(finished_observers_, finished_observers_as_vector);
    }

    for (ImageResourceObserver* observer : finished_observers_as_vector) {
      if (finished_observers_.Contains(observer))
        observer->ImageChanged(this, defer);
    }
  }
  {
    HeapVector<Member<ImageResourceObserver>> observers_as_vector;
    {
      ProhibitAddRemoveObserverInScope prohibit_add_remove_observer_in_scope(
          this);
      CopyToVector(observers_, observers_as_vector);
    }

    for (ImageResourceObserver* observer : observers_as_vector) {
      if (observers_.Contains(observer)) {
        observer->ImageChanged(this, defer);
        if (notifying_finish_option == kShouldNotifyFinish &&
            observers_.Contains(observer)) {
          HandleObserverFinished(observer);
        }
      }
    }
  }
}

scoped_refptr<Image> ImageResourceContent::CreateImage(bool is_multipart) {
  String content_dpr_value =
      info_->GetResponse().HttpHeaderField(http_names::kContentDPR);
  wtf_size_t comma = content_dpr_value.ReverseFind(',');
  if (comma != kNotFound && comma < content_dpr_value.length() - 1) {
    content_dpr_value = content_dpr_value.Substring(comma + 1);
  }
  device_pixel_ratio_header_value_ =
      content_dpr_value.ToFloat(&has_device_pixel_ratio_header_value_);
  if (!has_device_pixel_ratio_header_value_ ||
      device_pixel_ratio_header_value_ <= 0.0) {
    device_pixel_ratio_header_value_ = 1.0;
    has_device_pixel_ratio_header_value_ = false;
  }
  if (info_->GetResponse().MimeType() == "image/svg+xml")
    return SVGImage::Create(this, is_multipart);
  return BitmapImage::Create(this, is_multipart);
}

void ImageResourceContent::ClearImage() {
  if (!image_)
    return;

  // If our Image has an observer, it's always us so we need to clear the back
  // pointer before dropping our reference.
  image_->ClearImageObserver();
  image_ = nullptr;
  size_available_ = Image::kSizeUnavailable;
}

// |new_status| is the status of corresponding ImageResource.
void ImageResourceContent::UpdateToLoadedContentStatus(
    ResourceStatus new_status) {
  // When |ShouldNotifyFinish|, we set content_status_
  // to a loaded ResourceStatus.

  // Checks |new_status| (i.e. Resource's current status).
  switch (new_status) {
    case ResourceStatus::kCached:
    case ResourceStatus::kPending:
      // In case of successful load, Resource's status can be
      // kCached (e.g. for second part of multipart image) or
      // still Pending (e.g. for a non-multipart image).
      // Therefore we use kCached as the new state here.
      new_status = ResourceStatus::kCached;
      break;

    case ResourceStatus::kLoadError:
    case ResourceStatus::kDecodeError:
      // In case of error, Resource's status is set to an error status
      // before UpdateImage() and thus we use the error status as-is.
      break;

    case ResourceStatus::kNotStarted:
      CHECK(false);
      break;
  }

  // Updates the status.
  content_status_ = new_status;
}

void ImageResourceContent::NotifyStartLoad() {
  // Checks ImageResourceContent's previous status.
  switch (GetContentStatus()) {
    case ResourceStatus::kPending:
      CHECK(false);
      break;

    case ResourceStatus::kNotStarted:
      // Normal load start.
      break;

    case ResourceStatus::kCached:
    case ResourceStatus::kLoadError:
    case ResourceStatus::kDecodeError:
      // Load start due to revalidation/reload.
      break;
  }

  content_status_ = ResourceStatus::kPending;
}

void ImageResourceContent::AsyncLoadCompleted(const blink::Image* image) {
  if (image_ != image)
    return;
  CHECK_EQ(size_available_, Image::kSizeAvailableAndLoadingAsynchronously);
  size_available_ = Image::kSizeAvailable;
  UpdateToLoadedContentStatus(ResourceStatus::kCached);
  NotifyObservers(kShouldNotifyFinish, CanDeferInvalidation::kNo);
}

ImageResourceContent::UpdateImageResult ImageResourceContent::UpdateImage(
    scoped_refptr<SharedBuffer> data,
    ResourceStatus status,
    UpdateImageOption update_image_option,
    bool all_data_received,
    bool is_multipart) {
  TRACE_EVENT0("blink", "ImageResourceContent::updateImage");

#if DCHECK_IS_ON()
  DCHECK(!is_update_image_being_called_);
  base::AutoReset<bool> scope(&is_update_image_being_called_, true);
#endif

  // Clears the existing image, if instructed by |updateImageOption|.
  switch (update_image_option) {
    case kClearAndUpdateImage:
    case kClearImageAndNotifyObservers:
      ClearImage();
      break;
    case kUpdateImage:
      break;
  }

  // Updates the image, if instructed by |updateImageOption|.
  switch (update_image_option) {
    case kClearImageAndNotifyObservers:
      DCHECK(!data);
      break;

    case kUpdateImage:
    case kClearAndUpdateImage:
      // Have the image update its data from its internal buffer. It will not do
      // anything now, but will delay decoding until queried for info (like size
      // or specific image frames).
      if (data) {
        if (!image_)
          image_ = CreateImage(is_multipart);
        DCHECK(image_);
        size_available_ = image_->SetData(std::move(data), all_data_received);
        DCHECK(all_data_received ||
               size_available_ !=
                   Image::kSizeAvailableAndLoadingAsynchronously);
      }

      // Go ahead and tell our observers to try to draw if we have either
      // received all the data or the size is known. Each chunk from the network
      // causes observers to repaint, which will force that chunk to decode.
      if (size_available_ == Image::kSizeUnavailable && !all_data_received)
        return UpdateImageResult::kNoDecodeError;

      if (image_) {
        // Mime type could be null, see https://crbug.com/1485926.
        if (!image_->MimeType()) {
          return UpdateImageResult::kShouldDecodeError;
        }
        const HashSet<String>* unsupported_mime_types =
            info_->GetUnsupportedImageMimeTypes();
        if (unsupported_mime_types &&
            unsupported_mime_types->Contains(image_->MimeType())) {
          return UpdateImageResult::kShouldDecodeError;
        }
      }

      // As per spec, zero intrinsic size SVG is a valid image so do not
      // consider such an image as DecodeError.
      // https://www.w3.org/TR/SVG/struct.html#SVGElementWidthAttribute
      if (!image_ ||
          (image_->IsNull() && (!IsA<SVGImage>(image_.get()) ||
                                size_available_ == Image::kSizeUnavailable))) {
        ClearImage();
        return UpdateImageResult::kShouldDecodeError;
      }
      break;
  }

  DCHECK(all_data_received ||
         size_available_ != Image::kSizeAvailableAndLoadingAsynchronously);

  // Notifies the observers.
  // It would be nice to only redraw the decoded band of the image, but with the
  // current design (decoding delayed until painting) that seems hard.
  //
  // In the case of kSizeAvailableAndLoadingAsynchronously, we are waiting for
  // SVG image completion, and thus we notify observers of kDoNotNotifyFinish
  // here, and will notify observers of finish later in AsyncLoadCompleted().
  //
  // Don't allow defering of invalidation if it resulted from a data update.
  // This is necessary to ensure that all PaintImages in a recording committed
  // to the compositor have the same data.
  if (all_data_received &&
      size_available_ != Image::kSizeAvailableAndLoadingAsynchronously) {
    UpdateToLoadedContentStatus(status);
    NotifyObservers(kShouldNotifyFinish, CanDeferInvalidation::kNo);
  } else {
    NotifyObservers(kDoNotNotifyFinish, CanDeferInvalidation::kNo);
  }

  return UpdateImageResult::kNoDecodeError;
}

ImageDecoder::CompressionFormat ImageResourceContent::GetCompressionFormat()
    const {
  if (!image_)
    return ImageDecoder::kUndefinedFormat;
  return ImageDecoder::GetCompressionFormat(image_->Data(),
                                            GetResponse().HttpContentType());
}

uint64_t ImageResourceContent::ContentSizeForEntropy() const {
  int64_t resource_length = GetResponse().ExpectedContentLength();
  if (resource_length <= 0) {
    if (image_ && image_->HasData()) {
      // WPT and LayoutTests server returns -1 or 0 for the content length.
      resource_length = image_->DataSize();
    } else {
      resource_length = 0;
    }
  }
  return resource_length;
}

void ImageResourceContent::DecodedSizeChangedTo(const blink::Image* image,
                                                size_t new_size) {
  if (!image || image != image_)
    return;

  info_->SetDecodedSize(new_size);
}

bool ImageResourceContent::ShouldPauseAnimation(const blink::Image* image) {
  if (!image || image != image_)
    return false;

  ProhibitAddRemoveObserverInScope prohibit_add_remove_observer_in_scope(this);

  for (const auto& it : finished_observers_) {
    if (it.key->WillRenderImage())
      return false;
  }

  for (const auto& it : observers_) {
    if (it.key->WillRenderImage())
      return false;
  }

  return true;
}

void ImageResourceContent::UpdateImageAnimationPolicy() {
  if (!image_)
    return;

  mojom::blink::ImageAnimationPolicy new_policy =
      mojom::blink::ImageAnimationPolicy::kImageAnimationPolicyAllowed;
  {
    ProhibitAddRemoveObserverInScope prohibit_add_remove_observer_in_scope(
        this);
    for (const auto& it : finished_observers_) {
      if (it.key->GetImageAnimationPolicy(new_policy))
        break;
    }
    for (const auto& it : observers_) {
      if (it.key->GetImageAnimationPolicy(new_policy))
        break;
    }
  }

  image_->SetAnimationPolicy(new_policy);
}

void ImageResourceContent::Changed(const blink::Image* image) {
  if (!image || image != image_)
    return;
  NotifyObservers(kDoNotNotifyFinish, CanDeferInvalidation::kYes);
}

bool ImageResourceContent::IsAccessAllowed() const {
  return info_->IsAccessAllowed(
      GetImage()->CurrentFrameHasSingleSecurityOrigin()
          ? ImageResourceInfo::kHasSingleSecurityOrigin
          : ImageResourceInfo::kHasMultipleSecurityOrigin);
}

void ImageResourceContent::EmulateLoadStartedForInspector(
    ResourceFetcher* fetcher,
    const AtomicString& initiator_name) {
  info_->EmulateLoadStartedForInspector(fetcher, initiator_name);
}

void ImageResourceContent::SetIsSufficientContentLoadedForPaint() {
  NOTREACHED();
}

bool ImageResourceContent::IsSufficientContentLoadedForPaint() const {
  return IsLoaded();
}

bool ImageResourceContent::IsLoaded() const {
  return GetContentStatus() > ResourceStatus::kPending;
}

bool ImageResourceContent::IsLoading() const {
  return GetContentStatus() == ResourceStatus::kPending;
}

bool ImageResourceContent::ErrorOccurred() const {
  return GetContentStatus() == ResourceStatus::kLoadError ||
         GetContentStatus() == ResourceStatus::kDecodeError;
}

bool ImageResourceContent::LoadFailedOrCanceled() const {
  return GetContentStatus() == ResourceStatus::kLoadError;
}

ResourceStatus ImageResourceContent::GetContentStatus() const {
  return content_status_;
}

bool ImageResourceContent::IsAnimatedImage() const {
  return image_ && !image_->IsNull() && image_->MaybeAnimated();
}

bool ImageResourceContent::IsPaintedFirstFrame() const {
  return IsAnimatedImage() && image_->CurrentFrameIsComplete();
}

bool ImageResourceContent::TimingAllowPassed() const {
  return GetResponse().TimingAllowPassed();
}

// TODO(hiroshige): Consider removing the following methods, or stopping
// redirecting to ImageResource.
const KURL& ImageResourceContent::Url() const {
  return info_->Url();
}

bool ImageResourceContent::IsDataUrl() const {
  return Url().ProtocolIsData();
}

AtomicString ImageResourceContent::MediaType() const {
  if (!image_)
    return AtomicString();
  return AtomicString(image_->FilenameExtension());
}

void ImageResourceContent::SetIsBroken() {
  is_broken_ = true;
}

bool ImageResourceContent::IsBroken() const {
  return is_broken_;
}

base::TimeTicks ImageResourceContent::DiscoveryTime() const {
  return info_->DiscoveryTime();
}

base::TimeTicks ImageResourceContent::LoadStart() const {
  return info_->LoadStart();
}

base::TimeTicks ImageResourceContent::LoadEnd() const {
  return info_->LoadEnd();
}

base::TimeTicks ImageResourceContent::LoadResponseEnd() const {
  return info_->LoadResponseEnd();
}

bool ImageResourceContent::HasCacheControlNoStoreHeader() const {
  return info_->HasCacheControlNoStoreHeader();
}

float ImageResourceContent::DevicePixelRatioHeaderValue() const {
  return device_pixel_ratio_header_value_;
}

bool ImageResourceContent::HasDevicePixelRatioHeaderValue() const {
  return has_device_pixel_ratio_header_value_;
}

const ResourceResponse& ImageResourceContent::GetResponse() const {
  return info_->GetResponse();
}

std::optional<ResourceError> ImageResourceContent::GetResourceError() const {
  return info_->GetResourceError();
}

bool ImageResourceContent::IsCacheValidator() const {
  return info_->IsCacheValidator();
}

void ImageResourceContent::LoadDeferredImage(ResourceFetcher* fetcher) {
  info_->LoadDeferredImage(fetcher);
}

bool ImageResourceContent::IsAdResource() const {
  return info_->IsAdResource();
}

void ImageResourceContent::RecordDecodedImageType(UseCounter* use_counter) {
  if (auto* bitmap_image = DynamicTo<BitmapImage>(image_.get()))
    bitmap_image->RecordDecodedImageType(use_counter);
}

}  // namespace blink
```