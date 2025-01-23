Response:
Let's break down the thought process to analyze the provided C++ code for `ImageDownloaderImpl.cc`.

**1. Initial Reading and Goal Identification:**

The first step is a quick skim to get a general sense of the file. The name "ImageDownloaderImpl" strongly suggests its primary function is downloading images. The comments about copyright and licensing confirm it's Chromium code. The `#include` statements hint at dependencies related to network requests, image decoding, and accessibility.

The request asks for the following:

* Functionality of the file.
* Relationship to JavaScript, HTML, and CSS.
* Logical reasoning (input/output).
* Common user/programming errors.
* User steps to reach this code (debugging).

**2. Deeper Dive - Section by Section:**

Now, go through the code more methodically.

* **Includes:** Note the important includes:
    * `mojom/fetch/fetch_api_request.mojom-blink.h`:  This confirms interaction with the Fetch API, which is exposed to JavaScript.
    * `public/platform/web_data.h`, `public/platform/web_string.h`, `public/web/web_image.h`:  These are Blink's platform abstractions for data, strings, and image handling, crucial for understanding how Blink processes web content.
    * `core/dom/document.h`, `core/frame/local_dom_window.h`, `core/frame/local_frame.h`: These point to the DOM structure and frame management, highlighting the integration of image downloading within the rendering engine.
    * `modules/accessibility/ax_object.h`:  Indicates accessibility features are involved in image retrieval.
    * `modules/image_downloader/multi_resolution_image_resource_fetcher.h`:  Reveals the use of a dedicated class for fetching images, especially for handling multiple resolutions.
    * Skia (`skia/ext/image_operations.h`): Image manipulation library, likely for resizing.

* **Anonymous Namespace:**  Focus on the functions within the anonymous namespace. These are internal helpers:
    * `DecodeImageData`: Clearly decodes raw image data based on MIME type. SVG handling is a key detail.
    * `ImagesFromDataUrl`:  Parses data URLs and uses `DecodeImageData`.
    * `ResizeImage`:  Resizes a single `SkBitmap`.
    * `FilterAndResizeImagesForMaximalSize`:  The most complex helper. It filters images based on a maximum size, and if none fit, it resizes the smallest one.

* **`ImageDownloaderImpl` Class:** This is the core of the functionality.
    * **`kSupplementName`:**  An internal identifier for Blink's supplement system.
    * **`From()` and `ProvideTo()`:**  Standard methods for Blink supplements, allowing access to the `ImageDownloaderImpl` for a given frame.
    * **Constructor:** Initializes the Mojo receiver for communication with other processes.
    * **`CreateMojoService()`:** Sets up the Mojo interface, essential for inter-process communication in Chromium.
    * **`DownloadImage()`:**  The main entry point for downloading an image given a URL. Handles data URLs directly and delegates other URLs to `FetchImage`. Note the size constraints and the callback.
    * **`DownloadImageFromAxNode()`:**  Downloads an image associated with an accessibility node. This links image downloading to accessibility features.
    * **`DidDownloadImage()`:**  Processes the downloaded images, applying the size filtering and resizing.
    * **`FetchImage()`:**  Creates and starts the `MultiResolutionImageResourceFetcher`.
    * **`DidFetchImage()`:**  Handles the result of the fetch, decodes the image data, and cleans up the fetcher.
    * **`Trace()`:** For Blink's garbage collection and debugging.
    * **`ContextDestroyed()`:**  Handles cleanup when the associated frame is destroyed.

**3. Identifying Relationships with Web Technologies:**

Now, connect the dots between the code and web technologies:

* **JavaScript:**  The Mojo interface (`mojom::blink::ImageDownloader`) is the bridge. JavaScript code (via Blink's bindings) can call methods on this interface to initiate image downloads. Think about the `<img>` tag's `src` attribute being dynamically changed via JavaScript.
* **HTML:** The `<img>` tag is the most direct relationship. The browser needs to download images specified in `src` attributes. The `srcset` attribute is relevant to the multi-resolution fetching.
* **CSS:** Background images specified in CSS rules also need to be downloaded. `url()` in CSS properties triggers image fetching. `image-set()` is related to multi-resolution images.

**4. Logical Reasoning (Input/Output):**

For `FilterAndResizeImagesForMaximalSize`, constructing a simple example helps:

* **Input:**  A vector of `SkBitmap`s with different sizes, a `max_image_size`.
* **Process:** The function filters out images larger than `max_image_size`. If the result is empty, it finds the smallest original image and resizes it.
* **Output:** A vector of `SkBitmap`s (either the filtered ones or the resized smallest one), and a corresponding vector of original sizes.

**5. Common Errors:**

Think about scenarios where things could go wrong:

* **Invalid URL:**  User provides a malformed URL in the `src` attribute.
* **Network Issues:**  The image server is down, or there's a network problem.
* **Incorrect MIME Type:** The server returns the wrong MIME type for the image data.
* **Large Images:**  User uploads very large images, potentially causing performance problems if not handled correctly (this is where the resizing comes in).

**6. User Steps and Debugging:**

Consider how a user's actions in the browser lead to this code being executed:

* **Simple `<img>` tag:** The browser parses the HTML, encounters an `<img>` tag, extracts the `src`, and initiates a download.
* **JavaScript image loading:** JavaScript dynamically creates an `Image` object or modifies the `src` of an existing one.
* **CSS background image:** The CSS parser encounters a `background-image: url(...)` rule and triggers the download.
* **Accessibility features:**  Screen readers might request image data for accessibility purposes.

For debugging, imagine setting breakpoints in `DownloadImage`, `FetchImage`, and `DidFetchImage` to trace the flow of execution when an image fails to load.

**7. Structuring the Answer:**

Finally, organize the findings into a clear and coherent answer, addressing each part of the original request. Use headings, bullet points, and examples to make the information easy to understand. Start with a high-level summary and then delve into the details. Use code snippets where appropriate.

**Self-Correction/Refinement:**

During the analysis, I might realize I missed something or made an incorrect assumption. For example, initially, I might not have fully grasped the significance of the Mojo interface. Reviewing the `CreateMojoService` and how it's used in `DownloadImage` would correct this. Similarly, realizing the connection between `DownloadImageFromAxNode` and accessibility features reinforces the file's role beyond just basic image loading. The key is to continuously refine the understanding as more details emerge from the code.
这是 `blink/renderer/modules/image_downloader/image_downloader_impl.cc` 文件的功能列表以及它与 JavaScript、HTML、CSS 的关系，逻辑推理，用户错误和调试线索的说明。

**文件功能:**

`ImageDownloaderImpl.cc` 文件实现了 `ImageDownloader` 接口，负责在 Blink 渲染引擎中下载和处理图像。其主要功能包括：

1. **下载图像:**
   - 根据给定的 URL 下载图像资源。
   - 支持 HTTP(S) 和 data URL 协议。
   - 可以选择绕过缓存。
   - 可以指定首选的图像尺寸。
   - 可以限制下载图像的最大尺寸。
   - 使用 `MultiResolutionImageResourceFetcher` 来处理可能存在多分辨率的图像。

2. **解码图像数据:**
   - 将下载的图像数据解码为 `SkBitmap` 对象。
   - 支持多种图像格式，包括 SVG。

3. **处理 data URL:**
   - 解析 data URL 并解码其中的图像数据。

4. **调整图像尺寸:**
   - 根据 `max_bitmap_size` 限制，按比例缩小图像。
   - 提供过滤和调整图像尺寸的功能，确保最终使用的图像不会超过指定的最大尺寸。

5. **为可访问性下载图像:**
   - 允许根据无障碍节点 (AXNode) 的 ID 下载关联的图像。
   - 从 AXNode 获取图像的 data URL。

6. **作为 Blink 渲染引擎的补充 (Supplement):**
   - 作为 `LocalFrame` 的补充存在，这意味着每个 frame 都有一个 `ImageDownloaderImpl` 实例。
   - 通过 Mojo 接口与其他进程通信。

**与 JavaScript, HTML, CSS 的关系:**

`ImageDownloaderImpl.cc` 的功能直接支持了 web 页面中图像的加载和显示，这与 JavaScript、HTML 和 CSS 息息相关：

* **HTML:**
    - **`<img>` 标签:** 当浏览器解析到 `<img>` 标签时，会提取 `src` 属性中的 URL，并通过 `ImageDownloaderImpl` 下载图像。
        - **举例:**  `<img src="https://example.com/image.png">`，浏览器会调用 `ImageDownloaderImpl::DownloadImage` 来下载 `image.png`。
    - **`<link rel="icon">` 标签:**  浏览器会使用 `ImageDownloaderImpl` 下载网站的 favicon。
        - **举例:** `<link rel="icon" href="/favicon.ico">`。

* **CSS:**
    - **`background-image` 属性:**  当 CSS 规则中使用了 `background-image: url(...)` 时，`ImageDownloaderImpl` 会被调用来下载背景图像。
        - **举例:** `body { background-image: url("image.jpg"); }`。
    - **`list-style-image` 属性:**  用于设置列表项标记的图像，也会调用 `ImageDownloaderImpl`。
        - **举例:** `ul { list-style-image: url("bullet.gif"); }`。
    - **`content` 属性 (用于生成内容):**  可以使用 `url()` 函数在 `::before` 或 `::after` 伪元素中插入图像，这也会触发图像下载。
        - **举例:** `a::before { content: url("arrow.png"); }`。
    - **`image-set()` CSS 函数:**  用于提供不同分辨率的图像资源，`ImageDownloaderImpl` 可以利用这些信息进行下载。

* **JavaScript:**
    - **动态创建 `<img>` 元素:**  JavaScript 可以动态创建 `<img>` 元素并设置其 `src` 属性，从而触发图像下载。
        - **举例:**
          ```javascript
          var img = new Image();
          img.src = "https://example.com/dynamic_image.png";
          document.body.appendChild(img);
          ```
    - **修改现有 `<img>` 元素的 `src` 属性:**  JavaScript 可以修改页面上现有 `<img>` 元素的 `src` 属性，导致浏览器重新下载图像。
        - **举例:** `document.getElementById('myImage').src = "new_image.jpg";`
    - **使用 `XMLHttpRequest` 或 `fetch` API 获取图像数据:**  虽然 `ImageDownloaderImpl` 主要处理渲染引擎内部的图像下载，但 JavaScript 可以使用 `fetch` API 获取图像数据，然后可能通过其他方式（例如 Canvas）进行处理。虽然不是直接调用，但最终渲染仍然可能涉及到 `SkBitmap` 的使用。
    - **无障碍功能相关的 JavaScript API:**  例如，某些辅助技术相关的 JavaScript 代码可能需要获取图像信息，这可能间接涉及到通过 AXNode 获取图像的功能。

**逻辑推理 (假设输入与输出):**

**场景 1: 下载一个普通的 PNG 图片**

* **假设输入:**
    * `image_url`: "https://example.com/cat.png"
    * `is_favicon`: false
    * `preferred_size`: (0, 0)  (没有指定首选尺寸)
    * `max_bitmap_size`: 100 (限制最大尺寸为 100 像素)
    * `bypass_cache`: false
* **逻辑推理:**
    1. `DownloadImage` 方法被调用。
    2. 由于 URL 不是 data URL，调用 `FetchImage` 创建 `MultiResolutionImageResourceFetcher` 来下载 "https://example.com/cat.png"。
    3. `MultiResolutionImageResourceFetcher` 发起网络请求。
    4. 假设请求成功，返回 HTTP 状态码 200，图像数据以及 MIME 类型 "image/png"。
    5. `DidFetchImage` 被调用，使用 "image/png" 解码图像数据得到 `SkBitmap` 数组。
    6. `DidDownloadImage` 被调用，将解码后的 `SkBitmap` 数组传递给 `FilterAndResizeImagesForMaximalSize`。
    7. `FilterAndResizeImagesForMaximalSize` 会检查图像尺寸，如果原始图像的宽度或高度大于 100 像素，则会按比例缩小。
    8. **假设原始图像为 200x150:**  缩小后的 `SkBitmap` 尺寸可能接近 100x75。
    9. **输出:** `DownloadImageCallback` 被调用，携带 HTTP 状态码 200，包含缩小后的 `SkBitmap` 的数组，以及原始尺寸 (200x150) 的数组。

**场景 2: 下载一个 data URL 的 SVG 图片**

* **假设输入:**
    * `image_url`: "data:image/svg+xml,%3Csvg..." (一个 SVG 数据的 data URL)
    * `is_favicon`: false
    * `preferred_size`: (50, 50)
    * `max_bitmap_size`: 0 (没有限制最大尺寸)
    * `bypass_cache`: false
* **逻辑推理:**
    1. `DownloadImage` 方法被调用。
    2. 由于 URL 是 data URL，调用 `ImagesFromDataUrl`。
    3. `ImagesFromDataUrl` 解析 data URL，提取 MIME 类型 "image/svg+xml" 和 SVG 数据。
    4. 调用 `DecodeImageData`，使用 `WebImage::DecodeSVG` 解码 SVG 数据，并尝试按照 `preferred_size` (50x50) 进行渲染。
    5. **假设 SVG 成功解码并渲染为 50x50 的位图。**
    6. `DidDownloadImage` 被调用，将解码后的 `SkBitmap` 数组传递给 `FilterAndResizeImagesForMaximalSize`。
    7. 由于 `max_bitmap_size` 为 0，不会进行尺寸过滤或调整。
    8. **输出:** `DownloadImageCallback` 被调用，携带 HTTP 状态码 0 (data URL 没有 HTTP 状态码)，包含一个 50x50 的 `SkBitmap` 的数组，以及原始尺寸 (50x50) 的数组。

**用户或编程常见的使用错误:**

1. **错误的图像 URL:** 用户在 HTML 或 JavaScript 中提供了无效的图像 URL，导致下载失败。
   - **举例:** `<img src="htp://example.com/image.png">` (缺少 's')，或者 URL 指向不存在的资源。
   - **结果:** `DidFetchImage` 或网络层会返回错误状态码，`DownloadImageCallback` 会收到错误信息。

2. **CORS (跨域资源共享) 问题:** 尝试下载来自不同源的图像，但服务器没有设置正确的 CORS 头，导致浏览器阻止访问。
   - **举例:** 页面在 `domain-a.com`，尝试加载 `domain-b.com/image.png`，但 `domain-b.com` 的服务器没有设置 `Access-Control-Allow-Origin` 头。
   - **结果:** 下载请求可能失败，或者即使下载成功，由于安全限制，渲染引擎可能无法使用该图像。

3. **混合内容 (Mixed Content):** 在 HTTPS 页面中加载 HTTP 资源（包括图像），浏览器可能会阻止该请求。
   - **举例:** HTTPS 页面包含 `<img src="http://example.com/image.png">`。
   - **结果:** 图像下载可能被阻止。

4. **过大的 `max_bitmap_size` 或 `preferred_size`:**  如果应用程序或代码中设置了过大的 `max_bitmap_size` 或 `preferred_size`，可能会导致下载和解码大量数据，消耗过多资源，影响性能。

5. **无限循环或重复下载:** 编程错误可能导致 JavaScript 代码不断地创建新的 `<img>` 元素或修改 `src` 属性，触发无限循环的图像下载。

6. **不正确的 data URL 格式:**  手动构造 data URL 时，格式错误可能导致解析失败。
   - **举例:** 缺少 MIME 类型，或者编码不正确。

**用户操作是如何一步步的到达这里，作为调试线索:**

以下是一些用户操作导致代码执行到 `ImageDownloaderImpl.cc` 的步骤，可以作为调试线索：

1. **用户在浏览器地址栏输入 URL 并访问一个网页:**
   - 浏览器解析 HTML 响应。
   - 当解析到 `<img>` 标签、CSS 中的 `background-image` 等需要加载图像的资源时，会创建相应的资源请求。
   - 这些请求会路由到 Blink 渲染引擎。
   - Blink 引擎会调用 `ImageDownloaderImpl::DownloadImage` 来处理图像下载。

2. **用户通过 JavaScript 操作 DOM，动态添加或修改包含图像 URL 的元素:**
   - JavaScript 代码执行，例如使用 `document.createElement('img')` 创建新的 `<img>` 元素并设置 `src` 属性。
   - 或者修改现有元素的 `src` 属性。
   - 这些操作会触发渲染引擎重新布局和渲染页面。
   - 当需要加载新的图像资源时，会调用 `ImageDownloaderImpl::DownloadImage`。

3. **用户与网页交互，触发需要加载新图像的操作:**
   - 例如，用户点击一个按钮，JavaScript 代码根据用户操作动态加载新的图片。
   - 滚动页面导致懒加载图片元素进入视口。

4. **浏览器需要加载网站的 favicon:**
   - 当用户访问一个网站时，浏览器会尝试下载该网站的 favicon。
   - 这也会调用 `ImageDownloaderImpl`。

5. **辅助功能软件请求图像信息:**
   - 辅助功能软件（例如屏幕阅读器）可能会请求页面元素的无障碍信息。
   - 如果需要获取与某个 AXNode 关联的图像数据，可能会调用 `ImageDownloaderImpl::DownloadImageFromAxNode`。

**调试线索:**

* **断点:** 在 `ImageDownloaderImpl::DownloadImage`, `ImageDownloaderImpl::FetchImage`, `ImageDownloaderImpl::DidFetchImage`, `DecodeImageData`, `FilterAndResizeImagesForMaximalSize` 等方法中设置断点，可以追踪图像下载和处理的流程。
* **网络面板:** 使用 Chrome 开发者工具的网络面板，可以查看图像请求的状态、URL、HTTP 头信息（包括 CORS 相关头）、响应内容等，帮助诊断网络问题或服务器配置问题。
* **控制台:**  查看浏览器控制台是否有与图像加载相关的错误或警告信息（例如 CORS 错误，混合内容警告）。
* **Blink 内部日志:** Chromium 提供了内部日志系统，可以查看更底层的图像加载和解码相关的日志信息。
* **Accessibility 工具:** 使用 Chrome 开发者工具的 Accessibility 面板，可以查看页面的无障碍树，了解辅助功能软件是如何获取图像信息的，从而理解 `DownloadImageFromAxNode` 的调用场景。

总而言之，`ImageDownloaderImpl.cc` 是 Blink 渲染引擎中负责图像下载和处理的关键组件，它与 Web 开发中的 HTML、CSS 和 JavaScript 紧密结合，共同实现了网页中图像的呈现。理解其功能和工作原理对于调试图像加载相关的问题至关重要。

### 提示词
```
这是目录为blink/renderer/modules/image_downloader/image_downloader_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/image_downloader/image_downloader_impl.h"

#include <utility>

#include "base/check.h"
#include "base/functional/bind.h"
#include "skia/ext/image_operations.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/platform/interface_registry.h"
#include "third_party/blink/public/platform/web_data.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_vector.h"
#include "third_party/blink/public/web/web_image.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object.h"
#include "third_party/blink/renderer/modules/image_downloader/multi_resolution_image_resource_fetcher.h"
#include "third_party/blink/renderer/platform/heap/visitor.h"
#include "third_party/blink/renderer/platform/network/network_utils.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "ui/gfx/geometry/size.h"

namespace {

WTF::Vector<SkBitmap> DecodeImageData(const std::string& data,
                                      const std::string& mime_type,
                                      const gfx::Size& preferred_size) {
  // Decode the image using Blink's image decoder.
  blink::WebData buffer(data.data(), data.size());
  WTF::Vector<SkBitmap> bitmaps;
  if (mime_type == "image/svg+xml") {
    SkBitmap bitmap = blink::WebImage::DecodeSVG(buffer, preferred_size);
    if (!bitmap.drawsNothing()) {
      bitmaps.push_back(bitmap);
    }
  } else {
    blink::WebVector<SkBitmap> original_bitmaps =
        blink::WebImage::FramesFromData(buffer);
    bitmaps.AppendRange(std::make_move_iterator(original_bitmaps.begin()),
                        std::make_move_iterator(original_bitmaps.end()));
    bitmaps.Reverse();
  }
  return bitmaps;
}

// Decodes a data: URL into one or more images, or no images in case of failure.
WTF::Vector<SkBitmap> ImagesFromDataUrl(const blink::KURL& url,
                                        const gfx::Size& preferred_size) {
  std::string mime_type, data;
  if (!blink::network_utils::IsDataURLMimeTypeSupported(url, &data,
                                                        &mime_type) ||
      data.empty()) {
    return WTF::Vector<SkBitmap>();
  }
  return DecodeImageData(data, mime_type, preferred_size);
}

//  Proportionally resizes the |image| to fit in a box of size
// |max_image_size|.
SkBitmap ResizeImage(const SkBitmap& image, uint32_t max_image_size) {
  if (max_image_size == 0) {
    return image;
  }
  uint32_t max_dimension = std::max(image.width(), image.height());
  if (max_dimension <= max_image_size) {
    return image;
  }
  // Proportionally resize the minimal image to fit in a box of size
  // max_image_size.
  return skia::ImageOperations::Resize(
      image, skia::ImageOperations::RESIZE_BEST,
      static_cast<uint32_t>(image.width()) * max_image_size / max_dimension,
      static_cast<uint32_t>(image.height()) * max_image_size / max_dimension);
}

// Filters the array of bitmaps, removing all images that do not fit in a box of
// size |max_image_size|. Returns the result if it is not empty. Otherwise,
// find the smallest image in the array and resize it proportionally to fit
// in a box of size |max_image_size|.
// Sets |original_image_sizes| to the sizes of |images| before resizing. Both
// output vectors are guaranteed to have the same size.
void FilterAndResizeImagesForMaximalSize(
    const WTF::Vector<SkBitmap>& unfiltered,
    uint32_t max_image_size,
    WTF::Vector<SkBitmap>* images,
    WTF::Vector<gfx::Size>* original_image_sizes) {
  images->clear();
  original_image_sizes->clear();

  if (unfiltered.empty()) {
    return;
  }

  if (max_image_size == 0) {
    max_image_size = std::numeric_limits<uint32_t>::max();
  }

  const SkBitmap* min_image = nullptr;
  uint32_t min_image_size = std::numeric_limits<uint32_t>::max();
  // Filter the images by |max_image_size|, and also identify the smallest image
  // in case all the images are bigger than |max_image_size|.
  for (const SkBitmap& image : unfiltered) {
    uint32_t current_size = std::max(image.width(), image.height());
    if (current_size < min_image_size) {
      min_image = &image;
      min_image_size = current_size;
    }
    if (static_cast<uint32_t>(image.width()) <= max_image_size &&
        static_cast<uint32_t>(image.height()) <= max_image_size) {
      images->push_back(image);
      original_image_sizes->push_back(gfx::Size(image.width(), image.height()));
    }
  }
  DCHECK(min_image);
  if (images->size()) {
    return;
  }
  // Proportionally resize the minimal image to fit in a box of size
  // |max_image_size|.
  SkBitmap resized = ResizeImage(*min_image, max_image_size);
  // Drop null or empty SkBitmap.
  if (resized.drawsNothing()) {
    return;
  }
  images->push_back(resized);
  original_image_sizes->push_back(
      gfx::Size(min_image->width(), min_image->height()));
}

}  // namespace

namespace blink {

// static
const char ImageDownloaderImpl::kSupplementName[] = "ImageDownloader";

// static
ImageDownloaderImpl* ImageDownloaderImpl::From(LocalFrame& frame) {
  return Supplement<LocalFrame>::From<ImageDownloaderImpl>(frame);
}

// static
void ImageDownloaderImpl::ProvideTo(LocalFrame& frame) {
  if (ImageDownloaderImpl::From(frame)) {
    return;
  }

  Supplement<LocalFrame>::ProvideTo(
      frame, MakeGarbageCollected<ImageDownloaderImpl>(frame));
}

ImageDownloaderImpl::ImageDownloaderImpl(LocalFrame& frame)
    : Supplement<LocalFrame>(frame),
      ExecutionContextLifecycleObserver(frame.DomWindow()),
      receiver_(this, frame.DomWindow()) {
  frame.GetInterfaceRegistry()->AddInterface(WTF::BindRepeating(
      &ImageDownloaderImpl::CreateMojoService, WrapWeakPersistent(this)));
}

ImageDownloaderImpl::~ImageDownloaderImpl() {}

void ImageDownloaderImpl::CreateMojoService(
    mojo::PendingReceiver<mojom::blink::ImageDownloader> receiver) {
  receiver_.Bind(std::move(receiver),
                 GetSupplementable()->GetTaskRunner(TaskType::kNetworking));
  receiver_.set_disconnect_handler(
      WTF::BindOnce(&ImageDownloaderImpl::Dispose, WrapWeakPersistent(this)));
}

// ImageDownloader methods:
void ImageDownloaderImpl::DownloadImage(const KURL& image_url,
                                        bool is_favicon,
                                        const gfx::Size& preferred_size,
                                        uint32_t max_bitmap_size,
                                        bool bypass_cache,
                                        DownloadImageCallback callback) {
  // Constrain the preferred size by the max bitmap size. This will prevent
  // resizing of the resulting image if the preferred size is used.
  gfx::Size constrained_preferred_size(preferred_size);
  uint32_t max_preferred_dimension =
      std::max(preferred_size.width(), preferred_size.height());
  if (max_bitmap_size && max_bitmap_size < max_preferred_dimension) {
    float scale = float(max_bitmap_size) / max_preferred_dimension;
    constrained_preferred_size = gfx::ScaleToFlooredSize(preferred_size, scale);
  }
  auto download_callback =
      WTF::BindOnce(&ImageDownloaderImpl::DidDownloadImage,
                    WrapPersistent(this), max_bitmap_size, std::move(callback));

  if (!image_url.ProtocolIsData()) {
    FetchImage(image_url, is_favicon, constrained_preferred_size, bypass_cache,
               std::move(download_callback));
    // Will complete asynchronously via ImageDownloaderImpl::DidFetchImage.
    return;
  }

  WTF::Vector<SkBitmap> result_images =
      ImagesFromDataUrl(image_url, constrained_preferred_size);
  std::move(download_callback).Run(0, result_images);
}

void ImageDownloaderImpl::DownloadImageFromAxNode(
    int ax_node_id,
    const gfx::Size& preferred_size,
    uint32_t max_bitmap_size,
    bool bypass_cache,
    DownloadImageCallback callback) {
  LocalFrame* frame = GetSupplementable();
  CHECK(frame);
  auto* document = frame->GetDocument();
  CHECK(document);
  auto* cache = document->ExistingAXObjectCache();

  const int NOT_FOUND = 404;

  // If accessibility is not enabled just return not found for the images.
  if (!cache) {
    std::move(callback).Run(NOT_FOUND, {}, {});
  }

  auto* obj = cache->ObjectFromAXID(ax_node_id);

  // Similarly if the object that the node id is referring to is not there, also
  // return not found.
  if (!obj) {
    std::move(callback).Run(NOT_FOUND, {}, {});
    return;
  }

  // Use the data url since the src attribute may not contain the scheme.
  KURL url(obj->ImageDataUrl(gfx::Size()));
  DownloadImage(url, /*is_favicon=*/false, preferred_size, max_bitmap_size,
                bypass_cache, std::move(callback));
}

void ImageDownloaderImpl::DidDownloadImage(
    uint32_t max_image_size,
    DownloadImageCallback callback,
    int32_t http_status_code,
    const WTF::Vector<SkBitmap>& images) {
  WTF::Vector<SkBitmap> result_images;
  WTF::Vector<gfx::Size> result_original_image_sizes;
  FilterAndResizeImagesForMaximalSize(images, max_image_size, &result_images,
                                      &result_original_image_sizes);

  DCHECK_EQ(result_images.size(), result_original_image_sizes.size());

  std::move(callback).Run(http_status_code, result_images,
                          result_original_image_sizes);
}

void ImageDownloaderImpl::Dispose() {
  receiver_.reset();
}

void ImageDownloaderImpl::FetchImage(const KURL& image_url,
                                     bool is_favicon,
                                     const gfx::Size& preferred_size,
                                     bool bypass_cache,
                                     DownloadCallback callback) {
  // Create an image resource fetcher and assign it with a call back object.
  image_fetchers_.push_back(
      std::make_unique<MultiResolutionImageResourceFetcher>(
          image_url, GetSupplementable(), is_favicon,
          bypass_cache ? blink::mojom::FetchCacheMode::kBypassCache
                       : blink::mojom::FetchCacheMode::kDefault,
          WTF::BindOnce(&ImageDownloaderImpl::DidFetchImage,
                        WrapPersistent(this), std::move(callback),
                        preferred_size)));
}

void ImageDownloaderImpl::DidFetchImage(
    DownloadCallback callback,
    const gfx::Size& preferred_size,
    MultiResolutionImageResourceFetcher* fetcher,
    const std::string& image_data,
    const WebString& mime_type) {
  int32_t http_status_code = fetcher->http_status_code();

  Vector<SkBitmap> images =
      DecodeImageData(image_data, mime_type.Utf8(), preferred_size);

  // Remove the image fetcher from our pending list. We're in the callback from
  // MultiResolutionImageResourceFetcher, best to delay deletion.
  for (auto it = image_fetchers_.begin(); it != image_fetchers_.end(); ++it) {
    MultiResolutionImageResourceFetcher* image_fetcher = it->get();
    DCHECK(image_fetcher);
    if (image_fetcher == fetcher) {
      it = image_fetchers_.erase(it);
      break;
    }
  }

  // |this| may be destructed after callback is run.
  std::move(callback).Run(http_status_code, images);
}

void ImageDownloaderImpl::Trace(Visitor* visitor) const {
  visitor->Trace(receiver_);
  Supplement<LocalFrame>::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

void ImageDownloaderImpl::ContextDestroyed() {
  for (const auto& fetcher : image_fetchers_) {
    // Will run callbacks with an empty image vector.
    fetcher->Dispose();
  }
  image_fetchers_.clear();
}

}  // namespace blink
```