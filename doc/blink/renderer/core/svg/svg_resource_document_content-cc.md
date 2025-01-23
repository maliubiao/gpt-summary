Response:
Let's break down the thought process for analyzing the `svg_resource_document_content.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relationship to web technologies (JavaScript, HTML, CSS), logical reasoning, common errors, and debugging information. Essentially, it's a comprehensive analysis of this specific Chromium component.

2. **Initial Scan and Key Terms:**  Start by quickly reading through the code, paying attention to class names, method names, included headers, and any comments. This helps identify the core purpose. Key terms that stand out immediately are: `SVGResourceDocumentContent`, `SVGDocumentResource`, `IsolatedSVGDocumentHost`, `SVGElement`, `SVGResourceDocumentCache`, `SVGResourceDocumentObserver`, `Document`, `Frame`, `ResourceStatus`, `Fetch`, `UpdateDocument`, `LoadingFinished`, `Observers`.

3. **Core Functionality - What Does It Do?** Based on the key terms, it seems this class is responsible for managing the content of an SVG resource (likely an external SVG file). It handles loading, caching, parsing, and notifying observers about changes. The `IsolatedSVGDocumentHost` suggests it's dealing with the actual rendering and parsing of the SVG within a separate context.

4. **Relationship to Web Technologies:**
    * **HTML:** SVG is often embedded within HTML using tags like `<image>`, `<object>`, `<iframe>`, or directly within the HTML structure. This class is responsible for handling the content *of* those SVG resources. The example of `<image xlink:href="image.svg#my-element" />` clearly demonstrates how this class would be involved in fetching and accessing the `#my-element` part.
    * **CSS:** CSS can style SVG elements. This class, by managing the SVG document, indirectly plays a role in how CSS is applied. The example of CSS targeting an SVG element by ID (`#my-shape { fill: red; }`) is relevant here, as this class is responsible for providing access to those elements.
    * **JavaScript:** JavaScript can manipulate the DOM of an SVG document. This class makes the parsed SVG `Document` accessible, enabling JavaScript interaction. The example of JavaScript using `getElementById()` is directly tied to the `GetResourceTarget()` method in this class.

5. **Logical Reasoning (Input/Output):**  Think about the core methods and how data flows.
    * **Input:** A URL pointing to an SVG resource.
    * **Processing:** The `Fetch()` method initiates the loading process, potentially using the cache. `UpdateDocument()` handles the actual data received. `IsolatedSVGDocumentHost` parses the SVG data.
    * **Output:** A `Document` object representing the parsed SVG, and notifications to observers when the content changes or loading is complete. The `GetResourceTarget()` method allows accessing specific elements within the SVG.

6. **Common Errors:** Consider what could go wrong in this process.
    * **Invalid SVG:**  The SVG file might be malformed.
    * **Network Errors:** The resource might not be found (404), or there might be network connectivity issues.
    * **CORS Issues:**  If the SVG is on a different origin, CORS restrictions could prevent loading.
    * **Incorrect Fragment Identifiers:**  Referring to a non-existent ID within the SVG.
    * **Disposal Issues:**  Trying to use the content after it's been disposed of.

7. **Debugging Clues (User Actions):** Trace back the user's actions that might lead to this code being executed.
    * **Loading a page with SVG:**  The most obvious case.
    * **Using `<img>`, `<object>`, `<iframe>` for SVGs:**  These trigger resource loading.
    * **CSS `background-image` with SVGs:** Similar to `<img>`.
    * **JavaScript manipulating SVG resources:**  Actions like setting the `src` attribute or fetching an SVG.
    * **Clicking on a link to an SVG file:**  The browser would load and render the SVG.

8. **Structure the Answer:**  Organize the information logically using headings and bullet points for clarity. Start with the core functionality and then address the specific points in the request (JavaScript, HTML, CSS, logic, errors, debugging).

9. **Refine and Elaborate:**  Review the generated answer. Ensure the explanations are clear and accurate. Add more detail and specific examples where necessary. For instance, explain *why* `AllowedRequestMode` checks for same-origin and CORS with same-origin credentials.

10. **Self-Correction/Improvements during the process:**
    * Initially, I might have focused too much on the technical details of `IsolatedSVGDocumentHost`. Realizing the request asks for a broader perspective, I would shift to emphasize the user-facing aspects and the relationship with web technologies.
    * I might initially forget to mention the caching mechanism, which is a significant aspect of this class. Reviewing the code, I'd see the interaction with `SVGResourceDocumentCache` and add that detail.
    * I might provide overly technical error scenarios. I would refine them to be more user-centric, like "Typing the wrong URL" instead of just "Network error."

By following this thought process, combining code analysis with an understanding of web development concepts, one can arrive at a comprehensive and helpful explanation like the example provided in the initial prompt.
好的，让我们详细分析一下 `blink/renderer/core/svg/svg_resource_document_content.cc` 这个文件。

**功能概述**

`SVGResourceDocumentContent` 类在 Blink 渲染引擎中负责管理外部 SVG 资源的内容。它的主要功能包括：

1. **加载和解析 SVG 资源:** 从网络或缓存中获取 SVG 数据，并使用 `IsolatedSVGDocumentHost` 来解析这些数据，创建一个独立的 SVG 文档。
2. **缓存管理:**  与 `SVGResourceDocumentCache` 协同工作，缓存已加载的 SVG 资源，以便在后续使用时快速获取。
3. **状态管理:** 跟踪 SVG 资源的加载状态 (未开始、加载中、已缓存、加载错误、解码错误)。
4. **观察者模式:**  允许其他对象（例如 `ExternalSVGResource` 和 `SVGUseElement`) 注册为观察者，以便在 SVG 资源加载完成或内容发生变化时得到通知。
5. **资源目标获取:**  提供方法 `GetResourceTarget`，根据元素的 ID 获取 SVG 文档中的特定元素，这对于诸如 `<use>` 元素引用 SVG 文档中的符号非常重要。
6. **内容变更通知:**  当 SVG 文档的内容发生变化（例如，通过脚本动画）时，通知所有观察者。
7. **生命周期管理:**  处理 SVG 资源的加载、卸载和清理过程。

**与 JavaScript, HTML, CSS 的关系及举例说明**

`SVGResourceDocumentContent` 在幕后支持了 SVG 在 Web 页面中的使用，它与 JavaScript, HTML, CSS 都有着密切的关系：

* **HTML:**
    * **嵌入 SVG:** 当 HTML 中使用 `<image>`, `<object>`, `<iframe>` 等标签引用外部 SVG 文件时，Blink 会创建 `SVGResourceDocumentContent` 对象来处理该 SVG 文件的加载和解析。
    * **`<use>` 元素:**  `<use>` 元素允许在 SVG 文档中重用其他 SVG 文档中的元素。`SVGResourceDocumentContent` 负责加载被 `<use>` 元素引用的外部 SVG 文件，并通过 `GetResourceTarget` 方法找到目标元素。
        * **举例:**  HTML 中有 `<svg><use xlink:href="image.svg#my-element" /></svg>`。这里的 `image.svg` 将由 `SVGResourceDocumentContent` 加载，并通过 `#my-element` 定位到 SVG 文件中的特定元素。
* **CSS:**
    * **SVG 样式:** CSS 可以用来样式化 SVG 元素。当一个外部 SVG 被加载后，其内部的元素就可以被 CSS 选择器选中并应用样式。`SVGResourceDocumentContent` 确保 SVG 文档被正确加载和解析，使得 CSS 能够生效。
    * **`background-image` 等属性:**  CSS 的 `background-image` 属性可以使用 SVG 文件作为背景。`SVGResourceDocumentContent` 负责加载这些 SVG 背景图像。
        * **举例:**  CSS 中有 `div { background-image: url("icon.svg"); }`。 `icon.svg` 会通过 `SVGResourceDocumentContent` 进行加载。
* **JavaScript:**
    * **DOM 操作:** JavaScript 可以访问和操作 SVG 文档的 DOM 结构。`SVGResourceDocumentContent` 提供了获取已加载 SVG 文档的方法 `GetDocument()`，使得 JavaScript 可以通过标准 DOM API (如 `getElementById`, `querySelector` 等) 与 SVG 内容交互。
    * **动态更新:** JavaScript 可以动态修改 SVG 文档的内容。当 SVG 文档通过 `IsolatedSVGDocumentHost` 被修改后，`SVGResourceDocumentContent` 会通知观察者，以便相关的渲染对象进行更新。
        * **举例:**  JavaScript 代码 `document.getElementById('my-svg-element').setAttribute('fill', 'red');`  如果 'my-svg-element' 存在于由 `SVGResourceDocumentContent` 管理的外部 SVG 文档中，那么这段代码会修改 SVG 内容，并且 `ContentChanged()` 方法会被调用，通知观察者进行更新。

**逻辑推理、假设输入与输出**

假设我们有以下场景：

**假设输入:**

1. **用户操作:** 在浏览器中打开一个包含以下 HTML 代码的网页：
   ```html
   <!DOCTYPE html>
   <html>
   <head>
       <title>SVG Test</title>
   </head>
   <body>
       <img src="my_icon.svg" alt="My Icon">
   </body>
   </html>
   ```
2. **`my_icon.svg` 内容:**
   ```xml
   <svg width="100" height="100">
       <circle cx="50" cy="50" r="40" fill="green" id="myCircle" />
   </svg>
   ```
3. **`FetchParameters`:**  `Fetch` 方法接收到的参数包含 `my_icon.svg` 的 URL，请求模式为 `kSameOrigin`。

**逻辑推理:**

1. 当浏览器解析到 `<img>` 标签时，会创建一个资源请求来获取 `my_icon.svg`。
2. `SVGResourceDocumentContent::Fetch` 方法会被调用，传入包含 `my_icon.svg` URL 的 `FetchParameters` 对象。
3. `Fetch` 方法会检查缓存中是否已存在 `my_icon.svg` 的内容。
4. 如果缓存未命中，则会创建一个 `SVGDocumentResource` 来发起网络请求。
5. `NotifyStartLoad()` 方法被调用，将状态设置为 `kPending`。
6. 一旦 `my_icon.svg` 的数据被下载下来，`UpdateDocument` 方法会被调用，传入下载的数据。
7. `UpdateDocument` 创建一个 `IsolatedSVGDocumentHost` 来解析 SVG 数据。
8. 如果解析成功，`LoadingFinished` 方法会被调用，将状态设置为 `kCached`。
9. 所有注册的观察者（例如负责渲染 `<img>` 标签的对象）会被通知，SVG 内容已加载完成。
10. 用户可以在页面上看到绿色的圆形图标。

**假设输出:**

1. `SVGResourceDocumentContent` 对象的状态变为 `kCached`。
2. 观察者收到通知，开始渲染 SVG 内容。
3. 如果后续有 JavaScript 代码尝试访问 `document.getElementById('myCircle')`，`GetResourceTarget` 方法会被调用，并返回表示该圆形元素的 `SVGResourceTarget` 对象。

**用户或编程常见的使用错误**

1. **CORS 问题:** 如果 SVG 资源位于不同的域名下，并且没有设置正确的 CORS 头信息，浏览器会阻止加载。
    * **错误示例:**  HTML 中引用了 `https://otherdomain.com/image.svg`，但 `image.svg` 的响应头中缺少 `Access-Control-Allow-Origin` 或其值不包含当前域名。
    * **调试线索:**  开发者工具的 Network 面板会显示 CORS 错误。
    * **用户操作:** 用户尝试访问包含跨域 SVG 资源的页面。

2. **SVG 文件格式错误:**  如果 SVG 文件本身存在语法错误或格式不正确，`IsolatedSVGDocumentHost` 解析时会失败。
    * **错误示例:**  `my_icon.svg` 中缺少闭合标签或者属性值不符合规范。
    * **调试线索:**  `UpdateStatus` 可能会被调用，将状态设置为 `kDecodeError`。开发者工具的 Console 面板可能会显示 XML 解析错误。
    * **用户操作:** 用户访问的页面引用的 SVG 文件已损坏或格式错误。

3. **引用不存在的 SVG 片段:**  在使用 `<use>` 元素时，如果引用的片段 ID 在目标 SVG 文件中不存在，`GetResourceTarget` 会返回 `nullptr`。
    * **错误示例:**  `<use xlink:href="image.svg#nonExistentId" />`，但 `image.svg` 中没有 ID 为 `nonExistentId` 的元素。
    * **调试线索:**  页面上对应的元素可能不会显示出来。如果 JavaScript 代码尝试操作这个不存在的元素，可能会引发错误。
    * **用户操作:**  开发者在 HTML 中使用了错误的 SVG 片段引用。

4. **在 SVG 加载完成前尝试访问其内容:** 如果 JavaScript 代码尝试在 SVG 完全加载完成之前访问其 DOM，可能会遇到问题，因为 `GetDocument()` 可能返回 `nullptr`。
    * **错误示例:**  在页面加载的早期阶段，执行 `document.querySelector('object[data="my_icon.svg"]').contentDocument.getElementById('myCircle')`，此时 SVG 可能尚未加载完成。
    * **调试线索:**  `GetDocument()` 返回 `nullptr`。需要确保在 SVG 的 `load` 事件触发后或在适当的时机访问其内容。
    * **用户操作:**  用户的网络环境较差，SVG 加载缓慢，同时页面上的 JavaScript 代码过早地尝试访问 SVG 内容。

**说明用户操作是如何一步步的到达这里，作为调试线索。**

假设用户访问一个包含以下 HTML 的网页：

```html
<!DOCTYPE html>
<html>
<head>
    <title>SVG Debug Test</title>
</head>
<body>
    <object data="interactive.svg" type="image/svg+xml"></object>
    <script>
        window.onload = function() {
            const svgObject = document.querySelector('object[data="interactive.svg"]');
            const svgDoc = svgObject.contentDocument;
            if (svgDoc) {
                const myRect = svgDoc.getElementById('myRect');
                if (myRect) {
                    myRect.setAttribute('fill', 'blue');
                } else {
                    console.error("Element with ID 'myRect' not found in SVG.");
                }
            } else {
                console.error("SVG document not loaded yet.");
            }
        };
    </script>
</body>
</html>
```

以及 `interactive.svg` 的内容：

```xml
<svg width="200" height="100">
  <rect id="myRect" width="100" height="50" fill="red" />
</svg>
```

**用户操作步骤与调试线索:**

1. **用户在浏览器地址栏输入网址或点击链接访问该网页。**
   * **调试线索:**  在开发者工具的 Network 面板中可以看到对 `interactive.svg` 的请求。

2. **浏览器开始解析 HTML。**
   * **调试线索:**  浏览器的渲染流程开始。

3. **浏览器遇到 `<object data="interactive.svg" ...>` 标签。**
   * **调试线索:**  Blink 引擎会创建一个 `SVGResourceDocumentContent` 对象来负责加载 `interactive.svg`。可以设置断点在 `SVGResourceDocumentContent::Fetch` 方法查看其被调用。

4. **`SVGResourceDocumentContent::Fetch` 被调用，尝试从缓存或网络加载 `interactive.svg`。**
   * **调试线索:**  检查 `SVGResourceDocumentCache` 的状态，查看是否命中缓存。如果未命中，可以看到对 `interactive.svg` 的网络请求。

5. **`NotifyStartLoad()` 被调用，SVG 资源状态变为 `kPending`。**
   * **调试线索:**  可以观察 `SVGResourceDocumentContent` 对象的内部状态。

6. **`interactive.svg` 的数据被下载。**
   * **调试线索:**  Network 面板中 `interactive.svg` 的请求状态变为 200 OK。

7. **`UpdateDocument` 方法被调用，传入下载的 SVG 数据。**
   * **调试线索:**  可以设置断点在 `UpdateDocument` 方法，查看传入的数据内容。

8. **`IsolatedSVGDocumentHost` 被创建，开始解析 SVG 数据。**
   * **调试线索:**  如果 SVG 数据有错误，这里可能会发生解析异常。

9. **如果解析成功，`LoadingFinished` 被调用，SVG 资源状态变为 `kCached`。**
   * **调试线索:**  检查 `SVGResourceDocumentContent` 的状态。

10. **注册到该 `SVGResourceDocumentContent` 的观察者被通知，SVG 加载完成。**
    * **调试线索:**  例如，负责渲染 `<object>` 标签的对象会收到通知。

11. **HTML 的 `window.onload` 事件触发，JavaScript 代码开始执行。**
    * **调试线索:**  可以在 JavaScript 代码中设置断点。

12. **JavaScript 代码尝试获取 `<object>` 元素和其 `contentDocument`。**
    * **调试线索:**  检查 `svgObject.contentDocument` 的值是否为 `null`。如果为 `null`，可能是 SVG 尚未加载完成。

13. **JavaScript 代码使用 `svgDoc.getElementById('myRect')` 获取 SVG 中的矩形元素。**
    * **调试线索:**  如果获取失败，可能是 SVG 中没有 ID 为 `myRect` 的元素，或者 SVG 加载不完整。可以检查 `interactive.svg` 的内容。这里会调用 `SVGResourceDocumentContent::GetResourceTarget`。

14. **JavaScript 代码将矩形的填充色设置为蓝色。**
    * **调试线索:**  在 Elements 面板中查看 `<rect>` 元素的 `fill` 属性是否已变为蓝色。

通过以上步骤和调试线索，开发者可以跟踪 SVG 资源的加载过程，定位可能出现的问题，例如网络错误、SVG 文件格式错误、JavaScript 代码错误等。`SVGResourceDocumentContent` 在这个过程中扮演着核心的角色，负责 SVG 资源的生命周期管理。

### 提示词
```
这是目录为blink/renderer/core/svg/svg_resource_document_content.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
    Copyright (C) 2010 Rob Buis <rwlbuis@gmail.com>
    Copyright (C) 2011 Cosmin Truta <ctruta@gmail.com>
    Copyright (C) 2012 University of Szeged
    Copyright (C) 2012 Renata Hodovan <reni@webkit.org>

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Library General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Library General Public License for more details.

    You should have received a copy of the GNU Library General Public License
    along with this library; see the file COPYING.LIB.  If not, write to
    the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
    Boston, MA 02110-1301, USA.
*/

#include "third_party/blink/renderer/core/svg/svg_resource_document_content.h"

#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/loader/resource/svg_document_resource.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/svg/graphics/isolated_svg_document_host.h"
#include "third_party/blink/renderer/core/svg/graphics/svg_image_chrome_client.h"
#include "third_party/blink/renderer/core/svg/svg_element.h"
#include "third_party/blink/renderer/core/svg/svg_resource_document_cache.h"
#include "third_party/blink/renderer/core/svg/svg_resource_document_observer.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_parameters.h"
#include "third_party/blink/renderer/platform/supplementable.h"

namespace blink {

namespace {

bool CanReuseContent(const SVGResourceDocumentContent& content) {
  // Don't reuse if loading failed.
  return !content.ErrorOccurred();
}

bool AllowedRequestMode(const ResourceRequest& request) {
  // Same-origin
  if (request.GetMode() == network::mojom::blink::RequestMode::kSameOrigin) {
    return true;
  }
  // CORS with same-origin credentials mode ("CORS anonymous").
  if (request.GetMode() == network::mojom::blink::RequestMode::kCors) {
    return request.GetCredentialsMode() ==
           network::mojom::CredentialsMode::kSameOrigin;
  }
  return false;
}

}  // namespace

class SVGResourceDocumentContent::ChromeClient final
    : public IsolatedSVGChromeClient {
 public:
  explicit ChromeClient(SVGResourceDocumentContent* content)
      : content_(content) {}

  void Trace(Visitor* visitor) const override {
    visitor->Trace(content_);
    IsolatedSVGChromeClient::Trace(visitor);
  }

 private:
  void ChromeDestroyed() override { content_.Clear(); }
  void InvalidateContainer() override { content_->ContentChanged(); }
  void ScheduleAnimation(const LocalFrameView*, base::TimeDelta) override {
    content_->ContentChanged();
  }

  Member<SVGResourceDocumentContent> content_;
};

SVGResourceDocumentContent::SVGResourceDocumentContent(
    AgentGroupScheduler& agent_group_scheduler,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : agent_group_scheduler_(agent_group_scheduler),
      task_runner_(std::move(task_runner)) {}

SVGResourceDocumentContent::~SVGResourceDocumentContent() = default;

void SVGResourceDocumentContent::NotifyStartLoad() {
  // Check previous status.
  switch (status_) {
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
  status_ = ResourceStatus::kPending;
}

void SVGResourceDocumentContent::UpdateStatus(ResourceStatus new_status) {
  switch (new_status) {
    case ResourceStatus::kCached:
    case ResourceStatus::kPending:
      // In case of successful load, Resource's status can be kCached or
      // kPending. Set it to kCached in both cases.
      new_status = ResourceStatus::kCached;
      break;

    case ResourceStatus::kLoadError:
    case ResourceStatus::kDecodeError:
      // In case of error, Resource's status is set to an error status before
      // updating the document and thus we use the error status as-is.
      break;

    case ResourceStatus::kNotStarted:
      CHECK(false);
      break;
  }
  status_ = new_status;
}

SVGResourceDocumentContent::UpdateResult
SVGResourceDocumentContent::UpdateDocument(scoped_refptr<SharedBuffer> data,
                                           const KURL& request_url) {
  if (data->empty() || was_disposed_) {
    return UpdateResult::kError;
  }
  CHECK(!document_host_);
  auto* chrome_client = MakeGarbageCollected<ChromeClient>(this);
  document_host_ = MakeGarbageCollected<IsolatedSVGDocumentHost>(
      *chrome_client, *agent_group_scheduler_, std::move(data),
      WTF::BindOnce(&SVGResourceDocumentContent::AsyncLoadingFinished,
                    WrapWeakPersistent(this)),
      nullptr, IsolatedSVGDocumentHost::ProcessingMode::kStatic);
  // If IsLoaded() returns true then the document load completed synchronously,
  // so we can check if we have a usable document and notify our listeners. If
  // not, then we need to wait for the async load completion callback.
  if (!document_host_->IsLoaded()) {
    return UpdateResult::kAsync;
  }
  LoadingFinished();
  return UpdateResult::kCompleted;
}

void SVGResourceDocumentContent::LoadingFinished() {
  LocalFrame* frame = document_host_->GetFrame();
  frame->View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kSVGImage);
  UpdateStatus(ResourceStatus::kCached);
}

void SVGResourceDocumentContent::AsyncLoadingFinished() {
  LoadingFinished();
  NotifyObservers();
}

void SVGResourceDocumentContent::Dispose() {
  ClearDocument();
  was_disposed_ = true;
}

void SVGResourceDocumentContent::ClearDocument() {
  if (!document_host_) {
    return;
  }
  auto* document_host = document_host_.Release();
  document_host->Shutdown();
}

Document* SVGResourceDocumentContent::GetDocument() const {
  // Only return a Document if the load sequence fully completed.
  if (document_host_ && document_host_->IsLoaded()) {
    return document_host_->GetFrame()->GetDocument();
  }
  return nullptr;
}

const KURL& SVGResourceDocumentContent::Url() const {
  return url_;
}

void SVGResourceDocumentContent::AddObserver(
    SVGResourceDocumentObserver* observer) {
  // We currently don't have any N:1 relations (multiple observer registrations
  // for a single document content) among the existing clients
  // (ExternalSVGResource and SVGUseElement).
  DCHECK(!observers_.Contains(observer));
  observers_.insert(observer);
  if (IsLoaded()) {
    task_runner_->PostTask(
        FROM_HERE,
        WTF::BindOnce(&SVGResourceDocumentContent::NotifyObserver,
                      WrapPersistent(this), WrapWeakPersistent(observer)));
  }
}

void SVGResourceDocumentContent::RemoveObserver(
    SVGResourceDocumentObserver* observer) {
  observers_.erase(observer);
}

void SVGResourceDocumentContent::NotifyObserver(
    SVGResourceDocumentObserver* observer) {
  if (observer && observers_.Contains(observer)) {
    observer->ResourceNotifyFinished(this);
  }
}

void SVGResourceDocumentContent::NotifyObservers() {
  for (auto& observer : observers_) {
    observer->ResourceNotifyFinished(this);
  }
}

SVGResourceTarget* SVGResourceDocumentContent::GetResourceTarget(
    const AtomicString& element_id) {
  Document* document = GetDocument();
  if (!document) {
    return nullptr;
  }
  auto* svg_target =
      DynamicTo<SVGElement>(document->getElementById(element_id));
  if (!svg_target) {
    return nullptr;
  }
  return &svg_target->EnsureResourceTarget();
}

void SVGResourceDocumentContent::ContentChanged() {
  for (auto& observer : observers_) {
    observer->ResourceContentChanged(this);
  }
}

bool SVGResourceDocumentContent::IsLoaded() const {
  return status_ > ResourceStatus::kPending;
}

bool SVGResourceDocumentContent::IsLoading() const {
  return status_ == ResourceStatus::kPending;
}

bool SVGResourceDocumentContent::ErrorOccurred() const {
  return status_ == ResourceStatus::kLoadError ||
         status_ == ResourceStatus::kDecodeError;
}

void SVGResourceDocumentContent::Trace(Visitor* visitor) const {
  visitor->Trace(document_host_);
  visitor->Trace(agent_group_scheduler_);
  visitor->Trace(observers_);
}

SVGResourceDocumentContent* SVGResourceDocumentContent::Fetch(
    FetchParameters& params,
    Document& document) {
  CHECK(!params.Url().IsNull());
  // Callers need to set the request and credentials mode to something suitably
  // restrictive. This limits the actual modes (simplifies caching) that we
  // allow and avoids accidental creation of overly privileged requests.
  CHECK(AllowedRequestMode(params.GetResourceRequest()));

  DCHECK_EQ(params.GetResourceRequest().GetRequestContext(),
            mojom::blink::RequestContextType::UNSPECIFIED);
  params.SetRequestContext(mojom::blink::RequestContextType::IMAGE);
  params.SetRequestDestination(network::mojom::RequestDestination::kImage);

  Page* page = document.GetPage();
  auto& cache = page->GetSVGResourceDocumentCache();

  const SVGResourceDocumentCache::CacheKey key =
      SVGResourceDocumentCache::MakeCacheKey(params);
  auto* cached_content = cache.Get(key);
  if (cached_content && CanReuseContent(*cached_content)) {
    return cached_content;
  }

  SVGDocumentResource* resource = SVGDocumentResource::Fetch(
      params, document.Fetcher(), page->GetAgentGroupScheduler());
  if (!resource) {
    return nullptr;
  }
  cache.Put(key, resource->GetContent());
  return resource->GetContent();
}

}  // namespace blink
```