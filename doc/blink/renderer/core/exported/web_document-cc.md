Response:
Let's break down the thought process for analyzing this C++ header file (`web_document.cc`) and generating the comprehensive response.

**1. Understanding the Goal:**

The core request is to understand the functionality of `web_document.cc` within the Chromium Blink rendering engine. Specifically, the prompt asks for:

* **Functionality:** What does this code *do*?
* **Relationships (JavaScript, HTML, CSS):** How does it connect to the web development trinity?
* **Logic & Examples:** Can we illustrate with hypothetical inputs and outputs?
* **User Errors:** What mistakes could developers make when interacting with this?
* **Debugging Clues:** How can this file be useful for tracking down issues?

**2. Initial Code Scan and Identification of Key Areas:**

The first step is to quickly scan the `#include` statements and the member functions defined in the `blink::WebDocument` class. This immediately gives a high-level overview:

* **Includes:**  `web_document.h`, core Blink components (`Document`, `Element`, `Frame`, `CSS`, etc.), and public platform types (`WebURL`, `WebElement`). This signals that `web_document.cc` is part of the public API of Blink, providing access to document-related functionalities.
* **Class `WebDocument`:**  This is the central point. The functions within this class likely expose the underlying `Document` object's features to the outside world (often the Chromium browser process or embedders).
* **Methods:**  Lots of "getter" methods (`Url`, `Title`, `Body`, `Forms`), methods related to styling (`InsertStyleSheet`, `RemoveInsertedStyleSheet`, `WatchCSSSelectors`), and some more advanced features (`InitiatePreview`).

**3. Deeper Dive into Functionality (Grouping by Concern):**

Now, let's analyze the individual methods and group them by the kind of functionality they provide. This helps organize the information logically:

* **Document Properties:**  `Url`, `GetSecurityOrigin`, `IsSecureContext`, `Encoding`, `ContentLanguage`, `GetReferrer`, `ThemeColor`, `OpenSearchDescriptionURL`, `BaseURL`, `GetUkmSourceId`, `SiteForCookies`, `StorageAccessApiStatus`, `TopFrameOrigin`. These provide basic information *about* the document.
* **Accessing Document Content:** `DocumentElement`, `Body`, `Head`, `Title`, `ContentAsTextForTesting`, `All`, `UnassociatedFormControls`, `Forms`, `GetTopLevelForms`. These methods allow access to the structure and content of the HTML.
* **Finding Elements:** `GetElementById`, `FocusedElement`. Standard ways to locate specific elements.
* **Styling:** `InsertStyleSheet`, `RemoveInsertedStyleSheet`, `WatchCSSSelectors`, `DraggableRegions`. These are crucial for how CSS is applied and managed.
* **Advanced Features:** `DistillabilityFeatures`, `SetShowBeforeUnloadDialog`, `GetVisualViewportScrollingElementIdForTesting`, `IsLoaded`, `IsPrerendering`, `HasDocumentPictureInPictureWindow`, `AddPostPrerenderingActivationStep`, `SetCookieManager`, `InitiatePreview`, `GetReferrerPolicy`, `OutgoingReferrer`. These represent more specialized or browser-level interactions.

**4. Connecting to JavaScript, HTML, and CSS:**

For each group of functionalities, consider how they relate to the web development stack:

* **HTML:** Methods accessing elements directly correspond to HTML tags and the DOM structure (`Body`, `Head`, `Forms`).
* **CSS:** Styling methods directly manipulate the CSSOM (`InsertStyleSheet`, `WatchCSSSelectors`).
* **JavaScript:** Many of these methods are directly mirrored in the JavaScript `document` object (`document.URL`, `document.title`, `document.getElementById`, `document.querySelectorAll`). This class acts as a bridge between the C++ rendering engine and the JavaScript environment. Think about what JavaScript APIs ultimately rely on the underlying C++ implementation.

**5. Creating Examples (Logic & Input/Output):**

Choose a few representative methods and construct simple scenarios to illustrate how they work. Think about:

* **Input:** What parameters are passed to the method?
* **Processing:** What does the method *do* internally (even if you don't know the exact code)?
* **Output:** What does the method return?

For instance, `GetElementById`:

* **Input:** A `WebString` representing an HTML ID.
* **Processing:** The engine searches the DOM for an element with that ID.
* **Output:** A `WebElement` object (if found) or an empty `WebElement`.

**6. Identifying Potential User/Programming Errors:**

Think about common mistakes developers might make when working with these APIs:

* **Incorrect IDs:** Passing a non-existent ID to `GetElementById`.
* **Invalid URLs:** Providing a malformed URL to methods that expect URLs.
* **Type Mismatches:** Assuming a returned `WebElement` is a specific type without checking.
* **Incorrect CSS Selectors:** Providing invalid CSS selectors to `WatchCSSSelectors`.
* **Timing Issues:**  Trying to access elements before the DOM is fully loaded.

**7. Tracing User Actions to the Code (Debugging Clues):**

Consider how a user interaction might lead to the execution of code within `web_document.cc`:

* **Page Load:**  Accessing `document.URL`, `document.title`, etc., will trigger the corresponding getter methods in this file.
* **JavaScript DOM Manipulation:**  `document.getElementById()`, `document.querySelector()`, creating and inserting elements will involve this code.
* **CSS Application:**  When the browser parses CSS, the `InsertStyleSheet` and related methods are involved.
* **Form Submission:** Accessing form elements (`document.forms`) and their values.
* **Link Clicking/Navigation:**  Potentially related to referrer policies and URL handling.

**8. Structuring the Response:**

Organize the information into logical sections, mirroring the prompt's requirements:

* **Overview of Functionality:** Start with a high-level summary.
* **Detailed Functionality Breakdown:** Go through the methods, grouping them by purpose.
* **Relationships with Web Technologies:** Explain the connections to JavaScript, HTML, and CSS with examples.
* **Logic and Examples:** Provide concrete input/output scenarios.
* **Common User Errors:** List potential pitfalls.
* **Debugging Clues:** Explain how to use this file for troubleshooting.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This file just provides access to the `Document` object."  **Correction:** While true, it's more than just simple forwarding. It handles the conversion between internal Blink types and public `Web*` types. It also manages some higher-level features.
* **Initial thought:** "Just list all the methods." **Correction:** Grouping by functionality makes the explanation much clearer and easier to understand.
* **Initial thought:**  "Focus on the code details." **Correction:** Emphasize the *user-facing* aspects – how web developers interact with these functionalities through JavaScript and how the browser uses them internally.

By following these steps, which involve progressively deeper analysis and consideration of different perspectives (developer, browser, debugger), we can arrive at a comprehensive and insightful explanation of the `web_document.cc` file.
这个文件 `blink/renderer/core/exported/web_document.cc` 是 Chromium Blink 渲染引擎中的一部分，它的主要功能是**向外部（通常是 Chromium 的其他部分，如 content 层）提供对内部 `blink::Document` 对象的访问和操作接口**。  它定义了 `blink::WebDocument` 类，这是一个公共的、不依赖于 Blink 内部实现的接口类，用于操作和获取文档的相关信息。

可以将其理解为 `blink::Document` 的一个“代理”或“外观”类，它隐藏了 Blink 内部复杂的实现细节，并提供了一组稳定、易于使用的 API。

下面详细列举其功能，并根据与 JavaScript、HTML、CSS 的关系进行说明：

**核心功能：**

1. **获取文档基本信息:**
   - `Url()`: 获取文档的 URL。
   - `GetSecurityOrigin()`: 获取文档的安全源 (Origin)。
   - `IsSecureContext()`: 判断文档是否处于安全上下文。
   - `Encoding()`: 获取文档的编码方式。
   - `ContentLanguage()`: 获取文档的内容语言。
   - `GetReferrer()`: 获取文档的引用 URL。
   - `ThemeColor()`: 获取文档定义的主题颜色。
   - `OpenSearchDescriptionURL()`: 获取文档关联的 OpenSearch 描述文件的 URL。
   - `BaseURL()`: 获取文档的基础 URL。
   - `GetUkmSourceId()`: 获取用于 UKM (User Keyed Metrics) 的源 ID。
   - `SiteForCookies()`: 获取用于 Cookie 的站点信息。
   - `StorageAccessApiStatus()`: 获取存储访问 API 的状态。
   - `TopFrameOrigin()`: 获取顶层框架的源。

2. **访问文档结构：**
   - `DocumentElement()`: 获取文档的根元素 (`<html>`)。 **(HTML)**
   - `Body()`: 获取文档的 `<body>` 元素。 **(HTML)**
   - `Head()`: 获取文档的 `<head>` 元素。 **(HTML)**

3. **获取文档内容：**
   - `Title()`: 获取文档的标题 (`<title>`). **(HTML)**
   - `ContentAsTextForTesting()`:  以纯文本形式获取文档内容，主要用于测试。

4. **查找元素：**
   - `All()`: 获取文档中所有元素的集合。 **(HTML, JavaScript)** 这对应于 JavaScript 中的 `document.all` (虽然不推荐使用)。
   - `GetElementById(const WebString& id)`: 根据 ID 获取文档中的元素。 **(HTML, JavaScript)** 对应于 JavaScript 中的 `document.getElementById()`.
   - `FocusedElement()`: 获取当前拥有焦点的元素。 **(HTML)**

5. **操作表单：**
   - `UnassociatedFormControls()`: 获取不属于任何表单的表单控件元素。 **(HTML)**
   - `Forms()`: 获取文档中所有表单元素的集合。 **(HTML)** 对应于 JavaScript 中的 `document.forms`.
   - `GetTopLevelForms()`: 获取文档顶层的表单元素。

6. **处理 URL：**
   - `CompleteURL(const WebString& partial_url)`: 将部分 URL 解析为完整的 URL。

7. **操作样式表：**
   - `InsertStyleSheet(const WebString& source_code, const WebStyleSheetKey* key, WebCssOrigin origin, BackForwardCacheAware back_forward_cache_aware)`:  向文档插入一个新的样式表。 **(CSS, JavaScript)** 这可以被 JavaScript 调用来动态添加样式。  `source_code` 就是 CSS 代码。
   - `RemoveInsertedStyleSheet(const WebStyleSheetKey& key, WebCssOrigin origin)`: 移除通过 `InsertStyleSheet` 插入的样式表。 **(CSS, JavaScript)**
   - `WatchCSSSelectors(const WebVector<WebString>& web_selectors)`: 监听与给定 CSS 选择器匹配的元素的变化。 **(CSS, JavaScript)** 这允许在 CSS 规则应用或元素结构改变时得到通知。

8. **处理拖拽区域：**
   - `DraggableRegions()`: 获取文档中可拖拽的区域。 **(HTML, CSS, JavaScript)**  `draggable` 属性和相关的 CSS 样式会影响此功能。

9. **获取文档特性：**
   - `DistillabilityFeatures()`: 获取文档的可提炼性特征，用于判断文档是否适合被提炼（例如，去除广告和导航）。

10. **控制行为：**
    - `SetShowBeforeUnloadDialog(bool show_dialog)`: 设置是否显示“离开此页面？”对话框。 **(JavaScript)**  这与 JavaScript 的 `beforeunload` 事件相关。

11. **获取框架信息：**
    - `GetFrame()`: 获取与该文档关联的框架 (Frame)。

12. **判断文档类型：**
    - `IsHTMLDocument()`: 判断文档是否为 HTML 文档。
    - `IsXHTMLDocument()`: 判断文档是否为 XHTML 文档。
    - `IsPluginDocument()`: 判断文档是否为插件文档。

13. **其他功能：**
    - `GetVisualViewportScrollingElementIdForTesting()`:  获取用于测试的可视视口滚动元素的 ID。
    - `IsLoaded()`: 判断文档是否已加载完成。
    - `IsPrerendering()`: 判断文档是否正在预渲染。
    - `HasDocumentPictureInPictureWindow()`: 判断文档是否拥有画中画窗口。
    - `AddPostPrerenderingActivationStep(base::OnceClosure callback)`: 添加预渲染激活后的步骤。
    - `SetCookieManager(...)`: 设置 Cookie 管理器。
    - `GetReferrerPolicy()`: 获取文档的引用策略。
    - `OutgoingReferrer()`: 获取即将发出的请求的引用 URL。
    - `InitiatePreview(const WebURL& url)`:  启动指定 URL 的预览。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **HTML:**
    * 当 JavaScript 代码执行 `document.getElementById("myElement")` 时，最终会调用到 `WebDocument::GetElementById` 方法，该方法在内部会查找具有指定 ID 的 HTML 元素。
    * 当浏览器解析 HTML 时，会创建 `HTMLBodyElement` 对象，而 `WebDocument::Body()` 方法就是用来获取这个对象的。

* **CSS:**
    * 当 JavaScript 执行 `document.createElement('style'); style.innerHTML = '.my-class { color: red; }'; document.head.appendChild(style);` 时，背后会调用到 `WebDocument::InsertStyleSheet` 方法，将 CSS 代码注入到文档中。
    * `WebDocument::WatchCSSSelectors` 可以用于实现一些高级功能，例如在某个 CSS 动画完成后执行 JavaScript 代码。

* **JavaScript:**
    * `WebDocument` 类的方法通常会在 JavaScript 的 `document` 对象上暴露出来。例如，`WebDocument::Url()` 对应于 JavaScript 中的 `document.URL`。
    * JavaScript 可以通过 `document.forms` 访问文档中的所有表单，这对应于 `WebDocument::Forms()` 方法返回的结果。

**逻辑推理的假设输入与输出：**

**假设输入：**  JavaScript 代码 `let element = document.getElementById("myDiv");` 在一个 HTML 文档中执行，该文档包含 `<div id="myDiv"></div>`。

**输出：** `WebDocument::GetElementById("myDiv")` 方法被调用，内部在文档 DOM 树中查找到 `HTMLDivElement` 对象，并将其包装成 `WebElement` 返回。JavaScript 变量 `element` 将持有对这个 `WebElement` 的引用，允许进一步操作该元素。

**假设输入：**  JavaScript 代码 `document.title = "New Title";` 在页面加载完成后执行。

**输出：** 最终会调用到 `WebDocument` 内部关联的 `Document` 对象的相应方法来修改文档的标题。下次调用 `WebDocument::Title()` 时，将返回 "New Title"。  浏览器窗口的标题也会相应更新。

**用户或编程常见的使用错误举例说明：**

1. **使用错误的 ID 查询元素：** 用户在 JavaScript 中使用 `document.getElementById("nonExistentId")` 尝试获取一个不存在的元素。`WebDocument::GetElementById` 会返回一个空的 `WebElement`，如果后续代码没有进行判空处理，可能会导致错误（例如，尝试访问空对象的属性）。

2. **在文档加载完成前操作元素：**  用户编写 JavaScript 代码尝试在 DOMContentLoaded 事件触发之前访问或修改元素。这时 `WebDocument::GetElementById` 可能找不到元素，或者操作可能会失败，因为 DOM 结构尚未完全构建。

3. **错误地管理动态插入的样式表：** 用户使用 `WebDocument::InsertStyleSheet` 插入样式表后，忘记保存返回的 `WebStyleSheetKey`，导致无法移除该样式表。这可能导致样式冲突或内存泄漏。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在一个网页上点击了一个按钮，该按钮触发了一些 JavaScript 代码来修改页面的样式。

1. **用户操作：** 用户点击按钮。
2. **事件触发：** 浏览器捕获到点击事件，并执行与该按钮关联的 JavaScript 事件处理函数。
3. **JavaScript 代码执行：**  JavaScript 代码可能调用了类似 `document.createElement('style')` 和 `document.head.appendChild(style)` 或者直接修改元素的 `style` 属性。
4. **Blink 内部调用：** 如果是创建并添加 `<style>` 标签，最终会调用到 `WebDocument::InsertStyleSheet` 方法，将新的 CSS 规则应用到页面。
5. **调试线索：** 如果在调试过程中发现样式没有按预期生效，或者出现与样式相关的性能问题，开发者可以通过断点设置在 `WebDocument::InsertStyleSheet` 或 `WebDocument::RemoveInsertedStyleSheet` 等方法上，来追踪样式的添加和移除过程，查看传递的 CSS 代码和参数是否正确。

再比如，如果用户在地址栏输入一个新的 URL 并回车，导致页面导航：

1. **用户操作：** 用户在地址栏输入 URL 并回车。
2. **浏览器请求：** 浏览器发起对该 URL 的请求。
3. **接收响应：** 浏览器接收到服务器返回的 HTML 内容。
4. **HTML 解析：** Blink 的 HTML 解析器开始解析 HTML 内容，构建 DOM 树。
5. **`WebDocument` 创建：**  在解析过程中，会创建一个新的 `WebDocument` 对象来表示当前加载的文档。
6. **各种 `WebDocument` 方法调用：**  解析过程中会涉及到 `WebDocument` 的各种方法，例如获取文档 URL、编码方式等。
7. **调试线索：** 如果在页面加载过程中出现问题，例如资源加载失败，可以通过检查 `WebDocument::Url()` 返回的 URL 是否正确，或者查看 `WebDocument::GetReferrer()` 是否与预期一致，来帮助定位问题。

总而言之，`web_document.cc` 文件是 Blink 渲染引擎中非常核心的一个组件，它连接了内部的文档表示和外部的访问接口，使得 Chromium 的其他部分以及 JavaScript 能够方便地操作和获取文档的信息。 理解这个文件的功能对于理解 Blink 的工作原理以及调试 Web 页面至关重要。

### 提示词
```
这是目录为blink/renderer/core/exported/web_document.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2009 Google Inc. All rights reserved.
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

#include "third_party/blink/public/web/web_document.h"

#include "base/memory/scoped_refptr.h"
#include "net/storage_access_api/status.h"
#include "services/network/public/mojom/referrer_policy.mojom-blink.h"
#include "third_party/blink/public/common/loader/referrer_utils.h"
#include "third_party/blink/public/platform/web_distillability.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/web/web_dom_event.h"
#include "third_party/blink/public/web/web_element.h"
#include "third_party/blink/public/web/web_element_collection.h"
#include "third_party/blink/public/web/web_form_control_element.h"
#include "third_party/blink/public/web/web_form_element.h"
#include "third_party/blink/renderer/core/css/css_selector_watch.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_statistics_collector.h"
#include "third_party/blink/renderer/core/dom/document_type.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/forms/html_form_control_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/html_all_collection.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_collection.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/html/html_link_element.h"
#include "third_party/blink/renderer/core/html/plugin_document.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/speculation_rules/document_speculation_rules.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"

namespace {

static const blink::WebStyleSheetKey GenerateStyleSheetKey() {
  static unsigned counter = 0;
  return String::Number(++counter);
}

}  // namespace

namespace blink {

const DocumentToken& WebDocument::Token() const {
  return ConstUnwrap<Document>()->Token();
}

WebURL WebDocument::Url() const {
  return ConstUnwrap<Document>()->Url();
}

WebSecurityOrigin WebDocument::GetSecurityOrigin() const {
  if (!ConstUnwrap<Document>())
    return WebSecurityOrigin();
  ExecutionContext* context = ConstUnwrap<Document>()->GetExecutionContext();
  if (!context)
    return WebSecurityOrigin();
  return WebSecurityOrigin(context->GetSecurityOrigin());
}

bool WebDocument::IsSecureContext() const {
  const Document* document = ConstUnwrap<Document>();
  ExecutionContext* context =
      document ? document->GetExecutionContext() : nullptr;
  return context && context->IsSecureContext();
}

WebString WebDocument::Encoding() const {
  return ConstUnwrap<Document>()->EncodingName();
}

WebString WebDocument::ContentLanguage() const {
  return ConstUnwrap<Document>()->ContentLanguage();
}

WebString WebDocument::GetReferrer() const {
  return ConstUnwrap<Document>()->referrer();
}

std::optional<SkColor> WebDocument::ThemeColor() {
  std::optional<Color> color = Unwrap<Document>()->ThemeColor();
  if (color)
    return color->Rgb();
  return std::nullopt;
}

WebURL WebDocument::OpenSearchDescriptionURL() const {
  return const_cast<Document*>(ConstUnwrap<Document>())
      ->OpenSearchDescriptionURL();
}

WebLocalFrame* WebDocument::GetFrame() const {
  return WebLocalFrameImpl::FromFrame(ConstUnwrap<Document>()->GetFrame());
}

bool WebDocument::IsHTMLDocument() const {
  return IsA<HTMLDocument>(ConstUnwrap<Document>());
}

bool WebDocument::IsXHTMLDocument() const {
  return ConstUnwrap<Document>()->IsXHTMLDocument();
}

bool WebDocument::IsPluginDocument() const {
  return IsA<PluginDocument>(ConstUnwrap<Document>());
}

WebURL WebDocument::BaseURL() const {
  return ConstUnwrap<Document>()->BaseURL();
}

ukm::SourceId WebDocument::GetUkmSourceId() const {
  return ConstUnwrap<Document>()->UkmSourceID();
}

net::SiteForCookies WebDocument::SiteForCookies() const {
  return ConstUnwrap<Document>()->SiteForCookies();
}

net::StorageAccessApiStatus WebDocument::StorageAccessApiStatus() const {
  return ConstUnwrap<Document>()
      ->GetExecutionContext()
      ->GetStorageAccessApiStatus();
}

WebSecurityOrigin WebDocument::TopFrameOrigin() const {
  return ConstUnwrap<Document>()->TopFrameOrigin();
}

WebElement WebDocument::DocumentElement() const {
  return WebElement(ConstUnwrap<Document>()->documentElement());
}

WebElement WebDocument::Body() const {
  return WebElement(ConstUnwrap<Document>()->body());
}

WebElement WebDocument::Head() {
  return WebElement(Unwrap<Document>()->head());
}

WebString WebDocument::Title() const {
  return WebString(ConstUnwrap<Document>()->title());
}

WebString WebDocument::ContentAsTextForTesting() const {
  Element* document_element = ConstUnwrap<Document>()->documentElement();
  if (!document_element)
    return WebString();
  return document_element->innerText();
}

WebElementCollection WebDocument::All() const {
  return WebElementCollection(
      const_cast<Document*>(ConstUnwrap<Document>())->all());
}

WebVector<WebFormControlElement> WebDocument::UnassociatedFormControls() const {
  Vector<WebFormControlElement> unassociated_form_controls;
  for (const auto& element :
       ConstUnwrap<Document>()->UnassociatedListedElements()) {
    if (auto* form_control =
            blink::DynamicTo<HTMLFormControlElement>(element.Get())) {
      unassociated_form_controls.push_back(form_control);
    }
  }
  return unassociated_form_controls;
}

WebVector<WebFormElement> WebDocument::Forms() const {
  HTMLCollection* forms =
      const_cast<Document*>(ConstUnwrap<Document>())->forms();

  Vector<WebFormElement> form_elements;
  form_elements.reserve(forms->length());
  for (Element* element : *forms) {
    form_elements.emplace_back(blink::To<HTMLFormElement>(element));
  }
  return form_elements;
}

WebVector<WebFormElement> WebDocument::GetTopLevelForms() const {
  Vector<WebFormElement> web_forms;
  HeapVector<Member<HTMLFormElement>> forms =
      const_cast<Document*>(ConstUnwrap<Document>())->GetTopLevelForms();
  web_forms.reserve(forms.size());
  for (auto& form : forms) {
    web_forms.push_back(form.Get());
  }
  return web_forms;
}

WebURL WebDocument::CompleteURL(const WebString& partial_url) const {
  return ConstUnwrap<Document>()->CompleteURL(partial_url);
}

WebElement WebDocument::GetElementById(const WebString& id) const {
  return WebElement(ConstUnwrap<Document>()->getElementById(id));
}

WebElement WebDocument::FocusedElement() const {
  return WebElement(ConstUnwrap<Document>()->FocusedElement());
}

WebStyleSheetKey WebDocument::InsertStyleSheet(
    const WebString& source_code,
    const WebStyleSheetKey* key,
    WebCssOrigin origin,
    BackForwardCacheAware back_forward_cache_aware) {
  Document* document = Unwrap<Document>();
  DCHECK(document);
  if (back_forward_cache_aware == BackForwardCacheAware::kPossiblyDisallow) {
    document->GetFrame()->GetFrameScheduler()->RegisterStickyFeature(
        SchedulingPolicy::Feature::kInjectedStyleSheet,
        {SchedulingPolicy::DisableBackForwardCache()});
  }
  auto* parsed_sheet = MakeGarbageCollected<StyleSheetContents>(
      MakeGarbageCollected<CSSParserContext>(*document));
  parsed_sheet->ParseString(source_code);
  const WebStyleSheetKey& injection_key =
      key && !key->IsNull() ? *key : GenerateStyleSheetKey();
  DCHECK(!injection_key.IsEmpty());
  document->GetStyleEngine().InjectSheet(injection_key, parsed_sheet, origin);
  return injection_key;
}

void WebDocument::RemoveInsertedStyleSheet(const WebStyleSheetKey& key,
                                           WebCssOrigin origin) {
  Unwrap<Document>()->GetStyleEngine().RemoveInjectedSheet(key, origin);
}

void WebDocument::WatchCSSSelectors(const WebVector<WebString>& web_selectors) {
  Document* document = Unwrap<Document>();
  CSSSelectorWatch* watch = CSSSelectorWatch::FromIfExists(*document);
  if (!watch && web_selectors.empty())
    return;
  Vector<String> selectors;
  selectors.AppendSpan(base::span(web_selectors));
  CSSSelectorWatch::From(*document).WatchCSSSelectors(selectors);
}

WebVector<WebDraggableRegion> WebDocument::DraggableRegions() const {
  WebVector<WebDraggableRegion> draggable_regions;
  const Document* document = ConstUnwrap<Document>();
  if (document->HasDraggableRegions()) {
    const Vector<DraggableRegionValue>& regions = document->DraggableRegions();
    draggable_regions = WebVector<WebDraggableRegion>(regions.size());
    for (wtf_size_t i = 0; i < regions.size(); i++) {
      const DraggableRegionValue& value = regions[i];
      draggable_regions[i].draggable = value.draggable;
      draggable_regions[i].bounds = ToPixelSnappedRect(value.bounds);
    }
  }
  return draggable_regions;
}

WebDistillabilityFeatures WebDocument::DistillabilityFeatures() {
  return DocumentStatisticsCollector::CollectStatistics(*Unwrap<Document>());
}

void WebDocument::SetShowBeforeUnloadDialog(bool show_dialog) {
  if (!IsHTMLDocument())
    return;

  Document* doc = Unwrap<Document>();
  doc->SetShowBeforeUnloadDialog(show_dialog);
}

cc::ElementId WebDocument::GetVisualViewportScrollingElementIdForTesting() {
  return blink::To<Document>(private_.Get())
      ->GetPage()
      ->GetVisualViewport()
      .GetScrollElementId();
}

bool WebDocument::IsLoaded() {
  return !ConstUnwrap<Document>()->Parser();
}

bool WebDocument::IsPrerendering() {
  return ConstUnwrap<Document>()->IsPrerendering();
}

bool WebDocument::HasDocumentPictureInPictureWindow() const {
  return ConstUnwrap<Document>()->HasDocumentPictureInPictureWindow();
}

void WebDocument::AddPostPrerenderingActivationStep(
    base::OnceClosure callback) {
  return Unwrap<Document>()->AddPostPrerenderingActivationStep(
      std::move(callback));
}

void WebDocument::SetCookieManager(
    CrossVariantMojoRemote<network::mojom::RestrictedCookieManagerInterfaceBase>
        cookie_manager) {
  Unwrap<Document>()->SetCookieManager(std::move(cookie_manager));
}

WebDocument::WebDocument(Document* elem) : WebNode(elem) {}

DEFINE_WEB_NODE_TYPE_CASTS(WebDocument, ConstUnwrap<Node>()->IsDocumentNode())

WebDocument& WebDocument::operator=(Document* elem) {
  private_ = elem;
  return *this;
}

WebDocument::operator Document*() const {
  return blink::To<Document>(private_.Get());
}

net::ReferrerPolicy WebDocument::GetReferrerPolicy() const {
  network::mojom::ReferrerPolicy policy =
      ConstUnwrap<Document>()->GetExecutionContext()->GetReferrerPolicy();
  if (policy == network::mojom::ReferrerPolicy::kDefault) {
    return blink::ReferrerUtils::GetDefaultNetReferrerPolicy();
  } else {
    return network::ReferrerPolicyForUrlRequest(policy);
  }
}

WebString WebDocument::OutgoingReferrer() const {
  return WebString(ConstUnwrap<Document>()->domWindow()->OutgoingReferrer());
}

void WebDocument::InitiatePreview(const WebURL& url) {
  if (!url.IsValid()) {
    return;
  }

  Document* document = blink::To<Document>(private_.Get());
  if (!document) {
    return;
  }

  KURL kurl(url);
  DocumentSpeculationRules::From(*document).InitiatePreview(kurl);
}

}  // namespace blink
```