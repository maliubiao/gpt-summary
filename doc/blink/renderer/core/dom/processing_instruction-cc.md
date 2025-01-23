Response:
Let's break down the thought process for analyzing this C++ file.

**1. Initial Understanding - What is ProcessingInstruction?**

The filename `processing_instruction.cc` and the class name `ProcessingInstruction` immediately suggest this file deals with XML processing instructions. My prior knowledge tells me these are elements in XML (and sometimes HTML-like contexts) that start with `<?` and end with `?>`, providing instructions to the processing application. Examples include `<?xml version="1.0"?>` or `<?xml-stylesheet type="text/css" href="style.css"?>`.

**2. High-Level Functionality by Observing Includes:**

Looking at the `#include` directives provides strong clues about the file's responsibilities:

* **CSS-related:** `css_style_sheet.h`, `media_list.h`, `style_engine.h`, `style_sheet_contents.h`. This strongly suggests the file handles processing instructions related to CSS stylesheets.
* **DOM-related:** `document.h`, `increment_load_event_delay_count.h`. This indicates the `ProcessingInstruction` class is a part of the Document Object Model and likely interacts with the overall document loading process.
* **Execution Context:** `execution_context/execution_context.h`. This hints at interaction with the runtime environment where JavaScript executes.
* **Resource Loading:** `loader/resource/css_style_sheet_resource.h`, `loader/resource/xsl_style_sheet_resource.h`, `platform/loader/fetch/...`. This is a crucial indicator that the file is responsible for fetching and processing external resources referenced in processing instructions (especially stylesheets).
* **XML-related:** `xml/document_xslt.h`, `xml/parser/xml_document_parser.h`, `xml/xsl_style_sheet.h`. This reinforces the connection to XML and specifically XSLT stylesheets.
* **Platform/Utility:** `platform/heap/garbage_collected.h`. This is a Blink-specific detail about memory management.

**3. Deeper Dive into the Class Definition and Methods:**

Now, examine the `ProcessingInstruction` class members and methods:

* **Constructor:** `ProcessingInstruction(Document& document, const String& target, const String& data)` –  Stores the target (e.g., "xml-stylesheet") and data (the attributes).
* **`nodeName()`:** Returns the target. This fits the DOM Node interface.
* **`CloneWithData()`:** Creates a copy, suggesting it's part of node cloning mechanisms.
* **`DidAttributeChanged()`:** This is a key method. It's triggered when the data within the processing instruction changes. This immediately suggests handling updates to stylesheet references.
* **`CheckStyleSheet()`:**  Parses the data string to identify if it's a stylesheet instruction (`target_ == "xml-stylesheet"`). It extracts the `type`, `href`, `charset`, `alternate`, `title`, and `media` attributes. This is where the connection to CSS and XSLT becomes concrete.
* **`Process()`:**  This is the core logic for handling stylesheet processing instructions. It fetches the stylesheet resource (CSS or XSLT) based on the `href`. It distinguishes between local `#` references and external URLs.
* **`IsLoading()`:**  Checks if the stylesheet is currently being loaded.
* **`SheetLoaded()`:**  Notifies that the stylesheet has loaded.
* **`NotifyFinished()`:**  Handles the completion of the resource fetch. It creates either a `CSSStyleSheet` or an `XSLStyleSheet` object and parses the content.
* **`InsertedInto()`:**  Called when the processing instruction is added to the DOM. It triggers the `Process()` method to start loading the stylesheet.
* **`RemovedFrom()`:**  Called when the processing instruction is removed. It cleans up resources and removes pending loads.
* **`ClearSheet()` and `RemovePendingSheet()`:**  Methods for managing the lifecycle of the associated stylesheet objects.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Based on the identified functionality, I can now connect it to web technologies:

* **HTML:**  The `<link>` tag is the primary way to include CSS. However, processing instructions like `<?xml-stylesheet type="text/css" href="style.css"?>` are used in XML documents and can also appear within HTML documents (although less common for CSS, more so for other XML-based processing).
* **CSS:** The file directly deals with loading and parsing CSS stylesheets based on the `type` attribute.
* **JavaScript:** While this C++ code doesn't directly execute JavaScript, it's part of the browser engine that *supports* JavaScript. JavaScript can manipulate the DOM, including adding or modifying processing instructions. This can trigger `DidAttributeChanged()` and cause stylesheets to be loaded or reloaded.

**5. Logical Reasoning and Assumptions:**

* **Assumption:**  The `ParseAttributes()` function (defined elsewhere) parses the `data_` string into a key-value map of attributes.
* **Input (HTML):** `<?xml-stylesheet type="text/css" href="style.css"?>`
* **Output:** The `ProcessingInstruction` object will initiate a network request to fetch `style.css` and, upon success, create a `CSSStyleSheet` object in the DOM.
* **Input (JavaScript):** `document.head.innerHTML += '<?xml-stylesheet type="text/xsl" href="transform.xsl"?>';`
* **Output:** This would likely trigger the `InsertedInto()` method, leading to the fetching and processing of `transform.xsl` as an XSLT stylesheet.

**6. Common User/Programming Errors:**

* **Incorrect `type` attribute:**  If the `type` is misspelled or not a recognized CSS/XSLT type, the stylesheet won't be loaded.
* **Invalid `href`:** A broken or incorrect URL will lead to a failed resource fetch.
* **Placing in the wrong location:** Stylesheet processing instructions typically belong in the document prolog (before the root element for XML) or within the `<head>` for HTML-like contexts. Placing them elsewhere might not have the intended effect.
* **Forgetting the `href`:** Without an `href`, the browser won't know where to fetch the stylesheet.

**7. Debugging Scenario:**

To reach this code during debugging, a developer might:

1. **Load a web page (HTML or XML) that includes a stylesheet processing instruction.**
2. **Observe that a stylesheet is not being applied as expected.**
3. **Use browser developer tools (Network tab) to see if the stylesheet is being fetched.**
4. **If not, they might suspect an issue with the processing instruction itself.**
5. **Set a breakpoint in `ProcessingInstruction::CheckStyleSheet()` or `ProcessingInstruction::Process()` in the Chromium source code.**
6. **Reload the page.** The breakpoint will be hit when the browser encounters the processing instruction, allowing the developer to inspect the `target_`, `data_`, and extracted attributes to identify any errors. They could step through the code to see how the URL is being resolved and the resource fetch initiated.

This step-by-step approach, starting with the overall purpose and then drilling down into the details of the code, allows for a comprehensive understanding of the file's functionality and its relation to web technologies.
好的，让我们来分析一下 `blink/renderer/core/dom/processing_instruction.cc` 这个 Chromium Blink 引擎源代码文件。

**功能概述**

这个文件的核心功能是处理文档中的 **Processing Instruction (PI)** 节点。Processing Instruction 是一种 XML（以及某些 HTML 场景下）的节点类型，它允许文档包含用于指导应用程序如何处理文档的信息。最常见的例子就是用于引入外部 CSS 样式表的 `<?xml-stylesheet ... ?>`。

具体来说，`ProcessingInstruction.cc` 实现了 `ProcessingInstruction` 类，该类负责以下主要任务：

1. **解析 Processing Instruction 的内容：** 特别是当 Processing Instruction 的目标（target）是 `xml-stylesheet` 时，它会解析 `type`、`href`、`charset`、`media`、`title` 和 `alternate` 等属性。
2. **加载外部资源（主要是 CSS 和 XSLT 样式表）：**  当解析到 `xml-stylesheet` 并且 `href` 属性指向外部文件时，它会发起网络请求来加载这些资源。
3. **创建和管理 `CSSStyleSheet` 或 `XSLStyleSheet` 对象：**  一旦资源加载完成，它会创建相应的样式表对象，并将其关联到该 Processing Instruction。
4. **处理样式表的加载和卸载：** 监控样式表的加载状态，并在 Processing Instruction 被添加到文档或从文档中移除时进行相应的处理。
5. **与 StyleEngine 交互：** 将加载的 CSS 样式表注册到 Blink 的样式引擎 (`StyleEngine`) 中，使其能够影响页面的渲染。
6. **处理嵌入式样式表：** 对于 `href` 以 `#` 开头的 Processing Instruction，它会将其视为嵌入在文档内的样式表。
7. **支持 XSLT 转换：**  如果 Processing Instruction 指定的是 XSLT 样式表，它会处理 XSLT 相关的加载和解析。

**与 JavaScript, HTML, CSS 的关系及举例说明**

* **HTML:**  虽然 Processing Instruction 主要与 XML 相关，但在某些 HTML 文档中也可能出现，尤其是在使用 XML 序列化格式的 HTML (如 XHTML) 中。
    * **举例：**  在一个 XHTML 文档中，你可能会看到 `<?xml-stylesheet type="text/css" href="styles.css"?>`。Blink 会解析这个 PI，并加载 `styles.css` 应用到页面。
    * **用户操作如何到达这里：** 用户访问一个包含上述 PI 的 XHTML 页面时，Blink 的 HTML 解析器会遇到这个 PI 节点，并创建 `ProcessingInstruction` 对象。

* **CSS:**  `ProcessingInstruction.cc` 的一个核心功能就是处理引入 CSS 样式表的 PI。
    * **举例：**  `<?xml-stylesheet type="text/css" href="layout.css" media="screen"?>`。这个 PI 指示浏览器加载 `layout.css`，并只在屏幕设备上应用。
    * **假设输入与输出：**
        * **假设输入 (data_ 属性内容):** `type="text/css" href="theme.css"`
        * **逻辑推理：** `CheckStyleSheet` 函数会识别出 `target_` 是 "xml-stylesheet"，`type` 是 "text/css"，并提取出 `href` 的值为 "theme.css"。`Process` 函数会被调用，发起对 "theme.css" 的加载请求。
        * **假设输出：** 如果加载成功，会创建一个 `CSSStyleSheet` 对象，并将 `theme.css` 的样式规则添加到文档的样式系统中。
    * **用户操作如何到达这里：** 开发者在 XML 或 XHTML 文档中添加了 `<?xml-stylesheet ... ?>` 标签，当浏览器解析到这个标签时，会创建 `ProcessingInstruction` 对象并调用其方法。

* **JavaScript:** JavaScript 可以通过 DOM API 来操作 Processing Instruction 节点。
    * **举例：** JavaScript 可以使用 `document.createProcessingInstruction()` 创建一个新的 Processing Instruction 节点，并使用 `parentNode.insertBefore()` 将其添加到文档中。
    * **用户操作如何到达这里：** 网页上的 JavaScript 代码执行了创建和插入 `<?xml-stylesheet ... ?>` 节点的操作。例如，一个动态主题切换功能可能会使用 JavaScript 创建并插入不同的 CSS 样式表 PI。
    * **假设输入与输出：**
        * **假设输入 (JavaScript 代码):**
          ```javascript
          var pi = document.createProcessingInstruction('xml-stylesheet', 'type="text/css" href="dynamic.css"');
          document.head.appendChild(pi);
          ```
        * **逻辑推理：** 当这个 JavaScript 代码执行时，会创建一个 `ProcessingInstruction` 对象，目标是 "xml-stylesheet"，数据是 'type="text/css" href="dynamic.css"'。当这个节点被添加到文档中 (`appendChild`) 时，`InsertedInto` 方法会被调用。
        * **假设输出：** `InsertedInto` 方法会调用 `CheckStyleSheet` 和 `Process`，最终导致 `dynamic.css` 被加载并应用。

**逻辑推理的假设输入与输出**

我们已经在上面的 CSS 和 JavaScript 部分给出了一些逻辑推理的例子。再补充一个关于 XSLT 的例子：

* **假设输入 (data_ 属性内容):** `type="text/xsl" href="transform.xsl"`
* **逻辑推理：** `CheckStyleSheet` 会识别出 `type` 是 "text/xsl"，并提取 `href` 为 "transform.xsl"。 `Process` 会发起对 "transform.xsl" 的加载请求，并将其视为 XSLT 样式表。
* **假设输出：** 如果加载成功，会创建一个 `XSLStyleSheet` 对象。后续，这个 XSLT 样式表可以用于转换 XML 文档。

**用户或编程常见的使用错误及举例说明**

1. **拼写错误或错误的 `type` 属性：** 如果 `type` 属性的值不是浏览器支持的样式表类型（例如，拼写成 "text/cas"），浏览器将不会识别它为样式表，也就不会加载。
    * **错误示例：** `<?xml-stylesheet type="text/cas" href="styles.css"?>`
    * **调试线索：** 在 `CheckStyleSheet` 方法中，`is_css_` 和 `is_xsl_` 变量会是 `false`，导致后续的 `Process` 方法不会被调用。

2. **`href` 路径错误或无法访问：** 如果 `href` 指向一个不存在的文件或者因为网络问题无法访问，样式表加载会失败。
    * **错误示例：** `<?xml-stylesheet type="text/css" href="styels.css"?>` (拼写错误)
    * **调试线索：** 在 `Process` 方法中，资源加载会失败，`NotifyFinished` 方法中的 `resource` 参数会指示加载错误。

3. **将 `xml-stylesheet` PI 放在错误的位置：**  虽然在 XML 中位置相对自由，但在 HTML 中，最好将它们放在 `<head>` 标签内，以确保尽早加载样式。
    * **错误示例：** 将 `<?xml-stylesheet ... ?>` 放在 `<body>` 标签的末尾，可能会导致样式应用延迟或出现 FOUC (Flash of Unstyled Content)。
    * **调试线索：** 尽管功能上可能正确，但性能上会有影响。开发者可以通过观察页面加载过程和样式应用的顺序来发现问题。

4. **忘记指定 `href` 属性：**  如果没有 `href` 属性，浏览器无法知道要加载哪个样式表。
    * **错误示例：** `<?xml-stylesheet type="text/css"?>`
    * **调试线索：** `CheckStyleSheet` 方法会返回 `false`，因为缺少必要的 `href` 属性。

**用户操作如何一步步的到达这里，作为调试线索**

假设用户遇到了一个网页，该网页的样式没有正确加载。作为开发者，可以按照以下步骤进行调试，最终可能会追踪到 `ProcessingInstruction.cc`：

1. **打开浏览器开发者工具 (通常按 F12)。**
2. **检查 "Elements" (或 "Inspect") 面板：** 查看文档的 DOM 结构，确认是否存在 `<?xml-stylesheet ... ?>` 节点。
3. **检查 "Network" 面板：** 查看是否有对 `href` 属性中指定的 CSS 文件的请求。
    * **如果没有请求：**  这可能意味着 Processing Instruction 没有被正确解析或处理。可以回到 "Elements" 面板检查 PI 的属性是否正确。
    * **如果有请求但失败 (HTTP 状态码 404, 500 等)：**  这表明 `href` 指向的资源存在问题。
    * **如果有请求且成功，但样式未应用：**  可能存在 CSS 语法错误或其他样式冲突问题，但这与 `ProcessingInstruction.cc` 的关系不大。
4. **如果怀疑是 Processing Instruction 解析问题：**  可以在 Chromium 源代码中设置断点进行调试。
    * **在 `blink/renderer/core/dom/processing_instruction.cc` 文件的以下方法中设置断点：**
        * `ProcessingInstruction::CheckStyleSheet()`：检查是否正确识别了样式表 PI。
        * `ProcessingInstruction::Process()`：检查是否发起了资源加载请求。
        * `ProcessingInstruction::NotifyFinished()`：检查资源加载是否成功以及样式表对象是否被正确创建。
        * `ProcessingInstruction::InsertedInto()`：检查当 PI 被插入文档时是否触发了正确的处理流程。
5. **重新加载网页。** 当代码执行到断点时，可以检查相关的变量值，例如 `target_`, `data_`, `href`, `type` 等，以确定问题所在。

通过以上步骤，开发者可以逐步缩小问题范围，最终确定是否是与 `ProcessingInstruction` 相关的代码逻辑导致了样式加载问题。例如，如果断点在 `CheckStyleSheet` 中被触发，但由于 `type` 属性错误而返回 `false`，那么问题就定位在了 PI 的属性上。

总而言之，`blink/renderer/core/dom/processing_instruction.cc` 是 Blink 引擎中处理文档中 Processing Instruction 节点的核心组件，特别是在加载和管理外部 CSS 和 XSLT 样式表方面起着至关重要的作用。理解其功能有助于开发者调试与样式表引入相关的各种问题。

### 提示词
```
这是目录为blink/renderer/core/dom/processing_instruction.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2000 Peter Kelly (pmk@post.com)
 * Copyright (C) 2006, 2008, 2009 Apple Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/dom/processing_instruction.h"

#include <memory>

#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/media_list.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/increment_load_event_delay_count.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/loader/resource/css_style_sheet_resource.h"
#include "third_party/blink/renderer/core/loader/resource/xsl_style_sheet_resource.h"
#include "third_party/blink/renderer/core/xml/document_xslt.h"
#include "third_party/blink/renderer/core/xml/parser/xml_document_parser.h"  // for parseAttributes()
#include "third_party/blink/renderer/core/xml/xsl_style_sheet.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_type_names.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_parameters.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"

namespace blink {

ProcessingInstruction::ProcessingInstruction(Document& document,
                                             const String& target,
                                             const String& data)
    : CharacterData(document, data, kCreateProcessingInstruction),
      target_(target),
      loading_(false),
      alternate_(false),
      is_css_(false),
      is_xsl_(false),
      listener_for_xslt_(nullptr) {}

ProcessingInstruction::~ProcessingInstruction() = default;

EventListener* ProcessingInstruction::EventListenerForXSLT() {
  if (!listener_for_xslt_)
    return nullptr;

  return listener_for_xslt_->ToEventListener();
}

void ProcessingInstruction::ClearEventListenerForXSLT() {
  if (listener_for_xslt_) {
    listener_for_xslt_->Detach();
    listener_for_xslt_.Clear();
  }
}

String ProcessingInstruction::nodeName() const {
  return target_;
}

CharacterData* ProcessingInstruction::CloneWithData(Document& factory,
                                                    const String& data) const {
  // FIXME: Is it a problem that this does not copy local_href_?
  // What about other data members?
  return MakeGarbageCollected<ProcessingInstruction>(factory, target_, data);
}

void ProcessingInstruction::DidAttributeChanged() {
  if (sheet_) {
    if (sheet_->IsLoading())
      RemovePendingSheet();
    ClearSheet();
  }

  String href;
  String charset;
  if (!CheckStyleSheet(href, charset))
    return;
  Process(href, charset);
}

bool ProcessingInstruction::CheckStyleSheet(String& href, String& charset) {
  if (target_ != "xml-stylesheet" || !GetDocument().GetFrame() ||
      parentNode() != GetDocument())
    return false;

  // see http://www.w3.org/TR/xml-stylesheet/
  // ### support stylesheet included in a fragment of this (or another) document
  // ### make sure this gets called when adding from javascript
  bool attrs_ok;
  const HashMap<String, String> attrs = ParseAttributes(data_, attrs_ok);
  if (!attrs_ok)
    return false;
  HashMap<String, String>::const_iterator i = attrs.find("type");
  String type;
  if (i != attrs.end())
    type = i->value;

  is_css_ = type.empty() || type == "text/css";
  is_xsl_ = (type == "text/xml" || type == "text/xsl" ||
             type == "application/xml" || type == "application/xhtml+xml" ||
             type == "application/rss+xml" || type == "application/atom+xml");
  if (!is_css_ && !is_xsl_)
    return false;

  auto it_href = attrs.find("href");
  href = it_href != attrs.end() ? it_href->value : "";
  auto it_charset = attrs.find("charset");
  charset = it_charset != attrs.end() ? it_charset->value : "";
  auto it_alternate = attrs.find("alternate");
  String alternate = it_alternate != attrs.end() ? it_alternate->value : "";
  alternate_ = alternate == "yes";
  auto it_title = attrs.find("title");
  title_ = it_title != attrs.end() ? it_title->value : "";
  auto it_media = attrs.find("media");
  media_ = it_media != attrs.end() ? it_media->value : "";

  return !alternate_ || !title_.empty();
}

void ProcessingInstruction::Process(const String& href, const String& charset) {
  if (href.length() > 1 && href[0] == '#') {
    local_href_ = href.Substring(1);
    // We need to make a synthetic XSLStyleSheet that is embedded.
    // It needs to be able to kick off import/include loads that
    // can hang off some parent sheet.
    if (is_xsl_) {
      KURL final_url(local_href_);
      sheet_ = MakeGarbageCollected<XSLStyleSheet>(this, final_url.GetString(),
                                                   final_url, true);
      loading_ = false;
    }
    return;
  }

  ClearResource();

  ResourceLoaderOptions options(GetExecutionContext()->GetCurrentWorld());
  options.initiator_info.name =
      fetch_initiator_type_names::kProcessinginstruction;
  FetchParameters params(ResourceRequest(GetDocument().CompleteURL(href)),
                         options);
  loading_ = true;
  if (is_xsl_) {
    params.MutableResourceRequest().SetMode(
        network::mojom::RequestMode::kSameOrigin);
    XSLStyleSheetResource::Fetch(params, GetDocument().Fetcher(), this);
  } else {
    params.SetCharset(charset.empty() ? GetDocument().Encoding()
                                      : WTF::TextEncoding(charset));
    GetDocument().GetStyleEngine().AddPendingBlockingSheet(
        *this, PendingSheetType::kBlocking);
    CSSStyleSheetResource::Fetch(params, GetDocument().Fetcher(), this);
  }
}

bool ProcessingInstruction::IsLoading() const {
  if (loading_)
    return true;
  if (!sheet_)
    return false;
  return sheet_->IsLoading();
}

bool ProcessingInstruction::SheetLoaded() {
  if (!IsLoading()) {
    if (!DocumentXSLT::SheetLoaded(GetDocument(), this))
      RemovePendingSheet();
    return true;
  }
  return false;
}

void ProcessingInstruction::NotifyFinished(Resource* resource) {
  if (!isConnected()) {
    DCHECK(!sheet_);
    return;
  }

  std::unique_ptr<IncrementLoadEventDelayCount> delay =
      is_xsl_ ? std::make_unique<IncrementLoadEventDelayCount>(GetDocument())
              : nullptr;
  if (is_xsl_) {
    sheet_ = MakeGarbageCollected<XSLStyleSheet>(
        this, resource->Url(), resource->GetResponse().ResponseUrl(), false);
    To<XSLStyleSheet>(sheet_.Get())
        ->ParseString(To<XSLStyleSheetResource>(resource)->Sheet());
  } else {
    DCHECK(is_css_);
    auto* style_resource = To<CSSStyleSheetResource>(resource);
    auto* parser_context = MakeGarbageCollected<CSSParserContext>(
        GetDocument(), style_resource->GetResponse().ResponseUrl(),
        style_resource->GetResponse().IsCorsSameOrigin(),
        Referrer(style_resource->GetResponse().ResponseUrl(),
                 style_resource->GetReferrerPolicy()),
        style_resource->Encoding());
    if (style_resource->GetResourceRequest().IsAdResource())
      parser_context->SetIsAdRelated();

    auto* new_sheet = MakeGarbageCollected<StyleSheetContents>(
        parser_context, style_resource->Url());

    auto* css_sheet = MakeGarbageCollected<CSSStyleSheet>(new_sheet, *this);
    css_sheet->setDisabled(alternate_);
    css_sheet->SetTitle(title_);
    if (!alternate_ && !title_.empty()) {
      GetDocument().GetStyleEngine().SetPreferredStylesheetSetNameIfNotSet(
          title_);
    }
    css_sheet->SetMediaQueries(
        MediaQuerySet::Create(media_, GetExecutionContext()));
    sheet_ = css_sheet;
    // We don't need the cross-origin security check here because we are
    // getting the sheet text in "strict" mode. This enforces a valid CSS MIME
    // type.
    css_sheet->Contents()->ParseString(
        style_resource->SheetText(parser_context));
  }

  ClearResource();
  loading_ = false;

  if (is_css_)
    To<CSSStyleSheet>(sheet_.Get())->Contents()->CheckLoaded();
  else if (is_xsl_)
    To<XSLStyleSheet>(sheet_.Get())->CheckLoaded();
}

Node::InsertionNotificationRequest ProcessingInstruction::InsertedInto(
    ContainerNode& insertion_point) {
  CharacterData::InsertedInto(insertion_point);
  if (!insertion_point.isConnected())
    return kInsertionDone;

  String href;
  String charset;
  bool is_valid = CheckStyleSheet(href, charset);
  if (!DocumentXSLT::ProcessingInstructionInsertedIntoDocument(GetDocument(),
                                                               this))
    GetDocument().GetStyleEngine().AddStyleSheetCandidateNode(*this);
  if (is_valid)
    Process(href, charset);
  return kInsertionDone;
}

void ProcessingInstruction::RemovedFrom(ContainerNode& insertion_point) {
  CharacterData::RemovedFrom(insertion_point);
  if (!insertion_point.isConnected())
    return;

  // No need to remove XSLStyleSheet from StyleEngine.
  if (!DocumentXSLT::ProcessingInstructionRemovedFromDocument(GetDocument(),
                                                              this)) {
    GetDocument().GetStyleEngine().RemoveStyleSheetCandidateNode(
        *this, insertion_point);
  }

  if (IsLoading())
    RemovePendingSheet();

  if (sheet_) {
    DCHECK_EQ(sheet_->ownerNode(), this);
    ClearSheet();
  }

  // No need to remove pending sheets.
  ClearResource();
}

void ProcessingInstruction::ClearSheet() {
  DCHECK(sheet_);
  sheet_.Release()->ClearOwnerNode();
}

void ProcessingInstruction::RemovePendingSheet() {
  if (is_xsl_)
    return;
  GetDocument().GetStyleEngine().RemovePendingBlockingSheet(
      *this, PendingSheetType::kBlocking);
}

void ProcessingInstruction::Trace(Visitor* visitor) const {
  visitor->Trace(sheet_);
  visitor->Trace(listener_for_xslt_);
  CharacterData::Trace(visitor);
  ResourceClient::Trace(visitor);
}

}  // namespace blink
```