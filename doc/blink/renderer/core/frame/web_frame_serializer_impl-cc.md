Response:
Let's break down the thought process for analyzing this code and generating the description.

1. **Understand the Core Goal:** The file name `web_frame_serializer_impl.cc` and the presence of terms like "serialize", "DOM", "frame" immediately suggest this code is responsible for converting a web frame's content (HTML, etc.) into a serializable format, likely a string. The comments at the top about the `<base>` tag issue provide further context – this serializer needs to handle cases where the base URL might be dynamically set.

2. **Identify Key Classes and Functions:** Skimming the `#include` directives and the class definition reveals important components:
    * `WebFrameSerializerImpl`: The main class implementing the serialization logic.
    * `SerializeDomParam`: A helper structure likely used to pass context during the serialization process.
    * `PreActionBeforeSerializeOpenTag`, `PostActionAfterSerializeOpenTag`, etc.:  These function names strongly suggest a step-by-step process of serializing elements. The "pre" and "post" actions indicate hooks for modifying the output before and after the core serialization of an element's tag.
    * `OpenTagToString`, `EndTagToString`, `BuildContentForNode`: These seem to be the core functions responsible for generating the string representation of elements and their content.
    * `SaveHTMLContentToBuffer`, `EncodeAndFlushBuffer`: Functions dealing with buffering and encoding the serialized output.
    * `RewriteLink`, `RewriteFrameSource`:  Methods within the delegate suggest a mechanism for modifying URLs during serialization.

3. **Analyze the Serialization Process (High-Level):**  The `Serialize()` function appears to be the entry point. It gets the `Document` and its URL. The call to `BuildContentForNode` with the `documentElement` indicates a recursive traversal of the DOM. The buffering and encoding steps suggest handling for different character encodings.

4. **Focus on HTML, CSS, and JavaScript Relevance:** The code directly manipulates HTML elements (e.g., `HTMLBaseElement`, `HTMLMetaElement`, `HTMLHeadElement`). The `<base>` tag handling is a prime example of interacting with HTML structure. The comments explicitly mention JavaScript's potential to modify the `<base>` tag, indicating an awareness of dynamic content. While the code doesn't directly parse or execute JavaScript or CSS, it needs to be aware of how these interact with the DOM and how their linked resources should be handled during serialization.

5. **Look for Logic and Decision Points:** The `PreAction...` and `PostAction...` functions contain conditional logic based on the type of element. The handling of the `<base>` tag is a significant example of this logic. The checks for `param->is_html_document` indicate different behavior for HTML and XML documents. The `RewriteLink` delegate call suggests a configurable way to modify URLs, which is crucial for handling relative paths and resource locations.

6. **Identify Potential User Errors and Edge Cases:** The comments about the dynamically generated `<base>` tag highlight a specific problem. The logic to comment out old `<base>` tags and insert new ones is a direct solution to this potential issue. The handling of character encoding and the BOM (Byte Order Mark) also point to concerns about ensuring proper rendering of the saved content. The comment about WebKit's parsing limitations (first 512 bytes) reveals another edge case the serializer needs to address.

7. **Construct the Description:** Based on the above analysis, start drafting the description, focusing on the main purpose of the file. Then elaborate on specific functionalities, relating them to HTML, CSS, and JavaScript where applicable.

8. **Generate Examples:** Create illustrative examples based on the identified logic and potential issues. For instance, the `<base>` tag example demonstrates the problem and the serializer's solution. The link rewriting example shows how the delegate can modify URLs.

9. **Review and Refine:** Read through the generated description and examples. Ensure clarity, accuracy, and completeness. Check for any logical inconsistencies or missing information. For example, initially, I might have just said it "serializes HTML."  But the details about `<base>` tag handling and link rewriting are important nuances. Refining involves adding these details and making the language more precise. Also, consider the audience. A developer working with Blink would understand more technical terms.

**(Self-Correction Example during the process):** Initially, I might have overlooked the significance of the `RewriteLink` delegate. On a second pass, noticing its usage within the attribute processing loop, I would realize its importance in handling resource URLs and update the description accordingly. Similarly, the initial focus might have been solely on HTML. Recognizing the XML handling would lead to adding information about that aspect.

By following these steps, systematically analyzing the code, and focusing on the key aspects, it's possible to generate a comprehensive and accurate description like the example provided in the prompt.
这个文件 `blink/renderer/core/frame/web_frame_serializer_impl.cc` 的主要功能是**实现将 WebFrame (通常是浏览器中的一个标签页或 iframe) 的内容序列化为字符串的功能**。  这个序列化过程通常用于“保存网页为完整 HTML”之类的操作。

更具体地说，它负责将 DOM 树（文档对象模型）转换成一个可以保存或传输的字符串表示形式。这个过程需要考虑各种细节，例如：

**主要功能:**

1. **DOM 树遍历和序列化:**  核心功能是遍历 `WebFrame` 关联的 `Document` 对象的 DOM 树，并将每个节点（例如元素、文本节点、注释等）转换成其对应的字符串表示形式。

2. **处理 `<base>` 标签:**  这是一个非常重要的功能，也是代码注释中重点讨论的部分。当保存网页时，需要正确处理 `<base>` 标签，以确保保存后的页面能够正确加载相对路径的资源（CSS、JavaScript、图片等）。该文件采用的策略是：
    * **注释掉原始的 `<base>` 标签:**  避免原始 `<base>` 标签影响保存后页面的资源加载。
    * **插入新的 `<base href=".">` 标签:**  指定当前目录为基础 URL，使得相对路径资源能够从保存的本地目录加载。同时会继承原始文档的 `base target` 属性。
    * **处理 JavaScript 动态添加的 `<base>` 标签:**  通过在每个原始 `<base>` 标签后添加新的 `<base>` 标签，来覆盖可能由 JavaScript 在页面加载后动态插入的错误 `<base>` 标签。

3. **处理字符编码:**  确保序列化后的 HTML 使用正确的字符编码，通常会添加 `<meta charset="...">` 标签来声明编码。

4. **处理 `<!DOCTYPE>` 声明:**  保留原始文档的 `<!DOCTYPE>` 声明。

5. **处理浏览器特定的标记:** 例如，添加 "Mark of the Web" (MOTW) 注释，这主要用于 Internet Explorer，以指示文件来自互联网区域，从而启用某些安全特性。

6. **处理 XML 文档:**  对于非 HTML 文档（例如 XML），会添加 XML 声明 (`<?xml version="..." encoding="..."?>`)。

7. **链接重写 (通过委托):**  它允许通过 `WebFrameSerializer::LinkRewritingDelegate` 来修改链接 (URL) 的生成方式。这对于将绝对路径转换为相对路径，或者指向本地保存的资源非常有用。

8. **帧 (Frame) 处理:**  能够处理包含 iframe 或 frame 的页面，并递归地序列化子帧的内容。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**  这个文件的核心工作是序列化 HTML 结构。
    * **例 1 ( `<base>` 标签 ):**  当遇到 `<base href="http://example.com/">` 时，会被序列化为 `<!--<base href="http://example.com/">--><base href=".">`。这样，保存后的页面会使用本地目录作为基础 URL。
    * **例 2 ( `<meta charset>` ):**  如果原始文档的字符编码是 UTF-8，则会确保序列化的 HTML 包含类似 `<meta charset="utf-8">` 的标签。
    * **例 3 ( 元素属性 ):**  HTML 元素的属性会被正确地序列化，例如 `<a href="page.html">` 会被序列化为 `<a href="page.html">` (可能经过链接重写)。

* **JavaScript:**  该文件需要处理 JavaScript 动态修改 DOM 的情况，特别是 `<base>` 标签。
    * **例 1 ( JavaScript 修改 `<base>` ):** 假设页面 JavaScript 执行了 `document.write('<base href="http://another.com/">');`。  序列化时，原有的 `<base>` (如果存在) 会被注释并添加新的 `<base href=".">`，而 JavaScript 插入的 `<base>` 也会被类似地处理。 这样，无论 JavaScript 如何修改，最终保存的页面都会有一个指向本地目录的 `<base>` 标签。

* **CSS:**  虽然该文件不直接处理 CSS 的解析或修改，但它会影响 CSS 资源的加载方式。
    * **例 1 ( CSS 相对路径 ):**  如果 CSS 文件中包含 `background-image: url('images/bg.png');`，并且页面正确地处理了 `<base href=".">`，那么保存后的页面会尝试从本地 `images/bg.png` 加载图片。
    * **例 2 ( 链接重写 ):**  通过 `LinkRewritingDelegate`，可以将 CSS 文件中引用的图片或其他资源的 URL 修改为本地保存的路径。

**逻辑推理、假设输入与输出:**

**假设输入:**  一个包含以下 HTML 的 WebFrame：

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="ISO-8859-1">
  <title>Example Page</title>
  <base href="http://original.example.com/">
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <a href="page2.html">Link</a>
  <script src="script.js"></script>
  <img src="images/logo.png">
  <iframe src="frame.html"></iframe>
  <script>
    document.write('<base href="http://dynamic.example.com/">');
  </script>
</body>
</html>
```

**逻辑推理:**

1. 识别到 `<!DOCTYPE html>`，会保留。
2. 识别到 `<meta charset="ISO-8859-1">`，但由于要确保编码正确，可能会添加或替换为基于实际编码的 `<meta charset="...">`。
3. 识别到 `<base href="http://original.example.com/">`，会注释并添加 `<base href=".">`。
4. 识别到 `<link rel="stylesheet" href="style.css">`，`href` 属性可能通过 `LinkRewritingDelegate` 被修改为本地路径。
5. 识别到 `<a href="page2.html">`，`href` 属性可能通过 `LinkRewritingDelegate` 被修改为本地路径。
6. 识别到 `<script src="script.js">`，`src` 属性可能通过 `LinkRewritingDelegate` 被修改为本地路径。
7. 识别到 `<img src="images/logo.png">`，`src` 属性可能通过 `LinkRewritingDelegate` 被修改为本地路径。
8. 识别到 `<iframe src="frame.html"></iframe>`，`src` 属性可能通过 `LinkRewritingDelegate` 被修改为本地路径，并且会递归地序列化 `frame.html` 的内容。
9. 识别到 JavaScript 动态插入的 `<base href="http://dynamic.example.com/">`，会注释并添加 `<base href=".">`。

**可能的输出 (简化版，假设 `LinkRewritingDelegate` 将所有相对路径资源指向本地同名文件):**

```html
<!DOCTYPE html>
<!-- saved from url=(0000)http://original.example.com/ -->
<html>
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <!--<meta charset="ISO-8859-1">--><meta charset="utf-8">
  <title>Example Page</title>
  <!--<base href="http://original.example.com/">--><base href=".">
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <a href="page2.html">Link</a>
  <script src="script.js"></script>
  <img src="images/logo.png">
  <iframe src="frame.html"></iframe>
  <script>
    document.write('<base href="http://dynamic.example.com/">');
  </script>
  <!--<base href="http://dynamic.example.com/">--><base href=".">
</body>
</html>
```

**涉及用户或编程常见的使用错误:**

1. **不正确的字符编码处理:** 如果没有正确处理字符编码，保存的页面可能会出现乱码。用户可能会看到无法识别的字符。
    * **错误示例:**  原始页面是 UTF-8 编码，但序列化时没有添加 `<meta charset="utf-8">` 或者添加了错误的编码声明。

2. **`<base>` 标签处理不当:**  如果 `<base>` 标签处理有缺陷，保存后的页面可能无法正确加载 CSS、JavaScript 或图片等资源。
    * **错误示例:**  没有注释掉原始的 `<base>` 标签，导致保存后的页面仍然使用原始网站的基础 URL，无法找到本地保存的资源。

3. **链接重写逻辑错误:** `LinkRewritingDelegate` 的实现可能存在错误，导致链接指向错误的位置或无法访问。
    * **错误示例:**  在重写链接时，没有考虑到子目录结构，导致链接指向了错误的本地文件路径。

4. **处理动态内容不完整:**  虽然该文件尝试处理 JavaScript 动态添加的 `<base>` 标签，但可能无法完全处理所有动态修改 DOM 的情况。
    * **错误示例:**  如果 JavaScript 在页面加载后动态创建了新的 `<img>` 标签并设置了 `src` 属性，序列化时可能无法捕获到这些动态添加的元素。

5. **帧 (Frame) 处理错误:**  在处理包含 iframe 或 frame 的页面时，如果序列化逻辑有误，可能导致子帧的内容丢失或显示不正确。
    * **错误示例:**  没有递归地序列化子帧的内容，导致保存后的页面中 iframe 部分为空白。

总而言之，`web_frame_serializer_impl.cc` 是 Chromium Blink 引擎中一个关键的组件，负责将 WebFrame 的内容转换为可保存的格式，并且需要处理许多与 HTML 结构、资源加载和动态内容相关的复杂问题。

### 提示词
```
这是目录为blink/renderer/core/frame/web_frame_serializer_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
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

// How we handle the base tag better.
// Current status:
// At now the normal way we use to handling base tag is
// a) For those links which have corresponding local saved files, such as
// savable CSS, JavaScript files, they will be written to relative URLs which
// point to local saved file. Why those links can not be resolved as absolute
// file URLs, because if they are resolved as absolute URLs, after moving the
// file location from one directory to another directory, the file URLs will
// be dead links.
// b) For those links which have not corresponding local saved files, such as
// links in A, AREA tags, they will be resolved as absolute URLs.
// c) We comment all base tags when serialzing DOM for the page.
// FireFox also uses above way to handle base tag.
//
// Problem:
// This way can not handle the following situation:
// the base tag is written by JavaScript.
// For example. The page "www.yahoo.com" use
// "document.write('<base href="http://www.yahoo.com/"...');" to setup base URL
// of page when loading page. So when saving page as completed-HTML, we assume
// that we save "www.yahoo.com" to "c:\yahoo.htm". After then we load the saved
// completed-HTML page, then the JavaScript will insert a base tag
// <base href="http://www.yahoo.com/"...> to DOM, so all URLs which point to
// local saved resource files will be resolved as
// "http://www.yahoo.com/yahoo_files/...", which will cause all saved  resource
// files can not be loaded correctly. Also the page will be rendered ugly since
// all saved sub-resource files (such as CSS, JavaScript files) and sub-frame
// files can not be fetched.
// Now FireFox, IE and WebKit based Browser all have this problem.
//
// Solution:
// My solution is that we comment old base tag and write new base tag:
// <base href="." ...> after the previous commented base tag. In WebKit, it
// always uses the latest "href" attribute of base tag to set document's base
// URL. Based on this behavior, when we encounter a base tag, we comment it and
// write a new base tag <base href="."> after the previous commented base tag.
// The new added base tag can help engine to locate correct base URL for
// correctly loading local saved resource files. Also I think we need to inherit
// the base target value from document object when appending new base tag.
// If there are multiple base tags in original document, we will comment all old
// base tags and append new base tag after each old base tag because we do not
// know those old base tags are original content or added by JavaScript. If
// they are added by JavaScript, it means when loading saved page, the script(s)
// will still insert base tag(s) to DOM, so the new added base tag(s) can
// override the incorrect base URL and make sure we alway load correct local
// saved resource files.

#include "third_party/blink/renderer/core/frame/web_frame_serializer_impl.h"

#include "third_party/blink/public/platform/web_vector.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_type.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/frame/frame_serializer.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/html_all_collection.h"
#include "third_party/blink/renderer/core/html/html_base_element.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_frame_element_base.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html/html_meta_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding.h"

namespace blink {

namespace {

// Generate the default base tag declaration.
String GenerateBaseTagDeclaration(const String& base_target) {
  // TODO(yosin) We should call |FrameSerializer::baseTagDeclarationOf()|.
  if (base_target.empty())
    return String("<base href=\".\">");
  String base_string = "<base href=\".\" target=\"" + base_target + "\">";
  return base_string;
}

}  // namespace

// Maximum length of data buffer which is used to temporary save generated
// html content data. This is a soft limit which might be passed if a very large
// contegious string is found in the html document.
static const unsigned kDataBufferCapacity = 65536;

WebFrameSerializerImpl::SerializeDomParam::SerializeDomParam(
    const KURL& url,
    const WTF::TextEncoding& text_encoding,
    Document* document)
    : url(url),
      text_encoding(text_encoding),
      document(document),
      is_html_document(IsA<HTMLDocument>(document)),
      have_seen_doc_type(false),
      have_added_charset_declaration(false),
      skip_meta_element(nullptr),
      have_added_xml_processing_directive(false),
      have_added_contents_before_end(false) {}

String WebFrameSerializerImpl::PreActionBeforeSerializeOpenTag(
    const Element* element,
    SerializeDomParam* param,
    bool* need_skip) {
  StringBuilder result;

  *need_skip = false;
  if (param->is_html_document) {
    // Skip the open tag of original META tag which declare charset since we
    // have overrided the META which have correct charset declaration after
    // serializing open tag of HEAD element.
    DCHECK(element);
    auto* meta = DynamicTo<HTMLMetaElement>(element);
    if (meta && meta->ComputeEncoding().IsValid()) {
      // Found META tag declared charset, we need to skip it when
      // serializing DOM.
      param->skip_meta_element = element;
      *need_skip = true;
    } else if (IsA<HTMLHtmlElement>(element)) {
      // Check something before processing the open tag of HEAD element.
      // First we add doc type declaration if original document has it.
      if (!param->have_seen_doc_type) {
        param->have_seen_doc_type = true;
        result.Append(CreateMarkup(param->document->doctype()));
      }

      // Add MOTW declaration before html tag.
      // See http://msdn2.microsoft.com/en-us/library/ms537628(VS.85).aspx.
      result.Append(
          WebFrameSerializer::GenerateMarkOfTheWebDeclaration(param->url));
    } else if (IsA<HTMLBaseElement>(*element)) {
      // Comment the BASE tag when serializing dom.
      result.Append("<!--");
    }
  } else {
    // Write XML declaration.
    if (!param->have_added_xml_processing_directive) {
      param->have_added_xml_processing_directive = true;
      // Get encoding info.
      String xml_encoding = param->document->xmlEncoding();
      if (xml_encoding.empty())
        xml_encoding = param->document->EncodingName();
      if (xml_encoding.empty())
        xml_encoding = UTF8Encoding().GetName();
      result.Append("<?xml version=\"");
      result.Append(param->document->xmlVersion());
      result.Append("\" encoding=\"");
      result.Append(xml_encoding);
      if (param->document->xmlStandalone())
        result.Append("\" standalone=\"yes");
      result.Append("\"?>\n");
    }
    // Add doc type declaration if original document has it.
    if (!param->have_seen_doc_type) {
      param->have_seen_doc_type = true;
      result.Append(CreateMarkup(param->document->doctype()));
    }
  }
  return result.ToString();
}

String WebFrameSerializerImpl::PostActionAfterSerializeOpenTag(
    const Element* element,
    SerializeDomParam* param) {
  StringBuilder result;

  param->have_added_contents_before_end = false;
  if (!param->is_html_document)
    return result.ToString();
  // Check after processing the open tag of HEAD element
  if (!param->have_added_charset_declaration &&
      IsA<HTMLHeadElement>(*element)) {
    param->have_added_charset_declaration = true;
    // Check meta element. WebKit only pre-parse the first 512 bytes of the
    // document. If the whole <HEAD> is larger and meta is the end of head
    // part, then this kind of html documents aren't decoded correctly
    // because of this issue. So when we serialize the DOM, we need to make
    // sure the meta will in first child of head tag.
    // See http://bugs.webkit.org/show_bug.cgi?id=16621.
    // First we generate new content for writing correct META element.
    result.Append(WebFrameSerializer::GenerateMetaCharsetDeclaration(
        param->text_encoding.GetName()));

    param->have_added_contents_before_end = true;
    // Will search each META which has charset declaration, and skip them all
    // in PreActionBeforeSerializeOpenTag.
  }

  return result.ToString();
}

String WebFrameSerializerImpl::PreActionBeforeSerializeEndTag(
    const Element* element,
    SerializeDomParam* param,
    bool* need_skip) {
  String result;

  *need_skip = false;
  if (!param->is_html_document)
    return result;
  // Skip the end tag of original META tag which declare charset.
  // Need not to check whether it's META tag since we guarantee
  // skipMetaElement is definitely META tag if it's not 0.
  if (param->skip_meta_element == element) {
    *need_skip = true;
  }

  return result;
}

// After we finish serializing end tag of a element, we give the target
// element a chance to do some post work to add some additional data.
String WebFrameSerializerImpl::PostActionAfterSerializeEndTag(
    const Element* element,
    SerializeDomParam* param) {
  StringBuilder result;

  if (!param->is_html_document)
    return result.ToString();
  // Comment the BASE tag when serializing DOM.
  if (IsA<HTMLBaseElement>(*element)) {
    result.Append("-->");
    // Append a new base tag declaration.
    result.Append(GenerateBaseTagDeclaration(param->document->BaseTarget()));
  }

  return result.ToString();
}

void WebFrameSerializerImpl::SaveHTMLContentToBuffer(const String& result,
                                                     SerializeDomParam* param) {
  data_buffer_.Append(result);
  EncodeAndFlushBuffer(WebFrameSerializerClient::kCurrentFrameIsNotFinished,
                       param, kDoNotForceFlush);
}

void WebFrameSerializerImpl::EncodeAndFlushBuffer(
    WebFrameSerializerClient::FrameSerializationStatus status,
    SerializeDomParam* param,
    FlushOption flush_option) {
  // Data buffer is not full nor do we want to force flush.
  if (flush_option != kForceFlush &&
      data_buffer_.length() <= kDataBufferCapacity)
    return;

  String content = data_buffer_.ToString();
  data_buffer_.Clear();

  std::string encoded_content =
      param->text_encoding.Encode(content, WTF::kEntitiesForUnencodables);

  // Send result to the client.
  client_->DidSerializeDataForFrame(
      WebVector<char>(encoded_content.c_str(), encoded_content.length()),
      status);
}

// TODO(yosin): We should utilize |MarkupFormatter| here to share code,
// especially escaping attribute values, done by |WebEntities| |m_htmlEntities|
// and |m_xmlEntities|.
void WebFrameSerializerImpl::AppendAttribute(StringBuilder& result,
                                             bool is_html_document,
                                             const String& attr_name,
                                             const String& attr_value) {
  result.Append(' ');
  result.Append(attr_name);
  result.Append("=\"");
  if (is_html_document)
    result.Append(html_entities_.ConvertEntitiesInString(attr_value));
  else
    result.Append(xml_entities_.ConvertEntitiesInString(attr_value));
  result.Append('\"');
}

void WebFrameSerializerImpl::OpenTagToString(Element* element,
                                             SerializeDomParam* param) {
  bool need_skip;
  StringBuilder result;
  // Do pre action for open tag.
  result.Append(PreActionBeforeSerializeOpenTag(element, param, &need_skip));
  if (need_skip)
    return;
  // Add open tag
  result.Append('<');
  result.Append(element->nodeName().DeprecatedLower());

  // Find out if we need to do frame-specific link rewriting.
  WebFrame* frame = nullptr;
  if (auto* frame_owner_element = DynamicTo<HTMLFrameOwnerElement>(element)) {
    frame = WebFrame::FromCoreFrame(frame_owner_element->ContentFrame());
  }
  WebString rewritten_frame_link;
  bool should_rewrite_frame_src =
      frame && delegate_->RewriteFrameSource(frame, &rewritten_frame_link);
  bool did_rewrite_frame_src = false;

  // Go through all attributes and serialize them.
  for (const auto& it : element->Attributes()) {
    const QualifiedName& attr_name = it.GetName();
    String attr_value = it.Value();

    // Skip srcdoc attribute if we will emit src attribute (for frames).
    if (should_rewrite_frame_src && attr_name == html_names::kSrcdocAttr)
      continue;

    // Rewrite the attribute value if requested.
    if (element->HasLegalLinkAttribute(attr_name)) {
      // For links start with "javascript:", we do not change it.
      if (!attr_value.StartsWithIgnoringASCIICase("javascript:")) {
        // Get the absolute link.
        KURL complete_url = param->document->CompleteURL(attr_value);

        // Check whether we have a local file to link to.
        WebString rewritten_url;
        if (should_rewrite_frame_src) {
          attr_value = rewritten_frame_link;
          did_rewrite_frame_src = true;
        } else if (delegate_->RewriteLink(complete_url, &rewritten_url)) {
          attr_value = rewritten_url;
        } else {
          attr_value = complete_url;
        }
      }
    }

    AppendAttribute(result, param->is_html_document, attr_name.ToString(),
                    attr_value);
  }

  // For frames where link rewriting was requested, ensure that src attribute
  // is written even if the original document didn't have that attribute
  // (mainly needed for iframes with srcdoc, but with no src attribute).
  if (should_rewrite_frame_src && !did_rewrite_frame_src &&
      IsA<HTMLIFrameElement>(element)) {
    AppendAttribute(result, param->is_html_document,
                    html_names::kSrcAttr.ToString(), rewritten_frame_link);
  }

  // Do post action for open tag.
  String added_contents = PostActionAfterSerializeOpenTag(element, param);
  // Complete the open tag for element when it has child/children.
  if (element->HasChildren() || param->have_added_contents_before_end ||
      element->AuthorShadowRoot()) {
    result.Append('>');
  }
  // Append the added contents generate in  post action of open tag.
  result.Append(added_contents);
  // Save the result to data buffer.
  SaveHTMLContentToBuffer(result.ToString(), param);
}

// Serialize end tag of an specified element.
void WebFrameSerializerImpl::EndTagToString(Element* element,
                                            SerializeDomParam* param) {
  bool need_skip;
  StringBuilder result;
  // Do pre action for end tag.
  result.Append(PreActionBeforeSerializeEndTag(element, param, &need_skip));
  if (need_skip)
    return;
  // Write end tag when element has child/children.
  if (element->HasChildren() || param->have_added_contents_before_end ||
      element->AuthorShadowRoot()) {
    result.Append("</");
    result.Append(element->nodeName().DeprecatedLower());
    result.Append('>');
  } else {
    // Check whether we have to write end tag for empty element.
    if (param->is_html_document) {
      result.Append('>');
      // FIXME: This code is horribly wrong.  WebFrameSerializerImpl must die.
      auto* html_element = DynamicTo<HTMLElement>(element);
      if (!html_element || html_element->ShouldSerializeEndTag()) {
        // We need to write end tag when it is required.
        result.Append("</");
        result.Append(element->nodeName().DeprecatedLower());
        result.Append('>');
      }
    } else {
      // For xml base document.
      result.Append(" />");
    }
  }
  // Do post action for end tag.
  result.Append(PostActionAfterSerializeEndTag(element, param));
  // Save the result to data buffer.
  SaveHTMLContentToBuffer(result.ToString(), param);
}

void WebFrameSerializerImpl::ShadowRootTagToString(ShadowRoot* shadow_root,
                                                   SerializeDomParam* param) {
  CHECK(!shadow_root->IsUserAgent());

  StringBuilder result;
  result.Append("<template shadowrootmode=");
  result.Append(shadow_root->IsOpen() ? "\"open\"" : "\"closed\"");

  if (shadow_root->delegatesFocus()) {
    result.Append(" shadowrootdelegatesfocus");
  }

  result.Append('>');

  SaveHTMLContentToBuffer(result.ToString(), param);
}

void WebFrameSerializerImpl::BuildContentForNode(Node* node,
                                                 SerializeDomParam* param) {
  switch (node->getNodeType()) {
    case Node::kElementNode: {
      auto* element = To<Element>(node);
      // Process open tag of element.
      OpenTagToString(element, param);

      // Process the ShadowRoot into a <template> if present.
      if (auto* shadow_root = element->AuthorShadowRoot()) {
        ShadowRootTagToString(shadow_root, param);
        for (Node* child = shadow_root->firstChild(); child;
             child = child->nextSibling()) {
          BuildContentForNode(child, param);
        }
        SaveHTMLContentToBuffer("</template>", param);
      }

      // Walk through the children nodes and process it.
      for (Node* child = element->firstChild(); child;
           child = child->nextSibling()) {
        BuildContentForNode(child, param);
      }

      // Process end tag of element.
      EndTagToString(element, param);
      break;
    }
    case Node::kTextNode:
      SaveHTMLContentToBuffer(CreateMarkup(node), param);
      break;
    case Node::kAttributeNode:
    case Node::kDocumentNode:
    case Node::kDocumentFragmentNode:
      // Should not exist.
      NOTREACHED();
    // Document type node can be in DOM?
    case Node::kDocumentTypeNode:
      param->have_seen_doc_type = true;
      [[fallthrough]];
    default:
      // For other type node, call default action.
      SaveHTMLContentToBuffer(CreateMarkup(node), param);
      break;
  }
}

WebFrameSerializerImpl::WebFrameSerializerImpl(
    WebLocalFrame* frame,
    WebFrameSerializerClient* client,
    WebFrameSerializer::LinkRewritingDelegate* delegate,
    bool save_with_empty_url)
    : client_(client),
      delegate_(delegate),
      save_with_empty_url_(save_with_empty_url),
      html_entities_(false),
      xml_entities_(true) {
  // Must specify available webframe.
  DCHECK(frame);
  specified_web_local_frame_impl_ = To<WebLocalFrameImpl>(frame);
  // Make sure we have non null client and delegate.
  DCHECK(client);
  DCHECK(delegate);

  DCHECK(data_buffer_.empty());
}

bool WebFrameSerializerImpl::Serialize() {
  bool did_serialization = false;

  Document* document =
      specified_web_local_frame_impl_->GetFrame()->GetDocument();
  const KURL& url =
      save_with_empty_url_ ? KURL("about:internet") : document->Url();

  if (url.IsValid()) {
    did_serialization = true;

    const WTF::TextEncoding& text_encoding =
        document->Encoding().IsValid() ? document->Encoding() : UTF8Encoding();
    if (text_encoding.IsNonByteBasedEncoding()) {
      const UChar kByteOrderMark = 0xFEFF;
      data_buffer_.Append(kByteOrderMark);
    }

    SerializeDomParam param(url, text_encoding, document);

    Element* document_element = document->documentElement();
    if (document_element)
      BuildContentForNode(document_element, &param);

    EncodeAndFlushBuffer(WebFrameSerializerClient::kCurrentFrameIsFinished,
                         &param, kForceFlush);
  } else {
    // Report empty contents for invalid URLs.
    client_->DidSerializeDataForFrame(
        WebVector<char>(), WebFrameSerializerClient::kCurrentFrameIsFinished);
  }

  DCHECK(data_buffer_.empty());
  return did_serialization;
}

}  // namespace blink
```