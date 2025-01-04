Response:
My thinking process to answer the request goes through these stages:

1. **Understand the Core Request:** The request asks for a summary of the functionality of `xml_document_parser.cc`, particularly its relationship to web technologies (JavaScript, HTML, CSS), logic examples (input/output), common user/programming errors, debugging clues, and a final concise summary of its function for part 1.

2. **Identify Key Areas from the Code:** I scan the included header files and the structure of the code to pinpoint the main responsibilities of this class. Key areas that jump out are:
    * **XML Parsing:**  The inclusion of `<libxml/parser.h>` and related libxml headers immediately signals that this class is responsible for parsing XML.
    * **DOM Manipulation:** The presence of headers like `core/dom/document.h`, `core/dom/element.h`, `core/dom/text.h`, etc., indicates that the parser constructs and modifies the Document Object Model (DOM) based on the parsed XML.
    * **Error Handling:**  The `XMLErrors` class and the `HandleError` function point to the parser's ability to detect and manage XML parsing errors.
    * **Namespace Handling:**  The `StartElementNs` and `EndElementNs` functions, along with related structures, suggest the parser deals with XML namespaces.
    * **Script Execution:** The `XMLParserScriptRunner` and related logic imply that the parser can handle embedded scripts within XML documents.
    * **Fragment Parsing:** The `ParseDocumentFragment` function shows it can parse XML fragments in specific contexts.
    * **External Resource Loading:** The `OpenFunc`, `ReadFunc`, `CloseFunc` functions suggest mechanisms for loading external resources referenced in the XML (like DTDs or external entities).
    * **Callbacks/Events:** The `Pending...Callback` classes hint at how parsing events are managed and potentially delayed.

3. **Relate to Web Technologies (JavaScript, HTML, CSS):** Now I connect the identified functionalities to the web technologies mentioned:
    * **JavaScript:** The `XMLParserScriptRunner` directly links to JavaScript execution within XML documents. The parser needs to handle `<script>` tags within XML (if allowed).
    * **HTML:** Although this is an *XML* parser, it's part of the Blink rendering engine, which also handles HTML. The code mentions `HTMLConstructionSite`, suggesting interaction or shared concepts with HTML parsing. The parsing of XML fragments in the context of HTML elements (like `<script>` or `<style>`) is another key link. The check for XHTML documents is relevant.
    * **CSS:** The mention of `StyleEngine` and the `HasNoStyleInformation` function suggests the parser interacts with the CSS engine, likely to determine if a document needs CSS processing. XSLT transformations (related to styling XML) are also mentioned.

4. **Construct Logic Examples (Input/Output):** Based on the identified functionalities, I create simple hypothetical input and output scenarios:
    * **Basic XML:**  A simple XML snippet and how it would be translated into a DOM structure.
    * **Namespaces:** An example demonstrating how namespace declarations in the input XML affect the resulting DOM.
    * **Errors:** An example of malformed XML and the resulting error message.
    * **Scripts:** A simple XML document with an embedded script tag and the expected execution behavior.

5. **Identify Common Errors:** I think about typical mistakes developers might make when dealing with XML:
    * **Malformed XML:** Incorrect tag nesting, missing closing tags, etc.
    * **Namespace Issues:** Incorrectly declared or used namespaces.
    * **External Resource Errors:** Problems with loading DTDs or external entities (network issues, incorrect paths, security restrictions).
    * **Encoding Problems:** Incorrect character encoding leading to parsing failures.

6. **Develop Debugging Clues:** I consider how a developer might end up inspecting this code during debugging:
    * Loading an XML document in the browser.
    * Using `XMLHttpRequest` to fetch XML data.
    * Encountering errors while parsing XML responses.
    * Inspecting the DOM structure of an XML document.
    * Investigating script execution within an XML document.

7. **Synthesize a Concise Summary for Part 1:** Finally, I condense the key functionalities into a brief summary, highlighting the core purpose of the `XMLDocumentParser`.

8. **Refine and Organize:** I review the generated points, ensuring they are clear, accurate, and address all aspects of the request. I organize the information logically into the specified categories. For instance, grouping related functionalities together improves readability.

By following these steps, I can systematically analyze the provided code snippet and generate a comprehensive and informative answer that addresses all the requirements of the prompt. The process involves understanding the code's purpose, connecting it to broader web concepts, creating concrete examples, anticipating potential problems, and finally summarizing the findings.
好的，这是对 `blink/renderer/core/xml/parser/xml_document_parser.cc` 文件功能的分析和归纳（第 1 部分）：

**功能列举：**

`XMLDocumentParser` 类在 Chromium Blink 引擎中负责解析 XML 文档和 XML 片段。其主要功能包括：

1. **XML 语法解析:**  使用 `libxml2` 库来解析 XML 文本，包括标签、属性、文本内容、注释、CDATA 区块、处理指令等。
2. **构建 DOM 树:**  根据解析的 XML 结构，逐步构建 XML 文档的 DOM (Document Object Model) 树。这包括创建 `Document`、`Element`、`Text`、`Comment` 等 DOM 节点，并将它们组织成树形结构。
3. **命名空间处理:**  正确处理 XML 命名空间，将元素和属性关联到正确的命名空间 URI。
4. **错误处理:**  检测 XML 语法错误，并生成相应的错误信息。这些错误信息可能会显示在浏览器的开发者工具中。
5. **外部实体和 DTD 处理:**  处理 XML 文档中引用的外部实体和文档类型定义 (DTD)。它会尝试加载这些外部资源，但出于安全考虑，会对加载行为进行限制（例如，同源策略）。
6. **XSLT 处理检测:**  检测 XML 文档中是否包含 XSLT 样式表的声明 (`<?xml-stylesheet type="text/xsl"?>`)，并标记 `saw_xsl_transform_` 标志。
7. **脚本处理:**  虽然是 XML 解析器，但它也需要处理嵌入在 XML 文档中的脚本（通常是 SVG 文档）。它会创建一个 `XMLParserScriptRunner` 来执行这些脚本。
8. **片段解析:**  支持解析 XML 文档片段，这些片段可以插入到现有的 DOM 树中。
9. **字符编码处理:**  处理不同字符编码的 XML 输入，例如 UTF-8 和 UTF-16。
10. **性能优化:**  使用缓冲区 (`buffered_text_`) 来暂存文本内容，并在合适的时机将其添加到 DOM 树中，以提高解析效率。
11. **暂停和恢复解析:**  支持暂停和恢复 XML 解析过程，这在处理包含脚本的文档时可能用到。
12. **与渲染引擎集成:**  它是 Blink 渲染引擎的一部分，其解析结果直接用于渲染页面的内容。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **JavaScript:**
    * **嵌入式脚本:**  如果 XML 文档（例如 SVG）中包含 `<script>` 标签，`XMLDocumentParser` 会负责识别这些脚本块，并交由 `XMLParserScriptRunner` 来执行。
        * **假设输入:** 一个包含以下内容的 SVG 文件：
          ```xml
          <svg>
            <script type="text/javascript">
              alert("Hello from SVG!");
            </script>
          </svg>
          ```
        * **输出:**  `XMLDocumentParser` 会解析 `<script>` 标签，`XMLParserScriptRunner` 会执行其中的 JavaScript 代码，导致浏览器显示一个 "Hello from SVG!" 的警告框。
    * **通过 JavaScript 操作 XML DOM:**  一旦 XML 文档被 `XMLDocumentParser` 解析完成，JavaScript 代码可以通过 DOM API (例如 `document.querySelector`, `element.textContent`) 来访问和操作 XML 文档的结构和内容。
* **HTML:**
    * **解析 XHTML:**  `XMLDocumentParser` 可以解析符合 XML 规范的 HTML 文档（XHTML）。虽然现代浏览器主要使用 HTML 解析器来解析 HTML，但在某些情况下，例如解析通过 `application/xhtml+xml` MIME 类型提供的文档，会使用 XML 解析器。
        * **假设输入:** 一个以 `application/xhtml+xml` 提供的简单 XHTML 文档：
          ```xml
          <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
          <html xmlns="http://www.w3.org/1999/xhtml">
          <head>
            <title>XHTML Example</title>
          </head>
          <body>
            <p>This is an XHTML document.</p>
          </body>
          </html>
          ```
        * **输出:** `XMLDocumentParser` 会解析该文档，构建一个标准的 XML DOM 树，其中包含 `html`、`head`、`title`、`body`、`p` 等元素。
    * **解析 HTML 片段（特殊情况）:**  在极少数情况下，`ParseDocumentFragment` 方法会被用于解析 HTML 片段，特别是当上下文元素是 `<script>` 或 `<style>` 时，这是一种特殊的处理方式。
* **CSS:**
    * **检测 XSLT 样式表:**  `XMLDocumentParser` 会检测 XML 文档中通过处理指令声明的 XSLT 样式表。
    * **判断是否需要样式信息:** `HasNoStyleInformation` 函数会检查文档是否可能包含样式信息（例如，是否看到已知命名空间的元素，或者是否关联了 XSLT 转换）。这有助于优化渲染过程。

**逻辑推理的假设输入与输出：**

* **假设输入:**  以下 XML 片段：
  ```xml
  <root>
    <item id="1">Value 1</item>
    <item id="2">Value 2</item>
  </root>
  ```
* **逻辑推理:** `XMLDocumentParser` 会逐个解析标签和文本内容，并创建相应的 DOM 节点。
* **输出:**  将会构建一个包含 `root` 元素，以及两个 `item` 子元素的 DOM 树。每个 `item` 元素都有一个 `id` 属性，并且包含相应的文本内容。

**用户或编程常见的使用错误及举例说明：**

1. **XML 格式错误:**  用户提供了格式不正确的 XML 数据。
    * **例子:** 缺少闭合标签，例如 `<item>` 没有 `</item>`。
    * **错误信息:** `XMLDocumentParser` 会产生类似 "Tag mismatch" 的错误信息。
2. **命名空间错误:**  错误地使用了 XML 命名空间。
    * **例子:**  使用了未声明的命名空间前缀。
    * **错误信息:** `XMLDocumentParser` 可能会报告 "Namespace prefix is not defined" 的错误。
3. **尝试加载被阻止的外部资源:**  XML 文档引用了由于安全策略（例如跨域）而被阻止加载的外部实体或 DTD。
    * **例子:**  引用了一个位于不同域名的 DTD 文件。
    * **结果:**  `XMLDocumentParser` 会阻止加载该资源，并可能在控制台输出安全相关的错误信息。
4. **字符编码问题:**  XML 文档的字符编码声明与实际编码不符。
    * **例子:**  XML 声明是 `<?xml version="1.0" encoding="UTF-8"?>`，但实际文件是 Latin-1 编码。
    * **结果:**  `XMLDocumentParser` 可能会解析出乱码，或者报告编码错误。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户在浏览器中打开一个 XML 文件:**  浏览器会根据文件的 MIME 类型 (`application/xml` 或 `text/xml`) 决定使用 `XMLDocumentParser` 来解析该文件。
2. **网页通过 XMLHttpRequest 或 Fetch API 请求 XML 数据:**  当 JavaScript 代码发起对 XML 数据的请求时，浏览器接收到响应后，会创建 `XMLDocumentParser` 来解析响应体中的 XML 内容。
3. **SVG 图像加载:** 当浏览器加载一个 SVG 图像时，会使用 `XMLDocumentParser` 来解析 SVG 文件的 XML 结构。
4. **解析内联 SVG 或 MathML:**  在 HTML 文档中嵌入的 `<svg>` 或 `<math>` 标签内的内容也会由 `XMLDocumentParser` 解析。
5. **开发者工具检查 XML 内容:**  在浏览器的开发者工具中查看 "网络" 或 "元素" 面板时，如果看到 XML 内容，很可能这些内容就是通过 `XMLDocumentParser` 解析的。
6. **遇到 XML 解析错误:**  当网页显示不正常或开发者工具中出现 XML 解析错误信息时，开发者可能会深入研究 `XMLDocumentParser` 的代码来定位问题。

**本部分功能归纳：**

`XMLDocumentParser` 的主要功能是作为 Chromium Blink 引擎中解析 XML 文档和片段的核心组件。它利用 `libxml2` 库将 XML 文本转换为浏览器可以理解和操作的 DOM 树结构，并处理命名空间、错误、外部资源以及嵌入式脚本等关键方面。它在加载 XML 文件、处理 AJAX 请求返回的 XML 数据以及渲染 SVG 等场景中发挥着至关重要的作用。

请期待第 2 部分和第 3 部分的更深入分析。

Prompt: 
```
这是目录为blink/renderer/core/xml/parser/xml_document_parser.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2000 Peter Kelly (pmk@post.com)
 * Copyright (C) 2005, 2006, 2008, 2014 Apple Inc. All rights reserved.
 * Copyright (C) 2006 Alexey Proskuryakov (ap@webkit.org)
 * Copyright (C) 2007 Samuel Weinig (sam@webkit.org)
 * Copyright (C) 2008 Nokia Corporation and/or its subsidiary(-ies)
 * Copyright (C) 2008 Holger Hans Peter Freyther
 * Copyright (C) 2008 Torch Mobile Inc. All rights reserved.
 * (http://www.torchmobile.com/)
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

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/xml/parser/xml_document_parser.h"

#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/xmlversion.h>
#include <libxslt/xslt.h>

#include <algorithm>
#include <memory>

#include "base/auto_reset.h"
#include "base/numerics/safe_conversions.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/cdata_section.h"
#include "third_party/blink/renderer/core/dom/comment.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/document_parser_timing.h"
#include "third_party/blink/renderer/core/dom/document_type.h"
#include "third_party/blink/renderer/core/dom/processing_instruction.h"
#include "third_party/blink/renderer/core/dom/throw_on_dynamic_markup_insertion_count_incrementer.h"
#include "third_party/blink/renderer/core/dom/transform_source.h"
#include "third_party/blink/renderer/core/dom/xml_document.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/custom/ce_reactions_scope.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/html/html_template_element.h"
#include "third_party/blink/renderer/core/html/parser/html_construction_site.h"
#include "third_party/blink/renderer/core/html/parser/html_entity_parser.h"
#include "third_party/blink/renderer/core/html/parser/text_resource_decoder.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/core/loader/image_loader.h"
#include "third_party/blink/renderer/core/svg/graphics/svg_image.h"
#include "third_party/blink/renderer/core/xml/document_xml_tree_viewer.h"
#include "third_party/blink/renderer/core/xml/document_xslt.h"
#include "third_party/blink/renderer/core/xml/parser/shared_buffer_reader.h"
#include "third_party/blink/renderer/core/xml/parser/xml_document_parser_scope.h"
#include "third_party/blink/renderer/core/xml/parser/xml_parser_input.h"
#include "third_party/blink/renderer/core/xmlns_names.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/allowed_by_nosniff.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_type_names.h"
#include "third_party/blink/renderer/platform/loader/fetch/raw_resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_error.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/utf8.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"

namespace blink {

// FIXME: HTMLConstructionSite has a limit of 512, should these match?
static const unsigned kMaxXMLTreeDepth = 5000;

static inline String ToString(const xmlChar* string, size_t length) {
  return String::FromUTF8(base::span(string, length));
}

static inline String ToString(const xmlChar* string) {
  return String::FromUTF8(reinterpret_cast<const char*>(string));
}

static inline AtomicString ToAtomicString(const xmlChar* string,
                                          size_t length) {
  return AtomicString::FromUTF8(base::span(string, length));
}

static inline AtomicString ToAtomicString(const xmlChar* string) {
  return AtomicString::FromUTF8(reinterpret_cast<const char*>(string));
}

static inline bool HasNoStyleInformation(Document* document) {
  if (document->SawElementsInKnownNamespaces() ||
      DocumentXSLT::HasTransformSourceDocument(*document))
    return false;

  if (!document->GetFrame() || !document->GetFrame()->GetPage())
    return false;

  if (!document->IsInMainFrame() || document->GetFrame()->IsInFencedFrameTree())
    return false;  // This document has style information from a parent.

  if (SVGImage::IsInSVGImage(document))
    return false;

  return true;
}

class PendingStartElementNSCallback final
    : public XMLDocumentParser::PendingCallback {
 public:
  PendingStartElementNSCallback(const AtomicString& local_name,
                                const AtomicString& prefix,
                                const AtomicString& uri,
                                int namespace_count,
                                const xmlChar** namespaces,
                                int attribute_count,
                                int defaulted_count,
                                const xmlChar** attributes,
                                TextPosition text_position)
      : PendingCallback(text_position),
        local_name_(local_name),
        prefix_(prefix),
        uri_(uri),
        namespace_count_(namespace_count),
        attribute_count_(attribute_count),
        defaulted_count_(defaulted_count) {
    namespaces_ = static_cast<xmlChar**>(
        xmlMalloc(sizeof(xmlChar*) * namespace_count * 2));
    for (int i = 0; i < namespace_count * 2; ++i)
      namespaces_[i] = xmlStrdup(namespaces[i]);
    attributes_ = static_cast<xmlChar**>(
        xmlMalloc(sizeof(xmlChar*) * attribute_count * 5));
    for (int i = 0; i < attribute_count; ++i) {
      // Each attribute has 5 elements in the array:
      // name, prefix, uri, value and an end pointer.
      for (int j = 0; j < 3; ++j)
        attributes_[i * 5 + j] = xmlStrdup(attributes[i * 5 + j]);
      int length =
          static_cast<int>(attributes[i * 5 + 4] - attributes[i * 5 + 3]);
      attributes_[i * 5 + 3] = xmlStrndup(attributes[i * 5 + 3], length);
      attributes_[i * 5 + 4] = attributes_[i * 5 + 3] + length;
    }
  }

  ~PendingStartElementNSCallback() override {
    for (int i = 0; i < namespace_count_ * 2; ++i)
      xmlFree(namespaces_[i]);
    xmlFree(namespaces_);
    for (int i = 0; i < attribute_count_; ++i)
      for (int j = 0; j < 4; ++j)
        xmlFree(attributes_[i * 5 + j]);
    xmlFree(attributes_);
  }

  void Call(XMLDocumentParser* parser) override {
    parser->StartElementNs(local_name_, prefix_, uri_, namespace_count_,
                           const_cast<const xmlChar**>(namespaces_),
                           attribute_count_, defaulted_count_,
                           const_cast<const xmlChar**>(attributes_));
  }

 private:
  AtomicString local_name_;
  AtomicString prefix_;
  AtomicString uri_;
  int namespace_count_;
  xmlChar** namespaces_;
  int attribute_count_;
  int defaulted_count_;
  xmlChar** attributes_;
};

class PendingEndElementNSCallback final
    : public XMLDocumentParser::PendingCallback {
 public:
  explicit PendingEndElementNSCallback(TextPosition script_start_position,
                                       TextPosition text_position)
      : PendingCallback(text_position),
        script_start_position_(script_start_position) {}

  void Call(XMLDocumentParser* parser) override {
    parser->SetScriptStartPosition(script_start_position_);
    parser->EndElementNs();
  }

 private:
  TextPosition script_start_position_;
};

class PendingCharactersCallback final
    : public XMLDocumentParser::PendingCallback {
 public:
  PendingCharactersCallback(const xmlChar* chars,
                            int length,
                            TextPosition text_position)
      : PendingCallback(text_position),
        chars_(xmlStrndup(chars, length)),
        length_(length) {}

  ~PendingCharactersCallback() override { xmlFree(chars_); }

  void Call(XMLDocumentParser* parser) override {
    parser->Characters(chars_, length_);
  }

 private:
  xmlChar* chars_;
  int length_;
};

class PendingProcessingInstructionCallback final
    : public XMLDocumentParser::PendingCallback {
 public:
  PendingProcessingInstructionCallback(const String& target,
                                       const String& data,
                                       TextPosition text_position)
      : PendingCallback(text_position), target_(target), data_(data) {}

  void Call(XMLDocumentParser* parser) override {
    parser->GetProcessingInstruction(target_, data_);
  }

 private:
  String target_;
  String data_;
};

class PendingCDATABlockCallback final
    : public XMLDocumentParser::PendingCallback {
 public:
  explicit PendingCDATABlockCallback(const String& text,
                                     TextPosition text_position)
      : PendingCallback(text_position), text_(text) {}

  void Call(XMLDocumentParser* parser) override { parser->CdataBlock(text_); }

 private:
  String text_;
};

class PendingCommentCallback final : public XMLDocumentParser::PendingCallback {
 public:
  explicit PendingCommentCallback(const String& text,
                                  TextPosition text_position)
      : PendingCallback(text_position), text_(text) {}

  void Call(XMLDocumentParser* parser) override { parser->Comment(text_); }

 private:
  String text_;
};

class PendingInternalSubsetCallback final
    : public XMLDocumentParser::PendingCallback {
 public:
  PendingInternalSubsetCallback(const String& name,
                                const String& external_id,
                                const String& system_id,
                                TextPosition text_position)
      : PendingCallback(text_position),
        name_(name),
        external_id_(external_id),
        system_id_(system_id) {}

  void Call(XMLDocumentParser* parser) override {
    parser->InternalSubset(name_, external_id_, system_id_);
  }

 private:
  String name_;
  String external_id_;
  String system_id_;
};

class PendingErrorCallback final : public XMLDocumentParser::PendingCallback {
 public:
  PendingErrorCallback(XMLErrors::ErrorType type,
                       const xmlChar* message,
                       TextPosition text_position)
      : PendingCallback(text_position),
        type_(type),
        message_(xmlStrdup(message)) {}

  ~PendingErrorCallback() override { xmlFree(message_); }

  void Call(XMLDocumentParser* parser) override {
    parser->HandleError(type_, reinterpret_cast<char*>(message_),
                        GetTextPosition());
  }

 private:
  XMLErrors::ErrorType type_;
  xmlChar* message_;
};

void XMLDocumentParser::PushCurrentNode(ContainerNode* n) {
  DCHECK(n);
  DCHECK(current_node_);
  current_node_stack_.push_back(current_node_);
  current_node_ = n;
  if (current_node_stack_.size() > kMaxXMLTreeDepth)
    HandleError(XMLErrors::kErrorTypeFatal, "Excessive node nesting.",
                GetTextPosition());
}

void XMLDocumentParser::PopCurrentNode() {
  if (!current_node_)
    return;
  DCHECK(current_node_stack_.size());
  current_node_ = current_node_stack_.back();
  current_node_stack_.pop_back();
}

void XMLDocumentParser::ClearCurrentNodeStack() {
  current_node_ = nullptr;
  leaf_text_node_ = nullptr;

  if (current_node_stack_.size()) {  // Aborted parsing.
    current_node_stack_.clear();
  }
}

void XMLDocumentParser::Append(const String& input_source) {
  const SegmentedString source(input_source);
  if (saw_xsl_transform_ || !saw_first_element_)
    original_source_for_transform_.Append(source);

  if (IsStopped() || saw_xsl_transform_)
    return;

  if (parser_paused_) {
    pending_src_.Append(source);
    return;
  }

  DoWrite(source.ToString());
}

void XMLDocumentParser::HandleError(XMLErrors::ErrorType type,
                                    const char* formatted_message,
                                    TextPosition position) {
  xml_errors_.HandleError(type, formatted_message, position);
  if (type != XMLErrors::kErrorTypeWarning)
    saw_error_ = true;
  if (type == XMLErrors::kErrorTypeFatal)
    StopParsing();
}

void XMLDocumentParser::CreateLeafTextNodeIfNeeded() {
  is_start_of_new_chunk_ = false;
  if (leaf_text_node_)
    return;

  DCHECK_EQ(buffered_text_.size(), 0u);
  leaf_text_node_ = Text::Create(current_node_->GetDocument(), "");
  current_node_->ParserAppendChild(leaf_text_node_.Get());
}

bool XMLDocumentParser::UpdateLeafTextNode() {
  if (IsStopped())
    return false;

  is_start_of_new_chunk_ = false;
  if (!leaf_text_node_)
    return true;

  leaf_text_node_->ParserAppendData(
      ToString(buffered_text_.data(), buffered_text_.size()));
  buffered_text_.clear();
  leaf_text_node_ = nullptr;

  // Mutation event handlers executed by appendData() might detach this parser.
  return !IsStopped();
}

void XMLDocumentParser::Detach() {
  if (script_runner_)
    script_runner_->Detach();
  script_runner_ = nullptr;

  ClearCurrentNodeStack();
  ScriptableDocumentParser::Detach();
}

void XMLDocumentParser::end() {
  TRACE_EVENT0("blink", "XMLDocumentParser::end");
  // XMLDocumentParserLibxml2 will do bad things to the document if doEnd() is
  // called.  I don't believe XMLDocumentParserQt needs doEnd called in the
  // fragment case.
  DCHECK(!parsing_fragment_);

  DoEnd();

  // doEnd() call above can detach the parser and null out its document.
  // In that case, we just bail out.
  if (IsDetached())
    return;

  // doEnd() could process a script tag, thus pausing parsing.
  if (parser_paused_)
    return;

  // StopParsing() calls InsertErrorMessageBlock() if there was a parsing
  // error. Avoid showing the error message block twice.
  // TODO(crbug.com/898775): Rationalize this.
  if (saw_error_ && !IsStopped()) {
    InsertErrorMessageBlock();
    // InsertErrorMessageBlock() may detach the document
    if (IsDetached())
      return;
  } else {
    UpdateLeafTextNode();
  }

  if (IsParsing())
    PrepareToStopParsing();
  GetDocument()->SetReadyState(Document::kInteractive);
  ClearCurrentNodeStack();
  GetDocument()->FinishedParsing();
}

void XMLDocumentParser::Finish() {
  // FIXME: We should DCHECK(!m_parserStopped) here, since it does not
  // makes sense to call any methods on DocumentParser once it's been stopped.
  // However, FrameLoader::stop calls DocumentParser::finish unconditionally.

  Flush();
  if (IsDetached())
    return;

  if (parser_paused_)
    finish_called_ = true;
  else
    end();
}

void XMLDocumentParser::InsertErrorMessageBlock() {
  xml_errors_.InsertErrorMessageBlock();
}

bool XMLDocumentParser::IsWaitingForScripts() const {
  return script_runner_ && script_runner_->HasParserBlockingScript();
}

void XMLDocumentParser::PauseParsing() {
  if (!parsing_fragment_)
    parser_paused_ = true;
}

bool XMLDocumentParser::ParseDocumentFragment(
    const String& chunk,
    DocumentFragment* fragment,
    Element* context_element,
    ParserContentPolicy parser_content_policy,
    ExceptionState& exception_state) {
  if (!chunk.length())
    return true;

  // FIXME: We need to implement the HTML5 XML Fragment parsing algorithm:
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/the-xhtml-syntax.html#xml-fragment-parsing-algorithm
  // For now we have a hack for script/style innerHTML support:
  if (context_element &&
      (context_element->HasLocalName(html_names::kScriptTag.LocalName()) ||
       context_element->HasLocalName(html_names::kStyleTag.LocalName()))) {
    fragment->ParserAppendChild(fragment->GetDocument().createTextNode(chunk));
    return true;
  }

  TryRethrowScope rethrow_scope(fragment->GetDocument().GetAgent().isolate(),
                                exception_state);
  auto* parser = MakeGarbageCollected<XMLDocumentParser>(
      fragment, context_element, parser_content_policy);
  bool well_formed = parser->AppendFragmentSource(chunk);

  // Do not call finish(). Current finish() and doEnd() implementations touch
  // the main Document/loader and can cause crashes in the fragment case.

  // Allows ~DocumentParser to assert it was detached before destruction.
  parser->Detach();
  // appendFragmentSource()'s wellFormed is more permissive than wellFormed().
  return well_formed;
}

static int g_global_descriptor = 0;

static int MatchFunc(const char*) {
  // Any use of libxml in the renderer process must:
  //
  // - have a XMLDocumentParserScope on the stack so the various callbacks know
  //   which blink::Document they are interacting with.
  // - only occur on the main thread, since the current document is not stored
  //   in a TLS variable.
  //
  // These conditionals are enforced by a CHECK() rather than being used to
  // calculate the return value since this allows XML parsing to fail safe in
  // case these preconditions are violated.
  CHECK(XMLDocumentParserScope::current_document_ && IsMainThread());
  // Tell libxml to always use Blink's set of input callbacks.
  return 1;
}

static inline void SetAttributes(
    Element* element,
    Vector<Attribute, kAttributePrealloc>& attribute_vector,
    ParserContentPolicy parser_content_policy) {
  if (!ScriptingContentIsAllowed(parser_content_policy))
    element->StripScriptingAttributes(attribute_vector);
  element->ParserSetAttributes(attribute_vector);
}

static void SwitchEncoding(xmlParserCtxtPtr ctxt, bool is_8bit) {
  // Make sure we don't call xmlSwitchEncoding in an error state.
  if (ctxt->errNo != XML_ERR_OK) {
    return;
  }

  if (is_8bit) {
    xmlSwitchEncoding(ctxt, XML_CHAR_ENCODING_8859_1);
    return;
  }

  const UChar kBOM = 0xFEFF;
  const unsigned char bom_high_byte =
      *reinterpret_cast<const unsigned char*>(&kBOM);
  xmlSwitchEncoding(ctxt, bom_high_byte == 0xFF ? XML_CHAR_ENCODING_UTF16LE
                                                : XML_CHAR_ENCODING_UTF16BE);
}

static void ParseChunk(xmlParserCtxtPtr ctxt, const String& chunk) {
  bool is_8bit = chunk.Is8Bit();
  // Reset the encoding for each chunk to reflect if it is Latin-1 or UTF-16.
  SwitchEncoding(ctxt, is_8bit);
  if (is_8bit)
    xmlParseChunk(ctxt, reinterpret_cast<const char*>(chunk.Characters8()),
                  sizeof(LChar) * chunk.length(), 0);
  else
    xmlParseChunk(ctxt, reinterpret_cast<const char*>(chunk.Characters16()),
                  sizeof(UChar) * chunk.length(), 0);
}

static void FinishParsing(xmlParserCtxtPtr ctxt) {
  xmlParseChunk(ctxt, nullptr, 0, 1);
}

#define xmlParseChunk \
#error "Use parseChunk instead to select the correct encoding."

static bool IsLibxmlDefaultCatalogFile(const String& url_string) {
  // On non-Windows platforms libxml with catalogs enabled asks for
  // this URL, the "XML_XML_DEFAULT_CATALOG", on initialization.
  if (url_string == "file:///etc/xml/catalog")
    return true;

  // On Windows, libxml with catalogs enabled computes a URL relative
  // to where its DLL resides.
  if (url_string.StartsWithIgnoringASCIICase("file:///") &&
      url_string.EndsWithIgnoringASCIICase("/etc/catalog"))
    return true;
  return false;
}

static bool ShouldAllowExternalLoad(const KURL& url) {
  String url_string = url.GetString();

  // libxml should not be configured with catalogs enabled, so it
  // should not be asking to load default catalogs.
  CHECK(!IsLibxmlDefaultCatalogFile(url));

  // The most common DTD. There isn't much point in hammering www.w3c.org by
  // requesting this URL for every XHTML document.
  if (url_string.StartsWithIgnoringASCIICase("http://www.w3.org/TR/xhtml"))
    return false;

  // Similarly, there isn't much point in requesting the SVG DTD.
  if (url_string.StartsWithIgnoringASCIICase("http://www.w3.org/Graphics/SVG"))
    return false;

  // The libxml doesn't give us a lot of context for deciding whether to allow
  // this request. In the worst case, this load could be for an external
  // entity and the resulting document could simply read the retrieved
  // content. If we had more context, we could potentially allow the parser to
  // load a DTD. As things stand, we take the conservative route and allow
  // same-origin requests only.
  auto* current_context =
      XMLDocumentParserScope::current_document_->GetExecutionContext();
  if (!current_context->GetSecurityOrigin()->CanRequest(url)) {
    // FIXME: This is copy/pasted. We should probably build console logging into
    // canRequest().
    if (!url.IsNull()) {
      String message = "Unsafe attempt to load URL " + url.ElidedString() +
                       " from frame with URL " +
                       current_context->Url().ElidedString() +
                       ". Domains, protocols and ports must match.\n";
      current_context->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          mojom::blink::ConsoleMessageSource::kSecurity,
          mojom::blink::ConsoleMessageLevel::kError, message));
    }
    return false;
  }

  return true;
}

static void* OpenFunc(const char* uri) {
  Document* document = XMLDocumentParserScope::current_document_;
  DCHECK(document);
  CHECK(IsMainThread());

  KURL url(NullURL(), uri);

  // If the document has no ExecutionContext, it's detached. Detached documents
  // aren't allowed to fetch.
  if (!document->GetExecutionContext())
    return &g_global_descriptor;

  if (!ShouldAllowExternalLoad(url))
    return &g_global_descriptor;

  KURL final_url;
  scoped_refptr<const SharedBuffer> data;

  {
    XMLDocumentParserScope scope(nullptr);
    // FIXME: We should restore the original global error handler as well.
    ResourceLoaderOptions options(
        document->GetExecutionContext()->GetCurrentWorld());
    options.initiator_info.name = fetch_initiator_type_names::kXml;
    FetchParameters params(ResourceRequest(url), options);
    params.MutableResourceRequest().SetMode(
        network::mojom::RequestMode::kSameOrigin);
    Resource* resource =
        RawResource::FetchSynchronously(params, document->Fetcher());

    if (!AllowedByNosniff::MimeTypeAsXMLExternalEntity(
            document->GetExecutionContext(), resource->GetResponse())) {
      return &g_global_descriptor;
    }

    if (!resource->ErrorOccurred()) {
      data = resource->ResourceBuffer();
      final_url = resource->GetResponse().CurrentRequestUrl();
    }
  }

  // We have to check the URL again after the load to catch redirects.
  // See <https://bugs.webkit.org/show_bug.cgi?id=21963>.
  if (!ShouldAllowExternalLoad(final_url))
    return &g_global_descriptor;

  UseCounter::Count(XMLDocumentParserScope::current_document_,
                    WebFeature::kXMLExternalResourceLoad);

  return new SharedBufferReader(data);
}

static int ReadFunc(void* context, char* buffer, int len) {
  // Do 0-byte reads in case of a null descriptor
  if (context == &g_global_descriptor)
    return 0;

  SharedBufferReader* data = static_cast<SharedBufferReader*>(context);
  auto buffer_span = base::span(buffer, base::checked_cast<size_t>(len));
  return base::checked_cast<int>(data->ReadData(buffer_span));
}

static int WriteFunc(void*, const char*, int) {
  // Always just do 0-byte writes
  return 0;
}

static int CloseFunc(void* context) {
  if (context != &g_global_descriptor) {
    SharedBufferReader* data = static_cast<SharedBufferReader*>(context);
    delete data;
  }
  return 0;
}

static void ErrorFunc(void*, const char*, ...) {
  // FIXME: It would be nice to display error messages somewhere.
}

static void InitializeLibXMLIfNecessary() {
  static bool did_init = false;
  if (did_init)
    return;

  xmlInitParser();
  xmlRegisterInputCallbacks(MatchFunc, OpenFunc, ReadFunc, CloseFunc);
  xmlRegisterOutputCallbacks(MatchFunc, OpenFunc, WriteFunc, CloseFunc);
  did_init = true;
}

scoped_refptr<XMLParserContext> XMLParserContext::CreateStringParser(
    xmlSAXHandlerPtr handlers,
    void* user_data) {
  InitializeLibXMLIfNecessary();
  xmlParserCtxtPtr parser =
      xmlCreatePushParserCtxt(handlers, nullptr, nullptr, 0, nullptr);
  xmlCtxtUseOptions(parser, XML_PARSE_HUGE | XML_PARSE_NOENT);
  parser->_private = user_data;
  return base::AdoptRef(new XMLParserContext(parser));
}

// Chunk should be encoded in UTF-8
scoped_refptr<XMLParserContext> XMLParserContext::CreateMemoryParser(
    xmlSAXHandlerPtr handlers,
    void* user_data,
    const std::string& chunk) {
  InitializeLibXMLIfNecessary();

  // appendFragmentSource() checks that the length doesn't overflow an int.
  xmlParserCtxtPtr parser = xmlCreateMemoryParserCtxt(
      chunk.c_str(), base::checked_cast<int>(chunk.length()));

  if (!parser)
    return nullptr;

  // Copy the sax handler
  memcpy(parser->sax, handlers, sizeof(xmlSAXHandler));

  // Set parser options.
  // XML_PARSE_NODICT: default dictionary option.
  // XML_PARSE_NOENT: force entities substitutions.
  // XML_PARSE_HUGE: don't impose arbitrary limits on document size.
  xmlCtxtUseOptions(parser,
                    XML_PARSE_NODICT | XML_PARSE_NOENT | XML_PARSE_HUGE);

#if LIBXML_VERSION < 21300
  // Internal initialization required before libxml2 2.13.
  // Fixed with https://gitlab.gnome.org/GNOME/libxml2/-/commit/8c5848bd
  parser->sax2 = 1;
  parser->instate = XML_PARSER_CONTENT;  // We are parsing a CONTENT
  parser->depth = 0;
  parser->str_xml = xmlDictLookup(parser->dict, BAD_CAST "xml", 3);
  parser->str_xmlns = xmlDictLookup(parser->dict, BAD_CAST "xmlns", 5);
  parser->str_xml_ns = xmlDictLookup(parser->dict, XML_XML_NAMESPACE, 36);
#endif
  parser->_private = user_data;

  return base::AdoptRef(new XMLParserContext(parser));
}

// --------------------------------

bool XMLDocumentParser::SupportsXMLVersion(const String& version) {
  return version == "1.0";
}

XMLDocumentParser::XMLDocumentParser(Document& document,
                                     LocalFrameView* frame_view)
    : ScriptableDocumentParser(document),
      context_(nullptr),
      current_node_(&document),
      is_currently_parsing8_bit_chunk_(false),
      saw_error_(false),
      saw_css_(false),
      saw_xsl_transform_(false),
      saw_first_element_(false),
      is_xhtml_document_(false),
      parser_paused_(false),
      requesting_script_(false),
      finish_called_(false),
      xml_errors_(&document),
      document_(&document),
      script_runner_(frame_view
                         ? MakeGarbageCollected<XMLParserScriptRunner>(this)
                         : nullptr),  // Don't execute scripts for
                                      // documents without frames.
      script_start_position_(TextPosition::BelowRangePosition()),
      parsing_fragment_(false) {
  // This is XML being used as a document resource.
  if (frame_view && IsA<XMLDocument>(document))
    UseCounter::Count(document, WebFeature::kXMLDocument);
}

XMLDocumentParser::XMLDocumentParser(DocumentFragment* fragment,
                                     Element* parent_element,
                                     ParserContentPolicy parser_content_policy)
    : ScriptableDocumentParser(fragment->GetDocument(), parser_content_policy),
      context_(nullptr),
      current_node_(fragment),
      is_currently_parsing8_bit_chunk_(false),
      saw_error_(false),
      saw_css_(false),
      saw_xsl_transform_(false),
      saw_first_element_(false),
      is_xhtml_document_(false),
      parser_paused_(false),
      requesting_script_(false),
      finish_called_(false),
      xml_errors_(&fragment->GetDocument()),
      document_(&fragment->GetDocument()),
      script_runner_(nullptr),  // Don't execute scripts for document fragments.
      script_start_position_(TextPosition::BelowRangePosition()),
      parsing_fragment_(true) {
  // Step 2 of
  // https://html.spec.whatwg.org/C/#xml-fragment-parsing-algorithm
  // The following code collects prefix-namespace mapping in scope on
  // |parent_element|.
  HeapVector<Member<Element>> elem_stack;
  for (; parent_element; parent_element = parent_element->parentElement())
    elem_stack.push_back(parent_element);

  if (elem_stack.empty())
    return;

  for (; !elem_stack.empty(); elem_stack.pop_back()) {
    Element* element = elem_stack.back();
    // According to https://dom.spec.whatwg.org/#locate-a-namespace, a namespace
    // from the element name should have higher priority. So we check xmlns
    // attributes first, then overwrite the map with the namespace of the
    // element name.
    AttributeCollection attributes = element->Attributes();
    for (auto& attribute : attributes) {
      if (attribute.LocalName() == g_xmlns_atom)
        default_namespace_uri_ = attribute.Value();
      else if (attribute.Prefix() == g_xmlns_atom)
        prefix_to_namespace_map_.Set(attribute.LocalName(), attribute.Value());
    }
    if (element->namespaceURI().IsNull())
      continue;
    if (element->prefix().empty())
      default_namespace_uri_ = element->namespaceURI();
    else
      prefix_to_namespace_map_.Set(element->prefix(), element->namespaceURI());
  }
}

XMLParserContext::~XMLParserContext() {
  if (context_->myDoc)
    xmlFreeDoc(context_->myDoc);
  xmlFreeParserCtxt(context_);
}

XMLDocumentParser::~XMLDocumentParser() = default;

void XMLDocumentParser::Trace(Visitor* visitor) const {
  visitor->Trace(current_node_);
  visitor->Trace(current_node_stack_);
  visitor->Trace(leaf_text_node_);
  visitor->Trace(xml_errors_);
  visitor->Trace(document_);
  visitor->Trace(script_runner_);
  ScriptableDocumentParser::Trace(visitor);
  XMLParserScriptRunnerHost::Trace(visitor);
}

void XMLDocumentParser::DoWrite(const String& parse_string) {
  TRACE_EVENT0("blink", "XMLDocumentParser::doWrite");
  DCHECK(!IsDetached());
  if (!context_)
    InitializeParserContext();

  // Protect the libxml context from deletion during a callback
  scoped_refptr<XMLParserContext> context = context_;

  // libXML throws an error if you try to switch the encoding for an empty
  // string.
  if (parse_string.length()) {
    XMLDocumentParserScope scope(GetDocument());
    base::AutoReset<bool> encoding_scope(&is_currently_parsing8_bit_chunk_,
                                         parse_string.Is8Bit());
    is_start_of_new_chunk_ = true;
    ParseChunk(context->Context(), parse_string);

    // JavaScript (which may be run under the parseChunk callstack) may
    // cause the parser to be stopped or detached.
    if (IsStopped())
      return;
  }

  // FIXME: Why is this here? And why is it after we process the passed
  // source?
  if (GetDocument()->SawDecodingError()) {
    // If the decoder saw an error, report it as fatal (stops parsing)
    TextPosition position(
        OrdinalNumber::FromOneBasedInt(context->Context()->input->line),
        OrdinalNumber::FromOneBasedInt(context->Context()->input->col));
    HandleError(XMLErrors::kErrorTypeFatal, "Encoding error", position);
  }
}

struct xmlSAX2Namespace {
  const xmlChar* prefix;
  const xmlChar* uri;
};

static inline bool HandleNamespaceAttribu
"""


```