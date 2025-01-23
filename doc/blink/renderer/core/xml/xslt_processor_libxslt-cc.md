Response:
Let's break down the thought process for analyzing this `xslt_processor_libxslt.cc` file.

**1. Initial Understanding and Core Function:**

* **File Path:** `blink/renderer/core/xml/xslt_processor_libxslt.cc` immediately suggests this file is responsible for handling XSLT processing within the Blink rendering engine. The `libxslt` suffix points to the underlying library used.
* **Copyright and License:** The header information confirms this is related to XSLT implementation and uses the GNU Library General Public License. This isn't directly related to functionality but tells us about the software's licensing.
* **Includes:** The `#include` directives are crucial. They reveal the dependencies and give strong clues about the file's purpose. Notice includes like:
    * `xslt_processor.h`:  Likely the header for the `XSLTProcessor` class.
    * `<libxslt/...>`:  Direct usage of the `libxslt` library.
    * `core/dom/...`: Interaction with the Document Object Model (DOM).
    * `core/frame/...`:  Integration with the browser's frame structure (console, etc.).
    * `core/xml/...`:  Handling XML documents and stylesheets.
    * `platform/loader/fetch/...`:  Fetching resources (documents, stylesheets).
    * `platform/wtf/...`:  WTF utilities (strings, buffers, memory management).
* **Namespace:** The `namespace blink { ... }` indicates this code is part of the Blink rendering engine.

**2. Identifying Key Functionalities:**

* **`GenericErrorFunc` and `ParseErrorFunc`:** These functions handle errors and warnings during XSLT processing. They integrate with the browser's console to display messages.
* **`DocLoaderFunc`:**  This is a critical function. The comment "FIXME: There seems to be no way to control the ctxt pointer..." hints at a workaround. Analyzing the code reveals it's responsible for fetching XML documents and XSLT stylesheets, particularly for `<xsl:import>` and `<xsl:include>`. It uses Blink's resource fetching mechanism.
* **`SetXSLTLoadCallBack`:**  This function sets the custom document loading function (`DocLoaderFunc`) in `libxslt`. This is the glue that connects Blink's resource loading to `libxslt`.
* **`WriteToStringBuilder` and `SaveResultToString`:** These functions handle the output of the XSLT transformation. They convert the `libxslt` output (which is often UTF-8) to Blink's `String` type (UTF-16). The "workaround for bugzilla.gnome.org" comment is interesting.
* **Parameter Handling (`AllocateParameterArray`, `XsltParamArrayFromParameterMap`, `FreeXsltParamArray`):** These functions deal with passing parameters from the Blink code to the `libxslt` processor.
* **Stylesheet Compilation (`XsltStylesheetPointer`):** This function takes a DOM node representing an XSLT stylesheet and compiles it using Blink's `XSLStyleSheet` class.
* **Source Document Handling (`XmlDocPtrFromNode`):** This function converts a Blink DOM node (either a whole document or a subtree) into a `libxslt` compatible `xmlDocPtr`.
* **Result MIME Type Determination (`ResultMIMEType`):** This function figures out the correct MIME type for the output of the XSLT transformation (text/html, application/xml, text/plain).
* **`TransformToString`:** This is the main entry point for performing an XSLT transformation. It orchestrates the loading of stylesheets, the transformation process using `libxslt`, and the conversion of the result to a string.

**3. Relating to JavaScript, HTML, and CSS:**

* **JavaScript:**  JavaScript code running in a web page can use the `XSLTProcessor` interface (provided by the browser) to perform XSLT transformations. This file implements the underlying logic for that interface. The example demonstrates this.
* **HTML:** XSLT can transform XML data into HTML. The `ResultMIMEType` function explicitly handles the "html" output method. The example demonstrates transforming XML into HTML.
* **CSS:**  While XSLT doesn't directly generate CSS, it can be used to manipulate XML data that is then used to generate CSS (e.g., using server-side XSLT to create CSS files). However, this file doesn't have direct interaction with CSS parsing or application *within the rendering pipeline*.

**4. Logic Inference and Examples:**

* For each function, consider the inputs and outputs. For `DocLoaderFunc`, the input is a URI, and the output is an `xmlDocPtr`. The logic involves fetching the resource.
* Construct simple input/output examples to illustrate the functionality. For `TransformToString`, provide a simple XML input, an XSLT stylesheet, and the expected HTML output.

**5. Identifying User/Programming Errors:**

* Think about common mistakes when using XSLT:
    * Incorrect stylesheet syntax (handled by the parser).
    * Referencing non-existent files (handled by the `DocLoaderFunc` and resource loading).
    * Providing incorrect parameters.
    * Security issues (the code explicitly sets security preferences).
* Create examples to demonstrate these errors.

**6. Tracing User Actions (Debugging):**

* Consider how a user's action (e.g., opening a web page) leads to XSLT processing. Think about the different ways XSLT can be used:
    * Directly in an XML document using a processing instruction.
    * Via JavaScript using the `XSLTProcessor` API.
    * Potentially through browser extensions or other mechanisms.
* Outline the steps involved in reaching this code during debugging. Break down the call stack.

**7. Refinement and Organization:**

* Group related functionalities together.
* Use clear and concise language.
* Provide code snippets where appropriate.
* Use formatting (like bolding and bullet points) to improve readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This file just does the transformation."
* **Realization:**  "No, it also handles loading stylesheets, managing parameters, error handling, and integrating with the browser's resource loading."
* **Initial thought:** "XSLT directly generates CSS."
* **Realization:** "It can *help* generate CSS, but it's not a direct part of the CSS rendering pipeline. The output is HTML or XML, which *may* contain links to CSS."
* **Ensuring clarity:** Instead of just listing function names, briefly explain *what* each function does. The "glue" analogy for `SetXSLTLoadCallBack` is helpful.

By following these steps, one can systematically analyze the source code and understand its functionality, relationships, potential errors, and debugging context. The key is to break down the problem into smaller, manageable parts and use the available information (file path, includes, comments, code) to infer the purpose and behavior of the code.
这个文件 `blink/renderer/core/xml/xslt_processor_libxslt.cc` 是 Chromium Blink 引擎中负责 **XSLT (Extensible Stylesheet Language Transformations) 处理**的核心组件。它使用 `libxslt` 库来实现 XSLT 的转换功能。

以下是它的主要功能以及与 JavaScript、HTML 和 CSS 的关系：

**主要功能:**

1. **XSLT 转换执行:**  这是文件的核心功能。它负责接收一个 XML 文档和一个 XSLT 样式表，并根据样式表中的规则将 XML 文档转换为另一种格式（通常是 HTML、XML 或文本）。它内部调用 `libxslt` 库来完成实际的转换工作。
2. **样式表加载和编译:**  它能够加载 XSLT 样式表。样式表可以内联在 HTML 中，也可以作为单独的文件引用。它会将加载的样式表编译成 `libxslt` 可以理解的格式。
3. **输入文档加载:**  它负责加载需要进行转换的 XML 文档。
4. **参数传递:** 允许在执行 XSLT 转换时传递参数，这些参数可以在 XSLT 样式表中使用。
5. **错误处理:**  它包含了错误处理机制，可以将 XSLT 转换过程中出现的错误和警告信息输出到浏览器的开发者工具的控制台中。
6. **资源加载:**  它定义了如何加载 XSLT 样式表和需要转换的 XML 文档，包括处理相对路径和安全策略。
7. **扩展支持:** 它支持 XSLT 扩展功能，允许在 XSLT 样式表中调用自定义的函数。
8. **输出处理:**  它处理 XSLT 转换后的输出结果，并将其转换为 Blink 引擎可以使用的字符串格式。
9. **安全控制:**  它实现了安全策略，限制 XSLT 样式表在转换过程中可以执行的操作，例如禁止访问本地文件系统或网络资源。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**
    * **接口桥梁:**  JavaScript 可以通过 `XSLTProcessor` 接口来调用这个文件提供的 XSLT 处理功能。开发者可以使用 JavaScript 加载 XML 文档和 XSLT 样式表，设置参数，并执行转换。
    * **动态转换:**  JavaScript 可以动态地创建 XML 文档或修改现有文档，然后使用 `XSLTProcessor` 进行转换，并将结果插入到 HTML 页面中。

    **举例说明:**

    ```javascript
    // JavaScript 代码
    const xsltProcessor = new XSLTProcessor();
    const xsltRequest = new XMLHttpRequest();
    xsltRequest.open('GET', 'style.xsl');
    xsltRequest.onload = function() {
      const xsltDoc = xsltRequest.responseXML;
      xsltProcessor.importStylesheet(xsltDoc);

      const xmlRequest = new XMLHttpRequest();
      xmlRequest.open('GET', 'data.xml');
      xmlRequest.onload = function() {
        const xmlDoc = xmlRequest.responseXML;
        const resultDocument = xsltProcessor.transformToDocument(xmlDoc);
        document.getElementById('output').appendChild(
          document.importNode(resultDocument.documentElement, true)
        );
      };
      xmlRequest.send();
    };
    xsltRequest.send();
    ```

    在这个例子中，JavaScript 使用 `XSLTProcessor` 对象来加载 `style.xsl` (XSLT 样式表) 和 `data.xml` (XML 文档)，然后执行转换并将结果添加到 HTML 页面中 id 为 `output` 的元素中。

* **HTML:**
    * **内联样式表:**  XSLT 样式表可以通过 `<xml-stylesheet>` 处理指令嵌入到 XML 文档中，浏览器会解析这个指令并使用 `XSLTProcessor` 进行转换。
    * **转换结果插入:**  XSLT 转换的最终结果通常是 HTML 片段或完整的 HTML 文档，这些结果会被插入到浏览器渲染的 HTML 页面中。

    **举例说明:**

    ```xml
    <!-- data.xml -->
    <?xml version="1.0"?>
    <?xml-stylesheet type="text/xsl" href="style.xsl"?>
    <data>
      <item>Item 1</item>
      <item>Item 2</item>
    </data>
    ```

    当浏览器加载 `data.xml` 时，会识别出 `<?xml-stylesheet type="text/xsl" href="style.xsl"?>` 指令，然后加载 `style.xsl` 并使用 `XSLTProcessor` 将 `data.xml` 转换为 HTML。

* **CSS:**
    * **间接影响:**  XSLT 的转换结果经常是 HTML，而生成的 HTML 页面会使用 CSS 进行样式化。因此，XSLT 可以间接地影响页面的最终样式。XSLT 样式表本身可以生成带有特定 CSS 类或 ID 的 HTML 元素，以便应用相应的 CSS 规则。
    * **CSS 生成（不常见）：** 在某些情况下，XSLT 也可以被用来生成 CSS 文件。例如，根据 XML 数据动态生成 CSS 变量或样式规则。

    **举例说明:**

    假设 `style.xsl` 将上面的 `data.xml` 转换为以下 HTML：

    ```html
    <div>
      <p class="item">Item 1</p>
      <p class="item">Item 2</p>
    </div>
    ```

    然后，可以使用 CSS 来样式化这些元素：

    ```css
    /* style.css */
    .item {
      font-weight: bold;
      color: blue;
    }
    ```

    XSLT 的转换结果生成了带有 `item` class 的 `<p>` 元素，CSS 规则会应用到这些元素上。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* **XML 文档 (input.xml):**
  ```xml
  <bookstore>
    <book category="COOKING">
      <title lang="en">Everyday Italian</title>
      <author>Giada De Laurentiis</author>
      <year>2005</year>
      <price>30.00</price>
    </book>
    <book category="CHILDREN">
      <title lang="en">Harry Potter</title>
      <author>J.K. Rowling</author>
      <year>2005</year>
      <price>29.99</price>
    </book>
  </bookstore>
  ```

* **XSLT 样式表 (style.xsl):**
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
      <html>
        <body>
          <h2>Books</h2>
          <xsl:for-each select="bookstore/book">
            <p>
              Title: <xsl:value-of select="title"/><br/>
              Author: <xsl:value-of select="author"/>
            </p>
          </xsl:for-each>
        </body>
      </html>
    </xsl:template>
  </xsl:stylesheet>
  ```

**假设输出 (HTML):**

```html
<html>
  <body>
    <h2>Books</h2>
    <p>
      Title: Everyday Italian<br/>
      Author: Giada De Laurentiis
    </p>
    <p>
      Title: Harry Potter<br/>
      Author: J.K. Rowling
    </p>
  </body>
</html>
```

**用户或编程常见的使用错误:**

1. **XSLT 样式表语法错误:**  如果 XSLT 样式表包含语法错误，例如标签未闭合或使用了错误的 XSLT 指令，`libxslt` 会报错，这些错误会被 `ParseErrorFunc` 捕获并输出到控制台。

   **举例:**  在 `style.xsl` 中，如果将 `<xsl:value-of select="title"/>` 写成 `<xsl:value-of select="titel"/>` (拼写错误)，转换会失败，控制台会显示错误信息。

2. **尝试加载不存在的样式表或 XML 文件:** 如果 XSLT 样式表中引用的外部样式表或需要转换的 XML 文件不存在，`DocLoaderFunc` 会尝试加载，但会失败，并可能导致转换错误。

   **举例:** 如果在 `data.xml` 中引用了一个不存在的样式表 `missing.xsl`，加载该 XML 时会报错。

3. **跨域问题:**  如果 XSLT 样式表或 XML 文件与当前页面的域名不同源，浏览器会出于安全原因阻止加载，除非配置了 CORS (跨域资源共享)。

   **举例:** 如果 HTML 页面在 `example.com`，而 `style.xsl` 在 `different-domain.com` 上，直接尝试转换会因为跨域问题而失败。

4. **无限循环或性能问题:** 设计不当的 XSLT 样式表可能导致无限循环或执行时间过长，影响页面性能。

   **举例:**  一个错误的 `<xsl:template match="/">` 内部又包含了应用相同模板的 `<xsl:apply-templates/>`，可能会导致无限递归。

5. **参数传递错误:** 在 JavaScript 中调用 `XSLTProcessor.setParameter()` 时，如果参数名称或值不符合 XSLT 样式表的预期，转换结果可能不正确。

   **举例:**  如果 XSLT 样式表期望一个名为 `bookCategory` 的参数，但在 JavaScript 中传递了 `category`，参数将不会被正确识别。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中打开一个包含需要进行 XSLT 转换的 XML 文档的网页。**  这个 XML 文档可能通过 `<xml-stylesheet>` 指令引用了 XSLT 样式表。
2. **浏览器解析 HTML 或 XML 文档。**  当解析器遇到 `<xml-stylesheet>` 指令时，会触发加载 XSLT 样式表的过程。
3. **Blink 引擎的资源加载器开始加载 XSLT 样式表文件。**  这会涉及到网络请求和响应。
4. **`DocLoaderFunc` 被调用来加载样式表。**  这个函数会使用 Blink 的资源加载机制来获取样式表的内容。
5. **Blink 引擎创建一个 `XSLTProcessor` 对象。**
6. **`XSLTProcessor::importStylesheet()` 方法被调用，将加载的样式表传递给 `libxslt` 进行编译。**
7. **如果 XML 文档需要转换（例如，通过 `<xml-stylesheet>`），或者 JavaScript 代码调用 `XSLTProcessor.transformToDocument()` 或 `transformToString()` 方法，则会触发转换过程。**
8. **`XSLTProcessor::TransformToString()` 方法被调用，这是 `xslt_processor_libxslt.cc` 文件中的核心函数。**
9. **在 `TransformToString()` 内部，会调用 `libxslt` 的函数来执行实际的转换。**
10. **`libxslt` 在转换过程中可能会调用 `DocLoaderFunc` 来加载额外的文档 (例如，通过 `<xsl:import>` 或 `<xsl:include>`)。**
11. **转换过程中产生的错误和警告信息会通过 `ParseErrorFunc` 输出到浏览器的控制台。**
12. **转换完成后，结果会被转换成字符串，并返回给调用者（JavaScript 或浏览器渲染引擎）。**
13. **最终，转换后的内容会被渲染到网页上。**

**调试线索:**

* **控制台错误信息:**  如果 XSLT 转换失败或有警告，控制台通常会显示相关的错误消息，包括错误的文件名和行号（由 `ParseErrorFunc` 输出）。
* **网络面板:**  可以查看浏览器网络面板，确认 XSLT 样式表和 XML 文件是否成功加载，以及是否有跨域问题。
* **断点调试:**  可以在 `xslt_processor_libxslt.cc` 文件中的关键函数（例如 `TransformToString`, `DocLoaderFunc`, `ParseErrorFunc`) 设置断点，逐步跟踪 XSLT 转换的过程，查看变量的值，以定位问题所在。
* **查看 `libxslt` 的日志输出 (如果启用):**  虽然 Blink 封装了 `libxslt`，但有时 `libxslt` 本身的日志输出也可能提供有用的信息。
* **检查 JavaScript 代码:**  如果通过 JavaScript 调用 XSLTProcessor，检查 JavaScript 代码中加载文件、设置参数和执行转换的逻辑是否正确。

理解 `blink/renderer/core/xml/xslt_processor_libxslt.cc` 的功能对于调试和理解 Chromium 浏览器如何处理 XSLT 转换至关重要。它连接了 JavaScript API、HTML 解析以及底层的 `libxslt` 库，实现了 Web 页面上的 XML 数据转换功能。

### 提示词
```
这是目录为blink/renderer/core/xml/xslt_processor_libxslt.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * This file is part of the XSL implementation.
 *
 * Copyright (C) 2004, 2005, 2006, 2007, 2008 Apple, Inc. All rights reserved.
 * Copyright (C) 2005, 2006 Alexey Proskuryakov <ap@webkit.org>
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

#include "third_party/blink/renderer/core/xml/xslt_processor.h"

#include <libxslt/imports.h>
#include <libxslt/security.h>
#include <libxslt/variables.h>
#include <libxslt/xsltutils.h>
#include "base/numerics/checked_math.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/transform_source.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/frame/frame_console.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/xml/parser/xml_document_parser.h"
#include "third_party/blink/renderer/core/xml/parser/xml_document_parser_scope.h"
#include "third_party/blink/renderer/core/xml/xsl_style_sheet.h"
#include "third_party/blink/renderer/core/xml/xslt_extensions.h"
#include "third_party/blink/renderer/core/xml/xslt_unicode_sort.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_type_names.h"
#include "third_party/blink/renderer/platform/loader/fetch/raw_resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_error.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/allocator/partitions.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/string_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/utf8.h"

namespace {

constexpr int kDoubleXsltMaxVars = 30000;

}

namespace blink {

void XSLTProcessor::GenericErrorFunc(void*, const char*, ...) {
  // It would be nice to do something with this error message.
}

void XSLTProcessor::ParseErrorFunc(void* user_data, const xmlError* error) {
  FrameConsole* console = static_cast<FrameConsole*>(user_data);
  if (!console)
    return;

  mojom::ConsoleMessageLevel level;
  switch (error->level) {
    case XML_ERR_NONE:
      level = mojom::ConsoleMessageLevel::kVerbose;
      break;
    case XML_ERR_WARNING:
      level = mojom::ConsoleMessageLevel::kWarning;
      break;
    case XML_ERR_ERROR:
    case XML_ERR_FATAL:
    default:
      level = mojom::ConsoleMessageLevel::kError;
      break;
  }

  console->AddMessage(MakeGarbageCollected<ConsoleMessage>(
      mojom::ConsoleMessageSource::kXml, level, error->message,
      std::make_unique<SourceLocation>(error->file, String(), error->line, 0,
                                       nullptr)));
}

// FIXME: There seems to be no way to control the ctxt pointer for loading here,
// thus we have globals.
static XSLTProcessor* g_global_processor = nullptr;
static ResourceFetcher* g_global_resource_fetcher = nullptr;

static xmlDocPtr DocLoaderFunc(const xmlChar* uri,
                               xmlDictPtr,
                               int options,
                               void* ctxt,
                               xsltLoadType type) {
  if (!g_global_processor)
    return nullptr;

  switch (type) {
    case XSLT_LOAD_DOCUMENT: {
      XMLDocumentParserScope scope(
          g_global_processor->XslStylesheet()->OwnerDocument());

      xsltTransformContextPtr context = (xsltTransformContextPtr)ctxt;
      xmlChar* base = xmlNodeGetBase(context->document->doc, context->node);
      KURL url(KURL(reinterpret_cast<const char*>(base)),
               reinterpret_cast<const char*>(uri));
      xmlFree(base);

      ResourceLoaderOptions fetch_options(nullptr /* world */);
      fetch_options.initiator_info.name = fetch_initiator_type_names::kXml;
      FetchParameters params(ResourceRequest(url), fetch_options);
      params.MutableResourceRequest().SetMode(
          network::mojom::RequestMode::kSameOrigin);
      Resource* resource =
          RawResource::FetchSynchronously(params, g_global_resource_fetcher);
      if (!g_global_processor)
        return nullptr;
      scoped_refptr<const SharedBuffer> data = resource->ResourceBuffer();
      if (!data)
        return nullptr;

      FrameConsole* console = nullptr;
      LocalFrame* frame =
          g_global_processor->XslStylesheet()->OwnerDocument()->GetFrame();
      if (frame)
        console = &frame->Console();
      xmlSetStructuredErrorFunc(console, XSLTProcessor::ParseErrorFunc);
      xmlSetGenericErrorFunc(console, XSLTProcessor::GenericErrorFunc);

      xmlDocPtr doc = nullptr;

      // We don't specify an encoding here. Neither Gecko nor WinIE respects
      // the encoding specified in the HTTP headers.
      xmlParserCtxtPtr ctx = xmlCreatePushParserCtxt(
          nullptr, nullptr, nullptr, 0, reinterpret_cast<const char*>(uri));
      if (ctx && !xmlCtxtUseOptions(ctx, options)) {
        size_t offset = 0;
        for (const auto& span : *data) {
          bool final_chunk = offset + span.size() == data->size();
          // Stop parsing chunks if xmlParseChunk returns an error.
          if (xmlParseChunk(ctx, span.data(), static_cast<int>(span.size()),
                            final_chunk))
            break;
          offset += span.size();
        }

        if (ctx->wellFormed)
          doc = ctx->myDoc;
      }

      xmlFreeParserCtxt(ctx);
      xmlSetStructuredErrorFunc(nullptr, nullptr);
      xmlSetGenericErrorFunc(nullptr, nullptr);

      return doc;
    }
    case XSLT_LOAD_STYLESHEET:
      return g_global_processor->XslStylesheet()->LocateStylesheetSubResource(
          ((xsltStylesheetPtr)ctxt)->doc, uri);
    default:
      break;
  }

  return nullptr;
}

static inline void SetXSLTLoadCallBack(xsltDocLoaderFunc func,
                                       XSLTProcessor* processor,
                                       ResourceFetcher* fetcher) {
  xsltSetLoaderFunc(func);
  g_global_processor = processor;
  g_global_resource_fetcher = fetcher;
}

static int WriteToStringBuilder(void* context, const char* buffer, int len) {
  if (!len)
    return 0;

  StringBuffer<UChar> string_buffer(len);

  base::span<const uint8_t> source_buffer(
      reinterpret_cast<const uint8_t*>(buffer),
      base::checked_cast<size_t>(len));
  WTF::unicode::ConversionResult result =
      WTF::unicode::ConvertUTF8ToUTF16(source_buffer, string_buffer.Span());
  CHECK(result.status == WTF::unicode::kConversionOK ||
        result.status == WTF::unicode::kSourceExhausted);

  StringBuilder& result_output = *static_cast<StringBuilder*>(context);
  result_output.Append(result.converted);
  return base::checked_cast<int>(result.consumed);
}

static bool SaveResultToString(xmlDocPtr result_doc,
                               xsltStylesheetPtr sheet,
                               String& result_string) {
  xmlOutputBufferPtr output_buf = xmlAllocOutputBuffer(nullptr);
  if (!output_buf)
    return false;

  StringBuilder result_builder;
  output_buf->context = &result_builder;
  output_buf->writecallback = WriteToStringBuilder;

  int retval = xsltSaveResultTo(output_buf, result_doc, sheet);
  xmlOutputBufferClose(output_buf);
  if (retval < 0)
    return false;

  // Workaround for <http://bugzilla.gnome.org/show_bug.cgi?id=495668>:
  // libxslt appends an extra line feed to the result.
  if (result_builder.length() > 0 &&
      result_builder[result_builder.length() - 1] == '\n')
    result_builder.Resize(result_builder.length() - 1);

  result_string = result_builder.ToString();

  return true;
}

static char* AllocateParameterArray(const char* data) {
  size_t length = strlen(data) + 1;
  char* parameter_array = static_cast<char*>(WTF::Partitions::FastMalloc(
      length, WTF_HEAP_PROFILER_TYPE_NAME(XSLTProcessor)));
  memcpy(parameter_array, data, length);
  return parameter_array;
}

static const char** XsltParamArrayFromParameterMap(
    XSLTProcessor::ParameterMap& parameters) {
  if (parameters.empty())
    return nullptr;

  base::CheckedNumeric<size_t> size = parameters.size();
  size *= 2;
  ++size;
  size *= sizeof(char*);
  const char** parameter_array =
      static_cast<const char**>(WTF::Partitions::FastMalloc(
          size.ValueOrDie(), WTF_HEAP_PROFILER_TYPE_NAME(XSLTProcessor)));

  unsigned index = 0;
  for (auto& parameter : parameters) {
    parameter_array[index++] =
        AllocateParameterArray(parameter.key.Utf8().c_str());
    parameter_array[index++] =
        AllocateParameterArray(parameter.value.Utf8().c_str());
  }
  parameter_array[index] = nullptr;

  return parameter_array;
}

static void FreeXsltParamArray(const char** params) {
  const char** temp = params;
  if (!params)
    return;

  while (*temp) {
    WTF::Partitions::FastFree(const_cast<char*>(*(temp++)));
    WTF::Partitions::FastFree(const_cast<char*>(*(temp++)));
  }
  WTF::Partitions::FastFree(params);
}

static xsltStylesheetPtr XsltStylesheetPointer(
    Document* document,
    Member<XSLStyleSheet>& cached_stylesheet,
    Node* stylesheet_root_node) {
  if (!cached_stylesheet && stylesheet_root_node) {
    // When using importStylesheet, we will use the given document as the
    // imported stylesheet's owner.
    cached_stylesheet = MakeGarbageCollected<XSLStyleSheet>(
        stylesheet_root_node->parentNode()
            ? &stylesheet_root_node->parentNode()->GetDocument()
            : document,
        stylesheet_root_node,
        stylesheet_root_node->GetDocument().Url().GetString(),
        stylesheet_root_node->GetDocument().Url(),
        false);  // FIXME: Should we use baseURL here?

    // According to Mozilla documentation, the node must be a Document node,
    // an xsl:stylesheet or xsl:transform element. But we just use text
    // content regardless of node type.
    cached_stylesheet->ParseString(CreateMarkup(stylesheet_root_node));
  }

  if (!cached_stylesheet || !cached_stylesheet->GetDocument())
    return nullptr;

  return cached_stylesheet->CompileStyleSheet();
}

static inline xmlDocPtr XmlDocPtrFromNode(Node* source_node,
                                          bool& should_delete) {
  Document* owner_document = &source_node->GetDocument();
  bool source_is_document = (source_node == owner_document);

  xmlDocPtr source_doc = nullptr;
  if (source_is_document && owner_document->GetTransformSource())
    source_doc =
        (xmlDocPtr)owner_document->GetTransformSource()->PlatformSource();
  if (!source_doc) {
    source_doc = (xmlDocPtr)XmlDocPtrForString(
        owner_document, CreateMarkup(source_node),
        source_is_document ? owner_document->Url().GetString() : String());
    should_delete = source_doc;
  }
  return source_doc;
}

static inline String ResultMIMEType(xmlDocPtr result_doc,
                                    xsltStylesheetPtr sheet) {
  // There are three types of output we need to be able to deal with:
  // HTML (create an HTML document), XML (create an XML document),
  // and text (wrap in a <pre> and create an XML document).

  const xmlChar* result_type = nullptr;
  XSLT_GET_IMPORT_PTR(result_type, sheet, method);
  if (!result_type && result_doc->type == XML_HTML_DOCUMENT_NODE)
    result_type = (const xmlChar*)"html";

  if (xmlStrEqual(result_type, (const xmlChar*)"html"))
    return "text/html";
  if (xmlStrEqual(result_type, (const xmlChar*)"text"))
    return "text/plain";

  return "application/xml";
}

bool XSLTProcessor::TransformToString(Node* source_node,
                                      String& mime_type,
                                      String& result_string,
                                      String& result_encoding) {
  Document* owner_document = &source_node->GetDocument();

  SetXSLTLoadCallBack(DocLoaderFunc, this, owner_document->Fetcher());
  xsltStylesheetPtr sheet = XsltStylesheetPointer(document_.Get(), stylesheet_,
                                                  stylesheet_root_node_.Get());
  if (!sheet) {
    SetXSLTLoadCallBack(nullptr, nullptr, nullptr);
    stylesheet_ = nullptr;
    return false;
  }
  stylesheet_->ClearDocuments();

  xmlChar* orig_method = sheet->method;
  if (!orig_method && mime_type == "text/html")
    sheet->method = (xmlChar*)"html";

  bool success = false;
  bool should_free_source_doc = false;
  if (xmlDocPtr source_doc =
          XmlDocPtrFromNode(source_node, should_free_source_doc)) {
    // The XML declaration would prevent parsing the result as a fragment,
    // and it's not needed even for documents, as the result of this
    // function is always immediately parsed.
    sheet->omitXmlDeclaration = true;

    // Double the number of vars xslt uses internally before it is used in
    // xsltNewTransformContext. See http://crbug.com/796505
    DCHECK(xsltMaxVars == kDoubleXsltMaxVars ||
           xsltMaxVars == kDoubleXsltMaxVars / 2)
        << "We should be doubling xsltMaxVars' default value from libxslt with "
           "our new value. actual value: "
        << xsltMaxVars;
    xsltMaxVars = kDoubleXsltMaxVars;

    xsltTransformContextPtr transform_context =
        xsltNewTransformContext(sheet, source_doc);
    RegisterXSLTExtensions(transform_context);

    xsltSecurityPrefsPtr security_prefs = xsltNewSecurityPrefs();
    // Read permissions are checked by docLoaderFunc.
    CHECK_EQ(0, xsltSetSecurityPrefs(security_prefs, XSLT_SECPREF_WRITE_FILE,
                                     xsltSecurityForbid));
    CHECK_EQ(0,
             xsltSetSecurityPrefs(security_prefs, XSLT_SECPREF_CREATE_DIRECTORY,
                                  xsltSecurityForbid));
    CHECK_EQ(0, xsltSetSecurityPrefs(security_prefs, XSLT_SECPREF_WRITE_NETWORK,
                                     xsltSecurityForbid));
    CHECK_EQ(0, xsltSetCtxtSecurityPrefs(security_prefs, transform_context));

    // <http://bugs.webkit.org/show_bug.cgi?id=16077>: XSLT processor
    // <xsl:sort> algorithm only compares by code point.
    xsltSetCtxtSortFunc(transform_context, XsltUnicodeSortFunction);

    // This is a workaround for a bug in libxslt.
    // The bug has been fixed in version 1.1.13, so once we ship that this
    // can be removed.
    if (!transform_context->globalVars)
      transform_context->globalVars = xmlHashCreate(20);

    const char** params = XsltParamArrayFromParameterMap(parameters_);
    xsltQuoteUserParams(transform_context, params);
    xmlDocPtr result_doc = xsltApplyStylesheetUser(
        sheet, source_doc, nullptr, nullptr, nullptr, transform_context);

    xsltFreeTransformContext(transform_context);
    xsltFreeSecurityPrefs(security_prefs);
    FreeXsltParamArray(params);

    if (should_free_source_doc)
      xmlFreeDoc(source_doc);

    success = SaveResultToString(result_doc, sheet, result_string);
    if (success) {
      mime_type = ResultMIMEType(result_doc, sheet);
      result_encoding = (char*)result_doc->encoding;
    }
    xmlFreeDoc(result_doc);
  }

  sheet->method = orig_method;
  SetXSLTLoadCallBack(nullptr, nullptr, nullptr);
  xsltFreeStylesheet(sheet);
  stylesheet_ = nullptr;

  return success;
}

}  // namespace blink
```