Response:
Let's break down the thought process for analyzing the `css_style_sheet_resource.cc` file.

1. **Understand the Goal:** The request asks for the functionalities of this specific Chromium Blink file, its relationships to web technologies (HTML, CSS, JavaScript), potential errors, and debugging context.

2. **Initial Skim and Keyword Recognition:**  Read through the file quickly, looking for obvious keywords and patterns. I see:
    * `CSSStyleSheetResource` (repeatedly): This is the core class, likely responsible for handling CSS style sheet resources.
    * `Fetch`, `CreateForTest`:  Indicates ways to obtain or create instances of the class.
    * `ResourceRequest`, `ResourceLoaderOptions`, `TextResourceDecoderOptions`:  Standard resource loading concepts.
    * `StyleSheetContents`:  Suggests a parsed representation of the CSS.
    * `parsed_style_sheet_cache_`: An important member variable related to caching.
    * `SetParsedStyleSheetCache`, `CreateParsedStyleSheetFromCache`, `SaveParsedStyleSheet`: Functions managing the cache.
    * `SheetText`:  Getting the actual CSS text.
    * `NotifyFinished`, `DestroyDecodedDataIfPossible`: Lifecycle management.
    * `CanUseSheet`: Validation of the CSS resource.
    * `MIMETypeRegistry`, `HttpContentType`:  Dealing with content types.
    * Headers like `Referrer-Policy`.
    * Includes: `css/style_sheet_contents.h`, loader related headers, `network/http_names.h`.

3. **Identify Core Functionality Blocks:**  Group related functions and variables to understand the main responsibilities of the class. I see these logical blocks:

    * **Resource Fetching and Creation:**  `Fetch`, `CreateForTest`, constructor. These deal with initiating and setting up the loading process.
    * **Caching:** `parsed_style_sheet_cache_`, `SetParsedStyleSheetCache`, `CreateParsedStyleSheetFromCache`, `SaveParsedStyleSheet`, `DestroyDecodedDataIfPossible`, `DestroyDecodedDataForFailedRevalidation`. Caching is clearly a central aspect.
    * **Accessing CSS Text:** `SheetText`. How the CSS content is retrieved.
    * **Lifecycle and Post-Processing:** `NotifyFinished`, `UpdateDecodedSize`. Actions taken after loading.
    * **Validation:** `CanUseSheet`. Determining if the resource is a valid CSS stylesheet.
    * **Metadata:** `GetReferrerPolicy`. Retrieving relevant HTTP headers.
    * **Memory Management:** `OnMemoryDump`.

4. **Analyze Interactions with Web Technologies:** Consider how the functionality relates to HTML, CSS, and JavaScript:

    * **HTML:**  `<link rel="stylesheet">` tags trigger the fetching of CSS resources, which this class handles. Inline `<style>` tags are processed differently.
    * **CSS:** This class *is* the representation of a loaded CSS stylesheet. It manages the text, parsed representation, and caching.
    * **JavaScript:**  JavaScript can manipulate stylesheets through the DOM (`document.styleSheets`). While this class doesn't directly execute JavaScript, it provides the CSS data that JavaScript interacts with.

5. **Infer Logical Reasoning and Examples:**  For each functionality block, think about the inputs and outputs and how the logic works. Consider edge cases and common scenarios. For example:

    * **Caching:** Input:  A successful CSS fetch. Output:  The parsed stylesheet is stored. Subsequent requests for the same URL might retrieve from the cache. Input: Different `CSSParserContext`. Output: Cache might not be used.
    * **`CanUseSheet`:** Input:  A fetched resource with a `Content-Type` header. Output:  `true` if it's likely CSS, `false` otherwise. Input: A local file. Output: `true` only if the extension is typical for CSS.

6. **Identify Potential Errors:** Think about common mistakes developers make when working with CSS:

    * **Incorrect `Content-Type`:**  The server might serve a CSS file with the wrong header.
    * **Typos in URLs:** The browser won't find the CSS file.
    * **Local File Issues:**  Not having the correct extension on a local CSS file.
    * **Cache Invalidation Problems:**  Old CSS being served due to caching.

7. **Construct Debugging Scenarios:**  Imagine a situation where a stylesheet isn't loading correctly. Trace the steps that would lead to this code:

    * The user opens a web page.
    * The HTML parser encounters a `<link>` tag.
    * Blink starts the resource loading process.
    * `CSSStyleSheetResource::Fetch` is called.
    * The resource is fetched.
    * If there's an issue, developers might set breakpoints within this class to see how the loading and parsing are proceeding.

8. **Structure the Answer:**  Organize the findings logically with clear headings and examples. Use bullet points for listing functionalities and errors. Explain the connections to web technologies concisely. Provide concrete examples for assumptions and errors.

9. **Review and Refine:** Read through the answer to ensure clarity, accuracy, and completeness. Check for any ambiguities or areas that could be explained better. For example, ensure the explanation of `CSSParserContext` is clear and the caching logic is well articulated. Make sure the debugging scenario is realistic.

This systematic approach helps ensure all aspects of the request are addressed comprehensively and accurately. It involves understanding the code's purpose, its interactions with the broader system, potential issues, and how developers might interact with it during debugging.
好的，我们来分析一下 `blink/renderer/core/loader/resource/css_style_sheet_resource.cc` 这个文件。

**文件功能概述:**

`CSSStyleSheetResource` 类是 Blink 渲染引擎中用于加载和管理 CSS 样式表资源的核心组件。 它的主要功能包括：

1. **发起和管理 CSS 资源的获取:**  负责发起网络请求，下载 CSS 文件内容。
2. **缓存 CSS 资源:**  实现内存缓存机制，避免重复下载相同的 CSS 文件，提高页面加载速度。
3. **解码 CSS 内容:**  将下载的字节流数据解码为可用的文本格式，并处理字符编码问题。
4. **管理已解析的 CSS 样式表:**  关联并管理 `StyleSheetContents` 对象，该对象包含了已解析的 CSS 规则和信息。
5. **提供 CSS 文本内容:**  提供获取 CSS 文本内容的接口，供渲染引擎的其他部分使用。
6. **处理与安全相关的策略:**  例如，处理 `Referrer-Policy` HTTP 头，确定在请求相关资源时如何设置 `Referer` 头。
7. **验证 CSS 资源的有效性:**  例如，根据 HTTP `Content-Type` 头或者文件扩展名判断资源是否是合法的 CSS 文件。
8. **内存管理:**  在内存转储时提供关于自身内存使用情况的信息。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    * **功能关系:** 当 HTML 解析器遇到 `<link rel="stylesheet" href="...">` 标签时，会触发 `CSSStyleSheetResource` 来加载对应的 CSS 文件。
    * **举例:**  在 HTML 文件中有 `<link rel="stylesheet" href="style.css">`，浏览器会创建一个 `CSSStyleSheetResource` 实例来加载 `style.css` 文件。

* **CSS:**
    * **功能关系:**  `CSSStyleSheetResource` 本身就是 CSS 资源的载体。它负责读取 CSS 文件的内容，并将其提供给 CSS 解析器进行解析。
    * **举例:**  `CSSStyleSheetResource` 的 `SheetText()` 方法会被调用，以获取 `style.css` 文件的文本内容，然后这个内容会被传递给 CSS 解析器来构建样式规则。

* **JavaScript:**
    * **功能关系:**  JavaScript 可以通过 DOM API 操作样式表，例如 `document.styleSheets` 集合。这些 `StyleSheet` 对象背后关联着 `CSSStyleSheetResource` 加载的 CSS 数据。JavaScript 的修改最终会影响到 `StyleSheetContents` 中存储的样式信息。
    * **举例:**  JavaScript 代码 `document.styleSheets[0].insertRule('body { background-color: red; }')` 可能会导致与该样式表关联的 `CSSStyleSheetResource` 间接参与到样式的更新过程中。

**逻辑推理及假设输入与输出:**

**假设输入:**

1. **场景 1 (成功加载):**
   * 用户在浏览器中打开一个包含 `<link rel="stylesheet" href="https://example.com/style.css">` 的 HTML 页面。
   * 服务器 `example.com` 成功响应请求，返回 `style.css` 文件内容，并且 `Content-Type` 头为 `text/css`。

2. **场景 2 (MIME 类型错误):**
   * 用户在浏览器中打开一个包含 `<link rel="stylesheet" href="https://example.com/style.css">` 的 HTML 页面。
   * 服务器 `example.com` 成功响应请求，返回 `style.css` 文件内容，但是 `Content-Type` 头为 `text/plain`。

3. **场景 3 (本地文件无扩展名):**
   * 用户在浏览器中打开一个包含 `<link rel="stylesheet" href="file:///path/to/mystyle">` 的 HTML 页面。

**逻辑推理与输出:**

1. **场景 1 (成功加载):**
   * **输入:** `FetchParameters` 包含 `https://example.com/style.css` 的 URL，`ResourceFetcher` 对象。
   * **输出:** `CSSStyleSheetResource::Fetch` 方法会创建一个 `CSSStyleSheetResource` 对象，并开始加载资源。加载完成后，`NotifyFinished()` 会被调用，解码 CSS 内容并缓存。`SheetText()` 方法会返回 `style.css` 的文本内容。`CanUseSheet()` 返回 `true`。

2. **场景 2 (MIME 类型错误):**
   * **输入:** `FetchParameters` 包含 `https://example.com/style.css` 的 URL，服务器返回的 `Content-Type` 为 `text/plain`。
   * **输出:**  `CanUseSheet()` 方法会因为 `Content-Type` 不是 `text/css` (或 `application/x-unknown-content-type`) 而返回 `false`。这个样式表可能不会被应用，或者浏览器会发出警告。`SheetText()` 方法会返回空字符串。

3. **场景 3 (本地文件无扩展名):**
   * **输入:** `FetchParameters` 包含 `file:///path/to/mystyle` 的 URL。
   * **输出:** `CanUseSheet()` 方法会检查本地文件的扩展名。由于 `mystyle` 没有常见的 CSS 文件扩展名（如 `.css`），`CanUseSheet()` 可能会返回 `false` (取决于具体的实现和配置)。浏览器可能会拒绝加载这个样式表，并在开发者工具中显示警告。

**涉及用户或编程常见的使用错误及举例说明:**

1. **服务器配置错误导致错误的 `Content-Type`:**
   * **错误:**  网站管理员错误地配置了服务器，导致 CSS 文件返回的 `Content-Type` 是 `text/plain` 而不是 `text/css`。
   * **用户操作:** 用户访问该网站，浏览器尝试加载 CSS 文件。
   * **`CSSStyleSheetResource` 行为:** `CanUseSheet()` 会返回 `false`，浏览器将不会把该文件当作 CSS 处理，页面样式会错乱。

2. **链接到不存在或路径错误的 CSS 文件:**
   * **错误:** HTML 中 `<link>` 标签的 `href` 属性指向了一个不存在的文件或者路径不正确。
   * **用户操作:** 用户访问该页面。
   * **`CSSStyleSheetResource` 行为:**  资源加载会失败，`ErrorOccurred()` 会返回 `true`。`SheetText()` 会返回空字符串。页面将不会应用该样式表。

3. **本地开发时忘记添加 `.css` 扩展名:**
   * **错误:**  开发者在本地开发时创建了一个名为 `mystyle` 的 CSS 文件，并在 HTML 中使用 `<link rel="stylesheet" href="mystyle">` 引用。
   * **用户操作:** 开发者在本地浏览器中打开 HTML 文件。
   * **`CSSStyleSheetResource` 行为:**  `CanUseSheet()` 可能会因为本地文件缺少 `.css` 扩展名而返回 `false`，导致样式不生效。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设用户报告了一个网页样式错乱的问题，开发者需要调试 CSS 加载过程，可能会按照以下步骤进行：

1. **用户访问网页:** 用户在浏览器地址栏输入网址或点击链接，开始加载网页。
2. **HTML 解析:** 浏览器开始解析 HTML 文档。
3. **遇到 `<link>` 标签:** 当 HTML 解析器遇到 `<link rel="stylesheet" href="styles.css">` 这样的标签时，会触发资源加载流程。
4. **创建 `CSSStyleSheetResource`:**  Blink 引擎会创建一个 `CSSStyleSheetResource` 对象，用于加载 `styles.css`。 这通常发生在 `HTMLLinkElement::process()` 或相关的资源加载启动代码中。
5. **发起网络请求:** `CSSStyleSheetResource::Fetch()` 方法会被调用，创建一个网络请求并发送给服务器。
6. **接收响应:** 浏览器接收到服务器的响应，包括 HTTP 头和 CSS 文件内容。
7. **`CSSStyleSheetResource` 处理响应:**
   * **检查状态码:**  `CSSStyleSheetResource` 会检查 HTTP 状态码，例如 200 OK 表示成功。
   * **检查 `Content-Type`:**  `CanUseSheet()` 方法会检查 `Content-Type` 头，确认是否是 `text/css`。
   * **解码内容:** 如果加载成功，`NotifyFinished()` 会被调用，解码 CSS 文件内容。
   * **缓存:**  解码后的内容可能会被缓存起来。
8. **解析 CSS:**  `CSSStyleSheetResource` 将解码后的文本传递给 CSS 解析器，生成 `StyleSheetContents` 对象。
9. **应用样式:**  渲染引擎使用 `StyleSheetContents` 中的样式规则来渲染页面。

**调试线索:**

如果样式出现问题，开发者可能会在以下几个地方设置断点进行调试：

* **`CSSStyleSheetResource::Fetch()`:**  查看资源请求是如何发起的。
* **`CSSStyleSheetResource::CanUseSheet()`:** 检查是否因为 MIME 类型或其他原因导致 CSS 文件被拒绝。
* **`CSSStyleSheetResource::NotifyFinished()`:** 查看资源加载完成后是否正确解码。
* **`CSSStyleSheetResource::SheetText()`:**  查看最终提供给解析器的 CSS 文本内容。
* **网络面板:**  检查网络请求的状态码、Headers (特别是 `Content-Type`) 和 Response 内容。

通过这些调试步骤，开发者可以逐步追踪 CSS 资源的加载和处理过程，从而定位样式问题的根源。

### 提示词
```
这是目录为blink/renderer/core/loader/resource/css_style_sheet_resource.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
    Copyright (C) 1998 Lars Knoll (knoll@mpi-hd.mpg.de)
    Copyright (C) 2001 Dirk Mueller (mueller@kde.org)
    Copyright (C) 2002 Waldo Bastian (bastian@kde.org)
    Copyright (C) 2006 Samuel Weinig (sam.weinig@gmail.com)
    Copyright (C) 2004, 2005, 2006 Apple Computer, Inc.

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

    This class provides all functionality needed for loading images, style
    sheets and html pages from the web. It has a memory cache for these objects.
*/

#include "third_party/blink/renderer/core/loader/resource/css_style_sheet_resource.h"

#include "base/metrics/histogram_functions.h"
#include "base/task/single_thread_task_runner.h"
#include "base/trace_event/trace_event.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/loader/request_context_frame_type.mojom-blink.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_persistent.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_parameters.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/loader/fetch/response_body_loader.h"
#include "third_party/blink/renderer/platform/loader/fetch/text_resource_decoder_options.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/network/mime/mime_type_registry.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/worker_pool.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_mojo.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding.h"

namespace blink {
CSSStyleSheetResource* CSSStyleSheetResource::Fetch(FetchParameters& params,
                                                    ResourceFetcher* fetcher,
                                                    ResourceClient* client) {
  params.SetRequestContext(mojom::blink::RequestContextType::STYLE);
  params.SetRequestDestination(network::mojom::RequestDestination::kStyle);
  auto* resource = To<CSSStyleSheetResource>(
      fetcher->RequestResource(params, CSSStyleSheetResourceFactory(), client));
  return resource;
}

CSSStyleSheetResource* CSSStyleSheetResource::CreateForTest(
    const KURL& url,
    const WTF::TextEncoding& encoding) {
  ResourceRequest request(url);
  request.SetCredentialsMode(network::mojom::CredentialsMode::kOmit);
  ResourceLoaderOptions options(nullptr /* world */);
  TextResourceDecoderOptions decoder_options(
      TextResourceDecoderOptions::kCSSContent, encoding);
  return MakeGarbageCollected<CSSStyleSheetResource>(request, options,
                                                     decoder_options);
}

CSSStyleSheetResource::CSSStyleSheetResource(
    const ResourceRequest& resource_request,
    const ResourceLoaderOptions& options,
    const TextResourceDecoderOptions& decoder_options)
    : TextResource(resource_request,
                   ResourceType::kCSSStyleSheet,
                   options,
                   decoder_options) {}

CSSStyleSheetResource::~CSSStyleSheetResource() = default;

void CSSStyleSheetResource::SetParsedStyleSheetCache(
    StyleSheetContents* new_sheet) {
  if (parsed_style_sheet_cache_)
    parsed_style_sheet_cache_->ClearReferencedFromResource();
  parsed_style_sheet_cache_ = new_sheet;
  if (parsed_style_sheet_cache_)
    parsed_style_sheet_cache_->SetReferencedFromResource(this);

  // Updates the decoded size to take parsed stylesheet cache into account.
  UpdateDecodedSize();
}

void CSSStyleSheetResource::Trace(Visitor* visitor) const {
  visitor->Trace(parsed_style_sheet_cache_);
  TextResource::Trace(visitor);
}

void CSSStyleSheetResource::OnMemoryDump(
    WebMemoryDumpLevelOfDetail level_of_detail,
    WebProcessMemoryDump* memory_dump) const {
  Resource::OnMemoryDump(level_of_detail, memory_dump);
  const String name = GetMemoryDumpName() + "/style_sheets";
  auto* dump = memory_dump->CreateMemoryAllocatorDump(name);
  dump->AddScalar("size", "bytes", decoded_sheet_text_.CharactersSizeInBytes());
  memory_dump->AddSuballocation(
      dump->Guid(), String(WTF::Partitions::kAllocatedObjectPoolName));
}

network::mojom::ReferrerPolicy CSSStyleSheetResource::GetReferrerPolicy()
    const {
  network::mojom::ReferrerPolicy referrer_policy =
      network::mojom::ReferrerPolicy::kDefault;
  String referrer_policy_header =
      GetResponse().HttpHeaderField(http_names::kReferrerPolicy);
  if (!referrer_policy_header.IsNull()) {
    SecurityPolicy::ReferrerPolicyFromHeaderValue(
        referrer_policy_header, kDoNotSupportReferrerPolicyLegacyKeywords,
        &referrer_policy);
  }
  return referrer_policy;
}

const String CSSStyleSheetResource::SheetText(
    const CSSParserContext* parser_context,
    MIMETypeCheck mime_type_check) const {
  if (!CanUseSheet(parser_context, mime_type_check))
    return String();

  // Use cached decoded sheet text when available
  if (!decoded_sheet_text_.IsNull()) {
    // We should have the decoded sheet text cached when the resource is fully
    // loaded.
    DCHECK_EQ(GetStatus(), ResourceStatus::kCached);

    return decoded_sheet_text_;
  }

  if (!Data() || Data()->empty())
    return String();

  return DecodedText();
}

void CSSStyleSheetResource::NotifyFinished() {
  // Decode the data to find out the encoding and cache the decoded sheet text.
  if (Data()) {
    SetDecodedSheetText(DecodedText());
  }

  Resource::NotifyFinished();
  // Clear raw bytes as now we have the full decoded sheet text.
  // We wait for all LinkStyle::setCSSStyleSheet to run (at least once)
  // as SubresourceIntegrity checks require raw bytes.
  // Note that LinkStyle::setCSSStyleSheet can be called from didAddClient too,
  // but is safe as we should have a cached ResourceIntegrityDisposition.
  ClearData();
}

void CSSStyleSheetResource::DestroyDecodedDataIfPossible() {
  if (!parsed_style_sheet_cache_)
    return;

  SetParsedStyleSheetCache(nullptr);
}

void CSSStyleSheetResource::DestroyDecodedDataForFailedRevalidation() {
  SetDecodedSheetText(String());
  DestroyDecodedDataIfPossible();
}

bool CSSStyleSheetResource::CanUseSheet(const CSSParserContext* parser_context,
                                        MIMETypeCheck mime_type_check) const {
  if (ErrorOccurred())
    return false;

  // For `file:` URLs, we may need to be a little more strict than the below.
  // Though we'll likely change this in the future, for the moment we're going
  // to enforce a file-extension requirement on stylesheets loaded from `file:`
  // URLs and see how far it gets us.
  KURL sheet_url = GetResponse().CurrentRequestUrl();
  if (sheet_url.IsLocalFile()) {
    if (parser_context) {
      parser_context->Count(WebFeature::kLocalCSSFile);
    }
    // Grab |sheet_url|'s filename's extension (if present), and check whether
    // or not it maps to a `text/css` MIME type:
    String extension;
    String last_path_component = sheet_url.LastPathComponent().ToString();
    int last_dot = last_path_component.ReverseFind('.');
    if (last_dot != -1) {
      extension = last_path_component.Substring(last_dot + 1);
    }
    if (!EqualIgnoringASCIICase(
            MIMETypeRegistry::GetMIMETypeForExtension(extension), "text/css")) {
      if (parser_context) {
        parser_context->CountDeprecation(
            WebFeature::kLocalCSSFileExtensionRejected);
      }
      return false;
    }
  }

  // This check exactly matches Firefox. Note that we grab the Content-Type
  // header directly because we want to see what the value is BEFORE content
  // sniffing. Firefox does this by setting a "type hint" on the channel. This
  // implementation should be observationally equivalent.
  //
  // This code defaults to allowing the stylesheet for non-HTTP protocols so
  // folks can use standards mode for local HTML documents.
  if (mime_type_check == MIMETypeCheck::kLax)
    return true;
  AtomicString content_type = HttpContentType();
  return content_type.empty() ||
         EqualIgnoringASCIICase(content_type, "text/css") ||
         EqualIgnoringASCIICase(content_type,
                                "application/x-unknown-content-type");
}

StyleSheetContents* CSSStyleSheetResource::CreateParsedStyleSheetFromCache(
    const CSSParserContext* context) {
  if (!parsed_style_sheet_cache_) {
    return nullptr;
  }
  if (parsed_style_sheet_cache_->HasFailedOrCanceledSubresources()) {
    SetParsedStyleSheetCache(nullptr);
    return nullptr;
  }

  DCHECK(parsed_style_sheet_cache_->IsCacheableForResource());
  DCHECK(parsed_style_sheet_cache_->IsReferencedFromResource());

  // Contexts must be identical so we know we would get the same exact result if
  // we parsed again.
  if (*parsed_style_sheet_cache_->ParserContext() != *context) {
    return nullptr;
  }

  // StyleSheetContents with @media queries are shared between different
  // documents, in the same rendering process, which may evaluate these media
  // queries differently. For instance, two documents rendered in different tabs
  // or iframes with different sizes. In that case, an active stylesheet update
  // in one document may clear the cached RuleSet in StyleSheetContents, that
  // would otherwise be a valid cache for the other document.
  //
  // This should not be problematic as the case of continuously modifying,
  // adding, or removing stylesheets, while at the same time have different
  // media query evaluations in the different documents should be quite rare.

  DCHECK(!parsed_style_sheet_cache_->IsLoading());
  return parsed_style_sheet_cache_.Get();
}

void CSSStyleSheetResource::SaveParsedStyleSheet(StyleSheetContents* sheet) {
  DCHECK(sheet);
  DCHECK(sheet->IsCacheableForResource());

  if (!MemoryCache::Get()->Contains(this)) {
    // This stylesheet resource did conflict with another resource and was not
    // added to the cache.
    SetParsedStyleSheetCache(nullptr);
    return;
  }
  SetParsedStyleSheetCache(sheet);
}

void CSSStyleSheetResource::SetDecodedSheetText(
    const String& decoded_sheet_text) {
  decoded_sheet_text_ = decoded_sheet_text;
  UpdateDecodedSize();
}

void CSSStyleSheetResource::UpdateDecodedSize() {
  size_t decoded_size = decoded_sheet_text_.CharactersSizeInBytes();
  if (parsed_style_sheet_cache_)
    decoded_size += parsed_style_sheet_cache_->EstimatedSizeInBytes();
  SetDecodedSize(decoded_size);
}

}  // namespace blink
```