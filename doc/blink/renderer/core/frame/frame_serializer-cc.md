Response:
The user wants a summary of the functionality of the `frame_serializer.cc` file in the Chromium Blink engine. They are also interested in how this file relates to JavaScript, HTML, and CSS. The request includes specific instructions for providing examples, logical reasoning (with assumptions), and common usage errors.

Here's a plan to address the user's request:

1. **Identify the core purpose:** Analyze the included headers, class names (e.g., `FrameSerializer`, `MultiResourcePacker`), and function names to determine the main goal of the file. It seems related to serializing the state of a frame.

2. **Break down the functionalities:** Examine the key classes and their methods to understand the different steps involved in the serialization process. Pay attention to how resources (HTML, CSS, images, fonts) are handled.

3. **Relate to web technologies:** Connect the observed functionalities to JavaScript, HTML, and CSS. For instance, how does the serializer handle `<script>` tags, CSS rules, or image resources?

4. **Provide examples:**  Illustrate the interactions with web technologies using concrete examples of HTML, CSS, and scenarios involving JavaScript.

5. **Infer logical reasoning:** Based on the code, make educated guesses about the input and output of certain processes within the file. Clearly state the assumptions made.

6. **Identify potential errors:** Think about common mistakes developers might make or edge cases that could lead to issues during serialization.

7. **Focus on the provided code snippet:** Since this is part 1 of 2, concentrate on the functionality exposed in this specific excerpt. The summary should reflect the operations visible here.

**Pre-computation/Analysis of the code:**

* **`FrameSerializer` class:**  Likely the main class responsible for orchestrating the serialization process.
* **`MultiResourcePacker` class:**  Manages the collection and storage of resources (HTML, CSS, images, fonts) needed for the serialized frame. It handles deduplication and asynchronous fetching of resources.
* **Resource handling:**  The code deals with various resource types (images, fonts, stylesheets) and their associated data. It appears to fetch resources and store them for later use.
* **Markup generation:** The `SerializerMarkupAccumulator` class suggests the generation of HTML markup representing the frame's structure.
* **CSS handling:**  The code interacts with CSS rules, stylesheets, and even adopted stylesheets. The presence of `MHTMLImprovementsEnabled()` suggests different approaches to CSS serialization.
* **Shadow DOM:** The code explicitly handles shadow DOM by encapsulating its content within `<template>` elements with special attributes.
* **Resource URLs:** The code maintains a set of `resource_urls_` to avoid duplicate inclusion of resources.
* **Skipping elements/attributes:** There's logic to ignore certain elements (e.g., `<script>`, `<noscript>`, hidden elements) and attributes (e.g., `srcset`, scripting attributes).

By following this plan and analyzing the code, I can generate a comprehensive summary of the `frame_serializer.cc` file's functionality as presented in this first part.
```
文件路径：blink/renderer/core/frame/frame_serializer.cc
功能概述（第1部分）：

这个文件 `frame_serializer.cc` 的主要功能是**将一个浏览器的帧（Frame）及其相关资源序列化为一种可以保存或传输的格式，特别是 MHTML (MIME HTML) 格式。**  它负责遍历帧的 DOM 树，提取必要的信息，并将 HTML 结构、CSS 样式、图片、字体等资源打包在一起。

**具体功能点 (基于提供的代码片段)：**

1. **资源管理和打包:**
   - 使用 `MultiResourcePacker` 类来管理需要序列化的资源（HTML、CSS、图片、字体等）。
   - 跟踪已添加的资源 URL，避免重复添加。
   - 提供添加主资源 (`AddMainResource`) 和其他资源 (`AddToResources`, `AddImageToResources`, `AddFontToResources`) 的方法。
   - 能够异步地获取资源 (`FetchAndAddResource`)，并使用 `ResourceWaiter` 等待资源加载完成。
   - 最终将所有序列化的资源组织成一个队列 (`Deque<SerializedResource>`)。

2. **HTML 结构序列化:**
   - 使用 `SerializerMarkupAccumulator` 类，这是一个继承自 `MarkupAccumulator` 的类，专门用于序列化 HTML 结构。
   -  `SerializerMarkupAccumulator` 负责遍历 DOM 树，生成 HTML 标记。
   -  在生成标记的过程中，会考虑以下因素：
      - **忽略特定元素:**  例如 `<script>`, `<noscript>`, 某些 `<meta>` 标签（如包含 CSP 指令的），隐藏的元素等。
      - **忽略特定属性:** 例如 `srcset`, `ping`, 包含 JavaScript 代码的属性等。
      - **自定义属性处理:**  例如，为 `<img>` 元素添加 `width` 和 `height` 属性，如果在高 DPR 设备上加载了不同的图片。
      - **Shadow DOM 处理:** 将 Shadow DOM 的内容包裹在 `<template>` 元素中，并添加 `shadowmode` 和 `shadowdelegatesfocus` 属性来表示 Shadow DOM 的模式。
      - **`<style>` 元素处理:**  根据 `MHTMLImprovementsEnabled()` 的状态，可能将 `<style>` 元素替换为指向序列化 CSS 资源的 `<link>` 元素，或者直接序列化 `<style>` 标签的内容。

3. **CSS 样式序列化:**
   - 代码中包含了对 CSS 规则 (`CSSStyleRule`, `CSSFontFaceRule`, `CSSImportRule`) 和样式表 (`CSSStyleSheet`) 的引用。
   -  `SerializeCSSResources` 函数（虽然没有在这个片段中完全展开，但被调用了）负责序列化 CSS 样式表。
   -  根据 `MHTMLImprovementsEnabled()` 的状态，处理内联的 `<style>` 标签和外部样式表。新的实现会尝试保留 `<style>` 标签，并在样式表被修改时才序列化其内容。

4. **资源 URL 处理:**
   -  `RewriteLink` 函数用于重写帧元素的 `srcdoc` 属性，将其内容替换为指向序列化内容的链接 (使用 `cid:` 协议)。
   -  创建伪造的 URL (`MakePseudoUrl`, `MakePseudoCSSUrl`) 用于表示序列化的 CSS 样式。

5. **配置和标志:**
   - 使用 `MHTMLImprovementsEnabled()` 函数来判断是否启用新的 MHTML 序列化改进功能，这会影响 `<style>` 标签和 adoptedStyleSheets 的处理方式。
   - `kPopupOverlayZIndexThreshold` 常量用于判断是否忽略 z-index 值高于某个阈值的浮层元素。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **HTML:** `FrameSerializer` 的核心任务就是序列化 HTML 结构。
    * **例子:** 当遇到一个 `<div>Hello</div>` 元素时，`SerializerMarkupAccumulator` 会生成相应的 `<div>Hello</div>` 字符串。
    * **例子:** 如果一个 `<img>` 标签有 `srcset` 属性，`WillProcessAttribute` 会阻止这个属性被序列化。
    * **例子:** 如果一个 `<template>` 元素关联了一个 Shadow DOM，`GetShadowTree` 会返回一个新的 `<template>` 元素，并带有 `shadowmode` 属性。

* **CSS:**  `FrameSerializer` 需要将页面的样式信息保存下来。
    * **例子:** 当遇到一个 `<style>` 标签时，如果 `MHTMLImprovementsEnabled()` 为 true 且样式表被修改过，`SerializeInlineCSSStyleSheet` 会将该样式表的内容序列化为一个 CSS 资源。
    * **例子:** 对于外部样式表 `<link rel="stylesheet" href="style.css">`, `MultiResourcePacker` 会尝试获取 `style.css` 的内容并作为单独的资源保存。
    * **例子:**  `AppendStylesheets` 函数（未完全展示）会将 CSS 规则添加到 `<head>` 标签中，通常以 `<link>` 标签的形式引用序列化的 CSS 资源。

* **JavaScript:**  `FrameSerializer` 通常会忽略或排除 JavaScript 代码，因为它在 MHTML 页面加载时不会执行。
    * **例子:** `<script>` 标签会被 `WillProcessElement` 忽略，不会被包含在序列化的 HTML 中。
    * **例子:**  HTML 元素的 `onclick` 等事件处理属性会被 `WillProcessAttribute` 忽略。

**逻辑推理与假设输入/输出:**

假设输入一个包含以下 HTML 的帧：

```html
<!DOCTYPE html>
<html>
<head>
  <title>Test Page</title>
  <link rel="stylesheet" href="style.css">
  <style>body { color: red; }</style>
</head>
<body>
  <img src="image.png" alt="An image">
  <div id="container">Hello</div>
  <script>console.log("This will be ignored");</script>
</body>
</html>
```

假设 `style.css` 的内容是 `body { background-color: blue; }`， `image.png` 是一个图片文件。

**输出 (简化描述):**

序列化后的 MHTML 文件将包含多个部分：

1. **主 HTML 部分:**  大致如下（可能因为 `MHTMLImprovementsEnabled()` 的状态而有所不同）：
   ```html
   <!DOCTYPE html>
   <html>
   <head>
     <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
     <title>Test Page</title>
     <link rel="stylesheet" type="text/css" href="cid:css-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx@mhtml.blink" />
     <style>/* 可能包含序列化的 body { color: red; } */</style>
   </head>
   <body>
     <img src="cid:image-yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy@mhtml.blink" alt="An image">
     <div id="container">Hello</div>
   </body>
   </html>
   ```
   -  `<link>` 标签指向序列化的 `style.css` 内容。
   -  `<img>` 标签的 `src` 属性被替换为指向序列化的 `image.png` 的 `cid:` URL。
   -  `<script>` 标签被移除。

2. **CSS 资源部分:**  包含 `style.css` 的内容，例如：
   ```
   body { background-color: blue; }
   ```

3. **图片资源部分:** 包含 `image.png` 的二进制数据。

**用户或编程常见的使用错误 (基于提供的代码片段):**

1. **忘记调用 `Finish()`:**  `MultiResourcePacker` 使用异步方式加载资源。如果在使用 `MultiResourcePacker` 后忘记调用 `Finish()` 方法并提供回调，则资源可能不会被全部加载和处理，导致最终的 MHTML 文件不完整。

2. **错误地假设资源已经同步加载:**  在添加资源后立即尝试访问其内容可能会导致错误，因为 `FetchAndAddResource` 是异步的。必须等待 `Finish()` 回调执行。

3. **在 `ShouldSkipResource` 中进行副作用操作:** `ShouldAddURL` 注释中提到 `ShouldSkipResource()` 有隐藏行为，会跟踪哪些资源被添加。如果开发者在 `ShouldSkipResource` 中进行其他重要的逻辑操作，可能会导致意外的行为，因为它可能会被多次调用。

4. **假设所有 CSS 都会被完美序列化:** CSS 序列化可能存在一些边缘情况或不完全支持的特性。依赖于复杂的 CSS 特性可能导致序列化后的页面样式与原始页面略有不同。

**总结一下它的功能 (针对第 1 部分):**

`frame_serializer.cc` (提供的第 1 部分代码) 的核心功能是**为将浏览器帧的内容序列化为 MHTML 格式做准备，主要负责管理和组织需要包含在 MHTML 文件中的各种资源（HTML 结构、CSS 样式、图片等），并提供了初步的 HTML 结构序列化能力，能够根据配置和策略选择性地包含或排除特定的 HTML 元素和属性。**  它定义了如何收集、获取和准备这些资源，为后续的 MHTML 文件生成奠定了基础。  代码中也体现了对性能和资源去重的考虑。
```

Prompt: 
```
这是目录为blink/renderer/core/frame/frame_serializer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/frame/frame_serializer.h"

#include <optional>

#include "base/metrics/histogram_functions.h"
#include "base/timer/elapsed_timer.h"
#include "services/network/public/cpp/resource_request.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/web/web_frame_serializer.h"
#include "third_party/blink/renderer/core/css/css_font_face_rule.h"
#include "third_party/blink/renderer/core/css/css_font_face_src_value.h"
#include "third_party/blink/renderer/core/css/css_image_value.h"
#include "third_party/blink/renderer/core/css/css_import_rule.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_rule_list.h"
#include "third_party/blink/renderer/core/css/css_style_declaration.h"
#include "third_party/blink/renderer/core/css/css_style_rule.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/style_rule.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/attribute.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/serializers/markup_accumulator.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/custom/custom_element.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_registry.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_frame_element_base.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_image_loader.h"
#include "third_party/blink/renderer/core/html/html_link_element.h"
#include "third_party/blink/renderer/core/html/html_meta_element.h"
#include "third_party/blink/renderer/core/html/html_no_script_element.h"
#include "third_party/blink/renderer/core/html/html_picture_element.h"
#include "third_party/blink/renderer/core/html/html_plugin_element.h"
#include "third_party/blink/renderer/core/html/html_script_element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/html/html_template_element.h"
#include "third_party/blink/renderer/core/html/image_document.h"
#include "third_party/blink/renderer/core/html/link_rel_attribute.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/loader/resource/font_resource.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource_content.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/style/style_fetched_image.h"
#include "third_party/blink/renderer/core/style/style_image.h"
#include "third_party/blink/renderer/core/svg/svg_image_element.h"
#include "third_party/blink/renderer/platform/graphics/image.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_hash_set.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_parameters.h"
#include "third_party/blink/renderer/platform/loader/fetch/raw_resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/mhtml/mhtml_parser.h"
#include "third_party/blink/renderer/platform/mhtml/serialized_resource.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/uuid.h"

namespace blink {

namespace internal {
// TODO(crbug.com/363289333): Try to add this functionality to wtf::String.
String ReplaceAllCaseInsensitive(
    String source,
    const String& from,
    base::FunctionRef<String(const String&)> transform) {
  size_t offset = 0;
  size_t pos;
  StringBuilder builder;
  for (;;) {
    pos = source.Find(from, offset,
                      TextCaseSensitivity::kTextCaseASCIIInsensitive);
    if (pos == kNotFound) {
      break;
    }
    builder.Append(source.Substring(offset, pos - offset));
    builder.Append(transform(source.Substring(pos, from.length())));
    offset = pos + from.length();
  }
  if (builder.empty()) {
    return source;
  }
  builder.Append(source.Substring(offset));
  return builder.ToString();
}
}  // namespace internal

namespace {

const int kPopupOverlayZIndexThreshold = 50;
// Note that this is *not* the open web's declarative shadow DOM attribute,
// which is <template shadowrootmode>. This is a special attribute used by
// MHTML archive files to represent shadow roots.
const char kShadowModeAttributeName[] = "shadowmode";
const char kShadowDelegatesFocusAttributeName[] = "shadowdelegatesfocus";

using mojom::blink::FormControlType;

KURL MakePseudoUrl(StringView type) {
  StringBuilder pseudo_sheet_url_builder;
  pseudo_sheet_url_builder.Append("cid:");
  pseudo_sheet_url_builder.Append(type);
  pseudo_sheet_url_builder.Append("-");
  pseudo_sheet_url_builder.Append(WTF::CreateCanonicalUUIDString());
  pseudo_sheet_url_builder.Append("@mhtml.blink");
  return KURL(pseudo_sheet_url_builder.ToString());
}

KURL MakePseudoCSSUrl() {
  return MakePseudoUrl("css");
}

void AppendLinkElement(StringBuilder& markup, const KURL& url) {
  markup.Append(R"(<link rel="stylesheet" type="text/css" href=")");
  markup.Append(url.GetString());
  markup.Append("\" />");
}

// There are several improvements being added behind this flag. So far, it
// covers:
// * Serialize adopted stylesheets
// * Serialize styleSheets on shadow roots
// * Retain stylesheet order, previously order of stylesheets
//   was sometimes wrong.
// * Serialize <style> nodes as <style> nodes instead of <link> nodes.
// * Leave <style> nodes alone if their stylesheet is unmodified.
// * Injects a script into the serialized HTML to define custom elements to
//   ensure the same custom element names are defined.
// * Fonts are fetched.
bool MHTMLImprovementsEnabled() {
  return base::FeatureList::IsEnabled(blink::features::kMHTML_Improvements);
}

class MultiResourcePacker;

// A `RawResourceClient` that waits for the resource to load.
class ResourceWaiter : public GarbageCollected<ResourceWaiter>,
                       public RawResourceClient {
 public:
  explicit ResourceWaiter(MultiResourcePacker* packer,
                          mojom::blink::RequestContextType context_type)
      : packer_(packer), context_type_(context_type) {}

  void NotifyFinished(Resource* resource) override;

  void Trace(Visitor* visitor) const override;

  std::optional<SerializedResource> TakeResource() {
    return std::move(serialized_resource_);
  }

  String DebugName() const override { return "FrameSerializerResourceWaiter"; }

 private:
  Member<MultiResourcePacker> packer_;
  std::optional<SerializedResource> serialized_resource_;
  mojom::blink::RequestContextType context_type_;
};

// Stores the list of serialized resources which constitute the frame. The
// first resource should be the frame's content (usually HTML).
class MultiResourcePacker : public GarbageCollected<MultiResourcePacker> {
 public:
  explicit MultiResourcePacker(
      WebFrameSerializer::MHTMLPartsGenerationDelegate* web_delegate)
      : web_delegate_(web_delegate) {}

  void Trace(Visitor* visitor) const { visitor->Trace(resource_waiters_); }

  bool HasResource(const KURL& url) const {
    return resource_urls_.Contains(url);
  }

  void AddMainResource(const String& mime_type,
                       scoped_refptr<const SharedBuffer> data,
                       const KURL& url) {
    // The main resource must be first.
    // We do not call `ShouldAddURL()` for the main resource.
    resources_.emplace_front(
        SerializedResource(url, mime_type, std::move(data)));
  }

  void AddToResources(SerializedResource serialized_resource) {
    resources_.push_back(std::move(serialized_resource));
  }

  void AddToResources(const String& mime_type,
                      scoped_refptr<const SharedBuffer> data,
                      const KURL& url) {
    if (!data) {
      DLOG(ERROR) << "No data for resource " << url.GetString();
      return;
    }
    CHECK(resource_urls_.Contains(url))
        << "ShouldAddURL() not called before AddToResources";
    resources_.emplace_front(
        SerializedResource(url, mime_type, std::move(data)));
  }

  void AddImageToResources(ImageResourceContent* image, const KURL& url) {
    if (!image || !image->HasImage() || image->ErrorOccurred() ||
        !ShouldAddURL(url)) {
      return;
    }

    TRACE_EVENT2("page-serialization", "FrameSerializer::addImageToResources",
                 "type", "image", "url", url.ElidedString().Utf8());
    AddToResources(image->GetResponse().MimeType(), image->GetImage()->Data(),
                   url);
  }

  // Returns whether the resource for `url` should be added. This will return
  // true only once for a `url`, because we only want to store each resource
  // once.
  bool ShouldAddURL(const KURL& url) {
    bool should_add = url.IsValid() && !resource_urls_.Contains(url) &&
                      !url.ProtocolIsData() &&
                      !web_delegate_->ShouldSkipResource(url);
    if (should_add) {
      // Make sure that `ShouldAddURL()` returns true only once for any given
      // URL. This is done because `ShouldSkipResource()` has the hidden
      // behavior of tracking which resources are being added. This is why we
      // must call it only once per url.
      resource_urls_.insert(url);
    }
    return should_add;
  }

  void OldAddFontToResources(FontResource& font) {
    if (!font.IsLoaded() || !font.ResourceBuffer()) {
      return;
    }
    if (!ShouldAddURL(font.Url())) {
      return;
    }

    AddToResources(font.GetResponse().MimeType(), font.ResourceBuffer(),
                   font.Url());
  }

  // Fetch `url` and add it to the list of resources. Only adds the resource if
  // `ShouldAddURL()` returns true. The resource is fetched async, and won't be
  // available until after `Finish()` completes. If the fetch fails, no resource
  // is added.
  void FetchAndAddResource(Document& document,
                           const KURL& url,
                           mojom::blink::RequestContextType context_type,
                           mojom::blink::FetchCacheMode fetch_cache_mode) {
    if (!ShouldAddURL(url)) {
      return;
    }
    // Add a resource entry pointing to the new `ResourceWaiter`.
    ResourceEntry entry;
    entry.waiter_index = resource_waiters_.size();
    resources_.push_back(std::move(entry));

    // Start fetching the resource data.
    ResourceLoaderOptions loader_options(
        document.GetExecutionContext()->GetCurrentWorld());
    ResourceRequest request(url);
    request.SetCacheMode(fetch_cache_mode);
    request.SetRequestContext(context_type);
    FetchParameters fetch_params(std::move(request), loader_options);
    auto* waiter = MakeGarbageCollected<ResourceWaiter>(this, context_type);
    RawResource::Fetch(fetch_params, document.Fetcher(), waiter);
    resource_waiters_.push_back(waiter);
  }

  void AddFontToResources(Document& document, FontResource& font) {
    if (!MHTMLImprovementsEnabled()) {
      OldAddFontToResources(font);
      return;
    }

    // Check if the font is loaded. Loaded fonts may not have raw resource data,
    // so we ignore `font.ResourceBuffer()`.
    if (!font.GetCustomFontData()) {
      return;
    }

    // MHTML serialization is run frequently on Android Chrome to save pages
    // after they are loaded, so that they can be restored later without an
    // internet connection. `kForceCache` avoids adding additional network
    // requests that could impact performance. If a font isn't cached, the
    // fallback font is typically usable.
    FetchAndAddResource(document, font.Url(),
                        mojom::blink::RequestContextType::FONT,
                        mojom::blink::FetchCacheMode::kForceCache);
  }

  void Finish(base::OnceCallback<void(Deque<SerializedResource>)>
                  resources_ready_callback) {
    resources_ready_callback_ = std::move(resources_ready_callback);
    finished_ = true;
    CallReadyIfFinished();
  }

  void ResourceFetchComplete() {
    ++resource_done_count_;
    CallReadyIfFinished();
  }

 private:
  struct ResourceEntry {
    ResourceEntry() = default;
    explicit ResourceEntry(std::optional<SerializedResource> r)
        : resource(std::move(r)) {}

    // The serialized resource. May be nullopt for resources loaded
    // asynchronously.
    std::optional<SerializedResource> resource;
    // For asynchronously loaded resources, this is the index into
    // `resource_waiters_`.
    std::optional<wtf_size_t> waiter_index;
  };

  void CallReadyIfFinished() {
    if (finished_ && resource_done_count_ == resource_waiters_.size()) {
      Deque<SerializedResource> resources;
      for (ResourceEntry& entry : resources_) {
        if (entry.waiter_index) {
          entry.resource =
              resource_waiters_[*entry.waiter_index]->TakeResource();
        }
        if (entry.resource) {
          resources.push_back(std::move(*entry.resource));
        }
      }
      resources_.clear();
      base::UmaHistogramTimes("PageSerialization.Mhtml.FrameSerializerTime",
                              timer_.Elapsed());
      std::move(resources_ready_callback_).Run(std::move(resources));
    }
  }

  base::ElapsedTimer timer_;
  // This hashset is only used for de-duplicating resources to be serialized.
  HashSet<KURL> resource_urls_;
  Deque<ResourceEntry> resources_;
  WebFrameSerializer::MHTMLPartsGenerationDelegate* web_delegate_;
  // Whether `Finish()` has been called.
  bool finished_ = false;
  // Number of `ResourceWaiter`s that have completed.
  wtf_size_t resource_done_count_ = 0;
  HeapVector<Member<ResourceWaiter>> resource_waiters_;
  base::OnceCallback<void(Deque<SerializedResource>)> resources_ready_callback_;
};

void ResourceWaiter::Trace(Visitor* visitor) const {
  RawResourceClient::Trace(visitor);
  visitor->Trace(packer_);
}

void ResourceWaiter::NotifyFinished(Resource* resource) {
  bool fetched = !resource->ErrorOccurred() && resource->ResourceBuffer();
  if (fetched) {
    serialized_resource_ =
        SerializedResource(resource->Url(), resource->GetResponse().MimeType(),
                           resource->ResourceBuffer());
  }
  if (context_type_ == mojom::blink::RequestContextType::FONT) {
    base::UmaHistogramBoolean("PageSerialization.Mhtml.Fetched.Font", fetched);
  } else if (context_type_ == mojom::blink::RequestContextType::STYLE) {
    base::UmaHistogramBoolean("PageSerialization.Mhtml.Fetched.Style", fetched);
  }
  packer_->ResourceFetchComplete();
  resource->RemoveClient(this);
}

class SerializerMarkupAccumulator : public MarkupAccumulator {
  STACK_ALLOCATED();

 public:
  SerializerMarkupAccumulator(
      MultiResourcePacker* resource_serializer,
      WebFrameSerializer::MHTMLPartsGenerationDelegate* web_delegate,
      Document& document)
      : MarkupAccumulator(kResolveAllURLs,
                          IsA<HTMLDocument>(document) ? SerializationType::kHTML
                                                      : SerializationType::kXML,
                          ShadowRootInclusion()),
        resource_serializer_(resource_serializer),
        web_delegate_(web_delegate),
        document_(&document) {}
  ~SerializerMarkupAccumulator() override = default;

 private:
  bool ShouldIgnoreHiddenElement(const Element& element) const {
    // If an iframe is in the head, it will be moved to the body when the page
    // is being loaded. But if an iframe is injected into the head later, it
    // will stay there and not been displayed. To prevent it from being brought
    // to the saved page and cause it being displayed, we should not include it.
    if (IsA<HTMLIFrameElement>(element) &&
        Traversal<HTMLHeadElement>::FirstAncestor(element)) {
      return true;
    }

    // Do not include the element that is marked with hidden attribute.
    if (element.FastHasAttribute(html_names::kHiddenAttr)) {
      return true;
    }

    // Do not include the hidden form element.
    auto* html_element_element = DynamicTo<HTMLInputElement>(&element);
    return html_element_element && html_element_element->FormControlType() ==
                                       FormControlType::kInputHidden;
  }

  bool ShouldIgnoreMetaElement(const Element& element) const {
    // Do not include meta elements that declare Content-Security-Policy
    // directives. They should have already been enforced when the original
    // document is loaded. Since only the rendered resources are encapsulated in
    // the saved MHTML page, there is no need to carry the directives. If they
    // are still kept in the MHTML, child frames that are referred to using cid:
    // scheme could be prevented from loading.
    if (!IsA<HTMLMetaElement>(element)) {
      return false;
    }
    if (!element.FastHasAttribute(html_names::kContentAttr)) {
      return false;
    }
    const AtomicString& http_equiv =
        element.FastGetAttribute(html_names::kHttpEquivAttr);
    return http_equiv == "Content-Security-Policy";
  }

  bool ShouldIgnorePopupOverlayElement(const Element& element) const {
    // The element should be visible.
    LayoutBox* box = element.GetLayoutBox();
    if (!box) {
      return false;
    }

    // The bounding box of the element should contain center point of the
    // viewport.
    LocalDOMWindow* window = element.GetDocument().domWindow();
    DCHECK(window);
    int center_x = window->innerWidth() / 2;
    int center_y = window->innerHeight() / 2;
    if (Page* page = element.GetDocument().GetPage()) {
      center_x = page->GetChromeClient().WindowToViewportScalar(
          window->GetFrame(), center_x);
      center_y = page->GetChromeClient().WindowToViewportScalar(
          window->GetFrame(), center_y);
    }
    if (!PhysicalRect(box->PhysicalLocation(), box->Size())
             .Contains(LayoutUnit(center_x), LayoutUnit(center_y))) {
      return false;
    }

    // The z-index should be greater than the threshold.
    if (box->Style()->EffectiveZIndex() < kPopupOverlayZIndexThreshold) {
      return false;
    }

    popup_overlays_skipped_ = true;

    return true;
  }

  EmitAttributeChoice WillProcessAttribute(
      const Element& element,
      const Attribute& attribute) const override {
    // TODO(fgorski): Presence of srcset attribute causes MHTML to not display
    // images, as only the value of src is pulled into the archive. Discarding
    // srcset prevents the problem. Long term we should make sure to MHTML plays
    // nicely with srcset.
    if (IsA<HTMLImageElement>(element) &&
        (attribute.LocalName() == html_names::kSrcsetAttr ||
         attribute.LocalName() == html_names::kSizesAttr)) {
      return EmitAttributeChoice::kIgnore;
    }

    // Do not save ping attribute since anyway the ping will be blocked from
    // MHTML.
    // TODO(crbug.com/369219144): Should this be IsA<HTMLAnchorElementBase>?
    if (IsA<HTMLAnchorElement>(element) &&
        attribute.LocalName() == html_names::kPingAttr) {
      return EmitAttributeChoice::kIgnore;
    }

    // The special attribute in a template element to denote the shadow DOM
    // should only be generated from MHTML serialization. If it is found in the
    // original page, it should be ignored.
    if (IsA<HTMLTemplateElement>(element) &&
        (attribute.LocalName() == kShadowModeAttributeName ||
         attribute.LocalName() == kShadowDelegatesFocusAttributeName) &&
        !shadow_template_elements_.Contains(&element)) {
      return EmitAttributeChoice::kIgnore;
    }

    // If srcdoc attribute for frame elements will be rewritten as src attribute
    // containing link instead of html contents, don't ignore the attribute.
    // Bail out now to avoid the check in Element::isScriptingAttribute.
    bool is_src_doc_attribute = IsA<HTMLFrameElementBase>(element) &&
                                attribute.GetName() == html_names::kSrcdocAttr;
    String new_link_for_the_element;
    if (is_src_doc_attribute &&
        RewriteLink(element, new_link_for_the_element)) {
      return EmitAttributeChoice::kEmit;
    }

    //  Drop integrity attribute for those links with subresource loaded.
    auto* html_link_element = DynamicTo<HTMLLinkElement>(element);
    if (attribute.LocalName() == html_names::kIntegrityAttr &&
        html_link_element && html_link_element->sheet()) {
      return EmitAttributeChoice::kIgnore;
    }

    // Do not include attributes that contain javascript. This is because the
    // script will not be executed when a MHTML page is being loaded.
    if (element.IsScriptingAttribute(attribute)) {
      return EmitAttributeChoice::kIgnore;
    }
    return EmitAttributeChoice::kEmit;
  }

  bool RewriteLink(const Element& element, String& rewritten_link) const {
    auto* frame_owner = DynamicTo<HTMLFrameOwnerElement>(element);
    if (!frame_owner) {
      return false;
    }

    Frame* frame = frame_owner->ContentFrame();
    if (!frame) {
      return false;
    }

    KURL cid_uri = MHTMLParser::ConvertContentIDToURI(
        FrameSerializer::GetContentID(frame));
    DCHECK(cid_uri.IsValid());
    rewritten_link = cid_uri.GetString();
    return true;
  }

  Vector<Attribute> GetCustomAttributes(const Element& element) {
    Vector<Attribute> attributes;

    if (auto* image = DynamicTo<HTMLImageElement>(element)) {
      GetCustomAttributesForImageElement(*image, &attributes);
    }

    return attributes;
  }

  void GetCustomAttributesForImageElement(const HTMLImageElement& element,
                                          Vector<Attribute>* attributes) {
    // Currently only the value of src is pulled into the archive and the srcset
    // attribute is ignored (see shouldIgnoreAttribute() above). If the device
    // has a higher DPR, a different image from srcset could be loaded instead.
    // When this occurs, we should provide the rendering width and height for
    // <img> element if not set.

    // The image should be loaded and participate the layout.
    ImageResourceContent* image = element.CachedImage();
    if (!image || !image->HasImage() || image->ErrorOccurred() ||
        !element.GetLayoutObject()) {
      return;
    }

    // The width and height attributes should not be set.
    if (element.FastHasAttribute(html_names::kWidthAttr) ||
        element.FastHasAttribute(html_names::kHeightAttr)) {
      return;
    }

    // Check if different image is loaded. naturalWidth/naturalHeight will
    // return the image size adjusted with current DPR.
    if ((static_cast<int>(element.naturalWidth())) ==
            image->GetImage()->width() &&
        (static_cast<int>(element.naturalHeight())) ==
            image->GetImage()->height()) {
      return;
    }

    Attribute width_attribute(html_names::kWidthAttr,
                              AtomicString::Number(element.LayoutBoxWidth()));
    attributes->push_back(width_attribute);
    Attribute height_attribute(html_names::kHeightAttr,
                               AtomicString::Number(element.LayoutBoxHeight()));
    attributes->push_back(height_attribute);
  }

  std::pair<ShadowRoot*, HTMLTemplateElement*> GetShadowTree(
      const Element& element) const override {
    ShadowRoot* shadow_root = element.GetShadowRoot();
    if (!shadow_root || shadow_root->GetMode() == ShadowRootMode::kUserAgent) {
      return std::pair<ShadowRoot*, HTMLTemplateElement*>();
    }

    // Put the shadow DOM content inside a template element. A special attribute
    // is set to tell the mode of the shadow DOM.
    HTMLTemplateElement* template_element =
        MakeGarbageCollected<HTMLTemplateElement>(element.GetDocument());
    template_element->setAttribute(
        QualifiedName(AtomicString(kShadowModeAttributeName)),
        AtomicString(shadow_root->GetMode() == ShadowRootMode::kOpen
                         ? "open"
                         : "closed"));
    if (shadow_root->delegatesFocus()) {
      template_element->setAttribute(
          QualifiedName(AtomicString(kShadowDelegatesFocusAttributeName)),
          g_empty_atom);
    }
    shadow_template_elements_.insert(template_element);

    return std::pair<ShadowRoot*, HTMLTemplateElement*>(shadow_root,
                                                        template_element);
  }

  void AppendCustomAttributes(const Element& element) override {
    Vector<Attribute> attributes = GetCustomAttributes(element);
    for (const auto& attribute : attributes) {
      AppendAttribute(element, attribute);
    }
  }

  EmitElementChoice WillProcessElement(const Element& element) override {
    if (IsA<HTMLScriptElement>(element)) {
      return EmitElementChoice::kIgnore;
    }
    if (IsA<HTMLNoScriptElement>(element)) {
      return EmitElementChoice::kIgnore;
    }
    auto* meta = DynamicTo<HTMLMetaElement>(element);
    if (meta && meta->ComputeEncoding().IsValid()) {
      return EmitElementChoice::kIgnore;
    }

    if (MHTMLImprovementsEnabled()) {
      // When `MHTMLImprovementsEnabled()`, we replace <style> with a <link> to
      // the serialized style sheet.
      if (const HTMLStyleElement* style_element =
              DynamicTo<HTMLStyleElement>(element)) {
        CSSStyleSheet* sheet = style_element->sheet();
        if (sheet) {
          // JS may update styles programmatically for a <style> node. We detect
          // whether this has happened, and serialize the stylesheet if it has.
          // Otherwise, we leave the <style> node unmodified. Because CSS
          // serialization isn't perfect, it's better to leave the original
          // <style> element if possible.
          SerializeCSSResources(*sheet);
          if (!sheet->Contents()->IsMutable()) {
            return EmitElementChoice::kEmit;
          } else {
            style_elements_to_replace_contents_.insert(style_element);
            return EmitElementChoice::kEmitButIgnoreChildren;
          }
        }
      }
    } else {
      // A <link> element is inserted in `AppendExtraForHeadElement()` as a
      // substitute for this element.
      if (IsA<HTMLStyleElement>(element)) {
        return EmitElementChoice::kIgnore;
      }
    }

    if (ShouldIgnoreHiddenElement(element)) {
      return EmitElementChoice::kIgnore;
    }
    if (ShouldIgnoreMetaElement(element)) {
      return EmitElementChoice::kIgnore;
    }
    if (web_delegate_->RemovePopupOverlay() &&
        ShouldIgnorePopupOverlayElement(element)) {
      return EmitElementChoice::kIgnore;
    }
    // Remove <link> for stylesheets that do not load.
    auto* html_link_element = DynamicTo<HTMLLinkElement>(element);
    if (html_link_element && html_link_element->RelAttribute().IsStyleSheet() &&
        !html_link_element->sheet()) {
      return EmitElementChoice::kIgnore;
    }
    return MarkupAccumulator::WillProcessElement(element);
  }

  void WillCloseSyntheticTemplateElement(ShadowRoot& auxiliary_tree) override {
    if (MHTMLImprovementsEnabled()) {
      AppendAdoptedStyleSheets(&auxiliary_tree);
    }
  }

  AtomicString AppendElement(const Element& element) override {
    AtomicString prefix = MarkupAccumulator::AppendElement(element);

    if (IsA<HTMLHeadElement>(element)) {
      AppendExtraForHeadElement(element);
    }
    AddResourceForElement(*document_, element);

    // FIXME: For object (plugins) tags and video tag we could replace them by
    // an image of their current contents.

    return prefix;
  }

  void AppendEndTag(const Element& element,
                    const AtomicString& prefix) override {
    if (MHTMLImprovementsEnabled()) {
      // Add adopted stylesheets to the very end of the document, so they
      // processed after other stylesheets.
      if (IsA<HTMLHtmlElement>(element)) {
        AppendAdoptedStyleSheets(document_);
      }

      if (const HTMLStyleElement* style_element =
              DynamicTo<HTMLStyleElement>(element)) {
        if (style_elements_to_replace_contents_.Contains(style_element)) {
          CSSStyleSheet* sheet = style_element->sheet();
          markup_.Append(SerializeInlineCSSStyleSheet(*sheet));
        }
      }
    }
    MarkupAccumulator::AppendEndTag(element, prefix);
  }

  void AppendExtraForHeadElement(const Element& element) {
    DCHECK(IsA<HTMLHeadElement>(element));

    // TODO(tiger): Refactor MarkupAccumulator so it is easier to append an
    // element like this, without special cases for XHTML
    markup_.Append("<meta http-equiv=\"Content-Type\" content=\"");
    AppendAttributeValue(document_->SuggestedMIMEType());
    markup_.Append("; charset=");
    AppendAttributeValue(document_->characterSet());
    if (document_->IsXHTMLDocument()) {
      markup_.Append("\" />");
    } else {
      markup_.Append("\">");
    }

    // The CSS rules of a style element can be updated dynamically independent
    // of the CSS text included in the style element. So we can't use the inline
    // CSS text defined in the style element. To solve this, we serialize the
    // working CSS rules in document.stylesheets and document.adoptedStyleSheets
    // and wrap them in link elements.
    // Adopted stylesheets are evaluated last, so we append them last.
    if (!MHTMLImprovementsEnabled()) {
      AppendStylesheets(do
"""


```