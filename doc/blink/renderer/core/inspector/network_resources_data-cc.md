Response:
Let's break down the thought process for analyzing this C++ source code.

1. **Understand the Goal:** The primary goal is to understand the functionality of `network_resources_data.cc`, its relationship to web technologies (JavaScript, HTML, CSS), provide examples, explain logic, and highlight potential user/programmer errors.

2. **High-Level Overview:**  First, quickly scan the file for keywords, class names, and comments. Keywords like "inspector," "network," "resource," "data," "XHR," "content," "size," and "evict" immediately give a strong indication that this file is involved in collecting and managing data related to network requests made by a web page, likely for debugging and inspection purposes. The `blink::inspector` namespace confirms this.

3. **Identify Key Classes:** Notice the major classes: `XHRReplayData` and `NetworkResourcesData`. `ResourceData` is an inner class of `NetworkResourcesData`. This suggests a hierarchical structure for managing request information.

4. **Focus on `NetworkResourcesData`:** This appears to be the central class. Its constructor takes size limits, hinting at resource management. Its methods like `ResourceCreated`, `ResponseReceived`, `SetResourceType`, `SetResourceContent`, `MaybeAddResourceData`, and `MaybeDecodeDataToContent` clearly indicate its role in tracking and storing details about network requests.

5. **Examine `ResourceData`:**  This class holds the information for a *single* network request. It stores the request ID, loader ID, URL, content, headers, status code, and more. The presence of `xhr_replay_data_` suggests support for replaying XHR requests. Methods like `SetContent`, `AppendData`, `DecodeDataToContent`, and `EvictContent` show how the resource data is managed.

6. **Analyze Functionality by Method Group:**  Group related methods to understand specific functionalities:

    * **Resource Tracking:** `ResourceCreated`, `ResponseReceived`, `SetResourceType`, `AddResource`. These methods are called as network requests progress, storing metadata.
    * **Content Management:** `SetResourceContent`, `MaybeAddResourceData`, `MaybeDecodeDataToContent`, `EvictContent`, `ContentSize`, `RemoveResponseContent`. These deal with storing the actual content of the responses. The size limits and eviction logic are important here.
    * **XHR Handling:** `XHRReplayData` class and the `SetXHRReplayData` method indicate the file's involvement in capturing data for replaying XHR requests.
    * **Data Access:**  `Data`, `XhrReplayData`, `Resources`. These methods provide ways to retrieve the collected information.
    * **Cleanup/Management:** `Clear`, `SetResourcesDataSizeLimits`. These handle clearing out old data and setting size constraints.

7. **Connect to Web Technologies:** Now, think about how these functionalities relate to JavaScript, HTML, and CSS:

    * **JavaScript (XHR/Fetch):** The `XHRReplayData` class and the methods dealing with request and response data directly link to JavaScript's `XMLHttpRequest` and `fetch` API calls. The recorded data can be used to debug or replay these requests.
    * **HTML:** When the browser fetches an HTML document, the data is captured. Resources linked in the HTML (images, scripts, stylesheets) will also be tracked.
    * **CSS:** Similar to HTML, CSS files fetched by the browser will have their data managed by this code.

8. **Provide Concrete Examples:** Based on the analysis, create specific examples of how this code interacts with web content:

    * **JavaScript:** Show how an XHR request's URL, headers, and response could be stored.
    * **HTML:**  Illustrate how the data of the main HTML document and its linked resources are tracked.
    * **CSS:**  Demonstrate the capture of CSS content.

9. **Explain Logic and Reasoning:** Focus on non-trivial logic, like the resource content size limits and the eviction policy.

    * **Hypothetical Input/Output (Eviction):**  Create a scenario where adding a new resource triggers the eviction of an older one due to size limits.

10. **Identify Potential Errors:** Think about common mistakes developers might make that could interact with this code:

    * **Incorrect Content Type:**  If the server sends an incorrect `Content-Type` header, Blink might misinterpret the content.
    * **Large Resources:**  Downloading very large resources can exceed the configured size limits, leading to data loss or eviction.
    * **CORS Issues:** While this code doesn't directly *cause* CORS issues, the captured data is valuable for debugging them.

11. **Structure and Refine:** Organize the findings into logical sections (Functionality, Relation to Web Tech, Examples, Logic, Errors). Use clear and concise language. Ensure the explanations are easy to understand for someone with a basic understanding of web development and some familiarity with C++.

12. **Review and Iterate:**  Read through the entire explanation to ensure accuracy, clarity, and completeness. Are there any ambiguities? Are the examples clear?  Is the logic well-explained?  (Self-correction is important here). For instance, initially, I might just say "manages network requests."  But refining it to "collecting and managing *data* related to network requests *for debugging and inspection purposes*" is much more precise.

By following this structured thought process, one can effectively analyze and explain the functionality of complex source code like this Chromium file. The key is to start with a high-level understanding, dive into the details, connect the code to its purpose in the larger system (the web browser), and then illustrate those connections with concrete examples and potential pitfalls.
这个C++源文件 `blink/renderer/core/inspector/network_resources_data.cc` 的主要功能是**管理和存储通过网络加载的资源的相关数据，用于Chrome开发者工具 (Inspector) 的网络面板显示和分析。** 它充当了一个内存中的数据库，记录了每个网络请求的详细信息，包括请求头、响应头、内容、时间戳等等。

**以下是其具体功能列表：**

1. **存储资源元数据：**
   - 记录每个网络请求的唯一 ID (`request_id`) 和加载器 ID (`loader_id`)。
   - 存储请求的 URL (`requested_url`) 和方法 (例如 GET, POST)。
   - 保存请求和响应的头部信息。
   - 记录资源的类型 (`type_`)，例如文档、脚本、样式表、图片等。
   - 存储 HTTP 状态码 (`http_status_code_`)。
   - 记录原始头部的大小 (`raw_header_size_`)。
   - 保存请求是否包含凭据 (`include_credentials_`)。

2. **存储资源内容：**
   - 可以存储资源的文本内容 (`content_`) 或二进制数据 (`data_buffer_`)。
   - 标记内容是否以 Base64 编码 (`base64_encoded_`)。
   - 跟踪已下载文件 Blob (`downloaded_file_blob_`)。
   - 提供机制来延迟解码数据为文本内容 (`DecodeDataToContent`)。
   - 支持在内存不足时驱逐 (evict) 资源内容 (`EvictContent`)，以控制内存使用。

3. **支持 XHR 重放：**
   - 存储重放 XMLHttpRequest (XHR) 请求所需的数据 (`XHRReplayData`)，包括方法、URL、是否异步以及自定义头部。

4. **关联缓存资源：**
   - 可以关联网络资源与 Blink 的缓存系统中的 `Resource` 对象 (`cached_resource_`)，以便在资源被缓存清除时做出反应。

5. **管理内存使用：**
   - 设置了总的资源内容大小限制 (`maximum_resources_content_size_`) 和单个资源内容大小限制 (`maximum_single_resource_content_size_`)。
   - 使用一个双端队列 (`request_ids_deque_`) 来维护资源请求的顺序，以便在达到内存限制时驱逐最老的资源。

6. **提供数据访问接口：**
   - 提供方法来获取特定请求的资源数据 (`Data`)。
   - 提供方法来获取所有已存储的资源数据 (`Resources`)。

7. **处理字体资源：**
   - 特殊处理字体资源，在字体资源数据即将被清除时保存其数据。

**与 JavaScript, HTML, CSS 的功能关系及举例说明：**

这个文件虽然是 C++ 代码，但它直接服务于开发者工具的网络面板，而网络面板展示的是与 JavaScript、HTML 和 CSS 息息相关的网络活动。

* **JavaScript (通过 XHR/Fetch API 发起的请求):**
    - **功能关系：** 当 JavaScript 代码使用 `XMLHttpRequest` 或 `fetch` API 发起网络请求时，`NetworkResourcesData` 会记录这些请求的详细信息。
    - **举例说明：**
        ```javascript
        // JavaScript 代码发起一个 GET 请求
        fetch('https://example.com/api/data')
          .then(response => response.json())
          .then(data => console.log(data));

        // JavaScript 代码发起一个 POST 请求
        fetch('https://example.com/submit', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ key: 'value' })
        });
        ```
        对于上述 JavaScript 代码，`NetworkResourcesData` 会记录请求的 URL (`https://example.com/api/data`, `https://example.com/submit`)，请求方法 (`GET`, `POST`)，请求头 (`Content-Type` 等)，以及服务器返回的响应头和响应体 (如果未被驱逐)。  `XHRReplayData` 尤其用于存储重放这些 XHR 请求所需的信息。

* **HTML (加载文档和相关资源):**
    - **功能关系：** 当浏览器加载 HTML 页面时，`NetworkResourcesData` 会记录主文档以及页面中引用的其他资源 (例如图片、脚本、样式表) 的加载信息。
    - **举例说明：**
        ```html
        <!DOCTYPE html>
        <html>
        <head>
          <title>示例页面</title>
          <link rel="stylesheet" href="style.css">
        </head>
        <body>
          <img src="image.png" alt="示例图片">
          <script src="script.js"></script>
        </body>
        </html>
        ```
        对于这个 HTML 页面，`NetworkResourcesData` 会记录对 `style.css`、`image.png` 和 `script.js` 的请求和响应信息，包括各自的 URL、MIME 类型、状态码和内容。主 HTML 文档本身也会被记录。

* **CSS (加载样式表):**
    - **功能关系：**  当浏览器加载 CSS 样式表时，`NetworkResourcesData` 会记录这些请求的信息，以便在开发者工具中查看 CSS 内容和加载详情。
    - **举例说明：**  对于上面 HTML 例子中的 `style.css` 文件，`NetworkResourcesData` 会存储 `style.css` 文件的内容，允许开发者在网络面板中查看其 CSS 规则。

**逻辑推理的假设输入与输出：**

**假设输入：**

1. 用户访问一个包含一个大型图片 (10MB) 和一个小型脚本 (10KB) 的网页。
2. `maximum_resources_content_size_` 设置为 5MB。
3. `maximum_single_resource_content_size_` 设置为 2MB。

**逻辑推理和输出：**

1. **图片加载：** 当浏览器开始加载 10MB 的图片时，`PrepareToAddResourceData` 会检查大小。由于图片大小超过了 `maximum_single_resource_content_size_` (2MB)，所以图片的完整内容可能不会被存储。  `EvictContent()` 可能会被调用，但由于这是一个新的大型资源，可能一开始就不会尝试完整存储。
2. **脚本加载：** 当 10KB 的脚本开始加载时，`PrepareToAddResourceData` 会检查大小。脚本的大小远小于 `maximum_single_resource_content_size_`。
3. **内存管理：** 在图片加载过程中或之后，如果已存储的资源大小接近 `maximum_resources_content_size_` (5MB)，并且脚本加载需要额外的空间，那么 `EnsureFreeSpace` 可能会触发对已存储的其他资源 (如果存在) 的驱逐，以便为新脚本腾出空间。 最老的资源会被优先驱逐。
4. **最终状态：**  网络面板中，可能只能看到部分图片数据（如果一开始尝试存储了部分）或者根本不存储图片内容，而脚本的完整内容会被存储。  总的存储内容大小不会超过 5MB。

**用户或编程常见的使用错误举例说明：**

1. **服务端返回错误的 `Content-Type`：**  如果服务器返回一个资源，但其 `Content-Type` 头信息不正确（例如，本应是文本却标记为二进制），`NetworkResourcesData` 可能会按照错误的类型处理内容，导致解码失败或显示乱码。开发者可能会在网络面板中看到错误的内容展示。

2. **期望在 `Clear` 之后所有数据都被清除：**  `Clear` 方法接受一个 `preserved_loader_id` 参数。如果错误地使用了这个参数，例如在清理时不应该保留任何数据时传入了一个有效的 `loader_id`，那么与该 `loader_id` 相关的资源数据将不会被清除，这可能会导致后续调试的困惑。

3. **依赖于所有网络请求的内容都被完整存储：**  由于有大小限制和驱逐机制，开发者不能保证所有网络请求的内容都会被完整地存储在 `NetworkResourcesData` 中。如果应用程序的某些功能依赖于从开发者工具中获取完整的资源内容，这可能会导致问题。例如，一个自动化测试脚本依赖于网络面板中某个特定资源的完整响应体，但由于资源过大而被驱逐，脚本可能会失败。

4. **在资源加载过程中多次尝试修改资源数据：** 虽然代码中使用了 `DCHECK` 来检查某些状态，但在复杂的异步网络场景中，如果多个地方尝试同时修改同一个 `ResourceData` 对象的状态或内容，可能会导致数据不一致或程序崩溃。虽然设计上应该避免这种情况，但仍然是潜在的编程错误来源。

总而言之，`blink/renderer/core/inspector/network_resources_data.cc` 是 Blink 引擎中一个关键的组件，它负责收集和管理网络活动数据，为开发者工具的网络面板提供数据基础，从而帮助开发者分析和调试网页的性能和行为。 它与 JavaScript、HTML 和 CSS 的交互是通过记录加载这些资源时的网络请求和响应来实现的。

Prompt: 
```
这是目录为blink/renderer/core/inspector/network_resources_data.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY GOOGLE INC. AND ITS CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL GOOGLE INC.
 * OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/inspector/network_resources_data.h"

#include <memory>

#include "base/numerics/safe_conversions.h"
#include "third_party/blink/renderer/core/dom/dom_implementation.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/network/encoded_form_data.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"

namespace blink {

namespace {

bool IsPossiblyTextResourceType(InspectorPageAgent::ResourceType type) {
  return type == InspectorPageAgent::kManifestResource ||
         type == InspectorPageAgent::kStylesheetResource ||
         type == InspectorPageAgent::kScriptResource ||
         type == InspectorPageAgent::kDocumentResource ||
         type == InspectorPageAgent::kFetchResource ||
         type == InspectorPageAgent::kXHRResource;
}

bool IsHTTPErrorStatusCode(int status_code) {
  return status_code >= 400;
}

}  // namespace

void XHRReplayData::AddHeader(const AtomicString& key,
                              const AtomicString& value) {
  headers_.Set(key, value);
}

XHRReplayData::XHRReplayData(ExecutionContext* execution_context,
                             const AtomicString& method,
                             const KURL& url,
                             bool async,
                             bool include_credentials)
    : execution_context_(execution_context),
      method_(method),
      url_(url),
      async_(async),
      include_credentials_(include_credentials) {}

// ResourceData
NetworkResourcesData::ResourceData::ResourceData(
    NetworkResourcesData* network_resources_data,
    const String& request_id,
    const String& loader_id,
    const KURL& requested_url)
    : network_resources_data_(network_resources_data),
      request_id_(request_id),
      loader_id_(loader_id),
      requested_url_(requested_url),
      base64_encoded_(false),
      is_content_evicted_(false),
      type_(InspectorPageAgent::kOtherResource),
      http_status_code_(0),
      raw_header_size_(0),
      pending_encoded_data_length_(0),
      cached_resource_(nullptr) {}

void NetworkResourcesData::ResourceData::Trace(Visitor* visitor) const {
  visitor->Trace(network_resources_data_);
  visitor->Trace(xhr_replay_data_);
  visitor->template RegisterWeakCallbackMethod<
      NetworkResourcesData::ResourceData,
      &NetworkResourcesData::ResourceData::ProcessCustomWeakness>(this);
}

void NetworkResourcesData::ResourceData::SetContent(const String& content,
                                                    bool base64_encoded) {
  DCHECK(!HasData());
  DCHECK(!HasContent());
  content_ = content;
  base64_encoded_ = base64_encoded;
}

size_t NetworkResourcesData::ResourceData::ContentSize() const {
  size_t size = 0;
  if (HasData()) {
    DCHECK(!HasContent());
    size = data_buffer_->size();
  }
  if (HasContent()) {
    DCHECK(!HasData());
    size = content_.CharactersSizeInBytes();
  }
  if (post_data_)
    size += post_data_->SizeInBytes();
  return size;
}

size_t NetworkResourcesData::ResourceData::RemoveResponseContent() {
  DCHECK(HasContent());
  DCHECK(!HasData());
  const size_t size = content_.CharactersSizeInBytes();
  content_ = String();
  return size;
}

size_t NetworkResourcesData::ResourceData::EvictContent() {
  size_t size = ContentSize();
  is_content_evicted_ = true;
  data_buffer_ = std::nullopt;
  content_ = String();
  post_data_ = nullptr;
  return size;
}

void NetworkResourcesData::ResourceData::SetResource(
    const Resource* cached_resource) {
  cached_resource_ = cached_resource;
  if (const auto* font_resource = DynamicTo<FontResource>(cached_resource))
    font_resource->AddClearDataObserver(this);
}

void NetworkResourcesData::ResourceData::ProcessCustomWeakness(
    const LivenessBroker& info) {
  if (!cached_resource_ || info.IsHeapObjectAlive(cached_resource_))
    return;

  // Mark loaded resources or resources without the buffer as loaded.
  if (cached_resource_->IsLoaded() || !cached_resource_->ResourceBuffer()) {
    if (!IsHTTPErrorStatusCode(
            cached_resource_->GetResponse().HttpStatusCode())) {
      String content;
      bool base64_encoded;
      if (InspectorPageAgent::CachedResourceContent(cached_resource_, &content,
                                                    &base64_encoded))
        network_resources_data_->SetResourceContent(RequestId(), content,
                                                    base64_encoded);
    }
  } else {
    // We could be evicting resource being loaded, save the loaded part, the
    // rest will be appended.
    network_resources_data_->MaybeAddResourceData(
        RequestId(), cached_resource_->ResourceBuffer());
  }
  cached_resource_ = nullptr;
}

void NetworkResourcesData::ResourceData::FontResourceDataWillBeCleared() {
  if (cached_resource_->ResourceBuffer()) {
    // Save the cached resource before its data becomes unavailable.
    network_resources_data_->MaybeAddResourceData(
        RequestId(), cached_resource_->ResourceBuffer());
  }
  // There is no point tracking the resource anymore.
  cached_resource_ = nullptr;
  network_resources_data_->MaybeDecodeDataToContent(RequestId());
}

void NetworkResourcesData::ResourceData::AppendData(
    base::span<const char> data) {
  DCHECK(!HasContent());
  if (!data_buffer_) {
    data_buffer_ = SegmentedBuffer();
  }
  data_buffer_->Append(data);
}

size_t NetworkResourcesData::ResourceData::DecodeDataToContent() {
  DCHECK(!HasContent());
  DCHECK(HasData());
  size_t data_length = data_buffer_->size();
  bool success = InspectorPageAgent::SegmentedBufferContent(
      data_buffer_ ? &*data_buffer_ : nullptr, mime_type_, text_encoding_name_,
      &content_, &base64_encoded_);
  DCHECK(success);
  data_buffer_ = std::nullopt;
  return content_.CharactersSizeInBytes() - data_length;
}

// NetworkResourcesData
NetworkResourcesData::NetworkResourcesData(size_t total_buffer_size,
                                           size_t resource_buffer_size)
    : content_size_(0),
      maximum_resources_content_size_(total_buffer_size),
      maximum_single_resource_content_size_(resource_buffer_size) {}

NetworkResourcesData::~NetworkResourcesData() = default;

void NetworkResourcesData::Trace(Visitor* visitor) const {
  visitor->Trace(request_id_to_resource_data_map_);
}

void NetworkResourcesData::ResourceCreated(
    const String& request_id,
    const String& loader_id,
    const KURL& requested_url,
    scoped_refptr<EncodedFormData> post_data) {
  EnsureNoDataForRequestId(request_id);
  ResourceData* data = MakeGarbageCollected<ResourceData>(
      this, request_id, loader_id, requested_url);
  request_id_to_resource_data_map_.Set(request_id, data);
  if (post_data &&
      PrepareToAddResourceData(request_id, post_data->SizeInBytes())) {
    data->SetPostData(post_data);
  }
}

void NetworkResourcesData::ResponseReceived(const String& request_id,
                                            const String& frame_id,
                                            const ResourceResponse& response) {
  ResourceData* resource_data = ResourceDataForRequestId(request_id);
  if (!resource_data)
    return;
  resource_data->SetFrameId(frame_id);
  resource_data->SetMimeType(response.MimeType());
  if (IsPossiblyTextResourceType(resource_data->GetType())) {
    // ResourceResponse may come with some arbitrary encoding (e.g.
    // charset=utf-8). Depending on the actual resource type, it may be ignored
    // in Blink. We should not blindly transfer such resources as text to avoid
    // data corruption, and instead encode them as base64.
    resource_data->SetTextEncodingName(response.TextEncodingName());
  }
  resource_data->SetHTTPStatusCode(response.HttpStatusCode());
  resource_data->SetRawHeaderSize(response.EncodedDataLength());
}

void NetworkResourcesData::BlobReceived(const String& request_id,
                                        scoped_refptr<BlobDataHandle> blob) {
  ResourceData* resource_data = ResourceDataForRequestId(request_id);
  if (!resource_data)
    return;
  resource_data->SetDownloadedFileBlob(std::move(blob));
}

void NetworkResourcesData::SetResourceType(
    const String& request_id,
    InspectorPageAgent::ResourceType type) {
  ResourceData* resource_data = ResourceDataForRequestId(request_id);
  if (!resource_data)
    return;
  resource_data->SetType(type);
}

InspectorPageAgent::ResourceType NetworkResourcesData::GetResourceType(
    const String& request_id) {
  ResourceData* resource_data = ResourceDataForRequestId(request_id);
  if (!resource_data)
    return InspectorPageAgent::kOtherResource;
  return resource_data->GetType();
}

void NetworkResourcesData::SetResourceContent(const String& request_id,
                                              const String& content,
                                              bool base64_encoded) {
  ResourceData* resource_data = ResourceDataForRequestId(request_id);
  if (!resource_data)
    return;
  size_t data_length = content.CharactersSizeInBytes();
  if (data_length > maximum_single_resource_content_size_)
    return;
  if (resource_data->IsContentEvicted())
    return;
  if (EnsureFreeSpace(data_length) && !resource_data->IsContentEvicted()) {
    // We can not be sure that we didn't try to save this request data while it
    // was loading, so remove it, if any.
    if (resource_data->HasContent())
      content_size_ -= resource_data->RemoveResponseContent();
    request_ids_deque_.push_back(request_id);
    resource_data->SetContent(content, base64_encoded);
    content_size_ += data_length;
  }
}

NetworkResourcesData::ResourceData*
NetworkResourcesData::PrepareToAddResourceData(const String& request_id,
                                               uint64_t data_length) {
  ResourceData* resource_data = ResourceDataForRequestId(request_id);
  if (!resource_data)
    return nullptr;

  if (resource_data->ContentSize() + data_length >
      maximum_single_resource_content_size_) {
    content_size_ -= resource_data->EvictContent();
  }
  if (resource_data->IsContentEvicted())
    return nullptr;
  if (!EnsureFreeSpace(data_length) || resource_data->IsContentEvicted())
    return nullptr;

  request_ids_deque_.push_back(request_id);
  content_size_ += data_length;

  return resource_data;
}

void NetworkResourcesData::MaybeAddResourceData(const String& request_id,
                                                base::span<const char> data) {
  if (ResourceData* resource_data =
          PrepareToAddResourceData(request_id, data.size())) {
    resource_data->AppendData(data);
  }
}

void NetworkResourcesData::MaybeAddResourceData(
    const String& request_id,
    scoped_refptr<const SharedBuffer> data) {
  DCHECK(data);
  if (ResourceData* resource_data =
          PrepareToAddResourceData(request_id, data->size())) {
    for (const auto& span : *data)
      resource_data->AppendData(span);
  }
}

void NetworkResourcesData::MaybeDecodeDataToContent(const String& request_id) {
  ResourceData* resource_data = ResourceDataForRequestId(request_id);
  if (!resource_data)
    return;
  if (!resource_data->HasData())
    return;
  const size_t data_length_increment = resource_data->DecodeDataToContent();
  const size_t data_length = resource_data->Content().CharactersSizeInBytes();
  content_size_ += data_length_increment;
  if (data_length > maximum_single_resource_content_size_)
    content_size_ -= resource_data->EvictContent();
  else
    EnsureFreeSpace(data_length_increment);
  CHECK_GE(maximum_resources_content_size_, content_size_);
}

void NetworkResourcesData::AddResource(const String& request_id,
                                       const Resource* cached_resource) {
  ResourceData* resource_data = ResourceDataForRequestId(request_id);
  if (!resource_data)
    return;
  resource_data->SetResource(cached_resource);
}

NetworkResourcesData::ResourceData const* NetworkResourcesData::Data(
    const String& request_id) {
  return ResourceDataForRequestId(request_id);
}

XHRReplayData* NetworkResourcesData::XhrReplayData(const String& request_id) {
  ResourceData* resource_data = ResourceDataForRequestId(request_id);
  if (!resource_data)
    return nullptr;
  return resource_data->XhrReplayData();
}

void NetworkResourcesData::SetCertificate(
    const String& request_id,
    scoped_refptr<net::X509Certificate> certificate) {
  ResourceData* resource_data = ResourceDataForRequestId(request_id);
  if (!resource_data)
    return;
  resource_data->SetCertificate(std::move(certificate));
}

void NetworkResourcesData::SetXHRReplayData(const String& request_id,
                                            XHRReplayData* xhr_replay_data) {
  ResourceData* resource_data = ResourceDataForRequestId(request_id);
  if (!resource_data || resource_data->IsContentEvicted())
    return;

  resource_data->SetXHRReplayData(xhr_replay_data);
}

HeapVector<Member<NetworkResourcesData::ResourceData>>
NetworkResourcesData::Resources() {
  HeapVector<Member<ResourceData>> result;
  WTF::CopyValuesToVector(request_id_to_resource_data_map_, result);
  return result;
}

int64_t NetworkResourcesData::GetAndClearPendingEncodedDataLength(
    const String& request_id) {
  ResourceData* resource_data = ResourceDataForRequestId(request_id);
  if (!resource_data)
    return 0;

  int64_t pending_encoded_data_length =
      resource_data->PendingEncodedDataLength();
  resource_data->ClearPendingEncodedDataLength();
  return pending_encoded_data_length;
}

void NetworkResourcesData::AddPendingEncodedDataLength(
    const String& request_id,
    size_t encoded_data_length) {
  ResourceData* resource_data = ResourceDataForRequestId(request_id);
  if (!resource_data)
    return;

  resource_data->AddPendingEncodedDataLength(encoded_data_length);
}

void NetworkResourcesData::Clear(const String& preserved_loader_id) {
  if (request_id_to_resource_data_map_.empty())
    return;
  request_ids_deque_.clear();
  content_size_ = 0;

  ResourceDataMap preserved_map;

  for (auto& resource : request_id_to_resource_data_map_) {
    ResourceData* resource_data = resource.value;
    if (!preserved_loader_id.IsNull() &&
        resource_data->LoaderId() == preserved_loader_id) {
      preserved_map.Set(resource.key, resource.value);
      content_size_ += resource_data->ContentSize();
    }
  }
  request_id_to_resource_data_map_.swap(preserved_map);
}

void NetworkResourcesData::SetResourcesDataSizeLimits(
    size_t resources_content_size,
    size_t single_resource_content_size) {
  maximum_resources_content_size_ = resources_content_size;
  maximum_single_resource_content_size_ = single_resource_content_size;
  for (auto& entry : request_id_to_resource_data_map_) {
    if (entry.value->ContentSize() > maximum_single_resource_content_size_)
      content_size_ -= entry.value->EvictContent();
  }
  EnsureFreeSpace(0);
}

NetworkResourcesData::ResourceData*
NetworkResourcesData::ResourceDataForRequestId(const String& request_id) const {
  if (request_id.IsNull())
    return nullptr;
  auto it = request_id_to_resource_data_map_.find(request_id);
  return it != request_id_to_resource_data_map_.end() ? it->value.Get()
                                                      : nullptr;
}

void NetworkResourcesData::EnsureNoDataForRequestId(const String& request_id) {
  ResourceData* resource_data = ResourceDataForRequestId(request_id);
  if (!resource_data)
    return;
  content_size_ -= resource_data->EvictContent();
  request_id_to_resource_data_map_.erase(request_id);
}

bool NetworkResourcesData::EnsureFreeSpace(uint64_t size) {
  if (size > maximum_resources_content_size_)
    return false;

  while (content_size_ + size > maximum_resources_content_size_) {
    String request_id = request_ids_deque_.TakeFirst();
    ResourceData* resource_data = ResourceDataForRequestId(request_id);
    if (resource_data)
      content_size_ -= resource_data->EvictContent();
  }
  return true;
}

}  // namespace blink

"""

```