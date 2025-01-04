Response:
Let's break down the thought process for analyzing the `memory_cache.cc` file.

1. **Understand the Goal:** The request asks for the functionalities of the `MemoryCache` class in `memory_cache.cc`, its relationship to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, and common usage errors.

2. **Initial Scan for Keywords and Structure:**  Quickly skim the file for important terms like "cache," "add," "remove," "resource," "URL," "memory," "strong references," "statistics," and the different resource types (image, CSS, script, etc.). Notice the `#include` directives, which reveal dependencies on other Blink components. The `namespace blink` indicates this is part of the Blink rendering engine.

3. **Identify Core Functionalities (High-Level):** From the keywords, it's evident that the file implements a memory cache. The basic operations are likely adding, removing, and retrieving resources. The mention of "strong references" suggests a mechanism for keeping certain resources alive longer.

4. **Analyze Key Methods (Detailed):**  Go through the public and important private methods one by one.

    * **`Get()`:**  A static method, likely the entry point for accessing the singleton instance of `MemoryCache`. The `DCHECK(WTF::IsMainThread())` is crucial –  this cache is tied to the main thread.
    * **`Add(Resource*)`:**  Adds a resource to the cache. Note the use of `EnsureResourceMap` and `MemoryCacheEntry`.
    * **`Remove(Resource*)`:** Removes a resource from the cache.
    * **`Contains(const Resource*)`:** Checks if a resource is in the cache.
    * **`ResourceForURL(const KURL&, const String&)`:** Retrieves a resource based on its URL and cache identifier. The `RemoveFragmentIdentifierIfNeeded` is a detail worth noting.
    * **`ResourcesForURL(const KURL&)`:**  Retrieves *all* resources for a given URL across different cache identifiers.
    * **`Update(Resource*, size_t, size_t)`:**  Updates the size information of a cached resource.
    * **`RemoveURLFromCache(const KURL&)`:** Removes all resources associated with a specific URL.
    * **`GetStatistics()`:** Provides statistics about the cached resources (types, sizes, etc.). This is relevant for monitoring and debugging.
    * **`EvictResources()`:** Clears the entire cache.
    * **`OnMemoryDump()`:**  Part of the memory dumping infrastructure, providing information about the cache's memory usage.
    * **`OnMemoryPressure()`:**  Handles memory pressure events, potentially releasing strong references.
    * **`SavePageResourceStrongReferences(HeapVector<Member<Resource>>)` and `SaveStrongReference(Resource*)`:**  Mechanisms for adding strong references to resources.
    * **`PruneStrongReferences()`:** The logic for managing and potentially releasing strong references.
    * **`ClearStrongReferences()`:**  Clears all strong references.

5. **Identify Relationships with Web Technologies:** Consider how the cached resources relate to web content.

    * **HTML:** Images, scripts, stylesheets directly used in HTML.
    * **CSS:** Stylesheet resources.
    * **JavaScript:** Script resources.

6. **Logical Reasoning and Examples:** Think about the flow of data and how the cache is used.

    * **Input/Output:**  Imagine a browser fetching an image. The input is the image URL. The output is the cached image data (if present). If not present, the cache *becomes* the output after the fetch.
    * **Assumptions:**  Assume the cache aims to improve performance by avoiding repeated downloads. Assume resources are keyed by URL.

7. **Common Usage Errors:**  Consider how a developer interacting with a system *using* this cache (not directly this C++ code, but the browser in general) might encounter issues.

    * **Cache Invalidation:**  Outdated cached content.
    * **Privacy Issues:**  Sensitive data being cached unexpectedly.
    * **Performance Problems:**  Cache not being used effectively, or the cache itself becoming too large.

8. **Structure the Output:** Organize the findings into clear sections:

    * **Core Functionalities:**  List the primary responsibilities of the `MemoryCache`.
    * **Relationship to Web Technologies:** Explain how the cached resources interact with HTML, CSS, and JavaScript. Provide concrete examples.
    * **Logical Reasoning (Input/Output):** Create simple scenarios to illustrate how the cache works.
    * **Common Usage Errors:** Describe potential issues users or developers might face due to caching.

9. **Refine and Elaborate:**  Review the initial analysis and add more detail. For instance, when discussing strong references, explain their purpose and how they are managed. For statistics, explain *why* these statistics are useful. Ensure the examples are clear and easy to understand.

10. **Self-Correction/Review:**  Read through the generated output. Does it accurately reflect the code's functionality? Are there any ambiguities or missing pieces?  For example, initially, I might have focused too much on the low-level details of the data structures. The review process would help me shift the focus to the higher-level functionalities and their impact on web technologies. I would also double-check if I correctly interpreted the meaning of "strong references" and their role in preventing eviction.
这个 `memory_cache.cc` 文件是 Chromium Blink 引擎中负责实现内存缓存的核心组件。它管理着浏览器在内存中缓存的各种资源，以提高页面加载速度和减少网络请求。

以下是 `MemoryCache` 的主要功能以及它与 JavaScript、HTML 和 CSS 的关系：

**核心功能:**

1. **资源存储和检索:**
   - `Add(Resource* resource)`: 将一个资源（例如图片、脚本、样式表等）添加到内存缓存中。
   - `ResourceForURL(const KURL& resource_url, const String& cache_identifier)`:  根据 URL 和缓存标识符（通常为空字符串）从缓存中查找并返回资源。
   - `ResourcesForURL(const KURL& resource_url)`: 返回与给定 URL 关联的所有资源（可能存在于不同的缓存分区中）。
   - `Contains(const Resource* resource)`: 检查给定的资源是否已存在于缓存中。

2. **资源移除:**
   - `Remove(Resource* resource)`: 从缓存中移除特定的资源。
   - `RemoveURLFromCache(const KURL& url)`: 移除与给定 URL 关联的所有资源。
   - `EvictResources()`: 清空整个内存缓存。

3. **缓存管理和优化:**
   - **按需添加/移除:**  资源在被请求时添加到缓存，并在不再需要时或内存压力过大时被移除。
   - **资源大小跟踪:**  `Update(Resource* resource, size_t old_size, size_t new_size)` 方法用于跟踪缓存中资源大小的变化，从而可以监控缓存的总体大小。
   - **强引用 (Strong References):**  `SavePageResourceStrongReferences` 和 `SaveStrongReference` 方法允许将某些资源标记为“强引用”，这意味着即使在内存压力下，这些资源也不会轻易被清除。这对于当前页面正在使用的关键资源非常重要。
   - **强引用修剪 (Prune Strong References):** `PruneStrongReferences` 方法定期检查强引用资源，并根据时间和大小限制来移除旧的或超出限制的强引用，以防止内存过度占用。
   - **内存压力处理 (Memory Pressure Handling):**  `OnMemoryPressure` 方法响应系统的内存压力事件，并可能清除非强引用的资源来释放内存。

4. **统计信息收集:**
   - `GetStatistics()`: 提供关于缓存中各种资源类型的统计信息，例如图片、CSS、脚本等的数量和大小。

5. **内存转储 (Memory Dump):**
   - `OnMemoryDump`: 参与 Chromium 的内存转储机制，报告内存缓存的使用情况，用于性能分析和内存泄漏检测。

**与 JavaScript, HTML, CSS 的关系及举例:**

`MemoryCache` 直接影响着浏览器如何加载和渲染网页，因此与 JavaScript、HTML 和 CSS 密切相关。

* **HTML:**
    - **图片缓存:** 当浏览器解析 HTML 并遇到 `<img>` 标签时，它会尝试从内存缓存中获取图片资源。如果缓存命中，图片将立即显示，无需再次下载。
        * **假设输入:** HTML 中有 `<img src="https://example.com/image.png">`。
        * **逻辑推理:**  `MemoryCache::ResourceForURL("https://example.com/image.png", "")` 被调用。如果缓存中存在该图片，则返回，页面快速渲染。否则，发起网络请求。
    - **其他嵌入资源:** HTML 中引用的其他资源，如 `<link rel="icon">` (网站图标) 等，也会被缓存。

* **CSS:**
    - **样式表缓存:** 当浏览器解析 HTML 并遇到 `<link rel="stylesheet" href="style.css">` 或 `<style>` 标签时，CSS 样式表资源会被添加到内存缓存。下次加载相同的页面或在同一会话中访问其他页面时，如果样式表 URL 相同，则会直接从缓存加载，加快页面渲染速度。
        * **假设输入:** CSS 文件 `style.css` 的内容被成功下载并添加到缓存。
        * **逻辑推理:**  后续加载包含 `<link rel="stylesheet" href="style.css">` 的页面时，`MemoryCache::ResourceForURL("style.css", "")` 返回缓存的 CSS 资源，避免重新下载。

* **JavaScript:**
    - **脚本缓存:**  当浏览器解析 HTML 并遇到 `<script src="script.js">` 或内联 `<script>` 标签时，JavaScript 脚本资源会被缓存。这对于提高页面交互性和性能至关重要，因为脚本通常会被频繁执行。
        * **假设输入:** JavaScript 文件 `script.js` 被成功下载并缓存。
        * **逻辑推理:**  当页面需要执行 `script.js` 中的代码时，可以直接从缓存加载，而无需再次从网络获取。
    - **动态加载的脚本:**  通过 JavaScript 代码动态加载的脚本，例如使用 `fetch` 或 `XMLHttpRequest` 获取的脚本，也会被 `MemoryCache` 管理。

**逻辑推理举例 (假设输入与输出):**

假设用户首次访问 `https://example.com/page.html`，其中包含以下内容：

```html
<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <img src="image.png">
    <script src="script.js"></script>
</body>
</html>
```

**首次加载:**

* **假设输入:** 浏览器请求 `https://example.com/page.html`, `https://example.com/style.css`, `https://example.com/image.png`, `https://example.com/script.js`。
* **逻辑推理:**  `MemoryCache` 最初为空。当这些资源被下载后，`Add()` 方法会被调用，将它们添加到缓存中。
* **输出:**  `MemoryCache` 中包含 `style.css`、`image.png` 和 `script.js` 的资源条目。

**后续访问:**

* **假设输入:** 用户再次访问 `https://example.com/page.html`。
* **逻辑推理:**  浏览器解析 HTML 时，会首先检查 `MemoryCache` 是否存在 `style.css`、`image.png` 和 `script.js` 的缓存副本。`ResourceForURL()` 方法会被调用。
* **输出:** 如果缓存未失效且资源仍在缓存中，`ResourceForURL()` 会返回缓存的资源，浏览器直接使用这些缓存的资源，无需再次下载。

**涉及用户或者编程常见的使用错误举例:**

1. **缓存污染 (Cache Poisoning):**  虽然 `MemoryCache` 本身不直接涉及用户编程，但服务器端的配置错误或恶意攻击可能导致缓存中存储了错误的内容。用户会因此看到错误的页面或执行恶意的脚本。
    * **假设输入:**  恶意攻击者篡改了服务器响应，导致缓存中存储了包含恶意 JavaScript 的 `script.js`。
    * **后果:**  用户后续访问页面时，浏览器从缓存加载恶意的 `script.js` 并执行，可能导致安全问题。

2. **不合理的缓存策略:**  开发者可能在服务器端设置了不合理的缓存头 (e.g., 过长的过期时间)，导致用户即使在资源更新后仍然看到旧版本。这并非 `MemoryCache` 的错误，而是服务器配置不当。

3. **隐私问题:**  某些敏感数据如果被意外地缓存，可能会导致隐私泄露。`MemoryCache` 尝试避免缓存包含敏感信息的响应，但这依赖于正确的 HTTP 头设置。

4. **内存占用过高:** 如果浏览器缓存了过多的资源，可能会导致内存占用过高，影响浏览器和系统的性能。`MemoryCache` 会尝试进行资源回收，但如果强引用过多或资源本身过大，仍然可能出现问题。

总而言之，`memory_cache.cc` 中实现的 `MemoryCache` 是 Blink 引擎中一个关键的性能优化组件，它通过在内存中缓存资源来减少网络请求和提高页面加载速度，直接影响着用户浏览网页的体验。了解其工作原理有助于理解浏览器如何高效地处理网页资源。

Prompt: 
```
这是目录为blink/renderer/platform/loader/fetch/memory_cache.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
    Copyright (C) 1998 Lars Knoll (knoll@mpi-hd.mpg.de)
    Copyright (C) 2001 Dirk Mueller (mueller@kde.org)
    Copyright (C) 2002 Waldo Bastian (bastian@kde.org)
    Copyright (C) 2004, 2005, 2006, 2007, 2008 Apple Inc. All rights reserved.

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

#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"

#include <utility>

#include "base/auto_reset.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/metrics/histogram_functions.h"
#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/visitor.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loading_log.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"

namespace blink {

static Persistent<MemoryCache>* g_memory_cache;

static const base::TimeDelta kCUnloadPageResourceSaveTime = base::Minutes(5);

static constexpr char kPageSavedResourceStrongReferenceSize[] =
    "Blink.MemoryCache.PageSavedResourceStrongReferenceSize";

MemoryCache* ReplaceMemoryCacheForTesting(MemoryCache* cache) {
  MemoryCache::Get();
  MemoryCache* old_cache = g_memory_cache->Release();
  *g_memory_cache = cache;
  MemoryCacheDumpProvider::Instance()->SetMemoryCache(cache);
  return old_cache;
}

void MemoryCacheEntry::Trace(Visitor* visitor) const {
  visitor->template RegisterWeakCallbackMethod<
      MemoryCacheEntry, &MemoryCacheEntry::ClearResourceWeak>(this);
}

void MemoryCacheEntry::ClearResourceWeak(const LivenessBroker& info) {
  if (!resource_ || info.IsHeapObjectAlive(resource_))
    return;
  MemoryCache::Get()->Remove(resource_.Get());
  resource_.Clear();
}

// static
MemoryCache* MemoryCache::Get() {
  DCHECK(WTF::IsMainThread());
  if (!g_memory_cache) {
    g_memory_cache = new Persistent<MemoryCache>(
        MakeGarbageCollected<MemoryCache>(Thread::MainThread()->GetTaskRunner(
            MainThreadTaskRunnerRestricted())));
  }
  return g_memory_cache->Get();
}

MemoryCache::MemoryCache(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : strong_references_prune_duration_(kCUnloadPageResourceSaveTime),
      task_runner_(std::move(task_runner)) {
  MemoryCacheDumpProvider::Instance()->SetMemoryCache(this);
  MemoryPressureListenerRegistry::Instance().RegisterClient(this);
}

MemoryCache::~MemoryCache() = default;

void MemoryCache::Trace(Visitor* visitor) const {
  visitor->Trace(resource_maps_);
  visitor->Trace(strong_references_);
  MemoryCacheDumpClient::Trace(visitor);
  MemoryPressureListener::Trace(visitor);
}

KURL MemoryCache::RemoveFragmentIdentifierIfNeeded(const KURL& original_url) {
  if (!original_url.HasFragmentIdentifier())
    return original_url;
  // Strip away fragment identifier from HTTP URLs. Data URLs must be
  // unmodified. For file and custom URLs clients may expect resources to be
  // unique even when they differ by the fragment identifier only.
  if (!original_url.ProtocolIsInHTTPFamily())
    return original_url;
  KURL url = original_url;
  url.RemoveFragmentIdentifier();
  return url;
}

String MemoryCache::DefaultCacheIdentifier() {
  return g_empty_string;
}

MemoryCache::ResourceMap* MemoryCache::EnsureResourceMap(
    const String& cache_identifier) {
  if (!resource_maps_.Contains(cache_identifier)) {
    ResourceMapIndex::AddResult result = resource_maps_.insert(
        cache_identifier, MakeGarbageCollected<ResourceMap>());
    CHECK(result.is_new_entry);
  }
  return resource_maps_.at(cache_identifier);
}

void MemoryCache::Add(Resource* resource) {
  DCHECK(resource);
  ResourceMap* resources = EnsureResourceMap(resource->CacheIdentifier());
  AddInternal(resources, MakeGarbageCollected<MemoryCacheEntry>(resource));
  RESOURCE_LOADING_DVLOG(1)
      << "MemoryCache::add Added " << resource->Url().GetString()
      << ", resource " << resource;
}

void MemoryCache::AddInternal(ResourceMap* resource_map,
                              MemoryCacheEntry* entry) {
  DCHECK(WTF::IsMainThread());
  DCHECK(resource_map);

  Resource* resource = entry->GetResource();
  if (!resource)
    return;
  DCHECK(resource->Url().IsValid());

  KURL url = RemoveFragmentIdentifierIfNeeded(resource->Url());
  ResourceMap::iterator it = resource_map->find(url);
  if (it != resource_map->end()) {
    Resource* old_resource = it->value->GetResource();
    CHECK_NE(old_resource, resource);
    Update(old_resource, old_resource->size(), 0);
    strong_references_.erase(old_resource);
  }
  resource_map->Set(url, entry);
  Update(resource, 0, resource->size());
}

void MemoryCache::Remove(Resource* resource) {
  DCHECK(WTF::IsMainThread());
  DCHECK(resource);
  // Resources can be created with garbage urls in error cases. These Resources
  // should never be added to the cache (AddInternal() DCHECKs that the url is
  // valid). Null urls will crash if we attempt to hash them, so early exit.
  if (resource->Url().IsNull())
    return;

  RESOURCE_LOADING_DVLOG(1) << "Evicting resource " << resource << " for "
                            << resource->Url().GetString() << " from cache";
  TRACE_EVENT1("blink", "MemoryCache::evict", "resource",
               resource->Url().GetString().Utf8());

  const auto resource_maps_it =
      resource_maps_.find(resource->CacheIdentifier());
  if (resource_maps_it == resource_maps_.end())
    return;
  ResourceMap* resources = resource_maps_it->value.Get();

  KURL url = RemoveFragmentIdentifierIfNeeded(resource->Url());
  ResourceMap::iterator it = resources->find(url);
  if (it == resources->end() || it->value->GetResource() != resource)
    return;
  RemoveInternal(resources, it);
}

void MemoryCache::RemoveInternal(ResourceMap* resource_map,
                                 const ResourceMap::iterator& it) {
  DCHECK(WTF::IsMainThread());
  DCHECK(resource_map);

  Resource* resource = it->value->GetResource();
  DCHECK(resource);

  Update(resource, resource->size(), 0);
  resource_map->erase(it);
  strong_references_.erase(resource);
}

bool MemoryCache::Contains(const Resource* resource) const {
  if (!resource || resource->Url().IsEmpty())
    return false;

  const auto resource_maps_it =
      resource_maps_.find(resource->CacheIdentifier());
  if (resource_maps_it == resource_maps_.end())
    return false;
  const ResourceMap* resources = resource_maps_it->value.Get();

  KURL url = RemoveFragmentIdentifierIfNeeded(resource->Url());
  const auto resources_it = resources->find(url);
  if (resources_it == resources->end())
    return false;
  return resource == resources_it->value->GetResource();
}

Resource* MemoryCache::ResourceForURLForTesting(
    const KURL& resource_url) const {
  return ResourceForURL(resource_url, DefaultCacheIdentifier());
}

Resource* MemoryCache::ResourceForURL(const KURL& resource_url,
                                      const String& cache_identifier) const {
  DCHECK(WTF::IsMainThread());
  if (!resource_url.IsValid() || resource_url.IsNull())
    return nullptr;
  DCHECK(!cache_identifier.IsNull());

  const auto resource_maps_it = resource_maps_.find(cache_identifier);
  if (resource_maps_it == resource_maps_.end()) {
    return nullptr;
  }
  const ResourceMap* resources = resource_maps_it->value.Get();

  KURL url = RemoveFragmentIdentifierIfNeeded(resource_url);
  const auto resources_it = resources->find(url);
  if (resources_it == resources->end()) {
    return nullptr;
  }
  return resources_it->value->GetResource();
}

HeapVector<Member<Resource>> MemoryCache::ResourcesForURL(
    const KURL& resource_url) const {
  DCHECK(WTF::IsMainThread());
  KURL url = RemoveFragmentIdentifierIfNeeded(resource_url);
  HeapVector<Member<Resource>> results;
  for (const auto& resource_maps_it : resource_maps_) {
    const auto resources_it = resource_maps_it.value->find(url);
    if (resources_it == resource_maps_it.value->end())
      continue;
    Resource* resource = resources_it->value->GetResource();
    DCHECK(resource);
    results.push_back(resource);
  }
  return results;
}

void MemoryCache::Update(Resource* resource, size_t old_size, size_t new_size) {
  ptrdiff_t delta = new_size - old_size;
  if (Contains(resource)) {
    DCHECK(delta >= 0 || size_ >= static_cast<size_t>(-delta));
    size_ += delta;
  }
  if (strong_references_.Contains(resource)) {
    PruneStrongReferences();
  }
}

void MemoryCache::RemoveURLFromCache(const KURL& url) {
  HeapVector<Member<Resource>> resources = ResourcesForURL(url);
  for (Resource* resource : resources)
    Remove(resource);
}

void MemoryCache::TypeStatistic::AddResource(Resource* o) {
  count++;
  size += o->size();
  decoded_size += o->DecodedSize();
  encoded_size += o->EncodedSize();
  overhead_size += o->OverheadSize();
  code_cache_size += o->CodeCacheSize();
  encoded_size_duplicated_in_data_urls +=
      o->Url().ProtocolIsData() ? o->EncodedSize() : 0;
}

MemoryCache::Statistics MemoryCache::GetStatistics() const {
  Statistics stats;
  for (const auto& resource_map_iter : resource_maps_) {
    for (const auto& resource_iter : *resource_map_iter.value) {
      Resource* resource = resource_iter.value->GetResource();
      DCHECK(resource);
      switch (resource->GetType()) {
        case ResourceType::kImage:
          stats.images.AddResource(resource);
          break;
        case ResourceType::kCSSStyleSheet:
          stats.css_style_sheets.AddResource(resource);
          break;
        case ResourceType::kScript:
          stats.scripts.AddResource(resource);
          break;
        case ResourceType::kXSLStyleSheet:
          stats.xsl_style_sheets.AddResource(resource);
          break;
        case ResourceType::kFont:
          stats.fonts.AddResource(resource);
          break;
        default:
          stats.other.AddResource(resource);
          break;
      }
    }
  }
  return stats;
}

void MemoryCache::EvictResources() {
  for (auto resource_map_iter = resource_maps_.begin();
       resource_map_iter != resource_maps_.end();) {
    ResourceMap* resources = resource_map_iter->value.Get();
    for (auto resource_iter = resources->begin();
         resource_iter != resources->end();
         resource_iter = resources->begin()) {
      DCHECK(resource_iter.Get());
      DCHECK(resource_iter->value.Get());
      DCHECK(resource_iter->value->GetResource());
      Resource* resource = resource_iter->value->GetResource();
      DCHECK(resource);
      RemoveInternal(resources, resource_iter);
    }
    resource_maps_.erase(resource_map_iter);
    resource_map_iter = resource_maps_.begin();
  }
  ClearStrongReferences();
}

bool MemoryCache::OnMemoryDump(WebMemoryDumpLevelOfDetail level_of_detail,
                               WebProcessMemoryDump* memory_dump) {
  if (level_of_detail == WebMemoryDumpLevelOfDetail::kBackground) {
    Statistics stats = GetStatistics();
    WebMemoryAllocatorDump* dump1 =
        memory_dump->CreateMemoryAllocatorDump("web_cache/Image_resources");
    dump1->AddScalar("size", "bytes",
                     stats.images.encoded_size + stats.images.overhead_size);
    WebMemoryAllocatorDump* dump2 = memory_dump->CreateMemoryAllocatorDump(
        "web_cache/CSS stylesheet_resources");
    dump2->AddScalar("size", "bytes",
                     stats.css_style_sheets.encoded_size +
                         stats.css_style_sheets.overhead_size);
    WebMemoryAllocatorDump* dump3 =
        memory_dump->CreateMemoryAllocatorDump("web_cache/Script_resources");
    dump3->AddScalar("size", "bytes",
                     stats.scripts.encoded_size + stats.scripts.overhead_size);
    WebMemoryAllocatorDump* dump4 = memory_dump->CreateMemoryAllocatorDump(
        "web_cache/XSL stylesheet_resources");
    dump4->AddScalar("size", "bytes",
                     stats.xsl_style_sheets.encoded_size +
                         stats.xsl_style_sheets.overhead_size);
    WebMemoryAllocatorDump* dump5 =
        memory_dump->CreateMemoryAllocatorDump("web_cache/Font_resources");
    dump5->AddScalar("size", "bytes",
                     stats.fonts.encoded_size + stats.fonts.overhead_size);
    WebMemoryAllocatorDump* dump6 =
        memory_dump->CreateMemoryAllocatorDump("web_cache/Code_cache");
    dump6->AddScalar("size", "bytes", stats.scripts.code_cache_size);
    WebMemoryAllocatorDump* dump7 = memory_dump->CreateMemoryAllocatorDump(
        "web_cache/Encoded_size_duplicated_in_data_urls");
    dump7->AddScalar("size", "bytes",
                     stats.other.encoded_size +
                         stats.other.encoded_size_duplicated_in_data_urls);
    WebMemoryAllocatorDump* dump8 =
        memory_dump->CreateMemoryAllocatorDump("web_cache/Other_resources");
    dump8->AddScalar("size", "bytes",
                     stats.other.encoded_size + stats.other.overhead_size);
    return true;
  }

  for (const auto& resource_map_iter : resource_maps_) {
    for (const auto& resource_iter : *resource_map_iter.value) {
      Resource* resource = resource_iter.value->GetResource();
      resource->OnMemoryDump(level_of_detail, memory_dump);
    }
  }
  return true;
}

void MemoryCache::OnMemoryPressure(
    base::MemoryPressureListener::MemoryPressureLevel level) {
  if (base::FeatureList::IsEnabled(
          features::kReleaseResourceStrongReferencesOnMemoryPressure)) {
    ClearStrongReferences();
  }
}

void MemoryCache::SavePageResourceStrongReferences(
    HeapVector<Member<Resource>> resources) {
  DCHECK(base::FeatureList::IsEnabled(features::kMemoryCacheStrongReference));
  base::UmaHistogramCustomCounts(kPageSavedResourceStrongReferenceSize,
                                 resources.size(), 0, 200, 50);
  for (Resource* resource : resources) {
    resource->UpdateMemoryCacheLastAccessedTime();
    strong_references_.AppendOrMoveToLast(resource);
  }
  PruneStrongReferences();
}

void MemoryCache::SaveStrongReference(Resource* resource) {
  resource->UpdateMemoryCacheLastAccessedTime();
  strong_references_.AppendOrMoveToLast(resource);
  PruneStrongReferences();
}

void MemoryCache::PruneStrongReferences() {
  DCHECK(base::FeatureList::IsEnabled(features::kMemoryCacheStrongReference));
  static const size_t max_threshold = static_cast<size_t>(
      features::kMemoryCacheStrongReferenceTotalSizeThresholdParam.Get());

  base::TimeTicks last_ticks;
  size_t strong_reference_total_size = 0;
  for (Resource* resource : strong_references_) {
    // Sanity check on data structure.
    CHECK(resource->MemoryCacheLastAccessed() >= last_ticks);
    last_ticks = resource->MemoryCacheLastAccessed();
    strong_reference_total_size += resource->size();
  }

  while (strong_reference_total_size > max_threshold) {
    CHECK(!strong_references_.empty());
    Resource* front_resource = strong_references_.front();
    strong_references_.erase(strong_references_.begin());
    size_t resource_size = front_resource->size();
    CHECK_GE(strong_reference_total_size, resource_size);
    strong_reference_total_size -= resource_size;
  }

  base::TimeTicks now = base::TimeTicks::Now();
  while (!strong_references_.empty()) {
    Resource* front_resource = strong_references_.front();
    base::TimeTicks next_expiry = front_resource->MemoryCacheLastAccessed() +
                                  strong_references_prune_duration_;
    if (next_expiry > now) {
      if (strong_references_prune_time_ < now ||
          strong_references_prune_time_ > next_expiry) {
        task_runner_->PostDelayedTask(
            FROM_HERE,
            base::BindOnce(&MemoryCache::PruneStrongReferences,
                           WrapWeakPersistent(this)),
            next_expiry - now);
        strong_references_prune_time_ = next_expiry;
      }
      break;
    }
    strong_references_.erase(strong_references_.begin());
  }
}

void MemoryCache::ClearStrongReferences() {
  strong_references_.clear();
}

}  // namespace blink

"""

```