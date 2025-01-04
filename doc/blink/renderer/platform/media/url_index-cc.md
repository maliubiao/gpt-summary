Response: Let's break down the thought process for analyzing the `url_index.cc` file and generating the explanation.

**1. Initial Skim and High-Level Understanding:**

The first step is to quickly read through the code, paying attention to:

* **Includes:**  `third_party/blink`, `media/base`, `base/`. This tells us it's related to Blink's media handling, using Chromium's base libraries for threading, time, and feature flags.
* **Namespaces:**  The code is within the `blink` namespace.
* **Class Names:** `UrlIndex`, `UrlData`, `ResourceMultiBuffer`. These seem like the core components.
* **Key Data Structures:**  `UrlDataMap` (likely a `std::map`), `MultiBuffer::GlobalLRU`. This hints at managing a collection of URL data and using an LRU cache.
* **Constants:** `kBlockSizeShift`, `kUrlMappingTimeoutSeconds`. These likely define important configuration parameters.

From this initial skim, we can infer that this file manages some kind of index for URLs related to media resources, potentially for caching purposes.

**2. Deeper Dive into Class Responsibilities:**

Next, we examine each class in detail:

* **`ResourceMultiBuffer`:**  Inherits from `MultiBuffer`. Has a `UrlData*`. Provides methods like `CreateWriter`, `RangeSupported`, `OnEmpty`. This strongly suggests it's a buffer that stores data fetched from a URL, associated with a `UrlData` object. The `CreateWriter` function suggests a mechanism for writing data into the buffer.
* **`UrlData`:** Holds information about a specific URL: `url_`, `cors_mode_`, `length_`, `range_supported_`, `cacheable_`, `multibuffer_`. Methods like `set_length`, `set_cacheable`, `RedirectTo`, `Fail`, `Valid`, `FullyCached`. This class appears to be the central data structure for tracking the state and metadata of a fetched URL, including its caching status, whether range requests are supported, and the actual cached data via the `multibuffer_`. The `RedirectTo` and `Fail` methods indicate handling of redirects and failures.
* **`UrlIndex`:** Contains a `UrlDataMap`, a `MultiBuffer::GlobalLRU`, and a `ResourceFetchContext*`. Methods like `GetByUrl`, `NewUrlData`, `TryInsert`, `RemoveUrlData`, `OnMemoryPressure`. This class seems to be the manager or registry for `UrlData` objects. It handles looking up `UrlData` based on URL and CORS mode, creating new `UrlData` instances, and managing the overall cache using the LRU strategy. The `OnMemoryPressure` method clearly indicates cache eviction based on memory pressure.

**3. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Now, we consider how these classes relate to web technologies:

* **Media Elements (`<video>`, `<audio>`):**  The file is located in `blink/renderer/platform/media`, making it highly likely that it's involved in fetching and managing media resources requested by these elements.
* **Caching:** The presence of `cacheable_`, `cache_lookup_mode_`, `Valid`, `FullyCached`, and the LRU cache strongly suggest caching of media resources. This caching helps improve performance by reducing network requests.
* **CORS (Cross-Origin Resource Sharing):** The `cors_mode_` member in `UrlData` and the use of `SecurityOrigin::AreSameOrigin` indicate that this code is aware of and handles CORS for media resources. This is crucial for security in web browsers.
* **Range Requests:** `range_supported_` and the interaction with `MultiBuffer` point to the ability to request specific byte ranges of media files, which is essential for features like seeking in video and audio.
* **Redirects:** The `RedirectTo` and `Fail` methods in `UrlData` directly relate to HTTP redirects, which are common when fetching resources.

**4. Logical Reasoning and Input/Output Examples:**

We can construct hypothetical scenarios to illustrate the behavior of the classes:

* **Scenario 1 (Cache Hit):**
    * **Input:** JavaScript requests `<video src="https://example.com/video.mp4">`. The browser calls `UrlIndex::GetByUrl` with the URL.
    * **Logic:** `UrlIndex` checks its `indexed_data_`. If a valid `UrlData` for this URL and CORS mode exists, it's returned.
    * **Output:** The cached `UrlData` is returned, potentially avoiding a network request.

* **Scenario 2 (Cache Miss):**
    * **Input:**  JavaScript requests `<audio src="https://another.com/audio.ogg">`. `UrlIndex::GetByUrl` is called.
    * **Logic:** No valid `UrlData` is found. `NewUrlData` is called to create a new `UrlData` object.
    * **Output:** A new `UrlData` object is returned, and the browser will proceed to fetch the resource from the network.

* **Scenario 3 (Redirect):**
    * **Input:** Fetching `https://short.url/video` results in a 302 redirect to `https://cdn.example.com/actual_video.mp4`.
    * **Logic:** The `UrlData` for `https://short.url/video` will call `RedirectTo` with the `UrlData` for the new URL. Cached data might be transferred.
    * **Output:** Future requests for `https://short.url/video` might be handled by the `UrlData` for the redirected URL (depending on caching policies).

**5. Common Usage Errors:**

Thinking about how developers might misuse these features:

* **Assuming Caching Always Works:** Developers might assume a resource is cached when it isn't, leading to unexpected network requests. Understanding the `Valid()` method's logic is crucial.
* **Incorrect CORS Configuration:**  If the server doesn't send the correct CORS headers, the `UrlData` might not be considered valid, even if it's technically cached.
* **Not Handling Redirects Properly:** While the browser handles redirects internally, understanding the `RedirectTo` mechanism can be helpful for debugging caching issues.
* **Over-Reliance on Cache and Ignoring Server Headers:**  Developers need to be aware of server-side caching headers (like `Cache-Control`, `Expires`) that influence how the browser caches resources, and how `UrlIndex` respects these directives.

**6. Iteration and Refinement:**

After drafting the initial explanation, reviewing and refining it is essential. This involves:

* **Clarity and Conciseness:**  Ensuring the explanation is easy to understand and avoids jargon where possible.
* **Accuracy:** Double-checking the code to ensure the explanations are correct.
* **Completeness:**  Making sure all key aspects of the file's functionality are covered.
* **Examples:** Providing concrete examples to illustrate the concepts.

By following these steps, we can arrive at a comprehensive and informative explanation of the `url_index.cc` file. The process involves understanding the code's structure and purpose, connecting it to relevant web technologies, and considering practical usage scenarios and potential pitfalls.
这个 `blink/renderer/platform/media/url_index.cc` 文件是 Chromium Blink 渲染引擎中负责 **管理媒体资源 URL 及其相关元数据和缓存** 的核心组件。它主要用于优化媒体资源的加载和播放性能，并处理一些与安全和缓存相关的策略。

以下是它的主要功能分解：

**1. URL 数据管理 (UrlData Class):**

* **存储 URL 的元数据:** `UrlData` 类负责存储与特定 URL 相关的各种信息，例如：
    * **URL 本身 (`url_`)**
    * **CORS 策略 (`cors_mode_`)**:  用于处理跨域资源请求。
    * **资源长度 (`length_`)**:  媒体资源的预期大小。
    * **是否支持 Range 请求 (`range_supported_`)**:  指示服务器是否支持请求资源的特定部分。
    * **是否可缓存 (`cacheable_`)**:  指示资源是否可以被缓存。
    * **缓存查找模式 (`cache_lookup_mode_`)**:  控制如何进行缓存查找 (例如，正常查找、禁用缓存等)。
    * **上次修改时间 (`last_modified_`) 和 ETag (`etag_`)**:  用于缓存验证。
    * **是否已通过 Timing-Allow-Origin 检查 (`passed_timing_allow_origin_check_`)**:  用于防止某些跨域信息泄露。
    * **从缓存读取的字节数 (`bytes_read_from_cache_`)**:  用于统计。
    * **是否是跨域 CORS 请求 (`is_cors_cross_origin_`)**
    * **是否有 Access-Control-Allow-Origin 头 (`has_access_control_`)**
    * **指向实际缓存数据的 `ResourceMultiBuffer` 对象 (`multibuffer_`)**
* **管理缓存数据:** `UrlData` 内部关联着一个 `ResourceMultiBuffer` 对象，用于实际存储和管理下载的媒体数据块。
* **处理重定向:** `RedirectTo` 和 `Fail` 方法用于处理 HTTP 重定向和加载失败的情况。
* **维护有效性状态:** `Valid()` 方法检查 `UrlData` 是否仍然有效，例如是否过期或需要重新验证。
* **合并元数据:** `MergeFrom` 方法用于合并来自其他 `UrlData` 实例的元数据，这在处理重定向或多个请求指向同一资源时很有用。
* **管理回调:** `OnRedirect` 方法允许注册回调函数，在发生重定向时被调用。
* **跟踪最后使用时间:** `Use()` 方法更新 `UrlData` 的最后使用时间，用于缓存淘汰策略。

**2. URL 索引 (UrlIndex Class):**

* **维护 URL 数据的索引:** `UrlIndex` 类负责维护一个 `UrlDataMap`，用于存储和查找 `UrlData` 对象。键是 URL 和 CORS 模式的组合。
* **提供获取 `UrlData` 的接口:** `GetByUrl` 方法根据 URL 和 CORS 模式查找或创建 `UrlData` 对象。
* **管理缓存淘汰 (LRU):** `UrlIndex` 使用一个 `MultiBuffer::GlobalLRU` 对象来实现最近最少使用 (Least Recently Used) 的缓存淘汰策略，以限制内存使用。
* **处理内存压力:** `OnMemoryPressure` 方法响应系统内存压力事件，并尝试释放缓存的内存。
* **插入和更新 `UrlData`:** `TryInsert` 方法尝试插入或更新 `UrlData` 对象到索引中，并处理一些冲突情况，例如已存在相同 URL 的 `UrlData` 但元数据不同。
* **删除 `UrlData`:** `RemoveUrlData` 方法从索引中移除不再需要的 `UrlData` 对象。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件直接服务于浏览器中媒体元素的加载和播放，例如 `<video>` 和 `<audio>` 标签。

* **HTML (`<video>`, `<audio>`):** 当 HTML 中包含 `<video src="video.mp4">` 或 `<audio src="audio.ogg">` 时，Blink 的媒体管道会使用 `UrlIndex` 来查找或创建与这些 URL 关联的 `UrlData` 对象。`UrlData` 管理着这些媒体资源的缓存和元数据。
    * **举例:**  当用户首次访问包含 `<video src="https://example.com/movie.mp4">` 的页面时，`UrlIndex` 可能会创建一个新的 `UrlData` 对象来跟踪 `https://example.com/movie.mp4`。下载的视频数据会被存储在与该 `UrlData` 关联的 `ResourceMultiBuffer` 中。如果用户稍后再次访问该页面，`UrlIndex` 可以找到已存在的 `UrlData`，并利用缓存的数据加速加载。

* **JavaScript (通过 Media API):** JavaScript 可以通过 Media API (例如 `HTMLMediaElement`) 控制媒体元素的播放。Blink 内部会使用 `UrlIndex` 来管理这些媒体资源。
    * **举例:** JavaScript 代码设置 `videoElement.src = "https://example.com/another_movie.mp4"` 时，Blink 同样会通过 `UrlIndex` 来处理这个新的 URL。如果浏览器已经缓存了该视频，`UrlIndex` 可以快速提供缓存的数据，从而实现更快的加载速度。

* **CSS (间接关系):** CSS 本身不直接与 `url_index.cc` 交互。但是，如果 CSS 中使用了媒体资源 (例如，通过 `url()` 函数引用图片或视频)，那么当浏览器加载这些 CSS 引用的资源时，`UrlIndex` 可能会参与到这些资源的缓存管理中 (尽管这通常由更通用的资源加载机制处理，而不是专门为媒体元素设计的 `url_index.cc`)。
    * **举例:** 如果 CSS 中有 `background-image: url("video_thumbnail.png");`，当浏览器加载这个背景图片时，相关的缓存管理可能也会涉及到类似的机制，但 `url_index.cc` 主要关注的是 `<video>` 和 `<audio>` 等媒体元素。

**逻辑推理、假设输入与输出:**

假设有以下场景：

**输入:**

1. **用户访问包含 `<video src="https://test.com/video.mp4">` 的页面。**
2. **`UrlIndex` 中没有 `https://test.com/video.mp4` 的有效 `UrlData`。**

**逻辑推理:**

* `UrlIndex::GetByUrl("https://test.com/video.mp4", ...)` 被调用。
* 由于没有找到有效的 `UrlData`，`NewUrlData` 被调用创建一个新的 `UrlData` 对象。
* 新的 `UrlData` 对象被添加到 `UrlIndex` 的 `indexed_data_` 中。
* 浏览器开始从 `https://test.com/video.mp4` 下载数据，数据被写入与该 `UrlData` 关联的 `ResourceMultiBuffer`。
* 下载过程中，`UrlData` 可能会更新其 `length_`、`range_supported_` 等元数据。

**输出:**

* `UrlIndex::GetByUrl` 返回新创建的 `UrlData` 对象。
* `UrlIndex` 的 `indexed_data_` 中现在包含 `https://test.com/video.mp4` 的 `UrlData`。
* 媒体元素开始播放视频。

**假设输入与输出 (缓存命中场景):**

**输入:**

1. **用户再次访问包含 `<video src="https://test.com/video.mp4">` 的页面。**
2. **`UrlIndex` 中存在 `https://test.com/video.mp4` 的有效 `UrlData` (假设之前已成功加载并缓存)。**

**逻辑推理:**

* `UrlIndex::GetByUrl("https://test.com/video.mp4", ...)` 被调用。
* `indexed_data_` 中找到了有效的 `UrlData`。
* `UrlData::Valid()` 返回 `true` (假设缓存未过期)。

**输出:**

* `UrlIndex::GetByUrl` 返回缓存的 `UrlData` 对象。
* 浏览器可以直接从缓存中读取视频数据，加速加载。

**用户或编程常见的使用错误举例:**

* **错误地假设资源总是被缓存:** 开发者可能会错误地认为一旦资源被加载过就会永久缓存，而忽略了缓存失效、内存压力等因素。
    * **举例:**  一个网页依赖一个视频广告，开发者假设这个广告视频只会被下载一次。但如果用户的缓存被清理，或者系统内存压力大，视频可能需要重新下载。
* **CORS 配置错误导致缓存失效:**  如果服务器的 CORS 配置不正确，浏览器可能无法有效地缓存跨域资源。
    * **举例:** 一个网站引用了来自另一个域名的视频，但服务器没有设置正确的 `Access-Control-Allow-Origin` 头，浏览器可能不会缓存这个视频，或者在每次访问时都进行额外的 CORS 预检请求。
* **不理解 Range 请求的影响:**  开发者可能不清楚服务器是否支持 Range 请求，以及这如何影响缓存的粒度和效率。
    * **举例:**  如果服务器不支持 Range 请求，浏览器可能需要下载整个媒体文件才能播放，即使只需要播放其中的一小段。`UrlData` 的 `range_supported_` 字段记录了这方面的信息。
* **忘记处理重定向:**  开发者在处理媒体资源 URL 时，需要考虑到 HTTP 重定向的可能性。`UrlData` 的 `RedirectTo` 方法用于处理这种情况，但如果上层逻辑没有正确处理重定向，可能会导致缓存混乱或加载失败。

总而言之，`blink/renderer/platform/media/url_index.cc` 是 Blink 引擎中一个关键的媒体资源管理模块，它通过维护 URL 索引和管理缓存数据，显著提升了媒体资源的加载效率和用户体验。理解其功能有助于开发者更好地理解浏览器如何处理媒体资源，并避免一些常见的错误。

Prompt: 
```
这是目录为blink/renderer/platform/media/url_index.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/media/url_index.h"

#include <set>
#include <utility>

#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/ranges/algorithm.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "media/base/media_switches.h"
#include "third_party/blink/renderer/platform/media/resource_multi_buffer_data_provider.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"

namespace blink {

const int kBlockSizeShift = 15;  // 1<<15 == 32kb
const int kUrlMappingTimeoutSeconds = 300;

ResourceMultiBuffer::ResourceMultiBuffer(
    UrlData* url_data,
    int block_shift,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : MultiBuffer(block_shift, url_data->url_index_->lru_),
      url_data_(url_data),
      task_runner_(std::move(task_runner)) {}

ResourceMultiBuffer::~ResourceMultiBuffer() = default;

std::unique_ptr<MultiBuffer::DataProvider> ResourceMultiBuffer::CreateWriter(
    const MultiBufferBlockId& pos,
    bool is_client_audio_element) {
  auto writer = std::make_unique<ResourceMultiBufferDataProvider>(
      url_data_, pos, is_client_audio_element, task_runner_);
  writer->Start();
  return writer;
}

bool ResourceMultiBuffer::RangeSupported() const {
  return url_data_->range_supported_;
}

void ResourceMultiBuffer::OnEmpty() {
  url_data_->OnEmpty();
}

UrlData::UrlData(base::PassKey<UrlIndex>,
                 const KURL& url,
                 CorsMode cors_mode,
                 UrlIndex* url_index,
                 CacheMode cache_lookup_mode,
                 scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : UrlData(url,
              cors_mode,
              url_index,
              cache_lookup_mode,
              std::move(task_runner)) {}

UrlData::UrlData(const KURL& url,
                 CorsMode cors_mode,
                 UrlIndex* url_index,
                 CacheMode cache_lookup_mode,
                 scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : url_(url),
      have_data_origin_(false),
      cors_mode_(cors_mode),
      has_access_control_(false),
      url_index_(url_index),
      length_(kPositionNotSpecified),
      range_supported_(false),
      cacheable_(false),
      cache_lookup_mode_(cache_lookup_mode),
      multibuffer_(this, url_index_->block_shift_, std::move(task_runner)) {}

UrlData::~UrlData() = default;

std::pair<KURL, UrlData::CorsMode> UrlData::key() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return std::make_pair(url(), cors_mode());
}

void UrlData::set_valid_until(base::Time valid_until) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  valid_until_ = valid_until;
}

void UrlData::MergeFrom(const scoped_refptr<UrlData>& other) {
  // We're merging from another UrlData that refers to the *same*
  // resource, so when we merge the metadata, we can use the most
  // optimistic values.
  if (ValidateDataOrigin(other->data_origin_)) {
    DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
    valid_until_ = std::max(valid_until_, other->valid_until_);
    // set_length() will not override the length if already known.
    set_length(other->length_);
    cacheable_ |= other->cacheable_;
    cache_lookup_mode_ = other->cache_lookup_mode_;
    range_supported_ |= other->range_supported_;
    if (last_modified_.is_null()) {
      last_modified_ = other->last_modified_;
    }
    bytes_read_from_cache_ += other->bytes_read_from_cache_;
    // is_cors_corss_origin_ will not relax from true to false.
    set_is_cors_cross_origin(other->is_cors_cross_origin_);
    has_access_control_ |= other->has_access_control_;
    multibuffer()->MergeFrom(other->multibuffer());
  }
}

void UrlData::set_cacheable(bool cacheable) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  cacheable_ = cacheable;
}

void UrlData::set_length(int64_t length) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (length != kPositionNotSpecified) {
    length_ = length;
  }
}

void UrlData::set_is_cors_cross_origin(bool is_cors_cross_origin) {
  if (is_cors_cross_origin_)
    return;
  is_cors_cross_origin_ = is_cors_cross_origin;
}

void UrlData::set_has_access_control() {
  has_access_control_ = true;
}

void UrlData::set_mime_type(std::string mime_type) {
  mime_type_ = std::move(mime_type);
}

void UrlData::set_passed_timing_allow_origin_check(
    bool passed_timing_allow_origin_check) {
  passed_timing_allow_origin_check_ = passed_timing_allow_origin_check;
}

void UrlData::RedirectTo(const scoped_refptr<UrlData>& url_data) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  // Copy any cached data over to the new location.
  url_data->multibuffer()->MergeFrom(multibuffer());

  std::vector<RedirectCB> redirect_callbacks;
  redirect_callbacks.swap(redirect_callbacks_);
  for (RedirectCB& cb : redirect_callbacks) {
    std::move(cb).Run(url_data);
  }
}

void UrlData::Fail() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  // Handled similar to a redirect.
  std::vector<RedirectCB> redirect_callbacks;
  redirect_callbacks.swap(redirect_callbacks_);
  for (RedirectCB& cb : redirect_callbacks) {
    std::move(cb).Run(nullptr);
  }
}

void UrlData::OnRedirect(RedirectCB cb) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  redirect_callbacks_.push_back(std::move(cb));
}

void UrlData::Use() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  last_used_ = base::Time::Now();
}

bool UrlData::ValidateDataOrigin(const KURL& origin) {
  if (!have_data_origin_) {
    data_origin_ = origin;
    have_data_origin_ = true;
    return true;
  }
  if (cors_mode_ == UrlData::CORS_UNSPECIFIED) {
    return SecurityOrigin::SecurityOrigin::AreSameOrigin(data_origin_, origin);
  }
  // The actual cors checks is done in the net layer.
  return true;
}

void UrlData::OnEmpty() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  url_index_->RemoveUrlData(this);
}

bool UrlData::FullyCached() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (length_ == kPositionNotSpecified)
    return false;
  // Check that the first unavailable block in the cache is after the
  // end of the file.
  return (multibuffer()->FindNextUnavailable(0) << kBlockSizeShift) >= length_;
}

bool UrlData::Valid() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  base::Time now = base::Time::Now();
  if (!range_supported_ && !FullyCached())
    return false;
  // When ranges are not supported, we cannot re-use cached data.
  if (valid_until_ > now)
    return true;
  if (now - last_used_ < base::Seconds(kUrlMappingTimeoutSeconds))
    return true;
  return false;
}

void UrlData::set_last_modified(base::Time last_modified) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  last_modified_ = last_modified;
}

void UrlData::set_etag(const std::string& etag) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  etag_ = etag;
}

void UrlData::set_range_supported() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  range_supported_ = true;
}

ResourceMultiBuffer* UrlData::multibuffer() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return &multibuffer_;
}

size_t UrlData::CachedSize() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return multibuffer()->map().size();
}

UrlIndex::UrlIndex(ResourceFetchContext* fetch_context,
                   scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : UrlIndex(fetch_context, kBlockSizeShift, std::move(task_runner)) {}

UrlIndex::UrlIndex(ResourceFetchContext* fetch_context,
                   int block_shift,
                   scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : fetch_context_(fetch_context),
      lru_(base::MakeRefCounted<MultiBuffer::GlobalLRU>(task_runner)),
      block_shift_(block_shift),
      memory_pressure_listener_(FROM_HERE,
                                base::BindRepeating(&UrlIndex::OnMemoryPressure,
                                                    base::Unretained(this))),
      task_runner_(std::move(task_runner)) {}

UrlIndex::~UrlIndex() {
#if DCHECK_IS_ON()
  // Verify that only |this| holds reference to UrlData instances.
  auto dcheck_has_one_ref = [](const UrlDataMap::value_type& entry) {
    DCHECK(entry.value->HasOneRef());
  };
  base::ranges::for_each(indexed_data_, dcheck_has_one_ref);
#endif
}

void UrlIndex::RemoveUrlData(const scoped_refptr<UrlData>& url_data) {
  DCHECK(url_data->multibuffer()->map().empty());

  auto i = indexed_data_.find(url_data->key());
  if (i != indexed_data_.end() && i->value == url_data) {
    indexed_data_.erase(i);
  }
}

scoped_refptr<UrlData> UrlIndex::GetByUrl(const KURL& url,
                                          UrlData::CorsMode cors_mode,
                                          UrlData::CacheMode cache_mode) {
  if (cache_mode == UrlData::kNormal) {
    auto i = indexed_data_.find(std::make_pair(url, cors_mode));
    if (i != indexed_data_.end() && i->value->Valid()) {
      return i->value;
    }
  }

  return NewUrlData(url, cors_mode, cache_mode);
}

scoped_refptr<UrlData> UrlIndex::NewUrlData(
    const KURL& url,
    UrlData::CorsMode cors_mode,
    UrlData::CacheMode cache_lookup_mode) {
  return base::MakeRefCounted<UrlData>(base::PassKey<UrlIndex>(), url,
                                       cors_mode, this, cache_lookup_mode,
                                       task_runner_);
}

void UrlIndex::OnMemoryPressure(
    base::MemoryPressureListener::MemoryPressureLevel memory_pressure_level) {
  switch (memory_pressure_level) {
    case base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_NONE:
      break;
    case base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_MODERATE:
      lru_->TryFree(128);  // try to free 128 32kb blocks if possible
      break;
    case base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_CRITICAL:
      lru_->TryFreeAll();  // try to free as many blocks as possible
      break;
  }
}

namespace {
bool IsStrongEtag(const std::string& etag) {
  return etag.size() > 2 && etag[0] == '"';
}

bool IsNewDataForSameResource(const scoped_refptr<UrlData>& new_entry,
                              const scoped_refptr<UrlData>& old_entry) {
  if (IsStrongEtag(new_entry->etag()) && IsStrongEtag(old_entry->etag())) {
    if (new_entry->etag() != old_entry->etag())
      return true;
  }
  if (!new_entry->last_modified().is_null()) {
    if (new_entry->last_modified() != old_entry->last_modified())
      return true;
  }
  return false;
}
}  // namespace

scoped_refptr<UrlData> UrlIndex::TryInsert(
    const scoped_refptr<UrlData>& url_data) {
  auto iter = indexed_data_.find(url_data->key());
  if (iter == indexed_data_.end()) {
    // If valid and not already indexed, index it.
    if (url_data->Valid()) {
      indexed_data_.insert(url_data->key(), url_data);
    }
    return url_data;
  }

  // A UrlData instance for the same key is already indexed.

  // If the indexed instance is the same as |url_data|,
  // nothing needs to be done.
  if (iter->value == url_data) {
    return url_data;
  }

  // The indexed instance is different.
  // Check if it should be replaced with |url_data|.
  if (IsNewDataForSameResource(url_data, iter->value)) {
    if (url_data->Valid()) {
      iter->value = url_data;
    }
    return url_data;
  }

  // If the url data should bypass the cache lookup, we want to not merge it.
  if (url_data->cache_lookup_mode() == UrlData::kCacheDisabled) {
    return url_data;
  }

  if (url_data->Valid()) {
    if ((!iter->value->Valid() ||
         url_data->CachedSize() > iter->value->CachedSize())) {
      iter->value = url_data;
    } else {
      iter->value->MergeFrom(url_data);
    }
  }
  return iter->value;
}

}  // namespace blink

"""

```