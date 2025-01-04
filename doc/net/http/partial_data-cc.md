Response:
Let's break down the thought process to analyze the `partial_data.cc` file and answer the prompt.

1. **Understand the Goal:** The core request is to understand the *functionality* of this C++ file within the Chromium networking stack, particularly how it handles partial content requests. The request also asks for connections to JavaScript, logical reasoning examples, common user/programming errors, and debugging information.

2. **Initial Scan and Identification of Key Concepts:**
   -  The filename `partial_data.cc` immediately suggests it's related to handling requests for parts of a resource.
   -  Keywords like `Range`, `Content-Length`, `Content-Range`, `cache`, `sparse`, `truncated` jump out. These are the building blocks of partial content handling.
   -  The inclusion of Chromium-specific types like `HttpRequestHeaders`, `HttpResponseHeaders`, `disk_cache::Entry`, and `CompletionOnceCallback` indicates its role within the larger Chromium networking architecture.

3. **Core Functionality - Deconstructing the `PartialData` Class:**
   - **Initialization (`Init`):** How is a partial data request recognized? The code checks for the `Range` header. It parses this header to understand the requested byte range. This is a crucial first step.
   - **Header Management (`SetHeaders`, `RestoreHeaders`):** The class stores extra headers. This suggests it needs to manipulate or preserve headers during the partial content handling process. The `RestoreHeaders` method specifically reconstructs the `Range` header based on the current state.
   - **Cache Interaction (`ShouldValidateCache`, `PrepareCacheValidation`, `CacheRead`, `CacheWrite`):** A significant part of the code revolves around interacting with the disk cache. This interaction seems to involve:
      - Determining if a cached portion of the requested range exists.
      - Preparing cache validation requests (potentially modifying headers).
      - Reading from and writing to the cache.
   - **State Tracking (Members like `range_requested_`, `byte_range_`, `current_range_start_`, `resource_size_`, `truncated_`, `sparse_entry_`):** The class maintains various pieces of state, indicating the progress and nature of the partial content request. Understanding these members is key to grasping the class's logic.
   - **Response Handling (`UpdateFromStoredHeaders`, `IsRequestedRangeOK`, `ResponseHeadersOK`, `FixResponseHeaders`, `FixContentLength`):** The class examines and modifies HTTP response headers. This is critical for ensuring the client (browser) receives the correct information about the partial content.
   - **Completion Callbacks (`CompletionOnceCallback`, `GetAvailableRangeCompleted`):**  Asynchronous operations are common in networking. The use of callbacks indicates that the class handles asynchronous cache operations.

4. **Connecting to JavaScript:**
   - **The Browser's Perspective:** JavaScript in web pages initiates requests. If a website uses techniques like range requests for media streaming, large file downloads, or lazy loading, the browser's underlying networking stack (including this C++ code) will be involved.
   - **Specific Examples:** Think of `<video>` tags, where the browser might request chunks of the video as the user watches. `XMLHttpRequest` or `fetch` API calls can also explicitly set `Range` headers.
   - **Focus on the *Mechanism*, Not Direct API:** The C++ code doesn't directly *expose* APIs to JavaScript. It's part of the *implementation* that handles requests initiated by JavaScript.

5. **Logical Reasoning (Assumptions, Inputs, Outputs):**
   - **Scenario:** A browser requests bytes 100-199 of a 1000-byte resource.
   - **Assumptions:** The server supports range requests. The resource might or might not be in the cache.
   - **Input (to `PartialData`):** `HttpRequestHeaders` with `Range: bytes=100-199`.
   - **Output (from `PartialData` - conceptually):** Decisions about cache interaction, modified headers for subsequent requests (if needed), and ultimately, instructions on how to retrieve the requested bytes.

6. **Common Errors:**
   - **User Errors (Conceptual):**  A user might expect a partial download to resume perfectly even if the server doesn't support it or the resource has changed.
   - **Programming Errors (Within Chromium):** Incorrect parsing of `Range` headers, mishandling cache interactions, failing to correctly update response headers, leading to inconsistencies.

7. **Debugging:**
   - **Following the Request Flow:** Start from where the request originates (e.g., a network request in the browser process) and trace how it gets to the networking stack. Look for points where `PartialData` is instantiated and its methods are called.
   - **Logging Statements:** The `DVLOG` statements in the code are invaluable for seeing the values of variables and the flow of execution.
   - **Network Inspection Tools:** Browser developer tools can show the `Range` headers in requests and the `Content-Range` headers in responses.

8. **Structure the Answer:**  Organize the findings logically, starting with the core functionality, then moving to the more specific aspects like JavaScript interaction, examples, errors, and debugging. Use clear headings and bullet points to make the information easy to digest.

9. **Refine and Elaborate:**  After the initial analysis, go back and add more detail. For example, explain *why* certain checks are done in the code. Explain the significance of the different state variables.

By following these steps, we can systematically analyze the provided C++ code and construct a comprehensive answer that addresses all aspects of the prompt. The key is to understand the *purpose* of the code within the broader context of web browsing and network communication.
这个 `net/http/partial_data.cc` 文件是 Chromium 网络栈中用于处理 **部分内容请求 (Partial Content Request)** 的关键组件。它的主要功能是辅助处理 HTTP 状态码为 206 (Partial Content) 的响应，以及与缓存进行交互，以便高效地下载和管理大型资源的部分内容。

以下是它的详细功能列表：

**核心功能:**

1. **处理 Range 请求:**
   - **解析 Range Header:**  `Init()` 方法负责解析 HTTP 请求头中的 `Range` 字段，提取用户请求的字节范围。
   - **存储 Range 信息:**  存储解析出的字节范围信息，包括起始位置和结束位置 (或者后缀长度)。
   - **判断是否为 Range 请求:** 标记请求是否包含 `Range` 头。

2. **与 HTTP 缓存交互:**
   - **校验缓存 (ShouldValidateCache):**  决定是否需要验证缓存中已有的部分数据，以避免重复下载。它会查找缓存中是否存在请求范围内的可用数据。
   - **准备缓存验证请求 (PrepareCacheValidation):**  根据缓存中已有的数据和请求的范围，生成用于缓存验证的 `Range` 请求头。
   - **读取缓存 (CacheRead):** 从磁盘缓存中读取指定范围的数据。它支持读取普通缓存和稀疏缓存 (sparse cache)。
   - **写入缓存 (CacheWrite):** 将从网络下载的数据写入磁盘缓存的指定位置。它也支持写入普通缓存和稀疏缓存。
   - **更新缓存状态 (UpdateFromStoredHeaders):** 从缓存条目的头部信息中更新 `PartialData` 的状态，例如资源大小、是否截断等。

3. **处理 HTTP 响应头:**
   - **检查响应头 (ResponseHeadersOK):**  验证服务器返回的 HTTP 响应头是否符合部分内容请求的规范，例如状态码是否为 206，`Content-Range` 是否有效等。
   - **修正响应头 (FixResponseHeaders):**  在某些情况下，需要修正或调整 HTTP 响应头，例如在完成整个 Range 请求后，将状态码改为 200 OK，并设置正确的 `Content-Length`。
   - **修正 Content-Length (FixContentLength):** 强制设置 `Content-Length` 头为已知的资源总大小。

4. **处理截断 (Truncated) 的资源:**
   - **检测截断:**  识别缓存中存储的是否是不完整的 (截断的) 资源。
   - **发起校验请求:**  当发现截断的资源时，会发起一个特殊的校验请求 (通常是一个字节的 Range 请求) 来探测服务器是否支持断点续传。
   - **设置下载起始位置 (SetRangeToStartDownload):**  如果服务器支持断点续传，则将下载起始位置设置为截断资源的末尾，继续下载剩余部分。

5. **管理下载状态:**
   - **跟踪当前下载的 Range:** 记录当前正在处理的字节范围。
   - **判断当前 Range 是否已缓存 (IsCurrentRangeCached):**  判断当前请求的 Range 是否完全存在于缓存中。
   - **判断是否为最后一个 Range (IsLastRange):**  判断当前请求的 Range 是否是用户请求的最后一个 Range。

**它与 Javascript 的关系:**

`partial_data.cc` 本身是用 C++ 编写的，属于 Chromium 浏览器的底层网络实现，**不直接与 JavaScript 代码交互**。但是，它的功能对 JavaScript 发起的网络请求至关重要。

**举例说明:**

1. **`<video>` 或 `<audio>` 标签的流媒体播放:**
   - 当 JavaScript 代码通过 `<video>` 或 `<audio>` 标签请求播放媒体资源时，浏览器可能会使用 Range 请求来逐步下载媒体的不同部分。
   - `partial_data.cc` 负责处理这些 Range 请求，与缓存交互，并确保下载的各个部分被正确地组合和传递给媒体解码器。

2. **大型文件下载:**
   - 如果一个 JavaScript 应用使用 `fetch` 或 `XMLHttpRequest` API 下载一个大型文件，并且服务器支持 Range 请求，浏览器可能会自动或通过开发者设置使用 Range 请求将下载分成多个部分。
   - `partial_data.cc` 将会处理这些分段下载的逻辑，确保每个部分被正确地请求、缓存和最终组装。

3. **Service Worker 缓存:**
   - Service Worker 可以拦截网络请求，并从缓存中提供响应。如果缓存中存储了部分资源 (例如使用了 Cache API 的 `put` 方法存储了部分数据)，当 Service Worker 响应一个需要完整资源的请求时，`partial_data.cc` 可能会参与到从多个缓存条目中组合完整资源的过程中。

**逻辑推理的假设输入与输出:**

**假设输入:**

- **场景:**  用户通过浏览器请求下载一个大小为 1000 字节的图片 `image.jpg`。
- **首次请求:**  浏览器发送不带 `Range` 头的请求。
- **服务器响应:** 服务器返回 200 OK，包含完整的图片数据。Chromium 将数据缓存。
- **后续请求 (假设缓存过期或需要验证):** 用户再次请求 `image.jpg`。浏览器发送带有 `Range: bytes=500-799` 的请求。

**`partial_data.cc` 的处理流程:**

1. **`Init()` (输入: 请求头包含 `Range: bytes=500-799`):**
   - 输出: `range_requested_ = true`, `byte_range_ = {first_byte_position: 500, last_byte_position: 799}`.

2. **`ShouldValidateCache()` (假设缓存中存在该资源):**
   - 输入: 缓存条目，请求的 Range (500-799)。
   - 输出: 如果缓存中包含部分或全部的 500-799 字节，则返回一个正数表示需要进一步处理。如果缓存中完全没有相关数据，则可能返回 0 或错误码。

3. **`PrepareCacheValidation()` (假设缓存中存在 600-700 字节):**
   - 输入: 缓存条目，请求头 (初始可能为空)。
   - 输出: 修改后的请求头，可能包含 `Range: bytes=500-599` 和 `Range: bytes=700-799` (具体取决于缓存策略和实现)。这里假设需要从网络获取 500-599 和 700-799 这两部分。

4. **`ResponseHeadersOK()` (假设服务器返回 206 Partial Content，`Content-Range: bytes 500-599/1000`):**
   - 输入: 服务器的响应头。
   - 输出: 如果响应头符合预期 (状态码为 206，`Content-Range` 与请求的 Range 匹配)，则返回 `true`。

5. **`CacheWrite()`:**
   - 输入: 从网络下载的数据 (500-599 字节)，缓存条目。
   - 输出: 将数据写入缓存。

6. **重复上述步骤处理剩余的 Range (700-799)。**

7. **`FixResponseHeaders()` (最终将部分内容组合成完整响应，或者用户请求的是整个 Range):**
   - 输入: 最终的响应头。
   - 输出: 根据情况修改响应头，例如如果用户请求的是整个 Range 并且所有数据都已获取，则将状态码改为 200 OK，设置 `Content-Length` 为 1000。

**用户或编程常见的使用错误举例:**

1. **服务器不支持 Range 请求:**
   - **用户操作:**  用户尝试下载一个大型文件，但服务器没有正确配置以支持 `Range` 请求。
   - **`partial_data.cc` 的表现:**  `Init()` 方法会发现没有 `Range` 头，或者服务器返回 200 OK 而不是 206。浏览器会下载整个文件，而不是只下载一部分。

2. **缓存策略不当导致重复下载:**
   - **编程错误:**  开发者设置了过于激进的缓存策略，导致缓存频繁过期，即使服务器支持 Range 请求，也无法充分利用缓存，每次都从头下载部分内容。
   - **`partial_data.cc` 的表现:** 可能会频繁地进行缓存验证，但由于缓存已过期，仍然需要从网络下载数据。

3. **服务器返回错误的 `Content-Range`:**
   - **编程错误 (服务器端):** 服务器在返回 206 响应时，`Content-Range` 头的信息不正确 (例如，起始或结束字节与请求的 Range 不符，或者总长度错误)。
   - **`partial_data.cc` 的表现:** `ResponseHeadersOK()` 方法会检测到 `Content-Range` 错误，并可能导致下载失败或数据不一致。

4. **处理截断资源时的逻辑错误:**
   - **编程错误 (Chromium 内部):**  在处理缓存中已有的截断资源时，如果逻辑出现错误，可能导致发起错误的校验请求，或者无法正确地恢复下载。
   - **`partial_data.cc` 的表现:**  可能无法正确地与缓存交互，导致重复下载已有的部分，或者无法完成下载。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在浏览器中观看一个在线视频：

1. **用户打开包含视频的网页:** 浏览器加载 HTML、CSS 和 JavaScript。
2. **`<video>` 标签发起资源请求:**  浏览器解析 HTML，发现 `<video>` 标签，并根据 `src` 属性发起对视频资源的请求 (例如 `video.mp4`)。
3. **首次请求 (可能不带 Range):** 浏览器首次请求视频资源，服务器可能返回完整的视频数据 (状态码 200 OK)。Chromium 将数据缓存。
4. **拖动播放进度条:** 用户拖动视频播放进度条到某个位置，JavaScript 代码计算出需要播放的新的时间点。
5. **浏览器发起 Range 请求:**  浏览器为了获取视频的新位置的数据，可能会发起一个带有 `Range` 头的请求，例如 `Range: bytes=1000000-1999999`。
6. **网络栈处理 Range 请求:**  这个请求进入 Chromium 的网络栈。
7. **`PartialData::Init()` 被调用:**  网络栈的某个组件创建 `PartialData` 对象，并调用 `Init()` 方法解析请求头中的 `Range` 字段。
8. **缓存查找 (`ShouldValidateCache` 等):** `partial_data.cc` 的方法被调用，检查本地缓存是否已经存在请求范围内的部分数据。
9. **与服务器交互 (如果缓存未命中):** 如果缓存中没有所需的数据，或者需要验证缓存，`partial_data.cc` 会辅助构造新的 `Range` 请求发送给服务器。
10. **处理服务器响应 (`ResponseHeadersOK`):**  当服务器返回响应时 (状态码 206)，`partial_data.cc` 的方法会检查响应头是否符合预期。
11. **缓存写入 (`CacheWrite`):**  下载的数据会被写入缓存。
12. **数据传递给媒体播放器:**  最终，下载的视频数据被传递给浏览器的媒体播放器进行解码和播放。

通过在 Chromium 的网络代码中设置断点，并观察 `PartialData` 对象的创建、方法调用以及相关变量的值，开发者可以追踪部分内容请求的处理流程，定位问题。例如，可以检查 `byte_range_` 的值是否正确解析，缓存查找的结果，以及与服务器交互的请求和响应头信息。

Prompt: 
```
这是目录为net/http/partial_data.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/partial_data.h"

#include <limits>
#include <utility>

#include "base/format_macros.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "net/base/net_errors.h"
#include "net/disk_cache/disk_cache.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_status_code.h"
#include "net/http/http_util.h"

namespace net {

namespace {

// The headers that we have to process.
const char kLengthHeader[] = "Content-Length";
const char kRangeHeader[] = "Content-Range";
const int kDataStream = 1;

}  // namespace

PartialData::PartialData() = default;

PartialData::~PartialData() = default;

bool PartialData::Init(const HttpRequestHeaders& headers) {
  std::optional<std::string> range_header =
      headers.GetHeader(HttpRequestHeaders::kRange);
  if (!range_header) {
    range_requested_ = false;
    return false;
  }
  range_requested_ = true;

  std::vector<HttpByteRange> ranges;
  if (!HttpUtil::ParseRangeHeader(range_header.value(), &ranges) ||
      ranges.size() != 1) {
    return false;
  }

  // We can handle this range request.
  byte_range_ = ranges[0];
  user_byte_range_ = byte_range_;
  if (!byte_range_.IsValid())
    return false;

  current_range_start_ = byte_range_.first_byte_position();

  DVLOG(1) << "Range start: " << current_range_start_ << " end: " <<
               byte_range_.last_byte_position();
  return true;
}

void PartialData::SetHeaders(const HttpRequestHeaders& headers) {
  DCHECK(extra_headers_.IsEmpty());
  extra_headers_ = headers;
}

void PartialData::RestoreHeaders(HttpRequestHeaders* headers) const {
  DCHECK(current_range_start_ >= 0 || byte_range_.IsSuffixByteRange());
  int64_t end = byte_range_.IsSuffixByteRange()
                    ? byte_range_.suffix_length()
                    : byte_range_.last_byte_position();

  *headers = extra_headers_;
  if (truncated_ || !byte_range_.IsValid())
    return;

  if (current_range_start_ < 0) {
    headers->SetHeader(HttpRequestHeaders::kRange,
                       HttpByteRange::Suffix(end).GetHeaderValue());
  } else {
    headers->SetHeader(HttpRequestHeaders::kRange,
                       HttpByteRange::Bounded(
                           current_range_start_, end).GetHeaderValue());
  }
}

int PartialData::ShouldValidateCache(disk_cache::Entry* entry,
                                     CompletionOnceCallback callback) {
  DCHECK_GE(current_range_start_, 0);

  // Scan the disk cache for the first cached portion within this range.
  int len = GetNextRangeLen();
  if (!len)
    return 0;

  DVLOG(3) << "ShouldValidateCache len: " << len;

  if (sparse_entry_) {
    DCHECK(callback_.is_null());
    disk_cache::RangeResultCallback cb = base::BindOnce(
        &PartialData::GetAvailableRangeCompleted, weak_factory_.GetWeakPtr());
    disk_cache::RangeResult range =
        entry->GetAvailableRange(current_range_start_, len, std::move(cb));

    cached_min_len_ =
        range.net_error == OK ? range.available_len : range.net_error;
    if (cached_min_len_ == ERR_IO_PENDING) {
      callback_ = std::move(callback);
      return ERR_IO_PENDING;
    } else {
      cached_start_ = range.start;
    }
  } else if (!truncated_) {
    if (byte_range_.HasFirstBytePosition() &&
        byte_range_.first_byte_position() >= resource_size_) {
      // The caller should take care of this condition because we should have
      // failed IsRequestedRangeOK(), but it's better to be consistent here.
      len = 0;
    }
    cached_min_len_ = len;
    cached_start_ = current_range_start_;
  }

  if (cached_min_len_ < 0)
    return cached_min_len_;

  // Return a positive number to indicate success (versus error or finished).
  return 1;
}

void PartialData::PrepareCacheValidation(disk_cache::Entry* entry,
                                         HttpRequestHeaders* headers) {
  DCHECK_GE(current_range_start_, 0);
  DCHECK_GE(cached_min_len_, 0);

  int len = GetNextRangeLen();
  if (!len) {
    // Stored body is empty, so just use the original range header.
    headers->SetHeader(HttpRequestHeaders::kRange,
                       user_byte_range_.GetHeaderValue());
    return;
  }
  range_present_ = false;

  *headers = extra_headers_;

  if (!cached_min_len_) {
    // We don't have anything else stored.
    final_range_ = true;
    cached_start_ =
        byte_range_.HasLastBytePosition() ? current_range_start_  + len : 0;
  }

  if (current_range_start_ == cached_start_) {
    // The data lives in the cache.
    range_present_ = true;
    current_range_end_ = cached_start_ + cached_min_len_ - 1;
    if (len == cached_min_len_)
      final_range_ = true;
  } else {
    // This range is not in the cache.
    current_range_end_ = cached_start_ - 1;
  }
  headers->SetHeader(
      HttpRequestHeaders::kRange,
      HttpByteRange::Bounded(current_range_start_, current_range_end_)
          .GetHeaderValue());
}

bool PartialData::IsCurrentRangeCached() const {
  return range_present_;
}

bool PartialData::IsLastRange() const {
  return final_range_;
}

bool PartialData::UpdateFromStoredHeaders(const HttpResponseHeaders* headers,
                                          disk_cache::Entry* entry,
                                          bool truncated,
                                          bool writing_in_progress) {
  resource_size_ = 0;
  if (truncated) {
    DCHECK_EQ(headers->response_code(), 200);
    // We don't have the real length and the user may be trying to create a
    // sparse entry so let's not write to this entry.
    if (byte_range_.IsValid())
      return false;

    if (!headers->HasStrongValidators())
      return false;

    // Now we avoid resume if there is no content length, but that was not
    // always the case so double check here.
    int64_t total_length = headers->GetContentLength();
    if (total_length <= 0)
      return false;

    // In case we see a truncated entry, we first send a network request for
    // 1 byte range with If-Range: to probe server support for resumption.
    // The setting of |current_range_start_| and |cached_start_| below (with any
    // positive value of |cached_min_len_|) results in that.
    //
    // Setting |initial_validation_| to true is how this communicates to
    // HttpCache::Transaction that we're doing that (and that it's not the user
    // asking for one byte), so if it sees a 206 with that flag set it will call
    // SetRangeToStartDownload(), and then restart the process looking for the
    // entire file (which is what the user wanted), with the cache handling
    // the previous portion, and then a second network request for the entire
    // rest of the range. A 200 in response to the probe request can be simply
    // returned directly to the user.
    truncated_ = true;
    initial_validation_ = true;
    sparse_entry_ = false;
    int current_len = entry->GetDataSize(kDataStream);
    byte_range_.set_first_byte_position(current_len);
    resource_size_ = total_length;
    current_range_start_ = current_len;
    cached_min_len_ = current_len;
    cached_start_ = current_len + 1;
    return true;
  }

  sparse_entry_ = (headers->response_code() == HTTP_PARTIAL_CONTENT);

  if (writing_in_progress || sparse_entry_) {
    // |writing_in_progress| means another Transaction is still fetching the
    // body, so the only way we can see the length is if the server sent it
    // in Content-Length -- GetDataSize would just return what got written
    // thus far.
    //
    // |sparse_entry_| means a 206, and for those FixContentLength arranges it
    // so that Content-Length written to the cache has the full length (on wire
    // it's for a particular range only); while GetDataSize would be unusable
    // since the data is stored using WriteSparseData, and not in the usual data
    // stream.
    resource_size_ = headers->GetContentLength();
    if (resource_size_ <= 0)
      return false;
  } else {
    // If we can safely use GetDataSize, it's preferrable since it's usable for
    // things w/o Content-Length, such as chunked content.
    resource_size_ = entry->GetDataSize(kDataStream);
  }

  DVLOG(2) << "UpdateFromStoredHeaders size: " << resource_size_;

  if (sparse_entry_) {
    // If our previous is a 206, we need strong validators as we may be
    // stiching the cached data and network data together.
    if (!headers->HasStrongValidators())
      return false;
    // Make sure that this is really a sparse entry.
    return entry->CouldBeSparse();
  }
  return true;
}

void PartialData::SetRangeToStartDownload() {
  DCHECK(truncated_);
  DCHECK(!sparse_entry_);
  current_range_start_ = 0;
  cached_start_ = 0;
  initial_validation_ = false;
}

bool PartialData::IsRequestedRangeOK() {
  if (byte_range_.IsValid()) {
    if (!byte_range_.ComputeBounds(resource_size_))
      return false;
    if (truncated_)
      return true;

    if (current_range_start_ < 0)
      current_range_start_ = byte_range_.first_byte_position();
  } else {
    // This is not a range request but we have partial data stored.
    current_range_start_ = 0;
    byte_range_.set_last_byte_position(resource_size_ - 1);
  }

  bool rv = current_range_start_ >= 0;
  if (!rv)
    current_range_start_ = 0;

  return rv;
}

bool PartialData::ResponseHeadersOK(const HttpResponseHeaders* headers) {
  if (headers->response_code() == HTTP_NOT_MODIFIED) {
    if (!byte_range_.IsValid() || truncated_)
      return true;

    // We must have a complete range here.
    return byte_range_.HasFirstBytePosition() &&
        byte_range_.HasLastBytePosition();
  }

  int64_t start, end, total_length;
  if (!headers->GetContentRangeFor206(&start, &end, &total_length))
    return false;
  if (total_length <= 0)
    return false;

  DCHECK_EQ(headers->response_code(), 206);

  // A server should return a valid content length with a 206 (per the standard)
  // but relax the requirement because some servers don't do that.
  int64_t content_length = headers->GetContentLength();
  if (content_length > 0 && content_length != end - start + 1)
    return false;

  if (!resource_size_) {
    // First response. Update our values with the ones provided by the server.
    resource_size_ = total_length;
    if (!byte_range_.HasFirstBytePosition()) {
      byte_range_.set_first_byte_position(start);
      current_range_start_ = start;
    }
    if (!byte_range_.HasLastBytePosition())
      byte_range_.set_last_byte_position(end);
  } else if (resource_size_ != total_length) {
    return false;
  }

  if (truncated_) {
    if (!byte_range_.HasLastBytePosition())
      byte_range_.set_last_byte_position(end);
  }

  if (start != current_range_start_)
    return false;

  if (!current_range_end_) {
    // There is nothing in the cache.
    DCHECK(byte_range_.HasLastBytePosition());
    current_range_end_ = byte_range_.last_byte_position();
    if (current_range_end_ >= resource_size_) {
      // We didn't know the real file size, and the server is saying that the
      // requested range goes beyond the size. Fix it.
      current_range_end_ = end;
      byte_range_.set_last_byte_position(end);
    }
  }

  // If we received a range, but it's not exactly the range we asked for, avoid
  // trouble and signal an error.
  if (end != current_range_end_)
    return false;

  return true;
}

// We are making multiple requests to complete the range requested by the user.
// Just assume that everything is fine and say that we are returning what was
// requested.
void PartialData::FixResponseHeaders(HttpResponseHeaders* headers,
                                     bool success) {
  if (truncated_)
    return;

  if (!success) {
    headers->ReplaceStatusLine("HTTP/1.1 416 Requested Range Not Satisfiable");
    headers->SetHeader(
        kRangeHeader, base::StringPrintf("bytes 0-0/%" PRId64, resource_size_));
    headers->SetHeader(kLengthHeader, "0");
    return;
  }

  if (byte_range_.IsValid() && resource_size_) {
    headers->UpdateWithNewRange(byte_range_, resource_size_, !sparse_entry_);
  } else {
    if (headers->response_code() == HTTP_PARTIAL_CONTENT) {
      // TODO(rvargas): Is it safe to change the protocol version?
      headers->ReplaceStatusLine("HTTP/1.1 200 OK");
    }
    headers->RemoveHeader(kRangeHeader);
    headers->SetHeader(kLengthHeader,
                       base::StringPrintf("%" PRId64, resource_size_));
  }
}

void PartialData::FixContentLength(HttpResponseHeaders* headers) {
  headers->SetHeader(kLengthHeader,
                     base::StringPrintf("%" PRId64, resource_size_));
}

int PartialData::CacheRead(disk_cache::Entry* entry,
                           IOBuffer* data,
                           int data_len,
                           CompletionOnceCallback callback) {
  int read_len = std::min(data_len, cached_min_len_);
  if (!read_len)
    return 0;

  int rv = 0;
  if (sparse_entry_) {
    rv = entry->ReadSparseData(current_range_start_, data, read_len,
                               std::move(callback));
  } else {
    if (current_range_start_ > std::numeric_limits<int32_t>::max())
      return ERR_INVALID_ARGUMENT;

    rv = entry->ReadData(kDataStream, static_cast<int>(current_range_start_),
                         data, read_len, std::move(callback));
  }
  return rv;
}

int PartialData::CacheWrite(disk_cache::Entry* entry,
                            IOBuffer* data,
                            int data_len,
                            CompletionOnceCallback callback) {
  DVLOG(3) << "To write: " << data_len;
  if (sparse_entry_) {
    return entry->WriteSparseData(current_range_start_, data, data_len,
                                  std::move(callback));
  } else  {
    if (current_range_start_ > std::numeric_limits<int32_t>::max())
      return ERR_INVALID_ARGUMENT;

    return entry->WriteData(kDataStream, static_cast<int>(current_range_start_),
                            data, data_len, std::move(callback), true);
  }
}

void PartialData::OnCacheReadCompleted(int result) {
  DVLOG(3) << "Read: " << result;
  if (result > 0) {
    current_range_start_ += result;
    cached_min_len_ -= result;
    DCHECK_GE(cached_min_len_, 0);
  }
}

void PartialData::OnNetworkReadCompleted(int result) {
  if (result > 0)
    current_range_start_ += result;
}

int PartialData::GetNextRangeLen() {
  if (!resource_size_) {
    return 0;
  }
  int64_t range_len =
      byte_range_.HasLastBytePosition()
          ? byte_range_.last_byte_position() - current_range_start_ + 1
          : std::numeric_limits<int32_t>::max();
  if (range_len > std::numeric_limits<int32_t>::max())
    range_len = std::numeric_limits<int32_t>::max();
  return static_cast<int32_t>(range_len);
}

void PartialData::GetAvailableRangeCompleted(
    const disk_cache::RangeResult& result) {
  DCHECK(!callback_.is_null());
  DCHECK_NE(ERR_IO_PENDING, result.net_error);

  int len_or_error =
      result.net_error == OK ? result.available_len : result.net_error;
  cached_start_ = result.start;
  cached_min_len_ = len_or_error;

  // ShouldValidateCache has an unusual convention where 0 denotes EOF,
  // so convert end of range to success (since there may be things that need
  // fetching from network or other ranges).
  std::move(callback_).Run(len_or_error >= 0 ? 1 : len_or_error);
}

}  // namespace net

"""

```