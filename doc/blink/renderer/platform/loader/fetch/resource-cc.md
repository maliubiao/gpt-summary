Response:
The user wants a summary of the `Resource` class in the provided C++ code. I need to identify the core functionalities of this class within the Blink rendering engine. Specifically, I should look for:

1. **Core Purpose:** What does this class represent and manage?
2. **Relationship to Web Technologies:** How does it interact with concepts like JavaScript, HTML, and CSS?
3. **Logic and Data Flow:** Are there any clear input/output relationships I can infer?
4. **Potential Errors:** What mistakes could developers make when using this class?

Based on the code, it seems like `Resource` is responsible for managing the lifecycle and data of resources fetched from the network or cache. This includes handling requests, responses, caching, and notifying clients about the resource's status.

Here's a breakdown of my thought process:

* **File Path and Includes:** The path `blink/renderer/platform/loader/fetch/resource.cc` and the included headers (`<stdint.h>`, `<algorithm>`, `ResourceLoaderOptions.h`, etc.) strongly suggest this class is part of the network loading mechanism within Blink.

* **Class Definition and Members:** The `Resource` class has members like `type_`, `status_`, `data_`, `response_`, `loader_`, `clients_`, etc. These members indicate that the class tracks the type, loading status, data content, HTTP response, associated loader, and interested clients for a given resource.

* **Key Methods:**  Methods like `AppendData`, `NotifyFinished`, `FinishAsError`, `SetResponse`, `AddClient`, `RemoveClient`, `CanReuse` point to the core functions of managing resource data, signaling completion or errors, handling responses, and controlling client access.

* **Caching Logic:** The presence of `MemoryCache::Get()` and methods like `CanReuse`, along with considerations for revalidation and `no-store` headers, clearly indicate that this class plays a role in Blink's caching mechanism.

* **Client Notification:** The `clients_` and `finish_observers_` members, along with methods like `NotifyFinished` and `AddClient`, suggest a publish-subscribe pattern for informing interested parties about resource events.

* **Relationship to Web Technologies:** I can infer connections to JavaScript, HTML, and CSS based on the resource types handled (scripts, stylesheets) and the overall role of fetching resources required to render web pages.

* **Logic and Data Flow:** The methods for appending data, setting the response, and finishing the load establish a clear flow of information through the `Resource` object.

* **Potential Errors:** The `FinishAsError` method highlights the possibility of network or loading errors. The complexity of client management and caching could lead to incorrect usage.

Therefore, my plan is to summarize the `Resource` class's role in managing fetched resources, highlighting its connections to web technologies, illustrating logic with hypothetical scenarios, and providing examples of common usage errors.
这是对 Chromium Blink 引擎源代码文件 `blink/renderer/platform/loader/fetch/resource.cc` 的第一部分代码的分析和功能归纳。

**功能列举:**

`Resource.cc` 文件定义了 `Resource` 类，它是 Blink 渲染引擎中用于表示和管理从网络或缓存加载的各种资源的中心类。其核心功能包括：

1. **资源状态管理:**
   - 跟踪资源加载的生命周期状态（例如：未开始、加载中、已缓存、加载错误）。
   - 维护资源的错误信息。
   - 记录资源加载完成的时间。

2. **资源数据存储和访问:**
   - 存储资源的内容数据 (`data_`)，可以以 `SharedBuffer` 的形式存储，支持高效的内存管理。
   - 提供方法追加接收到的数据 (`AppendData`)。
   - 提供方法清空资源数据 (`ClearData`)。
   - 记录资源的编码大小 (`encoded_size_`) 和解码大小 (`decoded_size_`)。

3. **资源请求和响应信息管理:**
   - 存储原始的资源请求头 (`resource_request_`)。
   - 存储资源响应头 (`response_`)。
   - 处理重定向，并存储重定向链中的请求和响应信息 (`redirect_chain_`)。

4. **资源客户端管理:**
   - 维护一个客户端列表 (`clients_`)，这些客户端是需要接收资源加载通知的对象。
   - 提供添加 (`AddClient`) 和移除 (`RemoveClient`) 客户端的方法。
   - 提供在资源加载完成时通知客户端的方法 (`NotifyFinished`)。
   - 区分等待回调的客户端 (`clients_awaiting_callback_`) 和已完成的客户端 (`finished_clients_`)，以处理异步通知。

5. **资源缓存控制:**
   - 参与 Blink 的缓存机制，例如通过 `MemoryCache::Get()` 与内存缓存交互。
   - 确定资源是否可以从缓存中重用 (`CanReuse`)，并考虑请求的凭据模式、请求模式等因素。
   - 实现与 HTTP 缓存相关的逻辑，例如根据 `Cache-Control` 和 `Expires` 头计算新鲜度 (`FreshnessLifetime`)。
   - 处理 `no-store` 指令，尝试从易失性存储中删除资源。

6. **资源完整性检查 (Subresource Integrity - SRI):**
   - 存储资源的完整性元数据 (`IntegrityMetadata`)。
   - 提供方法检查资源的完整性 (`CheckResourceIntegrity`)，并根据检查结果设置 `integrity_disposition_`。

7. **资源完成观察者 (Resource Finish Observers):**
   - 允许添加观察者 (`AddFinishObserver`)，这些观察者会在资源加载完成后得到通知，但不一定需要接收资源数据。

8. **内存管理和性能优化:**
   - 使用 `SharedBuffer` 来高效存储资源数据。
   - 实现内存压力回调 (`OnPurgeMemory`)，允许在内存压力过大时释放解码后的数据。
   - 提供内存转储功能 (`OnMemoryDump`)，用于分析内存使用情况。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **JavaScript:**
    - 当 JavaScript 代码使用 `fetch()` API 或 `XMLHttpRequest` 发起网络请求时，Blink 会创建一个 `Resource` 对象来管理这个请求和响应。
    - 例如，JavaScript 下载一个 JSON 数据：`fetch('data.json').then(response => response.json()).then(data => console.log(data));`  `Resource` 对象会负责加载 `data.json`，并在加载完成后通知 JavaScript 代码（通过 Promise 的 resolve）。
    - 当 JavaScript 加载一个脚本文件 (`<script src="script.js"></script>`) 时，也会创建一个 `Resource` 对象来处理脚本的下载。

* **HTML:**
    - HTML 中的 `<img>` 标签用于加载图片资源。Blink 会创建一个 `Resource` 对象来处理图片的下载和缓存。
    - 例如，`<img src="image.png">` 会导致 Blink 创建一个 `Resource` 对象来获取 `image.png`。
    - `<link rel="stylesheet" href="style.css">` 标签加载 CSS 样式表，同样会创建一个 `Resource` 对象。

* **CSS:**
    - CSS 文件本身就是一个资源，由 `Resource` 对象管理加载。
    - CSS 中使用 `@import` 或 `url()` 引用的图片、字体等资源，也会由相应的 `Resource` 对象进行管理。
    - 例如，在 `style.css` 中有 `background-image: url('bg.png');`，Blink 会为 `bg.png` 创建一个 `Resource` 对象。

**逻辑推理（假设输入与输出）:**

假设输入：

1. **一个对 `image.png` 的网络请求被发起。**
2. **`Resource` 对象被创建，`type_` 设置为 `ResourceType::kImage`。**
3. **网络层开始下载 `image.png` 的数据。**

输出：

1. **`status_` 从 `ResourceStatus::kNotStarted` 变为 `ResourceStatus::kLoading`（虽然代码片段中没有直接展示状态的变更，但可以推断）。**
2. **接收到的数据块会通过 `AppendData` 方法添加到 `data_` (如果 `options_.data_buffering_policy` 为 `kBufferData`)。**
3. **注册为该资源客户端的渲染对象（例如 `HTMLImageElement`）会收到 `DataReceived` 通知。**
4. **当数据下载完成，`NotifyFinished` 方法会被调用，所有客户端会收到完成通知。**
5. **如果加载过程中发生错误，`FinishAsError` 方法会被调用，`status_` 会变为 `ResourceStatus::kLoadError`，客户端会收到错误通知。**

**用户或编程常见的使用错误举例说明:**

1. **忘记添加客户端:** 如果某个对象需要接收资源加载的通知，但没有调用 `AddClient` 将其注册到 `Resource` 对象，那么该对象将不会收到任何通知，导致逻辑错误或界面显示不完整。

   ```c++
   // 错误示例：忘记添加客户端
   class MyImageConsumer : public ResourceClient {
   public:
       void DataReceived(Resource*, base::span<const char>) override { /* 处理数据 */ }
       void NotifyFinished(Resource*) override { /* 处理完成 */ }
   };

   void LoadImage(const KURL& url) {
       ResourceRequest request(url);
       ResourceLoaderOptions options;
       auto resource = Resource::Create(request, ResourceType::kImage, options);
       // MyImageConsumer consumer;
       // resource->AddClient(&consumer, Platform::Current()->GetTaskRunner(blink::TaskType::kNetworking)); // 忘记添加客户端
       // ...启动资源加载...
   }
   ```

2. **在不应该的时候移除客户端:**  如果在资源加载过程中意外地移除了客户端，可能会导致在资源完成时无法正确通知到该客户端，特别是对于需要资源完成才能进行后续操作的场景。

3. **假设资源总是同步加载:** 有些类型的资源（例如小型的 CSS 或脚本）可能在缓存命中时同步返回。但开发者不能假设所有资源都同步加载，应该处理异步加载的情况，尤其是在涉及网络请求时。

4. **不正确地理解缓存行为:**  开发者可能错误地假设资源总是从网络加载，或者总是从缓存加载，而没有考虑到 HTTP 缓存头的控制，可能导致不必要的网络请求或使用了过期的缓存数据。

**功能归纳 (第一部分):**

`blink/renderer/platform/loader/fetch/resource.cc` 文件中的 `Resource` 类是 Blink 渲染引擎中负责管理和跟踪单个资源（例如图片、脚本、样式表）加载的核心组件。它维护着资源的状态、数据、请求/响应信息，并负责通知感兴趣的客户端关于资源加载的进度和结果。它还参与了 Blink 的缓存机制和资源完整性检查。该类的设计旨在提供一个统一的接口来处理各种类型的资源加载，并有效地管理资源生命周期和内存占用。

### 提示词
```
这是目录为blink/renderer/platform/loader/fetch/resource.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
    Copyright (C) 1998 Lars Knoll (knoll@mpi-hd.mpg.de)
    Copyright (C) 2001 Dirk Mueller (mueller@kde.org)
    Copyright (C) 2002 Waldo Bastian (bastian@kde.org)
    Copyright (C) 2006 Samuel Weinig (sam.weinig@gmail.com)
    Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011 Apple Inc. All
    rights reserved.

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

#include "third_party/blink/renderer/platform/loader/fetch/resource.h"

#include <stdint.h>

#include <algorithm>
#include <cassert>
#include <memory>
#include <utility>

#include "base/feature_list.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/default_clock.h"
#include "build/build_config.h"
#include "services/network/public/mojom/fetch_api.mojom-blink.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-shared.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_security_origin.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/instrumentation/instance_counters.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/loader/cors/cors.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_type_names.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_parameters.h"
#include "third_party/blink/renderer/platform/loader/fetch/integrity_metadata.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_client.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_client_walker.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_finish_observer.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_load_timing.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/background_response_processor.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

void NotifyFinishObservers(
    HeapHashSet<WeakMember<ResourceFinishObserver>>* observers) {
  for (const auto& observer : *observers)
    observer->NotifyFinished();
}

void GetSharedBufferMemoryDump(SharedBuffer* buffer,
                               const String& dump_prefix,
                               WebProcessMemoryDump* memory_dump) {
  size_t dump_size;
  String dump_name;
  buffer->GetMemoryDumpNameAndSize(dump_name, dump_size);

  WebMemoryAllocatorDump* dump =
      memory_dump->CreateMemoryAllocatorDump(dump_prefix + dump_name);
  dump->AddScalar("size", "bytes", dump_size);
  memory_dump->AddSuballocation(
      dump->Guid(), String(WTF::Partitions::kAllocatedObjectPoolName));
}

// These response headers are not copied from a revalidated response to the
// cached response headers. For compatibility, this list is based on Chromium's
// net/http/http_response_headers.cc.
const auto kHeadersToIgnoreAfterRevalidation = std::to_array<const char*>({
    "allow",
    "connection",
    "etag",
    "expires",
    "keep-alive",
    "last-modified",
    "proxy-authenticate",
    "proxy-connection",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "www-authenticate",
    "x-frame-options",
    "x-xss-protection",
});

// Some header prefixes mean "Don't copy this header from a 304 response.".
// Rather than listing all the relevant headers, we can consolidate them into
// this list, also grabbed from Chromium's net/http/http_response_headers.cc.
const auto kHeaderPrefixesToIgnoreAfterRevalidation =
    std::to_array<const char*>({"content-", "x-content-", "x-webkit-"});

inline bool ShouldUpdateHeaderAfterRevalidation(const AtomicString& header) {
  for (const auto* header_to_ignore : kHeadersToIgnoreAfterRevalidation) {
    if (EqualIgnoringASCIICase(header, header_to_ignore)) {
      return false;
    }
  }
  for (const auto* header_prefix_to_ignore :
       kHeaderPrefixesToIgnoreAfterRevalidation) {
    if (header.StartsWithIgnoringASCIICase(header_prefix_to_ignore)) {
      return false;
    }
  }
  return true;
}

const base::Clock* g_clock_for_testing = nullptr;

}  // namespace

static inline base::Time Now() {
  const base::Clock* clock = g_clock_for_testing
                                 ? g_clock_for_testing
                                 : base::DefaultClock::GetInstance();
  return clock->Now();
}

Resource::Resource(const ResourceRequestHead& request,
                   ResourceType type,
                   const ResourceLoaderOptions& options)
    : type_(type),
      status_(ResourceStatus::kNotStarted),
      encoded_size_(0),
      decoded_size_(0),
      cache_identifier_(MemoryCache::DefaultCacheIdentifier()),
      link_preload_(false),
      is_alive_(false),
      is_add_remove_client_prohibited_(false),
      revalidation_status_(RevalidationStatus::kNoRevalidatingOrFailed),
      integrity_disposition_(ResourceIntegrityDisposition::kNotChecked),
      options_(options),
      response_timestamp_(Now()),
      resource_request_(request),
      overhead_size_(CalculateOverheadSize()) {
  scoped_refptr<const SecurityOrigin> top_frame_origin =
      resource_request_.TopFrameOrigin();
  if (top_frame_origin) {
    net::SchemefulSite site(top_frame_origin->ToUrlOrigin());
    existing_top_frame_sites_in_cache_.insert(site);
  }

  InstanceCounters::IncrementCounter(InstanceCounters::kResourceCounter);

  if (IsMainThread())
    MemoryPressureListenerRegistry::Instance().RegisterClient(this);
}

Resource::~Resource() {
  InstanceCounters::DecrementCounter(InstanceCounters::kResourceCounter);
}

void Resource::Trace(Visitor* visitor) const {
  visitor->Trace(loader_);
  visitor->Trace(clients_);
  visitor->Trace(clients_awaiting_callback_);
  visitor->Trace(finished_clients_);
  visitor->Trace(finish_observers_);
  visitor->Trace(options_);
  MemoryPressureListener::Trace(visitor);
}

void Resource::SetLoader(ResourceLoader* loader) {
  CHECK(!loader_);
  DCHECK(StillNeedsLoad());
  loader_ = loader;
}

void Resource::CheckResourceIntegrity() {
  // Skip the check and reuse the previous check result, especially on
  // successful revalidation.
  if (integrity_disposition_ != ResourceIntegrityDisposition::kNotChecked) {
    return;
  }

  // Loading error occurred? Then result is uncheckable.
  integrity_report_info_.Clear();
  if (ErrorOccurred()) {
    CHECK(!Data());
    integrity_disposition_ = ResourceIntegrityDisposition::kNetworkError;
    return;
  }

  // No integrity attributes to check? Then we're passing.
  if (IntegrityMetadata().empty()) {
    integrity_disposition_ = ResourceIntegrityDisposition::kPassed;
    return;
  }

  if (SubresourceIntegrity::CheckSubresourceIntegrity(
          IntegrityMetadata(), Data(), Url(), *this, integrity_report_info_)) {
    integrity_disposition_ = ResourceIntegrityDisposition::kPassed;
  } else {
    integrity_disposition_ =
        ResourceIntegrityDisposition::kFailedIntegrityMetadata;
  }

  DCHECK_NE(integrity_disposition_, ResourceIntegrityDisposition::kNotChecked);
}

void Resource::NotifyFinished() {
  CHECK(IsLoaded());

  ResourceClientWalker<ResourceClient> w(clients_);
  while (ResourceClient* c = w.Next()) {
    MarkClientFinished(c);
    c->NotifyFinished(this);
  }
}

void Resource::MarkClientFinished(ResourceClient* client) {
  if (clients_.Contains(client)) {
    finished_clients_.insert(client);
    clients_.erase(client);
  }
}

void Resource::AppendData(
    absl::variant<SegmentedBuffer, base::span<const char>> data) {
  DCHECK(!IsCacheValidator());
  DCHECK(!ErrorOccurred());
  if (absl::holds_alternative<SegmentedBuffer>(data)) {
    AppendDataImpl(std::move(absl::get<SegmentedBuffer>(data)));
  } else {
    CHECK(absl::holds_alternative<base::span<const char>>(data));
    AppendDataImpl(absl::get<base::span<const char>>(data));
  }
}

void Resource::AppendDataImpl(SegmentedBuffer&& buffer) {
  TRACE_EVENT1("blink", "Resource::appendData", "length", buffer.size());
  SegmentedBuffer* data_ptr = &buffer;
  if (options_.data_buffering_policy == kBufferData) {
    CHECK(!data_);
    data_ = SharedBuffer::Create(std::move(buffer));
    data_ptr = data_.get();
    SetEncodedSize(data_->size());
  }
  for (const auto& span : *data_ptr) {
    NotifyDataReceived(span);
  }
}

void Resource::AppendDataImpl(base::span<const char> data) {
  TRACE_EVENT1("blink", "Resource::appendData", "length", data.size());
  if (options_.data_buffering_policy == kBufferData) {
    if (!data_) {
      data_ = SharedBuffer::Create();
    }
    data_->Append(data);
    SetEncodedSize(data_->size());
  }
  NotifyDataReceived(data);
}

void Resource::NotifyDataReceived(base::span<const char> data) {
  ResourceClientWalker<ResourceClient> w(Clients());
  while (ResourceClient* c = w.Next())
    c->DataReceived(this, data);
}

void Resource::SetResourceBuffer(scoped_refptr<SharedBuffer> resource_buffer) {
  DCHECK(!IsCacheValidator());
  DCHECK(!ErrorOccurred());
  DCHECK_EQ(options_.data_buffering_policy, kBufferData);
  data_ = std::move(resource_buffer);
  SetEncodedSize(data_->size());
}

void Resource::ClearData() {
  data_ = nullptr;
}

void Resource::TriggerNotificationForFinishObservers(
    base::SingleThreadTaskRunner* task_runner) {
  if (finish_observers_.empty())
    return;

  auto* new_collections =
      MakeGarbageCollected<HeapHashSet<WeakMember<ResourceFinishObserver>>>(
          std::move(finish_observers_));
  finish_observers_.clear();

  task_runner->PostTask(
      FROM_HERE,
      WTF::BindOnce(&NotifyFinishObservers, WrapPersistent(new_collections)));

  DidRemoveClientOrObserver();
}

void Resource::SetDataBufferingPolicy(
    DataBufferingPolicy data_buffering_policy) {
  options_.data_buffering_policy = data_buffering_policy;
  ClearData();
  SetEncodedSize(0);
}

static bool NeedsSynchronousCacheHit(ResourceType type,
                                     const ResourceLoaderOptions& options) {
  // Synchronous requests must always succeed or fail synchronously.
  if (options.synchronous_policy == kRequestSynchronously)
    return true;
  // Some resources types default to return data synchronously. For most of
  // these, it's because there are web tests that expect data to return
  // synchronously in case of cache hit. In the case of fonts, there was a
  // performance regression.
  // FIXME: Get to the point where we don't need to special-case sync/async
  // behavior for different resource types.
  if (type == ResourceType::kCSSStyleSheet)
    return true;
  if (type == ResourceType::kScript)
    return true;
  if (type == ResourceType::kFont)
    return true;
  return false;
}

void Resource::FinishAsError(const ResourceError& error,
                             base::SingleThreadTaskRunner* task_runner) {
  error_ = error;
  revalidation_status_ = RevalidationStatus::kNoRevalidatingOrFailed;

  if (IsMainThread())
    MemoryCache::Get()->Remove(this);

  bool failed_during_start = status_ == ResourceStatus::kNotStarted;
  if (!ErrorOccurred()) {
    SetStatus(ResourceStatus::kLoadError);
    // If the response type has not been set, set it to "error". This is
    // important because in some cases we arrive here after setting the response
    // type (e.g., while downloading payload), and that shouldn't change the
    // response type.
    if (response_.GetType() == network::mojom::FetchResponseType::kDefault)
      response_.SetType(network::mojom::FetchResponseType::kError);
  }
  DCHECK(ErrorOccurred());
  ClearData();
  loader_ = nullptr;
  CheckResourceIntegrity();
  TriggerNotificationForFinishObservers(task_runner);

  // Most resource types don't expect to succeed or fail inside
  // ResourceFetcher::RequestResource(). If the request does complete
  // immediately, the convention is to notify the client asynchronously
  // unless the type is exempted for historical reasons (mostly due to
  // performance implications to making those notifications asynchronous).
  // So if this is an immediate failure (i.e., before NotifyStartLoad()),
  // post a task if the Resource::Type supports it.
  if (failed_during_start && !NeedsSynchronousCacheHit(GetType(), options_)) {
    task_runner->PostTask(FROM_HERE, WTF::BindOnce(&Resource::NotifyFinished,
                                                   WrapWeakPersistent(this)));
  } else {
    NotifyFinished();
  }
}

void Resource::Finish(base::TimeTicks load_response_end,
                      base::SingleThreadTaskRunner* task_runner) {
  DCHECK(!IsCacheValidator());
  load_response_end_ = load_response_end;
  if (!ErrorOccurred())
    status_ = ResourceStatus::kCached;
  loader_ = nullptr;
  CheckResourceIntegrity();
  TriggerNotificationForFinishObservers(task_runner);
  NotifyFinished();
}

AtomicString Resource::HttpContentType() const {
  return GetResponse().HttpContentType();
}

bool Resource::MustRefetchDueToIntegrityMetadata(
    const FetchParameters& params) const {
  if (params.IntegrityMetadata().empty())
    return false;

  return !IntegrityMetadata::SetsEqual(IntegrityMetadata(),
                                       params.IntegrityMetadata());
}

const scoped_refptr<const SecurityOrigin>& Resource::GetOrigin() const {
  return LastResourceRequest().RequestorOrigin();
}

void Resource::DidDownloadToBlob(scoped_refptr<BlobDataHandle>) {}

static base::TimeDelta CurrentAge(const ResourceResponse& response,
                                  base::Time response_timestamp,
                                  UseCounter& use_counter) {
  // RFC2616 13.2.3
  // No compensation for latency as that is not terribly important in practice
  std::optional<base::Time> date_value = response.Date(use_counter);
  base::TimeDelta apparent_age;
  if (date_value && response_timestamp >= date_value.value())
    apparent_age = response_timestamp - date_value.value();
  std::optional<base::TimeDelta> age_value = response.Age();
  base::TimeDelta corrected_received_age =
      age_value ? std::max(apparent_age, age_value.value()) : apparent_age;
  base::TimeDelta resident_time = Now() - response_timestamp;
  return corrected_received_age + resident_time;
}

static base::TimeDelta FreshnessLifetime(const ResourceResponse& response,
                                         base::Time response_timestamp,
                                         UseCounter& use_counter) {
#if !BUILDFLAG(IS_ANDROID)
  // On desktop, local files should be reloaded in case they change.
  if (response.CurrentRequestUrl().IsLocalFile())
    return base::TimeDelta();
#endif

  // Cache other non-http / non-filesystem resources liberally.
  if (!response.CurrentRequestUrl().ProtocolIsInHTTPFamily() &&
      !response.CurrentRequestUrl().ProtocolIs("filesystem"))
    return base::TimeDelta::Max();

  // RFC2616 13.2.4
  std::optional<base::TimeDelta> max_age_value = response.CacheControlMaxAge();
  if (max_age_value)
    return max_age_value.value();
  std::optional<base::Time> expires = response.Expires(use_counter);
  std::optional<base::Time> date = response.Date(use_counter);
  base::Time creation_time = date ? date.value() : response_timestamp;
  if (expires)
    return expires.value() - creation_time;
  std::optional<base::Time> last_modified = response.LastModified(use_counter);
  if (last_modified)
    return (creation_time - last_modified.value()) * 0.1;
  // If no cache headers are present, the specification leaves the decision to
  // the UA. Other browsers seem to opt for 0.
  return base::TimeDelta();
}

base::TimeDelta Resource::FreshnessLifetime(UseCounter& use_counter) const {
  base::TimeDelta lifetime =
      blink::FreshnessLifetime(GetResponse(), response_timestamp_, use_counter);
  for (const auto& redirect : redirect_chain_) {
    base::TimeDelta redirect_lifetime = blink::FreshnessLifetime(
        redirect.redirect_response_, response_timestamp_, use_counter);
    lifetime = std::min(lifetime, redirect_lifetime);
  }
  return lifetime;
}

static bool CanUseResponse(const ResourceResponse& response,
                           bool allow_stale,
                           base::Time response_timestamp,
                           UseCounter& use_counter) {
  if (response.IsNull())
    return false;

  if (response.CacheControlContainsNoCache() ||
      response.CacheControlContainsNoStore())
    return false;

  if (response.HttpStatusCode() == 303) {
    // Must not be cached.
    return false;
  }

  if (response.HttpStatusCode() == 302 || response.HttpStatusCode() == 307) {
    // Default to not cacheable unless explicitly allowed.
    bool has_max_age = response.CacheControlMaxAge() != std::nullopt;
    bool has_expires = response.Expires(use_counter) != std::nullopt;
    // TODO: consider catching Cache-Control "private" and "public" here.
    if (!has_max_age && !has_expires)
      return false;
  }

  base::TimeDelta max_life =
      FreshnessLifetime(response, response_timestamp, use_counter);
  if (allow_stale)
    max_life += response.CacheControlStaleWhileRevalidate();

  return CurrentAge(response, response_timestamp, use_counter) <= max_life;
}

const ResourceRequestHead& Resource::LastResourceRequest() const {
  if (!redirect_chain_.size())
    return GetResourceRequest();
  return redirect_chain_.back().request_;
}

const ResourceResponse& Resource::LastResourceResponse() const {
  if (!redirect_chain_.size())
    return GetResponse();
  return redirect_chain_.back().redirect_response_;
}

size_t Resource::RedirectChainSize() const {
  return redirect_chain_.size();
}

void Resource::SetRevalidatingRequest(const ResourceRequestHead& request) {
  SECURITY_CHECK(redirect_chain_.empty());
  SECURITY_CHECK(!is_unused_preload_);
  DCHECK(!request.IsNull());
  CHECK(!is_revalidation_start_forbidden_);
  revalidation_status_ = RevalidationStatus::kRevalidating;
  resource_request_ = request;
  status_ = ResourceStatus::kNotStarted;
}

bool Resource::WillFollowRedirect(const ResourceRequest& new_request,
                                  const ResourceResponse& redirect_response) {
  if (IsCacheValidator()) {
    RevalidationFailed();
  }
  redirect_chain_.push_back(RedirectPair(new_request, redirect_response));
  return true;
}

void Resource::SetResponse(const ResourceResponse& response) {
  response_ = response;
}

void Resource::ResponseReceived(const ResourceResponse& response) {
  response_timestamp_ = Now();
  if (IsCacheValidator()) {
    if (IsSuccessfulRevalidationResponse(response)) {
      RevalidationSucceeded(response);
      return;
    }
    RevalidationFailed();
  }
  SetResponse(response);
  String encoding = response.TextEncodingName();
  if (!encoding.IsNull())
    SetEncoding(encoding);
}

void Resource::SetSerializedCachedMetadata(mojo_base::BigBuffer data) {
  DCHECK(!IsCacheValidator());
}

String Resource::ReasonNotDeletable() const {
  StringBuilder builder;
  if (HasClientsOrObservers()) {
    builder.Append("hasClients(");
    builder.AppendNumber(clients_.size());
    if (!clients_awaiting_callback_.empty()) {
      builder.Append(", AwaitingCallback=");
      builder.AppendNumber(clients_awaiting_callback_.size());
    }
    if (!finished_clients_.empty()) {
      builder.Append(", Finished=");
      builder.AppendNumber(finished_clients_.size());
    }
    builder.Append(')');
  }
  if (loader_) {
    if (!builder.empty())
      builder.Append(' ');
    builder.Append("loader_");
  }
  if (IsMainThread() && MemoryCache::Get()->Contains(this)) {
    if (!builder.empty())
      builder.Append(' ');
    builder.Append("in_memory_cache");
  }
  return builder.ToString();
}

void Resource::DidAddClient(ResourceClient* client) {
  if (scoped_refptr<SharedBuffer> data = Data()) {
    for (const auto& span : *data) {
      client->DataReceived(this, span);
      // Stop pushing data if the client removed itself.
      if (!HasClient(client))
        break;
    }
  }
  if (!HasClient(client))
    return;
  if (IsLoaded()) {
    client->SetHasFinishedFromMemoryCache();
    client->NotifyFinished(this);
    if (clients_.Contains(client)) {
      finished_clients_.insert(client);
      clients_.erase(client);
    }
  }
}

void Resource::WillAddClientOrObserver() {
  if (!HasClientsOrObservers()) {
    is_alive_ = true;
  }
}

void Resource::AddClient(ResourceClient* client,
                         base::SingleThreadTaskRunner* task_runner) {
  CHECK(!is_add_remove_client_prohibited_);

  WillAddClientOrObserver();

  if (IsCacheValidator()) {
    clients_.insert(client);
    return;
  }

  // If an error has occurred or we have existing data to send to the new client
  // and the resource type supports it, send it asynchronously.
  if ((ErrorOccurred() || !GetResponse().IsNull()) &&
      !NeedsSynchronousCacheHit(GetType(), options_)) {
    clients_awaiting_callback_.insert(client);
    if (!async_finish_pending_clients_task_.IsActive()) {
      async_finish_pending_clients_task_ =
          PostCancellableTask(*task_runner, FROM_HERE,
                              WTF::BindOnce(&Resource::FinishPendingClients,
                                            WrapWeakPersistent(this)));
    }
    return;
  }

  clients_.insert(client);
  DidAddClient(client);
  return;
}

void Resource::RemoveClient(ResourceClient* client) {
  CHECK(!is_add_remove_client_prohibited_);

  if (finished_clients_.Contains(client))
    finished_clients_.erase(client);
  else if (clients_awaiting_callback_.Contains(client))
    clients_awaiting_callback_.erase(client);
  else
    clients_.erase(client);

  if (clients_awaiting_callback_.empty() &&
      async_finish_pending_clients_task_.IsActive()) {
    async_finish_pending_clients_task_.Cancel();
  }

  DidRemoveClientOrObserver();
}

void Resource::AddFinishObserver(ResourceFinishObserver* client,
                                 base::SingleThreadTaskRunner* task_runner) {
  CHECK(!is_add_remove_client_prohibited_);
  DCHECK(!finish_observers_.Contains(client));

  WillAddClientOrObserver();
  finish_observers_.insert(client);
  if (IsLoaded())
    TriggerNotificationForFinishObservers(task_runner);
}

void Resource::RemoveFinishObserver(ResourceFinishObserver* client) {
  CHECK(!is_add_remove_client_prohibited_);

  finish_observers_.erase(client);
  DidRemoveClientOrObserver();
}

void Resource::DidRemoveClientOrObserver() {
  if (!HasClientsOrObservers() && is_alive_) {
    is_alive_ = false;
    AllClientsAndObserversRemoved();

    // RFC2616 14.9.2:
    // "no-store: ... MUST make a best-effort attempt to remove the information
    // from volatile storage as promptly as possible"
    // "... History buffers MAY store such responses as part of their normal
    // operation."
    if (HasCacheControlNoStoreHeader() && IsMainThread()) {
      MemoryCache::Get()->Remove(this);
    }
  }
}

void Resource::AllClientsAndObserversRemoved() {
  if (loader_)
    loader_->ScheduleCancel();
}

void Resource::SetDecodedSize(size_t decoded_size) {
  if (decoded_size == decoded_size_)
    return;
  size_t old_size = size();
  decoded_size_ = decoded_size;
  if (IsMainThread())
    MemoryCache::Get()->Update(this, old_size, size());
}

void Resource::SetEncodedSize(size_t encoded_size) {
  if (encoded_size == encoded_size_) {
    return;
  }
  size_t old_size = size();
  encoded_size_ = encoded_size;
  if (IsMainThread())
    MemoryCache::Get()->Update(this, old_size, size());
}

void Resource::FinishPendingClients() {
  // We're going to notify clients one by one. It is simple if the client does
  // nothing. However there are a couple other things that can happen.
  //
  // 1. Clients can be added during the loop. Make sure they are not processed.
  // 2. Clients can be removed during the loop. Make sure they are always
  //    available to be removed. Also don't call removed clients or add them
  //    back.
  //
  // Handle case (1) by saving a list of clients to notify. A separate list also
  // ensure a client is either in cliens_ or clients_awaiting_callback_.
  HeapVector<Member<ResourceClient>> clients_to_notify;
  CopyToVector(clients_awaiting_callback_, clients_to_notify);

  for (const auto& client : clients_to_notify) {
    // Handle case (2) to skip removed clients.
    if (!clients_awaiting_callback_.erase(client))
      continue;
    clients_.insert(client);

    // When revalidation starts after waiting clients are scheduled and
    // before they are added here. In such cases, we just add the clients
    // to |clients_| without DidAddClient(), as in Resource::AddClient().
    if (!IsCacheValidator()) {
      DidAddClient(client);
    }
  }

  // It is still possible for the above loop to finish a new client
  // synchronously. If there's no client waiting we should deschedule.
  bool scheduled = async_finish_pending_clients_task_.IsActive();
  if (scheduled && clients_awaiting_callback_.empty())
    async_finish_pending_clients_task_.Cancel();

  // Prevent the case when there are clients waiting but no callback scheduled.
  DCHECK(clients_awaiting_callback_.empty() || scheduled);
}

Resource::MatchStatus Resource::CanReuse(const FetchParameters& params) const {
  const ResourceRequest& new_request = params.GetResourceRequest();
  const ResourceLoaderOptions& new_options = params.Options();
  scoped_refptr<const SecurityOrigin> existing_origin =
      GetResourceRequest().RequestorOrigin();
  scoped_refptr<const SecurityOrigin> new_origin =
      new_request.RequestorOrigin();

  DCHECK(existing_origin);
  DCHECK(new_origin);

  // Never reuse opaque responses from a service worker for requests that are
  // not no-cors. https://crbug.com/625575
  // TODO(yhirano): Remove this.
  if (GetResponse().WasFetchedViaServiceWorker() &&
      GetResponse().GetType() == network::mojom::FetchResponseType::kOpaque &&
      new_request.GetMode() != network::mojom::RequestMode::kNoCors) {
    return MatchStatus::kUnknownFailure;
  }

  // Use GetResourceRequest to get the const resource_request_.
  const ResourceRequestHead& current_request = GetResourceRequest();

  // If credentials mode is defferent from the the previous request, re-fetch
  // the resource.
  //
  // This helps with the case where the server sends back
  // "Access-Control-Allow-Origin: *" all the time, but some of the client's
  // requests are made without CORS and some with.
  if (current_request.GetCredentialsMode() !=
      new_request.GetCredentialsMode()) {
    return MatchStatus::kRequestCredentialsModeDoesNotMatch;
  }

  // Certain requests (e.g., XHRs) might have manually set headers that require
  // revalidation. In theory, this should be a Revalidate case. In practice, the
  // MemoryCache revalidation path assumes a whole bunch of things about how
  // revalidation works that manual headers violate, so punt to Reload instead.
  //
  // Similarly, a request with manually added revalidation headers can lead to a
  // 304 response for a request that wasn't flagged as a revalidation attempt.
  // Normally, successful revalidation will maintain the original response's
  // status code, but for a manual revalidation the response code remains 304.
  // In this case, the Resource likely has insufficient context to provide a
  // useful cache hit or revalidation. See http://crbug.com/643659
  if (new_request.IsConditional() || response_.HttpStatusCode() == 304) {
    return MatchStatus::kUnknownFailure;
  }

  // Answers the question "can a separate request with different options be
  // re-used" (e.g. preload request). The safe (but possibly slow) answer is
  // always false.
  //
  // Data buffering policy differences are believed to be safe for re-use.
  //
  // TODO: Check content_security_policy_option.
  //
  // initiator_info is purely informational and should be benign for re-use.
  //
  // request_initiator_context is benign (indicates document vs. worker).

  // Reuse only if both the existing Resource and the new request are
  // asynchronous. Particularly,
  // 1. Sync and async Resource/requests shouldn't be mixed (crbug.com/652172),
  // 2. Sync existing Resources shouldn't be revalidated, and
  // 3. Sync new requests shouldn't revalidate existing Resources.
  //
  // 2. and 3. are because SyncResourceHandler handles redirects without
  // calling WillFollowRedirect, and causes response URL mismatch
  // (crbug.com/618967) and bypassing redirect restriction around revalidation
  // (crbug.com/613971 for 2. and crbug.com/614989 for 3.).
  if (new_options.synchronous_policy == kRequestSynchronously ||
      options_.synchronous_policy == kRequestSynchronously) {
    return MatchStatus::kSynchronousFlagDoesNotMatch;
  }

  if (current_request.GetKeepalive() || new_request.GetKeepalive())
    return MatchStatus::kKeepaliveSet;

  if (current_request.HttpMethod() != http_names::kGET ||
      new_request.HttpMethod() != http_names::kGET) {
    return MatchStatus::kRequestMethodDoesNotMatch;
  }

  // A GET request doesn't have a request body.
  DCHECK(!new_request.HttpBody());

  // Don't reuse an existing resource when the source origin is different.
  if (!existing_origin->IsSameOriginWith(new_origin.get()))
    return MatchStatus::kUnknownFailure;

  if (new_request.GetCredentialsMode() !=
      current_request.GetCredentialsMode()) {
    return MatchStatus::kRequestCredentialsModeDoesNotMatch;
  }

  const auto new_mode = new_request.GetMode();
  const auto existing_mode = current_request.GetMode();

  if (new_mode != existing_mode)
    return MatchStatus::kRequestModeDoesNotMatch;

  return MatchStatus::kOk;
}

void Resource::Prune() {
  DestroyDecodedDataIfPossible();
}

void Resource::OnPurgeMemory() {
  if (base::FeatureList::IsEnabled(
          features::kReleaseResourceDecodedDataOnMemoryPressure)) {
    Prune();
  }
}

void Resource::OnMemoryDump(WebMemoryDumpLevelOfDetail level_of_detail,
                            WebProcessMemoryDump* memory_dump) const {
  static const size_t kMaxURLReportLength = 128;
  static const int kMaxResourceClientToShowInMemoryInfra = 10;

  const String dump_name = GetMemoryDumpName();
  WebMemoryAllocatorDump* dump =
      memory_dump->CreateMemoryAllocatorDump(dump_name);

  if (data_)
    GetSharedBufferMemoryDump(Data(), dump_name, memory_dump);

  if (level_of_detail == WebMemoryDumpLevelOfDetail::kDetailed) {
    String url_to_report = Url().GetString();
    if (url_to_report.length() > kMaxURLReportLength) {
      url_to_report.Truncate(kMaxURLReportLength);
      url_to_report = url_to_report + "...";
    }
    dump->AddString("url", "", url_to_report);

    dump->AddString("reason_not_deletable", "", ReasonNotDeletable());

    Vector<String> client_names;
    ResourceClientWalker<ResourceClient> walker(clients_);
    while (ResourceClient* client = walker.Next())
      client_names.push_back(client->DebugName());
    ResourceClientWalker<ResourceClient> walker2(clients_awaiting_callback_);
    while (ResourceClient* client = walker2.Next())
      client_names.push_back("(awaiting) " + client->DebugName());
    ResourceClientWalker<ResourceClient> walker3(finished_clients_);
    while (ResourceClient* client = walker3.Next())
      client_names.push_back("(finished) " + client->DebugName());
```