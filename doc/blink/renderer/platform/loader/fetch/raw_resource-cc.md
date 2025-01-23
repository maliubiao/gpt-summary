Response:
Let's break down the thought process for analyzing this `RawResource.cc` file.

1. **Understand the Goal:** The core request is to understand the *functionality* of this Chromium Blink engine source file (`blink/renderer/platform/loader/fetch/raw_resource.cc`) and its relation to web technologies.

2. **Initial Scan and Keywords:**  Quickly skim the code looking for recognizable keywords and patterns. I see:
    * `#include`: Indicates dependencies on other modules. The included files like `fetch_parameters.h`, `resource_fetcher.h`, and `response_body_loader.h` strongly suggest this file deals with fetching resources.
    * `RawResource`:  The central class. Its methods will define the core functionality.
    * `FetchSynchronously`, `Fetch`, `FetchMedia`, `FetchTextTrack`, `FetchManifest`:  These look like different ways to initiate fetching.
    * `ResourceClient`, `RawResourceClient`:  Suggest a client-server interaction pattern. The `RawResource` acts as a server for `RawResourceClient`s.
    * `AppendData`, `ResponseReceived`, `ResponseBodyReceived`, `DidDownloadData`:  These are likely callbacks related to the fetching process.
    * `mojom::blink::...`:  Indicates inter-process communication using Mojo, a common mechanism in Chromium.
    * `BytesConsumer`:  A pattern for handling data streams efficiently.
    * `RedirectReceived`, `RedirectBlocked`: Relates to HTTP redirects.
    * `BlobDataHandle`: Deals with binary large objects (Blobs).

3. **Identify Core Functionality (High-Level):** Based on the keywords, I can infer that `RawResource` is responsible for fetching various kinds of resources. The different `Fetch*` methods likely handle specifics for different resource types.

4. **Delve into Key Methods:**  Focus on the most important methods to understand how they work:

    * **`FetchSynchronously` and `Fetch`:** These are the entry points for initiating a fetch. They use a `ResourceFetcher` to handle the actual network request. The synchronous version blocks the thread.
    * **`FetchMedia`, `FetchTextTrack`, `FetchManifest`:** These are specialized fetch methods, setting specific `RequestContextType` and `ResourceType` values. This highlights that `RawResource` can handle different resource types.
    * **`AppendData`:**  Appends received data to the resource.
    * **`DidAddClient`:** This is crucial. It handles the scenario when a new client wants to receive data for an ongoing fetch. It manages redirects, initial response, and the data stream using the `BytesConsumer`. The logic for handling preloads (`bytes_consumer_for_preload_`) is significant here.
    * **`ResponseReceived` and `ResponseBodyReceived`:**  Callbacks when the HTTP response headers and body are received. Notice the handling of streaming responses and the `PreloadBytesConsumerClient`.
    * **`WillFollowRedirect` and `WillNotFollowRedirect`:** Handle HTTP redirect logic and notify clients.
    * **`DidDownloadToBlob`:** Manages downloading resources to Blobs.

5. **Analyze Relationships with Web Technologies:**

    * **JavaScript:** The `Fetch` API in JavaScript is the primary way developers initiate network requests. `RawResource` is a low-level component that *implements* the fetching logic behind the JavaScript `fetch`. The different `Fetch*` methods might correspond to different resource types requested via `fetch`. For example, fetching an image, audio, or video via JavaScript's `fetch` would eventually involve a `RawResource`. The `manifest` fetch is directly related to Progressive Web Apps (PWAs).
    * **HTML:**  HTML elements like `<script src="...">`, `<link rel="stylesheet" href="...">`, `<img>`, `<video>`, `<audio>`, and `<link rel="manifest" ...>` all trigger resource fetches. `RawResource` is the underlying mechanism to retrieve these resources. The `FetchTextTrack` method clearly relates to the `<track>` element for subtitles/captions.
    * **CSS:** When the browser encounters a `<link rel="stylesheet" href="...">` tag or `@import` rules in CSS, it needs to fetch the CSS file. `RawResource` handles this fetch.

6. **Identify Logic and Assumptions:**

    * **Assumption:** The `ResourceFetcher` is the component responsible for making the actual network request. `RawResource` acts as an intermediary, managing the lifecycle of the fetch and distributing data to clients.
    * **Logic:** The handling of `bytes_consumer_for_preload_` and `PreloadBytesConsumerClient` demonstrates a strategy for efficiently handling preloaded resources. It avoids unnecessary data copying when possible. The distinction between streaming and non-streaming destinations is important for how data is delivered to the client.
    * **Mojo:** The use of `mojom` indicates that `RawResource` might interact with other processes (like the network service) via Mojo interfaces.

7. **Consider User/Programming Errors:**

    * **Incorrect `RequestContextType`:** The `DCHECK` statements in the `FetchMedia` and `FetchManifest` methods highlight the importance of setting the correct request context. A programmer might accidentally use the wrong `Fetch*` method or configure the `FetchParameters` incorrectly.
    * **Synchronous Fetch on the Main Thread:**  Using `FetchSynchronously` on the main thread can lead to UI freezes and a poor user experience.
    * **Misunderstanding Preloading:**  Developers might not be aware of how preloading interacts with regular fetches and the implications for data delivery (streaming vs. buffered).

8. **Structure the Explanation:** Organize the findings logically, starting with a high-level overview and then diving into specific functionalities and relationships. Use clear examples to illustrate the connections to JavaScript, HTML, and CSS. Provide concrete examples for assumptions, logic, and potential errors.

9. **Review and Refine:** Read through the explanation to ensure clarity, accuracy, and completeness. Check for any jargon that needs to be explained.

This systematic approach allows for a comprehensive understanding of the `RawResource.cc` file and its role within the larger Blink rendering engine. It moves from a general understanding to specific details, connecting the code to relevant web technologies and potential developer pitfalls.
`blink/renderer/platform/loader/fetch/raw_resource.cc` 文件是 Chromium Blink 引擎中处理**原始资源（Raw Resources）**获取的核心组件。它的主要功能是：

**核心功能:**

1. **发起和管理资源请求:**  `RawResource` 类负责创建、发起和管理各种类型的资源请求，这些请求不属于特定的渲染对象（例如 HTML 文档、图片等），而是更底层的、原始的数据获取。

2. **处理不同类型的原始资源:** 该文件定义了用于获取不同类型原始资源的静态工厂方法，例如：
   - `Fetch()`:  用于获取通用的原始资源。
   - `FetchSynchronously()`:  用于同步获取原始资源（通常应避免在主线程使用）。
   - `FetchMedia()`:  用于获取音频或视频资源。
   - `FetchTextTrack()`:  用于获取文本轨道（例如字幕）资源。
   - `FetchManifest()`: 用于获取 Web App Manifest 文件。

3. **与 `ResourceFetcher` 交互:**  `RawResource` 依赖于 `ResourceFetcher` 类来执行实际的网络请求。它将请求参数传递给 `ResourceFetcher`，并接收 `Resource` 对象作为返回。

4. **管理客户端:**  `RawResource` 维护着一个客户端列表 (`RawResourceClient`)，这些客户端对这个资源的加载状态和数据感兴趣。当资源加载的不同阶段发生时（例如接收到响应头、接收到数据、加载完成等），`RawResource` 会通知这些客户端。

5. **处理重定向:**  `RawResource` 负责处理 HTTP 重定向。它会通知客户端重定向的发生，并决定是否跟随重定向。

6. **处理响应数据:**  `RawResource` 接收从网络或缓存返回的响应数据，并将其传递给相关的客户端。它支持以 `SegmentedBuffer` 或 `base::span<const char>` 的形式接收数据。

7. **支持预加载:**  该文件包含了处理预加载资源的逻辑。当一个资源被预加载后，`RawResource` 可以有效地将数据传递给后续实际需要该资源的请求。

8. **管理下载到 Blob 的资源:**  `RawResource` 可以将下载的资源存储为 Blob (Binary Large Object)，并提供访问该 Blob 的接口。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`RawResource` 位于 Blink 引擎的底层，虽然不直接暴露给 JavaScript, HTML 或 CSS，但它是实现这些 Web 技术资源加载的基础。

* **JavaScript 的 `fetch` API:**  当 JavaScript 使用 `fetch()` API 发起一个请求时，Blink 引擎最终会使用 `RawResource` 或其子类来处理这个请求。例如：
    ```javascript
    fetch('/data.json')
      .then(response => response.json())
      .then(data => console.log(data));
    ```
    在这个例子中，`RawResource` 的 `Fetch()` 方法可能会被用于获取 `/data.json` 资源。

* **HTML 的 `<audio>`, `<video>`, `<track>` 元素:** 当浏览器解析到这些 HTML 元素时，需要加载相应的媒体文件或文本轨道文件。 `RawResource` 的 `FetchMedia()` 和 `FetchTextTrack()` 方法会被用来获取这些资源。
    ```html
    <video src="video.mp4"></video>
    <track src="subtitles.vtt" kind="subtitles" srclang="en">
    ```
    加载 `video.mp4` 会使用 `RawResource::FetchMedia()`，加载 `subtitles.vtt` 会使用 `RawResource::FetchTextTrack()`。

* **HTML 的 `<link rel="manifest">` 元素:**  Progressive Web Apps (PWAs) 使用 manifest 文件来描述应用的元数据。浏览器会使用 `RawResource::FetchManifest()` 来获取这个文件。
    ```html
    <link rel="manifest" href="/manifest.json">
    ```

* **CSS 的 `@font-face` 规则:** 当 CSS 中使用 `@font-face` 来引用外部字体文件时，Blink 引擎会发起一个资源请求来下载字体文件，这也会涉及到 `RawResource` 的使用 (尽管更常见的是使用 `FontResource`，它继承自 `Resource`)。
    ```css
    @font-face {
      font-family: 'MyCustomFont';
      src: url('/fonts/my-font.woff2') format('woff2');
    }
    ```

**逻辑推理 (假设输入与输出):**

假设我们使用 JavaScript 的 `fetch` API 发起一个获取 JSON 数据的请求：

**假设输入:**

1. **`FetchParameters`:**
   - `resource_request.url` = "https://example.com/api/data"
   - `resource_request.method` = "GET"
   - `resource_request.credentialsMode` = "same-origin"
   - `resource_request.requestContext` = `mojom::blink::RequestContextType::FETCH`
   - `resource_type` = `ResourceType::kRaw`
2. **`ResourceFetcher` 对象**
3. **`RawResourceClient` 对象** (例如，负责处理 JavaScript `fetch` Promise 的逻辑)

**逻辑推理过程:**

1. JavaScript 的 `fetch()` 调用最终会调用到 Blink 引擎的资源加载模块。
2. Blink 引擎创建一个 `FetchParameters` 对象来描述这次请求。
3. `RawResource::Fetch()` 方法被调用，传入 `FetchParameters`、`ResourceFetcher` 和 `RawResourceClient`。
4. `RawResource::Fetch()` 调用 `fetcher->RequestResource()`，将请求传递给 `ResourceFetcher`。
5. `ResourceFetcher` 执行网络请求。
6. 当响应头到达时，`RawResource::ResponseReceived()` 被调用，并将响应信息传递给 `RawResourceClient` 的 `ResponseReceived()` 方法。
7. 当响应体数据到达时，`RawResource::ResponseBodyReceived()` 被调用，并将数据传递给 `RawResourceClient` 的 `ResponseBodyReceived()` 或 `DataReceived()` 方法。
8. 当请求完成时（成功或失败），`RawResource` 会通知其客户端。

**预期输出:**

1. `RawResourceClient` 的 `ResponseReceived()` 方法被调用，传入包含响应头信息的 `ResourceResponse` 对象。
2. `RawResourceClient` 的 `DataReceived()` 方法被多次调用，传入响应体的各个数据块。
3. `RawResourceClient` 的 `NotifyFinished()` 方法被调用，指示资源加载完成。如果请求成功，客户端会收到完整的 JSON 数据；如果请求失败，客户端会收到错误信息。

**用户或编程常见的使用错误举例:**

1. **在主线程同步获取资源:**  调用 `RawResource::FetchSynchronously()` 会阻塞渲染主线程，导致页面卡顿和无响应。这应该仅在 worker 线程或其他非主线程中使用。

   ```cpp
   // 错误示例 (在主线程)
   FetchParameters params;
   // ... 设置 params ...
   RawResource* resource = RawResource::FetchSynchronously(params, fetcher, client);
   ```

2. **没有正确设置 `RequestContextType`:**  对于特定类型的资源，例如 Manifest 文件，需要设置正确的 `RequestContextType`。如果设置错误，可能会导致资源加载失败或被错误处理。

   ```cpp
   // 错误示例
   FetchParameters params;
   params.GetResourceRequest().SetRequestContext(mojom::blink::RequestContextType::IMAGE); // 错误！应该是 MANIFEST
   RawResource::FetchManifest(params, fetcher, client);
   ```

3. **没有处理重定向:**  `RawResourceClient` 需要实现 `RedirectReceived()` 方法来处理重定向。如果忽略重定向，可能会导致请求失败或行为不符合预期。

   ```cpp
   class MyRawResourceClient : public RawResourceClient {
   public:
     // 可能会忘记实现 RedirectReceived
     void ResponseReceived(Resource*, const ResourceResponse&) override {}
     void DataReceived(Resource*, base::span<const char>) override {}
     void NotifyFinished(Resource*) override {}
   };
   ```

4. **假设数据一次性到达:**  网络请求的数据是分块到达的。`RawResourceClient` 需要能够处理多次 `DataReceived()` 调用，而不是假设所有数据会一次性到达。

5. **资源释放问题:**  如果 `RawResourceClient` 没有正确管理 `RawResource` 的生命周期，可能会导致内存泄漏或访问悬空指针。

总而言之，`RawResource.cc` 是 Blink 引擎中一个关键的底层模块，负责处理各种原始资源的获取。它与 JavaScript, HTML, CSS 的资源加载机制紧密相关，是实现这些 Web 技术的基础。理解其功能有助于深入了解浏览器如何加载和处理网络资源。

### 提示词
```
这是目录为blink/renderer/platform/loader/fetch/raw_resource.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2011 Google Inc. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/platform/loader/fetch/raw_resource.h"

#include <memory>

#include "base/compiler_specific.h"
#include "base/containers/span.h"
#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/loader/request_context_frame_type.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/loader/fetch/buffering_bytes_consumer.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_parameters.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_client_walker.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/response_body_loader.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"

namespace blink {

RawResource* RawResource::FetchSynchronously(FetchParameters& params,
                                             ResourceFetcher* fetcher,
                                             RawResourceClient* client) {
  params.MakeSynchronous();
  return ToRawResource(fetcher->RequestResource(
      params, RawResourceFactory(ResourceType::kRaw), client));
}

RawResource* RawResource::Fetch(FetchParameters& params,
                                ResourceFetcher* fetcher,
                                RawResourceClient* client) {
  DCHECK_NE(params.GetResourceRequest().GetRequestContext(),
            mojom::blink::RequestContextType::UNSPECIFIED);
  return ToRawResource(fetcher->RequestResource(
      params, RawResourceFactory(ResourceType::kRaw), client));
}

RawResource* RawResource::FetchMedia(FetchParameters& params,
                                     ResourceFetcher* fetcher,
                                     RawResourceClient* client) {
  auto context = params.GetResourceRequest().GetRequestContext();
  DCHECK(context == mojom::blink::RequestContextType::AUDIO ||
         context == mojom::blink::RequestContextType::VIDEO);
  ResourceType type = (context == mojom::blink::RequestContextType::AUDIO)
                          ? ResourceType::kAudio
                          : ResourceType::kVideo;
  return ToRawResource(
      fetcher->RequestResource(params, RawResourceFactory(type), client));
}

RawResource* RawResource::FetchTextTrack(FetchParameters& params,
                                         ResourceFetcher* fetcher,
                                         RawResourceClient* client) {
  params.SetRequestContext(mojom::blink::RequestContextType::TRACK);
  params.SetRequestDestination(network::mojom::RequestDestination::kTrack);
  return ToRawResource(fetcher->RequestResource(
      params, RawResourceFactory(ResourceType::kTextTrack), client));
}

RawResource* RawResource::FetchManifest(FetchParameters& params,
                                        ResourceFetcher* fetcher,
                                        RawResourceClient* client) {
  DCHECK_EQ(params.GetResourceRequest().GetRequestContext(),
            mojom::blink::RequestContextType::MANIFEST);
  return ToRawResource(fetcher->RequestResource(
      params, RawResourceFactory(ResourceType::kManifest), client));
}

RawResource::RawResource(const ResourceRequest& resource_request,
                         ResourceType type,
                         const ResourceLoaderOptions& options)
    : Resource(resource_request, type, options) {}

void RawResource::AppendData(
    absl::variant<SegmentedBuffer, base::span<const char>> data) {
  if (GetResourceRequest().UseStreamOnResponse())
    return;

  Resource::AppendData(std::move(data));
}

class RawResource::PreloadBytesConsumerClient final
    : public GarbageCollected<PreloadBytesConsumerClient>,
      public BytesConsumer::Client {
 public:
  PreloadBytesConsumerClient(BytesConsumer& bytes_consumer,
                             RawResource& resource,
                             RawResourceClient& client)
      : bytes_consumer_(bytes_consumer),
        resource_(resource),
        client_(&client) {}
  void OnStateChange() override {
    auto* client = client_.Get();
    if (!client) {
      return;
    }
    while (resource_->HasClient(client)) {
      base::span<const char> buffer;
      auto result = bytes_consumer_->BeginRead(buffer);
      if (result == BytesConsumer::Result::kShouldWait)
        return;
      if (result == BytesConsumer::Result::kOk) {
        client->DataReceived(resource_, buffer);
        result = bytes_consumer_->EndRead(buffer.size());
      }
      if (result != BytesConsumer::Result::kOk) {
        return;
      }
    }
    client_ = nullptr;
  }

  String DebugName() const override { return "PreloadBytesConsumerClient"; }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(bytes_consumer_);
    visitor->Trace(resource_);
    visitor->Trace(client_);
    BytesConsumer::Client::Trace(visitor);
  }

 private:
  const Member<BytesConsumer> bytes_consumer_;
  const Member<RawResource> resource_;
  WeakMember<RawResourceClient> client_;
};

void RawResource::DidAddClient(ResourceClient* c) {
  auto* bytes_consumer_for_preload = bytes_consumer_for_preload_.Release();

  // CHECK()/RevalidationStartForbiddenScope are for
  // https://crbug.com/640960#c24.
  CHECK(!IsCacheValidator());
  if (!HasClient(c))
    return;
  DCHECK(c->IsRawResourceClient());
  RevalidationStartForbiddenScope revalidation_start_forbidden_scope(this);
  RawResourceClient* client = static_cast<RawResourceClient*>(c);
  for (const auto& redirect : RedirectChain()) {
    client->RedirectReceived(this, ResourceRequest(redirect.request_),
                             redirect.redirect_response_);
    if (!HasClient(c))
      return;
  }

  if (!GetResponse().IsNull()) {
    client->ResponseReceived(this, GetResponse());
  }
  if (!HasClient(c))
    return;

  if (bytes_consumer_for_preload) {
    bytes_consumer_for_preload->StopBuffering();

    if (matched_with_non_streaming_destination_) {
      // In this case, the client needs individual chunks so we need
      // PreloadBytesConsumerClient for the translation.
      auto* preload_bytes_consumer_client =
          MakeGarbageCollected<PreloadBytesConsumerClient>(
              *bytes_consumer_for_preload, *this, *client);
      bytes_consumer_for_preload->SetClient(preload_bytes_consumer_client);
      preload_bytes_consumer_client->OnStateChange();
    } else {
      // In this case, we can simply pass the BytesConsumer to the client.
      client->ResponseBodyReceived(this, *bytes_consumer_for_preload);
    }
  }

  if (!HasClient(c))
    return;

  Resource::DidAddClient(client);
}

bool RawResource::WillFollowRedirect(
    const ResourceRequest& new_request,
    const ResourceResponse& redirect_response) {
  bool follow = Resource::WillFollowRedirect(new_request, redirect_response);
  // The base class method takes a const reference of a ResourceRequest and
  // returns bool just for allowing RawResource to reject redirect. It must
  // always return true.
  DCHECK(follow);

  DCHECK(!redirect_response.IsNull());
  ResourceClientWalker<RawResourceClient> w(Clients());
  while (RawResourceClient* c = w.Next()) {
    if (!c->RedirectReceived(this, new_request, redirect_response))
      follow = false;
  }

  return follow;
}

void RawResource::WillNotFollowRedirect() {
  ResourceClientWalker<RawResourceClient> w(Clients());
  while (RawResourceClient* c = w.Next())
    c->RedirectBlocked();
}

scoped_refptr<BlobDataHandle> RawResource::DownloadedBlob() const {
  return downloaded_blob_;
}

void RawResource::Trace(Visitor* visitor) const {
  visitor->Trace(bytes_consumer_for_preload_);
  Resource::Trace(visitor);
}

void RawResource::ResponseReceived(const ResourceResponse& response) {
  Resource::ResponseReceived(response);

  ResourceClientWalker<RawResourceClient> w(Clients());
  while (RawResourceClient* c = w.Next()) {
    c->ResponseReceived(this, GetResponse());
  }
}

void RawResource::ResponseBodyReceived(
    ResponseBodyLoaderDrainableInterface& body_loader,
    scoped_refptr<base::SingleThreadTaskRunner> loader_task_runner) {
  DCHECK_LE(Clients().size(), 1u);
  RawResourceClient* client =
      ResourceClientWalker<RawResourceClient>(Clients()).Next();
  if (!client && GetResourceRequest().UseStreamOnResponse()) {
    // For preload, we want to store the body while dispatching
    // onload and onerror events.
    bytes_consumer_for_preload_ =
        BufferingBytesConsumer::Create(&body_loader.DrainAsBytesConsumer());
    return;
  }

  if (matched_with_non_streaming_destination_) {
    DCHECK(GetResourceRequest().UseStreamOnResponse());
    // The loading was initiated as a preload (hence UseStreamOnResponse is
    // set), but this resource has been matched with a request without
    // UseStreamOnResponse set.
    auto& bytes_consumer_for_preload = body_loader.DrainAsBytesConsumer();
    auto* preload_bytes_consumer_client =
        MakeGarbageCollected<PreloadBytesConsumerClient>(
            bytes_consumer_for_preload, *this, *client);
    bytes_consumer_for_preload.SetClient(preload_bytes_consumer_client);
    preload_bytes_consumer_client->OnStateChange();
    return;
  }

  if (!GetResourceRequest().UseStreamOnResponse()) {
    return;
  }

  client->ResponseBodyReceived(this, body_loader.DrainAsBytesConsumer());
}

void RawResource::SetSerializedCachedMetadata(mojo_base::BigBuffer data) {
  // Resource ignores the cached metadata.
  Resource::SetSerializedCachedMetadata(mojo_base::BigBuffer());

  ResourceClientWalker<RawResourceClient> w(Clients());
  // We rely on the fact that RawResource cannot have multiple clients.
  CHECK_LE(Clients().size(), 1u);
  if (RawResourceClient* c = w.Next()) {
    c->CachedMetadataReceived(this, std::move(data));
  }
}

void RawResource::DidSendData(uint64_t bytes_sent,
                              uint64_t total_bytes_to_be_sent) {
  ResourceClientWalker<RawResourceClient> w(Clients());
  while (RawResourceClient* c = w.Next())
    c->DataSent(this, bytes_sent, total_bytes_to_be_sent);
}

void RawResource::DidDownloadData(uint64_t data_length) {
  ResourceClientWalker<RawResourceClient> w(Clients());
  while (RawResourceClient* c = w.Next())
    c->DataDownloaded(this, data_length);
}

void RawResource::DidDownloadToBlob(scoped_refptr<BlobDataHandle> blob) {
  downloaded_blob_ = blob;
  ResourceClientWalker<RawResourceClient> w(Clients());
  while (RawResourceClient* c = w.Next())
    c->DidDownloadToBlob(this, blob);
}

void RawResource::MatchPreload(const FetchParameters& params) {
  Resource::MatchPreload(params);
  matched_with_non_streaming_destination_ =
      !params.GetResourceRequest().UseStreamOnResponse();
}

void RawResourceClient::DidDownloadToBlob(Resource*,
                                          scoped_refptr<BlobDataHandle>) {}

RawResourceClientStateChecker::RawResourceClientStateChecker() = default;

NOINLINE void RawResourceClientStateChecker::WillAddClient() {
  SECURITY_CHECK(state_ == kNotAddedAsClient);
  state_ = kStarted;
}

NOINLINE void RawResourceClientStateChecker::WillRemoveClient() {
  SECURITY_CHECK(state_ != kNotAddedAsClient);
  SECURITY_CHECK(state_ != kDetached);
  state_ = kDetached;
}

NOINLINE void RawResourceClientStateChecker::RedirectReceived() {
  SECURITY_CHECK(state_ == kStarted);
}

NOINLINE void RawResourceClientStateChecker::RedirectBlocked() {
  SECURITY_CHECK(state_ == kStarted);
  state_ = kRedirectBlocked;
}

NOINLINE void RawResourceClientStateChecker::DataSent() {
  SECURITY_CHECK(state_ == kStarted);
}

NOINLINE void RawResourceClientStateChecker::ResponseReceived() {
  // TODO(crbug.com/1431421): remove |state_| dump when the cause is clarified.
  SECURITY_CHECK(state_ == kStarted) << " state_ was " << state_;
  state_ = kResponseReceived;
}

NOINLINE void RawResourceClientStateChecker::SetSerializedCachedMetadata() {
  SECURITY_CHECK(state_ == kStarted || state_ == kResponseReceived ||
                 state_ == kDataReceivedAsBytesConsumer ||
                 state_ == kDataReceived);
}

NOINLINE void RawResourceClientStateChecker::ResponseBodyReceived() {
  SECURITY_CHECK(state_ == kResponseReceived);
  state_ = kDataReceivedAsBytesConsumer;
}

NOINLINE void RawResourceClientStateChecker::DataReceived() {
  SECURITY_CHECK(state_ == kResponseReceived ||
                 state_ == kDataReceived);
  state_ = kDataReceived;
}

NOINLINE void RawResourceClientStateChecker::DataDownloaded() {
  SECURITY_CHECK(state_ == kResponseReceived ||
                 state_ == kDataDownloaded);
  state_ = kDataDownloaded;
}

NOINLINE void RawResourceClientStateChecker::DidDownloadToBlob() {
  SECURITY_CHECK(state_ == kResponseReceived ||
                 state_ == kDataDownloaded);
  state_ = kDidDownloadToBlob;
}

NOINLINE void RawResourceClientStateChecker::NotifyFinished(
    Resource* resource) {
  SECURITY_CHECK(state_ != kNotAddedAsClient);
  SECURITY_CHECK(state_ != kDetached);
  SECURITY_CHECK(state_ != kNotifyFinished);

  SECURITY_CHECK(resource->ErrorOccurred() ||
                 (state_ == kResponseReceived || state_ == kDataReceived ||
                  state_ == kDataDownloaded ||
                  state_ == kDataReceivedAsBytesConsumer ||
                  state_ == kDidDownloadToBlob));
  state_ = kNotifyFinished;
}

}  // namespace blink
```