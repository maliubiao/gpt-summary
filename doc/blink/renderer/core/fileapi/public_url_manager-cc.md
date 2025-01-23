Response:
Let's break down the thought process for analyzing the `public_url_manager.cc` file.

1. **Understand the Goal:** The primary goal is to understand the functionality of this specific Chromium Blink file and how it relates to web technologies (JavaScript, HTML, CSS), including potential usage errors and providing concrete examples.

2. **Initial Scan for Keywords and Patterns:**  I'd quickly scan the code for recurring terms and recognizable patterns. Keywords like `URL`, `Blob`, `Register`, `Revoke`, `Resolve`, `ExecutionContext`, `SecurityOrigin`, and `mojom` jump out. The presence of `frame_url_store_` and `worker_url_store_` suggests different contexts where these URLs are managed. The copyright notice gives context about its origins.

3. **Identify the Core Responsibility:** The name `PublicURLManager` strongly suggests its primary function is managing publicly accessible URLs, specifically related to `Blob` objects. The presence of `RegisterURL`, `Revoke`, and `Resolve` confirms this.

4. **Decipher `Blob` Context:**  I know `Blob` is a web API for representing raw data. The interaction with `mojom::blink::BlobURLStore` implies this manager is a bridge between Blink's C++ layer and the browser process (via Mojo).

5. **Analyze Key Methods:** I'd examine the core methods in detail:

    * **`PublicURLManager` (Constructor):**  The constructors show different ways this manager is initialized, depending on whether it's in a frame, worker, or worklet context. The use of `GetRemoteNavigationAssociatedInterfaces` and `GetBrowserInterfaceBroker` points to communication with the browser process. The `TaskType::kFileReading` argument suggests I/O operations are involved.

    * **`RegisterURL`:** This method creates a unique "public" URL for a `Blob`. The `BlobURL::CreatePublicURL` call is crucial. The distinction between `IsMojoBlob` and the `URLRegistry` indicates two different mechanisms for managing these URLs, likely based on whether the `Blob` is handled directly by Mojo or within the renderer. The null origin handling is a detail to note.

    * **`Revoke`:** This method invalidates a previously registered `Blob` URL. The same-origin check is important for security. The interaction with `GetBlobURLStore().Revoke()` and the removal from internal data structures (`mojo_urls_`, `url_to_registry_`) are key.

    * **`Resolve` (Multiple Overloads):**  These methods handle the process of making the `Blob` accessible via its URL. The different overloads (`URLLoaderFactory`, `BlobURLToken`, `ResolveForWorkerScriptFetch`) indicate different use cases, such as fetching the `Blob` as a resource or for navigation. The metrics callbacks reveal the tracking of cross-origin and cross-agent-cluster access, which are important security and performance considerations.

    * **`ContextDestroyed`:** This method cleans up when the associated execution context is destroyed, revoking all registered URLs to prevent dangling references.

6. **Relate to Web Technologies:**  Now, I connect the dots to JavaScript, HTML, and CSS:

    * **JavaScript:**  The most direct connection is through the `URL.createObjectURL()` and `URL.revokeObjectURL()` methods, which are the JavaScript APIs that leverage this C++ code. Examples involving creating `Blob` objects and using the generated URLs in image `src` attributes or `<a>` tag `href` attributes are relevant.

    * **HTML:**  The generated `blob:` URLs are used within HTML tags, such as `<img>`, `<a>`, `<video>`, etc., to reference the `Blob` data.

    * **CSS:**  While less direct, `blob:` URLs can also be used in CSS properties like `background-image` or `list-style-image`.

7. **Infer Logic and Provide Examples:** For the `RegisterURL` and `Revoke` methods, I'd create simple scenarios:

    * **Register:**  Show a JavaScript `Blob` being created and `URL.createObjectURL()` being called, illustrating the input (the `Blob`) and the output (the `blob:` URL).
    * **Revoke:** Show `URL.revokeObjectURL()` being called on a previously created `blob:` URL, and what happens if you try to use that URL afterward (it becomes invalid).

8. **Identify Potential Usage Errors:**  I'd think about common mistakes developers might make:

    * **Forgetting to revoke:** Leading to memory leaks.
    * **Trying to revoke cross-origin URLs:** Security implications.
    * **Using revoked URLs:**  Resulting in errors or broken resources.

9. **Address the "Reasoning" Requirement:**  For methods like `Resolve`, the reasoning isn't as straightforward as input/output. Here, the "input" is the `blob:` URL, and the "output" is the ability to fetch the data. The underlying logic involves verifying the URL, potentially checking permissions, and then providing access to the `Blob`'s data. I'd simplify this by explaining that given a valid `blob:` URL, the system provides a way to access the underlying data.

10. **Structure the Output:** Finally, organize the information clearly with headings and bullet points, addressing each part of the prompt. Provide code examples to illustrate the concepts. Emphasize the connections to web standards and highlight potential pitfalls for developers. Use clear and concise language.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "Is this just about creating URLs?"  **Correction:** No, it's about *managing* these URLs, including registration, revocation, and resolving them to access the underlying data.

* **Considering edge cases:**  What happens with `null` origins? The code explicitly handles this, so I should mention it. What about different execution contexts?  The code handles frames, workers, and worklets, so highlighting these distinctions is important.

* **Clarity of examples:** Are the JavaScript examples clear and easy to understand? Could they be more concrete?  Adding specific HTML usage scenarios improves clarity.

* **Technical accuracy:** Am I correctly describing the interaction with Mojo?  Referring to the code comments and the use of `mojom` helps ensure accuracy.

By following this iterative process of scanning, analyzing, connecting, and refining, I can arrive at a comprehensive and accurate explanation of the `public_url_manager.cc` file.
这个文件 `public_url_manager.cc` 是 Chromium Blink 渲染引擎中的一部分，它的主要功能是**管理公开的 Blob (Binary Large Object) URL**。简单来说，它负责创建、跟踪、以及撤销在浏览器中可以被访问的 `blob:` 协议的 URL。

以下是它的详细功能，并结合了与 JavaScript, HTML, CSS 的关系、逻辑推理以及常见错误：

**主要功能:**

1. **注册 Blob URL (RegisterURL):**
   - 当 JavaScript 代码通过 `URL.createObjectURL()` 方法为一个 `Blob` 对象创建一个 URL 时，`PublicURLManager` 负责生成一个唯一的 `blob:` URL 并将其与底层的 `Blob` 对象关联起来。
   - 它会根据运行的上下文（主窗口、Worker、Worklet）选择不同的内部机制来存储和管理这些关联。这包括使用 `frame_url_store_` (针对主窗口) 和 `worker_url_store_` (针对 Worker 和 Worklet)。
   - 对于 `MojoBlob` (通过 Mojo 接口传递的 Blob)，它会通过 `BlobURLStore` Mojo 接口注册。
   - 对于非 `MojoBlob`，它会使用内部的 `URLRegistry` 来管理。
   - 如果当前执行上下文的 Security Origin 是 "null"，它会将这个 Blob URL 添加到 `BlobURLNullOriginMap` 中。

   **与 JavaScript 的关系：**  `URL.createObjectURL(blob)` 的调用会最终触发 `PublicURLManager::RegisterURL`。
   **假设输入与输出：**
     - **假设输入 (JavaScript):**  `const blob = new Blob(['hello'], { type: 'text/plain' }); const url = URL.createObjectURL(blob);`
     - **可能输出 (C++):** `PublicURLManager::RegisterURL` 被调用，生成一个类似 `blob:https://example.com/unique-id` 的 URL，并将该 URL 与 `blob` 对象关联。

2. **撤销 Blob URL (Revoke):**
   - 当 JavaScript 代码调用 `URL.revokeObjectURL(url)` 时，`PublicURLManager` 负责解除 `blob:` URL 与底层 `Blob` 对象的关联，使得该 URL 失效。
   - 它会调用 `BlobURLStore` 的 `Revoke` 方法（如果使用了 Mojo），或者从内部的 `URLRegistry` 中移除。
   - 它还会从 `BlobURLNullOriginMap` 中移除相应的 URL（如果存在）。
   - **安全考虑：** 只能撤销同源的 `blob:` URL。

   **与 JavaScript 的关系：** `URL.revokeObjectURL(url)` 的调用会触发 `PublicURLManager::Revoke`。
   **假设输入与输出：**
     - **假设输入 (JavaScript):**  `URL.revokeObjectURL(blobUrl);` (其中 `blobUrl` 是之前通过 `URL.createObjectURL` 创建的)
     - **可能输出 (C++):** `PublicURLManager::Revoke` 被调用，内部数据结构中 `blobUrl` 的关联被移除，尝试访问该 URL 将会失败。

3. **解析 Blob URL 用于资源加载 (ResolveAsURLLoaderFactory):**
   - 当浏览器需要加载一个 `blob:` URL 的资源时（例如，`<img>` 标签的 `src` 属性设置为一个 `blob:` URL），`PublicURLManager` 负责提供一个 `URLLoaderFactory`，以便可以从底层的 `Blob` 对象读取数据。
   - 它会通过 `BlobURLStore` Mojo 接口来处理这个请求。
   - **度量指标：**  它还会记录跨 Agent Cluster 和跨 Top-Level Site 访问 Blob URL 的情况，用于性能和安全分析。

   **与 HTML 的关系：**  在 HTML 中使用 `blob:` URL 作为资源 URL (例如 `<img src="blob:...">`) 会触发此功能。
   **与 CSS 的关系：**  在 CSS 中使用 `blob:` URL (例如 `background-image: url(blob:...)`) 也会触发此功能。
   **假设输入与输出：**
     - **假设输入 (HTML):** `<img src="blob:https://example.com/unique-id">` (假设该 URL 是有效的)
     - **可能输出 (C++):** `PublicURLManager::ResolveAsURLLoaderFactory` 被调用，返回一个 `URLLoaderFactory`，该工厂可以读取与该 URL 关联的 `Blob` 数据，并将其作为图片内容提供给渲染引擎。

4. **解析 Blob URL 用于导航 (ResolveForNavigation):**
   - 当尝试导航到一个 `blob:` URL 时（例如，在地址栏中输入或通过 `window.location.href` 设置），`PublicURLManager` 提供一个 `BlobURLToken`，允许浏览器进行导航。

   **与 JavaScript 的关系：**  设置 `window.location.href` 为一个 `blob:` URL 会触发此功能。
   **假设输入与输出：**
     - **假设输入 (JavaScript):** `window.location.href = 'blob:https://example.com/unique-id';`
     - **可能输出 (C++):** `PublicURLManager::ResolveForNavigation` 被调用，生成并返回一个 `BlobURLToken`，允许浏览器加载该 Blob 内容作为新的页面。

5. **解析 Blob URL 用于 Worker 脚本加载 (ResolveForWorkerScriptFetch):**
   - 当 Worker 尝试加载一个 `blob:` URL 作为其脚本时，`PublicURLManager` 负责处理。

   **与 JavaScript 的关系：** 在 Worker 中使用 `importScripts('blob:...')` 或 `new Worker('blob:...')` 会触发此功能。
   **假设输入与输出：**
     - **假设输入 (JavaScript, in a Worker):** `importScripts('blob:https://example.com/unique-id');`
     - **可能输出 (C++):** `PublicURLManager::ResolveForWorkerScriptFetch` 被调用，提供加载 Blob 内容作为 Worker 脚本的能力.

6. **生命周期管理 (ExecutionContextLifecycleObserver):**
   - `PublicURLManager` 继承自 `ExecutionContextLifecycleObserver`，这意味着它会监听其关联的 `ExecutionContext` 的生命周期事件。
   - 当 `ExecutionContext` 被销毁时 (`ContextDestroyed`), `PublicURLManager` 会撤销所有注册的 `blob:` URL，以避免资源泄漏。

**与 HTML, CSS 的关系举例：**

* **HTML:**
  ```html
  <img id="myImage">
  <a id="downloadLink">Download File</a>
  ```
  ```javascript
  const blob = new Blob(['This is some text content.'], { type: 'text/plain' });
  const blobURL = URL.createObjectURL(blob);
  document.getElementById('myImage').src = blobURL;
  document.getElementById('downloadLink').href = blobURL;
  document.getElementById('downloadLink').download = 'myFile.txt';

  // 稍后释放 URL
  // URL.revokeObjectURL(blobURL);
  ```
  在这个例子中，`blobURL` 由 `PublicURLManager` 创建，并被用于 `<img>` 标签的 `src` 属性，以及 `<a>` 标签的 `href` 属性，使得图片可以显示，文件可以下载。

* **CSS:**
  ```css
  .my-element {
    background-image: url(blob:https://example.com/some-blob-id);
  }
  ```
  虽然不常见，但 `blob:` URL 也可以用在 CSS 中，例如设置元素的背景图片。`PublicURLManager` 同样会参与处理这种场景。

**逻辑推理与假设输入输出：**

* **假设输入 (JavaScript):**  创建两个包含相同内容的 Blob，并为它们创建 URL。
  ```javascript
  const blob1 = new Blob(['data'], { type: 'text/plain' });
  const blob2 = new Blob(['data'], { type: 'text/plain' });
  const url1 = URL.createObjectURL(blob1);
  const url2 = URL.createObjectURL(blob2);
  console.log(url1);
  console.log(url2);
  ```
  **可能输出 (Console):** 两个不同的 `blob:` URL，例如：
  ```
  blob:https://example.com/unique-id-1
  blob:https://example.com/unique-id-2
  ```
  **推理:**  `PublicURLManager` 的 `RegisterURL` 方法会为每个 Blob 生成一个唯一的 URL，即使 Blob 的内容相同。

**用户或编程常见的使用错误：**

1. **忘记调用 `URL.revokeObjectURL()` 导致内存泄漏：**
   - **错误示例 (JavaScript):**
     ```javascript
     function displayImage(blob) {
       const imageUrl = URL.createObjectURL(blob);
       document.getElementById('myImage').src = imageUrl;
       // 忘记调用 URL.revokeObjectURL(imageUrl);
     }
     ```
   - **说明:** 如果不调用 `URL.revokeObjectURL()`，浏览器会一直持有对 Blob 数据的引用，即使该 URL 不再使用，可能导致内存消耗增加。

2. **尝试撤销来自不同 Origin 的 Blob URL：**
   - **错误示例 (假设在 `https://another-domain.com` 的页面尝试撤销 `https://example.com` 创建的 Blob URL):**
     ```javascript
     // 在 https://another-domain.com 上运行
     const blobUrlFromOtherOrigin = 'blob:https://example.com/some-id';
     URL.revokeObjectURL(blobUrlFromOtherOrigin); // 通常不会生效或抛出错误
     ```
   - **说明:**  `PublicURLManager::Revoke` 会检查 Origin，防止跨域撤销 Blob URL，这是一种安全措施。

3. **使用已经撤销的 Blob URL：**
   - **错误示例 (JavaScript):**
     ```javascript
     const blob = new Blob(['data'], { type: 'text/plain' });
     const blobUrl = URL.createObjectURL(blob);
     URL.revokeObjectURL(blobUrl);
     document.getElementById('myImage').src = blobUrl; // 尝试加载已失效的 URL
     ```
   - **说明:**  一旦 Blob URL 被撤销，尝试使用它加载资源或进行导航将会失败。通常浏览器会显示资源加载失败的错误。

总而言之，`public_url_manager.cc` 是 Blink 引擎中管理 `blob:` URL 的核心组件，它连接了 JavaScript 的 Blob API 和底层的资源加载机制，并负责确保 URL 的正确性和生命周期管理。理解它的功能对于理解浏览器如何处理 Blob 数据至关重要。

### 提示词
```
这是目录为blink/renderer/core/fileapi/public_url_manager.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 Motorola Mobility Inc.
 * Copyright (C) 2013 Google Inc. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/fileapi/public_url_manager.h"

#include "base/feature_list.h"
#include "base/notreached.h"
#include "base/types/pass_key.h"
#include "base/unguessable_token.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "net/base/features.h"
#include "third_party/blink/public/common/associated_interfaces/associated_interface_provider.h"
#include "third_party/blink/public/common/blob/blob_utils.h"
#include "third_party/blink/public/mojom/blob/blob_registry.mojom-blink.h"
#include "third_party/blink/public/mojom/blob/blob_url_store.mojom-blink.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fileapi/url_registry.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/core/workers/worklet_global_scope.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
#include "third_party/blink/renderer/platform/blob/blob_url.h"
#include "third_party/blink/renderer/platform/blob/blob_url_null_origin_map.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/network/blink_schemeful_site.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/task_type_names.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

static void RemoveFromNullOriginMapIfNecessary(const KURL& blob_url) {
  DCHECK(blob_url.ProtocolIs("blob"));
  if (BlobURL::GetOrigin(blob_url) == "null")
    BlobURLNullOriginMap::GetInstance()->Remove(blob_url);
}

}  // namespace

PublicURLManager::PublicURLManager(ExecutionContext* execution_context)
    : ExecutionContextLifecycleObserver(execution_context),
      frame_url_store_(execution_context),
      worker_url_store_(execution_context) {
  if (auto* window = DynamicTo<LocalDOMWindow>(execution_context)) {
    LocalFrame* frame = window->GetFrame();
    if (!frame) {
      is_stopped_ = true;
      return;
    }

    frame->GetRemoteNavigationAssociatedInterfaces()->GetInterface(
        frame_url_store_.BindNewEndpointAndPassReceiver(
            execution_context->GetTaskRunner(TaskType::kFileReading)));

  } else if (auto* worker_global_scope =
                 DynamicTo<WorkerGlobalScope>(execution_context)) {
    if (worker_global_scope->IsClosing()) {
      is_stopped_ = true;
      return;
    }

    worker_global_scope->GetBrowserInterfaceBroker().GetInterface(
        worker_url_store_.BindNewPipeAndPassReceiver(
            execution_context->GetTaskRunner(TaskType::kFileReading)));

  } else if (auto* worklet_global_scope =
                 DynamicTo<WorkletGlobalScope>(execution_context)) {
    if (worklet_global_scope->IsClosing()) {
      is_stopped_ = true;
      return;
    }

    if (worklet_global_scope->IsMainThreadWorkletGlobalScope()) {
      LocalFrame* frame = worklet_global_scope->GetFrame();
      if (!frame) {
        is_stopped_ = true;
        return;
      }

      frame->GetRemoteNavigationAssociatedInterfaces()->GetInterface(
          frame_url_store_.BindNewEndpointAndPassReceiver(
              execution_context->GetTaskRunner(TaskType::kFileReading)));
    } else {
      // For threaded worklets we don't have a frame accessible here, so
      // instead we'll use a PendingRemote provided by the frame that created
      // this worklet.
      mojo::PendingRemote<mojom::blink::BlobURLStore> pending_remote =
          worklet_global_scope->TakeBlobUrlStorePendingRemote();
      DCHECK(pending_remote.is_valid());
      worker_url_store_.Bind(
          std::move(pending_remote),
          execution_context->GetTaskRunner(TaskType::kFileReading));
    }
  } else {
    NOTREACHED();
  }
}

PublicURLManager::PublicURLManager(
    base::PassKey<GlobalStorageAccessHandle>,
    ExecutionContext* execution_context,
    mojo::PendingAssociatedRemote<mojom::blink::BlobURLStore>
        frame_url_store_remote)
    : ExecutionContextLifecycleObserver(execution_context),
      frame_url_store_(execution_context),
      worker_url_store_(execution_context) {
  frame_url_store_.Bind(
      std::move(frame_url_store_remote),
      execution_context->GetTaskRunner(TaskType::kFileReading));
}

mojom::blink::BlobURLStore& PublicURLManager::GetBlobURLStore() {
  DCHECK_NE(frame_url_store_.is_bound(), worker_url_store_.is_bound());
  if (frame_url_store_.is_bound()) {
    return *frame_url_store_.get();
  } else {
    return *worker_url_store_.get();
  }
}

String PublicURLManager::RegisterURL(URLRegistrable* registrable) {
  if (is_stopped_)
    return String();

  const KURL& url =
      BlobURL::CreatePublicURL(GetExecutionContext()->GetSecurityOrigin());
  DCHECK(!url.IsEmpty());
  const String& url_string = url.GetString();

  if (registrable->IsMojoBlob()) {
    mojo::PendingRemote<mojom::blink::Blob> blob_remote;
    mojo::PendingReceiver<mojom::blink::Blob> blob_receiver =
        blob_remote.InitWithNewPipeAndPassReceiver();

    // Determining the top-level site for workers is non-trivial. We assume
    // usage of blob URLs in workers is much lower than in windows, so we
    // should still get useful metrics even while ignoring workers.
    std::optional<BlinkSchemefulSite> top_level_site;
    if (GetExecutionContext()->IsWindow()) {
      auto* window = To<LocalDOMWindow>(GetExecutionContext());
      if (window->top() && window->top()->GetFrame()) {
        top_level_site = BlinkSchemefulSite(window->top()
                                                ->GetFrame()
                                                ->GetSecurityContext()
                                                ->GetSecurityOrigin());
      }
    }

    GetBlobURLStore().Register(std::move(blob_remote), url,
                               GetExecutionContext()->GetAgentClusterID(),
                               top_level_site);

    mojo_urls_.insert(url_string);
    registrable->CloneMojoBlob(std::move(blob_receiver));
  } else {
    URLRegistry* registry = &registrable->Registry();
    registry->RegisterURL(url, registrable);
    url_to_registry_.insert(url_string, registry);
  }

  SecurityOrigin* mutable_origin =
      GetExecutionContext()->GetMutableSecurityOrigin();
  if (mutable_origin->SerializesAsNull()) {
    BlobURLNullOriginMap::GetInstance()->Add(url, mutable_origin);
  }

  return url_string;
}

void PublicURLManager::Revoke(const KURL& url) {
  if (is_stopped_)
    return;
  // Don't bother trying to revoke URLs that can't have been registered anyway.
  if (!url.ProtocolIs("blob") || url.HasFragmentIdentifier())
    return;
  // Don't support revoking cross-origin blob URLs.
  if (!SecurityOrigin::Create(url)->IsSameOriginWith(
          GetExecutionContext()->GetSecurityOrigin()))
    return;

  GetBlobURLStore().Revoke(url);
  mojo_urls_.erase(url.GetString());

  RemoveFromNullOriginMapIfNecessary(url);
  auto it = url_to_registry_.find(url.GetString());
  if (it == url_to_registry_.end())
    return;
  it->value->UnregisterURL(url);
  url_to_registry_.erase(it);
}

void PublicURLManager::Resolve(
    const KURL& url,
    mojo::PendingReceiver<network::mojom::blink::URLLoaderFactory>
        factory_receiver) {
  if (is_stopped_)
    return;

  DCHECK(url.ProtocolIs("blob"));

  auto metrics_callback = [](ExecutionContext* execution_context,
                             const std::optional<base::UnguessableToken>&
                                 unsafe_agent_cluster_id,
                             const std::optional<BlinkSchemefulSite>&
                                 unsafe_top_level_site) {
    if (execution_context->GetAgentClusterID() != unsafe_agent_cluster_id) {
      execution_context->CountUse(
          WebFeature::
              kBlobStoreAccessAcrossAgentClustersInResolveAsURLLoaderFactory);
    }
    // Determining top-level site in a worker is non-trivial. Since this is only
    // used to calculate metrics it should be okay to not track top-level site
    // in that case, as long as the count for unknown top-level sites ends up
    // low enough compared to overall usage.
    std::optional<BlinkSchemefulSite> top_level_site;
    if (execution_context->IsWindow()) {
      auto* window = To<LocalDOMWindow>(execution_context);
      if (window->top() && window->top()->GetFrame()) {
        top_level_site = BlinkSchemefulSite(window->top()
                                                ->GetFrame()
                                                ->GetSecurityContext()
                                                ->GetSecurityOrigin());
      }
    }
    if ((!top_level_site || !unsafe_top_level_site) &&
        execution_context->GetAgentClusterID() != unsafe_agent_cluster_id) {
      // Either the registration or resolve happened in a context where it's not
      // easy to determine the top-level site, and agent cluster doesn't match
      // either (if agent cluster matches, by definition top-level site would
      // also match, so this only records page loads where there is a chance
      // that top-level site doesn't match).
      execution_context->CountUse(
          WebFeature::kBlobStoreAccessUnknownTopLevelSite);
    } else if (top_level_site != unsafe_top_level_site) {
      // Blob URL lookup happened with a different top-level site than Blob URL
      // registration.
      execution_context->CountUse(
          WebFeature::kBlobStoreAccessAcrossTopLevelSite);
    }
  };

  GetBlobURLStore().ResolveAsURLLoaderFactory(
      url, std::move(factory_receiver),
      WTF::BindOnce(metrics_callback, WrapPersistent(GetExecutionContext())));
}

void PublicURLManager::Resolve(
    const KURL& url,
    mojo::PendingReceiver<mojom::blink::BlobURLToken> token_receiver) {
  if (is_stopped_)
    return;

  DCHECK(url.ProtocolIs("blob"));

  auto metrics_callback = [](ExecutionContext* execution_context,
                             const std::optional<base::UnguessableToken>&
                                 unsafe_agent_cluster_id) {
    if (execution_context->GetAgentClusterID() != unsafe_agent_cluster_id) {
      execution_context->CountUse(
          WebFeature::
              kBlobStoreAccessAcrossAgentClustersInResolveForNavigation);
    }
  };

  GetBlobURLStore().ResolveForNavigation(
      url, std::move(token_receiver),
      WTF::BindOnce(metrics_callback, WrapPersistent(GetExecutionContext())));
}

void PublicURLManager::ResolveForWorkerScriptFetch(
    const KURL& url,
    mojo::PendingReceiver<mojom::blink::BlobURLToken> token_receiver) {
  if (is_stopped_) {
    return;
  }

  DCHECK(url.ProtocolIs("blob"));

  // This code used to be executed as part of the ResolveForNavigation flow, so
  // it is repeated to preserve the existing functionality.
  auto metrics_callback =
      [](ExecutionContext* execution_context,
         const std::optional<base::UnguessableToken>& unsafe_agent_cluster_id) {
        if (execution_context->GetAgentClusterID() != unsafe_agent_cluster_id) {
          execution_context->CountUse(
              WebFeature::
                  kBlobStoreAccessAcrossAgentClustersInResolveForNavigation);
        }
      };

  GetBlobURLStore().ResolveForWorkerScriptFetch(
      url, std::move(token_receiver),
      WTF::BindOnce(metrics_callback, WrapPersistent(GetExecutionContext())));
}

void PublicURLManager::ContextDestroyed() {
  if (is_stopped_)
    return;

  is_stopped_ = true;
  for (auto& url_registry : url_to_registry_) {
    url_registry.value->UnregisterURL(KURL(url_registry.key));
    RemoveFromNullOriginMapIfNecessary(KURL(url_registry.key));
  }
  for (const auto& url : mojo_urls_)
    RemoveFromNullOriginMapIfNecessary(KURL(url));

  url_to_registry_.clear();
  mojo_urls_.clear();
}

void PublicURLManager::Trace(Visitor* visitor) const {
  visitor->Trace(frame_url_store_);
  visitor->Trace(worker_url_store_);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

}  // namespace blink
```