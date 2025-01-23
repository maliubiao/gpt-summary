Response:
Let's break down the thought process to analyze this C++ file and answer the prompt.

1. **Understand the Goal:** The request asks for a functional description of `prefetched_signed_exchange_manager.cc`, its relationship to web technologies, logical reasoning examples, common errors, and how a user might trigger its execution (debugging clues).

2. **Initial Skim for Keywords and Structure:** Quickly read through the code looking for important terms like "Signed Exchange," "Prefetch," "URLLoader," "ResourceRequest," "Throttle," "Link Header," etc. Notice the class `PrefetchedSignedExchangeManager` and its inner class `PrefetchedSignedExchangeLoader`. This gives a high-level idea of the file's purpose.

3. **Focus on the Core Class:** The `PrefetchedSignedExchangeManager` is the central piece. Its constructor, methods like `MaybeCreate`, `StartPrefetchedLinkHeaderPreloads`, `MaybeCreateURLLoader`, `TriggerLoad`, and the presence of member variables like `alternative_resources_` and `prefetched_exchanges_map_` are key.

4. **Decipher the Functionality (Step-by-Step):**

   * **`MaybeCreate`:**  This suggests a conditional creation. It takes `Link` headers and a list of prefetched signed exchanges. The check for empty `prefetched_signed_exchanges` and the validation of `alternative_resources` indicate this class is only instantiated when prefetching signed exchanges is relevant and the necessary headers are present.

   * **Constructor:**  Simple initialization of member variables.

   * **`StartPrefetchedLinkHeaderPreloads`:** This method seems to initiate the actual preloading process. The clearing of `prefetched_exchanges_map_` and `alternative_resources_` after starting suggests these are temporary storage. The call to `TriggerLoad()` is crucial.

   * **`MaybeCreateURLLoader`:** This method is interesting because it intercepts requests. It checks if preloading has started and then tries to find a matching prefetch based on the request URL, destination, and language. If a match is found, it creates a `PrefetchedSignedExchangeLoader`. This hints at the mechanism for substituting a prefetched exchange for a normal resource request.

   * **`CreateDefaultURLLoader` and `CreatePrefetchedSignedExchangeURLLoader`:** These seem like factory methods for creating different types of `URLLoader` instances – one for regular loads and one specifically for prefetched signed exchanges. The latter takes a `loader_factory` as input, implying the prefetched exchange data comes from a different source (likely the browser process).

   * **`TriggerLoad`:** This is where the core logic of matching prefetches happens. It iterates through the `loaders_` (created by `MaybeCreateURLLoader`), tries to find corresponding prefetched exchanges based on URLs and header integrity, and then sets the correct `URLLoader` (either the default or the prefetched one) for each request. The error handling and console messages are important to note.

5. **Identify Relationships to Web Technologies:**

   * **Signed Exchanges:** The name itself points to a web standard. Connect this to the concept of pre-packaged HTTP responses and their security implications.
   * **Prefetching:** Link headers with `rel=prefetch` are the primary trigger. Explain how this HTML mechanism initiates the process.
   * **JavaScript:**  While not directly manipulating this C++ code, JavaScript can trigger navigation that benefits from these prefetched resources. Mention how a user clicking a link or a script initiating a navigation would be the end result.
   * **HTML:**  The `Link` header is an HTML concept, critical for signaling prefetch intent.
   * **CSS:** While less direct, CSS resources can be prefetched. This file helps manage the loading of those prefetched resources as well.

6. **Construct Logical Reasoning Examples:** Think of scenarios where the matching logic in `TriggerLoad` would succeed or fail. Create hypothetical inputs (request URLs, header values, prefetched exchange data) and predict the output (whether a prefetched exchange is used or a default load occurs).

7. **Consider Common Errors:**  Think about what could go wrong in the prefetching process. Mismatched URLs, incorrect header integrity values, and issues with the `loader_factory` are good candidates. Relate these to potential developer errors in configuring prefetching.

8. **Trace User Actions (Debugging Clues):** Start with a user action in the browser (e.g., typing a URL, clicking a link). Trace how this leads to the browser parsing HTML, encountering `Link` headers, initiating prefetches, and eventually reaching the code in this file when a navigation to a prefetched resource occurs.

9. **Structure the Answer:** Organize the findings into clear sections addressing each part of the prompt: Functionality, Web Technology Relationship, Logical Reasoning, Common Errors, and User Actions/Debugging. Use clear and concise language. Code snippets (even conceptual) can be helpful in the logical reasoning section.

10. **Review and Refine:** Read through the answer to ensure accuracy, clarity, and completeness. Check for any logical inconsistencies or missing information. Make sure the examples are illustrative and easy to understand. For instance, initially, I might focus too much on the technical details of `URLLoader`. Reviewing would prompt me to better explain the high-level purpose and its user-facing benefits.
好的，这是对 `blink/renderer/core/loader/prefetched_signed_exchange_manager.cc` 文件的功能分析：

**文件功能概述:**

`PrefetchedSignedExchangeManager` 类的主要功能是管理预取（prefetch）的签名交换 (Signed Exchange, SXG) 资源。它的目标是优化页面加载性能，特别是对于通过 `<link rel="prefetch">` 或其他机制预取的 SXG 资源。

**核心功能点:**

1. **存储和管理预取的 SXG 信息:**
   - 它接收并存储从浏览器进程传递过来的预取 SXG 资源的相关信息，例如外部 URL、内部 URL、头部完整性 (header integrity) 以及用于加载这些资源的 `URLLoaderFactory`。
   - 使用 `prefetched_exchanges_map_` 哈希映射来根据外部 URL 存储这些预取信息。

2. **拦截资源请求并尝试匹配预取的 SXG:**
   - 当页面发起资源请求时，特别是那些与预取 SXG 资源相关的子资源请求，`MaybeCreateURLLoader` 方法会被调用。
   - 它会检查请求的 URL、目标类型以及语言设置，尝试在已预取的 SXG 资源中找到匹配项。匹配的依据是 `<link>` 头部中 `alternate` 关系声明的 URL 和其他属性。

3. **创建自定义的 `URLLoader` 加载预取的 SXG:**
   - 如果找到匹配的预取 SXG 资源，它会创建一个 `PrefetchedSignedExchangeLoader` 实例。
   - `PrefetchedSignedExchangeLoader` 继承自 `URLLoader`，并负责实际的资源加载过程。它会延迟实际的 `URLLoader` 创建，直到确认可以使用预取的 SXG。

4. **触发预取链接头部的预加载:**
   - `StartPrefetchedLinkHeaderPreloads` 方法标志着预取过程的开始。
   - 它会调用 `TriggerLoad` 来尝试将之前创建的 `PrefetchedSignedExchangeLoader` 与实际的预取 SXG 资源关联起来。

5. **在 `TriggerLoad` 中验证并替换 `URLLoader`:**
   - `TriggerLoad` 方法是关键的匹配和替换逻辑所在。
   - 它会遍历所有待处理的 `PrefetchedSignedExchangeLoader`。
   - 对于每个 loader，它会再次检查是否存在匹配的预取 SXG 资源，并验证外部 URL、内部 URL 和头部完整性。
   - 如果所有条件都匹配，它会使用预取 SXG 提供的 `URLLoaderFactory` 创建一个新的 `URLLoader`，并将其设置到 `PrefetchedSignedExchangeLoader` 中，从而使用预取的资源进行加载。
   - 如果匹配失败，它会创建一个默认的 `URLLoader` 来加载原始的资源。

6. **处理匹配失败的情况:**
   - 如果在 `TriggerLoad` 中找不到所有预取资源的匹配项，或者匹配的完整性校验失败，它会降级并使用默认的加载方式加载所有相关的原始资源。这是一种安全机制，防止分发者向发布者发送任意信息。
   - 它会在控制台中输出错误消息，指示预取匹配失败。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    - **`<link rel="prefetch" href="...">`:**  这是触发预取机制的关键 HTML 元素。当浏览器解析到这个标签时，会请求预先加载指定的资源。如果预取的资源是 Signed Exchange，浏览器会将相关信息传递给 Blink 渲染引擎，`PrefetchedSignedExchangeManager` 就会参与进来管理这些预取资源。
        ```html
        <link rel="prefetch" href="https://example.com/page.sxg">
        ```
    - **`<link rel="alternate" href="..." headers="...">`:**  在预取 SXG 的上下文中，原始资源可能会通过 HTTP 头部或 `<link>` 标签声明一个指向 SXG 版本的 "alternate" 链接，并包含 `headers` 属性来描述 SXG 的头部完整性。`PrefetchedSignedExchangeManager` 会解析这些信息来找到匹配的预取 SXG。
        ```html
        <link rel="alternate" href="https://example.com/page.sxg" headers="digest: mi-sha256-base64:...">
        ```

* **JavaScript:**
    - JavaScript 本身不会直接操作 `PrefetchedSignedExchangeManager`。然而，JavaScript 可以触发页面导航或资源请求，从而间接地受益于预取的 SXG 资源。例如，用户点击一个链接，如果该链接对应的资源已被预取为 SXG，`PrefetchedSignedExchangeManager` 就会尝试使用预取的版本加载，加快页面加载速度。
    - 开发者可以使用 JavaScript 的 `Performance API` 或 `Resource Timing API` 来观察预取带来的性能提升。

* **CSS:**
    - CSS 文件本身也可以被预取，如果预取的 CSS 文件是 Signed Exchange，`PrefetchedSignedExchangeManager` 同样会参与管理。
    - CSS 中引用的其他资源（如图片、字体）也可能被预取为 SXG。

**逻辑推理示例:**

**假设输入:**

1. **预取链接:**  页面 HTML 中包含 `<link rel="prefetch" href="https://example.com/page.sxg">`。
2. **预取结果:** 浏览器成功预取了 `https://example.com/page.sxg`，并将其作为 Signed Exchange 存储，相关的 `URLLoaderFactory` 信息被传递给 `PrefetchedSignedExchangeManager`。
3. **导航:** 用户点击了一个链接，导致浏览器请求 `https://example.com/page.html`，而 `page.html` 的响应头部或 HTML 中声明了 `alternate` 链接指向 `https://example.com/page.sxg`，并且头部完整性信息匹配。

**输出:**

1. 当请求 `https://example.com/page.html` 时，`MaybeCreateURLLoader` 会被调用。
2. `TriggerLoad` 方法会被触发。
3. `PrefetchedSignedExchangeManager` 会找到与 `https://example.com/page.html` 匹配的预取 SXG 资源 `https://example.com/page.sxg`，并且头部完整性校验通过。
4. `PrefetchedSignedExchangeManager` 会使用预取 SXG 提供的 `URLLoaderFactory` 创建一个 `URLLoader`，并用它来加载 `https://example.com/page.html` 的内容，从而实现快速加载。

**用户或编程常见的使用错误及举例说明:**

1. **预取链接配置错误:**
   - **错误:**  `<link rel="prefetch" href="https://example.com/page">`，但实际服务器返回的资源不是 Signed Exchange，或者没有正确的 `alternate` 链接头。
   - **结果:** 预取操作无效，或者在尝试匹配时找不到对应的预取 SXG。`TriggerLoad` 会因为找不到匹配而回退到默认加载。

2. **头部完整性 (header integrity) 不匹配:**
   - **错误:**  原始资源声明的 SXG 头部完整性信息与预取到的 SXG 实际的头部信息不符。
   - **结果:**  `TriggerLoad` 中的完整性校验会失败，为了安全起见，会放弃使用预取的 SXG，转而加载原始资源。这通常是由于服务器配置错误或 SXG 生成过程中的问题导致。

3. **`alternate` 链接配置错误:**
   - **错误:**  原始资源没有正确配置 `alternate` 链接指向预取的 SXG，或者 `alternate` 链接中的 `headers` 属性信息不正确。
   - **结果:** `PrefetchedSignedExchangeManager` 无法将当前的资源请求与预取的 SXG 关联起来，导致预取失效。

4. **预取资源过期或失效:**
   - **错误:**  预取的 SXG 资源在被使用时已经过期或失效（例如，缓存策略导致）。
   - **结果:**  即使找到了匹配的预取资源，加载也可能失败，最终会回退到加载原始资源。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户发起页面请求或导航:** 用户在浏览器地址栏输入 URL，点击书签，或者点击页面上的链接。
2. **浏览器解析 HTML:** 浏览器接收到服务器返回的 HTML 响应后，开始解析 HTML 文档。
3. **发现 `<link rel="prefetch">` 标签:**  如果 HTML 中包含 `<link rel="prefetch" href="...">` 标签，浏览器会根据标签的属性发起预取请求。
4. **预取 Signed Exchange 资源:** 如果预取的资源是 Signed Exchange，浏览器会下载该资源，并将其存储在本地缓存中，同时会将预取的相关信息（包括 `URLLoaderFactory`）传递给渲染进程。
5. **渲染进程接收预取信息:**  Blink 渲染引擎的 `PrefetchedSignedExchangeManager` 接收到这些预取信息，并存储起来。
6. **用户触发资源请求:** 用户进行某些操作，例如点击链接，或者页面 JavaScript 发起资源请求。
7. **`MaybeCreateURLLoader` 被调用:** 当需要加载某个资源时，`ResourceLoader` 会调用 `PrefetchedSignedExchangeManager::MaybeCreateURLLoader`，看是否有匹配的预取 SXG 可以使用。
8. **`StartPrefetchedLinkHeaderPreloads` 被调用 (通常在文档加载后期):** 如果在文档加载过程中发现了有效的预取 SXG 资源，会调用此方法来启动匹配过程。
9. **`TriggerLoad` 执行匹配和替换:** `TriggerLoad` 方法会被调用，它会尝试将待加载的资源请求与之前预取的 SXG 资源进行匹配，如果匹配成功，则使用预取的资源进行加载。

**调试线索:**

* **网络面板:**  在 Chrome 开发者工具的网络面板中，可以查看预取请求的状态，以及资源是否以 Signed Exchange 的方式加载。
* **控制台消息:** `PrefetchedSignedExchangeManager` 在匹配失败时会输出控制台消息，可以关注这些消息来诊断问题。
* **`chrome://net-internals/#sxg`:**  这个 Chrome 内部页面提供了关于 Signed Exchange 的详细信息，包括缓存状态和错误信息。
* **Blink 调试日志:**  可以通过设置 Blink 的 tracing 或 logging 来查看 `PrefetchedSignedExchangeManager` 的内部运行状态和决策过程。
* **断点调试:**  在 `PrefetchedSignedExchangeManager.cc` 中设置断点，可以逐步跟踪代码的执行流程，查看预取信息的存储、匹配过程以及 `URLLoader` 的创建和替换。

总而言之，`PrefetchedSignedExchangeManager` 是 Blink 渲染引擎中一个关键的组件，它负责管理预取的 Signed Exchange 资源，并通过智能地匹配和替换 `URLLoader`，来优化页面加载性能并提升用户体验。理解其工作原理对于调试预取相关的问题至关重要。

### 提示词
```
这是目录为blink/renderer/core/loader/prefetched_signed_exchange_manager.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/loader/prefetched_signed_exchange_manager.h"

#include <optional>
#include <queue>
#include <utility>

#include "base/functional/callback.h"
#include "base/memory/weak_ptr.h"
#include "base/task/single_thread_task_runner.h"
#include "base/trace_event/trace_event.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/shared_url_loader_factory.h"
#include "services/network/public/cpp/wrapper_shared_url_loader_factory.h"
#include "services/network/public/mojom/url_loader_factory.mojom-blink.h"
#include "third_party/blink/public/mojom/devtools/console_message.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/resource_load_info_notifier_wrapper.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_url_request_extra_data.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/loader/alternate_signed_exchange_resource_info.h"
#include "third_party/blink/renderer/core/loader/loader_factory_for_frame.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/code_cache_host.h"
#include "third_party/blink/renderer/platform/loader/fetch/loader_freeze_mode.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader_client.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader_factory.h"
#include "third_party/blink/renderer/platform/loader/link_header.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_scheduler.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/kurl_hash.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

class PrefetchedSignedExchangeManager::PrefetchedSignedExchangeLoader
    : public URLLoader {
 public:
  PrefetchedSignedExchangeLoader(
      const network::ResourceRequest& request,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      Vector<std::unique_ptr<URLLoaderThrottle>> throttles)
      : request_(request),
        task_runner_(std::move(task_runner)),
        throttles_(std::move(throttles)) {
    TRACE_EVENT_NESTABLE_ASYNC_BEGIN1("loading",
                                      "PrefetchedSignedExchangeLoader", this,
                                      "url", request_.url.spec());
  }

  PrefetchedSignedExchangeLoader(const PrefetchedSignedExchangeLoader&) =
      delete;
  PrefetchedSignedExchangeLoader& operator=(
      const PrefetchedSignedExchangeLoader&) = delete;

  ~PrefetchedSignedExchangeLoader() override {
    TRACE_EVENT_NESTABLE_ASYNC_END0("loading", "PrefetchedSignedExchangeLoader",
                                    this);
  }

  base::WeakPtr<PrefetchedSignedExchangeLoader> GetWeakPtr() {
    return weak_ptr_factory_.GetWeakPtr();
  }

  void SetURLLoader(std::unique_ptr<URLLoader> url_loader) {
    DCHECK(!url_loader_);
    url_loader_ = std::move(url_loader);
    ExecutePendingMethodCalls();
  }

  const network::ResourceRequest& request() const { return request_; }

  Vector<std::unique_ptr<URLLoaderThrottle>> TakeThrottles() {
    return std::move(throttles_);
  }

  // URLLoader methods:
  void LoadSynchronously(std::unique_ptr<network::ResourceRequest> request,
                         scoped_refptr<const SecurityOrigin> top_frame_origin,
                         bool download_to_blob,
                         bool no_mime_sniffing,
                         base::TimeDelta timeout_interval,
                         URLLoaderClient* client,
                         WebURLResponse& response,
                         std::optional<WebURLError>& error,
                         scoped_refptr<SharedBuffer>& data,
                         int64_t& encoded_data_length,
                         uint64_t& encoded_body_length,
                         scoped_refptr<BlobDataHandle>& downloaded_blob,
                         std::unique_ptr<blink::ResourceLoadInfoNotifierWrapper>
                             resource_load_info_notifier_wrapper) override {
    NOTREACHED();
  }
  void LoadAsynchronously(
      std::unique_ptr<network::ResourceRequest> request,
      scoped_refptr<const SecurityOrigin> top_frame_origin,
      bool no_mime_sniffing,
      std::unique_ptr<blink::ResourceLoadInfoNotifierWrapper>
          resource_load_info_notifier_wrapper,
      CodeCacheHost* code_cache_host,
      URLLoaderClient* client) override {
    if (url_loader_) {
      url_loader_->LoadAsynchronously(
          std::move(request), std::move(top_frame_origin), no_mime_sniffing,
          std::move(resource_load_info_notifier_wrapper), code_cache_host,
          client);
      return;
    }
    // It is safe to use Unretained(client), because |client| is a
    // ResourceLoader which owns |this|, and we are binding with weak ptr of
    // |this| here.
    pending_method_calls_.push(WTF::BindOnce(
        [](base::WeakPtr<PrefetchedSignedExchangeLoader> self,
           std::unique_ptr<network::ResourceRequest> request,
           scoped_refptr<const SecurityOrigin> top_frame_origin,
           bool no_mime_sniffing,
           std::unique_ptr<blink::ResourceLoadInfoNotifierWrapper>
               resource_load_info_notifier_wrapper,
           base::WeakPtr<CodeCacheHost> code_cache_host,
           URLLoaderClient* client) {
          if (self) {
            self->LoadAsynchronously(
                std::move(request), top_frame_origin, no_mime_sniffing,
                std::move(resource_load_info_notifier_wrapper),
                code_cache_host.get(), client);
          }
        },
        GetWeakPtr(), std::move(request), std::move(top_frame_origin),
        no_mime_sniffing, std::move(resource_load_info_notifier_wrapper),
        code_cache_host ? code_cache_host->GetWeakPtr() : nullptr,
        WTF::Unretained(client)));
  }
  void Freeze(LoaderFreezeMode value) override {
    if (url_loader_) {
      url_loader_->Freeze(value);
      return;
    }
    pending_method_calls_.push(WTF::BindOnce(
        &PrefetchedSignedExchangeLoader::Freeze, GetWeakPtr(), value));
  }
  void DidChangePriority(WebURLRequest::Priority new_priority,
                         int intra_priority_value) override {
    if (url_loader_) {
      url_loader_->DidChangePriority(new_priority, intra_priority_value);
      return;
    }
    pending_method_calls_.push(
        WTF::BindOnce(&PrefetchedSignedExchangeLoader::DidChangePriority,
                      GetWeakPtr(), new_priority, intra_priority_value));
  }
  scoped_refptr<base::SingleThreadTaskRunner> GetTaskRunnerForBodyLoader()
      override {
    return task_runner_;
  }

 private:
  void ExecutePendingMethodCalls() {
    std::queue<base::OnceClosure> pending_calls =
        std::move(pending_method_calls_);
    while (!pending_calls.empty()) {
      std::move(pending_calls.front()).Run();
      pending_calls.pop();
    }
  }

  const network::ResourceRequest request_;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  Vector<std::unique_ptr<URLLoaderThrottle>> throttles_;
  std::unique_ptr<URLLoader> url_loader_;
  std::queue<base::OnceClosure> pending_method_calls_;

  base::WeakPtrFactory<PrefetchedSignedExchangeLoader> weak_ptr_factory_{this};
};

// static
PrefetchedSignedExchangeManager* PrefetchedSignedExchangeManager::MaybeCreate(
    LocalFrame* frame,
    const String& outer_link_header,
    const String& inner_link_header,
    WebVector<std::unique_ptr<WebNavigationParams::PrefetchedSignedExchange>>
        prefetched_signed_exchanges) {
  if (prefetched_signed_exchanges.empty())
    return nullptr;
  std::unique_ptr<AlternateSignedExchangeResourceInfo> alternative_resources =
      AlternateSignedExchangeResourceInfo::CreateIfValid(outer_link_header,
                                                         inner_link_header);
  if (!alternative_resources) {
    // There is no "allowed-alt-sxg" link header for this resource.
    return nullptr;
  }

  HashMap<KURL, std::unique_ptr<WebNavigationParams::PrefetchedSignedExchange>>
      prefetched_exchanges_map;
  for (auto& exchange : prefetched_signed_exchanges) {
    const KURL outer_url = exchange->outer_url;
    prefetched_exchanges_map.Set(outer_url, std::move(exchange));
  }

  return MakeGarbageCollected<PrefetchedSignedExchangeManager>(
      frame, std::move(alternative_resources),
      std::move(prefetched_exchanges_map));
}

PrefetchedSignedExchangeManager::PrefetchedSignedExchangeManager(
    LocalFrame* frame,
    std::unique_ptr<AlternateSignedExchangeResourceInfo> alternative_resources,
    HashMap<KURL,
            std::unique_ptr<WebNavigationParams::PrefetchedSignedExchange>>
        prefetched_exchanges_map)
    : frame_(frame),
      alternative_resources_(std::move(alternative_resources)),
      prefetched_exchanges_map_(std::move(prefetched_exchanges_map)) {
  TRACE_EVENT_NESTABLE_ASYNC_BEGIN0("loading",
                                    "PrefetchedSignedExchangeManager", this);
}

PrefetchedSignedExchangeManager::~PrefetchedSignedExchangeManager() {}

void PrefetchedSignedExchangeManager::Trace(Visitor* visitor) const {
  visitor->Trace(frame_);
}

void PrefetchedSignedExchangeManager::StartPrefetchedLinkHeaderPreloads() {
  DCHECK(!started_);
  started_ = true;
  TriggerLoad();
  // Clears |prefetched_exchanges_map_| to release URLLoaderFactory in the
  // browser process.
  prefetched_exchanges_map_.clear();
  // Clears |alternative_resources_| which will not be used forever.
  alternative_resources_.reset();
}

std::unique_ptr<URLLoader>
PrefetchedSignedExchangeManager::MaybeCreateURLLoader(
    const network::ResourceRequest& network_request,
    base::OnceCallback<Vector<std::unique_ptr<URLLoaderThrottle>>(void)>
        create_throttles_callback) {
  if (started_)
    return nullptr;
  const auto* matching_resource = alternative_resources_->FindMatchingEntry(
      KURL(network_request.url), network_request.destination,
      frame_->DomWindow()->navigator()->languages());
  if (!matching_resource)
    return nullptr;

  std::unique_ptr<PrefetchedSignedExchangeLoader> loader =
      std::make_unique<PrefetchedSignedExchangeLoader>(
          network_request,
          frame_->GetFrameScheduler()->GetTaskRunner(
              TaskType::kInternalLoading),
          std::move(create_throttles_callback).Run());
  loaders_.emplace_back(loader->GetWeakPtr());
  return loader;
}

std::unique_ptr<URLLoader>
PrefetchedSignedExchangeManager::CreateDefaultURLLoader(
    const network::ResourceRequest& request,
    Vector<std::unique_ptr<URLLoaderThrottle>> throttles) {
  return std::make_unique<blink::URLLoaderFactory>(
             frame_->GetURLLoaderFactory(),
             LoaderFactoryForFrame::GetCorsExemptHeaderList(),
             /*terminate_sync_load_event=*/nullptr)
      ->CreateURLLoader(request, frame_->GetTaskRunner(TaskType::kNetworking),
                        frame_->GetTaskRunner(TaskType::kNetworkingUnfreezable),
                        /*keep_alive_handle=*/mojo::NullRemote(),
                        /*back_forward_cache_loader_helper=*/nullptr,
                        std::move(throttles));
}

std::unique_ptr<URLLoader>
PrefetchedSignedExchangeManager::CreatePrefetchedSignedExchangeURLLoader(
    const network::ResourceRequest& request,
    Vector<std::unique_ptr<URLLoaderThrottle>> throttles,
    mojo::PendingRemote<network::mojom::blink::URLLoaderFactory>
        loader_factory) {
  return std::make_unique<URLLoaderFactory>(
             base::MakeRefCounted<network::WrapperSharedURLLoaderFactory>(
                 CrossVariantMojoRemote<
                     network::mojom::URLLoaderFactoryInterfaceBase>(
                     std::move(loader_factory))),
             LoaderFactoryForFrame::GetCorsExemptHeaderList(),
             /*terminate_sync_load_event=*/nullptr)
      ->CreateURLLoader(request, frame_->GetTaskRunner(TaskType::kNetworking),
                        frame_->GetTaskRunner(TaskType::kNetworkingUnfreezable),
                        /*keep_alive_handle=*/mojo::NullRemote(),
                        /*back_forward_cache_loader_helper=*/nullptr,
                        std::move(throttles));
}

void PrefetchedSignedExchangeManager::TriggerLoad() {
  Vector<WebNavigationParams::PrefetchedSignedExchange*>
      maching_prefetched_exchanges;
  const char* failure_reason = nullptr;
  for (auto loader : loaders_) {
    if (!loader) {
      // The loader has been canceled.
      maching_prefetched_exchanges.emplace_back(nullptr);
      // We can continue the matching, because the distributor can't send
      // arbitrary information to the publisher using this resource.
      continue;
    }
    const auto* matching_resource = alternative_resources_->FindMatchingEntry(
        KURL(loader->request().url), loader->request().destination,
        frame_->DomWindow()->navigator()->languages());
    const auto alternative_url = matching_resource->alternative_url();
    if (!alternative_url.IsValid()) {
      failure_reason =
          "no matching \"alternate\" link header in outer response header";
      break;
    }
    const auto exchange_it = prefetched_exchanges_map_.find(alternative_url);
    if (exchange_it == prefetched_exchanges_map_.end()) {
      failure_reason = "no matching prefetched exchange";
      break;
    }
    if (String(exchange_it->value->header_integrity) !=
        matching_resource->header_integrity()) {
      failure_reason = "header integrity doesn't match";
      break;
    }
    if (KURL(exchange_it->value->inner_url) !=
        matching_resource->anchor_url()) {
      failure_reason = "inner URL doesn't match";
      break;
    }
    maching_prefetched_exchanges.emplace_back(exchange_it->value.get());
  }
  if (loaders_.size() != maching_prefetched_exchanges.size()) {
    // Need to load the all original resources in this case to prevent the
    // distributor from sending arbitrary information to the publisher.
    String message =
        "Failed to match prefetched alternative signed exchange subresources. "
        "Requesting the all original resources ignoreing all alternative signed"
        " exchange responses.";
    frame_->GetDocument()->AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::ConsoleMessageSource::kNetwork,
            mojom::ConsoleMessageLevel::kError, message));
    for (auto loader : loaders_) {
      if (!loader)
        continue;
      loader->SetURLLoader(
          CreateDefaultURLLoader(loader->request(), loader->TakeThrottles()));
    }
    TRACE_EVENT_NESTABLE_ASYNC_END2(
        "loading", "PrefetchedSignedExchangeManager", this, "match_result",
        "failure", "reason", failure_reason);
    return;
  }
  for (wtf_size_t i = 0; i < loaders_.size(); ++i) {
    auto loader = loaders_.at(i);
    if (!loader)
      continue;
    auto* prefetched_exchange = maching_prefetched_exchanges.at(i);
    mojo::Remote<network::mojom::blink::URLLoaderFactory> loader_factory(
        std::move(prefetched_exchange->loader_factory));
    mojo::PendingRemote<network::mojom::blink::URLLoaderFactory>
        loader_factory_clone;
    loader_factory->Clone(
        loader_factory_clone.InitWithNewPipeAndPassReceiver());
    // Reset loader_factory_handle to support loading the same resource again.
    prefetched_exchange->loader_factory = std::move(loader_factory_clone);
    loader->SetURLLoader(CreatePrefetchedSignedExchangeURLLoader(
        loader->request(), loader->TakeThrottles(), loader_factory.Unbind()));
  }
  TRACE_EVENT_NESTABLE_ASYNC_END1("loading", "PrefetchedSignedExchangeManager",
                                  this, "match_result", "success");
}

}  // namespace blink
```