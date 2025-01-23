Response:
Let's break down the thought process for analyzing this C++ code and generating the explanation.

1. **Understand the Goal:** The primary goal is to explain the functionality of the provided C++ file (`service_worker_installed_scripts_manager.cc`) within the Chromium Blink engine, specifically focusing on its relationship to web technologies (JavaScript, HTML, CSS), potential user/programming errors, and how users might trigger this code.

2. **Initial Skim for Keywords and Structure:** Read through the code quickly, looking for important keywords and the overall structure. Notice things like:
    * Includes for platform-level features (`WebURL`, `WebEmbeddedWorker`) and Blink-specific modules (`service_worker_thread.h`).
    * Use of Mojo (bindings, receivers, data pipes).
    * Asynchronous operations and thread management (task runners, `PostCrossThreadTask`).
    * Data structures like `HashMap`, `Vector`.
    * The `blink` namespace.
    * Class names like `Receiver`, `BundledReceivers`, `Internal`, `ServiceWorkerInstalledScriptsManager`.

3. **Identify the Core Functionality:** The core responsibility appears to be managing the retrieval and storage of Service Worker scripts that are *already installed*. The name `ServiceWorkerInstalledScriptsManager` strongly suggests this. The file doesn't seem to be involved in the *installation* process itself.

4. **Analyze Key Classes:**  Examine the purpose of each class:
    * **`Receiver`:** This class handles reading data from a Mojo data pipe. It reads data in chunks and uses a `mojo::SimpleWatcher` for asynchronous I/O. The data being read is likely the script content or metadata.
    * **`BundledReceivers`:**  This class manages two `Receiver` instances, one for script body and one for metadata. It ensures both are fully received before proceeding. This suggests scripts have separate body and metadata components.
    * **`Internal`:**  This is the core logic that interacts with the browser process (via Mojo) to receive `ServiceWorkerScriptInfo` and then uses `BundledReceivers` to download the script content. It stores the received scripts in `script_container_`.
    * **`ServiceWorkerInstalledScriptsManager`:** This is the public interface. It initiates the script retrieval process by connecting to the `Internal` class on the IO thread. It also provides the `GetScriptData` and `GetRawScriptData` methods for accessing the stored scripts.

5. **Map to Web Technologies:** Connect the C++ code to higher-level web concepts:
    * **JavaScript:**  Service Workers are written in JavaScript. This manager is responsible for fetching the *code* of those JavaScript files.
    * **HTML:** HTML registers Service Workers using `<script>` tags with `type="module"`, or via JavaScript's `navigator.serviceWorker.register()`. While this file doesn't directly *parse* HTML, it manages the scripts registered *by* HTML pages.
    * **CSS:** Service Workers can intercept network requests, including CSS files. This manager handles fetching the JavaScript logic that would perform such interception. The metadata fetched might include HTTP headers, which are relevant to CSS caching.

6. **Trace the Data Flow:** Follow how script data is retrieved:
    1. The browser (not the code in this file) determines which Service Worker scripts are installed.
    2. The browser sends `ServiceWorkerScriptInfo` (via Mojo) to the `Internal` class.
    3. `Internal` uses `BundledReceivers` to download the script body and metadata via Mojo data pipes.
    4. The downloaded data is stored in the `script_container_`.
    5. When the Service Worker needs a script, it calls `GetScriptData` on `ServiceWorkerInstalledScriptsManager`.
    6. This might involve waiting (blocking the worker thread) for the script to be fully downloaded.
    7. The script data is then decoded and returned.

7. **Consider Logic and Assumptions:** Analyze the code for implicit assumptions and potential edge cases:
    * **Asynchronous nature:** The use of Mojo and task runners highlights the asynchronous nature of script retrieval.
    * **Error handling:** The `Receiver` class checks for errors during data pipe reads. The `WaitOnWorkerThread` function can fail.
    * **Data integrity:** The code checks if all data has been received.

8. **Identify Potential User/Programming Errors:** Think about how mistakes could lead to issues:
    * **Incorrect Service Worker registration:**  A typo in the registration URL in JavaScript/HTML would prevent the Service Worker from being associated correctly, but this file wouldn't directly be involved in *that* error.
    * **Network issues:** If the browser can't fetch the script initially, this manager won't have anything to manage. However, the *retry* mechanism (triggered by `GetRawScriptData` when the script is in the `kTaken` state) is relevant.
    * **Mojo communication failures:** Problems with the Mojo connection would prevent script data from being transferred.

9. **Simulate User Actions and Debugging:**  Imagine the steps a user would take and how a developer might debug issues:
    * **User action:** Navigating to a website with a registered Service Worker.
    * **Debugging:** Setting breakpoints in `GetScriptData`, `GetRawScriptData`, or within the `Internal` class to see when and how scripts are being fetched. Observing the Mojo message flow would also be crucial.

10. **Structure the Explanation:** Organize the findings into clear sections: Functionality, Relation to Web Technologies, Logic and Assumptions, User/Programming Errors, and User Actions/Debugging. Use clear and concise language, and provide concrete examples where possible.

11. **Refine and Review:** Read through the explanation to ensure accuracy, clarity, and completeness. Check for any logical inconsistencies or areas where more detail might be needed. For example, initially I might have overlooked the "retry" mechanism in `GetRawScriptData` when the status is `kTaken`, and I would then refine the explanation to include that.

This step-by-step process, moving from a high-level understanding to detailed analysis, and then back to a structured explanation, is crucial for effectively understanding and explaining complex code like this.
这个文件 `service_worker_installed_scripts_manager.cc` 是 Chromium Blink 引擎中负责管理已安装的 Service Worker 脚本的模块。它的主要功能是：

**核心功能：管理已安装 Service Worker 的脚本内容**

1. **接收已安装脚本的信息：** 当一个 Service Worker 被成功安装后，浏览器进程会将该 Service Worker 包含的脚本信息（包括脚本 URL、脚本内容、元数据等）通过 Mojo 接口传递给 Blink 渲染进程的这个管理器。

2. **存储脚本内容：**  该管理器使用 `ThreadSafeScriptContainer` 来安全地存储这些脚本的内容和元数据。`ThreadSafeScriptContainer` 允许在不同的线程（例如 IO 线程和 Worker 线程）安全地访问和操作这些数据。

3. **按需提供脚本内容：** 当 Service Worker 的 worker 线程需要执行某个已安装的脚本时，它会向该管理器请求该脚本的内容。管理器会从 `ThreadSafeScriptContainer` 中取出并提供。

4. **处理脚本内容的传输：**  脚本内容可能很大，因此通过 Mojo 数据管道进行传输。该管理器负责接收这些数据流，并将它们组合成完整的脚本内容。

**与 JavaScript, HTML, CSS 的关系：**

这个模块直接关系到 Service Worker 的核心功能，因此与 JavaScript 有着非常紧密的关系。

* **JavaScript：**
    * **功能体现：**  Service Worker 本身就是用 JavaScript 编写的。这个管理器负责获取和存储 Service Worker 的 JavaScript 代码。当浏览器需要执行 Service Worker 的生命周期事件（如 `install`, `activate`, `fetch` 等）或者处理消息时，它需要加载相应的 JavaScript 代码。
    * **举例说明：**  假设你的 Service Worker 的主脚本是 `sw.js`，当浏览器安装这个 Service Worker 时，浏览器会将 `sw.js` 的内容通过这个管理器传递给 Blink。当 Service Worker 启动并需要执行 `install` 事件中的代码时，Blink 会通过这个管理器获取 `sw.js` 的内容并执行。

* **HTML：**
    * **功能体现：** HTML 页面通过 `<script>` 标签或者 JavaScript 代码中的 `navigator.serviceWorker.register()` 方法来注册 Service Worker。虽然这个文件本身不直接处理 HTML，但它管理着由 HTML 注册的 Service Worker 的脚本。
    * **举例说明：**  如果你的 HTML 文件中包含 `<script>navigator.serviceWorker.register('/sw.js');</script>`，当浏览器加载这个 HTML 时，会触发 Service Worker 的注册。注册成功后，`/sw.js` 的内容会被这个管理器接收和管理。

* **CSS：**
    * **功能体现：** Service Worker 可以拦截网络请求，包括对 CSS 文件的请求，并进行自定义处理（例如缓存）。这个管理器负责管理 Service Worker 的 JavaScript 代码，而这些 JavaScript 代码可能会涉及到对 CSS 资源的拦截和处理。
    * **举例说明：**  你的 Service Worker 的 JavaScript 代码可能会包含类似这样的逻辑：
      ```javascript
      self.addEventListener('fetch', event => {
        if (event.request.url.endsWith('.css')) {
          // 自定义处理 CSS 请求
          event.respondWith(fetch('/cached-style.css'));
        }
      });
      ```
      为了执行这段 JavaScript 代码，Blink 需要通过 `ServiceWorkerInstalledScriptsManager` 获取 Service Worker 的脚本内容。

**逻辑推理 (假设输入与输出):**

**假设输入：**

1. **Service Worker 注册成功：** 浏览器成功注册了一个位于 `https://example.com/sw.js` 的 Service Worker。
2. **Mojo 消息：** 浏览器进程通过 Mojo 发送了一个 `ServiceWorkerScriptInfoPtr` 消息给 `Internal` 类，其中包含了以下信息：
    * `script_url`: `https://example.com/sw.js`
    * `meta_data`: 一个包含脚本元数据的 Mojo 数据管道句柄和大小。
    * `body`: 一个包含脚本内容的 Mojo 数据管道句柄和大小。
    * `encoding`: 脚本的编码 (例如 "utf-8")。
    * `headers`: 脚本的 HTTP 头部信息。

**逻辑推理过程：**

1. `Internal::TransferInstalledScript` 被调用，接收 `ServiceWorkerScriptInfoPtr`。
2. 创建 `BundledReceivers` 来处理 `meta_data` 和 `body` 两个数据管道的读取。
3. `BundledReceivers::Start` 启动数据管道的异步读取。
4. `Receiver::OnReadable` 被重复调用，直到所有数据都被从数据管道中读取出来。
5. 当 `meta_data` 和 `body` 的数据都接收完毕时，`Internal::OnScriptReceived` 被调用。
6. `Internal::OnScriptReceived` 从 `BundledReceivers` 中获取脚本内容和元数据。
7. 创建 `RawScriptData` 对象，存储脚本内容、元数据、编码和头部信息。
8. 调用 `script_container_->AddOnIOThread` 将 `RawScriptData` 存储起来，关联到 `https://example.com/sw.js`。

**可能输出：**

1. `ThreadSafeScriptContainer` 中会存储着 `https://example.com/sw.js` 的 `RawScriptData`，包含了脚本的字节流、元数据字节流、编码和头部信息。
2. 当 Service Worker 的 worker 线程请求 `https://example.com/sw.js` 的内容时，`ServiceWorkerInstalledScriptsManager::GetScriptData` 或 `ServiceWorkerInstalledScriptsManager::GetRawScriptData` 会返回存储在 `ThreadSafeScriptContainer` 中的相应数据。

**用户或编程常见的使用错误：**

1. **Service Worker 注册失败：** 如果 Service Worker 的注册过程失败（例如脚本 URL 不存在、网络错误、脚本内容解析错误等），那么这个管理器不会接收到该脚本的信息，后续也无法提供脚本内容。
    * **例子：** 用户在 HTML 中错误地将 Service Worker 的脚本路径写成 `navigator.serviceWorker.register('/sww.js');`，而服务器上没有 `sww.js` 文件。浏览器会尝试注册失败，这个管理器不会接收到任何关于 `sww.js` 的信息。

2. **Mojo 通信错误：** 如果浏览器进程和渲染进程之间的 Mojo 通信出现问题，导致 `ServiceWorkerScriptInfoPtr` 消息无法正确传递，或者数据管道读取失败，那么脚本内容也无法被正确接收。
    * **例子：**  这通常是内部错误，开发者不太容易直接触发。但如果 Chromium 内部的 Mojo 基础设施出现问题，可能会导致脚本加载失败。

3. **Service Worker 脚本内容错误：** 即使脚本被成功接收，如果脚本本身包含语法错误或者逻辑错误，Service Worker 的执行仍然会失败。但这与本文件关系不大，本文件只负责获取和存储脚本内容。

**用户操作如何一步步到达这里 (作为调试线索)：**

1. **用户访问一个网页：** 用户在浏览器中输入一个 URL 或者点击一个链接，导航到一个包含 Service Worker 注册代码的网页。
2. **浏览器解析 HTML：** 浏览器开始解析下载的 HTML 内容。
3. **发现 Service Worker 注册：** 浏览器在解析 HTML 或执行 JavaScript 时，遇到 `navigator.serviceWorker.register()` 调用。
4. **浏览器发起 Service Worker 注册请求：** 浏览器向网络发起请求，下载 Service Worker 的脚本文件（例如 `sw.js`）。
5. **脚本下载成功：** Service Worker 的脚本文件下载成功。
6. **浏览器准备安装 Service Worker：** 浏览器开始准备安装新的 Service Worker。
7. **浏览器进程通知 Blink 进程：** 浏览器进程通过 Mojo 接口向 Blink 渲染进程发送消息，告知需要安装的 Service Worker 的脚本信息，并传递脚本内容和元数据的数据管道句柄。
8. **`Internal::TransferInstalledScript` 被调用：** 在 Blink 渲染进程中，`service_worker_installed_scripts_manager.cc` 中的 `Internal::TransferInstalledScript` 方法接收到这个消息。
9. **脚本内容被接收和存储：** `Internal` 类开始从数据管道中读取脚本内容和元数据，并存储到 `ThreadSafeScriptContainer` 中。
10. **Service Worker 安装完成：**  一旦脚本被成功接收和存储，Service Worker 的安装过程完成。

**调试线索：**

* **断点设置：** 在 `Internal::TransferInstalledScript` 和 `Internal::OnScriptReceived` 方法中设置断点，可以观察脚本信息是如何传递和处理的。
* **Mojo 日志：** 检查 Chromium 的 Mojo 日志，可以查看 `ServiceWorkerInstalledScriptsManager` 相关的消息传递是否正常。
* **网络请求：** 使用浏览器的开发者工具查看网络请求，确认 Service Worker 的脚本文件是否成功下载。
* **Service Worker 的状态：** 在浏览器的开发者工具的 "Application" -> "Service Workers" 面板中，可以查看 Service Worker 的状态，如果安装失败，可以提供一些错误信息。
* **`ThreadSafeScriptContainer` 状态：**  虽然直接查看 `ThreadSafeScriptContainer` 的状态比较困难，但可以通过观察后续对已安装脚本的请求（例如在 Service Worker 的 `fetch` 事件中）是否能成功获取脚本内容，来间接判断脚本是否被成功存储。

总而言之，`service_worker_installed_scripts_manager.cc` 是 Service Worker 机制中一个关键的组成部分，负责在 Blink 渲染进程中管理已安装的 Service Worker 的脚本内容，确保 Service Worker 能够在需要时获取到正确的代码进行执行。

### 提示词
```
这是目录为blink/renderer/modules/service_worker/service_worker_installed_scripts_manager.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/service_worker/service_worker_installed_scripts_manager.h"

#include <memory>
#include <utility>

#include "base/barrier_closure.h"
#include "base/containers/span.h"
#include "base/not_fatal_until.h"
#include "base/numerics/safe_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "base/threading/thread_checker.h"
#include "base/trace_event/trace_event.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/web/web_embedded_worker.h"
#include "third_party/blink/renderer/core/html/parser/text_resource_decoder.h"
#include "third_party/blink/renderer/modules/service_worker/service_worker_thread.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/traced_value.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_mojo.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"

namespace blink {

using RawScriptData = ThreadSafeScriptContainer::RawScriptData;

namespace {

// Receiver is a class to read a Mojo data pipe. Received data are stored in
// chunks. Lives on the IO thread. Receiver is owned by Internal via
// BundledReceivers. It is created to read the script body or metadata from a
// data pipe, and is destroyed when the read finishes.
class Receiver {
  DISALLOW_NEW();

 public:
  Receiver(mojo::ScopedDataPipeConsumerHandle handle,
           uint64_t total_bytes,
           scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : handle_(std::move(handle)),
        watcher_(FROM_HERE,
                 mojo::SimpleWatcher::ArmingPolicy::MANUAL,
                 std::move(task_runner)),
        remaining_bytes_(total_bytes) {
    data_.ReserveInitialCapacity(base::checked_cast<wtf_size_t>(total_bytes));
  }

  void Start(base::OnceClosure callback) {
    if (!handle_.is_valid()) {
      std::move(callback).Run();
      return;
    }
    callback_ = std::move(callback);
    // Unretained is safe because |watcher_| is owned by |this|.
    MojoResult rv = watcher_.Watch(
        handle_.get(), MOJO_HANDLE_SIGNAL_READABLE,
        WTF::BindRepeating(&Receiver::OnReadable, WTF::Unretained(this)));
    DCHECK_EQ(MOJO_RESULT_OK, rv);
    watcher_.ArmOrNotify();
  }

  void OnReadable(MojoResult) {
    // It isn't necessary to handle MojoResult here since BeginReadDataRaw()
    // returns an equivalent error.
    base::span<const uint8_t> buffer;
    MojoResult rv = handle_->BeginReadData(MOJO_READ_DATA_FLAG_NONE, buffer);
    switch (rv) {
      case MOJO_RESULT_BUSY:
      case MOJO_RESULT_INVALID_ARGUMENT:
        NOTREACHED();
      case MOJO_RESULT_FAILED_PRECONDITION:
        // Closed by peer.
        OnCompleted();
        return;
      case MOJO_RESULT_SHOULD_WAIT:
        watcher_.ArmOrNotify();
        return;
      case MOJO_RESULT_OK:
        break;
      default:
        // mojo::BeginReadDataRaw() should not return any other values.
        // Notify the error to the browser by resetting the handle even though
        // it's in the middle of data transfer.
        OnCompleted();
        return;
    }

    if (!buffer.empty()) {
      data_.AppendSpan(base::as_chars(buffer));
    }

    rv = handle_->EndReadData(buffer.size());
    DCHECK_EQ(rv, MOJO_RESULT_OK);
    CHECK_GE(remaining_bytes_, buffer.size());
    remaining_bytes_ -= buffer.size();
    watcher_.ArmOrNotify();
  }

  bool IsRunning() const { return handle_.is_valid(); }
  bool HasReceivedAllData() const { return remaining_bytes_ == 0; }

  Vector<uint8_t> TakeData() {
    DCHECK(!IsRunning());
    return std::move(data_);
  }

 private:
  void OnCompleted() {
    handle_.reset();
    watcher_.Cancel();
    if (!HasReceivedAllData())
      data_.clear();
    DCHECK(callback_);
    std::move(callback_).Run();
  }

  base::OnceClosure callback_;
  mojo::ScopedDataPipeConsumerHandle handle_;
  mojo::SimpleWatcher watcher_;

  Vector<uint8_t> data_;
  uint64_t remaining_bytes_;
};

// BundledReceivers is a helper class to wait for the end of reading body and
// meta data. Lives on the IO thread.
class BundledReceivers {
 public:
  BundledReceivers(mojo::ScopedDataPipeConsumerHandle meta_data_handle,
                   uint64_t meta_data_size,
                   mojo::ScopedDataPipeConsumerHandle body_handle,
                   uint64_t body_size,
                   scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : meta_data_(std::move(meta_data_handle), meta_data_size, task_runner),
        body_(std::move(body_handle), body_size, std::move(task_runner)) {}

  // Starts reading the pipes and invokes |callback| when both are finished.
  void Start(base::OnceClosure callback) {
    base::RepeatingClosure wait_all_closure =
        base::BarrierClosure(2, std::move(callback));
    meta_data_.Start(wait_all_closure);
    body_.Start(wait_all_closure);
  }

  Receiver* meta_data() { return &meta_data_; }
  Receiver* body() { return &body_; }

 private:
  Receiver meta_data_;
  Receiver body_;
};

// Internal lives on the IO thread. This receives
// mojom::blink::ServiceWorkerScriptInfo for all installed scripts and then
// starts reading the body and meta data from the browser. This instance will be
// kept alive as long as the Mojo's connection is established.
class Internal : public mojom::blink::ServiceWorkerInstalledScriptsManager {
 public:
  // Called on the IO thread.
  // Creates and binds a new Internal instance to |receiver|.
  static void Create(
      scoped_refptr<ThreadSafeScriptContainer> script_container,
      mojo::PendingReceiver<mojom::blink::ServiceWorkerInstalledScriptsManager>
          receiver,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
    mojo::MakeSelfOwnedReceiver(
        std::make_unique<Internal>(std::move(script_container),
                                   std::move(task_runner)),
        std::move(receiver));
  }

  Internal(scoped_refptr<ThreadSafeScriptContainer> script_container,
           scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : script_container_(std::move(script_container)),
        task_runner_(std::move(task_runner)) {}

  ~Internal() override {
    DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);
    // Wake up a waiting thread so it does not wait forever. If the script has
    // not been added yet, that means something went wrong. From here,
    // script_container_->Wait() will return false if the script hasn't been
    // added yet.
    script_container_->OnAllDataAddedOnIOThread();
  }

  // Implements mojom::blink::ServiceWorkerInstalledScriptsManager.
  // Called on the IO thread.
  void TransferInstalledScript(
      mojom::blink::ServiceWorkerScriptInfoPtr script_info) override {
    DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);
    KURL script_url(script_info->script_url);
    auto receivers = std::make_unique<BundledReceivers>(
        std::move(script_info->meta_data), script_info->meta_data_size,
        std::move(script_info->body), script_info->body_size, task_runner_);
    receivers->Start(WTF::BindOnce(&Internal::OnScriptReceived,
                                   weak_factory_.GetWeakPtr(),
                                   std::move(script_info)));
    DCHECK(!running_receivers_.Contains(script_url));
    running_receivers_.insert(script_url, std::move(receivers));
  }

  // Called on the IO thread.
  void OnScriptReceived(mojom::blink::ServiceWorkerScriptInfoPtr script_info) {
    DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);
    auto iter = running_receivers_.find(script_info->script_url);
    CHECK(iter != running_receivers_.end(), base::NotFatalUntil::M130);
    std::unique_ptr<BundledReceivers> receivers = std::move(iter->value);
    DCHECK(receivers);
    if (!receivers->body()->HasReceivedAllData() ||
        !receivers->meta_data()->HasReceivedAllData()) {
      script_container_->AddOnIOThread(script_info->script_url,
                                       nullptr /* data */);
      running_receivers_.erase(iter);
      return;
    }

    auto script_data = std::make_unique<RawScriptData>(
        script_info->encoding, receivers->body()->TakeData(),
        receivers->meta_data()->TakeData());
    for (const auto& entry : script_info->headers)
      script_data->AddHeader(entry.key, entry.value);
    script_container_->AddOnIOThread(script_info->script_url,
                                     std::move(script_data));
    running_receivers_.erase(iter);
  }

 private:
  THREAD_CHECKER(io_thread_checker_);
  HashMap<KURL, std::unique_ptr<BundledReceivers>> running_receivers_;
  scoped_refptr<ThreadSafeScriptContainer> script_container_;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  base::WeakPtrFactory<Internal> weak_factory_{this};
};

std::unique_ptr<TracedValue> UrlToTracedValue(const KURL& url) {
  auto value = std::make_unique<TracedValue>();
  value->SetString("url", url.GetString());
  return value;
}

}  // namespace

ServiceWorkerInstalledScriptsManager::ServiceWorkerInstalledScriptsManager(
    std::unique_ptr<WebServiceWorkerInstalledScriptsManagerParams>
        installed_scripts_manager_params,
    scoped_refptr<base::SingleThreadTaskRunner> io_task_runner)
    : script_container_(base::MakeRefCounted<ThreadSafeScriptContainer>()) {
  DCHECK(installed_scripts_manager_params);

  DCHECK(installed_scripts_manager_params->manager_receiver);
  auto manager_receiver =
      mojo::PendingReceiver<mojom::blink::ServiceWorkerInstalledScriptsManager>(
          std::move(installed_scripts_manager_params->manager_receiver));

  DCHECK(installed_scripts_manager_params->manager_host_remote);
  manager_host_ = mojo::SharedRemote<
      mojom::blink::ServiceWorkerInstalledScriptsManagerHost>(
      std::move(installed_scripts_manager_params->manager_host_remote));

  // Don't touch |installed_urls_| after this point. We're on the initiator
  // thread now, but |installed_urls_| will be accessed on the
  // worker thread later, so they should keep isolated from the current thread.
  for (const WebURL& url :
       installed_scripts_manager_params->installed_scripts_urls) {
    installed_urls_.insert(KURL(url));
  }

  PostCrossThreadTask(
      *io_task_runner, FROM_HERE,
      CrossThreadBindOnce(&Internal::Create, script_container_,
                          std::move(manager_receiver), io_task_runner));
}

bool ServiceWorkerInstalledScriptsManager::IsScriptInstalled(
    const KURL& script_url) const {
  return installed_urls_.Contains(script_url);
}

std::unique_ptr<InstalledScriptsManager::ScriptData>
ServiceWorkerInstalledScriptsManager::GetScriptData(const KURL& script_url) {
  DCHECK(!IsMainThread());
  TRACE_EVENT1("ServiceWorker",
               "ServiceWorkerInstalledScriptsManager::GetScriptData",
               "script_url", UrlToTracedValue(script_url));
  if (!IsScriptInstalled(script_url))
    return nullptr;

  // This blocks until the script is received from the browser.
  std::unique_ptr<RawScriptData> raw_script_data = GetRawScriptData(script_url);
  if (!raw_script_data)
    return nullptr;

  // This is from WorkerClassicScriptLoader::DidReceiveData.
  std::unique_ptr<TextResourceDecoder> decoder =
      std::make_unique<TextResourceDecoder>(TextResourceDecoderOptions(
          TextResourceDecoderOptions::kPlainTextContent,
          raw_script_data->Encoding().empty()
              ? UTF8Encoding()
              : WTF::TextEncoding(raw_script_data->Encoding())));

  Vector<uint8_t> source_text = raw_script_data->TakeScriptText();
  String decoded_source_text = decoder->Decode(base::span(source_text));

  // TODO(crbug.com/946676): Remove the unique_ptr<> wrapper around the Vector
  // as we can just use Vector::IsEmpty() to distinguish missing code cache.
  std::unique_ptr<Vector<uint8_t>> meta_data;
  Vector<uint8_t> meta_data_in = raw_script_data->TakeMetaData();
  if (meta_data_in.size() > 0)
    meta_data = std::make_unique<Vector<uint8_t>>(std::move(meta_data_in));

  return std::make_unique<InstalledScriptsManager::ScriptData>(
      script_url, decoded_source_text, std::move(meta_data),
      raw_script_data->TakeHeaders());
}

std::unique_ptr<RawScriptData>
ServiceWorkerInstalledScriptsManager::GetRawScriptData(const KURL& script_url) {
  ThreadSafeScriptContainer::ScriptStatus status =
      script_container_->GetStatusOnWorkerThread(script_url);
  // If the script has already been taken, request the browser to send the
  // script.
  if (status == ThreadSafeScriptContainer::ScriptStatus::kTaken) {
    script_container_->ResetOnWorkerThread(script_url);
    manager_host_->RequestInstalledScript(script_url);
    status = script_container_->GetStatusOnWorkerThread(script_url);
  }

  // If the script has not been received at this point, wait for arrival by
  // blocking the worker thread.
  if (status == ThreadSafeScriptContainer::ScriptStatus::kPending) {
    // Wait for arrival of the script.
    const bool success = script_container_->WaitOnWorkerThread(script_url);
    // It can fail due to an error on Mojo pipes.
    if (!success)
      return nullptr;
    status = script_container_->GetStatusOnWorkerThread(script_url);
    DCHECK_NE(ThreadSafeScriptContainer::ScriptStatus::kPending, status);
  }

  if (status == ThreadSafeScriptContainer::ScriptStatus::kFailed)
    return nullptr;
  DCHECK_EQ(ThreadSafeScriptContainer::ScriptStatus::kReceived, status);

  return script_container_->TakeOnWorkerThread(script_url);
}

}  // namespace blink
```