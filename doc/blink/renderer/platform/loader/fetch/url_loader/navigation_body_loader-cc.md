Response:
Let's break down the thought process for analyzing this C++ source code file.

1. **Identify the Core Functionality:** The filename `navigation_body_loader.cc` and the class name `NavigationBodyLoader` strongly suggest this code is responsible for loading the body of a navigation request within the Blink rendering engine. The inclusion of "fetch" and "URL loader" in the path reinforces its role in network data retrieval.

2. **Examine Key Includes:** The `#include` directives provide crucial context. Look for familiar terms:
    * `third_party/blink`:  This confirms we're in the Blink rendering engine.
    * `platform/loader/fetch`: Reinforces the loading and fetching aspects.
    * `url_loader`:  Indicates interaction with the Chromium URL loading system.
    * `javascript`, `html`, `css`: While not directly included, the file's purpose relates to fetching the resources that enable these technologies.
    * `mojom`: Indicates interfaces for inter-process communication (likely with the browser process).
    * `network/public`: Shows interaction with the Chromium networking stack.
    * `base/`:  Suggests use of Chromium base library utilities (e.g., threading, memory management).

3. **Analyze the Class Structure:** Focus on the `NavigationBodyLoader` class and its key methods:
    * **Constructor:** Takes arguments related to the response (head, body, endpoints), suggesting it's initialized after the initial response headers are received.
    * **`StartLoadingBody`:**  This seems to be the entry point for initiating the body loading process. It takes a `Client` interface, implying a callback mechanism.
    * **`StartLoadingBodyInBackground`:**  Indicates an off-thread processing mechanism for potentially heavy tasks like decoding.
    * **`OnReceive*` methods:** These methods (`OnReceiveEarlyHints`, `OnReceiveResponse`, `OnReceiveRedirect`, `OnComplete`) are typical for a `URLLoaderClient`, suggesting this class acts as a client for the network loading process. The comments "This has already happened in the browser process" are important clues about where certain stages of the navigation happen.
    * **`SetDefersLoading`:** This hints at a mechanism for pausing or resuming the loading process, possibly related to rendering or prioritization.
    * **`OnReadable`:**  This suggests a data pipe is being used, and this method is called when data is available.
    * **`ProcessOffThreadData`:**  Handles data processed on a background thread.
    * **`ReadFromDataPipe`:** Reads data from the data pipe on the main thread.
    * **`NotifyCompletionIfAppropriate`:**  Signals the completion of the loading process.

4. **Identify Key Helper Classes and Structures:**
    * **`OffThreadBodyReader`:**  Clearly responsible for reading and decoding the response body on a separate thread. Look for its interaction with `BodyTextDecoder`.
    * **`MainThreadBodyReader`:** Handles reading the body directly on the main thread (likely when background processing is disabled or not applicable).
    * **`DataChunk`:** Represents a unit of data processed by the `OffThreadBodyReader`, containing both decoded and encoded data.
    * **`HeapArrayOrSize`:**  An optimization for storing encoded data, potentially avoiding unnecessary copying in some scenarios.

5. **Trace the Data Flow:** Try to follow how data moves through the system:
    * Response body arrives as a `mojo::ScopedDataPipeConsumerHandle`.
    * Data is read from the pipe, either on the main thread or a background thread.
    * If off-threading is used, `BodyTextDecoder` decodes the data.
    * Decoded data is passed to the `Client` through callbacks.
    * The `Client` (likely a higher-level component in Blink) uses this data to construct the web page.

6. **Look for Connections to Web Technologies (JavaScript, HTML, CSS):** Although this file doesn't *directly* execute JavaScript, parse HTML, or interpret CSS, it's crucial for *fetching* the resources that contain this code. The decoded data it provides will be the raw HTML, CSS, or JavaScript that other Blink components then process.

7. **Consider Error Handling and Completion:**  Note how the code handles network errors (`net::ERR_FAILED`), completion status, and cancellation.

8. **Analyze Conditional Logic and Flags:**  Pay attention to features enabled by flags (like `kThreadedBodyLoader`) as they indicate different execution paths and functionalities.

9. **Infer Potential User Errors:** Think about scenarios where things might go wrong from a user or programmer perspective. Incorrect server configurations, network issues, or unexpected data formats are possibilities.

10. **Formulate Assumptions for Logic and Examples:** Based on the code's behavior, create simple scenarios to illustrate the input and output. Think about the different paths based on whether off-threading is enabled, whether there are redirects, etc.

11. **Structure the Explanation:** Organize the findings into clear sections like "Core Functionality," "Relationship to Web Technologies," "Logic and Examples," and "Potential Errors." Use bullet points and code snippets to make the explanation easier to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This just reads the response body."  **Correction:** Realize there's more to it, including off-thread processing, decoding, and coordination with other components.
* **Misunderstanding a flag:**  Initially misinterpret the purpose of a feature flag. **Correction:** Re-examine the code where the flag is used and adjust the understanding.
* **Overlooking a key method:**  Miss an important method like `SetDefersLoading`. **Correction:** Review the class structure and method calls to ensure all significant aspects are covered.
* **Unclear explanation:**  A particular point is not well-articulated. **Correction:** Rephrase the explanation, possibly adding a more concrete example.

By following these steps and continually refining the understanding, you can effectively analyze and explain the functionality of a complex source code file like this one.
这个文件是 Chromium Blink 引擎中的 `navigation_body_loader.cc`，它的核心功能是**负责加载导航请求的 HTTP 响应体数据**。  更具体地说，它处理从网络层接收到的响应体数据，并将其传递给 Blink 渲染引擎的后续处理阶段。

以下是它的详细功能分解：

**核心功能：**

1. **接收和管理响应体数据流：**
   - 它通过 `mojo::ScopedDataPipeConsumerHandle` 接收来自网络进程的 HTTP 响应体数据流。
   - 它使用 `mojo::SimpleWatcher` 监听数据管道的可读事件，以便在有新数据到达时进行处理。

2. **支持主线程和后台线程的响应体读取：**
   - 为了避免阻塞主线程，它实现了将响应体读取和解码操作放在后台线程执行的机制 (`OffThreadBodyReader`)。
   - 同时，它也支持在主线程直接读取响应体数据 (`MainThreadBodyReader`)，这可能用于某些特殊情况或配置。

3. **字符编码解码：**
   - 它集成了 `BodyTextDecoder`，负责根据响应头的 `Content-Type` 中指定的字符编码（或通过自动检测）对响应体数据进行解码。

4. **数据分块处理：**
   - 它能够将接收到的数据分成多个块进行处理，这有助于提高性能和响应速度，尤其是在处理大型响应体时。
   - 可以配置每次任务处理的最大数据量 (`GetMaxDataToProcessPerTask`)。

5. **提供解码后的数据给客户端：**
   - 它通过 `WebNavigationBodyLoader::Client` 接口，将解码后的响应体数据 (`DecodedBodyDataReceived`) 和原始编码数据 (`BodyDataReceived`) 传递给 Blink 渲染引擎的其他部分进行进一步处理（例如 HTML 解析器、JavaScript 引擎）。

6. **处理加载完成和错误：**
   - 它监听网络加载的完成事件 (`OnComplete`)，并处理加载成功或失败的情况。
   - 如果加载过程中发生错误，它会将错误信息传递给客户端。

7. **支持加载延迟（Freezing）：**
   - 它实现了 `SetDefersLoading` 方法，允许在某些情况下暂停或恢复响应体的加载，这可能用于优化渲染优先级或处理资源加载依赖关系。

8. **与 Preload Scanner 集成（可选）：**
   - 通过 `ShouldSendDirectlyToPreloadScanner` 特性，它可以选择将响应体数据直接发送到预加载扫描器，以提前发现资源。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`NavigationBodyLoader` 本身不直接解析或执行 JavaScript、HTML 或 CSS，但它是获取这些资源的关键环节。它负责将网络上的原始字节流转换为可供 Blink 处理的数据。

* **HTML:**
    - **功能关系：** 当用户导航到一个新的网页时，`NavigationBodyLoader` 负责下载 HTML 响应体。解码后的 HTML 数据会被传递给 HTML 解析器，构建 DOM 树。
    - **举例：**  假设用户访问 `https://example.com/index.html`。`NavigationBodyLoader` 会下载 `index.html` 的内容，例如：
      ```html
      <!DOCTYPE html>
      <html>
      <head>
          <title>Example Page</title>
          <link rel="stylesheet" href="style.css">
      </head>
      <body>
          <h1>Hello, world!</h1>
          <script src="script.js"></script>
      </body>
      </html>
      ```
      `NavigationBodyLoader` 会解码这段 HTML，并将其传递给 HTML 解析器。

* **CSS:**
    - **功能关系：** 当 HTML 解析器遇到 `<link rel="stylesheet" href="style.css">` 这样的标签时，会触发加载 `style.css` 的请求。另一个 `NavigationBodyLoader` 实例（或类似的机制）会负责下载 `style.css` 的响应体。
    - **举例：**  `NavigationBodyLoader` 下载的 `style.css` 内容可能是：
      ```css
      h1 {
          color: blue;
      }
      ```
      解码后的 CSS 数据会被传递给 CSS 解析器，构建 CSSOM 树。

* **JavaScript:**
    - **功能关系：** 当 HTML 解析器遇到 `<script src="script.js"></script>` 这样的标签时，会触发加载 `script.js` 的请求。`NavigationBodyLoader` 会负责下载 `script.js` 的响应体。
    - **举例：** `NavigationBodyLoader` 下载的 `script.js` 内容可能是：
      ```javascript
      console.log("Page loaded!");
      ```
      解码后的 JavaScript 代码会被传递给 JavaScript 引擎进行解析和执行.

**逻辑推理及假设输入与输出：**

假设场景：用户导航到 `https://example.com/data.txt`，服务器返回以下响应：

```
HTTP/1.1 200 OK
Content-Type: text/plain; charset=UTF-8
Content-Length: 13

Hello, 世界!
```

**假设输入：**

- `response_head`: 包含 `Content-Type: text/plain; charset=UTF-8` 和 `Content-Length: 13` 等信息的 `network::mojom::URLResponseHeadPtr`。
- `response_body`: 一个 `mojo::ScopedDataPipeConsumerHandle`，其中包含编码后的字节流 `0x48 0x65 0x6c 0x6c 0x6f 0x2c 0x20 0xe4 0xb8 0x96 0xe7 0x界 0x21` (对应 "Hello, 世界!")。

**逻辑推理：**

1. `NavigationBodyLoader` 接收到 `response_head`，从中提取字符编码信息（UTF-8）。
2. 它开始从 `response_body` 对应的数据管道中读取字节流。
3. 如果启用了后台线程解码 (`kThreadedBodyLoader` 特性为 true)，`OffThreadBodyReader` 会在后台线程读取数据。
4. `BodyTextDecoder` 使用 UTF-8 编码解码字节流。
5. `NavigationBodyLoader` 通过 `client_->DecodedBodyDataReceived()` 将解码后的字符串 "Hello, 世界!" 传递给客户端。

**假设输出：**

- 调用 `client_->DecodedBodyDataReceived("Hello, 世界!", encoding_data, encoded_data_span)`，其中 `encoding_data` 包含 UTF-8 信息，`encoded_data_span` 指向原始的字节流。

**用户或编程常见的使用错误及举例说明：**

1. **服务器返回错误的字符编码信息：**
   - **错误：**  服务器的 `Content-Type` 声明为 `charset=ISO-8859-1`，但实际响应体使用了 UTF-8 编码。
   - **结果：** `BodyTextDecoder` 会使用 ISO-8859-1 错误地解码 UTF-8 字节，导致页面上出现乱码。

2. **客户端没有正确处理接收到的数据：**
   - **错误：** `WebNavigationBodyLoader::Client` 的实现没有正确地处理 `DecodedBodyDataReceived` 或 `BodyDataReceived` 中接收到的数据，例如，没有将数据添加到内部缓冲区或进行必要的转换。
   - **结果：** 页面内容可能无法完整加载或显示不正确。

3. **过早地取消加载：**
   - **错误：** 在 `NavigationBodyLoader` 完成接收所有数据之前，Blink 的其他部分（例如页面导航被中断）取消了加载。
   - **结果：**  `NavigationBodyLoader` 会调用 `resource_load_info_notifier_wrapper_->NotifyResourceLoadCanceled(net::ERR_ABORTED)`，指示加载被中止，可能导致页面加载不完整。

4. **在后台线程解码时访问主线程资源（如果在 `OffThreadBodyReader` 中直接进行）：**
   - **错误：**  虽然代码设计上避免了这个问题，但如果错误地在 `OffThreadBodyReader` 的后台线程中尝试直接操作 DOM 或访问只能在主线程访问的对象。
   - **结果：**  会导致崩溃或未定义的行为。 这也是为什么 `OffThreadBodyReader` 通过 `PostCrossThreadTask` 将解码后的数据传递回主线程处理。

总之，`navigation_body_loader.cc` 是 Blink 引擎中负责高效、可靠地获取和初步处理 HTTP 响应体数据的关键组件，它为后续的 HTML 解析、CSS 解析和 JavaScript 执行等步骤提供了必要的数据基础。

### 提示词
```
这是目录为blink/renderer/platform/loader/fetch/url_loader/navigation_body_loader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/url_loader/navigation_body_loader.h"

#include <algorithm>
#include <utility>

#include "base/containers/heap_array.h"
#include "base/containers/span.h"
#include "base/functional/bind.h"
#include "base/memory/raw_ptr.h"
#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram_functions.h"
#include "base/numerics/safe_conversions.h"
#include "base/run_loop.h"
#include "base/strings/strcat.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/trace_event/trace_event.h"
#include "mojo/public/cpp/base/big_buffer.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/cpp/record_ontransfersizeupdate_utils.h"
#include "services/network/public/cpp/url_loader_completion_status.h"
#include "services/network/public/mojom/early_hints.mojom.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/loader/referrer_utils.h"
#include "third_party/blink/public/mojom/loader/code_cache.mojom-blink.h"
#include "third_party/blink/public/mojom/navigation/navigation_params.mojom.h"
#include "third_party/blink/public/platform/resource_load_info_notifier_wrapper.h"
#include "third_party/blink/public/platform/web_url_error.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/public/web/web_navigation_params.h"
#include "third_party/blink/renderer/platform/loader/fetch/body_text_decoder.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/worker_pool.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"
#include "third_party/ced/src/compact_enc_det/compact_enc_det.h"

namespace blink {
namespace {

bool ShouldSendDirectlyToPreloadScanner() {
  static const base::FeatureParam<bool> kSendToScannerParam{
      &features::kThreadedBodyLoader, "send-to-scanner", true};
  return kSendToScannerParam.Get();
}

// Returns the maximum data size to process in TakeData(). Returning 0 means
// process all the data available.
size_t GetMaxDataToProcessPerTask() {
  static const base::FeatureParam<int> kMaxDataToProcessParam{
      &features::kThreadedBodyLoader, "max-data-to-process", 0};
  return kMaxDataToProcessParam.Get();
}

// Either 1) owns the original, encoded data (if
// `should_keep_encoded_data` was passed to `StartLoadingBodyInBackground()`)
// or, or 2) just stores the data size (if `!should_keep_encoded_data`).
class HeapArrayOrSize {
 public:
  HeapArrayOrSize(base::span<const char> data, bool should_keep_encoded_data)
      : heap_array_or_size_(should_keep_encoded_data
                                ? std::variant<base::HeapArray<char>, size_t>(
                                      base::HeapArray<char>::CopiedFrom(data))
                                : data.size()) {}

  ~HeapArrayOrSize() = default;

  HeapArrayOrSize(const HeapArrayOrSize&) = delete;
  HeapArrayOrSize& operator=(const HeapArrayOrSize&) = delete;
  HeapArrayOrSize(HeapArrayOrSize&&) = default;
  HeapArrayOrSize& operator=(HeapArrayOrSize&&) = default;

  base::SpanOrSize<const char> AsSpanOrSize() const {
    return std::visit(
        [](const auto& value) { return base::SpanOrSize<const char>(value); },
        heap_array_or_size_);
  }

  size_t size() const { return AsSpanOrSize().size(); }

 private:
  std::variant<base::HeapArray<char>, size_t> heap_array_or_size_;
};

// A chunk of data read by the OffThreadBodyReader. This will be created on a
// background thread and processed on the main thread.
struct DataChunk {
  String decoded_data;
  bool has_seen_end_of_data = false;
  bool has_error = false;
  HeapArrayOrSize encoded_data;
  WebEncodingData encoding_data;
};

// This interface abstracts out the logic for consuming the response body and
// allows calling ReadFromDataPipeImpl() on either the main thread or a
// background thread.
class BodyReader {
 public:
  virtual ~BodyReader() = default;
  virtual bool ShouldContinueReading() = 0;
  virtual void FinishedReading(bool has_error) = 0;
  virtual bool DataReceived(base::span<const char> data) = 0;
};

void ReadFromDataPipeImpl(BodyReader& reader,
                          mojo::ScopedDataPipeConsumerHandle& handle,
                          mojo::SimpleWatcher& handle_watcher) {
  size_t num_bytes_consumed = 0;
  while (reader.ShouldContinueReading()) {
    base::span<const uint8_t> buffer;
    MojoResult result = handle->BeginReadData(MOJO_READ_DATA_FLAG_NONE, buffer);
    if (result == MOJO_RESULT_SHOULD_WAIT) {
      handle_watcher.ArmOrNotify();
      return;
    }
    if (result == MOJO_RESULT_FAILED_PRECONDITION) {
      reader.FinishedReading(/*has_error=*/false);
      return;
    }
    if (result != MOJO_RESULT_OK) {
      reader.FinishedReading(/*has_error=*/true);
      return;
    }
    const size_t chunk_size = network::features::kMaxNumConsumedBytesInTask;
    DCHECK_LE(num_bytes_consumed, chunk_size);
    buffer = buffer.first(
        std::min<size_t>(buffer.size(), chunk_size - num_bytes_consumed));
    if (buffer.empty()) {
      // We've already consumed many bytes in this task. Defer the remaining
      // to the next task.
      result = handle->EndReadData(0);
      DCHECK_EQ(result, MOJO_RESULT_OK);
      handle_watcher.ArmOrNotify();
      return;
    }
    num_bytes_consumed += buffer.size();
    if (!reader.DataReceived(base::as_chars(buffer))) {
      return;
    }
    result = handle->EndReadData(buffer.size());
    DCHECK_EQ(MOJO_RESULT_OK, result);
  }
}

}  // namespace

class NavigationBodyLoader::OffThreadBodyReader : public BodyReader {
 public:
  OffThreadBodyReader(
      mojo::ScopedDataPipeConsumerHandle response_body,
      std::unique_ptr<BodyTextDecoder> decoder,
      base::WeakPtr<NavigationBodyLoader> body_loader,
      scoped_refptr<base::SingleThreadTaskRunner> main_thread_task_runner,
      scoped_refptr<base::SequencedTaskRunner> reader_task_runner,
      bool should_keep_encoded_data)
      : response_body_(std::move(response_body)),
        decoder_(std::move(decoder)),
        should_keep_encoded_data_(should_keep_encoded_data),
        main_thread_task_runner_(std::move(main_thread_task_runner)),
        reader_task_runner_(std::move(reader_task_runner)),
        body_loader_(std::move(body_loader)) {
    DCHECK(IsMainThread());
    PostCrossThreadTask(
        *reader_task_runner_, FROM_HERE,
        CrossThreadBindOnce(&OffThreadBodyReader::StartInBackground,
                            CrossThreadUnretained(this)));
  }

  ~OffThreadBodyReader() override {
    DCHECK(reader_task_runner_->RunsTasksInCurrentSequence());
  }

  Vector<DataChunk> TakeData(size_t max_data_to_process) {
    DCHECK(IsMainThread());
    base::AutoLock lock(lock_);
    if (max_data_to_process == 0)
      return std::move(data_chunks_);

    Vector<DataChunk> data;
    size_t data_processed = 0;
    while (!data_chunks_.empty() && data_processed < max_data_to_process) {
      data.emplace_back(std::move(data_chunks_.front()));
      data_processed += data.back().encoded_data.size();
      data_chunks_.erase(data_chunks_.begin());
    }
    if (!data_chunks_.empty()) {
      PostCrossThreadTask(
          *main_thread_task_runner_, FROM_HERE,
          CrossThreadBindOnce(&NavigationBodyLoader::ProcessOffThreadData,
                              body_loader_));
    }
    return data;
  }

  void StoreProcessBackgroundDataCallback(Client* client) {
    DCHECK(IsMainThread());
    if (background_callback_set_)
      return;

    auto callback = client->TakeProcessBackgroundDataCallback();
    if (!callback)
      return;

    background_callback_set_ = true;

    base::AutoLock lock(lock_);
    process_background_data_callback_ = std::move(callback);

    // Process any existing data to make sure we don't miss any.
    for (const auto& chunk : data_chunks_)
      process_background_data_callback_.Run(chunk.decoded_data);
  }

  void Delete() const {
    DCHECK(IsMainThread());
    reader_task_runner_->DeleteSoon(FROM_HERE, this);
  }

  void FlushForTesting() {
    base::RunLoop run_loop;
    reader_task_runner_->PostTask(FROM_HERE, run_loop.QuitClosure());
    run_loop.Run();
  }

 private:
  // BodyReader:
  bool ShouldContinueReading() override {
    // It's fine to keep reading unconditionally here because the main thread
    // will wait to process the data if loading is deferred.
    return true;
  }

  void FinishedReading(bool has_error) override {
    has_seen_end_of_data_ = true;
    AddChunk(decoder_->Flush(), base::span<const char>(), has_error);
  }

  bool DataReceived(base::span<const char> data) override {
    AddChunk(decoder_->Decode(data), data, /*has_error=*/false);
    return true;
  }

  void StartInBackground() {
    TRACE_EVENT0("loading", "OffThreadBodyReader::StartInBackground");
    DCHECK(reader_task_runner_->RunsTasksInCurrentSequence());
    response_body_watcher_ = std::make_unique<mojo::SimpleWatcher>(
        FROM_HERE, mojo::SimpleWatcher::ArmingPolicy::MANUAL);
    response_body_watcher_->Watch(
        response_body_.get(), MOJO_HANDLE_SIGNAL_READABLE,
        base::BindRepeating(&OffThreadBodyReader::ReadFromDataPipe,
                            base::Unretained(this)));
    ReadFromDataPipe(MOJO_RESULT_OK);
  }

  void ReadFromDataPipe(MojoResult unused) {
    TRACE_EVENT0("loading", "OffThreadBodyReader::ReadFromDataPipe");
    ReadFromDataPipeImpl(*this, response_body_, *response_body_watcher_);
  }

  void AddChunk(const String& decoded_data,
                base::span<const char> encoded_data,
                bool has_error) {
    DCHECK(reader_task_runner_->RunsTasksInCurrentSequence());
    HeapArrayOrSize encoded_data_or_size(encoded_data,
                                         should_keep_encoded_data_);

    bool post_task = false;
    {
      base::AutoLock lock(lock_);
      if (decoded_data && process_background_data_callback_)
        process_background_data_callback_.Run(decoded_data);

      // If |data_chunks_| is not empty, there is already a task posted which
      // will consume the data, so no need to post another one.
      post_task = data_chunks_.empty();
      data_chunks_.push_back(
          DataChunk{.decoded_data = decoded_data,
                    .has_seen_end_of_data = has_seen_end_of_data_,
                    .has_error = has_error,
                    .encoded_data = std::move(encoded_data_or_size),
                    .encoding_data = decoder_->GetEncodingData()});
    }
    if (post_task) {
      PostCrossThreadTask(
          *main_thread_task_runner_, FROM_HERE,
          CrossThreadBindOnce(&NavigationBodyLoader::ProcessOffThreadData,
                              body_loader_));
    }
  }

  mojo::ScopedDataPipeConsumerHandle response_body_;
  std::unique_ptr<mojo::SimpleWatcher> response_body_watcher_;
  std::unique_ptr<BodyTextDecoder> decoder_;
  bool should_keep_encoded_data_;
  scoped_refptr<base::SingleThreadTaskRunner> main_thread_task_runner_;
  scoped_refptr<base::SequencedTaskRunner> reader_task_runner_;
  base::WeakPtr<NavigationBodyLoader> body_loader_;
  bool has_seen_end_of_data_ = false;

  base::Lock lock_;
  // This bool is used on the main thread to avoid locking when the callback has
  // already been set.
  bool background_callback_set_ = false;
  Client::ProcessBackgroundDataCallback process_background_data_callback_
      GUARDED_BY(lock_);
  Vector<DataChunk> data_chunks_ GUARDED_BY(lock_);
};

void NavigationBodyLoader::OffThreadBodyReaderDeleter::operator()(
    const OffThreadBodyReader* ptr) {
  if (ptr)
    ptr->Delete();
}

class NavigationBodyLoader::MainThreadBodyReader : public BodyReader {
 public:
  explicit MainThreadBodyReader(NavigationBodyLoader* loader)
      : loader_(loader) {}

  bool ShouldContinueReading() override {
    return loader_->freeze_mode_ == WebLoaderFreezeMode::kNone;
  }

  void FinishedReading(bool has_error) override {
    loader_->has_seen_end_of_data_ = true;
    if (has_error) {
      loader_->status_.error_code = net::ERR_FAILED;
      loader_->has_received_completion_ = true;
    }
    loader_->NotifyCompletionIfAppropriate();
  }

  bool DataReceived(base::span<const char> data) override {
    base::WeakPtr<NavigationBodyLoader> weak_self =
        loader_->weak_factory_.GetWeakPtr();
    loader_->client_->BodyDataReceived(data);
    return weak_self.get();
  }

 private:
  raw_ptr<NavigationBodyLoader, DanglingUntriaged> loader_;
};

NavigationBodyLoader::NavigationBodyLoader(
    const KURL& original_url,
    network::mojom::URLResponseHeadPtr response_head,
    mojo::ScopedDataPipeConsumerHandle response_body,
    network::mojom::URLLoaderClientEndpointsPtr endpoints,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    std::unique_ptr<ResourceLoadInfoNotifierWrapper>
        resource_load_info_notifier_wrapper)
    : response_head_(std::move(response_head)),
      response_body_(std::move(response_body)),
      endpoints_(std::move(endpoints)),
      task_runner_(std::move(task_runner)),
      handle_watcher_(FROM_HERE,
                      mojo::SimpleWatcher::ArmingPolicy::MANUAL,
                      task_runner_),
      resource_load_info_notifier_wrapper_(
          std::move(resource_load_info_notifier_wrapper)),
      original_url_(original_url),
      should_send_directly_to_preload_scanner_(
          ShouldSendDirectlyToPreloadScanner()),
      max_data_to_process_per_task_(GetMaxDataToProcessPerTask()) {}

NavigationBodyLoader::~NavigationBodyLoader() {
  if (!has_received_completion_ || !has_seen_end_of_data_) {
    resource_load_info_notifier_wrapper_->NotifyResourceLoadCanceled(
        net::ERR_ABORTED);
  }
}

void NavigationBodyLoader::OnReceiveEarlyHints(
    network::mojom::EarlyHintsPtr early_hints) {
  // This has already happened in the browser process.
  NOTREACHED();
}

void NavigationBodyLoader::OnReceiveResponse(
    network::mojom::URLResponseHeadPtr head,
    mojo::ScopedDataPipeConsumerHandle body,
    std::optional<mojo_base::BigBuffer> cached_metadata) {
  // This has already happened in the browser process.
  NOTREACHED();
}

void NavigationBodyLoader::OnReceiveRedirect(
    const net::RedirectInfo& redirect_info,
    network::mojom::URLResponseHeadPtr head) {
  // This has already happened in the browser process.
  NOTREACHED();
}

void NavigationBodyLoader::OnUploadProgress(int64_t current_position,
                                            int64_t total_size,
                                            OnUploadProgressCallback callback) {
  // This has already happened in the browser process.
  NOTREACHED();
}

void NavigationBodyLoader::OnTransferSizeUpdated(int32_t transfer_size_diff) {
  network::RecordOnTransferSizeUpdatedUMA(
      network::OnTransferSizeUpdatedFrom::kNavigationBodyLoader);
  resource_load_info_notifier_wrapper_->NotifyResourceTransferSizeUpdated(
      transfer_size_diff);
}

void NavigationBodyLoader::OnComplete(
    const network::URLLoaderCompletionStatus& status) {
  // Except for errors, there must always be a response's body.
  DCHECK(has_received_body_handle_ || status.error_code != net::OK);
  has_received_completion_ = true;
  status_ = status;
  NotifyCompletionIfAppropriate();
}

void NavigationBodyLoader::SetDefersLoading(WebLoaderFreezeMode mode) {
  if (freeze_mode_ == mode)
    return;
  freeze_mode_ = mode;
  if (handle_.is_valid())
    OnReadable(MOJO_RESULT_OK);
  else if (off_thread_body_reader_)
    ProcessOffThreadData();
}

void NavigationBodyLoader::StartLoadingBody(
    WebNavigationBodyLoader::Client* client) {
  TRACE_EVENT1("loading", "NavigationBodyLoader::StartLoadingBody", "url",
               original_url_.GetString().Utf8());
  client_ = client;

  resource_load_info_notifier_wrapper_->NotifyResourceResponseReceived(
      std::move(response_head_));
  base::WeakPtr<NavigationBodyLoader> weak_self = weak_factory_.GetWeakPtr();
  NotifyCompletionIfAppropriate();
  if (!weak_self)
    return;

  // TODO(dgozman): we should explore retrieveing code cache in parallel with
  // receiving response or reading the first data chunk.
  BindURLLoaderAndStartLoadingResponseBodyIfPossible();
}

void NavigationBodyLoader::StartLoadingBodyInBackground(
    std::unique_ptr<BodyTextDecoder> decoder,
    bool should_keep_encoded_data) {
  if (!response_body_)
    return;

  // Initializing the map used when detecting encodings is not thread safe.
  // Initialize on the main thread here to avoid races.
  // TODO(crbug.com/1384221): Consider making the map thread safe in
  // third_party/ced/src/util/encodings/encodings.cc.
  EncodingNameAliasToEncoding("");

  off_thread_body_reader_.reset(new OffThreadBodyReader(
      std::move(response_body_), std::move(decoder), weak_factory_.GetWeakPtr(),
      task_runner_, worker_pool::CreateSequencedTaskRunner({}),
      should_keep_encoded_data));
}

void NavigationBodyLoader::FlushOffThreadBodyReaderForTesting() {
  if (!off_thread_body_reader_)
    return;
  off_thread_body_reader_->FlushForTesting();
}

void NavigationBodyLoader::BindURLLoaderAndContinue() {
  url_loader_.Bind(std::move(endpoints_->url_loader), task_runner_);
  url_loader_client_receiver_.Bind(std::move(endpoints_->url_loader_client),
                                   task_runner_);
  url_loader_client_receiver_.set_disconnect_handler(base::BindOnce(
      &NavigationBodyLoader::OnConnectionClosed, base::Unretained(this)));
}

void NavigationBodyLoader::OnConnectionClosed() {
  // If the connection aborts before the load completes, mark it as failed.
  if (!has_received_completion_)
    OnComplete(network::URLLoaderCompletionStatus(net::ERR_FAILED));
}

void NavigationBodyLoader::OnReadable(MojoResult unused) {
  TRACE_EVENT1("loading", "NavigationBodyLoader::OnReadable", "url",
               original_url_.GetString().Utf8());
  if (has_seen_end_of_data_ || freeze_mode_ != WebLoaderFreezeMode::kNone ||
      is_in_on_readable_)
    return;
  // Protect against reentrancy:
  // - when the client calls SetDefersLoading;
  // - when nested message loop starts from BodyDataReceived
  //   and we get notified by the watcher.
  // Note: we cannot use AutoReset here since |this| may be deleted
  // before reset.
  is_in_on_readable_ = true;
  base::WeakPtr<NavigationBodyLoader> weak_self = weak_factory_.GetWeakPtr();
  ReadFromDataPipe();
  if (!weak_self)
    return;
  is_in_on_readable_ = false;
}

void NavigationBodyLoader::ProcessOffThreadData() {
  if (has_seen_end_of_data_ || freeze_mode_ != WebLoaderFreezeMode::kNone ||
      !client_) {
    return;
  }

  Vector<DataChunk> chunks =
      off_thread_body_reader_->TakeData(max_data_to_process_per_task_);
  auto weak_self = weak_factory_.GetWeakPtr();
  for (const DataChunk& chunk : chunks) {
    client_->DecodedBodyDataReceived(chunk.decoded_data, chunk.encoding_data,
                                     chunk.encoded_data.AsSpanOrSize());
    if (!weak_self)
      return;

    if (chunk.has_seen_end_of_data)
      has_seen_end_of_data_ = true;

    if (chunk.has_error) {
      status_.error_code = net::ERR_FAILED;
      has_received_completion_ = true;
      break;
    }
  }
  if (weak_self && should_send_directly_to_preload_scanner_)
    off_thread_body_reader_->StoreProcessBackgroundDataCallback(client_);

  NotifyCompletionIfAppropriate();
}

void NavigationBodyLoader::ReadFromDataPipe() {
  TRACE_EVENT1("loading", "NavigationBodyLoader::ReadFromDataPipe", "url",
               original_url_.GetString().Utf8());
  DCHECK(!off_thread_body_reader_);
  MainThreadBodyReader reader(this);
  ReadFromDataPipeImpl(reader, handle_, handle_watcher_);
}

void NavigationBodyLoader::NotifyCompletionIfAppropriate() {
  if (!has_received_completion_ || !has_seen_end_of_data_)
    return;

  handle_watcher_.Cancel();

  std::optional<WebURLError> error;
  if (status_.error_code != net::OK) {
    error = WebURLError::Create(status_, original_url_);
  }

  resource_load_info_notifier_wrapper_->NotifyResourceLoadCompleted(status_);

  if (!client_)
    return;

  // |this| may be deleted after calling into client_, so clear it in advance.
  WebNavigationBodyLoader::Client* client = client_;
  client_ = nullptr;
  client->BodyLoadingFinished(
      status_.completion_time, status_.encoded_data_length,
      status_.encoded_body_length, status_.decoded_body_length, error);
}

void NavigationBodyLoader::
    BindURLLoaderAndStartLoadingResponseBodyIfPossible() {
  if (!response_body_ && !off_thread_body_reader_)
    return;
  // Bind the mojo::URLLoaderClient interface in advance, because we will start
  // to read from the data pipe immediately which may potentially postpone the
  // method calls from the remote. That causes the flakiness of some layout
  // tests.
  // TODO(minggang): The binding was executed after OnReceiveResponse
  // originally (prior to passing the response body from the browser process
  // during navigation), we should try to put it back if all the
  // webkit_layout_tests can pass in that way.
  BindURLLoaderAndContinue();

  DCHECK(!has_received_body_handle_);
  has_received_body_handle_ = true;

  if (off_thread_body_reader_) {
    ProcessOffThreadData();
    return;
  }

  DCHECK(response_body_.is_valid());

  DCHECK(!has_received_completion_);
  handle_ = std::move(response_body_);
  DCHECK(handle_.is_valid());
  handle_watcher_.Watch(handle_.get(), MOJO_HANDLE_SIGNAL_READABLE,
                        base::BindRepeating(&NavigationBodyLoader::OnReadable,
                                            base::Unretained(this)));
  OnReadable(MOJO_RESULT_OK);
  // Don't use |this| here as it might have been destroyed.
}

// static
void WebNavigationBodyLoader::FillNavigationParamsResponseAndBodyLoader(
    mojom::CommonNavigationParamsPtr common_params,
    mojom::CommitNavigationParamsPtr commit_params,
    int request_id,
    network::mojom::URLResponseHeadPtr response_head,
    mojo::ScopedDataPipeConsumerHandle response_body,
    network::mojom::URLLoaderClientEndpointsPtr url_loader_client_endpoints,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    std::unique_ptr<ResourceLoadInfoNotifierWrapper>
        resource_load_info_notifier_wrapper,
    bool is_main_frame,
    WebNavigationParams* navigation_params,
    bool is_ad_frame) {
  // Use the original navigation url to start with. We'll replay the
  // redirects afterwards and will eventually arrive to the final url.
  const KURL original_url = !commit_params->original_url.is_empty()
                                ? KURL(commit_params->original_url)
                                : KURL(common_params->url);
  KURL url = original_url;
  resource_load_info_notifier_wrapper->NotifyResourceLoadInitiated(
      request_id, GURL(url),
      !commit_params->original_method.empty() ? commit_params->original_method
                                              : common_params->method,
      common_params->referrer->url, common_params->request_destination,
      is_main_frame ? net::HIGHEST : net::LOWEST, is_ad_frame);
  size_t redirect_count = commit_params->redirect_response.size();

  if (redirect_count != commit_params->redirects.size()) {
    // We currently incorrectly send empty redirect_response and redirect_infos
    // on frame reloads and some cases involving throttles. There are also other
    // reports of non-empty cases, so further investigation is still needed.
    // TODO(https://crbug.com/1171225): Fix this.
    redirect_count = std::min(redirect_count, commit_params->redirects.size());
  }
  navigation_params->redirects.reserve(redirect_count);
  navigation_params->redirects.resize(redirect_count);
  for (size_t i = 0; i < redirect_count; ++i) {
    WebNavigationParams::RedirectInfo& redirect =
        navigation_params->redirects[i];
    auto& redirect_info = commit_params->redirect_infos[i];
    auto& redirect_response = commit_params->redirect_response[i];
    redirect.redirect_response =
        WebURLResponse::Create(url, *redirect_response,
                               response_head->ssl_info.has_value(), request_id);
    resource_load_info_notifier_wrapper->NotifyResourceRedirectReceived(
        redirect_info, std::move(redirect_response));
    if (url.ProtocolIsData())
      redirect.redirect_response.SetHttpStatusCode(200);
    redirect.new_url = KURL(redirect_info.new_url);
    // WebString treats default and empty strings differently while std::string
    // does not. A default value is expected for new_referrer rather than empty.
    if (!redirect_info.new_referrer.empty())
      redirect.new_referrer = WebString::FromUTF8(redirect_info.new_referrer);
    redirect.new_referrer_policy = ReferrerUtils::NetToMojoReferrerPolicy(
        redirect_info.new_referrer_policy);
    redirect.new_http_method = WebString::FromLatin1(redirect_info.new_method);
    url = KURL(redirect_info.new_url);
  }

  navigation_params->response = WebURLResponse::Create(
      url, *response_head, response_head->ssl_info.has_value(), request_id);
  if (url.ProtocolIsData())
    navigation_params->response.SetHttpStatusCode(200);

  if (url_loader_client_endpoints) {
    navigation_params->body_loader.reset(new NavigationBodyLoader(
        original_url, std::move(response_head), std::move(response_body),
        std::move(url_loader_client_endpoints), task_runner,
        std::move(resource_load_info_notifier_wrapper)));
  }
}

}  // namespace blink
```