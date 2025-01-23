Response:
Let's break down the thought process for analyzing the given C++ code and answering the prompt.

**1. Initial Understanding of the Request:**

The core request is to understand the functionality of the `v8_wasm_response_extensions.cc` file in the Chromium Blink engine. The request specifically asks about:

*   Listing its functions.
*   Its relationship with JavaScript, HTML, and CSS.
*   Logical reasoning with input/output examples.
*   Common user/programming errors.
*   Debugging clues related to how a user action reaches this code.

**2. High-Level Code Overview:**

My first step is to scan the code for key elements:

*   **Includes:** These tell me the dependencies and what functionalities are being used (e.g., `v8.h` for V8 integration, `Response.h` for network responses, `ScriptPromise.h` for asynchronous operations).
*   **Namespaces:** The code is within the `blink` namespace, indicating its part of the Blink rendering engine. The anonymous namespace `namespace {` suggests internal helpers.
*   **Function Declarations and Definitions:**  I look for functions like `SendCachedData`, `WasmCodeCachingCallback`, `FetchDataLoaderForWasmStreaming`, `StreamFromResponseCallback`, and `Initialize`. These are the main building blocks of the file.
*   **Keywords:**  Keywords like `Wasm`, `streaming`, `cache`, `response`, `promise`, `v8`, and `callback` are strong indicators of the file's purpose.
*   **Comments:**  Comments like "// Copyright..." and specific `TODO`s provide valuable context.
*   **Macros and Classes:**  Macros like `TRACE_EVENT_INSTANT` and classes like `CachedMetadata` point to specific functionalities (debugging and caching).

**3. Deconstructing the Functionality - Iterative Process:**

I go through each significant part of the code, trying to understand its role:

*   **`SendCachedData`:** This function clearly handles sending WebAssembly module data to the code cache. The inputs suggest it takes the response URL, time, cache name, execution context, and the serialized module.
*   **`WasmCodeCachingCallback`:** This class seems responsible for the process of serializing a compiled WebAssembly module and sending it to the cache. It's a callback because it's invoked by V8 after compilation. The `OnMoreFunctionsCanBeSerialized` method is the core of this.
*   **`FetchDataLoaderForWasmStreaming`:** This is a key class. Its name suggests it handles loading data specifically for streaming WebAssembly compilation. The interaction with `v8::WasmStreaming` is crucial. The `OnStateChange` method handles reading data from the network. The `MaybeConsumeCodeCache` method indicates it checks and uses cached modules.
*   **`WasmDataLoaderClient`:** This appears to be a simple adapter or interface for `FetchDataLoader`.
*   **`PropagateExceptionToWasmStreaming`:** This utility function handles converting exceptions to abort signals for the Wasm streaming process.
*   **`GetContextTaskRunner`:** This function determines the correct task runner for posting tasks based on the execution context (main thread, worker thread, etc.).
*   **`StreamFromResponseCallback`:** This is the main entry point triggered by V8. It takes a `Response` object as input and initiates the WebAssembly streaming compilation process. It performs checks on the response (status, MIME type, body state). It also manages the creation of `FetchDataLoaderForWasmStreaming` and the `WasmCodeCachingCallback`.
*   **`Initialize`:** This function sets the V8 streaming callback.

**4. Connecting to JavaScript, HTML, and CSS:**

Now, I explicitly address the request about these relationships:

*   **JavaScript:** The most direct connection is the `WebAssembly.compileStreaming()` API in JavaScript. This function fetches and compiles a WebAssembly module in a streaming fashion. The C++ code directly implements the backend logic for this API. I provide a JavaScript example.
*   **HTML:**  HTML's `<script>` tag can load and execute WebAssembly modules, especially with `type="module"`. The `fetch()` API used in conjunction with `WebAssembly.compileStreaming()` is often triggered from within an HTML page.
*   **CSS:**  There's generally no direct functional relationship between this specific C++ code and CSS. CSS deals with styling and layout, while this code handles WebAssembly compilation.

**5. Logical Reasoning and Examples:**

I try to create a simple scenario:

*   **Input:** A `Response` object in JavaScript (obtained via `fetch()`) containing a valid WebAssembly file.
*   **Output:**  The successful compilation of the WebAssembly module in V8, potentially using cached data.

I also consider the negative case:

*   **Input:** A `Response` object with an incorrect MIME type.
*   **Output:** An error in the JavaScript console.

**6. User and Programming Errors:**

I think about common mistakes developers might make when using WebAssembly:

*   Incorrect MIME type on the server.
*   Trying to use the response body after it has already been read.
*   Network errors.

**7. Debugging Clues and User Actions:**

Finally, I trace back how a user action might lead to this code:

1. User visits a webpage.
2. JavaScript code on the page uses `fetch()` to request a `.wasm` file.
3. The browser receives the response.
4. JavaScript calls `WebAssembly.compileStreaming()` with the `Response` object.
5. V8 calls the `StreamFromResponseCallback` in the C++ code.

I also mention debugging techniques like breakpoints in the C++ code and network inspection in the browser's developer tools.

**8. Refinement and Organization:**

Throughout this process, I organize my thoughts into the requested categories. I use clear and concise language, providing code examples and explanations where necessary. I make sure to address all parts of the original prompt.

**Self-Correction/Refinement during the process:**

*   Initially, I might focus too much on the low-level details of the `FetchDataLoader`. I need to step back and remember the higher-level function of the file: handling the `WebAssembly.compileStreaming()` API.
*   I realize the connection with HTML is more about *triggering* the fetch, not a direct functional dependency within this C++ code.
*   I need to ensure the input/output examples are clear and realistic.
*   I need to explicitly state the assumptions made in the logical reasoning.

By following these steps, I can systematically analyze the C++ code and provide a comprehensive answer to the prompt.这个文件 `v8_wasm_response_extensions.cc` 是 Chromium Blink 引擎中负责处理与 WebAssembly 响应相关的 V8 (JavaScript 引擎) 扩展功能的代码。它主要关注如何将从网络或其他来源获取的 WebAssembly 响应数据高效地传递给 V8 进行编译和执行，并支持 WebAssembly 模块的缓存。

以下是它的主要功能：

1. **实现 `WebAssembly.compileStreaming()` 的后端逻辑:**  这是该文件最核心的功能。`WebAssembly.compileStreaming()` 是 JavaScript 中用于异步编译 WebAssembly 模块的 API，它允许在下载过程中逐步编译模块，提高加载速度。这个文件中的代码负责接收来自 `fetch()` API 返回的 `Response` 对象，并将其数据流传递给 V8 的 WebAssembly 流式编译接口。

2. **处理 `Response` 对象:**  该文件接收一个 `Response` 对象作为输入，并对其进行各种检查，以确保它是适合进行 WebAssembly 流式编译的有效响应。这些检查包括：
    *   **HTTP 状态码:**  确保响应的 HTTP 状态码表示成功 (通常是 2xx)。
    *   **MIME 类型:**  验证响应的 `Content-Type` 是否为 `application/wasm`。
    *   **Body 状态:**  检查响应的 body 是否已被读取或锁定。
    *   **Body 内容:** 确保响应 body 不为空。

3. **与 V8 的 `WasmStreaming` API 交互:**  该文件使用 V8 提供的 `v8::WasmStreaming` API 来进行流式编译。它创建一个 `v8::WasmStreaming` 对象，并将来自 `Response` body 的数据逐步提供给它。

4. **WebAssembly 模块缓存:**  该文件实现了 WebAssembly 模块的缓存机制，以提高后续加载速度。它涉及以下步骤：
    *   **检查缓存:** 在开始编译之前，尝试从缓存中加载已编译的模块。
    *   **存储缓存:**  如果编译成功，并且响应可以缓存，则将编译后的模块序列化并存储到缓存中。
    *   **使用缓存:**  如果缓存命中，则直接从缓存加载已编译的模块，而无需重新下载和编译。
    *   **缓存失效:**  如果缓存中的模块与当前下载的模块不匹配（例如，由于内容更改），则会清除缓存。

5. **与 Blink 基础设施集成:**  该文件使用了 Blink 提供的各种基础设施，例如：
    *   **`ExecutionContext`:**  用于获取当前执行上下文（例如，文档或 Worker）。
    *   **`FetchDataLoader`:**  用于管理数据加载过程。
    *   **`CachedMetadata`:**  用于存储和加载缓存的元数据。
    *   **`ScriptPromise`:**  用于返回表示异步编译结果的 Promise 对象。
    *   **`ScriptState`:**  用于与 V8 隔离堆进行交互。
    *   **性能指标收集:** 使用 `base::metrics` 来记录 WebAssembly 编译和缓存相关的性能指标。

**与 JavaScript, HTML, CSS 的关系:**

*   **JavaScript:**  该文件直接实现了 JavaScript API `WebAssembly.compileStreaming()` 的后端逻辑。当 JavaScript 代码调用 `WebAssembly.compileStreaming(fetch('module.wasm'))` 时，`fetch()` 返回的 `Response` 对象最终会传递到这个 C++ 文件中的代码进行处理。
    *   **示例:**
        ```javascript
        fetch('module.wasm')
          .then(response => WebAssembly.compileStreaming(response))
          .then(module => {
            console.log('WebAssembly module compiled successfully:', module);
            // 使用 module
          })
          .catch(error => {
            console.error('Failed to compile WebAssembly module:', error);
          });
        ```

*   **HTML:**  HTML 中的 `<script>` 标签可以加载和执行 JavaScript 代码，而这些 JavaScript 代码可能会调用 `WebAssembly.compileStreaming()`。因此，间接地，该文件与 HTML 有关。
    *   **示例:**
        ```html
        <!DOCTYPE html>
        <html>
        <head>
          <title>WebAssembly Example</title>
        </head>
        <body>
          <script>
            fetch('module.wasm')
              .then(response => WebAssembly.compileStreaming(response))
              .then(module => {
                // ...
              });
          </script>
        </body>
        </html>
        ```

*   **CSS:**  该文件与 CSS 没有直接的功能关系。CSS 负责网页的样式和布局，而这个文件专注于 WebAssembly 模块的加载和编译。

**逻辑推理 (假设输入与输出):**

**假设输入:**

*   一个 JavaScript 环境，例如浏览器或 Node.js (在支持 `WebAssembly` API 的情况下)。
*   JavaScript 代码调用 `WebAssembly.compileStreaming(response)`，其中 `response` 是一个由 `fetch()` 返回的 `Response` 对象。
*   `response` 对象对应一个 URL，该 URL 指向一个有效的 WebAssembly 文件 (`.wasm`)，并且服务器返回了正确的 `Content-Type: application/wasm` 头信息，以及 HTTP 状态码 200 OK。

**输出:**

*   V8 引擎会开始流式地编译 WebAssembly 模块。
*   如果编译成功，`WebAssembly.compileStreaming()` 返回的 Promise 将会 resolve，并带有一个 `WebAssembly.Module` 对象。
*   如果启用了缓存，并且是第一次加载该模块，编译后的模块将被序列化并存储到缓存中。
*   如果在编译过程中发生错误（例如，WebAssembly 文件格式错误），Promise 将会 reject，并带有一个错误对象。

**涉及用户或编程常见的使用错误:**

1. **服务器配置错误:**  服务器没有配置正确的 `Content-Type` 头信息 (`application/wasm`)。这将导致该文件中的代码判断 MIME 类型错误，并拒绝进行流式编译。
    *   **用户操作:** 用户访问包含加载 WebAssembly 模块的网页。
    *   **错误:** JavaScript 抛出 `TypeError: Incorrect response MIME type. Expected 'application/wasm'.`

2. **尝试编译已读取的 `Response` 对象:**  `Response` 对象的 body 只能被读取一次。如果 JavaScript 代码在调用 `WebAssembly.compileStreaming()` 之前已经读取了 `response.body`，将会导致错误。
    *   **用户操作:** 用户访问包含尝试多次读取 `Response` body 的网页。
    *   **错误:** JavaScript 抛出 `TypeError: Cannot compile WebAssembly.Module from an already read Response`.

3. **网络错误:** 在下载 WebAssembly 模块的过程中发生网络错误（例如，连接超时，DNS 解析失败）。
    *   **用户操作:** 用户访问包含加载 WebAssembly 模块的网页，但网络连接不稳定。
    *   **错误:** `fetch()` 操作本身可能会失败，导致 `WebAssembly.compileStreaming()` 接收到错误的 `Response` 对象或根本没有接收到 `Response` 对象。

4. **WebAssembly 文件格式错误:**  下载的 `.wasm` 文件内容损坏或格式不正确，导致 V8 编译失败。
    *   **用户操作:** 用户访问包含指向损坏的 WebAssembly 文件的网页。
    *   **错误:** JavaScript 抛出 `CompileError` 或其他与 WebAssembly 编译相关的错误。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设用户访问了一个网页 `example.com/index.html`，该网页包含以下 JavaScript 代码：

```javascript
fetch('my_module.wasm')
  .then(response => {
    console.log('Response received:', response);
    return WebAssembly.compileStreaming(response);
  })
  .then(module => {
    console.log('WebAssembly module compiled:', module);
    // ... 使用 module
  })
  .catch(error => {
    console.error('Error loading WebAssembly:', error);
  });
```

1. **用户操作:** 用户在浏览器地址栏输入 `example.com/index.html` 并按下回车键。
2. **浏览器请求 HTML:** 浏览器向服务器请求 `index.html` 文件。
3. **服务器响应 HTML:** 服务器返回 `index.html` 文件。
4. **浏览器解析 HTML:** 浏览器解析 HTML 内容，遇到 `<script>` 标签。
5. **执行 JavaScript:** 浏览器执行 JavaScript 代码，开始执行 `fetch('my_module.wasm')`。
6. **浏览器请求 WebAssembly 文件:** 浏览器向服务器请求 `my_module.wasm` 文件。
7. **服务器响应 WebAssembly 文件:** 服务器返回 `my_module.wasm` 文件，并设置相应的 HTTP 头信息（包括 `Content-Type: application/wasm`）。
8. **`fetch()` Promise resolve:**  `fetch()` 操作成功，返回一个 `Response` 对象。
9. **调用 `WebAssembly.compileStreaming()`:**  JavaScript 代码调用 `WebAssembly.compileStreaming(response)`，并将 `Response` 对象作为参数传递。
10. **V8 调用扩展函数:**  V8 引擎接收到 `WebAssembly.compileStreaming()` 的调用，并且识别出需要调用 Blink 提供的扩展函数来处理 `Response` 对象。这个扩展函数就是 `v8_wasm_response_extensions.cc` 中定义的 `StreamFromResponseCallback`。
11. **`StreamFromResponseCallback` 执行:** `StreamFromResponseCallback` 函数被调用，接收到 `Response` 对象作为参数。
12. **执行各种检查:**  `StreamFromResponseCallback` 中的代码会进行各种检查，例如 MIME 类型、HTTP 状态码等。
13. **创建 `FetchDataLoaderForWasmStreaming`:** 如果检查通过，会创建一个 `FetchDataLoaderForWasmStreaming` 对象，用于处理 WebAssembly 数据的流式加载。
14. **启动数据加载:**  调用 `response->BodyBuffer()->StartLoading()`，开始从 `Response` body 中读取数据。
15. **数据传递给 V8:** 读取到的数据逐步传递给 V8 的 `WasmStreaming` API 进行编译。
16. **编译结果返回:** V8 完成编译后，会将结果返回给 JavaScript，`WebAssembly.compileStreaming()` 返回的 Promise resolve。

**调试线索:**

*   **JavaScript 控制台:**  查看 JavaScript 控制台的错误信息，例如 `TypeError` 或 `CompileError`。
*   **浏览器开发者工具的网络面板:**  检查对 `my_module.wasm` 的网络请求，查看 HTTP 状态码、响应头信息（特别是 `Content-Type`）和响应内容。
*   **Chrome 的 `chrome://inspect/#devices` 或 `chrome://tracing`:**  可以使用 Chrome 的开发者工具进行更深入的调试，查看 V8 的日志和性能信息。
*   **在 `v8_wasm_response_extensions.cc` 中添加日志:**  为了更精细地跟踪代码执行流程，可以在关键位置添加 `LOG()` 或 `DLOG()` 语句来输出调试信息。需要重新编译 Chromium 才能看到这些日志。例如，可以在 `StreamFromResponseCallback` 的开头和检查关键条件的地方添加日志，以便了解 `Response` 对象的状态以及代码执行路径。

总而言之，`v8_wasm_response_extensions.cc` 是 Blink 引擎中处理 WebAssembly 流式编译的关键组成部分，它连接了 JavaScript 的 `WebAssembly` API 和 V8 的 WebAssembly 引擎，并负责处理网络响应和模块缓存。

### 提示词
```
这是目录为blink/renderer/bindings/core/v8/v8_wasm_response_extensions.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/bindings/core/v8/v8_wasm_response_extensions.h"

#include "base/debug/dump_without_crashing.h"
#include "base/memory/scoped_refptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/numerics/safe_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "components/crash/core/common/crash_key.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_response.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fetch/body_stream_buffer.h"
#include "third_party/blink/renderer/core/fetch/fetch_data_loader.h"
#include "third_party/blink/renderer/core/fetch/response.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/workers/worker_backing_thread.h"
#include "third_party/blink/renderer/core/workers/worker_or_worklet_global_scope.h"
#include "third_party/blink/renderer/core/workers/worker_thread.h"
#include "third_party/blink/renderer/core/workers/worklet_global_scope.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_isolate_data.h"
#include "third_party/blink/renderer/platform/crypto.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/loader/fetch/cached_metadata.h"
#include "third_party/blink/renderer/platform/loader/fetch/script_cached_metadata_handler.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"

namespace blink {

namespace {

// The first `kWireBytesDigestSize` bytes of CachedMetadata body stores the
// SHA-256 hash of the wire bytes and created/consumed here in Blink. The
// remaining part of CachedMetadata is created/consumed by V8.
static const size_t kWireBytesDigestSize = 32;

// Wasm only has a single metadata type, but we need to tag it.
// `2` is used to invalidate old cached data (which used kWasmModuleTag = 1).
static const int kWasmModuleTag = 2;

void SendCachedData(String response_url,
                    base::Time response_time,
                    String cache_storage_cache_name,
                    ExecutionContext* execution_context,
                    Vector<uint8_t> serialized_module) {
  if (!execution_context)
    return;
  scoped_refptr<CachedMetadata> cached_metadata =
      CachedMetadata::CreateFromSerializedData(std::move(serialized_module));

  CodeCacheHost* code_cache_host =
      ExecutionContext::GetCodeCacheHostFromContext(execution_context);
  CachedMetadataSender::SendToCodeCacheHost(
      code_cache_host, mojom::blink::CodeCacheType::kWebAssembly, response_url,
      response_time, cache_storage_cache_name,
      cached_metadata->SerializedData());
}

class WasmCodeCachingCallback {
 public:
  WasmCodeCachingCallback(
      const String& response_url,
      const base::Time& response_time,
      const String& cache_storage_cache_name,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      ExecutionContext* execution_context)
      : response_url_(response_url),
        response_time_(response_time),
        cache_storage_cache_name_(cache_storage_cache_name),
        execution_context_task_runner_(std::move(task_runner)),
        execution_context_(execution_context) {}

  WasmCodeCachingCallback(const WasmCodeCachingCallback&) = delete;
  WasmCodeCachingCallback operator=(const WasmCodeCachingCallback&) = delete;

  void OnMoreFunctionsCanBeSerialized(v8::CompiledWasmModule compiled_module) {
    // Called from V8 background thread.
    TRACE_EVENT_INSTANT1(TRACE_DISABLED_BY_DEFAULT("devtools.timeline"),
                         "v8.wasm.compiledModule", TRACE_EVENT_SCOPE_THREAD,
                         "url", response_url_.Utf8());
    v8::OwnedBuffer serialized_module;
    {
      // Use a standard milliseconds based timer (up to 10 seconds, 50 buckets),
      // similar to "V8.WasmDeserializationTimeMilliSeconds" defined in V8.
      SCOPED_UMA_HISTOGRAM_TIMER("V8.WasmSerializationTimeMilliSeconds");
      serialized_module = compiled_module.Serialize();
    }
    // V8 might not be able to serialize the module.
    if (serialized_module.size == 0)
      return;

    TRACE_EVENT_INSTANT1(TRACE_DISABLED_BY_DEFAULT("devtools.timeline"),
                         "v8.wasm.cachedModule", TRACE_EVENT_SCOPE_THREAD,
                         "producedCacheSize", serialized_module.size);

    v8::MemorySpan<const uint8_t> wire_bytes =
        compiled_module.GetWireBytesRef();
    DigestValue wire_bytes_digest;
    {
      TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("devtools.timeline"),
                   "v8.wasm.compileDigestForCreate");
      if (!ComputeDigest(kHashAlgorithmSha256, wire_bytes, wire_bytes_digest)) {
        return;
      }
      if (wire_bytes_digest.size() != kWireBytesDigestSize)
        return;
    }

    // The resources needed for caching may have been GC'ed, but we should still
    // save the compiled module. Use the platform API directly.
    Vector<uint8_t> serialized_data = CachedMetadata::GetSerializedDataHeader(
        kWasmModuleTag, kWireBytesDigestSize + base::checked_cast<wtf_size_t>(
                                                   serialized_module.size));
    serialized_data.AppendSpan(base::span(wire_bytes_digest));
    serialized_data.Append(
        reinterpret_cast<const uint8_t*>(serialized_module.buffer.get()),
        base::checked_cast<wtf_size_t>(serialized_module.size));

    // Make sure the data could be copied.
    if (serialized_data.size() < serialized_module.size)
      return;

    DCHECK(execution_context_task_runner_.get());
    execution_context_task_runner_->PostTask(
        FROM_HERE, ConvertToBaseOnceCallback(WTF::CrossThreadBindOnce(
                       &SendCachedData, response_url_, response_time_,
                       cache_storage_cache_name_, execution_context_,
                       std::move(serialized_data))));
  }

  void SetBuffer(scoped_refptr<CachedMetadata> cached_module) {
    cached_module_ = cached_module;
  }

 private:
  const String response_url_;
  const base::Time response_time_;
  const String cache_storage_cache_name_;
  scoped_refptr<CachedMetadata> cached_module_;
  scoped_refptr<base::SingleThreadTaskRunner> execution_context_task_runner_;
  CrossThreadWeakPersistent<ExecutionContext> execution_context_;
};

// The |FetchDataLoader| for streaming compilation of WebAssembly code. The
// received bytes get forwarded to the V8 API class |WasmStreaming|.
class FetchDataLoaderForWasmStreaming final : public FetchDataLoader,
                                              public BytesConsumer::Client {
 public:
  FetchDataLoaderForWasmStreaming(
      const String& url,
      std::shared_ptr<v8::WasmStreaming> streaming,
      ScriptState* script_state,
      ScriptCachedMetadataHandler* cache_handler,
      std::shared_ptr<WasmCodeCachingCallback> code_caching_callback)
      : url_(url),
        streaming_(std::move(streaming)),
        script_state_(script_state),
        cache_handler_(cache_handler),
        code_caching_callback_(std::move(code_caching_callback)) {}

  v8::WasmStreaming* streaming() const { return streaming_.get(); }

  void Start(BytesConsumer* consumer,
             FetchDataLoader::Client* client) override {
    DCHECK(!consumer_);
    DCHECK(!client_);
    client_ = client;
    consumer_ = consumer;
    consumer_->SetClient(this);
    OnStateChange();
  }

  enum class CodeCacheState {
    kBeforeFirstByte,
    kUseCodeCache,
    kNoCodeCache,
  };

  void OnStateChange() override {
    TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("devtools.timeline"),
                 "v8.wasm.compileConsume");
    // Continue reading until we either finished, aborted, or no data is
    // available any more (handled below).
    while (streaming_) {
      // |buffer| is owned by |consumer_|.
      base::span<const char> buffer;
      BytesConsumer::Result result = consumer_->BeginRead(buffer);

      if (result == BytesConsumer::Result::kShouldWait)
        return;
      if (result == BytesConsumer::Result::kOk) {
        // Ignore more bytes after an abort (streaming == nullptr).
        if (!buffer.empty()) {
          if (code_cache_state_ == CodeCacheState::kBeforeFirstByte)
            code_cache_state_ = MaybeConsumeCodeCache();

          auto bytes = base::as_bytes(buffer);
          if (code_cache_state_ == CodeCacheState::kUseCodeCache) {
            TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("devtools.timeline"),
                         "v8.wasm.compileDigestForConsume");
            digestor_.Update(bytes);
          }
          streaming_->OnBytesReceived(bytes.data(), bytes.size());
        }
        result = consumer_->EndRead(buffer.size());
      }
      switch (result) {
        case BytesConsumer::Result::kShouldWait:
          NOTREACHED();
        case BytesConsumer::Result::kOk:
          break;
        case BytesConsumer::Result::kDone: {
          TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("devtools.timeline"),
                       "v8.wasm.compileConsumeDone");
          {
            ScriptState::Scope scope(script_state_);
            streaming_->Finish(HasValidCodeCache());
          }
          client_->DidFetchDataLoadedCustomFormat();
          streaming_.reset();
          return;
        }
        case BytesConsumer::Result::kError:
          DCHECK_EQ(BytesConsumer::PublicState::kErrored,
                    consumer_->GetPublicState());
          AbortCompilation("Network error: " + consumer_->GetError().Message());
          break;
      }
    }
  }

  String DebugName() const override { return "FetchDataLoaderForWasmModule"; }

  void Cancel() override {
    consumer_->Cancel();
    return AbortCompilation("Cancellation requested");
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(consumer_);
    visitor->Trace(client_);
    visitor->Trace(script_state_);
    visitor->Trace(cache_handler_);
    FetchDataLoader::Trace(visitor);
    BytesConsumer::Client::Trace(visitor);
  }

  void AbortFromClient() {
    // Ignore a repeated abort request, or abort after successfully finishing.
    if (!streaming_) {
      return;
    }
    auto* exception =
        MakeGarbageCollected<DOMException>(DOMExceptionCode::kAbortError);
    ScriptState::Scope scope(script_state_);

    // Calling ToV8 in a ScriptForbiddenScope will trigger a CHECK and
    // cause a crash. ToV8 just invokes a constructor for wrapper creation,
    // which is safe (no author script can be run). Adding AllowUserAgentScript
    // directly inside createWrapper could cause a perf impact (calling
    // isMainThread() every time a wrapper is created is expensive). Ideally,
    // resolveOrReject shouldn't be called inside a ScriptForbiddenScope.
    {
      ScriptForbiddenScope::AllowUserAgentScript allow_script;
      v8::Local<v8::Value> v8_exception =
          ToV8Traits<DOMException>::ToV8(script_state_, exception);
      streaming_->Abort(v8_exception);
      streaming_.reset();
    }
  }

 private:
  // TODO(ahaas): replace with spec-ed error types, once spec clarifies
  // what they are.
  void AbortCompilation(String reason) {
    // Ignore a repeated abort request, or abort after successfully finishing.
    if (!streaming_) {
      return;
    }
    if (script_state_->ContextIsValid()) {
      ScriptState::Scope scope(script_state_);
      streaming_->Abort(V8ThrowException::CreateTypeError(
          script_state_->GetIsolate(),
          "WebAssembly compilation aborted: " + reason));
    } else {
      // We are not allowed to execute a script, which indicates that we should
      // not reject the promise of the streaming compilation. By passing no
      // abort reason, we indicate the V8 side that the promise should not get
      // rejected.
      streaming_->Abort(v8::Local<v8::Value>());
    }
    streaming_.reset();
  }

  CodeCacheState MaybeConsumeCodeCache() {
    // The enum values need to match "WasmCodeCaching" in
    // tools/metrics/histograms/enums.xml.
    enum class WasmCodeCaching {
      kMiss = 0,
      kHit = 1,
      kInvalidCacheEntry = 2,
      kNoCacheHandler = 3,

      kMaxValue = kNoCacheHandler
    };

    if (!cache_handler_) {
      base::UmaHistogramEnumeration("V8.WasmCodeCaching",
                                    WasmCodeCaching::kNoCacheHandler);
      return CodeCacheState::kNoCodeCache;
    }

    // We must wait until we see the first byte of the response body before
    // checking for GetCachedMetadata(). The serialized cache metadata is
    // guaranteed to be set on the handler before the body stream is provided,
    // but this can happen some time after the Response head is received.
    scoped_refptr<CachedMetadata> cached_module =
        cache_handler_->GetCachedMetadata(kWasmModuleTag);
    if (!cached_module) {
      base::UmaHistogramEnumeration("V8.WasmCodeCaching",
                                    WasmCodeCaching::kMiss);
      return CodeCacheState::kNoCodeCache;
    }
    base::span<const uint8_t> metadata_with_digest = cached_module->Data();

    TRACE_EVENT_INSTANT2(TRACE_DISABLED_BY_DEFAULT("devtools.timeline"),
                         "v8.wasm.moduleCacheHit", TRACE_EVENT_SCOPE_THREAD,
                         "url", url_.Utf8(), "consumedCacheSize",
                         metadata_with_digest.size());

    bool is_valid = false;
    if (metadata_with_digest.size() >= kWireBytesDigestSize) {
      auto metadata = metadata_with_digest.subspan(kWireBytesDigestSize);
      is_valid =
          streaming_->SetCompiledModuleBytes(metadata.data(), metadata.size());
    }

    if (!is_valid) {
      TRACE_EVENT_INSTANT0(TRACE_DISABLED_BY_DEFAULT("devtools.timeline"),
                           "v8.wasm.moduleCacheInvalid",
                           TRACE_EVENT_SCOPE_THREAD);
      base::UmaHistogramEnumeration("V8.WasmCodeCaching",
                                    WasmCodeCaching::kInvalidCacheEntry);
      // TODO(mythria): Also support using context specific code cache host
      // here. When we pass nullptr for CodeCacheHost we use per-process
      // interface. Currently this code is run on a thread started via a
      // Platform::PostJob. So it isn't safe to use CodeCacheHost interface
      // that was bound on the frame / worker threads. We should instead post
      // a task back to the frame / worker threads with the required data
      // which can then write to generated code caches.
      cache_handler_->ClearCachedMetadata(
          /*code_cache_host*/ nullptr,
          CachedMetadataHandler::kClearPersistentStorage);
      return CodeCacheState::kNoCodeCache;
    }

    base::UmaHistogramEnumeration("V8.WasmCodeCaching", WasmCodeCaching::kHit);
    // Keep the buffer alive until V8 is ready to deserialize it.
    // TODO(wasm): Shorten the life time of {cached_module} to reduce memory
    // usage.
    code_caching_callback_->SetBuffer(cached_module);
    return CodeCacheState::kUseCodeCache;
  }

  bool HasValidCodeCache() {
    if (code_cache_state_ != CodeCacheState::kUseCodeCache)
      return false;
    if (!cache_handler_)
      return false;
    scoped_refptr<CachedMetadata> cached_module =
        cache_handler_->GetCachedMetadata(kWasmModuleTag);
    if (!cached_module)
      return false;
    base::span<const uint8_t> metadata_with_digest = cached_module->Data();
    if (metadata_with_digest.size() < kWireBytesDigestSize) {
      return false;
    }

    DigestValue wire_bytes_digest;
    digestor_.Finish(wire_bytes_digest);
    if (digestor_.has_failed() ||
        wire_bytes_digest != metadata_with_digest.first(kWireBytesDigestSize)) {
      TRACE_EVENT_INSTANT0(TRACE_DISABLED_BY_DEFAULT("devtools.timeline"),
                           "v8.wasm.moduleCacheInvalidDigest",
                           TRACE_EVENT_SCOPE_THREAD);
      cache_handler_->ClearCachedMetadata(
          /*code_cache_host*/ nullptr,
          CachedMetadataHandler::kClearPersistentStorage);
      return false;
    }

    return true;
  }

  const String url_;
  Member<BytesConsumer> consumer_;
  Member<FetchDataLoader::Client> client_;
  std::shared_ptr<v8::WasmStreaming> streaming_;
  const Member<ScriptState> script_state_;
  Member<ScriptCachedMetadataHandler> cache_handler_;
  std::shared_ptr<WasmCodeCachingCallback> code_caching_callback_;
  CodeCacheState code_cache_state_ = CodeCacheState::kBeforeFirstByte;
  Digestor digestor_{kHashAlgorithmSha256};
};

// TODO(mtrofin): WasmDataLoaderClient is necessary so we may provide an
// argument to BodyStreamBuffer::startLoading, however, it fulfills
// a very small role. Consider refactoring to avoid it.
class WasmDataLoaderClient final
    : public GarbageCollected<WasmDataLoaderClient>,
      public FetchDataLoader::Client {
 public:
  explicit WasmDataLoaderClient(FetchDataLoaderForWasmStreaming* loader)
      : loader_(loader) {}

  WasmDataLoaderClient(const WasmDataLoaderClient&) = delete;
  WasmDataLoaderClient& operator=(const WasmDataLoaderClient&) = delete;

  void DidFetchDataLoadedCustomFormat() override {}
  void DidFetchDataLoadFailed() override { NOTREACHED(); }
  void Abort() override { loader_->AbortFromClient(); }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(loader_);
    FetchDataLoader::Client::Trace(visitor);
  }

 private:
  Member<FetchDataLoaderForWasmStreaming> loader_;
};

// Convert an exception to an abort message for WasmStreaming. This rejects the
// promise instead of actually throwing the exception.
// No further methods should be called on the WasmStreaming object afterwards,
// hence we receive the shared_ptr by reference and clear it.
void PropagateExceptionToWasmStreaming(
    ScriptState* script_state,
    v8::Local<v8::Value> exception,
    std::shared_ptr<v8::WasmStreaming>& streaming) {
  ApplyContextToException(script_state, exception,
                          ExceptionContext(v8::ExceptionContext::kOperation,
                                           "WebAssembly", "compile"));
  streaming->Abort(exception);
  streaming.reset();
}

scoped_refptr<base::SingleThreadTaskRunner> GetContextTaskRunner(
    ExecutionContext& execution_context) {
  if (execution_context.IsWorkerGlobalScope()) {
    WorkerOrWorkletGlobalScope& global_scope =
        To<WorkerOrWorkletGlobalScope>(execution_context);
    return global_scope.GetThread()
        ->GetWorkerBackingThread()
        .BackingThread()
        .GetTaskRunner();
  }

  if (execution_context.IsWindow()) {
    return DynamicTo<LocalDOMWindow>(execution_context)
        ->GetTaskRunner(TaskType::kInternalNavigationAssociated);
  }

  DCHECK(execution_context.IsWorkletGlobalScope());
  WorkletGlobalScope& worklet_global_scope =
      To<WorkletGlobalScope>(execution_context);
  if (worklet_global_scope.IsMainThreadWorkletGlobalScope()) {
    return worklet_global_scope.GetFrame()->GetTaskRunner(
        TaskType::kInternalNavigationAssociated);
  }

  return worklet_global_scope.GetThread()
      ->GetWorkerBackingThread()
      .BackingThread()
      .GetTaskRunner();
}

void StreamFromResponseCallback(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  TRACE_EVENT_INSTANT0(TRACE_DISABLED_BY_DEFAULT("devtools.timeline"),
                       "v8.wasm.streamFromResponseCallback",
                       TRACE_EVENT_SCOPE_THREAD);
  std::shared_ptr<v8::WasmStreaming> streaming =
      v8::WasmStreaming::Unpack(args.GetIsolate(), args.Data());

  ScriptState* script_state = ScriptState::ForCurrentRealm(args);
  if (!script_state->ContextIsValid()) {
    // We do not have an execution context, we just abort streaming compilation
    // immediately without error.
    streaming->Abort(v8::Local<v8::Value>());
    return;
  }

  // The enum values need to match "WasmStreamingInputType" in
  // tools/metrics/histograms/enums.xml.
  enum class WasmStreamingInputType {
    kNoResponse = 0,
    kResponseNotOK = 1,
    kWrongMimeType = 2,
    kReponseEmpty = 3,
    kReponseLocked = 4,
    kNoURL = 5,
    kValidHttp = 6,
    kValidHttps = 7,
    kValidDataURL = 8,
    kValidFileURL = 9,
    kValidBlob = 10,
    kValidChromeExtension = 11,
    kValidOtherProtocol = 12,

    kMaxValue = kValidOtherProtocol
  };

  Response* response = V8Response::ToWrappable(args.GetIsolate(), args[0]);
  if (!response) {
    base::UmaHistogramEnumeration("V8.WasmStreamingInputType",
                                  WasmStreamingInputType::kNoResponse);
    auto exception = V8ThrowException::CreateTypeError(
        args.GetIsolate(),
        "An argument must be provided, which must be a "
        "Response or Promise<Response> object");
    PropagateExceptionToWasmStreaming(script_state, exception, streaming);
    return;
  }

  if (!response->ok()) {
    base::UmaHistogramEnumeration("V8.WasmStreamingInputType",
                                  WasmStreamingInputType::kResponseNotOK);
    auto exception = V8ThrowException::CreateTypeError(
        args.GetIsolate(), "HTTP status code is not ok");
    PropagateExceptionToWasmStreaming(script_state, exception, streaming);
    return;
  }

  // The spec explicitly disallows any extras on the Content-Type header,
  // so we check against ContentType() rather than MimeType(), which
  // implicitly strips extras.
  if (!EqualIgnoringASCIICase(response->ContentType(), "application/wasm")) {
    base::UmaHistogramEnumeration("V8.WasmStreamingInputType",
                                  WasmStreamingInputType::kWrongMimeType);
    auto exception = V8ThrowException::CreateTypeError(
        args.GetIsolate(),
        "Incorrect response MIME type. Expected 'application/wasm'.");
    PropagateExceptionToWasmStreaming(script_state, exception, streaming);
    return;
  }

  if (response->IsBodyLocked() || response->IsBodyUsed()) {
    base::UmaHistogramEnumeration("V8.WasmStreamingInputType",
                                  WasmStreamingInputType::kReponseLocked);
    auto exception = V8ThrowException::CreateTypeError(
        args.GetIsolate(),
        "Cannot compile WebAssembly.Module from an already read Response");
    PropagateExceptionToWasmStreaming(script_state, exception, streaming);
    return;
  }

  if (!response->BodyBuffer()) {
    base::UmaHistogramEnumeration("V8.WasmStreamingInputType",
                                  WasmStreamingInputType::kReponseEmpty);
    // Since the status is 2xx (ok), this must be status 204 (No Content),
    // status 205 (Reset Content) or a malformed status 200 (OK).
    auto exception = V8ThrowException::CreateWasmCompileError(
        args.GetIsolate(), "Empty WebAssembly module");
    PropagateExceptionToWasmStreaming(script_state, exception, streaming);
    return;
  }

  auto protocol_type = WasmStreamingInputType::kNoURL;
  if (const KURL* kurl = response->GetResponse()->Url()) {
    String protocol = kurl->Protocol();
    // Http and https can be cached; also track other protocols we expect in
    // Wasm streaming. If {kValidOtherProtocol} spikes, we should add more enum
    // values.
    protocol_type = protocol == "http"    ? WasmStreamingInputType::kValidHttp
                    : protocol == "https" ? WasmStreamingInputType::kValidHttps
                    : protocol == "data" ? WasmStreamingInputType::kValidDataURL
                    : protocol == "file" ? WasmStreamingInputType::kValidFileURL
                    : protocol == "blob" ? WasmStreamingInputType::kValidBlob
                    : protocol == "chrome-extension"
                        ? WasmStreamingInputType::kValidChromeExtension
                        : WasmStreamingInputType::kValidOtherProtocol;
  }
  base::UmaHistogramEnumeration("V8.WasmStreamingInputType", protocol_type);

  String url = response->url();
  const std::string& url_utf8 = url.Utf8();
  streaming->SetUrl(url_utf8.c_str(), url_utf8.size());
  auto* cache_handler = response->BodyBuffer()->GetCachedMetadataHandler();
  std::shared_ptr<WasmCodeCachingCallback> code_caching_callback;
  if (cache_handler) {
    auto* execution_context = ExecutionContext::From(script_state);
    DCHECK_NE(execution_context, nullptr);

    code_caching_callback = std::make_shared<WasmCodeCachingCallback>(
        url, response->GetResponse()->InternalResponse()->ResponseTime(),
        response->GetResponse()->InternalResponse()->CacheStorageCacheName(),
        GetContextTaskRunner(*execution_context), execution_context);
    streaming->SetMoreFunctionsCanBeSerializedCallback(
        [code_caching_callback](v8::CompiledWasmModule compiled_module) {
          code_caching_callback->OnMoreFunctionsCanBeSerialized(
              std::move(compiled_module));
        });
  }

  FetchDataLoaderForWasmStreaming* loader =
      MakeGarbageCollected<FetchDataLoaderForWasmStreaming>(
          url, std::move(streaming), script_state, cache_handler,
          code_caching_callback);
  response->BodyBuffer()->StartLoading(
      loader, MakeGarbageCollected<WasmDataLoaderClient>(loader),
      PassThroughException(args.GetIsolate()));
}

}  // namespace

void WasmResponseExtensions::Initialize(v8::Isolate* isolate) {
  isolate->SetWasmStreamingCallback(StreamFromResponseCallback);
}

}  // namespace blink
```