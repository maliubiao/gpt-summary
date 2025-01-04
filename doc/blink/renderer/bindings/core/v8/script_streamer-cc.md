Response:
My thinking process to arrive at the summary of `script_streamer.cc` goes like this:

1. **Understand the Goal:** The request asks for a summary of the file's functionality, its relationship to web technologies, potential errors, debugging hints, and explicitly asks for this to be the *first* part of a larger explanation. This suggests focusing on the core purpose and avoiding deep dives into specific implementations.

2. **Identify Key Classes and Structures:** I quickly scan the file for prominent class names. `ScriptStreamer`, `ResourceScriptStreamer`, and `SourceStream` immediately stand out. These are likely the main actors.

3. **Analyze `SourceStream`:** This class has methods like `GetMoreData`, `Cancel`, `TakeDataAndPipeOnMainThread`, etc. The name and methods strongly suggest it's responsible for fetching and providing script data, likely in chunks. The interaction with `mojo::ScopedDataPipeConsumerHandle` further confirms this involves asynchronous data transfer. The comments within `GetMoreData` explicitly mention blocking and interacting with V8.

4. **Analyze `ResourceScriptStreamer`:** This class seems to orchestrate the streaming process. Methods like `TryStartStreamingTask`, `StreamingCompleteOnBackgroundThread`, `SuppressStreaming`, and the constructor parameters (including `ScriptResource`, `ResponseBodyLoaderClient`) point to it being the central manager of a single script's streaming. The interaction with V8 compile hints and code cache also becomes apparent.

5. **Analyze `ScriptStreamer` (the base class):**  This class seems to have static methods like `TakeFrom` and `RecordStreamingHistogram`. This suggests it provides higher-level utilities and tracking related to script streaming.

6. **Infer the Overall Workflow:**  Based on the class analysis, a general flow emerges:
    * A script resource is being loaded.
    * `ResourceScriptStreamer` is created to manage streaming for this resource.
    * Data is received through a `mojo::ScopedDataPipeConsumerHandle`.
    * `SourceStream` acts as an intermediary, providing this data to V8's streaming compiler.
    * `TryStartStreamingTask` attempts to initiate the background compilation.
    * V8 compiles the script incrementally using data from `SourceStream`.
    * `StreamingCompleteOnBackgroundThread` signals the completion (or failure) of the streaming compilation.

7. **Connect to Web Technologies:**  The keywords "javascript", "html", and "css" in the prompt require me to link the functionality to these areas. JavaScript is the most direct connection, as the file deals with script compilation. HTML comes into play because `<script>` tags trigger the loading and processing of JavaScript. While this specific file doesn't directly handle CSS, the concept of resource loading and optimization applies broadly to web content.

8. **Consider Error Handling and Debugging:**  Methods like `Cancel`, `SuppressStreaming`, and the various `NotStreamingReason` enum values indicate error scenarios and reasons why streaming might not occur. The comments about blocking and background threads provide debugging hints. The mention of user actions (like clicking a link) that lead to resource loading provides a starting point for tracing execution.

9. **Address the "Part 1" Constraint:** Since this is the first part, I need to provide a high-level overview without going into too much detail about specific V8 API calls or the intricacies of Mojo data pipes. The goal is to establish the fundamental purpose.

10. **Structure the Summary:** I organize the information into clear sections: Core Functionality, Relationship to Web Technologies, Logical Reasoning (albeit limited in this part), Potential Errors, and User Actions/Debugging. This structure directly addresses the prompt's requirements.

11. **Refine and Condense:** I review the generated summary, ensuring it's concise, accurate, and easy to understand. I avoid jargon where possible and focus on the key takeaways. For instance, instead of explaining every detail of Mojo data pipes, I simply mention that it's used for efficient data transfer.

By following these steps, I can generate a comprehensive yet concise summary of the `script_streamer.cc` file's functionality, as demonstrated in the provided example answer. The process emphasizes understanding the core purpose, identifying key components, and linking them to the broader context of web technologies and browser operation.
```
这是目录为blink/renderer/bindings/core/v8/script_streamer.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

这个 `script_streamer.cc` 文件在 Chromium Blink 渲染引擎中扮演着重要的角色，其核心功能是**优化 JavaScript 代码的加载和解析过程，通过流式传输 (streaming) 的方式将 JavaScript 代码传递给 V8 引擎进行编译，从而提高页面加载速度和用户体验。**

更具体地说，它的功能可以归纳为以下几点：

1. **JavaScript 流式解析的实现:** 该文件实现了将通过网络接收到的 JavaScript 代码分块地、逐步地传递给 V8 JavaScript 引擎进行编译的功能。这种方式避免了必须等待整个脚本下载完成后才能开始解析的传统模式。

2. **与 V8 引擎的交互:** 它定义了 `SourceStream` 类，该类实现了 V8 引擎要求的 `v8::ScriptCompiler::ExternalSourceStream` 接口。这个接口允许 V8 在后台线程上按需从流中获取 JavaScript 代码进行编译。

3. **数据管道 (Data Pipe) 的使用:** 它利用 Mojo 数据管道 (`mojo::ScopedDataPipeConsumerHandle`) 来接收来自网络或其他来源的 JavaScript 代码。数据管道提供了一种高效的异步数据传输机制。

4. **编译提示 (Compile Hints) 的管理:** 它集成了编译提示功能，允许在流式编译过程中向 V8 提供额外的元数据，以进一步优化编译过程。这包括从缓存中获取的编译提示以及通过魔术注释提供的提示。

5. **处理不同的脚本类型:** 它能够区分和处理不同类型的 JavaScript 脚本，例如经典的 script 和模块 (module)。

6. **错误处理和取消机制:** 它提供了取消正在进行的流式传输的功能，并在发生错误时进行处理。

7. **性能监控和指标收集:** 它使用 UMA 宏记录了流式解析的统计信息，例如是否使用了流式传输、未能使用流式传输的原因等，用于性能分析和优化。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**  这是该文件最直接关联的功能。它的核心目的是优化 JavaScript 代码的加载和执行。
    * **例子:** 当浏览器解析 HTML 遇到 `<script>` 标签时，如果启用了流式解析，`script_streamer.cc` 中的代码就会被调用，将下载的 JavaScript 代码流式地传递给 V8 进行编译，而不是等待整个脚本下载完成。

* **HTML:** HTML 中的 `<script>` 标签是触发 JavaScript 加载和解析的关键。`script_streamer.cc` 的功能是为了加速这些脚本的加载过程。
    * **例子:**  考虑以下 HTML 代码：
      ```html
      <!DOCTYPE html>
      <html>
      <head>
          <title>Example</title>
      </head>
      <body>
          <script src="large_script.js"></script>
      </body>
      </html>
      ```
      当浏览器加载 `large_script.js` 时，`script_streamer.cc` 的功能会尽可能早地开始解析脚本，即使脚本还在下载中。

* **CSS:** 虽然该文件本身不直接处理 CSS，但其优化的 JavaScript 加载有助于提高整体页面渲染性能，包括 CSS 的应用。JavaScript 常常用于操作 DOM 和 CSS 样式，更快的 JavaScript 执行意味着更快的页面交互和视觉呈现。
    * **例子:**  如果一个网站使用 JavaScript 来动态地修改 CSS 样式，例如根据用户交互改变元素颜色或布局，那么更快的 JavaScript 加载和执行将使得这些动态效果更快地呈现给用户。

**逻辑推理的假设输入与输出:**

假设输入：

1. **HTML 解析器遇到一个 `<script src="my_script.js">` 标签。**
2. **浏览器开始下载 `my_script.js`。**
3. **`script_streamer.cc` 中的代码被调用，并接收到 `my_script.js` 的部分数据流 (通过 Mojo 数据管道)。**

假设输出：

1. **`SourceStream` 对象被创建，用于管理与 V8 引擎的数据传输。**
2. **`SourceStream` 将接收到的数据块逐步地传递给 V8 引擎的后台编译线程。**
3. **V8 引擎开始对接收到的 JavaScript 代码进行流式解析和编译。**
4. **在整个脚本下载完成之前，V8 引擎可能已经完成部分或全部的编译工作。**

**涉及用户或编程常见的使用错误及举例说明:**

虽然用户不会直接与 `script_streamer.cc` 交互，但开发者可能会遇到与其相关的错误，例如：

* **服务器配置错误导致不正确的 MIME 类型:** 如果服务器返回的 JavaScript 文件的 `Content-Type` 不是 JavaScript 相关的 MIME 类型（例如 `text/plain`），浏览器可能不会将其识别为 JavaScript，从而不会启动流式解析。
    * **例子:**  开发者错误地将 JavaScript 文件的 MIME 类型配置为 `text/plain`。浏览器下载该文件后，由于 MIME 类型不匹配，可能不会尝试进行流式解析，而是按照普通文本处理。

* **网络问题导致数据传输中断:** 如果网络连接不稳定，导致 JavaScript 文件的下载中断，流式解析过程也会受到影响，可能导致解析失败或需要重新加载。
    * **例子:** 用户在网络环境不佳的情况下访问网页，加载大型 JavaScript 文件时网络连接中断，导致流式解析过程被打断。

* **代码缓存问题:**  虽然流式解析旨在提高性能，但在某些情况下，如果代码缓存机制出现问题，可能会导致重复解析或加载失败。
    * **例子:**  浏览器的代码缓存损坏，导致即使脚本内容没有变化，也无法利用缓存，每次加载都需要重新进行流式解析。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入网址或点击链接。**
2. **浏览器开始请求网页的 HTML 内容。**
3. **浏览器解析 HTML 内容，遇到 `<script>` 标签。**
4. **浏览器开始请求 `<script>` 标签指定的 JavaScript 文件。**
5. **网络层接收到 JavaScript 文件的数据流。**
6. **Blink 渲染引擎的资源加载器 (Resource Loader) 接收到 JavaScript 资源的数据。**
7. **`ResourceScriptStreamer` (与 `script_streamer.cc` 相关联的类) 被创建来处理该 JavaScript 资源的加载。**
8. **Mojo 数据管道被创建，用于将 JavaScript 数据传递给 `script_streamer.cc` 中的 `SourceStream`。**
9. **`SourceStream` 将数据传递给 V8 引擎进行流式解析。**

**作为调试线索：** 如果在调试过程中怀疑 JavaScript 加载或解析存在问题，可以关注以下几点：

* **网络请求:** 检查 JavaScript 文件的网络请求状态，确认是否成功下载，以及响应头中的 `Content-Type` 是否正确。
* **控制台错误:** 查看浏览器的开发者工具控制台是否有 JavaScript 相关的错误信息。
* **性能分析:** 使用浏览器的性能分析工具 (例如 Chrome DevTools 的 Performance 面板) 查看 JavaScript 的加载和解析时间，判断是否使用了流式解析以及是否存在性能瓶颈。
* **断点调试:**  在 `script_streamer.cc` 或相关文件中设置断点，跟踪 JavaScript 数据流的传递和 V8 引擎的解析过程。

**归纳一下它的功能（第 1 部分）：**

`blink/renderer/bindings/core/v8/script_streamer.cc` 的核心功能是**实现 JavaScript 代码的流式加载和解析，通过与 V8 引擎的紧密协作，利用 Mojo 数据管道高效地将 JavaScript 代码分块地传递给 V8 进行后台编译，从而显著提升页面加载性能。** 它负责管理数据流、处理不同类型的脚本、集成编译提示，并提供错误处理和性能监控机制。它的存在是为了优化用户访问网页时 JavaScript 的加载体验。

Prompt: 
```
这是目录为blink/renderer/bindings/core/v8/script_streamer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/bindings/core/v8/script_streamer.h"

#include <atomic>
#include <memory>
#include <utility>

#include "base/check_op.h"
#include "base/containers/heap_array.h"
#include "base/containers/span.h"
#include "base/memory/ptr_util.h"
#include "base/memory/scoped_refptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/notreached.h"
#include "base/numerics/safe_conversions.h"
#include "base/sequence_checker.h"
#include "base/state_transitions.h"
#include "base/synchronization/lock.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/threading/scoped_blocking_call.h"
#include "base/threading/thread_restrictions.h"
#include "base/types/pass_key.h"
#include "mojo/public/cpp/system/data_pipe_drainer.h"
#include "mojo/public/cpp/system/wait.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/page/v8_compile_hints_histograms.h"
#include "third_party/blink/public/mojom/script/script_type.mojom-blink-forward.h"
#include "third_party/blink/public/mojom/script/script_type.mojom-shared.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_code_cache.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_compile_hints_common.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_compile_hints_consumer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_compile_hints_for_streaming.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_compile_hints_producer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_local_compile_hints_consumer.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/loader/resource/script_resource.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_isolate_data.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_handle.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_persistent.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/loader/fetch/cached_metadata.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/response_body_loader.h"
#include "third_party/blink/renderer/platform/network/mime/mime_type_registry.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/worker_pool.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_mojo.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/deque.h"
#include "third_party/blink/renderer/platform/wtf/forward.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding_registry.h"

namespace WTF {

template <>
struct CrossThreadCopier<mojo_base::BigBuffer> {
  STATIC_ONLY(CrossThreadCopier);
  using Type = mojo_base::BigBuffer;
  static Type Copy(Type&& value) { return std::move(value); }
};

}  // namespace WTF

namespace blink {
namespace {

v8::ScriptType ScriptTypeForStreamingTask(ScriptResource* script_resource) {
  switch (script_resource->GetInitialRequestScriptType()) {
    case mojom::blink::ScriptType::kModule:
      return v8::ScriptType::kModule;
    case mojom::blink::ScriptType::kClassic: {
      // <link rel=preload as=script ref=module.mjs> is a common pattern instead
      // of <link rel=modulepreload>. Try streaming parsing as module instead in
      // these cases (https://crbug.com/1178198).
      if (script_resource->IsUnusedPreload()) {
        if (script_resource->Url().GetPath().ToString().EndsWithIgnoringCase(
                ".mjs")) {
          return v8::ScriptType::kModule;
        }
      }
      return v8::ScriptType::kClassic;
    }
  }
  NOTREACHED();
}

}  // namespace

// SourceStream implements the streaming interface towards V8. The main
// functionality is preparing the data to give to V8 on main thread, and
// actually giving the data (via GetMoreData which is called on a background
// thread).
class SourceStream : public v8::ScriptCompiler::ExternalSourceStream {
 public:
  SourceStream() = default;

  SourceStream(const SourceStream&) = delete;
  SourceStream& operator=(const SourceStream&) = delete;

  ~SourceStream() override = default;

  // Called by V8 on a background thread. Should block until we can return
  // some data. Ownership of the |src| data buffer is passed to the caller,
  // unless |src| is null.
  size_t GetMoreData(const uint8_t** src) override {
    DCHECK(!IsMainThread());
    CHECK(ready_to_run_.IsSet());

    if (load_state_ != ResourceScriptStreamer::LoadingState::kLoading) {
      return 0;
    }

    if (cancelled_.IsSet()) {
      SetFinished(ResourceScriptStreamer::LoadingState::kCancelled);
      return 0;
    }

    if (!initial_data_.empty()) {
      size_t len = initial_data_.size();
      if (src) {
        *src = std::move(initial_data_).leak().data();
      } else {
        initial_data_ = base::HeapArray<uint8_t>();
      }
      return len;
    }

    CHECK(initial_data_.empty());
    CHECK(data_pipe_.is_valid());

    // Start a new two-phase read, blocking until data is available.
    while (true) {
      base::span<const uint8_t> buffer;
      MojoResult result =
          data_pipe_->BeginReadData(MOJO_READ_DATA_FLAG_NONE, buffer);

      switch (result) {
        case MOJO_RESULT_OK: {
          // num_bytes could only be 0 if the handle was being read elsewhere.
          CHECK_GT(buffer.size(), 0u);

          if (src) {
            auto copy_for_script_stream =
                base::HeapArray<uint8_t>::CopiedFrom(buffer);
            *src = std::move(copy_for_script_stream).leak().data();
          }

          // TODO(leszeks): It would be nice to get rid of this second copy, and
          // either share ownership of the chunks, or only give chunks back to
          // the client once the streaming completes.
          Vector<char> copy_for_decoder;
          copy_for_decoder.AppendSpan(base::as_chars(buffer));
          if (absl::holds_alternative<ScriptDecoder*>(script_decoder_)) {
            absl::get<ScriptDecoder*>(script_decoder_)
                ->DidReceiveData(std::move(copy_for_decoder));
          } else {
            CHECK(absl::holds_alternative<ScriptDecoderWithClient*>(
                script_decoder_));
            absl::get<ScriptDecoderWithClient*>(script_decoder_)
                ->DidReceiveData(std::move(copy_for_decoder),
                                 /*send_to_client=*/true);
          }

          result = data_pipe_->EndReadData(buffer.size());
          CHECK_EQ(result, MOJO_RESULT_OK);

          return buffer.size();
        }

        case MOJO_RESULT_SHOULD_WAIT: {
          {
            TRACE_EVENT_END0(
                "v8,devtools.timeline," TRACE_DISABLED_BY_DEFAULT("v8.compile"),
                "v8.parseOnBackgroundParsing");
            TRACE_EVENT_BEGIN0(
                "v8,devtools.timeline," TRACE_DISABLED_BY_DEFAULT("v8.compile"),
                "v8.parseOnBackgroundWaiting");
            base::ScopedAllowBaseSyncPrimitives
                scoped_allow_base_sync_primitives;
            base::ScopedBlockingCall scoped_blocking_call(
                FROM_HERE, base::BlockingType::WILL_BLOCK);

            result = mojo::Wait(data_pipe_.get(), MOJO_HANDLE_SIGNAL_READABLE);
            TRACE_EVENT_END0(
                "v8,devtools.timeline," TRACE_DISABLED_BY_DEFAULT("v8.compile"),
                "v8.parseOnBackgroundWaiting");
            TRACE_EVENT_BEGIN0(
                "v8,devtools.timeline," TRACE_DISABLED_BY_DEFAULT("v8.compile"),
                "v8.parseOnBackgroundParsing");
          }

          if (result != MOJO_RESULT_OK) {
            // If the producer handle was closed, then treat as EOF.
            CHECK_EQ(result, MOJO_RESULT_FAILED_PRECONDITION);
            SetFinished(ResourceScriptStreamer::LoadingState::kLoaded);
            return 0;
          }

          // We were blocked, so check for cancelation again.
          if (cancelled_.IsSet()) {
            SetFinished(ResourceScriptStreamer::LoadingState::kCancelled);
            return 0;
          }

          // Loop to read the data.
          continue;
        }

        case MOJO_RESULT_FAILED_PRECONDITION:
          // If the producer handle was closed, then treat as EOF.
          SetFinished(ResourceScriptStreamer::LoadingState::kLoaded);
          return 0;

        default:
          // Some other error occurred.
          SetFinished(ResourceScriptStreamer::LoadingState::kFailed);
          return 0;
      }
    }
  }

  void DrainRemainingDataWithoutStreaming() {
    DCHECK(!IsMainThread());
    if (load_state_ == ResourceScriptStreamer::LoadingState::kLoading) {
      // Keep reading data until we finish (returning 0). It won't be streaming
      // compiled any more, but it will continue being forwarded to the client.
      while (GetMoreData(nullptr) != 0) {
      }
    }
    CHECK_NE(load_state_, ResourceScriptStreamer::LoadingState::kLoading);
  }

  void Cancel() {
    // The script is no longer needed by the upper layers. Stop streaming
    // it. The next time GetMoreData is called (or woken up), it will return
    // 0, which will be interpreted as EOS by V8 and the parsing will
    // fail. ResourceScriptStreamer::StreamingComplete will be called, and at
    // that point we will release the references to SourceStream.
    cancelled_.Set();
  }

  void TakeDataAndPipeOnMainThread(ScriptResource* resource,
                                   ResourceScriptStreamer* streamer,
                                   mojo::ScopedDataPipeConsumerHandle data_pipe,
                                   ScriptDecoderWithClient* script_decoder) {
    DCHECK(IsMainThread());
    CHECK(data_pipe);
    CHECK(!ready_to_run_.IsSet());
    CHECK(!cancelled_.IsSet());

    // The Resource must still be alive; otherwise we should've cancelled
    // the streaming (if we have cancelled, the background thread is not
    // waiting).
    DCHECK(resource);

    const SharedBuffer* resource_buffer = resource->ResourceBuffer().get();

    CHECK(initial_data_.empty());

    // Get the data that is already in the ResourceBuffer.
    const size_t length = resource_buffer->size();

    if (length > 0) {
      initial_data_ = base::HeapArray<uint8_t>::Uninit(length);

      bool success = resource_buffer->GetBytes(initial_data_);
      CHECK(success);
    }

    data_pipe_ = std::move(data_pipe);
    script_decoder_ = script_decoder;

    CHECK(data_pipe_);
    ready_to_run_.Set();
  }

  void TakeDataAndPipeOnBackgroundThread(
      mojo::ScopedDataPipeConsumerHandle data_pipe,
      ScriptDecoder* script_decoder) {
    CHECK(data_pipe);
    CHECK(!ready_to_run_.IsSet());
    CHECK(!cancelled_.IsSet());
    CHECK(initial_data_.empty());
    data_pipe_ = std::move(data_pipe);
    script_decoder_ = script_decoder;
    ready_to_run_.Set();
  }

  mojo::ScopedDataPipeConsumerHandle ReleaseDataPipe() {
    mojo::ScopedDataPipeConsumerHandle body = std::move(data_pipe_);
    data_pipe_.reset();
    return body;
  }

  ResourceScriptStreamer::LoadingState LoadingState() const {
    return load_state_;
  }

 private:
  void SetFinished(ResourceScriptStreamer::LoadingState state) {
    load_state_ = state;
    data_pipe_.reset();
  }

  // TODO(leszeks): Make this a DCHECK-only flag.
  base::AtomicFlag ready_to_run_;
  base::AtomicFlag cancelled_;

  // Only used by background thread
  ResourceScriptStreamer::LoadingState load_state_ =
      ResourceScriptStreamer::LoadingState::kLoading;

  // The initial data that was already on the Resource, rather than being read
  // directly from the data pipe.
  base::HeapArray<uint8_t> initial_data_;

  mojo::ScopedDataPipeConsumerHandle data_pipe_;
  absl::variant<ScriptDecoderWithClient*, ScriptDecoder*> script_decoder_;
};

std::tuple<ScriptStreamer*, ScriptStreamer::NotStreamingReason>
ScriptStreamer::TakeFrom(ScriptResource* script_resource,
                         mojom::blink::ScriptType expected_type) {
  const v8::ScriptType expected_script_type =
      expected_type == mojom::blink::ScriptType::kClassic
          ? v8::ScriptType::kClassic
          : v8::ScriptType::kModule;
  NotStreamingReason not_streamed_reason = script_resource->NoStreamerReason();
  ScriptStreamer* streamer = script_resource->TakeStreamer();
  if (streamer) {
    if (streamer->IsStreamingSuppressed()) {
      not_streamed_reason = streamer->StreamingSuppressedReason();
      streamer = nullptr;
    } else {
      // When `streamer` is a BackgroundResourceScriptStreamer,
      // `not_streamed_reason` is kBackgroundResponseProcessorWillBeUsed`.
      CHECK(not_streamed_reason == NotStreamingReason::kInvalid ||
            not_streamed_reason ==
                NotStreamingReason::kBackgroundResponseProcessorWillBeUsed);
      not_streamed_reason = NotStreamingReason::kInvalid;
      if (streamer->GetScriptType() != expected_script_type) {
        streamer = nullptr;
        not_streamed_reason = NotStreamingReason::kErrorScriptTypeMismatch;
      }
    }
    return std::make_tuple(streamer, not_streamed_reason);
  }
  return std::make_tuple(nullptr, not_streamed_reason);
}

namespace {

enum class StreamedBoolean {
  // Must match BooleanStreamed in enums.xml.
  kNotStreamed = 0,
  kStreamed = 1,
  kMaxValue = kStreamed
};

void RecordStartedStreamingHistogram(ScriptSchedulingType type,
                                     bool did_use_streamer) {
  StreamedBoolean streamed = did_use_streamer ? StreamedBoolean::kStreamed
                                              : StreamedBoolean::kNotStreamed;
  switch (type) {
    case ScriptSchedulingType::kParserBlocking: {
      UMA_HISTOGRAM_ENUMERATION(
          "WebCore.Scripts.ParsingBlocking.StartedStreaming", streamed);
      break;
    }
    case ScriptSchedulingType::kDefer: {
      UMA_HISTOGRAM_ENUMERATION("WebCore.Scripts.Deferred.StartedStreaming",
                                streamed);
      break;
    }
    case ScriptSchedulingType::kAsync: {
      UMA_HISTOGRAM_ENUMERATION("WebCore.Scripts.Async.StartedStreaming",
                                streamed);
      break;
    }
    default: {
      UMA_HISTOGRAM_ENUMERATION("WebCore.Scripts.Other.StartedStreaming",
                                streamed);
      break;
    }
  }
}

void RecordNotStreamingReasonHistogram(
    ScriptSchedulingType type,
    ScriptStreamer::NotStreamingReason reason) {
  switch (type) {
    case ScriptSchedulingType::kParserBlocking: {
      UMA_HISTOGRAM_ENUMERATION(
          "WebCore.Scripts.ParsingBlocking.NotStreamingReason", reason);
      break;
    }
    case ScriptSchedulingType::kDefer: {
      UMA_HISTOGRAM_ENUMERATION("WebCore.Scripts.Deferred.NotStreamingReason",
                                reason);
      break;
    }
    case ScriptSchedulingType::kAsync: {
      UMA_HISTOGRAM_ENUMERATION("WebCore.Scripts.Async.NotStreamingReason",
                                reason);
      break;
    }
    default: {
      UMA_HISTOGRAM_ENUMERATION("WebCore.Scripts.Other.NotStreamingReason",
                                reason);
      break;
    }
  }
}

}  // namespace

void ScriptStreamer::RecordStreamingHistogram(
    ScriptSchedulingType type,
    bool can_use_streamer,
    ScriptStreamer::NotStreamingReason reason) {
  RecordStartedStreamingHistogram(type, can_use_streamer);
  if (!can_use_streamer) {
    DCHECK_NE(ScriptStreamer::NotStreamingReason::kInvalid, reason);
    RecordNotStreamingReasonHistogram(type, reason);
  }
}

bool ScriptStreamer::ConvertEncoding(
    const AtomicString& encoding_name,
    v8::ScriptCompiler::StreamedSource::Encoding* encoding) {
  // Here's a list of encodings we can use for streaming. These are
  // the canonical names.
  if (encoding_name == "windows-1252" || encoding_name == "ISO-8859-1" ||
      encoding_name == "US-ASCII") {
    *encoding = v8::ScriptCompiler::StreamedSource::WINDOWS_1252;
    return true;
  }
  if (encoding_name == "UTF-8") {
    *encoding = v8::ScriptCompiler::StreamedSource::UTF8;
    return true;
  }
  // We don't stream other encodings; especially we don't stream two
  // byte scripts to avoid the handling of endianness. Most scripts
  // are Latin1 or UTF-8 anyway, so this should be enough for most
  // real world purposes.
  return false;
}

v8_compile_hints::V8LocalCompileHintsConsumer*
ResourceScriptStreamer::GetV8LocalCompileHintsConsumerForTest() const {
  return compile_hints_->GetV8LocalCompileHintsConsumerForTest();
}

bool ResourceScriptStreamer::IsStreamingStarted() const {
  DCHECK(IsMainThread());
  return !!stream_;
}

bool ResourceScriptStreamer::IsStreamingSuppressed() const {
  DCHECK(IsMainThread());
  return suppressed_reason_ != NotStreamingReason::kInvalid;
}

bool ResourceScriptStreamer::IsLoaded() const {
  DCHECK(IsMainThread());
  return loading_state_ != LoadingState::kLoading;
}

bool ResourceScriptStreamer::CanStartStreaming() const {
  DCHECK(IsMainThread());
  return !IsStreamingStarted() && !IsStreamingSuppressed();
}

bool ResourceScriptStreamer::IsFinished() const {
  DCHECK(IsMainThread());
  // We are finished when we know that we won't start streaming later (either
  // because we are streaming already or streaming was suppressed).
  return IsLoaded() && !CanStartStreaming();
}

bool ResourceScriptStreamer::IsClientDetached() const {
  DCHECK(IsMainThread());
  return !response_body_loader_client_;
}

void ResourceScriptStreamer::StreamingCompleteOnBackgroundThread(
    LoadingState state) {
  DCHECK(!IsMainThread());

  // notifyFinished might already be called, or it might be called in the
  // future (if the parsing finishes earlier because of a parse error).
  script_decoder_->FinishDecode(
      CrossThreadBindOnce(&ResourceScriptStreamer::StreamingComplete,
                          WrapCrossThreadPersistent(this), state));

  // The task might be the only remaining reference to the ScriptStreamer, and
  // there's no way to guarantee that this function has returned before the task
  // is ran, so we should not access the "this" object after posting the task.
}

void ResourceScriptStreamer::Cancel() {
  DCHECK(IsMainThread());
  // The upper layer doesn't need the script any more, but streaming might
  // still be ongoing. Tell SourceStream to try to cancel it whenever it gets
  // the control the next time. It can also be that V8 has already completed
  // its operations and streamingComplete will be called soon.
  response_body_loader_client_.Release();
  script_resource_.Release();
  if (stream_)
    stream_->Cancel();
  CHECK(IsClientDetached());
}

void ResourceScriptStreamer::SuppressStreaming(NotStreamingReason reason) {
  DCHECK(IsMainThread());
  CHECK_EQ(suppressed_reason_, NotStreamingReason::kInvalid);
  CHECK_NE(reason, NotStreamingReason::kInvalid);
  suppressed_reason_ = reason;
}

void ResourceScriptStreamer::RunScriptStreamingTask(
    std::unique_ptr<v8::ScriptCompiler::ScriptStreamingTask> task,
    ResourceScriptStreamer* streamer,
    SourceStream* stream) {
  // TODO(leszeks): Add flow event data again
  TRACE_EVENT_BEGIN1(
      "v8,devtools.timeline," TRACE_DISABLED_BY_DEFAULT("v8.compile"),
      "v8.parseOnBackground", "data", [&](perfetto::TracedValue context) {
        inspector_parse_script_event::Data(std::move(context),
                                           streamer->ScriptResourceIdentifier(),
                                           streamer->ScriptURLString());
      });

  TRACE_EVENT_BEGIN0(
      "v8,devtools.timeline," TRACE_DISABLED_BY_DEFAULT("v8.compile"),
      "v8.parseOnBackgroundParsing");
  // Running the task can and will block: SourceStream::GetSomeData will get
  // called and it will block and wait for data from the network.
  task->Run();

  // V8 may have exited early due to a parsing error, so make sure we finish
  // draining the datapipe to the client.
  // TODO(leszeks): This could be done asynchronously, using a mojo watcher.
  stream->DrainRemainingDataWithoutStreaming();

  TRACE_EVENT_END0(
      "v8,devtools.timeline," TRACE_DISABLED_BY_DEFAULT("v8.compile"),
      "v8.parseOnBackgroundParsing");

  // Send a single callback back to the streamer signifying that the streaming
  // is complete, and how it completed (success/fail/cancelled). The streamer
  // will forward the state to the client on the main thread. We don't send the
  // success/fail/cancelled client callback in separate tasks, as they can kill
  // the (context-specific) task runner, which would make this StreamingComplete
  // afterward fail to post.
  streamer->StreamingCompleteOnBackgroundThread(stream->LoadingState());

  TRACE_EVENT_END0(
      "v8,devtools.timeline," TRACE_DISABLED_BY_DEFAULT("v8.compile"),
      "v8.parseOnBackground");

  // TODO(crbug.com/1021571); Remove this once the last event stops being
  // dropped.
  TRACE_EVENT_END0(
      "v8,devtools.timeline," TRACE_DISABLED_BY_DEFAULT("v8.compile"),
      "v8.parseOnBackground2");
}

// Try to start a task streaming the script from the datapipe, with the task
// taking ownership of the datapipe and weak ownership of the client. Returns
// true if streaming succeeded and false otherwise.
//
// Streaming may fail to start because:
//
//   * The encoding is invalid (not UTF-8 or one-byte data)
//   * The script is too small to check for a byte-order marker
//   * There is a code cache for this script already
//   * V8 failed to create a script streamer
//
// If this method returns true, the datapipe handle will be cleared and the
// streaming task becomes responsible for draining the datapipe and forwarding
// data to the client. Otherwise, we should continue as if this were a no-op.
bool ResourceScriptStreamer::TryStartStreamingTask() {
  DCHECK(IsMainThread());
  if (!CanStartStreaming())
    return false;

  // Skip non-JS modules based on the mime-type.
  // TODO(crbug/1132413),TODO(crbug/1061857): Disable streaming for non-JS
  // based the specific import statements.
  if (script_type_ == v8::ScriptType::kModule &&
      !MIMETypeRegistry::IsSupportedJavaScriptMIMEType(
          script_resource_->GetResponse().HttpContentType())) {
    SuppressStreaming(NotStreamingReason::kNonJavascriptModule);
    return false;
  }

  // Even if the first data chunk is small, the script can still be big enough -
  // wait until the next data chunk comes before deciding whether to start the
  // streaming.
  if (!script_resource_->ResourceBuffer() ||
      script_resource_->ResourceBuffer()->size() < kMaximumLengthOfBOM) {
    CHECK(!IsLoaded());
    return false;
  }

  {
    // Check for BOM (byte order marks), because that might change our
    // understanding of the data encoding.
    std::array<char, kMaximumLengthOfBOM> maybe_bom = {};
    if (!script_resource_->ResourceBuffer()->GetBytes(
            base::as_writable_byte_span(maybe_bom))) {
      NOTREACHED();
    }

    std::unique_ptr<TextResourceDecoder> decoder(
        std::make_unique<TextResourceDecoder>(TextResourceDecoderOptions(
            TextResourceDecoderOptions::kPlainTextContent,
            WTF::TextEncoding(script_resource_->Encoding()))));
    decoder->CheckForBOM(maybe_bom);

    // The encoding may change when we see the BOM. Check for BOM now
    // and update the encoding from the decoder when necessary. Suppress
    // streaming if the encoding is unsupported.
    if (!ConvertEncoding(decoder->Encoding().GetName(), &encoding_)) {
      SuppressStreaming(NotStreamingReason::kEncodingNotSupported);
      return false;
    }
  }

  if (script_resource_->CacheHandler()) {
    // Exclude scripts for which we're not going to generate metadata.
    V8CodeCache::RecordCacheGetStatistics(script_resource_->CacheHandler());
  }

  // Here we can't call Check on the cache handler because it requires the
  // script source, which would require having already loaded the script. It is
  // OK at this point to disable streaming even though we might end up rejecting
  // the cached data later, because we expect that the cached data is usually
  // acceptable. If we detect a content mismatch once the content is loaded,
  // then we reset the code cache entry to just a timestamp, so this condition
  // will allow streaming the next time we load the resource.
  if (V8CodeCache::HasCodeCache(script_resource_->CacheHandler(),
                                CachedMetadataHandler::kAllowUnchecked)) {
    // The resource has a code cache entry, so it's unnecessary to stream
    // and parse the code.
    // TODO(leszeks): Can we even reach this code path with data pipes?
    stream_ = nullptr;
    source_.reset();
    SuppressStreaming(ScriptStreamer::NotStreamingReason::kHasCodeCache);
    return false;
  }

  DCHECK(!stream_);
  DCHECK(!source_);
  auto stream_ptr = std::make_unique<SourceStream>();
  stream_ = stream_ptr.get();
  // |source_| takes ownership of |stream_|, and will keep |stream_| alive until
  // |source_| is destructed.
  source_ = std::make_unique<v8::ScriptCompiler::StreamedSource>(
      std::move(stream_ptr), encoding_);

  const bool has_hot_timestamp =
      V8CodeCache::HasHotTimestamp(script_resource_->CacheHandler());
  compile_hints_ =
      v8_compile_hints::CompileHintsForStreaming::Builder(
          script_resource_->GetV8CrowdsourcedCompileHintsProducer(),
          script_resource_->GetV8CrowdsourcedCompileHintsConsumer(),
          script_resource_->Url(),
          script_resource_->GetV8CompileHintsMagicCommentMode())
          .Build((V8CodeCache::HasCompileHints(
                      script_resource_->CacheHandler(),
                      CachedMetadataHandler::kAllowUnchecked) &&
                  has_hot_timestamp)
                     ? V8CodeCache::GetCachedMetadataForCompileHints(
                           script_resource_->CacheHandler(),
                           CachedMetadataHandler::kAllowUnchecked)
                     : nullptr,
                 has_hot_timestamp);
  CHECK(compile_hints_);

  v8::Isolate* isolate = script_resource_->GetIsolateOrNull();
  if (!isolate) {
    stream_ = nullptr;
    source_.reset();
    SuppressStreaming(NotStreamingReason::kContextNotValid);
    return false;
  }

  // Isolate is valid to pass to another thread because it is the main thread
  // isolate that is never destroyed.
  std::unique_ptr<v8::ScriptCompiler::ScriptStreamingTask>
      script_streaming_task =
          base::WrapUnique(v8::ScriptCompiler::StartStreaming(
              isolate, source_.get(), script_type_,
              compile_hints_->compile_options(),
              compile_hints_->GetCompileHintCallback(),
              compile_hints_->GetCompileHintCallbackData()));

  if (!script_streaming_task) {
    // V8 cannot stream the script.
    stream_ = nullptr;
    source_.reset();
    SuppressStreaming(NotStreamingReason::kV8CannotStream);
    return false;
  }

  TRACE_EVENT_WITH_FLOW1(
      TRACE_DISABLED_BY_DEFAULT("v8.compile"), "v8.streamingCompile.start",
      this, TRACE_EVENT_FLAG_FLOW_OUT, "data",
      [&](perfetto::TracedValue context) {
        inspector_parse_script_event::Data(
            std::move(context), ScriptResourceIdentifier(), ScriptURLString());
      });

  stream_->TakeDataAndPipeOnMainThread(
      script_resource_, this, std::move(data_pipe_), script_decoder_.get());

  // This reset will also cancel the watcher.
  watcher_.reset();

  // Script streaming tasks are high priority, as they can block the parser,
  // and they can (and probably will) block during their own execution as
  // they wait for more input.
  // TODO(leszeks): Decrease the priority of these tasks where possible.
  worker_pool::PostTask(
      FROM_HERE, {base::TaskPriority::USER_BLOCKING, base::MayBlock()},
      CrossThreadBindOnce(RunScriptStreamingTask,
                          std::move(script_streaming_task),
                          WrapCrossThreadPersistent(this),
                          WTF::CrossThreadUnretained(stream_)));

  return true;
}

v8::ScriptType ResourceScriptStreamer::GetScriptType() const {
  return script_type_;
}

ResourceScriptStreamer::ResourceScriptStreamer(
    ScriptResource* script_resource,
    mojo::ScopedDataPipeConsumerHandle data_pipe,
    ResponseBodyLoaderClient* response_body_loader_client,
    std::unique_ptr<TextResourceDecoder> decoder,
    scoped_refptr<base::SingleThreadTaskRunner> loading_task_runner)
    : script_resource_(script_resource),
      response_body_loader_client_(response_body_loader_client),
      script_decoder_(
          ScriptDecoderWithClient::Create(response_body_loader_client,
                                          std::move(decoder),
                                          loading_task_runner)),
      data_pipe_(std::move(data_pipe)),
      script_url_string_(script_resource->Url().GetString()),
      script_resource_identifier_(script_resource->InspectorId()),
      // Unfortunately there's no dummy encoding value in the enum; let's use
      // one we don't stream.
      encoding_(v8::ScriptCompiler::StreamedSource::TWO_BYTE),
      script_type_(ScriptTypeForStreamingTask(script_resource)) {
  watcher_ = std::make_unique<mojo::SimpleWatcher>(
      FROM_HERE, mojo::SimpleWatcher::ArmingPolicy::MANUAL,
      loading_task_runner);

  watcher_->Watch(
      data_pipe_.get(), MOJO_HANDLE_SIGNAL_READABLE,
      MOJO_TRIGGER_CONDITION_SIGNALS_SATISFIED,
      WTF::BindRepeating(&ResourceScriptStreamer::OnDataPipeReadable,
                         WrapWeakPersistent(this)));

  MojoResult ready_result;
  mojo::HandleSignalsState ready_state;
  MojoResult rv = watcher_->Arm(&ready_result, &ready_state);
  if (rv == MOJO_RESULT_OK)
    return;

  DCHECK_EQ(MOJO_RESULT_FAILED_PRECONDITION, rv);
  OnDataPipeReadable(ready_result, ready_state);
}

void ResourceScriptStreamer::OnDataPipeReadable(
    MojoResult result,
    const mojo::HandleSignalsState& state) {
  if (IsClientDetached())
    return;

  switch (result) {
    case MOJO_RESULT_OK:
      // All good, so read the data that we were notified that we received.
      break;

    case MOJO_RESULT_CANCELLED:
      // The consumer handle got closed, which means this script is done
      // loading, and did so without streaming (otherwise the watcher wouldn't
      // have been armed, and the handle ownership would have passed to the
      // streaming task.
      watcher_.reset();
      LoadCompleteWithoutStreaming(LoadingState::kCancelled,
                                   NotStreamingReason::kLoadingCancelled);
      return;

    case MOJO_RESULT_FAILED_PRECONDITION:
      // This means the producer finished and we never started streaming. This
      // must be because we suppressed streaming earlier, or never got enough
      // data to start streaming.
      CHECK(IsStreamingSuppressed() || !script_resource_->ResourceBuffer() ||
            script_resource_->ResourceBuffer()->size() < kMaximumLengthOfBOM);
      watcher_.reset();
      // Pass kScriptTooSmall for the !IsStreamingSuppressed() case, it won't
      // override an existing streaming reason.
      LoadCompleteWithoutStreaming(LoadingState::kLoaded,
                                   NotStreamingReason::kScriptTooSmall);
      return;

    case MOJO_RESULT_SHOULD_WAIT:
      NOTREACHED();

    default:
      // Some other error occurred.
      watcher_.reset();
      LoadCompleteWithoutStreaming(LoadingState::kFailed,
                                   NotStreamingReason::kErrorOccurred);
      return;
  }
 
"""


```