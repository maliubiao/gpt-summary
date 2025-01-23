Response:
The user wants me to analyze a C++ source code file (`script_streamer.cc`) from the Chromium Blink engine.
Specifically, they want me to:

1. **Summarize the functionality** of the provided code snippet (which is part 2 of 3).
2. **Identify relationships** with web technologies (JavaScript, HTML, CSS) and provide examples.
3. **Illustrate logical reasoning** with input/output examples.
4. **Highlight common user/programming errors** related to this code.
5. **Explain user actions** that lead to this code being executed, as debugging clues.

Since this is part 2, I need to focus on the functionalities present in this specific segment of the code.

**Plan:**

1. **Read and understand the code:**  Identify the classes and methods defined in this snippet.
2. **Summarize functionality:** Describe the purpose of each class and the core operations performed by the methods.
3. **Relate to web technologies:** Analyze how these operations are connected to the loading and processing of scripts in a web browser.
4. **Logical reasoning:** Find examples of conditional logic and data processing that can be illustrated with input/output.
5. **Common errors:**  Look for error handling, assertions, and potential points of failure.
6. **User actions:**  Trace back how the script loading process initiated by a user action could lead to this code being executed.
这是 `blink/renderer/bindings/core/v8/script_streamer.cc` 文件的一部分，主要负责在后台线程处理脚本资源流式加载和编译。

**功能归纳 (针对提供的代码片段):**

这段代码主要实现了 `BackgroundResourceScriptStreamer::BackgroundProcessor` 类，负责在后台线程处理脚本资源的下载和初步处理，以便进行流式编译。其主要功能包括：

1. **接收和处理网络响应：**  `MaybeStartProcessingResponse` 方法接收来自网络的响应头 (`URLResponseHeadPtr`) 和响应体数据管道 (`mojo::ScopedDataPipeConsumerHandle`)，以及可能的代码缓存元数据 (`cached_metadata`).
2. **MIME 类型检查：**  对于模块脚本，会检查响应的 MIME 类型是否为支持的 JavaScript 类型。
3. **字符编码处理：**  根据响应头中的 `charset` 信息更新脚本的字符编码。
4. **代码缓存处理 (如果启用 `BackgroundCodeCacheDecoderStart` 特性):**
   - 如果存在代码缓存元数据，则尝试创建一个 `ConsumeCodeCacheTask` 在后台线程消费代码缓存。
   - 如果创建成功，则启动一个单独的任务 `RunConsumingCodeCacheTask` 在后台线程执行代码缓存的消费。
   - 同时，创建一个 `DataPipeScriptDecoder` 来解码脚本内容。
5. **编译提示处理：** 如果没有可用的代码缓存，则构建用于流式编译的编译提示 (`CompileHintsForStreaming`)。
6. **数据管道监听：**  使用 `mojo::SimpleWatcher` 监听数据管道 (`body_`) 的可读状态。
7. **尝试启动流式处理任务：** `TryStartStreamingTask` 方法会在数据管道中有足够的数据时被调用，用于检测 BOM (Byte Order Mark) 并确定脚本编码，然后启动 `ScriptStreamingTask` 在后台线程进行流式编译。
8. **脚本解码：**  创建 `ScriptDecoder`  用于解码脚本内容。
9. **流式数据传输：**  `SourceStream` 将从数据管道读取的数据传递给 `ScriptDecoder`。
10. **错误处理和状态管理：** 使用 `BackgroundProcessorState` 枚举管理后台处理器的状态，并在不同阶段进行状态检查和转换。
11. **抑制流式处理：**  在某些情况下 (例如，非 JavaScript 模块、存在代码缓存但特性未启用、编码不支持、脚本太小、发生错误等)，会调用 `SuppressStreaming` 来阻止流式编译。
12. **完成回调：** 当后台处理完成时，会调用 `Client::DidFinishBackgroundResponseProcessor` 将处理结果返回给主线程。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **JavaScript:** 这是处理 JavaScript 脚本的核心逻辑。
    * **例子：** 当浏览器加载一个 `<script src="script.js"></script>` 标签时，网络请求会返回 JavaScript 代码。这段代码负责在后台线程接收和预处理 `script.js` 的内容，以便 V8 引擎可以进行流式编译，从而加快脚本的解析和执行速度。
* **HTML:** HTML 中的 `<script>` 标签触发了脚本的加载流程，最终会调用到这里的代码。
    * **例子：**  HTML 中内联的 `<script>` 标签或者通过 `src` 属性引用的外部脚本，其内容都会被此处的代码处理。
* **CSS:**  这段代码直接与 CSS 无关。CSS 文件的加载和解析有独立的流程。

**逻辑推理及假设输入与输出：**

假设输入：

1. **网络响应头：**
   ```
   HTTP/1.1 200 OK
   Content-Type: application/javascript; charset=utf-8
   ```
2. **数据管道内容 (部分):**  假设脚本内容的前几个字节是 UTF-8 编码的 JavaScript 代码，例如：`const a = 1;`

逻辑推理：

* `MaybeStartProcessingResponse` 接收到响应头和数据管道。
* 由于 `Content-Type` 是 `application/javascript`，且字符集为 `utf-8`，所以 MIME 类型检查通过，编码被设置为 UTF-8。
* `TryStartStreamingTask` 被调用。
* 从数据管道读取前几个字节，检测 BOM。由于是 UTF-8，通常没有 BOM，或者 BOM 会被正确识别。
* 创建 `ScriptDecoder` 和 `SourceStream`。
* `SourceStream` 开始从数据管道读取数据，并通过 `ScriptDecoder` 进行解码。
* 后台会启动 `v8::ScriptCompiler::ScriptStreamingTask` 来进行流式编译。

预期输出：

* `BackgroundProcessor` 的状态会从 `kWaitingForResponse` 经过 `kResponseReceived` 到达 `kWaitingForParseResult` (假设流式编译正常启动)。
* `ScriptStreamingTask` 会在后台线程运行，逐步编译脚本。
* 解码后的脚本内容会被传递给 V8 引擎。

**用户或编程常见的使用错误及举例说明：**

* **MIME 类型配置错误：** 服务器返回的 JavaScript 文件的 `Content-Type` 不是标准的 JavaScript MIME 类型 (例如，返回 `text/plain`)。
    * **例子：** 用户配置错误的 Web 服务器，将 `.js` 文件的 MIME 类型设置为 `text/plain`。这将导致 `MaybeStartProcessingResponse` 中的 MIME 类型检查失败 (对于模块脚本)，并调用 `SuppressStreaming(NotStreamingReason::kNonJavascriptModuleBackground)`。
* **字符编码不匹配：** 服务器声明的字符编码与实际文件编码不一致。
    * **例子：**  服务器声明 `charset=iso-8859-1`，但脚本文件实际是 UTF-8 编码。这可能导致 `ScriptDecoder` 解码错误，甚至导致 V8 编译失败。虽然这里的代码会尝试根据响应头设置编码，但如果响应头信息不正确，仍然可能出错。
* **代码缓存问题：**  代码缓存元数据损坏或与当前 V8 版本不兼容。
    * **例子：** 用户清除了浏览器的缓存，但某些代码缓存文件没有被完全清除或损坏。当尝试消费这些损坏的代码缓存时，可能会导致错误，但这段代码主要处理启动消费的流程，具体的消费错误会在 V8 内部处理。
* **数据管道错误：** 在极少数情况下，Mojo 数据管道可能发生错误，导致数据读取失败。
    * **例子：** 系统资源紧张或其他底层错误导致数据管道不可用。这会在 `TryStartStreamingTask` 中读取数据时返回非 `MOJO_RESULT_OK` 的结果，从而触发错误处理逻辑。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中输入网址或点击链接：** 这会发起一个网络请求。
2. **浏览器解析 HTML：** 当浏览器接收到 HTML 响应后，开始解析 HTML 内容。
3. **遇到 `<script>` 标签：** 解析器遇到 `<script>` 标签，无论是内联脚本还是通过 `src` 引入的外部脚本。
4. **发起脚本资源请求：** 如果是外部脚本，浏览器会发起一个新的网络请求去获取脚本资源。
5. **接收到脚本响应头和响应体：** 网络层接收到脚本资源的响应头和响应体数据流。
6. **创建 `ResourceScriptStreamer`：** 在 Blink 渲染引擎中，会为该脚本资源创建一个 `ResourceScriptStreamer` 对象。
7. **创建 `BackgroundResourceScriptStreamer` 和 `BackgroundProcessor`：**  `ResourceScriptStreamer` 会创建一个 `BackgroundResourceScriptStreamer` 来处理后台的流式加载和编译，并创建 `BackgroundProcessor` 实例来执行具体的后台处理逻辑。
8. **调用 `MaybeStartProcessingResponse`：**  网络栈会将响应头和数据管道传递给 `BackgroundProcessor` 的 `MaybeStartProcessingResponse` 方法。
9. **后续处理：**  根据响应头、数据内容和是否启用代码缓存等因素，执行 `TryStartStreamingTask`、创建解码器、启动流式编译任务等操作。

**调试线索：**

* 如果脚本加载缓慢或失败，可以检查网络请求是否成功，响应头是否正确（特别是 `Content-Type` 和 `charset`）。
* 可以通过 Chrome DevTools 的 Network 面板查看脚本资源的请求和响应头信息。
* 可以使用 `chrome://tracing` 或 Perfetto 等工具来追踪 V8 的编译过程，查看是否有流式编译的事件发生以及是否发生错误。
* 如果怀疑代码缓存问题，可以尝试清除浏览器缓存并重新加载页面。
* 可以设置断点在 `MaybeStartProcessingResponse` 和 `TryStartStreamingTask` 等关键方法中，查看数据管道的状态和处理流程。

### 提示词
```
这是目录为blink/renderer/bindings/core/v8/script_streamer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
CHECK(state.readable());
  CHECK(data_pipe_);

  base::span<const uint8_t> data;
  MojoReadDataFlags flags_to_pass = MOJO_READ_DATA_FLAG_NONE;
  MojoResult begin_read_result = data_pipe_->BeginReadData(flags_to_pass, data);
  // There should be data, so this read should succeed.
  CHECK_EQ(begin_read_result, MOJO_RESULT_OK);

  std::string_view chars = base::as_string_view(data);
  response_body_loader_client_->DidReceiveData(chars);
  script_decoder_->DidReceiveData(Vector<char>(chars),
                                  /*send_to_client=*/false);

  MojoResult end_read_result = data_pipe_->EndReadData(data.size());

  CHECK_EQ(end_read_result, MOJO_RESULT_OK);

  if (TryStartStreamingTask()) {
    return;
  }

  // TODO(leszeks): Depending on how small the chunks are, we may want to
  // loop until a certain number of bytes are synchronously read rather than
  // going back to the scheduler.
  watcher_->ArmOrNotify();
}

ResourceScriptStreamer::~ResourceScriptStreamer() = default;

void ResourceScriptStreamer::Prefinalize() {
  // Reset and cancel the watcher. This has to be called in the prefinalizer,
  // rather than relying on the destructor, as accesses by the watcher of the
  // script resource between prefinalization and destruction are invalid. See
  // https://crbug.com/905975#c34 for more details.
  watcher_.reset();

  // Cancel any on-going streaming.
  Cancel();
}

void ResourceScriptStreamer::Trace(Visitor* visitor) const {
  visitor->Trace(script_resource_);
  visitor->Trace(response_body_loader_client_);
  ScriptStreamer::Trace(visitor);
}

void ResourceScriptStreamer::StreamingComplete(LoadingState loading_state) {
  TRACE_EVENT_WITH_FLOW2(
      TRACE_DISABLED_BY_DEFAULT("v8.compile"), "v8.streamingCompile.complete",
      this, TRACE_EVENT_FLAG_FLOW_IN, "streaming_suppressed",
      IsStreamingSuppressed(), "data", [&](perfetto::TracedValue context) {
        inspector_parse_script_event::Data(
            std::move(context), ScriptResourceIdentifier(), ScriptURLString());
      });

  // The background task is completed; do the necessary ramp-down in the main
  // thread.
  DCHECK(IsMainThread());

  AdvanceLoadingState(loading_state);

  // Sending a finished notification to the client also indicates that streaming
  // completed.
  SendClientLoadFinishedCallback();
}

void ResourceScriptStreamer::LoadCompleteWithoutStreaming(
    LoadingState state,
    NotStreamingReason no_streaming_reason) {
  // We might have previously suppressed streaming, in which case we want to
  // keep the previous reason and not re-suppress.
  if (!IsStreamingSuppressed()) {
    SuppressStreaming(no_streaming_reason);
  }
  AdvanceLoadingState(state);

  // Make sure decoding is finished before finishing the load.
  script_decoder_->FinishDecode(CrossThreadBindOnce(
      &ResourceScriptStreamer::SendClientLoadFinishedCallback,
      WrapCrossThreadPersistent(this)));
}

void ResourceScriptStreamer::SendClientLoadFinishedCallback() {
  // Don't do anything if we're detached, there's no client to send signals to.
  if (IsClientDetached())
    return;

  CHECK(IsFinished());

  switch (loading_state_) {
    case LoadingState::kLoading:
      CHECK(false);
      break;
    case LoadingState::kCancelled:
      response_body_loader_client_->DidCancelLoadingBody();
      break;
    case LoadingState::kFailed:
      response_body_loader_client_->DidFailLoadingBody();
      break;
    case LoadingState::kLoaded:
      response_body_loader_client_->DidFinishLoadingBody();
      break;
  }

  response_body_loader_client_.Release();
}

void ResourceScriptStreamer::AdvanceLoadingState(LoadingState new_state) {
  switch (loading_state_) {
    case LoadingState::kLoading:
      CHECK(new_state == LoadingState::kLoaded ||
            new_state == LoadingState::kFailed ||
            new_state == LoadingState::kCancelled);
      break;
    case LoadingState::kLoaded:
    case LoadingState::kFailed:
    case LoadingState::kCancelled:
      CHECK(false);
      break;
  }

  loading_state_ = new_state;
  CheckState();
}

void ResourceScriptStreamer::CheckState() const {
  switch (loading_state_) {
    case LoadingState::kLoading:
      // If we are still loading, we either
      //   1) Are still waiting for enough data to come in to start streaming,
      //   2) Have already started streaming, or
      //   3) Have suppressed streaming.
      // TODO(leszeks): This check, with the current implementation, always
      // returns true. We should either try to check something stronger, or get
      // rid of it.
      CHECK(CanStartStreaming() || IsStreamingStarted() ||
            IsStreamingSuppressed());
      break;
    case LoadingState::kLoaded:
    case LoadingState::kFailed:
    case LoadingState::kCancelled:
      // Otherwise, if we aren't still loading, we either
      //   1) Have already started streaming, or
      //   2) Have suppressed streaming.
      CHECK(IsStreamingStarted() || IsStreamingSuppressed());
      break;
  }
}

class InlineSourceStream final
    : public v8::ScriptCompiler::ExternalSourceStream {
 public:
  explicit InlineSourceStream(const String& text) : text_(text) {}
  ~InlineSourceStream() override = default;

  size_t GetMoreData(const uint8_t** src) override {
    if (!text_) {
      // The V8 scanner requires a valid pointer when using TWO_BYTE sources,
      // even if the length is 0.
      *src = new uint8_t[0];
      return 0;
    }

    auto text_bytes = text_.RawByteSpan();
    size_t size = text_bytes.size();
    auto data_copy = base::HeapArray<uint8_t>::CopiedFrom(text_bytes);
    text_ = String();

    *src = std::move(data_copy).leak().data();
    return size;
  }

 private:
  String text_;
};

BackgroundInlineScriptStreamer::BackgroundInlineScriptStreamer(
    v8::Isolate* isolate,
    const String& text,
    v8::ScriptCompiler::CompileOptions compile_options) {
  auto stream = std::make_unique<InlineSourceStream>(text);
  source_ = std::make_unique<v8::ScriptCompiler::StreamedSource>(
      std::move(stream), text.Is8Bit()
                             ? v8::ScriptCompiler::StreamedSource::ONE_BYTE
                             : v8::ScriptCompiler::StreamedSource::TWO_BYTE);

  // We don't generate code caches for inline scripts, so we never pass the
  // kFollowCompileHintsMagicComment compile option.
  CHECK((compile_options &
         v8::ScriptCompiler::kFollowCompileHintsMagicComment) == 0);
  task_ = base::WrapUnique(v8::ScriptCompiler::StartStreaming(
      isolate, source_.get(), v8::ScriptType::kClassic, compile_options));
}

void BackgroundInlineScriptStreamer::Run() {
  TRACE_EVENT0("blink", "BackgroundInlineScriptStreamer::Run");
  if (cancelled_.IsSet())
    return;

  started_.Set();
  task_->Run();
  task_.reset();

  // We signal an event here instead of posting a task to the main thread
  // because it's possible the task wouldn't be run by the time the script
  // streamer is needed. This allows us to compile the inline script right up to
  // when it is needed. If the script hasn't finished compiling, the main thread
  // will block while it finishes on the worker thread. The worker thread should
  // have already gotten a head start, so this should block the main thread for
  // less time than the compile would have taken.
  event_.Signal();
}

v8::ScriptCompiler::StreamedSource* BackgroundInlineScriptStreamer::Source(
    v8::ScriptType expected_type) {
  TRACE_EVENT0("blink", "BackgroundInlineScriptStreamer::Source");
  SCOPED_UMA_HISTOGRAM_TIMER_MICROS("WebCore.Scripts.InlineStreamerWaitTime");
  DCHECK(IsMainThread());
  DCHECK_EQ(expected_type, v8::ScriptType::kClassic);
  static const base::FeatureParam<base::TimeDelta> kWaitTimeoutParam{
      &features::kPrecompileInlineScripts, "inline-script-timeout",
      base::Milliseconds(0)};
  // Make sure the script has finished compiling in the background. See comment
  // above in Run().
  bool signaled = event_.TimedWait(kWaitTimeoutParam.Get());
  base::UmaHistogramBoolean("WebCore.Scripts.InlineStreamerTimedOut",
                            !signaled);
  if (!signaled)
    return nullptr;
  return source_.get();
}

// static
InlineScriptStreamer* InlineScriptStreamer::From(
    scoped_refptr<BackgroundInlineScriptStreamer> streamer) {
  return MakeGarbageCollected<InlineScriptStreamer>(std::move(streamer));
}

namespace {

enum class BackgroundProcessorState {
  kWaitingForResponse = 0,
  kResponseReceived,
  kCheckingEncoding,
  kWaitingForDataPipeReadable,
  kWaitingForParseResult,
  kWaitingForConsumeCodeCacheResultAndDecodedScript,
  kWaitingForConsumeCodeCacheResult,
  kWaitingForDecodedScript,
  kStreamingSupressed,
  kFinished,
};

#if DCHECK_IS_ON()
std::ostream& operator<<(std::ostream& o, const BackgroundProcessorState& s) {
  return o << static_cast<unsigned>(s);
}
#endif  // DCHECK_IS_ON()

std::unique_ptr<v8::ScriptCompiler::ConsumeCodeCacheTask>
MaybeCreateConsumeCodeCacheTask(std::optional<mojo_base::BigBuffer>& big_buffer,
                                const String& encoding,
                                v8::Isolate* isolate,
                                bool& has_code_cache,
                                v8::ScriptType script_type) {
  CHECK(!has_code_cache);
  if (script_type == v8::ScriptType::kModule) {
    // Currently ModuleScript doesn't support off-thread cache consumption.
    return nullptr;
  }
  if (!big_buffer) {
    return nullptr;
  }
  scoped_refptr<CachedMetadata> metadata =
      CachedMetadata::CreateFromSerializedData(*big_buffer);
  if (!metadata) {
    return nullptr;
  }
  std::unique_ptr<v8::ScriptCompiler::ConsumeCodeCacheTask> task;
  if (V8CodeCache::HasCodeCache(*metadata, encoding)) {
    has_code_cache = true;
    if (features::kBackgroundCodeCacheDecoderStart.Get()) {
      task.reset(v8::ScriptCompiler::StartConsumingCodeCacheOnBackground(
          isolate, V8CodeCache::CreateCachedData(metadata)));
    }
  }
  absl::variant<Vector<uint8_t>, mojo_base::BigBuffer> drained_data =
      std::move(*metadata).DrainSerializedData();
  CHECK(absl::holds_alternative<mojo_base::BigBuffer>(drained_data));
  big_buffer = std::move(absl::get<mojo_base::BigBuffer>(drained_data));
  return task;
}

std::unique_ptr<v8_compile_hints::CompileHintsForStreaming>
BuildCompileHintsForStreaming(
    v8_compile_hints::CompileHintsForStreaming::Builder& builder,
    std::optional<mojo_base::BigBuffer>& big_buffer,
    const String& encoding) {
  // Same as the HasCodeCache() method above, this method creates a
  // CachedMetadata from the the passed BigBuffer and passes it to
  // V8CodeCache::HasHotCompileHints(). And then takes the BigBuffer from the
  // CachedMetadata and set it back to the input argument `big_buffer`.
  scoped_refptr<CachedMetadata> metadata =
      big_buffer ? CachedMetadata::CreateFromSerializedData(*big_buffer)
                 : nullptr;

  V8CodeCache::RecordCacheGetStatistics(metadata.get(), encoding);
  std::unique_ptr<v8_compile_hints::CompileHintsForStreaming> result =
      std::move(builder).Build(
          (metadata && V8CodeCache::HasHotCompileHints(*metadata, encoding))
              ? metadata
              : nullptr,
          metadata && V8CodeCache::HasHotTimestamp(*metadata, encoding));
  if (metadata) {
    absl::variant<Vector<uint8_t>, mojo_base::BigBuffer> drained_data =
        std::move(*metadata).DrainSerializedData();
    CHECK(absl::holds_alternative<mojo_base::BigBuffer>(drained_data));
    big_buffer = std::move(absl::get<mojo_base::BigBuffer>(drained_data));
  }
  return result;
}

}  // namespace

BackgroundResourceScriptStreamer::Result::Result(
    String decoded_data,
    std::unique_ptr<ParkableStringImpl::SecureDigest> digest,
    std::unique_ptr<v8::ScriptCompiler::StreamedSource> streamed_source)
    : decoded_data(std::move(decoded_data)),
      digest(std::move(digest)),
      streamed_source(std::move(streamed_source)) {}

BackgroundResourceScriptStreamer::Result::Result(
    String decoded_data,
    std::unique_ptr<ParkableStringImpl::SecureDigest> digest,
    std::unique_ptr<v8::ScriptCompiler::ConsumeCodeCacheTask>
        consume_code_cache_task)
    : decoded_data(std::move(decoded_data)),
      digest(std::move(digest)),
      consume_code_cache_task(std::move(consume_code_cache_task)) {}

class BackgroundResourceScriptStreamer::BackgroundProcessor final
    : public BackgroundResponseProcessor {
 public:
  BackgroundProcessor(
      v8::ScriptType script_type,
      const String script_url_string,
      uint64_t script_resource_identifier,
      v8::Isolate* isolate,
      WTF::TextEncoding encoding,
      std::unique_ptr<v8_compile_hints::CompileHintsForStreaming::Builder>
          compile_hints_builder,
      CrossThreadWeakHandle<BackgroundResourceScriptStreamer> streamer_handle);
  BackgroundProcessor(const BackgroundProcessor&) = delete;
  BackgroundProcessor& operator=(const BackgroundProcessor&) = delete;
  ~BackgroundProcessor() override;

  bool MaybeStartProcessingResponse(
      network::mojom::URLResponseHeadPtr& head,
      mojo::ScopedDataPipeConsumerHandle& body,
      std::optional<mojo_base::BigBuffer>& cached_metadata_buffer,
      scoped_refptr<base::SequencedTaskRunner> background_task_runner,
      Client* client) override;

  v8::ScriptType script_type() const { return script_type_; }
  bool IsStreamingSuppressed();

 private:
  static void RunScriptStreamingTask(
      const String script_url_string,
      uint64_t script_resource_identifier,
      std::unique_ptr<v8::ScriptCompiler::ScriptStreamingTask>
          script_streaming_task,
      std::unique_ptr<v8::ScriptCompiler::StreamedSource> streamed_source,
      SourceStream* source_stream_ptr,
      ScriptDecoderPtr script_decoder,
      std::unique_ptr<v8_compile_hints::CompileHintsForStreaming> compile_hints,
      base::WeakPtr<BackgroundProcessor> background_processor_weak_ptr);
  static void RunConsumingCodeCacheTask(
      const String script_url_string,
      uint64_t script_resource_identifier,
      std::unique_ptr<v8::ScriptCompiler::ConsumeCodeCacheTask>
          consume_code_cache_task,
      scoped_refptr<base::SequencedTaskRunner> background_task_runner,
      mojo_base::BigBuffer cached_metadata,
      base::WeakPtr<BackgroundProcessor> background_processor_weak_ptr,
      const uint64_t trace_id);

  void SetState(BackgroundProcessorState state);

  void OnDataPipeReadable(MojoResult ready_result,
                          const mojo::HandleSignalsState& ready_state);
  bool TryStartStreamingTask(MojoResult result,
                             const mojo::HandleSignalsState& state);

  void OnFinishStreaming(
      std::unique_ptr<v8::ScriptCompiler::StreamedSource> streamed_source,
      ScriptDecoderPtr script_decoder,
      ScriptDecoder::Result result);

  void OnFinishCodeCacheConsumer(
      std::unique_ptr<v8::ScriptCompiler::ConsumeCodeCacheTask>
          consume_code_cache_task,
      mojo_base::BigBuffer cached_metadata);
  void OnFinishScriptDecode(ScriptDecoder::Result result);
  void OnFinishCodeCacheConsumerScriptDecode();

  void SuppressStreaming(NotStreamingReason reason);

  const v8::ScriptType script_type_;
  // Keep the script URL string for event tracing.
  const String script_url_string_;
  // Keep the script resource identifier for event tracing.
  const uint64_t script_resource_identifier_;

  v8::Isolate* isolate_;
  WTF::TextEncoding encoding_;

  SourceStream* source_stream_ptr_ = nullptr;

  // For CompileHints
  std::unique_ptr<v8_compile_hints::CompileHintsForStreaming::Builder>
      compile_hints_builder_;
  std::unique_ptr<v8_compile_hints::CompileHintsForStreaming> compile_hints_;

  CrossThreadWeakHandle<BackgroundResourceScriptStreamer> streamer_handle_;

  // Used for reading first few bytes of the body to detecting BOM.
  std::unique_ptr<mojo::SimpleWatcher> watcher_;

  network::mojom::URLResponseHeadPtr head_;
  mojo::ScopedDataPipeConsumerHandle body_;
  std::optional<mojo_base::BigBuffer> cached_metadata_;
  scoped_refptr<base::SequencedTaskRunner> background_task_runner_;
  DataPipeScriptDecoderPtr data_pipe_script_decoder_;

  std::unique_ptr<v8::ScriptCompiler::ConsumeCodeCacheTask>
      consume_code_cache_task_;
  std::optional<ScriptDecoder::Result> decoder_result_;

  Client* client_;

  NotStreamingReason suppressed_reason_ = NotStreamingReason::kInvalid;

  BackgroundProcessorState state_ =
      BackgroundProcessorState::kWaitingForResponse;

  SEQUENCE_CHECKER(background_sequence_checker_);
  base::WeakPtrFactory<BackgroundProcessor> weak_factory_{this};
};

class BackgroundResourceScriptStreamer::BackgroundProcessorFactory final
    : public BackgroundResponseProcessorFactory {
 public:
  BackgroundProcessorFactory(
      ScriptResource* script_resource,
      CrossThreadWeakHandle<BackgroundResourceScriptStreamer> streamer_handle)
      : script_type_(ScriptTypeForStreamingTask(script_resource)),
        script_url_string_(script_resource->Url().GetString()),
        script_resource_identifier_(script_resource->InspectorId()),
        isolate_(script_resource->GetIsolateOrNull()),
        encoding_(script_resource->Encoding()),
        compile_hints_builder_(
            std::make_unique<
                v8_compile_hints::CompileHintsForStreaming::Builder>(
                script_resource->GetV8CrowdsourcedCompileHintsProducer(),
                script_resource->GetV8CrowdsourcedCompileHintsConsumer(),
                script_resource->Url(),
                script_resource->GetV8CompileHintsMagicCommentMode())),
        streamer_handle_(std::move(streamer_handle)) {}
  BackgroundProcessorFactory(const BackgroundProcessorFactory&) = delete;
  BackgroundProcessorFactory& operator=(const BackgroundProcessorFactory&) =
      delete;
  ~BackgroundProcessorFactory() override = default;

  std::unique_ptr<BackgroundResponseProcessor> Create() && override {
    return std::make_unique<BackgroundProcessor>(
        script_type_, script_url_string_, script_resource_identifier_, isolate_,
        encoding_, std::move(compile_hints_builder_),
        std::move(streamer_handle_));
  }

  const v8::ScriptType script_type_;
  const String script_url_string_;
  const uint64_t script_resource_identifier_;
  v8::Isolate* isolate_;
  const WTF::TextEncoding encoding_;
  std::unique_ptr<v8_compile_hints::CompileHintsForStreaming::Builder>
      compile_hints_builder_;
  CrossThreadWeakHandle<BackgroundResourceScriptStreamer> streamer_handle_;
};

BackgroundResourceScriptStreamer::BackgroundProcessor::BackgroundProcessor(
    v8::ScriptType script_type,
    const String script_url_string,
    uint64_t script_resource_identifier,
    v8::Isolate* isolate,
    WTF::TextEncoding encoding,
    std::unique_ptr<v8_compile_hints::CompileHintsForStreaming::Builder>
        compile_hints_builder,
    CrossThreadWeakHandle<BackgroundResourceScriptStreamer> streamer_handle)
    : script_type_(script_type),
      script_url_string_(script_url_string),
      script_resource_identifier_(script_resource_identifier),
      isolate_(isolate),
      encoding_(encoding),
      compile_hints_builder_(std::move(compile_hints_builder)),
      streamer_handle_(std::move(streamer_handle)) {}

BackgroundResourceScriptStreamer::BackgroundProcessor::~BackgroundProcessor() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(background_sequence_checker_);
  watcher_.reset();
  if (source_stream_ptr_) {
    source_stream_ptr_->Cancel();
  }
}

void BackgroundResourceScriptStreamer::BackgroundProcessor::SetState(
    BackgroundProcessorState state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(background_sequence_checker_);
#if DCHECK_IS_ON()
  using S = BackgroundProcessorState;
  DEFINE_THREAD_SAFE_STATIC_LOCAL(
      base::StateTransitions<S>, transitions,
      ({
          {S::kWaitingForResponse,
           {// The BackgroundProcessor receives the response.
            S::kResponseReceived}},
          {S::kResponseReceived,
           {// The mime type of the response is not supported, or the received
            // metadata contains code cache.
            S::kStreamingSupressed,
            // There is no data in the data pipe that can be read synchronously.
            S::kWaitingForDataPipeReadable,
            // There is some data in the data pipe, so let's try to check the
            // encoding.
            S::kCheckingEncoding,
            // There is a code cache metadata, so start to consume the
            // code cache. This state is used only when
            // BackgroundCodeCacheDecoderStart is enabled.
            S::kWaitingForConsumeCodeCacheResultAndDecodedScript}},
          {S::kCheckingEncoding,
           {// Finished loading all body data which is smaller than
            // kMaximumLengthOfBOM, or error occurred while reading the data
            // pipe, or the detected encoding is not supported.
            S::kStreamingSupressed,
            // The data in the passed data pipe is too small to detect the
            // encoding.
            S::kWaitingForDataPipeReadable,
            // Started the parser on another thread.
            S::kWaitingForParseResult}},
          {S::kWaitingForDataPipeReadable,
           {// There is some data in the data pipe, so let's try to check the
            // encoding.
            S::kCheckingEncoding}},
          {S::kWaitingForParseResult,
           {// The background parser finished.
            S::kFinished}},
          {S::kWaitingForConsumeCodeCacheResultAndDecodedScript,
           {// Received the result from the script decoder.
            S::kWaitingForConsumeCodeCacheResult,
            // Received the result from the code cache consumer.
            S::kWaitingForDecodedScript}},
          {S::kWaitingForConsumeCodeCacheResult,
           {// Received the result from the code cache consumer.
            S::kFinished}},
          {S::kWaitingForDecodedScript,
           {// Received the result from the script decoder.
            S::kFinished}},
      }));
  DCHECK_STATE_TRANSITION(&transitions, state_, state);
#endif  // DCHECK_IS_ON()
  state_ = state;
}

bool BackgroundResourceScriptStreamer::BackgroundProcessor::
    MaybeStartProcessingResponse(
        network::mojom::URLResponseHeadPtr& head,
        mojo::ScopedDataPipeConsumerHandle& body,
        std::optional<mojo_base::BigBuffer>& cached_metadata,
        scoped_refptr<base::SequencedTaskRunner> background_task_runner,
        Client* client) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(background_sequence_checker_);
  CHECK(background_task_runner->RunsTasksInCurrentSequence());
  TRACE_EVENT1("v8,devtools.timeline," TRACE_DISABLED_BY_DEFAULT("v8.compile"),
               "BackgroundProcessor::MaybeStartProcessingResponse", "url",
               script_url_string_.Utf8());
  CHECK(body);
  CHECK(head);
  SetState(BackgroundProcessorState::kResponseReceived);

  client_ = client;

  if (script_type_ == v8::ScriptType::kModule) {
    std::string mime_type;
    if (!head->headers->GetMimeType(&mime_type) ||
        !MIMETypeRegistry::IsSupportedJavaScriptMIMEType(String(mime_type))) {
      SuppressStreaming(NotStreamingReason::kNonJavascriptModuleBackground);
      return false;
    }
  }
  if (!head->charset.empty()) {
    WTF::TextEncoding new_encoding = WTF::TextEncoding(String(head->charset));
    if (new_encoding.IsValid()) {
      encoding_ = new_encoding;
    }
  }

  head_ = std::move(head);
  body_ = std::move(body);
  cached_metadata_ = std::move(cached_metadata);
  background_task_runner_ = background_task_runner;

  bool has_code_cache = false;
  if (auto consume_code_cache_task = MaybeCreateConsumeCodeCacheTask(
          cached_metadata_, encoding_.GetName(), isolate_, has_code_cache,
          script_type())) {
    const uint64_t trace_id =
        static_cast<uint64_t>(reinterpret_cast<uintptr_t>(this));
    TRACE_EVENT_WITH_FLOW1(
        "v8," TRACE_DISABLED_BY_DEFAULT("v8.compile"),
        "v8.deserializeOnBackground.start", TRACE_ID_LOCAL(trace_id),
        TRACE_EVENT_FLAG_FLOW_OUT, "data", [&](perfetto::TracedValue context) {
          inspector_deserialize_script_event::Data(std::move(context),
                                                   script_resource_identifier_,
                                                   script_url_string_);
        });
    CHECK(features::kBackgroundCodeCacheDecoderStart.Get());
    V8CodeCache::RecordCacheGetStatistics(
        V8CodeCache::GetMetadataType::kCodeCache);
    SetState(BackgroundProcessorState::
                 kWaitingForConsumeCodeCacheResultAndDecodedScript);
    data_pipe_script_decoder_ = DataPipeScriptDecoder::Create(
        std::make_unique<TextResourceDecoder>(TextResourceDecoderOptions(
            TextResourceDecoderOptions::kPlainTextContent, encoding_)),
        background_task_runner_,
        CrossThreadBindOnce(&BackgroundProcessor::OnFinishScriptDecode,
                            weak_factory_.GetWeakPtr()));
    data_pipe_script_decoder_->Start(std::move(body_));
    // The cached metadata must be passed to the worker thread to avoid UAF,
    // because `this` is deleted when the request is canceled.
    worker_pool::PostTask(
        FROM_HERE, {base::TaskPriority::USER_BLOCKING, base::MayBlock()},
        CrossThreadBindOnce(
            &BackgroundProcessor::RunConsumingCodeCacheTask, script_url_string_,
            script_resource_identifier_, std::move(consume_code_cache_task),
            background_task_runner_, std::move(*cached_metadata_),
            weak_factory_.GetWeakPtr(), trace_id));
    return true;
  }

  // TODO(40244488): Remove this when BackgroundCodeCacheDecoderStart feature
  // is removed.
  if (has_code_cache) {
    // There is a code cache, but the BackgroundCodeCacheDecoderStart feature is
    // disabled.
    CHECK(!features::kBackgroundCodeCacheDecoderStart.Get());
    head = std::move(head_);
    body = std::move(body_);
    cached_metadata = std::move(cached_metadata_);
    SuppressStreaming(NotStreamingReason::kHasCodeCacheBackground);
    V8CodeCache::RecordCacheGetStatistics(
        V8CodeCache::GetMetadataType::kCodeCache);
    return false;
  }

  compile_hints_ = BuildCompileHintsForStreaming(
      *compile_hints_builder_, cached_metadata_, encoding_.GetName());
  CHECK(compile_hints_);

  watcher_ = std::make_unique<mojo::SimpleWatcher>(
      FROM_HERE, mojo::SimpleWatcher::ArmingPolicy::MANUAL);
  watcher_->Watch(body_.get(), MOJO_HANDLE_SIGNAL_NEW_DATA_READABLE,
                  MOJO_TRIGGER_CONDITION_SIGNALS_SATISFIED,
                  WTF::BindRepeating(&BackgroundProcessor::OnDataPipeReadable,
                                     weak_factory_.GetWeakPtr()));
  MojoResult ready_result;
  mojo::HandleSignalsState ready_state;
  MojoResult rv = watcher_->Arm(&ready_result, &ready_state);
  if (rv == MOJO_RESULT_OK) {
    // There is no data in the data pipe, so let's wait until new data is
    // available to read. BackgroundProcessor::OnDataPipeReadable() will be
    // called when new data is available or the data pipe is closed.
    SetState(BackgroundProcessorState::kWaitingForDataPipeReadable);
    return true;
  }
  // The following code is executed when there is some data in the data pipe or
  // the data pipe is closed. To reduce the cost of PostTask, we check the data
  // pipe synchronously here.
  DCHECK_EQ(MOJO_RESULT_FAILED_PRECONDITION, rv);
  if (TryStartStreamingTask(ready_result, ready_state)) {
    CHECK_EQ(state_, BackgroundProcessorState::kWaitingForParseResult);
    // Trere is enough data in the data pipe to detect the encoding, and
    // ScriptStreamingTask has been started on the background thread.
    return true;
  }
  if (watcher_) {
    CHECK(!IsStreamingSuppressed());
    CHECK_EQ(state_, BackgroundProcessorState::kWaitingForDataPipeReadable);
    // The data in the data pipe is too small to detect the encoding. So call
    // ArmOrNotify() and let's wait until new data is available to read.
    watcher_->ArmOrNotify();
    return true;
  }
  CHECK(IsStreamingSuppressed());
  CHECK_EQ(state_, BackgroundProcessorState::kStreamingSupressed);
  // We checked the data in the data pipe synchronously, and the detected
  // encoding is not supported. So reset `head`, `body`, `cached_metadata` and
  // return false here.
  head = std::move(head_);
  body = std::move(body_);
  cached_metadata = std::move(cached_metadata_);
  return false;
}

void BackgroundResourceScriptStreamer::BackgroundProcessor::OnDataPipeReadable(
    MojoResult ready_result,
    const mojo::HandleSignalsState& ready_state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(background_sequence_checker_);
  TRACE_EVENT0("v8,devtools.timeline," TRACE_DISABLED_BY_DEFAULT("v8.compile"),
               "BackgroundProcessor::OnDataPipeReadable");
  CHECK_EQ(state_, BackgroundProcessorState::kWaitingForDataPipeReadable);
  if (TryStartStreamingTask(ready_result, ready_state)) {
    CHECK_EQ(state_, BackgroundProcessorState::kWaitingForParseResult);
    return;
  }
  if (watcher_) {
    CHECK(!IsStreamingSuppressed());
    CHECK_EQ(state_, BackgroundProcessorState::kWaitingForDataPipeReadable);
    // The data in the data pipe is  too small to detect the encoding. So call
    // ArmOrNotify().
    watcher_->ArmOrNotify();
    return;
  }
  CHECK(IsStreamingSuppressed());
  CHECK_EQ(state_, BackgroundProcessorState::kStreamingSupressed);
  // We checked the data in the data pipe asynchronously, and the detected
  // encoding is not supported or some error occurred while reading the data
  // pipe or the data was too small. So call
  // DidFinishBackgroundResponseProcessor() with `head_`, `body_`,
  // `cached_metadata_` which were passed at MaybeStartProcessingResponse().
  client_->DidFinishBackgroundResponseProcessor(
      std::move(head_), std::move(body_), std::move(cached_metadata_));
}

bool BackgroundResourceScriptStreamer::BackgroundProcessor::
    TryStartStreamingTask(MojoResult result,
                          const mojo::HandleSignalsState& state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(background_sequence_checker_);
  TRACE_EVENT0("v8,devtools.timeline," TRACE_DISABLED_BY_DEFAULT("v8.compile"),
               "BackgroundProcessor::TryStartStreamingTask");
  SetState(BackgroundProcessorState::kCheckingEncoding);
  switch (result) {
    case MOJO_RESULT_OK:
      break;
    case MOJO_RESULT_FAILED_PRECONDITION:
      // The data is smaller than kMaximumLengthOfBOM.
      watcher_.reset();
      SuppressStreaming(NotStreamingReason::kScriptTooSmallBackground);
      return false;
    case MOJO_RESULT_SHOULD_WAIT:
      NOTREACHED();
    default:
      // Some other error occurred.
      watcher_.reset();
      SuppressStreaming(NotStreamingReason::kErrorOccurredBackground);
      return false;
  }
  CHECK(state.readable());
  base::span<const uint8_t> data;
  constexpr uint32_t kMaximumLengthOfBOM = 4;
  MojoResult begin_read_result =
      body_->BeginReadData(MOJO_READ_DATA_FLAG_NONE, data);
  CHECK_EQ(begin_read_result, MOJO_RESULT_OK);
  CHECK_GT(data.size(), 0u);
  if (data.size() < kMaximumLengthOfBOM) {
    MojoResult end_read_result = body_->EndReadData(0);
    CHECK_EQ(end_read_result, MOJO_RESULT_OK);
    // We keep `watcher_` to read more data.
    CHECK(watcher_);
    SetState(BackgroundProcessorState::kWaitingForDataPipeReadable);
    return false;
  }
  watcher_.reset();

  std::unique_ptr<TextResourceDecoder> decoder(
      std::make_unique<TextResourceDecoder>(TextResourceDecoderOptions(
          TextResourceDecoderOptions::kPlainTextContent, encoding_)));
  decoder->CheckForBOM(base::as_chars(data.first(kMaximumLengthOfBOM)));
  MojoResult end_read_result = body_->EndReadData(0);
  CHECK_EQ(end_read_result, MOJO_RESULT_OK);
  v8::ScriptCompiler::StreamedSource::Encoding script_source_encoding =
      v8::ScriptCompiler::StreamedSource::UTF8;
  if (!ScriptStreamer::ConvertEncoding(decoder->Encoding().GetName(),
                                       &script_source_encoding)) {
    SuppressStreaming(NotStreamingReason::kEncodingNotSupportedBackground);
    return false;
  }

  ScriptDecoderPtr script_decoder = ScriptDecoder::Create(
      std::make_unique<TextResourceDecoder>(TextResourceDecoderOptions(
          TextResourceDecoderOptions::kPlainTextContent, encoding_)),
      background_task_runner_);
  auto source_stream = std::make_unique<SourceStream>();
  source_stream_ptr_ = source_stream.get();
  source_stream->TakeDataAndPipeOnBackgroundThread(std::move(body_),
                                                   script_decoder.get());
  std::unique_ptr<v8::ScriptCompiler::StreamedSource> streamed_source =
      std::make_unique<v8::ScriptCompiler::StreamedSource>(
```