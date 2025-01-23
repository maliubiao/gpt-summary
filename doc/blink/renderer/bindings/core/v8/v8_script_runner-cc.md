Response:
My goal is to understand the functionality of the provided C++ code snippet from Chromium's Blink rendering engine and explain its relation to web technologies like JavaScript, HTML, and CSS. I also need to identify potential user errors and describe the user actions leading to this code execution. Finally, I need to summarize the functionality of this first part of the file.

Here's a breakdown of my thought process:

1. **Identify the Core Functionality:** The file name `v8_script_runner.cc` strongly suggests that this code is responsible for running JavaScript code within the Blink engine. The presence of `#include "third_party/blink/renderer/bindings/core/v8/v8_script_runner.h"` confirms this.

2. **Analyze Key Includes:**  The included headers provide clues about the file's responsibilities:
    * `v8.h`:  Indicates interaction with the V8 JavaScript engine.
    * `script_evaluation_result.h`, `script_function.h`, `script_streamer.h`: Suggest managing the process of evaluating and executing scripts.
    * `v8_code_cache.h`, `v8_compile_hints_...`: Point towards optimization techniques like code caching and compile hints.
    * `execution_context.h`, `local_dom_window.h`, `local_frame.h`:  Link the script execution to the browser's document model and frame structure.
    * `classic_script.h`, `module_script.h`:  Indicate support for both traditional and module-based JavaScript.

3. **Examine Key Functions:** I'll scan the code for functions that appear central to its purpose.
    * `CompileScriptInternal`, `CompileScript`, `CompileModule`: Clearly related to turning JavaScript source code into an executable form. The different variations likely handle classic scripts and modules separately. The "Internal" version suggests a core compilation logic.
    * `RunCompiledScript`:  Responsible for actually executing the compiled JavaScript code.
    * `CompileAndRunScript`:  Combines the compilation and execution steps.

4. **Connect to Web Technologies:**  How do these functions relate to JavaScript, HTML, and CSS?
    * **JavaScript:**  This is the primary focus. The code handles parsing, compiling, and running JavaScript code embedded in web pages or loaded as separate files.
    * **HTML:**  HTML elements (like `<script>`) often contain or reference JavaScript code. When the browser encounters these, this code gets involved in processing the script.
    * **CSS:**  While this file doesn't directly handle CSS parsing or application, JavaScript can manipulate CSS styles dynamically. Therefore, the execution of JavaScript (handled by this code) can have a direct impact on the styling of a webpage.

5. **Identify Potential User Errors:**  What mistakes could a web developer make that would lead to this code being executed, potentially resulting in errors?
    * Syntax errors in JavaScript.
    * Trying to load a script from a non-existent URL.
    * Security violations (e.g., trying to access properties across domains without CORS).
    * Exceeding stack limits with recursive functions.

6. **Trace User Actions:** How does a user's interaction with a webpage lead to this code?
    * **Page Load:** When a browser loads an HTML page, it parses the HTML and encounters `<script>` tags. This triggers the loading and execution of the JavaScript.
    * **User Interaction:** Events like button clicks, mouse movements, or form submissions can trigger JavaScript event handlers, causing the execution of associated scripts.
    * **Dynamic Script Loading:** JavaScript itself can dynamically load and execute other scripts.

7. **Logical Reasoning (Hypothetical Input/Output):**
    * **Input:**  A string of JavaScript code with a syntax error.
    * **Output:** An error message in the browser's developer console. The `try_catch` block in `CompileAndRunScript` is relevant here.
    * **Input:** A `<script>` tag with a `src` attribute pointing to a valid JavaScript file.
    * **Output:** The JavaScript code in the file is fetched, compiled, and executed, potentially modifying the DOM or making network requests.

8. **Summarize the Functionality (Part 1):**  Focus on the core tasks handled in the provided snippet. It's mainly about the initial stages of handling JavaScript: compilation, including considerations for caching and optimization hints. The `CompileAndRunScript` function provides a higher-level entry point.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the individual functions. I realized I need to step back and understand the broader workflow: how scripts are loaded, compiled, and then run.
* I noticed the code deals with both "classic" scripts and "module" scripts. This distinction is important and should be included in the summary.
* The inclusion of "compile hints" was a detail I needed to investigate further to understand its purpose (optimization).
* I initially missed the connection between JavaScript execution and CSS manipulation, so I added that point.

By following these steps, I can systematically analyze the code snippet and generate a comprehensive explanation of its functionality.
```cpp
/*
 * Copyright (C) 2009 Google Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/bindings/core/v8/v8_script_runner.h"

#include "base/feature_list.h"
#include "base/metrics/histogram_functions.h"
#include "build/build_config.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/page/v8_compile_hints_histograms.h"
#include "third_party/blink/public/mojom/v8_cache_options.mojom-blink.h"
#include "third_party/blink/renderer/bindings/buildflags.h"
#include "third_party/blink/renderer/bindings/core/v8/binding_security.h"
#include "third_party/blink/renderer/bindings/core/v8/referrer_script_info.h"
#include "third_party/blink/renderer/bindings/core/v8/script_cache_consumer.h"
#include "third_party/blink/renderer/bindings/core/v8/script_evaluation_result.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_streamer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_code_cache.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_compile_hints_common.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_compile_hints_consumer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_compile_hints_producer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_initializer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_local_compile_hints_consumer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_local_compile_hints_producer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/worker_or_worklet_script_controller.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/loader/modulescript/module_script_creation_params.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/core/script/modulator.h"
#include "third_party/blink/renderer/core/script/module_script.h"
#include "third_party/blink/renderer/core/workers/worker_or_worklet_global_scope.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/loader/fetch/cached_metadata.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/cached_metadata_handler.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding.h"

namespace blink {

namespace {

// Used to throw an exception before we exceed the C++ stack and crash.
// This limit was arrived at arbitrarily. crbug.com/449744
const int kMaxRecursionDepth = 44;

// In order to make sure all pending messages to be processed in
// v8::Function::Call, we don't call throwStackOverflowException
// directly. Instead, we create a v8::Function of
// throwStackOverflowException and call it.
void ThrowStackOverflowException(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  V8ThrowException::ThrowRangeError(info.GetIsolate(),
                                    "Maximum call stack size exceeded.");
}

void ThrowScriptForbiddenException(v8::Isolate* isolate) {
  V8ThrowException::ThrowError(isolate, "Script execution is forbidden.");
}

v8::MaybeLocal<v8::Value> ThrowStackOverflowExceptionIfNeeded(
    v8::Isolate* isolate,
    v8::MicrotaskQueue* microtask_queue) {
  if (V8PerIsolateData::From(isolate)->IsHandlingRecursionLevelError()) {
    // If we are already handling a recursion level error, we should
    // not invoke v8::Function::Call.
    return v8::Undefined(isolate);
  }
  v8::MicrotasksScope microtasks_scope(
      isolate, microtask_queue, v8::MicrotasksScope::kDoNotRunMicrotasks);
  V8PerIsolateData::From(isolate)->SetIsHandlingRecursionLevelError(true);

  ScriptForbiddenScope::AllowUserAgentScript allow_script;
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  v8::MaybeLocal<v8::Value> result =
      v8::Function::New(context, ThrowStackOverflowException,
                        v8::Local<v8::Value>(), 0,
                        v8::ConstructorBehavior::kThrow)
          .ToLocalChecked()
          ->Call(context, v8::Undefined(isolate), 0, nullptr);

  V8PerIsolateData::From(isolate)->SetIsHandlingRecursionLevelError(false);
  return result;
}

v8::MaybeLocal<v8::Script> CompileScriptInternal(
    v8::Isolate* isolate,
    ScriptState* script_state,
    const ClassicScript& classic_script,
    v8::ScriptOrigin origin,
    v8::ScriptCompiler::CompileOptions compile_options,
    v8::ScriptCompiler::NoCacheReason no_cache_reason,
    bool can_use_crowdsourced_compile_hints,
    std::optional<inspector_compile_script_event::V8ConsumeCacheResult>*
        cache_result) {
  // Record the script compilation in ScriptState (accessible via
  // internals.idl).
  {
    const bool use_code_cache =
        (compile_options & v8::ScriptCompiler::kConsumeCodeCache) != 0;
    script_state->RecordScriptCompilation(classic_script.SourceUrl(),
                                          use_code_cache);
  }

  v8::Local<v8::String> code = V8String(isolate, classic_script.SourceText());

  // TODO(kouhei): Plumb the ScriptState into this function and replace all
  // Isolate->GetCurrentContext in this function with ScriptState->GetContext.
  if (ScriptStreamer* streamer = classic_script.Streamer()) {
    if (v8::ScriptCompiler::StreamedSource* source =
            streamer->Source(v8::ScriptType::kClassic)) {
      // Final compile call for a streamed compilation.
      // Streaming compilation may involve use of code cache.
      // TODO(leszeks): Add compile timer to streaming compilation.
      return v8::ScriptCompiler::Compile(script_state->GetContext(), source,
                                         code, origin);
    }
  }

  // Allow inspector to use its own compilation cache store.
  v8::ScriptCompiler::CachedData* inspector_data = nullptr;
  // The probe below allows inspector to either inject the cached code
  // or override compile_options to force eager compilation of code
  // when producing the cache.
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  probe::ApplyCompilationModeOverride(execution_context, classic_script,
                                      &inspector_data, &compile_options);
  if (inspector_data) {
    v8::ScriptCompiler::Source source(code, origin, inspector_data);
    v8::MaybeLocal<v8::Script> script =
        v8::ScriptCompiler::Compile(script_state->GetContext(), &source,
                                    v8::ScriptCompiler::kConsumeCodeCache);
    return script;
  }

  switch (static_cast<int>(compile_options)) {
    case v8::ScriptCompiler::kConsumeCompileHints:
    case v8::ScriptCompiler::kConsumeCompileHints |
        v8::ScriptCompiler::kFollowCompileHintsMagicComment: {
      // We can only consume local or crowdsourced compile hints, but
      // not both at the same time. If the page has crowdsourced compile hints,
      // we won't generate local compile hints, so won't ever have them.
      // We'd only have both local and crowdsourced compile hints available in
      // special cases, e.g., if crowdsourced compile hints were temporarily
      // unavailable, we generated local compile hints, and during the next page
      // load we have both available.

      // TODO(40286622): Enable using crowdsourced compile hints and augmenting
      // them with local compile hints. 1) Enable consuming compile hints and at
      // the same time, producing compile hints for functions which were still
      // lazy and 2) enable consuming both kind of compile hints at the same
      // time.
      if (can_use_crowdsourced_compile_hints) {
        base::UmaHistogramEnumeration(
            v8_compile_hints::kStatusHistogram,
            v8_compile_hints::Status::
                kConsumeCrowdsourcedCompileHintsClassicNonStreaming);

        // Based on how `can_use_crowdsourced_compile_hints` in CompileScript is
        // computed, we must get a non-null LocalDOMWindow and LocalFrame here.
        LocalDOMWindow* window = DynamicTo<LocalDOMWindow>(execution_context);
        CHECK(window);
        LocalFrame* frame = window->GetFrame();
        CHECK(frame);
        Page* page = frame->GetPage();
        CHECK(page);
        // This ptr keeps the data alive during v8::ScriptCompiler::Compile.
        std::unique_ptr<v8_compile_hints::V8CrowdsourcedCompileHintsConsumer::
                            DataAndScriptNameHash>
            compile_hint_data =
                page->GetV8CrowdsourcedCompileHintsConsumer()
                    .GetDataWithScriptNameHash(v8_compile_hints::ScriptNameHash(
                        origin.ResourceName(), script_state->GetContext(),
                        isolate));
        v8::ScriptCompiler::Source source(
            code, origin,
            &v8_compile_hints::V8CrowdsourcedCompileHintsConsumer::
                CompileHintCallback,
            compile_hint_data.get());
        return v8::ScriptCompiler::Compile(script_state->GetContext(), &source,
                                           compile_options, no_cache_reason);
      }
      // No crowdsourced compile hints; compile with local compile hints.
      CHECK(base::FeatureList::IsEnabled(features::kLocalCompileHints));
      base::UmaHistogramEnumeration(
          v8_compile_hints::kStatusHistogram,
          v8_compile_hints::Status::
              kConsumeLocalCompileHintsClassicNonStreaming);
      CachedMetadataHandler* cache_handler = classic_script.CacheHandler();
      CHECK(cache_handler);
      scoped_refptr<CachedMetadata> cached_metadata =
          V8CodeCache::GetCachedMetadataForCompileHints(cache_handler);
      v8_compile_hints::V8LocalCompileHintsConsumer
          v8_local_compile_hints_consumer(cached_metadata.get());
      if (v8_local_compile_hints_consumer.IsRejected()) {
        cache_handler->ClearCachedMetadata(
            ExecutionContext::GetCodeCacheHostFromContext(execution_context),
            CachedMetadataHandler::kClearPersistentStorage);
        // Compile without compile hints.
        compile_options = v8::ScriptCompiler::CompileOptions(
            compile_options & (~v8::ScriptCompiler::kConsumeCompileHints));
        v8::ScriptCompiler::Source source(code, origin);
        return v8::ScriptCompiler::Compile(script_state->GetContext(), &source,
                                           compile_options, no_cache_reason);
      }
      v8::ScriptCompiler::Source source(
          code, origin,
          v8_compile_hints::V8LocalCompileHintsConsumer::GetCompileHint,
          &v8_local_compile_hints_consumer);
      return v8::ScriptCompiler::Compile(script_state->GetContext(), &source,
                                         compile_options, no_cache_reason);
    }
    case v8::ScriptCompiler::kProduceCompileHints:
    case v8::ScriptCompiler::kProduceCompileHints |
        v8::ScriptCompiler::kFollowCompileHintsMagicComment: {
      base::UmaHistogramEnumeration(
          v8_compile_hints::kStatusHistogram,
          v8_compile_hints::Status::kProduceCompileHintsClassicNonStreaming);
      v8::ScriptCompiler::Source source(code, origin);
      return v8::ScriptCompiler::Compile(script_state->GetContext(), &source,
                                         compile_options, no_cache_reason);
    }
    case v8::ScriptCompiler::kNoCompileOptions:
    case v8::ScriptCompiler::kEagerCompile:
    case v8::ScriptCompiler::kFollowCompileHintsMagicComment: {
      base::UmaHistogramEnumeration(
          v8_compile_hints::kStatusHistogram,
          v8_compile_hints::Status::kNoCompileHintsClassicNonStreaming);
      v8::ScriptCompiler::Source source(code, origin);
      return v8::ScriptCompiler::Compile(script_state->GetContext(), &source,
                                         compile_options, no_cache_reason);
    }

    case v8::ScriptCompiler::kConsumeCodeCache: {
      base::UmaHistogramEnumeration(
          v8_compile_hints::kStatusHistogram,
          v8_compile_hints::Status::kConsumeCodeCacheClassicNonStreaming);
      // Compile a script, and consume a V8 cache that was generated previously.
      CachedMetadataHandler* cache_handler = classic_script.CacheHandler();
      ScriptCacheConsumer* cache_consumer = classic_script.CacheConsumer();
      scoped_refptr<CachedMetadata> cached_metadata =
          V8CodeCache::GetCachedMetadata(cache_handler);
      const bool full_code_cache = V8CodeCache::IsFull(cached_metadata.get());
      v8::ScriptCompiler::Source source(
          code, origin,
          V8CodeCache::CreateCachedData(cached_metadata).release(),
          cache_consumer
              ? cache_consumer->TakeV8ConsumeTask(cached_metadata.get())
              : nullptr);
      const v8::ScriptCompiler::CachedData* cached_data =
          source.GetCachedData();
      v8::MaybeLocal<v8::Script> script =
          v8::ScriptCompiler::Compile(script_state->GetContext(), &source,
                                      v8::ScriptCompiler::kConsumeCodeCache);
      cache_handler->DidUseCodeCache();
      // The ScriptState has an associated context. We expect the current
      // context to match the context associated with Script context when
      // compiling the script for main world. Hence it is safe to use the
      // CodeCacheHost corresponding to the script execution context. For
      // isolated world (for ex: extension scripts), the current context
      // may not match the script context. Though currently code caching is
      // disabled for extensions.
      if (cached_data->rejected) {
        cache_handler->ClearCachedMetadata(
            ExecutionContext::GetCodeCacheHostFromContext(
                ExecutionContext::From(script_state)),
            CachedMetadataHandler::kClearPersistentStorage);
      }
      if (cache_result) {
        *cache_result = std::make_optional(
            inspector_compile_script_event::V8ConsumeCacheResult(
                cached_data->length, cached_data->rejected, full_code_cache));
      }
      return script;
    }
    default:
      NOTREACHED();
  }
}

int GetMicrotasksScopeDepth(v8::Isolate* isolate,
                            v8::MicrotaskQueue* microtask_queue) {
  if (microtask_queue)
    return microtask_queue->GetMicrotasksScopeDepth();
  return v8::MicrotasksScope::GetCurrentDepth(isolate);
}

}  // namespace

v8::MaybeLocal<v8::Script> V8ScriptRunner::CompileScript(
    ScriptState* script_state,
    const ClassicScript& classic_script,
    v8::ScriptOrigin origin,
    v8::ScriptCompiler::CompileOptions compile_options,
    v8::ScriptCompiler::NoCacheReason no_cache_reason,
    bool can_use_crowdsourced_compile_hints) {
  v8::Isolate* isolate = script_state->GetIsolate();
  if (classic_script.SourceText().length() >= v8::String::kMaxLength) {
    V8ThrowException::ThrowError(isolate, "Source file too large.");
    return v8::Local<v8::Script>();
  }

  const String& file_name = classic_script.SourceUrl();
  const TextPosition& script_start_position = classic_script.StartPosition();

  constexpr const char* kTraceEventCategoryGroup = "v8,devtools.timeline";
  TRACE_EVENT_BEGIN1(kTraceEventCategoryGroup, "v8.compile", "fileName",
                     file_name.Utf8());
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  probe::V8Compile probe(execution_context, file_name,
                         script_start_position.line_.ZeroBasedInt(),
                         script_start_position.column_.ZeroBasedInt());

  if (!*TRACE_EVENT_API_GET_CATEGORY_GROUP_ENABLED(kTraceEventCategoryGroup)) {
    return CompileScriptInternal(isolate, script_state, classic_script, origin,
                                 compile_options, no_cache_reason,
                                 can_use_crowdsourced_compile_hints, nullptr);
  }

  std::optional<inspector_compile_script_event::V8ConsumeCacheResult>
      cache_result;
  v8::MaybeLocal<v8::Script> script = CompileScriptInternal(
      isolate, script_state, classic_script, origin, compile_options,
      no_cache_reason, can_use_crowdsourced_compile_hints, &cache_result);
  TRACE_EVENT_END1(
      kTraceEventCategoryGroup, "v8.compile", "data",
      [&](perfetto::TracedValue context) {
        inspector_compile_script_event::Data(
            std::move(context), file_name, script_start_position, cache_result,
            compile_options == v8::ScriptCompiler::kEagerCompile,
            classic_script.Streamer(), classic_script.NotStreamingReason());
      });
  return script;
}

v8::MaybeLocal<v8::Module> V8ScriptRunner::CompileModule(
    v8::Isolate* isolate,
    const ModuleScriptCreationParams& params,
    const TextPosition& start_position,
    v8::ScriptCompiler::CompileOptions compile_options,
    v8::ScriptCompiler::NoCacheReason no_cache_reason,
    const ReferrerScriptInfo& referrer_info) {
  const String file_name = params.SourceURL();
  constexpr const char* kTraceEventCategoryGroup = "v8,devtools.timeline";
  TRACE_EVENT_BEGIN1(kTraceEventCategoryGroup, "v8.compileModule", "fileName",
                     file_name.Utf8());

  // |resource_is_shared_cross_origin| is always true and |resource_is_opaque|
  // is always false because CORS is enforced to module scripts.
  v8::ScriptOrigin origin(
      V8String(isolate, file_name), start_position.line_.ZeroBasedInt(),
      start_position.column_.ZeroBasedInt(),
      true,                        // resource_is_shared_cross_origin
      -1,                          // script id
      v8::String::Empty(isolate),  // source_map_url
      false,                       // resource_is_opaque
      false,                       // is_wasm
      true,                        // is_module
      referrer_info.ToV8HostDefinedOptions(isolate, params.SourceURL()));

  v8::Local<v8::String> code = V8String(isolate, params.GetSourceText());
  std::optional<inspector_compile_script_event::V8ConsumeCacheResult>
      cache_result;
  v8::MaybeLocal<v8::Module> script;
  ScriptStreamer* streamer = params.GetScriptStreamer();
  if (streamer) {
    // Final compile call for a streamed compilation.
    // Streaming compilation may involve use of code cache.
    // TODO(leszeks): Add compile timer to streaming compilation.
    script = v8::ScriptCompiler::CompileModule(
        isolate->GetCurrentContext(), streamer->Source(v8::ScriptType::kModule),
        code, origin);
  } else {
    switch (static_cast<int>(compile_options)) {
      // TODO(40286622): Compile hints for modules.
      case v8::ScriptCompiler::kProduceCompileHints:
      case v8::ScriptCompiler::kConsumeCompileHints:
      case v8::ScriptCompiler::kFollowCompileHintsMagicComment |
          v8::ScriptCompiler::kProduceCompileHints:
      case v8::ScriptCompiler::kFollowCompileHintsMagicComment |
          v8::ScriptCompiler::kConsumeCompileHints:
        compile_options = v8::ScriptCompiler::CompileOptions(
            compile_options & (~(v8::ScriptCompiler::kProduceCompileHints |
                                 v8::ScriptCompiler::kConsumeCompileHints)));
        ABSL_FALLTHROUGH_INTENDED;
      case v8::ScriptCompiler::kFollowCompileHintsMagicComment:
      case v8::ScriptCompiler::kNoCompileOptions:
      case v8::ScriptCompiler::kEagerCompile: {
        base::UmaHistogramEnumeration(
            v8_compile_hints::kStatusHistogram,
            v8_compile_hints::Status::kNoCompileHintsModuleNonStreaming);
        v8::ScriptCompiler::Source source(code, origin);
        script = v8::ScriptCompiler::CompileModule(
            isolate, &source, compile_options, no_cache_reason);
        break;
      }

      case v8::ScriptCompiler::kConsumeCodeCache: {
        base::UmaHistogramEnumeration(
            v8_compile_hints::kStatusHistogram,
            v8_compile_hints::Status::kConsumeCodeCacheModuleNonStreaming);
        // Compile a script, and consume a V8 cache that was generated
        // previously.
        CachedMetadataHandler* cache_handler = params.CacheHandler();
        DCHECK(cache_handler);
        cache_handler->DidUseCodeCache();
        const scoped_refptr<CachedMetadata> cached_metadata =
            V8CodeCache::GetCachedMetadata(cache_handler);
        const bool full_code_cache = V8CodeCache::IsFull(cached_metadata.get());
        // TODO(leszeks): Add support for passing in ScriptCacheConsumer.
        v8::ScriptCompiler::Source source(
            code, origin,
            V8CodeCache::CreateCachedData(cache_handler).release());
        const v8::ScriptCompiler::CachedData* cached_data =
            source.GetCachedData();
        script = v8::ScriptCompiler::CompileModule(
            isolate, &source, compile_options, no_cache_reason);
        // The ScriptState also has an associated context. We expect the current
        // context to match the context associated with Script context when
        // compiling the module. Hence it is safe to use the CodeCacheHost
        // corresponding to the current execution context.
        ExecutionContext* execution_context =
            ExecutionContext::From(isolate->GetCurrentContext());
        if (cached_data->rejected) {
          cache_handler->ClearCachedMetadata(
              ExecutionContext::GetCodeCacheHostFromContext(execution_context),
              CachedMetadataHandler::kClearPersistentStorage);
        }
        cache_result = std::make_optional(
            inspector_compile_script_event::V8ConsumeCacheResult(
                cached_data->length, cached_data->rejected, full_code_cache));
        break;
      }
      default:
        NOTREACHED();
    }
  }

  TRACE_EVENT_END1(kTraceEventCategoryGroup, "v8.compileModule", "data",
                   [&](perfetto::TracedValue context) {
                     inspector_compile_script_event::Data(
                         std::move(context), file_name, start_position,
                         cache_result,
                         compile_options == v8::ScriptCompiler::kEagerCompile,
                         streamer, params.NotStreamingReason());
                   });
  return script;
}

v8::MaybeLocal<v8::Value> V8ScriptRunner::RunCompiledScript(
    v8::Isolate* isolate,
    v8::Local<v8::Script> script,
    v8::Local<v8::Data> host_defined_options,
    ExecutionContext* context) {
  DCHECK(!script.IsEmpty());

  v8::Local<v8::Value> script_name =
      script->GetUnboundScript()->GetScriptName();
  TRACE_EVENT1("v8", "v8.run", "fileName",
               TRACE_STR_COPY(*v8::String::Utf8Value(isolate, script_name)));
  RuntimeCallStatsScopedTracer rcs_scoped_tracer(isolate);
  RUNTIME_CALL_TIMER_SCOPE(isolate, RuntimeCallStats::CounterId::kV8);

  v8::MicrotaskQueue* microtask_queue = ToMicrotaskQueue(context);
  if (GetMicrotasksScopeDepth(isolate, microtask_queue) > kMaxRecursionDepth)
    return ThrowStackOverflowExceptionIfNeeded(isolate, microtask_queue);

  CHECK(!context->ContextLifecycleObserverSet().IsIteratingOverObservers());

  // Run the script and keep track of the current recursion depth.
  v8::MaybeLocal<v8::Value> result;
  {
    if (ScriptForbiddenScope::IsScriptForbidden()) {
      ThrowScriptForbiddenException(isolate);
      return v8::MaybeLocal<v8::Value>();
    }
    if (RuntimeEnabledFeatures::BlinkLifecycleScriptForbiddenEnabled()) {
      CHECK(!ScriptForbiddenScope::WillBeScriptForbidden());
    } else {
      DCHECK(!ScriptForbiddenScope::WillBeScriptForbidden());
    }

    v8::MicrotasksScope microtasks_scope(isolate, microtask_queue,
                                         v8::MicrotasksScope::kRunMicrotasks);
    v8::Local<v8::String> script_url;
    if (!script_name->ToString(isolate->GetCurrentContext())
             .ToLocal(&script_url))
      return result;

    // ToCoreString here should be zero copy due to externalized string
    // unpacked.
    String url = ToCoreString(isolate, script_url);
    probe::ExecuteScript probe(context, isolate->GetCurrentContext(), url,
                               script->GetUnboundScript()->GetId());
    result = script->Run(isolate->GetCurrentContext(), host_defined_options);
  }

  CHECK(!isolate->IsDead());
  return result;
}

namespace {
void DelayedProduceCodeCacheTask(ScriptState* script_state,
                                 v8::Global<v8::Script> script,
                                 CachedMetadataHandler* cache_handler,
                                 size_t source_text_length,
                                 KURL source_url,
                                 TextPosition
### 提示词
```
这是目录为blink/renderer/bindings/core/v8/v8_script_runner.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2009 Google Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/bindings/core/v8/v8_script_runner.h"

#include "base/feature_list.h"
#include "base/metrics/histogram_functions.h"
#include "build/build_config.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/page/v8_compile_hints_histograms.h"
#include "third_party/blink/public/mojom/v8_cache_options.mojom-blink.h"
#include "third_party/blink/renderer/bindings/buildflags.h"
#include "third_party/blink/renderer/bindings/core/v8/binding_security.h"
#include "third_party/blink/renderer/bindings/core/v8/referrer_script_info.h"
#include "third_party/blink/renderer/bindings/core/v8/script_cache_consumer.h"
#include "third_party/blink/renderer/bindings/core/v8/script_evaluation_result.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_streamer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_code_cache.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_compile_hints_common.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_compile_hints_consumer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_compile_hints_producer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_initializer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_local_compile_hints_consumer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_local_compile_hints_producer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/worker_or_worklet_script_controller.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/loader/modulescript/module_script_creation_params.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/core/script/modulator.h"
#include "third_party/blink/renderer/core/script/module_script.h"
#include "third_party/blink/renderer/core/workers/worker_or_worklet_global_scope.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/loader/fetch/cached_metadata.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/cached_metadata_handler.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding.h"

namespace blink {

namespace {

// Used to throw an exception before we exceed the C++ stack and crash.
// This limit was arrived at arbitrarily. crbug.com/449744
const int kMaxRecursionDepth = 44;

// In order to make sure all pending messages to be processed in
// v8::Function::Call, we don't call throwStackOverflowException
// directly. Instead, we create a v8::Function of
// throwStackOverflowException and call it.
void ThrowStackOverflowException(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  V8ThrowException::ThrowRangeError(info.GetIsolate(),
                                    "Maximum call stack size exceeded.");
}

void ThrowScriptForbiddenException(v8::Isolate* isolate) {
  V8ThrowException::ThrowError(isolate, "Script execution is forbidden.");
}

v8::MaybeLocal<v8::Value> ThrowStackOverflowExceptionIfNeeded(
    v8::Isolate* isolate,
    v8::MicrotaskQueue* microtask_queue) {
  if (V8PerIsolateData::From(isolate)->IsHandlingRecursionLevelError()) {
    // If we are already handling a recursion level error, we should
    // not invoke v8::Function::Call.
    return v8::Undefined(isolate);
  }
  v8::MicrotasksScope microtasks_scope(
      isolate, microtask_queue, v8::MicrotasksScope::kDoNotRunMicrotasks);
  V8PerIsolateData::From(isolate)->SetIsHandlingRecursionLevelError(true);

  ScriptForbiddenScope::AllowUserAgentScript allow_script;
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  v8::MaybeLocal<v8::Value> result =
      v8::Function::New(context, ThrowStackOverflowException,
                        v8::Local<v8::Value>(), 0,
                        v8::ConstructorBehavior::kThrow)
          .ToLocalChecked()
          ->Call(context, v8::Undefined(isolate), 0, nullptr);

  V8PerIsolateData::From(isolate)->SetIsHandlingRecursionLevelError(false);
  return result;
}

v8::MaybeLocal<v8::Script> CompileScriptInternal(
    v8::Isolate* isolate,
    ScriptState* script_state,
    const ClassicScript& classic_script,
    v8::ScriptOrigin origin,
    v8::ScriptCompiler::CompileOptions compile_options,
    v8::ScriptCompiler::NoCacheReason no_cache_reason,
    bool can_use_crowdsourced_compile_hints,
    std::optional<inspector_compile_script_event::V8ConsumeCacheResult>*
        cache_result) {
  // Record the script compilation in ScriptState (accessible via
  // internals.idl).
  {
    const bool use_code_cache =
        (compile_options & v8::ScriptCompiler::kConsumeCodeCache) != 0;
    script_state->RecordScriptCompilation(classic_script.SourceUrl(),
                                          use_code_cache);
  }

  v8::Local<v8::String> code = V8String(isolate, classic_script.SourceText());

  // TODO(kouhei): Plumb the ScriptState into this function and replace all
  // Isolate->GetCurrentContext in this function with ScriptState->GetContext.
  if (ScriptStreamer* streamer = classic_script.Streamer()) {
    if (v8::ScriptCompiler::StreamedSource* source =
            streamer->Source(v8::ScriptType::kClassic)) {
      // Final compile call for a streamed compilation.
      // Streaming compilation may involve use of code cache.
      // TODO(leszeks): Add compile timer to streaming compilation.
      return v8::ScriptCompiler::Compile(script_state->GetContext(), source,
                                         code, origin);
    }
  }

  // Allow inspector to use its own compilation cache store.
  v8::ScriptCompiler::CachedData* inspector_data = nullptr;
  // The probe below allows inspector to either inject the cached code
  // or override compile_options to force eager compilation of code
  // when producing the cache.
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  probe::ApplyCompilationModeOverride(execution_context, classic_script,
                                      &inspector_data, &compile_options);
  if (inspector_data) {
    v8::ScriptCompiler::Source source(code, origin, inspector_data);
    v8::MaybeLocal<v8::Script> script =
        v8::ScriptCompiler::Compile(script_state->GetContext(), &source,
                                    v8::ScriptCompiler::kConsumeCodeCache);
    return script;
  }

  switch (static_cast<int>(compile_options)) {
    case v8::ScriptCompiler::kConsumeCompileHints:
    case v8::ScriptCompiler::kConsumeCompileHints |
        v8::ScriptCompiler::kFollowCompileHintsMagicComment: {
      // We can only consume local or crowdsourced compile hints, but
      // not both at the same time. If the page has crowdsourced compile hints,
      // we won't generate local compile hints, so won't ever have them.
      // We'd only have both local and crowdsourced compile hints available in
      // special cases, e.g., if crowdsourced compile hints were temporarily
      // unavailable, we generated local compile hints, and during the next page
      // load we have both available.

      // TODO(40286622): Enable using crowdsourced compile hints and augmenting
      // them with local compile hints. 1) Enable consuming compile hints and at
      // the same time, producing compile hints for functions which were still
      // lazy and 2) enable consuming both kind of compile hints at the same
      // time.
      if (can_use_crowdsourced_compile_hints) {
        base::UmaHistogramEnumeration(
            v8_compile_hints::kStatusHistogram,
            v8_compile_hints::Status::
                kConsumeCrowdsourcedCompileHintsClassicNonStreaming);

        // Based on how `can_use_crowdsourced_compile_hints` in CompileScript is
        // computed, we must get a non-null LocalDOMWindow and LocalFrame here.
        LocalDOMWindow* window = DynamicTo<LocalDOMWindow>(execution_context);
        CHECK(window);
        LocalFrame* frame = window->GetFrame();
        CHECK(frame);
        Page* page = frame->GetPage();
        CHECK(page);
        // This ptr keeps the data alive during v8::ScriptCompiler::Compile.
        std::unique_ptr<v8_compile_hints::V8CrowdsourcedCompileHintsConsumer::
                            DataAndScriptNameHash>
            compile_hint_data =
                page->GetV8CrowdsourcedCompileHintsConsumer()
                    .GetDataWithScriptNameHash(v8_compile_hints::ScriptNameHash(
                        origin.ResourceName(), script_state->GetContext(),
                        isolate));
        v8::ScriptCompiler::Source source(
            code, origin,
            &v8_compile_hints::V8CrowdsourcedCompileHintsConsumer::
                CompileHintCallback,
            compile_hint_data.get());
        return v8::ScriptCompiler::Compile(script_state->GetContext(), &source,
                                           compile_options, no_cache_reason);
      }
      // No crowdsourced compile hints; compile with local compile hints.
      CHECK(base::FeatureList::IsEnabled(features::kLocalCompileHints));
      base::UmaHistogramEnumeration(
          v8_compile_hints::kStatusHistogram,
          v8_compile_hints::Status::
              kConsumeLocalCompileHintsClassicNonStreaming);
      CachedMetadataHandler* cache_handler = classic_script.CacheHandler();
      CHECK(cache_handler);
      scoped_refptr<CachedMetadata> cached_metadata =
          V8CodeCache::GetCachedMetadataForCompileHints(cache_handler);
      v8_compile_hints::V8LocalCompileHintsConsumer
          v8_local_compile_hints_consumer(cached_metadata.get());
      if (v8_local_compile_hints_consumer.IsRejected()) {
        cache_handler->ClearCachedMetadata(
            ExecutionContext::GetCodeCacheHostFromContext(execution_context),
            CachedMetadataHandler::kClearPersistentStorage);
        // Compile without compile hints.
        compile_options = v8::ScriptCompiler::CompileOptions(
            compile_options & (~v8::ScriptCompiler::kConsumeCompileHints));
        v8::ScriptCompiler::Source source(code, origin);
        return v8::ScriptCompiler::Compile(script_state->GetContext(), &source,
                                           compile_options, no_cache_reason);
      }
      v8::ScriptCompiler::Source source(
          code, origin,
          v8_compile_hints::V8LocalCompileHintsConsumer::GetCompileHint,
          &v8_local_compile_hints_consumer);
      return v8::ScriptCompiler::Compile(script_state->GetContext(), &source,
                                         compile_options, no_cache_reason);
    }
    case v8::ScriptCompiler::kProduceCompileHints:
    case v8::ScriptCompiler::kProduceCompileHints |
        v8::ScriptCompiler::kFollowCompileHintsMagicComment: {
      base::UmaHistogramEnumeration(
          v8_compile_hints::kStatusHistogram,
          v8_compile_hints::Status::kProduceCompileHintsClassicNonStreaming);
      v8::ScriptCompiler::Source source(code, origin);
      return v8::ScriptCompiler::Compile(script_state->GetContext(), &source,
                                         compile_options, no_cache_reason);
    }
    case v8::ScriptCompiler::kNoCompileOptions:
    case v8::ScriptCompiler::kEagerCompile:
    case v8::ScriptCompiler::kFollowCompileHintsMagicComment: {
      base::UmaHistogramEnumeration(
          v8_compile_hints::kStatusHistogram,
          v8_compile_hints::Status::kNoCompileHintsClassicNonStreaming);
      v8::ScriptCompiler::Source source(code, origin);
      return v8::ScriptCompiler::Compile(script_state->GetContext(), &source,
                                         compile_options, no_cache_reason);
    }

    case v8::ScriptCompiler::kConsumeCodeCache: {
      base::UmaHistogramEnumeration(
          v8_compile_hints::kStatusHistogram,
          v8_compile_hints::Status::kConsumeCodeCacheClassicNonStreaming);
      // Compile a script, and consume a V8 cache that was generated previously.
      CachedMetadataHandler* cache_handler = classic_script.CacheHandler();
      ScriptCacheConsumer* cache_consumer = classic_script.CacheConsumer();
      scoped_refptr<CachedMetadata> cached_metadata =
          V8CodeCache::GetCachedMetadata(cache_handler);
      const bool full_code_cache = V8CodeCache::IsFull(cached_metadata.get());
      v8::ScriptCompiler::Source source(
          code, origin,
          V8CodeCache::CreateCachedData(cached_metadata).release(),
          cache_consumer
              ? cache_consumer->TakeV8ConsumeTask(cached_metadata.get())
              : nullptr);
      const v8::ScriptCompiler::CachedData* cached_data =
          source.GetCachedData();
      v8::MaybeLocal<v8::Script> script =
          v8::ScriptCompiler::Compile(script_state->GetContext(), &source,
                                      v8::ScriptCompiler::kConsumeCodeCache);
      cache_handler->DidUseCodeCache();
      // The ScriptState has an associated context. We expect the current
      // context to match the context associated with Script context when
      // compiling the script for main world. Hence it is safe to use the
      // CodeCacheHost corresponding to the script execution context. For
      // isolated world (for ex: extension scripts), the current context
      // may not match the script context. Though currently code caching is
      // disabled for extensions.
      if (cached_data->rejected) {
        cache_handler->ClearCachedMetadata(
            ExecutionContext::GetCodeCacheHostFromContext(
                ExecutionContext::From(script_state)),
            CachedMetadataHandler::kClearPersistentStorage);
      }
      if (cache_result) {
        *cache_result = std::make_optional(
            inspector_compile_script_event::V8ConsumeCacheResult(
                cached_data->length, cached_data->rejected, full_code_cache));
      }
      return script;
    }
    default:
      NOTREACHED();
  }
}

int GetMicrotasksScopeDepth(v8::Isolate* isolate,
                            v8::MicrotaskQueue* microtask_queue) {
  if (microtask_queue)
    return microtask_queue->GetMicrotasksScopeDepth();
  return v8::MicrotasksScope::GetCurrentDepth(isolate);
}

}  // namespace

v8::MaybeLocal<v8::Script> V8ScriptRunner::CompileScript(
    ScriptState* script_state,
    const ClassicScript& classic_script,
    v8::ScriptOrigin origin,
    v8::ScriptCompiler::CompileOptions compile_options,
    v8::ScriptCompiler::NoCacheReason no_cache_reason,
    bool can_use_crowdsourced_compile_hints) {
  v8::Isolate* isolate = script_state->GetIsolate();
  if (classic_script.SourceText().length() >= v8::String::kMaxLength) {
    V8ThrowException::ThrowError(isolate, "Source file too large.");
    return v8::Local<v8::Script>();
  }

  const String& file_name = classic_script.SourceUrl();
  const TextPosition& script_start_position = classic_script.StartPosition();

  constexpr const char* kTraceEventCategoryGroup = "v8,devtools.timeline";
  TRACE_EVENT_BEGIN1(kTraceEventCategoryGroup, "v8.compile", "fileName",
                     file_name.Utf8());
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  probe::V8Compile probe(execution_context, file_name,
                         script_start_position.line_.ZeroBasedInt(),
                         script_start_position.column_.ZeroBasedInt());

  if (!*TRACE_EVENT_API_GET_CATEGORY_GROUP_ENABLED(kTraceEventCategoryGroup)) {
    return CompileScriptInternal(isolate, script_state, classic_script, origin,
                                 compile_options, no_cache_reason,
                                 can_use_crowdsourced_compile_hints, nullptr);
  }

  std::optional<inspector_compile_script_event::V8ConsumeCacheResult>
      cache_result;
  v8::MaybeLocal<v8::Script> script = CompileScriptInternal(
      isolate, script_state, classic_script, origin, compile_options,
      no_cache_reason, can_use_crowdsourced_compile_hints, &cache_result);
  TRACE_EVENT_END1(
      kTraceEventCategoryGroup, "v8.compile", "data",
      [&](perfetto::TracedValue context) {
        inspector_compile_script_event::Data(
            std::move(context), file_name, script_start_position, cache_result,
            compile_options == v8::ScriptCompiler::kEagerCompile,
            classic_script.Streamer(), classic_script.NotStreamingReason());
      });
  return script;
}

v8::MaybeLocal<v8::Module> V8ScriptRunner::CompileModule(
    v8::Isolate* isolate,
    const ModuleScriptCreationParams& params,
    const TextPosition& start_position,
    v8::ScriptCompiler::CompileOptions compile_options,
    v8::ScriptCompiler::NoCacheReason no_cache_reason,
    const ReferrerScriptInfo& referrer_info) {
  const String file_name = params.SourceURL();
  constexpr const char* kTraceEventCategoryGroup = "v8,devtools.timeline";
  TRACE_EVENT_BEGIN1(kTraceEventCategoryGroup, "v8.compileModule", "fileName",
                     file_name.Utf8());

  // |resource_is_shared_cross_origin| is always true and |resource_is_opaque|
  // is always false because CORS is enforced to module scripts.
  v8::ScriptOrigin origin(
      V8String(isolate, file_name), start_position.line_.ZeroBasedInt(),
      start_position.column_.ZeroBasedInt(),
      true,                        // resource_is_shared_cross_origin
      -1,                          // script id
      v8::String::Empty(isolate),  // source_map_url
      false,                       // resource_is_opaque
      false,                       // is_wasm
      true,                        // is_module
      referrer_info.ToV8HostDefinedOptions(isolate, params.SourceURL()));

  v8::Local<v8::String> code = V8String(isolate, params.GetSourceText());
  std::optional<inspector_compile_script_event::V8ConsumeCacheResult>
      cache_result;
  v8::MaybeLocal<v8::Module> script;
  ScriptStreamer* streamer = params.GetScriptStreamer();
  if (streamer) {
    // Final compile call for a streamed compilation.
    // Streaming compilation may involve use of code cache.
    // TODO(leszeks): Add compile timer to streaming compilation.
    script = v8::ScriptCompiler::CompileModule(
        isolate->GetCurrentContext(), streamer->Source(v8::ScriptType::kModule),
        code, origin);
  } else {
    switch (static_cast<int>(compile_options)) {
      // TODO(40286622): Compile hints for modules.
      case v8::ScriptCompiler::kProduceCompileHints:
      case v8::ScriptCompiler::kConsumeCompileHints:
      case v8::ScriptCompiler::kFollowCompileHintsMagicComment |
          v8::ScriptCompiler::kProduceCompileHints:
      case v8::ScriptCompiler::kFollowCompileHintsMagicComment |
          v8::ScriptCompiler::kConsumeCompileHints:
        compile_options = v8::ScriptCompiler::CompileOptions(
            compile_options & (~(v8::ScriptCompiler::kProduceCompileHints |
                                 v8::ScriptCompiler::kConsumeCompileHints)));
        ABSL_FALLTHROUGH_INTENDED;
      case v8::ScriptCompiler::kFollowCompileHintsMagicComment:
      case v8::ScriptCompiler::kNoCompileOptions:
      case v8::ScriptCompiler::kEagerCompile: {
        base::UmaHistogramEnumeration(
            v8_compile_hints::kStatusHistogram,
            v8_compile_hints::Status::kNoCompileHintsModuleNonStreaming);
        v8::ScriptCompiler::Source source(code, origin);
        script = v8::ScriptCompiler::CompileModule(
            isolate, &source, compile_options, no_cache_reason);
        break;
      }

      case v8::ScriptCompiler::kConsumeCodeCache: {
        base::UmaHistogramEnumeration(
            v8_compile_hints::kStatusHistogram,
            v8_compile_hints::Status::kConsumeCodeCacheModuleNonStreaming);
        // Compile a script, and consume a V8 cache that was generated
        // previously.
        CachedMetadataHandler* cache_handler = params.CacheHandler();
        DCHECK(cache_handler);
        cache_handler->DidUseCodeCache();
        const scoped_refptr<CachedMetadata> cached_metadata =
            V8CodeCache::GetCachedMetadata(cache_handler);
        const bool full_code_cache = V8CodeCache::IsFull(cached_metadata.get());
        // TODO(leszeks): Add support for passing in ScriptCacheConsumer.
        v8::ScriptCompiler::Source source(
            code, origin,
            V8CodeCache::CreateCachedData(cache_handler).release());
        const v8::ScriptCompiler::CachedData* cached_data =
            source.GetCachedData();
        script = v8::ScriptCompiler::CompileModule(
            isolate, &source, compile_options, no_cache_reason);
        // The ScriptState also has an associated context. We expect the current
        // context to match the context associated with Script context when
        // compiling the module. Hence it is safe to use the CodeCacheHost
        // corresponding to the current execution context.
        ExecutionContext* execution_context =
            ExecutionContext::From(isolate->GetCurrentContext());
        if (cached_data->rejected) {
          cache_handler->ClearCachedMetadata(
              ExecutionContext::GetCodeCacheHostFromContext(execution_context),
              CachedMetadataHandler::kClearPersistentStorage);
        }
        cache_result = std::make_optional(
            inspector_compile_script_event::V8ConsumeCacheResult(
                cached_data->length, cached_data->rejected, full_code_cache));
        break;
      }
      default:
        NOTREACHED();
    }
  }

  TRACE_EVENT_END1(kTraceEventCategoryGroup, "v8.compileModule", "data",
                   [&](perfetto::TracedValue context) {
                     inspector_compile_script_event::Data(
                         std::move(context), file_name, start_position,
                         cache_result,
                         compile_options == v8::ScriptCompiler::kEagerCompile,
                         streamer, params.NotStreamingReason());
                   });
  return script;
}

v8::MaybeLocal<v8::Value> V8ScriptRunner::RunCompiledScript(
    v8::Isolate* isolate,
    v8::Local<v8::Script> script,
    v8::Local<v8::Data> host_defined_options,
    ExecutionContext* context) {
  DCHECK(!script.IsEmpty());

  v8::Local<v8::Value> script_name =
      script->GetUnboundScript()->GetScriptName();
  TRACE_EVENT1("v8", "v8.run", "fileName",
               TRACE_STR_COPY(*v8::String::Utf8Value(isolate, script_name)));
  RuntimeCallStatsScopedTracer rcs_scoped_tracer(isolate);
  RUNTIME_CALL_TIMER_SCOPE(isolate, RuntimeCallStats::CounterId::kV8);

  v8::MicrotaskQueue* microtask_queue = ToMicrotaskQueue(context);
  if (GetMicrotasksScopeDepth(isolate, microtask_queue) > kMaxRecursionDepth)
    return ThrowStackOverflowExceptionIfNeeded(isolate, microtask_queue);

  CHECK(!context->ContextLifecycleObserverSet().IsIteratingOverObservers());

  // Run the script and keep track of the current recursion depth.
  v8::MaybeLocal<v8::Value> result;
  {
    if (ScriptForbiddenScope::IsScriptForbidden()) {
      ThrowScriptForbiddenException(isolate);
      return v8::MaybeLocal<v8::Value>();
    }
    if (RuntimeEnabledFeatures::BlinkLifecycleScriptForbiddenEnabled()) {
      CHECK(!ScriptForbiddenScope::WillBeScriptForbidden());
    } else {
      DCHECK(!ScriptForbiddenScope::WillBeScriptForbidden());
    }

    v8::MicrotasksScope microtasks_scope(isolate, microtask_queue,
                                         v8::MicrotasksScope::kRunMicrotasks);
    v8::Local<v8::String> script_url;
    if (!script_name->ToString(isolate->GetCurrentContext())
             .ToLocal(&script_url))
      return result;

    // ToCoreString here should be zero copy due to externalized string
    // unpacked.
    String url = ToCoreString(isolate, script_url);
    probe::ExecuteScript probe(context, isolate->GetCurrentContext(), url,
                               script->GetUnboundScript()->GetId());
    result = script->Run(isolate->GetCurrentContext(), host_defined_options);
  }

  CHECK(!isolate->IsDead());
  return result;
}

namespace {
void DelayedProduceCodeCacheTask(ScriptState* script_state,
                                 v8::Global<v8::Script> script,
                                 CachedMetadataHandler* cache_handler,
                                 size_t source_text_length,
                                 KURL source_url,
                                 TextPosition source_start_position) {
  if (!script_state->ContextIsValid())
    return;
  ScriptState::Scope scope(script_state);
  v8::Isolate* isolate = script_state->GetIsolate();
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  V8CodeCache::ProduceCache(
      isolate, ExecutionContext::GetCodeCacheHostFromContext(execution_context),
      script.Get(isolate), cache_handler, source_text_length, source_url,
      source_start_position,
      V8CodeCache::ProduceCacheOptions::kProduceCodeCache);
}
}  // namespace

ScriptEvaluationResult V8ScriptRunner::CompileAndRunScript(
    ScriptState* script_state,
    ClassicScript* classic_script,
    ExecuteScriptPolicy policy,
    RethrowErrorsOption rethrow_errors) {
  CHECK(script_state);

  // |script_state->GetContext()| must be initialized here already, typically
  // due to a WindowProxy() call inside ToScriptState*() that is used to get the
  // ScriptState.

  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  DCHECK(execution_context->IsContextThread());

  if (policy == ExecuteScriptPolicy::kDoNotExecuteScriptWhenScriptsDisabled &&
      !execution_context->CanExecuteScripts(kAboutToExecuteScript)) {
    return ScriptEvaluationResult::FromClassicNotRun();
  }

  v8::Isolate* isolate = script_state->GetIsolate();
  const SanitizeScriptErrors sanitize_script_errors =
      classic_script->GetSanitizeScriptErrors();

  LocalDOMWindow* window = DynamicTo<LocalDOMWindow>(execution_context);
  WorkerOrWorkletGlobalScope* worker_or_worklet_global_scope =
      DynamicTo<WorkerOrWorkletGlobalScope>(execution_context);
  LocalFrame* frame = window ? window->GetFrame() : nullptr;

  if (window && window->document()->IsInitialEmptyDocument()) {
    window->GetFrame()->Loader().DidAccessInitialDocument();
  } else if (worker_or_worklet_global_scope) {
    DCHECK_EQ(
        script_state,
        worker_or_worklet_global_scope->ScriptController()->GetScriptState());
    DCHECK(worker_or_worklet_global_scope->ScriptController()
               ->IsContextInitialized());
    DCHECK(worker_or_worklet_global_scope->ScriptController()
               ->IsReadyToEvaluate());
  }

  v8::Context::Scope scope(script_state->GetContext());

  DEVTOOLS_TIMELINE_TRACE_EVENT(
      "EvaluateScript", inspector_evaluate_script_event::Data, isolate, frame,
      classic_script->SourceUrl().GetString(), classic_script->StartPosition());

  // Scope for |v8::TryCatch|.
  {
    v8::TryCatch try_catch(isolate);
    // Step 8.3. Otherwise, rethrow errors is false. Perform the following
    // steps: [spec text]
    // Step 8.3.1. Report the exception given by evaluationStatus.[[Value]]
    // for script. [spec text]
    //
    // This will be done inside V8 by setting TryCatch::SetVerbose(true) here.
    if (!rethrow_errors.ShouldRethrow()) {
      try_catch.SetVerbose(true);
    }

    v8::Local<v8::Script> script;

    CachedMetadataHandler* cache_handler = classic_script->CacheHandler();
    if (cache_handler) {
      cache_handler->Check(
          ExecutionContext::GetCodeCacheHostFromContext(execution_context),
          classic_script->SourceText());
    }
    v8::ScriptCompiler::CompileOptions compile_options;
    V8CodeCache::ProduceCacheOptions produce_cache_options;
    v8::ScriptCompiler::NoCacheReason no_cache_reason;
    Page* page = frame != nullptr ? frame->GetPage() : nullptr;
    const bool is_http = classic_script->SourceUrl().ProtocolIsInHTTPFamily();
    const bool might_generate_crowdsourced_compile_hints =
        is_http && page != nullptr &&
        page->GetV8CrowdsourcedCompileHintsProducer().MightGenerateData();
    const bool can_use_crowdsourced_compile_hints =
        is_http && page != nullptr && page->MainFrame() == frame &&
        page->GetV8CrowdsourcedCompileHintsConsumer().HasData();

    std::tie(compile_options, produce_cache_options, no_cache_reason) =
        V8CodeCache::GetCompileOptions(
            execution_context->GetV8CacheOptions(), *classic_script,
            might_generate_crowdsourced_compile_hints,
            can_use_crowdsourced_compile_hints,
            v8_compile_hints::GetMagicCommentMode(execution_context));

    v8::ScriptOrigin origin = classic_script->CreateScriptOrigin(isolate);
    v8::MaybeLocal<v8::Value> maybe_result;
    if (V8ScriptRunner::CompileScript(script_state, *classic_script, origin,
                                      compile_options, no_cache_reason,
                                      can_use_crowdsourced_compile_hints)
            .ToLocal(&script)) {
      DEVTOOLS_TIMELINE_TRACE_EVENT_WITH_CATEGORIES(
          TRACE_DISABLED_BY_DEFAULT("devtools.target-rundown"),
          "ScriptCompiled", inspector_target_rundown_event::Data,
          execution_context, isolate, script_state,
          script->GetUnboundScript()->GetId());
      maybe_result = V8ScriptRunner::RunCompiledScript(
          isolate, script, origin.GetHostDefinedOptions(), execution_context);
      probe::DidProduceCompilationCache(
          probe::ToCoreProbeSink(execution_context), *classic_script, script);

      // The ScriptState has an associated context. We expect the current
      // context to match the context associated with Script context when
      // compiling the script in the main world. Hence it is safe to use the
      // CodeCacheHost corresponding to the script execution context. For
      // isolated world the contexts may not match. Though code caching is
      // disabled for extensions so it is OK to use execution_context here.

      if (produce_cache_options ==
              V8CodeCache::ProduceCacheOptions::kProduceCodeCache &&
          cache_handler) {
        cache_handler->WillProduceCodeCache();
      }
      if (produce_cache_options ==
              V8CodeCache::ProduceCacheOptions::kProduceCodeCache &&
          base::FeatureList::IsEnabled(features::kCacheCodeOnIdle) &&
          (features::kCacheCodeOnIdleDelayServiceWorkerOnlyParam.Get()
               ? execution_context->IsServiceWorkerGlobalScope()
```