Response:
Let's break down the thought process for analyzing this `gpu.cc` file.

**1. Initial Skim and Keyword Spotting:**

The first step is a quick read-through, looking for keywords and patterns that give clues about the file's purpose. I'd be scanning for:

* **`webgpu`**:  The directory name itself is a strong indicator, confirmed by the `#include` and the class name `GPU`.
* **`javascript`, `html`, `css` (or related terms like `bindings`, `v8`, `dom`, `canvas`)**: These would signal interaction with the web platform.
* **`adapter`, `device`, `buffer`, `texture`, `command buffer`**:  These are common terms in graphics APIs, suggesting the file deals with low-level graphics operations.
* **`promise`, `callback`, `async`**:  Indicate asynchronous operations, common when interacting with hardware or external processes.
* **`console`, `warning`, `error`**: Suggest error handling and user feedback.
* **`mojom`**: This signifies Mojo interfaces, which are used for inter-process communication in Chromium.
* **`feature list`, `identifiability`, `privacy budget`**: Point to potential configuration and privacy-related concerns.
* **`ContextDestroyed`**:  A lifecycle method, important for resource management.

**2. Identifying Core Functionality:**

Based on the keywords, it's clear this file is the main entry point for the WebGPU API within the Blink renderer. The primary function seems to be managing the interaction between JavaScript WebGPU calls and the underlying graphics system (likely Dawn, as hinted by `dawn_enum_conversions.h` and `DawnControlClientHolder`).

**3. Dissecting Key Methods:**

Now, I'd focus on the prominent methods to understand their specific roles:

* **`GPU::gpu(NavigatorBase& navigator)`**: This is likely how the `GPU` object is accessed from JavaScript. The `Supplement` pattern confirms this.
* **`RequestAdapterImpl` and `requestAdapter`**:  These are central to obtaining a `GPUAdapter`, the starting point for most WebGPU operations. The `Impl` suffix often indicates an internal implementation detail. The presence of promises confirms its asynchronous nature.
* **`OnRequestAdapterCallback`**: This handles the result of the adapter request, dealing with success and error scenarios.
* **`ContextDestroyed`**:  This is crucial for cleanup when the rendering context is lost, preventing memory leaks and ensuring stability. The detaching of `ArrayBuffer`s is a key detail here.
* **`getPreferredCanvasFormat`**: This deals with a specific aspect of integrating WebGPU with the `<canvas>` element.
* **`TrackMappableBuffer` and `UntrackMappableBuffer`**: These methods indicate the file manages the lifecycle of certain buffers that can be mapped to JavaScript `ArrayBuffer`s.

**4. Connecting to JavaScript, HTML, and CSS:**

With the core functionality understood, I can now make connections to the web platform:

* **JavaScript:** The `requestAdapter` method is directly exposed to JavaScript. The `GPUAdapter`, `GPUBuffer`, etc., mentioned in the includes, will also have JavaScript counterparts. The code uses V8-specific types (`ScriptState`, `ScriptPromiseResolver`) confirming the bridge between C++ and JavaScript.
* **HTML:** The `getPreferredCanvasFormat` method directly relates to the `<canvas>` element and how WebGPU integrates with it.
* **CSS:**  While no direct CSS interaction is apparent in this file, WebGPU ultimately *renders* things that might be styled by CSS. However, this file focuses on the *API* itself, not the rendering pipeline. It's important to distinguish the API layer from the rendering and styling layers.

**5. Logical Reasoning and Examples (Hypothetical Input/Output):**

For `requestAdapter`, I'd consider:

* **Input:** JavaScript calls `navigator.gpu.requestAdapter()`.
* **Output:** A Promise that resolves with a `GPUAdapter` object (if successful) or `null` (though the code mentions it doesn't reject, just warns).

For `getPreferredCanvasFormat`:

* **Input:** JavaScript calls `navigator.gpu.getPreferredCanvasFormat()`.
* **Output:** A string like `"bgra8unorm"` or `"rgba8unorm"`.

**6. Common Usage Errors:**

I'd look for error handling and consider what could go wrong:

* Calling `requestAdapter` before the GPU service is available.
* Incorrectly specifying adapter options (though the code currently ignores `powerPreference` on Windows).
* Not handling the asynchronous nature of `requestAdapter` (e.g., trying to use the adapter before the promise resolves).
* Resource leaks if `destroy()` methods are not called properly on WebGPU objects. The `ContextDestroyed` method addresses a part of this, but user code also plays a role.

**7. Debugging Clues and User Actions:**

To trace how a user reaches this code, I'd think about the WebGPU workflow:

1. **User opens a web page.**
2. **JavaScript code on the page calls `navigator.gpu`.** This leads to the `GPU::gpu` method.
3. **The script calls `navigator.gpu.requestAdapter(options)`.** This hits the `requestAdapter` method in `gpu.cc`.
4. **The browser then interacts with the GPU process** via Mojo to get an adapter.

Debugging might involve setting breakpoints in `requestAdapter`, `OnRequestAdapterCallback`, and the Dawn-related code to see the flow of execution and the values of variables.

**8. Refinement and Organization:**

Finally, I'd organize the information into clear categories (Functionality, Relationship to Web Technologies, Logic, Errors, Debugging) and provide concrete examples where possible. I would also explicitly state assumptions and areas where the code's behavior is noted (like `powerPreference` on Windows). The goal is to be comprehensive and easy to understand.
This file, `blink/renderer/modules/webgpu/gpu.cc`, is the core implementation of the `GPU` interface in the WebGPU API within the Blink rendering engine (which powers Chromium's rendering). It acts as the entry point for JavaScript code to interact with the underlying graphics hardware capabilities.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Entry Point for WebGPU:** It provides the `navigator.gpu` property in JavaScript, allowing web pages to access WebGPU functionality. The `GPU::gpu(NavigatorBase& navigator)` static method is responsible for creating and providing this object.
2. **Adapter Requesting (`requestAdapter`):** The primary function is to handle the `requestAdapter()` method called from JavaScript. This method allows web applications to request access to a suitable GPU adapter (graphics card).
    * It takes `GPURequestAdapterOptions` as input, allowing the application to specify preferences like power usage (`low-power` or `high-performance`).
    * It communicates with the browser process (via Mojo) and the GPU process (potentially via Dawn, a cross-platform WebGPU implementation) to find a suitable adapter.
    * It returns a `Promise` that resolves with a `GPUAdapter` object (if successful) or `null` (in cases where an adapter isn't available or an error occurs).
3. **Preferred Canvas Format (`getPreferredCanvasFormat`):**  It provides a method to determine the preferred texture format for rendering to a `<canvas>` element. This helps optimize performance and compatibility.
4. **Manages Dawn Integration:** It interacts with Dawn through `DawnControlClientHolder` to manage the underlying WebGPU implementation. This includes initializing the Dawn context and handling context loss.
5. **Handles Context Lifecycle:** It implements `ContextDestroyed()` to clean up resources (like destroying WebGPU buffers) when the rendering context is lost. This is crucial to prevent memory leaks.
6. **Tracks Mappable Buffers:** It maintains a set of `GPUBuffer` objects that can be mapped to JavaScript `ArrayBuffer`s for CPU access. This allows efficient data transfer between the CPU and GPU.
7. **Privacy Budget Integration:** The code includes logic to record adapter requests and available features for privacy analysis using the Identifiability framework. This helps understand potential fingerprinting risks associated with WebGPU.
8. **Feature Flag Handling:** It checks for the `kWebGPUService` feature flag, indicating whether WebGPU is enabled on the current platform.
9. **Console Warnings and Errors:** It adds console messages to inform developers about potential issues, such as using WebGPU on experimental platforms or when specific options are ignored.

**Relationship to JavaScript, HTML, and CSS:**

* **JavaScript:** This file directly bridges the gap between JavaScript and the underlying graphics system. The `GPU` class and its methods (`requestAdapter`, `getPreferredCanvasFormat`) are exposed to JavaScript through the `navigator.gpu` object. JavaScript code uses these methods to initiate WebGPU operations.

    * **Example:**  A JavaScript snippet like this directly interacts with `gpu.cc`:
      ```javascript
      navigator.gpu.requestAdapter().then(adapter => {
        if (adapter) {
          console.log("Found an adapter!", adapter);
          // ... proceed to create a device, etc.
        } else {
          console.log("No adapter found.");
        }
      });
      ```

* **HTML:** While this file doesn't directly manipulate the HTML DOM, it's intrinsically linked to the `<canvas>` element. The `getPreferredCanvasFormat()` method is specifically designed for optimal WebGPU rendering within a canvas. WebGPU is often used to render graphics within a canvas.

    * **Example:** When a WebGL context is requested on a `<canvas>` element, and WebGPU is the underlying implementation, this code plays a role in setting up the rendering pipeline.

* **CSS:** There's no direct interaction with CSS at the level of this file. However, the visual output generated by WebGPU (driven by JavaScript interacting with this `gpu.cc` implementation) will ultimately be rendered within the web page's layout, which is influenced by CSS.

**Logical Reasoning and Examples (Hypothetical Input and Output):**

Let's focus on the `requestAdapter` method:

**Hypothetical Input:**

A JavaScript call:

```javascript
navigator.gpu.requestAdapter({ powerPreference: "high-performance" });
```

**Logical Reasoning within `gpu.cc`:**

1. The `requestAdapter` method in `gpu.cc` is called with `options` specifying "high-performance".
2. The code converts the `V8GPUPowerPreference` enum to the Dawn equivalent (`wgpu::PowerPreference::HighPerformance`).
3. It communicates with the GPU service (via Mojo) to request an adapter with this preference.
4. The GPU service (potentially using Dawn) enumerates available GPUs and selects one that best matches the criteria.
5. The result (the `wgpu::Adapter` object) is passed back to the `OnRequestAdapterCallback`.
6. A `GPUAdapter` object is created in Blink and the promise in JavaScript resolves with this object.

**Hypothetical Output:**

The JavaScript promise resolves with a `GPUAdapter` object representing a discrete high-performance GPU (if available). If no such adapter is found, the promise might resolve with `null`, or a warning might be logged to the console.

**Common Usage Errors and Examples:**

1. **Calling `requestAdapter` without proper error handling:**

   ```javascript
   const adapter = await navigator.gpu.requestAdapter(); // Potential error if no adapter found
   const device = await adapter.requestDevice(); // adapter might be null, causing an error
   ```
   **Explanation:** If `requestAdapter` fails to find a suitable adapter, it might return `null`. Trying to call methods on a `null` object will lead to JavaScript errors.

2. **Assuming synchronous behavior:**

   ```javascript
   const adapter = navigator.gpu.requestAdapter();
   const device = adapter.requestDevice(); // Incorrect, adapter is a Promise
   ```
   **Explanation:** `requestAdapter` returns a `Promise`. Developers need to use `then()` or `await` to access the resolved `GPUAdapter` object.

3. **Ignoring console warnings:**

   If the code logs warnings about `powerPreference` being ignored on certain platforms, developers who rely on this option might not get the intended behavior.

**User Operation Steps to Reach This Code (Debugging Clues):**

1. **User opens a web page that uses WebGPU:** The page's JavaScript code will start executing.
2. **JavaScript calls `navigator.gpu.requestAdapter(options)`:** This is the primary entry point into `gpu.cc`.
3. **The browser then communicates with the GPU process:** You might see Mojo messages being exchanged in debugging tools.
4. **Dawn (or another WebGPU implementation) interacts with the graphics driver:** Lower-level debugging might involve looking at graphics API calls.

**As a debugging线索 (debugging clue):**

* **Breakpoints:** Setting breakpoints in `GPU::requestAdapterImpl`, `GPU::OnRequestAdapterCallback`, and potentially within the Dawn integration code (`DawnControlClientHolder`) would be useful to trace the flow of execution.
* **Console Logging:**  The code itself uses console logging for warnings. Adding more logging within these methods can provide valuable insights into the values of variables and the decision-making process.
* **Mojo Inspection:** Tools for inspecting Mojo message passing can help understand the communication between the renderer process and the GPU process.
* **GPU Tracing Tools:** Platform-specific GPU tracing tools can reveal how the requested adapter is selected and the underlying graphics API calls being made.

In summary, `blink/renderer/modules/webgpu/gpu.cc` is a crucial file that acts as the central hub for the WebGPU API within the Blink rendering engine. It handles the initial steps of requesting a GPU adapter and sets the stage for further WebGPU operations initiated by JavaScript code.

### 提示词
```
这是目录为blink/renderer/modules/webgpu/gpu.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webgpu/gpu.h"

#include <utility>

#include "base/feature_list.h"
#include "base/notreached.h"
#include "base/synchronization/waitable_event.h"
#include "gpu/command_buffer/client/webgpu_interface.h"
#include "gpu/config/gpu_finch_features.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_metric_builder.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_study_settings.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_token_builder.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/mojom/gpu/gpu.mojom-blink.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-shared.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_graphics_context_3d_provider.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_request_adapter_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_texture_format.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/navigator_base.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/modules/webgpu/dawn_enum_conversions.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_adapter.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_buffer.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_supported_features.h"
#include "third_party/blink/renderer/modules/webgpu/string_utils.h"
#include "third_party/blink/renderer/modules/webgpu/wgsl_language_features.h"
#include "third_party/blink/renderer/platform/graphics/gpu/dawn_control_client_holder.h"
#include "third_party/blink/renderer/platform/graphics/gpu/webgpu_callback.h"
#include "third_party/blink/renderer/platform/graphics/web_graphics_context_3d_provider_util.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_handle.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/privacy_budget/identifiability_digest_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"

namespace blink {

namespace {

[[maybe_unused]] void AddConsoleWarning(ExecutionContext* execution_context,
                                        const char* message) {
  if (execution_context) {
    auto* console_message = MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kRendering,
        mojom::blink::ConsoleMessageLevel::kWarning,
        StringFromASCIIAndUTF8(message));
    execution_context->AddConsoleMessage(console_message);
  }
}

wgpu::PowerPreference AsDawnType(V8GPUPowerPreference power_preference) {
  switch (power_preference.AsEnum()) {
    case V8GPUPowerPreference::Enum::kLowPower:
      return wgpu::PowerPreference::LowPower;
    case V8GPUPowerPreference::Enum::kHighPerformance:
      return wgpu::PowerPreference::HighPerformance;
  }
}

wgpu::RequestAdapterOptions AsDawnType(
    const GPURequestAdapterOptions* webgpu_options) {
  DCHECK(webgpu_options);

  wgpu::RequestAdapterOptions dawn_options = {
      .forceFallbackAdapter = webgpu_options->forceFallbackAdapter(),
      .compatibilityMode = webgpu_options->compatibilityMode(),
  };
  if (webgpu_options->hasPowerPreference()) {
    dawn_options.powerPreference =
        AsDawnType(webgpu_options->powerPreference());
  }

  return dawn_options;
}

// Returns the execution context token given the context. Currently returning
// the WebGPU specific execution context token.
// TODO(dawn:549) Might be able to use ExecutionContextToken instead of WebGPU
//     specific execution context token if/when DocumentToken becomes a part of
//     ExecutionContextToken.
WebGPUExecutionContextToken GetExecutionContextToken(
    const ExecutionContext* execution_context) {
  // WebGPU only supports the following types of context tokens: DocumentTokens,
  // DedicatedWorkerTokens, SharedWorkerTokens, and ServiceWorkerTokens. The
  // token is sent to the GPU process so that it can be cross-referenced against
  // the browser process to get an isolation key for caching purposes.
  if (execution_context->IsDedicatedWorkerGlobalScope()) {
    return execution_context->GetExecutionContextToken()
        .GetAs<DedicatedWorkerToken>();
  }
  if (execution_context->IsSharedWorkerGlobalScope()) {
    return execution_context->GetExecutionContextToken()
        .GetAs<SharedWorkerToken>();
  }
  if (execution_context->IsServiceWorkerGlobalScope()) {
    return execution_context->GetExecutionContextToken()
        .GetAs<ServiceWorkerToken>();
  }
  if (execution_context->IsWindow()) {
    return To<LocalDOMWindow>(execution_context)->document()->Token();
  }
  NOTREACHED();
}

}  // anonymous namespace

// static
const char GPU::kSupplementName[] = "GPU";

// static
GPU* GPU::gpu(NavigatorBase& navigator) {
  GPU* gpu = Supplement<NavigatorBase>::From<GPU>(navigator);
  if (!gpu) {
    gpu = MakeGarbageCollected<GPU>(navigator);
    ProvideTo(navigator, gpu);
  }
  return gpu;
}

GPU::GPU(NavigatorBase& navigator)
    : Supplement<NavigatorBase>(navigator),
      ExecutionContextLifecycleObserver(navigator.GetExecutionContext()),
      wgsl_language_features_(
          MakeGarbageCollected<WGSLLanguageFeatures>(GatherWGSLFeatures())),
      mappable_buffer_handles_(
          base::MakeRefCounted<BoxedMappableWGPUBufferHandles>()) {}

GPU::~GPU() = default;

WGSLLanguageFeatures* GPU::wgslLanguageFeatures() const {
  return wgsl_language_features_.Get();
}

void GPU::Trace(Visitor* visitor) const {
  ScriptWrappable::Trace(visitor);
  Supplement<NavigatorBase>::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
  visitor->Trace(mappable_buffers_);
  visitor->Trace(wgsl_language_features_);
}

void GPU::ContextDestroyed() {
  if (!dawn_control_client_) {
    return;
  }
  // Ensure all DOMArrayBuffers backed by shared memory are detached before
  // the WebGPU command buffer and transfer buffers are destroyed.
  // This is necessary because we will free the shmem backings, and some
  // short amount of JS can still execute after the ContextDestroyed event
  // is received.
  if (!mappable_buffers_.empty()) {
    v8::Isolate* isolate = GetExecutionContext()->GetIsolate();
    v8::HandleScope scope(isolate);
    for (GPUBuffer* buffer : mappable_buffers_) {
      buffer->DetachMappedArrayBuffers(isolate);
    }
  }
  // GPUBuffer::~GPUBuffer and GPUBuffer::destroy will remove wgpu::Buffers from
  // |mappable_buffer_handles_|.
  // However, there may be GPUBuffers that were removed from mappable_buffers_
  // for which ~GPUBuffer has not run yet. These GPUBuffers and their
  // DOMArrayBuffer mappings are no longer reachable from JS, so we don't need
  // to detach them, but we do need to eagerly destroy the wgpu::Buffer so that
  // its shared memory is freed before the context is completely destroyed.
  mappable_buffer_handles_->ClearAndDestroyAll();
  dawn_control_client_->Destroy();
}

void GPU::OnRequestAdapterCallback(
    ScriptState* script_state,
    const GPURequestAdapterOptions* options,
    ScriptPromiseResolver<IDLNullable<GPUAdapter>>* resolver,
    wgpu::RequestAdapterStatus status,
    wgpu::Adapter adapter,
    wgpu::StringView error_message) {
  GPUAdapter* gpu_adapter = nullptr;
  switch (status) {
    case wgpu::RequestAdapterStatus::Success:
      gpu_adapter = MakeGarbageCollected<GPUAdapter>(
          this, std::move(adapter), dawn_control_client_, options);
      break;

    // Note: requestAdapter never rejects, but we print a console warning if
    // there are error messages.
    case wgpu::RequestAdapterStatus::Unavailable:
    case wgpu::RequestAdapterStatus::Error:
    case wgpu::RequestAdapterStatus::Unknown:
    case wgpu::RequestAdapterStatus::InstanceDropped:
      break;
  }
  if (error_message.length != 0) {
    ExecutionContext* execution_context = ExecutionContext::From(script_state);
    auto* console_message = MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kRendering,
        mojom::blink::ConsoleMessageLevel::kWarning,
        StringFromASCIIAndUTF8(error_message));
    execution_context->AddConsoleMessage(console_message);
  }
  RecordAdapterForIdentifiability(script_state, options, gpu_adapter);
  resolver->Resolve(gpu_adapter);
}

void GPU::RecordAdapterForIdentifiability(
    ScriptState* script_state,
    const GPURequestAdapterOptions* options,
    GPUAdapter* adapter) const {
  constexpr IdentifiableSurface::Type type =
      IdentifiableSurface::Type::kGPU_RequestAdapter;
  if (!IdentifiabilityStudySettings::Get()->ShouldSampleType(type))
    return;
  ExecutionContext* context = GetExecutionContext();
  if (!context)
    return;

  IdentifiableTokenBuilder input_builder;
  if (options && options->hasPowerPreference()) {
    input_builder.AddToken(IdentifiabilityBenignStringToken(
        options->powerPreference().AsString()));
  }
  const auto surface =
      IdentifiableSurface::FromTypeAndToken(type, input_builder.GetToken());

  IdentifiableTokenBuilder output_builder;
  if (adapter) {
    for (const auto& feature : adapter->features()->FeatureNameSet()) {
      output_builder.AddToken(IdentifiabilityBenignStringToken(feature));
    }
  }

  IdentifiabilityMetricBuilder(context->UkmSourceID())
      .Add(surface, output_builder.GetToken())
      .Record(context->UkmRecorder());
}

std::unique_ptr<WebGraphicsContext3DProvider> CheckContextProvider(
    const KURL& url,
    std::unique_ptr<WebGraphicsContext3DProvider> context_provider) {
  // Note that we check for API blocking *after* creating the context. This is
  // because context creation synchronizes against GpuProcessHost lifetime in
  // the browser process, and GpuProcessHost destruction is what updates API
  // blocking state on a GPU process crash. See https://crbug.com/1215907#c10
  // for more details.
  bool blocked = true;
  mojo::Remote<mojom::blink::GpuDataManager> gpu_data_manager;
  Platform::Current()->GetBrowserInterfaceBroker()->GetInterface(
      gpu_data_manager.BindNewPipeAndPassReceiver());
  gpu_data_manager->Are3DAPIsBlockedForUrl(url, &blocked);
  if (blocked) {
    return nullptr;
  }

  // TODO(kainino): we will need a better way of accessing the GPU interface
  // from multiple threads than BindToCurrentSequence et al.
  if (context_provider && !context_provider->BindToCurrentSequence()) {
    // TODO(crbug.com/973017): Collect GPU info and surface context creation
    // error.
    return nullptr;
  }
  return context_provider;
}

void GPU::RequestAdapterImpl(
    ScriptState* script_state,
    const GPURequestAdapterOptions* options,
    ScriptPromiseResolver<IDLNullable<GPUAdapter>>* resolver) {
  ExecutionContext* execution_context = ExecutionContext::From(script_state);

  // Validate that the featureLevel is undefined. If not return a null adapter.
  // This logic will evolve as feature levels are added in the future.
  if (options->hasFeatureLevel()) {
    OnRequestAdapterCallback(script_state, options, resolver,
                             wgpu::RequestAdapterStatus::Error, nullptr,
                             "Unknown feature level");
    return;
  }

#if BUILDFLAG(IS_WIN)
  // TODO(crbug.com/369219127): Chrome always uses the same GPU adapter that's
  // been allocated for other Chrome workloads on Windows, which for laptops is
  // generally the integrated graphics card, due to the power usage aspect (ie:
  // power saving).
  if (options->hasPowerPreference()) {
    AddConsoleWarning(
        execution_context,
        "The powerPreference option is currently ignored when calling "
        "requestAdapter() on Windows. See https://crbug.com/369219127");
  }
#endif

  if (!dawn_control_client_ || dawn_control_client_->IsContextLost()) {
    dawn_control_client_initialized_callbacks_.push_back(WTF::BindOnce(
        [](GPU* gpu, ScriptState* script_state,
           const GPURequestAdapterOptions* options,
           ScriptPromiseResolver<IDLNullable<GPUAdapter>>* resolver) {
          if (gpu->dawn_control_client_ &&
              !gpu->dawn_control_client_->IsContextLost()) {
            gpu->RequestAdapterImpl(script_state, options, resolver);
          } else {
            // Failed to create context provider, won't be able to request
            // adapter
            // TODO(crbug.com/973017): Collect GPU info and surface context
            // creation error.
            gpu->OnRequestAdapterCallback(
                script_state, options, resolver,
                wgpu::RequestAdapterStatus::Error, nullptr,
                "Failed to create WebGPU Context Provider");
          }
        },
        WrapPersistent(this), WrapPersistent(script_state),
        WrapPersistent(options), WrapPersistent(resolver)));

    // Returning since the task to create the control client from a previous
    // call to EnsureDawnControlClientInitialized should be already running
    if (dawn_control_client_initialized_callbacks_.size() > 1) {
      return;
    }

    CreateWebGPUGraphicsContext3DProviderAsync(
        execution_context->Url(),
        execution_context->GetTaskRunner(TaskType::kWebGPU),
        CrossThreadBindOnce(
            [](CrossThreadHandle<GPU> gpu_handle,
               CrossThreadHandle<ExecutionContext> execution_context_handle,
               std::unique_ptr<WebGraphicsContext3DProvider> context_provider) {
              auto unwrap_gpu = MakeUnwrappingCrossThreadHandle(gpu_handle);
              auto unwrap_execution_context =
                  MakeUnwrappingCrossThreadHandle(execution_context_handle);
              if (!unwrap_gpu || !unwrap_execution_context) {
                return;
              }
              auto* gpu = unwrap_gpu.GetOnCreationThread();
              auto* execution_context =
                  unwrap_execution_context.GetOnCreationThread();
              const KURL& url = execution_context->Url();
              context_provider =
                  CheckContextProvider(url, std::move(context_provider));
              if (context_provider) {
                context_provider->WebGPUInterface()
                    ->SetWebGPUExecutionContextToken(
                        GetExecutionContextToken(execution_context));

                // Make a new DawnControlClientHolder with the context provider
                // we just made and set the lost context callback
                gpu->dawn_control_client_ = DawnControlClientHolder::Create(
                    std::move(context_provider),
                    execution_context->GetTaskRunner(TaskType::kWebGPU));
              }

              WTF::Vector<base::OnceCallback<void()>> callbacks =
                  std::move(gpu->dawn_control_client_initialized_callbacks_);
              for (auto& callback : callbacks) {
                std::move(callback).Run();
              }
            },
            MakeCrossThreadHandle(this),
            MakeCrossThreadHandle(execution_context)));
    return;
  }

  DCHECK_NE(dawn_control_client_, nullptr);

  wgpu::RequestAdapterOptions dawn_options = AsDawnType(options);
  auto* callback = MakeWGPUOnceCallback(resolver->WrapCallbackInScriptScope(
      WTF::BindOnce(&GPU::OnRequestAdapterCallback, WrapPersistent(this),
                    WrapPersistent(script_state), WrapPersistent(options))));

  dawn_control_client_->GetWGPUInstance().RequestAdapter(
      &dawn_options, wgpu::CallbackMode::AllowSpontaneous,
      callback->UnboundCallback(), callback->AsUserdata());
  dawn_control_client_->EnsureFlush(
      *execution_context->GetAgent()->event_loop());

  UseCounter::Count(execution_context, WebFeature::kWebGPURequestAdapter);
}

ScriptPromise<IDLNullable<GPUAdapter>> GPU::requestAdapter(
    ScriptState* script_state,
    const GPURequestAdapterOptions* options) {
  // Remind developers when they are using WebGPU on unsupported platforms.
  ExecutionContext* execution_context = GetExecutionContext();
  if (execution_context &&
      !base::FeatureList::IsEnabled(features::kWebGPUService)) {
    execution_context->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kJavaScript,
        mojom::blink::ConsoleMessageLevel::kInfo,
        "WebGPU is experimental on this platform. See "
        "https://github.com/gpuweb/gpuweb/wiki/"
        "Implementation-Status#implementation-status"));
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLNullable<GPUAdapter>>>(
          script_state);
  auto promise = resolver->Promise();
  RequestAdapterImpl(script_state, options, resolver);
  return promise;
}

V8GPUTextureFormat GPU::getPreferredCanvasFormat() {
  return FromDawnEnum(preferred_canvas_format());
}

wgpu::TextureFormat GPU::preferred_canvas_format() {
#if BUILDFLAG(IS_ANDROID)
  return wgpu::TextureFormat::RGBA8Unorm;
#else
  return wgpu::TextureFormat::BGRA8Unorm;
#endif
}

void GPU::TrackMappableBuffer(GPUBuffer* buffer) {
  mappable_buffers_.insert(buffer);
  mappable_buffer_handles_->insert(buffer->GetHandle());
}

void GPU::UntrackMappableBuffer(GPUBuffer* buffer) {
  mappable_buffers_.erase(buffer);
  mappable_buffer_handles_->erase(buffer->GetHandle());
}

void BoxedMappableWGPUBufferHandles::ClearAndDestroyAll() {
  for (const wgpu::Buffer& b : contents_) {
    b.Destroy();
  }
  contents_.clear();
}

void GPU::SetDawnControlClientHolderForTesting(
    scoped_refptr<DawnControlClientHolder> dawn_control_client) {
  dawn_control_client_ = std::move(dawn_control_client);
}

}  // namespace blink
```