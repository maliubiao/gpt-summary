Response:
Let's break down the request and the provided code to formulate a comprehensive answer.

**1. Understanding the Goal:**

The core request is to analyze the `gpu_adapter.cc` file in the Chromium Blink engine and explain its functionality, its relation to web technologies, any logical reasoning, potential user errors, and how a user's actions might lead to this code being executed.

**2. Initial Code Scan & Keyword Identification:**

I started by quickly scanning the code, looking for key terms and patterns. This immediately highlights:

* **`GPUAdapter` class:** This is the central entity.
* **`wgpu::Adapter`:**  Interaction with the underlying WebGPU implementation (likely Dawn).
* **`requestDevice`:**  A key function for obtaining a `GPUDevice`.
* **`requestAdapterInfo`:**  A function for retrieving adapter details.
* **Feature enums (`wgpu::FeatureName`, `V8GPUFeatureName`):**  Dealing with hardware/software capabilities.
* **Limits (`wgpu::SupportedLimits`):**  Handling resource constraints.
* **Promises (`ScriptPromise`):**  Asynchronous operations.
* **Descriptors (`GPUDeviceDescriptor`):**  Configuration objects.
* **Callbacks (`OnRequestDeviceCallback`):**  Handling asynchronous results.
* **Error handling (`DOMException`, `DeviceLostCallback`, `UncapturedErrorCallback`):**  Managing errors and device loss.
* **UKM (User Keyed Metrics):**  Telemetry data collection.
* **Console warnings (`AddConsoleWarning`):** Providing feedback to developers.
* **`RuntimeEnabledFeatures`:**  Feature flags controlling behavior.

**3. Deconstructing Functionality:**

Based on the keywords, I began to piece together the responsibilities of `GPUAdapter`:

* **Representation of a GPU:** It's an abstraction over a physical or virtual GPU.
* **Capability Discovery:**  It queries the underlying `wgpu::Adapter` to determine supported features and limits.
* **Device Creation:**  The primary purpose seems to be the `requestDevice` method, which allows a web page to request a `GPUDevice` for rendering.
* **Information Provision:** `requestAdapterInfo` provides details about the adapter.
* **Error and Device Loss Handling:** It manages device creation errors and handles situations where a device becomes unusable.
* **Feature Negotiation:**  It validates requested features against supported features.
* **Compatibility Considerations:** The `isCompatibilityMode` flag and checks for specific features suggest handling different driver/hardware levels.
* **Metrics and Debugging:**  UKM for telemetry and console warnings for developer feedback.

**4. Relating to Web Technologies (JavaScript, HTML, CSS):**

This requires connecting the C++ backend to the JavaScript API exposed to web developers:

* **JavaScript:** The `requestAdapter()` method in JavaScript (part of the WebGPU API) will eventually lead to the creation of a `GPUAdapter` object in the Blink engine. The `requestDevice()` method on the JavaScript `GPUAdapter` object directly maps to the C++ `GPUAdapter::requestDevice`. Similarly for `requestAdapterInfo`. The properties of the JavaScript `GPUAdapterInfo` object are populated from the C++ `GPUAdapterInfo`.
* **HTML:**  The `<canvas>` element is the drawing surface. WebGPU rendering happens within the context of a canvas.
* **CSS:**  CSS can indirectly affect WebGPU by influencing the size and visibility of the canvas.

**5. Logical Reasoning and Assumptions:**

This involves analyzing the code's decision-making processes:

* **Feature Validation:** The code checks if requested features are supported. If not, it rejects the promise.
* **Device Loss Handling:**  The code handles cases where the adapter is "consumed" (already used to create a device), forcing a device loss.
* **Error Handling in Callbacks:**  The `OnRequestDeviceCallback` function has different logic based on the `wgpu::RequestDeviceStatus`.
* **Conditional Feature Enabling:** The `RuntimeEnabledFeatures` checks control the availability of experimental or developer features.

**6. User and Programming Errors:**

This focuses on common mistakes developers might make when using the WebGPU API:

* **Requesting Unsupported Features:**  Specifying a feature in `requiredFeatures` that the adapter doesn't support.
* **Requesting Unsupported Limits:**  Setting `requiredLimits` to values that exceed the adapter's capabilities.
* **Incorrect Descriptor Configuration:** Providing an invalid `GPUDeviceDescriptor`.
* **Not Handling Device Loss:** Failing to listen for and respond to `deviceLost` events.

**7. User Operations and Debugging:**

This involves tracing the user's actions that trigger this code:

* **Accessing a Web Page:**  A user navigates to a page that uses WebGPU.
* **JavaScript Execution:** The JavaScript code on the page calls `navigator.gpu.requestAdapter()`.
* **Adapter Selection (Implicit):** The browser internally selects a suitable GPU adapter.
* **Requesting a Device:** The JavaScript code calls `adapter.requestDevice()`.

**8. Structuring the Answer:**

Finally, I organized the information into the requested sections: functionality, relation to web technologies, logical reasoning, user errors, and debugging clues. I used examples to illustrate the concepts and tried to provide clear and concise explanations.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the Dawn API details. I needed to shift the focus to how this C++ code relates to the *web-facing* WebGPU API.
* I realized the importance of explaining the asynchronous nature of `requestDevice` and the role of Promises.
* I made sure to distinguish between user errors (developers using the API incorrectly) and potential internal issues.
* I double-checked the feature flag logic and how it influences the available functionality.

By following this systematic approach, I could extract the necessary information from the code and present it in a well-organized and comprehensive manner.
好的，让我们来分析一下 `blink/renderer/modules/webgpu/gpu_adapter.cc` 这个文件。

**文件功能概要:**

`gpu_adapter.cc` 文件在 Chromium Blink 引擎中，主要负责实现 WebGPU API 中的 `GPUAdapter` 接口。`GPUAdapter` 对象代表了用户的计算机上的一个 WebGPU 适配器（通常是一个物理 GPU 或软件渲染器）。该文件的核心功能包括：

1. **枚举和表示 GPU 适配器:**  它负责发现和表示系统上的可用 WebGPU 适配器。
2. **获取适配器信息:**  提供方法来查询适配器的各种属性，例如厂商、架构、设备 ID、描述、驱动程序信息以及支持的特性和限制。
3. **请求 GPU 设备:**  实现 `requestDevice()` 方法，允许 Web 页面请求一个与特定适配器关联的 `GPUDevice` 对象。`GPUDevice` 是进行实际 WebGPU 操作的关键接口。
4. **管理设备生命周期:**  处理设备创建过程中的错误和设备丢失事件。
5. **特性和限制协商:**  在请求设备时，根据用户指定的所需特性和限制，与适配器进行协商。
6. **兼容性处理:**  处理不同适配器和驱动程序的兼容性问题。
7. **性能和调试支持:**  集成用户关键指标 (UKM) 用于性能跟踪，并在控制台中输出警告信息帮助开发者调试。

**与 JavaScript, HTML, CSS 的关系:**

`GPUAdapter` 是 WebGPU JavaScript API 的一部分，因此它与 JavaScript 直接相关。

* **JavaScript:**
    * **`navigator.gpu.requestAdapter()`:**  在 JavaScript 中调用这个方法会触发 Blink 引擎中查找和创建 `GPUAdapter` 实例的逻辑。`gpu_adapter.cc` 中的代码负责实现这一过程。
    * **`GPUAdapter` 对象的方法:**  JavaScript 中 `GPUAdapter` 对象的 `requestDevice()` 和 `requestAdapterInfo()` 方法的实现逻辑都在 `gpu_adapter.cc` 中。
    * **特性和限制:**  JavaScript 可以通过 `GPUAdapter` 对象查询支持的特性 (`features()`) 和限制 (`limits()`)，这些信息的获取逻辑也在 `gpu_adapter.cc` 中。
    * **错误处理:**  当 `requestDevice()` 失败时，JavaScript 中返回的 Promise 会被拒绝，拒绝的原因可能来自于 `gpu_adapter.cc` 中的错误处理逻辑。

    **举例:**

    ```javascript
    // JavaScript 代码
    navigator.gpu.requestAdapter().then(adapter => {
      if (adapter) {
        console.log("找到适配器:", adapter.name); // 这里的 adapter 对象对应 blink 中的 GPUAdapter
        adapter.requestDevice().then(device => {
          // 使用 device 进行 WebGPU 操作
        }).catch(error => {
          console.error("请求设备失败:", error); // 失败原因可能来自 gpu_adapter.cc
        });
        adapter.requestAdapterInfo().then(info => {
          console.log("适配器信息:", info); // info 对象的信息由 gpu_adapter.cc 提供
        });
      } else {
        console.log("未找到适配器");
      }
    });
    ```

* **HTML:**
    * **`<canvas>` 元素:** WebGPU 的渲染目标通常是 HTML 中的 `<canvas>` 元素。虽然 `gpu_adapter.cc` 本身不直接操作 HTML 元素，但它创建的 `GPUDevice` 对象最终会被用于在 canvas 上进行渲染。

* **CSS:**
    * **间接影响:** CSS 可以影响 `<canvas>` 元素的尺寸和可见性，这会间接影响 WebGPU 的渲染过程。`gpu_adapter.cc` 不直接与 CSS 交互。

**逻辑推理 (假设输入与输出):**

假设 JavaScript 代码请求一个支持 `timestamp-query` 特性的 GPU 设备：

**假设输入:**

* JavaScript 调用 `adapter.requestDevice({ requiredFeatures: ['timestamp-query'] })`
* 系统上存在一个支持 `timestamp-query` 特性的 GPU 适配器。

**逻辑推理过程 (在 `gpu_adapter.cc` 中):**

1. `GPUAdapter::requestDevice()` 被调用。
2. 从 `GPUDeviceDescriptor` 中提取 `requiredFeatures`，得到 `timestamp-query`。
3. 遍历 `requiredFeatures`，检查 `timestamp-query` 是否在当前 `GPUAdapter` 的 `features_` 中（该集合由 `MakeFeatureNameSet` 函数在适配器创建时填充）。
4. 由于适配器支持 `timestamp-query`，检查通过。
5. 构建 Dawn (WebGPU 的底层实现) 的设备描述符 `dawn_desc`，并将 `timestamp-query` 添加到 `dawn_desc.requiredFeatures` 中。
6. 调用 Dawn 的 `RequestDevice` 方法来创建设备。
7. Dawn 返回成功创建的设备。
8. `GPUAdapter::OnRequestDeviceCallback()` 被调用，状态为 `wgpu::RequestDeviceStatus::Success`。
9. 创建 `GPUDevice` 对象并初始化。
10. Promise 被解析，并将 `GPUDevice` 对象返回给 JavaScript。

**假设输出:**

* JavaScript 中 `requestDevice()` 返回的 Promise 成功解析，得到一个可以使用的 `GPUDevice` 对象。

**用户或编程常见的使用错误:**

1. **请求不支持的特性:** 用户在 `requiredFeatures` 中指定了当前适配器不支持的特性。

   **举例:** 假设某个适配器不支持 `shader-f16` 特性，但 JavaScript 代码请求了：

   ```javascript
   adapter.requestDevice({ requiredFeatures: ['shader-f16'] });
   ```

   **`gpu_adapter.cc` 中的处理:**  在 `GPUAdapter::requestDevice()` 中，会检查 `descriptor->requiredFeatures()` 中的每个特性是否在 `features_` 中。如果发现 `shader-f16` 不存在，会调用 `resolver->RejectWithTypeError()` 拒绝 Promise，并返回一个错误消息，例如 "Unsupported feature: shader-f16"。

2. **请求超出限制的值:**  用户在 `requiredLimits` 中请求了超出适配器能力的值。

   **举例:** 假设适配器的最大纹理尺寸是 8192，但 JavaScript 代码请求了：

   ```javascript
   adapter.requestDevice({ requiredLimits: { maxTextureDimension2D: 16384 } });
   ```

   **`gpu_adapter.cc` 中的处理:**  `GPUSupportedLimits::Populate()` 会尝试将用户提供的限制值填充到 Dawn 的 `wgpu::RequiredLimits` 结构中。如果用户请求的值超过了适配器报告的 `wgpu::SupportedLimits`，Dawn 的 `RequestDevice` 可能会失败，或者 `gpu_adapter.cc` 在构建 `dawn_desc` 时就可能检测到并拒绝 Promise。在 `OnRequestDeviceCallback` 中，如果 Dawn 返回错误状态，Promise 会被拒绝，并带有相应的错误消息。

3. **在适配器“消耗”后再次请求设备:** 一旦一个 `GPUAdapter` 被用于成功创建一个 `GPUDevice`，它就被认为是“消耗”了。再次使用同一个适配器请求设备会导致设备丢失。

   **`gpu_adapter.cc` 中的处理:**  `is_consumed_` 标志用于记录适配器是否已被使用。如果在 `is_consumed_` 为 `true` 的情况下调用 `requestDevice()`,  `OnRequestDeviceCallback` 会立即创建一个 lost 状态的 `GPUDevice` 并解析 Promise。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户访问一个使用了 WebGPU 的网页。**
2. **网页的 JavaScript 代码执行 `navigator.gpu.requestAdapter()`。** 这会导致 Blink 引擎开始查找可用的 GPU 适配器。相关的代码可能在 `blink/renderer/modules/webgpu/gpu.cc` 中。
3. **Blink 引擎根据一定的策略（例如，考虑 powerPreference）选择一个适配器并创建 `GPUAdapter` 对象。**  `gpu_adapter.cc` 中的 `GPUAdapter` 构造函数会被调用，它会查询 Dawn 获取适配器的信息、特性和限制。
4. **JavaScript 代码随后调用 `adapter.requestDevice(descriptor)`。** 这里的 `descriptor` 包含了用户希望使用的特性和限制。
5. **浏览器进程将这个请求传递给渲染器进程。**
6. **渲染器进程中的 `gpu_adapter.cc` 文件的 `GPUAdapter::requestDevice()` 方法被调用。**
7. **该方法会验证用户请求的特性和限制。**
8. **如果验证通过，会构建一个 Dawn 的设备描述符，并调用 Dawn 的 `RequestDevice` 方法。**
9. **Dawn 与 GPU 驱动进行交互，尝试创建设备。**
10. **Dawn 的结果（成功或失败）会通过回调函数传递回 `gpu_adapter.cc` 的 `GPUAdapter::OnRequestDeviceCallback()` 方法。**
11. **`OnRequestDeviceCallback()` 根据 Dawn 的结果，解析或拒绝 JavaScript 的 Promise，并将 `GPUDevice` 对象传递给 JavaScript 代码（如果成功）。**

**调试线索:**

* **Console 输出:**  `gpu_adapter.cc` 中的 `AddConsoleWarning()` 方法会在控制台中输出警告信息，例如关于兼容性问题或性能考量的提示。
* **WebGPU 内部日志:**  Chromium 提供了 `chrome://gpu` 页面，其中包含了 WebGPU 的内部日志，可以查看设备创建的详细过程和可能出现的错误。
* **断点调试:**  开发者可以使用 Chromium 的开发者工具，在 `gpu_adapter.cc` 的关键位置设置断点，例如 `requestDevice()`、`OnRequestDeviceCallback()` 和特性/限制的检查逻辑处，来单步跟踪代码的执行流程。
* **UKM 数据:** 虽然开发者不能直接查看 UKM 数据，但 Chrome 团队会利用这些数据来了解 WebGPU 的使用情况和潜在问题。
* **错误消息:**  当 `requestDevice()` 失败时，JavaScript 中捕获的错误消息通常包含了来自 `gpu_adapter.cc` 或 Dawn 的信息，可以帮助定位问题。

总而言之，`gpu_adapter.cc` 是 Blink 引擎中 WebGPU 功能的核心组成部分，它桥接了 JavaScript API 和底层的 GPU 驱动程序，负责管理 GPU 适配器的生命周期，并为 Web 开发者提供了访问 GPU 能力的关键入口。

### 提示词
```
这是目录为blink/renderer/modules/webgpu/gpu_adapter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/modules/webgpu/gpu_adapter.h"

#include "services/metrics/public/cpp/ukm_builders.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_object_builder.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_device_descriptor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_queue_descriptor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_request_adapter_options.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/modules/webgpu/dawn_enum_conversions.h"
#include "third_party/blink/renderer/modules/webgpu/gpu.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_adapter_info.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_device.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_device_lost_info.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_memory_heap_info.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_supported_features.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_supported_limits.h"
#include "third_party/blink/renderer/modules/webgpu/string_utils.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

namespace {

std::optional<V8GPUFeatureName::Enum> ToV8FeatureNameEnum(wgpu::FeatureName f) {
  switch (f) {
    case wgpu::FeatureName::Depth32FloatStencil8:
      return V8GPUFeatureName::Enum::kDepth32FloatStencil8;
    case wgpu::FeatureName::TimestampQuery:
      return V8GPUFeatureName::Enum::kTimestampQuery;
    case wgpu::FeatureName::ChromiumExperimentalTimestampQueryInsidePasses:
      return V8GPUFeatureName::Enum::
          kChromiumExperimentalTimestampQueryInsidePasses;
    case wgpu::FeatureName::TextureCompressionBC:
      return V8GPUFeatureName::Enum::kTextureCompressionBc;
    case wgpu::FeatureName::TextureCompressionETC2:
      return V8GPUFeatureName::Enum::kTextureCompressionEtc2;
    case wgpu::FeatureName::TextureCompressionASTC:
      return V8GPUFeatureName::Enum::kTextureCompressionAstc;
    case wgpu::FeatureName::IndirectFirstInstance:
      return V8GPUFeatureName::Enum::kIndirectFirstInstance;
    case wgpu::FeatureName::DepthClipControl:
      return V8GPUFeatureName::Enum::kDepthClipControl;
    case wgpu::FeatureName::RG11B10UfloatRenderable:
      return V8GPUFeatureName::Enum::kRg11B10UfloatRenderable;
    case wgpu::FeatureName::BGRA8UnormStorage:
      return V8GPUFeatureName::Enum::kBgra8UnormStorage;
    case wgpu::FeatureName::ShaderF16:
      return V8GPUFeatureName::Enum::kShaderF16;
    case wgpu::FeatureName::Float32Filterable:
      return V8GPUFeatureName::Enum::kFloat32Filterable;
    case wgpu::FeatureName::Float32Blendable:
      return V8GPUFeatureName::Enum::kFloat32Blendable;
    case wgpu::FeatureName::DualSourceBlending:
      return V8GPUFeatureName::Enum::kDualSourceBlending;
    case wgpu::FeatureName::Subgroups:
      return V8GPUFeatureName::Enum::kSubgroups;
    case wgpu::FeatureName::SubgroupsF16:
      return V8GPUFeatureName::Enum::kSubgroupsF16;
    case wgpu::FeatureName::ClipDistances:
      return V8GPUFeatureName::Enum::kClipDistances;
    case wgpu::FeatureName::MultiDrawIndirect:
      return V8GPUFeatureName::Enum::kChromiumExperimentalMultiDrawIndirect;
    case wgpu::FeatureName::Unorm16TextureFormats:
      return V8GPUFeatureName::Enum::kChromiumExperimentalUnorm16TextureFormats;
    case wgpu::FeatureName::Snorm16TextureFormats:
      return V8GPUFeatureName::Enum::kChromiumExperimentalSnorm16TextureFormats;
    default:
      return std::nullopt;
  }
}

}  // anonymous namespace

namespace {

// TODO(crbug.com/351564777): should be UNSAFE_BUFFER_USAGE
GPUSupportedFeatures* MakeFeatureNameSet(wgpu::Adapter adapter,
                                         ExecutionContext* execution_context) {
  GPUSupportedFeatures* features = MakeGarbageCollected<GPUSupportedFeatures>();
  DCHECK(features->FeatureNameSet().empty());

  wgpu::SupportedFeatures supported_features;
  adapter.GetFeatures(&supported_features);
  // SAFETY: Required from caller
  const auto features_span = UNSAFE_BUFFERS(base::span<const wgpu::FeatureName>(
      supported_features.features, supported_features.featureCount));
  for (const auto& f : features_span) {
    auto feature_name_enum_optional = ToV8FeatureNameEnum(f);
    if (feature_name_enum_optional) {
      V8GPUFeatureName::Enum feature_name_enum =
          feature_name_enum_optional.value();
      // Subgroups features are under OT.
      // TODO(crbug.com/349125474): remove this check after subgroups features
      // OT finished.
      if ((feature_name_enum_optional == V8GPUFeatureName::Enum::kSubgroups) ||
          (feature_name_enum_optional ==
           V8GPUFeatureName::Enum::kSubgroupsF16)) {
        if (!RuntimeEnabledFeatures::WebGPUSubgroupsFeaturesEnabled(
                execution_context)) {
          continue;
        }
      }
      features->AddFeatureName(V8GPUFeatureName(feature_name_enum));
    }
  }
  return features;
}

}  // anonymous namespace

// TODO(crbug.com/351564777): should be UNSAFE_BUFFER_USAGE
GPUAdapter::GPUAdapter(
    GPU* gpu,
    wgpu::Adapter handle,
    scoped_refptr<DawnControlClientHolder> dawn_control_client,
    const GPURequestAdapterOptions* options)
    : DawnObject(dawn_control_client, std::move(handle), String()), gpu_(gpu) {
  wgpu::AdapterInfo info = {};
  wgpu::ChainedStructOut** propertiesChain = &info.nextInChain;
  wgpu::AdapterPropertiesMemoryHeaps memoryHeapProperties = {};
  if (GetHandle().HasFeature(wgpu::FeatureName::AdapterPropertiesMemoryHeaps)) {
    *propertiesChain = &memoryHeapProperties;
    propertiesChain = &(*propertiesChain)->nextInChain;
  }
  wgpu::AdapterPropertiesD3D d3dProperties = {};
  bool supportsPropertiesD3D =
      GetHandle().HasFeature(wgpu::FeatureName::AdapterPropertiesD3D);
  if (supportsPropertiesD3D) {
    *propertiesChain = &d3dProperties;
    propertiesChain = &(*propertiesChain)->nextInChain;
  }
  wgpu::AdapterPropertiesVk vkProperties = {};
  bool supportsPropertiesVk =
      GetHandle().HasFeature(wgpu::FeatureName::AdapterPropertiesVk);
  if (supportsPropertiesVk) {
    *propertiesChain = &vkProperties;
    propertiesChain = &(*propertiesChain)->nextInChain;
  }
  GetHandle().GetInfo(&info);
  is_fallback_adapter_ = info.adapterType == wgpu::AdapterType::CPU;
  adapter_type_ = info.adapterType;
  backend_type_ = info.backendType;
  is_compatibility_mode_ = info.compatibilityMode;

  // TODO(crbug.com/359418629): Report xr compatibility in GetInfo()
  is_xr_compatible_ = options->xrCompatible();

  vendor_ = String::FromUTF8(info.vendor);
  architecture_ = String::FromUTF8(info.architecture);
  if (info.deviceID <= 0xffff) {
    device_ = String::Format("0x%04x", info.deviceID);
  } else {
    device_ = String::Format("0x%08x", info.deviceID);
  }
  description_ = String::FromUTF8(info.device);
  driver_ = String::FromUTF8(info.description);
  for (size_t i = 0; i < memoryHeapProperties.heapCount; ++i) {
    memory_heaps_.push_back(MakeGarbageCollected<GPUMemoryHeapInfo>(
        UNSAFE_TODO(memoryHeapProperties.heapInfo[i])));
  }
  if (supportsPropertiesD3D) {
    d3d_shader_model_ = d3dProperties.shaderModel;
  }
  if (supportsPropertiesVk) {
    vk_driver_version_ = vkProperties.driverVersion;
  }

  features_ = MakeFeatureNameSet(GetHandle(), gpu_->GetExecutionContext());

  wgpu::SupportedLimits limits = {};
  // Chain to get subgroup limits, if support subgroups feature.
  wgpu::DawnExperimentalSubgroupLimits subgroupLimits = {};
  if (features_->has(V8GPUFeatureName::Enum::kSubgroups)) {
    limits.nextInChain = &subgroupLimits;
  }

  GetHandle().GetLimits(&limits);
  limits_ = MakeGarbageCollected<GPUSupportedLimits>(limits);

  info_ = CreateAdapterInfoForAdapter();
}

GPUAdapterInfo* GPUAdapter::CreateAdapterInfoForAdapter() {
  GPUAdapterInfo* info;
  if (RuntimeEnabledFeatures::WebGPUDeveloperFeaturesEnabled()) {
    // If WebGPU developer features have been enabled then provide all available
    // adapter info values.
    info = MakeGarbageCollected<GPUAdapterInfo>(
        vendor_, architecture_, device_, description_, driver_,
        FromDawnEnum(backend_type_), FromDawnEnum(adapter_type_),
        d3d_shader_model_, vk_driver_version_);
    for (GPUMemoryHeapInfo* memory_heap : memory_heaps_) {
      info->AppendMemoryHeapInfo(memory_heap);
    }
  } else {
    info = MakeGarbageCollected<GPUAdapterInfo>(vendor_, architecture_);
  }
  return info;
}

void GPUAdapter::AddConsoleWarning(ExecutionContext* execution_context,
                                   const char* message) {
  if (execution_context && allowed_console_warnings_remaining_ > 0) {
    auto* console_message = MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kRendering,
        mojom::blink::ConsoleMessageLevel::kWarning,
        StringFromASCIIAndUTF8(message));
    execution_context->AddConsoleMessage(console_message);

    allowed_console_warnings_remaining_--;
    if (allowed_console_warnings_remaining_ == 0) {
      auto* final_message = MakeGarbageCollected<ConsoleMessage>(
          mojom::blink::ConsoleMessageSource::kRendering,
          mojom::blink::ConsoleMessageLevel::kWarning,
          "WebGPU: too many warnings, no more warnings will be reported to the "
          "console for this GPUAdapter.");
      execution_context->AddConsoleMessage(final_message);
    }
  }
}

GPUSupportedFeatures* GPUAdapter::features() const {
  return features_.Get();
}

GPUAdapterInfo* GPUAdapter::info() const {
  return info_.Get();
}

bool GPUAdapter::isFallbackAdapter() const {
  return is_fallback_adapter_;
}

wgpu::BackendType GPUAdapter::backendType() const {
  return backend_type_;
}

bool GPUAdapter::SupportsMultiPlanarFormats() const {
  return GetHandle().HasFeature(wgpu::FeatureName::DawnMultiPlanarFormats);
}

bool GPUAdapter::isCompatibilityMode() const {
  return is_compatibility_mode_;
}

void GPUAdapter::OnRequestDeviceCallback(
    GPUDevice* device,
    const GPUDeviceDescriptor* descriptor,
    ScriptPromiseResolver<GPUDevice>* resolver,
    wgpu::RequestDeviceStatus status,
    wgpu::Device dawn_device,
    wgpu::StringView error_message) {
  switch (status) {
    case wgpu::RequestDeviceStatus::Success: {
      DCHECK(dawn_device);

      GPUDeviceLostInfo* device_lost_info = nullptr;
      if (is_consumed_) {
        // Immediately force the device to be lost.
        // TODO: Ideally this should be handled in Dawn, which can return an
        // error device.
        device_lost_info = MakeGarbageCollected<GPUDeviceLostInfo>(
            wgpu::DeviceLostReason::Unknown,
            StringFromASCIIAndUTF8(
                "The adapter is invalid because it has already been used to "
                "create a device. A lost device has been returned."));
      }
      is_consumed_ = true;

      device->Initialize(dawn_device, descriptor, device_lost_info);

      if (device_lost_info) {
        // Ensure the Dawn device is marked as lost as well.
        device->InjectError(
            wgpu::ErrorType::DeviceLost,
            "Device was marked as lost due to a stale adapter.");
      }

      resolver->Resolve(device);

      ukm::builders::ClientRenderingAPI(
          device->GetExecutionContext()->UkmSourceID())
          .SetGPUDevice(static_cast<int>(true))
          .Record(device->GetExecutionContext()->UkmRecorder());
      break;
    }

    case wgpu::RequestDeviceStatus::Error:
    case wgpu::RequestDeviceStatus::Unknown:
    case wgpu::RequestDeviceStatus::InstanceDropped:
      if (dawn_device) {
        // A device provided with an error is already a lost device on the Dawn
        // side, reflect that by resolving the lost property immediately.
        device->Initialize(dawn_device, descriptor,
                           MakeGarbageCollected<GPUDeviceLostInfo>(
                               wgpu::DeviceLostReason::Unknown,
                               StringFromASCIIAndUTF8(error_message)));

        // Resolve with the lost device.
        resolver->Resolve(device);
      } else {
        // If a device is not returned, that means that an error occurred while
        // validating features or limits, and as a result the promise should be
        // rejected with an OperationError.
        resolver->RejectWithDOMException(DOMExceptionCode::kOperationError,
                                         StringFromASCIIAndUTF8(error_message));
      }
      break;
  }
}

ScriptPromise<GPUDevice> GPUAdapter::requestDevice(
    ScriptState* script_state,
    GPUDeviceDescriptor* descriptor) {
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<GPUDevice>>(
      script_state, ExceptionContext(v8::ExceptionContext::kOperation,
                                     "GPUAdapter", "requestDevice"));
  auto promise = resolver->Promise();

  wgpu::DeviceDescriptor dawn_desc = {};

  wgpu::RequiredLimits required_limits = {};
  if (descriptor->hasRequiredLimits()) {
    dawn_desc.requiredLimits = &required_limits;
    GPUSupportedLimits::MakeUndefined(&required_limits);
    if (!GPUSupportedLimits::Populate(&required_limits,
                                      descriptor->requiredLimits(), resolver)) {
      return promise;
    }
  }

  Vector<wgpu::FeatureName> required_features;
  // The ShaderModuleCompilationOptions feature is required only if the adapter
  // has the ShaderModuleCompilationOptions feature and the user has enabled the
  // WebGPUDeveloperFeatures flag. It is needed to control
  // strict math during shader module compilation.
  if (RuntimeEnabledFeatures::WebGPUDeveloperFeaturesEnabled() &&
      GetHandle().HasFeature(
          wgpu::FeatureName::ShaderModuleCompilationOptions)) {
    required_features.push_back(
        wgpu::FeatureName::ShaderModuleCompilationOptions);
  }
  if (descriptor->hasRequiredFeatures()) {
    // Insert features into a set to dedup them.
    HashSet<wgpu::FeatureName> required_features_set;
    for (const V8GPUFeatureName& f : descriptor->requiredFeatures()) {
      // If the feature is not a valid feature reject with a type error.
      if (!features_->has(f.AsEnum())) {
        resolver->RejectWithTypeError(
            String::Format("Unsupported feature: %s", f.AsCStr()));
        return promise;
      }
      required_features_set.insert(AsDawnEnum(f));
    }

    // Then, push the deduped features into a vector.
    required_features.AppendRange(required_features_set.begin(),
                                  required_features_set.end());
    dawn_desc.requiredFeatures = required_features.data();
    dawn_desc.requiredFeatureCount = required_features.size();
  }

  std::string label = descriptor->label().Utf8();
  if (!label.empty()) {
    dawn_desc.label = label.c_str();
  }

  std::string queueLabel = descriptor->defaultQueue()->label().Utf8();
  if (!queueLabel.empty()) {
    dawn_desc.defaultQueue.label = queueLabel.c_str();
  }

  // Create a GPUDevice without the handle, so that we can set up its callbacks
  // in the wgpu::DeviceDescriptor.
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  auto* device = MakeGarbageCollected<GPUDevice>(
      execution_context, GetDawnControlClient(), this, descriptor->label());
  dawn_desc.SetUncapturedErrorCallback(
      device->error_callback()->UnboundCallback(),
      device->error_callback()->AsUserdata());
  dawn_desc.SetDeviceLostCallback(wgpu::CallbackMode::AllowSpontaneous,
                                  device->lost_callback()->UnboundCallback(),
                                  device->lost_callback()->AsUserdata());

  auto* callback = MakeWGPUOnceCallback(resolver->WrapCallbackInScriptScope(
      WTF::BindOnce(&GPUAdapter::OnRequestDeviceCallback, WrapPersistent(this),
                    WrapPersistent(device), WrapPersistent(descriptor))));

  GetHandle().RequestDevice(&dawn_desc, wgpu::CallbackMode::AllowSpontaneous,
                            callback->UnboundCallback(),
                            callback->AsUserdata());
  EnsureFlush(ToEventLoop(script_state));

  return promise;
}

ScriptPromise<GPUAdapterInfo> GPUAdapter::requestAdapterInfo(
    ScriptState* script_state) {
  return ToResolvedPromise<GPUAdapterInfo>(script_state, info_);
}

void GPUAdapter::Trace(Visitor* visitor) const {
  visitor->Trace(gpu_);
  visitor->Trace(features_);
  visitor->Trace(limits_);
  visitor->Trace(info_);
  visitor->Trace(memory_heaps_);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink
```