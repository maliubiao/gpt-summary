Response:
Let's break down the thought process for analyzing this `GPUDevice.cc` file.

1. **Understand the Goal:** The primary objective is to understand the functionality of this file within the Chromium/Blink WebGPU implementation. This includes its interactions with other web technologies (JavaScript, HTML, CSS), potential logical inferences, common errors, and how user actions might lead to this code being executed.

2. **Initial Code Scan - Identify Key Components:**  The first step is to quickly skim the code, paying attention to includes, class names, method names, and any obvious patterns.

    * **Includes:**  These provide immediate clues about dependencies and related functionalities. Notice includes like `gpu/command_buffer/client/webgpu_interface.h`,  `third_party/blink/public/mojom/...`, and numerous `third_party/blink/renderer/modules/webgpu/...`. This suggests interaction with the underlying GPU command buffer, communication with the browser process (via Mojo), and the broader WebGPU module implementation. The presence of `v8_*` includes signifies integration with the V8 JavaScript engine.

    * **Class Name:** `GPUDevice` is the central class. This hints that the file manages the state and functionality of a WebGPU device.

    * **Method Names:**  Names like `createBuffer`, `createTexture`, `createRenderPipeline`, `queue()`, `lost()`, `destroy()`, `pushErrorScope`, `popErrorScope`, and event handlers like `OnUncapturedError`, `OnDeviceLostError` are highly informative. They point to the core operations a WebGPU device provides.

    * **Helper Functions:**  The anonymous namespace contains functions like `RequiredFeatureForTextureFormat` and `RequiredFeatureForBlendFactor`. This suggests validation of WebGPU feature requirements.

3. **Categorize Functionality:**  Based on the initial scan, start grouping related functionalities:

    * **Resource Creation:**  Methods like `createBuffer`, `createTexture`, `createSampler`, `createBindGroup`, etc., clearly handle the creation of WebGPU resources.
    * **Pipeline Management:** `createRenderPipeline`, `createComputePipeline`, and their asynchronous counterparts manage the creation of rendering and compute pipelines.
    * **Command Submission:** `createCommandEncoder` is involved in creating command encoders.
    * **Error Handling:** `pushErrorScope`, `popErrorScope`, `OnUncapturedError`, and `OnDeviceLostError` deal with error management.
    * **Device State:**  Methods like `lost()`, `destroy()`, and the `lost_property_` member manage the device's lifecycle and loss state.
    * **Feature Support:** The `features()` method and the helper functions in the anonymous namespace are responsible for checking and managing supported WebGPU features.
    * **Queue Management:** The `queue()` method returns the default command queue.
    * **External Texture Handling:** `importExternalTexture` and `ExternalTextureCache` manage external textures.
    * **Internal Setup:** The `Initialize` method handles the initial setup of the `GPUDevice`.
    * **Logging:** The `OnLogging` method handles logging messages from the underlying WebGPU implementation.

4. **Analyze Interactions with Web Technologies:**

    * **JavaScript:** The presence of `ScriptPromise`, `ScriptPromiseResolver`, and the binding code structure clearly indicates that `GPUDevice` exposes functionality to JavaScript via the WebGPU API. The methods like `createRenderPipelineAsync` and `popErrorScope` return promises that JavaScript can await. The input parameters to these methods often correspond directly to JavaScript API calls.

    * **HTML:**  The connection to HTML is through the `<canvas>` element. WebGPU operations often target a canvas for rendering output. The `preferred_canvas_format()` mentioned in a warning relates directly to how the canvas is configured.

    * **CSS:**  While `GPUDevice.cc` itself doesn't directly interact with CSS, the visual results of WebGPU rendering are displayed within the context of the HTML page and are subject to CSS layout and rendering.

5. **Identify Logical Inferences and Assumptions:**

    * **Feature Requirements:** The `RequiredFeatureForTextureFormat` and `RequiredFeatureForBlendFactor` functions perform logical checks. The assumption is that certain WebGPU functionalities depend on specific hardware or software features. The output is whether a feature flag needs to be enabled.

6. **Consider Common User/Programming Errors:**

    * **Invalid Descriptors:** Passing incorrect or incomplete descriptor objects to resource creation methods is a common mistake. The code includes validation steps that can throw `TypeError` exceptions.
    * **Using Unsupported Features:** Attempting to use a texture format or blend factor without the necessary feature being enabled will result in an error.
    * **Device Loss:** Not handling the `device lost` promise can lead to unexpected behavior when the GPU device becomes unavailable.
    * **Incorrect Error Handling:**  Misusing error scopes (`pushErrorScope`/`popErrorScope`) or ignoring the `lost` promise can hinder proper error management.

7. **Trace User Operations (Debugging Context):**  Think about the sequence of events that leads to this code being executed:

    1. **User opens a web page:** The browser loads the HTML, CSS, and JavaScript.
    2. **JavaScript code is executed:**  The JavaScript calls `navigator.gpu.requestAdapter()`.
    3. **An adapter is obtained:** The user (or browser) selects a GPU adapter.
    4. **JavaScript calls `adapter.requestDevice()`:** This initiates the creation of a `GPUDevice`.
    5. **The `GPUDevice` constructor and `Initialize` method are called:** This is where `GPUDevice.cc` comes into play.
    6. **JavaScript makes further WebGPU API calls:**  Methods like `createBuffer`, `createTexture`, `createRenderPipeline`, `createCommandEncoder`, etc., are invoked, leading to the execution of the corresponding functions in `GPUDevice.cc`.
    7. **Rendering occurs:**  Commands are submitted to the GPU, and the results are displayed on the canvas.
    8. **Errors might occur:**  Validation errors, out-of-memory errors, or device loss can trigger the error handling mechanisms within `GPUDevice.cc`.

8. **Refine and Organize:**  Finally, organize the gathered information into a clear and structured format, using headings, bullet points, and examples as shown in the initial good answer. Ensure that the explanations are concise and easy to understand. Pay attention to the specific requirements of the prompt, such as providing input/output examples for logical inferences and concrete examples for common errors.

By following this systematic approach, you can effectively analyze and understand the functionality of a complex source code file like `GPUDevice.cc`. The key is to start with a broad overview and gradually drill down into the details, focusing on the interactions between different parts of the system.
好的，让我们来详细分析一下 `blink/renderer/modules/webgpu/gpu_device.cc` 这个文件。

**文件功能概述:**

`GPUDevice.cc` 文件是 Chromium Blink 引擎中实现 WebGPU `GPUDevice` 接口的核心部分。 `GPUDevice` 代表一个对 GPU 的逻辑连接，允许在 Web 页面上执行 GPU 操作。  这个文件主要负责以下功能：

1. **设备生命周期管理:**  创建、初始化、销毁 WebGPU 设备。
2. **资源创建工厂:** 提供创建各种 WebGPU 资源的方法，例如缓冲区（`GPUBuffer`）、纹理（`GPUTexture`）、采样器（`GPUSampler`）、绑定组（`GPUBindGroup`）、管线（`GPURenderPipeline`, `GPUComputePipeline`）等。
3. **命令编码器创建:**  创建用于记录 GPU 命令的编码器（`GPUCommandEncoder`，`GPURenderBundleEncoder`）。
4. **错误处理:**  管理设备上的错误，包括未捕获的错误和设备丢失错误。
5. **功能查询:**  暴露设备支持的特性（features）和限制（limits）。
6. **队列访问:**  提供访问设备关联的命令队列（`GPUQueue`）的接口。
7. **异步操作处理:**  处理管线创建等异步操作的结果。
8. **与底层 GPU 通信:**  通过 `gpu::command_buffer::client::webgpu_interface` 与 Chromium 的 GPU 进程进行通信，最终驱动 GPU 硬件。
9. **与 JavaScript 的桥梁:**  作为 Blink 渲染引擎的一部分，它提供了 JavaScript 可以调用的 WebGPU API 的底层实现。

**与 JavaScript, HTML, CSS 的关系及举例:**

`GPUDevice.cc` 是 WebGPU API 的核心实现，因此与 JavaScript 的关系最为紧密。 HTML 通过 `<canvas>` 元素提供 WebGPU 渲染的表面，CSS 则控制页面的布局和样式，间接地影响 WebGPU 的使用场景。

**JavaScript 举例:**

```javascript
// 获取 GPUAdapter (在另一个文件中实现)
navigator.gpu.requestAdapter().then(adapter => {
  // 请求 GPUDevice
  adapter.requestDevice().then(device => {
    // 创建一个缓冲区
    const buffer = device.createBuffer({
      size: 16,
      usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST
    });

    // 创建一个渲染管线 (会调用 GPUDevice::createRenderPipeline)
    const renderPipeline = device.createRenderPipeline({
      // ... 渲染管线描述符
    });

    // 获取设备的命令队列 (会调用 GPUDevice::queue())
    const queue = device.queue;

    // 监听设备丢失事件
    device.lost.then(info => {
      console.log("Device lost!", info);
    });
  });
});
```

在这个例子中，`device` 对象是由 `adapter.requestDevice()` 返回的，其底层实现就是 `GPUDevice.cc` 中的 `GPUDevice` 类。  `device.createBuffer()`, `device.createRenderPipeline()`, `device.queue`, `device.lost` 等方法和属性都在 `GPUDevice.cc` 中定义和实现。

**HTML 举例:**

```html
<!DOCTYPE html>
<html>
<head>
  <title>WebGPU Example</title>
</head>
<body>
  <canvas id="gpuCanvas" width="500" height="300"></canvas>
  <script src="main.js"></script>
</body>
</html>
```

虽然 `GPUDevice.cc` 本身不直接操作 HTML，但 WebGPU 的渲染结果通常会显示在 `<canvas>` 元素上。 JavaScript 代码会获取 `<canvas>` 元素，并使用 `GPUDevice` 创建渲染上下文，最终将图像绘制到 canvas 上。

**CSS 举例:**

```css
#gpuCanvas {
  border: 1px solid black;
  width: 100%;
  height: auto;
}
```

CSS 用于设置 `<canvas>` 元素的样式，例如边框、尺寸等。 这会影响 WebGPU 渲染结果在页面上的呈现方式。

**逻辑推理与假设输入输出:**

文件中的 `RequiredFeatureForTextureFormat` 函数就是一个逻辑推理的例子。

**假设输入:**  一个 `V8GPUTextureFormat::Enum` 类型的枚举值，例如 `V8GPUTextureFormat::Enum::kBc7RgbaUnormSrgb`。

**逻辑推理:**  `RequiredFeatureForTextureFormat` 函数内部有一个 `switch` 语句，根据输入的纹理格式判断是否需要特定的 WebGPU 功能特性。 对于 `kBc7RgbaUnormSrgb`，它会匹配到 `return V8GPUFeatureName::Enum::kTextureCompressionBc;`。

**输出:**  `std::optional<V8GPUFeatureName::Enum>` 类型的值，如果需要特定功能，则返回对应的 `V8GPUFeatureName::Enum`，否则返回 `std::nullopt`。  对于上述输入，输出将是 `V8GPUFeatureName::Enum::kTextureCompressionBc`。

**用户或编程常见的使用错误举例:**

1. **尝试使用未启用的特性:**

   * **场景:** 开发者尝试使用 BC 压缩纹理格式，但用户使用的浏览器或硬件不支持 `texture-compression-bc` 特性。
   * **代码:**
     ```javascript
     device.createTexture({
       format: 'bc7-rgba-unorm-srgb', // 需要 texture-compression-bc 特性
       // ... 其他纹理描述符
     });
     ```
   * **`GPUDevice.cc` 的处理:** `GPUDevice::ValidateTextureFormatUsage` 会检查 `features_` 中是否包含 `V8GPUFeatureName::Enum::kTextureCompressionBc`。 如果没有，则会抛出一个 `TypeError` 异常，提示用户需要启用该特性。

2. **设备丢失后尝试操作:**

   * **场景:** GPU 设备因为某些原因（例如驱动崩溃、硬件错误）丢失，但 JavaScript 代码仍然尝试使用该设备创建资源或提交命令。
   * **代码:**
     ```javascript
     device.lost.then(info => {
       console.log("Device lost, cannot perform further operations.");
     });

     // 假设设备已经丢失
     const buffer = device.createBuffer({
       size: 16,
       usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST
     });
     ```
   * **`GPUDevice.cc` 的处理:**  当设备丢失时，`OnDeviceLostError` 会被调用，并将 `lost_property_` 的状态设置为已解决。 之后，任何尝试在已丢失的设备上执行操作都可能导致错误或被忽略。 例如，在 `GPUDevice::createBuffer` 中，会检查设备是否已销毁。

**用户操作如何一步步到达这里 (调试线索):**

假设用户在一个使用了 WebGPU 的网页上执行了某些操作，导致了一个 WebGPU 错误。 以下是可能的步骤：

1. **用户打开网页:** 浏览器加载 HTML、CSS 和 JavaScript。
2. **JavaScript 请求 GPU 设备:** JavaScript 代码调用 `navigator.gpu.requestAdapter()` 和 `adapter.requestDevice()`。  这会导致 `GPUDevice` 对象被创建并初始化。
3. **JavaScript 创建 WebGPU 资源和命令:** JavaScript 代码调用 `device.createBuffer()`, `device.createTexture()`, `device.createCommandEncoder()` 等方法。 这些调用会映射到 `GPUDevice.cc` 中相应的方法。
4. **JavaScript 提交命令:** JavaScript 代码调用 `device.queue.submit()` 提交命令缓冲区。 这会将命令发送到 Chromium 的 GPU 进程。
5. **GPU 进程执行命令:** GPU 进程接收命令并将其发送到 GPU 硬件执行。
6. **发生错误:**  在执行过程中，GPU 驱动程序或硬件可能遇到错误，例如访问越界、使用了不支持的功能等。
7. **错误信息传递回 Blink:** GPU 进程将错误信息通过 `gpu::command_buffer::client::webgpu_interface` 传递回 Blink 渲染进程。
8. **`GPUDevice` 接收错误:** `GPUDevice.cc` 中的 `OnUncapturedError` 回调函数会被调用，接收错误类型和错误消息。
9. **处理错误:** `OnUncapturedError` 会根据错误类型创建相应的 `GPUError` 对象（例如 `GPUValidationError`, `GPUOutOfMemoryError`），并创建一个 `GPUUncapturedErrorEvent` 并派发到 JavaScript。
10. **控制台输出:** 如果错误事件没有被 `preventDefault()` 阻止，`OnUncapturedError` 还会调用 `AddConsoleWarning` 将错误信息输出到浏览器的开发者控制台。

**调试线索:**

* **浏览器的开发者工具 (Console):**  查看是否有 WebGPU 相关的错误或警告信息。 `GPUDevice::AddConsoleWarning` 会将一些警告信息输出到这里。
* **WebGPU API 调用堆栈:**  浏览器的开发者工具通常可以显示 JavaScript 调用 WebGPU API 的堆栈信息，帮助定位错误的起源。
* **断点调试:**  在 `GPUDevice.cc` 中设置断点，例如在 `OnUncapturedError`, `OnDeviceLostError`, `createBuffer` 等方法中，可以追踪错误的发生和处理流程。
* **日志输出:** Chromium 的日志系统（可以通过 `--enable-logging` 等命令行参数启用）可能会包含更详细的 WebGPU 内部信息。
* **WebGPU 信息覆盖层:** 一些浏览器提供了 WebGPU 信息覆盖层，可以显示当前 WebGPU 的状态、错误信息等。

总而言之，`GPUDevice.cc` 是 Blink 引擎中 WebGPU 设备的核心实现，它负责管理设备生命周期、资源创建、错误处理以及与底层 GPU 进程的通信，是连接 JavaScript WebGPU API 和 GPU 硬件的关键桥梁。 理解这个文件的功能对于调试 WebGPU 应用中的问题至关重要。

### 提示词
```
这是目录为blink/renderer/modules/webgpu/gpu_device.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/modules/webgpu/gpu_device.h"

#include "gpu/command_buffer/client/webgpu_interface.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_compute_pipeline_descriptor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_device_descriptor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_error_filter.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_feature_name.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_query_set_descriptor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_queue_descriptor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_render_pipeline_descriptor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_uncaptured_error_event_init.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/modules/event_target_modules.h"
#include "third_party/blink/renderer/modules/webgpu/dawn_conversions.h"
#include "third_party/blink/renderer/modules/webgpu/gpu.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_adapter.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_adapter_info.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_bind_group.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_bind_group_layout.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_buffer.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_command_encoder.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_compute_pipeline.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_device_lost_info.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_external_texture.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_internal_error.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_out_of_memory_error.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_pipeline_error.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_pipeline_layout.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_query_set.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_queue.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_render_bundle_encoder.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_render_pipeline.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_sampler.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_shader_module.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_supported_features.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_supported_limits.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_texture.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_uncaptured_error_event.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_validation_error.h"
#include "third_party/blink/renderer/modules/webgpu/string_utils.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"

namespace blink {

namespace {

std::optional<V8GPUFeatureName::Enum> RequiredFeatureForTextureFormat(
    V8GPUTextureFormat::Enum format) {
  switch (format) {
    case V8GPUTextureFormat::Enum::kBc1RgbaUnorm:
    case V8GPUTextureFormat::Enum::kBc1RgbaUnormSrgb:
    case V8GPUTextureFormat::Enum::kBc2RgbaUnorm:
    case V8GPUTextureFormat::Enum::kBc2RgbaUnormSrgb:
    case V8GPUTextureFormat::Enum::kBc3RgbaUnorm:
    case V8GPUTextureFormat::Enum::kBc3RgbaUnormSrgb:
    case V8GPUTextureFormat::Enum::kBc4RUnorm:
    case V8GPUTextureFormat::Enum::kBc4RSnorm:
    case V8GPUTextureFormat::Enum::kBc5RgUnorm:
    case V8GPUTextureFormat::Enum::kBc5RgSnorm:
    case V8GPUTextureFormat::Enum::kBc6HRgbUfloat:
    case V8GPUTextureFormat::Enum::kBc6HRgbFloat:
    case V8GPUTextureFormat::Enum::kBc7RgbaUnorm:
    case V8GPUTextureFormat::Enum::kBc7RgbaUnormSrgb:
      return V8GPUFeatureName::Enum::kTextureCompressionBc;

    case V8GPUTextureFormat::Enum::kEtc2Rgb8Unorm:
    case V8GPUTextureFormat::Enum::kEtc2Rgb8UnormSrgb:
    case V8GPUTextureFormat::Enum::kEtc2Rgb8A1Unorm:
    case V8GPUTextureFormat::Enum::kEtc2Rgb8A1UnormSrgb:
    case V8GPUTextureFormat::Enum::kEtc2Rgba8Unorm:
    case V8GPUTextureFormat::Enum::kEtc2Rgba8UnormSrgb:
    case V8GPUTextureFormat::Enum::kEacR11Unorm:
    case V8GPUTextureFormat::Enum::kEacR11Snorm:
    case V8GPUTextureFormat::Enum::kEacRg11Unorm:
    case V8GPUTextureFormat::Enum::kEacRg11Snorm:
      return V8GPUFeatureName::Enum::kTextureCompressionEtc2;

    case V8GPUTextureFormat::Enum::kAstc4X4Unorm:
    case V8GPUTextureFormat::Enum::kAstc4X4UnormSrgb:
    case V8GPUTextureFormat::Enum::kAstc5X4Unorm:
    case V8GPUTextureFormat::Enum::kAstc5X4UnormSrgb:
    case V8GPUTextureFormat::Enum::kAstc5X5Unorm:
    case V8GPUTextureFormat::Enum::kAstc5X5UnormSrgb:
    case V8GPUTextureFormat::Enum::kAstc6X5Unorm:
    case V8GPUTextureFormat::Enum::kAstc6X5UnormSrgb:
    case V8GPUTextureFormat::Enum::kAstc6X6Unorm:
    case V8GPUTextureFormat::Enum::kAstc6X6UnormSrgb:
    case V8GPUTextureFormat::Enum::kAstc8X5Unorm:
    case V8GPUTextureFormat::Enum::kAstc8X5UnormSrgb:
    case V8GPUTextureFormat::Enum::kAstc8X6Unorm:
    case V8GPUTextureFormat::Enum::kAstc8X6UnormSrgb:
    case V8GPUTextureFormat::Enum::kAstc8X8Unorm:
    case V8GPUTextureFormat::Enum::kAstc8X8UnormSrgb:
    case V8GPUTextureFormat::Enum::kAstc10X5Unorm:
    case V8GPUTextureFormat::Enum::kAstc10X5UnormSrgb:
    case V8GPUTextureFormat::Enum::kAstc10X6Unorm:
    case V8GPUTextureFormat::Enum::kAstc10X6UnormSrgb:
    case V8GPUTextureFormat::Enum::kAstc10X8Unorm:
    case V8GPUTextureFormat::Enum::kAstc10X8UnormSrgb:
    case V8GPUTextureFormat::Enum::kAstc10X10Unorm:
    case V8GPUTextureFormat::Enum::kAstc10X10UnormSrgb:
    case V8GPUTextureFormat::Enum::kAstc12X10Unorm:
    case V8GPUTextureFormat::Enum::kAstc12X10UnormSrgb:
    case V8GPUTextureFormat::Enum::kAstc12X12Unorm:
    case V8GPUTextureFormat::Enum::kAstc12X12UnormSrgb:
      return V8GPUFeatureName::Enum::kTextureCompressionAstc;

    case V8GPUTextureFormat::Enum::kDepth32FloatStencil8:
      return V8GPUFeatureName::Enum::kDepth32FloatStencil8;

    case V8GPUTextureFormat::Enum::kR16Unorm:
    case V8GPUTextureFormat::Enum::kRg16Unorm:
    case V8GPUTextureFormat::Enum::kRgba16Unorm:
      return V8GPUFeatureName::Enum::kChromiumExperimentalUnorm16TextureFormats;

    case V8GPUTextureFormat::Enum::kR16Snorm:
    case V8GPUTextureFormat::Enum::kRg16Snorm:
    case V8GPUTextureFormat::Enum::kRgba16Snorm:
      return V8GPUFeatureName::Enum::kChromiumExperimentalSnorm16TextureFormats;

    default:
      return std::nullopt;
  }
}

std::optional<V8GPUFeatureName::Enum> RequiredFeatureForBlendFactor(
    V8GPUBlendFactor::Enum blend_factor) {
  switch (blend_factor) {
    case V8GPUBlendFactor::Enum::kSrc1:
    case V8GPUBlendFactor::Enum::kOneMinusSrc1:
    case V8GPUBlendFactor::Enum::kSrc1Alpha:
    case V8GPUBlendFactor::Enum::kOneMinusSrc1Alpha:
      return V8GPUFeatureName::Enum::kDualSourceBlending;
    default:
      return std::nullopt;
  }
}

}  // anonymous namespace

GPUDevice::GPUDevice(ExecutionContext* execution_context,
                     scoped_refptr<DawnControlClientHolder> dawn_control_client,
                     GPUAdapter* adapter,
                     const String& label)
    : ExecutionContextClient(execution_context),
      DawnObject(dawn_control_client, label),
      adapter_(adapter),
      lost_property_(MakeGarbageCollected<LostProperty>(execution_context)),
      error_callback_(BindWGPURepeatingCallback(&GPUDevice::OnUncapturedError,
                                                WrapWeakPersistent(this))),
      logging_callback_(BindWGPURepeatingCallback(&GPUDevice::OnLogging,
                                                  WrapWeakPersistent(this))),
      // Note: This is a *repeating* callback even though we expect it to only
      // be called once. This is because it may be called *zero* times.
      // Because it might never be called, the GPUDevice needs to own the
      // allocation so it can be appropriately freed on destruction. Thus, the
      // callback should not be a OnceCallback which self-deletes after it is
      // called.
      lost_callback_(BindWGPURepeatingCallback(&GPUDevice::OnDeviceLostError,
                                               WrapWeakPersistent(this))) {}

void GPUDevice::Initialize(wgpu::Device handle,
                           const GPUDeviceDescriptor* descriptor,
                           GPUDeviceLostInfo* lost_info) {
  SetHandle(std::move(handle));
  features_ = MakeGarbageCollected<GPUSupportedFeatures>(
      descriptor->requiredFeatures());
  queue_ = MakeGarbageCollected<GPUQueue>(this, GetHandle().GetQueue(),
                                          descriptor->defaultQueue()->label());

  wgpu::SupportedLimits limits = {};
  // Chain to get subgroup limits, if device has subgroups feature.
  wgpu::DawnExperimentalSubgroupLimits subgroupLimits = {};
  if (features_->has(V8GPUFeatureName::Enum::kSubgroups)) {
    limits.nextInChain = &subgroupLimits;
  }

  // Increment subgroups features counter for OT.
  // TODO(crbug.com/349125474): Clean up after OT finished.
  if (features_->has(V8GPUFeatureName::Enum::kSubgroups) ||
      features_->has(V8GPUFeatureName::Enum::kSubgroupsF16)) {
    DCHECK(RuntimeEnabledFeatures::WebGPUSubgroupsFeaturesEnabled(
        GetExecutionContext()));
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kWebGPUSubgroupsFeatures);
  }

  GetHandle().GetLimits(&limits);
  limits_ = MakeGarbageCollected<GPUSupportedLimits>(limits);

  adapter_info_ = adapter_->CreateAdapterInfoForAdapter();

  GetHandle().SetLoggingCallback(logging_callback_->UnboundCallback(),
                                 logging_callback_->AsUserdata());

  external_texture_cache_ = MakeGarbageCollected<ExternalTextureCache>(this);

  // If lost_info is supplied it means the device should be treated as being
  // lost at creation time.
  if (lost_info) {
    lost_property_->Resolve(lost_info);
  }
}

GPUDevice::~GPUDevice() {
  // Perform destruction that's safe to do inside a GC (as in it doesn't touch
  // other GC objects).

  // Clear the callbacks since we can't handle callbacks after finalization.
  // error_callback_, logging_callback_, and lost_callback_ will be deleted.
  if (GetHandle().Get() != nullptr) {
    GetHandle().SetUncapturedErrorCallback(nullptr, nullptr);
    GetHandle().SetLoggingCallback(nullptr, nullptr);
    GetHandle().SetDeviceLostCallback(nullptr, nullptr);
  }
}

void GPUDevice::InjectError(wgpu::ErrorType type, const char* message) {
  GetHandle().InjectError(type, message);
}

void GPUDevice::AddConsoleWarning(wgpu::StringView message) {
  AddConsoleWarning(StringFromASCIIAndUTF8(message));
}
void GPUDevice::AddConsoleWarning(const char* message) {
  AddConsoleWarning(StringFromASCIIAndUTF8(message));
}
void GPUDevice::AddConsoleWarning(const String& message) {
  ExecutionContext* execution_context = GetExecutionContext();
  if (execution_context && allowed_console_warnings_remaining_ > 0) {
    auto* console_message = MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kRendering,
        mojom::blink::ConsoleMessageLevel::kWarning, message);
    execution_context->AddConsoleMessage(console_message);

    allowed_console_warnings_remaining_--;
    if (allowed_console_warnings_remaining_ == 0) {
      auto* final_message = MakeGarbageCollected<ConsoleMessage>(
          mojom::blink::ConsoleMessageSource::kRendering,
          mojom::blink::ConsoleMessageLevel::kWarning,
          "WebGPU: too many warnings, no more warnings will be reported to the "
          "console for this GPUDevice.");
      execution_context->AddConsoleMessage(final_message);
    }
  }
}

void GPUDevice::AddSingletonWarning(GPUSingletonWarning type) {
  size_t index = static_cast<size_t>(type);
  if (!singleton_warning_fired_[index]) [[unlikely]] {
    singleton_warning_fired_[index] = true;

    String message;
    switch (type) {
      case GPUSingletonWarning::kNonPreferredFormat:
        message =
            "WebGPU canvas configured with a different format than is "
            "preferred by this device (\"" +
            FromDawnEnum(GPU::preferred_canvas_format()).AsString() +
            "\"). This requires an extra copy, which may impact performance.";
        break;
      case GPUSingletonWarning::kDepthKey:
        message =
            "The key \"depth\" was included in a GPUExtent3D dictionary, which "
            "has no effect. It is likely that \"depthOrArrayLayers\" was "
            "intended instead.";
        break;
      case GPUSingletonWarning::kCount:
        NOTREACHED();
    }

    ExecutionContext* execution_context = GetExecutionContext();
    if (execution_context) {
      auto* console_message = MakeGarbageCollected<ConsoleMessage>(
          mojom::blink::ConsoleMessageSource::kRendering,
          mojom::blink::ConsoleMessageLevel::kWarning, message);
      execution_context->AddConsoleMessage(console_message);
    }
  }
}

// Validates that any features required for the given texture format are enabled
// for this device. If not, throw a TypeError to ensure consistency with
// browsers that haven't yet implemented the feature.
bool GPUDevice::ValidateTextureFormatUsage(V8GPUTextureFormat format,
                                           ExceptionState& exception_state) {
  auto requiredFeatureOptional =
      RequiredFeatureForTextureFormat(format.AsEnum());

  if (!requiredFeatureOptional) {
    return true;
  }

  V8GPUFeatureName::Enum requiredFeatureEnum = requiredFeatureOptional.value();

  if (features_->has(requiredFeatureEnum)) {
    return true;
  }

  V8GPUFeatureName requiredFeature = V8GPUFeatureName(requiredFeatureEnum);

  exception_state.ThrowTypeError(String::Format(
      "Use of the '%s' texture format requires the '%s' feature "
      "to be enabled on %s.",
      format.AsCStr(), requiredFeature.AsCStr(), formattedLabel().c_str()));
  return false;
}

std::string GPUDevice::formattedLabel() const {
  std::string deviceLabel =
      label().empty() ? "[Device]" : "[Device \"" + label().Utf8() + "\"]";

  return deviceLabel;
}

// Validates that any features required for the given blend factor are enabled
// for this device. If not, throw a TypeError to ensure consistency with
// browsers that haven't yet implemented the feature.
bool GPUDevice::ValidateBlendFactor(V8GPUBlendFactor blend_factor,
                                    ExceptionState& exception_state) {
  auto requiredFeatureOptional =
      RequiredFeatureForBlendFactor(blend_factor.AsEnum());

  if (!requiredFeatureOptional) {
    return true;
  }

  V8GPUFeatureName::Enum requiredFeatureEnum = requiredFeatureOptional.value();

  if (features_->has(requiredFeatureEnum)) {
    return true;
  }

  V8GPUFeatureName requiredFeature = V8GPUFeatureName(requiredFeatureEnum);

  exception_state.ThrowTypeError(
      String::Format("Use of the '%s' blend factor requires the '%s' feature "
                     "to be enabled on %s.",
                     blend_factor.AsCStr(), requiredFeature.AsCStr(),
                     formattedLabel().c_str()));
  return false;
}

void GPUDevice::OnUncapturedError(const wgpu::Device& device,
                                  wgpu::ErrorType errorType,
                                  wgpu::StringView message) {
  // Suppress errors once the device is lost.
  if (lost_property_->GetState() == LostProperty::kResolved) {
    return;
  }

  DCHECK_NE(errorType, wgpu::ErrorType::NoError);
  DCHECK_NE(errorType, wgpu::ErrorType::DeviceLost);
  LOG(ERROR) << "GPUDevice: " << std::string_view(message);

  GPUUncapturedErrorEventInit* init = GPUUncapturedErrorEventInit::Create();
  if (errorType == wgpu::ErrorType::Validation) {
    init->setError(MakeGarbageCollected<GPUValidationError>(
        StringFromASCIIAndUTF8(message)));
  } else if (errorType == wgpu::ErrorType::OutOfMemory) {
    init->setError(MakeGarbageCollected<GPUOutOfMemoryError>(
        StringFromASCIIAndUTF8(message)));
  } else if (errorType == wgpu::ErrorType::Internal) {
    init->setError(MakeGarbageCollected<GPUInternalError>(
        StringFromASCIIAndUTF8(message)));
  } else {
    return;
  }

  GPUUncapturedErrorEvent* event =
      GPUUncapturedErrorEvent::Create(event_type_names::kUncapturederror, init);
  DispatchEvent(*event);
  if (!event->defaultPrevented()) {
    AddConsoleWarning(message);
  }
}

void GPUDevice::OnLogging(WGPULoggingType cLoggingType,
                          WGPUStringView message) {
  std::string_view messageView = {message.data, message.length};
  wgpu::LoggingType loggingType = static_cast<wgpu::LoggingType>(cLoggingType);
  // Callback function for WebGPU logging return command
  mojom::blink::ConsoleMessageLevel level;
  switch (loggingType) {
    case (wgpu::LoggingType::Verbose): {
      level = mojom::blink::ConsoleMessageLevel::kVerbose;
      break;
    }
    case (wgpu::LoggingType::Info): {
      level = mojom::blink::ConsoleMessageLevel::kInfo;
      break;
    }
    case (wgpu::LoggingType::Warning): {
      level = mojom::blink::ConsoleMessageLevel::kWarning;
      break;
    }
    case (wgpu::LoggingType::Error): {
      level = mojom::blink::ConsoleMessageLevel::kError;
      break;
    }
    default: {
      level = mojom::blink::ConsoleMessageLevel::kError;
      break;
    }
  }
  ExecutionContext* execution_context = GetExecutionContext();
  if (execution_context) {
    auto* console_message = MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kRendering, level,
        StringFromASCIIAndUTF8(messageView));
    execution_context->AddConsoleMessage(console_message);
  }
}

void GPUDevice::OnDeviceLostError(const wgpu::Device& device,
                                  wgpu::DeviceLostReason reason,
                                  wgpu::StringView message) {
  // Early-out if the context is being destroyed (see WrapCallbackInScriptScope)
  if (!GetExecutionContext()) {
    return;
  }

  if (reason != wgpu::DeviceLostReason::Destroyed) {
    AddConsoleWarning(message);
  }

  if (lost_property_->GetState() == LostProperty::kPending) {
    auto* device_lost_info = MakeGarbageCollected<GPUDeviceLostInfo>(
        reason, StringFromASCIIAndUTF8(message));
    lost_property_->Resolve(device_lost_info);
  }
}

void GPUDevice::OnCreateRenderPipelineAsyncCallback(
    const String& label,
    ScriptPromiseResolver<GPURenderPipeline>* resolver,
    wgpu::CreatePipelineAsyncStatus status,
    wgpu::RenderPipeline render_pipeline,
    wgpu::StringView message) {
  ScriptState* script_state = resolver->GetScriptState();
  switch (status) {
    case wgpu::CreatePipelineAsyncStatus::Success: {
      GPURenderPipeline* pipeline = MakeGarbageCollected<GPURenderPipeline>(
          this, std::move(render_pipeline), label);
      resolver->Resolve(pipeline);
      break;
    }

    case wgpu::CreatePipelineAsyncStatus::ValidationError: {
      resolver->Reject(GPUPipelineError::Create(
          script_state->GetIsolate(), StringFromASCIIAndUTF8(message),
          V8GPUPipelineErrorReason::Enum::kValidation));
      break;
    }

    case wgpu::CreatePipelineAsyncStatus::InternalError:
    case wgpu::CreatePipelineAsyncStatus::DeviceLost:
    case wgpu::CreatePipelineAsyncStatus::DeviceDestroyed:
    case wgpu::CreatePipelineAsyncStatus::InstanceDropped:
    case wgpu::CreatePipelineAsyncStatus::Unknown: {
      resolver->Reject(GPUPipelineError::Create(
          script_state->GetIsolate(), StringFromASCIIAndUTF8(message),
          V8GPUPipelineErrorReason::Enum::kInternal));
      break;
    }
  }
}

void GPUDevice::OnCreateComputePipelineAsyncCallback(
    const String& label,
    ScriptPromiseResolver<GPUComputePipeline>* resolver,
    wgpu::CreatePipelineAsyncStatus status,
    wgpu::ComputePipeline compute_pipeline,
    wgpu::StringView message) {
  ScriptState* script_state = resolver->GetScriptState();
  switch (status) {
    case wgpu::CreatePipelineAsyncStatus::Success: {
      GPUComputePipeline* pipeline = MakeGarbageCollected<GPUComputePipeline>(
          this, std::move(compute_pipeline), label);
      resolver->Resolve(pipeline);
      break;
    }

    case wgpu::CreatePipelineAsyncStatus::ValidationError: {
      resolver->Reject(GPUPipelineError::Create(
          script_state->GetIsolate(), StringFromASCIIAndUTF8(message),
          V8GPUPipelineErrorReason::Enum::kValidation));
      break;
    }

    case wgpu::CreatePipelineAsyncStatus::InternalError:
    case wgpu::CreatePipelineAsyncStatus::DeviceLost:
    case wgpu::CreatePipelineAsyncStatus::DeviceDestroyed:
    case wgpu::CreatePipelineAsyncStatus::InstanceDropped:
    case wgpu::CreatePipelineAsyncStatus::Unknown: {
      resolver->Reject(GPUPipelineError::Create(
          script_state->GetIsolate(), StringFromASCIIAndUTF8(message),
          V8GPUPipelineErrorReason::Enum::kInternal));
      break;
    }
  }
}

GPUAdapter* GPUDevice::adapter() const {
  return adapter_.Get();
}

GPUSupportedFeatures* GPUDevice::features() const {
  return features_.Get();
}

GPUAdapterInfo* GPUDevice::adapterInfo() const {
  return adapter_info_.Get();
}

ScriptPromise<GPUDeviceLostInfo> GPUDevice::lost(ScriptState* script_state) {
  return lost_property_->Promise(script_state->World());
}

GPUQueue* GPUDevice::queue() {
  return queue_.Get();
}

bool GPUDevice::destroyed() const {
  return destroyed_;
}

void GPUDevice::destroy(v8::Isolate* isolate) {
  destroyed_ = true;
  external_texture_cache_->Destroy();
  // Dissociate mailboxes before destroying the device. This ensures that
  // mailbox operations which run during dissociation can succeed.
  DissociateMailboxes();
  UnmapAllMappableBuffers(isolate);
  GetHandle().Destroy();
  FlushNow();
}

GPUBuffer* GPUDevice::createBuffer(const GPUBufferDescriptor* descriptor,
                                   ExceptionState& exception_state) {
  return GPUBuffer::Create(this, descriptor, exception_state);
}

GPUTexture* GPUDevice::createTexture(const GPUTextureDescriptor* descriptor,
                                     ExceptionState& exception_state) {
  return GPUTexture::Create(this, descriptor, exception_state);
}

GPUSampler* GPUDevice::createSampler(const GPUSamplerDescriptor* descriptor) {
  return GPUSampler::Create(this, descriptor);
}

GPUExternalTexture* GPUDevice::importExternalTexture(
    const GPUExternalTextureDescriptor* descriptor,
    ExceptionState& exception_state) {
  return external_texture_cache_->Import(descriptor, exception_state);
}

GPUBindGroup* GPUDevice::createBindGroup(
    const GPUBindGroupDescriptor* descriptor,
    ExceptionState& exception_state) {
  return GPUBindGroup::Create(this, descriptor, exception_state);
}

GPUBindGroupLayout* GPUDevice::createBindGroupLayout(
    const GPUBindGroupLayoutDescriptor* descriptor,
    ExceptionState& exception_state) {
  return GPUBindGroupLayout::Create(this, descriptor, exception_state);
}

GPUPipelineLayout* GPUDevice::createPipelineLayout(
    const GPUPipelineLayoutDescriptor* descriptor) {
  return GPUPipelineLayout::Create(this, descriptor);
}

GPUShaderModule* GPUDevice::createShaderModule(
    const GPUShaderModuleDescriptor* descriptor) {
  return GPUShaderModule::Create(this, descriptor);
}

GPURenderPipeline* GPUDevice::createRenderPipeline(
    ScriptState* script_state,
    const GPURenderPipelineDescriptor* descriptor) {
  return GPURenderPipeline::Create(script_state, this, descriptor);
}

GPUComputePipeline* GPUDevice::createComputePipeline(
    const GPUComputePipelineDescriptor* descriptor,
    ExceptionState& exception_state) {
  return GPUComputePipeline::Create(this, descriptor);
}

ScriptPromise<GPURenderPipeline> GPUDevice::createRenderPipelineAsync(
    ScriptState* script_state,
    const GPURenderPipelineDescriptor* descriptor,
    ExceptionState& exception_state) {
  OwnedRenderPipelineDescriptor dawn_desc_info;
  ConvertToDawnType(script_state->GetIsolate(), this, descriptor,
                    &dawn_desc_info, exception_state);
  if (exception_state.HadException()) {
    return EmptyPromise();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<GPURenderPipeline>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  auto* callback = MakeWGPUOnceCallback(resolver->WrapCallbackInScriptScope(
      WTF::BindOnce(&GPUDevice::OnCreateRenderPipelineAsyncCallback,
                    WrapPersistent(this), descriptor->label())));

  GetHandle().CreateRenderPipelineAsync(
      &dawn_desc_info.dawn_desc, wgpu::CallbackMode::AllowSpontaneous,
      callback->UnboundCallback(), callback->AsUserdata());

  // WebGPU guarantees that promises are resolved in finite time so we need to
  // ensure commands are flushed.
  EnsureFlush(ToEventLoop(script_state));
  return promise;
}

ScriptPromise<GPUComputePipeline> GPUDevice::createComputePipelineAsync(
    ScriptState* script_state,
    const GPUComputePipelineDescriptor* descriptor) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<GPUComputePipeline>>(
          script_state);
  auto promise = resolver->Promise();

  std::string desc_label;
  OwnedProgrammableStage computeStage;
  wgpu::ComputePipelineDescriptor dawn_desc =
      AsDawnType(this, descriptor, &desc_label, &computeStage);

  auto* callback = MakeWGPUOnceCallback(resolver->WrapCallbackInScriptScope(
      WTF::BindOnce(&GPUDevice::OnCreateComputePipelineAsyncCallback,
                    WrapPersistent(this), descriptor->label())));

  GetHandle().CreateComputePipelineAsync(
      &dawn_desc, wgpu::CallbackMode::AllowSpontaneous,
      callback->UnboundCallback(), callback->AsUserdata());
  // WebGPU guarantees that promises are resolved in finite time so we need to
  // ensure commands are flushed.
  EnsureFlush(ToEventLoop(script_state));
  return promise;
}

GPUCommandEncoder* GPUDevice::createCommandEncoder(
    const GPUCommandEncoderDescriptor* descriptor) {
  return GPUCommandEncoder::Create(this, descriptor);
}

GPURenderBundleEncoder* GPUDevice::createRenderBundleEncoder(
    const GPURenderBundleEncoderDescriptor* descriptor,
    ExceptionState& exception_state) {
  return GPURenderBundleEncoder::Create(this, descriptor, exception_state);
}

GPUQuerySet* GPUDevice::createQuerySet(const GPUQuerySetDescriptor* descriptor,
                                       ExceptionState& exception_state) {
  const V8GPUFeatureName::Enum kTimestampQuery =
      V8GPUFeatureName::Enum::kTimestampQuery;
  const V8GPUFeatureName::Enum kTimestampQueryInsidePasses =
      V8GPUFeatureName::Enum::kChromiumExperimentalTimestampQueryInsidePasses;
  if (descriptor->type() == V8GPUQueryType::Enum::kTimestamp &&
      !features_->has(kTimestampQuery) &&
      !features_->has(kTimestampQueryInsidePasses)) {
    exception_state.ThrowTypeError(
        String::Format("Use of timestamp queries requires the '%s' or '%s' "
                       "feature to be enabled on %s.",
                       V8GPUFeatureName(kTimestampQuery).AsCStr(),
                       V8GPUFeatureName(kTimestampQueryInsidePasses).AsCStr(),
                       formattedLabel().c_str()));
    return nullptr;
  }
  return GPUQuerySet::Create(this, descriptor);
}

void GPUDevice::pushErrorScope(const V8GPUErrorFilter& filter) {
  GetHandle().PushErrorScope(AsDawnEnum(filter));
}

ScriptPromise<IDLNullable<GPUError>> GPUDevice::popErrorScope(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLNullable<GPUError>>>(
          script_state);
  auto promise = resolver->Promise();

  auto* callback =
      MakeWGPUOnceCallback(resolver->WrapCallbackInScriptScope(WTF::BindOnce(
          &GPUDevice::OnPopErrorScopeCallback, WrapPersistent(this))));

  GetHandle().PopErrorScope(wgpu::CallbackMode::AllowSpontaneous,
                            callback->UnboundCallback(),
                            callback->AsUserdata());

  // WebGPU guarantees that promises are resolved in finite time so we
  // need to ensure commands are flushed.
  EnsureFlush(ToEventLoop(script_state));
  return promise;
}

void GPUDevice::OnPopErrorScopeCallback(
    ScriptPromiseResolver<IDLNullable<GPUError>>* resolver,
    wgpu::PopErrorScopeStatus status,
    wgpu::ErrorType type,
    wgpu::StringView message) {
  switch (status) {
    case wgpu::PopErrorScopeStatus::InstanceDropped:
      resolver->RejectWithDOMException(DOMExceptionCode::kOperationError,
                                       "Instance dropped in popErrorScope");
      return;
    case wgpu::PopErrorScopeStatus::Success:
      break;
  }
  switch (type) {
    case wgpu::ErrorType::NoError:
      resolver->Resolve(nullptr);
      break;
    case wgpu::ErrorType::OutOfMemory:
      resolver->Resolve(MakeGarbageCollected<GPUOutOfMemoryError>(
          StringFromASCIIAndUTF8(message)));
      break;
    case wgpu::ErrorType::Validation:
      resolver->Resolve(MakeGarbageCollected<GPUValidationError>(
          StringFromASCIIAndUTF8(message)));
      break;
    case wgpu::ErrorType::Internal:
      resolver->Resolve(MakeGarbageCollected<GPUInternalError>(
          StringFromASCIIAndUTF8(message)));
      break;
    case wgpu::ErrorType::Unknown:
      resolver->RejectWithDOMException(DOMExceptionCode::kOperationError,
                                       "Unknown failure in popErrorScope");
      break;
    case wgpu::ErrorType::DeviceLost:
      resolver->RejectWithDOMException(
          DOMExceptionCode::kOperationError,
          "Device lost during popErrorScope (do not use this error for "
          "recovery - it is NOT guaranteed to happen on device loss)");
      break;
  }
}

ExecutionContext* GPUDevice::GetExecutionContext() const {
  return ExecutionContextClient::GetExecutionContext();
}

const AtomicString& GPUDevice::InterfaceName() const {
  return event_target_names::kGPUDevice;
}

void GPUDevice::Trace(Visitor* visitor) const {
  visitor->Trace(adapter_);
  visitor->Trace(features_);
  visitor->Trace(limits_);
  visitor->Trace(adapter_info_);
  visitor->Trace(queue_);
  visitor->Trace(lost_property_);
  visitor->Trace(external_texture_cache_);
  visitor->Trace(textures_with_mailbox_);
  visitor->Trace(mappable_buffers_);
  ExecutionContextClient::Trace(visitor);
  EventTarget::Trace(visitor);
}

void GPUDevice::Dispose() {
  // This call accesses other GC objects, so it cannot be called inside GC
  // objects destructors. Instead call it in the pre-finalizer.
  if (external_texture_cache_ != nullptr) {
    external_texture_cache_->Destroy();
  }
}

void GPUDevice::DissociateMailboxes() {
  for (auto& texture : textures_with_mailbox_) {
    texture->DissociateMailbox();
  }
  textures_with_mailbox_.clear();
}

void GPUDevice::UnmapAllMappableBuffers(v8::Isolate* isolate) {
  for (GPUBuffer* buffer : mappable_buffers_) {
    buffer->unmap(isolate);
  }
}

void GPUDevice::TrackMappableBuffer(GPUBuffer* buffer) {
  mappable_buffers_.insert(buffer);
}

void GPUDevice::UntrackMappableBuffer(GPUBuffer* buffer) {
  mappable_buffers_.erase(buffer);
}

void GPUDevice::TrackTextureWithMailbox(GPUTexture* texture) {
  DCHECK(texture);
  textures_with_mailbox_.insert(texture);
}

void GPUDevice::UntrackTextureWithMailbox(GPUTexture* texture) {
  DCHECK(texture);
  textures_with_mailbox_.erase(texture);
}

WGPURepeatingCallback<
    void(const wgpu::Device&, wgpu::ErrorType, wgpu::StringView)>*
GPUDevice::error_callback() {
  return error_callback_.get();
}

WGPURepeatingCallback<
    void(const wgpu::Device&, wgpu::DeviceLostReason, wgpu::StringView)>*
GPUDevice::lost_callback() {
  return lost_callback_.get();
}
}  // namespace blink
```