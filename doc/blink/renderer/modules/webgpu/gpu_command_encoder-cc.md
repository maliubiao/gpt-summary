Response:
Let's break down the thought process for analyzing the `gpu_command_encoder.cc` file.

1. **Understand the Core Purpose:** The filename itself, `gpu_command_encoder.cc`, strongly suggests this file is responsible for the `GPUCommandEncoder` class. This class is likely the mechanism for recording a sequence of GPU commands. The `#include` directives at the top confirm this by pulling in related WebGPU types (render passes, compute passes, textures, buffers, etc.).

2. **Identify Key Functionalities by Examining Public Methods:**  A quick scan of the class's public methods reveals its main capabilities:
    * `Create`:  Indicates object creation. Likely involves interacting with the underlying WebGPU implementation (Dawn in this case).
    * `beginRenderPass`:  Starts recording commands for a render pass (drawing to the screen).
    * `beginComputePass`: Starts recording commands for a compute pass (general-purpose GPU computation).
    * `copyBufferToTexture`, `copyTextureToBuffer`, `copyTextureToTexture`:  Data transfer operations between different GPU memory locations.
    * `writeTimestamp`:  For performance measurement and synchronization.
    * `finish`:  Finalizes the recording and creates a `GPUCommandBuffer`.

3. **Analyze Interactions with Other Components (Based on Includes and Method Parameters):**  The `#include` directives and method parameter types give clues about how this class interacts with other parts of the system:
    * **JavaScript Bindings:** The inclusion of `v8_gpu_*` header files strongly suggests this class is exposed to JavaScript. The method parameters often use types directly corresponding to JavaScript WebGPU API objects (e.g., `GPURenderPassDescriptor`).
    * **HTML/CSS (Indirectly):** Render passes are used to draw content that eventually appears on the HTML page. So, while this file doesn't directly handle HTML or CSS parsing, its output is crucial for rendering what those languages define.
    * **Dawn (Underlying WebGPU Implementation):** The presence of `dawn_conversions.h` and the use of `wgpu::` types everywhere indicate this class acts as a bridge between the Blink rendering engine and the Dawn implementation of WebGPU.
    * **Other WebGPU Classes:** The methods take and return instances of other `GPU*` classes like `GPUBuffer`, `GPUTexture`, `GPUQuerySet`, `GPUCommandBuffer`, `GPURenderPassEncoder`, and `GPUComputePassEncoder`. This shows a clear workflow of creating commands and managing GPU resources.

4. **Look for Logic and Conversions:**  The code within the methods primarily focuses on:
    * **Validation:**  Checking input parameters for correctness (e.g., `ValidateColorAttachmentsDepthSlice`, `ValidateAndConvertTimestampWrites`). This is essential to prevent crashes or unexpected behavior.
    * **Conversion to Dawn Types:**  The `ConvertToDawn` functions are central to translating Blink's internal representation of WebGPU objects into the format expected by the Dawn library. This involves mapping data structures and enums.
    * **Calling Dawn API:**  The core functionality of each method often involves calling a corresponding method on the underlying `wgpu::CommandEncoder` object obtained from Dawn.

5. **Identify Potential User Errors:** Based on the validation logic and the nature of GPU programming, common errors are likely to involve:
    * **Incorrect Resource Usage:**  Trying to copy data between incompatible buffer/texture formats, sizes, or usages.
    * **Invalid Descriptor Values:** Providing out-of-range or semantically incorrect values in the descriptor objects (e.g., `depthSlice` being too large, incorrect load/store operations).
    * **Feature Requirements:** Attempting to use features not supported by the current device or not explicitly requested.
    * **Incorrect Sequencing of Operations:**  Trying to use resources or encoders in an invalid order.

6. **Trace User Actions (Debugging Context):** To understand how a user might reach this code during debugging, consider the typical WebGPU workflow:
    * **Get a GPUDevice:** The user first needs a `GPUDevice` instance, often obtained through `navigator.gpu.requestAdapter()` and `adapter.requestDevice()`.
    * **Create a GPUCommandEncoder:**  The `device.createCommandEncoder()` method is the entry point to this file's functionality.
    * **Begin a Pass:**  The user then calls `commandEncoder.beginRenderPass()` or `commandEncoder.beginComputePass()` to start recording commands.
    * **Record Commands:**  Various methods on the render or compute pass encoder are called (these are *not* in this file, but are subsequent steps).
    * **Finish Encoding:**  Finally, `commandEncoder.finish()` is called to create a `GPUCommandBuffer`.
    * **Submit the Buffer:** The command buffer is submitted to the `GPUQueue` for execution.

7. **Structure the Answer:** Organize the findings into clear categories: Functionality, Relation to Web Technologies, Logic and Assumptions, Common Errors, and User Interaction/Debugging. Use the information gleaned in the previous steps to provide concrete examples and explanations.

8. **Refine and Review:** Read through the generated answer, ensuring accuracy, clarity, and completeness. Check for any logical inconsistencies or areas where further detail could be beneficial. For instance, explicitly mentioning the role of the `ExceptionState` in error handling is important.

This systematic approach, starting with the big picture and gradually drilling down into specifics, helps to thoroughly analyze the functionality and context of a source code file.
这个文件 `blink/renderer/modules/webgpu/gpu_command_encoder.cc` 是 Chromium Blink 引擎中负责实现 WebGPU API 中 `GPUCommandEncoder` 接口的关键部分。`GPUCommandEncoder` 的主要功能是 **记录一系列的 GPU 操作指令**，这些指令随后会被提交到 GPU 执行。

以下是这个文件的详细功能列表：

**1. 创建 `GPUCommandEncoder` 对象:**

*   `GPUCommandEncoder::Create(GPUDevice* device, const GPUCommandEncoderDescriptor* webgpu_desc)`: 静态方法，负责根据给定的描述符创建一个 `GPUCommandEncoder` 的实例。
*   接收一个 `GPUDevice` 指针，表示这个命令编码器属于哪个设备。
*   接收一个 `GPUCommandEncoderDescriptor` 对象，包含创建命令编码器的可选配置，例如标签（label）。
*   内部会调用 Dawn (WebGPU 的 C++ 实现) 的接口来创建底层的命令编码器。

**2. 开始记录渲染通道 (Render Pass):**

*   `GPUCommandEncoder::beginRenderPass(const GPURenderPassDescriptor* descriptor, ExceptionState& exception_state)`:  开始一个新的渲染通道。
*   接收一个 `GPURenderPassDescriptor` 对象，详细描述了渲染通道的配置，包括：
    *   颜色附件 (`colorAttachments`):  指定渲染的目标纹理视图，以及如何加载和存储这些附件的内容。
    *   深度/模板附件 (`depthStencilAttachment`): 指定深度和模板缓冲区，以及它们的加载和存储操作。
    *   遮挡查询集 (`occlusionQuerySet`): 用于进行遮挡查询。
    *   时间戳写入 (`timestampWrites`): 用于在渲染通道开始和结束时记录时间戳。
    *   最大绘制调用计数 (`maxDrawCount`):  限制渲染通道中的绘制调用次数。
*   内部会将 `GPURenderPassDescriptor` 的信息转换为 Dawn 可以理解的格式。
*   创建一个 `GPURenderPassEncoder` 对象，用于记录渲染通道内的具体渲染指令。

**3. 开始记录计算通道 (Compute Pass):**

*   `GPUCommandEncoder::beginComputePass(const GPUComputePassDescriptor* descriptor, ExceptionState& exception_state)`: 开始一个新的计算通道。
*   接收一个 `GPUComputePassDescriptor` 对象，描述了计算通道的配置，包括：
    *   时间戳写入 (`timestampWrites`): 用于在计算通道开始和结束时记录时间戳。
*   内部会将 `GPUComputePassDescriptor` 的信息转换为 Dawn 可以理解的格式。
*   创建一个 `GPUComputePassEncoder` 对象，用于记录计算通道内的具体计算指令。

**4. 资源拷贝操作:**

*   `GPUCommandEncoder::copyBufferToTexture(GPUImageCopyBuffer* source, GPUImageCopyTexture* destination, const V8GPUExtent3D* copy_size, ExceptionState& exception_state)`: 将缓冲区的内容拷贝到纹理。
*   接收源缓冲区 (`GPUImageCopyBuffer`)、目标纹理 (`GPUImageCopyTexture`) 和拷贝区域大小 (`V8GPUExtent3D`)。
*   `GPUCommandEncoder::copyTextureToBuffer(GPUImageCopyTexture* source, GPUImageCopyBuffer* destination, const V8GPUExtent3D* copy_size, ExceptionState& exception_state)`: 将纹理的内容拷贝到缓冲区。
*   接收源纹理、目标缓冲区和拷贝区域大小。
*   `GPUCommandEncoder::copyTextureToTexture(GPUImageCopyTexture* source, GPUImageCopyTexture* destination, const V8GPUExtent3D* copy_size, ExceptionState& exception_state)`: 将一个纹理的内容拷贝到另一个纹理。
*   接收源纹理、目标纹理和拷贝区域大小。
*   这些方法会将 Blink 的 WebGPU 对象转换为 Dawn 的对应类型，并调用 Dawn 的拷贝函数。

**5. 写入时间戳:**

*   `GPUCommandEncoder::writeTimestamp(DawnObject<wgpu::QuerySet>* querySet, uint32_t queryIndex, ExceptionState& exception_state)`:  在命令流中插入一个时间戳。
*   接收一个查询集 (`GPUQuerySet`) 和一个查询索引 (`queryIndex`)。
*   要求设备支持 `timestamp-query` 功能。

**6. 完成命令编码并创建 `GPUCommandBuffer`:**

*   `GPUCommandEncoder::finish(const GPUCommandBufferDescriptor* descriptor)`: 完成命令的编码过程。
*   接收一个 `GPUCommandBufferDescriptor` 对象，包含创建命令缓冲区的可选配置，例如标签。
*   内部会调用 Dawn 的接口来完成命令编码，并将记录的指令存储在一个 `GPUCommandBuffer` 对象中。

**与 JavaScript, HTML, CSS 的关系及举例:**

`GPUCommandEncoder` 是 WebGPU API 的一部分，直接暴露给 JavaScript。HTML 和 CSS 通过 JavaScript 调用 WebGPU API 来控制图形渲染和 GPU 计算。

*   **JavaScript:**  开发者使用 JavaScript 调用 `GPUDevice.createCommandEncoder()` 方法来创建 `GPUCommandEncoder` 的实例。然后，使用 `beginRenderPass` 或 `beginComputePass` 开始记录指令，并调用 `copyBufferToTexture` 等方法进行资源管理。最后，调用 `finish` 方法生成 `GPUCommandBuffer`。

    ```javascript
    const canvas = document.querySelector('canvas');
    const adapter = await navigator.gpu.requestAdapter();
    const device = await adapter.requestDevice();
    const context = canvas.getContext('webgpu');
    context.configure({
      device: device,
      format: navigator.gpu.getPreferredCanvasFormat(),
    });

    const commandEncoder = device.createCommandEncoder();
    const renderPassDescriptor = {
      colorAttachments: [{
        view: context.getCurrentTexture().createView(),
        loadOp: 'clear',
        storeOp: 'store',
        clearValue: { r: 0.0, g: 0.0, b: 0.0, a: 1.0 },
      }],
    };
    const passEncoder = commandEncoder.beginRenderPass(renderPassDescriptor);
    // ... 在 passEncoder 上记录渲染指令 ...
    passEncoder.end();

    const commandBuffer = commandEncoder.finish();
    device.queue.submit([commandBuffer]);
    ```

*   **HTML:** HTML 提供了 `<canvas>` 元素，WebGPU 通常在这个画布上进行渲染。JavaScript 代码获取 canvas 元素，并使用 WebGPU API 在其上进行绘制。

    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <title>WebGPU Example</title>
    </head>
    <body>
      <canvas id="gpuCanvas" width="512" height="512"></canvas>
      <script src="main.js"></script>
    </body>
    </html>
    ```

*   **CSS:** CSS 可以影响 canvas 元素的外观和布局，但它不直接控制 WebGPU 的渲染过程。CSS 影响的是 HTML 元素的样式，而 WebGPU 操作的是 canvas 元素的底层像素缓冲区。

**逻辑推理 (假设输入与输出):**

假设有以下 JavaScript 代码片段：

```javascript
const commandEncoder = device.createCommandEncoder();
const buffer = device.createBuffer({ size: 16, usage: GPUBufferUsage.COPY_SRC });
const texture = device.createTexture({ size: [4, 4, 1], format: 'rgba8unorm', usage: GPUTextureUsage.COPY_DST });

const source = {
  buffer: buffer,
  offset: 0,
  bytesPerRow: 16,
  rowsPerImage: 1,
};

const destination = {
  texture: texture,
  origin: [0, 0, 0],
};

const copySize = [4, 4, 1];

commandEncoder.copyBufferToTexture(source, destination, copySize);
const commandBuffer = commandEncoder.finish();
```

**假设输入:**

*   一个有效的 `GPUDevice` 对象。
*   一个 `GPUBuffer` 对象 (`buffer`)，大小为 16 字节，用途为 `COPY_SRC`。
*   一个 `GPUTexture` 对象 (`texture`)，大小为 4x4x1，格式为 `rgba8unorm`，用途为 `COPY_DST`。
*   `source` 对象描述了从缓冲区拷贝数据的布局。
*   `destination` 对象描述了向纹理拷贝数据的起始位置。
*   `copySize` 数组指定了拷贝的大小为 4x4x1。

**逻辑推理:**

`GPUCommandEncoder::copyBufferToTexture` 方法会被调用。内部会进行以下操作：

1. **参数转换:** 将 JavaScript 传递的 `source`, `destination`, `copySize` 对象转换为 Dawn 对应的 C++ 数据结构 (`wgpu::ImageCopyBuffer`, `wgpu::ImageCopyTexture`, `wgpu::Extent3D`)。
2. **校验:**  可能会进行一些校验，例如确保缓冲区的大小足够容纳拷贝的数据，纹理的用途允许写入等。虽然这个具体校验逻辑可能在其他地方，但 `GPUCommandEncoder` 负责构建发送给 Dawn 的指令。
3. **调用 Dawn API:** 调用 Dawn 的 `wgpu::CommandEncoder::CopyBufferToTexture` 方法，传入转换后的参数。这会在底层的命令流中记录一个将缓冲区内容拷贝到纹理的指令。

**预期输出:**

*   `commandEncoder.finish()` 方法会返回一个 `GPUCommandBuffer` 对象，该对象包含了将 `buffer` 的内容拷贝到 `texture` 的指令。
*   当这个 `GPUCommandBuffer` 被提交到 `GPUQueue` 并执行后，`buffer` 的前 16 个字节的数据将被拷贝到 `texture` 的 (0, 0, 0) 位置，填充整个纹理。

**用户或编程常见的使用错误:**

1. **在 `beginRenderPass` 或 `beginComputePass` 之后，没有调用对应的 `end()` 方法:** 这会导致命令编码器处于未完成状态，后续的 `finish()` 调用可能会出错或者产生不完整的命令缓冲区。

    ```javascript
    const commandEncoder = device.createCommandEncoder();
    const passEncoder = commandEncoder.beginRenderPass(renderPassDescriptor);
    // 忘记调用 passEncoder.end();
    const commandBuffer = commandEncoder.finish(); // 错误：渲染通道未结束
    ```

2. **尝试在已经 `finish()` 过的命令编码器上继续记录指令:**  一旦 `finish()` 被调用，命令编码器就不能再添加新的指令。

    ```javascript
    const commandEncoder = device.createCommandEncoder();
    // ... 记录一些指令 ...
    const commandBuffer1 = commandEncoder.finish();

    // 错误：尝试在已完成的编码器上开始新的渲染通道
    const passEncoder2 = commandEncoder.beginRenderPass(renderPassDescriptor);
    ```

3. **资源拷贝的参数不匹配:**  例如，尝试将大小不匹配的缓冲区拷贝到纹理，或者源和目标资源的用途不兼容。

    ```javascript
    const commandEncoder = device.createCommandEncoder();
    const smallBuffer = device.createBuffer({ size: 8, usage: GPUBufferUsage.COPY_SRC });
    const largeTexture = device.createTexture({ size: [4, 4, 1], format: 'rgba8unorm', usage: GPUTextureUsage.COPY_DST });

    const source = { buffer: smallBuffer, offset: 0, bytesPerRow: 8, rowsPerImage: 1 };
    const destination = { texture: largeTexture, origin: [0, 0, 0] };
    const copySize = [4, 4, 1]; // 尝试拷贝 16 字节的数据，但 buffer 只有 8 字节

    commandEncoder.copyBufferToTexture(source, destination, copySize); // 可能导致错误
    ```

4. **在需要特定 feature 的情况下调用 `writeTimestamp` 但 feature 未启用:**

    ```javascript
    const commandEncoder = device.createCommandEncoder();
    const querySet = device.createQuerySet({ type: 'timestamp', count: 2 });
    // 假设设备没有启用 timestamp-query feature
    commandEncoder.writeTimestamp(querySet, 0); // 错误：需要 timestamp-query feature
    ```

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 JavaScript 代码，使用 WebGPU API 进行图形渲染或 GPU 计算。**
2. **代码中调用了 `GPUDevice.createCommandEncoder()` 方法。**  这会在 Blink 内部创建一个 `GPUCommandEncoder` 对象，对应于 `gpu_command_encoder.cc` 中的 `GPUCommandEncoder::Create` 方法。
3. **用户调用 `commandEncoder.beginRenderPass(descriptor)` 或 `commandEncoder.beginComputePass(descriptor)`。**  这将调用 `gpu_command_encoder.cc` 中的相应方法，开始记录特定类型的 GPU 操作序列。
4. **在渲染通道或计算通道中，用户可能调用各种方法来设置状态、绑定资源和提交绘制或计算调用（这些操作在 `GPURenderPassEncoder.cc` 或 `GPUComputePassEncoder.cc` 中实现）。**
5. **用户可能调用 `commandEncoder.copyBufferToTexture()`, `copyTextureToBuffer()`, 或 `copyTextureToTexture()` 来管理 GPU 资源。** 这些操作会直接调用 `gpu_command_encoder.cc` 中的相应拷贝方法。
6. **如果用户需要进行性能分析，可能会调用 `commandEncoder.writeTimestamp()`。**  这会触发 `gpu_command_encoder.cc` 中的 `writeTimestamp` 方法。
7. **最后，用户调用 `commandEncoder.finish()` 方法。**  这将调用 `gpu_command_encoder.cc` 中的 `finish` 方法，完成命令的编码并创建一个可以提交到 GPU 队列的 `GPUCommandBuffer` 对象。

**调试线索:**

当开发者在使用 WebGPU 时遇到问题，例如渲染结果不正确、程序崩溃或性能问题，他们可能会使用浏览器提供的开发者工具进行调试。

*   **断点:** 可以在 `gpu_command_encoder.cc` 中的关键方法（例如 `beginRenderPass`, `copyBufferToTexture`, `finish`) 设置断点，以便在代码执行到这些地方时暂停，检查参数的值和程序状态。
*   **WebGPU 追踪工具:** 浏览器可能提供 WebGPU 相关的追踪工具，可以记录和回放 WebGPU API 的调用序列，帮助开发者理解命令的执行流程。
*   **错误消息:**  如果 WebGPU API 的使用不正确，通常会抛出 JavaScript 异常或者在控制台中打印错误消息。这些错误消息可能指示问题出在哪个 `GPUCommandEncoder` 的方法调用上。
*   **Dawn 的验证层:**  Dawn 提供了验证层，可以在开发阶段启用，以捕获更多 WebGPU API 使用上的错误，这些错误可能在 Blink 层面被捕获并传递给开发者。

通过以上分析，开发者可以理解 `gpu_command_encoder.cc` 文件的作用，以及用户操作是如何一步步触发这些代码的执行，从而更好地进行 WebGPU 应用的开发和调试。

Prompt: 
```
这是目录为blink/renderer/modules/webgpu/gpu_command_encoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webgpu/gpu_command_encoder.h"

#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_command_buffer_descriptor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_command_encoder_descriptor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_compute_pass_descriptor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_compute_pass_timestamp_writes.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_image_copy_buffer.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_image_copy_texture.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_render_pass_color_attachment.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_render_pass_depth_stencil_attachment.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_render_pass_descriptor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_render_pass_timestamp_writes.h"
#include "third_party/blink/renderer/modules/webgpu/dawn_conversions.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_buffer.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_command_buffer.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_compute_pass_encoder.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_device.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_query_set.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_render_pass_encoder.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_supported_features.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_texture.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_texture_view.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

bool ConvertToDawn(const GPURenderPassColorAttachment* in,
                   wgpu::RenderPassColorAttachment* out,
                   ExceptionState& exception_state) {
  DCHECK(in);
  DCHECK(out);

  *out = {
      .view = in->view()->GetHandle(),
      .loadOp = AsDawnEnum(in->loadOp()),
      .storeOp = AsDawnEnum(in->storeOp()),
  };
  if (in->hasDepthSlice()) {
    out->depthSlice = in->depthSlice();
  }
  if (in->hasResolveTarget()) {
    out->resolveTarget = in->resolveTarget()->GetHandle();
  }
  if (in->hasClearValue() &&
      !ConvertToDawn(in->clearValue(), &out->clearValue, exception_state)) {
    return false;
  }

  return true;
}

namespace {

// Dawn represents `undefined` as the special uint32_t value
// wgpu::kDepthSliceUndefined (0xFFFF'FFFF). Blink must make sure that an
// actual value of 0xFFFF'FFFF coming in from JS is not treated as
// wgpu::kDepthSliceUndefined, so it injects an error in that case.
std::string ValidateColorAttachmentsDepthSlice(
    const HeapVector<Member<GPURenderPassColorAttachment>>& in,
    const char* desc_label) {
  for (wtf_size_t i = 0; i < in.size(); ++i) {
    if (!in[i]) {
      continue;
    }

    const GPURenderPassColorAttachment* attachment = in[i].Get();
    if (attachment->hasDepthSlice() &&
        attachment->depthSlice() == wgpu::kDepthSliceUndefined) {
      std::ostringstream error;
      error << "depthSlice (" << attachment->depthSlice()
            << ") is too large when validating [GPURenderPassDescriptor";
      if (desc_label != nullptr && strlen(desc_label) != 0) {
        error << " '" << desc_label << "'";
      }
      error << "] against the colorAttachment (" << i << ").";
      return error.str();
    }
  }

  return std::string();
}

// Dawn represents `undefined` as the special uint32_t value
// wgpu::kQuerySetIndexUndefined (0xFFFF'FFFF). Blink must make sure that an
// actual value of 0xFFFF'FFFF coming in from JS is not treated as
// wgpu::kQuerySetIndexUndefined, so it injects an error in that case.
template <typename GPUTimestampWrites, typename TimestampWrites>
std::string ValidateAndConvertTimestampWrites(
    const GPUTimestampWrites* webgpu_desc,
    TimestampWrites* dawn_desc,
    const char* desc_type,
    const char* desc_label) {
  DCHECK(webgpu_desc);
  DCHECK(webgpu_desc->querySet());

  uint32_t beginningOfPassWriteIndex = 0;
  if (webgpu_desc->hasBeginningOfPassWriteIndex()) {
    beginningOfPassWriteIndex = webgpu_desc->beginningOfPassWriteIndex();
    if (beginningOfPassWriteIndex == wgpu::kQuerySetIndexUndefined) {
      std::ostringstream error;
      error << "beginningOfPassWriteIndex (" << beginningOfPassWriteIndex
            << ") is too large when validating [" << desc_type;
      if (desc_label != nullptr && strlen(desc_label) != 0) {
        error << " '" << desc_label << "'";
      }
      error << "].";

      return error.str();
    }
  } else {
    beginningOfPassWriteIndex = wgpu::kQuerySetIndexUndefined;
  }

  uint32_t endOfPassWriteIndex = 0;
  if (webgpu_desc->hasEndOfPassWriteIndex()) {
    endOfPassWriteIndex = webgpu_desc->endOfPassWriteIndex();
    if (endOfPassWriteIndex == wgpu::kQuerySetIndexUndefined) {
      std::ostringstream error;
      error << "endOfPassWriteIndex (" << endOfPassWriteIndex
            << ") is too large when validating [" << desc_type;
      if (desc_label != nullptr && strlen(desc_label) != 0) {
        error << " '" << desc_label << "'";
      }
      error << "].";
      return error.str();
    }
  } else {
    endOfPassWriteIndex = wgpu::kQuerySetIndexUndefined;
  }

  *dawn_desc = {
      .querySet = webgpu_desc->querySet()->GetHandle(),
      .beginningOfPassWriteIndex = beginningOfPassWriteIndex,
      .endOfPassWriteIndex = endOfPassWriteIndex,
  };

  return std::string();
}

wgpu::RenderPassDepthStencilAttachment AsDawnType(
    GPUDevice* device,
    const GPURenderPassDepthStencilAttachment* webgpu_desc) {
  DCHECK(webgpu_desc);

  wgpu::RenderPassDepthStencilAttachment dawn_desc = {
      .view = webgpu_desc->view()->GetHandle(),
      // NaN is the default value in Dawn
      .depthClearValue = webgpu_desc->getDepthClearValueOr(
          std::numeric_limits<float>::quiet_NaN()),
      .depthReadOnly = webgpu_desc->depthReadOnly(),
      .stencilReadOnly = webgpu_desc->stencilReadOnly(),
  };

  if (webgpu_desc->hasDepthLoadOp()) {
    dawn_desc.depthLoadOp = AsDawnEnum(webgpu_desc->depthLoadOp());
  }

  if (webgpu_desc->hasDepthStoreOp()) {
    dawn_desc.depthStoreOp = AsDawnEnum(webgpu_desc->depthStoreOp());
  }

  if (webgpu_desc->hasStencilLoadOp()) {
    dawn_desc.stencilLoadOp = AsDawnEnum(webgpu_desc->stencilLoadOp());
    dawn_desc.stencilClearValue = webgpu_desc->stencilClearValue();
  }

  if (webgpu_desc->hasStencilStoreOp()) {
    dawn_desc.stencilStoreOp = AsDawnEnum(webgpu_desc->stencilStoreOp());
  }

  return dawn_desc;
}

wgpu::ImageCopyBuffer ValidateAndConvertImageCopyBuffer(
    const GPUImageCopyBuffer* webgpu_view,
    const char** error) {
  DCHECK(webgpu_view);
  DCHECK(webgpu_view->buffer());

  wgpu::ImageCopyBuffer dawn_view = {.buffer =
                                         webgpu_view->buffer()->GetHandle()};

  *error = ValidateTextureDataLayout(webgpu_view, &dawn_view.layout);
  return dawn_view;
}

wgpu::CommandEncoderDescriptor AsDawnType(
    const GPUCommandEncoderDescriptor* webgpu_desc,
    std::string* label) {
  DCHECK(webgpu_desc);
  DCHECK(label);

  wgpu::CommandEncoderDescriptor dawn_desc = {};
  *label = webgpu_desc->label().Utf8();
  if (!label->empty()) {
    dawn_desc.label = label->c_str();
  }

  return dawn_desc;
}

}  // anonymous namespace

// static
GPUCommandEncoder* GPUCommandEncoder::Create(
    GPUDevice* device,
    const GPUCommandEncoderDescriptor* webgpu_desc) {
  DCHECK(device);
  DCHECK(webgpu_desc);

  std::string label;
  wgpu::CommandEncoderDescriptor dawn_desc = AsDawnType(webgpu_desc, &label);

  GPUCommandEncoder* encoder = MakeGarbageCollected<GPUCommandEncoder>(
      device, device->GetHandle().CreateCommandEncoder(&dawn_desc),
      webgpu_desc->label());
  return encoder;
}

GPUCommandEncoder::GPUCommandEncoder(GPUDevice* device,
                                     wgpu::CommandEncoder command_encoder,
                                     const String& label)
    : DawnObject<wgpu::CommandEncoder>(device,
                                       std::move(command_encoder),
                                       label) {}

GPURenderPassEncoder* GPUCommandEncoder::beginRenderPass(
    const GPURenderPassDescriptor* descriptor,
    ExceptionState& exception_state) {
  DCHECK(descriptor);

  wgpu::RenderPassDescriptor dawn_desc = {};

  std::string label = descriptor->label().Utf8();
  if (!label.empty()) {
    dawn_desc.label = label.c_str();
  }

  std::unique_ptr<wgpu::RenderPassColorAttachment[]> color_attachments;
  dawn_desc.colorAttachmentCount = descriptor->colorAttachments().size();
  if (dawn_desc.colorAttachmentCount > 0) {
    std::string error = ValidateColorAttachmentsDepthSlice(
        descriptor->colorAttachments(), label.c_str());
    if (!error.empty()) {
      GetHandle().InjectValidationError(error.c_str());
    }

    if (!ConvertToDawn(descriptor->colorAttachments(), &color_attachments,
                       exception_state)) {
      return nullptr;
    }
    dawn_desc.colorAttachments = color_attachments.get();
  }

  wgpu::RenderPassDepthStencilAttachment depthStencilAttachment = {};
  if (descriptor->hasDepthStencilAttachment()) {
    const GPURenderPassDepthStencilAttachment* depth_stencil =
        descriptor->depthStencilAttachment();
    depthStencilAttachment = AsDawnType(device_, depth_stencil);
    dawn_desc.depthStencilAttachment = &depthStencilAttachment;
  }

  if (descriptor->hasOcclusionQuerySet()) {
    dawn_desc.occlusionQuerySet = AsDawnType(descriptor->occlusionQuerySet());
  }

  wgpu::RenderPassTimestampWrites timestampWrites = {};
  if (descriptor->hasTimestampWrites()) {
    GPURenderPassTimestampWrites* timestamp_writes =
        descriptor->timestampWrites();
    std::string error = ValidateAndConvertTimestampWrites(
        timestamp_writes, &timestampWrites, "GPURenderPassDescriptor",
        label.c_str());
    if (!error.empty()) {
      GetHandle().InjectValidationError(error.c_str());
    } else {
      dawn_desc.timestampWrites = &timestampWrites;
    }
  }

  wgpu::RenderPassMaxDrawCount max_draw_count = {};
  if (descriptor->hasMaxDrawCount()) {
    max_draw_count.maxDrawCount = descriptor->maxDrawCount();
    dawn_desc.nextInChain = &max_draw_count;
  }

  GPURenderPassEncoder* encoder = MakeGarbageCollected<GPURenderPassEncoder>(
      device_, GetHandle().BeginRenderPass(&dawn_desc), descriptor->label());
  return encoder;
}

GPUComputePassEncoder* GPUCommandEncoder::beginComputePass(
    const GPUComputePassDescriptor* descriptor,
    ExceptionState& exception_state) {
  wgpu::ComputePassDescriptor dawn_desc = {};
  std::string label = descriptor->label().Utf8();
  if (!label.empty()) {
    dawn_desc.label = label.c_str();
  }

  wgpu::ComputePassTimestampWrites timestampWrites = {};
  if (descriptor->hasTimestampWrites()) {
    GPUComputePassTimestampWrites* timestamp_writes =
        descriptor->timestampWrites();
    std::string error = ValidateAndConvertTimestampWrites(
        timestamp_writes, &timestampWrites, "GPUComputePassDescriptor",
        label.c_str());
    if (!error.empty()) {
      GetHandle().InjectValidationError(error.c_str());
    } else {
      dawn_desc.timestampWrites = &timestampWrites;
    }
  }

  GPUComputePassEncoder* encoder = MakeGarbageCollected<GPUComputePassEncoder>(
      device_, GetHandle().BeginComputePass(&dawn_desc), descriptor->label());
  return encoder;
}

void GPUCommandEncoder::copyBufferToTexture(GPUImageCopyBuffer* source,
                                            GPUImageCopyTexture* destination,
                                            const V8GPUExtent3D* copy_size,
                                            ExceptionState& exception_state) {
  wgpu::Extent3D dawn_copy_size;
  wgpu::ImageCopyTexture dawn_destination;
  if (!ConvertToDawn(copy_size, &dawn_copy_size, device_, exception_state) ||
      !ConvertToDawn(destination, &dawn_destination, exception_state)) {
    return;
  }

  const char* error = nullptr;
  wgpu::ImageCopyBuffer dawn_source =
      ValidateAndConvertImageCopyBuffer(source, &error);
  if (error) {
    GetHandle().InjectValidationError(error);
    return;
  }

  GetHandle().CopyBufferToTexture(&dawn_source, &dawn_destination,
                                  &dawn_copy_size);
}

void GPUCommandEncoder::copyTextureToBuffer(GPUImageCopyTexture* source,
                                            GPUImageCopyBuffer* destination,
                                            const V8GPUExtent3D* copy_size,
                                            ExceptionState& exception_state) {
  wgpu::Extent3D dawn_copy_size;
  wgpu::ImageCopyTexture dawn_source;
  if (!ConvertToDawn(copy_size, &dawn_copy_size, device_, exception_state) ||
      !ConvertToDawn(source, &dawn_source, exception_state)) {
    return;
  }

  const char* error = nullptr;
  wgpu::ImageCopyBuffer dawn_destination =
      ValidateAndConvertImageCopyBuffer(destination, &error);
  if (error) {
    GetHandle().InjectValidationError(error);
    return;
  }

  GetHandle().CopyTextureToBuffer(&dawn_source, &dawn_destination,
                                  &dawn_copy_size);
}

void GPUCommandEncoder::copyTextureToTexture(GPUImageCopyTexture* source,
                                             GPUImageCopyTexture* destination,
                                             const V8GPUExtent3D* copy_size,
                                             ExceptionState& exception_state) {
  wgpu::Extent3D dawn_copy_size;
  wgpu::ImageCopyTexture dawn_source;
  wgpu::ImageCopyTexture dawn_destination;
  if (!ConvertToDawn(copy_size, &dawn_copy_size, device_, exception_state) ||
      !ConvertToDawn(source, &dawn_source, exception_state) ||
      !ConvertToDawn(destination, &dawn_destination, exception_state)) {
    return;
  }

  GetHandle().CopyTextureToTexture(&dawn_source, &dawn_destination,
                                   &dawn_copy_size);
}

void GPUCommandEncoder::writeTimestamp(DawnObject<wgpu::QuerySet>* querySet,
                                       uint32_t queryIndex,
                                       ExceptionState& exception_state) {
  V8GPUFeatureName::Enum requiredFeatureEnum =
      V8GPUFeatureName::Enum::kTimestampQuery;
  if (!device_->features()->has(requiredFeatureEnum)) {
    exception_state.ThrowTypeError(
        String::Format("Use of the writeTimestamp() method requires the '%s' "
                       "feature to be enabled on %s.",
                       V8GPUFeatureName(requiredFeatureEnum).AsCStr(),
                       device_->formattedLabel().c_str()));
    return;
  }
  GetHandle().WriteTimestamp(querySet->GetHandle(), queryIndex);
}

GPUCommandBuffer* GPUCommandEncoder::finish(
    const GPUCommandBufferDescriptor* descriptor) {
  wgpu::CommandBufferDescriptor dawn_desc = {};
  std::string label = descriptor->label().Utf8();
  if (!label.empty()) {
    dawn_desc.label = label.c_str();
  }

  GPUCommandBuffer* command_buffer = MakeGarbageCollected<GPUCommandBuffer>(
      device_, GetHandle().Finish(&dawn_desc), descriptor->label());

  return command_buffer;
}

}  // namespace blink

"""

```