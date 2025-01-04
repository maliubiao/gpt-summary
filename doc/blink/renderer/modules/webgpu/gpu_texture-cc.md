Response:
Let's break down the thought process for analyzing the `gpu_texture.cc` file and generating the detailed explanation.

**1. Initial Understanding of the File's Role:**

The first step is to recognize the file path: `blink/renderer/modules/webgpu/gpu_texture.cc`. This immediately tells us several things:

* **Part of the Blink Renderer:** This code is responsible for rendering web pages and handling browser functionality within the Chromium project.
* **WebGPU Module:** It's specifically related to the WebGPU API, a modern web graphics API that provides access to GPU capabilities.
* **`gpu_texture`:**  The file name strongly suggests it's about managing GPU textures. Textures are fundamental in computer graphics for storing image data used in rendering.

**2. Analyzing the `#include` Directives:**

The included headers provide crucial clues about the file's dependencies and responsibilities:

* **`gpu/command_buffer/client/webgpu_interface.h`:**  Indicates interaction with the low-level GPU command buffer. This file likely deals with sending commands to the actual GPU.
* **`third_party/blink/renderer/bindings/modules/v8/v8_gpu_texture_descriptor.h` and `v8_gpu_texture_view_descriptor.h`:**  Highlights the connection to JavaScript. These headers define how JavaScript objects representing texture descriptors and view descriptors are mapped to C++ structures. The `V8` in the path confirms this interaction with the V8 JavaScript engine.
* **`third_party/blink/renderer/core/html/canvas/canvas_rendering_context.h` and `html_canvas_element.h`:** Suggests integration with the HTML `<canvas>` element, a common way to draw graphics on web pages. This is a key point for understanding the relationship with HTML.
* **`third_party/blink/renderer/modules/webgpu/*`:**  Shows dependencies on other WebGPU-related modules within Blink, such as `dawn_conversions.h` (likely for converting between Blink's internal representation and the Dawn implementation of WebGPU), `gpu_device.h`, `gpu_texture_usage.h`, and `gpu_texture_view.h`.
* **`third_party/blink/renderer/platform/graphics/*`:**  Indicates interaction with platform-specific graphics abstractions, including `AcceleratedStaticBitmapImage.h`, `CanvasResourceProvider.h`, `gpu/SharedGpuContext.h`, `gpu/WebgpuMailboxTexture.h`, and `gpu/WebgpuResourceProviderCache.h`. The `MailboxTexture` is particularly interesting, hinting at a mechanism for sharing textures between processes or contexts.

**3. Examining the `namespace blink { namespace { ... } }` Structure:**

The anonymous namespace `namespace { ... }` contains helper functions that are internal to this file. This helps organize the code and prevents naming conflicts. The functions `ConvertToDawn`, `AsDawnType`, and `ValidateTextureMipLevelAndArrayLayerCounts` are good candidates for deeper inspection.

**4. Deconstructing Key Functions:**

* **`ConvertToDawn`:** This function is clearly responsible for converting a `GPUTextureDescriptor` (likely a Blink representation of a texture description coming from JavaScript) into a `wgpu::TextureDescriptor` (the Dawn representation). The presence of `wgpu::TextureBindingViewDimensionDescriptor` suggests it handles specific aspects of how the texture can be viewed. The involvement of `GPUDevice` and `ExceptionState` hints at error handling and interaction with the GPU device.
* **`AsDawnType`:**  Similar to `ConvertToDawn`, but for `GPUTextureViewDescriptor`. It converts the Blink representation of a texture view descriptor into its Dawn counterpart.
* **`ValidateTextureMipLevelAndArrayLayerCounts`:** This function performs validation on texture view descriptors, specifically checking for invalid values for mip level and array layer counts. The error message construction is important for understanding how errors are reported.

**5. Analyzing the `GPUTexture` Class:**

This is the core class of the file. Key aspects to note:

* **Creation Methods (`Create`):** Multiple `Create` methods suggest different ways to instantiate a `GPUTexture` object. One takes a `GPUTextureDescriptor`, likely for creating new textures. Another takes a `wgpu::TextureDescriptor`, perhaps for internal use or wrapping existing Dawn textures. The `CreateError` method is for creating placeholder textures when an error occurs.
* **Constructor:** The constructors initialize the `GPUTexture` with its Dawn handle, device, and other properties like dimension, format, and usage. The constructor handling `WebGPUMailboxTexture` indicates support for shared textures.
* **`createView`:** This method is responsible for creating `GPUTextureView` objects, which represent specific ways to access a texture (e.g., a subset of mip levels or array layers).
* **`destroy`:**  Handles the proper cleanup of the texture, including releasing resources. The `destroy_callback_` suggests a mechanism for executing code just before destruction. The handling of `mailbox_texture_` is crucial for managing shared textures.
* **Getter Methods:**  Methods like `width()`, `height()`, `mipLevelCount()`, `format()`, and `usage()` provide access to the texture's properties.
* **`DissociateMailbox` and `GetMailboxTexture`:**  These methods are specifically for managing shared textures via the mailbox mechanism.

**6. Connecting to JavaScript, HTML, and CSS:**

At this stage, we can start drawing connections:

* **JavaScript:** The presence of `V8GPUTextureDescriptor` and `V8GPUTextureViewDescriptor` strongly indicates that JavaScript code using the WebGPU API will interact with this C++ code. JavaScript calls to `device.createTexture()` or `texture.createView()` will eventually lead to the execution of the `Create` and `createView` methods in this file.
* **HTML:** The inclusion of `html_canvas_element.h` suggests that WebGPU textures can be associated with `<canvas>` elements. This is a common use case where the canvas is used as a drawing surface for WebGPU rendering.
* **CSS:** While CSS doesn't directly interact with `gpu_texture.cc`, it can indirectly influence it. For example, CSS might control the size or visibility of a `<canvas>` element that is being used for WebGPU rendering.

**7. Identifying Potential User/Programming Errors:**

By examining the validation logic and the API design, we can identify common errors:

* **Invalid `GPUTextureDescriptor`:** Providing incorrect values for texture dimensions, format, usage, etc., in the JavaScript `createTexture()` call.
* **Invalid `GPUTextureViewDescriptor`:**  Supplying out-of-bounds mip level or array layer ranges in `texture.createView()`. The validation function explicitly checks for this.
* **Using a destroyed texture:**  Attempting to use a texture after its `destroy()` method has been called.
* **Incorrect texture usage:**  Trying to use a texture in a way that's not allowed by its `usage` flags (e.g., trying to read from a texture that was only created for writing).

**8. Constructing Debugging Scenarios:**

To understand how a user might end up in this code, we can trace a typical WebGPU workflow:

1. User opens a web page with WebGPU content.
2. JavaScript code on the page obtains a `GPUDevice`.
3. The JavaScript calls `device.createTexture(descriptor)` with a `GPUTextureDescriptor`. This call is handled by the `GPUTexture::Create` method in `gpu_texture.cc`.
4. Later, the JavaScript might call `texture.createView(descriptor)` to create a view of the texture. This is handled by the `GPUTexture::createView` method.
5. If there's an error in the descriptors, the validation logic in `gpu_texture.cc` might be triggered, and an error would be reported.

**9. Refining and Organizing the Explanation:**

Finally, the information gathered from the preceding steps is organized into a clear and structured explanation, covering the file's functionality, relationships with web technologies, logic, potential errors, and debugging scenarios. This involves grouping related points together and providing illustrative examples.
好的，让我们来分析一下 `blink/renderer/modules/webgpu/gpu_texture.cc` 这个文件。

**文件功能概述:**

`gpu_texture.cc` 文件是 Chromium Blink 引擎中负责实现 WebGPU `GPUTexture` 接口的关键部分。它的主要功能是：

1. **创建和管理 GPU 纹理对象:**  它提供了 `GPUTexture` 类的实现，该类封装了对底层 GPU 纹理资源的访问和操作。
2. **处理纹理描述符:**  它负责接收来自 JavaScript 的 `GPUTextureDescriptor` 对象，并将其转换为底层 Dawn 库（WebGPU 的一个实现）所需的格式。
3. **创建纹理视图:**  它实现了 `createView` 方法，允许创建 `GPUTextureView` 对象，用于访问纹理的特定部分或格式。
4. **处理纹理销毁:**  它负责在 `GPUTexture` 对象被垃圾回收时销毁底层的 GPU 纹理资源。
5. **与底层 GPU API 交互:**  它使用 `gpu::command_buffer::client::webgpu_interface::WebGPUInterface` 与 GPU 驱动进行通信，创建和管理纹理。
6. **处理 Mailbox 纹理:**  它支持 Mailbox 纹理，这是一种用于在不同上下文或进程之间共享 GPU 纹理的机制。
7. **进行参数验证:**  它包含一些用于验证输入参数（如纹理描述符）的逻辑，以确保其符合 WebGPU 规范。
8. **错误处理:**  当创建或操作纹理时发生错误，它可以创建“错误纹理”对象。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件是 WebGPU API 在 Blink 渲染引擎中的核心实现，因此与 JavaScript 和 HTML 有着直接的关系，而与 CSS 的关系较为间接。

* **JavaScript:**
    * **接口实现:** `GPUTexture` 类直接对应了 JavaScript 中的 `GPUTexture` 接口。当 JavaScript 代码调用 `device.createTexture(descriptor)` 时，Blink 会创建一个 `GPUTexture` 对象，而 `gpu_texture.cc` 中的 `GPUTexture::Create` 方法会被调用。
    ```javascript
    const device = await navigator.gpu.requestAdapter().then(adapter => adapter.requestDevice());
    const texture = device.createTexture({
      size: [256, 256, 1],
      format: 'rgba8unorm',
      usage: GPUTextureUsage.RENDER_ATTACHMENT | GPUTextureUsage.COPY_SRC,
    });
    ```
    在这个例子中，`device.createTexture()` 的调用会触发 `gpu_texture.cc` 中创建 `GPUTexture` 对象的逻辑，并根据传入的 `descriptor` 创建底层的 GPU 纹理。
    * **纹理视图创建:** 当 JavaScript 代码调用 `texture.createView(descriptor)` 时，`gpu_texture.cc` 中的 `GPUTexture::createView` 方法会被调用，创建一个 `GPUTextureView` 对象。
    ```javascript
    const textureView = texture.createView({
      format: 'rgba8unorm',
      dimension: '2d',
      // ...其他视图属性
    });
    ```
    这个调用会将 JavaScript 的 `descriptor` 转换为 Dawn 的格式，并创建相应的纹理视图。

* **HTML:**
    * **`<canvas>` 元素:** WebGPU 通常与 HTML 的 `<canvas>` 元素一起使用。可以将 WebGPU 渲染到 `<canvas>` 上。`gpu_texture.cc` 中包含了对 `HTMLCanvasElement` 的引用，这表明 `GPUTexture` 可以与 `<canvas>` 元素关联，例如作为渲染目标。
    ```html
    <canvas id="gpuCanvas" width="512" height="512"></canvas>
    <script>
      const canvas = document.getElementById('gpuCanvas');
      const context = canvas.getContext('webgpu');
      const canvasFormat = navigator.gpu.getPreferredCanvasFormat();
      context.configure({
        device: gpuDevice,
        format: canvasFormat,
      });
      // ...创建纹理并渲染到 context.getCurrentTexture().createView()
    </script>
    ```
    在上面的例子中，`context.getCurrentTexture()` 返回的 `GPUTexture` 对象就是由 `gpu_texture.cc` 管理的。

* **CSS:**
    * **间接影响:** CSS 可以影响 `<canvas>` 元素的大小和布局，从而间接地影响到 WebGPU 纹理的使用。例如，如果 CSS 调整了 `<canvas>` 的大小，那么后续创建的与该 `<canvas>` 关联的 WebGPU 纹理可能需要适应新的尺寸。但是，CSS 不会直接操作 `GPUTexture` 对象或调用其方法。

**逻辑推理、假设输入与输出:**

假设 JavaScript 代码调用 `device.createTexture` 并传入以下 `GPUTextureDescriptor`:

**假设输入 (JavaScript `GPUTextureDescriptor`):**

```javascript
{
  size: [100, 200, 1],
  format: 'rgba8unorm',
  usage: GPUTextureUsage.RENDER_ATTACHMENT | GPUTextureUsage.SAMPLED,
  mipLevelCount: 5,
  sampleCount: 1,
  dimension: '2d',
  label: 'myTexture'
}
```

**`gpu_texture.cc` 中的逻辑推理和处理:**

1. **`GPUTexture::Create` 调用:**  当 Blink 接收到这个 JavaScript 调用时，会调用 `gpu_texture.cc` 中的 `GPUTexture::Create` 方法，并将 JavaScript 的 `GPUTextureDescriptor` 对象 `webgpu_desc` 作为参数传入。
2. **`ConvertToDawn` 转换:**  `ConvertToDawn` 函数会将 `webgpu_desc` 中的信息提取出来，并填充到 Dawn 的 `wgpu::TextureDescriptor` 结构体 `dawn_desc` 中。例如：
    * `dawn_desc.size` 将被设置为 `{ width: 100, height: 200, depthOrArrayLayers: 1 }`。
    * `dawn_desc.format` 将被设置为 `wgpu::TextureFormat::RGBA8Unorm`。
    * `dawn_desc.usage` 将被设置为 `wgpu::TextureUsage::RenderAttachment | wgpu::TextureUsage::Sampled`。
    * `dawn_desc.mipLevelCount` 将被设置为 `5`。
    * `dawn_desc.sampleCount` 将被设置为 `1`。
    * `dawn_desc.dimension` 将被设置为 `wgpu::TextureDimension::e2D`。
    * `dawn_desc.label` 将被设置为 "myTexture"。
3. **设备验证:**  `device->ValidateTextureFormatUsage` 会被调用，以确保 `rgba8unorm` 格式可以用于指定的 `usage`。
4. **Dawn 纹理创建:**  `device->GetHandle().CreateTexture(&dawn_desc)` 会被调用，实际在底层 Dawn 库中创建一个 GPU 纹理对象。
5. **`GPUTexture` 对象创建:**  创建一个新的 `GPUTexture` 对象，并将从 Dawn 获取的纹理句柄存储起来。
6. **返回:**  `GPUTexture` 对象会被返回给 JavaScript。

**假设输出 (C++ `wgpu::TextureDescriptor`):**

```cpp
wgpu::TextureDescriptor dawn_desc = {
  .label = "myTexture",
  .usage = wgpu::TextureUsage::RenderAttachment | wgpu::TextureUsage::Sampled,
  .dimension = wgpu::TextureDimension::e2D,
  .format = wgpu::TextureFormat::RGBA8Unorm,
  .size = { .width = 100, .height = 200, .depthOrArrayLayers = 1 },
  .mipLevelCount = 5,
  .sampleCount = 1,
  .viewFormatCount = 0,
  .viewFormats = nullptr,
  .nextInChain = nullptr
};
```

**用户或编程常见的使用错误举例说明:**

1. **纹理格式与用途不匹配:** 用户可能创建了一个纹理，其格式不支持所需的用途。例如，创建一个 `R8Unorm` 格式的纹理，并尝试将其用作颜色附件进行渲染。`GPUTexture::Create` 方法内部的 `device->ValidateTextureFormatUsage` 会检测到这种错误，并可能导致纹理创建失败。
    ```javascript
    const texture = device.createTexture({
      size: [100, 100],
      format: 'r8unorm', // 仅红色通道
      usage: GPUTextureUsage.RENDER_ATTACHMENT // 尝试作为颜色附件
    });
    // 这可能会导致错误，因为 R8Unorm 通常不作为颜色附件的最佳选择
    ```

2. **创建超出设备限制的纹理:** 用户可能尝试创建一个尺寸过大或者 mip 级别过多的纹理，超出 GPU 的硬件限制。虽然 `gpu_texture.cc` 本身可能不直接处理所有硬件限制，但底层的 Dawn 库或 GPU 驱动会进行检查，并可能导致纹理创建失败。

3. **在纹理销毁后使用:** 用户可能在调用 `texture.destroy()` 后仍然尝试使用该纹理或其视图。`GPUTexture::destroy` 方法会释放底层的 GPU 资源，再次使用会导致错误。

4. **创建无效的纹理视图:**  用户可能创建了一个超出纹理范围的纹理视图，例如 `baseMipLevel` 或 `baseArrayLayer` 超出范围，或者 `mipLevelCount` 或 `arrayLayerCount` 导致越界。`GPUTexture::createView` 中的 `ValidateTextureMipLevelAndArrayLayerCounts` 函数会进行一些验证，但更底层的 Dawn 库也会进行更严格的检查。
    ```javascript
    const textureView = texture.createView({
      baseMipLevel: 10, // 如果纹理只有 5 个 mip 级别，这将是无效的
    });
    ```

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户遇到了一个 WebGPU 应用中纹理创建失败的问题，可以按照以下步骤进行调试，可能会涉及到 `gpu_texture.cc`：

1. **用户打开网页或运行 WebGPU 应用。**
2. **JavaScript 代码尝试获取 `GPUAdapter` 和 `GPUDevice`。** 如果失败，则问题可能在更早的阶段。
3. **JavaScript 代码调用 `device.createTexture(descriptor)`。**
4. **Blink 引擎接收到这个调用，并开始执行 `gpu_texture.cc` 中的 `GPUTexture::Create` 方法。**
5. **在 `GPUTexture::Create` 中:**
    * **`ConvertToDawn` 被调用，尝试将 JavaScript 的描述符转换为 Dawn 的格式。**  如果转换过程中发现类型不匹配或值超出范围，可能会在这里抛出异常或记录错误。
    * **`device->ValidateTextureFormatUsage` 被调用，验证纹理格式是否支持指定的用途。** 如果验证失败，会记录错误。
    * **`device->GetHandle().CreateTexture(&dawn_desc)` 被调用，尝试在底层 Dawn 库中创建纹理。**  如果底层 Dawn 库或 GPU 驱动返回错误（例如，内存不足，格式不支持，尺寸过大），这个调用会失败。
6. **如果 `CreateTexture` 返回 nullptr，则说明纹理创建失败。**  JavaScript 中 `device.createTexture` 的 Promise 将会被 reject。
7. **开发者可以通过浏览器的开发者工具查看控制台的错误信息。**  Chromium 的 WebGPU 实现会将错误信息传递到控制台。
8. **开发者可以设置断点在 `gpu_texture.cc` 的 `GPUTexture::Create` 方法中，查看传入的 `webgpu_desc` 和转换后的 `dawn_desc`，以及 `device->ValidateTextureFormatUsage` 的返回值，来定位问题所在。**
9. **如果涉及到 Mailbox 纹理，可以关注 `GPUTexture` 的构造函数中对 `WebGPUMailboxTexture` 的处理，以及 `DissociateMailbox` 和 `GetMailboxTexture` 方法。**

总而言之，`gpu_texture.cc` 是 WebGPU 纹理功能在 Chromium Blink 引擎中的核心实现，负责与 JavaScript 交互，管理纹理的生命周期，并与底层的 GPU 驱动进行通信。 理解这个文件的功能对于调试 WebGPU 相关的渲染问题至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/webgpu/gpu_texture.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webgpu/gpu_texture.h"

#include "base/containers/heap_array.h"
#include "gpu/command_buffer/client/webgpu_interface.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_texture_descriptor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_texture_view_descriptor.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_rendering_context.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/modules/webgpu/dawn_conversions.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_device.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_texture_usage.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_texture_view.h"
#include "third_party/blink/renderer/platform/graphics/accelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource_provider.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/gpu/webgpu_mailbox_texture.h"
#include "third_party/blink/renderer/platform/graphics/gpu/webgpu_resource_provider_cache.h"

namespace blink {

namespace {

bool ConvertToDawn(const GPUTextureDescriptor* in,
                   wgpu::TextureDescriptor* out,
                   wgpu::TextureBindingViewDimensionDescriptor*
                       out_texture_binding_view_dimension,
                   std::string* label,
                   base::HeapArray<wgpu::TextureFormat>* view_formats,
                   GPUDevice* device,
                   ExceptionState& exception_state) {
  DCHECK(in);
  DCHECK(out);
  DCHECK(out_texture_binding_view_dimension);
  DCHECK(label);
  DCHECK(view_formats);
  DCHECK(device);

  *out = {};
  out->usage = static_cast<wgpu::TextureUsage>(in->usage());
  out->dimension = AsDawnEnum(in->dimension());
  out->format = AsDawnEnum(in->format());
  out->mipLevelCount = in->mipLevelCount();
  out->sampleCount = in->sampleCount();

  if (in->hasTextureBindingViewDimension()) {
    wgpu::TextureViewDimension texture_binding_view_dimension =
        AsDawnEnum(in->textureBindingViewDimension());
    if (texture_binding_view_dimension !=
        wgpu::TextureViewDimension::Undefined) {
      *out_texture_binding_view_dimension = {};
      out_texture_binding_view_dimension->textureBindingViewDimension =
          texture_binding_view_dimension;
      out->nextInChain = out_texture_binding_view_dimension;
    }
  }

  *label = in->label().Utf8();
  if (!label->empty()) {
    out->label = label->c_str();
  }

  *view_formats = AsDawnEnum<wgpu::TextureFormat>(in->viewFormats());
  out->viewFormatCount = in->viewFormats().size();
  out->viewFormats = view_formats->data();

  return ConvertToDawn(in->size(), &out->size, device, exception_state);
}

wgpu::TextureViewDescriptor AsDawnType(
    const GPUTextureViewDescriptor* webgpu_desc,
    std::string* label) {
  DCHECK(webgpu_desc);
  DCHECK(label);

  wgpu::TextureViewDescriptor dawn_desc = {};
  if (webgpu_desc->hasFormat()) {
    dawn_desc.format = AsDawnEnum(webgpu_desc->format());
  }
  if (webgpu_desc->hasDimension()) {
    dawn_desc.dimension = AsDawnEnum(webgpu_desc->dimension());
  }
  dawn_desc.baseMipLevel = webgpu_desc->baseMipLevel();
  if (webgpu_desc->hasMipLevelCount()) {
    dawn_desc.mipLevelCount = webgpu_desc->mipLevelCount();
  }
  dawn_desc.baseArrayLayer = webgpu_desc->baseArrayLayer();
  if (webgpu_desc->hasArrayLayerCount()) {
    dawn_desc.arrayLayerCount = webgpu_desc->arrayLayerCount();
  }
  dawn_desc.aspect = AsDawnEnum(webgpu_desc->aspect());
  *label = webgpu_desc->label().Utf8();
  if (!label->empty()) {
    dawn_desc.label = label->c_str();
  }
  if (webgpu_desc->hasUsage()) {
    dawn_desc.usage = static_cast<wgpu::TextureUsage>(webgpu_desc->usage());
  }

  return dawn_desc;
}

// Dawn represents `undefined` as the special uint32_t value (0xFFFF'FFFF).
// Blink must make sure that an actual value of 0xFFFF'FFFF coming in from JS
// is not treated as the special `undefined` value, so it injects an error in
// that case.
std::string ValidateTextureMipLevelAndArrayLayerCounts(
    const GPUTextureViewDescriptor* webgpu_desc) {
  DCHECK(webgpu_desc);

  if (webgpu_desc->hasMipLevelCount() &&
      webgpu_desc->mipLevelCount() == wgpu::kMipLevelCountUndefined) {
    std::ostringstream error;
    error << "mipLevelCount (" << webgpu_desc->mipLevelCount()
          << ") is too large when validating [GPUTextureViewDescriptor";
    if (!webgpu_desc->label().empty()) {
      error << " '" << webgpu_desc->label().Utf8() << "'";
    }
    error << "].";
    return error.str();
  }

  if (webgpu_desc->hasArrayLayerCount() &&
      webgpu_desc->arrayLayerCount() == wgpu::kArrayLayerCountUndefined) {
    std::ostringstream error;
    error << "arrayLayerCount (" << webgpu_desc->arrayLayerCount()
          << ") is too large when validating [GPUTextureViewDescriptor";
    if (!webgpu_desc->label().empty()) {
      error << " '" << webgpu_desc->label().Utf8() << "'";
    }
    error << "].";
    return error.str();
  }

  return std::string();
}

}  // anonymous namespace

// static
GPUTexture* GPUTexture::Create(GPUDevice* device,
                               const GPUTextureDescriptor* webgpu_desc,
                               ExceptionState& exception_state) {
  DCHECK(device);
  DCHECK(webgpu_desc);

  wgpu::TextureDescriptor dawn_desc;
  wgpu::TextureBindingViewDimensionDescriptor
      texture_binding_view_dimension_desc;

  std::string label;
  base::HeapArray<wgpu::TextureFormat> view_formats;
  if (!ConvertToDawn(webgpu_desc, &dawn_desc,
                     &texture_binding_view_dimension_desc, &label,
                     &view_formats, device, exception_state)) {
    return nullptr;
  }

  if (!device->ValidateTextureFormatUsage(webgpu_desc->format(),
                                          exception_state)) {
    return nullptr;
  }

  for (auto view_format : webgpu_desc->viewFormats()) {
    if (!device->ValidateTextureFormatUsage(view_format, exception_state)) {
      return nullptr;
    }
  }

  GPUTexture* texture = MakeGarbageCollected<GPUTexture>(
      device, device->GetHandle().CreateTexture(&dawn_desc),
      webgpu_desc->label());
  return texture;
}

GPUTexture* GPUTexture::Create(GPUDevice* device,
                               const wgpu::TextureDescriptor* desc) {
  DCHECK(device);
  DCHECK(desc);

  return MakeGarbageCollected<GPUTexture>(
      device, device->GetHandle().CreateTexture(desc),
      String::FromUTF8(desc->label));
}

// static
GPUTexture* GPUTexture::CreateError(GPUDevice* device,
                                    const wgpu::TextureDescriptor* desc) {
  DCHECK(device);
  DCHECK(desc);
  return MakeGarbageCollected<GPUTexture>(
      device, device->GetHandle().CreateErrorTexture(desc),
      String::FromUTF8(desc->label));
}

GPUTexture::GPUTexture(GPUDevice* device,
                       wgpu::Texture texture,
                       const String& label)
    : DawnObject<wgpu::Texture>(device, std::move(texture), label),
      dimension_(GetHandle().GetDimension()),
      format_(GetHandle().GetFormat()),
      usage_(GetHandle().GetUsage()) {}

GPUTexture::GPUTexture(GPUDevice* device,
                       wgpu::TextureFormat format,
                       wgpu::TextureUsage usage,
                       scoped_refptr<WebGPUMailboxTexture> mailbox_texture,
                       const String& label)
    : DawnObject<wgpu::Texture>(device, mailbox_texture->GetTexture(), label),
      format_(format),
      usage_(usage),
      mailbox_texture_(std::move(mailbox_texture)) {
  if (mailbox_texture_) {
    device_->TrackTextureWithMailbox(this);
  }

  // Mailbox textures are all 2d texture.
  dimension_ = wgpu::TextureDimension::e2D;
}

GPUTextureView* GPUTexture::createView(
    const GPUTextureViewDescriptor* webgpu_desc,
    ExceptionState& exception_state) {
  DCHECK(webgpu_desc);

  if (webgpu_desc->hasFormat() && !device()->ValidateTextureFormatUsage(
                                      webgpu_desc->format(), exception_state)) {
    return nullptr;
  }

  std::string error = ValidateTextureMipLevelAndArrayLayerCounts(webgpu_desc);
  if (!error.empty()) {
    device()->InjectError(wgpu::ErrorType::Validation, error.c_str());
    return MakeGarbageCollected<GPUTextureView>(
        device(), GetHandle().CreateErrorView(nullptr), String());
  }

  std::string label;
  wgpu::TextureViewDescriptor dawn_desc = AsDawnType(webgpu_desc, &label);
  GPUTextureView* view = MakeGarbageCollected<GPUTextureView>(
      device_, GetHandle().CreateView(&dawn_desc), webgpu_desc->label());
  return view;
}

GPUTexture::~GPUTexture() {
  DissociateMailbox();
}

void GPUTexture::destroy() {
  if (destroyed_) {
    return;
  }

  if (destroy_callback_) {
    std::move(destroy_callback_).Run();
  }

  if (mailbox_texture_) {
    DissociateMailbox();
    device_->UntrackTextureWithMailbox(this);
  }
  GetHandle().Destroy();
  destroyed_ = true;
}

uint32_t GPUTexture::width() const {
  return GetHandle().GetWidth();
}

uint32_t GPUTexture::height() const {
  return GetHandle().GetHeight();
}

uint32_t GPUTexture::depthOrArrayLayers() const {
  return GetHandle().GetDepthOrArrayLayers();
}

uint32_t GPUTexture::mipLevelCount() const {
  return GetHandle().GetMipLevelCount();
}

uint32_t GPUTexture::sampleCount() const {
  return GetHandle().GetSampleCount();
}

V8GPUTextureDimension GPUTexture::dimension() const {
  return FromDawnEnum(GetHandle().GetDimension());
}

V8GPUTextureFormat GPUTexture::format() const {
  return FromDawnEnum(GetHandle().GetFormat());
}

uint32_t GPUTexture::usage() const {
  return static_cast<uint32_t>(GetHandle().GetUsage());
}

void GPUTexture::DissociateMailbox() {
  if (mailbox_texture_) {
    mailbox_texture_->Dissociate();
    mailbox_texture_ = nullptr;
  }
}

scoped_refptr<WebGPUMailboxTexture> GPUTexture::GetMailboxTexture() {
  return mailbox_texture_;
}

void GPUTexture::SetBeforeDestroyCallback(base::OnceClosure callback) {
  destroy_callback_ = std::move(callback);
}

void GPUTexture::ClearBeforeDestroyCallback() {
  destroy_callback_.Reset();
}

}  // namespace blink

"""

```