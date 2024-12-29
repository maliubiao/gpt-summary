Response:
The user wants to understand the functionality of the provided C++ code file.
The file is named `dawn_enum_conversions.cc` and is part of the Chromium Blink engine, specifically within the `webgpu` module.

Based on the name and the included headers, it's highly likely that this file is responsible for converting enum values between the WebGPU API (as exposed in JavaScript) and the underlying Dawn graphics library.

Here's a breakdown of the plan:
1. **Identify the core functionality:**  The file contains functions for converting enum types between `V8GPU...` (representing the JavaScript/WebGPU side) and `wgpu::...` (representing the Dawn/native side).
2. **Explain the relationship to web technologies:** WebGPU is a JavaScript API for accessing GPU capabilities. This file bridges the gap between the JavaScript API and the native graphics implementation.
3. **Provide examples:**  Demonstrate how these conversions might be used in a WebGPU context.
4. **Illustrate logical reasoning:** Show a simple conversion scenario with input and output.
5. **Highlight potential user errors:** Explain common mistakes when working with WebGPU enums.
6. **Describe the user journey:** Outline the steps a user might take in a web application that would eventually lead to the execution of this code.
7. **Summarize the functionality for part 1.**
```
该文件 `dawn_enum_conversions.cc` 的主要功能是在 Chromium Blink 引擎的 WebGPU 模块中，实现 **WebGPU JavaScript API 中定义的枚举类型 (例如 `GPUTextureFormat`, `GPUCompareFunction` 等) 与 Dawn 图形库中对应的枚举类型 (`wgpu::TextureFormat`, `wgpu::CompareFunction` 等) 之间的相互转换**。

**与 JavaScript, HTML, CSS 的关系以及举例说明:**

WebGPU 是一个 JavaScript API，允许 Web 开发者利用 GPU 的强大计算能力进行图形渲染和通用计算。这个文件是 WebGPU 在浏览器内部实现的一部分，负责将 JavaScript 中对 WebGPU API 的调用转换为底层的图形库操作。

* **JavaScript:**  Web 开发者在 JavaScript 代码中使用 WebGPU API 时会涉及到各种枚举类型来配置 GPU 的行为。例如，在创建纹理时，需要指定纹理的格式 (`GPUTextureFormat`)：

   ```javascript
   const texture = device.createTexture({
     size: [256, 256, 1],
     format: 'rgba8unorm', // 这里使用了 GPUTextureFormat 的一个枚举值
     usage: GPUTextureUsage.RENDER_ATTACHMENT | GPUTextureUsage.TEXTURE_BINDING
   });
   ```
   `dawn_enum_conversions.cc` 中的代码会将 JavaScript 中的字符串 `'rgba8unorm'` 转换为 Dawn 库中对应的 `wgpu::TextureFormat::RGBA8Unorm` 枚举值，以便 Dawn 能够理解和执行创建纹理的操作。

* **HTML:**  HTML 负责网页的结构，虽然不直接涉及枚举转换，但 WebGPU 的使用场景通常是在 `<canvas>` 元素上进行渲染。JavaScript 代码会获取 `<canvas>` 元素并创建 WebGPU 上下文。

* **CSS:** CSS 负责网页的样式，与这里的枚举转换没有直接关系。但是，WebGPU 渲染的结果最终会显示在网页上，CSS 可以用于控制包含 `<canvas>` 元素的布局和样式。

**逻辑推理与假设输入输出:**

假设一个 JavaScript WebGPU 应用想要创建一个使用无符号归一化 RGBA8 格式的纹理。

* **假设输入 (JavaScript):**  字符串 `'rgba8unorm'` (对应 `V8GPUTextureFormat::Enum::kRgba8Unorm`)
* **逻辑推理 (C++ 代码):** `AsDawnEnum` 函数会接收这个 `V8GPUTextureFormat` 枚举值，并在 `switch` 语句中找到匹配的 `case`。
* **输出 (Dawn):** `wgpu::TextureFormat::RGBA8Unorm`

反过来，如果 Dawn 库返回一个 `wgpu::QueryType::Timestamp` 枚举值。

* **假设输入 (Dawn):** `wgpu::QueryType::Timestamp`
* **逻辑推理 (C++ 代码):** `FromDawnEnum` 函数会接收这个 `wgpu::QueryType` 枚举值，并在 `switch` 语句中找到匹配的 `case`。
* **输出 (JavaScript):**  `V8GPUQueryType` 对象，其内部枚举值为 `V8GPUQueryType::Enum::kTimestamp`。 这会被转换回 JavaScript 中可用的 `'timestamp'` 字符串。

**用户或编程常见的使用错误:**

用户在使用 WebGPU API 时，可能会传递错误的枚举值字符串。例如，在指定纹理格式时，输入了一个 Dawn 库支持但 WebGPU API 未暴露的格式名称，或者只是一个拼写错误的字符串。

* **举例说明:**
   ```javascript
   const texture = device.createTexture({
     size: [256, 256, 1],
     format: 'rgba8unormm', // 注意这里多了一个 'm'，是一个错误的格式名
     usage: GPUTextureUsage.RENDER_ATTACHMENT | GPUTextureUsage.TEXTURE_BINDING
   });
   ```
   在这种情况下，Blink 引擎在尝试将 JavaScript 的字符串 `'rgba8unormm'` 转换为 `V8GPUTextureFormat` 枚举时会失败。这通常会导致 JavaScript 抛出一个错误，指示传递了无效的枚举值。浏览器会在控制台中打印相关的错误信息，帮助开发者识别问题。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户编写 JavaScript 代码:** 开发者编写使用 WebGPU API 的 JavaScript 代码，例如创建纹理、缓冲区、渲染管线等，并在配置对象中指定各种枚举值。
2. **JavaScript 调用 WebGPU API:** 当 JavaScript 代码执行到 WebGPU API 调用时，例如 `device.createTexture({...})`。
3. **Blink 引擎接收 API 调用:** Chromium 的 Blink 渲染引擎接收到这个 JavaScript API 调用。
4. **参数转换:** Blink 引擎需要将 JavaScript 传递的参数转换为底层的 C++ 对象。对于枚举类型的参数，会调用 `dawn_enum_conversions.cc` 中定义的 `AsDawnEnum` 函数进行转换。
5. **Dawn 库调用:** 转换后的 Dawn 枚举值会被传递给 Dawn 图形库，Dawn 库会根据这些枚举值执行实际的 GPU 操作。
6. **Dawn 库返回结果 (可能需要转换):** 如果 Dawn 库返回包含枚举类型的结果，例如查询的结果类型，Blink 引擎会调用 `FromDawnEnum` 函数将其转换回 JavaScript 可以理解的枚举值。
7. **JavaScript 接收结果:** 最终，JavaScript 代码会接收到 WebGPU API 调用的结果。

如果在调试过程中发现 WebGPU 的行为与预期的枚举值不符，或者在控制台中看到与枚举值转换相关的错误信息，那么 `dawn_enum_conversions.cc` 就是一个需要关注的调试点。开发者可以检查这个文件中的转换逻辑，确认 JavaScript 传递的枚举值是否被正确地转换为 Dawn 库可以理解的值。

**功能归纳 (第 1 部分):**

`dawn_enum_conversions.cc` 文件的主要功能是提供了一组 C++ 函数，用于在 Chromium Blink 引擎中将 WebGPU JavaScript API 定义的各种枚举类型转换为 Dawn 图形库中对应的枚举类型，以及反向转换。这 обеспечивается WebGPU 功能在浏览器中的正确实现，使得 JavaScript 代码可以控制底层的图形操作。
```
Prompt: 
```
这是目录为blink/renderer/modules/webgpu/dawn_enum_conversions.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webgpu/dawn_enum_conversions.h"

#include "base/notreached.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_address_mode.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_blend_factor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_blend_operation.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_buffer_binding_type.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_buffer_map_state.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_compare_function.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_cull_mode.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_error_filter.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_feature_name.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_filter_mode.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_front_face.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_index_format.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_load_op.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_mipmap_filter_mode.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_primitive_topology.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_query_type.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_sampler_binding_type.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_stencil_operation.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_storage_texture_access.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_store_op.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_texture_aspect.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_texture_dimension.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_texture_format.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_texture_sample_type.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_texture_view_dimension.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_vertex_format.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_vertex_step_mode.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_wgsl_feature_name.h"
#include "third_party/blink/renderer/platform/graphics/graphics_types.h"

namespace blink {

wgpu::BufferBindingType AsDawnEnum(const V8GPUBufferBindingType& webgpu_enum) {
  switch (webgpu_enum.AsEnum()) {
    case V8GPUBufferBindingType::Enum::kUniform:
      return wgpu::BufferBindingType::Uniform;
    case V8GPUBufferBindingType::Enum::kStorage:
      return wgpu::BufferBindingType::Storage;
    case V8GPUBufferBindingType::Enum::kReadOnlyStorage:
      return wgpu::BufferBindingType::ReadOnlyStorage;
  }
}

wgpu::SamplerBindingType AsDawnEnum(
    const V8GPUSamplerBindingType& webgpu_enum) {
  switch (webgpu_enum.AsEnum()) {
    case V8GPUSamplerBindingType::Enum::kFiltering:
      return wgpu::SamplerBindingType::Filtering;
    case V8GPUSamplerBindingType::Enum::kNonFiltering:
      return wgpu::SamplerBindingType::NonFiltering;
    case V8GPUSamplerBindingType::Enum::kComparison:
      return wgpu::SamplerBindingType::Comparison;
  }
}

wgpu::TextureSampleType AsDawnEnum(const V8GPUTextureSampleType& webgpu_enum) {
  switch (webgpu_enum.AsEnum()) {
    case V8GPUTextureSampleType::Enum::kFloat:
      return wgpu::TextureSampleType::Float;
    case V8GPUTextureSampleType::Enum::kUnfilterableFloat:
      return wgpu::TextureSampleType::UnfilterableFloat;
    case V8GPUTextureSampleType::Enum::kDepth:
      return wgpu::TextureSampleType::Depth;
    case V8GPUTextureSampleType::Enum::kSint:
      return wgpu::TextureSampleType::Sint;
    case V8GPUTextureSampleType::Enum::kUint:
      return wgpu::TextureSampleType::Uint;
  }
}

wgpu::StorageTextureAccess AsDawnEnum(
    const V8GPUStorageTextureAccess& webgpu_enum) {
  switch (webgpu_enum.AsEnum()) {
    case V8GPUStorageTextureAccess::Enum::kWriteOnly:
      return wgpu::StorageTextureAccess::WriteOnly;
    case V8GPUStorageTextureAccess::Enum::kReadOnly:
      return wgpu::StorageTextureAccess::ReadOnly;
    case V8GPUStorageTextureAccess::Enum::kReadWrite:
      return wgpu::StorageTextureAccess::ReadWrite;
  }
}

wgpu::CompareFunction AsDawnEnum(const V8GPUCompareFunction& webgpu_enum) {
  switch (webgpu_enum.AsEnum()) {
    case V8GPUCompareFunction::Enum::kNever:
      return wgpu::CompareFunction::Never;
    case V8GPUCompareFunction::Enum::kLess:
      return wgpu::CompareFunction::Less;
    case V8GPUCompareFunction::Enum::kEqual:
      return wgpu::CompareFunction::Equal;
    case V8GPUCompareFunction::Enum::kLessEqual:
      return wgpu::CompareFunction::LessEqual;
    case V8GPUCompareFunction::Enum::kGreater:
      return wgpu::CompareFunction::Greater;
    case V8GPUCompareFunction::Enum::kNotEqual:
      return wgpu::CompareFunction::NotEqual;
    case V8GPUCompareFunction::Enum::kGreaterEqual:
      return wgpu::CompareFunction::GreaterEqual;
    case V8GPUCompareFunction::Enum::kAlways:
      return wgpu::CompareFunction::Always;
  }
}

wgpu::QueryType AsDawnEnum(const V8GPUQueryType& webgpu_enum) {
  switch (webgpu_enum.AsEnum()) {
    case V8GPUQueryType::Enum::kOcclusion:
      return wgpu::QueryType::Occlusion;
    case V8GPUQueryType::Enum::kTimestamp:
      return wgpu::QueryType::Timestamp;
  }
}

V8GPUQueryType FromDawnEnum(wgpu::QueryType dawn_enum) {
  switch (dawn_enum) {
    case wgpu::QueryType::Occlusion:
      return V8GPUQueryType(V8GPUQueryType::Enum::kOcclusion);
    case wgpu::QueryType::Timestamp:
      return V8GPUQueryType(V8GPUQueryType::Enum::kTimestamp);
  }
  NOTREACHED();
}

wgpu::TextureFormat AsDawnEnum(const V8GPUTextureFormat& webgpu_enum) {
  switch (webgpu_enum.AsEnum()) {
      // Normal 8 bit formats
    case V8GPUTextureFormat::Enum::kR8Unorm:
      return wgpu::TextureFormat::R8Unorm;
    case V8GPUTextureFormat::Enum::kR8Snorm:
      return wgpu::TextureFormat::R8Snorm;
    case V8GPUTextureFormat::Enum::kR8Uint:
      return wgpu::TextureFormat::R8Uint;
    case V8GPUTextureFormat::Enum::kR8Sint:
      return wgpu::TextureFormat::R8Sint;

      // Normal 16 bit formats
    case V8GPUTextureFormat::Enum::kR16Uint:
      return wgpu::TextureFormat::R16Uint;
    case V8GPUTextureFormat::Enum::kR16Sint:
      return wgpu::TextureFormat::R16Sint;
    case V8GPUTextureFormat::Enum::kR16Float:
      return wgpu::TextureFormat::R16Float;
    case V8GPUTextureFormat::Enum::kRg8Unorm:
      return wgpu::TextureFormat::RG8Unorm;
    case V8GPUTextureFormat::Enum::kRg8Snorm:
      return wgpu::TextureFormat::RG8Snorm;
    case V8GPUTextureFormat::Enum::kRg8Uint:
      return wgpu::TextureFormat::RG8Uint;
    case V8GPUTextureFormat::Enum::kRg8Sint:
      return wgpu::TextureFormat::RG8Sint;

      // Normal 32 bit formats
    case V8GPUTextureFormat::Enum::kR32Uint:
      return wgpu::TextureFormat::R32Uint;
    case V8GPUTextureFormat::Enum::kR32Sint:
      return wgpu::TextureFormat::R32Sint;
    case V8GPUTextureFormat::Enum::kR32Float:
      return wgpu::TextureFormat::R32Float;
    case V8GPUTextureFormat::Enum::kRg16Uint:
      return wgpu::TextureFormat::RG16Uint;
    case V8GPUTextureFormat::Enum::kRg16Sint:
      return wgpu::TextureFormat::RG16Sint;
    case V8GPUTextureFormat::Enum::kRg16Float:
      return wgpu::TextureFormat::RG16Float;
    case V8GPUTextureFormat::Enum::kRgba8Unorm:
      return wgpu::TextureFormat::RGBA8Unorm;
    case V8GPUTextureFormat::Enum::kRgba8UnormSrgb:
      return wgpu::TextureFormat::RGBA8UnormSrgb;
    case V8GPUTextureFormat::Enum::kRgba8Snorm:
      return wgpu::TextureFormat::RGBA8Snorm;
    case V8GPUTextureFormat::Enum::kRgba8Uint:
      return wgpu::TextureFormat::RGBA8Uint;
    case V8GPUTextureFormat::Enum::kRgba8Sint:
      return wgpu::TextureFormat::RGBA8Sint;
    case V8GPUTextureFormat::Enum::kBgra8Unorm:
      return wgpu::TextureFormat::BGRA8Unorm;
    case V8GPUTextureFormat::Enum::kBgra8UnormSrgb:
      return wgpu::TextureFormat::BGRA8UnormSrgb;

      // Packed 32 bit formats
    case V8GPUTextureFormat::Enum::kRgb9E5Ufloat:
      return wgpu::TextureFormat::RGB9E5Ufloat;
    case V8GPUTextureFormat::Enum::kRgb10A2Uint:
      return wgpu::TextureFormat::RGB10A2Uint;
    case V8GPUTextureFormat::Enum::kRgb10A2Unorm:
      return wgpu::TextureFormat::RGB10A2Unorm;
    case V8GPUTextureFormat::Enum::kRg11B10Ufloat:
      return wgpu::TextureFormat::RG11B10Ufloat;

      // Normal 64 bit formats
    case V8GPUTextureFormat::Enum::kRg32Uint:
      return wgpu::TextureFormat::RG32Uint;
    case V8GPUTextureFormat::Enum::kRg32Sint:
      return wgpu::TextureFormat::RG32Sint;
    case V8GPUTextureFormat::Enum::kRg32Float:
      return wgpu::TextureFormat::RG32Float;
    case V8GPUTextureFormat::Enum::kRgba16Uint:
      return wgpu::TextureFormat::RGBA16Uint;
    case V8GPUTextureFormat::Enum::kRgba16Sint:
      return wgpu::TextureFormat::RGBA16Sint;
    case V8GPUTextureFormat::Enum::kRgba16Float:
      return wgpu::TextureFormat::RGBA16Float;

      // Normal 128 bit formats
    case V8GPUTextureFormat::Enum::kRgba32Uint:
      return wgpu::TextureFormat::RGBA32Uint;
    case V8GPUTextureFormat::Enum::kRgba32Sint:
      return wgpu::TextureFormat::RGBA32Sint;
    case V8GPUTextureFormat::Enum::kRgba32Float:
      return wgpu::TextureFormat::RGBA32Float;

      // Depth / Stencil formats
    case V8GPUTextureFormat::Enum::kDepth32Float:
      return wgpu::TextureFormat::Depth32Float;
    case V8GPUTextureFormat::Enum::kDepth32FloatStencil8:
      return wgpu::TextureFormat::Depth32FloatStencil8;
    case V8GPUTextureFormat::Enum::kDepth24Plus:
      return wgpu::TextureFormat::Depth24Plus;
    case V8GPUTextureFormat::Enum::kDepth24PlusStencil8:
      return wgpu::TextureFormat::Depth24PlusStencil8;
    case V8GPUTextureFormat::Enum::kDepth16Unorm:
      return wgpu::TextureFormat::Depth16Unorm;
    case V8GPUTextureFormat::Enum::kStencil8:
      return wgpu::TextureFormat::Stencil8;

      // Block Compression (BC) formats
    case V8GPUTextureFormat::Enum::kBc1RgbaUnorm:
      return wgpu::TextureFormat::BC1RGBAUnorm;
    case V8GPUTextureFormat::Enum::kBc1RgbaUnormSrgb:
      return wgpu::TextureFormat::BC1RGBAUnormSrgb;
    case V8GPUTextureFormat::Enum::kBc2RgbaUnorm:
      return wgpu::TextureFormat::BC2RGBAUnorm;
    case V8GPUTextureFormat::Enum::kBc2RgbaUnormSrgb:
      return wgpu::TextureFormat::BC2RGBAUnormSrgb;
    case V8GPUTextureFormat::Enum::kBc3RgbaUnorm:
      return wgpu::TextureFormat::BC3RGBAUnorm;
    case V8GPUTextureFormat::Enum::kBc3RgbaUnormSrgb:
      return wgpu::TextureFormat::BC3RGBAUnormSrgb;
    case V8GPUTextureFormat::Enum::kBc4RUnorm:
      return wgpu::TextureFormat::BC4RUnorm;
    case V8GPUTextureFormat::Enum::kBc4RSnorm:
      return wgpu::TextureFormat::BC4RSnorm;
    case V8GPUTextureFormat::Enum::kBc5RgUnorm:
      return wgpu::TextureFormat::BC5RGUnorm;
    case V8GPUTextureFormat::Enum::kBc5RgSnorm:
      return wgpu::TextureFormat::BC5RGSnorm;
    case V8GPUTextureFormat::Enum::kBc6HRgbUfloat:
      return wgpu::TextureFormat::BC6HRGBUfloat;
    case V8GPUTextureFormat::Enum::kBc6HRgbFloat:
      return wgpu::TextureFormat::BC6HRGBFloat;
    case V8GPUTextureFormat::Enum::kBc7RgbaUnorm:
      return wgpu::TextureFormat::BC7RGBAUnorm;
    case V8GPUTextureFormat::Enum::kBc7RgbaUnormSrgb:
      return wgpu::TextureFormat::BC7RGBAUnormSrgb;

      // Ericsson Compression (ETC2) formats
    case V8GPUTextureFormat::Enum::kEtc2Rgb8Unorm:
      return wgpu::TextureFormat::ETC2RGB8Unorm;
    case V8GPUTextureFormat::Enum::kEtc2Rgb8UnormSrgb:
      return wgpu::TextureFormat::ETC2RGB8UnormSrgb;
    case V8GPUTextureFormat::Enum::kEtc2Rgb8A1Unorm:
      return wgpu::TextureFormat::ETC2RGB8A1Unorm;
    case V8GPUTextureFormat::Enum::kEtc2Rgb8A1UnormSrgb:
      return wgpu::TextureFormat::ETC2RGB8A1UnormSrgb;
    case V8GPUTextureFormat::Enum::kEtc2Rgba8Unorm:
      return wgpu::TextureFormat::ETC2RGBA8Unorm;
    case V8GPUTextureFormat::Enum::kEtc2Rgba8UnormSrgb:
      return wgpu::TextureFormat::ETC2RGBA8UnormSrgb;
    case V8GPUTextureFormat::Enum::kEacR11Unorm:
      return wgpu::TextureFormat::EACR11Unorm;
    case V8GPUTextureFormat::Enum::kEacR11Snorm:
      return wgpu::TextureFormat::EACR11Snorm;
    case V8GPUTextureFormat::Enum::kEacRg11Unorm:
      return wgpu::TextureFormat::EACRG11Unorm;
    case V8GPUTextureFormat::Enum::kEacRg11Snorm:
      return wgpu::TextureFormat::EACRG11Snorm;

      // Adaptable Scalable Compression (ASTC) formats
    case V8GPUTextureFormat::Enum::kAstc4X4Unorm:
      return wgpu::TextureFormat::ASTC4x4Unorm;
    case V8GPUTextureFormat::Enum::kAstc4X4UnormSrgb:
      return wgpu::TextureFormat::ASTC4x4UnormSrgb;
    case V8GPUTextureFormat::Enum::kAstc5X4Unorm:
      return wgpu::TextureFormat::ASTC5x4Unorm;
    case V8GPUTextureFormat::Enum::kAstc5X4UnormSrgb:
      return wgpu::TextureFormat::ASTC5x4UnormSrgb;
    case V8GPUTextureFormat::Enum::kAstc5X5Unorm:
      return wgpu::TextureFormat::ASTC5x5Unorm;
    case V8GPUTextureFormat::Enum::kAstc5X5UnormSrgb:
      return wgpu::TextureFormat::ASTC5x5UnormSrgb;
    case V8GPUTextureFormat::Enum::kAstc6X5Unorm:
      return wgpu::TextureFormat::ASTC6x5Unorm;
    case V8GPUTextureFormat::Enum::kAstc6X5UnormSrgb:
      return wgpu::TextureFormat::ASTC6x5UnormSrgb;
    case V8GPUTextureFormat::Enum::kAstc6X6Unorm:
      return wgpu::TextureFormat::ASTC6x6Unorm;
    case V8GPUTextureFormat::Enum::kAstc6X6UnormSrgb:
      return wgpu::TextureFormat::ASTC6x6UnormSrgb;
    case V8GPUTextureFormat::Enum::kAstc8X5Unorm:
      return wgpu::TextureFormat::ASTC8x5Unorm;
    case V8GPUTextureFormat::Enum::kAstc8X5UnormSrgb:
      return wgpu::TextureFormat::ASTC8x5UnormSrgb;
    case V8GPUTextureFormat::Enum::kAstc8X6Unorm:
      return wgpu::TextureFormat::ASTC8x6Unorm;
    case V8GPUTextureFormat::Enum::kAstc8X6UnormSrgb:
      return wgpu::TextureFormat::ASTC8x6UnormSrgb;
    case V8GPUTextureFormat::Enum::kAstc8X8Unorm:
      return wgpu::TextureFormat::ASTC8x8Unorm;
    case V8GPUTextureFormat::Enum::kAstc8X8UnormSrgb:
      return wgpu::TextureFormat::ASTC8x8UnormSrgb;
    case V8GPUTextureFormat::Enum::kAstc10X5Unorm:
      return wgpu::TextureFormat::ASTC10x5Unorm;
    case V8GPUTextureFormat::Enum::kAstc10X5UnormSrgb:
      return wgpu::TextureFormat::ASTC10x5UnormSrgb;
    case V8GPUTextureFormat::Enum::kAstc10X6Unorm:
      return wgpu::TextureFormat::ASTC10x6Unorm;
    case V8GPUTextureFormat::Enum::kAstc10X6UnormSrgb:
      return wgpu::TextureFormat::ASTC10x6UnormSrgb;
    case V8GPUTextureFormat::Enum::kAstc10X8Unorm:
      return wgpu::TextureFormat::ASTC10x8Unorm;
    case V8GPUTextureFormat::Enum::kAstc10X8UnormSrgb:
      return wgpu::TextureFormat::ASTC10x8UnormSrgb;
    case V8GPUTextureFormat::Enum::kAstc10X10Unorm:
      return wgpu::TextureFormat::ASTC10x10Unorm;
    case V8GPUTextureFormat::Enum::kAstc10X10UnormSrgb:
      return wgpu::TextureFormat::ASTC10x10UnormSrgb;
    case V8GPUTextureFormat::Enum::kAstc12X10Unorm:
      return wgpu::TextureFormat::ASTC12x10Unorm;
    case V8GPUTextureFormat::Enum::kAstc12X10UnormSrgb:
      return wgpu::TextureFormat::ASTC12x10UnormSrgb;
    case V8GPUTextureFormat::Enum::kAstc12X12Unorm:
      return wgpu::TextureFormat::ASTC12x12Unorm;
    case V8GPUTextureFormat::Enum::kAstc12X12UnormSrgb:
      return wgpu::TextureFormat::ASTC12x12UnormSrgb;

      // R/RG/RGBA16 norm texture formats
    case V8GPUTextureFormat::Enum::kR16Unorm:
      return wgpu::TextureFormat::R16Unorm;
    case V8GPUTextureFormat::Enum::kRg16Unorm:
      return wgpu::TextureFormat::RG16Unorm;
    case V8GPUTextureFormat::Enum::kRgba16Unorm:
      return wgpu::TextureFormat::RGBA16Unorm;
    case V8GPUTextureFormat::Enum::kR16Snorm:
      return wgpu::TextureFormat::R16Snorm;
    case V8GPUTextureFormat::Enum::kRg16Snorm:
      return wgpu::TextureFormat::RG16Snorm;
    case V8GPUTextureFormat::Enum::kRgba16Snorm:
      return wgpu::TextureFormat::RGBA16Snorm;
  }
  NOTREACHED();
}

V8GPUTextureFormat FromDawnEnum(wgpu::TextureFormat dawn_enum) {
  switch (dawn_enum) {
    // Normal 8 bit formats
    case wgpu::TextureFormat::R8Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kR8Unorm);
    case wgpu::TextureFormat::R8Snorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kR8Snorm);
    case wgpu::TextureFormat::R8Uint:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kR8Uint);
    case wgpu::TextureFormat::R8Sint:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kR8Sint);

    // Normal 16 bit formats
    case wgpu::TextureFormat::R16Uint:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kR16Uint);
    case wgpu::TextureFormat::R16Sint:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kR16Sint);
    case wgpu::TextureFormat::R16Float:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kR16Float);
    case wgpu::TextureFormat::RG8Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRg8Unorm);
    case wgpu::TextureFormat::RG8Snorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRg8Snorm);
    case wgpu::TextureFormat::RG8Uint:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRg8Uint);
    case wgpu::TextureFormat::RG8Sint:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRg8Sint);

    // Normal 32 bit formats
    case wgpu::TextureFormat::R32Uint:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kR32Uint);
    case wgpu::TextureFormat::R32Sint:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kR32Sint);
    case wgpu::TextureFormat::R32Float:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kR32Float);
    case wgpu::TextureFormat::RG16Uint:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRg16Uint);
    case wgpu::TextureFormat::RG16Sint:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRg16Sint);
    case wgpu::TextureFormat::RG16Float:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRg16Float);
    case wgpu::TextureFormat::RGBA8Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRgba8Unorm);
    case wgpu::TextureFormat::RGBA8UnormSrgb:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRgba8UnormSrgb);
    case wgpu::TextureFormat::RGBA8Snorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRgba8Snorm);
    case wgpu::TextureFormat::RGBA8Uint:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRgba8Uint);
    case wgpu::TextureFormat::RGBA8Sint:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRgba8Sint);
    case wgpu::TextureFormat::BGRA8Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kBgra8Unorm);
    case wgpu::TextureFormat::BGRA8UnormSrgb:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kBgra8UnormSrgb);

    // Packed 32 bit formats
    case wgpu::TextureFormat::RGB9E5Ufloat:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRgb9E5Ufloat);
    case wgpu::TextureFormat::RGB10A2Uint:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRgb10A2Uint);
    case wgpu::TextureFormat::RGB10A2Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRgb10A2Unorm);
    case wgpu::TextureFormat::RG11B10Ufloat:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRg11B10Ufloat);

    // Normal 64 bit formats
    case wgpu::TextureFormat::RG32Uint:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRg32Uint);
    case wgpu::TextureFormat::RG32Sint:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRg32Sint);
    case wgpu::TextureFormat::RG32Float:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRg32Float);
    case wgpu::TextureFormat::RGBA16Uint:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRgba16Uint);
    case wgpu::TextureFormat::RGBA16Sint:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRgba16Sint);
    case wgpu::TextureFormat::RGBA16Float:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRgba16Float);

    // Normal 128 bit formats
    case wgpu::TextureFormat::RGBA32Uint:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRgba32Uint);
    case wgpu::TextureFormat::RGBA32Sint:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRgba32Sint);
    case wgpu::TextureFormat::RGBA32Float:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRgba32Float);

    // Depth / Stencil formats
    case wgpu::TextureFormat::Depth32Float:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kDepth32Float);
    case wgpu::TextureFormat::Depth32FloatStencil8:
      return V8GPUTextureFormat(
          V8GPUTextureFormat::Enum::kDepth32FloatStencil8);
    case wgpu::TextureFormat::Depth24Plus:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kDepth24Plus);
    case wgpu::TextureFormat::Depth24PlusStencil8:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kDepth24PlusStencil8);
    case wgpu::TextureFormat::Depth16Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kDepth16Unorm);
    case wgpu::TextureFormat::Stencil8:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kStencil8);

    // Block Compression (BC) formats
    case wgpu::TextureFormat::BC1RGBAUnorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kBc1RgbaUnorm);
    case wgpu::TextureFormat::BC1RGBAUnormSrgb:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kBc1RgbaUnormSrgb);
    case wgpu::TextureFormat::BC2RGBAUnorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kBc2RgbaUnorm);
    case wgpu::TextureFormat::BC2RGBAUnormSrgb:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kBc2RgbaUnormSrgb);
    case wgpu::TextureFormat::BC3RGBAUnorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kBc3RgbaUnorm);
    case wgpu::TextureFormat::BC3RGBAUnormSrgb:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kBc3RgbaUnormSrgb);
    case wgpu::TextureFormat::BC4RUnorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kBc4RUnorm);
    case wgpu::TextureFormat::BC4RSnorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kBc4RSnorm);
    case wgpu::TextureFormat::BC5RGUnorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kBc5RgUnorm);
    case wgpu::TextureFormat::BC5RGSnorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kBc5RgSnorm);
    case wgpu::TextureFormat::BC6HRGBUfloat:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kBc6HRgbUfloat);
    case wgpu::TextureFormat::BC6HRGBFloat:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kBc6HRgbFloat);
    case wgpu::TextureFormat::BC7RGBAUnorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kBc7RgbaUnorm);
    case wgpu::TextureFormat::BC7RGBAUnormSrgb:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kBc7RgbaUnormSrgb);

    // Ericsson Compression (ETC2) formats
    case wgpu::TextureFormat::ETC2RGB8Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kEtc2Rgb8Unorm);
    case wgpu::TextureFormat::ETC2RGB8UnormSrgb:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kEtc2Rgb8UnormSrgb);
    case wgpu::TextureFormat::ETC2RGB8A1Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kEtc2Rgb8A1Unorm);
    case wgpu::TextureFormat::ETC2RGB8A1UnormSrgb:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kEtc2Rgb8A1UnormSrgb);
    case wgpu::TextureFormat::ETC2RGBA8Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kEtc2Rgba8Unorm);
    case wgpu::TextureFormat::ETC2RGBA8UnormSrgb:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kEtc2Rgba8UnormSrgb);
    case wgpu::TextureFormat::EACR11Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kEacR11Unorm);
    case wgpu::TextureFormat::EACR11Snorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kEacR11Snorm);
    case wgpu::TextureFormat::EACRG11Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kEacRg11Unorm);
    case wgpu::TextureFormat::EACRG11Snorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kEacRg11Snorm);

    // Adaptable Scalable Compression (ASTC) formats
    case wgpu::TextureFormat::ASTC4x4Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc4X4Unorm);
    case wgpu::TextureFormat::ASTC4x4UnormSrgb:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc4X4UnormSrgb);
    case wgpu::TextureFormat::ASTC5x4Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc5X4Unorm);
    case wgpu::TextureFormat::ASTC5x4UnormSrgb:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc5X4UnormSrgb);
    case wgpu::TextureFormat::ASTC5x5Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc5X5Unorm);
    case wgpu::TextureFormat::ASTC5x5UnormSrgb:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc5X5UnormSrgb);
    case wgpu::TextureFormat::ASTC6x5Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc6X5Unorm);
    case wgpu::TextureFormat::ASTC6x5UnormSrgb:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc6X5UnormSrgb);
    case wgpu::TextureFormat::ASTC6x6Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc6X6Unorm);
    case wgpu::TextureFormat::ASTC6x6UnormSrgb:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc6X6UnormSrgb);
    case wgpu::TextureFormat::ASTC8x5Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc8X5Unorm);
    case wgpu::TextureFormat::ASTC8x5UnormSrgb:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc8X5UnormSrgb);
    case wgpu::TextureFormat::ASTC8x6Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc8X6Unorm);
    case wgpu::TextureFormat::ASTC8x6UnormSrgb:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc8X6UnormSrgb);
    case wgpu::TextureFormat::ASTC8x8Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc8X8Unorm);
    case wgpu::TextureFormat::ASTC8x8UnormSrgb:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc8X8UnormSrgb);
    case wgpu::TextureFormat::ASTC10x5Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc10X5Unorm);
    case wgpu::TextureFormat::ASTC10x5UnormSrgb:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc10X5UnormSrgb);
    case wgpu::TextureFormat::ASTC10x6Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc10X6Unorm);
    case wgpu::TextureFormat::ASTC10x6UnormSrgb:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc10X6UnormSrgb);
    case wgpu::TextureFormat::ASTC10x8Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc10X8Unorm);
    case wgpu::TextureFormat::ASTC10x8UnormSrgb:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc10X8UnormSrgb);
    case wgpu::TextureFormat::ASTC10x10Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc10X10Unorm);
    case wgpu::TextureFormat::ASTC10x10UnormSrgb:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc10X10UnormSrgb);
    case wgpu::TextureFormat::ASTC12x10Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc12X10Unorm);
    case wgpu::TextureFormat::ASTC12x10UnormSrgb:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc12X10UnormSrgb);
    case wgpu::TextureFormat::ASTC12x12Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc12X12Unorm);
    case wgpu::TextureFormat::ASTC12x12UnormSrgb:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kAstc12X12UnormSrgb);

    // R/RG/RGBA16 norm texture formats
    case wgpu::TextureFormat::R16Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kR16Unorm);
    case wgpu::TextureFormat::RG16Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRg16Unorm);
    case wgpu::TextureFormat::RGBA16Unorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRgba16Unorm);
    case wgpu::TextureFormat::R16Snorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kR16Snorm);
    case wgpu::TextureFormat::RG16Snorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRg16Snorm);
    case wgpu::TextureFormat::RGBA16Snorm:
      return V8GPUTextureFormat(V8GPUTextureFormat::Enum::kRgba16Snorm);
    default:
      break;
  }
  NOTREACHED();
}

wgpu::TextureDimension AsDawnEnum(const V8GPUTextureDimension& webgpu_enum) {
  switch (webgpu_enum.AsEnum()) {
    case V8GPUTextureDimension::Enum::k1d:
      return wgpu::TextureDimension::e1D;
    case V8GPUTextureDimension::Enum::k2D:
      return wgpu::TextureDimension::e2D;
    case V8GPUTextureDimension::Enum::k3d:
      return wgpu::TextureDimension::e3D;
  }
  NOTREACHED();
}

V8GPUTextureDimension FromDawnEnum(wgpu::TextureDimension dawn_enum) {
  switch (dawn_enum) {
    case wgpu::TextureDimension::e1D:
      return V8GPUTextureDimension(V8GPUTextureDimension::Enum::k1d);
    case wgpu::TextureDimension::e2D:
      return V8GPUTextureDimension(V8GPUTextureDimension::Enum::k2D);
    case wgpu::TextureDimension::e3D:
      return V8GPUTextureDimension(V8GPUTextureDimension::Enum::k3d);
    case wgpu::TextureDimension::Undefined:
      break;
  }
  NOTREACHED();
}

wgpu::TextureViewDimension AsDawnEnum(
    const V8GPUTextureViewDimension& webgpu_enum) {
  switch (webgpu_enum.AsEnum()) {
    case V8GPUTextureViewDimension::Enum::k1d:
      return wgpu::TextureViewDimension::e1D;
    case V8GPUTextureViewDimension::Enum::k2D:
      return wgpu::TextureViewDimension::e2D;
    case V8GPUTextureViewDimension::Enum::k2DArray:
      return wgpu::TextureViewDimension::e2DArray;
    case V8GPUTextureViewDimension::Enum::kCube:
      return wgpu::TextureViewDimension::Cube;
    case V8GPUTextureViewDimension::Enum::kCubeArray:
      return wgpu::TextureViewDimension::CubeArray;
    case V8GPUTextureViewDimension::Enum::k3d:
      return wgpu::TextureViewDimension::e3D;
  }
  NOTREACHED();
}

wgpu::StencilOperation AsDawnEnum(const V8GPUStencilOperation& webgpu_enum) {
  switch (webgpu_enum.AsEnum()) {
    case V8GPUStencilOperation::Enum::kKeep:
      return wgpu::StencilOperation::Keep;
    case V8GPUStencilOperation::Enum::kZero:
      return wgpu::StencilOperation::Zero;
    case V8GPUStencilOperation::Enum::kReplace:
      return wgpu::StencilOperation::Replace;
    case V8GPUStencilOperation::Enum::kInvert:
      return wgpu::StencilOperation::Invert;
    case V8GPUStencilOperation::Enum::kIncrementClamp:
      return wgpu::StencilOperation::IncrementClamp;
    case V8GPUStencilOperation::Enum::kDecrementClamp:
      return wgpu::StencilOperation::DecrementClamp;
    case V8GPUStencilOperation::Enum::kIncrementWrap:
      return wgpu::StencilOperation::IncrementWrap;
    case V8GPUStencilOperation::Enum::kDecrementWrap:
      return wgpu::StencilOperation::DecrementWrap;
  }
  NOTREACHED();
}

wgpu::StoreOp AsDawnEnum(const V8GPUStoreOp& webgpu_enum) {
  switch (webgpu_enum.AsEnum()) {
    case V8GPUStoreOp::Enum::kStore:
      return wgpu::StoreOp::Store;
    case V8GPUStoreOp::Enum::kDiscard:
      return wgpu::StoreOp::Discard;
  }
  NOTREACHED();
}

wgpu::LoadOp AsDawnEnum(const V8GPULoadOp& webgpu_enum) {
  switch (webgpu_enum.AsEnum()) {
    case V8GPULoadOp::Enum::kLoad:
      return wgpu::LoadOp::Load;
    case V8GPULoadOp::Enum::kClear:
      return wgpu::LoadOp::Clear;
  }
  NOTREACHED();
}

wgpu::IndexFormat AsDawnEnum(const V8GPUIndexFormat& webgpu_enum) {
  switch (webgpu_enum.AsEnum()) {
    case V8GPUIndexFormat::Enum::kUint16:
      return wgpu::IndexFormat::Uint16;
    case V8GPUIndexFormat::Enum::kUint32:
      return wgpu::IndexFormat::Uint32;
  }
  NOTREACHED();
}

wgpu::FeatureName AsDawnEnum(const V8GPUFeatureName& webgpu_enum) {
  switch (webgpu_enum.AsEnum()) {
    case V8GPUFeatureName::Enum::kTextureCompressionBc:
      return wgpu::FeatureName::TextureCompressionBC;
    case V8GPUFeatureName::Enum::kTextureCompressionEtc2:
      return wgpu::FeatureName::TextureCompressionETC2;
    case V8GPUFeatureName::Enum::kTextureCompressionAstc:
      return wgpu::FeatureName::TextureCompressionASTC;
    case V8GPUFeatureName::Enum::kTimestampQuery:
      return wgpu::FeatureName::TimestampQuery;
    case V8GPUFeatureName::Enum:
"""


```