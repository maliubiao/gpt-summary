Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Understanding of the Request:**

The request asks for an analysis of a specific Chromium source code file (`texture_utils.cc`). The analysis should cover:

* **Functionality:** What does the code do?
* **Relation to Web Technologies:** How does it relate to JavaScript, HTML, and CSS?
* **Logic and Examples:**  Illustrate the code's logic with hypothetical inputs and outputs.
* **Common Errors:**  Identify potential mistakes users or programmers might make.
* **Debugging Context:** Explain how a user's actions could lead to this code being executed.

**2. Code Examination - First Pass (Skimming and High-Level Overview):**

I started by quickly reading through the code, noting the following key elements:

* **Includes:**  `gpu_device.h` suggests this code is related to the WebGPU API within the Chromium browser.
* **Namespace:**  `blink::webgpu` confirms the WebGPU context.
* **`TexelBlockInfo` struct:**  This structure holds information about the size and dimensions of texel blocks. This hints at dealing with compressed texture formats.
* **`GetTexelBlockInfoForCopy` function:** This looks like the core logic, determining texel block information based on `wgpu::TextureFormat` and `wgpu::TextureAspect`. The extensive `switch` statements suggest handling a wide range of texture formats.
* **`EstimateWriteTextureBytesUpperBound` function:** This function calculates an upper bound on the number of bytes needed for a texture write operation. It utilizes `GetTexelBlockInfoForCopy`.

**3. Deeper Dive into `GetTexelBlockInfoForCopy`:**

This is the most complex part. I analyzed the nested `switch` statements:

* **Outer `switch` on `aspect`:** This differentiates between copying all aspects, depth-only, and stencil-only aspects of a texture.
* **Inner `switch` on `format`:**  This handles the various WebGPU texture formats. Notice the different return values for different formats. Some return `{byteSize, 1u, 1u}` (uncompressed), while others return `{byteSize, blockWidth, blockHeight}` (compressed). This confirms the handling of block compression.
* **`kInvalidTexelBlockInfo`:**  This is used for unsupported or invalid format/aspect combinations.

**4. Analyzing `EstimateWriteTextureBytesUpperBound`:**

I focused on how this function uses the output of `GetTexelBlockInfoForCopy`:

* **Early Exit:**  If `extent.depthOrArrayLayers` is 0, it returns 0.
* **Call to `GetTexelBlockInfoForCopy`:** This retrieves the block information.
* **Handling Invalid Formats:** If `blockInfo.byteSize` is 0, it returns 0.
* **Block Calculation:** It calculates `widthInBlocks` and `heightInBlocks`.
* **`CheckedNumeric`:** This indicates a concern for potential integer overflows.
* **Padding Calculation:** The code explicitly calculates padding bytes for multi-layered textures.
* **Calculation of Required Bytes:** It combines the block information, layout parameters, and extent to estimate the total bytes.

**5. Connecting to Web Technologies:**

This requires understanding how WebGPU is used in the browser.

* **JavaScript API:**  WebGPU is exposed as a JavaScript API. Functions like `device.createTexture()`, `queue.writeTexture()`, and related objects like `GPUTexture`, `GPUImageCopyTexture`, and `GPUImageDataLayout` are relevant.
* **HTML `<canvas>`:** WebGPU rendering often targets a `<canvas>` element.
* **CSS (Indirect):** While CSS doesn't directly interact with WebGPU at this level, CSS can style the `<canvas>` element that WebGPU renders to.

**6. Crafting Examples and Scenarios:**

* **Hypothetical Input/Output:**  I chose a simple uncompressed format (`R8Unorm`) and a compressed format (`BC1RGBAUnorm`) to illustrate the different behavior of `GetTexelBlockInfoForCopy`. For `EstimateWriteTextureBytesUpperBound`, I demonstrated how the layout parameters influence the calculated size.
* **Common Errors:** I thought about typical mistakes users make when working with textures, such as mismatched formats, incorrect layout parameters, and attempting to write to incompatible texture aspects.
* **User Operations Leading to the Code:** I traced a likely user flow: using the WebGPU API in JavaScript to create and write to a texture. This involves getting a `GPUDevice`, creating a `GPUTexture`, and using `GPUQueue.writeTexture()`.

**7. Structuring the Response:**

I organized the information into clear sections as requested: Functionality, Relationship to Web Technologies, Logic and Examples, Common Errors, and Debugging Clues. I used code blocks for clarity and provided detailed explanations for each point.

**Self-Correction/Refinement during the process:**

* **Initial thought:** I might have initially focused too much on the individual texture formats. I realized it was more important to highlight the general purpose of the code (estimating write sizes) and how it handles compressed vs. uncompressed formats.
* **Clarity of Examples:** I ensured the examples were simple and easy to understand, focusing on demonstrating the key concepts.
* **Debugging Clues:** I made sure the debugging section was practical and provided concrete steps a developer could take.

By following these steps, combining code analysis with an understanding of WebGPU's context, and thinking about potential user scenarios, I was able to generate a comprehensive and accurate response to the request.
This C++ source code file, `texture_utils.cc`, located within the `blink/renderer/modules/webgpu` directory of the Chromium project, provides utility functions for working with textures in the WebGPU API implementation. Its primary focus is on **calculating the memory requirements for texture write operations.**

Here's a breakdown of its functionality:

**1. Determining Texel Block Information (`GetTexelBlockInfoForCopy`):**

   - This function is the core of the file. It takes a `wgpu::TextureFormat` and a `wgpu::TextureAspect` as input and returns a `TexelBlockInfo` struct.
   - `TexelBlockInfo` contains:
     - `byteSize`: The size of a single texel block in bytes.
     - `width`: The width of a texel block in texels.
     - `height`: The height of a texel block in texels.
   - **Purpose:**  It determines the layout and size of the fundamental units of data within a texture, which are crucial for calculating memory requirements.
   - **Logic:**  It uses a nested `switch` statement to handle different texture formats and aspects.
     - The outer `switch` is on `wgpu::TextureAspect` (e.g., `All`, `DepthOnly`, `StencilOnly`), specifying which part of the texture is being considered.
     - The inner `switch` is on `wgpu::TextureFormat` (e.g., `RGBA8Unorm`, `BC7RGBAUnorm`, `Depth32FloatStencil8`), defining the data format of the texture.
     - For uncompressed formats, the block is typically 1x1 texel. For compressed formats (like BC, ETC2, ASTC), the block dimensions and byte size vary.
   - **Example:**
     - Input: `wgpu::TextureFormat::RGBA8Unorm`, `wgpu::TextureAspect::All`
     - Output: `{4u, 1u, 1u}` (4 bytes per texel, 1x1 block)
     - Input: `wgpu::TextureFormat::BC7RGBAUnorm`, `wgpu::TextureAspect::All`
     - Output: `{16u, 4u, 4u}` (16 bytes per block, 4x4 block)
     - Input: `wgpu::TextureFormat::Depth24PlusStencil8`, `wgpu::TextureAspect::StencilOnly`
     - Output: `{1u, 1u, 1u}` (1 byte per stencil value)

**2. Estimating Texture Write Bytes (`EstimateWriteTextureBytesUpperBound`):**

   - This function estimates the maximum number of bytes required for a `writeTexture` operation in WebGPU.
   - It takes the following inputs:
     - `wgpu::TextureDataLayout layout`:  Describes the layout of the source data in memory (e.g., `bytesPerRow`, `rowsPerImage`).
     - `wgpu::Extent3D extent`: Defines the dimensions of the texture region being written to (width, height, depthOrArrayLayers).
     - `wgpu::TextureFormat format`: The format of the texture.
     - `wgpu::TextureAspect aspect`: The aspect of the texture being written to.
   - **Purpose:** To provide an upper bound on the memory needed for copying texture data, taking into account the texture format, layout, and extent. This is likely used for pre-allocation or validation purposes.
   - **Logic:**
     - It first handles the case of an empty copy (`extent.depthOrArrayLayers == 0`).
     - It calls `GetTexelBlockInfoForCopy` to get the block information for the given format and aspect.
     - It calculates the number of blocks in the width and height of the copy region.
     - It uses `base::CheckedNumeric` to perform calculations safely and prevent integer overflows.
     - It accounts for padding bytes required for each image layer when `depthOrArrayLayers > 1`.
     - It calculates the bytes needed for the last row and then for the entire image (or layer).
     - It sums up the bytes for all layers to get the final estimate.
   - **Assumptions and Logic Inference:**
     - **Assumption:** The `layout.bytesPerRow` and `layout.rowsPerImage` parameters are used to handle potential row and image padding in the source data.
     - **Logic:**  The calculation iterates through the layers, rows (in blocks), and then calculates the bytes per block to arrive at the total size.
   - **Hypothetical Input and Output:**
     - Input:
       - `layout`: `{ 256, 0 }` (256 bytes per row, no image padding)
       - `extent`: `{ 64, 64, 1 }` (64x64, single layer)
       - `format`: `wgpu::TextureFormat::RGBA8Unorm`
       - `aspect`: `wgpu::TextureAspect::All`
     - Call to `GetTexelBlockInfoForCopy(RGBA8Unorm, All)` returns `{4u, 1u, 1u}`.
     - `widthInBlocks` = 64 / 1 = 64
     - `heightInBlocks` = 64 / 1 = 64
     - `requiredBytesInCopy` = 64 * 64 * 4 = 16384
     - Output: `16384`

     - Input:
       - `layout`: `{ 0, 0 }` (bytesPerRow and rowsPerImage are undefined, meaning tightly packed)
       - `extent`: `{ 16, 16, 1 }`
       - `format`: `wgpu::TextureFormat::BC7RGBAUnorm`
       - `aspect`: `wgpu::TextureAspect::All`
     - Call to `GetTexelBlockInfoForCopy(BC7RGBAUnorm, All)` returns `{16u, 4u, 4u}`.
     - `widthInBlocks` = 16 / 4 = 4
     - `heightInBlocks` = 16 / 4 = 4
     - `requiredBytesInCopy` = 4 * 4 * 16 = 256
     - Output: `256`

**Relationship to JavaScript, HTML, and CSS:**

This C++ code directly implements parts of the WebGPU API, which is exposed to JavaScript.

- **JavaScript:** When a web developer uses the WebGPU API in JavaScript to write data to a texture (using `GPUQueue.writeTexture`), the browser's implementation will eventually call into code like this.
  ```javascript
  const device = await navigator.gpu.requestAdapter().requestDevice();
  const texture = device.createTexture({
    size: [64, 64, 1],
    format: 'rgba8unorm',
    usage: GPUTextureUsage.COPY_DST | GPUTextureUsage.RENDER_ATTACHMENT
  });

  const pixelData = new Uint8Array(64 * 64 * 4); // Example pixel data

  device.queue.writeTexture(
    { texture: texture },
    pixelData,
    { bytesPerRow: 256 }, // Corresponds to layout.bytesPerRow
    { width: 64, height: 64 } // Corresponds to extent.width and extent.height
  );
  ```
  In this JavaScript example, the `format` ('rgba8unorm'), the `size` of the texture, and the `bytesPerRow` in the `writeTexture` call directly influence the parameters passed to the C++ functions in `texture_utils.cc`.

- **HTML:**  While HTML doesn't directly interact with this code, WebGPU often renders to a `<canvas>` element in HTML. The size and properties of the canvas might indirectly influence the textures used in the rendering process.

- **CSS:** CSS styles the visual presentation of web pages, including the `<canvas>` element where WebGPU renders. Again, the size of the canvas might indirectly affect texture creation and usage, but CSS doesn't directly interact with the core texture calculations in this C++ code.

**Common User or Programming Mistakes:**

1. **Incorrect `bytesPerRow`:**  A common mistake is providing an incorrect `bytesPerRow` value in the `writeTexture` call in JavaScript, which doesn't match the actual layout of the `pixelData`. This can lead to data being written to the wrong offsets in the texture.
   - **Example:**  The `pixelData` is tightly packed (e.g., `width * 4` for RGBA8), but the `bytesPerRow` is set to a larger value. This will introduce gaps in the texture data.

2. **Mismatched Texture Format and Data:**  Trying to write data with a format that doesn't match the texture's declared format. WebGPU is strict about this.
   - **Example:** Creating a texture with `format: 'rgba8unorm'` but providing `pixelData` as an array of 16-bit integers.

3. **Incorrect Extent:** Specifying an `extent` in `writeTexture` that goes beyond the bounds of the texture. This will result in an error.
   - **Example:**  A texture is created with size 64x64, but the `writeTexture` call attempts to write to an extent of 128x128.

4. **Writing to Incompatible Texture Aspects:**  Trying to write data to an aspect of the texture that's not supported for write operations.
   - **Example:** Trying to write to the depth aspect of a depth texture without the appropriate write operations enabled.

**User Operations Leading to This Code (Debugging Clues):**

To reach the code in `texture_utils.cc`, a user would typically perform the following steps in a web browser:

1. **Open a web page:** The web page contains JavaScript code that uses the WebGPU API.
2. **Execute JavaScript WebGPU code:** The JavaScript code interacts with the WebGPU API.
3. **Create a `GPUTexture`:** The JavaScript code calls `device.createTexture()` to create a texture object, specifying its format, size, and usage.
4. **Prepare texture data:** The JavaScript code creates an `ArrayBuffer` or `TypedArray` containing the data to be written to the texture.
5. **Call `queue.writeTexture()`:** The JavaScript code calls `device.queue.writeTexture()` to copy the data to the texture. This is the key step that triggers the execution of the C++ code in `texture_utils.cc`.
6. **The browser's WebGPU implementation:** The browser's rendering engine (Blink in Chromium's case) receives the `writeTexture` command from the JavaScript.
7. **Validation and execution:** The browser's WebGPU implementation needs to validate the parameters of the `writeTexture` call and then execute the data copy. This involves calculating the memory requirements for the copy operation, which is where `EstimateWriteTextureBytesUpperBound` and `GetTexelBlockInfoForCopy` come into play.

**As a debugger, you might set breakpoints in `texture_utils.cc` to:**

- Inspect the `format`, `aspect`, `layout`, and `extent` values being passed to the functions.
- Verify the calculated `TexelBlockInfo`.
- Check the estimated byte size calculated by `EstimateWriteTextureBytesUpperBound`.
- Understand how the browser handles different texture formats and layouts during write operations.

By stepping through the code, you can understand how the browser determines the memory requirements for texture operations and identify potential discrepancies between the user's intent (in JavaScript) and the underlying implementation.

Prompt: 
```
这是目录为blink/renderer/modules/webgpu/texture_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webgpu/texture_utils.h"

#include "third_party/blink/renderer/modules/webgpu/gpu_device.h"

namespace blink {

namespace {

struct TexelBlockInfo {
  uint32_t byteSize;
  uint32_t width;
  uint32_t height;
};

TexelBlockInfo GetTexelBlockInfoForCopy(wgpu::TextureFormat format,
                                        wgpu::TextureAspect aspect) {
  constexpr TexelBlockInfo kInvalidTexelBlockInfo = {0, 0, 0};

  switch (aspect) {
    case wgpu::TextureAspect::All:
      switch (format) {
        case wgpu::TextureFormat::R8Unorm:
        case wgpu::TextureFormat::R8Snorm:
        case wgpu::TextureFormat::R8Uint:
        case wgpu::TextureFormat::R8Sint:
          return {1u, 1u, 1u};

        case wgpu::TextureFormat::R16Uint:
        case wgpu::TextureFormat::R16Sint:
        case wgpu::TextureFormat::R16Float:
        case wgpu::TextureFormat::RG8Unorm:
        case wgpu::TextureFormat::RG8Snorm:
        case wgpu::TextureFormat::RG8Uint:
        case wgpu::TextureFormat::RG8Sint:
          return {2u, 1u, 1u};

        case wgpu::TextureFormat::R32Float:
        case wgpu::TextureFormat::R32Uint:
        case wgpu::TextureFormat::R32Sint:
        case wgpu::TextureFormat::RG16Uint:
        case wgpu::TextureFormat::RG16Sint:
        case wgpu::TextureFormat::RG16Float:
        case wgpu::TextureFormat::RGBA8Unorm:
        case wgpu::TextureFormat::RGBA8UnormSrgb:
        case wgpu::TextureFormat::RGBA8Snorm:
        case wgpu::TextureFormat::RGBA8Uint:
        case wgpu::TextureFormat::RGBA8Sint:
        case wgpu::TextureFormat::BGRA8Unorm:
        case wgpu::TextureFormat::BGRA8UnormSrgb:
        case wgpu::TextureFormat::RGB10A2Uint:
        case wgpu::TextureFormat::RGB10A2Unorm:
        case wgpu::TextureFormat::RG11B10Ufloat:
        case wgpu::TextureFormat::RGB9E5Ufloat:
          return {4u, 1u, 1u};

        case wgpu::TextureFormat::RG32Float:
        case wgpu::TextureFormat::RG32Uint:
        case wgpu::TextureFormat::RG32Sint:
        case wgpu::TextureFormat::RGBA16Uint:
        case wgpu::TextureFormat::RGBA16Sint:
        case wgpu::TextureFormat::RGBA16Float:
          return {8u, 1u, 1u};

        case wgpu::TextureFormat::RGBA32Float:
        case wgpu::TextureFormat::RGBA32Uint:
        case wgpu::TextureFormat::RGBA32Sint:
          return {16u, 1u, 1u};

        case wgpu::TextureFormat::Depth16Unorm:
          return {2u, 1u, 1u};
        case wgpu::TextureFormat::Stencil8:
          return {1u, 1u, 1u};

        case wgpu::TextureFormat::BC1RGBAUnorm:
        case wgpu::TextureFormat::BC1RGBAUnormSrgb:
        case wgpu::TextureFormat::BC4RUnorm:
        case wgpu::TextureFormat::BC4RSnorm:
          return {8u, 4u, 4u};

        case wgpu::TextureFormat::BC2RGBAUnorm:
        case wgpu::TextureFormat::BC2RGBAUnormSrgb:
        case wgpu::TextureFormat::BC3RGBAUnorm:
        case wgpu::TextureFormat::BC3RGBAUnormSrgb:
        case wgpu::TextureFormat::BC5RGUnorm:
        case wgpu::TextureFormat::BC5RGSnorm:
        case wgpu::TextureFormat::BC6HRGBUfloat:
        case wgpu::TextureFormat::BC6HRGBFloat:
        case wgpu::TextureFormat::BC7RGBAUnorm:
        case wgpu::TextureFormat::BC7RGBAUnormSrgb:
          return {16u, 4u, 4u};

        case wgpu::TextureFormat::ETC2RGB8Unorm:
        case wgpu::TextureFormat::ETC2RGB8UnormSrgb:
        case wgpu::TextureFormat::ETC2RGB8A1Unorm:
        case wgpu::TextureFormat::ETC2RGB8A1UnormSrgb:
        case wgpu::TextureFormat::EACR11Unorm:
        case wgpu::TextureFormat::EACR11Snorm:
          return {8u, 4u, 4u};

        case wgpu::TextureFormat::ETC2RGBA8Unorm:
        case wgpu::TextureFormat::ETC2RGBA8UnormSrgb:
        case wgpu::TextureFormat::EACRG11Unorm:
        case wgpu::TextureFormat::EACRG11Snorm:
          return {16u, 4u, 4u};

        case wgpu::TextureFormat::ASTC4x4Unorm:
        case wgpu::TextureFormat::ASTC4x4UnormSrgb:
          return {16u, 4u, 4u};
        case wgpu::TextureFormat::ASTC5x4Unorm:
        case wgpu::TextureFormat::ASTC5x4UnormSrgb:
          return {16u, 5u, 4u};
        case wgpu::TextureFormat::ASTC5x5Unorm:
        case wgpu::TextureFormat::ASTC5x5UnormSrgb:
          return {16u, 5u, 5u};
        case wgpu::TextureFormat::ASTC6x5Unorm:
        case wgpu::TextureFormat::ASTC6x5UnormSrgb:
          return {16u, 6u, 5u};
        case wgpu::TextureFormat::ASTC6x6Unorm:
        case wgpu::TextureFormat::ASTC6x6UnormSrgb:
          return {16u, 6u, 6u};
        case wgpu::TextureFormat::ASTC8x5Unorm:
        case wgpu::TextureFormat::ASTC8x5UnormSrgb:
          return {16u, 8u, 5u};
        case wgpu::TextureFormat::ASTC8x6Unorm:
        case wgpu::TextureFormat::ASTC8x6UnormSrgb:
          return {16u, 8u, 6u};
        case wgpu::TextureFormat::ASTC8x8Unorm:
        case wgpu::TextureFormat::ASTC8x8UnormSrgb:
          return {16u, 8u, 8u};
        case wgpu::TextureFormat::ASTC10x5Unorm:
        case wgpu::TextureFormat::ASTC10x5UnormSrgb:
          return {16u, 10u, 5u};
        case wgpu::TextureFormat::ASTC10x6Unorm:
        case wgpu::TextureFormat::ASTC10x6UnormSrgb:
          return {16u, 10u, 6u};
        case wgpu::TextureFormat::ASTC10x8Unorm:
        case wgpu::TextureFormat::ASTC10x8UnormSrgb:
          return {16u, 10u, 8u};
        case wgpu::TextureFormat::ASTC10x10Unorm:
        case wgpu::TextureFormat::ASTC10x10UnormSrgb:
          return {16u, 10u, 10u};
        case wgpu::TextureFormat::ASTC12x10Unorm:
        case wgpu::TextureFormat::ASTC12x10UnormSrgb:
          return {16u, 12u, 10u};
        case wgpu::TextureFormat::ASTC12x12Unorm:
        case wgpu::TextureFormat::ASTC12x12UnormSrgb:
          return {16u, 12u, 12u};

        default:
          return kInvalidTexelBlockInfo;
      }

    // Copies to depth/stencil aspects are fairly restricted, see
    // https://gpuweb.github.io/gpuweb/#depth-formats so we only list
    // combinations of format and aspects that can be copied to with a
    // WriteTexture.
    case wgpu::TextureAspect::DepthOnly:
      switch (format) {
        case wgpu::TextureFormat::Depth16Unorm:
          return GetTexelBlockInfoForCopy(format, wgpu::TextureAspect::All);

        default:
          return kInvalidTexelBlockInfo;
      }

    case wgpu::TextureAspect::StencilOnly:
      switch (format) {
        case wgpu::TextureFormat::Depth24PlusStencil8:
        case wgpu::TextureFormat::Depth32FloatStencil8:
          return {1u, 1u, 1u};

        case wgpu::TextureFormat::Stencil8:
          return GetTexelBlockInfoForCopy(format, wgpu::TextureAspect::All);

        default:
          return kInvalidTexelBlockInfo;
      }

    default:
      NOTREACHED();
  }
}

}  // anonymous namespace

size_t EstimateWriteTextureBytesUpperBound(wgpu::TextureDataLayout layout,
                                           wgpu::Extent3D extent,
                                           wgpu::TextureFormat format,
                                           wgpu::TextureAspect aspect) {
  // Check for empty copies because of depth first so we can early out. Note
  // that we can't early out because of height or width being 0 because padding
  // images still need to be accounted for.
  if (extent.depthOrArrayLayers == 0) {
    return 0;
  }

  TexelBlockInfo blockInfo = GetTexelBlockInfoForCopy(format, aspect);

  // Unknown format/aspect combination will be validated by the GPU process
  // again.
  if (blockInfo.byteSize == 0) {
    return 0;
  }

  // If the block size doesn't divide the extent, a validation error will be
  // produced on the GPU process side so we don't need to guard against it.
  uint32_t widthInBlocks = extent.width / blockInfo.width;
  uint32_t heightInBlocks = extent.height / blockInfo.height;

  // Use checked numerics even though the GPU process will guard against OOB
  // because otherwise UBSan will complain about overflows. Note that if
  // bytesPerRow or rowsPerImage are wgpu::kCopyStrideUndefined and used, the
  // GPU process will also create a validation error because it means that they
  // are used when copySize.height/depthOrArrayLayers > 1.
  base::CheckedNumeric<size_t> requiredBytesInCopy = 0;

  // WebGPU requires that the padding bytes for images are counted, even if the
  // copy is empty.
  if (extent.depthOrArrayLayers > 1) {
    requiredBytesInCopy = layout.bytesPerRow;
    requiredBytesInCopy *= layout.rowsPerImage;
    requiredBytesInCopy *= (extent.depthOrArrayLayers - 1);
  }

  if (heightInBlocks != 0) {
    base::CheckedNumeric<size_t> lastRowBytes = widthInBlocks;
    lastRowBytes *= blockInfo.byteSize;

    base::CheckedNumeric<size_t> lastImageBytes = layout.bytesPerRow;
    lastImageBytes *= (heightInBlocks - 1);
    lastImageBytes += lastRowBytes;

    requiredBytesInCopy += lastImageBytes;
  }

  return requiredBytesInCopy.ValueOrDefault(0);
}

}  // namespace blink

"""

```