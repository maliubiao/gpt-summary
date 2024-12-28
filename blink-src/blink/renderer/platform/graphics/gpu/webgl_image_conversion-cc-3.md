Response:
The user wants to understand the functionality of the provided C++ code snippet from a Chromium Blink engine file. The code seems to be related to image format conversion for WebGL. I need to:

1. **Summarize the code's purpose:**  Focus on the core task of converting image data between different formats, likely for use in WebGL.
2. **Explain its relationship to web technologies (JavaScript, HTML, CSS):**  How does this code facilitate displaying images in web browsers using WebGL?
3. **Illustrate with examples:** Provide hypothetical input and output scenarios for the conversion functions.
4. **Highlight potential user/programming errors:**  What common mistakes might occur when using or interacting with this type of code?
5. **Synthesize the information into a concise summary (as this is part 4 of 5).**

**Breakdown of the code:**

* **Template functions `Pack`:** These functions seem to be responsible for packing pixel data from a source format to a destination format. They handle various data types (uint8_t, uint16_t, float, etc.) and alpha operations (premultiply, unmultiply, do nothing).
* **Helper functions `HasAlpha`, `HasColor`:** These functions determine if a given image format includes alpha or color components.
* **Template structs `IsInt8Format`, `IsUInt8Format`, etc.:** These are type traits to check the underlying data type of a given format.
* **Template struct `DataTypeForFormat`:** This seems to map a WebGL image format to its corresponding C++ data type.
* **Template struct `UsesFloatIntermediateFormat`, `IntermediateFormat`:** These might determine if an intermediate floating-point representation is needed during conversion and what that format is.
* **Function `TexelBytesForFormat`:**  This returns the number of bytes per pixel for a given format.
* **Class `FormatConverter`:** This class appears to orchestrate the image conversion process, handling source and destination buffers, strides, and the conversion logic itself.

**Relationship to web technologies:**

* **JavaScript/WebGL:** This code is directly used by the WebGL API. When a JavaScript application uploads image data (e.g., from an `<canvas>` element, `<img>` tag, or `ImageData` object) to a WebGL texture, this code (or related parts of the Blink engine) is responsible for converting the image data into a format suitable for the GPU.
* **HTML:** The `<canvas>` element is a common source of image data for WebGL. The `drawImage` method of the canvas rendering context can be used to draw images onto the canvas, which can then be read back and uploaded to WebGL.
* **CSS:** While CSS doesn't directly interact with this low-level conversion, CSS properties can affect how images are rendered *before* being uploaded to WebGL (e.g., image scaling, transformations).

**Hypothetical Input/Output:**

Imagine converting a simple 1x1 RGBA image:

* **Input (RGBA8, uint8_t):**  `source = {255, 0, 0, 128}` (red color with 50% alpha)
* **Output (RGBA8, uint8_t, with premultiplication):** The `Pack` function for `kDataFormatRGBA8` with `kAlphaDoPremultiply` would calculate:
    * `scale_factor = 128 / 255.0f` (approximately 0.5)
    * `destination[0] = static_cast<uint8_t>(255 * 0.5) = 127`
    * `destination[1] = static_cast<uint8_t>(0 * 0.5) = 0`
    * `destination[2] = static_cast<uint8_t>(0 * 0.5) = 0`
    * `destination[3] = 128`
    * **Output:** `destination = {127, 0, 0, 128}`

**Common Errors:**

* **Incorrect format specification:**  The JavaScript code might specify a different image format than the actual data being provided, leading to incorrect interpretation. For example, sending RGB data but telling WebGL it's RGBA.
* **Mismatched data types:**  Providing floating-point data when the target format expects integers, or vice-versa, without proper conversion.
* **Premultiplication issues:**  Not understanding when and how alpha premultiplication should be applied can lead to unexpected blending results in WebGL.
* **Buffer overflows:**  If the destination buffer is not large enough to hold the converted image data.

Now, let's put it all together in the final summary.
这是目录为 `blink/renderer/platform/graphics/gpu/webgl_image_conversion.cc` 的 Chromium Blink 引擎源代码文件的第 4 部分，它主要负责 **将各种格式的图像数据打包 (packing) 成 WebGL 可以使用的特定格式**。

**核心功能归纳:**

这一部分的代码主要定义了 `Pack` 模板函数的多个特化版本，这些函数的功能是将源图像数据按照指定的格式和 Alpha 操作 (如预乘、不处理、反乘) 转换并写入到目标缓冲区。  它涵盖了多种 WebGL 支持的图像内部格式，包括：

* **RGBA 格式：**  RGBA8 (8位无符号整数), RGBA16 (16位无符号整数), RGBA16_S (16位有符号整数), RGBA32 (32位无符号整数), RGBA32_S (32位有符号整数), RGBA2_10_10_10 (每个颜色分量 10 位，Alpha 2 位)。
* **RG 格式：** RG8 (8位无符号整数), RG16F (16位浮点数), RG32F (32位浮点数)。

同时，它还定义了一些辅助函数和结构体，用于判断图像格式的特性，例如是否包含 Alpha 通道、颜色分量以及数据类型等。

**与 JavaScript, HTML, CSS 的关系：**

虽然这段 C++ 代码本身不直接与 JavaScript, HTML, CSS 交互，但它是实现 WebGL 功能的关键部分，使得 JavaScript 能够向 GPU 上传和操作各种格式的图像数据。

* **JavaScript/WebGL:**  当 JavaScript 代码使用 WebGL API (例如 `texImage2D` 或 `texSubImage2D`) 上传图像数据到纹理时，Blink 引擎会调用 `WebGLImageConversion` 相关的代码来处理图像格式的转换。这段代码负责将 JavaScript 提供的 `ArrayBufferView` 或其他图像源 (例如 `<canvas>` 元素) 中的像素数据转换为 WebGL 期望的 GPU 内部格式。
    * **举例说明：** 假设 JavaScript 代码从一个 `<canvas>` 元素获取图像数据，并尝试将其上传为 `RGBA8` 格式的 WebGL 纹理。这段 C++ 代码中的 `Pack<WebGLImageConversion::kDataFormatRGBA8, ...>` 的某个特化版本就会被调用，将 `<canvas>` 元素的像素数据 (可能 изначально 是不同的格式) 转换为 `RGBA8` 并写入到 GPU 内存。

* **HTML:**  HTML 中的 `<canvas>` 元素或 `<img>` 标签可以作为 WebGL 纹理的图像数据来源。当 JavaScript 代码使用 WebGL 上传这些元素的内容时，这段 C++ 代码会参与处理这些图像数据。
    * **举例说明：**  如果一个 `<img>` 标签加载了一张 PNG 图片，JavaScript 通过 WebGL 将其作为纹理上传。这段 C++ 代码需要处理 PNG 图像的解码以及到 WebGL 目标格式的转换。

* **CSS:** CSS 样式会影响 HTML 元素的渲染，间接地影响通过 `<canvas>` 元素获取的图像数据。例如，CSS 可以缩放或旋转 `<canvas>` 的内容，这些变换会反映在通过 WebGL 上传的纹理中。然而，这段 C++ 代码本身不直接处理 CSS。

**逻辑推理与假设输入输出：**

以 `Pack<WebGLImageConversion::kDataFormatRGBA8, WebGLImageConversion::kAlphaDoPremultiply, uint8_t, uint8_t>` 为例：

* **假设输入：**
    * `source` 指向包含 RGBA 像素数据的 `uint8_t` 数组，每个像素包含 4 个字节 (R, G, B, A)，取一个像素为例: `{255, 0, 0, 128}` (红色，Alpha值为 128)。
    * `destination` 指向用于存储转换后数据的 `uint8_t` 数组。
    * `pixels_per_row` 为该行像素数量。
* **逻辑推理：** 该函数将执行预乘 Alpha 操作。对于每个像素，它会计算一个缩放因子 `scale_factor = alpha / 255.0f` (因为源和目标都是 `uint8_t`)，然后将 RGB 分量乘以这个缩放因子。
* **假设输出：** 对于上述输入像素，计算过程如下：
    * `scale_factor = 128 / 255.0f` (约等于 0.5)
    * `destination[0] = static_cast<uint8_t>(255 * 0.5) = 127`
    * `destination[1] = static_cast<uint8_t>(0 * 0.5) = 0`
    * `destination[2] = static_cast<uint8_t>(0 * 0.5) = 0`
    * `destination[3]` 保持不变，为 `128`。
    * 因此，`destination` 中对应的像素数据为 `{127, 0, 0, 128}`。

**用户或编程常见的使用错误：**

* **格式不匹配：**  JavaScript 代码中指定的 WebGL 纹理格式与实际提供的图像数据格式不符。例如，提供了 RGB 数据，但告诉 WebGL 使用 RGBA 格式，可能导致数据错位或渲染错误。
* **数据类型错误：**  提供的图像数据类型与 `Pack` 函数期望的类型不一致。例如，期望 `uint8_t` 数据，但提供了浮点数数据。
* **Alpha 预乘/反乘混淆：**  在需要预乘 Alpha 的情况下没有进行预乘，或者在已经预乘的情况下又进行了预乘，导致颜色混合错误。
* **目标缓冲区溢出：**  目标缓冲区 `destination` 的大小不足以容纳转换后的图像数据。

总而言之，这段代码是 WebGL 图像处理流程中至关重要的一环，它确保了不同来源和格式的图像数据能够被正确地转换成 WebGL 能够理解和处理的内部格式，从而在网页上渲染出丰富的 3D 图形效果。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/gpu/webgl_image_conversion.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
ixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[3] = ClampMin(source[3]);
    float scale_factor = static_cast<float>(destination[3]) / kMaxInt8Value;
    destination[0] = static_cast<int8_t>(
        static_cast<float>(ClampMin(source[0])) * scale_factor);
    destination[1] = static_cast<int8_t>(
        static_cast<float>(ClampMin(source[1])) * scale_factor);
    destination[2] = static_cast<int8_t>(
        static_cast<float>(ClampMin(source[2])) * scale_factor);
    source += 4;
    destination += 4;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA16,
          WebGLImageConversion::kAlphaDoPremultiply,
          uint16_t,
          uint16_t>(const uint16_t* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = static_cast<float>(source[3]) / kMaxUInt16Value;
    destination[0] =
        static_cast<uint16_t>(static_cast<float>(source[0]) * scale_factor);
    destination[1] =
        static_cast<uint16_t>(static_cast<float>(source[1]) * scale_factor);
    destination[2] =
        static_cast<uint16_t>(static_cast<float>(source[2]) * scale_factor);
    destination[3] = source[3];
    source += 4;
    destination += 4;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA16,
          WebGLImageConversion::kAlphaDoPremultiply,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = ClampAndScaleFloat<uint16_t>(source[0] * source[3]);
    destination[1] = ClampAndScaleFloat<uint16_t>(source[1] * source[3]);
    destination[2] = ClampAndScaleFloat<uint16_t>(source[2] * source[3]);
    destination[3] = ClampAndScaleFloat<uint16_t>(source[3]);
    source += 4;
    destination += 4;
  }
}

// Can not be targeted by DOM uploads, so does not need to support float
// input data.

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA16_S,
          WebGLImageConversion::kAlphaDoPremultiply,
          int16_t,
          int16_t>(const int16_t* source,
                   int16_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[3] = ClampMin(source[3]);
    float scale_factor = static_cast<float>(destination[3]) / kMaxInt16Value;
    destination[0] = static_cast<int16_t>(
        static_cast<float>(ClampMin(source[0])) * scale_factor);
    destination[1] = static_cast<int16_t>(
        static_cast<float>(ClampMin(source[1])) * scale_factor);
    destination[2] = static_cast<int16_t>(
        static_cast<float>(ClampMin(source[2])) * scale_factor);
    source += 4;
    destination += 4;
  }
}

// Can not be targeted by DOM uploads, so does not need to support float
// input data.

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA32,
          WebGLImageConversion::kAlphaDoPremultiply,
          uint32_t,
          uint32_t>(const uint32_t* source,
                    uint32_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    double scale_factor = static_cast<double>(source[3]) / kMaxUInt32Value;
    destination[0] =
        static_cast<uint32_t>(static_cast<double>(source[0]) * scale_factor);
    destination[1] =
        static_cast<uint32_t>(static_cast<double>(source[1]) * scale_factor);
    destination[2] =
        static_cast<uint32_t>(static_cast<double>(source[2]) * scale_factor);
    destination[3] = source[3];
    source += 4;
    destination += 4;
  }
}

// Can not be targeted by DOM uploads, so does not need to support float
// input data.

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA32_S,
          WebGLImageConversion::kAlphaDoPremultiply,
          int32_t,
          int32_t>(const int32_t* source,
                   int32_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[3] = ClampMin(source[3]);
    double scale_factor = static_cast<double>(destination[3]) / kMaxInt32Value;
    destination[0] = static_cast<int32_t>(
        static_cast<double>(ClampMin(source[0])) * scale_factor);
    destination[1] = static_cast<int32_t>(
        static_cast<double>(ClampMin(source[1])) * scale_factor);
    destination[2] = static_cast<int32_t>(
        static_cast<double>(ClampMin(source[2])) * scale_factor);
    source += 4;
    destination += 4;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA2_10_10_10,
          WebGLImageConversion::kAlphaDoNothing,
          float,
          uint32_t>(const float* source,
                    uint32_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    uint32_t r = static_cast<uint32_t>(source[0] * 1023.0f);
    uint32_t g = static_cast<uint32_t>(source[1] * 1023.0f);
    uint32_t b = static_cast<uint32_t>(source[2] * 1023.0f);
    uint32_t a = static_cast<uint32_t>(source[3] * 3.0f);
    destination[0] = (a << 30) | (b << 20) | (g << 10) | r;
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA2_10_10_10,
          WebGLImageConversion::kAlphaDoPremultiply,
          float,
          uint32_t>(const float* source,
                    uint32_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    uint32_t r = static_cast<uint32_t>(source[0] * source[3] * 1023.0f);
    uint32_t g = static_cast<uint32_t>(source[1] * source[3] * 1023.0f);
    uint32_t b = static_cast<uint32_t>(source[2] * source[3] * 1023.0f);
    uint32_t a = static_cast<uint32_t>(source[3] * 3.0f);
    destination[0] = (a << 30) | (b << 20) | (g << 10) | r;
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA2_10_10_10,
          WebGLImageConversion::kAlphaDoUnmultiply,
          float,
          uint32_t>(const float* source,
                    uint32_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 1023.0f / source[3] : 1023.0f;
    uint32_t r = static_cast<uint32_t>(source[0] * scale_factor);
    uint32_t g = static_cast<uint32_t>(source[1] * scale_factor);
    uint32_t b = static_cast<uint32_t>(source[2] * scale_factor);
    uint32_t a = static_cast<uint32_t>(source[3] * 3.0f);
    destination[0] = (a << 30) | (b << 20) | (g << 10) | r;
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRG8,
          WebGLImageConversion::kAlphaDoNothing,
          uint8_t,
          uint8_t>(const uint8_t* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = source[0];
    destination[1] = source[1];
    source += 4;
    destination += 2;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRG8,
          WebGLImageConversion::kAlphaDoNothing,
          float,
          uint8_t>(const float* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = ClampAndScaleFloat<uint8_t>(source[0]);
    destination[1] = ClampAndScaleFloat<uint8_t>(source[1]);
    source += 4;
    destination += 2;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRG8,
          WebGLImageConversion::kAlphaDoPremultiply,
          uint8_t,
          uint8_t>(const uint8_t* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = static_cast<float>(source[3]) / kMaxUInt8Value;
    destination[0] =
        static_cast<uint8_t>(static_cast<float>(source[0]) * scale_factor);
    destination[1] =
        static_cast<uint8_t>(static_cast<float>(source[1]) * scale_factor);
    source += 4;
    destination += 2;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRG8,
          WebGLImageConversion::kAlphaDoPremultiply,
          float,
          uint8_t>(const float* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = ClampAndScaleFloat<uint8_t>(source[0] * source[3]);
    destination[1] = ClampAndScaleFloat<uint8_t>(source[1] * source[3]);
    source += 4;
    destination += 2;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRG8,
          WebGLImageConversion::kAlphaDoUnmultiply,
          uint8_t,
          uint8_t>(const uint8_t* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor =
        source[3] ? kMaxUInt8Value / static_cast<float>(source[3]) : 1.0f;
    destination[0] =
        static_cast<uint8_t>(static_cast<float>(source[0]) * scale_factor);
    destination[1] =
        static_cast<uint8_t>(static_cast<float>(source[1]) * scale_factor);
    source += 4;
    destination += 2;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRG8,
          WebGLImageConversion::kAlphaDoUnmultiply,
          float,
          uint8_t>(const float* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 1.0f / source[3] : 1.0f;
    destination[0] = ClampAndScaleFloat<uint8_t>(source[0] * scale_factor);
    destination[1] = ClampAndScaleFloat<uint8_t>(source[1] * scale_factor);
    source += 4;
    destination += 2;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRG16F,
          WebGLImageConversion::kAlphaDoNothing,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = ConvertFloatToHalfFloat(source[0]);
    destination[1] = ConvertFloatToHalfFloat(source[1]);
    source += 4;
    destination += 2;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRG16F,
          WebGLImageConversion::kAlphaDoPremultiply,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3];
    destination[0] = ConvertFloatToHalfFloat(source[0] * scale_factor);
    destination[1] = ConvertFloatToHalfFloat(source[1] * scale_factor);
    source += 4;
    destination += 2;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRG16F,
          WebGLImageConversion::kAlphaDoUnmultiply,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 1.0f / source[3] : 1.0f;
    destination[0] = ConvertFloatToHalfFloat(source[0] * scale_factor);
    destination[1] = ConvertFloatToHalfFloat(source[1] * scale_factor);
    source += 4;
    destination += 2;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRG32F,
          WebGLImageConversion::kAlphaDoNothing,
          float,
          float>(const float* source,
                 float* destination,
                 unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = source[0];
    destination[1] = source[1];
    source += 4;
    destination += 2;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRG32F,
          WebGLImageConversion::kAlphaDoPremultiply,
          float,
          float>(const float* source,
                 float* destination,
                 unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3];
    destination[0] = source[0] * scale_factor;
    destination[1] = source[1] * scale_factor;
    source += 4;
    destination += 2;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRG32F,
          WebGLImageConversion::kAlphaDoUnmultiply,
          float,
          float>(const float* source,
                 float* destination,
                 unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 1.0f / source[3] : 1.0f;
    destination[0] = source[0] * scale_factor;
    destination[1] = source[1] * scale_factor;
    source += 4;
    destination += 2;
  }
}

bool HasAlpha(int format) {
  return format == WebGLImageConversion::kDataFormatA8 ||
         format == WebGLImageConversion::kDataFormatA16F ||
         format == WebGLImageConversion::kDataFormatA32F ||
         format == WebGLImageConversion::kDataFormatRA8 ||
         format == WebGLImageConversion::kDataFormatAR8 ||
         format == WebGLImageConversion::kDataFormatRA16F ||
         format == WebGLImageConversion::kDataFormatRA32F ||
         format == WebGLImageConversion::kDataFormatRGBA8 ||
         format == WebGLImageConversion::kDataFormatBGRA8 ||
         format == WebGLImageConversion::kDataFormatARGB8 ||
         format == WebGLImageConversion::kDataFormatABGR8 ||
         format == WebGLImageConversion::kDataFormatRGBA16F ||
         format == WebGLImageConversion::kDataFormatRGBA32F ||
         format == WebGLImageConversion::kDataFormatRGBA4444 ||
         format == WebGLImageConversion::kDataFormatRGBA5551 ||
         format == WebGLImageConversion::kDataFormatRGBA8_S ||
         format == WebGLImageConversion::kDataFormatRGBA16 ||
         format == WebGLImageConversion::kDataFormatRGBA16_S ||
         format == WebGLImageConversion::kDataFormatRGBA32 ||
         format == WebGLImageConversion::kDataFormatRGBA32_S ||
         format == WebGLImageConversion::kDataFormatRGBA2_10_10_10;
}

bool HasColor(int format) {
  return format == WebGLImageConversion::kDataFormatRGBA8 ||
         format == WebGLImageConversion::kDataFormatRGBA16F ||
         format == WebGLImageConversion::kDataFormatRGBA32F ||
         format == WebGLImageConversion::kDataFormatRGB8 ||
         format == WebGLImageConversion::kDataFormatRGB16F ||
         format == WebGLImageConversion::kDataFormatRGB32F ||
         format == WebGLImageConversion::kDataFormatBGR8 ||
         format == WebGLImageConversion::kDataFormatBGRA8 ||
         format == WebGLImageConversion::kDataFormatARGB8 ||
         format == WebGLImageConversion::kDataFormatABGR8 ||
         format == WebGLImageConversion::kDataFormatRGBA5551 ||
         format == WebGLImageConversion::kDataFormatRGBA4444 ||
         format == WebGLImageConversion::kDataFormatRGB565 ||
         format == WebGLImageConversion::kDataFormatR8 ||
         format == WebGLImageConversion::kDataFormatR16F ||
         format == WebGLImageConversion::kDataFormatR32F ||
         format == WebGLImageConversion::kDataFormatRA8 ||
         format == WebGLImageConversion::kDataFormatRA16F ||
         format == WebGLImageConversion::kDataFormatRA32F ||
         format == WebGLImageConversion::kDataFormatAR8 ||
         format == WebGLImageConversion::kDataFormatRGBA8_S ||
         format == WebGLImageConversion::kDataFormatRGBA16 ||
         format == WebGLImageConversion::kDataFormatRGBA16_S ||
         format == WebGLImageConversion::kDataFormatRGBA32 ||
         format == WebGLImageConversion::kDataFormatRGBA32_S ||
         format == WebGLImageConversion::kDataFormatRGBA2_10_10_10 ||
         format == WebGLImageConversion::kDataFormatRGB8_S ||
         format == WebGLImageConversion::kDataFormatRGB16 ||
         format == WebGLImageConversion::kDataFormatRGB16_S ||
         format == WebGLImageConversion::kDataFormatRGB32 ||
         format == WebGLImageConversion::kDataFormatRGB32_S ||
         format == WebGLImageConversion::kDataFormatRGB10F11F11F ||
         format == WebGLImageConversion::kDataFormatRGB5999 ||
         format == WebGLImageConversion::kDataFormatRG8 ||
         format == WebGLImageConversion::kDataFormatRG8_S ||
         format == WebGLImageConversion::kDataFormatRG16 ||
         format == WebGLImageConversion::kDataFormatRG16_S ||
         format == WebGLImageConversion::kDataFormatRG32 ||
         format == WebGLImageConversion::kDataFormatRG32_S ||
         format == WebGLImageConversion::kDataFormatRG16F ||
         format == WebGLImageConversion::kDataFormatRG32F ||
         format == WebGLImageConversion::kDataFormatR8_S ||
         format == WebGLImageConversion::kDataFormatR16 ||
         format == WebGLImageConversion::kDataFormatR16_S ||
         format == WebGLImageConversion::kDataFormatR32 ||
         format == WebGLImageConversion::kDataFormatR32_S;
}

template <int Format>
struct IsInt8Format {
  STATIC_ONLY(IsInt8Format);
  static const bool value =
      Format == WebGLImageConversion::kDataFormatRGBA8_S ||
      Format == WebGLImageConversion::kDataFormatRGB8_S ||
      Format == WebGLImageConversion::kDataFormatRG8_S ||
      Format == WebGLImageConversion::kDataFormatR8_S;
};

template <int Format>
struct IsInt16Format {
  STATIC_ONLY(IsInt16Format);
  static const bool value =
      Format == WebGLImageConversion::kDataFormatRGBA16_S ||
      Format == WebGLImageConversion::kDataFormatRGB16_S ||
      Format == WebGLImageConversion::kDataFormatRG16_S ||
      Format == WebGLImageConversion::kDataFormatR16_S;
};

template <int Format>
struct IsInt32Format {
  STATIC_ONLY(IsInt32Format);
  static const bool value =
      Format == WebGLImageConversion::kDataFormatRGBA32_S ||
      Format == WebGLImageConversion::kDataFormatRGB32_S ||
      Format == WebGLImageConversion::kDataFormatRG32_S ||
      Format == WebGLImageConversion::kDataFormatR32_S;
};

template <int Format>
struct IsUInt8Format {
  STATIC_ONLY(IsUInt8Format);
  static const bool value = Format == WebGLImageConversion::kDataFormatRGBA8 ||
                            Format == WebGLImageConversion::kDataFormatRGB8 ||
                            Format == WebGLImageConversion::kDataFormatRG8 ||
                            Format == WebGLImageConversion::kDataFormatR8 ||
                            Format == WebGLImageConversion::kDataFormatBGRA8 ||
                            Format == WebGLImageConversion::kDataFormatBGR8 ||
                            Format == WebGLImageConversion::kDataFormatARGB8 ||
                            Format == WebGLImageConversion::kDataFormatABGR8 ||
                            Format == WebGLImageConversion::kDataFormatRA8 ||
                            Format == WebGLImageConversion::kDataFormatAR8 ||
                            Format == WebGLImageConversion::kDataFormatA8;
};

template <int Format>
struct IsUInt16Format {
  STATIC_ONLY(IsUInt16Format);
  static const bool value = Format == WebGLImageConversion::kDataFormatRGBA16 ||
                            Format == WebGLImageConversion::kDataFormatRGB16 ||
                            Format == WebGLImageConversion::kDataFormatRG16 ||
                            Format == WebGLImageConversion::kDataFormatR16;
};

template <int Format>
struct IsUInt32Format {
  STATIC_ONLY(IsUInt32Format);
  static const bool value = Format == WebGLImageConversion::kDataFormatRGBA32 ||
                            Format == WebGLImageConversion::kDataFormatRGB32 ||
                            Format == WebGLImageConversion::kDataFormatRG32 ||
                            Format == WebGLImageConversion::kDataFormatR32;
};

template <int Format>
struct IsFloatFormat {
  STATIC_ONLY(IsFloatFormat);
  static const bool value =
      Format == WebGLImageConversion::kDataFormatRGBA32F ||
      Format == WebGLImageConversion::kDataFormatRGB32F ||
      Format == WebGLImageConversion::kDataFormatRA32F ||
      Format == WebGLImageConversion::kDataFormatR32F ||
      Format == WebGLImageConversion::kDataFormatA32F ||
      Format == WebGLImageConversion::kDataFormatRG32F;
};

template <int Format>
struct IsHalfFloatFormat {
  STATIC_ONLY(IsHalfFloatFormat);
  static const bool value =
      Format == WebGLImageConversion::kDataFormatRGBA16F ||
      Format == WebGLImageConversion::kDataFormatRGB16F ||
      Format == WebGLImageConversion::kDataFormatRA16F ||
      Format == WebGLImageConversion::kDataFormatR16F ||
      Format == WebGLImageConversion::kDataFormatA16F ||
      Format == WebGLImageConversion::kDataFormatRG16F;
};

template <int Format>
struct Is32bppFormat {
  STATIC_ONLY(Is32bppFormat);
  static const bool value =
      Format == WebGLImageConversion::kDataFormatRGBA2_10_10_10 ||
      Format == WebGLImageConversion::kDataFormatRGB5999 ||
      Format == WebGLImageConversion::kDataFormatRGB10F11F11F;
};

template <int Format>
struct Is16bppFormat {
  STATIC_ONLY(Is16bppFormat);
  static const bool value =
      Format == WebGLImageConversion::kDataFormatRGBA5551 ||
      Format == WebGLImageConversion::kDataFormatRGBA4444 ||
      Format == WebGLImageConversion::kDataFormatRGB565;
};

template <int Format,
          bool IsInt8Format = IsInt8Format<Format>::value,
          bool IsUInt8Format = IsUInt8Format<Format>::value,
          bool IsInt16Format = IsInt16Format<Format>::value,
          bool IsUInt16Format = IsUInt16Format<Format>::value,
          bool IsInt32Format = IsInt32Format<Format>::value,
          bool IsUInt32Format = IsUInt32Format<Format>::value,
          bool IsFloat = IsFloatFormat<Format>::value,
          bool IsHalfFloat = IsHalfFloatFormat<Format>::value,
          bool Is16bpp = Is16bppFormat<Format>::value,
          bool Is32bpp = Is32bppFormat<Format>::value>
struct DataTypeForFormat {
  STATIC_ONLY(DataTypeForFormat);
  typedef double Type;  // Use a type that's not used in unpack/pack.
};

template <int Format>
struct DataTypeForFormat<Format,
                         true,
                         false,
                         false,
                         false,
                         false,
                         false,
                         false,
                         false,
                         false,
                         false> {
  STATIC_ONLY(DataTypeForFormat);
  typedef int8_t Type;
};

template <int Format>
struct DataTypeForFormat<Format,
                         false,
                         true,
                         false,
                         false,
                         false,
                         false,
                         false,
                         false,
                         false,
                         false> {
  STATIC_ONLY(DataTypeForFormat);
  typedef uint8_t Type;
};

template <int Format>
struct DataTypeForFormat<Format,
                         false,
                         false,
                         true,
                         false,
                         false,
                         false,
                         false,
                         false,
                         false,
                         false> {
  STATIC_ONLY(DataTypeForFormat);
  typedef int16_t Type;
};

template <int Format>
struct DataTypeForFormat<Format,
                         false,
                         false,
                         false,
                         true,
                         false,
                         false,
                         false,
                         false,
                         false,
                         false> {
  STATIC_ONLY(DataTypeForFormat);
  typedef uint16_t Type;
};

template <int Format>
struct DataTypeForFormat<Format,
                         false,
                         false,
                         false,
                         false,
                         true,
                         false,
                         false,
                         false,
                         false,
                         false> {
  STATIC_ONLY(DataTypeForFormat);
  typedef int32_t Type;
};

template <int Format>
struct DataTypeForFormat<Format,
                         false,
                         false,
                         false,
                         false,
                         false,
                         true,
                         false,
                         false,
                         false,
                         false> {
  STATIC_ONLY(DataTypeForFormat);
  typedef uint32_t Type;
};

template <int Format>
struct DataTypeForFormat<Format,
                         false,
                         false,
                         false,
                         false,
                         false,
                         false,
                         true,
                         false,
                         false,
                         false> {
  STATIC_ONLY(DataTypeForFormat);
  typedef float Type;
};

template <int Format>
struct DataTypeForFormat<Format,
                         false,
                         false,
                         false,
                         false,
                         false,
                         false,
                         false,
                         true,
                         false,
                         false> {
  STATIC_ONLY(DataTypeForFormat);
  typedef uint16_t Type;
};

template <int Format>
struct DataTypeForFormat<Format,
                         false,
                         false,
                         false,
                         false,
                         false,
                         false,
                         false,
                         false,
                         true,
                         false> {
  STATIC_ONLY(DataTypeForFormat);
  typedef uint16_t Type;
};

template <int Format>
struct DataTypeForFormat<Format,
                         false,
                         false,
                         false,
                         false,
                         false,
                         false,
                         false,
                         false,
                         false,
                         true> {
  STATIC_ONLY(DataTypeForFormat);
  typedef uint32_t Type;
};

template <int Format>
struct UsesFloatIntermediateFormat {
  STATIC_ONLY(UsesFloatIntermediateFormat);
  static const bool value =
      IsFloatFormat<Format>::value || IsHalfFloatFormat<Format>::value ||
      Format == WebGLImageConversion::kDataFormatRGBA2_10_10_10 ||
      Format == WebGLImageConversion::kDataFormatRGB10F11F11F ||
      Format == WebGLImageConversion::kDataFormatRGB5999;
};

template <int Format>
struct IntermediateFormat {
  STATIC_ONLY(IntermediateFormat);
  static const int value =
      UsesFloatIntermediateFormat<Format>::value
          ? WebGLImageConversion::kDataFormatRGBA32F
          : IsInt32Format<Format>::value
                ? WebGLImageConversion::kDataFormatRGBA32_S
                : IsUInt32Format<Format>::value
                      ? WebGLImageConversion::kDataFormatRGBA32
                      : IsInt16Format<Format>::value
                            ? WebGLImageConversion::kDataFormatRGBA16_S
                            : (IsUInt16Format<Format>::value ||
                               Is32bppFormat<Format>::value)
                                  ? WebGLImageConversion::kDataFormatRGBA16
                                  : IsInt8Format<Format>::value
                                        ? WebGLImageConversion::
                                              kDataFormatRGBA8_S
                                        : WebGLImageConversion::
                                              kDataFormatRGBA8;
};

unsigned TexelBytesForFormat(WebGLImageConversion::DataFormat format) {
  switch (format) {
    case WebGLImageConversion::kDataFormatR8:
    case WebGLImageConversion::kDataFormatR8_S:
    case WebGLImageConversion::kDataFormatA8:
      return 1;
    case WebGLImageConversion::kDataFormatRG8:
    case WebGLImageConversion::kDataFormatRG8_S:
    case WebGLImageConversion::kDataFormatRA8:
    case WebGLImageConversion::kDataFormatAR8:
    case WebGLImageConversion::kDataFormatRGBA5551:
    case WebGLImageConversion::kDataFormatRGBA4444:
    case WebGLImageConversion::kDataFormatRGB565:
    case WebGLImageConversion::kDataFormatA16F:
    case WebGLImageConversion::kDataFormatR16:
    case WebGLImageConversion::kDataFormatR16_S:
    case WebGLImageConversion::kDataFormatR16F:
    case WebGLImageConversion::kDataFormatD16:
      return 2;
    case WebGLImageConversion::kDataFormatRGB8:
    case WebGLImageConversion::kDataFormatRGB8_S:
    case WebGLImageConversion::kDataFormatBGR8:
      return 3;
    case WebGLImageConversion::kDataFormatRGBA8:
    case WebGLImageConversion::kDataFormatRGBA8_S:
    case WebGLImageConversion::kDataFormatARGB8:
    case WebGLImageConversion::kDataFormatABGR8:
    case WebGLImageConversion::kDataFormatBGRA8:
    case WebGLImageConversion::kDataFormatR32:
    case WebGLImageConversion::kDataFormatR32_S:
    case WebGLImageConversion::kDataFormatR32F:
    case WebGLImageConversion::kDataFormatA32F:
    case WebGLImageConversion::kDataFormatRA16F:
    case WebGLImageConversion::kDataFormatRGBA2_10_10_10:
    case WebGLImageConversion::kDataFormatRGB10F11F11F:
    case WebGLImageConversion::kDataFormatRGB5999:
    case WebGLImageConversion::kDataFormatRG16:
    case WebGLImageConversion::kDataFormatRG16_S:
    case WebGLImageConversion::kDataFormatRG16F:
    case WebGLImageConversion::kDataFormatD32:
    case WebGLImageConversion::kDataFormatD32F:
    case WebGLImageConversion::kDataFormatDS24_8:
      return 4;
    case WebGLImageConversion::kDataFormatRGB16:
    case WebGLImageConversion::kDataFormatRGB16_S:
    case WebGLImageConversion::kDataFormatRGB16F:
      return 6;
    case WebGLImageConversion::kDataFormatRGBA16:
    case WebGLImageConversion::kDataFormatRGBA16_S:
    case WebGLImageConversion::kDataFormatRA32F:
    case WebGLImageConversion::kDataFormatRGBA16F:
    case WebGLImageConversion::kDataFormatRG32:
    case WebGLImageConversion::kDataFormatRG32_S:
    case WebGLImageConversion::kDataFormatRG32F:
      return 8;
    case WebGLImageConversion::kDataFormatRGB32:
    case WebGLImageConversion::kDataFormatRGB32_S:
    case WebGLImageConversion::kDataFormatRGB32F:
      return 12;
    case WebGLImageConversion::kDataFormatRGBA32:
    case WebGLImageConversion::kDataFormatRGBA32_S:
    case WebGLImageConversion::kDataFormatRGBA32F:
      return 16;
    default:
      return 0;
  }
}

/* END CODE SHARED WITH MOZILLA FIREFOX */

class FormatConverter {
  STACK_ALLOCATED();

 public:
  FormatConverter(const gfx::Rect& source_data_sub_rectangle,
                  int depth,
                  int unpack_image_height,
                  const void* src_start,
                  void* dst_start,
                  int src_stride,
                  int src_row_offset,
                  int dst_stride)
      : src_sub_rectangle_(source_data_sub_rectangle),
        depth_(depth),
        unpack_image_height_(unpack_image_height),
        src_start_(src_start),
        dst_start_(dst_start),
        src_stride_(src_stride),
        src_row_offset_(src_row_offset),
        dst_stride_(dst_stride),
        success_(false) {
    const unsigned kMaxNumberOfComponents = 4;
    const unsigned kMaxBytesPerComponent = 4;
    unpacked_intermediate_src_data_ = std::make_unique<uint8_t[]>(
        src_sub_rectangle_.width() * kMaxNumberOfComponents *
        kMaxBytesPerComponent);
    DCHECK(unpacked_intermediate_src_data_.get());
  }

  void Convert(WebGLImageConversion::DataFormat src_format,
               WebGLImageConversion::DataFormat dst_format,
               WebGLImageConversion::AlphaOp);
  bool Success() const { return success_; }

 private:
  template <WebGLImageConversion::DataFormat SrcFormat>
  void Convert(WebGLImageConversion::DataFormat dst_format,
               WebGLImageConversion::AlphaOp);

  template <WebGLImageConversion::DataFormat SrcFormat,
            WebGLImageConversion::DataFormat DstFormat>
  void Convert(WebGLImageConversion::AlphaOp);

  template <WebGLImageConversion::DataFormat SrcFormat,
            WebGLImageConversion::DataFormat DstFormat,
            WebGLImageConversion::AlphaOp alphaOp>
  void Convert();

  const gfx::Rect& src_sub_rectangle_;
  const int depth_;
  const int unpack_image_height_;
  const void* const src_start_;
  
"""


```