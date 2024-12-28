Response:
My thinking process to answer the request about the `webgl_image_conversion.cc` file goes through these stages:

1. **Understanding the Core Function:** I first recognize that the code deals with image data manipulation, specifically within the context of WebGL. The numerous `template <> void Pack<...>` functions strongly suggest that the primary function is to convert image data between different formats. The template parameters likely represent source and destination data types, pixel formats (like RGB, RGBA), and alpha handling methods.

2. **Identifying Key Data Conversion Aspects:** I look for recurring patterns and concepts within the code. The presence of "Pack," different data formats (e.g., RGB8, RGBA8, RGB565, float, uint8_t, uint16_t), and alpha handling options (Premultiply, Unmultiply, Nothing) stand out. This tells me the code handles various ways image data can be represented in memory.

3. **Relating to WebGL:**  The filename itself includes "WebGL," which is a crucial connection. WebGL deals with rendering 2D and 3D graphics in a web browser. Image data is a fundamental part of texturing and other visual elements in WebGL. Therefore, this code is likely involved in preparing image data for use within WebGL.

4. **Considering Browser Context:** Since it's part of Chromium's Blink engine, I know this code runs within a web browser. This means it interacts with other browser components and handles data coming from various sources within the browser.

5. **Connecting to Web Technologies (HTML, CSS, JavaScript):**
    * **JavaScript:**  WebGL APIs are exposed through JavaScript. JavaScript code uses these APIs to upload image data to the GPU. This conversion code is the *underlying mechanism* that makes this JavaScript functionality possible. I look for keywords that hint at this interaction, such as data types commonly used in JavaScript's WebGL API (like `Uint8Array`, `Float32Array`).
    * **HTML:** The `<canvas>` element is the target for WebGL rendering. Images loaded through `<img>` tags or fetched via JavaScript can be used as WebGL textures. This conversion code handles the preparation of that image data.
    * **CSS:**  While less direct, CSS can influence how images are presented, and those images might eventually be used in WebGL. For example, a CSS filter might be applied to an image before it's uploaded as a texture.

6. **Inferring Logic and Assumptions:** The code heavily relies on loops and bitwise operations. The scaling and clamping functions are evident. I can infer that the input is likely an array of pixel data, and the code iterates through it, converting each pixel according to the specified format and alpha handling. I can create hypothetical inputs and trace the output based on the code. For example, for `RGBA8` to `RGB8` with no alpha, the alpha channel is simply discarded.

7. **Identifying Potential Errors:**  Based on the code's operations, I can consider common pitfalls. Incorrect data types in JavaScript when uploading textures, mismatches between the image format and the WebGL texture format, and misunderstanding alpha premultiplication are all potential user errors that this code (or the broader system) is designed to handle (or at least be a part of). Division by zero when unmultiplying alpha is a specific error I can see the code attempting to handle with the `source[3] ? ... : 1.0f` check.

8. **Structuring the Answer:** I organize my findings into the requested categories: functionality, relationship to web technologies, logical reasoning, and user errors. I use clear examples to illustrate the connections.

9. **Focusing on the Provided Snippet:** Although the request mentions the entire file, I concentrate my analysis on the provided code snippets. I recognize that this is a section dealing specifically with the `Pack` function templates.

10. **Synthesizing the Summary:** Finally, I summarize the main purpose of this specific part of the file: pixel data format conversion with various options for alpha handling. I emphasize the role of templates in providing flexibility and the connection to WebGL's texture uploading process.

By following these steps, I can break down the code, understand its purpose, connect it to the broader web development context, and formulate a comprehensive answer. The iterative nature of this process is important – I might revisit earlier steps as I discover more about the code. For instance, seeing the SIMD optimizations reinforces the idea that this is performance-critical code within the rendering pipeline.

好的，让我们来归纳一下这段代码的功能。

**功能归纳：**

这段代码主要定义了一系列的模板函数 `Pack`，用于将源图像数据转换为目标图像数据，并支持多种像素格式和不同的 Alpha 处理方式。

具体来说，这些 `Pack` 函数实现了以下功能：

1. **像素格式转换：**  将源像素数据从一种格式转换为另一种格式。例如，从 RGBA（红绿蓝透明度）转换为 RGB（红绿蓝），或者在不同的位深度之间转换，比如 RGB8 (每个颜色通道 8 位) 到 RGB565 (红色 5 位，绿色 6 位，蓝色 5 位)。

2. **数据类型转换：**  支持不同的源数据类型和目标数据类型。例如，可以将 `float` 类型的像素数据转换为 `uint8_t` 类型的像素数据，或者在 `uint8_t` 和 `uint16_t` 之间转换。

3. **Alpha 处理：**  提供不同的 Alpha 处理策略：
    * `kAlphaDoNothing`: 不对 Alpha 通道做任何处理。
    * `kAlphaDoPremultiply`:  预乘 Alpha。将 RGB 分量乘以 Alpha 值。
    * `kAlphaDoUnmultiply`: 反预乘 Alpha。将 RGB 分量除以 Alpha 值。

4. **逐像素处理：**  这些函数通常以逐像素的方式处理图像数据，通过循环遍历每个像素，并根据指定的转换规则进行计算。

5. **SIMD 优化：**  在某些架构下（例如 x86、ARM NEON、MIPS MSA、LoongArch），代码使用了 SIMD (单指令多数据) 指令集进行优化，可以一次处理多个像素，提高转换效率。

**与 javascript, html, css 的功能关系举例：**

这段 C++ 代码是浏览器底层实现的一部分，它直接与 WebGL API 相关联，而 WebGL API 是 JavaScript 可以调用的。

1. **JavaScript 和 WebGL 的 `texImage2D` / `texSubImage2D`：**  当 JavaScript 代码使用 WebGL 的 `texImage2D` 或 `texSubImage2D` 方法上传图像数据到 GPU 时，浏览器底层可能会调用这段代码中的 `Pack` 函数来进行必要的格式转换。

   **举例说明：**

   * **假设输入（JavaScript）：**  一个 `ImageData` 对象，其数据格式为 RGBA8 (每个像素 4 个字节，红绿蓝和 Alpha)。
   * **假设输出（WebGL 纹理）：**  需要创建一个 RGB565 格式的纹理（每个像素 2 个字节）。
   * **`webgl_image_conversion.cc` 的作用：**  浏览器底层会选择合适的 `Pack` 模板函数，例如 `Pack<WebGLImageConversion::kDataFormatRGB565, WebGLImageConversion::kAlphaDoNothing, uint8_t, uint16_t>`，将 `ImageData` 中的 RGBA8 数据转换为 RGB565 格式，然后再上传到 GPU。

2. **HTML `<img>` 标签和 CSS 背景图片：**  当 HTML 中使用 `<img>` 标签加载图片，或者 CSS 中使用 `background-image` 设置背景图片时，这些图片最终也可能被用作 WebGL 的纹理。浏览器需要将这些图片解码并转换为 WebGL 可以接受的格式，`webgl_image_conversion.cc` 中的代码可能参与了这个转换过程。

   **举例说明：**

   * **假设输入（HTML `<img>`）：** 一个 PNG 格式的图片，其内部数据可能是 RGBA。
   * **假设输出（WebGL 纹理）：**  需要在 WebGL 中创建一个 RGB 格式的纹理。
   * **`webgl_image_conversion.cc` 的作用：**  在将 PNG 图片作为 WebGL 纹理上传之前，浏览器可能会使用 `Pack` 函数将 RGBA 数据转换为 RGB 数据，丢弃 Alpha 通道。

**逻辑推理的假设输入与输出：**

让我们以一个具体的 `Pack` 函数为例进行逻辑推理：

**选择的 `Pack` 函数：**

```c++
template <>
void Pack<WebGLImageConversion::kDataFormatRGB8,
          WebGLImageConversion::kAlphaDoNothing,
          uint8_t,
          uint8_t>(const uint8_t* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = source[0];
    destination[1] = source[1];
    destination[2] = source[2];
    source += 4;
    destination += 3;
  }
}
```

**假设输入：**

* `source`: 一个指向 `uint8_t` 数组的指针，包含 RGBA 格式的像素数据。例如，前 4 个字节是第一个像素的 R、G、B、A 值，分别为 255, 0, 0, 255 (红色不透明)。
* `destination`: 一个指向 `uint8_t` 数组的指针，用于存储转换后的 RGB 数据。
* `pixels_per_row`:  1 (假设只转换一个像素)。

**逻辑推理：**

1. 循环开始，`i = 0`。
2. `destination[0]` 被赋值为 `source[0]`，即 255 (红色)。
3. `destination[1]` 被赋值为 `source[1]`，即 0 (绿色)。
4. `destination[2]` 被赋值为 `source[2]`，即 0 (蓝色)。
5. `source` 指针向前移动 4 个字节，指向下一个像素（如果存在）。
6. `destination` 指针向前移动 3 个字节，准备存储下一个 RGB 像素。
7. 循环结束。

**假设输出：**

* `destination` 指向的数组的前 3 个字节将是 255, 0, 0，表示一个红色的 RGB 像素。  Alpha 通道被丢弃。

**涉及用户或编程常见的使用错误举例：**

1. **数据类型不匹配：**  在 JavaScript 中，如果尝试使用一个 `Float32Array` 来提供 `uint8_t` 类型的纹理数据，可能会导致数据解析错误或崩溃。这段 C++ 代码虽然会尝试进行转换，但如果源数据类型和目标数据类型完全不兼容，可能会产生意想不到的结果。

   **例子：** JavaScript 代码尝试将一个包含浮点数值 (0.0 到 1.0) 的数组上传到一个预期 `uint8_t` (0 到 255) 数据的纹理，且没有进行适当的缩放。

2. **Alpha 预乘/反预乘错误：**  如果在上传纹理时，对 Alpha 预乘的理解有误，或者 WebGL 的状态设置不正确，可能会导致渲染结果中的颜色和透明度不正确。

   **例子：**  JavaScript 代码上传了已经预乘 Alpha 的图像数据，但没有在 WebGL 中启用相应的混合模式，导致颜色看起来偏暗。反之，如果数据没有预乘 Alpha，但 WebGL 期望预乘的数据，也会出现问题。

3. **纹理格式不匹配：**  创建 WebGL 纹理时指定的格式与上传的图像数据格式不一致。

   **例子：**  JavaScript 代码创建了一个 `gl.RGB` 格式的纹理，但尝试上传包含 Alpha 通道的 RGBA 数据。这段 C++ 代码可能会尝试提取 RGB 分量，但 Alpha 通道会被忽略，这可能不是用户期望的结果。

总而言之，这段代码是 Chromium 浏览器 Blink 引擎中负责 WebGL 图像数据转换的关键部分，它确保了各种来源和格式的图像数据能够被正确地加载到 GPU 中，用于 WebGL 的渲染过程。它通过模板实现对多种数据格式和 Alpha 处理方式的支持，并利用 SIMD 指令进行性能优化。用户在使用 WebGL API 时，需要注意数据类型、Alpha 预乘以及纹理格式的匹配，以避免出现错误。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/gpu/webgl_image_conversion.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能

"""
t8_t source_r =
        static_cast<uint8_t>(static_cast<float>(source[0]) * scale_factor);
    uint8_t source_g =
        static_cast<uint8_t>(static_cast<float>(source[1]) * scale_factor);
    uint8_t source_b =
        static_cast<uint8_t>(static_cast<float>(source[2]) * scale_factor);
    destination[0] = source_r;
    destination[1] = source_g;
    destination[2] = source_b;
    source += 4;
    destination += 3;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGB8,
          WebGLImageConversion::kAlphaDoPremultiply,
          float,
          uint8_t>(const float* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = ClampAndScaleFloat<uint8_t>(source[0] * source[3]);
    destination[1] = ClampAndScaleFloat<uint8_t>(source[1] * source[3]);
    destination[2] = ClampAndScaleFloat<uint8_t>(source[2] * source[3]);
    source += 4;
    destination += 3;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGB8,
          WebGLImageConversion::kAlphaDoUnmultiply,
          uint8_t,
          uint8_t>(const uint8_t* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 255.0f / source[3] : 1.0f;
    uint8_t source_r =
        static_cast<uint8_t>(static_cast<float>(source[0]) * scale_factor);
    uint8_t source_g =
        static_cast<uint8_t>(static_cast<float>(source[1]) * scale_factor);
    uint8_t source_b =
        static_cast<uint8_t>(static_cast<float>(source[2]) * scale_factor);
    destination[0] = source_r;
    destination[1] = source_g;
    destination[2] = source_b;
    source += 4;
    destination += 3;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGB8,
          WebGLImageConversion::kAlphaDoUnmultiply,
          float,
          uint8_t>(const float* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 1.0f / source[3] : 1.0f;
    destination[0] = ClampAndScaleFloat<uint8_t>(source[0] * scale_factor);
    destination[1] = ClampAndScaleFloat<uint8_t>(source[1] * scale_factor);
    destination[2] = ClampAndScaleFloat<uint8_t>(source[2] * scale_factor);
    source += 4;
    destination += 3;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA8,
          WebGLImageConversion::kAlphaDoPremultiply,
          uint8_t,
          uint8_t>(const uint8_t* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] / 255.0f;
    uint8_t source_r =
        static_cast<uint8_t>(static_cast<float>(source[0]) * scale_factor);
    uint8_t source_g =
        static_cast<uint8_t>(static_cast<float>(source[1]) * scale_factor);
    uint8_t source_b =
        static_cast<uint8_t>(static_cast<float>(source[2]) * scale_factor);
    destination[0] = source_r;
    destination[1] = source_g;
    destination[2] = source_b;
    destination[3] = source[3];
    source += 4;
    destination += 4;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA8,
          WebGLImageConversion::kAlphaDoPremultiply,
          float,
          uint8_t>(const float* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = ClampAndScaleFloat<uint8_t>(source[0] * source[3]);
    destination[1] = ClampAndScaleFloat<uint8_t>(source[1] * source[3]);
    destination[2] = ClampAndScaleFloat<uint8_t>(source[2] * source[3]);
    destination[3] = ClampAndScaleFloat<uint8_t>(source[3]);
    source += 4;
    destination += 4;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA8,
          WebGLImageConversion::kAlphaDoUnmultiply,
          uint8_t,
          uint8_t>(const uint8_t* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
#if defined(ARCH_CPU_X86_FAMILY)
  simd::PackOneRowOfRGBA8LittleToRGBA8(source, destination, pixels_per_row);
#endif
#if defined(HAVE_MIPS_MSA_INTRINSICS)
  simd::packOneRowOfRGBA8LittleToRGBA8MSA(source, destination, pixels_per_row);
#endif
#if defined(ARCH_CPU_LOONGARCH_FAMILY)
  simd::PackOneRowOfRGBA8LittleToRGBA8(source, destination, pixels_per_row);
#endif
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 255.0f / source[3] : 1.0f;
    uint8_t source_r =
        static_cast<uint8_t>(static_cast<float>(source[0]) * scale_factor);
    uint8_t source_g =
        static_cast<uint8_t>(static_cast<float>(source[1]) * scale_factor);
    uint8_t source_b =
        static_cast<uint8_t>(static_cast<float>(source[2]) * scale_factor);
    destination[0] = source_r;
    destination[1] = source_g;
    destination[2] = source_b;
    destination[3] = source[3];
    source += 4;
    destination += 4;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA8,
          WebGLImageConversion::kAlphaDoUnmultiply,
          float,
          uint8_t>(const float* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 1.0f / source[3] : 1.0f;
    destination[0] = ClampAndScaleFloat<uint8_t>(source[0] * scale_factor);
    destination[1] = ClampAndScaleFloat<uint8_t>(source[1] * scale_factor);
    destination[2] = ClampAndScaleFloat<uint8_t>(source[2] * scale_factor);
    destination[3] = ClampAndScaleFloat<uint8_t>(source[3]);
    source += 4;
    destination += 4;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA4444,
          WebGLImageConversion::kAlphaDoNothing,
          uint8_t,
          uint16_t>(const uint8_t* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
#if defined(CPU_ARM_NEON)
  simd::PackOneRowOfRGBA8ToUnsignedShort4444(source, destination,
                                             pixels_per_row);
#endif
#if defined(HAVE_MIPS_MSA_INTRINSICS)
  simd::packOneRowOfRGBA8ToUnsignedShort4444MSA(source, destination,
                                                pixels_per_row);
#endif
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    *destination = (((source[0] & 0xF0) << 8) | ((source[1] & 0xF0) << 4) |
                    (source[2] & 0xF0) | (source[3] >> 4));
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA4444,
          WebGLImageConversion::kAlphaDoNothing,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    uint8_t r = ClampAndScaleFloat<uint8_t>(source[0]);
    uint8_t g = ClampAndScaleFloat<uint8_t>(source[1]);
    uint8_t b = ClampAndScaleFloat<uint8_t>(source[2]);
    uint8_t a = ClampAndScaleFloat<uint8_t>(source[3]);
    *destination =
        (((r & 0xF0) << 8) | ((g & 0xF0) << 4) | (b & 0xF0) | (a >> 4));
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA4444,
          WebGLImageConversion::kAlphaDoPremultiply,
          uint8_t,
          uint16_t>(const uint8_t* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] / 255.0f;
    uint8_t source_r =
        static_cast<uint8_t>(static_cast<float>(source[0]) * scale_factor);
    uint8_t source_g =
        static_cast<uint8_t>(static_cast<float>(source[1]) * scale_factor);
    uint8_t source_b =
        static_cast<uint8_t>(static_cast<float>(source[2]) * scale_factor);
    *destination = (((source_r & 0xF0) << 8) | ((source_g & 0xF0) << 4) |
                    (source_b & 0xF0) | (source[3] >> 4));
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA4444,
          WebGLImageConversion::kAlphaDoPremultiply,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    uint8_t r = ClampAndScaleFloat<uint8_t>(source[0] * source[3]);
    uint8_t g = ClampAndScaleFloat<uint8_t>(source[1] * source[3]);
    uint8_t b = ClampAndScaleFloat<uint8_t>(source[2] * source[3]);
    uint8_t a = ClampAndScaleFloat<uint8_t>(source[3]);
    *destination =
        (((r & 0xF0) << 8) | ((g & 0xF0) << 4) | (b & 0xF0) | (a >> 4));
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA4444,
          WebGLImageConversion::kAlphaDoUnmultiply,
          uint8_t,
          uint16_t>(const uint8_t* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 255.0f / source[3] : 1.0f;
    uint8_t source_r =
        static_cast<uint8_t>(static_cast<float>(source[0]) * scale_factor);
    uint8_t source_g =
        static_cast<uint8_t>(static_cast<float>(source[1]) * scale_factor);
    uint8_t source_b =
        static_cast<uint8_t>(static_cast<float>(source[2]) * scale_factor);
    *destination = (((source_r & 0xF0) << 8) | ((source_g & 0xF0) << 4) |
                    (source_b & 0xF0) | (source[3] >> 4));
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA4444,
          WebGLImageConversion::kAlphaDoUnmultiply,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 1.0f / source[3] : 1.0f;
    uint8_t r = ClampAndScaleFloat<uint8_t>(source[0] * scale_factor);
    uint8_t g = ClampAndScaleFloat<uint8_t>(source[1] * scale_factor);
    uint8_t b = ClampAndScaleFloat<uint8_t>(source[2] * scale_factor);
    uint8_t a = ClampAndScaleFloat<uint8_t>(source[3]);
    *destination =
        (((r & 0xF0) << 8) | ((g & 0xF0) << 4) | (b & 0xF0) | (a >> 4));
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA5551,
          WebGLImageConversion::kAlphaDoNothing,
          uint8_t,
          uint16_t>(const uint8_t* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
#if defined(CPU_ARM_NEON)
  simd::PackOneRowOfRGBA8ToUnsignedShort5551(source, destination,
                                             pixels_per_row);
#endif
#if defined(HAVE_MIPS_MSA_INTRINSICS)
  simd::packOneRowOfRGBA8ToUnsignedShort5551MSA(source, destination,
                                                pixels_per_row);
#endif
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    *destination = (((source[0] & 0xF8) << 8) | ((source[1] & 0xF8) << 3) |
                    ((source[2] & 0xF8) >> 2) | (source[3] >> 7));
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA5551,
          WebGLImageConversion::kAlphaDoNothing,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    uint8_t r = ClampAndScaleFloat<uint8_t>(source[0]);
    uint8_t g = ClampAndScaleFloat<uint8_t>(source[1]);
    uint8_t b = ClampAndScaleFloat<uint8_t>(source[2]);
    uint8_t a = ClampAndScaleFloat<uint8_t>(source[3]);
    *destination =
        (((r & 0xF8) << 8) | ((g & 0xF8) << 3) | ((b & 0xF8) >> 2) | (a >> 7));
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA5551,
          WebGLImageConversion::kAlphaDoPremultiply,
          uint8_t,
          uint16_t>(const uint8_t* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] / 255.0f;
    uint8_t source_r =
        static_cast<uint8_t>(static_cast<float>(source[0]) * scale_factor);
    uint8_t source_g =
        static_cast<uint8_t>(static_cast<float>(source[1]) * scale_factor);
    uint8_t source_b =
        static_cast<uint8_t>(static_cast<float>(source[2]) * scale_factor);
    *destination = (((source_r & 0xF8) << 8) | ((source_g & 0xF8) << 3) |
                    ((source_b & 0xF8) >> 2) | (source[3] >> 7));
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA5551,
          WebGLImageConversion::kAlphaDoPremultiply,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    uint8_t r = ClampAndScaleFloat<uint8_t>(source[0] * source[3]);
    uint8_t g = ClampAndScaleFloat<uint8_t>(source[1] * source[3]);
    uint8_t b = ClampAndScaleFloat<uint8_t>(source[2] * source[3]);
    uint8_t a = ClampAndScaleFloat<uint8_t>(source[3]);
    *destination =
        (((r & 0xF8) << 8) | ((g & 0xF8) << 3) | ((b & 0xF8) >> 2) | (a >> 7));
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA5551,
          WebGLImageConversion::kAlphaDoUnmultiply,
          uint8_t,
          uint16_t>(const uint8_t* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 255.0f / source[3] : 1.0f;
    uint8_t source_r =
        static_cast<uint8_t>(static_cast<float>(source[0]) * scale_factor);
    uint8_t source_g =
        static_cast<uint8_t>(static_cast<float>(source[1]) * scale_factor);
    uint8_t source_b =
        static_cast<uint8_t>(static_cast<float>(source[2]) * scale_factor);
    *destination = (((source_r & 0xF8) << 8) | ((source_g & 0xF8) << 3) |
                    ((source_b & 0xF8) >> 2) | (source[3] >> 7));
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA5551,
          WebGLImageConversion::kAlphaDoUnmultiply,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 1.0f / source[3] : 1.0f;
    uint8_t r = ClampAndScaleFloat<uint8_t>(source[0] * scale_factor);
    uint8_t g = ClampAndScaleFloat<uint8_t>(source[1] * scale_factor);
    uint8_t b = ClampAndScaleFloat<uint8_t>(source[2] * scale_factor);
    uint8_t a = ClampAndScaleFloat<uint8_t>(source[3]);
    *destination =
        (((r & 0xF8) << 8) | ((g & 0xF8) << 3) | ((b & 0xF8) >> 2) | (a >> 7));
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGB565,
          WebGLImageConversion::kAlphaDoNothing,
          uint8_t,
          uint16_t>(const uint8_t* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
#if defined(CPU_ARM_NEON)
  simd::PackOneRowOfRGBA8ToUnsignedShort565(source, destination,
                                            pixels_per_row);
#endif
#if defined(HAVE_MIPS_MSA_INTRINSICS)
  simd::packOneRowOfRGBA8ToUnsignedShort565MSA(source, destination,
                                               pixels_per_row);
#endif
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    *destination = (((source[0] & 0xF8) << 8) | ((source[1] & 0xFC) << 3) |
                    ((source[2] & 0xF8) >> 3));
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGB565,
          WebGLImageConversion::kAlphaDoNothing,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    uint8_t r = ClampAndScaleFloat<uint8_t>(source[0]);
    uint8_t g = ClampAndScaleFloat<uint8_t>(source[1]);
    uint8_t b = ClampAndScaleFloat<uint8_t>(source[2]);
    *destination = (((r & 0xF8) << 8) | ((g & 0xFC) << 3) | ((b & 0xF8) >> 3));
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGB565,
          WebGLImageConversion::kAlphaDoPremultiply,
          uint8_t,
          uint16_t>(const uint8_t* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] / 255.0f;
    uint8_t source_r =
        static_cast<uint8_t>(static_cast<float>(source[0]) * scale_factor);
    uint8_t source_g =
        static_cast<uint8_t>(static_cast<float>(source[1]) * scale_factor);
    uint8_t source_b =
        static_cast<uint8_t>(static_cast<float>(source[2]) * scale_factor);
    *destination = (((source_r & 0xF8) << 8) | ((source_g & 0xFC) << 3) |
                    ((source_b & 0xF8) >> 3));
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGB565,
          WebGLImageConversion::kAlphaDoPremultiply,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    uint8_t r = ClampAndScaleFloat<uint8_t>(source[0] * source[3]);
    uint8_t g = ClampAndScaleFloat<uint8_t>(source[1] * source[3]);
    uint8_t b = ClampAndScaleFloat<uint8_t>(source[2] * source[3]);
    *destination = (((r & 0xF8) << 8) | ((g & 0xFC) << 3) | ((b & 0xF8) >> 3));
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGB565,
          WebGLImageConversion::kAlphaDoUnmultiply,
          uint8_t,
          uint16_t>(const uint8_t* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 255.0f / source[3] : 1.0f;
    uint8_t source_r =
        static_cast<uint8_t>(static_cast<float>(source[0]) * scale_factor);
    uint8_t source_g =
        static_cast<uint8_t>(static_cast<float>(source[1]) * scale_factor);
    uint8_t source_b =
        static_cast<uint8_t>(static_cast<float>(source[2]) * scale_factor);
    *destination = (((source_r & 0xF8) << 8) | ((source_g & 0xFC) << 3) |
                    ((source_b & 0xF8) >> 3));
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGB565,
          WebGLImageConversion::kAlphaDoUnmultiply,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 1.0f / source[3] : 1.0f;
    uint8_t r = ClampAndScaleFloat<uint8_t>(source[0] * scale_factor);
    uint8_t g = ClampAndScaleFloat<uint8_t>(source[1] * scale_factor);
    uint8_t b = ClampAndScaleFloat<uint8_t>(source[2] * scale_factor);
    *destination = (((r & 0xF8) << 8) | ((g & 0xFC) << 3) | ((b & 0xF8) >> 3));
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGB32F,
          WebGLImageConversion::kAlphaDoNothing,
          float,
          float>(const float* source,
                 float* destination,
                 unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = source[0];
    destination[1] = source[1];
    destination[2] = source[2];
    source += 4;
    destination += 3;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGB32F,
          WebGLImageConversion::kAlphaDoPremultiply,
          float,
          float>(const float* source,
                 float* destination,
                 unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3];
    destination[0] = source[0] * scale_factor;
    destination[1] = source[1] * scale_factor;
    destination[2] = source[2] * scale_factor;
    source += 4;
    destination += 3;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGB32F,
          WebGLImageConversion::kAlphaDoUnmultiply,
          float,
          float>(const float* source,
                 float* destination,
                 unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 1.0f / source[3] : 1.0f;
    destination[0] = source[0] * scale_factor;
    destination[1] = source[1] * scale_factor;
    destination[2] = source[2] * scale_factor;
    source += 4;
    destination += 3;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA32F,
          WebGLImageConversion::kAlphaDoPremultiply,
          float,
          float>(const float* source,
                 float* destination,
                 unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3];
    destination[0] = source[0] * scale_factor;
    destination[1] = source[1] * scale_factor;
    destination[2] = source[2] * scale_factor;
    destination[3] = source[3];
    source += 4;
    destination += 4;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA32F,
          WebGLImageConversion::kAlphaDoUnmultiply,
          float,
          float>(const float* source,
                 float* destination,
                 unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 1.0f / source[3] : 1.0f;
    destination[0] = source[0] * scale_factor;
    destination[1] = source[1] * scale_factor;
    destination[2] = source[2] * scale_factor;
    destination[3] = source[3];
    source += 4;
    destination += 4;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatA32F,
          WebGLImageConversion::kAlphaDoNothing,
          float,
          float>(const float* source,
                 float* destination,
                 unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = source[3];
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatR32F,
          WebGLImageConversion::kAlphaDoNothing,
          float,
          float>(const float* source,
                 float* destination,
                 unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = source[0];
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatR32F,
          WebGLImageConversion::kAlphaDoPremultiply,
          float,
          float>(const float* source,
                 float* destination,
                 unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3];
    destination[0] = source[0] * scale_factor;
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatR32F,
          WebGLImageConversion::kAlphaDoUnmultiply,
          float,
          float>(const float* source,
                 float* destination,
                 unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 1.0f / source[3] : 1.0f;
    destination[0] = source[0] * scale_factor;
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRA32F,
          WebGLImageConversion::kAlphaDoNothing,
          float,
          float>(const float* source,
                 float* destination,
                 unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = source[0];
    destination[1] = source[3];
    source += 4;
    destination += 2;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRA32F,
          WebGLImageConversion::kAlphaDoPremultiply,
          float,
          float>(const float* source,
                 float* destination,
                 unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3];
    destination[0] = source[0] * scale_factor;
    destination[1] = source[3];
    source += 4;
    destination += 2;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRA32F,
          WebGLImageConversion::kAlphaDoUnmultiply,
          float,
          float>(const float* source,
                 float* destination,
                 unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 1.0f / source[3] : 1.0f;
    destination[0] = source[0] * scale_factor;
    destination[1] = source[3];
    source += 4;
    destination += 2;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA16F,
          WebGLImageConversion::kAlphaDoNothing,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = ConvertFloatToHalfFloat(source[0]);
    destination[1] = ConvertFloatToHalfFloat(source[1]);
    destination[2] = ConvertFloatToHalfFloat(source[2]);
    destination[3] = ConvertFloatToHalfFloat(source[3]);
    source += 4;
    destination += 4;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA16F,
          WebGLImageConversion::kAlphaDoPremultiply,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3];
    destination[0] = ConvertFloatToHalfFloat(source[0] * scale_factor);
    destination[1] = ConvertFloatToHalfFloat(source[1] * scale_factor);
    destination[2] = ConvertFloatToHalfFloat(source[2] * scale_factor);
    destination[3] = ConvertFloatToHalfFloat(source[3]);
    source += 4;
    destination += 4;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA16F,
          WebGLImageConversion::kAlphaDoUnmultiply,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 1.0f / source[3] : 1.0f;
    destination[0] = ConvertFloatToHalfFloat(source[0] * scale_factor);
    destination[1] = ConvertFloatToHalfFloat(source[1] * scale_factor);
    destination[2] = ConvertFloatToHalfFloat(source[2] * scale_factor);
    destination[3] = ConvertFloatToHalfFloat(source[3]);
    source += 4;
    destination += 4;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGB16F,
          WebGLImageConversion::kAlphaDoNothing,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = ConvertFloatToHalfFloat(source[0]);
    destination[1] = ConvertFloatToHalfFloat(source[1]);
    destination[2] = ConvertFloatToHalfFloat(source[2]);
    source += 4;
    destination += 3;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGB16F,
          WebGLImageConversion::kAlphaDoPremultiply,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3];
    destination[0] = ConvertFloatToHalfFloat(source[0] * scale_factor);
    destination[1] = ConvertFloatToHalfFloat(source[1] * scale_factor);
    destination[2] = ConvertFloatToHalfFloat(source[2] * scale_factor);
    source += 4;
    destination += 3;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGB16F,
          WebGLImageConversion::kAlphaDoUnmultiply,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 1.0f / source[3] : 1.0f;
    destination[0] = ConvertFloatToHalfFloat(source[0] * scale_factor);
    destination[1] = ConvertFloatToHalfFloat(source[1] * scale_factor);
    destination[2] = ConvertFloatToHalfFloat(source[2] * scale_factor);
    source += 4;
    destination += 3;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRA16F,
          WebGLImageConversion::kAlphaDoNothing,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = ConvertFloatToHalfFloat(source[0]);
    destination[1] = ConvertFloatToHalfFloat(source[3]);
    source += 4;
    destination += 2;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRA16F,
          WebGLImageConversion::kAlphaDoPremultiply,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3];
    destination[0] = ConvertFloatToHalfFloat(source[0] * scale_factor);
    destination[1] = ConvertFloatToHalfFloat(source[3]);
    source += 4;
    destination += 2;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRA16F,
          WebGLImageConversion::kAlphaDoUnmultiply,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 1.0f / source[3] : 1.0f;
    destination[0] = ConvertFloatToHalfFloat(source[0] * scale_factor);
    destination[1] = ConvertFloatToHalfFloat(source[3]);
    source += 4;
    destination += 2;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatR16F,
          WebGLImageConversion::kAlphaDoNothing,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = ConvertFloatToHalfFloat(source[0]);
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatR16F,
          WebGLImageConversion::kAlphaDoPremultiply,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3];
    destination[0] = ConvertFloatToHalfFloat(source[0] * scale_factor);
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatR16F,
          WebGLImageConversion::kAlphaDoUnmultiply,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 1.0f / source[3] : 1.0f;
    destination[0] = ConvertFloatToHalfFloat(source[0] * scale_factor);
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatA16F,
          WebGLImageConversion::kAlphaDoNothing,
          float,
          uint16_t>(const float* source,
                    uint16_t* destination,
                    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = ConvertFloatToHalfFloat(source[3]);
    source += 4;
    destination += 1;
  }
}

// Can not be targeted by DOM uploads, so does not need to support float
// input data.

template <>
void Pack<WebGLImageConversion::kDataFormatRGBA8_S,
          WebGLImageConversion::kAlphaDoPremultiply,
          int8_t,
          int8_t>(const int8_t* source,
                  int8_t* destination,
                  unsigned p
"""


```