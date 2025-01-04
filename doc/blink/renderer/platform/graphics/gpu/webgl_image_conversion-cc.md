Response:
Let's break down the thought process for analyzing this C++ code snippet.

**1. Initial Scan and Keyword Identification:**

First, I scanned the code for recognizable keywords and patterns. This gives a high-level understanding:

* **`// Copyright`**:  Indicates licensing information, not functional code.
* **`#ifdef`, `#endif`**: Conditional compilation. In this case, it mentions `UNSAFE_BUFFERS_BUILD`. This immediately raises a flag – there's likely a safety/performance trade-off being considered.
* **`#include`**:  Includes standard C++ libraries (`cstring`, `limits`, `memory`) and Blink-specific headers. The Blink headers are crucial for understanding the context:
    * `webgl_image_conversion.h`:  This strongly suggests the file deals with converting images for WebGL.
    * Headers with "neon", "lsx", "msa", "sse":  These are CPU instruction set extensions for SIMD (Single Instruction, Multiple Data) operations, indicating potential optimizations for different architectures. This suggests performance is a concern.
    * `image_observer.h`, `skia_utils.h`, `image-decoders/image_decoder.h`, `SkImage.h`:  These confirm the focus is on image manipulation within the Blink rendering engine, specifically involving Skia (the graphics library used by Chrome).
* **`namespace blink { namespace { ... } }`**:  Namespaces for organization, the inner anonymous namespace suggests utility functions not meant for external use.
* **Constants (e.g., `kMaxInt8Value`):** Defining maximum values for different data types, likely used for clamping or scaling.
* **`ClampMin`, `ClampImpl`, `ClampFloat`, `ClampAndScaleFloat`**:  Functions for limiting values within a range, essential for data conversion where overflows or underflows might occur.
* **`WebGLImageConversion::DataFormat WebGLImageConversion::GetDataFormat(...)`**:  A function that maps OpenGL enum values (like `GL_RGB`, `GL_UNSIGNED_BYTE`) to an internal `DataFormat` enum. This is a core function for understanding input data types.
* **Large arrays (`g_base_table`, `g_shift_table`, `g_mantissa_table`):** These large, pre-computed tables strongly suggest some form of look-up table based conversion, likely for performance reasons. The names involving "half-float" hint at conversions between single-precision and half-precision floating-point numbers.
* **`ConvertFloatToHalfFloat`**: A function explicitly named for converting floats to half-floats.
* **Comments explaining table generation:** The commented-out C code for generating the lookup tables provides valuable insight into *how* those tables were created and the underlying math.

**2. Deduce Core Functionality:**

Based on the keywords and included headers, the primary function of this file is **converting image data between different formats specifically for use in WebGL**. This involves:

* **Determining the internal data format:** The `GetDataFormat` function does this by examining the OpenGL `format` and `type` parameters.
* **Clamping and scaling values:** The `Clamp...` functions ensure values stay within valid ranges for the target data type.
* **Converting between float and half-float:** The lookup tables and the `ConvertFloatToHalfFloat` function handle this specific conversion.

**3. Identify Relationships to Web Technologies:**

* **JavaScript/WebGL:** The file name and the use of `GLenum` directly link it to WebGL, a JavaScript API for 3D graphics in the browser. JavaScript uses WebGL to send image data to the GPU.
* **HTML:**  Images displayed in HTML (using `<img>` tags or `<canvas>`) can be used as textures in WebGL. This conversion logic is likely involved in processing those images.
* **CSS:** While CSS directly manipulates visual presentation, it can indirectly affect this process. For example, if a CSS filter is applied to an image, the browser might need to process the image data before it's passed to WebGL.

**4. Logical Reasoning and Hypothetical Inputs/Outputs:**

* **Input:**  OpenGL `format` (e.g., `GL_RGB`) and `type` (e.g., `GL_UNSIGNED_BYTE`).
* **Output:** A `WebGLImageConversion::DataFormat` enum value (e.g., `kDataFormatRGB8`).
* **Input:** A `float` value.
* **Output:** A `uint16_t` representing the half-float equivalent.

**5. Identify Potential Usage Errors:**

* **Incorrect `format`/`type` combinations:** Passing incompatible OpenGL format and type values to `GetDataFormat` could result in `kDataFormatNumFormats`, indicating an error. This might happen if the JavaScript code sending data to WebGL has a bug.
* **Data range issues:** If JavaScript provides image data with values outside the expected range for a specific WebGL texture format, the clamping functions in this C++ code will mitigate the issue, but it might lead to unexpected visual results.

**6. Structure the Summary (Following the Prompt's Instructions):**

Finally, I organized the findings into the requested categories:

* **Functionality:** Clearly stating the primary purpose of the file.
* **Relationship to Web Technologies:** Providing specific examples of how the code interacts with JavaScript, HTML, and CSS.
* **Logical Reasoning:** Describing the input and output of key functions like `GetDataFormat` and `ConvertFloatToHalfFloat`.
* **User/Programming Errors:** Giving examples of common mistakes that could involve this code.
* **Overall Summary:**  A concise one-sentence summary of the file's role.

This systematic approach, starting with high-level scanning and progressing to detailed analysis of individual code elements, allows for a comprehensive understanding of the file's purpose and its place within the larger browser architecture. The key is to recognize the domain (WebGL image processing) and leverage that knowledge to interpret the code.
好的，让我们来分析一下 `blink/renderer/platform/graphics/gpu/webgl_image_conversion.cc` 这个文件的功能。

**功能归纳:**

该文件 (`webgl_image_conversion.cc`) 的主要功能是 **处理和转换用于 WebGL 的图像数据格式**。它提供了一系列工具函数，用于将不同来源的图像数据转换成 WebGL 可以理解和使用的格式。这包括确定数据格式、进行数据类型的转换（例如，浮点数到半精度浮点数）、以及对数值进行裁剪和缩放。

**与 Javascript, HTML, CSS 的关系及举例说明:**

这个文件直接与 **JavaScript (WebGL API)** 相关，间接与 HTML 和 CSS 相关。

* **JavaScript (WebGL API):**
    * **功能关系:** WebGL 是一个 JavaScript API，用于在浏览器中渲染 2D 和 3D 图形。当 JavaScript 代码使用 WebGL API 上传纹理数据（例如通过 `texImage2D` 或 `texSubImage2D` 函数）时，这些函数接收各种格式的图像数据。`webgl_image_conversion.cc` 中的代码负责理解和转换这些数据，以便 GPU 能够正确处理。
    * **举例说明:** 假设一个 WebGL 应用从 `<canvas>` 元素中获取图像数据并将其作为纹理上传：
        ```javascript
        const canvas = document.getElementById('myCanvas');
        const gl = canvas.getContext('webgl');
        const texture = gl.createTexture();
        gl.bindTexture(gl.TEXTURE_2D, texture);

        // ... 设置纹理参数 ...

        // 从 canvas 获取图像数据
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, canvas);
        ```
        在这个例子中，`gl.texImage2D` 函数接收了 `canvas` 元素作为图像源，并指定了 `gl.RGBA` 的内部格式和数据格式为 `gl.UNSIGNED_BYTE`。 `webgl_image_conversion.cc` 中的 `GetDataFormat` 函数会被调用来解析这些 `GLenum` 值，确定实际的数据格式 (`kDataFormatRGBA8`)，并进行后续的转换处理。

* **HTML:**
    * **功能关系:**  HTML 提供了 `<canvas>` 元素和 `<img>` 元素，这些元素可以作为 WebGL 纹理数据的来源。 `webgl_image_conversion.cc` 处理来自这些元素的图像数据。
    * **举例说明:**  WebGL 应用可以使用 `<img>` 标签加载的图片作为纹理：
        ```javascript
        const image = new Image();
        image.onload = function() {
          const gl = canvas.getContext('webgl');
          const texture = gl.createTexture();
          gl.bindTexture(gl.TEXTURE_2D, texture);
          // ... 设置纹理参数 ...
          gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, image);
        };
        image.src = 'myimage.png';
        ```
        当 `gl.texImage2D` 被调用时，`webgl_image_conversion.cc` 同样会参与处理 `image` 对象中的像素数据。

* **CSS:**
    * **功能关系:** CSS 可以影响 HTML 元素的渲染，包括 `<img>` 和 `<canvas>`。虽然 CSS 不直接控制 WebGL 的数据格式转换，但它可能会影响浏览器内部对这些元素的处理，进而间接影响 WebGL 接收到的数据。例如，CSS 滤镜或变换可能会导致浏览器在将图像数据传递给 WebGL 之前进行额外的处理。
    * **举例说明:** 假设一个 `<canvas>` 元素应用了 CSS 滤镜：
        ```html
        <canvas id="myCanvas" style="filter: blur(5px);"></canvas>
        ```
        当 WebGL 从这个 canvas 获取数据时，浏览器可能需要先将应用了滤镜的效果“烘焙”到 canvas 的像素数据中。 `webgl_image_conversion.cc` 处理的是最终传递给 WebGL 的像素数据，因此它会处理已经应用了 CSS 效果的图像数据。

**逻辑推理及假设输入与输出:**

* **假设输入 (针对 `GetDataFormat` 函数):**
    * `format`: `GL_RGB`
    * `type`: `GL_UNSIGNED_BYTE`
* **预期输出 (针对 `GetDataFormat` 函数):**
    * `kDataFormatRGB8`

* **假设输入 (针对 `ConvertFloatToHalfFloat` 函数):**
    * `f`: `1.0`
* **预期输出 (针对 `ConvertFloatToHalfFloat` 函数):**
    * `0x3c00` (这是 IEEE 754 半精度浮点数表示的 1.0)

* **假设输入 (针对 `ClampFloat<int8_t>` 函数):**
    * `value`: `150.0`
* **预期输出 (针对 `ClampFloat<int8_t>` 函数):**
    * `127` (因为 `INT8_MAX` 是 127)

* **假设输入 (针对 `ClampAndScaleFloat<uint8_t>` 函数):**
    * `value`: `0.75`
* **预期输出 (针对 `ClampAndScaleFloat<uint8_t>` 函数):**
    * `191` (因为 `0.75 * UINT8_MAX` 约为 `0.75 * 255 = 191.25`，会被裁剪到整数)

**用户或者编程常见的使用错误举例说明:**

* **WebGL 纹理格式不匹配:**  JavaScript 代码中指定的 WebGL 内部纹理格式（例如 `gl.RGBA`）与提供的数据格式不匹配。例如，尝试将一个只有红色通道数据的图像作为 `gl.RGBA` 纹理上传。虽然 `webgl_image_conversion.cc` 可能会尝试转换，但最终结果可能不是预期的，或者会导致 WebGL 错误。
* **数据类型理解错误:** 程序员可能错误地认为他们提供的数据类型与 WebGL 期望的数据类型一致。例如，假设他们提供了浮点数数据，但 WebGL 期望的是归一化的无符号字节数据。`webgl_image_conversion.cc` 中的转换函数会尽力处理，但可能会导致精度损失或值范围错误。
* **忘记考虑颜色空间:** 当处理来自不同来源的图像时，颜色空间可能不同。`webgl_image_conversion.cc`  涉及到 Skia 库，这暗示了颜色空间管理。如果开发者没有正确处理颜色空间，即使数据格式正确，最终渲染的颜色也可能不准确。
* **假设数据总是规范化的:**  某些 WebGL 纹理格式期望数据是规范化的（例如，颜色值在 0 到 1 之间）。如果程序员提供了未规范化的数据，并且没有进行相应的 WebGL 设置，那么 `webgl_image_conversion.cc` 中的裁剪和缩放函数可能会产生意想不到的结果。

**该部分功能总结:**

总而言之，`webgl_image_conversion.cc` 的这部分代码主要负责 **理解和初步处理 WebGL 接收到的各种图像数据格式**。它通过 `GetDataFormat` 函数确定数据的内部表示，并提供了一些基础的数值裁剪和缩放功能。它还包含了用于将单精度浮点数转换为半精度浮点数的优化代码（通过查找表实现）。这部分是 WebGL 图像处理流程的早期阶段，为后续的纹理上传和 GPU 渲染做准备。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/gpu/webgl_image_conversion.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/graphics/gpu/webgl_image_conversion.h"

#include <cstring>
#include <limits>
#include <memory>

#include "base/compiler_specific.h"
#include "base/numerics/checked_math.h"
#include "build/build_config.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/graphics/cpu/arm/webgl_image_conversion_neon.h"
#include "third_party/blink/renderer/platform/graphics/cpu/loongarch64/webgl_image_conversion_lsx.h"
#include "third_party/blink/renderer/platform/graphics/cpu/mips/webgl_image_conversion_msa.h"
#include "third_party/blink/renderer/platform/graphics/cpu/x86/webgl_image_conversion_sse.h"
#include "third_party/blink/renderer/platform/graphics/image_observer.h"
#include "third_party/blink/renderer/platform/graphics/skia/skia_utils.h"
#include "third_party/blink/renderer/platform/image-decoders/image_decoder.h"
#include "third_party/skia/include/core/SkColorSpace.h"
#include "third_party/skia/include/core/SkImage.h"

namespace blink {

namespace {

const float kMaxInt8Value = INT8_MAX;
const float kMaxUInt8Value = UINT8_MAX;
const float kMaxInt16Value = INT16_MAX;
const float kMaxUInt16Value = UINT16_MAX;
const double kMaxInt32Value = INT32_MAX;
const double kMaxUInt32Value = UINT32_MAX;

int8_t ClampMin(int8_t value) {
  const static int8_t kMinInt8Value = INT8_MIN + 1;
  return value < kMinInt8Value ? kMinInt8Value : value;
}

int16_t ClampMin(int16_t value) {
  const static int16_t kMinInt16Value = INT16_MIN + 1;
  return value < kMinInt16Value ? kMinInt16Value : value;
}

int32_t ClampMin(int32_t value) {
  const static int32_t kMinInt32Value = INT32_MIN + 1;
  return value < kMinInt32Value ? kMinInt32Value : value;
}

template <class T>
T ClampImpl(const float& v, const T& lo, const T& hi) {
  return (v < lo) ? lo : ((hi < v) ? hi : static_cast<T>(v));
}

template <class T>
T ClampFloat(float value) {
  if (std::numeric_limits<T>::is_signed) {
    // Generate an equal number of positive and negative values. Two's
    // complement has one more negative number than positive number.
    return ClampImpl<T>(value, std::numeric_limits<T>::min() + 1,
                        std::numeric_limits<T>::max());
  } else {
    return ClampImpl<T>(value, std::numeric_limits<T>::min(),
                        std::numeric_limits<T>::max());
  }
}

template <class T>
T ClampAndScaleFloat(float value) {
  return ClampFloat<T>(value * std::numeric_limits<T>::max());
}

}  // namespace

WebGLImageConversion::DataFormat WebGLImageConversion::GetDataFormat(
    GLenum format,
    GLenum type) {
  DataFormat result = kDataFormatRGBA8;
  switch (type) {
    case GL_BYTE:
      switch (format) {
        case GL_RED:
        case GL_RED_INTEGER:
          result = kDataFormatR8_S;
          break;
        case GL_RG:
        case GL_RG_INTEGER:
          result = kDataFormatRG8_S;
          break;
        case GL_RGB:
        case GL_RGB_INTEGER:
          result = kDataFormatRGB8_S;
          break;
        case GL_RGBA:
        case GL_RGBA_INTEGER:
          result = kDataFormatRGBA8_S;
          break;
        default:
          return kDataFormatNumFormats;
      }
      break;
    case GL_UNSIGNED_BYTE:
      switch (format) {
        case GL_RGB:
        case GL_RGB_INTEGER:
        case GL_SRGB_EXT:
          result = kDataFormatRGB8;
          break;
        case GL_RGBA:
        case GL_RGBA_INTEGER:
        case GL_SRGB_ALPHA_EXT:
          result = kDataFormatRGBA8;
          break;
        case GL_ALPHA:
          result = kDataFormatA8;
          break;
        case GL_LUMINANCE:
        case GL_RED:
        case GL_RED_INTEGER:
          result = kDataFormatR8;
          break;
        case GL_RG:
        case GL_RG_INTEGER:
          result = kDataFormatRG8;
          break;
        case GL_LUMINANCE_ALPHA:
          result = kDataFormatRA8;
          break;
        default:
          return kDataFormatNumFormats;
      }
      break;
    case GL_SHORT:
      switch (format) {
        case GL_RED_INTEGER:
          result = kDataFormatR16_S;
          break;
        case GL_RG_INTEGER:
          result = kDataFormatRG16_S;
          break;
        case GL_RGB_INTEGER:
          result = kDataFormatRGB16_S;
          break;
        case GL_RGBA_INTEGER:
          result = kDataFormatRGBA16_S;
          break;
        default:
          return kDataFormatNumFormats;
      }
      break;
    case GL_UNSIGNED_SHORT:
      switch (format) {
        case GL_RED_INTEGER:
          result = kDataFormatR16;
          break;
        case GL_DEPTH_COMPONENT:
          result = kDataFormatD16;
          break;
        case GL_RG_INTEGER:
          result = kDataFormatRG16;
          break;
        case GL_RGB_INTEGER:
          result = kDataFormatRGB16;
          break;
        case GL_RGBA_INTEGER:
          result = kDataFormatRGBA16;
          break;
        default:
          return kDataFormatNumFormats;
      }
      break;
    case GL_INT:
      switch (format) {
        case GL_RED_INTEGER:
          result = kDataFormatR32_S;
          break;
        case GL_RG_INTEGER:
          result = kDataFormatRG32_S;
          break;
        case GL_RGB_INTEGER:
          result = kDataFormatRGB32_S;
          break;
        case GL_RGBA_INTEGER:
          result = kDataFormatRGBA32_S;
          break;
        default:
          return kDataFormatNumFormats;
      }
      break;
    case GL_UNSIGNED_INT:
      switch (format) {
        case GL_RED_INTEGER:
          result = kDataFormatR32;
          break;
        case GL_DEPTH_COMPONENT:
          result = kDataFormatD32;
          break;
        case GL_RG_INTEGER:
          result = kDataFormatRG32;
          break;
        case GL_RGB_INTEGER:
          result = kDataFormatRGB32;
          break;
        case GL_RGBA_INTEGER:
          result = kDataFormatRGBA32;
          break;
        default:
          return kDataFormatNumFormats;
      }
      break;
    case GL_HALF_FLOAT_OES:  // OES_texture_half_float
    case GL_HALF_FLOAT:
      switch (format) {
        case GL_RGBA:
          result = kDataFormatRGBA16F;
          break;
        case GL_RGB:
          result = kDataFormatRGB16F;
          break;
        case GL_RG:
          result = kDataFormatRG16F;
          break;
        case GL_ALPHA:
          result = kDataFormatA16F;
          break;
        case GL_LUMINANCE:
        case GL_RED:
          result = kDataFormatR16F;
          break;
        case GL_LUMINANCE_ALPHA:
          result = kDataFormatRA16F;
          break;
        default:
          return kDataFormatNumFormats;
      }
      break;
    case GL_FLOAT:  // OES_texture_float
      switch (format) {
        case GL_RGBA:
          result = kDataFormatRGBA32F;
          break;
        case GL_RGB:
          result = kDataFormatRGB32F;
          break;
        case GL_RG:
          result = kDataFormatRG32F;
          break;
        case GL_ALPHA:
          result = kDataFormatA32F;
          break;
        case GL_LUMINANCE:
        case GL_RED:
          result = kDataFormatR32F;
          break;
        case GL_DEPTH_COMPONENT:
          result = kDataFormatD32F;
          break;
        case GL_LUMINANCE_ALPHA:
          result = kDataFormatRA32F;
          break;
        default:
          return kDataFormatNumFormats;
      }
      break;
    case GL_UNSIGNED_SHORT_4_4_4_4:
      result = kDataFormatRGBA4444;
      break;
    case GL_UNSIGNED_SHORT_5_5_5_1:
      result = kDataFormatRGBA5551;
      break;
    case GL_UNSIGNED_SHORT_5_6_5:
      result = kDataFormatRGB565;
      break;
    case GL_UNSIGNED_INT_5_9_9_9_REV:
      result = kDataFormatRGB5999;
      break;
    case GL_UNSIGNED_INT_24_8:
      result = kDataFormatDS24_8;
      break;
    case GL_UNSIGNED_INT_10F_11F_11F_REV:
      result = kDataFormatRGB10F11F11F;
      break;
    case GL_UNSIGNED_INT_2_10_10_10_REV:
      result = kDataFormatRGBA2_10_10_10;
      break;
    default:
      return kDataFormatNumFormats;
  }
  return result;
}

namespace {

// The following Float to Half-Float conversion code is from the implementation
// of http://www.fox-toolkit.org/ftp/fasthalffloatconversion.pdf , "Fast Half
// Float Conversions" by Jeroen van der Zijp, November 2008 (Revised September
// 2010). Specially, the basetable[512] and shifttable[512] are generated as
// follows:
/*
unsigned short basetable[512];
unsigned char shifttable[512];

void generatetables(){
    unsigned int i;
    int e;
    for (i = 0; i < 256; ++i){
        e = i - 127;
        if (e < -24){ // Very small numbers map to zero
            basetable[i | 0x000] = 0x0000;
            basetable[i | 0x100] = 0x8000;
            shifttable[i | 0x000] = 24;
            shifttable[i | 0x100] = 24;
        }
        else if (e < -14) { // Small numbers map to denorms
            basetable[i | 0x000] = (0x0400>>(-e-14));
            basetable[i | 0x100] = (0x0400>>(-e-14)) | 0x8000;
            shifttable[i | 0x000] = -e-1;
            shifttable[i | 0x100] = -e-1;
        }
        else if (e <= 15){ // Normal numbers just lose precision
            basetable[i | 0x000] = ((e+15)<<10);
            basetable[i| 0x100] = ((e+15)<<10) | 0x8000;
            shifttable[i|0x000] = 13;
            shifttable[i|0x100] = 13;
        }
        else if (e<128){ // Large numbers map to Infinity
            basetable[i|0x000] = 0x7C00;
            basetable[i|0x100] = 0xFC00;
            shifttable[i|0x000] = 24;
            shifttable[i|0x100] = 24;
        }
        else { // Infinity and NaN's stay Infinity and NaN's
            basetable[i|0x000] = 0x7C00;
            basetable[i|0x100] = 0xFC00;
            shifttable[i|0x000] = 13;
            shifttable[i|0x100] = 13;
       }
    }
}
*/

const uint16_t g_base_table[512] = {
    0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    0,     0,     0,     0,     1,     2,     4,     8,     16,    32,    64,
    128,   256,   512,   1024,  2048,  3072,  4096,  5120,  6144,  7168,  8192,
    9216,  10240, 11264, 12288, 13312, 14336, 15360, 16384, 17408, 18432, 19456,
    20480, 21504, 22528, 23552, 24576, 25600, 26624, 27648, 28672, 29696, 30720,
    31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744,
    31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744,
    31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744,
    31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744,
    31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744,
    31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744,
    31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744,
    31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744,
    31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744,
    31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744, 31744,
    31744, 31744, 31744, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768,
    32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768,
    32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768,
    32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768,
    32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768,
    32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768,
    32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768,
    32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768,
    32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768,
    32768, 32768, 32768, 32768, 32768, 32768, 32768, 32769, 32770, 32772, 32776,
    32784, 32800, 32832, 32896, 33024, 33280, 33792, 34816, 35840, 36864, 37888,
    38912, 39936, 40960, 41984, 43008, 44032, 45056, 46080, 47104, 48128, 49152,
    50176, 51200, 52224, 53248, 54272, 55296, 56320, 57344, 58368, 59392, 60416,
    61440, 62464, 63488, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512,
    64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512,
    64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512,
    64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512,
    64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512,
    64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512,
    64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512,
    64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512,
    64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512,
    64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512, 64512,
    64512, 64512, 64512, 64512, 64512, 64512};

const unsigned char g_shift_table[512] = {
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 13, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 23, 22,
    21, 20, 19, 18, 17, 16, 15, 14, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 13};

uint16_t ConvertFloatToHalfFloat(float f) {
  unsigned temp;
  std::memcpy(&temp, &f, 4);
  uint16_t signexp = (temp >> 23) & 0x1ff;
  return g_base_table[signexp] +
         ((temp & 0x007fffff) >> g_shift_table[signexp]);
}

// The mantissatable[2048], offsettable[64] and exponenttable[64] are
// generated as follows:
/*
unsigned int mantissatable[2048];
unsigned short offsettable[64];
unsigned int exponenttable[64];

unsigned int convertmantissa(unsigned int i) {
  unsigned int m=i<<13; // Zero pad mantissa bits
  unsigned int e=0; // Zero exponent
  while(!(m&0x00800000)){ // While not normalized
    e-=0x00800000; // Decrement exponent (1<<23)
    m<<=1; // Shift mantissa
  }
  m&=~0x00800000; // Clear leading 1 bit
  e+=0x38800000; // Adjust bias ((127-14)<<23)
  return m | e; // Return combined number
}

void generatef16tof32tables() {
  int i;
  mantissatable[0] = 0;
  for (i = 1; i <= 1023; ++i)
    mantissatable[i] = convertmantissa(i);
  for (i = 1024; i <= 2047; ++i)
    mantissatable[i] = 0x38000000 + ((i-1024)<<13);

  exponenttable[0] = 0;
  exponenttable[32]= 0x80000000;
  for (int i = 1; i <= 30; ++i)
    exponenttable[i] = i<<23;
  for (int i = 33; i <= 62; ++i)
    exponenttable[i] = 0x80000000 + ((i-32)<<23);
  exponenttable[31]= 0x47800000;
  exponenttable[63]= 0xC7800000;

  for (i = 0; i <= 63; ++i)
    offsettable[i] = 1024;
  offsettable[0] = 0;
  offsettable[32] = 0;
}
*/

const uint32_t g_mantissa_table[2048] = {
    0x0,        0x33800000, 0x34000000, 0x34400000, 0x34800000, 0x34a00000,
    0x34c00000, 0x34e00000, 0x35000000, 0x35100000, 0x35200000, 0x35300000,
    0x35400000, 0x35500000, 0x35600000, 0x35700000, 0x35800000, 0x35880000,
    0x35900000, 0x35980000, 0x35a00000, 0x35a80000, 0x35b00000, 0x35b80000,
    0x35c00000, 0x35c80000, 0x35d00000, 0x35d80000, 0x35e00000, 0x35e80000,
    0x35f00000, 0x35f80000, 0x36000000, 0x36040000, 0x36080000, 0x360c0000,
    0x36100000, 0x36140000, 0x36180000, 0x361c0000, 0x36200000, 0x36240000,
    0x36280000, 0x362c0000, 0x36300000, 0x36340000, 0x36380000, 0x363c0000,
    0x36400000, 0x36440000, 0x36480000, 0x364c0000, 0x36500000, 0x36540000,
    0x36580000, 0x365c0000, 0x36600000, 0x36640000, 0x36680000, 0x366c0000,
    0x36700000, 0x36740000, 0x36780000, 0x367c0000, 0x36800000, 0x36820000,
    0x36840000, 0x36860000, 0x36880000, 0x368a0000, 0x368c0000, 0x368e0000,
    0x36900000, 0x36920000, 0x36940000, 0x36960000, 0x36980000, 0x369a0000,
    0x369c0000, 0x369e0000, 0x36a00000, 0x36a20000, 0x36a40000, 0x36a60000,
    0x36a80000, 0x36aa0000, 0x36ac0000, 0x36ae0000, 0x36b00000, 0x36b20000,
    0x36b40000, 0x36b60000, 0x36b80000, 0x36ba0000, 0x36bc0000, 0x36be0000,
    0x36c00000, 0x36c20000, 0x36c40000, 0x36c60000, 0x36c80000, 0x36ca0000,
    0x36cc0000, 0x36ce0000, 0x36d00000, 0x36d20000, 0x36d40000, 0x36d60000,
    0x36d80000, 0x36da0000, 0x36dc0000, 0x36de0000, 0x36e00000, 0x36e20000,
    0x36e40000, 0x36e60000, 0x36e80000, 0x36ea0000, 0x36ec0000, 0x36ee0000,
    0x36f00000, 0x36f20000, 0x36f40000, 0x36f60000, 0x36f80000, 0x36fa0000,
    0x36fc0000, 0x36fe0000, 0x37000000, 0x37010000, 0x37020000, 0x37030000,
    0x37040000, 0x37050000, 0x37060000, 0x37070000, 0x37080000, 0x37090000,
    0x370a0000, 0x370b0000, 0x370c0000, 0x370d0000, 0x370e0000, 0x370f0000,
    0x37100000, 0x37110000, 0x37120000, 0x37130000, 0x37140000, 0x37150000,
    0x37160000, 0x37170000, 0x37180000, 0x37190000, 0x371a0000, 0x371b0000,
    0x371c0000, 0x371d0000, 0x371e0000, 0x371f0000, 0x37200000, 0x37210000,
    0x37220000, 0x37230000, 0x37240000, 0x37250000, 0x37260000, 0x37270000,
    0x37280000, 0x37290000, 0x372a0000, 0x372b0000, 0x372c0000, 0x372d0000,
    0x372e0000, 0x372f0000, 0x37300000, 0x37310000, 0x37320000, 0x37330000,
    0x37340000, 0x37350000, 0x37360000, 0x37370000, 0x37380000, 0x37390000,
    0x373a0000, 0x373b0000, 0x373c0000, 0x373d0000, 0x373e0000, 0x373f0000,
    0x37400000, 0x37410000, 0x37420000, 0x37430000, 0x37440000, 0x37450000,
    0x37460000, 0x37470000, 0x37480000, 0x37490000, 0x374a0000, 0x374b0000,
    0x374c0000, 0x374d0000, 0x374e0000, 0x374f0000, 0x37500000, 0x37510000,
    0x37520000, 0x37530000, 0x37540000, 0x37550000, 0x37560000, 0x37570000,
    0x37580000, 0x37590000, 0x375a0000, 0x375b0000, 0x375c0000, 0x375d0000,
    0x375e0000, 0x375f0000, 0x37600000, 0x37610000, 0x37620000, 0x37630000,
    0x37640000, 0x37650000, 0x37660000, 0x37670000, 0x37680000, 0x37690000,
    0x376a0000, 0x376b0000, 0x376c0000, 0x376d0000, 0x376e0000, 0x376f0000,
    0x37700000, 0x37710000, 0x37720000, 0x37730000, 0x37740000, 0x37750000,
    0x37760000, 0x37770000, 0x37780000, 0x37790000, 0x377a0000, 0x377b0000,
    0x377c0000, 0x377d0000, 0x377e0000, 0x377f0000, 0x37800000, 0x37808000,
    0x37810000, 0x37818000, 0x37820000, 0x37828000, 0x37830000, 0x37838000,
    0x37840000, 0x37848000, 0x37850000, 0x37858000, 0x37860000, 0x37868000,
    0x37870000, 0x37878000, 0x37880000, 0x37888000, 0x37890000, 0x37898000,
    0x378a0000, 0x378a8000, 0x378b0000, 0x378b8000, 0x378c0000, 0x378c8000,
    0x378d0000, 0x378d8000, 0x378e0000, 0x378e8000, 0x378f0000, 0x378f8000,
    0x37900000, 0x37908000, 0x37910000, 0x37918000, 0x37920000, 0x37928000,
    0x37930000, 0x37938000, 0x37940000, 0x37948000, 0x37950000, 0x37958000,
    0x37960000, 0x37968000, 0x37970000, 0x37978000, 0x37980000, 0x37988000,
    0x37990000, 0x37998000, 0x379a0000, 0x379a8000, 0x379b0000, 0x379b8000,
    0x379c0000, 0x379c8000, 0x379d0000, 0x379d8000, 0x379e0000, 0x379e8000,
    0x379f0000, 0x379f8000, 0x37a00000, 0x37a08000, 0x37a10000, 0x37a18000,
    0x37a20000, 0x37a28000, 0x37a30000, 0x37a38000, 0x37a40000, 0x37a48000,
    0x37a50000, 0x37a58000, 0x37a60000, 0x37a68000, 0x37a70000, 0x37a78000,
    0x37a80000, 0x37a88000, 0x37a90000, 0x37a98000, 0x37aa0000, 0x37aa8000,
    0x37ab0000, 0x37ab8000, 0x37ac0000, 0x37ac8000, 0x37ad0000, 0x37ad8000,
    0x37ae0000, 0x37ae8000, 0x37af0000, 0x37af8000, 0x37b00000, 0x37b08000,
    0x37b10000, 0x37b18000, 0x37b20000, 0x37b28000, 0x37b30000, 0x37b38000,
    0x37b40000, 0x37b48000, 0x37b50000, 0x37b58000, 0x37b60000, 0x37b68000,
    0x37b70000, 0x37b78000, 0x37b80000, 0x37b88000, 0x37b90000, 0x37b98000,
    0x37ba0000, 0x37ba8000, 0x37bb0000, 0x37bb8000, 0x37bc0000, 0x37bc8000,
    0x37bd0000, 0x37bd8000, 0x37be0000, 0x37be8000, 0x37bf0000, 0x37bf8000,
    0x37c00000, 0x37c08000, 0x37c10000, 0x37c18000, 0x37c20000, 0x37c28000,
    0x37c30000, 0x37c38000, 0x37c40000, 0x37c48000, 0x37c50000, 0x37c58000,
    0x37c60000, 0x37c68000, 0x37c70000, 0x37c78000, 0x37c80000, 0x37c88000,
    0x37c90000, 0x37c98000, 0x37ca0000, 0x37ca8000, 0x37cb0000, 0x37cb8000,
    0x37cc0000, 0x37cc8000, 0x37cd0000, 0x37cd8000, 0x37ce0000, 0x37ce8000,
    0x37cf0000, 0x37cf8000, 0x37d00000, 0x37d08000, 0x37d10000, 0x37d18000,
    0x37d20000, 0x37d28000, 0x37d30000, 0x37d38000, 0x37d40000, 0x37d48000,
    0x37d50000, 0x37d58000, 0x37d60000, 0x37d68000, 0x37d70000, 0x37d78000,
    0x37d80000, 0x37d88000, 0x37d90000, 0x37d98000, 0x37da0000, 0x37da8000,
    0x37db0000, 0x37db8000, 0x37dc0000, 0x37dc8000, 0x37dd0000, 0x37dd8000,
    0x37de0000, 0x37de8000, 0x37df0000, 0x37df8000, 0x37e00000, 0x37e08000,
    0x37e10000, 0x37e18000, 0x37e20000, 0x37e28000, 0x37e30000, 0x37e38000,
    0x37e40000, 0x37e48000, 0x37e50000, 0x37e58000, 0x37e60000, 0x37e68000,
    0x37e70000, 0x37e78000, 0x37e80000, 0x37e88000, 0x37e90000, 0x37e98000,
    0x37ea0000, 0x37ea8000, 0x37eb0000, 0x37eb8000, 0x37ec0000, 0x37ec8000,
    0x37ed0000, 0x37ed8000, 0x37ee0000, 0x37ee8000, 0x37ef0000, 0x37ef8000,
    0x37f00000, 0x37f08000, 0x37f10000, 0x37f18000, 0x37f20000, 0x37f28000,
    0x37f30000, 0x37f38000, 0x37f40000, 0x37f48000, 0x37f50000, 0x37f58000,
    0x37f60000, 0x37f68000, 0x37f70000, 0x37f78000, 0x37f80000, 0x37f88000,
    0x37f90000, 0x37f98000, 0x37fa0000, 0x37fa8000, 0x37fb0000, 0x37fb8000,
    0x37fc0000, 0x37fc8000, 0x37fd0000, 0x37fd8000, 0x37fe0000, 0x37fe8000,
    0x37ff0000, 0x37ff8000, 0x38000000, 0x38004000, 0x38008000, 0x3800c000,
    0x38010000, 0x38014000, 0x38018000, 0x3801c000, 0x38020000, 0x38024000,
    0x38028000, 0x3802c000, 0x38030000, 0x38034000, 0x38038000, 0x3803c000,
    0x38040000, 0x38044000, 0x38048000, 0x3804c000, 0x38050000, 0x38054000,
    0x38058000, 0x3805c000, 0x38060000, 0x38064000, 0x38068000, 0x3806c000,
    0x38070000, 0x38074000, 0x38078000, 0x3807c000, 0x38080000, 0x38084000,
    0x38088000, 0x3808c000, 0x38090000, 0x38094000, 0x38098000, 0x3809c000,
    0x380a0000, 0x380a4000, 0x380a8000, 0x380ac000, 0x380b0000, 0x380b4000,
    0x380b8000, 0x380bc000, 0x380c0000, 0x380c4000, 0x380c8000, 0x380cc000,
    0x380d0000, 0x380d4000, 0x380d8000, 0x380dc000, 0x380e0000, 0x380e4000,
    0x380e8000, 0x380ec000, 0x380f0000, 0x380f4000, 0x380f8000, 0x380fc000,
    0x38100000, 0x38104000, 0x38108000, 0x3810c000, 0x38110000, 0x38114000,
    0x38118000, 0x3811c000, 0x38120000, 0x38124000, 0x38128000, 0x3812c000,
    0x38130000, 0x38134000, 0x38138000, 0x3813c000, 0x38140000, 0x38144000,
    0x38148000, 0x3814c000, 0x38150000, 0x38154000, 0x38158000, 0x3815c000,
    0x38160000, 0x38164000, 0x38168000, 0x3816c000, 0x38170000, 0x38174000,
    0x38178000, 0x3817c000, 0x38180000, 0x38184000, 0x38188000, 0x3818c000,
    0x38190000, 0x38194000, 0x38198000, 0x3819c000, 0x381a0000, 0x381a4000,
    0x381a8000, 0x381ac000, 0x381b0000, 0x381b4000, 0x381b8000, 0x381bc000,
    0x381c0000, 0x381c4000, 0x381c8000, 0x381cc000, 0x381d0000, 0x381d4000,
    0x381d8000, 0x381dc000, 0x381e0000, 0x381e4000, 0x381e8000, 0x381ec000,
    0x381f0000, 0x381f4000, 0x381f8000, 0x381fc000, 0x38200000, 0x38204000,
    0x38208000, 0x3820c000, 0x38210000, 0x38214000, 0x38218000, 0x3821c000,
    0x38220000, 0x38224000, 0x38228000, 0x3822c000, 0x38230000, 0x38234000,
    0x38238000, 0x3823c000, 0x38240000, 0x38244000, 0x38248000, 0x3824c000,
    0x38250000, 0x38254000, 0x38258000, 0x3825c000, 0x38260000, 0x38264000,
    0x38268000, 0x3826c000, 0x38270000, 0x38274000, 0x38278000, 0x3827c000,
    0x38280000, 0x38284000, 0x38288000, 0x3828c000, 0x38290000, 0x38294000,
    0x38298000, 0x3829c000, 0x382a0000, 0x382a4000, 0x382a8000, 0x382ac000,
    0x382b0000, 0x382b4000, 0x382b8000, 0x382bc000, 0x382c0000, 0x382c4000,
    0x382c8000, 0x382cc000, 0x382d0000, 0x382d4000, 0x382d8000, 0x382dc000,
    0x382e0000, 0x382e4000, 0x382e8000, 0x382ec000, 0x382f0000, 0x382f4000,
    0x382f8000, 0x382fc000, 0x38300000, 0x38304000, 0x38308000, 0x3830c000,
    0x38310000, 0x38314000, 0x38318000, 0x3831c000, 0x38320000, 0x38324000,
    0x38328000, 0x3832c000, 0x38330000, 0x38334000, 0x38338000, 0x3833c000,
    0x38340000, 0x38344000, 0x38348000, 0x3834c000, 0x38350000, 0x38354000,
    0x38358000, 0x3835c000, 0x38360000, 0x38364000, 0x38368000, 0x3836c000,
    0x38370000, 0x38374000, 0x38378000, 0x3837c000, 0x38380000, 0x38384000,
    0x38388000, 0x3838c000, 0x38390000, 0x38394000, 0x38398000, 0x3839c000,
    0x383a0000, 0x383a4000, 0x383a8000, 0x383ac000, 0x383b0000, 0x383b4000,
    0x383b8000, 0x383bc000, 0x383c0000, 0x383c4000, 0x383c8000, 0x383cc000,
    0x383d0000, 0x383d4000, 0x383d8000, 0x383dc000, 0x383e0000, 0x383e4000,
    0x383e8000, 0x383ec000, 0x383f0000, 0x383f4000, 0x383f8000, 0x383fc000,
    0x38400000, 0x38404000, 0x38408000, 0x3840c000, 0x38410000, 0x38414000,
    0x38418000, 0x3841c000, 0x38420000, 0x38424000, 0x38428000, 0x3842c000,
    0x38430000, 0x38434000, 0x38438000, 0x3843c000, 0x38440000, 0x38444000,
    0x38448000, 0x3844c000, 0x38450000, 0x38454000, 0x38458000, 0x3845c000,
    0x38460000, 0x38464000, 0x38468000, 0x3846c000, 0x38470000, 0x38474000,
    0x38478000, 0x3847c000, 0x38480000, 0x38484000, 0x38488000, 0x3848c000,
    0x38490000, 0x38494000, 0x38498000, 0x3849c000, 0x384a0000, 0x384a4000,
    0x384a8000, 0x384ac000, 0x384b0000, 0x384b4000, 0x384b8000, 0x384bc000,
    0x384c0000, 0x384c4000, 0x384c8000, 0x384cc000, 0x384d0000, 0x384d4000,
    0x384d8000, 0x384dc000, 0x384e0000, 0x384e4000, 0x384e8000, 0x384ec000,
    0x384f0000, 0x384f4000, 0x384f8000, 0x384fc000, 0x38500000, 0x38504000,
    0x38508000, 0x3850c000, 0x38510000, 0x38514000, 0x38518000, 0x3851c000,
    0x38520000, 0x38524000, 0x38528000, 0x3852c000, 0x38530000, 0x38534000,
    0x38538000, 0x3853c000, 0x38540000, 0x38544000, 0x38548000, 0x3854c000,
    0x38550000, 0x38554000, 0x38558000, 0x3855c000, 0x38560000, 0x38564000,
    0x38568000, 0x3856c000, 0x38570000, 0x38574000, 0x38578000, 0x3857c000,
    0x38580000, 0x38584000, 0x38588000, 0x3858c000, 0x38590000, 0x38594000,
    0x38598000, 0x3859c000, 0x385a0000, 0x385a4000, 0x385a8000, 0x385ac000,
    0x385b0000, 0x385b4000, 0x385b8000, 0x385bc000, 0x385c0000, 0x385c4000,
    0x385c8000, 0x385cc000, 0x385d0000, 0x385d4000, 0x385d8000, 0x385dc000,
    0x385e0000, 0x385e4000, 0x385e8000, 0x385ec000, 0x385f0000, 0x385f4000,
    0x385f8000, 0x385fc000, 0x38600000, 0x38604000, 0x38608000, 0x3860c000,
    0x38610000, 0x38614000, 0x38618000, 0x3861c000, 0x38620000, 0x38624000,
    0x38628000, 0x3862c000, 0x38630000, 0x38634000, 0x38638000, 0x3863c000,
    0x38640000, 0x38644000, 0x38648000, 0x3864c000, 0x38650000, 0x38654000,
    0x38658000, 0x3865c000, 0x38660000, 0x38664000, 0x38668000, 0x3866c000,
    0x38670000, 0x38674000, 0x38678000, 0x3867c000, 0x38680000, 0x38684000,
    0x38688000, 0x3868c000, 0x38690000, 0x38694000, 0x38698000, 0x3869c000,
    0x386a0000, 0x386a4000, 0x386a8000, 0x386ac000, 0x386b0000, 0x386b4000,
    0x386b8000, 0x386bc000, 0x386c0000, 0x386c4000, 0x386c8000, 0x386cc000,
    0x386d0000, 0x386d4000, 0x386d8000, 0x386dc000, 0x386e0000, 0x386e4000,
    0x386e8000, 0x386ec000, 0x386f0000, 0x386f4000, 0x386f8000, 0x386fc000,
    0x38700000, 0x38704000, 0x38708000, 0x3870c000, 0x38710000, 0x38714000,
    0x38718000, 0x3871c000, 0x38720000, 0x38724000, 0x38728000, 0x3872c000,
    0x38730000, 0x38734000, 0x38738000, 0x3873c000, 0x38740000, 0x38744000,
    0x38748000, 0x3874c000, 0x38750000, 0x38754000, 0x38758000, 0x3875c000,
    0x38760000, 0x38764000, 0x38768000, 0x3876c000, 0x38770000, 0x38774000,
    0x38778000, 0x3877c000, 0x38780000, 0x38784000, 0x38788000, 0x3878c000,
    0x38790000, 0x38794000, 0x38798000, 0x3879c000, 0x387a0000, 0x387a4000,
    0x387a8000, 0x387ac000, 0x387b0000, 0x387b4000, 0x387b8000, 0x387bc000,
    0x387c0000, 0x387c4000, 0x387c8000, 0x387cc000, 0x387d0000, 0x387d4000,
    0x387d8000, 0x387dc000, 0x387e0000, 0x387e4000, 0x387e8000, 0x387ec000,
    0x387f0000, 0x387f4000, 0x387f8000, 0x387fc000, 0x38000000, 0x38002000,
    0x38004000, 0x38006000, 0x38008000, 0x3800a000, 0x3800c000, 0x3800e000,
    0x38010000, 0x38012000, 0x38014000, 0x38016000, 0x38018000, 0x3801a000,
    0x3801c000, 0x3801e000, 0x38020000, 0x38022000, 0x38024000, 0x38026000,
    0x38028000, 0x3802a000, 0x3802c000, 0x3802e000, 0x38030000, 0x38032000,
    0x38034000, 0x38036000, 0x38038000, 0x3803a000, 0x3803c000, 0x3803e000,
    0x38040000, 0x38042000, 0x38044000, 0x38046000, 0x38048000, 0x3804a000,
    0x3804c000, 0x3804e000, 0x38050000, 0x38052000, 0x38054000, 0x38056000,
    0x38058000, 0x3805a000, 0x3805c000, 0x3805e000, 0x38060000, 0x38062000,
    0x38064000, 0x38066000, 0x38068000, 0x3806a000, 0x3806c000, 0x3806e000,
    0x38070000, 0x38072000, 0x38074000, 0x38076000, 0x38078000, 0x3807a000,
    0x3807c000, 0x3807e000, 0x38080000, 0x38082000, 0x38084000, 0x38086000,
    0x38088000, 0x3808a000, 0x3808c000, 0x3808e000, 0x38090000, 0x38092000,
    0x38094000, 0x38096000, 0x38098000, 0x3809a000, 0x3809c000, 0x3809e000,
    0x380a0000, 0x380a2000, 0x380a4000, 0x380a6000, 0x380a8000, 0x380aa000,
    0x380ac000, 0x380ae000, 0x380b0000, 0x380b2000, 0x380b4000, 0x380b6000,
    0x380b8000, 0x380ba000, 0x380bc000, 0x380be000, 0x380c0000, 0x380c2000,
    0x380c4000, 0x380c6000, 0x380c8000, 0x380ca000, 0x380cc000, 0x380ce000,
    0x380d0000, 0x380d2000, 0x380d4000, 0x380d6000, 0x380d8000, 0x380da000,
    0x380dc000, 0x380de000, 0x380e0000, 0x380e2000, 0x380e4000, 0x380e6000,
    0x380e8000, 0x380ea000, 0x380ec000, 0x380ee000, 0x380f0000, 0x380f2000,
    0x380f4000, 0x380f6000, 0x380f8000, 0x380fa000, 0x380fc000, 0x380fe000,
    0x38100000, 0x38102000, 0x38104000, 0x38106000, 0x38108000, 0x3810a000,
    0x3810c000, 0x3810e000, 0x38110000, 0x38112000, 0x38114000, 0x38116000,
    0x38118000, 0x3811a000, 0x3811c000, 0x3811e000, 0x38120000, 0x38122000,
    0x38124000, 0x38126000, 0x38128000, 0x3812a000, 0x3812c000, 0x3812e000,
    0x38130000, 0x38132000, 0x38134000, 0x38136000, 0x38138000, 0x3813a000,
    0x3813c000, 0x3813e000, 0x38140000, 0x38142000, 0x38144000, 0x38146000,
    0x38148000, 0x3814a000, 0x3814c000, 0x3814e000, 0x38150000, 0x38152000,
    0x38154000, 0x38156000, 0x38158000, 0x3815a000, 0x3815c000, 0x3815e000,
    0x38160000, 0x38162000, 0x38164
"""


```