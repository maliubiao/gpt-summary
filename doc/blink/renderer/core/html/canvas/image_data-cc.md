Response:
Let's break down the thought process for analyzing this `ImageData.cc` file.

**1. Initial Understanding of the File's Purpose:**

The file path `blink/renderer/core/html/canvas/image_data.cc` immediately suggests this file is part of the Blink rendering engine, specifically related to the `<canvas>` element and the `ImageData` object in JavaScript. The `.cc` extension confirms it's a C++ source file.

**2. Core Functionality Identification (Reading the Code - First Pass):**

* **Constructor-like functions:** I see `ValidateAndCreate` and multiple `CreateForTest` functions. This hints at how `ImageData` objects are instantiated. `ValidateAndCreate` suggests input validation is crucial.
* **Data storage:**  The presence of `data_u8_`, `data_u16_`, `data_f32_`, and the `storage_format_` member indicate different ways of storing pixel data (8-bit clamped integers, 16-bit integers, 32-bit floats).
* **Color space:** The `color_space_` member and related functions like `GetPredefinedColorSpace` and `colorSpace()` clearly point to managing color information.
* **`GetSkPixmap`:** This suggests interaction with the Skia graphics library, used for rendering.
* **`CreateImageBitmap`:** This links `ImageData` to the `ImageBitmap` API, allowing for more efficient image processing.
* **Validation checks:**  Numerous `if` statements within `ValidateAndCreate` check for valid width, height, data size, and data type. Exceptions are thrown for invalid inputs.

**3. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **JavaScript `ImageData`:** The file name itself is a strong clue. I know that JavaScript has an `ImageData` object used with the Canvas API. This C++ file *must* be the implementation behind that JavaScript object.
* **HTML `<canvas>`:**  `ImageData` objects are primarily created and used in conjunction with the `<canvas>` element. JavaScript code running on a web page with a `<canvas>` will interact with this C++ code when manipulating image data.
* **CSS (Indirectly):**  While not directly involved, CSS styles the `<canvas>` element itself. The rendered content *within* the canvas, potentially including images manipulated via `ImageData`, is influenced by the canvas's size and position, which can be set via CSS.

**4. Logical Reasoning and Examples:**

* **Constructor logic:**  The `ValidateAndCreate` function is a prime candidate for demonstrating logical flow. I can trace the steps: input parameters (width, height, data, settings) -> validation checks -> color space/storage format determination -> data allocation (or using provided data) -> object creation.
* **Data type handling:** The `switch` statements based on `storage_format_` show how different data types are handled internally.
* **Size limitations:** The checks against `std::numeric_limits<int>::max()` and `v8::TypedArray::kMaxByteLength` illustrate the engine's constraints on image dimensions and data size.

**5. Common User Errors:**

Based on the validation logic, I can identify potential errors:

* **Invalid dimensions:** Providing zero or excessively large width/height.
* **Incorrect data length:** Providing a data array that doesn't match the expected size based on width and height.
* **Mismatched data type:** Providing a data array with a different type than expected by the `ImageData` object.

**6. User Operations Leading to `ImageData.cc`:**

This requires thinking about the typical workflow of using the Canvas API:

1. **HTML:** The user creates a `<canvas>` element in their HTML.
2. **JavaScript:**
   * Get the canvas rendering context (usually 2D).
   * Call `createImageData()`: This is the most direct way to create an `ImageData` object. The parameters passed here (width, height, optional settings) directly influence the execution of `ImageData::ValidateAndCreate`.
   * Call `getImageData()`: This extracts a region of pixels from the canvas into an `ImageData` object. The dimensions of the extracted region determine the `ImageData`'s properties.
   * Manipulate the `data` property of an `ImageData` object: When JavaScript code accesses or modifies the `data` (which is a `Uint8ClampedArray`, `Uint16Array`, or `Float32Array`), the underlying C++ data buffer is being accessed.
   * Use `putImageData()`: This puts the data from an `ImageData` object back onto the canvas.

**7. Iterative Refinement:**

After the initial analysis, I'd review the code again, looking for more subtle details or connections. For example, understanding the role of `ImageDataSettings` and how color spaces are handled adds depth to the explanation. Also, noting the "perf hack" comment regarding `AssociateWithWrapper` is important for understanding optimization strategies.

By following this systematic approach—starting with the big picture and then drilling down into specific functionalities and their relationships to web technologies—it becomes possible to generate a comprehensive and accurate description of the `ImageData.cc` file.
这个文件 `blink/renderer/core/html/canvas/image_data.cc` 是 Chromium Blink 引擎中关于 `ImageData` 接口的 C++ 实现。 `ImageData` 是 HTML Canvas API 的一部分，它允许 JavaScript 代码访问和操作画布上的像素数据。

**主要功能:**

1. **创建 ImageData 对象:**  该文件包含了创建 `ImageData` 对象的逻辑，包括参数校验、内存分配和初始化。 它实现了 JavaScript 中 `CanvasRenderingContext2D.createImageData()` 和 `new ImageData()` 等方法。

2. **管理像素数据:**  `ImageData` 对象本质上是一个包含画布像素数据的数组。 这个文件负责管理这些像素数据的存储，支持不同的数据类型 (例如 `Uint8ClampedArray`, `Uint16Array`, `Float32Array`) 和颜色空间。

3. **数据校验和错误处理:**  在创建 `ImageData` 对象时，它会进行各种参数校验，例如宽度、高度是否为正数，数据数组的大小是否匹配等。 如果参数不合法，会抛出相应的 JavaScript 异常 (例如 `IndexSizeError`, `RangeError`, `NotSupportedError`)。

4. **与 Skia 集成:**  `GetSkPixmap()` 函数表明 `ImageData` 对象可以转换为 Skia 的 `SkPixmap` 对象，Skia 是 Chromium 用于图形渲染的库。 这使得 `ImageData` 的像素数据可以被 Skia 用于绘制或其他图形操作。

5. **支持 ImageBitmap:**  `CreateImageBitmap()` 函数允许从 `ImageData` 对象创建 `ImageBitmap` 对象。 `ImageBitmap` 提供了更高效的图像处理方式，并且可以在不同的上下文中使用。

6. **颜色空间管理:**  代码中处理了不同的颜色空间（例如 sRGB, P3, Rec2020），这对于确保在不同设备和显示器上颜色的一致性非常重要。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **JavaScript:**  `ImageData` 对象是 JavaScript 代码直接操作的对象。
    * **创建:**  JavaScript 可以使用 `ctx.createImageData(width, height)` 或 `new ImageData(width, height)` 创建一个空的 `ImageData` 对象。该文件中的 `ImageData::ValidateAndCreate` 方法会被调用。
        ```javascript
        const canvas = document.getElementById('myCanvas');
        const ctx = canvas.getContext('2d');
        const imageData = ctx.createImageData(100, 50); // 创建一个 100x50 的 ImageData 对象
        console.log(imageData.width, imageData.height, imageData.data.length); // 输出 100, 50, 20000 (100 * 50 * 4)
        ```
    * **获取像素数据:**  `ctx.getImageData(x, y, width, height)` 方法会返回一个包含指定区域像素数据的 `ImageData` 对象。该文件中的相关逻辑会被调用以创建并填充 `ImageData`。
        ```javascript
        const canvas = document.getElementById('myCanvas');
        const ctx = canvas.getContext('2d');
        // 在画布上绘制一些内容...
        const imageData = ctx.getImageData(10, 10, 50, 50);
        const redPixel = imageData.data[0]; // 获取第一个像素的红色分量
        ```
    * **设置像素数据:**  可以直接修改 `ImageData.data` 属性（一个 `Uint8ClampedArray`）。
        ```javascript
        const canvas = document.getElementById('myCanvas');
        const ctx = canvas.getContext('2d');
        const imageData = ctx.createImageData(10, 10);
        // 将所有像素设置为红色
        for (let i = 0; i < imageData.data.length; i += 4) {
            imageData.data[i] = 255;   // Red
            imageData.data[i + 1] = 0;   // Green
            imageData.data[i + 2] = 0;   // Blue
            imageData.data[i + 3] = 255; // Alpha
        }
        ctx.putImageData(imageData, 50, 50); // 将修改后的 ImageData 绘制到画布上
        ```
    * **颜色空间和存储格式:**  可以使用 `ImageData(width, height, { colorSpace: 'display-p3' })` 或 `ImageData(width, height, { storageFormat: 'float32' })` 等选项来指定颜色空间和存储格式。这些选项会影响该文件中 `ImageData` 对象的创建过程。

* **HTML:**  `ImageData` 对象通常与 `<canvas>` 元素一起使用。HTML 定义了 `<canvas>` 元素，而 JavaScript 使用 Canvas API（包括 `ImageData`) 来操作它。
    ```html
    <canvas id="myCanvas" width="200" height="100"></canvas>
    <script src="script.js"></script>
    ```

* **CSS:** CSS 可以用来设置 `<canvas>` 元素的大小和样式，但这不直接影响 `ImageData` 对象本身包含的像素数据。CSS 影响的是画布在页面上的呈现方式，而 `ImageData` 关注的是底层的像素信息。

**逻辑推理和假设输入/输出:**

假设 JavaScript 代码调用 `ctx.createImageData(10, 5)`:

* **假设输入:** `width = 10`, `height = 5`
* **`ImageData::ValidateAndCreate` 的执行:**
    * 检查 `width` 和 `height` 是否为正数且在合理范围内。
    * 计算所需的像素数据大小：`10 * 5 * 4 = 200` 字节 (每个像素 4 个字节：R, G, B, A)。
    * 分配一个 `Uint8ClampedArray` 来存储 200 个字节的像素数据。
    * 创建一个 `ImageData` 对象，并将宽度、高度和数据数组存储在其中。
* **假设输出:**  一个新的 `ImageData` 对象，其 `width` 为 10，`height` 为 5，`data` 属性是一个长度为 200 的 `Uint8ClampedArray`，初始值都为 0。

假设 JavaScript 代码调用 `new ImageData(new Uint8ClampedArray([255, 0, 0, 255, 0, 255, 0, 255]), 1, 2)`:

* **假设输入:** `data = Uint8ClampedArray([255, 0, 0, 255, 0, 255, 0, 255])`, `width = 1`, `height = 2`
* **`ImageData::ValidateAndCreate` 的执行:**
    * 检查提供的 `data` 是否为 `Uint8ClampedArray`。
    * 检查 `data` 的长度是否与 `width * height * 4` 相符：`8 === 1 * 2 * 4`，成立。
    * 创建一个 `ImageData` 对象，使用提供的 `data`，并设置宽度和高度。
* **假设输出:** 一个新的 `ImageData` 对象，其 `width` 为 1，`height` 为 2，`data` 属性指向提供的 `Uint8ClampedArray`，包含红色和绿色的像素。

**用户或编程常见的使用错误:**

1. **`IndexSizeError`:**
    * **用户操作:** 在 JavaScript 中调用 `ctx.createImageData()` 或 `new ImageData()` 时，提供非正数的宽度或高度。
    * **代码示例:** `ctx.createImageData(0, 10);` 或 `new ImageData(10, -5);`
    * **在该文件中:**  `ImageData::ValidateAndCreate` 方法会检查 `width` 和 `height` 是否大于 0，如果不是则抛出 `DOMExceptionCode::kIndexSizeError`。

2. **`InvalidStateError`:**
    * **用户操作:** 在 JavaScript 中使用已经 detached 的 `ArrayBuffer` 来创建 `ImageData`。
    * **代码示例:**
      ```javascript
      const buffer = new ArrayBuffer(100);
      const uint8Clamped = new Uint8ClampedArray(buffer);
      buffer.detach();
      try {
        new ImageData(uint8Clamped, 10, 2);
      } catch (e) {
        console.error(e.name, e.message); // 输出 "InvalidStateError", "The source data has been detached."
      }
      ```
    * **在该文件中:**  `ImageData::ValidateAndCreate` 中会检查提供的 `data` 是否已经被 detached。

3. **`RangeError`:**
    * **用户操作:**  尝试创建非常大的 `ImageData` 对象，超出内存限制。
    * **代码示例:** `ctx.createImageData(Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER);` （这通常会导致崩溃或资源耗尽，实际错误信息取决于浏览器实现）。
    * **在该文件中:** `ImageData::ValidateAndCreate` 中计算像素数据大小时，会进行溢出检查，并与 `v8::TypedArray::kMaxByteLength` 比较，如果超出限制则抛出 `DOMExceptionCode::kIndexSizeError` 或 `RangeError`。

4. **数据长度不匹配:**
    * **用户操作:**  使用 `new ImageData(data, width, height)` 时，提供的 `data` 数组的长度与 `width * height * 4` 不匹配。
    * **代码示例:** `new ImageData(new Uint8ClampedArray(10), 2, 2);` // 需要 16 个元素
    * **在该文件中:** `ImageData::ValidateAndCreate` 会检查 `data` 的长度是否是 4 的倍数，以及是否等于 `width * height * 4`。

**用户操作是如何一步步的到达这里:**

1. **用户编写 HTML 页面，包含 `<canvas>` 元素。**
2. **用户编写 JavaScript 代码，获取 Canvas 的 2D 渲染上下文。**
   ```javascript
   const canvas = document.getElementById('myCanvas');
   const ctx = canvas.getContext('2d');
   ```
3. **用户调用 CanvasRenderingContext2D 的方法来创建或获取 `ImageData` 对象:**
   * **`ctx.createImageData(width, height)`:**  用户明确指定了 `ImageData` 的尺寸，浏览器会调用 `blink/renderer/core/html/canvas/image_data.cc` 中的 `ImageData::ValidateAndCreate` 方法，根据指定的宽度和高度创建并初始化一个空的 `ImageData` 对象。
   * **`ctx.getImageData(x, y, width, height)`:** 用户想要获取画布上特定区域的像素数据，浏览器会调用相关逻辑（可能涉及到 `ImageData::ValidateAndCreate` 来创建 `ImageData` 对象，并从画布的后备缓冲区复制像素数据）。
   * **`new ImageData(width, height)` 或 `new ImageData(data, width, height)`:** 用户直接使用 `ImageData` 构造函数创建对象，浏览器会调用 `ImageData::ValidateAndCreate` 进行参数校验和对象创建。
4. **在 `ImageData::ValidateAndCreate` 方法中，会进行各种参数校验和内存分配等操作。** 如果用户提供的参数不合法，该方法会抛出相应的 JavaScript 异常。如果参数合法，则创建一个 `ImageData` 对象并返回给 JavaScript 代码。
5. **JavaScript 代码可以进一步操作 `ImageData` 对象的 `data` 属性来修改像素信息，并使用 `ctx.putImageData()` 将修改后的像素数据绘制到画布上。**

总而言之，`blink/renderer/core/html/canvas/image_data.cc` 文件是浏览器引擎中负责 `ImageData` 对象创建、管理和校验的核心组件，它连接了 JavaScript 的 Canvas API 和底层的像素数据存储。 用户的 JavaScript 代码通过 Canvas API 与这个 C++ 文件进行交互，最终实现对画布像素数据的读写操作。

Prompt: 
```
这是目录为blink/renderer/core/html/canvas/image_data.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。

"""
/*
 * Copyright (C) 2008 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/html/canvas/image_data.h"

#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_image_bitmap_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_float32array_uint16array_uint8clampedarray.h"
#include "third_party/blink/renderer/core/html/canvas/predefined_color_space.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "v8/include/v8.h"

namespace blink {

ImageData* ImageData::ValidateAndCreate(
    unsigned width,
    std::optional<unsigned> height,
    std::optional<NotShared<DOMArrayBufferView>> data,
    const ImageDataSettings* settings,
    ValidateAndCreateParams params,
    ExceptionState& exception_state) {
  gfx::Size size;
  if (params.require_canvas_floating_point &&
      !RuntimeEnabledFeatures::CanvasFloatingPointEnabled()) {
    exception_state.ThrowTypeError("Overload resolution failed.");
    return nullptr;
  }

  if (!width) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        "The source width is zero or not a number.");
    return nullptr;
  }
  if (width > static_cast<unsigned>(std::numeric_limits<int>::max())) {
    // TODO(crbug.com/1273969): Should throw RangeError instead.
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        "The requested image size exceeds the supported range.");
    return nullptr;
  }
  size.set_width(width);

  if (height) {
    if (!*height) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kIndexSizeError,
          "The source height is zero or not a number.");
      return nullptr;
    }
    if (height > static_cast<unsigned>(std::numeric_limits<int>::max())) {
      // TODO(crbug.com/1273969): Should throw RangeError instead.
      exception_state.ThrowDOMException(
          DOMExceptionCode::kIndexSizeError,
          "The requested image size exceeds the supported range.");
      return nullptr;
    }
    size.set_height(*height);
  }

  // Ensure the size does not overflow.
  unsigned size_in_elements = 0;
  {
    // Please note that the number "4" in the means number of channels required
    // to describe a pixel, namely, red, green, blue and alpha.
    base::CheckedNumeric<unsigned> size_in_elements_checked = 4;
    size_in_elements_checked *= size.width();
    size_in_elements_checked *= size.height();
    if (!params.context_2d_error_mode) {
      if (!size_in_elements_checked.IsValid()) {
        // TODO(crbug.com/1273969): Should throw RangeError instead.
        exception_state.ThrowDOMException(
            DOMExceptionCode::kIndexSizeError,
            "The requested image size exceeds the supported range.");
        return nullptr;
      }
    }
    if (!size_in_elements_checked.IsValid() ||
        size_in_elements_checked.ValueOrDie() >
            v8::TypedArray::kMaxByteLength) {
      exception_state.ThrowRangeError("Out of memory at ImageData creation.");
      return nullptr;
    }
    size_in_elements = size_in_elements_checked.ValueOrDie();
  }

  // Query the color space and storage format from |settings|.
  PredefinedColorSpace color_space = params.default_color_space;
  ImageDataStorageFormat storage_format = ImageDataStorageFormat::kUint8;
  if (settings) {
    if (settings->hasColorSpace() &&
        !ValidateAndConvertColorSpace(settings->colorSpace(), color_space,
                                      exception_state)) {
      return nullptr;
    }
    if (settings->hasStorageFormat()) {
      switch (settings->storageFormat().AsEnum()) {
        case V8ImageDataStorageFormat::Enum::kUint8:
          storage_format = ImageDataStorageFormat::kUint8;
          break;
        case V8ImageDataStorageFormat::Enum::kUint16:
          storage_format = ImageDataStorageFormat::kUint16;
          break;
        case V8ImageDataStorageFormat::Enum::kFloat32:
          storage_format = ImageDataStorageFormat::kFloat32;
          break;
      }
    }
  }

  // If |data| is provided, ensure it is a reasonable format, and that it can
  // work with |size|. Update |storage_format| to reflect |data|'s format.
  if (data) {
    DCHECK(data);
    switch ((*data)->GetType()) {
      case DOMArrayBufferView::ViewType::kTypeUint8Clamped:
        storage_format = ImageDataStorageFormat::kUint8;
        break;
      case DOMArrayBufferView::ViewType::kTypeUint16:
        storage_format = ImageDataStorageFormat::kUint16;
        break;
      case DOMArrayBufferView::ViewType::kTypeFloat32:
        storage_format = ImageDataStorageFormat::kFloat32;
        break;
      default:
        exception_state.ThrowDOMException(
            DOMExceptionCode::kNotSupportedError,
            "The input data type is not supported.");
        return nullptr;
    }
    static_assert(
        std::numeric_limits<unsigned>::max() >=
            std::numeric_limits<uint32_t>::max(),
        "We use UINT32_MAX as the upper bound of the input size and expect "
        "that the result fits into an `unsigned`.");

    unsigned data_length_in_bytes = 0;
    if (!base::CheckedNumeric<uint32_t>((*data)->byteLength())
             .AssignIfValid(&data_length_in_bytes)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kNotSupportedError,
          "The input data is too large. The maximum size is 4294967295.");
      return nullptr;
    }
    if (!data_length_in_bytes) {
      exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                        "The input data has zero elements.");
      return nullptr;
    }

    const unsigned data_length_in_elements =
        data_length_in_bytes / (*data)->TypeSize();
    if (data_length_in_elements % 4) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidStateError,
          "The input data length is not a multiple of 4.");
      return nullptr;
    }

    const unsigned data_length_in_pixels = data_length_in_elements / 4;
    if (data_length_in_pixels % width) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kIndexSizeError,
          "The input data length is not a multiple of (4 * width).");
      return nullptr;
    }

    const unsigned expected_height = data_length_in_pixels / width;
    if (height) {
      if (*height != expected_height) {
        exception_state.ThrowDOMException(
            DOMExceptionCode::kIndexSizeError,
            "The input data length is not equal to (4 * width * height).");
        return nullptr;
      }
    } else {
      size.set_height(expected_height);
    }
  }

  NotShared<DOMArrayBufferView> allocated_data;
  if (!data) {
    allocated_data =
        AllocateAndValidateDataArray(size_in_elements, storage_format,
                                     params.zero_initialize, exception_state);
    if (!allocated_data)
      return nullptr;
  }

  return MakeGarbageCollected<ImageData>(size, data ? *data : allocated_data,
                                         color_space, storage_format);
}

NotShared<DOMArrayBufferView> ImageData::AllocateAndValidateDataArray(
    const unsigned& length,
    ImageDataStorageFormat storage_format,
    bool zero_initialize,
    ExceptionState& exception_state) {
  if (!length)
    return NotShared<DOMArrayBufferView>();

  NotShared<DOMArrayBufferView> data_array;
  switch (storage_format) {
    case ImageDataStorageFormat::kUint8:
      data_array = NotShared<DOMArrayBufferView>(
          zero_initialize
              ? DOMUint8ClampedArray::CreateOrNull(length)
              : DOMUint8ClampedArray::CreateUninitializedOrNull(length));
      break;
    case ImageDataStorageFormat::kUint16:
      data_array = NotShared<DOMArrayBufferView>(
          zero_initialize ? DOMUint16Array::CreateOrNull(length)
                          : DOMUint16Array::CreateUninitializedOrNull(length));
      break;
    case ImageDataStorageFormat::kFloat32:
      data_array = NotShared<DOMArrayBufferView>(
          zero_initialize ? DOMFloat32Array::CreateOrNull(length)
                          : DOMFloat32Array::CreateUninitializedOrNull(length));
      break;
    default:
      NOTREACHED();
  }

  size_t expected_size;
  if (!data_array || (!base::CheckMul(length, data_array->TypeSize())
                           .AssignIfValid(&expected_size) &&
                      expected_size != data_array->byteLength())) {
    exception_state.ThrowRangeError("Out of memory at ImageData creation");
    return NotShared<DOMArrayBufferView>();
  }

  return data_array;
}

// This function accepts size (0, 0) and always returns the ImageData in
// "srgb" color space and "uint8" storage format.
ImageData* ImageData::CreateForTest(const gfx::Size& size) {
  base::CheckedNumeric<unsigned> data_size = 4;
  data_size *= size.width();
  data_size *= size.height();
  if (!data_size.IsValid() ||
      data_size.ValueOrDie() > v8::TypedArray::kMaxByteLength) {
    return nullptr;
  }

  NotShared<DOMUint8ClampedArray> byte_array(
      DOMUint8ClampedArray::CreateOrNull(data_size.ValueOrDie()));
  if (!byte_array)
    return nullptr;

  return MakeGarbageCollected<ImageData>(size, byte_array,
                                         PredefinedColorSpace::kSRGB,
                                         ImageDataStorageFormat::kUint8);
}

// This function is called from unit tests, and all the parameters are supposed
// to be validated on the call site.
ImageData* ImageData::CreateForTest(const gfx::Size& size,
                                    NotShared<DOMArrayBufferView> buffer_view,
                                    PredefinedColorSpace color_space,
                                    ImageDataStorageFormat storage_format) {
  return MakeGarbageCollected<ImageData>(size, buffer_view, color_space,
                                         storage_format);
}

ScriptPromise<ImageBitmap> ImageData::CreateImageBitmap(
    ScriptState* script_state,
    std::optional<gfx::Rect> crop_rect,
    const ImageBitmapOptions* options,
    ExceptionState& exception_state) {
  if (IsBufferBaseDetached()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The source data has been detached.");
    return EmptyPromise();
  }
  return ImageBitmapSource::FulfillImageBitmap(
      script_state, MakeGarbageCollected<ImageBitmap>(this, crop_rect, options),
      options, exception_state);
}

PredefinedColorSpace ImageData::GetPredefinedColorSpace() const {
  return color_space_;
}

ImageDataStorageFormat ImageData::GetImageDataStorageFormat() const {
  return storage_format_;
}

V8PredefinedColorSpace ImageData::colorSpace() const {
  switch (color_space_) {
    case PredefinedColorSpace::kSRGB:
      return V8PredefinedColorSpace(V8PredefinedColorSpace::Enum::kSRGB);
    case PredefinedColorSpace::kRec2020:
      return V8PredefinedColorSpace(V8PredefinedColorSpace::Enum::kRec2020);
    case PredefinedColorSpace::kP3:
      return V8PredefinedColorSpace(V8PredefinedColorSpace::Enum::kDisplayP3);
    case PredefinedColorSpace::kRec2100HLG:
      return V8PredefinedColorSpace(V8PredefinedColorSpace::Enum::kRec2100Hlg);
    case PredefinedColorSpace::kRec2100PQ:
      return V8PredefinedColorSpace(V8PredefinedColorSpace::Enum::kRec2100Pq);
    case PredefinedColorSpace::kSRGBLinear:
      return V8PredefinedColorSpace(V8PredefinedColorSpace::Enum::kSRGBLinear);
  }
  NOTREACHED();
}

V8ImageDataStorageFormat ImageData::storageFormat() const {
  switch (storage_format_) {
    case ImageDataStorageFormat::kUint8:
      return V8ImageDataStorageFormat(V8ImageDataStorageFormat::Enum::kUint8);
    case ImageDataStorageFormat::kUint16:
      return V8ImageDataStorageFormat(V8ImageDataStorageFormat::Enum::kUint16);
    case ImageDataStorageFormat::kFloat32:
      return V8ImageDataStorageFormat(V8ImageDataStorageFormat::Enum::kFloat32);
  }
  NOTREACHED();
}

bool ImageData::IsBufferBaseDetached() const {
  switch (data_->GetContentType()) {
    case V8ImageDataArray::ContentType::kFloat32Array:
      return data_->GetAsFloat32Array()->BufferBase()->IsDetached();
    case V8ImageDataArray::ContentType::kUint16Array:
      return data_->GetAsUint16Array()->BufferBase()->IsDetached();
    case V8ImageDataArray::ContentType::kUint8ClampedArray:
      return data_->GetAsUint8ClampedArray()->BufferBase()->IsDetached();
  }

  NOTREACHED();
}

SkPixmap ImageData::GetSkPixmap() const {
  CHECK(!IsBufferBaseDetached());
  SkColorType color_type = kRGBA_8888_SkColorType;
  const void* data = nullptr;
  switch (data_->GetContentType()) {
    case V8ImageDataArray::ContentType::kFloat32Array:
      color_type = kRGBA_F32_SkColorType;
      data = data_->GetAsFloat32Array()->Data();
      break;
    case V8ImageDataArray::ContentType::kUint16Array:
      color_type = kR16G16B16A16_unorm_SkColorType;
      data = data_->GetAsUint16Array()->Data();
      break;
    case V8ImageDataArray::ContentType::kUint8ClampedArray:
      color_type = kRGBA_8888_SkColorType;
      data = data_->GetAsUint8ClampedArray()->Data();
      break;
  }
  SkImageInfo info = SkImageInfo::Make(
      width(), height(), color_type, kUnpremul_SkAlphaType,
      PredefinedColorSpaceToSkColorSpace(GetPredefinedColorSpace()));
  return SkPixmap(info, data, info.minRowBytes());
}

void ImageData::Trace(Visitor* visitor) const {
  visitor->Trace(settings_);
  visitor->Trace(data_);
  visitor->Trace(data_u8_);
  visitor->Trace(data_u16_);
  visitor->Trace(data_f32_);
  ScriptWrappable::Trace(visitor);
}

v8::Local<v8::Object> ImageData::AssociateWithWrapper(
    v8::Isolate* isolate,
    const WrapperTypeInfo* wrapper_type_info,
    v8::Local<v8::Object> wrapper) {
  wrapper = ScriptWrappable::AssociateWithWrapper(isolate, wrapper_type_info,
                                                  wrapper);

  if (data_->IsUint8ClampedArray()) {
    // Create a V8 object with |data_| and set the "data" property
    // of the ImageData object to the created v8 object, eliminating the
    // C++ callback when accessing the "data" property.
    //
    // This is a perf hack breaking the web interop.

    ScriptState* script_state = ScriptState::ForRelevantRealm(isolate, wrapper);
    v8::Local<v8::Value> v8_data =
        ToV8Traits<V8ImageDataArray>::ToV8(script_state, data_);
    bool defined_property;
    if (!wrapper
             ->DefineOwnProperty(isolate->GetCurrentContext(),
                                 V8AtomicString(isolate, "data"), v8_data,
                                 v8::ReadOnly)
             .To(&defined_property)) {
      return wrapper;
    }
  }

  return wrapper;
}

ImageData::ImageData(const gfx::Size& size,
                     NotShared<DOMArrayBufferView> data,
                     PredefinedColorSpace color_space,
                     ImageDataStorageFormat storage_format)
    : size_(size),
      settings_(ImageDataSettings::Create()),
      color_space_(color_space),
      storage_format_(storage_format) {
  DCHECK_GE(size.width(), 0);
  DCHECK_GE(size.height(), 0);
  DCHECK(data);

  data_u8_.Clear();
  data_u16_.Clear();
  data_f32_.Clear();

  if (settings_) {
    settings_->setColorSpace(colorSpace());
    settings_->setStorageFormat(storageFormat());
  }

  switch (storage_format_) {
    case ImageDataStorageFormat::kUint8:
      DCHECK_EQ(data->GetType(),
                DOMArrayBufferView::ViewType::kTypeUint8Clamped);
      data_u8_ = data;
      DCHECK(data_u8_);
      SECURITY_CHECK(
          (base::CheckedNumeric<size_t>(size.width()) * size.height() * 4)
              .ValueOrDie() <= data_u8_->length());
      data_ = MakeGarbageCollected<V8ImageDataArray>(data_u8_);
      break;

    case ImageDataStorageFormat::kUint16:
      DCHECK_EQ(data->GetType(), DOMArrayBufferView::ViewType::kTypeUint16);
      data_u16_ = data;
      DCHECK(data_u16_);
      SECURITY_CHECK(
          (base::CheckedNumeric<size_t>(size.width()) * size.height() * 4)
              .ValueOrDie() <= data_u16_->length());
      data_ = MakeGarbageCollected<V8ImageDataArray>(data_u16_);
      break;

    case ImageDataStorageFormat::kFloat32:
      DCHECK_EQ(data->GetType(), DOMArrayBufferView::ViewType::kTypeFloat32);
      data_f32_ = data;
      DCHECK(data_f32_);
      SECURITY_CHECK(
          (base::CheckedNumeric<size_t>(size.width()) * size.height() * 4)
              .ValueOrDie() <= data_f32_->length());
      data_ = MakeGarbageCollected<V8ImageDataArray>(data_f32_);
      break;

    default:
      NOTREACHED();
  }
}

}  // namespace blink

"""

```