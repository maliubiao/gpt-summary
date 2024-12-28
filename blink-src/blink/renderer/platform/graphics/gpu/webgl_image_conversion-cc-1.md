Response:
My thought process for analyzing the provided code snippet goes like this:

1. **Identify the core purpose:** The filename `webgl_image_conversion.cc` and the presence of `Unpack` and `Pack` template functions strongly suggest that this code deals with converting image data formats, specifically for use with WebGL.

2. **Look for key data structures:** The presence of `g_mantissa_table`, `g_offset_table`, and `g_exponent_table` immediately stands out. The names, along with the `ConvertHalfFloatToFloat` function, indicate these are used for handling half-float (16-bit) to single-precision float (32-bit) conversion. The large array of hex values likely represents precomputed data for this conversion.

3. **Analyze `ConvertHalfFloatToFloat`:** This function clearly takes a `uint16_t` (half-float) as input and returns a `float`. It uses the precomputed tables to perform the conversion. This confirms the suspicion from step 2.

4. **Examine the `Unpack` templates:**  The `Unpack` templates are parameterized by `format`, `SourceType`, and `DstType`. This structure indicates a variety of possible conversions from different source data types to different destination data types. The explicit template specializations for different `kDataFormat` values (like `ARGB8`, `ABGR8`, `BGRA8`, `RGBA5551`, etc.) show the supported input formats. The destination type is often `uint8_t` or `float`, suggesting conversion to common image formats. The `pixels_per_row` argument indicates the processing is done row by row. The use of SIMD instructions (like `simd::UnpackOneRowOfBGRA8LittleToRGBA8`) highlights performance considerations for these conversions.

5. **Examine the `Pack` templates:** Similar to `Unpack`, `Pack` is parameterized by `format`, `alphaOp`, `SourceType`, and `DstType`. The `alphaOp` parameter suggests handling of alpha channel operations like pre-multiplication and un-multiplication. The explicit template specializations again list supported formats and source/destination types. The presence of `kAlphaDoNothing`, `kAlphaDoPremultiply`, and `kAlphaDoUnmultiply` confirms the alpha handling aspect. Similar to `Unpack`, SIMD optimizations are present.

6. **Identify connections to web technologies:** The "WebGL" in the filename is the most direct link. The `Unpack` and `Pack` operations are fundamental for getting image data (from sources like `<canvas>`, `<img>`, `<video>`) into WebGL textures and potentially reading data back. The handling of different pixel formats and alpha operations is crucial for ensuring correct rendering in WebGL.

7. **Consider the "why":** Why is this conversion necessary? Browsers handle images in various internal formats. WebGL, being a lower-level graphics API, has specific requirements for texture data. This code acts as a bridge, converting browser-internal image formats into formats suitable for WebGL. The alpha operations are needed because different image sources might have pre-multiplied or separate alpha channels, and WebGL needs to handle these correctly.

8. **Formulate the functional summary:** Based on the above, the core function is image format conversion for WebGL. This includes unpacking data from various formats (like `BGRA`, `RGBA5551`) into a standard `RGBA8` or `float` representation and packing data from a source format (often `RGBA8` or `float`) into a WebGL texture format, with optional alpha manipulation.

9. **Address specific prompt questions:**
    * **Functionality:** List the key functionalities identified (half-float conversion, unpacking, packing, alpha operations).
    * **Relation to web technologies:** Explain the connection to JavaScript (manipulating image sources), HTML (`<img>`, `<video>`, `<canvas>`), and CSS (potentially influencing image rendering which might be captured by `<canvas>`). Give concrete examples.
    * **Logical reasoning (assumptions and outputs):** Create simple scenarios demonstrating input and output for `ConvertHalfFloatToFloat` and `Unpack`/`Pack`.
    * **User/programming errors:**  Think about common mistakes, like providing incorrect data types to the conversion functions or misunderstanding alpha pre-multiplication.
    * **Part 2 summary:** Synthesize the analysis into a concise summary of the code's purpose within the larger context. Emphasize the image format conversion and alpha handling aspects.

By following these steps, I can systematically analyze the code snippet and generate a comprehensive and informative answer that addresses all aspects of the prompt. The key is to start with the obvious clues (filename, function names), delve into the details (data structures, template specializations), and then connect the code's purpose to the broader context of web technologies and potential usage scenarios.
这是 `blink/renderer/platform/graphics/gpu/webgl_image_conversion.cc` 文件的第 2 部分，从提供的代码片段来看，它主要包含用于 **WebGL 图像数据转换** 的核心逻辑。具体来说，它涵盖了：

**1. 半精度浮点数 (Half-float) 到单精度浮点数 (Float) 的转换:**

*   提供了一个 `ConvertHalfFloatToFloat` 函数，用于将 16 位的半精度浮点数转换为 32 位的单精度浮点数。
*   使用了三个预先计算好的查找表 `g_mantissa_table`, `g_offset_table`, 和 `g_exponent_table` 来加速转换过程。

**2. 像素数据解包 (Unpacking) 功能:**

*   定义了一组 `Unpack` 模板函数，用于将不同格式的像素数据解包为 RGBA8 (uint8_t) 或 RGBA (float) 格式。
*   针对不同的输入像素格式 (例如 `ARGB8`, `ABGR8`, `BGRA8`, `RGBA5551`, `RGBA4444`, `RA8`, `AR8`, `RA32F`, `RGBA2_10_10_10`, `RGBA16F`) 提供了特化版本。
*   在某些情况下，利用了 SIMD (Single Instruction, Multiple Data) 指令集（例如 x86 的 SSE、ARM 的 NEON、MIPS 的 MSA、LoongArch 的指令）来优化解包性能。

**3. 像素数据打包 (Packing) 功能:**

*   定义了一组 `Pack` 模板函数，用于将 RGBA8 (uint8_t) 或 RGBA (float) 格式的像素数据打包为 WebGL 可以使用的特定格式。
*   支持多种目标像素格式 (例如 `A8`, `R8`, `RA8`, `RGB8`)。
*   引入了 `alphaOp` 参数，用于处理 alpha 通道的预乘 (Premultiply) 和反预乘 (Unmultiply) 操作。这对于处理来自不同来源（例如 2D canvas）的可能已预乘 alpha 的图像数据至关重要。
*   同样，在某些情况下使用了 SIMD 指令集来优化打包性能。

**与 Javascript, HTML, CSS 的关系：**

这个文件中的代码直接为 WebGL API 提供底层支持，因此与 JavaScript, HTML, CSS 的交互是间接但至关重要的。

*   **JavaScript:**  当 JavaScript 代码使用 WebGL API (例如 `texImage2D`, `texSubImage2D`) 上传图像数据到 GPU 时，`webgl_image_conversion.cc` 中的函数会被调用来转换和处理这些数据。例如：
    *   用户在 JavaScript 中使用 `canvas.getContext('webgl').texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, canvas)` 时，如果 canvas 的内部数据格式与 WebGL 的纹理格式不匹配，这里的 `Unpack` 或 `Pack` 函数就会被调用进行转换。
    *   用户从 `<img>` 或 `<video>` 元素获取图像数据并上传到 WebGL，也会触发这里的转换逻辑。
    *   JavaScript 可以通过操作 HTML 中的 `<canvas>` 元素来生成图像数据，这些数据最终可能被 WebGL 使用，需要经过这里的转换。

*   **HTML:**  HTML 元素如 `<img>`, `<video>`, `<canvas>` 是图像数据的来源。`webgl_image_conversion.cc` 负责将这些 HTML 元素中包含的图像数据转换成 WebGL 可以理解的格式。

*   **CSS:** CSS 可以影响 HTML 元素的渲染，包括 `<canvas>` 元素的内容。虽然 CSS 不直接调用此文件中的代码，但通过 CSS 渲染到 canvas 上的内容，当被 WebGL 使用时，会间接涉及到这里的图像转换。

**逻辑推理与假设输入/输出：**

**假设输入 (ConvertHalfFloatToFloat):**  一个 16 位的半精度浮点数，例如 `0x3c00` (表示 1.0)。

**假设输出 (ConvertHalfFloatToFloat):**  一个 32 位的单精度浮点数，其二进制表示对应于 1.0。

**假设输入 (Unpack<kDataFormatBGRA8, uint8_t, uint8_t>):**  一个 BGRA8 格式的像素数据 buffer，例如 `[0x00, 0x00, 0xFF, 0xFF]` (蓝色，不透明)。

**假设输出 (Unpack<kDataFormatBGRA8, uint8_t, uint8_t>):**  一个 RGBA8 格式的像素数据 buffer，例如 `[0xFF, 0x00, 0x00, 0xFF]` (红色，不透明，因为BGRA8解包成RGBA8时会发生通道顺序的调整)。

**假设输入 (Pack<kDataFormatRGB8, kAlphaDoNothing, uint8_t, uint8_t>):**  一个 RGBA8 格式的像素数据 buffer，例如 `[0xFF, 0x00, 0x00, 0xFF]` (红色，不透明)。

**假设输出 (Pack<kDataFormatRGB8, kAlphaDoNothing, uint8_t, uint8_t>):**  一个 RGB8 格式的像素数据 buffer，例如 `[0xFF, 0x00, 0x00]` (红色，alpha 通道被丢弃)。

**用户或编程常见的使用错误：**

*   **数据类型不匹配:**  在 JavaScript 中使用 `texImage2D` 或 `texSubImage2D` 时，提供的图像数据类型与 WebGL 期望的类型不一致。例如，WebGL 期望 `UNSIGNED_BYTE`，但提供了浮点数数据。虽然这里的代码会进行转换，但错误的数据类型可能导致意想不到的结果或性能问题。
*   **理解 Alpha 预乘:**  开发者可能不理解 alpha 预乘的概念，导致在上传带有透明度的图像时出现渲染错误。例如，如果 canvas 的上下文是预乘 alpha 的，但在上传到 WebGL 时没有进行正确的处理，可能会导致颜色变淡或边缘出现锯齿。`Pack` 函数中的 `alphaOp` 参数就是为了解决这个问题，但需要开发者正确选择。
*   **使用了错误的纹理格式:**  开发者可能选择了不适合图像数据的 WebGL 纹理格式。例如，将带有 alpha 通道的图像上传到 `RGB` 纹理格式，会导致 alpha 信息丢失。

**功能归纳 (第 2 部分):**

这部分代码主要负责 WebGL 中图像数据的格式转换，包括：

*   将半精度浮点数转换为单精度浮点数。
*   将各种常见的图像像素格式（例如 BGRA, RGBA5551, RA）解包为 RGBA8 或 RGBA (float) 格式，以便进一步处理或上传到 GPU。
*   将 RGBA8 或 RGBA (float) 格式的像素数据打包为 WebGL 支持的特定纹理格式（例如 RGB, RA），并能处理 alpha 预乘/反预乘的需求。

总的来说，这部分是 `webgl_image_conversion.cc` 的核心，它确保了来自不同来源的图像数据能够被正确地转换成 WebGL 能够使用的格式，从而实现 WebGL 的图像渲染功能。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/gpu/webgl_image_conversion.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能

"""
000, 0x38166000, 0x38168000, 0x3816a000,
    0x3816c000, 0x3816e000, 0x38170000, 0x38172000, 0x38174000, 0x38176000,
    0x38178000, 0x3817a000, 0x3817c000, 0x3817e000, 0x38180000, 0x38182000,
    0x38184000, 0x38186000, 0x38188000, 0x3818a000, 0x3818c000, 0x3818e000,
    0x38190000, 0x38192000, 0x38194000, 0x38196000, 0x38198000, 0x3819a000,
    0x3819c000, 0x3819e000, 0x381a0000, 0x381a2000, 0x381a4000, 0x381a6000,
    0x381a8000, 0x381aa000, 0x381ac000, 0x381ae000, 0x381b0000, 0x381b2000,
    0x381b4000, 0x381b6000, 0x381b8000, 0x381ba000, 0x381bc000, 0x381be000,
    0x381c0000, 0x381c2000, 0x381c4000, 0x381c6000, 0x381c8000, 0x381ca000,
    0x381cc000, 0x381ce000, 0x381d0000, 0x381d2000, 0x381d4000, 0x381d6000,
    0x381d8000, 0x381da000, 0x381dc000, 0x381de000, 0x381e0000, 0x381e2000,
    0x381e4000, 0x381e6000, 0x381e8000, 0x381ea000, 0x381ec000, 0x381ee000,
    0x381f0000, 0x381f2000, 0x381f4000, 0x381f6000, 0x381f8000, 0x381fa000,
    0x381fc000, 0x381fe000, 0x38200000, 0x38202000, 0x38204000, 0x38206000,
    0x38208000, 0x3820a000, 0x3820c000, 0x3820e000, 0x38210000, 0x38212000,
    0x38214000, 0x38216000, 0x38218000, 0x3821a000, 0x3821c000, 0x3821e000,
    0x38220000, 0x38222000, 0x38224000, 0x38226000, 0x38228000, 0x3822a000,
    0x3822c000, 0x3822e000, 0x38230000, 0x38232000, 0x38234000, 0x38236000,
    0x38238000, 0x3823a000, 0x3823c000, 0x3823e000, 0x38240000, 0x38242000,
    0x38244000, 0x38246000, 0x38248000, 0x3824a000, 0x3824c000, 0x3824e000,
    0x38250000, 0x38252000, 0x38254000, 0x38256000, 0x38258000, 0x3825a000,
    0x3825c000, 0x3825e000, 0x38260000, 0x38262000, 0x38264000, 0x38266000,
    0x38268000, 0x3826a000, 0x3826c000, 0x3826e000, 0x38270000, 0x38272000,
    0x38274000, 0x38276000, 0x38278000, 0x3827a000, 0x3827c000, 0x3827e000,
    0x38280000, 0x38282000, 0x38284000, 0x38286000, 0x38288000, 0x3828a000,
    0x3828c000, 0x3828e000, 0x38290000, 0x38292000, 0x38294000, 0x38296000,
    0x38298000, 0x3829a000, 0x3829c000, 0x3829e000, 0x382a0000, 0x382a2000,
    0x382a4000, 0x382a6000, 0x382a8000, 0x382aa000, 0x382ac000, 0x382ae000,
    0x382b0000, 0x382b2000, 0x382b4000, 0x382b6000, 0x382b8000, 0x382ba000,
    0x382bc000, 0x382be000, 0x382c0000, 0x382c2000, 0x382c4000, 0x382c6000,
    0x382c8000, 0x382ca000, 0x382cc000, 0x382ce000, 0x382d0000, 0x382d2000,
    0x382d4000, 0x382d6000, 0x382d8000, 0x382da000, 0x382dc000, 0x382de000,
    0x382e0000, 0x382e2000, 0x382e4000, 0x382e6000, 0x382e8000, 0x382ea000,
    0x382ec000, 0x382ee000, 0x382f0000, 0x382f2000, 0x382f4000, 0x382f6000,
    0x382f8000, 0x382fa000, 0x382fc000, 0x382fe000, 0x38300000, 0x38302000,
    0x38304000, 0x38306000, 0x38308000, 0x3830a000, 0x3830c000, 0x3830e000,
    0x38310000, 0x38312000, 0x38314000, 0x38316000, 0x38318000, 0x3831a000,
    0x3831c000, 0x3831e000, 0x38320000, 0x38322000, 0x38324000, 0x38326000,
    0x38328000, 0x3832a000, 0x3832c000, 0x3832e000, 0x38330000, 0x38332000,
    0x38334000, 0x38336000, 0x38338000, 0x3833a000, 0x3833c000, 0x3833e000,
    0x38340000, 0x38342000, 0x38344000, 0x38346000, 0x38348000, 0x3834a000,
    0x3834c000, 0x3834e000, 0x38350000, 0x38352000, 0x38354000, 0x38356000,
    0x38358000, 0x3835a000, 0x3835c000, 0x3835e000, 0x38360000, 0x38362000,
    0x38364000, 0x38366000, 0x38368000, 0x3836a000, 0x3836c000, 0x3836e000,
    0x38370000, 0x38372000, 0x38374000, 0x38376000, 0x38378000, 0x3837a000,
    0x3837c000, 0x3837e000, 0x38380000, 0x38382000, 0x38384000, 0x38386000,
    0x38388000, 0x3838a000, 0x3838c000, 0x3838e000, 0x38390000, 0x38392000,
    0x38394000, 0x38396000, 0x38398000, 0x3839a000, 0x3839c000, 0x3839e000,
    0x383a0000, 0x383a2000, 0x383a4000, 0x383a6000, 0x383a8000, 0x383aa000,
    0x383ac000, 0x383ae000, 0x383b0000, 0x383b2000, 0x383b4000, 0x383b6000,
    0x383b8000, 0x383ba000, 0x383bc000, 0x383be000, 0x383c0000, 0x383c2000,
    0x383c4000, 0x383c6000, 0x383c8000, 0x383ca000, 0x383cc000, 0x383ce000,
    0x383d0000, 0x383d2000, 0x383d4000, 0x383d6000, 0x383d8000, 0x383da000,
    0x383dc000, 0x383de000, 0x383e0000, 0x383e2000, 0x383e4000, 0x383e6000,
    0x383e8000, 0x383ea000, 0x383ec000, 0x383ee000, 0x383f0000, 0x383f2000,
    0x383f4000, 0x383f6000, 0x383f8000, 0x383fa000, 0x383fc000, 0x383fe000,
    0x38400000, 0x38402000, 0x38404000, 0x38406000, 0x38408000, 0x3840a000,
    0x3840c000, 0x3840e000, 0x38410000, 0x38412000, 0x38414000, 0x38416000,
    0x38418000, 0x3841a000, 0x3841c000, 0x3841e000, 0x38420000, 0x38422000,
    0x38424000, 0x38426000, 0x38428000, 0x3842a000, 0x3842c000, 0x3842e000,
    0x38430000, 0x38432000, 0x38434000, 0x38436000, 0x38438000, 0x3843a000,
    0x3843c000, 0x3843e000, 0x38440000, 0x38442000, 0x38444000, 0x38446000,
    0x38448000, 0x3844a000, 0x3844c000, 0x3844e000, 0x38450000, 0x38452000,
    0x38454000, 0x38456000, 0x38458000, 0x3845a000, 0x3845c000, 0x3845e000,
    0x38460000, 0x38462000, 0x38464000, 0x38466000, 0x38468000, 0x3846a000,
    0x3846c000, 0x3846e000, 0x38470000, 0x38472000, 0x38474000, 0x38476000,
    0x38478000, 0x3847a000, 0x3847c000, 0x3847e000, 0x38480000, 0x38482000,
    0x38484000, 0x38486000, 0x38488000, 0x3848a000, 0x3848c000, 0x3848e000,
    0x38490000, 0x38492000, 0x38494000, 0x38496000, 0x38498000, 0x3849a000,
    0x3849c000, 0x3849e000, 0x384a0000, 0x384a2000, 0x384a4000, 0x384a6000,
    0x384a8000, 0x384aa000, 0x384ac000, 0x384ae000, 0x384b0000, 0x384b2000,
    0x384b4000, 0x384b6000, 0x384b8000, 0x384ba000, 0x384bc000, 0x384be000,
    0x384c0000, 0x384c2000, 0x384c4000, 0x384c6000, 0x384c8000, 0x384ca000,
    0x384cc000, 0x384ce000, 0x384d0000, 0x384d2000, 0x384d4000, 0x384d6000,
    0x384d8000, 0x384da000, 0x384dc000, 0x384de000, 0x384e0000, 0x384e2000,
    0x384e4000, 0x384e6000, 0x384e8000, 0x384ea000, 0x384ec000, 0x384ee000,
    0x384f0000, 0x384f2000, 0x384f4000, 0x384f6000, 0x384f8000, 0x384fa000,
    0x384fc000, 0x384fe000, 0x38500000, 0x38502000, 0x38504000, 0x38506000,
    0x38508000, 0x3850a000, 0x3850c000, 0x3850e000, 0x38510000, 0x38512000,
    0x38514000, 0x38516000, 0x38518000, 0x3851a000, 0x3851c000, 0x3851e000,
    0x38520000, 0x38522000, 0x38524000, 0x38526000, 0x38528000, 0x3852a000,
    0x3852c000, 0x3852e000, 0x38530000, 0x38532000, 0x38534000, 0x38536000,
    0x38538000, 0x3853a000, 0x3853c000, 0x3853e000, 0x38540000, 0x38542000,
    0x38544000, 0x38546000, 0x38548000, 0x3854a000, 0x3854c000, 0x3854e000,
    0x38550000, 0x38552000, 0x38554000, 0x38556000, 0x38558000, 0x3855a000,
    0x3855c000, 0x3855e000, 0x38560000, 0x38562000, 0x38564000, 0x38566000,
    0x38568000, 0x3856a000, 0x3856c000, 0x3856e000, 0x38570000, 0x38572000,
    0x38574000, 0x38576000, 0x38578000, 0x3857a000, 0x3857c000, 0x3857e000,
    0x38580000, 0x38582000, 0x38584000, 0x38586000, 0x38588000, 0x3858a000,
    0x3858c000, 0x3858e000, 0x38590000, 0x38592000, 0x38594000, 0x38596000,
    0x38598000, 0x3859a000, 0x3859c000, 0x3859e000, 0x385a0000, 0x385a2000,
    0x385a4000, 0x385a6000, 0x385a8000, 0x385aa000, 0x385ac000, 0x385ae000,
    0x385b0000, 0x385b2000, 0x385b4000, 0x385b6000, 0x385b8000, 0x385ba000,
    0x385bc000, 0x385be000, 0x385c0000, 0x385c2000, 0x385c4000, 0x385c6000,
    0x385c8000, 0x385ca000, 0x385cc000, 0x385ce000, 0x385d0000, 0x385d2000,
    0x385d4000, 0x385d6000, 0x385d8000, 0x385da000, 0x385dc000, 0x385de000,
    0x385e0000, 0x385e2000, 0x385e4000, 0x385e6000, 0x385e8000, 0x385ea000,
    0x385ec000, 0x385ee000, 0x385f0000, 0x385f2000, 0x385f4000, 0x385f6000,
    0x385f8000, 0x385fa000, 0x385fc000, 0x385fe000, 0x38600000, 0x38602000,
    0x38604000, 0x38606000, 0x38608000, 0x3860a000, 0x3860c000, 0x3860e000,
    0x38610000, 0x38612000, 0x38614000, 0x38616000, 0x38618000, 0x3861a000,
    0x3861c000, 0x3861e000, 0x38620000, 0x38622000, 0x38624000, 0x38626000,
    0x38628000, 0x3862a000, 0x3862c000, 0x3862e000, 0x38630000, 0x38632000,
    0x38634000, 0x38636000, 0x38638000, 0x3863a000, 0x3863c000, 0x3863e000,
    0x38640000, 0x38642000, 0x38644000, 0x38646000, 0x38648000, 0x3864a000,
    0x3864c000, 0x3864e000, 0x38650000, 0x38652000, 0x38654000, 0x38656000,
    0x38658000, 0x3865a000, 0x3865c000, 0x3865e000, 0x38660000, 0x38662000,
    0x38664000, 0x38666000, 0x38668000, 0x3866a000, 0x3866c000, 0x3866e000,
    0x38670000, 0x38672000, 0x38674000, 0x38676000, 0x38678000, 0x3867a000,
    0x3867c000, 0x3867e000, 0x38680000, 0x38682000, 0x38684000, 0x38686000,
    0x38688000, 0x3868a000, 0x3868c000, 0x3868e000, 0x38690000, 0x38692000,
    0x38694000, 0x38696000, 0x38698000, 0x3869a000, 0x3869c000, 0x3869e000,
    0x386a0000, 0x386a2000, 0x386a4000, 0x386a6000, 0x386a8000, 0x386aa000,
    0x386ac000, 0x386ae000, 0x386b0000, 0x386b2000, 0x386b4000, 0x386b6000,
    0x386b8000, 0x386ba000, 0x386bc000, 0x386be000, 0x386c0000, 0x386c2000,
    0x386c4000, 0x386c6000, 0x386c8000, 0x386ca000, 0x386cc000, 0x386ce000,
    0x386d0000, 0x386d2000, 0x386d4000, 0x386d6000, 0x386d8000, 0x386da000,
    0x386dc000, 0x386de000, 0x386e0000, 0x386e2000, 0x386e4000, 0x386e6000,
    0x386e8000, 0x386ea000, 0x386ec000, 0x386ee000, 0x386f0000, 0x386f2000,
    0x386f4000, 0x386f6000, 0x386f8000, 0x386fa000, 0x386fc000, 0x386fe000,
    0x38700000, 0x38702000, 0x38704000, 0x38706000, 0x38708000, 0x3870a000,
    0x3870c000, 0x3870e000, 0x38710000, 0x38712000, 0x38714000, 0x38716000,
    0x38718000, 0x3871a000, 0x3871c000, 0x3871e000, 0x38720000, 0x38722000,
    0x38724000, 0x38726000, 0x38728000, 0x3872a000, 0x3872c000, 0x3872e000,
    0x38730000, 0x38732000, 0x38734000, 0x38736000, 0x38738000, 0x3873a000,
    0x3873c000, 0x3873e000, 0x38740000, 0x38742000, 0x38744000, 0x38746000,
    0x38748000, 0x3874a000, 0x3874c000, 0x3874e000, 0x38750000, 0x38752000,
    0x38754000, 0x38756000, 0x38758000, 0x3875a000, 0x3875c000, 0x3875e000,
    0x38760000, 0x38762000, 0x38764000, 0x38766000, 0x38768000, 0x3876a000,
    0x3876c000, 0x3876e000, 0x38770000, 0x38772000, 0x38774000, 0x38776000,
    0x38778000, 0x3877a000, 0x3877c000, 0x3877e000, 0x38780000, 0x38782000,
    0x38784000, 0x38786000, 0x38788000, 0x3878a000, 0x3878c000, 0x3878e000,
    0x38790000, 0x38792000, 0x38794000, 0x38796000, 0x38798000, 0x3879a000,
    0x3879c000, 0x3879e000, 0x387a0000, 0x387a2000, 0x387a4000, 0x387a6000,
    0x387a8000, 0x387aa000, 0x387ac000, 0x387ae000, 0x387b0000, 0x387b2000,
    0x387b4000, 0x387b6000, 0x387b8000, 0x387ba000, 0x387bc000, 0x387be000,
    0x387c0000, 0x387c2000, 0x387c4000, 0x387c6000, 0x387c8000, 0x387ca000,
    0x387cc000, 0x387ce000, 0x387d0000, 0x387d2000, 0x387d4000, 0x387d6000,
    0x387d8000, 0x387da000, 0x387dc000, 0x387de000, 0x387e0000, 0x387e2000,
    0x387e4000, 0x387e6000, 0x387e8000, 0x387ea000, 0x387ec000, 0x387ee000,
    0x387f0000, 0x387f2000, 0x387f4000, 0x387f6000, 0x387f8000, 0x387fa000,
    0x387fc000, 0x387fe000};

const uint16_t g_offset_table[64] = {
    0,    1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024,
    1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024,
    1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 0,
    1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024,
    1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024,
    1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024};

const uint32_t g_exponent_table[64] = {
    0x0,        0x800000,   0x1000000,  0x1800000,  0x2000000,  0x2800000,
    0x3000000,  0x3800000,  0x4000000,  0x4800000,  0x5000000,  0x5800000,
    0x6000000,  0x6800000,  0x7000000,  0x7800000,  0x8000000,  0x8800000,
    0x9000000,  0x9800000,  0xa000000,  0xa800000,  0xb000000,  0xb800000,
    0xc000000,  0xc800000,  0xd000000,  0xd800000,  0xe000000,  0xe800000,
    0xf000000,  0x47800000, 0x80000000, 0x80800000, 0x81000000, 0x81800000,
    0x82000000, 0x82800000, 0x83000000, 0x83800000, 0x84000000, 0x84800000,
    0x85000000, 0x85800000, 0x86000000, 0x86800000, 0x87000000, 0x87800000,
    0x88000000, 0x88800000, 0x89000000, 0x89800000, 0x8a000000, 0x8a800000,
    0x8b000000, 0x8b800000, 0x8c000000, 0x8c800000, 0x8d000000, 0x8d800000,
    0x8e000000, 0x8e800000, 0x8f000000, 0xc7800000};

float ConvertHalfFloatToFloat(uint16_t half) {
  uint32_t temp =
      g_mantissa_table[g_offset_table[half >> 10] + (half & 0x3ff)] +
      g_exponent_table[half >> 10];
  float ret;
  std::memcpy(&ret, &temp, 4);
  return ret;
}

/* BEGIN CODE SHARED WITH MOZILLA FIREFOX */

// The following packing and unpacking routines are expressed in terms of
// function templates and inline functions to achieve generality and speedup.
// Explicit template specializations correspond to the cases that would occur.
// Some code are merged back from Mozilla code in
// http://mxr.mozilla.org/mozilla-central/source/content/canvas/src/WebGLTexelConversions.h

//----------------------------------------------------------------------
// Pixel unpacking routines.
template <int format, typename SourceType, typename DstType>
void Unpack(const SourceType*, DstType*, unsigned) {
  NOTREACHED();
}

template <>
void Unpack<WebGLImageConversion::kDataFormatARGB8, uint8_t, uint8_t>(
    const uint8_t* source,
    uint8_t* destination,
    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = source[1];
    destination[1] = source[2];
    destination[2] = source[3];
    destination[3] = source[0];
    source += 4;
    destination += 4;
  }
}

template <>
void Unpack<WebGLImageConversion::kDataFormatABGR8, uint8_t, uint8_t>(
    const uint8_t* source,
    uint8_t* destination,
    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = source[3];
    destination[1] = source[2];
    destination[2] = source[1];
    destination[3] = source[0];
    source += 4;
    destination += 4;
  }
}

template <>
void Unpack<WebGLImageConversion::kDataFormatBGRA8, uint8_t, uint8_t>(
    const uint8_t* source,
    uint8_t* destination,
    unsigned pixels_per_row) {
  const uint32_t* source32 = reinterpret_cast_ptr<const uint32_t*>(source);
  uint32_t* destination32 = reinterpret_cast_ptr<uint32_t*>(destination);

#if defined(ARCH_CPU_X86_FAMILY)
  simd::UnpackOneRowOfBGRA8LittleToRGBA8(source32, destination32,
                                         pixels_per_row);
#endif
#if defined(HAVE_MIPS_MSA_INTRINSICS)
  simd::unpackOneRowOfBGRA8LittleToRGBA8MSA(source32, destination32,
                                            pixels_per_row);
#endif
#if defined(ARCH_CPU_LOONGARCH_FAMILY)
  simd::UnpackOneRowOfBGRA8LittleToRGBA8(source32, destination32,
                                         pixels_per_row);
#endif
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    uint32_t bgra = source32[i];
#if defined(ARCH_CPU_BIG_ENDIAN)
    uint32_t brMask = 0xff00ff00;
    uint32_t gaMask = 0x00ff00ff;
#else
    uint32_t br_mask = 0x00ff00ff;
    uint32_t ga_mask = 0xff00ff00;
#endif
    uint32_t rgba =
        (((bgra >> 16) | (bgra << 16)) & br_mask) | (bgra & ga_mask);
    destination32[i] = rgba;
  }
}

template <>
void Unpack<WebGLImageConversion::kDataFormatRGBA5551, uint16_t, uint8_t>(
    const uint16_t* source,
    uint8_t* destination,
    unsigned pixels_per_row) {
#if defined(ARCH_CPU_X86_FAMILY)
  simd::UnpackOneRowOfRGBA5551LittleToRGBA8(source, destination,
                                            pixels_per_row);
#endif
#if defined(CPU_ARM_NEON)
  simd::UnpackOneRowOfRGBA5551ToRGBA8(source, destination, pixels_per_row);
#endif
#if defined(HAVE_MIPS_MSA_INTRINSICS)
  simd::unpackOneRowOfRGBA5551ToRGBA8MSA(source, destination, pixels_per_row);
#endif
#if defined(ARCH_CPU_LOONGARCH_FAMILY)
  simd::UnpackOneRowOfRGBA5551LittleToRGBA8(source, destination,
                                            pixels_per_row);
#endif

  for (unsigned i = 0; i < pixels_per_row; ++i) {
    uint16_t packed_value = source[0];
    uint8_t r = packed_value >> 11;
    uint8_t g = (packed_value >> 6) & 0x1F;
    uint8_t b = (packed_value >> 1) & 0x1F;
    destination[0] = (r << 3) | (r & 0x7);
    destination[1] = (g << 3) | (g & 0x7);
    destination[2] = (b << 3) | (b & 0x7);
    destination[3] = (packed_value & 0x1) ? 0xFF : 0x0;
    source += 1;
    destination += 4;
  }
}

template <>
void Unpack<WebGLImageConversion::kDataFormatRGBA4444, uint16_t, uint8_t>(
    const uint16_t* source,
    uint8_t* destination,
    unsigned pixels_per_row) {
#if defined(ARCH_CPU_X86_FAMILY)
  simd::UnpackOneRowOfRGBA4444LittleToRGBA8(source, destination,
                                            pixels_per_row);
#endif
#if defined(CPU_ARM_NEON)
  simd::UnpackOneRowOfRGBA4444ToRGBA8(source, destination, pixels_per_row);
#endif
#if defined(HAVE_MIPS_MSA_INTRINSICS)
  simd::unpackOneRowOfRGBA4444ToRGBA8MSA(source, destination, pixels_per_row);
#endif
#if defined(ARCH_CPU_LOONGARCH_FAMILY)
  simd::UnpackOneRowOfRGBA4444LittleToRGBA8(source, destination,
                                            pixels_per_row);
#endif
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    uint16_t packed_value = source[0];
    uint8_t r = packed_value >> 12;
    uint8_t g = (packed_value >> 8) & 0x0F;
    uint8_t b = (packed_value >> 4) & 0x0F;
    uint8_t a = packed_value & 0x0F;
    destination[0] = r << 4 | r;
    destination[1] = g << 4 | g;
    destination[2] = b << 4 | b;
    destination[3] = a << 4 | a;
    source += 1;
    destination += 4;
  }
}

template <>
void Unpack<WebGLImageConversion::kDataFormatRA8, uint8_t, uint8_t>(
    const uint8_t* source,
    uint8_t* destination,
    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = source[0];
    destination[1] = source[0];
    destination[2] = source[0];
    destination[3] = source[1];
    source += 2;
    destination += 4;
  }
}

template <>
void Unpack<WebGLImageConversion::kDataFormatAR8, uint8_t, uint8_t>(
    const uint8_t* source,
    uint8_t* destination,
    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = source[1];
    destination[1] = source[1];
    destination[2] = source[1];
    destination[3] = source[0];
    source += 2;
    destination += 4;
  }
}

template <>
void Unpack<WebGLImageConversion::kDataFormatRGBA8, uint8_t, float>(
    const uint8_t* source,
    float* destination,
    unsigned pixels_per_row) {
  const float kScaleFactor = 1.0f / 255.0f;
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = source[0] * kScaleFactor;
    destination[1] = source[1] * kScaleFactor;
    destination[2] = source[2] * kScaleFactor;
    destination[3] = source[3] * kScaleFactor;
    source += 4;
    destination += 4;
  }
}

template <>
void Unpack<WebGLImageConversion::kDataFormatBGRA8, uint8_t, float>(
    const uint8_t* source,
    float* destination,
    unsigned pixels_per_row) {
  const float kScaleFactor = 1.0f / 255.0f;
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = source[2] * kScaleFactor;
    destination[1] = source[1] * kScaleFactor;
    destination[2] = source[0] * kScaleFactor;
    destination[3] = source[3] * kScaleFactor;
    source += 4;
    destination += 4;
  }
}

template <>
void Unpack<WebGLImageConversion::kDataFormatABGR8, uint8_t, float>(
    const uint8_t* source,
    float* destination,
    unsigned pixels_per_row) {
  const float kScaleFactor = 1.0f / 255.0f;
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = source[3] * kScaleFactor;
    destination[1] = source[2] * kScaleFactor;
    destination[2] = source[1] * kScaleFactor;
    destination[3] = source[0] * kScaleFactor;
    source += 4;
    destination += 4;
  }
}

template <>
void Unpack<WebGLImageConversion::kDataFormatARGB8, uint8_t, float>(
    const uint8_t* source,
    float* destination,
    unsigned pixels_per_row) {
  const float kScaleFactor = 1.0f / 255.0f;
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = source[1] * kScaleFactor;
    destination[1] = source[2] * kScaleFactor;
    destination[2] = source[3] * kScaleFactor;
    destination[3] = source[0] * kScaleFactor;
    source += 4;
    destination += 4;
  }
}

template <>
void Unpack<WebGLImageConversion::kDataFormatRA32F, float, float>(
    const float* source,
    float* destination,
    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = source[0];
    destination[1] = source[0];
    destination[2] = source[0];
    destination[3] = source[1];
    source += 2;
    destination += 4;
  }
}

template <>
void Unpack<WebGLImageConversion::kDataFormatRGBA2_10_10_10, uint32_t, float>(
    const uint32_t* source,
    float* destination,
    unsigned pixels_per_row) {
  static const float kRgbScaleFactor = 1.0f / 1023.0f;
  static const float kAlphaScaleFactor = 1.0f / 3.0f;
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    uint32_t packed_value = source[0];
    destination[0] = static_cast<float>(packed_value & 0x3FF) * kRgbScaleFactor;
    destination[1] =
        static_cast<float>((packed_value >> 10) & 0x3FF) * kRgbScaleFactor;
    destination[2] =
        static_cast<float>((packed_value >> 20) & 0x3FF) * kRgbScaleFactor;
    destination[3] = static_cast<float>(packed_value >> 30) * kAlphaScaleFactor;
    source += 1;
    destination += 4;
  }
}

// Used for non-trivial conversions of RGBA16F data.
template <>
void Unpack<WebGLImageConversion::kDataFormatRGBA16F, uint16_t, float>(
    const uint16_t* source,
    float* destination,
    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = ConvertHalfFloatToFloat(source[0]);
    destination[1] = ConvertHalfFloatToFloat(source[1]);
    destination[2] = ConvertHalfFloatToFloat(source[2]);
    destination[3] = ConvertHalfFloatToFloat(source[3]);
    source += 4;
    destination += 4;
  }
}

// Used for the trivial conversion of RGBA16F data to RGBA8.
template <>
void Unpack<WebGLImageConversion::kDataFormatRGBA16F, uint16_t, uint8_t>(
    const uint16_t* source,
    uint8_t* destination,
    unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] =
        ClampAndScaleFloat<uint8_t>(ConvertHalfFloatToFloat(source[0]));
    destination[1] =
        ClampAndScaleFloat<uint8_t>(ConvertHalfFloatToFloat(source[1]));
    destination[2] =
        ClampAndScaleFloat<uint8_t>(ConvertHalfFloatToFloat(source[2]));
    destination[3] =
        ClampAndScaleFloat<uint8_t>(ConvertHalfFloatToFloat(source[3]));
    source += 4;
    destination += 4;
  }
}

//----------------------------------------------------------------------
// Pixel packing routines.
//

// All of the formats below refer to the format of the texture being
// uploaded. Only the formats that accept DOM sources (images, videos,
// ImageBitmap, etc.) need to:
//
//  (a) support conversions from "other" formats than the destination
//      format, since the other cases are simply handling Y-flips or alpha
//      premultiplication of data supplied via ArrayBufferView
//
//  (b) support the kAlphaDoUnmultiply operation, which is needed because
//      there are some DOM-related data sources (like 2D canvas) which are
//      stored in premultiplied form. Note that the alpha-only formats
//      inherently don't need to support the kAlphaDoUnmultiply operation.
//
// The formats that accept DOM-related inputs are in the table for
// texImage2D taking TexImageSource in the WebGL 2.0 specification, plus
// all of the formats in the WebGL 1.0 specification, including legacy
// formats like luminance, alpha and luminance-alpha formats (which are
// renamed in the DataFormat enum to things like "red-alpha"). Extensions
// like EXT_texture_norm16 add to the supported formats
//
// Currently, those texture formats to which DOM-related inputs can be
// uploaded have to support two basic input formats coming from the rest of
// the browser: uint8_t, for RGBA8, and float, for RGBA16F.

template <int format, int alphaOp, typename SourceType, typename DstType>
void Pack(const SourceType*, DstType*, unsigned) {
  NOTREACHED();
}

template <>
void Pack<WebGLImageConversion::kDataFormatA8,
          WebGLImageConversion::kAlphaDoNothing,
          uint8_t,
          uint8_t>(const uint8_t* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = source[3];
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatA8,
          WebGLImageConversion::kAlphaDoNothing,
          float,
          uint8_t>(const float* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = ClampAndScaleFloat<uint8_t>(source[3]);
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatR8,
          WebGLImageConversion::kAlphaDoNothing,
          uint8_t,
          uint8_t>(const uint8_t* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = source[0];
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatR8,
          WebGLImageConversion::kAlphaDoNothing,
          float,
          uint8_t>(const float* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = ClampAndScaleFloat<uint8_t>(source[0]);
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatR8,
          WebGLImageConversion::kAlphaDoPremultiply,
          uint8_t,
          uint8_t>(const uint8_t* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] / 255.0f;
    uint8_t source_r =
        static_cast<uint8_t>(static_cast<float>(source[0]) * scale_factor);
    destination[0] = source_r;
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatR8,
          WebGLImageConversion::kAlphaDoPremultiply,
          float,
          uint8_t>(const float* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    uint8_t source_r = ClampAndScaleFloat<uint8_t>(source[0] * source[3]);
    destination[0] = source_r;
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatR8,
          WebGLImageConversion::kAlphaDoUnmultiply,
          uint8_t,
          uint8_t>(const uint8_t* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
#if defined(ARCH_CPU_X86_FAMILY)
  simd::PackOneRowOfRGBA8LittleToR8(source, destination, pixels_per_row);
#endif
#if defined(HAVE_MIPS_MSA_INTRINSICS)
  simd::packOneRowOfRGBA8LittleToR8MSA(source, destination, pixels_per_row);
#endif
#if defined(ARCH_CPU_LOONGARCH_FAMILY)
  simd::PackOneRowOfRGBA8LittleToR8(source, destination, pixels_per_row);
#endif
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 255.0f / source[3] : 1.0f;
    uint8_t source_r =
        static_cast<uint8_t>(static_cast<float>(source[0]) * scale_factor);
    destination[0] = source_r;
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatR8,
          WebGLImageConversion::kAlphaDoUnmultiply,
          float,
          uint8_t>(const float* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 1.0f / source[3] : 1.0f;
    uint8_t source_r = ClampAndScaleFloat<uint8_t>(source[0] * scale_factor);
    destination[0] = source_r;
    source += 4;
    destination += 1;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRA8,
          WebGLImageConversion::kAlphaDoNothing,
          uint8_t,
          uint8_t>(const uint8_t* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = source[0];
    destination[1] = source[3];
    source += 4;
    destination += 2;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRA8,
          WebGLImageConversion::kAlphaDoNothing,
          float,
          uint8_t>(const float* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = ClampAndScaleFloat<uint8_t>(source[0]);
    destination[1] = ClampAndScaleFloat<uint8_t>(source[3]);
    source += 4;
    destination += 2;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRA8,
          WebGLImageConversion::kAlphaDoPremultiply,
          uint8_t,
          uint8_t>(const uint8_t* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] / 255.0f;
    uint8_t source_r =
        static_cast<uint8_t>(static_cast<float>(source[0]) * scale_factor);
    destination[0] = source_r;
    destination[1] = source[3];
    source += 4;
    destination += 2;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRA8,
          WebGLImageConversion::kAlphaDoPremultiply,
          float,
          uint8_t>(const float* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = ClampAndScaleFloat<uint8_t>(source[0] * source[3]);
    destination[1] = ClampAndScaleFloat<uint8_t>(source[3]);
    source += 4;
    destination += 2;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRA8,
          WebGLImageConversion::kAlphaDoUnmultiply,
          uint8_t,
          uint8_t>(const uint8_t* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
#if defined(ARCH_CPU_X86_FAMILY)
  simd::PackOneRowOfRGBA8LittleToRA8(source, destination, pixels_per_row);
#endif
#if defined(HAVE_MIPS_MSA_INTRINSICS)
  simd::packOneRowOfRGBA8LittleToRA8MSA(source, destination, pixels_per_row);
#endif
#if defined(ARCH_CPU_LOONGARCH_FAMILY)
  simd::PackOneRowOfRGBA8LittleToRA8(source, destination, pixels_per_row);
#endif
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 255.0f / source[3] : 1.0f;
    uint8_t source_r =
        static_cast<uint8_t>(static_cast<float>(source[0]) * scale_factor);
    destination[0] = source_r;
    destination[1] = source[3];
    source += 4;
    destination += 2;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRA8,
          WebGLImageConversion::kAlphaDoUnmultiply,
          float,
          uint8_t>(const float* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] ? 1.0f / source[3] : 1.0f;
    uint8_t source_r = ClampAndScaleFloat<uint8_t>(source[0] * scale_factor);
    destination[0] = source_r;
    destination[1] = ClampAndScaleFloat<uint8_t>(source[3]);
    source += 4;
    destination += 2;
  }
}

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

template <>
void Pack<WebGLImageConversion::kDataFormatRGB8,
          WebGLImageConversion::kAlphaDoNothing,
          float,
          uint8_t>(const float* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    destination[0] = ClampAndScaleFloat<uint8_t>(source[0]);
    destination[1] = ClampAndScaleFloat<uint8_t>(source[1]);
    destination[2] = ClampAndScaleFloat<uint8_t>(source[2]);
    source += 4;
    destination += 3;
  }
}

template <>
void Pack<WebGLImageConversion::kDataFormatRGB8,
          WebGLImageConversion::kAlphaDoPremultiply,
          uint8_t,
          uint8_t>(const uint8_t* source,
                   uint8_t* destination,
                   unsigned pixels_per_row) {
  for (unsigned i = 0; i < pixels_per_row; ++i) {
    float scale_factor = source[3] / 255.0f;
    uin
"""


```