Response:
Let's break down the thought process for analyzing the provided C++ code snippet and fulfilling the user's request.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `JPEGImageDecoder` class within the Chromium Blink rendering engine. The request also asks for specific connections to web technologies (JavaScript, HTML, CSS), logical reasoning with inputs and outputs, and potential user/programmer errors. Finally, it asks for a summary of the functionality as part 2 of a series.

**2. Initial Code Scan and Keyword Recognition:**

The first step is to quickly scan the code for important keywords and patterns. This helps establish the core responsibilities of the class. Keywords like:

* `JPEGImageDecoder`:  The class name itself clearly indicates its purpose.
* `Decode`:  Multiple `Decode` methods suggest the core operation.
* `YUV`, `RGB`, `CMYK`: These point to color space conversions and handling different image formats within JPEG.
* `Size`, `Width`, `Height`:  Image dimensions are being managed.
* `reader_`, `JPEGImageReader`: There's a dependency on another class to handle the low-level JPEG parsing.
* `ImageFrame`, `ImagePlanes`: These likely represent the in-memory representation of the decoded image data.
* `SkData`, `SkISize`, `SkYUVColorSpace`:  Integration with the Skia graphics library is evident.
* `metadata_decoder`: Support for embedded metadata.
* `TRACE_EVENT`: Performance tracking.
* `gfx::Size`, `cc::YUVSubsampling`: Integration with Chromium's graphics and compositing layers.

**3. Deconstructing Function by Function:**

Next, analyze each function individually to understand its specific role:

* **Constructor (`JPEGImageDecoder(...)`)**: Initializes the decoder with data and offset.
* **`SetDecodedSize(...)`**:  Sets the decoded image dimensions.
* **`GetYUVSubsampling()`**: Retrieves YUV subsampling information (how chroma is sampled relative to luma). Crucial for understanding the structure of YUV data.
* **`DecodedYUVSize(...)`**: Calculates the dimensions of the individual Y, U, and V planes.
* **`DecodedYUVWidthBytes(...)`**: Calculates the row stride (bytes per row) for the YUV planes.
* **`DesiredScaleNumerator()` (both static and non-static)**:  Deals with downsampling images to fit within memory constraints. This is important for performance.
* **`ShouldGenerateAllSizes()`**:  Indicates if all possible decode sizes are supported.
* **`DecodeToYUV()`**:  Triggers decoding specifically into the YUV color space.
* **`GetYUVColorSpace()`**: Returns the YUV color space used by the decoder.
* **`SetSupportedDecodeSizes(...)` and `GetSupportedDecodeSizes()`**:  Manages a list of supported output sizes. This is related to optimizing for different display resolutions.
* **`GetGainmapInfoAndData(...)`**:  Handles gain maps, which are auxiliary images used for HDR rendering.
* **`GetImageCodedSize()`**: Returns the actual size of the encoded JPEG data, which might be different from the decoded size due to subsampling.
* **`DecodeSize()`**: Decodes only the image header to get metadata like dimensions.
* **`Decode(wtf_size_t)`**: Decodes the entire image to a bitmap.
* **`MakeMetadataForDecodeAcceleration()`**: Creates metadata used for hardware acceleration of decoding.
* **`SetPixel<colorSpace>(...)`**: (Template function) Writes pixel data to the `ImageFrame` based on the color space. Note the explicit specializations for `JCS_RGB` and `JCS_CMYK`.
* **`OutputRows<colorSpace>(...)`**: (Template function)  Reads scanlines from the JPEG data and writes them to the `ImageFrame`. Includes color profile transformation.
* **`OutputRawData(...)`**:  Specifically handles outputting to YUV image planes.
* **`OutputScanlines()`**:  The main function for outputting decoded scanlines, choosing between bitmap and YUV output.
* **`Complete()`**: Finalizes the decoding process, marking the image as complete.
* **`IsComplete(...)`**: Checks if the decoding is finished.
* **`Decode(DecodingMode)`**: The core decoding function, managing the `JPEGImageReader` and handling different decoding modes.

**4. Identifying Connections to Web Technologies:**

This requires thinking about how JPEG images are used in web browsers:

* **HTML `<img>` tag:**  The most direct connection. The browser needs to decode JPEG images for display.
* **CSS `background-image`:** JPEGs are commonly used as background images.
* **JavaScript (Canvas API, Image API, Fetch API):** JavaScript can manipulate image data, fetch images, and draw them on canvases. The browser's JPEG decoder is used internally when these APIs deal with JPEG files.

**5. Formulating Logical Reasoning (Input/Output):**

Consider a typical scenario:

* **Input:** Raw JPEG image data (a byte stream).
* **Processing:** The `JPEGImageDecoder` parses the header, potentially downsamples the image, converts color spaces, and writes the pixel data to memory.
* **Output:**  Either a bitmap (RGBA pixels) in an `ImageFrame` or YUV image planes. The metadata (dimensions, color space, etc.) is also an important output.

**6. Identifying Potential Errors:**

Think about common issues with image decoding:

* **Corrupted JPEG data:** The decoder needs to handle this gracefully.
* **Insufficient memory:** Downsampling logic helps, but very large images can still cause issues.
* **Unsupported JPEG features:**  While libjpeg is widely compatible, some exotic JPEG features might not be fully supported.
* **Incorrect usage of the decoder API:**  Calling methods in the wrong order or with invalid parameters.

**7. Structuring the Output (Following the Request):**

Organize the findings according to the user's specific questions:

* **Functionality Listing:**  Provide a bulleted list summarizing what each function does.
* **Relationship to Web Technologies:** Explain how the `JPEGImageDecoder` is essential for rendering JPEGs in the browser, giving examples with HTML, CSS, and JavaScript.
* **Logical Reasoning (Input/Output):** Describe the decoding process with a clear input and output.
* **User/Programming Errors:**  List potential errors and how they might occur.
* **Summary of Functionality (Part 2):**  Provide a concise overview of the class's purpose and key responsibilities, referencing the previous analysis (implicitly, since this is part 2).

**8. Refining and Reviewing:**

Finally, review the generated output for clarity, accuracy, and completeness. Ensure that the language is easy to understand and that all aspects of the request have been addressed. For example, make sure the explanation of YUV subsampling is clear and relates to the code. Double-check the input/output example for correctness.

This systematic approach, combining code analysis, domain knowledge (web technologies, image formats), and logical reasoning, allows for a comprehensive and accurate understanding of the `JPEGImageDecoder`'s role.
这是对 `blink/renderer/platform/image-decoders/jpeg/jpeg_image_decoder.cc` 文件代码片段的第二部分分析，延续了第一部分的内容，进一步归纳其功能。

根据提供的代码片段，我们可以总结出 `JPEGImageDecoder` 的以下关键功能：

**核心图像解码与数据处理:**

* **获取和管理解码后的 YUV 数据：**
    * `GetYUVSubsampling()`:  返回 JPEG 图像的 YUV 颜色空间的子采样信息（例如 4:2:0, 4:4:4），这决定了色度分量相对于亮度分量的采样率。
    * `DecodedYUVSize(cc::YUVIndex index)`:  计算并返回解码后 YUV 各个分量（Y, U, V）的尺寸。
    * `DecodedYUVWidthBytes(cc::YUVIndex index)`: 计算并返回解码后 YUV 各个分量的每行字节数（stride）。
* **支持解码到 YUV 格式:**
    * `DecodeToYUV()`:  执行解码并将结果存储为 YUV 图像平面。
    * `GetYUVColorSpace()`: 返回解码后 YUV 数据的色彩空间，默认为 `kJPEG_SkYUVColorSpace`。
* **原始 YUV 数据输出:**
    * `OutputRawData(JPEGImageReader* reader, ImagePlanes* image_planes)`:  将解码后的原始 YUV 数据直接写入 `ImagePlanes` 对象中，避免了中间的 RGB 转换。
* **处理图像的编码尺寸:**
    * `GetImageCodedSize()`:  返回 JPEG 图像实际编码时使用的尺寸，这可能与解码后的尺寸不同，尤其是在存在色度子采样的情况下。

**解码控制与优化:**

* **支持按需解码尺寸:**
    * `SetSupportedDecodeSizes(Vector<SkISize> sizes)`:  允许设置支持的解码输出尺寸列表。
    * `GetSupportedDecodeSizes()`:  返回当前支持的解码输出尺寸列表。
* **动态调整解码比例:**
    * `DesiredScaleNumerator()` (静态和非静态方法):  根据最大解码字节数和原始字节数，计算出合适的缩放比例分子，用于降低内存消耗。这个方法决定了在内存受限的情况下，如何对图像进行降采样。
    * `ShouldGenerateAllSizes()`:  判断是否需要生成所有可能的解码尺寸，通常当 `supported_decode_sizes_` 为空时返回 true。
* **解码模式控制:**
    * `DecodeSize()`:  只解码 JPEG 头部信息，获取图像尺寸等元数据。
    * `Decode(wtf_size_t)`:  执行完整的图像解码，生成位图数据。
    * `Decode(DecodingMode decoding_mode)`:  根据指定的解码模式进行解码，例如解码到 YUV 或位图。

**元数据处理:**

* **获取 Gainmap 信息:**
    * `GetGainmapInfoAndData(SkGainmapInfo& out_gainmap_info, scoped_refptr<SegmentReader>& out_gainmap_data)`:  尝试从 JPEG 文件中提取 Gainmap（用于高动态范围图像）的相关信息和数据。

**与 Chromium 渲染引擎的集成:**

* **创建解码加速所需的元数据:**
    * `MakeMetadataForDecodeAcceleration()`:  生成用于硬件加速解码的元数据，包括是否为渐进式 JPEG 以及编码尺寸等信息。

**错误处理与状态管理:**

* **`Complete()`:**  标记解码完成，并设置帧缓冲区的状态为完整。
* **`IsComplete(const JPEGImageDecoder* decoder, JPEGImageDecoder::DecodingMode decoding_mode)`:** 检查指定解码模式下解码是否已完成。

**像素数据输出 (模板函数):**

* **`SetPixel<colorSpace>(ImageFrame::PixelData*, JSAMPARRAY samples, int column)` (模板函数):**  根据不同的颜色空间（目前只实现了 `JCS_RGB` 和 `JCS_CMYK`）将解码后的像素数据写入 `ImageFrame::PixelData`。这部分代码是高度优化的，直接操作像素数据。
* **`OutputRows<colorSpace>(JPEGImageReader* reader, ImageFrame& buffer)` (模板函数):**  读取 JPEG 解码器输出的扫描线，并使用 `SetPixel` 函数将像素数据写入到 `ImageFrame` 中。还处理了颜色配置文件转换。
* **`OutputScanlines()`:**  根据是否解码到 YUV 以及颜色空间，选择合适的输出方法（`OutputRawData` 或 `OutputRows`）。

**延续第一部分的总结，`JPEGImageDecoder` 的核心职责是：**

1. **解析 JPEG 图像数据：**  使用 `JPEGImageReader` 从原始数据中读取并解析 JPEG 的各个段。
2. **解码 JPEG 图像：**  将压缩的 JPEG 数据解压成像素数据，支持解码成 RGB 位图或 YUV 数据。
3. **管理解码后的图像数据：**  存储和管理解码后的像素数据，无论是位图格式还是 YUV 格式。
4. **提供解码后的图像信息：**  提供图像的尺寸、颜色空间、YUV 子采样等信息。
5. **支持按需缩放解码：**  根据内存限制和需求，动态调整解码的输出尺寸。
6. **与 Chromium 渲染管道集成：**  提供 Chromium 渲染引擎所需的图像数据和元数据，例如用于硬件加速解码的信息。
7. **处理特殊图像类型：**  支持处理包含 Gainmap 等额外信息的 JPEG 图像。

这段代码进一步展示了 `JPEGImageDecoder` 在处理 YUV 数据、优化解码过程以及与 Chromium 渲染引擎更深层次的集成方面所起的作用。 它不仅仅是将 JPEG 解码成位图，还支持更底层的 YUV 解码，这在视频处理和硬件加速解码中非常重要。

Prompt: 
```
这是目录为blink/renderer/platform/image-decoders/jpeg/jpeg_image_decoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
signed width, unsigned height) {
  decoded_size_ = gfx::Size(width, height);
}

cc::YUVSubsampling JPEGImageDecoder::GetYUVSubsampling() const {
  DCHECK(reader_->Info());
  // reader_->Info() should have gone through a jpeg_read_header() call.
  DCHECK(IsDecodedSizeAvailable());
  return YuvSubsampling(*reader_->Info());
}

gfx::Size JPEGImageDecoder::DecodedYUVSize(cc::YUVIndex index) const {
  DCHECK(reader_);
  const jpeg_decompress_struct* info = reader_->Info();

  DCHECK_EQ(info->jpeg_color_space, JCS_YCbCr);
  return ComputeYUVSize(info, static_cast<int>(index));
}

wtf_size_t JPEGImageDecoder::DecodedYUVWidthBytes(cc::YUVIndex index) const {
  DCHECK(reader_);
  const jpeg_decompress_struct* info = reader_->Info();

  DCHECK_EQ(info->jpeg_color_space, JCS_YCbCr);
  return ComputeYUVWidthBytes(info, static_cast<int>(index));
}

unsigned JPEGImageDecoder::DesiredScaleNumerator() const {
  wtf_size_t original_bytes = Size().width() * Size().height() * 4;

  return JPEGImageDecoder::DesiredScaleNumerator(
      max_decoded_bytes_, original_bytes, g_scale_denominator);
}

// static
unsigned JPEGImageDecoder::DesiredScaleNumerator(wtf_size_t max_decoded_bytes,
                                                 wtf_size_t original_bytes,
                                                 unsigned scale_denominator) {
  if (original_bytes <= max_decoded_bytes) {
    return scale_denominator;
  }

  // Downsample according to the maximum decoded size.
  return static_cast<unsigned>(floor(sqrt(
      // MSVC needs explicit parameter type for sqrt().
      static_cast<float>(max_decoded_bytes) / original_bytes *
      scale_denominator * scale_denominator)));
}

bool JPEGImageDecoder::ShouldGenerateAllSizes() const {
  return supported_decode_sizes_.empty();
}

void JPEGImageDecoder::DecodeToYUV() {
  DCHECK(HasImagePlanes());
  DCHECK(CanDecodeToYUV());

  // Only 8-bit YUV decode is currently supported.
  DCHECK_EQ(image_planes_->color_type(), kGray_8_SkColorType);

  {
    TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("devtools.timeline"), "Decode Image",
                 "imageType", "JPEG");
    Decode(DecodingMode::kDecodeToYuv);
  }
}

// TODO(crbug.com/919627): Confirm that this is correct for all cases.
SkYUVColorSpace JPEGImageDecoder::GetYUVColorSpace() const {
  return SkYUVColorSpace::kJPEG_SkYUVColorSpace;
}

void JPEGImageDecoder::SetSupportedDecodeSizes(Vector<SkISize> sizes) {
  supported_decode_sizes_ = std::move(sizes);
}

Vector<SkISize> JPEGImageDecoder::GetSupportedDecodeSizes() const {
  // DCHECK IsDecodedSizeAvailable instead of IsSizeAvailable, since the latter
  // has side effects of actually doing the decode.
  DCHECK(IsDecodedSizeAvailable());
  return supported_decode_sizes_;
}

bool JPEGImageDecoder::GetGainmapInfoAndData(
    SkGainmapInfo& out_gainmap_info,
    scoped_refptr<SegmentReader>& out_gainmap_data) const {
  auto* metadata_decoder = reader_ ? reader_->GetMetadataDecoder() : nullptr;
  if (!metadata_decoder) {
    return false;
  }

  if (!metadata_decoder->mightHaveGainmapImage()) {
    return false;
  }

  // TODO(crbug.com/356827770): This function will be removed once all decoders
  // rely on ImageDecoder::aux_image_ to decode the gainmap, instead of
  // extracting gainmap data.
  sk_sp<SkData> base_image_data = data_->GetAsSkData();
  DCHECK(base_image_data);
  sk_sp<SkData> gainmap_image_data;
  SkGainmapInfo gainmap_info;
  if (!metadata_decoder->findGainmapImage(base_image_data, gainmap_image_data,
                                          gainmap_info)) {
    return false;
  }
  out_gainmap_info = gainmap_info;
  out_gainmap_data = data_;
  return true;
}

gfx::Size JPEGImageDecoder::GetImageCodedSize() const {
  // We use the |max_{h,v}_samp_factor|s returned by
  // AreValidSampleFactorsAvailable() since the ones available via
  // Info()->max_{h,v}_samp_factor are not updated until the image is actually
  // being decoded.
  int max_h_samp_factor;
  int max_v_samp_factor;
  if (!reader_->AreValidSampleFactorsAvailable(&max_h_samp_factor,
                                               &max_v_samp_factor)) {
    return gfx::Size();
  }

  const int coded_width = Align(Size().width(), max_h_samp_factor * 8);
  const int coded_height = Align(Size().height(), max_v_samp_factor * 8);

  return gfx::Size(coded_width, coded_height);
}

void JPEGImageDecoder::DecodeSize() {
  Decode(DecodingMode::kDecodeHeader);
}

void JPEGImageDecoder::Decode(wtf_size_t) {
  // Use DecodeToYUV for YUV decoding.
  Decode(DecodingMode::kDecodeToBitmap);
}

cc::ImageHeaderMetadata JPEGImageDecoder::MakeMetadataForDecodeAcceleration()
    const {
  cc::ImageHeaderMetadata image_metadata =
      ImageDecoder::MakeMetadataForDecodeAcceleration();
  image_metadata.jpeg_is_progressive = reader_->Info()->buffered_image;
  image_metadata.coded_size = GetImageCodedSize();
  return image_metadata;
}

// At the moment we support only JCS_RGB and JCS_CMYK values of the
// J_COLOR_SPACE enum.
// If you need a specific implementation for other J_COLOR_SPACE values,
// please add a full template specialization for this function below.
template <J_COLOR_SPACE colorSpace>
void SetPixel(ImageFrame::PixelData*, JSAMPARRAY samples, int column) = delete;

// Used only for debugging with libjpeg (instead of libjpeg-turbo).
template <>
void SetPixel<JCS_RGB>(ImageFrame::PixelData* pixel,
                       JSAMPARRAY samples,
                       int column) {
  JSAMPLE* jsample = *samples + column * 3;
  ImageFrame::SetRGBARaw(pixel, jsample[0], jsample[1], jsample[2], 255);
}

template <>
void SetPixel<JCS_CMYK>(ImageFrame::PixelData* pixel,
                        JSAMPARRAY samples,
                        int column) {
  JSAMPLE* jsample = *samples + column * 4;

  // Source is 'Inverted CMYK', output is RGB.
  // See: http://www.easyrgb.com/math.php?MATH=M12#text12
  // Or: http://www.ilkeratalay.com/colorspacesfaq.php#rgb
  // From CMYK to CMY:
  // X =   X    * (1 -   K   ) +   K  [for X = C, M, or Y]
  // Thus, from Inverted CMYK to CMY is:
  // X = (1-iX) * (1 - (1-iK)) + (1-iK) => 1 - iX*iK
  // From CMY (0..1) to RGB (0..1):
  // R = 1 - C => 1 - (1 - iC*iK) => iC*iK  [G and B similar]
  unsigned k = jsample[3];
  ImageFrame::SetRGBARaw(pixel, jsample[0] * k / 255, jsample[1] * k / 255,
                         jsample[2] * k / 255, 255);
}

// Used only for JCS_CMYK and JCS_RGB output.  Note that JCS_RGB is used only
// for debugging with libjpeg (instead of libjpeg-turbo).
template <J_COLOR_SPACE colorSpace>
bool OutputRows(JPEGImageReader* reader, ImageFrame& buffer) {
  JSAMPARRAY samples = reader->Samples();
  jpeg_decompress_struct* info = reader->Info();
  int width = info->output_width;

  while (info->output_scanline < info->output_height) {
    // jpeg_read_scanlines will increase the scanline counter, so we
    // save the scanline before calling it.
    int y = info->output_scanline;
    // Request one scanline: returns 0 or 1 scanlines.
    if (jpeg_read_scanlines(info, samples, 1) != 1) {
      return false;
    }

    ImageFrame::PixelData* pixel = buffer.GetAddr(0, y);
    for (int x = 0; x < width; ++pixel, ++x) {
      SetPixel<colorSpace>(pixel, samples, x);
    }

    ColorProfileTransform* xform = reader->Decoder()->ColorTransform();
    if (xform) {
      ImageFrame::PixelData* row = buffer.GetAddr(0, y);
      skcms_AlphaFormat alpha_format = skcms_AlphaFormat_Unpremul;
      bool color_conversion_successful = skcms_Transform(
          row, XformColorFormat(), alpha_format, xform->SrcProfile(), row,
          XformColorFormat(), alpha_format, xform->DstProfile(), width);
      DCHECK(color_conversion_successful);
    }
  }

  buffer.SetPixelsChanged(true);
  return true;
}

static bool OutputRawData(JPEGImageReader* reader, ImagePlanes* image_planes) {
  JSAMPARRAY samples = reader->Samples();
  jpeg_decompress_struct* info = reader->Info();

  DCHECK_EQ(info->out_color_space, JCS_YCbCr);

  JSAMPARRAY bufferraw[3];
  JSAMPROW bufferraw2[32];
  bufferraw[0] = &bufferraw2[0];   // Y channel rows (8 or 16)
  bufferraw[1] = &bufferraw2[16];  // U channel rows (8)
  bufferraw[2] = &bufferraw2[24];  // V channel rows (8)
  int y_height = info->output_height;
  int v = info->comp_info[0].v_samp_factor;
  gfx::Size uv_size = reader->UvSize();
  int uv_height = uv_size.height();
  JSAMPROW output_y =
      static_cast<JSAMPROW>(image_planes->Plane(cc::YUVIndex::kY));
  JSAMPROW output_u =
      static_cast<JSAMPROW>(image_planes->Plane(cc::YUVIndex::kU));
  JSAMPROW output_v =
      static_cast<JSAMPROW>(image_planes->Plane(cc::YUVIndex::kV));
  wtf_size_t row_bytes_y = image_planes->RowBytes(cc::YUVIndex::kY);
  wtf_size_t row_bytes_u = image_planes->RowBytes(cc::YUVIndex::kU);
  wtf_size_t row_bytes_v = image_planes->RowBytes(cc::YUVIndex::kV);

  // Request 8 or 16 scanlines: returns 0 or more scanlines.
  int y_scanlines_to_read = DCTSIZE * v;
  JSAMPROW dummy_row = *samples;
  while (info->output_scanline < info->output_height) {
    // Assign 8 or 16 rows of memory to read the Y channel.
    for (int i = 0; i < y_scanlines_to_read; ++i) {
      int scanline = info->output_scanline + i;
      if (scanline < y_height) {
        bufferraw2[i] = &output_y[scanline * row_bytes_y];
      } else {
        bufferraw2[i] = dummy_row;
      }
    }

    // Assign 8 rows of memory to read the U and V channels.
    int scaled_scanline = info->output_scanline / v;
    for (int i = 0; i < 8; ++i) {
      int scanline = scaled_scanline + i;
      if (scanline < uv_height) {
        bufferraw2[16 + i] = &output_u[scanline * row_bytes_u];
        bufferraw2[24 + i] = &output_v[scanline * row_bytes_v];
      } else {
        bufferraw2[16 + i] = dummy_row;
        bufferraw2[24 + i] = dummy_row;
      }
    }

    JDIMENSION scanlines_read =
        jpeg_read_raw_data(info, bufferraw, y_scanlines_to_read);
    if (!scanlines_read) {
      return false;
    }
  }

  info->output_scanline = std::min(info->output_scanline, info->output_height);
  image_planes->SetHasCompleteScan();
  return true;
}

bool JPEGImageDecoder::OutputScanlines() {
  if (HasImagePlanes()) {
    return OutputRawData(reader_.get(), image_planes_.get());
  }

  if (frame_buffer_cache_.empty()) {
    return false;
  }

  jpeg_decompress_struct* info = reader_->Info();

  // Initialize the framebuffer if needed.
  ImageFrame& buffer = frame_buffer_cache_[0];
  if (buffer.GetStatus() == ImageFrame::kFrameEmpty) {
    DCHECK_EQ(info->output_width,
              static_cast<JDIMENSION>(decoded_size_.width()));
    DCHECK_EQ(info->output_height,
              static_cast<JDIMENSION>(decoded_size_.height()));

    if (!buffer.AllocatePixelData(info->output_width, info->output_height,
                                  ColorSpaceForSkImages())) {
      return SetFailed();
    }

    buffer.ZeroFillPixelData();
    // The buffer is transparent outside the decoded area while the image is
    // loading. The image will be marked fully opaque in Complete().
    buffer.SetStatus(ImageFrame::kFramePartial);
    buffer.SetHasAlpha(true);

    // For JPEGs, the frame always fills the entire image.
    buffer.SetOriginalFrameRect(gfx::Rect(Size()));
  }

#if defined(TURBO_JPEG_RGB_SWIZZLE)
  if (turboSwizzled(info->out_color_space)) {
    while (info->output_scanline < info->output_height) {
      unsigned char* row = reinterpret_cast_ptr<unsigned char*>(
          buffer.GetAddr(0, info->output_scanline));
      if (jpeg_read_scanlines(info, &row, 1) != 1) {
        return false;
      }

      ColorProfileTransform* xform = ColorTransform();
      if (xform) {
        skcms_AlphaFormat alpha_format = skcms_AlphaFormat_Unpremul;
        bool color_conversion_successful = skcms_Transform(
            row, XformColorFormat(), alpha_format, xform->SrcProfile(), row,
            XformColorFormat(), alpha_format, xform->DstProfile(),
            info->output_width);
        DCHECK(color_conversion_successful);
      }
    }
    buffer.SetPixelsChanged(true);
    return true;
  }
#endif

  switch (info->out_color_space) {
    case JCS_RGB:
      return OutputRows<JCS_RGB>(reader_.get(), buffer);
    case JCS_CMYK:
      return OutputRows<JCS_CMYK>(reader_.get(), buffer);
    default:
      NOTREACHED();
  }
}

void JPEGImageDecoder::Complete() {
  if (frame_buffer_cache_.empty()) {
    return;
  }

  frame_buffer_cache_[0].SetHasAlpha(false);
  frame_buffer_cache_[0].SetStatus(ImageFrame::kFrameComplete);
}

inline bool IsComplete(const JPEGImageDecoder* decoder,
                       JPEGImageDecoder::DecodingMode decoding_mode) {
  if (decoding_mode == JPEGImageDecoder::DecodingMode::kDecodeToYuv) {
    DCHECK(decoder->HasImagePlanes());
    return true;
  }

  return decoder->FrameIsDecodedAtIndex(0);
}

void JPEGImageDecoder::Decode(DecodingMode decoding_mode) {
  if (Failed()) {
    return;
  }

  if (!reader_) {
    reader_ = std::make_unique<JPEGImageReader>(this, offset_);
    reader_->SetData(data_);
  }

  // If we couldn't decode the image but have received all the data, decoding
  // has failed.
  if (!reader_->Decode(decoding_mode) && IsAllDataReceived()) {
    SetFailed();
  }

  // If decoding is done or failed, we don't need the JPEGImageReader anymore.
  if (IsComplete(this, decoding_mode) || Failed()) {
    reader_.reset();
  }
}

}  // namespace blink

"""


```