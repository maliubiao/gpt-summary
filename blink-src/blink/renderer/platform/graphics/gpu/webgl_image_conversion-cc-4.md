Response:
The user wants a summary of the provided C++ source code file, specifically focusing on its function, relationship to web technologies, logical reasoning with examples, common usage errors, and a final concise summary.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Functionality:** The filename `webgl_image_conversion.cc` and the class `FormatConverter` strongly suggest that the primary function is converting image data between different formats, specifically for WebGL. The code heavily uses templates based on `WebGLImageConversion::DataFormat` and `WebGLImageConversion::AlphaOp`, reinforcing this idea.

2. **Analyze the `FormatConverter` Class:**
    * **Members:** `dst_start_`, `src_stride_`, `src_row_offset_`, `dst_stride_`, `success_`, `unpacked_intermediate_src_data_`. These members point to the input and output buffers, strides (memory layout), and a flag for conversion success. The `unpacked_intermediate_src_data_` suggests an intermediate step might be needed for some conversions.
    * **`Convert` Methods:**  The presence of multiple overloaded `Convert` methods using nested switches based on source format, destination format, and alpha operation confirms the core function of format conversion. The `#define` macros simplify the switch case definitions.
    * **Templates:** The extensive use of templates allows the code to be generic and handle various data formats and alpha operations without writing separate functions for each combination.

3. **Examine Helper Functions and Structs:**
    * **`SupportsConversionFromDomElements`:** This template struct indicates that certain conversions are specifically related to data coming from DOM elements (like `<canvas>`, `<img>`, etc.).
    * **`DataTypeForFormat` and `IntermediateFormat`:**  These (likely defined elsewhere) are crucial for understanding the data types involved in the conversions.
    * **`IsFloatFormat`, `HasAlpha`, `HasColor`:** These helper functions provide metadata about the formats, guiding the conversion logic.
    * **`PixelStoreParams`:**  This struct represents the parameters that affect how pixel data is arranged in memory, directly mirroring WebGL's pixel store parameters.
    * **`SkColorTypeToDataFormat` and `DataFormatToSkColorType`:** These functions bridge the gap between Skia (Chromium's 2D graphics library) color types and the WebGL data formats, highlighting Skia's involvement in image processing.
    * **`ComputeFormatAndTypeParameters` and `ComputeImageSizeInBytes`:** These functions are critical for determining the size and layout of image data based on format, type, and pixel store parameters. This is essential for memory management and correct data interpretation.
    * **`GetChannelBitsByFormat`:**  This function likely provides information about the color channels present in a given format.
    * **`PackSkPixmap` and `ExtractTextureData`:** These functions demonstrate specific use cases of the conversion logic: packing Skia Pixmaps for WebGL and extracting texture data while handling pixel store parameters and alpha operations.
    * **`PackPixels` and `UnpackPixels`:** These are the core functions that perform the actual pixel data manipulation based on the source and destination formats and alpha operations.

4. **Connect to Web Technologies:**
    * **JavaScript/WebGL:** The filename and the frequent references to `GLenum` (OpenGL enum) directly connect this code to WebGL. JavaScript uses WebGL APIs to interact with the GPU for 3D graphics, including uploading and manipulating textures.
    * **HTML:**  DOM elements like `<canvas>` and `<img>` are the primary sources of image data that might need format conversion before being used in WebGL. The `SupportsConversionFromDomElements` struct explicitly highlights this connection.
    * **CSS:** While CSS doesn't directly interact with the pixel-level conversion, CSS properties can affect the rendering of these HTML elements, and thus the image data that might eventually be passed to WebGL. For example, CSS transforms or filters applied to an image might result in different pixel data being read from the element.

5. **Infer Logical Reasoning and Provide Examples:**
    * **Format Conversion Logic:** The nested switches in the `Convert` methods clearly illustrate the logic of selecting the appropriate conversion routine based on the source and destination formats. Hypothetical examples can show how a specific source format (e.g., RGBA8) and destination format (e.g., RGB8) would lead to a specific code path.
    * **Alpha Handling:** The `AlphaOp` enum and its use in the `Convert` methods demonstrate the logic for pre-multiplying or un-multiplying alpha. Examples can show how an image with alpha would be processed differently based on the chosen alpha operation.

6. **Identify Potential Usage Errors:**
    * **Mismatched Formats:**  Trying to convert between incompatible formats (e.g., a depth texture to an RGB texture) is a likely error.
    * **Incorrect Pixel Store Parameters:**  Setting incorrect alignment or row length can lead to misinterpretation of the source data.
    * **Premultiplication/Unmultiplication Errors:** Applying the wrong alpha operation can result in incorrect blending in WebGL.

7. **Synthesize the Summary:** Combine the identified functionalities and relationships into a concise overview of the file's purpose.

8. **Structure the Answer:** Organize the findings into the requested sections (functionality, relationship to web technologies, logical reasoning, usage errors, and final summary). Use clear and concise language, providing examples where necessary. Since this is the final part of a five-part answer, explicitly state this and reiterate the overall function.```cpp
void* const dst_start_;
  const int src_stride_, src_row_offset_, dst_stride_;
  bool success_;
  std::unique_ptr<uint8_t[]> unpacked_intermediate_src_data_;
};

void FormatConverter::Convert(WebGLImageConversion::DataFormat src_format,
                              WebGLImageConversion::DataFormat dst_format,
                              WebGLImageConversion::AlphaOp alpha_op) {
#define FORMATCONVERTER_CASE_SRCFORMAT(SrcFormat) \
  case SrcFormat:                                 \
    return Convert<SrcFormat>(dst_format, alpha_op);

  switch (src_format) {
    FORMATCONVERTER_CASE_SRCFORMAT(WebGLImageConversion::kDataFormatRA8)
    FORMATCONVERTER_CASE_SRCFORMAT(WebGLImageConversion::kDataFormatRA32F)
    FORMATCONVERTER_CASE_SRCFORMAT(WebGLImageConversion::kDataFormatRGBA8)
    FORMATCONVERTER_CASE_SRCFORMAT(WebGLImageConversion::kDataFormatRGBA16)
    FORMATCONVERTER_CASE_SRCFORMAT(WebGLImageConversion::kDataFormatARGB8)
    FORMATCONVERTER_CASE_SRCFORMAT(WebGLImageConversion::kDataFormatABGR8)
    FORMATCONVERTER_CASE_SRCFORMAT(WebGLImageConversion::kDataFormatAR8)
    FORMATCONVERTER_CASE_SRCFORMAT(WebGLImageConversion::kDataFormatBGRA8)
    FORMATCONVERTER_CASE_SRCFORMAT(WebGLImageConversion::kDataFormatRGBA5551)
    FORMATCONVERTER_CASE_SRCFORMAT(WebGLImageConversion::kDataFormatRGBA4444)
    FORMATCONVERTER_CASE_SRCFORMAT(WebGLImageConversion::kDataFormatRGBA32F)
    FORMATCONVERTER_CASE_SRCFORMAT(
        WebGLImageConversion::kDataFormatRGBA2_10_10_10)
    // Only used by ImageBitmap, when colorspace conversion is needed.
    FORMATCONVERTER_CASE_SRCFORMAT(WebGLImageConversion::kDataFormatRGBA16F)
    default:
      NOTREACHED();
  }
#undef FORMATCONVERTER_CASE_SRCFORMAT
}

template <WebGLImageConversion::DataFormat SrcFormat>
void FormatConverter::Convert(WebGLImageConversion::DataFormat dst_format,
                              WebGLImageConversion::AlphaOp alpha_op) {
#define FORMATCONVERTER_CASE_DSTFORMAT(DstFormat) \
  case DstFormat:                                 \
    return Convert<SrcFormat, DstFormat>(alpha_op);

  switch (dst_format) {
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatR8)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatR16F)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatR32F)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatA8)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatA16F)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatA32F)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRA8)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRA16F)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRA32F)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGB8)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGB565)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGB16F)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGB32F)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGBA8)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGBA5551)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGBA4444)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGBA16F)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGBA32F)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGBA8_S)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGBA16)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGBA16_S)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGBA32)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGBA32_S)
    FORMATCONVERTER_CASE_DSTFORMAT(
        WebGLImageConversion::kDataFormatRGBA2_10_10_10)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRG8)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRG16F)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRG32F)
    default:
      NOTREACHED();
  }

#undef FORMATCONVERTER_CASE_DSTFORMAT
}

template <WebGLImageConversion::DataFormat SrcFormat,
          WebGLImageConversion::DataFormat DstFormat>
void FormatConverter::Convert(WebGLImageConversion::AlphaOp alpha_op) {
#define FORMATCONVERTER_CASE_ALPHAOP(alphaOp) \
  case alphaOp:                               \
    return Convert<SrcFormat, DstFormat, alphaOp>();

  switch (alpha_op) {
    FORMATCONVERTER_CASE_ALPHAOP(WebGLImageConversion::kAlphaDoNothing)
    FORMATCONVERTER_CASE_ALPHAOP(WebGLImageConversion::kAlphaDoPremultiply)
    FORMATCONVERTER_CASE_ALPHAOP(WebGLImageConversion::kAlphaDoUnmultiply)
    default:
      NOTREACHED();
  }
#undef FORMATCONVERTER_CASE_ALPHAOP
}

template <int Format>
struct SupportsConversionFromDomElements {
  STATIC_ONLY(SupportsConversionFromDomElements);
  static const bool value =
      Format == WebGLImageConversion::kDataFormatRGBA8 ||
      Format == WebGLImageConversion::kDataFormatRGB8 ||
      Format == WebGLImageConversion::kDataFormatRG8 ||
      Format == WebGLImageConversion::kDataFormatRA8 ||
      Format == WebGLImageConversion::kDataFormatR8 ||
      Format == WebGLImageConversion::kDataFormatRGBA32F ||
      Format == WebGLImageConversion::kDataFormatRGB32F ||
      Format == WebGLImageConversion::kDataFormatRG32F ||
      Format == WebGLImageConversion::kDataFormatRA32F ||
      Format == WebGLImageConversion::kDataFormatR32F ||
      Format == WebGLImageConversion::kDataFormatRGBA16F ||
      Format == WebGLImageConversion::kDataFormatRGB16F ||
      Format == WebGLImageConversion::kDataFormatRG16F ||
      Format == WebGLImageConversion::kDataFormatRA16F ||
      Format == WebGLImageConversion::kDataFormatR16F ||
      Format == WebGLImageConversion::kDataFormatRGBA5551 ||
      Format == WebGLImageConversion::kDataFormatRGBA4444 ||
      Format == WebGLImageConversion::kDataFormatRGB565 ||
      Format == WebGLImageConversion::kDataFormatRGBA2_10_10_10;
};

template <WebGLImageConversion::DataFormat SrcFormat,
          WebGLImageConversion::DataFormat DstFormat,
          WebGLImageConversion::AlphaOp alphaOp>
void FormatConverter::Convert() {
  // Many instantiations of this template function will never be entered, so we
  // try to return immediately in these cases to avoid generating useless code.
  if (SrcFormat == DstFormat &&
      alphaOp == WebGLImageConversion::kAlphaDoNothing) {
    NOTREACHED();
  }
  // Note that ImageBitmaps with SrcFormat==kDataFormatRGBA16F return
  // false for IsFloatFormat since the input data is uint16_t.
  if (!IsFloatFormat<DstFormat>::value && IsFloatFormat<SrcFormat>::value) {
    NOTREACHED();
  }

  // Only textures uploaded from DOM elements or ImageData can allow DstFormat
  // != SrcFormat.
  const bool src_format_comes_from_dom_element_or_image_data =
      WebGLImageConversion::SrcFormatComesFromDOMElementOrImageData(SrcFormat);
  if (!src_format_comes_from_dom_element_or_image_data &&
      SrcFormat != DstFormat) {
    NOTREACHED();
  }
  // Likewise, only textures uploaded from DOM elements or ImageData can
  // possibly need to be unpremultiplied.
  if (!src_format_comes_from_dom_element_or_image_data &&
      alphaOp == WebGLImageConversion::kAlphaDoUnmultiply) {
    NOTREACHED();
  }
  if (src_format_comes_from_dom_element_or_image_data &&
      alphaOp == WebGLImageConversion::kAlphaDoUnmultiply &&
      !SupportsConversionFromDomElements<DstFormat>::value) {
    NOTREACHED();
  }
  if ((!HasAlpha(SrcFormat) || !HasColor(SrcFormat) || !HasColor(DstFormat)) &&
      alphaOp != WebGLImageConversion::kAlphaDoNothing) {
    NOTREACHED();
  }
  // If converting DOM element data to UNSIGNED_INT_5_9_9_9_REV or
  // UNSIGNED_INT_10F_11F_11F_REV, we should always switch to FLOAT instead to
  // avoid unpacking/packing these two types.
  if (src_format_comes_from_dom_element_or_image_data &&
      SrcFormat != DstFormat &&
      (DstFormat == WebGLImageConversion::kDataFormatRGB5999 ||
       DstFormat == WebGLImageConversion::kDataFormatRGB10F11F11F)) {
    NOTREACHED();
  }

  typedef typename DataTypeForFormat<SrcFormat>::Type SrcType;
  typedef typename DataTypeForFormat<DstFormat>::Type DstType;
  const int kIntermFormat = IntermediateFormat<DstFormat>::value;
  typedef typename DataTypeForFormat<kIntermFormat>::Type IntermType;
  // stride here could be negative.
  const ptrdiff_t src_stride_in_elements =
      src_stride_ / static_cast<int>(sizeof(SrcType));
  const ptrdiff_t dst_stride_in_elements =
      dst_stride_ / static_cast<int>(sizeof(DstType));
  const bool kTrivialUnpack = SrcFormat == kIntermFormat;
  const bool kTrivialPack = DstFormat == kIntermFormat &&
                            alphaOp == WebGLImageConversion::kAlphaDoNothing;
  DCHECK(!kTrivialUnpack || !kTrivialPack);

  const SrcType* src_row_start =
      static_cast<const SrcType*>(static_cast<const void*>(
          static_cast<const uint8_t*>(src_start_) +
          ((src_stride_ * src_sub_rectangle_.y()) + src_row_offset_)));

  // If packing multiple images into a 3D texture, and flipY is true,
  // then the sub-rectangle is pointing at the start of the
  // "bottommost" of those images. Since the source pointer strides in
  // the positive direction, we need to back it up to point at the
  // last, or "topmost", of these images.
  if (dst_stride_ < 0 && depth_ > 1) {
    src_row_start -=
        (depth_ - 1) * src_stride_in_elements * unpack_image_height_;
  }

  DstType* dst_row_start = static_cast<DstType*>(dst_start_);
  if (kTrivialUnpack) {
    for (int d = 0; d < depth_; ++d) {
      for (int i = 0; i < src_sub_rectangle_.height(); ++i) {
        Pack<DstFormat, alphaOp>(src_row_start, dst_row_start,
                                 src_sub_rectangle_.width());
        src_row_start += src_stride_in_elements;
        dst_row_start += dst_stride_in_elements;
      }
      src_row_start += src_stride_in_elements *
                       (unpack_image_height_ - src_sub_rectangle_.height());
    }
  } else if (kTrivialPack) {
    for (int d = 0; d < depth_; ++d) {
      for (int i = 0; i < src_sub_rectangle_.height(); ++i) {
        Unpack<SrcFormat>(src_row_start, dst_row_start,
                          src_sub_rectangle_.width());
        src_row_start += src_stride_in_elements;
        dst_row_start += dst_stride_in_elements;
      }
      src_row_start += src_stride_in_elements *
                       (unpack_image_height_ - src_sub_rectangle_.height());
    }
  } else {
    for (int d = 0; d < depth_; ++d) {
      for (int i = 0; i < src_sub_rectangle_.height(); ++i) {
        Unpack<SrcFormat>(src_row_start,
                          reinterpret_cast<IntermType*>(
                              unpacked_intermediate_src_data_.get()),
                          src_sub_rectangle_.width());
        Pack<DstFormat, alphaOp>(reinterpret_cast<IntermType*>(
                                     unpacked_intermediate_src_data_.get()),
                                 dst_row_start, src_sub_rectangle_.width());
        src_row_start += src_stride_in_elements;
        dst_row_start += dst_stride_in_elements;
      }
      src_row_start += src_stride_in_elements *
                       (unpack_image_height_ - src_sub_rectangle_.height());
    }
  }
  success_ = true;
  return;
}

}  // anonymous namespace

WebGLImageConversion::PixelStoreParams::PixelStoreParams()
    : alignment(4),
      row_length(0),
      image_height(0),
      skip_pixels(0),
      skip_rows(0),
      skip_images(0) {}

WebGLImageConversion::DataFormat WebGLImageConversion::SkColorTypeToDataFormat(
    SkColorType color_type) {
  switch (color_type) {
    case kRGBA_8888_SkColorType:
      return kDataFormatRGBA8;
    case kBGRA_8888_SkColorType:
      return kDataFormatBGRA8;
    case kR16G16B16A16_unorm_SkColorType:
      return kDataFormatRGBA16;
    case kRGBA_F16_SkColorType:
      return kDataFormatRGBA16F;
    case kRGBA_F32_SkColorType:
      return kDataFormatRGBA32F;
    default:
      NOTREACHED();
  }
}

SkColorType WebGLImageConversion::DataFormatToSkColorType(
    WebGLImageConversion::DataFormat data_format,
    SkColorType default_color_type) {
  switch (data_format) {
    case kDataFormatRGBA8:
      return kRGBA_8888_SkColorType;
    case kDataFormatBGRA8:
      return kBGRA_8888_SkColorType;
    case kDataFormatRGBA16:
      return kR16G16B16A16_unorm_SkColorType;
    case kDataFormatRGBA16F:
      return kRGBA_F16_SkColorType;
    case kDataFormatRGBA32F:
      return kRGBA_F32_SkColorType;
    default:
      break;
  }
  return default_color_type;
}

bool WebGLImageConversion::ComputeFormatAndTypeParameters(
    GLenum format,
    GLenum type,
    unsigned* components_per_pixel,
    unsigned* bytes_per_component) {
  switch (format) {
    case GL_ALPHA:
    case GL_LUMINANCE:
    case GL_RED:
    case GL_RED_INTEGER:
    case GL_DEPTH_COMPONENT:
    case GL_DEPTH_STENCIL:  // Treat it as one component.
      *components_per_pixel = 1;
      break;
    case GL_LUMINANCE_ALPHA:
    case GL_RG:
    case GL_RG_INTEGER:
      *components_per_pixel = 2;
      break;
    case GL_RGB:
    case GL_RGB_INTEGER:
    case GL_SRGB_EXT:  // GL_EXT_sRGB
      *components_per_pixel = 3;
      break;
    case GL_RGBA:
    case GL_RGBA_INTEGER:
    case GL_BGRA_EXT:        // GL_EXT_texture_format_BGRA8888
    case GL_SRGB_ALPHA_EXT:  // GL_EXT_sRGB
      *components_per_pixel = 4;
      break;
    default:
      return false;
  }
  switch (type) {
    case GL_BYTE:
      *bytes_per_component = sizeof(GLbyte);
      break;
    case GL_UNSIGNED_BYTE:
      *bytes_per_component = sizeof(GLubyte);
      break;
    case GL_SHORT:
      *bytes_per_component = sizeof(GLshort);
      break;
    case GL_UNSIGNED_SHORT:
      *bytes_per_component = sizeof(GLushort);
      break;
    case GL_UNSIGNED_SHORT_5_6_5:
    case GL_UNSIGNED_SHORT_4_4_4_4:
    case GL_UNSIGNED_SHORT_5_5_5_1:
      *components_per_pixel = 1;
      *bytes_per_component = sizeof(GLushort);
      break;
    case GL_INT:
      *bytes_per_component = sizeof(GLint);
      break;
    case GL_UNSIGNED_INT:
      *bytes_per_component = sizeof(GLuint);
      break;
    case GL_UNSIGNED_INT_24_8_OES:
    case GL_UNSIGNED_INT_10F_11F_11F_REV:
    case GL_UNSIGNED_INT_5_9_9_9_REV:
    case GL_UNSIGNED_INT_2_10_10_10_REV:
      *components_per_pixel = 1;
      *bytes_per_component = sizeof(GLuint);
      break;
    case GL_FLOAT:  // OES_texture_float
      *bytes_per_component = sizeof(GLfloat);
      break;
    case GL_HALF_FLOAT:
    case GL_HALF_FLOAT_OES:  // OES_texture_half_float
      *bytes_per_component = sizeof(GLushort);
      break;
    default:
      return false;
  }
  return true;
}

GLenum WebGLImageConversion::ComputeImageSizeInBytes(
    GLenum format,
    GLenum type,
    GLsizei width,
    GLsizei height,
    GLsizei depth,
    const PixelStoreParams& params,
    unsigned* image_size_in_bytes,
    unsigned* padding_in_bytes,
    unsigned* skip_size_in_bytes) {
  DCHECK(image_size_in_bytes);
  DCHECK(params.alignment == 1 || params.alignment == 2 ||
         params.alignment == 4 || params.alignment == 8);
  DCHECK_GE(params.row_length, 0);
  DCHECK_GE(params.image_height, 0);
  DCHECK_GE(params.skip_pixels, 0);
  DCHECK_GE(params.skip_rows, 0);
  DCHECK_GE(params.skip_images, 0);
  if (width < 0 || height < 0 || depth < 0)
    return GL_INVALID_VALUE;
  if (!width || !height || !depth) {
    *image_size_in_bytes = 0;
    if (padding_in_bytes)
      *padding_in_bytes = 0;
    if (skip_size_in_bytes)
      *skip_size_in_bytes = 0;
    return GL_NO_ERROR;
  }

  int row_length = params.row_length > 0 ? params.row_length : width;
  int image_height = params.image_height > 0 ? params.image_height : height;

  unsigned bytes_per_component, components_per_pixel;
  if (!ComputeFormatAndTypeParameters(format, type, &bytes_per_component,
                                      &components_per_pixel))
    return GL_INVALID_ENUM;
  unsigned bytes_per_group = bytes_per_component * components_per_pixel;
  base::CheckedNumeric<uint32_t> checked_value =
      static_cast<uint32_t>(row_length);
  checked_value *= bytes_per_group;
  if (!checked_value.IsValid())
    return GL_INVALID_VALUE;

  unsigned last_row_size;
  if (params.row_length > 0 && params.row_length != width) {
    base::CheckedNumeric<uint32_t> tmp = width;
    tmp *= bytes_per_group;
    if (!tmp.IsValid())
      return GL_INVALID_VALUE;
    last_row_size = tmp.ValueOrDie();
  } else {
    last_row_size = checked_value.ValueOrDie();
  }

  unsigned padding = 0;
  base::CheckedNumeric<uint32_t> checked_residual = checked_value;
  checked_residual %= static_cast<uint32_t>(params.alignment);
  if (!checked_residual.IsValid()) {
    return GL_INVALID_VALUE;
  }
  unsigned residual = checked_residual.ValueOrDie();
  if (residual) {
    padding = params.alignment - residual;
    checked_value += padding;
  }
  if (!checked_value.IsValid())
    return GL_INVALID_VALUE;
  unsigned padded_row_size = checked_value.ValueOrDie();

  base::CheckedNumeric<uint32_t> rows = image_height;
  rows *= (depth - 1);
  // Last image is not affected by IMAGE_HEIGHT parameter.
  rows += height;
  if (!rows.IsValid())
    return GL_INVALID_VALUE;
  checked_value *= (rows - 1);
  // Last row is not affected by ROW_LENGTH parameter.
  checked_value += last_row_size;
  if (!checked_value.IsValid())
    return GL_INVALID_VALUE;
  *image_size_in_bytes = checked_value.ValueOrDie();
  if (padding_in_bytes)
    *padding_in_bytes = padding;

  base::CheckedNumeric<uint32_t> skip_size = 0;
  if (params.skip_images > 0) {
    base::CheckedNumeric<uint32_t> tmp = padded_row_size;
    tmp *= image_height;
    tmp *= params.skip_images;
    if (!tmp.IsValid())
      return GL_INVALID_VALUE;
    skip_size += tmp.ValueOrDie();
  }
  if (params.skip_rows > 0) {
    base::CheckedNumeric<uint32_t> tmp = padded_row_size;
    tmp *= params.skip_rows;
    if (!tmp.IsValid())
      return GL_INVALID_VALUE;
    skip_size += tmp.ValueOrDie();
  }
  if (params.skip_pixels > 0) {
    base::CheckedNumeric<uint32_t> tmp = bytes_per_group;
    tmp *= params.skip_pixels;
    if (!tmp.IsValid())
      return GL_INVALID_VALUE;
    skip_size += tmp.ValueOrDie();
  }
  if (!skip_size.IsValid())
    return GL_INVALID_VALUE;
  if (skip_size_in_bytes)
    *skip_size_in_bytes = skip_size.ValueOrDie();

  checked_value += skip_size.ValueOrDie();
  if (!checked_value.IsValid())
    return GL_INVALID_VALUE;
  return GL_NO_ERROR;
}

unsigned WebGLImageConversion::GetChannelBitsByFormat(GLenum format) {
  switch (format) {
    case GL_ALPHA:
      return kChannelAlpha;
    case GL_RED:
    case GL_RED_INTEGER:
    case GL_R8:
    case GL_R8_SNORM:
    case GL_R8UI:
    case GL_R8I:
    case GL_R16UI:
    case GL_R16I:
    case GL_R32UI:
    case GL_R32I:
    case GL_R16F:
    case GL_R32F:
      return kChannelRed;
    case GL_RG:
    case GL_RG_INTEGER:
    case GL_RG8:
    case GL_RG8_SNORM:
    case GL_RG8UI:
    case GL_RG8I:
    case GL_RG16UI:
    case GL_RG16I:
    case GL_RG32UI:
    case GL_RG32I:
    case GL_RG16F:
    case GL_RG32F:
      return kChannelRG;
    case GL_LUMINANCE:
      return kChannelRGB;
    case GL_LUMINANCE_ALPHA:
      return kChannelRGBA;
    case GL_RGB:
    case GL_RGB_INTEGER:
    case GL_RGB8:
    case GL_RGB8_SNORM:
    case GL_RGB8UI:
    case GL_RGB8I:
    case GL_RGB16UI:
    case GL_RGB16I:
    case GL_RGB32UI:
    case GL_RGB32I:
    case GL_RGB16F:
    case GL_RGB32F:
    case GL_RGB565:
    case GL_R11F_G11F_B10F:
    case GL_RGB9_E5:
    case GL_SRGB_EXT:
    case GL_SRGB8:
      return kChannelRGB;
    case GL_RGBA:
    case GL_RGBA_INTEGER:
    case GL_RGBA8:
    case GL_RGBA8_SNORM:
    case GL_RGBA8UI:
    case GL_RGBA8I:
    case GL_RGBA16UI:
    case GL_RGBA16I:
    case GL_RGBA32UI:
    case GL_RGBA32I:
    case GL_RGBA16F:
    case GL_RGBA32F:
    case GL_RGBA4:
    case GL_RGB5_A1:
    case GL_RGB10_A2:
    case GL_RGB10_A2UI:
    case GL_SRGB_ALPHA_EXT:
    case GL_SRGB8_ALPHA8:
      return kChannelRGBA;
    case GL_DEPTH_COMPONENT:
    case GL_DEPTH_COMPONENT16:
    case GL_DEPTH_COMPONENT24:
    case GL_DEPTH_COMPONENT32F:
      return kChannelDepth;
    case GL_STENCIL:
    case GL_STENCIL_INDEX8:
      return kChannelStencil;
    case GL_DEPTH_STENCIL:
    case GL_DEPTH24_STENCIL8:
    case GL_DEPTH32F_STENCIL8:
      return kChannelDepthStencil;
    default:
      return 0;
  }
}

bool WebGLImageConversion::PackSkPixmap(
    const SkPixmap* pixmap,
    GLenum format,
    GLenum type,
    bool flip_y,
    AlphaOp alpha_op,
    const gfx::Rect& source_image_sub_rectangle,
    int depth,
    unsigned source_unpack_alignment,
    int unpack_image_height,
    Vector<uint8_t>& data) {
  DCHECK(pixmap);
  const void* const pixels = pixmap->addr();
  DCHECK(pixels);
  const unsigned source_image_width = pixmap->width();
  DCHECK(source_image_width);
  const unsigned source_image_height = pixmap->height();
  DCHECK(source_image_height);
  const DataFormat source_format = SkColorTypeToDataFormat(pixmap->colorType());
Prompt: 
```
这是目录为blink/renderer/platform/graphics/gpu/webgl_image_conversion.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第5部分，共5部分，请归纳一下它的功能

"""
void* const dst_start_;
  const int src_stride_, src_row_offset_, dst_stride_;
  bool success_;
  std::unique_ptr<uint8_t[]> unpacked_intermediate_src_data_;
};

void FormatConverter::Convert(WebGLImageConversion::DataFormat src_format,
                              WebGLImageConversion::DataFormat dst_format,
                              WebGLImageConversion::AlphaOp alpha_op) {
#define FORMATCONVERTER_CASE_SRCFORMAT(SrcFormat) \
  case SrcFormat:                                 \
    return Convert<SrcFormat>(dst_format, alpha_op);

  switch (src_format) {
    FORMATCONVERTER_CASE_SRCFORMAT(WebGLImageConversion::kDataFormatRA8)
    FORMATCONVERTER_CASE_SRCFORMAT(WebGLImageConversion::kDataFormatRA32F)
    FORMATCONVERTER_CASE_SRCFORMAT(WebGLImageConversion::kDataFormatRGBA8)
    FORMATCONVERTER_CASE_SRCFORMAT(WebGLImageConversion::kDataFormatRGBA16)
    FORMATCONVERTER_CASE_SRCFORMAT(WebGLImageConversion::kDataFormatARGB8)
    FORMATCONVERTER_CASE_SRCFORMAT(WebGLImageConversion::kDataFormatABGR8)
    FORMATCONVERTER_CASE_SRCFORMAT(WebGLImageConversion::kDataFormatAR8)
    FORMATCONVERTER_CASE_SRCFORMAT(WebGLImageConversion::kDataFormatBGRA8)
    FORMATCONVERTER_CASE_SRCFORMAT(WebGLImageConversion::kDataFormatRGBA5551)
    FORMATCONVERTER_CASE_SRCFORMAT(WebGLImageConversion::kDataFormatRGBA4444)
    FORMATCONVERTER_CASE_SRCFORMAT(WebGLImageConversion::kDataFormatRGBA32F)
    FORMATCONVERTER_CASE_SRCFORMAT(
        WebGLImageConversion::kDataFormatRGBA2_10_10_10)
    // Only used by ImageBitmap, when colorspace conversion is needed.
    FORMATCONVERTER_CASE_SRCFORMAT(WebGLImageConversion::kDataFormatRGBA16F)
    default:
      NOTREACHED();
  }
#undef FORMATCONVERTER_CASE_SRCFORMAT
}

template <WebGLImageConversion::DataFormat SrcFormat>
void FormatConverter::Convert(WebGLImageConversion::DataFormat dst_format,
                              WebGLImageConversion::AlphaOp alpha_op) {
#define FORMATCONVERTER_CASE_DSTFORMAT(DstFormat) \
  case DstFormat:                                 \
    return Convert<SrcFormat, DstFormat>(alpha_op);

  switch (dst_format) {
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatR8)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatR16F)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatR32F)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatA8)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatA16F)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatA32F)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRA8)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRA16F)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRA32F)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGB8)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGB565)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGB16F)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGB32F)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGBA8)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGBA5551)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGBA4444)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGBA16F)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGBA32F)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGBA8_S)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGBA16)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGBA16_S)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGBA32)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRGBA32_S)
    FORMATCONVERTER_CASE_DSTFORMAT(
        WebGLImageConversion::kDataFormatRGBA2_10_10_10)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRG8)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRG16F)
    FORMATCONVERTER_CASE_DSTFORMAT(WebGLImageConversion::kDataFormatRG32F)
    default:
      NOTREACHED();
  }

#undef FORMATCONVERTER_CASE_DSTFORMAT
}

template <WebGLImageConversion::DataFormat SrcFormat,
          WebGLImageConversion::DataFormat DstFormat>
void FormatConverter::Convert(WebGLImageConversion::AlphaOp alpha_op) {
#define FORMATCONVERTER_CASE_ALPHAOP(alphaOp) \
  case alphaOp:                               \
    return Convert<SrcFormat, DstFormat, alphaOp>();

  switch (alpha_op) {
    FORMATCONVERTER_CASE_ALPHAOP(WebGLImageConversion::kAlphaDoNothing)
    FORMATCONVERTER_CASE_ALPHAOP(WebGLImageConversion::kAlphaDoPremultiply)
    FORMATCONVERTER_CASE_ALPHAOP(WebGLImageConversion::kAlphaDoUnmultiply)
    default:
      NOTREACHED();
  }
#undef FORMATCONVERTER_CASE_ALPHAOP
}

template <int Format>
struct SupportsConversionFromDomElements {
  STATIC_ONLY(SupportsConversionFromDomElements);
  static const bool value =
      Format == WebGLImageConversion::kDataFormatRGBA8 ||
      Format == WebGLImageConversion::kDataFormatRGB8 ||
      Format == WebGLImageConversion::kDataFormatRG8 ||
      Format == WebGLImageConversion::kDataFormatRA8 ||
      Format == WebGLImageConversion::kDataFormatR8 ||
      Format == WebGLImageConversion::kDataFormatRGBA32F ||
      Format == WebGLImageConversion::kDataFormatRGB32F ||
      Format == WebGLImageConversion::kDataFormatRG32F ||
      Format == WebGLImageConversion::kDataFormatRA32F ||
      Format == WebGLImageConversion::kDataFormatR32F ||
      Format == WebGLImageConversion::kDataFormatRGBA16F ||
      Format == WebGLImageConversion::kDataFormatRGB16F ||
      Format == WebGLImageConversion::kDataFormatRG16F ||
      Format == WebGLImageConversion::kDataFormatRA16F ||
      Format == WebGLImageConversion::kDataFormatR16F ||
      Format == WebGLImageConversion::kDataFormatRGBA5551 ||
      Format == WebGLImageConversion::kDataFormatRGBA4444 ||
      Format == WebGLImageConversion::kDataFormatRGB565 ||
      Format == WebGLImageConversion::kDataFormatRGBA2_10_10_10;
};

template <WebGLImageConversion::DataFormat SrcFormat,
          WebGLImageConversion::DataFormat DstFormat,
          WebGLImageConversion::AlphaOp alphaOp>
void FormatConverter::Convert() {
  // Many instantiations of this template function will never be entered, so we
  // try to return immediately in these cases to avoid generating useless code.
  if (SrcFormat == DstFormat &&
      alphaOp == WebGLImageConversion::kAlphaDoNothing) {
    NOTREACHED();
  }
  // Note that ImageBitmaps with SrcFormat==kDataFormatRGBA16F return
  // false for IsFloatFormat since the input data is uint16_t.
  if (!IsFloatFormat<DstFormat>::value && IsFloatFormat<SrcFormat>::value) {
    NOTREACHED();
  }

  // Only textures uploaded from DOM elements or ImageData can allow DstFormat
  // != SrcFormat.
  const bool src_format_comes_from_dom_element_or_image_data =
      WebGLImageConversion::SrcFormatComesFromDOMElementOrImageData(SrcFormat);
  if (!src_format_comes_from_dom_element_or_image_data &&
      SrcFormat != DstFormat) {
    NOTREACHED();
  }
  // Likewise, only textures uploaded from DOM elements or ImageData can
  // possibly need to be unpremultiplied.
  if (!src_format_comes_from_dom_element_or_image_data &&
      alphaOp == WebGLImageConversion::kAlphaDoUnmultiply) {
    NOTREACHED();
  }
  if (src_format_comes_from_dom_element_or_image_data &&
      alphaOp == WebGLImageConversion::kAlphaDoUnmultiply &&
      !SupportsConversionFromDomElements<DstFormat>::value) {
    NOTREACHED();
  }
  if ((!HasAlpha(SrcFormat) || !HasColor(SrcFormat) || !HasColor(DstFormat)) &&
      alphaOp != WebGLImageConversion::kAlphaDoNothing) {
    NOTREACHED();
  }
  // If converting DOM element data to UNSIGNED_INT_5_9_9_9_REV or
  // UNSIGNED_INT_10F_11F_11F_REV, we should always switch to FLOAT instead to
  // avoid unpacking/packing these two types.
  if (src_format_comes_from_dom_element_or_image_data &&
      SrcFormat != DstFormat &&
      (DstFormat == WebGLImageConversion::kDataFormatRGB5999 ||
       DstFormat == WebGLImageConversion::kDataFormatRGB10F11F11F)) {
    NOTREACHED();
  }

  typedef typename DataTypeForFormat<SrcFormat>::Type SrcType;
  typedef typename DataTypeForFormat<DstFormat>::Type DstType;
  const int kIntermFormat = IntermediateFormat<DstFormat>::value;
  typedef typename DataTypeForFormat<kIntermFormat>::Type IntermType;
  // stride here could be negative.
  const ptrdiff_t src_stride_in_elements =
      src_stride_ / static_cast<int>(sizeof(SrcType));
  const ptrdiff_t dst_stride_in_elements =
      dst_stride_ / static_cast<int>(sizeof(DstType));
  const bool kTrivialUnpack = SrcFormat == kIntermFormat;
  const bool kTrivialPack = DstFormat == kIntermFormat &&
                            alphaOp == WebGLImageConversion::kAlphaDoNothing;
  DCHECK(!kTrivialUnpack || !kTrivialPack);

  const SrcType* src_row_start =
      static_cast<const SrcType*>(static_cast<const void*>(
          static_cast<const uint8_t*>(src_start_) +
          ((src_stride_ * src_sub_rectangle_.y()) + src_row_offset_)));

  // If packing multiple images into a 3D texture, and flipY is true,
  // then the sub-rectangle is pointing at the start of the
  // "bottommost" of those images. Since the source pointer strides in
  // the positive direction, we need to back it up to point at the
  // last, or "topmost", of these images.
  if (dst_stride_ < 0 && depth_ > 1) {
    src_row_start -=
        (depth_ - 1) * src_stride_in_elements * unpack_image_height_;
  }

  DstType* dst_row_start = static_cast<DstType*>(dst_start_);
  if (kTrivialUnpack) {
    for (int d = 0; d < depth_; ++d) {
      for (int i = 0; i < src_sub_rectangle_.height(); ++i) {
        Pack<DstFormat, alphaOp>(src_row_start, dst_row_start,
                                 src_sub_rectangle_.width());
        src_row_start += src_stride_in_elements;
        dst_row_start += dst_stride_in_elements;
      }
      src_row_start += src_stride_in_elements *
                       (unpack_image_height_ - src_sub_rectangle_.height());
    }
  } else if (kTrivialPack) {
    for (int d = 0; d < depth_; ++d) {
      for (int i = 0; i < src_sub_rectangle_.height(); ++i) {
        Unpack<SrcFormat>(src_row_start, dst_row_start,
                          src_sub_rectangle_.width());
        src_row_start += src_stride_in_elements;
        dst_row_start += dst_stride_in_elements;
      }
      src_row_start += src_stride_in_elements *
                       (unpack_image_height_ - src_sub_rectangle_.height());
    }
  } else {
    for (int d = 0; d < depth_; ++d) {
      for (int i = 0; i < src_sub_rectangle_.height(); ++i) {
        Unpack<SrcFormat>(src_row_start,
                          reinterpret_cast<IntermType*>(
                              unpacked_intermediate_src_data_.get()),
                          src_sub_rectangle_.width());
        Pack<DstFormat, alphaOp>(reinterpret_cast<IntermType*>(
                                     unpacked_intermediate_src_data_.get()),
                                 dst_row_start, src_sub_rectangle_.width());
        src_row_start += src_stride_in_elements;
        dst_row_start += dst_stride_in_elements;
      }
      src_row_start += src_stride_in_elements *
                       (unpack_image_height_ - src_sub_rectangle_.height());
    }
  }
  success_ = true;
  return;
}

}  // anonymous namespace

WebGLImageConversion::PixelStoreParams::PixelStoreParams()
    : alignment(4),
      row_length(0),
      image_height(0),
      skip_pixels(0),
      skip_rows(0),
      skip_images(0) {}

WebGLImageConversion::DataFormat WebGLImageConversion::SkColorTypeToDataFormat(
    SkColorType color_type) {
  switch (color_type) {
    case kRGBA_8888_SkColorType:
      return kDataFormatRGBA8;
    case kBGRA_8888_SkColorType:
      return kDataFormatBGRA8;
    case kR16G16B16A16_unorm_SkColorType:
      return kDataFormatRGBA16;
    case kRGBA_F16_SkColorType:
      return kDataFormatRGBA16F;
    case kRGBA_F32_SkColorType:
      return kDataFormatRGBA32F;
    default:
      NOTREACHED();
  }
}

SkColorType WebGLImageConversion::DataFormatToSkColorType(
    WebGLImageConversion::DataFormat data_format,
    SkColorType default_color_type) {
  switch (data_format) {
    case kDataFormatRGBA8:
      return kRGBA_8888_SkColorType;
    case kDataFormatBGRA8:
      return kBGRA_8888_SkColorType;
    case kDataFormatRGBA16:
      return kR16G16B16A16_unorm_SkColorType;
    case kDataFormatRGBA16F:
      return kRGBA_F16_SkColorType;
    case kDataFormatRGBA32F:
      return kRGBA_F32_SkColorType;
    default:
      break;
  }
  return default_color_type;
}

bool WebGLImageConversion::ComputeFormatAndTypeParameters(
    GLenum format,
    GLenum type,
    unsigned* components_per_pixel,
    unsigned* bytes_per_component) {
  switch (format) {
    case GL_ALPHA:
    case GL_LUMINANCE:
    case GL_RED:
    case GL_RED_INTEGER:
    case GL_DEPTH_COMPONENT:
    case GL_DEPTH_STENCIL:  // Treat it as one component.
      *components_per_pixel = 1;
      break;
    case GL_LUMINANCE_ALPHA:
    case GL_RG:
    case GL_RG_INTEGER:
      *components_per_pixel = 2;
      break;
    case GL_RGB:
    case GL_RGB_INTEGER:
    case GL_SRGB_EXT:  // GL_EXT_sRGB
      *components_per_pixel = 3;
      break;
    case GL_RGBA:
    case GL_RGBA_INTEGER:
    case GL_BGRA_EXT:        // GL_EXT_texture_format_BGRA8888
    case GL_SRGB_ALPHA_EXT:  // GL_EXT_sRGB
      *components_per_pixel = 4;
      break;
    default:
      return false;
  }
  switch (type) {
    case GL_BYTE:
      *bytes_per_component = sizeof(GLbyte);
      break;
    case GL_UNSIGNED_BYTE:
      *bytes_per_component = sizeof(GLubyte);
      break;
    case GL_SHORT:
      *bytes_per_component = sizeof(GLshort);
      break;
    case GL_UNSIGNED_SHORT:
      *bytes_per_component = sizeof(GLushort);
      break;
    case GL_UNSIGNED_SHORT_5_6_5:
    case GL_UNSIGNED_SHORT_4_4_4_4:
    case GL_UNSIGNED_SHORT_5_5_5_1:
      *components_per_pixel = 1;
      *bytes_per_component = sizeof(GLushort);
      break;
    case GL_INT:
      *bytes_per_component = sizeof(GLint);
      break;
    case GL_UNSIGNED_INT:
      *bytes_per_component = sizeof(GLuint);
      break;
    case GL_UNSIGNED_INT_24_8_OES:
    case GL_UNSIGNED_INT_10F_11F_11F_REV:
    case GL_UNSIGNED_INT_5_9_9_9_REV:
    case GL_UNSIGNED_INT_2_10_10_10_REV:
      *components_per_pixel = 1;
      *bytes_per_component = sizeof(GLuint);
      break;
    case GL_FLOAT:  // OES_texture_float
      *bytes_per_component = sizeof(GLfloat);
      break;
    case GL_HALF_FLOAT:
    case GL_HALF_FLOAT_OES:  // OES_texture_half_float
      *bytes_per_component = sizeof(GLushort);
      break;
    default:
      return false;
  }
  return true;
}

GLenum WebGLImageConversion::ComputeImageSizeInBytes(
    GLenum format,
    GLenum type,
    GLsizei width,
    GLsizei height,
    GLsizei depth,
    const PixelStoreParams& params,
    unsigned* image_size_in_bytes,
    unsigned* padding_in_bytes,
    unsigned* skip_size_in_bytes) {
  DCHECK(image_size_in_bytes);
  DCHECK(params.alignment == 1 || params.alignment == 2 ||
         params.alignment == 4 || params.alignment == 8);
  DCHECK_GE(params.row_length, 0);
  DCHECK_GE(params.image_height, 0);
  DCHECK_GE(params.skip_pixels, 0);
  DCHECK_GE(params.skip_rows, 0);
  DCHECK_GE(params.skip_images, 0);
  if (width < 0 || height < 0 || depth < 0)
    return GL_INVALID_VALUE;
  if (!width || !height || !depth) {
    *image_size_in_bytes = 0;
    if (padding_in_bytes)
      *padding_in_bytes = 0;
    if (skip_size_in_bytes)
      *skip_size_in_bytes = 0;
    return GL_NO_ERROR;
  }

  int row_length = params.row_length > 0 ? params.row_length : width;
  int image_height = params.image_height > 0 ? params.image_height : height;

  unsigned bytes_per_component, components_per_pixel;
  if (!ComputeFormatAndTypeParameters(format, type, &bytes_per_component,
                                      &components_per_pixel))
    return GL_INVALID_ENUM;
  unsigned bytes_per_group = bytes_per_component * components_per_pixel;
  base::CheckedNumeric<uint32_t> checked_value =
      static_cast<uint32_t>(row_length);
  checked_value *= bytes_per_group;
  if (!checked_value.IsValid())
    return GL_INVALID_VALUE;

  unsigned last_row_size;
  if (params.row_length > 0 && params.row_length != width) {
    base::CheckedNumeric<uint32_t> tmp = width;
    tmp *= bytes_per_group;
    if (!tmp.IsValid())
      return GL_INVALID_VALUE;
    last_row_size = tmp.ValueOrDie();
  } else {
    last_row_size = checked_value.ValueOrDie();
  }

  unsigned padding = 0;
  base::CheckedNumeric<uint32_t> checked_residual = checked_value;
  checked_residual %= static_cast<uint32_t>(params.alignment);
  if (!checked_residual.IsValid()) {
    return GL_INVALID_VALUE;
  }
  unsigned residual = checked_residual.ValueOrDie();
  if (residual) {
    padding = params.alignment - residual;
    checked_value += padding;
  }
  if (!checked_value.IsValid())
    return GL_INVALID_VALUE;
  unsigned padded_row_size = checked_value.ValueOrDie();

  base::CheckedNumeric<uint32_t> rows = image_height;
  rows *= (depth - 1);
  // Last image is not affected by IMAGE_HEIGHT parameter.
  rows += height;
  if (!rows.IsValid())
    return GL_INVALID_VALUE;
  checked_value *= (rows - 1);
  // Last row is not affected by ROW_LENGTH parameter.
  checked_value += last_row_size;
  if (!checked_value.IsValid())
    return GL_INVALID_VALUE;
  *image_size_in_bytes = checked_value.ValueOrDie();
  if (padding_in_bytes)
    *padding_in_bytes = padding;

  base::CheckedNumeric<uint32_t> skip_size = 0;
  if (params.skip_images > 0) {
    base::CheckedNumeric<uint32_t> tmp = padded_row_size;
    tmp *= image_height;
    tmp *= params.skip_images;
    if (!tmp.IsValid())
      return GL_INVALID_VALUE;
    skip_size += tmp.ValueOrDie();
  }
  if (params.skip_rows > 0) {
    base::CheckedNumeric<uint32_t> tmp = padded_row_size;
    tmp *= params.skip_rows;
    if (!tmp.IsValid())
      return GL_INVALID_VALUE;
    skip_size += tmp.ValueOrDie();
  }
  if (params.skip_pixels > 0) {
    base::CheckedNumeric<uint32_t> tmp = bytes_per_group;
    tmp *= params.skip_pixels;
    if (!tmp.IsValid())
      return GL_INVALID_VALUE;
    skip_size += tmp.ValueOrDie();
  }
  if (!skip_size.IsValid())
    return GL_INVALID_VALUE;
  if (skip_size_in_bytes)
    *skip_size_in_bytes = skip_size.ValueOrDie();

  checked_value += skip_size.ValueOrDie();
  if (!checked_value.IsValid())
    return GL_INVALID_VALUE;
  return GL_NO_ERROR;
}

unsigned WebGLImageConversion::GetChannelBitsByFormat(GLenum format) {
  switch (format) {
    case GL_ALPHA:
      return kChannelAlpha;
    case GL_RED:
    case GL_RED_INTEGER:
    case GL_R8:
    case GL_R8_SNORM:
    case GL_R8UI:
    case GL_R8I:
    case GL_R16UI:
    case GL_R16I:
    case GL_R32UI:
    case GL_R32I:
    case GL_R16F:
    case GL_R32F:
      return kChannelRed;
    case GL_RG:
    case GL_RG_INTEGER:
    case GL_RG8:
    case GL_RG8_SNORM:
    case GL_RG8UI:
    case GL_RG8I:
    case GL_RG16UI:
    case GL_RG16I:
    case GL_RG32UI:
    case GL_RG32I:
    case GL_RG16F:
    case GL_RG32F:
      return kChannelRG;
    case GL_LUMINANCE:
      return kChannelRGB;
    case GL_LUMINANCE_ALPHA:
      return kChannelRGBA;
    case GL_RGB:
    case GL_RGB_INTEGER:
    case GL_RGB8:
    case GL_RGB8_SNORM:
    case GL_RGB8UI:
    case GL_RGB8I:
    case GL_RGB16UI:
    case GL_RGB16I:
    case GL_RGB32UI:
    case GL_RGB32I:
    case GL_RGB16F:
    case GL_RGB32F:
    case GL_RGB565:
    case GL_R11F_G11F_B10F:
    case GL_RGB9_E5:
    case GL_SRGB_EXT:
    case GL_SRGB8:
      return kChannelRGB;
    case GL_RGBA:
    case GL_RGBA_INTEGER:
    case GL_RGBA8:
    case GL_RGBA8_SNORM:
    case GL_RGBA8UI:
    case GL_RGBA8I:
    case GL_RGBA16UI:
    case GL_RGBA16I:
    case GL_RGBA32UI:
    case GL_RGBA32I:
    case GL_RGBA16F:
    case GL_RGBA32F:
    case GL_RGBA4:
    case GL_RGB5_A1:
    case GL_RGB10_A2:
    case GL_RGB10_A2UI:
    case GL_SRGB_ALPHA_EXT:
    case GL_SRGB8_ALPHA8:
      return kChannelRGBA;
    case GL_DEPTH_COMPONENT:
    case GL_DEPTH_COMPONENT16:
    case GL_DEPTH_COMPONENT24:
    case GL_DEPTH_COMPONENT32F:
      return kChannelDepth;
    case GL_STENCIL:
    case GL_STENCIL_INDEX8:
      return kChannelStencil;
    case GL_DEPTH_STENCIL:
    case GL_DEPTH24_STENCIL8:
    case GL_DEPTH32F_STENCIL8:
      return kChannelDepthStencil;
    default:
      return 0;
  }
}

bool WebGLImageConversion::PackSkPixmap(
    const SkPixmap* pixmap,
    GLenum format,
    GLenum type,
    bool flip_y,
    AlphaOp alpha_op,
    const gfx::Rect& source_image_sub_rectangle,
    int depth,
    unsigned source_unpack_alignment,
    int unpack_image_height,
    Vector<uint8_t>& data) {
  DCHECK(pixmap);
  const void* const pixels = pixmap->addr();
  DCHECK(pixels);
  const unsigned source_image_width = pixmap->width();
  DCHECK(source_image_width);
  const unsigned source_image_height = pixmap->height();
  DCHECK(source_image_height);
  const DataFormat source_format = SkColorTypeToDataFormat(pixmap->colorType());
  DCHECK_NE(source_format, kDataFormatNumFormats);

  unsigned packed_size;
  // Output data is tightly packed (alignment == 1).
  PixelStoreParams params;
  params.alignment = 1;
  if (ComputeImageSizeInBytes(format, type, source_image_sub_rectangle.width(),
                              source_image_sub_rectangle.height(), depth,
                              params, &packed_size, nullptr,
                              nullptr) != GL_NO_ERROR) {
    return false;
  }
  data.resize(packed_size);

  return PackPixels(reinterpret_cast<const uint8_t*>(pixels), source_format,
                    source_image_width, source_image_height,
                    source_image_sub_rectangle, depth, source_unpack_alignment,
                    unpack_image_height, format, type, alpha_op, data.data(),
                    flip_y);
}

bool WebGLImageConversion::ExtractTextureData(
    unsigned width,
    unsigned height,
    GLenum format,
    GLenum type,
    const PixelStoreParams& unpack_params,
    bool flip_y,
    bool premultiply_alpha,
    const void* pixels,
    Vector<uint8_t>& data) {
  // Assumes format, type, etc. have already been validated.
  DataFormat source_data_format = GetDataFormat(format, type);
  if (source_data_format == kDataFormatNumFormats)
    return false;

  // Resize the output buffer.
  unsigned int components_per_pixel, bytes_per_component;
  if (!ComputeFormatAndTypeParameters(format, type, &components_per_pixel,
                                      &bytes_per_component))
    return false;
  unsigned bytes_per_pixel = components_per_pixel * bytes_per_component;
  data.resize(width * height * bytes_per_pixel);

  unsigned image_size_in_bytes, skip_size_in_bytes;
  if (ComputeImageSizeInBytes(format, type, width, height, 1, unpack_params,
                              &image_size_in_bytes, nullptr,
                              &skip_size_in_bytes) != GL_NO_ERROR)
    return false;
  const uint8_t* src_data = static_cast<const uint8_t*>(pixels);
  if (skip_size_in_bytes) {
    src_data += skip_size_in_bytes;
  }

  if (!PackPixels(src_data, source_data_format,
                  unpack_params.row_length ? unpack_params.row_length : width,
                  height, gfx::Rect(0, 0, width, height), 1,
                  unpack_params.alignment, 0, format, type,
                  (premultiply_alpha ? kAlphaDoPremultiply : kAlphaDoNothing),
                  data.data(), flip_y))
    return false;

  return true;
}

bool WebGLImageConversion::PackPixels(
    const void* source_data,
    DataFormat source_data_format,
    unsigned source_data_width,
    unsigned source_data_height,
    const gfx::Rect& source_data_sub_rectangle,
    int depth,
    unsigned source_unpack_alignment,
    int unpack_image_height,
    unsigned destination_format,
    unsigned destination_type,
    AlphaOp alpha_op,
    void* destination_data,
    bool flip_y) {
  DCHECK_GE(depth, 1);
  if (unpack_image_height == 0) {
    unpack_image_height = source_data_sub_rectangle.height();
  }
  int valid_src = source_data_width * TexelBytesForFormat(source_data_format);
  int remainder =
      source_unpack_alignment ? (valid_src % source_unpack_alignment) : 0;
  int src_stride =
      remainder ? (valid_src + source_unpack_alignment - remainder) : valid_src;
  int src_row_offset =
      source_data_sub_rectangle.x() * TexelBytesForFormat(source_data_format);
  DataFormat dst_data_format =
      GetDataFormat(destination_format, destination_type);
  if (dst_data_format == kDataFormatNumFormats)
    return false;
  int dst_stride =
      source_data_sub_rectangle.width() * TexelBytesForFormat(dst_data_format);
  if (flip_y) {
    destination_data =
        static_cast<uint8_t*>(destination_data) +
        dst_stride * ((depth * source_data_sub_rectangle.height()) - 1);
    dst_stride = -dst_stride;
  }
  if (!HasAlpha(source_data_format) || !HasColor(source_data_format) ||
      !HasColor(dst_data_format))
    alpha_op = kAlphaDoNothing;

  if (source_data_format == dst_data_format && alpha_op == kAlphaDoNothing) {
    const uint8_t* base_ptr = static_cast<const uint8_t*>(source_data) +
                              src_stride * source_data_sub_rectangle.y();
    const uint8_t* base_end = static_cast<const uint8_t*>(source_data) +
                              src_stride * source_data_sub_rectangle.bottom();

    // If packing multiple images into a 3D texture, and flipY is true,
    // then the sub-rectangle is pointing at the start of the
    // "bottommost" of those images. Since the source pointer strides in
    // the positive direction, we need to back it up to point at the
    // last, or "topmost", of these images.
    if (flip_y && depth > 1) {
      const ptrdiff_t distance_to_top_image =
          (depth - 1) * src_stride * unpack_image_height;
      base_ptr -= distance_to_top_image;
      base_end -= distance_to_top_image;
    }

    unsigned row_size = (dst_stride > 0) ? dst_stride : -dst_stride;
    uint8_t* dst = static_cast<uint8_t*>(destination_data);

    for (int i = 0; i < depth; ++i) {
      const uint8_t* ptr = base_ptr;
      const uint8_t* ptr_end = base_end;
      while (ptr < ptr_end) {
        memcpy(dst, ptr + src_row_offset, row_size);
        ptr += src_stride;
        dst += dst_stride;
      }
      base_ptr += unpack_image_height * src_stride;
      base_end += unpack_image_height * src_stride;
    }
    return true;
  }

  FormatConverter converter(source_data_sub_rectangle, depth,
                            unpack_image_height, source_data, destination_data,
                            src_stride, src_row_offset, dst_stride);
  converter.Convert(source_data_format, dst_data_format, alpha_op);
  if (!converter.Success())
    return false;
  return true;
}

void WebGLImageConversion::UnpackPixels(const uint16_t* source_data,
                                        DataFormat source_data_format,
                                        unsigned pixels_per_row,
                                        uint8_t* destination_data) {
  switch (source_data_format) {
    case kDataFormatRGBA4444: {
      typedef typename DataTypeForFormat<
          WebGLImageConversion::kDataFormatRGBA4444>::Type SrcType;
      const SrcType* src_row_start = static_cast<const SrcType*>(source_data);
      Unpack<WebGLImageConversion::kDataFormatRGBA4444>(
          src_row_start, destination_data, pixels_per_row);
    } break;
    case kDataFormatRGBA5551: {
      typedef typename DataTypeForFormat<
          WebGLImageConversion::kDataFormatRGBA5551>::Type SrcType;
      const SrcType* src_row_start = static_cast<const SrcType*>(source_data);
      Unpack<WebGLImageConversion::kDataFormatRGBA5551>(
          src_row_start, destination_data, pixels_per_row);
    } break;
    case kDataFormatBGRA8: {
      const uint8_t* psrc = (const uint8_t*)source_data;
      typedef typename DataTypeForFormat<
          WebGLImageConversion::kDataFormatBGRA8>::Type SrcType;
      const SrcType* src_row_start = static_cast<const SrcType*>(psrc);
      Unpack<WebGLImageConversion::kDataFormatBGRA8>(
          src_row_start, destination_data, pixels_per_row);
    } break;
    default:
      break;
  }
}

void WebGLImageConversion::PackPixels(const uint8_t* source_data,
                                      DataFormat source_data_format,
                                      unsigned pixels_per_row,
                                      uint8_t* destination_data) {
  switch (source_data_format) {
    case kDataFormatRA8: {
      typedef typename DataTypeForFormat<
          WebGLImageConversion::kDataFormatRGBA8>::Type SrcType;
      const SrcType* src_row_start = static_cast<const SrcType*>(source_data);
      Pack<WebGLImageConversion::kDataFormatRA8,
           WebGLImageConversion::kAlphaDoUnmultiply>(
          src_row_start, destination_data, pixels_per_row);
    } break;
    case kDataFormatR8: {
      typedef typename DataTypeForFormat<
          WebGLImageConversion::kDataFormatRGBA8>::Type SrcType;
      const SrcType* src_row_start = static_cast<const SrcType*>(source_data);
      Pack<WebGLImageConversion::kDataFormatR8,
           WebGLImageConversion::kAlphaDoUnmultiply>(
          src_row_start, destination_data, pixels_per_row);
    } break;
    case kDataFormatRGBA8: {
      typedef typename DataTypeForFormat<
          WebGLImageConversion::kDataFormatRGBA8>::Type SrcType;
      const SrcType* src_row_start = static_cast<const SrcType*>(source_data);
      Pack<WebGLImageConversion::kDataFormatRGBA8,
           WebGLImageConversion::kAlphaDoUnmultiply>(
          src_row_start, destination_data, pixels_per_row);
    } break;
    case kDataFormatRGBA4444: {
      uint16_t* pdst = (uint16_t*)destination_data;
      typedef typename DataTypeForFormat<
          WebGLImageConversion::kDataFormatRGBA8>::Type SrcType;
      const SrcType* src_row_start = static_cast<const SrcType*>(source_data);
      typedef typename DataTypeForFormat<
          WebGLImageConversion::kDataFormatRGBA4444>::Type DstType;
      DstType* dst_row_start = static_cast<DstType*>(pdst);
      Pack<WebGLImageConversion::kDataFormatRGBA4444,
           WebGLImageConversion::kAlphaDoNothing>(src_row_start, dst_row_start,
                                                  pixels_per_row);
    } break;
    case kDataFormatRGBA5551: {
      uint16_t* pdst = (uint16_t*)destination_data;
      typedef typename DataTypeForFormat<
          WebGLImageConversion::kDataFormatRGBA8>::Type SrcType;
      const SrcType* src_row_start = static_cast<const SrcType*>(source_data);
      typedef typename DataTypeForFormat<
          WebGLImageConversion::kDataFormatRGBA5551>::Type DstType;
      DstType* dst_row_start = static_cast<DstType*>(pdst);
      Pack<WebGLImageConversion::kDataFormatRGBA5551,
           WebGLImageConversion::kAlphaDoNothing>(src_row_start, dst_row_start,
                                                  pixels_per_row);
    } break;
    case kDataFormatRGB565: {
      uint16_t* pdst = (uint16_t*)destination_data;
      typedef typename DataTypeForFormat<
          WebGLImageConversion::kDataFormatRGBA8>::Type SrcType;
      const SrcType* src_row_start = static_cast<const SrcType*>(source_data);
      typedef typename DataTypeForFormat<
          WebGLImageConversion::kDataFormatRGB565>::Type DstType;
      DstType* dst_row_start = static_cast<DstType*>(pdst);
      Pack<WebGLImageConversion::kDataFormatRGB565,
           WebGLImageConversion::kAlphaDoNothing>(src_row_start, dst_row_start,
                                                  pixels_per_row);
    } break;
    default:
      break;
  }
}

}  // namespace blink

"""


```