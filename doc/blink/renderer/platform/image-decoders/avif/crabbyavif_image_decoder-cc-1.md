Response:
The user is asking for a summary of the functionalities of the provided C++ code snippet from the Chromium Blink engine. This is the second part of a two-part request.

Here's a plan to address this request:

1. **Identify Core Functionalities:** Read through the code and identify the primary actions and responsibilities of the `CrabbyAVIFImageDecoder` class.
2. **Relate to Web Technologies:**  Analyze how these functionalities connect to HTML, CSS, and JavaScript in a web browser context.
3. **Logical Reasoning and Examples:**  For any logical deductions or processes, provide hypothetical inputs and their expected outputs.
4. **Common User/Programming Errors:** Identify potential mistakes developers or users might make when dealing with AVIF images or this decoder.
5. **Synthesize a Summary:**  Based on the identified functionalities, create a concise summary of the code's purpose.
这是 `CrabbyAVIFImageDecoder` 类的部分代码，它负责解码 AVIF 图像。 基于这段代码，我们可以归纳出以下功能：

**核心功能:**

1. **初始化解码器和解析容器信息:**
   - 检查 `crabbyavif` 库的版本兼容性。
   - 使用 `crabbyavif::crabby_avifDecoderCreate()` 创建 `crabbyavif` 解码器实例。
   - 通过 `crabbyavif::crabby_avifDecoderSetIOMemory()` 将图像数据传递给解码器。
   - 使用 `crabbyavif::crabby_avifDecoderParse()` 解析 AVIF 容器信息，包括图像尺寸、颜色格式、位深度、颜色空间等。
   - 验证解析结果，例如 YUV 格式是否在 AV1 标准中。

2. **处理图像元数据:**
   - 解析和存储色度抽样信息 (`chroma_shift_x_`, `chroma_shift_y_`)。
   - 处理 HDR 元数据 (CLLI/PALL) 并将其存储到 `hdr_metadata_`。
   - 处理嵌入的颜色配置文件 (ICC profile) 或 CICP 色彩描述，并使用 `SetEmbeddedColorProfile()` 设置颜色配置文件。
   - 解析并应用图像的旋转和镜像变换，通过 `container->transformFlags` 和相应的结构体 (`irot`, `imir`) 获取变换信息，并计算出 `orientation_` (图像方向)。
   - 处理 Clean Aperture 信息 (`clap`)，确定裁剪区域，并记录 `clap_type_` 以进行统计。如果 `clap` 信息的原点不是 (0,0)，则会忽略它。

3. **确定解码能力:**
   - 判断是否允许解码为 YUV 格式，限制条件包括：不支持 Alpha 通道、不支持动画、颜色空间可以转换为 SkYUVColorSpace 且没有颜色变换。

4. **记录统计信息:**
   - 对于满足特定条件的 8 位彩色静态图像（无 Alpha），记录其每像素比特数 (bpp)。

5. **设置解码图像尺寸:**
   - 根据是否应用 Clean Aperture，调用 `SetSize()` 设置解码后的图像尺寸。

6. **解码图像帧:**
   - `DecodeImage(wtf_size_t index)` 函数负责解码指定索引的图像帧。
   - 调用 `crabbyavif::crabby_avifDecoderNthImage()` 获取解码后的图像数据。
   - 验证解码后的图像帧的尺寸、位深度和 YUV 格式是否与容器信息一致。
   - 如果存在 Clean Aperture 且未被忽略，则调用 `CropDecodedImage()` 进行裁剪。
   - 在成功解码后，更新 bpp 直方图（如果适用）。
   - 记录 Clean Aperture 类型到 UMA 直方图。

7. **裁剪解码后的图像:**
   - `CropDecodedImage()` 使用 `crabbyavif::crabby_avifImageSetViewRect()` 根据 Clean Aperture 信息创建一个裁剪后的图像视图。

8. **渲染图像到缓冲区:**
   - `RenderImage()` 函数将解码后的 YUV 图像数据渲染到 RGB 缓冲区 `ImageFrame` 中。
   - 针对 YUV420 格式，为了兼容 libyuv 的处理方式，可能会采取备份上一行数据或延迟处理最后一行数据的策略。
   - 使用 `crabbyavif::crabby_avifImageYUVToRGB()` 执行 YUV 到 RGB 的转换。
   - 支持解码到半精度浮点格式。
   - 根据目标平台，选择不同的 RGB 像素格式 (RGBA 或 BGRA)。

9. **颜色校正:**
   - `ColorCorrectImage()` 函数根据颜色配置文件对渲染后的图像数据进行颜色校正。
   - 使用 `skcms_Transform()` 执行颜色空间转换。
   - 支持半精度浮点和 8 位像素格式的颜色校正。

10. **获取 Gainmap 信息和数据:**
    - `GetGainmapInfoAndData()` 用于获取 AVIF gainmap 扩展的信息和数据，用于 HDR 图像处理。
    - 只有在启用了 `features::kAvifGainmapHdrImages` 功能标志时才有效。
    - 解析 gainmap 的元数据，例如显示比例、伽马值、偏移量等。

11. **获取解码器图像:**
    - `GetDecoderImage()`  返回当前正在处理的 `crabbyavif::avifImage` 指针，可能是主图像或 gainmap 图像。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML `<img>` 标签:**  当 HTML 中使用 `<img>` 标签加载一个 AVIF 图像时，Blink 引擎会创建 `CrabbyAVIFImageDecoder` 的实例来解码该图像。解码后的像素数据最终会被用于在页面上渲染图像。

  ```html
  <img src="image.avif" alt="An AVIF image">
  ```

* **CSS `background-image` 属性:** 类似地，当 CSS 中使用 `background-image` 属性加载 AVIF 图像作为背景时，也会使用 `CrabbyAVIFImageDecoder` 进行解码。

  ```css
  .container {
    background-image: url("background.avif");
  }
  ```

* **JavaScript `Image()` 对象或 `fetch()` API:** JavaScript 可以使用 `Image()` 对象或者 `fetch()` API 下载 AVIF 图像数据。  Blink 引擎在接收到图像数据后，会使用 `CrabbyAVIFImageDecoder` 进行解码，以便在 `<canvas>` 元素上绘制或进行其他图像处理。

  ```javascript
  const img = new Image();
  img.onload = function() {
    // 图像加载完成，并且已经被解码
    canvasContext.drawImage(img, 0, 0);
  };
  img.src = 'image.avif';
  ```

**逻辑推理及假设输入与输出:**

**假设输入:** 一个包含 Clean Aperture 信息的 AVIF 图像，`clap` 属性指定了从 (10, 20) 开始，宽度为 100，高度为 150 的裁剪区域。

**预期输出:**
- 如果 `ignore_clap_` 为 false (默认情况)，且 `clap` 原点不为零，代码会打印 DLOG 并设置 `clap_type_` 为 `AVIFCleanApertureType::kNonzeroOrigin`，并且忽略 `clap` 信息，最终解码出原始大小的图像。
- 如果 `ignore_clap_` 被设置为 true，则会忽略 `clap` 信息，解码出原始大小的图像。

**假设输入:** 一个 8 位 YUV420 格式的 AVIF 图像，没有 Alpha 通道，且不是动画。

**预期输出:** `allow_decode_to_yuv_` 将被设置为 true，允许直接解码为 YUV 格式进行处理，这可能在某些特定渲染流程中提高效率。

**用户或编程常见的使用错误举例说明:**

1. **尝试解码不支持的 AVIF 功能:**  例如，尝试解码包含 Alpha 通道的 AVIF 图像到 YUV 缓冲区。由于 `allow_decode_to_yuv_` 会检查 `decoder_->alphaPresent`，如果存在 Alpha 通道，解码到 YUV 会失败。

2. **Clean Aperture 原点非零:**  用户可能错误地创建了 Clean Aperture 原点不是 (0, 0) 的 AVIF 图像。虽然 AVIF 规范允许这样做，但 Chromium 会将其视为潜在的隐私风险并忽略 `clap` 信息，显示完整图像，这可能与用户的预期不符。开发者应该避免创建此类 AVIF 图像。

3. **假设解码后的图像尺寸与容器尺寸一致:**  在存在 Clean Aperture 的情况下，解码后的图像尺寸可能小于容器尺寸。开发者在后续处理解码后的图像时，需要注意使用 `SetSize()` 设置的实际尺寸，而不是容器的原始尺寸。

4. **在不支持 Gainmap 的浏览器版本中使用 Gainmap AVIF:** 如果用户在未启用 `features::kAvifGainmapHdrImages` 的 Chromium 版本中查看包含 Gainmap 的 AVIF 图像，`GetGainmapInfoAndData()` 将返回 false，导致 Gainmap 功能无法生效。这可能是因为用户使用了较旧的浏览器版本或者相关实验性功能未被启用。

**总结:**

`CrabbyAVIFImageDecoder` 的主要功能是解析和解码 AVIF 图像数据，包括处理容器信息、元数据（颜色空间、HDR 信息、变换、Clean Aperture）、解码图像帧以及将 YUV 数据渲染到 RGB 缓冲区。它还负责处理与 Gainmap 相关的元数据和数据。 该解码器在 Chromium Blink 引擎中扮演着关键角色，使得浏览器能够正确显示网页中使用的 AVIF 图像。

### 提示词
```
这是目录为blink/renderer/platform/image-decoders/avif/crabbyavif_image_decoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
vif::AVIF_PIXEL_FORMAT_YUV400 ==
                crabbyavif::AVIF_PIXEL_FORMAT_YUV420 + 1);
  // Assert that after crabbyavif::crabby_avifDecoderParse() returns
  // crabbyavif::AVIF_RESULT_OK, decoder_->image->yuvFormat (the same as
  // container->yuvFormat) is one of the four YUV formats in AV1.
  CHECK(container->yuvFormat >= crabbyavif::AVIF_PIXEL_FORMAT_YUV444 &&
        container->yuvFormat <= crabbyavif::AVIF_PIXEL_FORMAT_YUV400)
      << "Invalid YUV format: " << container->yuvFormat;
  avif_yuv_format_ = container->yuvFormat;
  crabbyavif::avifPixelFormatInfo format_info;
  crabbyavif::crabby_avifGetPixelFormatInfo(container->yuvFormat, &format_info);
  chroma_shift_x_ = format_info.chromaShiftX;
  chroma_shift_y_ = format_info.chromaShiftY;

  if (container->clli.maxCLL || container->clli.maxPALL) {
    hdr_metadata_ = gfx::HDRMetadata();
    hdr_metadata_->cta_861_3 = gfx::HdrMetadataCta861_3(
        container->clli.maxCLL, container->clli.maxPALL);
  }

  // SetEmbeddedColorProfile() must be called before IsSizeAvailable() becomes
  // true. So call SetEmbeddedColorProfile() before calling SetSize(). The color
  // profile is either an ICC profile or the CICP color description.

  if (!IgnoresColorSpace()) {
    // The CICP color description is always present because we can always get it
    // from the AV1 sequence header for the frames. If an ICC profile is
    // present, use it instead of the CICP color description.
    if (container->icc.size) {
      std::unique_ptr<ColorProfile> profile = ColorProfile::Create(
          base::span(container->icc.data, container->icc.size));
      if (!profile) {
        DVLOG(1) << "Failed to parse image ICC profile";
        return false;
      }
      uint32_t data_color_space = profile->GetProfile()->data_color_space;
      const bool is_mono =
          container->yuvFormat == crabbyavif::AVIF_PIXEL_FORMAT_YUV400;
      if (is_mono) {
        if (data_color_space != skcms_Signature_Gray &&
            data_color_space != skcms_Signature_RGB) {
          profile = nullptr;
        }
      } else {
        if (data_color_space != skcms_Signature_RGB) {
          profile = nullptr;
        }
      }
      if (!profile) {
        DVLOG(1)
            << "Image contains ICC profile that does not match its color space";
        return false;
      }
      SetEmbeddedColorProfile(std::move(profile));
    } else if (container->colorPrimaries !=
                   crabbyavif::AVIF_COLOR_PRIMARIES_UNSPECIFIED ||
               container->transferCharacteristics !=
                   crabbyavif::AVIF_TRANSFER_CHARACTERISTICS_UNSPECIFIED) {
      gfx::ColorSpace frame_cs = GetColorSpace(container);

      sk_sp<SkColorSpace> sk_color_space =
          frame_cs.GetAsFullRangeRGB().ToSkColorSpace();
      if (!sk_color_space) {
        DVLOG(1) << "Image contains an unsupported color space";
        return false;
      }

      skcms_ICCProfile profile;
      sk_color_space->toProfile(&profile);
      SetEmbeddedColorProfile(std::make_unique<ColorProfile>(profile));
    }
  }

  // |angle| * 90 specifies the angle of anti-clockwise rotation in degrees.
  // Legal values: [0-3].
  int angle = 0;
  if (container->transformFlags & crabbyavif::AVIF_TRANSFORM_IROT) {
    angle = container->irot.angle;
    CHECK_LT(angle, 4);
  }
  // |axis| specifies how the mirroring is performed.
  //   -1: No mirroring.
  //    0: The top and bottom parts of the image are exchanged.
  //    1: The left and right parts of the image are exchanged.
  int axis = -1;
  if (container->transformFlags & crabbyavif::AVIF_TRANSFORM_IMIR) {
    axis = container->imir.axis;
    CHECK_LT(axis, 2);
  }
  // MIAF Section 7.3.6.7 (Clean aperture, rotation and mirror) says:
  //   These properties, if used, shall be indicated to be applied in the
  //   following order: clean aperture first, then rotation, then mirror.
  //
  // In the kAxisAngleToOrientation array, the first dimension is axis (with an
  // offset of 1). The second dimension is angle.
  constexpr ImageOrientationEnum kAxisAngleToOrientation[3][4] = {
      // No mirroring.
      {ImageOrientationEnum::kOriginTopLeft,
       ImageOrientationEnum::kOriginLeftBottom,
       ImageOrientationEnum::kOriginBottomRight,
       ImageOrientationEnum::kOriginRightTop},
      // Top-to-bottom mirroring. Change Top<->Bottom in the first row.
      {ImageOrientationEnum::kOriginBottomLeft,
       ImageOrientationEnum::kOriginLeftTop,
       ImageOrientationEnum::kOriginTopRight,
       ImageOrientationEnum::kOriginRightBottom},
      // Left-to-right mirroring. Change Left<->Right in the first row.
      {ImageOrientationEnum::kOriginTopRight,
       ImageOrientationEnum::kOriginRightBottom,
       ImageOrientationEnum::kOriginBottomLeft,
       ImageOrientationEnum::kOriginLeftTop},
  };
  orientation_ = kAxisAngleToOrientation[axis + 1][angle];

  // Determine whether the image can be decoded to YUV.
  // * Alpha channel is not supported.
  // * Multi-frame images (animations) are not supported. (The DecodeToYUV()
  //   method does not have an 'index' parameter.)
  allow_decode_to_yuv_ =
      avif_yuv_format_ != crabbyavif::AVIF_PIXEL_FORMAT_YUV400 &&
      !decoder_->alphaPresent && decoded_frame_count_ == 1 &&
      GetColorSpace(container).ToSkYUVColorSpace(container->depth,
                                                 &yuv_color_space_) &&
      // TODO(crbug.com/911246): Support color space transforms for YUV decodes.
      !ColorTransform();

  // Record bpp information only for 8-bit, color, still images that do not have
  // alpha.
  if (container->depth == 8 &&
      avif_yuv_format_ != crabbyavif::AVIF_PIXEL_FORMAT_YUV400 &&
      !decoder_->alphaPresent && decoded_frame_count_ == 1) {
    static constexpr char kType[] = "Avif";
    update_bpp_histogram_callback_ = base::BindOnce(&UpdateBppHistogram<kType>);
  }

  unsigned width = container->width;
  unsigned height = container->height;
  // If the image is cropped, pass the size of the cropped image (the clean
  // aperture) to SetSize().
  if (container->transformFlags & crabbyavif::AVIF_TRANSFORM_CLAP) {
    AVIFCleanApertureType clap_type;
    crabbyavif::avifCropRect crop_rect;
    crabbyavif::avifDiagnostics diag;
    crabbyavif::avifBool valid_clap =
        crabbyavif::crabby_avifCropRectConvertCleanApertureBox(
            &crop_rect, &container->clap, container->width, container->height,
            container->yuvFormat, &diag);
    if (!valid_clap) {
      DVLOG(1) << "Invalid 'clap' property: " << diag.error
               << "; showing the full image.";
      clap_type = AVIFCleanApertureType::kInvalid;
      ignore_clap_ = true;
    } else if (crop_rect.x != 0 || crop_rect.y != 0) {
      // To help discourage the creation of files with privacy risks, also
      // consider 'clap' properties whose origins are not at (0, 0) as invalid.
      // See https://github.com/AOMediaCodec/av1-avif/issues/188 and
      // https://github.com/AOMediaCodec/av1-avif/issues/189.
      DVLOG(1) << "Origin of 'clap' property anchored to (" << crop_rect.x
               << ", " << crop_rect.y << "); showing the full image.";
      clap_type = AVIFCleanApertureType::kNonzeroOrigin;
      ignore_clap_ = true;
    } else {
      clap_type = AVIFCleanApertureType::kZeroOrigin;
      clap_origin_.SetPoint(crop_rect.x, crop_rect.y);
      width = crop_rect.width;
      height = crop_rect.height;
    }
    clap_type_ = clap_type;
  }
  return SetSize(width, height);
}

crabbyavif::avifResult CrabbyAVIFImageDecoder::DecodeImage(wtf_size_t index) {
  const auto ret =
      crabbyavif::crabby_avifDecoderNthImage(decoder_.get(), index);
  // |index| should be less than what DecodeFrameCount() returns, so we should
  // not get the crabbyavif::AVIF_RESULT_NO_IMAGES_REMAINING error.
  DCHECK_NE(ret, crabbyavif::AVIF_RESULT_NO_IMAGES_REMAINING);
  if (ret != crabbyavif::AVIF_RESULT_OK &&
      ret != crabbyavif::AVIF_RESULT_WAITING_ON_IO) {
    DVLOG(1) << "crabbyavif::crabby_avifDecoderNthImage(" << index
             << ") failed: " << crabbyavif::crabby_avifResultToString(ret)
             << ": " << AvifDecoderErrorMessage(decoder_.get());
    return ret;
  }

  const auto* image = GetDecoderImage();
  // Frame size must be equal to container size.
  if (image->width != container_width_ || image->height != container_height_) {
    DVLOG(1) << "Frame size " << image->width << "x" << image->height
             << " differs from container size " << container_width_ << "x"
             << container_height_;
    return crabbyavif::AVIF_RESULT_UNKNOWN_ERROR;
  }
  // Frame bit depth must be equal to container bit depth.
  if (image->depth != bit_depth_) {
    DVLOG(1) << "Frame bit depth must be equal to container bit depth";
    return crabbyavif::AVIF_RESULT_UNKNOWN_ERROR;
  }
  // Frame YUV format must be equal to container YUV format.
  if (image->yuvFormat != avif_yuv_format_) {
    DVLOG(1) << "Frame YUV format must be equal to container YUV format";
    return crabbyavif::AVIF_RESULT_UNKNOWN_ERROR;
  }

  decoded_image_ = image;
  if ((image->transformFlags & crabbyavif::AVIF_TRANSFORM_CLAP) &&
      !ignore_clap_) {
    CropDecodedImage();
  }

  if (ret == crabbyavif::AVIF_RESULT_OK) {
    if (IsAllDataReceived() && update_bpp_histogram_callback_) {
      std::move(update_bpp_histogram_callback_).Run(Size(), data_->size());
    }

    if (clap_type_.has_value()) {
      base::UmaHistogramEnumeration("Blink.ImageDecoders.Avif.CleanAperture",
                                    clap_type_.value());
      clap_type_.reset();
    }
  }
  return ret;
}

void CrabbyAVIFImageDecoder::CropDecodedImage() {
  DCHECK_NE(decoded_image_, cropped_image_.get());
  if (!cropped_image_) {
    cropped_image_.reset(crabbyavif::crabby_avifImageCreateEmpty());
  }
  crabbyavif::avifCropRect rect;
  rect.x = clap_origin_.x();
  rect.y = clap_origin_.y();
  rect.width = Size().width();
  rect.height = Size().height();
  const crabbyavif::avifResult result = crabbyavif::crabby_avifImageSetViewRect(
      cropped_image_.get(), decoded_image_, &rect);
  CHECK_EQ(result, crabbyavif::AVIF_RESULT_OK);
  decoded_image_ = cropped_image_.get();
}

bool CrabbyAVIFImageDecoder::RenderImage(const crabbyavif::avifImage* image,
                                         int from_row,
                                         int* to_row,
                                         ImageFrame* buffer) {
  DCHECK_LT(from_row, *to_row);

  // libavif uses libyuv for the YUV 4:2:0 to RGB upsampling and/or conversion
  // as follows:
  //  - convert the top RGB row 0,
  //  - convert the RGB rows 1 and 2, then RGB rows 3 and 4 etc.,
  //  - convert the bottom (odd) RGB row if there is an even number of RGB rows.
  //
  // Unfortunately this cannot be applied incrementally as is. The RGB values
  // would differ because the first and last RGB rows have a formula using only
  // one UV row, while the other RGB rows use two UV rows as input each.
  // See https://crbug.com/libyuv/934.
  //
  // The workaround is a backup of the last converted even RGB row, called top
  // row, located right before |from_row|. The conversion is then called
  // starting at this top row, overwriting it with invalid values. The remaining
  // pairs of rows are correctly aligned and their freshly converted values are
  // valid. Then the backed up row is put back, fixing the issue.
  // The bottom row is postponed if the other half of the pair it belongs to is
  // not yet decoded.
  //
  //  UV rows |                 Y/RGB rows
  //          |  all  |  first decoding  |  second decoding
  //           ____ 0  ____ 0 (from_row)
  //    0 ---- ____ 1  ____ 1
  //           ____ 2  ____ 2             ____ 2 (backed up)
  //    1 ---- ____ 3  ____ 3 (postponed) ____ 3 (from_row)
  //           ____ 4       4 (*to_row)   ____ 4
  //    2 ---- ____ 5                     ____ 5
  //                                           6 (*to_row)

  const bool use_libyuv_bilinear_upsampling =
      !decode_to_half_float_ &&
      image->yuvFormat == crabbyavif::AVIF_PIXEL_FORMAT_YUV420;
  const bool save_top_row = use_libyuv_bilinear_upsampling && from_row > 0;
  const bool postpone_bottom_row =
      use_libyuv_bilinear_upsampling &&
      static_cast<uint32_t>(*to_row) < image->height;
  if (postpone_bottom_row) {
    // libavif outputs an even number of rows because 4:2:0 samples are decoded
    // in pairs.
    DCHECK(!(*to_row & 1));
    --*to_row;
    if (from_row == *to_row) {
      return true;  // Nothing to do.
    }
  }
  if (save_top_row) {
    // |from_row| is odd because it is equal to the output value of |*to_row|
    // from the previous RenderImage() call, and |*to_row| was even and then
    // decremented at that time.
    DCHECK(from_row & 1);
    --from_row;
  }

  // Focus |image| on rows [from_row, *to_row).
  std::unique_ptr<crabbyavif::avifImage,
                  decltype(&crabbyavif::crabby_avifImageDestroy)>
      view(nullptr, crabbyavif::crabby_avifImageDestroy);
  if (from_row > 0 || static_cast<uint32_t>(*to_row) < image->height) {
    const crabbyavif::avifCropRect rect = {
        0, static_cast<uint32_t>(from_row), image->width,
        static_cast<uint32_t>(*to_row - from_row)};
    view.reset(crabbyavif::crabby_avifImageCreateEmpty());
    const crabbyavif::avifResult result =
        crabbyavif::crabby_avifImageSetViewRect(view.get(), image, &rect);
    CHECK_EQ(result, crabbyavif::AVIF_RESULT_OK);
    image = view.get();
  }

  crabbyavif::avifRGBImage rgb_image;
  crabbyavif::crabby_avifRGBImageSetDefaults(&rgb_image, image);

  if (decode_to_half_float_) {
    rgb_image.depth = 16;
    rgb_image.isFloat = crabbyavif::CRABBY_AVIF_TRUE;
    rgb_image.pixels =
        reinterpret_cast<uint8_t*>(buffer->GetAddrF16(0, from_row));
    rgb_image.rowBytes = image->width * sizeof(uint64_t);
    // When decoding to half float, the pixel ordering is always RGBA on all
    // platforms.
    rgb_image.format = crabbyavif::AVIF_RGB_FORMAT_RGBA;
  } else {
    rgb_image.depth = 8;
    rgb_image.pixels = reinterpret_cast<uint8_t*>(buffer->GetAddr(0, from_row));
    rgb_image.rowBytes = image->width * sizeof(uint32_t);
    // When decoding to 8-bit, Android uses little-endian RGBA pixels. All other
    // platforms use BGRA pixels.
    static_assert(SK_B32_SHIFT == 16 - SK_R32_SHIFT);
    static_assert(SK_G32_SHIFT == 8);
    static_assert(SK_A32_SHIFT == 24);
#if SK_B32_SHIFT
    rgb_image.format = crabbyavif::AVIF_RGB_FORMAT_RGBA;
#else
    rgb_image.format = crabbyavif::AVIF_RGB_FORMAT_BGRA;
#endif
  }
  rgb_image.alphaPremultiplied = buffer->PremultiplyAlpha();
  rgb_image.maxThreads = decoder_->maxThreads;

  if (save_top_row) {
    previous_last_decoded_row_.resize(rgb_image.rowBytes);
    memcpy(previous_last_decoded_row_.data(), rgb_image.pixels,
           rgb_image.rowBytes);
  }
  const crabbyavif::avifResult result =
      crabbyavif::crabby_avifImageYUVToRGB(image, &rgb_image);
  if (save_top_row) {
    memcpy(rgb_image.pixels, previous_last_decoded_row_.data(),
           rgb_image.rowBytes);
  }
  return result == crabbyavif::AVIF_RESULT_OK;
}

void CrabbyAVIFImageDecoder::ColorCorrectImage(int from_row,
                                               int to_row,
                                               ImageFrame* buffer) {
  // Postprocess the image data according to the profile.
  const ColorProfileTransform* const transform = ColorTransform();
  if (!transform) {
    return;
  }
  const auto alpha_format = (buffer->HasAlpha() && buffer->PremultiplyAlpha())
                                ? skcms_AlphaFormat_PremulAsEncoded
                                : skcms_AlphaFormat_Unpremul;
  if (decode_to_half_float_) {
    const skcms_PixelFormat color_format = skcms_PixelFormat_RGBA_hhhh;
    for (int y = from_row; y < to_row; ++y) {
      ImageFrame::PixelDataF16* const row = buffer->GetAddrF16(0, y);
      const bool success = skcms_Transform(
          row, color_format, alpha_format, transform->SrcProfile(), row,
          color_format, alpha_format, transform->DstProfile(), Size().width());
      DCHECK(success);
    }
  } else {
    const skcms_PixelFormat color_format = XformColorFormat();
    for (int y = from_row; y < to_row; ++y) {
      ImageFrame::PixelData* const row = buffer->GetAddr(0, y);
      const bool success = skcms_Transform(
          row, color_format, alpha_format, transform->SrcProfile(), row,
          color_format, alpha_format, transform->DstProfile(), Size().width());
      DCHECK(success);
    }
  }
}

bool CrabbyAVIFImageDecoder::GetGainmapInfoAndData(
    SkGainmapInfo& out_gainmap_info,
    scoped_refptr<SegmentReader>& out_gainmap_data) const {
  if (!base::FeatureList::IsEnabled(features::kAvifGainmapHdrImages)) {
    return false;
  }
  // Ensure that parsing succeeded.
  if (!IsDecodedSizeAvailable()) {
    return false;
  }
  if (!decoder_->image->gainMap) {
    return false;
  }
  const crabbyavif::avifGainMap& gain_map = *decoder_->image->gainMap;
  if (gain_map.baseHdrHeadroom.d == 0 || gain_map.alternateHdrHeadroom.d == 0) {
    DVLOG(1) << "Invalid gainmap metadata: a denominator value is zero";
    return false;
  }
  const float base_headroom = std::exp2(
      FractionToFloat(gain_map.baseHdrHeadroom.n, gain_map.baseHdrHeadroom.d));
  const float alternate_headroom = std::exp2(FractionToFloat(
      gain_map.alternateHdrHeadroom.n, gain_map.alternateHdrHeadroom.d));
  const bool base_is_hdr = base_headroom > alternate_headroom;
  out_gainmap_info.fDisplayRatioSdr =
      base_is_hdr ? alternate_headroom : base_headroom;
  out_gainmap_info.fDisplayRatioHdr =
      base_is_hdr ? base_headroom : alternate_headroom;
  out_gainmap_info.fBaseImageType = base_is_hdr
                                        ? SkGainmapInfo::BaseImageType::kHDR
                                        : SkGainmapInfo::BaseImageType::kSDR;
  if (!gain_map.useBaseColorSpace) {
    // Try to use the alternate image's color space.
    out_gainmap_info.fGainmapMathColorSpace =
        GetAltImageColorSpace(*decoder_->image);
  }
  for (int i = 0; i < 3; ++i) {
    if (gain_map.gainMapMin[i].d == 0 || gain_map.gainMapMax[i].d == 0 ||
        gain_map.gainMapGamma[i].d == 0 || gain_map.baseOffset[i].d == 0 ||
        gain_map.alternateOffset[i].d == 0) {
      DVLOG(1) << "Invalid gainmap metadata: a denominator value is zero";
      return false;
    }
    if (gain_map.gainMapGamma[i].n == 0) {
      DVLOG(1) << "Invalid gainmap metadata: gamma is zero";
      return false;
    }

    const float min_log2 =
        FractionToFloat(gain_map.gainMapMin[i].n, gain_map.gainMapMin[i].d);
    const float max_log2 =
        FractionToFloat(gain_map.gainMapMax[i].n, gain_map.gainMapMax[i].d);
    out_gainmap_info.fGainmapRatioMin[i] = std::exp2(min_log2);
    out_gainmap_info.fGainmapRatioMax[i] = std::exp2(max_log2);

    // Numerator and denominator intentionally swapped to get 1.0/gamma.
    out_gainmap_info.fGainmapGamma[i] =
        FractionToFloat(gain_map.gainMapGamma[i].d, gain_map.gainMapGamma[i].n);
    const float base_offset =
        FractionToFloat(gain_map.baseOffset[i].n, gain_map.baseOffset[i].d);
    const float alternate_offset = FractionToFloat(
        gain_map.alternateOffset[i].n, gain_map.alternateOffset[i].d);
    out_gainmap_info.fEpsilonSdr[i] =
        base_is_hdr ? alternate_offset : base_offset;
    out_gainmap_info.fEpsilonHdr[i] =
        base_is_hdr ? base_offset : alternate_offset;
  }
  out_gainmap_data = data_;
  return true;
}

crabbyavif::avifImage* CrabbyAVIFImageDecoder::GetDecoderImage() const {
  CHECK(aux_image_ != cc::AuxImage::kGainmap ||
        (decoder_->image->gainMap != nullptr &&
         decoder_->image->gainMap->image != nullptr));
  return aux_image_ == cc::AuxImage::kGainmap ? decoder_->image->gainMap->image
                                              : decoder_->image;
}

CrabbyAVIFImageDecoder::AvifIOData::AvifIOData() = default;
CrabbyAVIFImageDecoder::AvifIOData::AvifIOData(
    scoped_refptr<const SegmentReader> reader,
    bool all_data_received)
    : reader(std::move(reader)), all_data_received(all_data_received) {}
CrabbyAVIFImageDecoder::AvifIOData::~AvifIOData() = default;

}  // namespace blink
```