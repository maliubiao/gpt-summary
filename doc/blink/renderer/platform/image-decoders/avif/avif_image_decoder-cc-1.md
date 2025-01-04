Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's Blink rendering engine. This code is part of the AVIF image decoder.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Functionality:** The file name `avif_image_decoder.cc` and the class name `AVIFImageDecoder` immediately suggest that this code is responsible for decoding AVIF image data.

2. **Analyze Key Methods:**  Scan the provided code for significant functions and their roles. Methods like `SetFrameProperties`, `DecodeImage`, `RenderImage`, `ColorCorrectImage`, and `GetGainmapInfoAndData` stand out.

3. **Break Down Functionality by Method:**  Examine each important method to understand its specific contribution to the decoding process.

    * **`SetFrameProperties`**:  This method appears to handle the initial setup after parsing the AVIF container. It extracts metadata like color profiles, rotation, mirroring, and determines if YUV decoding is possible. It also deals with "clean aperture" information (cropping).

    * **`DecodeImage`**: This function likely performs the actual decoding of the image data for a given frame. It checks for errors, ensures consistency between the frame and container properties, and handles cropping.

    * **`RenderImage`**: This method takes the decoded image data and renders it into an `ImageFrame` buffer. It seems to handle different pixel formats (8-bit and half-float) and deals with a specific optimization for YUV 4:2:0 decoding using `libyuv`.

    * **`ColorCorrectImage`**: This function applies color correction to the rendered image data based on the embedded color profile.

    * **`GetGainmapInfoAndData`**:  This method is related to AVIF gain maps, a feature for handling HDR images. It extracts metadata and provides access to the gain map data.

4. **Identify Relationships with Web Technologies (JavaScript, HTML, CSS):** Think about how image decoding in the browser relates to these technologies.

    * **HTML `<img>` tag:**  The browser uses the image decoder when it encounters an `<img src="image.avif">` tag to display the image.
    * **CSS `background-image`:** Similarly, when an AVIF image is used as a background in CSS (`background-image: url("image.avif");`), the decoder is involved.
    * **JavaScript `Image()` constructor and Canvas API:** JavaScript can load and manipulate images. The decoder is used when a script creates an `Image` object with an AVIF source or when drawing an AVIF image onto a canvas.

5. **Consider Logical Inferences (Hypothetical Inputs and Outputs):**  For each key function, imagine a simple input and what the expected output would be. This helps solidify understanding.

    * **`SetFrameProperties`**: Input: An `avifContainer` object containing metadata. Output:  The decoder's internal state is updated with properties like `orientation_`, `allow_decode_to_yuv_`, and `clap_type_`.

    * **`DecodeImage`**: Input: An index of the image frame to decode. Output: The `decoded_image_` member variable is updated with the decoded image data (or an error result).

    * **`RenderImage`**: Input: A decoded `avifImage`, row numbers, and an `ImageFrame` buffer. Output: The `ImageFrame` buffer is filled with the rendered pixel data.

6. **Identify Potential User/Programming Errors:** Think about common mistakes when working with images or using image decoders.

    * **Incorrect file format:** Trying to load a non-AVIF file.
    * **Corrupted AVIF file:** The decoder might fail or produce unexpected results.
    * **Memory allocation issues:**  Although not explicitly shown in this snippet, memory management is crucial in decoders.
    * **Using unsupported features:**  If an AVIF file uses a feature the decoder doesn't support (or a specific browser version doesn't support), it might fail.

7. **Structure the Response:** Organize the findings logically. Start with a high-level summary, then detail the functionality of each important method. Follow this with examples of how it relates to web technologies, logical inferences, and common errors.

8. **Address the "Part 2" Request:**  The prompt specifically mentions this is "part 2". The response should focus on summarizing the *overall* functionality based on the provided code snippet. Avoid repeating too much detail from a hypothetical "part 1". Emphasize the core purpose: decoding AVIF images for rendering in the browser.

9. **Review and Refine:**  Read through the generated response to ensure clarity, accuracy, and completeness. Make sure the language is easy to understand and the examples are relevant. For instance, ensure that the assumptions made in the "logical inference" section are reasonable.
这是对Chromium Blink引擎中 `blink/renderer/platform/image-decoders/avif/avif_image_decoder.cc` 文件功能的总结，基于您提供的第二部分代码。

**归纳其功能：**

总而言之，`AVIFImageDecoder` 的主要功能是**解码 AVIF 图像数据并将其转换为可以被 Blink 渲染引擎使用的像素格式**。它负责处理 AVIF 文件的容器格式、提取图像数据、进行解码、应用颜色校正和必要的变换（旋转、镜像、裁剪），最终将解码后的像素数据存储在 `ImageFrame` 对象中。

**更具体地，基于提供的第二部分代码，其功能包括：**

* **处理帧属性和元数据：**
    * 检查并应用内嵌的 ICC 颜色配置文件或根据容器中的颜色元数据（色域、传递特性）创建颜色配置文件。
    * 处理图像的旋转和镜像变换，并将其转换为 `ImageOrientationEnum` 枚举值。
    * 判断是否可以将图像解码为 YUV 格式（受限于 alpha 通道、动画和颜色空间变换的支持）。
    * 处理 AVIF 图像的裁剪信息 (Clean Aperture Box - clap)，如果 `clap` 属性有效且原点为 (0, 0)，则会设置解码后的图像尺寸为裁剪后的尺寸。否则，会忽略 `clap` 属性并显示完整图像。
* **解码图像数据：**
    * 使用 `avifDecoderNthImage` 函数实际解码指定索引的图像帧。
    * 验证解码后的帧的尺寸、位深和 YUV 格式是否与容器信息一致。
    * 如果图像包含裁剪信息且未被忽略，则调用 `CropDecodedImage` 进行裁剪。
    * 在成功解码后，记录图像的每像素比特数（bpp）信息（仅针对特定条件：8 位、彩色、静态、无 alpha）。
* **渲染图像到 `ImageFrame`：**
    * `RenderImage` 函数负责将解码后的 AVIF 图像数据渲染到 `ImageFrame` 缓冲区中。
    * 它处理了 `libyuv` 在 YUV 4:2:0 到 RGB 转换时的特殊性，采用了一种备份和恢复行的策略来保证转换的正确性。
    * 支持渲染为 8 位像素和半精度浮点像素。
    * 根据目标平台的字节序设置 RGB 像素的格式（RGBA 或 BGRA）。
* **应用颜色校正：**
    * `ColorCorrectImage` 函数根据之前提取或创建的颜色配置文件，对渲染后的图像数据进行颜色校正。
    * 它使用 `skcms_Transform` 函数进行色彩空间的转换。
* **获取增益图信息 (Gainmap)：**
    * `GetGainmapInfoAndData` 函数用于提取和提供与 AVIF 增益图相关的信息和数据。增益图用于支持高动态范围 (HDR) 图像。
    * 它解析增益图的元数据，例如显示比例、数学色彩空间、最小值、最大值、Gamma 值和偏移量。

**与 JavaScript, HTML, CSS 的关系举例：**

* **HTML `<img>` 标签：** 当浏览器遇到一个指向 AVIF 图像的 `<img>` 标签时，Blink 渲染引擎会调用 `AVIFImageDecoder` 来解码该图像，然后将解码后的像素数据用于在页面上显示图像。
    ```html
    <img src="image.avif" alt="An AVIF image">
    ```
    在这个例子中，`AVIFImageDecoder` 负责读取 `image.avif` 文件的数据，并将其解码成浏览器可以理解的像素格式。
* **CSS `background-image` 属性：**  类似地，如果 CSS 的 `background-image` 属性指定了一个 AVIF 图像，`AVIFImageDecoder` 也会被用来解码该图像。
    ```css
    .container {
      background-image: url("background.avif");
    }
    ```
    `AVIFImageDecoder` 会解码 `background.avif`，然后浏览器会用解码后的图像作为 `.container` 元素的背景。
* **JavaScript Canvas API：**  JavaScript 可以使用 Canvas API 来操作图像。如果 JavaScript 代码尝试在 canvas 上绘制一个 AVIF 图像，`AVIFImageDecoder` 会先解码该图像。
    ```javascript
    const image = new Image();
    image.src = 'canvas_image.avif';
    image.onload = function() {
      const canvas = document.getElementById('myCanvas');
      const ctx = canvas.getContext('2d');
      ctx.drawImage(image, 0, 0);
    };
    ```
    当 `image.src` 被设置为 AVIF 文件时，`AVIFImageDecoder` 会在后台解码图像，当 `onload` 事件触发时，解码后的图像数据就可以被绘制到 canvas 上。

**逻辑推理的假设输入与输出：**

假设输入是一个包含以下信息的 AVIF 图像：

* **容器信息：** 宽度 640px，高度 480px，YUV420 格式，8 位深度，包含 ICC 颜色配置文件，旋转角度为 90 度（逆时针）。
* **已解码的帧数据：** 成功的解码了第一帧图像数据。

**`SetFrameProperties` 的输出：**

* `orientation_` 将被设置为 `ImageOrientationEnum::kOriginLeftBottom` (对应于逆时针旋转 90 度)。
* `embedded_color_profile_` 将包含从容器中解析出的 ICC 颜色配置文件。
* `allow_decode_to_yuv_` 可能为 `true` 或 `false`，取决于是否存在 alpha 通道等其他因素。
* `size()` 将返回裁剪后的尺寸（如果存在有效的 `clap` 信息）或者原始尺寸 (640x480)。

**`DecodeImage` 的输出：**

* 如果 `index` 为 0，且解码成功，`decoded_image_` 将指向解码后的第一帧图像数据。
* 返回值为 `AVIF_RESULT_OK`。

**`RenderImage` 的假设输入与输出：**

* **假设输入：**
    * `image` 指向已解码的 `decoded_image_`。
    * `from_row` 为 0。
    * `*to_row` 为 480。
    * `buffer` 是一个可以容纳 640x480 像素的 `ImageFrame` 对象。
* **预期输出：**
    * `buffer` 将被填充上从 `decoded_image_` 渲染出的像素数据，并按照 `SetFrameProperties` 中确定的方向进行旋转。
    * 如果有颜色配置文件，颜色也会被校正。

**用户或编程常见的使用错误举例：**

* **尝试解码损坏的 AVIF 文件：**  如果用户加载了一个部分下载或内容损坏的 AVIF 文件，`avifDecoderNthImage` 可能会返回错误，导致解码失败，最终可能导致页面上图片显示错误或无法显示。
* **假设输入的索引超出范围：** 如果开发者错误地传递了一个大于图像帧数的 `index` 给 `DecodeImage`，`avifDecoderNthImage` 可能会返回 `AVIF_RESULT_NO_IMAGES_REMAINING`，虽然代码中有 `DCHECK_NE`，但这仍然是一个潜在的编程错误。
* **依赖不支持的 AVIF 功能：** 如果 AVIF 文件使用了 `AVIFImageDecoder` 当前版本不支持的功能（例如特定的颜色空间变换或高级编码特性），解码可能会失败或产生非预期的结果。例如，如果 `TODO(crbug.com/911246): Support color space transforms for YUV decodes.` 的问题尚未解决，尝试解码需要颜色空间转换的 YUV 图像将会失败。
* **未处理异步解码完成：** 对于动画 AVIF，解码是异步的。如果开发者没有正确处理解码完成的回调或 Promise，可能会尝试在图像完全解码之前使用图像数据，导致错误。

总而言之，`AVIFImageDecoder` 在 Blink 渲染引擎中扮演着至关重要的角色，它使得浏览器能够理解和显示 AVIF 这种现代高效的图像格式。它涉及到复杂的数据处理、颜色管理和图像变换，以确保用户在网页上看到正确的图像内容。

Prompt: 
```
这是目录为blink/renderer/platform/image-decoders/avif/avif_image_decoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
orProfile> profile = ColorProfile::Create(
          base::span(container->icc.data, container->icc.size));
      if (!profile) {
        DVLOG(1) << "Failed to parse image ICC profile";
        return false;
      }
      uint32_t data_color_space = profile->GetProfile()->data_color_space;
      const bool is_mono = container->yuvFormat == AVIF_PIXEL_FORMAT_YUV400;
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
    } else if (container->colorPrimaries != AVIF_COLOR_PRIMARIES_UNSPECIFIED ||
               container->transferCharacteristics !=
                   AVIF_TRANSFER_CHARACTERISTICS_UNSPECIFIED) {
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
  if (container->transformFlags & AVIF_TRANSFORM_IROT) {
    angle = container->irot.angle;
    CHECK_LT(angle, 4);
  }
  // |axis| specifies how the mirroring is performed.
  //   -1: No mirroring.
  //    0: The top and bottom parts of the image are exchanged.
  //    1: The left and right parts of the image are exchanged.
  int axis = -1;
  if (container->transformFlags & AVIF_TRANSFORM_IMIR) {
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
      avif_yuv_format_ != AVIF_PIXEL_FORMAT_YUV400 && !decoder_->alphaPresent &&
      decoded_frame_count_ == 1 &&
      GetColorSpace(container).ToSkYUVColorSpace(container->depth,
                                                 &yuv_color_space_) &&
      // TODO(crbug.com/911246): Support color space transforms for YUV decodes.
      !ColorTransform();

  // Record bpp information only for 8-bit, color, still images that do not have
  // alpha.
  if (container->depth == 8 && avif_yuv_format_ != AVIF_PIXEL_FORMAT_YUV400 &&
      !decoder_->alphaPresent && decoded_frame_count_ == 1) {
    static constexpr char kType[] = "Avif";
    update_bpp_histogram_callback_ = base::BindOnce(&UpdateBppHistogram<kType>);
  }

  unsigned width = container->width;
  unsigned height = container->height;
  // If the image is cropped, pass the size of the cropped image (the clean
  // aperture) to SetSize().
  if (container->transformFlags & AVIF_TRANSFORM_CLAP) {
    AVIFCleanApertureType clap_type;
    avifCropRect crop_rect;
    avifDiagnostics diag;
    avifBool valid_clap = avifCropRectConvertCleanApertureBox(
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

avifResult AVIFImageDecoder::DecodeImage(wtf_size_t index) {
  const auto ret = avifDecoderNthImage(decoder_.get(), index);
  // |index| should be less than what DecodeFrameCount() returns, so we should
  // not get the AVIF_RESULT_NO_IMAGES_REMAINING error.
  DCHECK_NE(ret, AVIF_RESULT_NO_IMAGES_REMAINING);
  if (ret != AVIF_RESULT_OK && ret != AVIF_RESULT_WAITING_ON_IO) {
    DVLOG(1) << "avifDecoderNthImage(" << index
             << ") failed: " << avifResultToString(ret) << ": "
             << AvifDecoderErrorMessage(decoder_.get());
    return ret;
  }

  const auto* image = GetDecoderImage();
  // Frame size must be equal to container size.
  if (image->width != container_width_ || image->height != container_height_) {
    DVLOG(1) << "Frame size " << image->width << "x" << image->height
             << " differs from container size " << container_width_ << "x"
             << container_height_;
    return AVIF_RESULT_UNKNOWN_ERROR;
  }
  // Frame bit depth must be equal to container bit depth.
  if (image->depth != bit_depth_) {
    DVLOG(1) << "Frame bit depth must be equal to container bit depth";
    return AVIF_RESULT_UNKNOWN_ERROR;
  }
  // Frame YUV format must be equal to container YUV format.
  if (image->yuvFormat != avif_yuv_format_) {
    DVLOG(1) << "Frame YUV format must be equal to container YUV format";
    return AVIF_RESULT_UNKNOWN_ERROR;
  }

  decoded_image_ = image;
  if ((image->transformFlags & AVIF_TRANSFORM_CLAP) && !ignore_clap_) {
    CropDecodedImage();
  }

  if (ret == AVIF_RESULT_OK) {
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

void AVIFImageDecoder::CropDecodedImage() {
  DCHECK_NE(decoded_image_, cropped_image_.get());
  if (!cropped_image_) {
    cropped_image_.reset(avifImageCreateEmpty());
  }
  avifCropRect rect;
  rect.x = clap_origin_.x();
  rect.y = clap_origin_.y();
  rect.width = Size().width();
  rect.height = Size().height();
  const avifResult result =
      avifImageSetViewRect(cropped_image_.get(), decoded_image_, &rect);
  CHECK_EQ(result, AVIF_RESULT_OK);
  decoded_image_ = cropped_image_.get();
}

bool AVIFImageDecoder::RenderImage(const avifImage* image,
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
      !decode_to_half_float_ && image->yuvFormat == AVIF_PIXEL_FORMAT_YUV420;
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
  std::unique_ptr<avifImage, decltype(&avifImageDestroy)> view(
      nullptr, avifImageDestroy);
  if (from_row > 0 || static_cast<uint32_t>(*to_row) < image->height) {
    const avifCropRect rect = {0, static_cast<uint32_t>(from_row), image->width,
                               static_cast<uint32_t>(*to_row - from_row)};
    view.reset(avifImageCreateEmpty());
    const avifResult result = avifImageSetViewRect(view.get(), image, &rect);
    CHECK_EQ(result, AVIF_RESULT_OK);
    image = view.get();
  }

  avifRGBImage rgb_image;
  avifRGBImageSetDefaults(&rgb_image, image);

  if (decode_to_half_float_) {
    rgb_image.depth = 16;
    rgb_image.isFloat = AVIF_TRUE;
    rgb_image.pixels =
        reinterpret_cast<uint8_t*>(buffer->GetAddrF16(0, from_row));
    rgb_image.rowBytes = image->width * sizeof(uint64_t);
    // When decoding to half float, the pixel ordering is always RGBA on all
    // platforms.
    rgb_image.format = AVIF_RGB_FORMAT_RGBA;
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
    rgb_image.format = AVIF_RGB_FORMAT_RGBA;
#else
    rgb_image.format = AVIF_RGB_FORMAT_BGRA;
#endif
  }
  rgb_image.alphaPremultiplied = buffer->PremultiplyAlpha();
  rgb_image.maxThreads = decoder_->maxThreads;

  if (save_top_row) {
    previous_last_decoded_row_.resize(rgb_image.rowBytes);
    memcpy(previous_last_decoded_row_.data(), rgb_image.pixels,
           rgb_image.rowBytes);
  }
  const avifResult result = avifImageYUVToRGB(image, &rgb_image);
  if (save_top_row) {
    memcpy(rgb_image.pixels, previous_last_decoded_row_.data(),
           rgb_image.rowBytes);
  }
  return result == AVIF_RESULT_OK;
}

void AVIFImageDecoder::ColorCorrectImage(int from_row,
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

bool AVIFImageDecoder::GetGainmapInfoAndData(
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
  const avifGainMap& gain_map = *decoder_->image->gainMap;
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

avifImage* AVIFImageDecoder::GetDecoderImage() const {
  CHECK(aux_image_ != cc::AuxImage::kGainmap ||
        (decoder_->image->gainMap != nullptr &&
         decoder_->image->gainMap->image != nullptr));
  return aux_image_ == cc::AuxImage::kGainmap ? decoder_->image->gainMap->image
                                              : decoder_->image;
}

AVIFImageDecoder::AvifIOData::AvifIOData() = default;
AVIFImageDecoder::AvifIOData::AvifIOData(
    scoped_refptr<const SegmentReader> reader,
    bool all_data_received)
    : reader(std::move(reader)), all_data_received(all_data_received) {}
AVIFImageDecoder::AvifIOData::~AvifIOData() = default;

}  // namespace blink

"""


```