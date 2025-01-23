Response:
The user is asking for a summary of the functionality of the provided C++ code snippet, which is part of the `ImageDecoder` class in the Chromium Blink rendering engine. I need to analyze the code and identify its main responsibilities and how it relates to web technologies like JavaScript, HTML, and CSS. I also need to consider potential usage errors and provide examples.

Here's a breakdown of the code's functionalities:

1. **Memory Management for Image Frames:** The code deals with tracking and managing the memory usage of decoded image frames. It includes checks for potential overflows and mechanisms for aggressively purging frames to stay within memory limits.

2. **Frame Status Tracking:** It keeps track of the decoding status of individual frames (partial or complete).

3. **Dependency Management Between Frames:**  For animated images, frames might depend on the content of previous frames. The code includes logic to determine which previous frame (if any) is required to decode the current frame. This logic considers the disposal method of previous frames.

4. **EXIF Metadata Handling:**  The code parses EXIF metadata embedded in image files to extract information like orientation and physical size.

5. **Color Profile Management:** The code handles embedded color profiles (like ICC profiles) and performs color space conversions if necessary to ensure correct color rendering. It manages the transformation between the image's embedded color profile and the Skia color space used for rendering.

Let's consider the relationships with JavaScript, HTML, and CSS:

*   **HTML:**  The `ImageDecoder` is crucial for rendering `<img>` elements and background images defined in CSS. When a browser encounters an image in HTML, this code is part of the process of decoding and preparing it for display.
*   **CSS:**  Similarly, when CSS properties like `background-image` point to an image, the `ImageDecoder` is involved.
*   **JavaScript:** JavaScript can interact with images through the `Image` object or the Canvas API. While JavaScript doesn't directly call `ImageDecoder` functions, the results of the decoding process managed by this class are what JavaScript manipulates and displays.

I need to provide an example of how these functionalities interact with web technologies and any potential errors.
```cpp
void ImageDecoder::ApplyExifMetadata(const SkData* exif_data,
                                     const gfx::Size& physical_size) {
  DCHECK(IsDecodedSizeAvailable());
  SkExif::Metadata metadata;
  SkExif::Parse(metadata, exif_data);

  orientation_ = static_cast<ImageOrientationEnum>(
      metadata.fOrigin.value_or(kTopLeft_SkEncodedOrigin));
  density_corrected_size_ =
      ExtractDensityCorrectedSize(metadata, physical_size);
}

ImagePlanes::ImagePlanes() {
  std::ranges::fill(planes_, nullptr);
  std::ranges::fill(row_bytes_, 0);
}

ImagePlanes::ImagePlanes(
    base::span<void*, cc::kNumYUVPlanes> planes,
    base::span<const wtf_size_t, cc::kNumYUVPlanes> row_bytes,
    SkColorType color_type)
    : color_type_(color_type) {
  base::span(planes_).copy_from(planes);
  base::span(row_bytes_).copy_from(row_bytes);
}

void* ImagePlanes::Plane(cc::YUVIndex index) {
  return planes_[static_cast<wtf_size_t>(index)];
}

wtf_size_t ImagePlanes::RowBytes(cc::YUVIndex index) const {
  return row_bytes_[static_cast<wtf_size_t>(index)];
}

ColorProfile::ColorProfile(const skcms_ICCProfile& profile,
                           base::HeapArray<uint8_t> buffer)
    : profile_(profile), buffer_(std::move(buffer)) {}

ColorProfile::~ColorProfile() = default;

std::unique_ptr<ColorProfile> ColorProfile::Create(
    base::span<const uint8_t> buffer) {
  // After skcms_Parse, profile will have pointers into the passed buffer,
  // so we need to copy first, then parse.
  auto owned_buffer = base::HeapArray<uint8_t>::CopiedFrom(buffer);
  skcms_ICCProfile profile;
  if (skcms_Parse(owned_buffer.data(), owned_buffer.size(), &profile)) {
    return std::make_unique<ColorProfile>(profile, std::move(owned_buffer));
  }
  return nullptr;
}

ColorProfileTransform::ColorProfileTransform(
    const skcms_ICCProfile* src_profile,
    const skcms_ICCProfile* dst_profile) {
  DCHECK(src_profile);
  DCHECK(dst_profile);
  src_profile_ = src_profile;
  dst_profile_ = *dst_profile;
}

const skcms_ICCProfile* ColorProfileTransform::SrcProfile() const {
  return src_profile_;
}

const skcms_ICCProfile* ColorProfileTransform::DstProfile() const {
  return &dst_profile_;
}

void ImageDecoder::SetEmbeddedColorProfile(
    std::unique_ptr<ColorProfile> profile) {
  DCHECK(!IgnoresColorSpace());

  embedded_color_profile_ = std::move(profile);
  sk_image_color_space_ = nullptr;
  embedded_to_sk_image_transform_.reset();
}

ColorProfileTransform* ImageDecoder::ColorTransform() {
  UpdateSkImageColorSpaceAndTransform();
  return embedded_to_sk_image_transform_.get();
}

ColorProfileTransform::~ColorProfileTransform() = default;

sk_sp<SkColorSpace> ImageDecoder::ColorSpaceForSkImages() {
  UpdateSkImageColorSpaceAndTransform();
  return sk_image_color_space_;
}

void ImageDecoder::UpdateSkImageColorSpaceAndTransform() {
  if (color_behavior_ == ColorBehavior::kIgnore) {
    return;
  }

  // If `color_behavior_` is not ignore, then this function will always set
  // `sk_image_color_space_` to something non-nullptr, so, if it is non-nullptr,
  // then everything is up to date.
  if (sk_image_color_space_) {
    return;
  }

  if (color_behavior_ == ColorBehavior::kTag) {
    // Set `sk_image_color_space_` to the best SkColorSpace approximation
    // of `embedded_color_profile_`.
    if (embedded_color_profile_) {
      const skcms_ICCProfile* profile = embedded_color_profile_->GetProfile();

      // If the ICC profile has CICP data, prefer to use that.
      if (profile->has_CICP) {
        sk_image_color_space_ =
            skia::CICPGetSkColorSpace(profile->CICP.color_primaries,
                                      profile->CICP.transfer_characteristics,
                                      profile->CICP.matrix_coefficients,
                                      profile->CICP.video_full_range_flag,
                                      /*prefer_srgb_trfn=*/true);
        // A CICP profile's SkColorSpace is considered an exact representation
        // of `profile`, so don't create `embedded_to_sk_image_transform_`.
        if (sk_image_color_space_) {
          return;
        }
      }

      // If there was not CICP data, then use the ICC profile.
      DCHECK(!sk_image_color_space_);
      sk_image_color_space_ = SkColorSpace::Make(*profile);

      // If the embedded color space isn't supported by Skia, we will transform
      // to a supported color space using `embedded_to_sk_image_transform_` at
      // decode time.
      if (!sk_image_color_space_ && profile->has_toXYZD50) {
        // Preserve the gamut, but convert to a standard transfer function.
        skcms_ICCProfile with_srgb = *profile;
        skcms_SetTransferFunction(&with_srgb, skcms_sRGB_TransferFunction());
        sk_image_color_space_ = SkColorSpace::Make(with_srgb);
      }

      // For color spaces without an identifiable gamut, just default to sRGB.
      if (!sk_image_color_space_) {
        sk_image_color_space_ = SkColorSpace::MakeSRGB();
      }
    } else {
      // If there is no `embedded_color_profile_`, then assume that the content
      // was sRGB (and `embedded_to_sk_image_transform_` is not needed).
      sk_image_color_space_ = SkColorSpace::MakeSRGB();
      return;
    }
  } else {
    DCHECK(color_behavior_ == ColorBehavior::kTransformToSRGB);
    sk_image_color_space_ = SkColorSpace::MakeSRGB();

    // If there is no `embedded_color_profile_`, then assume the content was
    // sRGB  (and, as above, `embedded_to_sk_image_transform_` is not needed).
    if (!embedded_color_profile_) {
      return;
    }
  }

  // If we arrive here then we may need to create a transform from
  // `embedded_color_profile_` to `sk_image_color_space_`.
  DCHECK(embedded_color_profile_);
  DCHECK(sk_image_color_space_);

  const skcms_ICCProfile* src_profile = embedded_color_profile_->GetProfile();
  skcms_ICCProfile dst_profile;
  sk_image_color_space_->toProfile(&dst_profile);
  if (skcms_ApproximatelyEqualProfiles(src_profile, &dst_profile)) {
    return;
  }

  embedded_to_sk_image_transform_ =
      std::make_unique<ColorProfileTransform>(src_profile, &dst_profile);
}

bool ImageDecoder::CanReusePreviousFrameBuffer(wtf_size_t) const {
  return false;
}

}  // namespace blink
```

## 功能归纳

这部分代码主要负责以下功能：

1. **EXIF 元数据处理:**  `ApplyExifMetadata` 函数解析图像文件中的 EXIF (Exchangeable image file format) 元数据。这包括：
    *   **图像方向:**  提取图像的原始方向（例如，是否需要旋转）。
    *   **像素密度修正尺寸:** 根据 EXIF 数据计算修正后的图像尺寸，这对于在不同设备上正确显示图像非常重要。

2. **图像平面数据结构:**  `ImagePlanes` 类用于表示图像的像素数据，尤其是在处理 YUV 格式的图像时。它包含指向不同颜色通道数据（例如，Y、U、V）的指针以及每一行的字节数。

3. **颜色配置文件管理:**
    *   `ColorProfile` 类封装了 ICC (International Color Consortium) 颜色配置文件的信息。它负责加载和存储颜色配置文件数据。
    *   `ColorProfileTransform` 类表示颜色空间之间的转换。它存储源颜色配置文件和目标颜色配置文件，以便在解码过程中进行颜色转换。
    *   `SetEmbeddedColorProfile` 函数用于设置图像解码器中嵌入的颜色配置文件。
    *   `ColorTransform` 函数返回用于颜色转换的 `ColorProfileTransform` 对象。
    *   `ColorSpaceForSkImages` 函数返回 Skia 图形库用于图像处理的颜色空间对象。
    *   `UpdateSkImageColorSpaceAndTransform` 函数负责根据解码器的颜色行为（忽略、标记、转换为 sRGB）和嵌入的颜色配置文件，确定最终使用的 Skia 颜色空间以及是否需要进行颜色空间转换。

## 与 JavaScript, HTML, CSS 的关系

这部分代码主要关注图像解码的底层处理，与 JavaScript、HTML 和 CSS 的交互更多是间接的：

*   **HTML (`<img>` 标签):** 当浏览器解析到 `<img>` 标签并需要显示图像时，`ImageDecoder` 会被调用来解码图像数据。`ApplyExifMetadata` 确保图像能根据其原始方向正确显示，例如，某些手机拍摄的照片可能带有旋转信息，需要进行调整才能在网页上正确定向显示。颜色配置文件处理确保图像的颜色在不同的设备和浏览器上尽可能一致。
    *   **举例:**  用户上传了一张用手机竖着拍摄的照片，但 EXIF 数据中记录了正确的方向。`ApplyExifMetadata` 会读取这个信息，即使图像数据本身是横向的，浏览器最终会以正确的竖向显示该图片在 `<img>` 标签中。

*   **CSS (`background-image` 属性):**  当 CSS 样式中使用 `background-image` 来设置背景图片时，`ImageDecoder` 同样会参与解码过程。颜色配置文件的处理在这里也很重要，确保背景图片的颜色与页面的其他元素协调一致。
    *   **举例:** 网站设计师使用了包含特定 ICC 颜色配置文件的背景图片。`UpdateSkImageColorSpaceAndTransform` 会根据浏览器的设置和图像的颜色配置文件，可能创建一个颜色转换，确保背景图片在用户的显示器上以预期的方式渲染，避免颜色偏差。

*   **JavaScript (Canvas API, `Image` 对象):**  虽然 JavaScript 不会直接调用这些 C++ 函数，但 JavaScript 可以通过 Canvas API 操作解码后的图像数据。`ImageDecoder` 的颜色配置文件处理会影响 Canvas API 获取到的像素数据，从而影响 JavaScript 对图像的操作结果。
    *   **举例:**  JavaScript 代码使用 Canvas API 加载一个图片并提取其像素数据进行分析。如果图片包含非 sRGB 的颜色配置文件，`ImageDecoder` 会将其转换为 Skia 使用的颜色空间，JavaScript 代码最终获取到的是经过颜色空间转换后的像素数据，这对于需要精确颜色信息的应用非常重要。

## 逻辑推理的假设输入与输出

**假设输入 (针对 `UpdateSkImageColorSpaceAndTransform`):**

1. `color_behavior_ = ColorBehavior::kTag` (表示尝试使用图像的颜色配置文件)。
2. `embedded_color_profile_` 存在，并且是一个非标准的 ICC 配置文件，但包含 CICP (Color Information Chunk Payload) 数据。

**输出:**

*   `sk_image_color_space_` 将被设置为通过 `skia::CICPGetSkColorSpace` 从 CICP 数据中获得的 Skia 颜色空间对象。
*   `embedded_to_sk_image_transform_` 将保持为空，因为 CICP 数据被认为是该配置文件的精确表示。

**假设输入 (针对 `UpdateSkImageColorSpaceAndTransform`):**

1. `color_behavior_ = ColorBehavior::kTransformToSRGB` (表示强制转换为 sRGB)。
2. `embedded_color_profile_` 存在，并且是一个 Display P3 颜色配置文件。

**输出:**

*   `sk_image_color_space_` 将被设置为 sRGB 颜色空间对象。
*   `embedded_to_sk_image_transform_` 将被创建一个 `ColorProfileTransform` 对象，用于将 Display P3 颜色空间的数据转换为 sRGB 颜色空间。

## 涉及用户或编程常见的使用错误

*   **图像颜色配置文件缺失或损坏:**  如果图像缺少颜色配置文件或者配置文件损坏，`skcms_Parse` 可能会失败，导致 `ColorProfile::Create` 返回空指针。这可能导致浏览器使用默认的 sRGB 颜色空间，从而使图像颜色显示不准确。开发者在生成图像时应确保正确嵌入有效的颜色配置文件。

*   **假设所有图像都是 sRGB:** 开发者可能会错误地假设所有在网页上使用的图像都是 sRGB 颜色空间，而忽略了其他颜色配置文件的存在。这可能导致在广色域显示器上，非 sRGB 图像的颜色看起来不饱和或不准确。浏览器开发者需要确保正确处理各种颜色配置文件。

*   **处理 EXIF 方向信息时的错误:**  开发者在处理用户上传的图片时，如果没有正确读取和应用 EXIF 方向信息，可能会导致图片显示方向错误。这在涉及到用户上传头像或者照片的场景中比较常见。浏览器需要可靠地解析和应用 EXIF 方向信息。

*   **在 Canvas 中进行颜色操作时未考虑颜色空间:**  当使用 Canvas API 操作图像时，如果没有意识到图像可能具有非 sRGB 的颜色空间，直接进行颜色计算可能会得到错误的结果。开发者需要根据图像的颜色空间进行相应的颜色转换。

总而言之，这部分 `ImageDecoder` 的代码专注于图像解码过程中的关键步骤，特别是处理图像的元数据（EXIF）和颜色信息（颜色配置文件），以确保图像能在浏览器中正确且一致地显示。它与前端技术通过浏览器渲染引擎的内部机制紧密相连。

### 提示词
```
这是目录为blink/renderer/platform/image-decoders/image_decoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
() if that size overflows
  DCHECK_EQ(frame_memory_usage / decoded_bytes_per_pixel,
            DecodedSize().Area64());

  const uint64_t total_memory_usage = frame_memory_usage * index;
  if (total_memory_usage / frame_memory_usage != index) {  // overflow occurred
    purge_aggressively_ = true;
    return;
  }

  if (total_memory_usage > max_decoded_bytes_) {
    purge_aggressively_ = true;
  }
}

bool ImageDecoder::FrameStatusSufficientForSuccessors(wtf_size_t index) {
  DCHECK(index < frame_buffer_cache_.size());
  ImageFrame::Status frame_status = frame_buffer_cache_[index].GetStatus();
  return frame_status == ImageFrame::kFramePartial ||
         frame_status == ImageFrame::kFrameComplete;
}

wtf_size_t ImageDecoder::FindRequiredPreviousFrame(wtf_size_t frame_index,
                                                   bool frame_rect_is_opaque) {
  DCHECK_LT(frame_index, frame_buffer_cache_.size());
  if (!frame_index) {
    // The first frame doesn't rely on any previous data.
    return kNotFound;
  }

  const ImageFrame* curr_buffer = &frame_buffer_cache_[frame_index];
  if ((frame_rect_is_opaque ||
       curr_buffer->GetAlphaBlendSource() == ImageFrame::kBlendAtopBgcolor) &&
      curr_buffer->OriginalFrameRect().Contains(gfx::Rect(Size()))) {
    return kNotFound;
  }

  // The starting state for this frame depends on the previous frame's
  // disposal method.
  wtf_size_t prev_frame = frame_index - 1;
  const ImageFrame* prev_buffer = &frame_buffer_cache_[prev_frame];

  // Frames that use the DisposeOverwritePrevious method are effectively
  // no-ops in terms of changing the starting state of a frame compared to
  // the starting state of the previous frame, so skip over them.
  while (prev_buffer->GetDisposalMethod() ==
         ImageFrame::kDisposeOverwritePrevious) {
    if (prev_frame == 0) {
      return kNotFound;
    }
    prev_frame--;
    prev_buffer = &frame_buffer_cache_[prev_frame];
  }

  switch (prev_buffer->GetDisposalMethod()) {
    case ImageFrame::kDisposeNotSpecified:
    case ImageFrame::kDisposeKeep:
      // |prev_frame| will be used as the starting state for this frame.
      // FIXME: Be even smarter by checking the frame sizes and/or
      // alpha-containing regions.
      return prev_frame;
    case ImageFrame::kDisposeOverwriteBgcolor:
      // If the previous frame fills the whole image, then the current frame
      // can be decoded alone. Likewise, if the previous frame could be
      // decoded without reference to any prior frame, the starting state for
      // this frame is a blank frame, so it can again be decoded alone.
      // Otherwise, the previous frame contributes to this frame.
      return (prev_buffer->OriginalFrameRect().Contains(gfx::Rect(Size())) ||
              (prev_buffer->RequiredPreviousFrameIndex() == kNotFound))
                 ? kNotFound
                 : prev_frame;
    case ImageFrame::kDisposeOverwritePrevious:
    default:
      NOTREACHED();
  }
}

void ImageDecoder::ApplyExifMetadata(const SkData* exif_data,
                                     const gfx::Size& physical_size) {
  DCHECK(IsDecodedSizeAvailable());
  SkExif::Metadata metadata;
  SkExif::Parse(metadata, exif_data);

  orientation_ = static_cast<ImageOrientationEnum>(
      metadata.fOrigin.value_or(kTopLeft_SkEncodedOrigin));
  density_corrected_size_ =
      ExtractDensityCorrectedSize(metadata, physical_size);
}

ImagePlanes::ImagePlanes() {
  std::ranges::fill(planes_, nullptr);
  std::ranges::fill(row_bytes_, 0);
}

ImagePlanes::ImagePlanes(
    base::span<void*, cc::kNumYUVPlanes> planes,
    base::span<const wtf_size_t, cc::kNumYUVPlanes> row_bytes,
    SkColorType color_type)
    : color_type_(color_type) {
  base::span(planes_).copy_from(planes);
  base::span(row_bytes_).copy_from(row_bytes);
}

void* ImagePlanes::Plane(cc::YUVIndex index) {
  return planes_[static_cast<wtf_size_t>(index)];
}

wtf_size_t ImagePlanes::RowBytes(cc::YUVIndex index) const {
  return row_bytes_[static_cast<wtf_size_t>(index)];
}

ColorProfile::ColorProfile(const skcms_ICCProfile& profile,
                           base::HeapArray<uint8_t> buffer)
    : profile_(profile), buffer_(std::move(buffer)) {}

ColorProfile::~ColorProfile() = default;

std::unique_ptr<ColorProfile> ColorProfile::Create(
    base::span<const uint8_t> buffer) {
  // After skcms_Parse, profile will have pointers into the passed buffer,
  // so we need to copy first, then parse.
  auto owned_buffer = base::HeapArray<uint8_t>::CopiedFrom(buffer);
  skcms_ICCProfile profile;
  if (skcms_Parse(owned_buffer.data(), owned_buffer.size(), &profile)) {
    return std::make_unique<ColorProfile>(profile, std::move(owned_buffer));
  }
  return nullptr;
}

ColorProfileTransform::ColorProfileTransform(
    const skcms_ICCProfile* src_profile,
    const skcms_ICCProfile* dst_profile) {
  DCHECK(src_profile);
  DCHECK(dst_profile);
  src_profile_ = src_profile;
  dst_profile_ = *dst_profile;
}

const skcms_ICCProfile* ColorProfileTransform::SrcProfile() const {
  return src_profile_;
}

const skcms_ICCProfile* ColorProfileTransform::DstProfile() const {
  return &dst_profile_;
}

void ImageDecoder::SetEmbeddedColorProfile(
    std::unique_ptr<ColorProfile> profile) {
  DCHECK(!IgnoresColorSpace());

  embedded_color_profile_ = std::move(profile);
  sk_image_color_space_ = nullptr;
  embedded_to_sk_image_transform_.reset();
}

ColorProfileTransform* ImageDecoder::ColorTransform() {
  UpdateSkImageColorSpaceAndTransform();
  return embedded_to_sk_image_transform_.get();
}

ColorProfileTransform::~ColorProfileTransform() = default;

sk_sp<SkColorSpace> ImageDecoder::ColorSpaceForSkImages() {
  UpdateSkImageColorSpaceAndTransform();
  return sk_image_color_space_;
}

void ImageDecoder::UpdateSkImageColorSpaceAndTransform() {
  if (color_behavior_ == ColorBehavior::kIgnore) {
    return;
  }

  // If `color_behavior_` is not ignore, then this function will always set
  // `sk_image_color_space_` to something non-nullptr, so, if it is non-nullptr,
  // then everything is up to date.
  if (sk_image_color_space_) {
    return;
  }

  if (color_behavior_ == ColorBehavior::kTag) {
    // Set `sk_image_color_space_` to the best SkColorSpace approximation
    // of `embedded_color_profile_`.
    if (embedded_color_profile_) {
      const skcms_ICCProfile* profile = embedded_color_profile_->GetProfile();

      // If the ICC profile has CICP data, prefer to use that.
      if (profile->has_CICP) {
        sk_image_color_space_ =
            skia::CICPGetSkColorSpace(profile->CICP.color_primaries,
                                      profile->CICP.transfer_characteristics,
                                      profile->CICP.matrix_coefficients,
                                      profile->CICP.video_full_range_flag,
                                      /*prefer_srgb_trfn=*/true);
        // A CICP profile's SkColorSpace is considered an exact representation
        // of `profile`, so don't create `embedded_to_sk_image_transform_`.
        if (sk_image_color_space_) {
          return;
        }
      }

      // If there was not CICP data, then use the ICC profile.
      DCHECK(!sk_image_color_space_);
      sk_image_color_space_ = SkColorSpace::Make(*profile);

      // If the embedded color space isn't supported by Skia, we will transform
      // to a supported color space using `embedded_to_sk_image_transform_` at
      // decode time.
      if (!sk_image_color_space_ && profile->has_toXYZD50) {
        // Preserve the gamut, but convert to a standard transfer function.
        skcms_ICCProfile with_srgb = *profile;
        skcms_SetTransferFunction(&with_srgb, skcms_sRGB_TransferFunction());
        sk_image_color_space_ = SkColorSpace::Make(with_srgb);
      }

      // For color spaces without an identifiable gamut, just default to sRGB.
      if (!sk_image_color_space_) {
        sk_image_color_space_ = SkColorSpace::MakeSRGB();
      }
    } else {
      // If there is no `embedded_color_profile_`, then assume that the content
      // was sRGB (and `embedded_to_sk_image_transform_` is not needed).
      sk_image_color_space_ = SkColorSpace::MakeSRGB();
      return;
    }
  } else {
    DCHECK(color_behavior_ == ColorBehavior::kTransformToSRGB);
    sk_image_color_space_ = SkColorSpace::MakeSRGB();

    // If there is no `embedded_color_profile_`, then assume the content was
    // sRGB  (and, as above, `embedded_to_sk_image_transform_` is not needed).
    if (!embedded_color_profile_) {
      return;
    }
  }

  // If we arrive here then we may need to create a transform from
  // `embedded_color_profile_` to `sk_image_color_space_`.
  DCHECK(embedded_color_profile_);
  DCHECK(sk_image_color_space_);

  const skcms_ICCProfile* src_profile = embedded_color_profile_->GetProfile();
  skcms_ICCProfile dst_profile;
  sk_image_color_space_->toProfile(&dst_profile);
  if (skcms_ApproximatelyEqualProfiles(src_profile, &dst_profile)) {
    return;
  }

  embedded_to_sk_image_transform_ =
      std::make_unique<ColorProfileTransform>(src_profile, &dst_profile);
}

bool ImageDecoder::CanReusePreviousFrameBuffer(wtf_size_t) const {
  return false;
}

}  // namespace blink
```