Response:
My thought process for analyzing the provided code snippet and fulfilling the request goes like this:

1. **Understand the Goal:** The primary goal is to understand the functionality of the `png_image_decoder_test.cc` file within the Chromium Blink engine. This involves identifying its purpose, its relationship to web technologies (JavaScript, HTML, CSS), and potential usage scenarios including common errors.

2. **Identify the Core Functionality:** The file name itself strongly suggests it's a *test* file for a PNG *image decoder*. Keywords like `TEST_P`, `EXPECT_EQ`, `ASSERT_TRUE`, and `ReadFile` reinforce this. The `#include` statements provide further clues, referencing classes like `ImageDecoder`, `SharedBuffer`, and types from the `png` and `skia` libraries, confirming it's testing the decoding of PNG images.

3. **Break Down the Code by Sections/Functions:** I'd start by examining individual test functions (`TEST_P`) and helper functions (`TestSize`, `TestSizeByteByByte`, `TestRepetitionCount`, etc.). This allows me to understand specific aspects of the decoder being tested.

4. **Analyze Individual Test Cases:**
    * **`sizeTest`:**  Tests if the decoder can correctly determine the size (width and height) of a PNG image.
    * **`repetitionCountTest`:** Checks if the decoder can identify the number of times an animated PNG should loop.
    * **`MetaDataTest`:** Verifies that the decoder extracts frame-specific metadata (duration, position, blending, disposal) for animated PNGs.
    * **`EmptyFrame`:**  Examines how the decoder handles an animated PNG with an empty frame.
    * **`ByteByByteSizeAvailable` and `ByteByByteMetaData`:** Test the progressive decoding of image metadata as data is received incrementally.
    * **`TestRandomFrameDecode` and `TestDecodeAfterReallocation`:**  Focus on the ability to decode specific frames and handle memory reallocation during the process.
    * **`ProgressiveDecode` and `ParseAndDecodeByteByByte`:**  Test the core progressive decoding functionality where image data is processed in chunks.
    * **`FailureDuringParsing`:** Checks how the decoder reacts to invalid data within the PNG structure (specifically the `fcTL` chunk).
    * **`ActlErrors`:** Investigates how the decoder handles issues related to the `acTL` chunk (animation control), such as its absence, duplication, or incorrect placement.
    * **`fdatBeforeIdat`:**  Tests the decoder's behavior when frame data chunks (`fdAT`) appear before the main image data chunk (`IDAT`), which is invalid for static PNGs but possible in APNG.
    * **`FrameOverflowX/Y`:**  Checks how the decoder handles frame offsets that extend beyond the image boundaries.
    * **`IdatSizeMismatch`:** Tests scenarios where the frame size doesn't match the declared image size.
    * **`EmptyFdatFails`:** Verifies that the decoder handles empty frame data chunks correctly.
    * **`VerifyFrameOutsideImageSizeFails`:**  Similar to overflow tests, but specifically checks if a frame's rectangle is entirely outside the image bounds.
    * **`ProgressiveDecodingContinuesAfterFullData`:** Ensures that progressive decoding can complete successfully when all data is eventually provided.
    * **`RandomDecodeAfterClearFrameBufferCache`:**  Tests the decoder's ability to decode frames after the frame buffer cache has been cleared.
    * **`VerifyAlphaBlending`:** Checks how the decoder handles different alpha blending modes in animated PNGs.

5. **Identify Relationships to Web Technologies:**  PNG images are a fundamental part of the web.
    * **HTML:** The `<img src="...">` tag is the primary way to display PNG images in HTML. The decoder's correctness directly impacts how these images are rendered.
    * **CSS:** CSS properties like `background-image` can also use PNGs. The decoding process is the same.
    * **JavaScript:** JavaScript can manipulate images through the Canvas API or by creating `Image` objects. The underlying decoding mechanism is the same, so the correctness of this test file ensures proper image handling in JavaScript contexts.

6. **Consider Logic and Assumptions:** Many tests involve creating "invalid" PNG data by modifying existing valid PNG files. This tests the decoder's error handling. I'd explicitly note the assumptions made in these tests, like "removing bytes will cause a parsing error."

7. **Identify Potential User/Programming Errors:**  Based on the tests, I can infer common errors:
    * **Corrupted PNG files:**  The tests that modify PNG data simulate this.
    * **Incorrectly generated animated PNGs:**  Issues with `acTL`, `fcTL`, or `fdAT` chunks could arise from faulty animation software.
    * **Assumptions about decoding behavior:** Developers might assume that a partially downloaded image will render immediately, while progressive decoding might have intermediate states.

8. **Address the "Rust Feature" Parameterization:** The `PNGTests` class uses `testing::TestWithParam<RustFeatureState>`. This indicates that the tests are run twice: once with the "Rusty PNG" feature enabled and once disabled. This is important for understanding the test coverage and potential differences in behavior between the C++ and Rust implementations.

9. **Structure the Output:**  I'd organize the findings logically, addressing each part of the request:
    * **Functionality Summary:** A concise overview of the file's purpose.
    * **Relationship to Web Technologies:** Clear examples of how PNG decoding is relevant to HTML, CSS, and JavaScript.
    * **Logic and Assumptions (with Input/Output):** For example, "Hypothesis: Removing bytes from the middle of a chunk will cause a parsing error. Input: Valid PNG data with a section removed. Output: `decoder->Failed()` returns `true`."
    * **Common Errors:** Listing the potential pitfalls for users and programmers.
    * **Summary:** A brief recap of the file's role in ensuring the reliability of PNG decoding.

10. **Refine and Review:**  Finally, I'd review the generated output for clarity, accuracy, and completeness, ensuring it directly answers all aspects of the original request. For instance, double-check the byte offsets mentioned in the comments and tests. Make sure the explanation of the Rust feature flag is clear.
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include <memory>

#include "base/logging.h"
#include "base/test/scoped_feature_list.h"
#include "base/time/time.h"
#include "png.h"
#include "skia/buildflags.h"
#include "skia/rusty_png_feature.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/image-decoders/image_decoder_test_helpers.h"
#include "third_party/blink/renderer/platform/image-decoders/png/png_decoder_factory.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/skia/include/core/SkColorPriv.h"
#include "third_party/skia/include/core/SkColorSpace.h"
#include "third_party/skia/include/core/SkImage.h"
#include "third_party/skia/include/core/SkImageInfo.h"
#include "third_party/skia/include/core/SkRefCnt.h"

// web_tests/images/resources/png-animated-idat-part-of-animation.png
// is modified in multiple tests to simulate erroneous PNGs. As a reference,
// the table below shows how the file is structured.
//
// Offset | 8     33    95    133   172   210   241   279   314   352   422
// -------------------------------------------------------------------------
// Chunk  | IHDR  acTL  fcTL  IDAT  fcTL  fdAT  fcTL  fdAT  fcTL  fdAT  IEND
//
// In between the acTL and fcTL there are two other chunks, PLTE and tRNS, but
// those are not specifically used in this test suite. The same holds for a
// tEXT chunk in between the last fdAT and IEND.
//
// In the current behavior of PNG image decoders, the 4 frames are detected when
// respectively 141, 249, 322 and 430 bytes are received. The first frame should
// be detected when the IDAT has been received, and non-first frames when the
// next fcTL or IEND chunk has been received. Note that all offsets are +8,
// because a chunk is identified by byte 4-7.

namespace blink {

namespace {

std::unique_ptr<ImageDecoder> CreatePNGDecoder(
    ImageDecoder::AlphaOption alpha_option) {
  return CreatePngImageDecoder(alpha_option, ImageDecoder::kDefaultBitDepth,
                               ColorBehavior::kTransformToSRGB,
                               ImageDecoder::kNoDecodedImageByteLimit);
}

std::unique_ptr<ImageDecoder> CreatePNGDecoder() {
  return CreatePNGDecoder(ImageDecoder::kAlphaNotPremultiplied);
}

std::unique_ptr<ImageDecoder> Create16BitPNGDecoder() {
  return CreatePngImageDecoder(ImageDecoder::kAlphaNotPremultiplied,
                               ImageDecoder::kHighBitDepthToHalfFloat,
                               ColorBehavior::kTag,
                               ImageDecoder::kNoDecodedImageByteLimit);
}

std::unique_ptr<ImageDecoder> CreatePNGDecoderWithPngData(
    const char* png_file) {
  auto decoder = CreatePNGDecoder();
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(png_file);
  EXPECT_FALSE(data->empty());
  decoder->SetData(data.get(), true);
  return decoder;
}

void TestSize(const char* png_file, gfx::Size expected_size) {
  auto decoder = CreatePNGDecoderWithPngData(png_file);
  EXPECT_TRUE(decoder->IsSizeAvailable());
  EXPECT_EQ(expected_size, decoder->Size());
}

// Test whether querying for the size of the image works if we present the
// data byte by byte.
void TestSizeByteByByte(const char* png_file,
                        size_t bytes_needed_to_decode_size,
                        gfx::Size expected_size) {
  auto decoder = CreatePNGDecoder();
  Vector<char> data = ReadFile(png_file);
  ASSERT_FALSE(data.empty());
  ASSERT_LT(bytes_needed_to_decode_size, data.size());

  const char* source = data.data();
  scoped_refptr<SharedBuffer> partial_data = SharedBuffer::Create();
  for (size_t length = 1; length <= bytes_needed_to_decode_size; length++) {
    partial_data->Append(source++, 1u);
    decoder->SetData(partial_data.get(), false);

    if (length < bytes_needed_to_decode_size) {
      EXPECT_FALSE(decoder->IsSizeAvailable());
      EXPECT_TRUE(decoder->Size().IsEmpty());
      EXPECT_FALSE(decoder->Failed());
    } else {
      EXPECT_TRUE(decoder->IsSizeAvailable());
      EXPECT_EQ(expected_size, decoder->Size());
    }
  }
  EXPECT_FALSE(decoder->Failed());
}

void WriteUint32(uint32_t val, png_byte* data) {
  data[0] = val >> 24;
  data[1] = val >> 16;
  data[2] = val >> 8;
  data[3] = val;
}

void TestRepetitionCount(const char* png_file, int expected_repetition_count) {
  auto decoder = CreatePNGDecoderWithPngData(png_file);
  // Decoding the frame count sets the number of repetitions as well.
  decoder->FrameCount();
  EXPECT_FALSE(decoder->Failed());
  EXPECT_EQ(expected_repetition_count, decoder->RepetitionCount());
}

struct PublicFrameInfo {
  base::TimeDelta duration;
  gfx::Rect frame_rect;
  ImageFrame::AlphaBlendSource alpha_blend;
  ImageFrame::DisposalMethod disposal_method;
};

// This is the frame data for the following PNG image:
// web_tests/images/resources/png-animated-idat-part-of-animation.png
static PublicFrameInfo g_png_animated_frame_info[] = {
    {base::Milliseconds(500),
     {gfx::Point(0, 0), gfx::Size(5, 5)},
     ImageFrame::kBlendAtopBgcolor,
     ImageFrame::kDisposeKeep},
    {base::Milliseconds(900),
     {gfx::Point(1, 1), gfx::Size(3, 1)},
     ImageFrame::kBlendAtopBgcolor,
     ImageFrame::kDisposeOverwriteBgcolor},
    {base::Milliseconds(2000),
     {gfx::Point(1, 2), gfx::Size(3, 2)},
     ImageFrame::kBlendAtopPreviousFrame,
     ImageFrame::kDisposeKeep},
    {base::Milliseconds(1500),
     {gfx::Point(1, 2), gfx::Size(3, 1)},
     ImageFrame::kBlendAtopBgcolor,
     ImageFrame::kDisposeKeep},
};

void CompareFrameWithExpectation(const PublicFrameInfo& expected,
                                 ImageDecoder* decoder,
                                 size_t index) {
  EXPECT_EQ(expected.duration, decoder->FrameDurationAtIndex(index));

  const auto* frame = decoder->DecodeFrameBufferAtIndex(index);
  ASSERT_TRUE(frame);

  EXPECT_EQ(expected.duration, frame->Duration());
  EXPECT_EQ(expected.disposal_method, frame->GetDisposalMethod());
  EXPECT_EQ(expected.frame_rect, frame->OriginalFrameRect());
  EXPECT_EQ(expected.alpha_blend, frame->GetAlphaBlendSource());
}

// This function removes |length| bytes at |offset|, and then calls FrameCount.
// It assumes the missing bytes should result in a failed decode because the
// parser jumps |length| bytes too far in the next chunk.
void TestMissingDataBreaksDecoding(const char* png_file,
                                   size_t offset,
                                   size_t length) {
  auto decoder = CreatePNGDecoder();
  Vector<char> data = ReadFile(png_file);
  ASSERT_FALSE(data.empty());

  scoped_refptr<SharedBuffer> invalid_data =
      SharedBuffer::Create(data.data(), offset);
  invalid_data->Append(data.data() + offset + length,
                       data.size() - offset - length);
  ASSERT_EQ(data.size() - length, invalid_data->size());

  decoder->SetData(invalid_data, true);
  decoder->FrameCount();
  EXPECT_TRUE(decoder->Failed());
}

// Verify that a decoder with a parse error converts to a static image.
static void ExpectStatic(ImageDecoder* decoder) {
  EXPECT_EQ(1u, decoder->FrameCount());
  EXPECT_FALSE(decoder->Failed());

  ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
  ASSERT_NE(nullptr, frame);
  EXPECT_EQ(ImageFrame::kFrameComplete, frame->GetStatus());
  EXPECT_FALSE(decoder->Failed());
  EXPECT_EQ(kAnimationNone, decoder->RepetitionCount());
}

// Decode up to the indicated fcTL offset and then provide an fcTL with the
// wrong chunk size (20 instead of 26).
void TestInvalidFctlSize(const char* png_file,
                         size_t offset_fctl,
                         size_t expected_frame_count,
                         bool should_fail) {
  Vector<char> data = ReadFile(png_file);
  ASSERT_FALSE(data.empty());

  auto decoder = CreatePNGDecoder();
  scoped_refptr<SharedBuffer> invalid_data =
      SharedBuffer::Create(data.data(), offset_fctl);

  // Test if this gives the correct frame count, before the fcTL is parsed.
  decoder->SetData(invalid_data, false);
  EXPECT_EQ(expected_frame_count, decoder->FrameCount());
  ASSERT_FALSE(decoder->Failed());

  // Append the wrong size to the data stream
  png_byte size_chunk[4];
  WriteUint32(20, size_chunk);
  invalid_data->Append(reinterpret_cast<char*>(size_chunk), 4u);

  // Skip the size in the original data, but provide a truncated fcTL,
  // which is 4B of tag, 20B of data and 4B of CRC, totalling 28B.
  invalid_data->Append(data.data() + offset_fctl + 4, 28u);
  // Append the rest of the data
  const size_t offset_post_fctl = offset_fctl + 38;
  invalid_data->Append(data.data() + offset_post_fctl,
                       data.size() - offset_post_fctl);

  decoder->SetData(invalid_data, false);
  if (should_fail) {
    EXPECT_EQ(expected_frame_count, decoder->FrameCount());
    EXPECT_EQ(true, decoder->Failed());
  } else {
    // `SkiaImageDecoderBase` doesn't report an overall failure, unless *all*
    // frames fail. If some animated frames have an error, then other animated
    // frames may continue to work. This is by design - see
    // https://crbug.com/371592786#comment3.
    if (!skia::IsRustyPngEnabled()) {
      ExpectStatic(decoder.get());
    }
  }
}

// Verify that the decoder can successfully decode the first frame when
// initially only half of the frame data is received, resulting in a partially
// decoded image, and then the rest of the image data is received. Verify that
// the bitmap hashes of the two stages are different. Also verify that the final
// bitmap hash is equivalent to the hash when all data is provided at once.
//
// This verifies that the decoder correctly keeps track of where it stopped
// decoding when the image was not yet fully received.
void TestProgressiveDecodingContinuesAfterFullData(
    const char* png_file,
    size_t offset_mid_first_frame) {
  Vector<char> full_data = ReadFile(png_file);
  ASSERT_FALSE(full_data.empty());

  auto decoder_upfront = CreatePNGDecoder();
  decoder_upfront->SetData(SharedBuffer::Create(full_data), true);
  EXPECT_GE(decoder_upfront->FrameCount(), 1u);
  const ImageFrame* const frame_upfront =
      decoder_upfront->DecodeFrameBufferAtIndex(0);
  ASSERT_EQ(ImageFrame::kFrameComplete, frame_upfront->GetStatus());
  const unsigned hash_upfront = HashBitmap(frame_upfront->Bitmap());

  auto decoder = CreatePNGDecoder();
  scoped_refptr<SharedBuffer> partial_data =
      SharedBuffer::Create(full_data.data(), offset_mid_first_frame);
  decoder->SetData(partial_data, false);

  EXPECT_EQ(1u, decoder->FrameCount());
  const ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
  EXPECT_EQ(frame->GetStatus(), ImageFrame::kFramePartial);
  const unsigned hash_partial = HashBitmap(frame->Bitmap());

  decoder->SetData(SharedBuffer::Create(full_data), true);
  frame = decoder->DecodeFrameBufferAtIndex(0);
  EXPECT_EQ(frame->GetStatus(), ImageFrame::kFrameComplete);
  const unsigned hash_full = HashBitmap(frame->Bitmap());

  EXPECT_FALSE(decoder->Failed());
  EXPECT_NE(hash_full, hash_partial);
  EXPECT_EQ(hash_full, hash_upfront);
}

enum class RustFeatureState { kRustEnabled, kRustDisabled };

class PNGTests : public testing::TestWithParam<RustFeatureState> {
 public:
  PNGTests() {
    switch (GetParam()) {
      case RustFeatureState::kRustEnabled:
        features_.InitAndEnableFeature(skia::kRustyPngFeature);
        break;
      case RustFeatureState::kRustDisabled:
        features_.InitAndDisableFeature(skia::kRustyPngFeature);
        break;
    }
  }

 protected:
  base::test::ScopedFeatureList features_;
};

// Animated PNG Tests

using AnimatedPNGTests = PNGTests;
TEST_P(AnimatedPNGTests, sizeTest) {
  TestSize(
      "/images/resources/"
      "png-animated-idat-part-of-animation.png",
      gfx::Size(5, 5));
  TestSize(
      "/images/resources/"
      "png-animated-idat-not-part-of-animation.png",
      gfx::Size(227, 35));
}

TEST_P(AnimatedPNGTests, repetitionCountTest) {
  TestRepetitionCount(
      "/images/resources/"
      "png-animated-idat-part-of-animation.png",
      6u);
  // This is an "animated" image with only one frame, that is, the IDAT is
  // ignored and there is one fdAT frame. so it should be considered
  // non-animated.
  TestRepetitionCount(
      "/images/resources/"
      "png-animated-idat-not-part-of-animation.png",
      kAnimationNone);
}

// Test if the decoded metadata corresponds to the defined expectations
TEST_P(AnimatedPNGTests, MetaDataTest) {
  const char* png_file =
      "/images/resources/"
      "png-animated-idat-part-of-animation.png";
  constexpr size_t kExpectedFrameCount = 4;

  auto decoder = CreatePNGDecoderWithPngData(png_file);
  ASSERT_EQ(kExpectedFrameCount, decoder->FrameCount());
  for (size_t i = 0; i < kExpectedFrameCount; i++) {
    CompareFrameWithExpectation(g_png_animated_frame_info[i], decoder.get(), i);
  }
}

TEST_P(AnimatedPNGTests, EmptyFrame) {
  const char* png_file = "/images/resources/empty-frame.png";
  auto decoder = CreatePNGDecoderWithPngData(png_file);
  // Frame 0 is empty. Ensure that decoding frame 1 (which depends on frame 0)
  // fails (rather than crashing).
  EXPECT_EQ(2u, decoder->FrameCount());
  EXPECT_FALSE(decoder->Failed());

  ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(1);
  ASSERT_NE(nullptr, frame);
  EXPECT_EQ(ImageFrame::kFrameEmpty, frame->GetStatus());

  if (skia::IsRustyPngEnabled()) {
    // `SkiaImageDecoderBase` doesn't report an overall failure, unless *all*
    // frames fail. This is by design - see
    // https://crbug.com/371592786#comment3.
    ASSERT_FALSE(decoder->Failed());
    EXPECT_EQ(decoder->FrameCount(), 2u);
  } else {
    ASSERT_TRUE(decoder->Failed());
  }
}

TEST_P(AnimatedPNGTests, ByteByByteSizeAvailable) {
  TestSizeByteByByte(
      "/images/resources/"
      "png-animated-idat-part-of-animation.png",
      141u, gfx::Size(5, 5));
  TestSizeByteByByte(
      "/images/resources/"
      "png-animated-idat-not-part-of-animation.png",
      79u, gfx::Size(227, 35));
}

TEST_P(AnimatedPNGTests, ByteByByteMetaData) {
  const char* png_file =
      "/images/resources/"
      "png-animated-idat-part-of-animation.png";
  constexpr size_t kExpectedFrameCount = 4;

  // These are the byte offsets where each frame should have been parsed.
  // It boils down to the offset of the first fcTL / IEND after the last
  // frame data chunk, plus 8 bytes for recognition. The exception on this is
  // the first frame, which is reported when its first framedata is seen.
  size_t frame_offsets[kExpectedFrameCount] = {141, 249, 322, 430};
  if (skia::IsRustyPngEnabled()) {
    // The original offsets correspond to 8 bytes after the corresponding
    // `fcTL` and `fdAT` chunk. `SkPngRustCodec` can discover and report
    // frame metadata earlier - as soon as the `fdAT` chunk is recognized.
    frame_offsets[1] = 218;
    frame_offsets[2] = 287;
    frame_offsets[3] = 360;
  }

  auto decoder = CreatePNGDecoder();
  Vector<char> data = ReadFile(png_file);
  ASSERT_FALSE(data.empty());
  size_t frames_parsed = 0;

  const char* source = data.data();
  scoped_refptr<SharedBuffer> partial_data = SharedBuffer::Create();
  for (size_t length = 1; length <= frame_offsets[kExpectedFrameCount - 1];
       length++) {
    partial_data->Append(source++, 1u);
    decoder->SetData(partial_data.get(), false);
    EXPECT_FALSE(decoder->Failed());
    if (length < frame_offsets[frames_parsed]) {
      EXPECT_EQ(frames_parsed, decoder->FrameCount());
    } else {
      if (skia::IsRustyPngEnabled() && frames_parsed > 0) {
        // `SkPngRustCodec` cannot discover new frames when in the middle of an
        // incremental decode (see http://review.skia.org/913917). To make
        // progress, we need to finish the previous decode.
        EXPECT_NE(nullptr,
                  decoder->DecodeFrameBufferAtIndex(frames_parsed - 1));
      }

      ASSERT_EQ(frames_parsed + 1, decoder->FrameCount());
      CompareFrameWithExpectation(g_png_animated_frame_info[frames_parsed],
                                  decoder.get(), frames_parsed);
      frames_parsed++;
    }
  }
  EXPECT_EQ(kExpectedFrameCount, decoder->FrameCount());
  EXPECT_FALSE(decoder->Failed());
}

TEST_P(AnimatedPNGTests, TestRandomFrameDecode) {
  TestRandomFrameDecode(&CreatePNGDecoder,
                        "/images/resources/"
                        "png-animated-idat-part-of-animation.png",
                        2u);
}

TEST_P(AnimatedPNGTests, TestDecodeAfterReallocation) {
  TestDecodeAfterReallocatingData(&CreatePNGDecoder,
                                  "/images/resources/"
                                  "png-animated-idat-part-of-animation.png");
}

TEST_P(AnimatedPNGTests, ProgressiveDecode) {
  TestProgressiveDecoding(&CreatePNGDecoder,
                          "/images/resources/"
                          "png-animated-idat-part-of-animation.png",
                          13u);
}

TEST_P(AnimatedPNGTests, ParseAndDecodeByteByByte) {
  TestByteByByteDecode(&CreatePNGDecoder,
                       "/images/resources/"
                       "png-animated-idat-part-of-animation.png",
                       4u, 6u);
}

TEST_P(AnimatedPNGTests, FailureDuringParsing) {
  // Test the first fcTL in the stream. Because no frame data has been set at
  // this point, the expected frame count is zero. 95 bytes is just before the
  // first fcTL chunk, at which the first frame is detected. This is before the
  // IDAT, so it should be treated as a static image.
  TestInvalidFctlSize(
      "/images/resources/"
      "png-animated-idat-part-of-animation.png",
      95u, 0u, false);

  // Test for the third fcTL in the stream. This should see 1 frame before the
  // fcTL, and then fail when parsing it.
  size_t expected_frame_count = 1u;
  bool should_fail = true;
  if (skia::IsRustyPngEnabled()) {
    // `SkiaImageDecoderBase` doesn't report an overall failure, unless *all*
    // frames fail. If some animated frames have an error, then other animated
    // frames may continue to work. This is by design - see
    // https://crbug.com/371592786#comment3.
    expected_frame_count = 2u;
    should_fail = false;
  }
  TestInvalidFctlSize(
      "/images/resources/"
      "png-animated-idat-part-of-animation.png",
      241u, expected_frame_count, should_fail);
}

TEST_P(AnimatedPNGTests, ActlErrors) {
  const char* png_file =
      "/images/resources/"
      "png-animated-idat-part-of-animation.png";
  Vector<char> data = ReadFile(png_file);
  ASSERT_FALSE(data.empty());

  const size_t kOffsetActl = 33u;
  const size_t kAcTLSize = 20u;
  {
    // Remove the acTL chunk from the stream. This results in a static image.
    scoped_refptr<SharedBuffer> no_actl_data =
        SharedBuffer::Create(data.data(), kOffsetActl);
    no_actl_data->Append(data.data() + kOffsetActl + kAcTLSize,
                         data.size() - kOffsetActl - kAcTLSize);

    auto decoder = CreatePNGDecoder();
    decoder->SetData(no_actl_data, true);
    EXPECT_EQ(1u, decoder->FrameCount());
    EXPECT_FALSE(decoder->Failed());
    EXPECT_EQ(kAnimationNone, decoder->RepetitionCount());
  }

  // Store the acTL for more tests.
  char ac_tl[kAcTLSize];
  memcpy(ac_tl, data.data() + kOffsetActl, kAcTLSize);

  // Insert an extra acTL at a couple of different offsets.
  // Prior to the IDAT, this should result in a static image. After, this
  // should fail.
  struct {
    size_t offset;
    bool should_fail;
  } kGRecs[] = {{8u, false},
                {kOffsetActl, false},
                {133u, false},
                {172u, true},
                {422u, true}};
  if (skia::IsRustyPngEnabled()) {
    // https://www.w3.org/TR/2003/REC-PNG-20031110/#5ChunkOrdering says that the
    // IHDR chunk "shall be first". Rust `png` crate treats this situation as an
    // error in accordance with the spec.
    kGRecs[0].should_fail = true;

    // `SkiaImageDecoderBase` doesn't report an overall failure, unless *all*
    // frames fail. This is by design - see
    // https://crbug.com/371592786#comment3.
    kGRecs[3].should_fail = false;
    kGRecs[4].should_fail = false;
  }
  for (const auto& rec : kGRecs) {
    const size_t offset = rec.offset;
    scoped_refptr<SharedBuffer> extra_actl_data =
        SharedBuffer::Create(data.data(), offset);
    extra_actl_data->Append(ac_tl, kAcTLSize);
    extra_actl_data->Append(data.data() + offset, data.size() - offset);
    auto decoder = CreatePNGDecoder();
    decoder->SetData(extra_actl_data, true);

    // `blink::PNGImageDecoder` falls back to the static image upon encountering
    // APNG-specific issues (as suggested by the APNG spec).
    // `blink::SkiaImageDecoderBase` in this situation animates the successful
    // frames, and ignore the failed frames (this is by design - see
    // https://crbug.com/371592786#comment3).
    wtf_size_t frame_count = decoder->FrameCount();
    if (skia::IsRustyPngEnabled()) {
      EXPECT_LE(0u, frame_count);
      EXPECT_LE(frame_count, 4u);
    } else {
      EXPECT_EQ(rec.should_fail ? 0u : 1u, decoder->FrameCount());
    }
    EXPECT_EQ(rec.should_fail, decoder->Failed());
  }

  // An acTL after IDAT is ignored.
  png_file =
      "/images/resources/"
      "cHRM_color_spin.png";
  {
    Vector<char> data2 = ReadFile(png_file);
    ASSERT_FALSE(data2.empty());
    const size_t kPostIDATOffset = 30971u;
    for (size_t times = 0; times < 2; times++) {
      scoped_refptr<SharedBuffer> extra_actl_data =
          SharedBuffer::Create(data2.data(), kPostIDATOffset);
      for (size_t i = 0; i < times; i++) {
        extra_actl_data->Append(ac_tl, kAcTLSize);
      }
      extra_actl_data->Append(data2.data() + kPostIDATOffset,
                              data2.size() - kPostIDATOffset);

      auto decoder = CreatePNGDecoder();
      decoder->
### 提示词
```
这是目录为blink/renderer/platform/image-decoders/png/png_image_decoder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include <memory>

#include "base/logging.h"
#include "base/test/scoped_feature_list.h"
#include "base/time/time.h"
#include "png.h"
#include "skia/buildflags.h"
#include "skia/rusty_png_feature.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/image-decoders/image_decoder_test_helpers.h"
#include "third_party/blink/renderer/platform/image-decoders/png/png_decoder_factory.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/skia/include/core/SkColorPriv.h"
#include "third_party/skia/include/core/SkColorSpace.h"
#include "third_party/skia/include/core/SkImage.h"
#include "third_party/skia/include/core/SkImageInfo.h"
#include "third_party/skia/include/core/SkRefCnt.h"

// web_tests/images/resources/png-animated-idat-part-of-animation.png
// is modified in multiple tests to simulate erroneous PNGs. As a reference,
// the table below shows how the file is structured.
//
// Offset | 8     33    95    133   172   210   241   279   314   352   422
// -------------------------------------------------------------------------
// Chunk  | IHDR  acTL  fcTL  IDAT  fcTL  fdAT  fcTL  fdAT  fcTL  fdAT  IEND
//
// In between the acTL and fcTL there are two other chunks, PLTE and tRNS, but
// those are not specifically used in this test suite. The same holds for a
// tEXT chunk in between the last fdAT and IEND.
//
// In the current behavior of PNG image decoders, the 4 frames are detected when
// respectively 141, 249, 322 and 430 bytes are received. The first frame should
// be detected when the IDAT has been received, and non-first frames when the
// next fcTL or IEND chunk has been received. Note that all offsets are +8,
// because a chunk is identified by byte 4-7.

namespace blink {

namespace {

std::unique_ptr<ImageDecoder> CreatePNGDecoder(
    ImageDecoder::AlphaOption alpha_option) {
  return CreatePngImageDecoder(alpha_option, ImageDecoder::kDefaultBitDepth,
                               ColorBehavior::kTransformToSRGB,
                               ImageDecoder::kNoDecodedImageByteLimit);
}

std::unique_ptr<ImageDecoder> CreatePNGDecoder() {
  return CreatePNGDecoder(ImageDecoder::kAlphaNotPremultiplied);
}

std::unique_ptr<ImageDecoder> Create16BitPNGDecoder() {
  return CreatePngImageDecoder(ImageDecoder::kAlphaNotPremultiplied,
                               ImageDecoder::kHighBitDepthToHalfFloat,
                               ColorBehavior::kTag,
                               ImageDecoder::kNoDecodedImageByteLimit);
}

std::unique_ptr<ImageDecoder> CreatePNGDecoderWithPngData(
    const char* png_file) {
  auto decoder = CreatePNGDecoder();
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(png_file);
  EXPECT_FALSE(data->empty());
  decoder->SetData(data.get(), true);
  return decoder;
}

void TestSize(const char* png_file, gfx::Size expected_size) {
  auto decoder = CreatePNGDecoderWithPngData(png_file);
  EXPECT_TRUE(decoder->IsSizeAvailable());
  EXPECT_EQ(expected_size, decoder->Size());
}

// Test whether querying for the size of the image works if we present the
// data byte by byte.
void TestSizeByteByByte(const char* png_file,
                        size_t bytes_needed_to_decode_size,
                        gfx::Size expected_size) {
  auto decoder = CreatePNGDecoder();
  Vector<char> data = ReadFile(png_file);
  ASSERT_FALSE(data.empty());
  ASSERT_LT(bytes_needed_to_decode_size, data.size());

  const char* source = data.data();
  scoped_refptr<SharedBuffer> partial_data = SharedBuffer::Create();
  for (size_t length = 1; length <= bytes_needed_to_decode_size; length++) {
    partial_data->Append(source++, 1u);
    decoder->SetData(partial_data.get(), false);

    if (length < bytes_needed_to_decode_size) {
      EXPECT_FALSE(decoder->IsSizeAvailable());
      EXPECT_TRUE(decoder->Size().IsEmpty());
      EXPECT_FALSE(decoder->Failed());
    } else {
      EXPECT_TRUE(decoder->IsSizeAvailable());
      EXPECT_EQ(expected_size, decoder->Size());
    }
  }
  EXPECT_FALSE(decoder->Failed());
}

void WriteUint32(uint32_t val, png_byte* data) {
  data[0] = val >> 24;
  data[1] = val >> 16;
  data[2] = val >> 8;
  data[3] = val;
}

void TestRepetitionCount(const char* png_file, int expected_repetition_count) {
  auto decoder = CreatePNGDecoderWithPngData(png_file);
  // Decoding the frame count sets the number of repetitions as well.
  decoder->FrameCount();
  EXPECT_FALSE(decoder->Failed());
  EXPECT_EQ(expected_repetition_count, decoder->RepetitionCount());
}

struct PublicFrameInfo {
  base::TimeDelta duration;
  gfx::Rect frame_rect;
  ImageFrame::AlphaBlendSource alpha_blend;
  ImageFrame::DisposalMethod disposal_method;
};

// This is the frame data for the following PNG image:
// web_tests/images/resources/png-animated-idat-part-of-animation.png
static PublicFrameInfo g_png_animated_frame_info[] = {
    {base::Milliseconds(500),
     {gfx::Point(0, 0), gfx::Size(5, 5)},
     ImageFrame::kBlendAtopBgcolor,
     ImageFrame::kDisposeKeep},
    {base::Milliseconds(900),
     {gfx::Point(1, 1), gfx::Size(3, 1)},
     ImageFrame::kBlendAtopBgcolor,
     ImageFrame::kDisposeOverwriteBgcolor},
    {base::Milliseconds(2000),
     {gfx::Point(1, 2), gfx::Size(3, 2)},
     ImageFrame::kBlendAtopPreviousFrame,
     ImageFrame::kDisposeKeep},
    {base::Milliseconds(1500),
     {gfx::Point(1, 2), gfx::Size(3, 1)},
     ImageFrame::kBlendAtopBgcolor,
     ImageFrame::kDisposeKeep},
};

void CompareFrameWithExpectation(const PublicFrameInfo& expected,
                                 ImageDecoder* decoder,
                                 size_t index) {
  EXPECT_EQ(expected.duration, decoder->FrameDurationAtIndex(index));

  const auto* frame = decoder->DecodeFrameBufferAtIndex(index);
  ASSERT_TRUE(frame);

  EXPECT_EQ(expected.duration, frame->Duration());
  EXPECT_EQ(expected.disposal_method, frame->GetDisposalMethod());
  EXPECT_EQ(expected.frame_rect, frame->OriginalFrameRect());
  EXPECT_EQ(expected.alpha_blend, frame->GetAlphaBlendSource());
}

// This function removes |length| bytes at |offset|, and then calls FrameCount.
// It assumes the missing bytes should result in a failed decode because the
// parser jumps |length| bytes too far in the next chunk.
void TestMissingDataBreaksDecoding(const char* png_file,
                                   size_t offset,
                                   size_t length) {
  auto decoder = CreatePNGDecoder();
  Vector<char> data = ReadFile(png_file);
  ASSERT_FALSE(data.empty());

  scoped_refptr<SharedBuffer> invalid_data =
      SharedBuffer::Create(data.data(), offset);
  invalid_data->Append(data.data() + offset + length,
                       data.size() - offset - length);
  ASSERT_EQ(data.size() - length, invalid_data->size());

  decoder->SetData(invalid_data, true);
  decoder->FrameCount();
  EXPECT_TRUE(decoder->Failed());
}

// Verify that a decoder with a parse error converts to a static image.
static void ExpectStatic(ImageDecoder* decoder) {
  EXPECT_EQ(1u, decoder->FrameCount());
  EXPECT_FALSE(decoder->Failed());

  ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
  ASSERT_NE(nullptr, frame);
  EXPECT_EQ(ImageFrame::kFrameComplete, frame->GetStatus());
  EXPECT_FALSE(decoder->Failed());
  EXPECT_EQ(kAnimationNone, decoder->RepetitionCount());
}

// Decode up to the indicated fcTL offset and then provide an fcTL with the
// wrong chunk size (20 instead of 26).
void TestInvalidFctlSize(const char* png_file,
                         size_t offset_fctl,
                         size_t expected_frame_count,
                         bool should_fail) {
  Vector<char> data = ReadFile(png_file);
  ASSERT_FALSE(data.empty());

  auto decoder = CreatePNGDecoder();
  scoped_refptr<SharedBuffer> invalid_data =
      SharedBuffer::Create(data.data(), offset_fctl);

  // Test if this gives the correct frame count, before the fcTL is parsed.
  decoder->SetData(invalid_data, false);
  EXPECT_EQ(expected_frame_count, decoder->FrameCount());
  ASSERT_FALSE(decoder->Failed());

  // Append the wrong size to the data stream
  png_byte size_chunk[4];
  WriteUint32(20, size_chunk);
  invalid_data->Append(reinterpret_cast<char*>(size_chunk), 4u);

  // Skip the size in the original data, but provide a truncated fcTL,
  // which is 4B of tag, 20B of data and 4B of CRC, totalling 28B.
  invalid_data->Append(data.data() + offset_fctl + 4, 28u);
  // Append the rest of the data
  const size_t offset_post_fctl = offset_fctl + 38;
  invalid_data->Append(data.data() + offset_post_fctl,
                       data.size() - offset_post_fctl);

  decoder->SetData(invalid_data, false);
  if (should_fail) {
    EXPECT_EQ(expected_frame_count, decoder->FrameCount());
    EXPECT_EQ(true, decoder->Failed());
  } else {
    // `SkiaImageDecoderBase` doesn't report an overall failure, unless *all*
    // frames fail.  If some animated frames have an error, then other animated
    // frames may continue to work.  This is by design - see
    // https://crbug.com/371592786#comment3.
    if (!skia::IsRustyPngEnabled()) {
      ExpectStatic(decoder.get());
    }
  }
}

// Verify that the decoder can successfully decode the first frame when
// initially only half of the frame data is received, resulting in a partially
// decoded image, and then the rest of the image data is received. Verify that
// the bitmap hashes of the two stages are different. Also verify that the final
// bitmap hash is equivalent to the hash when all data is provided at once.
//
// This verifies that the decoder correctly keeps track of where it stopped
// decoding when the image was not yet fully received.
void TestProgressiveDecodingContinuesAfterFullData(
    const char* png_file,
    size_t offset_mid_first_frame) {
  Vector<char> full_data = ReadFile(png_file);
  ASSERT_FALSE(full_data.empty());

  auto decoder_upfront = CreatePNGDecoder();
  decoder_upfront->SetData(SharedBuffer::Create(full_data), true);
  EXPECT_GE(decoder_upfront->FrameCount(), 1u);
  const ImageFrame* const frame_upfront =
      decoder_upfront->DecodeFrameBufferAtIndex(0);
  ASSERT_EQ(ImageFrame::kFrameComplete, frame_upfront->GetStatus());
  const unsigned hash_upfront = HashBitmap(frame_upfront->Bitmap());

  auto decoder = CreatePNGDecoder();
  scoped_refptr<SharedBuffer> partial_data =
      SharedBuffer::Create(full_data.data(), offset_mid_first_frame);
  decoder->SetData(partial_data, false);

  EXPECT_EQ(1u, decoder->FrameCount());
  const ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
  EXPECT_EQ(frame->GetStatus(), ImageFrame::kFramePartial);
  const unsigned hash_partial = HashBitmap(frame->Bitmap());

  decoder->SetData(SharedBuffer::Create(full_data), true);
  frame = decoder->DecodeFrameBufferAtIndex(0);
  EXPECT_EQ(frame->GetStatus(), ImageFrame::kFrameComplete);
  const unsigned hash_full = HashBitmap(frame->Bitmap());

  EXPECT_FALSE(decoder->Failed());
  EXPECT_NE(hash_full, hash_partial);
  EXPECT_EQ(hash_full, hash_upfront);
}

enum class RustFeatureState { kRustEnabled, kRustDisabled };

class PNGTests : public testing::TestWithParam<RustFeatureState> {
 public:
  PNGTests() {
    switch (GetParam()) {
      case RustFeatureState::kRustEnabled:
        features_.InitAndEnableFeature(skia::kRustyPngFeature);
        break;
      case RustFeatureState::kRustDisabled:
        features_.InitAndDisableFeature(skia::kRustyPngFeature);
        break;
    }
  }

 protected:
  base::test::ScopedFeatureList features_;
};

// Animated PNG Tests

using AnimatedPNGTests = PNGTests;
TEST_P(AnimatedPNGTests, sizeTest) {
  TestSize(
      "/images/resources/"
      "png-animated-idat-part-of-animation.png",
      gfx::Size(5, 5));
  TestSize(
      "/images/resources/"
      "png-animated-idat-not-part-of-animation.png",
      gfx::Size(227, 35));
}

TEST_P(AnimatedPNGTests, repetitionCountTest) {
  TestRepetitionCount(
      "/images/resources/"
      "png-animated-idat-part-of-animation.png",
      6u);
  // This is an "animated" image with only one frame, that is, the IDAT is
  // ignored and there is one fdAT frame. so it should be considered
  // non-animated.
  TestRepetitionCount(
      "/images/resources/"
      "png-animated-idat-not-part-of-animation.png",
      kAnimationNone);
}

// Test if the decoded metadata corresponds to the defined expectations
TEST_P(AnimatedPNGTests, MetaDataTest) {
  const char* png_file =
      "/images/resources/"
      "png-animated-idat-part-of-animation.png";
  constexpr size_t kExpectedFrameCount = 4;

  auto decoder = CreatePNGDecoderWithPngData(png_file);
  ASSERT_EQ(kExpectedFrameCount, decoder->FrameCount());
  for (size_t i = 0; i < kExpectedFrameCount; i++) {
    CompareFrameWithExpectation(g_png_animated_frame_info[i], decoder.get(), i);
  }
}

TEST_P(AnimatedPNGTests, EmptyFrame) {
  const char* png_file = "/images/resources/empty-frame.png";
  auto decoder = CreatePNGDecoderWithPngData(png_file);
  // Frame 0 is empty. Ensure that decoding frame 1 (which depends on frame 0)
  // fails (rather than crashing).
  EXPECT_EQ(2u, decoder->FrameCount());
  EXPECT_FALSE(decoder->Failed());

  ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(1);
  ASSERT_NE(nullptr, frame);
  EXPECT_EQ(ImageFrame::kFrameEmpty, frame->GetStatus());

  if (skia::IsRustyPngEnabled()) {
    // `SkiaImageDecoderBase` doesn't report an overall failure, unless *all*
    // frames fail.  This is by design - see
    // https://crbug.com/371592786#comment3.
    ASSERT_FALSE(decoder->Failed());
    EXPECT_EQ(decoder->FrameCount(), 2u);
  } else {
    ASSERT_TRUE(decoder->Failed());
  }
}

TEST_P(AnimatedPNGTests, ByteByByteSizeAvailable) {
  TestSizeByteByByte(
      "/images/resources/"
      "png-animated-idat-part-of-animation.png",
      141u, gfx::Size(5, 5));
  TestSizeByteByByte(
      "/images/resources/"
      "png-animated-idat-not-part-of-animation.png",
      79u, gfx::Size(227, 35));
}

TEST_P(AnimatedPNGTests, ByteByByteMetaData) {
  const char* png_file =
      "/images/resources/"
      "png-animated-idat-part-of-animation.png";
  constexpr size_t kExpectedFrameCount = 4;

  // These are the byte offsets where each frame should have been parsed.
  // It boils down to the offset of the first fcTL / IEND after the last
  // frame data chunk, plus 8 bytes for recognition. The exception on this is
  // the first frame, which is reported when its first framedata is seen.
  size_t frame_offsets[kExpectedFrameCount] = {141, 249, 322, 430};
  if (skia::IsRustyPngEnabled()) {
    // The original offsets correspond to 8 bytes after the corresponding
    // `fcTL` and `fdAT` chunk.  `SkPngRustCodec` can discover and report
    // frame metadata earlier - as soon as the `fdAT` chunk is recognized.
    frame_offsets[1] = 218;
    frame_offsets[2] = 287;
    frame_offsets[3] = 360;
  }

  auto decoder = CreatePNGDecoder();
  Vector<char> data = ReadFile(png_file);
  ASSERT_FALSE(data.empty());
  size_t frames_parsed = 0;

  const char* source = data.data();
  scoped_refptr<SharedBuffer> partial_data = SharedBuffer::Create();
  for (size_t length = 1; length <= frame_offsets[kExpectedFrameCount - 1];
       length++) {
    partial_data->Append(source++, 1u);
    decoder->SetData(partial_data.get(), false);
    EXPECT_FALSE(decoder->Failed());
    if (length < frame_offsets[frames_parsed]) {
      EXPECT_EQ(frames_parsed, decoder->FrameCount());
    } else {
      if (skia::IsRustyPngEnabled() && frames_parsed > 0) {
        // `SkPngRustCodec` cannot discover new frames when in the middle of an
        // incremental decode (see http://review.skia.org/913917).  To make
        // progress, we need to finish the previous decode.
        EXPECT_NE(nullptr,
                  decoder->DecodeFrameBufferAtIndex(frames_parsed - 1));
      }

      ASSERT_EQ(frames_parsed + 1, decoder->FrameCount());
      CompareFrameWithExpectation(g_png_animated_frame_info[frames_parsed],
                                  decoder.get(), frames_parsed);
      frames_parsed++;
    }
  }
  EXPECT_EQ(kExpectedFrameCount, decoder->FrameCount());
  EXPECT_FALSE(decoder->Failed());
}

TEST_P(AnimatedPNGTests, TestRandomFrameDecode) {
  TestRandomFrameDecode(&CreatePNGDecoder,
                        "/images/resources/"
                        "png-animated-idat-part-of-animation.png",
                        2u);
}

TEST_P(AnimatedPNGTests, TestDecodeAfterReallocation) {
  TestDecodeAfterReallocatingData(&CreatePNGDecoder,
                                  "/images/resources/"
                                  "png-animated-idat-part-of-animation.png");
}

TEST_P(AnimatedPNGTests, ProgressiveDecode) {
  TestProgressiveDecoding(&CreatePNGDecoder,
                          "/images/resources/"
                          "png-animated-idat-part-of-animation.png",
                          13u);
}

TEST_P(AnimatedPNGTests, ParseAndDecodeByteByByte) {
  TestByteByByteDecode(&CreatePNGDecoder,
                       "/images/resources/"
                       "png-animated-idat-part-of-animation.png",
                       4u, 6u);
}

TEST_P(AnimatedPNGTests, FailureDuringParsing) {
  // Test the first fcTL in the stream. Because no frame data has been set at
  // this point, the expected frame count is zero. 95 bytes is just before the
  // first fcTL chunk, at which the first frame is detected. This is before the
  // IDAT, so it should be treated as a static image.
  TestInvalidFctlSize(
      "/images/resources/"
      "png-animated-idat-part-of-animation.png",
      95u, 0u, false);

  // Test for the third fcTL in the stream. This should see 1 frame before the
  // fcTL, and then fail when parsing it.
  size_t expected_frame_count = 1u;
  bool should_fail = true;
  if (skia::IsRustyPngEnabled()) {
    // `SkiaImageDecoderBase` doesn't report an overall failure, unless *all*
    // frames fail.  If some animated frames have an error, then other animated
    // frames may continue to work.  This is by design - see
    // https://crbug.com/371592786#comment3.
    expected_frame_count = 2u;
    should_fail = false;
  }
  TestInvalidFctlSize(
      "/images/resources/"
      "png-animated-idat-part-of-animation.png",
      241u, expected_frame_count, should_fail);
}

TEST_P(AnimatedPNGTests, ActlErrors) {
  const char* png_file =
      "/images/resources/"
      "png-animated-idat-part-of-animation.png";
  Vector<char> data = ReadFile(png_file);
  ASSERT_FALSE(data.empty());

  const size_t kOffsetActl = 33u;
  const size_t kAcTLSize = 20u;
  {
    // Remove the acTL chunk from the stream. This results in a static image.
    scoped_refptr<SharedBuffer> no_actl_data =
        SharedBuffer::Create(data.data(), kOffsetActl);
    no_actl_data->Append(data.data() + kOffsetActl + kAcTLSize,
                         data.size() - kOffsetActl - kAcTLSize);

    auto decoder = CreatePNGDecoder();
    decoder->SetData(no_actl_data, true);
    EXPECT_EQ(1u, decoder->FrameCount());
    EXPECT_FALSE(decoder->Failed());
    EXPECT_EQ(kAnimationNone, decoder->RepetitionCount());
  }

  // Store the acTL for more tests.
  char ac_tl[kAcTLSize];
  memcpy(ac_tl, data.data() + kOffsetActl, kAcTLSize);

  // Insert an extra acTL at a couple of different offsets.
  // Prior to the IDAT, this should result in a static image. After, this
  // should fail.
  struct {
    size_t offset;
    bool should_fail;
  } kGRecs[] = {{8u, false},
                {kOffsetActl, false},
                {133u, false},
                {172u, true},
                {422u, true}};
  if (skia::IsRustyPngEnabled()) {
    // https://www.w3.org/TR/2003/REC-PNG-20031110/#5ChunkOrdering says that the
    // IHDR chunk "shall be first". Rust `png` crate treats this situation as an
    // error in accordance with the spec.
    kGRecs[0].should_fail = true;

    // `SkiaImageDecoderBase` doesn't report an overall failure, unless *all*
    // frames fail.  This is by design - see
    // https://crbug.com/371592786#comment3.
    kGRecs[3].should_fail = false;
    kGRecs[4].should_fail = false;
  }
  for (const auto& rec : kGRecs) {
    const size_t offset = rec.offset;
    scoped_refptr<SharedBuffer> extra_actl_data =
        SharedBuffer::Create(data.data(), offset);
    extra_actl_data->Append(ac_tl, kAcTLSize);
    extra_actl_data->Append(data.data() + offset, data.size() - offset);
    auto decoder = CreatePNGDecoder();
    decoder->SetData(extra_actl_data, true);

    // `blink::PNGImageDecoder` falls back to the static image upon encountering
    // APNG-specific issues (as suggested by the APNG spec).
    // `blink::SkiaImageDecoderBase` in this situation animates the successful
    // frames, and ignore the failed frames (this is by design - see
    // https://crbug.com/371592786#comment3).
    wtf_size_t frame_count = decoder->FrameCount();
    if (skia::IsRustyPngEnabled()) {
      EXPECT_LE(0u, frame_count);
      EXPECT_LE(frame_count, 4u);
    } else {
      EXPECT_EQ(rec.should_fail ? 0u : 1u, decoder->FrameCount());
    }
    EXPECT_EQ(rec.should_fail, decoder->Failed());
  }

  // An acTL after IDAT is ignored.
  png_file =
      "/images/resources/"
      "cHRM_color_spin.png";
  {
    Vector<char> data2 = ReadFile(png_file);
    ASSERT_FALSE(data2.empty());
    const size_t kPostIDATOffset = 30971u;
    for (size_t times = 0; times < 2; times++) {
      scoped_refptr<SharedBuffer> extra_actl_data =
          SharedBuffer::Create(data2.data(), kPostIDATOffset);
      for (size_t i = 0; i < times; i++) {
        extra_actl_data->Append(ac_tl, kAcTLSize);
      }
      extra_actl_data->Append(data2.data() + kPostIDATOffset,
                              data2.size() - kPostIDATOffset);

      auto decoder = CreatePNGDecoder();
      decoder->SetData(extra_actl_data, true);
      EXPECT_EQ(1u, decoder->FrameCount());
      EXPECT_FALSE(decoder->Failed());
      EXPECT_EQ(kAnimationNone, decoder->RepetitionCount());
      EXPECT_NE(nullptr, decoder->DecodeFrameBufferAtIndex(0));
      EXPECT_FALSE(decoder->Failed());
    }
  }
}

TEST_P(AnimatedPNGTests, fdatBeforeIdat) {
  const char* png_file =
      "/images/resources/"
      "png-animated-idat-not-part-of-animation.png";
  Vector<char> data = ReadFile(png_file);
  ASSERT_FALSE(data.empty());

  // Insert fcTL and fdAT prior to the IDAT
  const size_t kIdatOffset = 71u;
  scoped_refptr<SharedBuffer> modified_data_buffer =
      SharedBuffer::Create(data.data(), kIdatOffset);
  // Copy fcTL and fdAT
  const size_t kFctlPlusFdatSize = 38u + 1566u;
  modified_data_buffer->Append(data.data() + 2519u, kFctlPlusFdatSize);
  // Copy IDAT
  modified_data_buffer->Append(data.data() + kIdatOffset, 2448u);
  // Copy the remaining
  modified_data_buffer->Append(data.data() + 4123u, 39u + 12u);
  // Data has just been rearranged.
  ASSERT_EQ(data.size(), modified_data_buffer->size());

  {
    // This broken APNG will be treated as a static png.
    auto decoder = CreatePNGDecoder();
    decoder->SetData(modified_data_buffer.get(), true);
    ExpectStatic(decoder.get());
  }

  Vector<char> modified_data = modified_data_buffer->CopyAs<Vector<char>>();

  {
    // Remove the acTL from the modified image. It now has fdAT before
    // IDAT, but no acTL, so fdAT should be ignored.
    const size_t kOffsetActl = 33u;
    const size_t kAcTLSize = 20u;
    scoped_refptr<SharedBuffer> modified_data_buffer2 =
        SharedBuffer::Create(modified_data.data(), kOffsetActl);
    modified_data_buffer2->Append(
        modified_data.data() + kOffsetActl + kAcTLSize,
        modified_data.size() - kOffsetActl - kAcTLSize);
    auto decoder = CreatePNGDecoder();
    decoder->SetData(modified_data_buffer2.get(), true);
    ExpectStatic(decoder.get());

    Vector<char> modified_data2 = modified_data_buffer2->CopyAs<Vector<char>>();
    // Likewise, if an acTL follows the fdAT, it is ignored.
    const size_t kInsertionOffset = kIdatOffset + kFctlPlusFdatSize - kAcTLSize;
    scoped_refptr<SharedBuffer> modified_data3 =
        SharedBuffer::Create(modified_data2.data(), kInsertionOffset);
    modified_data3->Append(data.data() + kOffsetActl, kAcTLSize);
    modified_data3->Append(modified_data2.data() + kInsertionOffset,
                           modified_data2.size() - kInsertionOffset);
    decoder = CreatePNGDecoder();
    decoder->SetData(modified_data3.get(), true);
    ExpectStatic(decoder.get());
  }
}

TEST_P(AnimatedPNGTests, FrameOverflowX) {
  const char* png_file =
      "/images/resources/"
      "png-animated-idat-part-of-animation.png";
  Vector<char> data = ReadFile(png_file);
  ASSERT_FALSE(data.empty());

  // Change the x_offset for frame 1
  const size_t kFctlOffset = 172u;
  scoped_refptr<SharedBuffer> modified_data =
      SharedBuffer::Create(data.data(), kFctlOffset);
  const size_t kFctlSize = 38u;
  png_byte fctl[kFctlSize];
  memcpy(fctl, data.data() + kFctlOffset, kFctlSize);

  // Set the x_offset to a value that will overflow
  WriteUint32(4294967295, fctl + 20);
  // Correct the crc
  WriteUint32(689600712, fctl + 34);
  modified_data->Append((const char*)fctl, kFctlSize);
  const size_t kAfterFctl = kFctlOffset + kFctlSize;
  modified_data->Append(data.data() + kAfterFctl, data.size() - kAfterFctl);

  auto decoder = CreatePNGDecoder();
  decoder->SetData(modified_data.get(), true);
  for (size_t i = 0; i < decoder->FrameCount(); i++) {
    decoder->DecodeFrameBufferAtIndex(i);
  }

  if (skia::IsRustyPngEnabled()) {
    // `SkiaImageDecoderBase` doesn't report an overall failure, unless *all*
    // frames fail.  This is by design - see
    // https://crbug.com/371592786#comment3.
    ASSERT_FALSE(decoder->Failed());
    EXPECT_EQ(decoder->FrameCount(), 1u);
  } else {
    ASSERT_TRUE(decoder->Failed());
  }
}

// This test is exactly the same as above, except it changes y_offset.
TEST_P(AnimatedPNGTests, FrameOverflowY) {
  const char* png_file =
      "/images/resources/"
      "png-animated-idat-part-of-animation.png";
  Vector<char> data = ReadFile(png_file);
  ASSERT_FALSE(data.empty());

  // Change the y_offset for frame 1
  const size_t kFctlOffset = 172u;
  scoped_refptr<SharedBuffer> modified_data =
      SharedBuffer::Create(data.data(), kFctlOffset);
  const size_t kFctlSize = 38u;
  png_byte fctl[kFctlSize];
  memcpy(fctl, data.data() + kFctlOffset, kFctlSize);

  // Set the y_offset to a value that will overflow
  WriteUint32(4294967295, fctl + 24);
  // Correct the crc
  WriteUint32(2094185741, fctl + 34);
  modified_data->Append((const char*)fctl, kFctlSize);
  const size_t kAfterFctl = kFctlOffset + kFctlSize;
  modified_data->Append(data.data() + kAfterFctl, data.size() - kAfterFctl);

  auto decoder = CreatePNGDecoder();
  decoder->SetData(modified_data.get(), true);
  for (size_t i = 0; i < decoder->FrameCount(); i++) {
    decoder->DecodeFrameBufferAtIndex(i);
  }

  if (skia::IsRustyPngEnabled()) {
    // `SkiaImageDecoderBase` doesn't report an overall failure, unless *all*
    // frames fail.  This is by design - see
    // https://crbug.com/371592786#comment3.
    ASSERT_FALSE(decoder->Failed());
    EXPECT_EQ(decoder->FrameCount(), 1u);
  } else {
    ASSERT_TRUE(decoder->Failed());
  }
}

TEST_P(AnimatedPNGTests, IdatSizeMismatch) {
  // The default image must fill the image
  const char* png_file =
      "/images/resources/"
      "png-animated-idat-part-of-animation.png";
  Vector<char> data = ReadFile(png_file);
  ASSERT_FALSE(data.empty());

  const size_t kFctlOffset = 95u;
  scoped_refptr<SharedBuffer> modified_data =
      SharedBuffer::Create(data.data(), kFctlOffset);
  const size_t kFctlSize = 38u;
  png_byte fctl[kFctlSize];
  memcpy(fctl, data.data() + kFctlOffset, kFctlSize);
  // Set the height to a smaller value, so it does not fill the image.
  WriteUint32(3, fctl + 16);
  // Correct the crc
  WriteUint32(3210324191, fctl + 34);
  modified_data->Append((const char*)fctl, kFctlSize);
  const size_t kAfterFctl = kFctlOffset + kFctlSize;
  modified_data->Append(data.data() + kAfterFctl, data.size() - kAfterFctl);

  auto decoder = CreatePNGDecoder();
  decoder->SetData(modified_data.get(), true);

  if (skia::IsRustyPngEnabled()) {
    // `SkiaImageDecoderBase` doesn't report an overall failure, unless *all*
    // frames fail.  If some animated frames have an error, then other animated
    // frames may continue to work.  This is by design - see
    // https://crbug.com/371592786#comment3.
    EXPECT_FALSE(decoder->Failed());
    EXPECT_EQ(decoder->FrameCount(), 4u);
  } else {
    ExpectStatic(decoder.get());
  }
}

TEST_P(AnimatedPNGTests, EmptyFdatFails) {
  const char* png_file =
      "/images/resources/"
      "png-animated-idat-part-of-animation.png";
  Vector<char> data = ReadFile(png_file);
  ASSERT_FALSE(data.empty());

  // Modify the third fdAT to be empty.
  constexpr size_t kOffsetThirdFdat = 352;
  scoped_refptr<SharedBuffer> modified_data =
      SharedBuffer::Create(data.data(), kOffsetThirdFdat);
  png_byte four_bytes[4u];
  WriteUint32(0, four_bytes);
  modified_data->Append(reinterpret_cast<char*>(four_bytes), 4u);

  // fdAT tag
  modified_data->Append(data.data() + kOffsetThirdFdat + 4u, 4u);

  // crc computed from modified fdAT chunk
  WriteUint32(4122214294, four_bytes);
  modified_data->Append(reinterpret_cast<char*>(four_bytes), 4u);

  // IEND
  constexpr size_t kIENDOffset = 422u;
  modified_data->Append(data.data() + kIENDOffset, 12u);

  auto decoder = CreatePNGDecoder();
  decoder->SetData(std::move(modified_data), true);
  for (size_t i = 0; i < decoder->FrameCount(); i++) {
    decoder->DecodeFrameBufferAtIndex(i);
  }

  if (skia::IsRustyPngEnabled()) {
    // `SkiaImageDecoderBase` doesn't report an overall failure, unless *all*
    // frames fail.  This is by design - see
    // https://crbug.com/371592786#comment3.
    ASSERT_FALSE(decoder->Failed());
    EXPECT_EQ(decoder->FrameCount(), 3u);
  } else {
    ASSERT_TRUE(decoder->Failed());
  }
}

// Originally, the third frame has an offset of (1,2) and a size of (3,2). By
// changing the offset to (4,4), the frame rect is no longer within the image
// size of 5x5. This results in a failure.
TEST_P(AnimatedPNGTests, VerifyFrameOutsideImageSizeFails) {
  const char* png_file =
      "/images/resources/"
      "png-animated-idat-part-of-animation.png";
  Vector<char> data = ReadFile(png_file);
  auto decoder = CreatePNGDecoder();
  ASSERT_FALSE(data.empty());

  const size_t kOffsetThirdFctl = 241;
  scoped_refptr<SharedBuffer> modified_data =
      SharedBuffer::Create(data.data(), kOffsetThirdFctl);
  const size_t kFctlSize = 38u;
  png_byte fctl[kFctlSize];
  memcpy(fctl, data.data() + kOffsetThirdFctl, kFctlSize);
  // Modify offset and crc.
  WriteUint32(4, fctl + 20u);
  WriteUint32(4, fctl + 24u);
  WriteUint32(3700322018, fctl + 34u);

  modified_data->Append(const_cast<const char*>(reinterpret_cast<char*>(fctl)),
                        kFctlSize);
  modified_data->Append(data.data() + kOffsetThirdFctl + kFctlSize,
                        data.size() - kOffsetThirdFctl - kFctlSize);

  decoder->SetData(modified_data, true);

  gfx::Size expected_size(5, 5);
  EXPECT_TRUE(decoder->IsSizeAvailable());
  EXPECT_EQ(expected_size, decoder->Size());

  if (skia::IsRustyPngEnabled()) {
    // `SkiaImageDecoderBase` doesn't report an overall failure, unless *all*
    // frames fail.  This is by design - see
    // https://crbug.com/371592786#comment3.
    EXPECT_EQ(decoder->FrameCount(), 2u);
    ASSERT_FALSE(decoder->Failed());
  } else {
    EXPECT_EQ(decoder->FrameCount(), 0u);
    ASSERT_TRUE(decoder->Failed());
  }
}

TEST_P(AnimatedPNGTests, ProgressiveDecodingContinuesAfterFullData) {
  // 160u is a randomly chosen offset in the IDAT chunk of the first frame.
  TestProgressiveDecodingContinuesAfterFullData(
      "/images/resources/"
      "png-animated-idat-part-of-animation.png",
      160u);
}

TEST_P(AnimatedPNGTests, RandomDecodeAfterClearFrameBufferCache) {
  TestRandomDecodeAfterClearFrameBufferCache(
      &CreatePNGDecoder,
      "/images/resources/"
      "png-animated-idat-part-of-animation.png",
      2u);
}

TEST_P(AnimatedPNGTests, VerifyAlphaBlending) {
  TestAlphaBlending(&CreatePNGDecoder,
                    "/images/resources/"
                    "png-animated-idat-part
```