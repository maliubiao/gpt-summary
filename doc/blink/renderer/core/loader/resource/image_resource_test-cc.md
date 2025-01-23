Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The user wants to understand the functionality of the `image_resource_test.cc` file in the Chromium Blink engine. They are specifically interested in its relationship to JavaScript, HTML, and CSS, examples, logical reasoning with input/output, common errors, debugging steps, and a summary of its functionality. The prompt explicitly states it's part 1 of 2.

2. **Identify the File's Purpose:** The file name `image_resource_test.cc` strongly suggests it contains unit tests for the `ImageResource` class. This is the central piece of information.

3. **Scan the Includes:**  The included header files provide valuable clues about the functionality being tested. I'll look for key classes and concepts:
    * `image_resource.h`: Confirms the testing target.
    * `testing/gmock/include/gmock/gmock.h`, `testing/gtest/include/gtest/gtest.h`:  Indicates it's using Google Test and Google Mock for unit testing.
    * `platform/web_url.h`, `platform/web_url_response.h`:  Deals with URLs and HTTP responses.
    * `core/frame/local_dom_window.h`, `core/frame/local_frame.h`: Suggests integration with the DOM and frame structure.
    * `core/loader/resource/*`:  Points to the resource loading mechanism.
    * `platform/graphics/*`: Indicates interaction with image decoding and representation.
    * `platform/loader/fetch/*`:  Related to network fetching and caching.
    * The presence of `Mock*` classes (e.g., `MockImageResourceObserver`, `MockFetchContext`) confirms it's using mocking for testing dependencies.

4. **Analyze the Test Cases:** The body of the code consists of `TEST_F` blocks. Each block represents a specific scenario being tested. I will analyze a few key test cases to understand the file's scope:
    * `DimensionsDecodableFromPartialTestImage`: Tests if image dimensions can be extracted from partial data.
    * `MultipartImage`, `BitmapMultipartImage`: Tests handling of multipart image responses.
    * `CancelOnRemoveObserver`, `CancelWithImageAndFinishObserver`: Tests cancellation scenarios.
    * `DecodedDataRemainsWhileHasClients`: Tests resource pruning behavior.
    * `UpdateBitmapImages`, `SVGImage`, `SVGImageWithSubresource`: Tests handling of different image types.
    * `SuccessfulRevalidationJpeg`, `SuccessfulRevalidationSvg`, `FailedRevalidationJpegToJpeg`, `FailedRevalidationJpegToSvg`: Tests cache revalidation scenarios.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):** Based on the tested scenarios, I can infer the relationship with web technologies:
    * **HTML:**  Images are loaded via the `<img>` tag, `<picture>` element, or as background images in CSS. The tests implicitly cover the loading and rendering of these images. The multipart tests are relevant to less common but possible scenarios.
    * **CSS:** CSS properties like `background-image` load images. The tests ensure that the image loading process functions correctly regardless of how the image is initiated.
    * **JavaScript:**  JavaScript can dynamically load images (e.g., using `new Image()`, `fetch()`). The tests on resource loading, caching, and error handling are relevant to how JavaScript interacts with image resources.

6. **Consider Logical Reasoning (Input/Output):** For specific test cases, I can define potential inputs and expected outputs. For example:
    * **Input:** A partial JPEG image data.
    * **Expected Output:** The decoder should be able to extract the dimensions.
    * **Input:** A multipart response containing image data.
    * **Expected Output:** The `ImageResource` should handle the multipart structure and correctly decode the image parts.

7. **Identify Common Errors:** Based on the test scenarios, I can identify potential user or programming errors:
    * Incorrect image URLs.
    * Issues with server-side configuration for multipart responses.
    * Problems with caching mechanisms (e.g., incorrect cache headers).
    * Race conditions or improper handling of asynchronous loading.

8. **Outline Debugging Steps:** I can describe how a developer might reach this part of the code while debugging:
    * Investigating issues with image loading failures.
    * Analyzing performance problems related to image resources.
    * Debugging caching behavior for images.
    * Tracking down crashes or unexpected behavior related to image rendering.

9. **Summarize Functionality (Part 1):** Based on the analysis, I can summarize the main functions of the test file, focusing on the core purpose of testing the `ImageResource` class and its interactions with different aspects of the Blink rendering engine.

10. **Structure the Answer:** I will organize the answer into the requested sections (Functionality, Relationship to JS/HTML/CSS, Logical Reasoning, Common Errors, Debugging, Summary). I will use clear and concise language, providing examples where appropriate. I will also explicitly state that this is based on the provided code snippet and may not cover the entire file.

By following these steps, I can create a comprehensive and accurate answer that addresses all aspects of the user's request, even before seeing part 2. This methodical approach ensures that I cover the key aspects of the code and its context within the larger Chromium project.
```cpp
/*
 * Copyright (c) 2013, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/loader/resource/image_resource.h"

#include <memory>
#include <string_view>

#include "base/task/single_thread_task_runner.h"
#include "base/test/metrics/histogram_tester.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/loader/referrer_utils.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/loader/resource/mock_image_resource_observer.h"
#include "third_party/blink/renderer/core/svg/graphics/svg_image.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/testing/scoped_mock_overlay_scrollbars.h"
#include "third_party/blink/renderer/platform/exported/wrapped_resource_response.h"
#include "third_party/blink/renderer/platform/graphics/bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/image.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/instrumentation/instance_counters.h"
#include "third_party/blink/renderer/platform/loader/fetch/console_logger.h"
#party/blink/renderer/platform/loader/fetch/fetch_initiator_info.h"
#third_party/blink/renderer/platform/loader/fetch/fetch_initiator_type_names.h"
#third_party/blink/renderer/platform/loader/fetch/fetch_parameters.h"
#third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#third_party/blink/renderer/platform/loader/fetch/resource_finish_observer.h"
#third_party/blink/renderer/platform/loader/fetch/resource_loader.h"
#third_party/blink/renderer/platform/loader/fetch/unique_identifier.h"
#third_party/blink/renderer/platform/loader/testing/mock_fetch_context.h"
#third_party/blink/renderer/platform/loader/testing/mock_resource_client.h"
#third_party/blink/renderer/platform/loader/testing/test_loader_factory.h"
#third_party/blink/renderer/platform/loader/testing/test_resource_fetcher_properties.h"
#third_party/blink/renderer/platform/network/http_names.h"
#third_party/blink/renderer/platform/scheduler/test/fake_frame_scheduler.h"
#third_party/blink/renderer/platform/scheduler/test/fake_task_runner.h"
#third_party/blink/renderer/platform/testing/mock_context_lifecycle_notifier.h"
#third_party/blink/renderer/platform/testing/scoped_mocked_url.h"
#third_party/blink/renderer/platform/testing/task_environment.h"
#third_party/blink/renderer/platform/testing/testing_platform_support_with_mock_scheduler.h"
#third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#third_party/blink/renderer/platform/wtf/shared_buffer.h"
#third_party/blink/renderer/platform/wtf/text/base64.h"

namespace blink {

using test::ScopedMockedURLLoad;

namespace {

// An image of size 1x1.
constexpr unsigned char kJpegImage[] = {
    0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01,
    0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x13,
    0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x20, 0x77, 0x69, 0x74, 0x68,
    0x20, 0x47, 0x49, 0x4d, 0x50, 0xff, 0xdb, 0x00, 0x43, 0x00, 0x05, 0x03,
    0x04, 0x04, 0x04, 0x03, 0x05, 0x04, 0x04, 0x04, 0x05, 0x05, 0x05, 0x06,
    0x07, 0x0c, 0x08, 0x07, 0x07, 0x07, 0x07, 0x0f, 0x0b, 0x0b, 0x09, 0x0c,
    0x11, 0x0f, 0x12, 0x12, 0x11, 0x0f, 0x11, 0x11, 0x13, 0x16, 0x1c, 0x17,
    0x13, 0x14, 0x1a, 0x15, 0x11, 0x11, 0x18, 0x21, 0x18, 0x1a, 0x1d, 0x1d,
    0x1f, 0x1f, 0x1f, 0x13, 0x17, 0x22, 0x24, 0x22, 0x1e, 0x24, 0x1c, 0x1e,
    0x1f, 0x1e, 0xff, 0xdb, 0x00, 0x43, 0x01, 0x05, 0x05, 0x05, 0x07, 0x06,
    0x07, 0x0e, 0x08, 0x08, 0x0e, 0x1e, 0x14, 0x11, 0x14, 0x1e, 0x1e, 0x1e,
    0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e,
    0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e,
    0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e,
    0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0xff,
    0xc0, 0x00, 0x11, 0x08, 0x00, 0x01, 0x00, 0x01, 0x03, 0x01, 0x22, 0x00,
    0x02, 0x11, 0x01, 0x03, 0x11, 0x01, 0xff, 0xc4, 0x00, 0x15, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0xff, 0xc4, 0x00, 0x14, 0x10, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xff, 0xc4, 0x00, 0x14, 0x01, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xff, 0xc4, 0x00, 0x14, 0x11, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
    0xda, 0x00, 0x0c, 0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3f,
    0x00, 0xb2, 0xc0, 0x07, 0xff, 0xd9};

constexpr int kJpegImageWidth = 1;
constexpr int kJpegImageHeight = 1;

constexpr size_t kJpegImageSubrangeWithDimensionsLength =
    sizeof(kJpegImage) - 1;
constexpr size_t kJpegImageSubrangeWithoutDimensionsLength = 3;

class ImageResourceTest : public testing::Test,
                          private ScopedMockOverlayScrollbars {
  void TearDown() override {
    // Trigger a GC so MockFinishObserver gets destroyed and EXPECT_CALL gets
    // checked before the test ends.
    ThreadState::Current()->CollectAllGarbageForTesting(
        ThreadState::StackState::kNoHeapPointers);
  }

 private:
  test::TaskEnvironment task_environment_;
};

// Ensure that the image decoder can determine the dimensions of kJpegImage from
// just the first kJpegImageSubrangeWithDimensionsLength bytes. If this test
// fails, then the test data here probably needs to be updated.
TEST_F(ImageResourceTest, DimensionsDecodableFromPartialTestImage) {
  scoped_refptr<Image> image = BitmapImage::Create();
  EXPECT_EQ(
      Image::kSizeAvailable,
      image->SetData(SharedBuffer::Create(
                         kJpegImage, kJpegImageSubrangeWithDimensionsLength),
                     true));
  EXPECT_TRUE(IsA<BitmapImage>(image.get()));
  EXPECT_EQ(1, image->width());
  EXPECT_EQ(1, image->height());
}

// An image of size 50x50.
constexpr unsigned char kJpegImage2[] = {
    0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01,
    0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00, 0xff, 0xdb, 0x00, 0x43,
    0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xdb, 0x00, 0x43, 0x01, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xc0, 0x00, 0x11, 0x08, 0x00, 0x32, 0x00, 0x32, 0x03,
    0x01, 0x22, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01, 0xff, 0xc4, 0x00,
    0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xc4, 0x00, 0x14, 0x10,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xc4, 0x00, 0x15, 0x01, 0x01, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02, 0xff, 0xc4, 0x00, 0x14, 0x11, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xff, 0xda, 0x00, 0x0c, 0x03, 0x01, 0x00, 0x02, 0x11, 0x03,
    0x11, 0x00, 0x3f, 0x00, 0x00, 0x94, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03, 0xff, 0xd9};

constexpr std::string_view kSvgImage =
    "<svg width=\"200\" height=\"200\" xmlns=\"http://www.w3.org/2000/svg\" "
    "xmlns:xlink=\"http://www.w3.org/1999/xlink\">"
    "<rect x=\"0\" y=\"0\" width=\"100px\" height=\"100px\" fill=\"red\"/>"
    "</svg>";

constexpr std::string_view kSvgImage2 =
    "<svg width=\"300\" height=\"300\" xmlns=\"http://www.w3.org/2000/svg\" "
    "xmlns:xlink=\"http://www.w3.org/1999/xlink\">"
    "<rect x=\"0\" y=\"0\" width=\"200px\" height=\"200px\" fill=\"green\"/>"
    "</svg>";

constexpr char kTestURL[] = "http://www.test.com/cancelTest.html";

String GetTestFilePath() {
  return test::CoreTestDataPath("cancelTest.html");
}

constexpr std::string_view kSvgImageWithSubresource =
    "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"198\" height=\"100\">"
    "<style>"
    "  <![CDATA[@font-face{font-family:\"test\"; "
    "    src:url('data:font/ttf;base64,invalidFontData');}]]>"
    "</style>"
    "<text x=\"50\" y=\"50\" font-family=\"test\" font-size=\"16\">Fox</text>"
    "</svg>";

void ReceiveResponse(ImageResource* image_resource,
                     const KURL& url,
                     const char* mime_type,
                     base::span<const char> data) {
  ResourceResponse resource_response(url);
  resource_response.SetMimeType(AtomicString(mime_type));
  resource_response.SetHttpStatusCode(200);
  image_resource->NotifyStartLoad();
  image_resource->ResponseReceived(resource_response);
  image_resource->AppendData(data);
  image_resource->FinishForTest();
}

AtomicString BuildContentRange(size_t range_length, size_t total_length) {
  return AtomicString(String("bytes 0-" + String::Number(range_length - 1) +
                             "/" + String::Number(total_length)));
}

ResourceFetcher* CreateFetcher() {
  auto* properties = MakeGarbageCollected<TestResourceFetcherProperties>();
  return MakeGarbageCollected<ResourceFetcher>(ResourceFetcherInit(
      properties->MakeDetachable(), MakeGarbageCollected<MockFetchContext>(),
      base::MakeRefCounted<scheduler::FakeTaskRunner>(),
      base::MakeRefCounted<scheduler::FakeTaskRunner>(),
      MakeGarbageCollected<TestLoaderFactory>(),
      MakeGarbageCollected<MockContextLifecycleNotifier>(),
      nullptr /* back_forward_cache_loader_helper */));
}

TEST_F(ImageResourceTest, MultipartImage) {
  ResourceFetcher* fetcher = CreateFetcher();
  KURL test_url(kTestURL);
  ScopedMockedURLLoad scoped_mocked_url_load(test_url, GetTestFilePath());

  // Emulate starting a real load, but don't expect any "real"
  // URLLoaderClient callbacks.
  ImageResource* image_resource = ImageResource::CreateForTest(test_url);
  fetcher->StartLoad(image_resource);

  auto* observer = MakeGarbageCollected<MockImageResourceObserver>(
      image_resource->GetContent());
  EXPECT_EQ(ResourceStatus::kPending, image_resource->GetStatus());

  // Send the multipart response. No image or data buffer is created. Note that
  // the response must be routed through ResourceLoader to ensure the load is
  // flagged as multipart.
  ResourceResponse multipart_response(NullURL());
  multipart_response.SetMimeType(AtomicString("multipart/x-mixed-replace"));
  multipart_response.SetHttpHeaderField(
      http_names::kContentType,
      AtomicString("multipart/x-mixed-replace; boundary=boundary"));
  image_resource->Loader()->DidReceiveResponse(
      WrappedResourceResponse(multipart_response),
      /*body=*/mojo::ScopedDataPipeConsumerHandle(),
      /*cached_metadata=*/std::nullopt);
  EXPECT_FALSE(image_resource->ResourceBuffer());
  EXPECT_FALSE(image_resource->GetContent()->HasImage());
  EXPECT_EQ(0, observer->ImageChangedCount());
  EXPECT_FALSE(observer->ImageNotifyFinishedCalled());
  EXPECT_EQ("multipart/x-mixed-replace",
            image_resource->GetResponse().MimeType());

  const std::string_view kFirstPart =
      "--boundary\n"
      "Content-Type: image/svg+xml\n\n";
  image_resource->AppendData(kFirstPart);
  // Send the response for the first real part. No image or data buffer is
  // created.
  EXPECT_FALSE(image_resource->ResourceBuffer());
  EXPECT_FALSE(image_resource->GetContent()->HasImage());
  EXPECT_EQ(0, observer->ImageChangedCount());
  EXPECT_FALSE(observer->ImageNotifyFinishedCalled());
  EXPECT_EQ("image/svg+xml", image_resource->GetResponse().MimeType());

  const std::string_view kSecondPart =
      "<svg xmlns='http://www.w3.org/2000/svg' width='1' height='1'><rect "
      "width='1' height='1' fill='green'/></svg>\n";
  // The first bytes arrive. The data buffer is created, but no image is
  // created.
  image_resource->AppendData(kSecondPart);
  EXPECT_TRUE(image_resource->ResourceBuffer());
  EXPECT_FALSE(image_resource->GetContent()->HasImage());
  EXPECT_EQ(0, observer->ImageChangedCount());
  EXPECT_FALSE(observer->ImageNotifyFinishedCalled());

  // Add an observer to check an assertion error doesn't happen
  // (crbug.com/630983).
  auto* observer2 = MakeGarbageCollected<MockImageResourceObserver>(
      image_resource->GetContent());
  EXPECT_EQ(0, observer2->ImageChangedCount());
  EXPECT_FALSE(observer2->ImageNotifyFinishedCalled());

  const std::string_view kThirdPart = "--boundary";
  image_resource->AppendData(kThirdPart);
  ASSERT_TRUE(image_resource->ResourceBuffer());
  EXPECT_EQ(kSecondPart.size() - 1, image_resource->ResourceBuffer()->size());

  // This part finishes. The image is created, callbacks are sent, and the data
  // buffer is cleared.
  image_resource->Loader()->DidFinishLoading(base::TimeTicks(), 0, 0, 0);
  EXPECT_TRUE(image_resource->ResourceBuffer());
  EXPECT_FALSE(image_resource->ErrorOccurred());
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_FALSE(image_resource->GetContent()->GetImage()->IsNull());
  EXPECT_EQ(kJpegImageWidth, image_resource->GetContent()->GetImage()->width());
  EXPECT_EQ(kJpegImageHeight,
            image_resource
### 提示词
```
这是目录为blink/renderer/core/loader/resource/image_resource_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (c) 2013, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/loader/resource/image_resource.h"

#include <memory>
#include <string_view>

#include "base/task/single_thread_task_runner.h"
#include "base/test/metrics/histogram_tester.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/loader/referrer_utils.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/loader/resource/mock_image_resource_observer.h"
#include "third_party/blink/renderer/core/svg/graphics/svg_image.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/testing/scoped_mock_overlay_scrollbars.h"
#include "third_party/blink/renderer/platform/exported/wrapped_resource_response.h"
#include "third_party/blink/renderer/platform/graphics/bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/image.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/instrumentation/instance_counters.h"
#include "third_party/blink/renderer/platform/loader/fetch/console_logger.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_info.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_type_names.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_parameters.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_finish_observer.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader.h"
#include "third_party/blink/renderer/platform/loader/fetch/unique_identifier.h"
#include "third_party/blink/renderer/platform/loader/testing/mock_fetch_context.h"
#include "third_party/blink/renderer/platform/loader/testing/mock_resource_client.h"
#include "third_party/blink/renderer/platform/loader/testing/test_loader_factory.h"
#include "third_party/blink/renderer/platform/loader/testing/test_resource_fetcher_properties.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/scheduler/test/fake_frame_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/test/fake_task_runner.h"
#include "third_party/blink/renderer/platform/testing/mock_context_lifecycle_notifier.h"
#include "third_party/blink/renderer/platform/testing/scoped_mocked_url.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support_with_mock_scheduler.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"

namespace blink {

using test::ScopedMockedURLLoad;

namespace {

// An image of size 1x1.
constexpr unsigned char kJpegImage[] = {
    0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01,
    0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x13,
    0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x20, 0x77, 0x69, 0x74, 0x68,
    0x20, 0x47, 0x49, 0x4d, 0x50, 0xff, 0xdb, 0x00, 0x43, 0x00, 0x05, 0x03,
    0x04, 0x04, 0x04, 0x03, 0x05, 0x04, 0x04, 0x04, 0x05, 0x05, 0x05, 0x06,
    0x07, 0x0c, 0x08, 0x07, 0x07, 0x07, 0x07, 0x0f, 0x0b, 0x0b, 0x09, 0x0c,
    0x11, 0x0f, 0x12, 0x12, 0x11, 0x0f, 0x11, 0x11, 0x13, 0x16, 0x1c, 0x17,
    0x13, 0x14, 0x1a, 0x15, 0x11, 0x11, 0x18, 0x21, 0x18, 0x1a, 0x1d, 0x1d,
    0x1f, 0x1f, 0x1f, 0x13, 0x17, 0x22, 0x24, 0x22, 0x1e, 0x24, 0x1c, 0x1e,
    0x1f, 0x1e, 0xff, 0xdb, 0x00, 0x43, 0x01, 0x05, 0x05, 0x05, 0x07, 0x06,
    0x07, 0x0e, 0x08, 0x08, 0x0e, 0x1e, 0x14, 0x11, 0x14, 0x1e, 0x1e, 0x1e,
    0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e,
    0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e,
    0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e,
    0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0xff,
    0xc0, 0x00, 0x11, 0x08, 0x00, 0x01, 0x00, 0x01, 0x03, 0x01, 0x22, 0x00,
    0x02, 0x11, 0x01, 0x03, 0x11, 0x01, 0xff, 0xc4, 0x00, 0x15, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0xff, 0xc4, 0x00, 0x14, 0x10, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xff, 0xc4, 0x00, 0x14, 0x01, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xff, 0xc4, 0x00, 0x14, 0x11, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
    0xda, 0x00, 0x0c, 0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3f,
    0x00, 0xb2, 0xc0, 0x07, 0xff, 0xd9};

constexpr int kJpegImageWidth = 1;
constexpr int kJpegImageHeight = 1;

constexpr size_t kJpegImageSubrangeWithDimensionsLength =
    sizeof(kJpegImage) - 1;
constexpr size_t kJpegImageSubrangeWithoutDimensionsLength = 3;

class ImageResourceTest : public testing::Test,
                          private ScopedMockOverlayScrollbars {
  void TearDown() override {
    // Trigger a GC so MockFinishObserver gets destroyed and EXPECT_CALL gets
    // checked before the test ends.
    ThreadState::Current()->CollectAllGarbageForTesting(
        ThreadState::StackState::kNoHeapPointers);
  }

 private:
  test::TaskEnvironment task_environment_;
};

// Ensure that the image decoder can determine the dimensions of kJpegImage from
// just the first kJpegImageSubrangeWithDimensionsLength bytes. If this test
// fails, then the test data here probably needs to be updated.
TEST_F(ImageResourceTest, DimensionsDecodableFromPartialTestImage) {
  scoped_refptr<Image> image = BitmapImage::Create();
  EXPECT_EQ(
      Image::kSizeAvailable,
      image->SetData(SharedBuffer::Create(
                         kJpegImage, kJpegImageSubrangeWithDimensionsLength),
                     true));
  EXPECT_TRUE(IsA<BitmapImage>(image.get()));
  EXPECT_EQ(1, image->width());
  EXPECT_EQ(1, image->height());
}

// An image of size 50x50.
constexpr unsigned char kJpegImage2[] = {
    0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01,
    0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00, 0xff, 0xdb, 0x00, 0x43,
    0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xdb, 0x00, 0x43, 0x01, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xc0, 0x00, 0x11, 0x08, 0x00, 0x32, 0x00, 0x32, 0x03,
    0x01, 0x22, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01, 0xff, 0xc4, 0x00,
    0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xc4, 0x00, 0x14, 0x10,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xc4, 0x00, 0x15, 0x01, 0x01, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02, 0xff, 0xc4, 0x00, 0x14, 0x11, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xff, 0xda, 0x00, 0x0c, 0x03, 0x01, 0x00, 0x02, 0x11, 0x03,
    0x11, 0x00, 0x3f, 0x00, 0x00, 0x94, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0xff, 0xd9};

constexpr std::string_view kSvgImage =
    "<svg width=\"200\" height=\"200\" xmlns=\"http://www.w3.org/2000/svg\" "
    "xmlns:xlink=\"http://www.w3.org/1999/xlink\">"
    "<rect x=\"0\" y=\"0\" width=\"100px\" height=\"100px\" fill=\"red\"/>"
    "</svg>";

constexpr std::string_view kSvgImage2 =
    "<svg width=\"300\" height=\"300\" xmlns=\"http://www.w3.org/2000/svg\" "
    "xmlns:xlink=\"http://www.w3.org/1999/xlink\">"
    "<rect x=\"0\" y=\"0\" width=\"200px\" height=\"200px\" fill=\"green\"/>"
    "</svg>";

constexpr char kTestURL[] = "http://www.test.com/cancelTest.html";

String GetTestFilePath() {
  return test::CoreTestDataPath("cancelTest.html");
}

constexpr std::string_view kSvgImageWithSubresource =
    "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"198\" height=\"100\">"
    "<style>"
    "  <![CDATA[@font-face{font-family:\"test\"; "
    "    src:url('data:font/ttf;base64,invalidFontData');}]]>"
    "</style>"
    "<text x=\"50\" y=\"50\" font-family=\"test\" font-size=\"16\">Fox</text>"
    "</svg>";

void ReceiveResponse(ImageResource* image_resource,
                     const KURL& url,
                     const char* mime_type,
                     base::span<const char> data) {
  ResourceResponse resource_response(url);
  resource_response.SetMimeType(AtomicString(mime_type));
  resource_response.SetHttpStatusCode(200);
  image_resource->NotifyStartLoad();
  image_resource->ResponseReceived(resource_response);
  image_resource->AppendData(data);
  image_resource->FinishForTest();
}

AtomicString BuildContentRange(size_t range_length, size_t total_length) {
  return AtomicString(String("bytes 0-" + String::Number(range_length - 1) +
                             "/" + String::Number(total_length)));
}

ResourceFetcher* CreateFetcher() {
  auto* properties = MakeGarbageCollected<TestResourceFetcherProperties>();
  return MakeGarbageCollected<ResourceFetcher>(ResourceFetcherInit(
      properties->MakeDetachable(), MakeGarbageCollected<MockFetchContext>(),
      base::MakeRefCounted<scheduler::FakeTaskRunner>(),
      base::MakeRefCounted<scheduler::FakeTaskRunner>(),
      MakeGarbageCollected<TestLoaderFactory>(),
      MakeGarbageCollected<MockContextLifecycleNotifier>(),
      nullptr /* back_forward_cache_loader_helper */));
}

TEST_F(ImageResourceTest, MultipartImage) {
  ResourceFetcher* fetcher = CreateFetcher();
  KURL test_url(kTestURL);
  ScopedMockedURLLoad scoped_mocked_url_load(test_url, GetTestFilePath());

  // Emulate starting a real load, but don't expect any "real"
  // URLLoaderClient callbacks.
  ImageResource* image_resource = ImageResource::CreateForTest(test_url);
  fetcher->StartLoad(image_resource);

  auto* observer = MakeGarbageCollected<MockImageResourceObserver>(
      image_resource->GetContent());
  EXPECT_EQ(ResourceStatus::kPending, image_resource->GetStatus());

  // Send the multipart response. No image or data buffer is created. Note that
  // the response must be routed through ResourceLoader to ensure the load is
  // flagged as multipart.
  ResourceResponse multipart_response(NullURL());
  multipart_response.SetMimeType(AtomicString("multipart/x-mixed-replace"));
  multipart_response.SetHttpHeaderField(
      http_names::kContentType,
      AtomicString("multipart/x-mixed-replace; boundary=boundary"));
  image_resource->Loader()->DidReceiveResponse(
      WrappedResourceResponse(multipart_response),
      /*body=*/mojo::ScopedDataPipeConsumerHandle(),
      /*cached_metadata=*/std::nullopt);
  EXPECT_FALSE(image_resource->ResourceBuffer());
  EXPECT_FALSE(image_resource->GetContent()->HasImage());
  EXPECT_EQ(0, observer->ImageChangedCount());
  EXPECT_FALSE(observer->ImageNotifyFinishedCalled());
  EXPECT_EQ("multipart/x-mixed-replace",
            image_resource->GetResponse().MimeType());

  const std::string_view kFirstPart =
      "--boundary\n"
      "Content-Type: image/svg+xml\n\n";
  image_resource->AppendData(kFirstPart);
  // Send the response for the first real part. No image or data buffer is
  // created.
  EXPECT_FALSE(image_resource->ResourceBuffer());
  EXPECT_FALSE(image_resource->GetContent()->HasImage());
  EXPECT_EQ(0, observer->ImageChangedCount());
  EXPECT_FALSE(observer->ImageNotifyFinishedCalled());
  EXPECT_EQ("image/svg+xml", image_resource->GetResponse().MimeType());

  const std::string_view kSecondPart =
      "<svg xmlns='http://www.w3.org/2000/svg' width='1' height='1'><rect "
      "width='1' height='1' fill='green'/></svg>\n";
  // The first bytes arrive. The data buffer is created, but no image is
  // created.
  image_resource->AppendData(kSecondPart);
  EXPECT_TRUE(image_resource->ResourceBuffer());
  EXPECT_FALSE(image_resource->GetContent()->HasImage());
  EXPECT_EQ(0, observer->ImageChangedCount());
  EXPECT_FALSE(observer->ImageNotifyFinishedCalled());

  // Add an observer to check an assertion error doesn't happen
  // (crbug.com/630983).
  auto* observer2 = MakeGarbageCollected<MockImageResourceObserver>(
      image_resource->GetContent());
  EXPECT_EQ(0, observer2->ImageChangedCount());
  EXPECT_FALSE(observer2->ImageNotifyFinishedCalled());

  const std::string_view kThirdPart = "--boundary";
  image_resource->AppendData(kThirdPart);
  ASSERT_TRUE(image_resource->ResourceBuffer());
  EXPECT_EQ(kSecondPart.size() - 1, image_resource->ResourceBuffer()->size());

  // This part finishes. The image is created, callbacks are sent, and the data
  // buffer is cleared.
  image_resource->Loader()->DidFinishLoading(base::TimeTicks(), 0, 0, 0);
  EXPECT_TRUE(image_resource->ResourceBuffer());
  EXPECT_FALSE(image_resource->ErrorOccurred());
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_FALSE(image_resource->GetContent()->GetImage()->IsNull());
  EXPECT_EQ(kJpegImageWidth, image_resource->GetContent()->GetImage()->width());
  EXPECT_EQ(kJpegImageHeight,
            image_resource->GetContent()->GetImage()->height());
  EXPECT_TRUE(IsA<SVGImage>(image_resource->GetContent()->GetImage()));
  EXPECT_TRUE(image_resource->GetContent()
                  ->GetImage()
                  ->PaintImageForCurrentFrame()
                  .is_multipart());

  EXPECT_EQ(1, observer->ImageChangedCount());
  EXPECT_TRUE(observer->ImageNotifyFinishedCalled());
  EXPECT_EQ(1, observer2->ImageChangedCount());
  EXPECT_TRUE(observer2->ImageNotifyFinishedCalled());
}

TEST_F(ImageResourceTest, BitmapMultipartImage) {
  ResourceFetcher* fetcher = CreateFetcher();
  KURL test_url(kTestURL);
  ScopedMockedURLLoad scoped_mocked_url_load(test_url, GetTestFilePath());
  ResourceRequest resource_request(test_url);
  resource_request.SetInspectorId(CreateUniqueIdentifier());
  resource_request.SetRequestorOrigin(SecurityOrigin::CreateUniqueOpaque());
  resource_request.SetReferrerPolicy(
      ReferrerUtils::MojoReferrerPolicyResolveDefault(
          resource_request.GetReferrerPolicy()));
  resource_request.SetPriority(WebURLRequest::Priority::kLow);
  ImageResource* image_resource =
      ImageResource::Create(resource_request, nullptr /* world */);
  fetcher->StartLoad(image_resource);

  ResourceResponse multipart_response(NullURL());
  multipart_response.SetMimeType(AtomicString("multipart/x-mixed-replace"));
  multipart_response.SetHttpHeaderField(
      http_names::kContentType,
      AtomicString("multipart/x-mixed-replace; boundary=boundary"));
  image_resource->Loader()->DidReceiveResponse(
      WrappedResourceResponse(multipart_response),
      /*body=*/mojo::ScopedDataPipeConsumerHandle(),
      /*cached_metadata=*/std::nullopt);
  EXPECT_FALSE(image_resource->GetContent()->HasImage());

  const std::string_view kBoundary = "--boundary\n";
  const std::string_view kContentType = "Content-Type: image/jpeg\n\n";
  image_resource->AppendData(kBoundary);
  image_resource->AppendData(kContentType);
  image_resource->AppendData(base::as_chars(base::span(kJpegImage)));
  image_resource->AppendData(kBoundary);
  image_resource->Loader()->DidFinishLoading(base::TimeTicks(), 0, 0, 0);
  EXPECT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_TRUE(IsA<BitmapImage>(image_resource->GetContent()->GetImage()));
  EXPECT_TRUE(image_resource->GetContent()
                  ->GetImage()
                  ->PaintImageForCurrentFrame()
                  .is_multipart());
}

TEST_F(ImageResourceTest, CancelOnRemoveObserver) {
  KURL test_url(kTestURL);
  ScopedMockedURLLoad scoped_mocked_url_load(test_url, GetTestFilePath());

  ResourceFetcher* fetcher = CreateFetcher();
  scheduler::FakeTaskRunner* task_runner =
      static_cast<scheduler::FakeTaskRunner*>(fetcher->GetTaskRunner().get());
  task_runner->SetTime(1);

  // Emulate starting a real load.
  ImageResource* image_resource = ImageResource::CreateForTest(test_url);

  fetcher->StartLoad(image_resource);
  MemoryCache::Get()->Add(image_resource);

  auto* observer = MakeGarbageCollected<MockImageResourceObserver>(
      image_resource->GetContent());
  EXPECT_EQ(ResourceStatus::kPending, image_resource->GetStatus());

  // The load should still be alive, but a timer should be started to cancel the
  // load inside removeClient().
  observer->RemoveAsObserver();
  EXPECT_EQ(ResourceStatus::kPending, image_resource->GetStatus());
  EXPECT_TRUE(MemoryCache::Get()->ResourceForURLForTesting(test_url));

  // Trigger the cancel timer, ensure the load was cancelled and the resource
  // was evicted from the cache.
  task_runner->RunUntilIdle();
  EXPECT_EQ(ResourceStatus::kLoadError, image_resource->GetStatus());
  EXPECT_FALSE(MemoryCache::Get()->ResourceForURLForTesting(test_url));
}

class MockFinishObserver : public ResourceFinishObserver {
 public:
  static MockFinishObserver* Create() {
    return MakeGarbageCollected<testing::StrictMock<MockFinishObserver>>();
  }
  MOCK_METHOD0(NotifyFinished, void());
  String DebugName() const override { return "MockFinishObserver"; }

  void Trace(Visitor* visitor) const override {
    blink::ResourceFinishObserver::Trace(visitor);
  }

 protected:
  MockFinishObserver() = default;
};

TEST_F(ImageResourceTest, CancelWithImageAndFinishObserver) {
  KURL test_url(kTestURL);
  ScopedMockedURLLoad scoped_mocked_url_load(test_url, GetTestFilePath());

  ResourceFetcher* fetcher = CreateFetcher();
  scheduler::FakeTaskRunner* task_runner =
      static_cast<scheduler::FakeTaskRunner*>(fetcher->GetTaskRunner().get());

  // Emulate starting a real load.
  ImageResource* image_resource = ImageResource::CreateForTest(test_url);

  fetcher->StartLoad(image_resource);
  MemoryCache::Get()->Add(image_resource);

  Persistent<MockFinishObserver> finish_observer = MockFinishObserver::Create();
  image_resource->AddFinishObserver(finish_observer,
                                    fetcher->GetTaskRunner().get());

  // Send the image response.
  ResourceResponse resource_response(NullURL());
  resource_response.SetMimeType(AtomicString("image/jpeg"));
  resource_response.SetExpectedContentLength(sizeof(kJpegImage));
  image_resource->ResponseReceived(resource_response);
  image_resource->AppendData(base::as_chars(base::span(kJpegImage)));
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_EQ(ResourceStatus::kPending, image_resource->GetStatus());

  // This shouldn't crash. crbug.com/701723
  image_resource->Loader()->Cancel();

  EXPECT_EQ(ResourceStatus::kLoadError, image_resource->GetStatus());
  EXPECT_FALSE(MemoryCache::Get()->ResourceForURLForTesting(test_url));

  // ResourceFinishObserver is notified asynchronously.
  EXPECT_CALL(*finish_observer, NotifyFinished());
  task_runner->RunUntilIdle();
}

TEST_F(ImageResourceTest, DecodedDataRemainsWhileHasClients) {
  ImageResource* image_resource = ImageResource::CreateForTest(NullURL());
  image_resource->NotifyStartLoad();

  auto* observer = MakeGarbageCollected<MockImageResourceObserver>(
      image_resource->GetContent());

  // Send the image response.
  ResourceResponse resource_response(NullURL());
  resource_response.SetMimeType(AtomicString("multipart/x-mixed-replace"));
  image_resource->ResponseReceived(resource_response);

  resource_response.SetMimeType(AtomicString("image/jpeg"));
  resource_response.SetExpectedContentLength(sizeof(kJpegImage));
  image_resource->ResponseReceived(resource_response);
  image_resource->AppendData(base::as_chars(base::span(kJpegImage)));
  image_resource->FinishForTest();
  EXPECT_FALSE(image_resource->ErrorOccurred());
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_FALSE(image_resource->GetContent()->GetImage()->IsNull());
  EXPECT_TRUE(observer->ImageNotifyFinishedCalled());

  // The prune comes when the ImageResource still has observers. The image
  // should not be deleted.
  image_resource->Prune();
  EXPECT_TRUE(image_resource->IsAlive());
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_FALSE(image_resource->GetContent()->GetImage()->IsNull());

  // The ImageResource no longer has observers. The decoded image data should be
  // deleted by prune.
  observer->RemoveAsObserver();
  image_resource->Prune();
  EXPECT_FALSE(image_resource->IsAlive());
  EXPECT_TRUE(image_resource->GetContent()->HasImage());
  // TODO(hajimehoshi): Should check imageResource doesn't have decoded image
  // data.
}

TEST_F(ImageResourceTest, UpdateBitmapImages) {
  ImageResource* image_resource = ImageResource::CreateForTest(NullURL());
  image_resource->NotifyStartLoad();

  auto* observer = MakeGarbageCollected<MockImageResourceObserver>(
      image_resource->GetContent());

  // Send the image response.

  ResourceResponse resource_response(NullURL());
  resource_response.SetMimeType(AtomicString("image/jpeg"));
  resource_response.SetExpectedContentLength(sizeof(kJpegImage));
  image_resource->ResponseReceived(resource_response);
  image_resource->AppendData(base::as_chars(base::span(kJpegImage)));
  image_resource->FinishForTest();
  EXPECT_FALSE(image_resource->ErrorOccurred());
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_FALSE(image_resource->GetContent()->GetImage()->IsNull());
  EXPECT_EQ(2, observer->ImageChangedCount());
  EXPECT_TRUE(observer->ImageNotifyFinishedCalled());
  EXPECT_TRUE(IsA<BitmapImage>(image_resource->GetContent()->GetImage()));
}

TEST_F(ImageResourceTest, SVGImage) {
  KURL url("http://127.0.0.1:8000/foo");
  ImageResource* image_resource = ImageResource::CreateForTest(url);
  auto* observer = MakeGarbageCollected<MockImageResourceObserver>(
      image_resource->GetContent());

  ReceiveResponse(image_resource, url, "image/svg+xml", kSvgImage);

  EXPECT_FALSE(image_resource->ErrorOccurred());
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_FALSE(image_resource->GetContent()->GetImage()->IsNull());
  EXPECT_EQ(1, observer->ImageChangedCount());
  EXPECT_TRUE(observer->ImageNotifyFinishedCalled());
  EXPECT_FALSE(IsA<BitmapImage>(image_resource->GetContent()->GetImage()));
}

TEST_F(ImageResourceTest, SVGImageWithSubresource) {
  KURL url("http://127.0.0.1:8000/foo");
  ImageResource* image_resource = ImageResource::CreateForTest(url);
  auto* observer = MakeGarbageCollected<MockImageResourceObserver>(
      image_resource->GetContent());

  ReceiveResponse(image_resource, url, "image/svg+xml",
                  kSvgImageWithSubresource);

  EXPECT_FALSE(image_resource->ErrorOccurred());
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_FALSE(image_resource->GetContent()->GetImage()->IsNull());
  EXPECT_FALSE(IsA<BitmapImage>(image_resource->GetContent()->GetImage()));

  // At this point, image is (mostly) available but the loading is not yet
  // finished because of SVG's subresources, and thus ImageChanged() or
  // ImageNotifyFinished() are not called.
  EXPECT_EQ(ResourceStatus::kPending,
            image_resource->GetContent()->GetContentStatus());
  EXPECT_EQ(1, observer->ImageChangedCount());
  EXPECT_FALSE(observer->ImageNotifyFinishedCalled());
  EXPECT_EQ(198, image_resource->GetContent()->GetImage()->width());
  EXPECT_EQ(100, image_resource->GetContent()->GetImage()->height());

  // A new client added here shouldn't notified of finish.
  auto* observer2 = MakeGarbageCollected<MockImageResourceObserver>(
      image_resource->GetContent());
  EXPECT_EQ(1, observer2->ImageChangedCount());
  EXPECT_FALSE(observer2->ImageNotifyFinishedCalled());

  // After asynchronous tasks are executed, the loading of SVG document is
  // completed and ImageNotifyFinished() is called.
  test::RunPendingTasks();
  EXPECT_EQ(ResourceStatus::kCached,
            image_resource->GetContent()->GetContentStatus());
  EXPECT_EQ(2, observer->ImageChangedCount());
  EXPECT_TRUE(observer->ImageNotifyFinishedCalled());
  EXPECT_EQ(2, observer2->ImageChangedCount());
  EXPECT_TRUE(observer2->ImageNotifyFinishedCalled());
  EXPECT_EQ(198, image_resource->GetContent()->GetImage()->width());
  EXPECT_EQ(100, image_resource->GetContent()->GetImage()->height());

  MemoryCache::Get()->EvictResources();
}

TEST_F(ImageResourceTest, SuccessfulRevalidationJpeg) {
  KURL url("http://127.0.0.1:8000/foo");
  ImageResource* image_resource = ImageResource::CreateForTest(url);
  auto* observer = MakeGarbageCollected<MockImageResourceObserver>(
      image_resource->GetContent());

  ReceiveResponse(image_resource, url, "image/jpeg",
                  base::as_chars(base::span(kJpegImage)));

  EXPECT_FALSE(image_resource->ErrorOccurred());
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_FALSE(image_resource->GetContent()->GetImage()->IsNull());
  EXPECT_EQ(2, observer->ImageChangedCount());
  EXPECT_TRUE(observer->ImageNotifyFinishedCalled());
  EXPECT_TRUE(IsA<BitmapImage>(image_resource->GetContent()->GetImage()));
  EXPECT_EQ(kJpegImageWidth, image_resource->GetContent()->GetImage()->width());
  EXPECT_EQ(kJpegImageHeight,
            image_resource->GetContent()->GetImage()->height());

  image_resource->SetRevalidatingRequest(ResourceRequest(url));
  ResourceResponse resource_response(url);
  resource_response.SetHttpStatusCode(304);

  image_resource->ResponseReceived(resource_response);

  EXPECT_FALSE(image_resource->ErrorOccurred());
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_FALSE(image_resource->GetContent()->GetImage()->IsNull());
  EXPECT_EQ(2, observer->ImageChangedCount());
  EXPECT_TRUE(observer->ImageNotifyFinishedCalled());
  EXPECT_TRUE(IsA<BitmapImage>(image_resource->GetContent()->GetImage()));
  EXPECT_EQ(kJpegImageWidth, image_resource->GetContent()->GetImage()->width());
  EXPECT_EQ(kJpegImageHeight,
            image_resource->GetContent()->GetImage()->height());
}

TEST_F(ImageResourceTest, SuccessfulRevalidationSvg) {
  KURL url("http://127.0.0.1:8000/foo");
  ImageResource* image_resource = ImageResource::CreateForTest(url);
  auto* observer = MakeGarbageCollected<MockImageResourceObserver>(
      image_resource->GetContent());

  ReceiveResponse(image_resource, url, "image/svg+xml", kSvgImage);

  EXPECT_FALSE(image_resource->ErrorOccurred());
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_FALSE(image_resource->GetContent()->GetImage()->IsNull());
  EXPECT_EQ(1, observer->ImageChangedCount());
  EXPECT_TRUE(observer->ImageNotifyFinishedCalled());
  EXPECT_FALSE(IsA<BitmapImage>(image_resource->GetContent()->GetImage()));
  EXPECT_EQ(200, image_resource->GetContent()->GetImage()->width());
  EXPECT_EQ(200, image_resource->GetContent()->GetImage()->height());

  image_resource->SetRevalidatingRequest(ResourceRequest(url));
  ResourceResponse resource_response(url);
  resource_response.SetHttpStatusCode(304);
  image_resource->ResponseReceived(resource_response);

  EXPECT_FALSE(image_resource->ErrorOccurred());
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_FALSE(image_resource->GetContent()->GetImage()->IsNull());
  EXPECT_EQ(1, observer->ImageChangedCount());
  EXPECT_TRUE(observer->ImageNotifyFinishedCalled());
  EXPECT_FALSE(IsA<BitmapImage>(image_resource->GetContent()->GetImage()));
  EXPECT_EQ(200, image_resource->GetContent()->GetImage()->width());
  EXPECT_EQ(200, image_resource->GetContent()->GetImage()->height());
}

TEST_F(ImageResourceTest, FailedRevalidationJpegToJpeg) {
  KURL url("http://127.0.0.1:8000/foo");
  ImageResource* image_resource = ImageResource::CreateForTest(url);
  auto* observer = MakeGarbageCollected<MockImageResourceObserver>(
      image_resource->GetContent());

  ReceiveResponse(image_resource, url, "image/jpeg",
                  base::as_chars(base::span(kJpegImage)));

  EXPECT_FALSE(image_resource->ErrorOccurred());
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_FALSE(image_resource->GetContent()->GetImage()->IsNull());
  EXPECT_EQ(2, observer->ImageChangedCount());
  EXPECT_TRUE(observer->ImageNotifyFinishedCalled());
  EXPECT_TRUE(IsA<BitmapImage>(image_resource->GetContent()->GetImage()));
  EXPECT_EQ(kJpegImageWidth, image_resource->GetContent()->GetImage()->width());
  EXPECT_EQ(kJpegImageHeight,
            image_resource->GetContent()->GetImage()->height());

  image_resource->SetRevalidatingRequest(ResourceRequest(url));
  ReceiveResponse(image_resource, url, "image/jpeg",
                  base::as_chars(base::span(kJpegImage2)));

  EXPECT_FALSE(image_resource->ErrorOccurred());
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_FALSE(image_resource->GetContent()->GetImage()->IsNull());
  EXPECT_EQ(4, observer->ImageChangedCount());
  EXPECT_TRUE(observer->ImageNotifyFinishedCalled());
  EXPECT_TRUE(IsA<BitmapImage>(image_resource->GetContent()->GetImage()));
  EXPECT_EQ(50, image_resource->GetContent()->GetImage()->width());
  EXPECT_EQ(50, image_resource->GetContent()->GetImage()->height());
}

TEST_F(ImageResourceTest, FailedRevalidationJpegToSvg) {
  KURL url("http://127.0.0.1:8000/foo");
  ImageResource* image_resource = ImageResource::CreateForTest(url);
  auto* observer = MakeGarbageCollected<MockImageResourceObserver>(
      image_resource->GetContent());

  ReceiveResponse(image_resource, url, "image/jpeg",
                  base::as_chars(base::spa
```