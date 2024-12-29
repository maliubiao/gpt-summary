Response:
Let's break down the thought process for analyzing the `clipboard_writer.cc` file.

**1. Understanding the Goal:**

The core request is to understand the functionality of this specific Chromium Blink file (`clipboard_writer.cc`) and its interactions with web technologies (JavaScript, HTML, CSS). The prompt also asks for examples, debugging guidance, and error scenarios.

**2. Initial Code Scan - Identifying Key Components:**

I started by quickly skimming the code, looking for obvious patterns and keywords. Here’s what stood out:

* **Includes:**  A lot of Blink-specific headers (`clipboard/clipboard.h`, `core/dom/document_fragment.h`, `core/editing/serializers/serialization.h`, etc.) and some platform-level ones (`platform/image-decoders/image_decoder.h`, `platform/wtf/...`). This tells me the file is deeply integrated into Blink's rendering engine and handles low-level operations.
* **`namespace blink`:**  Confirms it's part of the Blink rendering engine.
* **Anonymous Namespace:**  The `namespace { ... }` section hints at internal helper classes.
* **Classes Deriving from `ClipboardWriter`:**  `ClipboardImageWriter`, `ClipboardTextWriter`, `ClipboardHtmlWriter`, `ClipboardSvgWriter`, `ClipboardCustomFormatWriter`. This strongly suggests a strategy pattern where different writers handle different data types for the clipboard.
* **`StartWrite` and `Write` Methods:**  These methods appear in each derived class and seem to be the core logic for processing the data.
* **`SystemClipboard`:**  An instance of this class is passed around, indicating it's the interface for interacting with the operating system's clipboard.
* **`ClipboardPromise`:**  Promises are used for asynchronous operations, suggesting that writing to the clipboard might involve delays or background processing.
* **`DOMArrayBuffer`:**  Indicates that data being written is often in binary format.
* **`FileReaderLoader`:**  Suggests handling of `Blob` objects, where data might need to be read from a file-like source.
* **MIME Types:**  Variables like `kMimeTypeImagePng`, `kMimeTypeTextPlain`, etc., clearly show the file deals with different content types.
* **`CreateMarkup`:** This function suggests the processing of HTML or XML structures.
* **Error Handling:**  Calls to `promise_->RejectFromReadOrDecodeFailure()` indicate error scenarios.
* **Threading (`worker_pool::PostTask`, `PostCrossThreadTask`):**  Implies that some operations are offloaded to background threads, especially image decoding.

**3. Dissecting the Derived Classes:**

I then focused on the individual `ClipboardWriter` subclasses to understand how each handles a specific data type:

* **`ClipboardImageWriter`:** Decodes PNG data on a background thread, converts it to a `SkBitmap`, and then writes it to the system clipboard.
* **`ClipboardTextWriter`:** Decodes UTF-8 text from the `ArrayBuffer` on a background thread and writes it as plain text.
* **`ClipboardHtmlWriter`:** Parses HTML from the `ArrayBuffer`, serializes it, and writes the serialized HTML along with the document's URL.
* **`ClipboardSvgWriter`:** Parses SVG from the `ArrayBuffer` and writes the serialized SVG.
* **`ClipboardCustomFormatWriter`:** Directly writes arbitrary binary data with a specified MIME type.

**4. Connecting to Web Technologies:**

Based on the data types handled, the connection to JavaScript, HTML, and CSS became clear:

* **JavaScript:** The `Clipboard` API in JavaScript (specifically the `navigator.clipboard.write()` method) allows web pages to write data to the clipboard. This file implements the backend logic for that API. The arguments to `write()` (e.g., `ClipboardItem` with a `Blob` or string) directly correspond to the data types handled here.
* **HTML:**  The `ClipboardHtmlWriter` specifically handles HTML content being copied. This is relevant when users select and copy rich text or elements from a web page.
* **CSS:**  While CSS itself isn't directly handled as a clipboard format, the HTML content being copied often includes styling information applied by CSS. Therefore, CSS indirectly plays a role in what gets copied as HTML.

**5. Inferring Functionality and Logic:**

Combining the code structure and the understanding of each derived class allowed me to infer the overall functionality:

* **Routing based on MIME type:** The `ClipboardWriter::Create` function acts as a factory, creating the appropriate writer based on the MIME type of the data being written.
* **Asynchronous processing:** The use of promises and background threads highlights the asynchronous nature of clipboard operations, especially for potentially large data like images.
* **Data conversion:** The code shows how different data formats (like `ArrayBuffer`, `Blob`, string) are converted into the appropriate representation for the system clipboard.
* **Security considerations:**  The existence of `ClipboardCustomFormatWriter` and the note about "unsanitized content" suggests that the browser needs to be careful about the types of data allowed on the clipboard.

**6. Crafting Examples and Scenarios:**

With a solid understanding of the code, creating examples for JavaScript interaction, error conditions, and debugging became straightforward. I focused on realistic user actions that would trigger the code.

**7. Debugging Clues:**

Thinking about how a developer would debug clipboard issues led to suggesting breakpoints within the `StartWrite` and `Write` methods, as well as examining the data being passed.

**8. Refinement and Organization:**

Finally, I organized the information into clear sections with headings and bullet points to make it easy to read and understand. I made sure to address all the points in the original prompt.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Maybe it directly interacts with the OS clipboard."  **Correction:** It uses a `SystemClipboard` abstraction, making it platform-independent within Blink's scope.
* **Initial thought:** "Is CSS directly involved?" **Correction:** CSS styles are part of the *HTML* content being copied, so the connection is indirect.
* **Ensuring all prompt points are covered:** I double-checked the original prompt to make sure I had addressed every aspect, including user actions, debugging, and error scenarios.
This file, `clipboard_writer.cc`, within the Chromium Blink rendering engine, is responsible for **writing data to the system clipboard**. It acts as an intermediary between the web content (JavaScript API calls) and the operating system's clipboard.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Receives Data and MIME Type:**  It takes data to be written to the clipboard along with its corresponding MIME type (e.g., `text/plain`, `image/png`, `text/html`). This data originates from JavaScript's `navigator.clipboard.write()` API.

2. **Selects Appropriate Writer:** Based on the provided MIME type, it creates an instance of a specific `ClipboardWriter` subclass designed to handle that type of data. This uses a factory pattern implemented in the `ClipboardWriter::Create` static method.

3. **Data Processing and Conversion:**  Each specialized writer subclass (`ClipboardImageWriter`, `ClipboardTextWriter`, `ClipboardHtmlWriter`, `ClipboardSvgWriter`, `ClipboardCustomFormatWriter`) performs the necessary processing and conversion steps to prepare the data for the system clipboard. This might involve:
    * **Decoding:** Decoding image data (like PNG) from `ArrayBuffer` to a `SkImage`.
    * **Encoding:** Encoding text data to UTF-8.
    * **Serialization:** Serializing HTML or SVG documents into string representations.
    * **No processing:** For custom formats, the raw `ArrayBuffer` might be directly passed.

4. **Interacts with `SystemClipboard`:**  Each writer subclass interacts with the `SystemClipboard` class (an abstraction over the OS clipboard) to actually write the formatted data. This involves calling methods like `WritePlainText`, `WriteHTML`, `WriteImage`, `WriteSvg`, or `WriteUnsanitizedCustomFormat`.

5. **Manages Asynchronous Operations:**  For data that might require processing (like reading a `Blob`), it uses `FileReaderLoader` to asynchronously read the data. It also uses background threads (`worker_pool::PostTask`) for tasks like image decoding to avoid blocking the main thread.

6. **Manages Promises:** It uses `ClipboardPromise` to track the success or failure of the write operation and communicate the outcome back to the JavaScript code.

**Relationship with JavaScript, HTML, and CSS:**

* **JavaScript:** This file is directly invoked as a result of JavaScript code using the `navigator.clipboard.write()` API. The data and MIME types passed to the JavaScript API are the inputs to this C++ code.
    * **Example:**
      ```javascript
      navigator.clipboard.write([
        new ClipboardItem({
          'text/plain': new Blob(['Hello, clipboard!'], { type: 'text/plain' })
        })
      ]);
      ```
      This JavaScript code would eventually lead to the creation of a `ClipboardTextWriter` in `clipboard_writer.cc` to handle the "text/plain" data.

* **HTML:** The `ClipboardHtmlWriter` specifically handles writing HTML content to the clipboard. This is used when a user copies selected content from a web page that includes HTML markup. The `CreateMarkup` function is used to serialize a DOM tree into an HTML string.
    * **Example:**  If a user selects the following HTML in a browser and copies it:
      ```html
      <h1>This is a heading</h1>
      <p style="color: blue;">This is a paragraph.</p>
      ```
      The `ClipboardHtmlWriter` would receive the HTML structure, potentially including inline styles, and write it to the clipboard.

* **CSS:** While CSS itself isn't directly a clipboard format handled by dedicated writers, it plays a role in the HTML content being copied. When HTML is copied, the styles applied to those elements (either through inline styles or referenced stylesheets) can be preserved in the copied HTML. The `ClipboardHtmlWriter` is responsible for serializing the HTML, which includes these styles.

**Logical Reasoning with Assumptions:**

Let's consider the `ClipboardImageWriter`:

* **Assumption (Input):** JavaScript calls `navigator.clipboard.write()` with a `ClipboardItem` containing `image/png` data as an `ArrayBuffer`.
* **Processing:**
    1. `ClipboardWriter::Create` instantiates a `ClipboardImageWriter`.
    2. `ClipboardImageWriter::StartWrite` receives the `DOMArrayBuffer`.
    3. The PNG data is moved to a background thread for decoding using `ImageDecoder`.
    4. If decoding is successful, an `SkImage` is created.
    5. The `SkImage` is converted to an `SkBitmap`.
    6. `SystemClipboard::WriteImage` is called with the `SkBitmap`.
* **Output:** The system clipboard now contains the image data in a format understandable by other applications.

**User or Programming Common Usage Errors:**

1. **Incorrect MIME Type:** Providing an incorrect or unsupported MIME type in the JavaScript `ClipboardItem`. This would likely lead to the `NOTREACHED()` statement in `ClipboardWriter::Create` and a failure to write to the clipboard.
    * **Example:**
      ```javascript
      navigator.clipboard.write([
        new ClipboardItem({
          'application/my-custom-type': new Blob(['some data'], { type: 'application/my-custom-type' })
        })
      ]);
      ```
      If `application/my-custom-type` is not a standard web custom format, this could lead to issues.

2. **Large Data Size:** Attempting to write very large amounts of data to the clipboard might exceed system limitations or browser restrictions (see `mojom::blink::ClipboardHost::kMaxDataSize` in `ClipboardCustomFormatWriter`). This could result in the `promise_->RejectFromReadOrDecodeFailure()` being called.
    * **Example:**  Trying to copy a multi-gigabyte file using the clipboard API.

3. **Incorrect Data Format:** Providing data that doesn't match the declared MIME type. For example, providing plain text data but declaring the MIME type as `image/png`. This would likely cause decoding errors in the specific writer (e.g., `ClipboardImageWriter` failing to decode non-PNG data).

4. **Permissions Issues:** The browser might not have permission to write to the clipboard, especially in secure contexts. This is handled at a higher level but could prevent the `clipboard_writer.cc` code from being reached effectively.

**User Operations Leading to This Code (Debugging Clues):**

1. **User copies text or images:** Selecting text or images on a web page and using the browser's "Copy" command (Ctrl+C or right-click "Copy").

2. **Web page uses the Clipboard API:** A website's JavaScript code explicitly calls `navigator.clipboard.write()` to programmatically write data to the clipboard. This could be in response to a button click, a drag-and-drop operation, or other user interactions within the web page.

**Debugging Steps:**

If you're trying to debug why something isn't being copied correctly, here's how you might trace it to `clipboard_writer.cc`:

1. **Set Breakpoints in JavaScript:** Start by setting breakpoints in the JavaScript code that calls `navigator.clipboard.write()`. Inspect the `ClipboardItem` data and the MIME types being passed.

2. **Follow the Call Stack:** Step through the JavaScript code to see how the browser handles the `navigator.clipboard.write()` call. This will eventually lead into the Blink rendering engine's C++ code.

3. **Set Breakpoints in `clipboard_writer.cc`:** Set breakpoints in the `ClipboardWriter::Create` method to see which specific writer is being instantiated based on the MIME type. Also, set breakpoints in the `StartWrite` and `Write` methods of the relevant writer subclass (e.g., `ClipboardTextWriter::StartWrite`).

4. **Inspect Data:** When the breakpoints are hit in the C++ code, inspect the `DOMArrayBuffer` or other data structures to see the raw data being passed. Check if the data matches the expected format for the given MIME type.

5. **Check `SystemClipboard` Calls:**  Set breakpoints in the `SystemClipboard` class's methods (e.g., `WritePlainText`, `WriteImage`) to verify that the correct data is being passed to the OS clipboard.

By following these steps, you can pinpoint where the clipboard writing process might be failing, whether it's an issue with the JavaScript code, the data formatting, or the interaction with the operating system's clipboard.

Prompt: 
```
这是目录为blink/renderer/modules/clipboard/clipboard_writer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/clipboard/clipboard_writer.h"

#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/clipboard/clipboard.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_supported_type.h"
#include "third_party/blink/renderer/core/clipboard/clipboard_mime_types.h"
#include "third_party/blink/renderer/core/clipboard/system_clipboard.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fileapi/file_reader_loader.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/core/keywords.h"
#include "third_party/blink/renderer/core/typed_arrays/array_buffer/array_buffer_contents.h"
#include "third_party/blink/renderer/core/xml/dom_parser.h"
#include "third_party/blink/renderer/modules/clipboard/clipboard.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_handle.h"
#include "third_party/blink/renderer/platform/image-decoders/image_decoder.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/worker_pool.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_skia.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"
#include "ui/base/clipboard/clipboard_constants.h"

namespace blink {

namespace {  // anonymous namespace for ClipboardWriter's derived classes.

// Writes image/png content to the System Clipboard.
class ClipboardImageWriter final : public ClipboardWriter {
 public:
  ClipboardImageWriter(SystemClipboard* system_clipboard,
                       ClipboardPromise* promise)
      : ClipboardWriter(system_clipboard, promise) {}
  ~ClipboardImageWriter() override = default;

 private:
  void StartWrite(
      DOMArrayBuffer* raw_data,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner) override {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

    // ArrayBufferContents is a thread-safe smart pointer around the backing
    // store.
    ArrayBufferContents contents = *raw_data->Content();
    worker_pool::PostTask(
        FROM_HERE,
        CrossThreadBindOnce(&ClipboardImageWriter::DecodeOnBackgroundThread,
                            std::move(contents), MakeCrossThreadHandle(this),
                            task_runner));
  }
  static void DecodeOnBackgroundThread(
      ArrayBufferContents png_data,
      CrossThreadHandle<ClipboardImageWriter> writer,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
    DCHECK(!IsMainThread());
    std::unique_ptr<ImageDecoder> decoder = ImageDecoder::Create(
        SegmentReader::CreateFromSkData(
            SkData::MakeWithoutCopy(png_data.Data(), png_data.DataLength())),
        /*data_complete=*/true, ImageDecoder::kAlphaPremultiplied,
        ImageDecoder::kDefaultBitDepth, ColorBehavior::kTag,
        cc::AuxImage::kDefault, Platform::GetMaxDecodedImageBytes());
    sk_sp<SkImage> image = nullptr;
    // `decoder` is nullptr if `png_data` doesn't begin with the PNG signature.
    if (decoder) {
      image = ImageBitmap::GetSkImageFromDecoder(std::move(decoder));
    }

    PostCrossThreadTask(
        *task_runner, FROM_HERE,
        CrossThreadBindOnce(&ClipboardImageWriter::Write,
                            MakeUnwrappingCrossThreadHandle(std::move(writer)),
                            std::move(image)));
  }
  void Write(sk_sp<SkImage> image) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    if (!image) {
      promise_->RejectFromReadOrDecodeFailure();
      return;
    }
    if (!promise_->GetLocalFrame()) {
      return;
    }
    SkBitmap bitmap;
    image->asLegacyBitmap(&bitmap);
    system_clipboard()->WriteImage(std::move(bitmap));
    promise_->CompleteWriteRepresentation();
  }
};

// Writes text/plain content to the System Clipboard.
class ClipboardTextWriter final : public ClipboardWriter {
 public:
  ClipboardTextWriter(SystemClipboard* system_clipboard,
                      ClipboardPromise* promise)
      : ClipboardWriter(system_clipboard, promise) {}
  ~ClipboardTextWriter() override = default;

 private:
  void StartWrite(
      DOMArrayBuffer* raw_data,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner) override {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

    // ArrayBufferContents is a thread-safe smart pointer around the backing
    // store.
    ArrayBufferContents contents = *raw_data->Content();
    worker_pool::PostTask(
        FROM_HERE,
        CrossThreadBindOnce(&ClipboardTextWriter::DecodeOnBackgroundThread,
                            std::move(contents), MakeCrossThreadHandle(this),
                            task_runner));
  }
  static void DecodeOnBackgroundThread(
      ArrayBufferContents raw_data,
      CrossThreadHandle<ClipboardTextWriter> writer,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
    DCHECK(!IsMainThread());

    String wtf_string = String::FromUTF8(raw_data.ByteSpan());
    PostCrossThreadTask(
        *task_runner, FROM_HERE,
        CrossThreadBindOnce(&ClipboardTextWriter::Write,
                            MakeUnwrappingCrossThreadHandle(std::move(writer)),
                            std::move(wtf_string)));
  }
  void Write(const String& text) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    if (!promise_->GetLocalFrame()) {
      return;
    }
    system_clipboard()->WritePlainText(text);

    promise_->CompleteWriteRepresentation();
  }
};

// Writes text/html content to the System Clipboard.
class ClipboardHtmlWriter final : public ClipboardWriter {
 public:
  ClipboardHtmlWriter(SystemClipboard* system_clipboard,
                      ClipboardPromise* promise)
      : ClipboardWriter(system_clipboard, promise) {}
  ~ClipboardHtmlWriter() override = default;

 private:
  void StartWrite(
      DOMArrayBuffer* html_data,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner) override {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

    LocalFrame* local_frame = promise_->GetLocalFrame();
    auto* execution_context = promise_->GetExecutionContext();
    if (!local_frame || !execution_context) {
      return;
    }
    const KURL& url = local_frame->GetDocument()->Url();
    DOMParser* dom_parser = DOMParser::Create(promise_->GetScriptState());
    String html_string = String::FromUTF8(html_data->ByteSpan());
    const Document* doc = dom_parser->parseFromString(
        html_string, V8SupportedType(V8SupportedType::Enum::kTextHtml));
    DCHECK(doc);
    String serialized_html = CreateMarkup(doc, kIncludeNode, kResolveAllURLs);
    Write(serialized_html, url);
  }

  void Write(const String& serialized_html, const KURL& url) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    system_clipboard()->WriteHTML(serialized_html, url);
    promise_->CompleteWriteRepresentation();
  }
};

// Write image/svg+xml content to the System Clipboard.
class ClipboardSvgWriter final : public ClipboardWriter {
 public:
  ClipboardSvgWriter(SystemClipboard* system_clipboard,
                     ClipboardPromise* promise)
      : ClipboardWriter(system_clipboard, promise) {}
  ~ClipboardSvgWriter() override = default;

 private:
  void StartWrite(
      DOMArrayBuffer* svg_data,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner) override {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

    LocalFrame* local_frame = promise_->GetLocalFrame();
    if (!local_frame) {
      return;
    }

    DOMParser* dom_parser = DOMParser::Create(promise_->GetScriptState());
    String svg_string = String::FromUTF8(svg_data->ByteSpan());
    const Document* doc = dom_parser->parseFromString(
        svg_string, V8SupportedType(V8SupportedType::Enum::kImageSvgXml));
    Write(CreateMarkup(doc, kIncludeNode, kResolveAllURLs));
  }

  void Write(const String& svg_html) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    system_clipboard()->WriteSvg(svg_html);
    promise_->CompleteWriteRepresentation();
  }
};

// Writes arbitrary, unsanitized content to the System Clipboard.
class ClipboardCustomFormatWriter final : public ClipboardWriter {
 public:
  ClipboardCustomFormatWriter(SystemClipboard* system_clipboard,
                              ClipboardPromise* promise,
                              const String& mime_type)
      : ClipboardWriter(system_clipboard, promise), mime_type_(mime_type) {}
  ~ClipboardCustomFormatWriter() override = default;

 private:
  void StartWrite(
      DOMArrayBuffer* custom_format_data,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner) override {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    Write(custom_format_data);
  }

  void Write(DOMArrayBuffer* custom_format_data) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    if (!promise_->GetLocalFrame()) {
      return;
    }
    if (custom_format_data->ByteLength() >=
        mojom::blink::ClipboardHost::kMaxDataSize) {
      promise_->RejectFromReadOrDecodeFailure();
      return;
    }
    mojo_base::BigBuffer buffer(
        base::make_span(static_cast<uint8_t*>(custom_format_data->Data()),
                        custom_format_data->ByteLength()));
    system_clipboard()->WriteUnsanitizedCustomFormat(mime_type_,
                                                     std::move(buffer));
    promise_->CompleteWriteRepresentation();
  }

  String mime_type_;
};

}  // anonymous namespace

// ClipboardWriter functions.

// static
ClipboardWriter* ClipboardWriter::Create(SystemClipboard* system_clipboard,
                                         const String& mime_type,
                                         ClipboardPromise* promise) {
  CHECK(ClipboardItem::supports(mime_type));
  String web_custom_format = Clipboard::ParseWebCustomFormat(mime_type);
  if (!web_custom_format.empty()) {
    // We write the custom MIME type without the "web " prefix into the web
    // custom format map so native applications don't have to add any string
    // parsing logic to read format from clipboard.
    return MakeGarbageCollected<ClipboardCustomFormatWriter>(
        system_clipboard, promise, web_custom_format);
  }

  if (mime_type == kMimeTypeImagePng) {
    return MakeGarbageCollected<ClipboardImageWriter>(system_clipboard,
                                                      promise);
  }

  if (mime_type == kMimeTypeTextPlain) {
    return MakeGarbageCollected<ClipboardTextWriter>(system_clipboard, promise);
  }

  if (mime_type == kMimeTypeTextHTML) {
    return MakeGarbageCollected<ClipboardHtmlWriter>(system_clipboard, promise);
  }

  if (mime_type == kMimeTypeImageSvg) {
    return MakeGarbageCollected<ClipboardSvgWriter>(system_clipboard, promise);
  }

  NOTREACHED()
      << "IsValidType() and Create() have inconsistent implementations.";
}

ClipboardWriter::ClipboardWriter(SystemClipboard* system_clipboard,
                                 ClipboardPromise* promise)
    : promise_(promise),
      clipboard_task_runner_(promise->GetExecutionContext()->GetTaskRunner(
          TaskType::kUserInteraction)),
      file_reading_task_runner_(promise->GetExecutionContext()->GetTaskRunner(
          TaskType::kFileReading)),
      system_clipboard_(system_clipboard) {}

ClipboardWriter::~ClipboardWriter() = default;

void ClipboardWriter::WriteToSystem(V8UnionBlobOrString* clipboard_item_data) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (clipboard_item_data->IsBlob()) {
    DCHECK(!file_reader_);
    file_reader_ = MakeGarbageCollected<FileReaderLoader>(
        this, std::move(file_reading_task_runner_));
    file_reader_->Start(clipboard_item_data->GetAsBlob()->GetBlobDataHandle());
  } else if (clipboard_item_data->IsString()) {
    DCHECK(RuntimeEnabledFeatures::ClipboardItemWithDOMStringSupportEnabled());
    StartWrite(
        DOMArrayBuffer::Create(clipboard_item_data->GetAsString().Span8()),
        clipboard_task_runner_);
  } else {
    NOTREACHED();
  }
}

// FileReaderClient implementation.
void ClipboardWriter::DidFinishLoading(FileReaderData contents) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DOMArrayBuffer* array_buffer = std::move(contents).AsDOMArrayBuffer();
  DCHECK(array_buffer);

  self_keep_alive_.Clear();
  file_reader_ = nullptr;

  StartWrite(array_buffer, clipboard_task_runner_);
}

void ClipboardWriter::DidFail(FileErrorCode error_code) {
  FileReaderAccumulator::DidFail(error_code);
  self_keep_alive_.Clear();
  file_reader_ = nullptr;
  promise_->RejectFromReadOrDecodeFailure();
}

void ClipboardWriter::Trace(Visitor* visitor) const {
  FileReaderAccumulator::Trace(visitor);
  visitor->Trace(promise_);
  visitor->Trace(system_clipboard_);
  visitor->Trace(file_reader_);
}

}  // namespace blink

"""

```