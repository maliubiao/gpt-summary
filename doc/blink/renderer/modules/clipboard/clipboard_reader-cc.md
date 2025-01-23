Response:
Let's break down the thought process for analyzing the `clipboard_reader.cc` file.

**1. Initial Understanding of the Purpose:**

The filename `clipboard_reader.cc` and the presence of `#include "third_party/blink/renderer/modules/clipboard/clipboard_reader.h"` immediately signal that this file is responsible for *reading* data from the system clipboard within the Chromium Blink rendering engine. The namespace `blink::clipboard` further reinforces this.

**2. Identifying Key Classes and Their Roles:**

Scanning the file reveals several key classes:

*   `ClipboardReader`: This appears to be the base class, likely defining the common interface for reading clipboard data.
*   `ClipboardPngReader`, `ClipboardTextReader`, `ClipboardHtmlReader`, `ClipboardSvgReader`, `ClipboardCustomFormatReader`:  These seem to be specialized subclasses of `ClipboardReader`, each handling a specific data format (PNG, plain text, HTML, SVG, and custom formats). This suggests a strategy pattern for handling different clipboard content types.
*   `SystemClipboard`: This is clearly an abstraction for interacting with the operating system's clipboard.
*   `ClipboardPromise`: This likely represents a promise-based API, where the result of reading from the clipboard will be delivered asynchronously.
*   `Blob`:  This is a standard web API object for representing raw data, indicating that the clipboard data is being read and prepared in this format for web consumption.

**3. Analyzing the Functionality of Each Reader Subclass:**

For each subclass, I'd look for the `Read()` method, which is the core action. I'd pay attention to:

*   **How it interacts with `SystemClipboard`:** What specific methods are called (`ReadPng`, `ReadPlainText`, `ReadHTML`, etc.)?  This reveals the underlying clipboard API usage.
*   **Data processing:** Does the data need any transformation after being read from the system clipboard?  For example, `ClipboardTextReader` encodes the text to UTF-8, and `ClipboardHtmlReader` and `ClipboardSvgReader` sanitize the content for security.
*   **Asynchronous operations:** The use of `WTF::BindOnce` and `PostCrossThreadTask` indicates asynchronous operations, likely to avoid blocking the main rendering thread. This is a common pattern in Blink.
*   **Creation of `Blob` objects:** Each reader eventually creates a `Blob` containing the clipboard data and its MIME type.
*   **Calling `promise_->OnRead()`:**  This confirms the promise-based approach, where the `Blob` is passed back to the waiting promise.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

*   **JavaScript:** The `ClipboardPromise` strongly suggests a connection to the JavaScript Clipboard API (`navigator.clipboard`). The `Read()` methods in these C++ classes are likely the underlying implementations for JavaScript's `navigator.clipboard.read()` and `navigator.clipboard.readText()`.
*   **HTML:** `ClipboardHtmlReader` directly deals with HTML content. The sanitization logic is crucial for preventing XSS (Cross-Site Scripting) vulnerabilities when pasting HTML into a web page.
*   **CSS:** While CSS isn't directly manipulated here, the fact that HTML is being processed means that CSS embedded within the HTML might be indirectly affected by the sanitization process. Also, images (PNG, SVG) fetched from the clipboard could be displayed using CSS.

**5. Identifying Potential User/Programming Errors:**

*   **Incorrect MIME types:** The `Create()` method checks if the provided `mime_type` is supported. Providing an incorrect or unsupported MIME type would lead to a `NOTREACHED()` error, indicating a programming error.
*   **Security issues with unsanitized HTML:** The existence of `sanitize_html_` in `ClipboardHtmlReader` highlights the security risk of pasting arbitrary HTML. If a developer bypasses sanitization (if such an option existed and was misused), it could lead to XSS vulnerabilities.
*   **Asynchronous nature of the API:**  Developers might incorrectly assume that reading from the clipboard is a synchronous operation. The promise-based API forces them to handle the asynchronous nature correctly using `.then()` or `async/await`.

**6. Constructing the "User Journey" and Debugging Clues:**

To understand how a user action leads to this code, I'd trace back from the JavaScript Clipboard API:

1. A user interacts with the web page (e.g., clicks a "paste" button or uses a keyboard shortcut like Ctrl+V).
2. JavaScript code uses the `navigator.clipboard.read()` or `navigator.clipboard.readText()` API.
3. This JavaScript call is internally routed through the Blink rendering engine.
4. The appropriate `ClipboardReader` subclass is created based on the requested MIME type.
5. The `Read()` method of the selected `ClipboardReader` subclass is executed, interacting with the system clipboard.
6. The data is processed, potentially on background threads.
7. A `Blob` is created and passed back to the JavaScript promise.
8. The JavaScript code receives the clipboard data and can then manipulate or display it.

Debugging clues would involve looking at the console for errors related to the Clipboard API, checking network requests if the pasted content involves external resources, and potentially using browser developer tools to step through the JavaScript code and see the values being passed to the Clipboard API. On the C++ side, logging or breakpoints within the `ClipboardReader` subclasses could be used to inspect the data being read and processed.

**7. Iteration and Refinement:**

As I went through the code, I might refine my understanding. For example, initially, I might not have fully grasped the purpose of the background thread processing. However, seeing the `PostCrossThreadTask` calls would lead me to investigate why this is necessary (performance and avoiding main thread blocking).

This iterative process of code examination, combined with knowledge of web technologies and the Chromium architecture, allows for a comprehensive understanding of the `clipboard_reader.cc` file.
好的，让我们来分析一下 `blink/renderer/modules/clipboard/clipboard_reader.cc` 这个文件。

**文件功能概述**

`clipboard_reader.cc` 文件的核心功能是**从系统剪贴板中读取数据，并将其转换为浏览器可以处理的 `Blob` 对象**。 这个过程中，它需要处理不同类型的数据（如纯文本、HTML、PNG、SVG 以及自定义格式），并根据需要进行一些预处理，例如 HTML 的安全清理。

**与 JavaScript, HTML, CSS 的关系**

这个文件是实现 Web API 中 `navigator.clipboard.read()` 和 `navigator.clipboard.readText()` 方法的关键部分，因此与 JavaScript 和它所操作的 HTML 内容有直接关系。

*   **JavaScript:**  当 JavaScript 代码调用 `navigator.clipboard.read()` 或 `navigator.clipboard.readText()` 时，Blink 引擎会触发相应的逻辑，最终会调用到 `clipboard_reader.cc` 中的代码来实际读取剪贴板数据。
*   **HTML:** `ClipboardHtmlReader` 类专门负责读取剪贴板中的 HTML 内容。它会获取 HTML 字符串，并可以选择进行安全清理，移除潜在的恶意脚本或其他不安全的内容，然后再将其封装成 `Blob` 对象。
    *   **举例说明:** 假设用户复制了一段包含 `<img>` 标签和 `<iframe>` 标签的 HTML 代码。`ClipboardHtmlReader` 在读取这段 HTML 时，如果启用了安全清理，可能会移除 `<iframe>` 标签以防止嵌入恶意网站。最终，JavaScript 通过 Clipboard API 读取到的 `Blob` 对象，其内容可能与原始复制的 HTML 有所不同（如果进行了清理）。
*   **CSS:** 虽然这个文件不直接处理 CSS，但如果剪贴板中包含 HTML，那么 HTML 中可能包含内联样式或引用的外部 CSS 文件。`ClipboardHtmlReader` 在处理 HTML 时，会保留这些样式信息，并将它们包含在最终的 `Blob` 对象中。当这段 HTML 被粘贴到文档中时，其样式也会生效。
    *   **举例说明:** 用户复制了一段带有 `style="color: red;"` 属性的 `<span>` 标签。`ClipboardHtmlReader` 会读取这段 HTML，并将包含样式的 HTML 内容放入 `Blob` 中。当 JavaScript 将这个 `Blob` 的内容插入到文档中时，文本会显示为红色。

**逻辑推理 (假设输入与输出)**

假设用户复制了以下内容到剪贴板：

*   **输入类型 1: 纯文本**
    *   **假设输入:**  剪贴板包含字符串 "Hello, world!"
    *   **处理流程:** `ClipboardTextReader` 被创建，调用 `Read()` 方法，从系统剪贴板读取纯文本。文本被编码为 UTF-8，并创建一个 `Blob` 对象，MIME 类型为 `text/plain`。
    *   **假设输出:** 一个 `Blob` 对象，包含 "Hello, world!" 的 UTF-8 编码数据，MIME 类型为 `text/plain`。

*   **输入类型 2: HTML**
    *   **假设输入:** 剪贴板包含 HTML 代码 `<p>This is <b>bold</b> text.</p>`
    *   **处理流程:** `ClipboardHtmlReader` 被创建，调用 `Read()` 方法，从系统剪贴板读取 HTML。根据 `sanitize_html_` 的值，可能会对 HTML 进行安全清理。HTML 被编码为 UTF-8，并创建一个 `Blob` 对象，MIME 类型为 `text/html`。
    *   **假设输出 (未清理):** 一个 `Blob` 对象，包含 `"<p>This is <b>bold</b> text.</p>"` 的 UTF-8 编码数据，MIME 类型为 `text/html`。
    *   **假设输出 (已清理 - 可能的修改):** 如果 HTML 中包含潜在风险的标签或属性，输出的 HTML 可能会被修改或移除。例如，如果输入包含 `<script>alert('XSS')</script>`，清理后可能变为 `<p>...</p>` (script 标签被移除)。

*   **输入类型 3: PNG 图片**
    *   **假设输入:** 剪贴板包含一个 PNG 格式的图片数据。
    *   **处理流程:** `ClipboardPngReader` 被创建，调用 `Read()` 方法，从系统剪贴板读取 PNG 数据。创建一个 `Blob` 对象，MIME 类型为 `image/png`。
    *   **假设输出:** 一个 `Blob` 对象，包含原始 PNG 图片数据，MIME 类型为 `image/png`。

**用户或编程常见的使用错误**

*   **尝试读取不支持的 MIME 类型:**  JavaScript 代码请求读取剪贴板中特定 MIME 类型的数据，但该类型的数据并不存在于剪贴板中。 这会导致 `navigator.clipboard.read()` 返回的 Promise 被 reject。
    *   **例子:** 用户复制了一张图片，但 JavaScript 代码尝试使用 `navigator.clipboard.read([{'types': ['text/plain']}])` 来读取纯文本。由于剪贴板中主要是图片数据，读取纯文本的操作会失败。
*   **在不安全的上下文中访问剪贴板 API:** Clipboard API 通常需要在安全上下文 (HTTPS) 中才能使用。在 HTTP 页面中尝试使用可能会导致权限错误。
*   **用户未授予剪贴板权限:**  浏览器可能会要求用户显式授予网站访问剪贴板的权限。如果用户拒绝了权限，尝试读取剪贴板会失败。
*   **滥用 `unsanitized` 选项 (如果存在且可访问):**  如果开发者有意跳过 HTML 安全清理，可能会引入安全漏洞，允许恶意脚本注入到页面中。这是一个编程错误，可能导致跨站脚本攻击 (XSS)。

**用户操作如何一步步到达这里 (调试线索)**

1. **用户操作:** 用户在操作系统中执行了复制操作 (例如，选中一段文本或图片，然后按下 Ctrl+C 或 Cmd+C)。此时，数据被放入系统剪贴板。
2. **网页交互:** 用户访问了一个网页，并且该网页的 JavaScript 代码尝试从剪贴板读取数据。这通常发生在用户执行粘贴操作 (Ctrl+V 或 Cmd+V)，或者网页上的某个按钮被点击，触发了读取剪贴板的操作。
3. **JavaScript 调用 Clipboard API:** 网页的 JavaScript 代码调用 `navigator.clipboard.read()` 或 `navigator.clipboard.readText()` 方法。例如：
    ```javascript
    navigator.clipboard.readText().then(text => {
      console.log('Pasted text:', text);
    });
    ```
    或者：
    ```javascript
    navigator.clipboard.read().then(clipboardItems => {
      for (const clipboardItem of clipboardItems) {
        for (const type of clipboardItem.types) {
          clipboardItem.getType(type).then(blob => {
            // 处理 Blob 数据
            console.log('Pasted data of type:', type, blob);
          });
        }
      }
    });
    ```
4. **Blink 引擎处理请求:**  浏览器接收到 JavaScript 的剪贴板读取请求。Blink 引擎会根据请求的 MIME 类型和是否需要安全清理等参数，创建相应的 `ClipboardReader` 子类的实例 (例如 `ClipboardTextReader`，`ClipboardHtmlReader`，`ClipboardPngReader` 等)。
5. **`ClipboardReader` 读取数据:**  创建的 `ClipboardReader` 实例的 `Read()` 方法被调用。这个方法会调用 `SystemClipboard` 类的方法，与操作系统底层的剪贴板 API 交互，实际读取剪贴板中的数据。
6. **数据转换和封装:** 读取到的数据会被转换为 `Blob` 对象，并设置相应的 MIME 类型。对于 HTML 和 SVG，可能会进行安全清理。
7. **返回结果给 JavaScript:**  `Blob` 对象通过 Promise 返回给 JavaScript 代码，JavaScript 代码可以进一步处理这些数据（例如，将文本插入到 DOM 中，显示图片等）。

**调试线索:**

*   **Chrome DevTools Console:** 查看是否有与 Clipboard API 相关的错误或警告信息。
*   **Chrome DevTools Sources 标签页:** 在 JavaScript 代码中设置断点，查看 `navigator.clipboard.read()` 或 `navigator.clipboard.readText()` 的调用和返回值。
*   **Blink 源码调试:** 如果需要深入了解 Blink 引擎的内部实现，可以在 `clipboard_reader.cc` 文件中设置断点，跟踪代码执行流程，查看读取到的原始数据和转换后的 `Blob` 对象。
*   **检查剪贴板内容:** 使用操作系统提供的剪贴板查看工具，确认剪贴板中实际包含的数据类型和内容，以便对比 JavaScript 代码的读取结果。
*   **权限检查:** 确认当前网页是否具有访问剪贴板的权限。可以在浏览器设置中查看网站的权限信息。

希望以上分析能够帮助你理解 `blink/renderer/modules/clipboard/clipboard_reader.cc` 文件的功能和它在浏览器中的作用。

### 提示词
```
这是目录为blink/renderer/modules/clipboard/clipboard_reader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "third_party/blink/renderer/modules/clipboard/clipboard_reader.h"

#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/public/mojom/clipboard/clipboard.mojom-blink.h"
#include "third_party/blink/renderer/core/clipboard/clipboard_mime_types.h"
#include "third_party/blink/renderer/core/clipboard/system_clipboard.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/modules/clipboard/clipboard.h"
#include "third_party/blink/renderer/modules/clipboard/clipboard_promise.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_handle.h"
#include "third_party/blink/renderer/platform/image-encoders/image_encoder.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/worker_pool.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"

namespace blink {

namespace {  // anonymous namespace for ClipboardReader's derived classes.

// Reads a PNG from the System Clipboard as a Blob with image/png content.
// Since the data returned from ReadPng() is already in the desired format, no
// encoding is required and the blob is created directly from Read().
class ClipboardPngReader final : public ClipboardReader {
 public:
  explicit ClipboardPngReader(SystemClipboard* system_clipboard,
                              ClipboardPromise* promise)
      : ClipboardReader(system_clipboard, promise) {}
  ~ClipboardPngReader() override = default;

  ClipboardPngReader(const ClipboardPngReader&) = delete;
  ClipboardPngReader& operator=(const ClipboardPngReader&) = delete;

  void Read() override {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    mojo_base::BigBuffer data =
        system_clipboard()->ReadPng(mojom::blink::ClipboardBuffer::kStandard);

    Blob* blob = nullptr;
    if (data.size()) {
      blob = Blob::Create(data, kMimeTypeImagePng);
    }
    promise_->OnRead(blob);
  }

 private:
  void NextRead(Vector<uint8_t> utf8_bytes) override { NOTREACHED(); }
};

// Reads an image from the System Clipboard as a Blob with text/plain content.
class ClipboardTextReader final : public ClipboardReader {
 public:
  explicit ClipboardTextReader(SystemClipboard* system_clipboard,
                               ClipboardPromise* promise)
      : ClipboardReader(system_clipboard, promise) {}
  ~ClipboardTextReader() override = default;

  ClipboardTextReader(const ClipboardTextReader&) = delete;
  ClipboardTextReader& operator=(const ClipboardTextReader&) = delete;

  void Read() override {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    system_clipboard()->ReadPlainText(
        mojom::blink::ClipboardBuffer::kStandard,
        WTF::BindOnce(&ClipboardTextReader::OnRead, WrapPersistent(this)));
  }

 private:
  void OnRead(const String& plain_text) {
    if (plain_text.empty()) {
      NextRead(Vector<uint8_t>());
      return;
    }

    worker_pool::PostTask(
        FROM_HERE,
        CrossThreadBindOnce(&ClipboardTextReader::EncodeOnBackgroundThread,
                            std::move(plain_text), MakeCrossThreadHandle(this),
                            std::move(clipboard_task_runner_)));
  }

  static void EncodeOnBackgroundThread(
      String plain_text,
      CrossThreadHandle<ClipboardTextReader> reader,
      scoped_refptr<base::SingleThreadTaskRunner> clipboard_task_runner) {
    DCHECK(!IsMainThread());

    // Encode WTF String to UTF-8, the standard text format for Blobs.
    StringUTF8Adaptor utf8_text(plain_text);
    Vector<uint8_t> utf8_bytes;
    utf8_bytes.ReserveInitialCapacity(utf8_text.size());
    utf8_bytes.AppendSpan(base::span(utf8_text));

    PostCrossThreadTask(
        *clipboard_task_runner, FROM_HERE,
        CrossThreadBindOnce(
            &ClipboardTextReader::NextRead,
            MakeUnwrappingCrossThreadHandle<ClipboardTextReader>(
                std::move(reader)),
            std::move(utf8_bytes)));
  }

  void NextRead(Vector<uint8_t> utf8_bytes) override {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    Blob* blob = nullptr;
    if (utf8_bytes.size()) {
      blob = Blob::Create(utf8_bytes, kMimeTypeTextPlain);
    }
    promise_->OnRead(blob);
  }
};

// Reads HTML from the System Clipboard as a Blob with text/html content.
class ClipboardHtmlReader final : public ClipboardReader {
 public:
  explicit ClipboardHtmlReader(SystemClipboard* system_clipboard,
                               ClipboardPromise* promise,
                               bool sanitize_html)
      : ClipboardReader(system_clipboard, promise),
        sanitize_html_(sanitize_html) {}
  ~ClipboardHtmlReader() override = default;

  void Read() override {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

    promise_->GetExecutionContext()->CountUse(
        sanitize_html_ ? WebFeature::kHtmlClipboardApiRead
                       : WebFeature::kHtmlClipboardApiUnsanitizedRead);
    system_clipboard()->ReadHTML(
        WTF::BindOnce(&ClipboardHtmlReader::OnRead, WrapPersistent(this)));
  }

 private:
  void OnRead(const String& html_string,
              const KURL& url,
              unsigned fragment_start,
              unsigned fragment_end) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    DCHECK_GE(fragment_start, 0u);
    DCHECK_LE(fragment_end, html_string.length());
    DCHECK_LE(fragment_start, fragment_end);

    LocalFrame* frame = promise_->GetLocalFrame();
    if (!frame || html_string.empty()) {
      NextRead(Vector<uint8_t>());
      return;
    }

    // Process the HTML string and strip out certain security sensitive tags if
    // needed. `CreateStrictlyProcessedMarkupWithContext` must be called on the
    // main thread because HTML DOM nodes can only be used on the main thread.
    String final_html =
        sanitize_html_ ? CreateStrictlyProcessedMarkupWithContext(
                             *frame->GetDocument(), html_string, fragment_start,
                             fragment_end, url, kIncludeNode, kResolveAllURLs)
                       : html_string;
    if (final_html.empty()) {
      NextRead(Vector<uint8_t>());
      return;
    }
    worker_pool::PostTask(
        FROM_HERE,
        CrossThreadBindOnce(&ClipboardHtmlReader::EncodeOnBackgroundThread,
                            std::move(final_html), MakeCrossThreadHandle(this),
                            std::move(clipboard_task_runner_)));
  }

  static void EncodeOnBackgroundThread(
      String plain_text,
      CrossThreadHandle<ClipboardHtmlReader> reader,
      scoped_refptr<base::SingleThreadTaskRunner> clipboard_task_runner) {
    DCHECK(!IsMainThread());

    // Encode WTF String to UTF-8, the standard text format for blobs.
    StringUTF8Adaptor utf8_text(plain_text);
    Vector<uint8_t> utf8_bytes;
    utf8_bytes.ReserveInitialCapacity(utf8_text.size());
    utf8_bytes.AppendSpan(base::span(utf8_text));

    PostCrossThreadTask(
        *clipboard_task_runner, FROM_HERE,
        CrossThreadBindOnce(&ClipboardHtmlReader::NextRead,
                            MakeUnwrappingCrossThreadHandle(std::move(reader)),
                            std::move(utf8_bytes)));
  }

  void NextRead(Vector<uint8_t> utf8_bytes) override {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    Blob* blob = nullptr;
    if (utf8_bytes.size()) {
      blob = Blob::Create(utf8_bytes, kMimeTypeTextHTML);
    }
    promise_->OnRead(blob);
  }

  bool sanitize_html_ = true;
};

// Reads SVG from the System Clipboard as a Blob with image/svg+xml content.
class ClipboardSvgReader final : public ClipboardReader {
 public:
  ClipboardSvgReader(SystemClipboard* system_clipboard,
                              ClipboardPromise* promise)
      : ClipboardReader(system_clipboard, promise) {}
  ~ClipboardSvgReader() override = default;

  // This must be called on the main thread because XML DOM nodes can
  // only be used on the main thread.
  void Read() override {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    system_clipboard()->ReadSvg(
        WTF::BindOnce(&ClipboardSvgReader::OnRead, WrapPersistent(this)));
  }

 private:
  void OnRead(const String& svg_string) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

    LocalFrame* frame = promise_->GetLocalFrame();
    if (!frame) {
      NextRead(Vector<uint8_t>());
      return;
    }

    // Now process the SVG string and strip out certain security sensitive tags.
    KURL url;
    unsigned fragment_start = 0;
    String strictly_processed_svg = CreateStrictlyProcessedMarkupWithContext(
        *frame->GetDocument(), svg_string, fragment_start, svg_string.length(),
        url, kIncludeNode, kResolveAllURLs);

    if (strictly_processed_svg.empty()) {
      NextRead(Vector<uint8_t>());
      return;
    }
    worker_pool::PostTask(
        FROM_HERE,
        CrossThreadBindOnce(&ClipboardSvgReader::EncodeOnBackgroundThread,
                            std::move(strictly_processed_svg),
                            MakeCrossThreadHandle(this),
                            std::move(clipboard_task_runner_)));
  }

  static void EncodeOnBackgroundThread(
      String plain_text,
      CrossThreadHandle<ClipboardSvgReader> reader,
      scoped_refptr<base::SingleThreadTaskRunner> clipboard_task_runner) {
    DCHECK(!IsMainThread());

    // Encode WTF String to UTF-8, the standard text format for Blobs.
    StringUTF8Adaptor utf8_text(plain_text);
    Vector<uint8_t> utf8_bytes;
    utf8_bytes.ReserveInitialCapacity(utf8_text.size());
    utf8_bytes.AppendSpan(base::span(utf8_text));

    PostCrossThreadTask(
        *clipboard_task_runner, FROM_HERE,
        CrossThreadBindOnce(&ClipboardSvgReader::NextRead,
                            MakeUnwrappingCrossThreadHandle(std::move(reader)),
                            std::move(utf8_bytes)));
  }

  void NextRead(Vector<uint8_t> utf8_bytes) override {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    Blob* blob = nullptr;
    if (utf8_bytes.size()) {
      blob = Blob::Create(utf8_bytes, kMimeTypeImageSvg);
    }
    promise_->OnRead(blob);
  }
};

// Reads unsanitized custom formats from the System Clipboard as a Blob with
// custom MIME type content.
class ClipboardCustomFormatReader final : public ClipboardReader {
 public:
  explicit ClipboardCustomFormatReader(SystemClipboard* system_clipboard,
                                       ClipboardPromise* promise,
                                       const String& mime_type)
      : ClipboardReader(system_clipboard, promise), mime_type_(mime_type) {}
  ~ClipboardCustomFormatReader() override = default;

  void Read() override {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

    system_clipboard()->ReadUnsanitizedCustomFormat(
        mime_type_,
        WTF::BindOnce(&ClipboardCustomFormatReader::OnCustomFormatRead,
                      WrapPersistent(this)));
  }

  void OnCustomFormatRead(mojo_base::BigBuffer data) {
    Blob* blob = Blob::Create(data, mime_type_);
    promise_->OnRead(blob);
  }

 private:
  void NextRead(Vector<uint8_t> utf8_bytes) override {}

  String mime_type_;
};

}  // anonymous namespace

// ClipboardReader functions.

// static
ClipboardReader* ClipboardReader::Create(SystemClipboard* system_clipboard,
                                         const String& mime_type,
                                         ClipboardPromise* promise,
                                         bool sanitize_html) {
  CHECK(ClipboardItem::supports(mime_type));
  // If this is a web custom format then read the unsanitized version.
  if (!Clipboard::ParseWebCustomFormat(mime_type).empty()) {
    // We read the custom MIME type that has the "web " prefix.
    // These MIME types are found in the web custom format map written by
    // native applications.
    return MakeGarbageCollected<ClipboardCustomFormatReader>(
        system_clipboard, promise, mime_type);
  }

  if (mime_type == kMimeTypeImagePng) {
    return MakeGarbageCollected<ClipboardPngReader>(system_clipboard, promise);
  }

  if (mime_type == kMimeTypeTextPlain) {
    return MakeGarbageCollected<ClipboardTextReader>(system_clipboard, promise);
  }

  if (mime_type == kMimeTypeTextHTML) {
    return MakeGarbageCollected<ClipboardHtmlReader>(system_clipboard, promise,
                                                     sanitize_html);
  }

  if (mime_type == kMimeTypeImageSvg) {
    return MakeGarbageCollected<ClipboardSvgReader>(system_clipboard, promise);
  }

  NOTREACHED()
      << "IsValidType() and Create() have inconsistent implementations.";
}

ClipboardReader::ClipboardReader(SystemClipboard* system_clipboard,
                                 ClipboardPromise* promise)
    : clipboard_task_runner_(promise->GetExecutionContext()->GetTaskRunner(
          TaskType::kUserInteraction)),
      promise_(promise),
      system_clipboard_(system_clipboard) {}

ClipboardReader::~ClipboardReader() = default;

void ClipboardReader::Trace(Visitor* visitor) const {
  visitor->Trace(system_clipboard_);
  visitor->Trace(promise_);
}

}  // namespace blink
```