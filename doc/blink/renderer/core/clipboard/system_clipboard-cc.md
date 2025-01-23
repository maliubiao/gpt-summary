Response:
Let's break down the thought process for analyzing this `system_clipboard.cc` file.

1. **Understand the Goal:** The request asks for a breakdown of the file's functionality, its relation to web technologies, potential errors, user actions leading to its use, and debugging tips.

2. **Initial Scan for Keywords:**  Look for obvious terms that hint at the file's purpose. "Clipboard" is central. Other important terms might include "read," "write," "HTML," "text," "image," "files," "data transfer," "selection," and mentions of browser interfaces. The copyright notice at the top confirms it's part of Chromium's Blink rendering engine.

3. **Identify Core Functionality:** Based on the keywords, it's clear this file manages interaction with the system clipboard. The methods like `ReadPlainText`, `WriteHTML`, `ReadImage`, etc., directly confirm this. The class name `SystemClipboard` reinforces this.

4. **Analyze Key Methods:**  Go through the public methods of the `SystemClipboard` class and describe what each does. Focus on the input and output types. For example:
    * `ReadPlainText()`: Reads plain text from the clipboard.
    * `WriteHTML()`: Writes HTML to the clipboard.
    * `ReadFiles()`: Reads file information from the clipboard.
    * `SetSelectionMode()`:  Indicates handling of the selection clipboard.

5. **Explore Relationships with Web Technologies:**  Consider how clipboard operations relate to JavaScript, HTML, and CSS.
    * **JavaScript:**  Think about the `navigator.clipboard` API. This file is part of the underlying implementation that makes that API work. Provide an example using `navigator.clipboard.readText()` and `navigator.clipboard.writeText()`.
    * **HTML:**  Copying and pasting content from and to HTML documents is a primary use case. Mention selecting text, images, or complex HTML structures.
    * **CSS:**  While CSS doesn't directly interact with the clipboard, the *rendering* of the copied content is affected by CSS. Mention how CSS styles are usually *not* preserved during plain text copy but *can* be (to some extent) with HTML copy.

6. **Consider Logic and Data Flow:**  Notice the `snapshot_` member. This suggests a mechanism for caching or managing clipboard data within Blink. Explain the `TakeSnapshot()` and `DropSnapshot()` methods and their purpose (likely for optimization or consistency within a specific operation).

7. **Identify Potential User/Programming Errors:** Think about common mistakes developers or users might make when dealing with the clipboard:
    * **Security Restrictions:** Browsers limit clipboard access for security reasons. Mention the requirement for user gestures.
    * **Asynchronous Operations:**  Clipboard operations (especially with `navigator.clipboard`) are often asynchronous. Explain the need for Promises and `async/await`.
    * **Format Mismatches:**  Trying to paste HTML into a plain text field, or vice versa, can lead to unexpected results.
    * **Large Data:** Copying very large amounts of data can cause performance issues or even failures.

8. **Trace User Actions to the Code:**  Think about the steps a user takes that would eventually invoke this code:
    * **Copying Text:** Selecting text and using Ctrl+C/Cmd+C or the context menu.
    * **Copying Images:** Right-clicking an image and selecting "Copy Image".
    * **Copying Files:**  Dragging and dropping files (less direct, but related to data transfer).
    * **Using JavaScript:**  Webpages using the `navigator.clipboard` API.

9. **Provide Debugging Tips:**  Suggest common debugging techniques related to clipboard issues:
    * **Browser Developer Tools:**  Look for console errors or network requests.
    * **Clipboard Viewers:**  Tools that show the contents of the system clipboard in various formats.
    * **Simplifying the Scenario:**  Testing with basic text or simple HTML to isolate the problem.
    * **Permissions:** Check browser permissions related to clipboard access.

10. **Structure and Refine:** Organize the information logically with clear headings and examples. Use bullet points or numbered lists for readability. Ensure the language is clear and concise. Avoid overly technical jargon where possible, or explain it if necessary. Review the output for clarity, accuracy, and completeness. For example, initially, I might forget to explicitly mention the asynchronous nature of the JavaScript Clipboard API, but during review, I'd realize its importance and add it. Similarly, explicitly mentioning user gestures for permissions is a crucial detail that might be added during refinement.

11. **Address Specific Instructions:** Go back to the original request and make sure all points have been addressed (functionality, relationship to web tech, logic, errors, user actions, debugging).

By following these steps, breaking down the problem, and thinking about the different aspects of clipboard interaction, we can generate a comprehensive and helpful analysis of the `system_clipboard.cc` file.
好的，让我们详细分析一下 `blink/renderer/core/clipboard/system_clipboard.cc` 这个文件。

**文件功能概述:**

`system_clipboard.cc` 文件在 Chromium Blink 渲染引擎中，负责实现与操作系统剪贴板的交互。它提供了一组接口，允许渲染进程中的代码（通常是 JavaScript 或 Blink 内部的其他 C++ 代码）读取和写入各种格式的数据到系统剪贴板。

**核心功能点:**

1. **读取剪贴板数据:**
   - 支持读取多种数据格式，包括：
     - **纯文本 (Plain Text):**  `ReadPlainText()`
     - **HTML:** `ReadHTML()` (包含 URL 和片段信息)
     - **RTF (Rich Text Format):** `ReadRTF()`
     - **PNG 图片:** `ReadPng()`
     - **文件列表:** `ReadFiles()`
     - **自定义数据:** `ReadDataTransferCustomData()` 和 `ReadUnsanitizedCustomFormat()`
     - **SVG:** `ReadSvg()`
   - 针对不同的 `ClipboardBuffer` (标准剪贴板或选择剪贴板) 进行读取。

2. **写入剪贴板数据:**
   - 支持写入多种数据格式：
     - **纯文本:** `WritePlainText()`
     - **HTML:** `WriteHTML()`
     - **图片 (SkBitmap 格式):** `WriteImage()`
     - **带有标签的图片 (用于富文本编辑器):** `WriteImageWithTag()`
     - **文件列表 (通过 `DataObject`):** `WriteDataObject()`
     - **自定义数据:** `WriteDataTransferCustomData()` 和 `WriteUnsanitizedCustomFormat()`
     - **SVG:** `WriteSvg()`
   - 可以设置智能替换标记 (`WriteSmartPasteMarker()`)。

3. **管理剪贴板状态:**
   - 获取剪贴板序列号 (`SequenceNumber()`)，用于检测剪贴板内容是否发生变化。
   - 查询特定格式的数据是否可用 (`IsFormatAvailable()`)。
   - 读取可用的数据类型列表 (`ReadAvailableTypes()`).
   - 读取可用的自定义和标准格式 (`ReadAvailableCustomAndStandardFormats()`).

4. **支持选择剪贴板:**
   - 通过 `SetSelectionMode()` 方法切换操作的剪贴板缓冲区 (标准剪贴板或选择剪贴板，例如 Linux 中的 middle-click 粘贴)。

5. **快照机制:**
   - 提供了 `TakeSnapshot()` 和 `DropSnapshot()` 方法，以及内部的 `Snapshot` 类。这允许在某个操作期间缓存剪贴板的状态，以便在后续读取操作中保持一致性，避免在一次操作中多次读取剪贴板导致数据不一致。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件是 Web 平台剪贴板 API 的底层实现的一部分。当 JavaScript 代码使用 `navigator.clipboard` API 进行剪贴板操作时，最终会调用到这个文件中的 C++ 代码。

**JavaScript:**

```javascript
// 写入文本到剪贴板
navigator.clipboard.writeText('Hello, clipboard!')
  .then(() => console.log('Text written to clipboard'))
  .catch(err => console.error('Could not copy text: ', err));

// 从剪贴板读取文本
navigator.clipboard.readText()
  .then(text => console.log('Pasted text: ', text))
  .catch(err => console.error('Could not read clipboard: ', err));

// 写入 HTML 到剪贴板 (通过 DataTransfer API，常用于拖放操作，但也可以用于复制)
const data = new DataTransfer();
data.setData('text/html', '<p>This is <b>bold</b> text.</p>');
navigator.clipboard.write(data.items); // 这里的实现会涉及到 SystemClipboard::WriteHTML

// 从剪贴板读取 HTML (需要 Permissions API 授权)
navigator.clipboard.read()
  .then(clipboardItems => {
    clipboardItems.forEach(item => {
      item.types.forEach(type => {
        if (type === 'text/html') {
          item.getType(type).then(blob => blob.text()).then(html => console.log('Pasted HTML:', html));
        }
      });
    });
  })
  .catch(err => console.error('Could not read clipboard: ', err));
```

当 JavaScript 调用 `navigator.clipboard.writeText()` 时，Blink 内部会调用 `SystemClipboard::WritePlainText()`。当调用 `navigator.clipboard.readText()` 时，会调用 `SystemClipboard::ReadPlainText()`。

**HTML:**

用户在网页上进行复制粘贴操作，例如：

1. **选择一段文本并按下 Ctrl+C (或 Cmd+C):** 这会导致浏览器调用 `SystemClipboard::WritePlainText()` 和/或 `SystemClipboard::WriteHTML()`，具体取决于选择的内容和浏览器的实现。
2. **复制图片:** 右键点击图片选择 "复制图片"，会调用 `SystemClipboard::WriteImageWithTag()` 或 `SystemClipboard::WriteImage()`。
3. **粘贴文本到 `<textarea>` 或可编辑的 `<div>`:** 浏览器会调用 `SystemClipboard::ReadPlainText()`。
4. **粘贴 HTML 内容到富文本编辑器:** 浏览器会调用 `SystemClipboard::ReadHTML()`。

**CSS:**

CSS 本身不直接与 `system_clipboard.cc` 交互。但是，当复制和粘贴 HTML 内容时，CSS 样式是否被保留取决于浏览器的实现和目标应用程序。`system_clipboard.cc` 负责传输 HTML 结构和内容，而样式的处理通常由接收方负责。

**逻辑推理 (假设输入与输出):**

**假设输入 (用户复制操作):**

- 用户在网页上选中了以下 HTML 片段并按下 Ctrl+C：
  ```html
  <p>This is <b>bold</b> text with a <a href="https://example.com">link</a>.</p>
  ```

**预期输出 (SystemClipboard 的写入操作):**

- `SystemClipboard::WritePlainText()` 可能会被调用，写入纯文本内容："This is bold text with a link."
- `SystemClipboard::WriteHTML()` 可能会被调用，写入 HTML 内容：
  ```html
  <meta http-equiv="content-type" content="text/html; charset=utf-8">
  <p>This is <b>bold</b> text with a <a href="https://example.com">link</a>.</p>
  ```
  同时，`document_url` 参数可能是当前页面的 URL。

**假设输入 (用户粘贴操作):**

- 用户在一个 `<textarea>` 元素中按下 Ctrl+V。
- 系统剪贴板中包含以下纯文本内容："Pasted from clipboard"

**预期输出 (SystemClipboard 的读取操作):**

- `SystemClipboard::ReadPlainText()` 会被调用。
- 该方法会返回字符串："Pasted from clipboard"。

**用户或编程常见的使用错误及举例说明:**

1. **未处理异步操作:** JavaScript 的 `navigator.clipboard` API 是异步的，如果开发者没有正确使用 Promises 或 async/await，可能会在剪贴板操作完成之前就尝试使用结果，导致错误。

   ```javascript
   // 错误示例：未等待剪贴板写入完成
   navigator.clipboard.writeText('Some text');
   console.log('Text might have been written.'); // 实际可能还没完成

   // 正确示例：使用 then() 或 async/await
   navigator.clipboard.writeText('Some text').then(() => {
     console.log('Text written successfully.');
   });

   async function copyText() {
     await navigator.clipboard.writeText('Another text');
     console.log('Text written successfully (async).');
   }
   ```

2. **安全限制导致的权限错误:** 浏览器出于安全考虑，限制了对剪贴板的访问。例如，在没有用户手势的情况下，网页可能无法无限制地读写剪贴板。这会导致 `navigator.clipboard.readText()` 或 `navigator.clipboard.writeText()` 抛出异常。

   ```javascript
   // 可能会因为没有用户手势而失败
   document.addEventListener('DOMContentLoaded', () => {
     navigator.clipboard.readText()
       .then(text => console.log('Read text:', text))
       .catch(err => console.error('Could not read clipboard:', err));
   });

   // 通常需要在用户交互事件中进行剪贴板操作
   document.getElementById('pasteButton').addEventListener('click', async () => {
     try {
       const text = await navigator.clipboard.readText();
       console.log('Pasted text:', text);
     } catch (err) {
       console.error('Could not read clipboard:', err);
     }
   });
   ```

3. **尝试读取不存在的格式:**  如果代码尝试读取剪贴板中不存在的数据格式，例如，尝试读取 HTML 但剪贴板中只有纯文本，则读取方法可能会返回空字符串或 null。

   ```javascript
   // 假设剪贴板只有纯文本
   navigator.clipboard.read()
     .then(clipboardItems => {
       clipboardItems.forEach(item => {
         if (item.types.includes('text/html')) {
           item.getType('text/html').then(blob => blob.text()).then(html => console.log('HTML:', html));
         } else {
           console.log('No HTML format found.');
         }
       });
     });
   ```

**用户操作如何一步步到达这里 (调试线索):**

1. **用户发起复制操作:**
   - 用户在浏览器中选择文本、图片或其他内容。
   - 用户按下 Ctrl+C (或 Cmd+C)，或者右键点击并选择 "复制"。
   - 浏览器的渲染进程接收到该事件。
   - Blink 引擎中的事件处理代码会识别这是一个复制操作。
   - 如果是文本或 HTML，可能会调用 `document.execCommand('copy')` 的实现，最终会调用到 `SystemClipboard` 的写入方法 (如 `WritePlainText`, `WriteHTML`)。
   - 如果是图片，可能涉及到图像元素的上下文菜单处理，最终调用 `SystemClipboard::WriteImageWithTag` 或 `WriteImage`。

2. **用户发起粘贴操作:**
   - 用户在浏览器中的某个可编辑区域（如 `<textarea>`, `contenteditable` 元素）按下 Ctrl+V (或 Cmd+V)，或者右键点击并选择 "粘贴"。
   - 浏览器的渲染进程接收到粘贴事件。
   - Blink 引擎中的事件处理代码会识别这是一个粘贴操作.
   - 根据上下文，可能会调用 `document.execCommand('paste')` 的实现，或者由 JavaScript 代码通过 `navigator.clipboard.readText()` 或 `navigator.clipboard.read()` 发起读取请求。
   - 这些 JavaScript API 的调用会最终到达 `SystemClipboard` 的读取方法 (如 `ReadPlainText`, `ReadHTML`, `ReadFiles`)。

3. **网页 JavaScript 代码使用 `navigator.clipboard` API:**
   - 开发者在网页的 JavaScript 代码中调用 `navigator.clipboard.writeText()`, `navigator.clipboard.readText()`, `navigator.clipboard.write()`, `navigator.clipboard.read()` 等方法。
   - 这些 JavaScript API 的实现会通过 Blink 的内部机制 (如消息传递) 调用到 `system_clipboard.cc` 中的相应方法。

**调试线索:**

- **断点:** 在 `system_clipboard.cc` 中设置断点，例如在 `WritePlainText`、`ReadHTML` 等方法的入口处，可以观察代码执行流程和剪贴板数据的变化。
- **日志输出:** 在关键方法中添加 `DLOG` 或 `DVLOG` 输出，记录传入的参数和执行结果。
- **Tracing:** 使用 Chromium 的 tracing 工具 (chrome://tracing) 可以捕获更详细的事件信息，包括剪贴板操作的调用栈。
- **审查 JavaScript 代码:** 检查网页 JavaScript 代码中是否正确使用了 `navigator.clipboard` API，是否有处理异步操作和权限错误的逻辑。
- **查看浏览器控制台:**  检查是否有与剪贴板操作相关的错误或警告信息。
- **使用剪贴板查看器:**  操作系统通常有第三方的剪贴板查看器，可以查看当前剪贴板中存储的各种格式的数据，有助于了解剪贴板的实际内容。

总而言之，`system_clipboard.cc` 是 Blink 引擎中处理与操作系统剪贴板交互的关键组件，它连接了 Web 平台提供的剪贴板 API 和底层的操作系统剪贴板功能。理解其功能对于调试与剪贴板相关的 Web 应用问题至关重要。

### 提示词
```
这是目录为blink/renderer/core/clipboard/system_clipboard.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/clipboard/system_clipboard.h"

#include "base/memory/scoped_refptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "build/build_config.h"
#include "mojo/public/cpp/base/big_buffer.h"
#include "mojo/public/cpp/system/platform_handle.h"
#include "skia/ext/skia_utils_base.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_drag_data.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/renderer/core/clipboard/clipboard_mime_types.h"
#include "third_party/blink/renderer/core/clipboard/clipboard_utilities.h"
#include "third_party/blink/renderer/core/clipboard/data_object.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/platform/graphics/image.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/skia/include/core/SkBitmap.h"

namespace blink {

namespace {

String NonNullString(const String& string) {
  return string.IsNull() ? g_empty_string16_bit : string;
}

// This function is needed to clone a PendingRemote because normally they are
// not clonable.  The input PendingRemote is "cloned" twice, so one of those
// copies is intended to replace the original PendingRemote passed in by the
// caller.
std::pair<mojo::PendingRemote<mojom::blink::FileSystemAccessDataTransferToken>,
          mojo::PendingRemote<mojom::blink::FileSystemAccessDataTransferToken>>
CloneFsaToken(
    mojo::PendingRemote<mojom::blink::FileSystemAccessDataTransferToken> in) {
  if (!in.is_valid()) {
    return {mojo::NullRemote(), mojo::NullRemote()};
  }
  mojo::Remote remote(std::move(in));
  mojo::PendingRemote<mojom::blink::FileSystemAccessDataTransferToken> copy;
  remote->Clone(copy.InitWithNewPipeAndPassReceiver());
  return {remote.Unbind(), std::move(copy)};
}

}  // namespace

SystemClipboard::SystemClipboard(LocalFrame* frame)
    : clipboard_(frame->DomWindow()) {
  frame->GetBrowserInterfaceBroker().GetInterface(
      clipboard_.BindNewPipeAndPassReceiver(
          frame->GetTaskRunner(TaskType::kUserInteraction)));
#if BUILDFLAG(IS_OZONE)
  is_selection_buffer_available_ =
      frame->GetSettings()->GetSelectionClipboardBufferAvailable();
#endif  // BUILDFLAG(IS_OZONE)
}

bool SystemClipboard::IsSelectionMode() const {
  return buffer_ == mojom::blink::ClipboardBuffer::kSelection;
}

void SystemClipboard::SetSelectionMode(bool selection_mode) {
  buffer_ = selection_mode ? mojom::blink::ClipboardBuffer::kSelection
                           : mojom::blink::ClipboardBuffer::kStandard;
}

bool SystemClipboard::IsFormatAvailable(blink::mojom::ClipboardFormat format) {
  if (!IsValidBufferType(buffer_) || !clipboard_.is_bound())
    return false;
  bool result = false;
  clipboard_->IsFormatAvailable(format, buffer_, &result);
  return result;
}

ClipboardSequenceNumberToken SystemClipboard::SequenceNumber() {
  if (!IsValidBufferType(buffer_) || !clipboard_.is_bound())
    return ClipboardSequenceNumberToken();
  ClipboardSequenceNumberToken result;
  clipboard_->GetSequenceNumber(buffer_, &result);
  return result;
}

Vector<String> SystemClipboard::ReadAvailableTypes() {
  if (!IsValidBufferType(buffer_) || !clipboard_.is_bound())
    return {};
  Vector<String> types;
  clipboard_->ReadAvailableTypes(buffer_, &types);
  return types;
}

String SystemClipboard::ReadPlainText() {
  return ReadPlainText(buffer_);
}

String SystemClipboard::ReadPlainText(mojom::blink::ClipboardBuffer buffer) {
  if (!IsValidBufferType(buffer) || !clipboard_.is_bound())
    return String();

  if (snapshot_ && snapshot_->HasPlainText(buffer)) {
    return snapshot_->PlainText(buffer);
  }

  String text;
  clipboard_->ReadText(buffer, &text);
  if (snapshot_) {
    snapshot_->SetPlainText(buffer, text);
  }

  return text;
}

void SystemClipboard::ReadPlainText(
    mojom::blink::ClipboardBuffer buffer,
    mojom::blink::ClipboardHost::ReadTextCallback callback) {
  if (!IsValidBufferType(buffer) || !clipboard_.is_bound()) {
    std::move(callback).Run(String());
    return;
  }
  clipboard_->ReadText(buffer, std::move(callback));
}

void SystemClipboard::WritePlainText(const String& plain_text,
                                     SmartReplaceOption) {
  DCHECK(!snapshot_);

  if (!clipboard_.is_bound())
    return;
  // TODO(https://crbug.com/106449): add support for smart replace, which is
  // currently under-specified.
  String text = plain_text;
#if BUILDFLAG(IS_WIN)
  ReplaceNewlinesWithWindowsStyleNewlines(text);
#endif
  clipboard_->WriteText(NonNullString(text));
}

String SystemClipboard::ReadHTML(KURL& url,
                                 unsigned& fragment_start,
                                 unsigned& fragment_end) {
  if (!IsValidBufferType(buffer_) || !clipboard_.is_bound()) {
    url = KURL();
    fragment_start = 0;
    fragment_end = 0;
    return String();
  }

  if (snapshot_ && snapshot_->HasHtml(buffer_)) {
    url = snapshot_->Url(buffer_);
    fragment_start = snapshot_->FragmentStart(buffer_);
    fragment_end = snapshot_->FragmentEnd(buffer_);
    return snapshot_->Html(buffer_);
  }

  // NOTE: `fragment_start` and `fragment_end` can be the same reference, so
  // use local variables here to make sure the snapshot is set correctly.
  String html;
  uint32_t local_fragment_start;
  uint32_t local_fragment_end;
  clipboard_->ReadHtml(buffer_, &html, &url, &local_fragment_start,
                       &local_fragment_end);
  if (html.empty()) {
    url = KURL();
    local_fragment_start = 0;
    local_fragment_end = 0;
  }

  if (snapshot_) {
    snapshot_->SetHtml(buffer_, html, url, local_fragment_start,
                       local_fragment_end);
  }

  fragment_start = local_fragment_start;
  fragment_end = local_fragment_end;
  return html;
}

void SystemClipboard::ReadHTML(
    mojom::blink::ClipboardHost::ReadHtmlCallback callback) {
  if (!IsValidBufferType(buffer_) || !clipboard_.is_bound()) {
    std::move(callback).Run(String(), KURL(), 0, 0);
    return;
  }
  clipboard_->ReadHtml(buffer_, std::move(callback));
}

void SystemClipboard::WriteHTML(const String& markup,
                                const KURL& document_url,
                                SmartReplaceOption smart_replace_option) {
  DCHECK(!snapshot_);

  if (!clipboard_.is_bound())
    return;
  clipboard_->WriteHtml(NonNullString(markup), document_url);
  if (smart_replace_option == kCanSmartReplace)
    clipboard_->WriteSmartPasteMarker();
}

void SystemClipboard::ReadSvg(
    mojom::blink::ClipboardHost::ReadSvgCallback callback) {
  if (!IsValidBufferType(buffer_) || !clipboard_.is_bound()) {
    std::move(callback).Run(String());
    return;
  }
  clipboard_->ReadSvg(buffer_, std::move(callback));
}

void SystemClipboard::WriteSvg(const String& markup) {
  DCHECK(!snapshot_);

  if (!clipboard_.is_bound())
    return;
  clipboard_->WriteSvg(NonNullString(markup));
}

String SystemClipboard::ReadRTF() {
  if (!IsValidBufferType(buffer_) || !clipboard_.is_bound())
    return String();

  if (snapshot_ && snapshot_->HasRtf(buffer_)) {
    return snapshot_->Rtf(buffer_);
  }

  String rtf;
  clipboard_->ReadRtf(buffer_, &rtf);
  if (snapshot_) {
    snapshot_->SetRtf(buffer_, rtf);
  }

  return rtf;
}

mojo_base::BigBuffer SystemClipboard::ReadPng(
    mojom::blink::ClipboardBuffer buffer) {
  if (!IsValidBufferType(buffer) || !clipboard_.is_bound())
    return mojo_base::BigBuffer();

  if (snapshot_ && snapshot_->HasPng(buffer)) {
    return snapshot_->Png(buffer);
  }

  mojo_base::BigBuffer png;
  clipboard_->ReadPng(buffer, &png);
  if (snapshot_) {
    snapshot_->SetPng(buffer, png);
  }

  return png;
}

String SystemClipboard::ReadImageAsImageMarkup(
    mojom::blink::ClipboardBuffer buffer) {
  mojo_base::BigBuffer png_data = ReadPng(buffer);
  return PNGToImageMarkup(png_data);
}

void SystemClipboard::WriteImageWithTag(Image* image,
                                        const KURL& url,
                                        const String& title) {
  DCHECK(!snapshot_);
  DCHECK(image);

  if (!clipboard_.is_bound())
    return;

  PaintImage paint_image = image->PaintImageForCurrentFrame();
  // Orient the data.
  if (!image->HasDefaultOrientation()) {
    paint_image = Image::ResizeAndOrientImage(
        paint_image, image->CurrentFrameOrientation(), gfx::Vector2dF(1, 1), 1,
        kInterpolationNone);
  }
  SkBitmap bitmap;
  if (sk_sp<SkImage> sk_image = paint_image.GetSwSkImage())
    sk_image->asLegacyBitmap(&bitmap);

  // The bitmap backing a canvas can be in non-native skia pixel order (aka
  // RGBA when kN32_SkColorType is BGRA-ordered, or higher bit-depth color-types
  // like F16. The IPC to the browser requires the bitmap to be in N32 format
  // so we convert it here if needed.
  SkBitmap n32_bitmap;
  if (skia::SkBitmapToN32OpaqueOrPremul(bitmap, &n32_bitmap) &&
      !n32_bitmap.isNull()) {
    clipboard_->WriteImage(n32_bitmap);
  }

  if (url.IsValid() && !url.IsEmpty()) {
#if !BUILDFLAG(IS_MAC)
    // See http://crbug.com/838808: Not writing text/plain on Mac for
    // consistency between platforms, and to help fix errors in applications
    // which prefer text/plain content over image content for compatibility with
    // Microsoft Word.
    clipboard_->WriteBookmark(url.GetString(), NonNullString(title));
#endif

    // When writing the image, we also write the image markup so that pasting
    // into rich text editors, such as Gmail, reveals the image. We also don't
    // want to call writeText(), since some applications (WordPad) don't pick
    // the image if there is also a text format on the clipboard.
    clipboard_->WriteHtml(URLToImageMarkup(url, title), KURL());
  }
}

void SystemClipboard::WriteImage(const SkBitmap& bitmap) {
  DCHECK(!snapshot_);

  if (!clipboard_.is_bound())
    return;
  clipboard_->WriteImage(bitmap);
}

mojom::blink::ClipboardFilesPtr SystemClipboard::ReadFiles() {
  mojom::blink::ClipboardFilesPtr files;
  if (!IsValidBufferType(buffer_) || !clipboard_.is_bound())
    return files;

  if (snapshot_ && snapshot_->HasFiles(buffer_)) {
    return snapshot_->Files(buffer_);
  }

  clipboard_->ReadFiles(buffer_, &files);
  if (snapshot_) {
    snapshot_->SetFiles(buffer_, files);
  }

  return files;
}

String SystemClipboard::ReadDataTransferCustomData(const String& type) {
  if (!IsValidBufferType(buffer_) || !clipboard_.is_bound())
    return String();

  if (snapshot_ && snapshot_->HasCustomData(buffer_, type)) {
    return snapshot_->CustomData(buffer_, type);
  }

  String data;
  clipboard_->ReadDataTransferCustomData(buffer_, NonNullString(type), &data);
  if (snapshot_) {
    snapshot_->SetCustomData(buffer_, type, data);
  }

  return data;
}

void SystemClipboard::WriteDataObject(DataObject* data_object) {
  DCHECK(!snapshot_);
  DCHECK(data_object);
  if (!clipboard_.is_bound())
    return;
  // This plagiarizes the logic in DropDataBuilder::Build, but only extracts the
  // data needed for the implementation of WriteDataObject.
  //
  // We avoid calling the WriteFoo functions if there is no data associated with
  // a type. This prevents stomping on clipboard contents that might have been
  // written by extension functions such as chrome.bookmarkManagerPrivate.copy.
  //
  // TODO(crbug.com/332555471): Use a mojo struct to send web_drag_data and
  // allow receiving side to extract the data required.
  // TODO(crbug.com/332571415): Properly support text/uri-list here.
  HashMap<String, String> custom_data;
  WebDragData data = data_object->ToWebDragData();
  for (const WebDragData::Item& item : data.Items()) {
    if (const auto* string_item =
            absl::get_if<WebDragData::StringItem>(&item)) {
      if (string_item->type == kMimeTypeTextPlain) {
        clipboard_->WriteText(NonNullString(string_item->data));
      } else if (string_item->type == kMimeTypeTextHTML) {
        clipboard_->WriteHtml(NonNullString(string_item->data), KURL());
      } else if (string_item->type != kMimeTypeDownloadURL) {
        custom_data.insert(string_item->type, NonNullString(string_item->data));
      }
    }
  }
  if (!custom_data.empty()) {
    clipboard_->WriteDataTransferCustomData(std::move(custom_data));
  }
}

void SystemClipboard::CommitWrite() {
  DCHECK(!snapshot_);
  if (!clipboard_.is_bound())
    return;
  clipboard_->CommitWrite();
}

void SystemClipboard::CopyToFindPboard(const String& text) {
#if BUILDFLAG(IS_MAC)
  if (!clipboard_.is_bound())
    return;
  clipboard_->WriteStringToFindPboard(text);
#endif
}

void SystemClipboard::ReadAvailableCustomAndStandardFormats(
    mojom::blink::ClipboardHost::ReadAvailableCustomAndStandardFormatsCallback
        callback) {
  if (!clipboard_.is_bound())
    return;
  clipboard_->ReadAvailableCustomAndStandardFormats(std::move(callback));
}

void SystemClipboard::ReadUnsanitizedCustomFormat(
    const String& type,
    mojom::blink::ClipboardHost::ReadUnsanitizedCustomFormatCallback callback) {
  // TODO(crbug.com/332555472): Add test coverage for all functions with this
  //  check in `SystemClipboard` and consider if it's appropriate to throw
  // exceptions or reject promises if the context is detached.
  if (!clipboard_.is_bound())
    return;
  // The format size restriction is added in `ClipboardItem::supports`.
  DCHECK_LT(type.length(), mojom::blink::ClipboardHost::kMaxFormatSize);
  clipboard_->ReadUnsanitizedCustomFormat(type, std::move(callback));
}

void SystemClipboard::WriteUnsanitizedCustomFormat(const String& type,
                                                   mojo_base::BigBuffer data) {
  DCHECK(!snapshot_);

  if (!clipboard_.is_bound() ||
      data.size() >= mojom::blink::ClipboardHost::kMaxDataSize) {
    return;
  }
  // The format size restriction is added in `ClipboardItem::supports`.
  DCHECK_LT(type.length(), mojom::blink::ClipboardHost::kMaxFormatSize);
  clipboard_->WriteUnsanitizedCustomFormat(type, std::move(data));
}

void SystemClipboard::Trace(Visitor* visitor) const {
  visitor->Trace(clipboard_);
}

bool SystemClipboard::IsValidBufferType(mojom::blink::ClipboardBuffer buffer) {
  switch (buffer) {
    case mojom::blink::ClipboardBuffer::kStandard:
      return true;
    case mojom::blink::ClipboardBuffer::kSelection:
      return is_selection_buffer_available_;
  }
  return true;
}

void SystemClipboard::TakeSnapshot() {
  ++snapshot_count_;
  if (snapshot_count_ == 1) {
    DCHECK(!snapshot_);
    snapshot_ = std::make_unique<Snapshot>();
  }
}

void SystemClipboard::DropSnapshot() {
  DCHECK_GT(snapshot_count_, 0u);
  --snapshot_count_;
  if (snapshot_count_ == 0) {
    snapshot_.reset();
  }
}

SystemClipboard::Snapshot::Snapshot() = default;

SystemClipboard::Snapshot::~Snapshot() = default;

bool SystemClipboard::Snapshot::HasPlainText(
    mojom::blink::ClipboardBuffer buffer) const {
  return buffer_.has_value() && plain_text_.has_value();
}

const String& SystemClipboard::Snapshot::PlainText(
    mojom::blink::ClipboardBuffer buffer) const {
  DCHECK(HasPlainText(buffer));
  return plain_text_.value();
}

void SystemClipboard::Snapshot::SetPlainText(
    mojom::blink::ClipboardBuffer buffer,
    const String& text) {
  BindToBuffer(buffer);
  plain_text_ = text;
}

bool SystemClipboard::Snapshot::HasHtml(
    mojom::blink::ClipboardBuffer buffer) const {
  return buffer_.has_value() && html_.has_value();
}

const KURL& SystemClipboard::Snapshot::Url(
    mojom::blink::ClipboardBuffer buffer) const {
  DCHECK(HasHtml(buffer));
  return url_;
}

unsigned SystemClipboard::Snapshot::FragmentStart(
    mojom::blink::ClipboardBuffer buffer) const {
  DCHECK(HasHtml(buffer));
  return fragment_start_;
}

unsigned SystemClipboard::Snapshot::FragmentEnd(
    mojom::blink::ClipboardBuffer buffer) const {
  DCHECK(HasHtml(buffer));
  return fragment_end_;
}

const String& SystemClipboard::Snapshot::Html(
    mojom::blink::ClipboardBuffer buffer) const {
  DCHECK(HasHtml(buffer));
  return html_.value();
}

void SystemClipboard::Snapshot::SetHtml(mojom::blink::ClipboardBuffer buffer,
                                        const String& html,
                                        const KURL& url,
                                        unsigned fragment_start,
                                        unsigned fragment_end) {
  BindToBuffer(buffer);
  html_ = html;
  url_ = url;
  fragment_start_ = fragment_start;
  fragment_end_ = fragment_end;
}

bool SystemClipboard::Snapshot::HasRtf(
    mojom::blink::ClipboardBuffer buffer) const {
  return buffer_.has_value() && rtf_.has_value();
}

const String& SystemClipboard::Snapshot::Rtf(
    mojom::blink::ClipboardBuffer buffer) const {
  DCHECK(HasRtf(buffer));
  return rtf_.value();
}

void SystemClipboard::Snapshot::SetRtf(mojom::blink::ClipboardBuffer buffer,
                                       const String& rtf) {
  BindToBuffer(buffer);
  rtf_ = rtf;
}

bool SystemClipboard::Snapshot::HasPng(
    mojom::blink::ClipboardBuffer buffer) const {
  return buffer_.has_value() && png_.has_value();
}

mojo_base::BigBuffer SystemClipboard::Snapshot::Png(
    mojom::blink::ClipboardBuffer buffer) const {
  DCHECK(HasPng(buffer));
  // Make an owning copy of the png to return to user.
  base::span<const uint8_t> span = base::make_span(png_.value());
  return mojo_base::BigBuffer(span);
}

// TODO(https://crbug.com/1412180): Reduce data copies.
void SystemClipboard::Snapshot::SetPng(mojom::blink::ClipboardBuffer buffer,
                                       const mojo_base::BigBuffer& png) {
  BindToBuffer(buffer);
  // Make an owning copy of the png to save locally.
  base::span<const uint8_t> span = base::make_span(png);
  png_ = mojo_base::BigBuffer(span);
}

bool SystemClipboard::Snapshot::HasFiles(
    mojom::blink::ClipboardBuffer buffer) const {
  return buffer_.has_value() && files_.has_value();
}

mojom::blink::ClipboardFilesPtr SystemClipboard::Snapshot::Files(
    mojom::blink::ClipboardBuffer buffer) const {
  DCHECK(HasFiles(buffer));
  return CloneFiles(files_.value());
}

void SystemClipboard::Snapshot::SetFiles(
    mojom::blink::ClipboardBuffer buffer,
    mojom::blink::ClipboardFilesPtr& files) {
  BindToBuffer(buffer);
  files_ = CloneFiles(files);
}

bool SystemClipboard::Snapshot::HasCustomData(
    mojom::blink::ClipboardBuffer buffer,
    const String& type) const {
  return buffer_.has_value() && custom_data_.Contains(type);
}

String SystemClipboard::Snapshot::CustomData(
    mojom::blink::ClipboardBuffer buffer,
    const String& type) const {
  DCHECK(HasCustomData(buffer, type));
  return custom_data_.at(type);
}

void SystemClipboard::Snapshot::SetCustomData(
    mojom::blink::ClipboardBuffer buffer,
    const String& type,
    const String& data) {
  BindToBuffer(buffer);
  custom_data_.Set(type, data);
}

// static
mojom::blink::ClipboardFilesPtr SystemClipboard::Snapshot::CloneFiles(
    mojom::blink::ClipboardFilesPtr& files) {
  if (!files) {
    return {};
  }

  WTF::Vector<mojom::blink::DataTransferFilePtr> vec;
  for (auto& dtf : files->files) {
    auto clones = CloneFsaToken(std::move(dtf->file_system_access_token));
    dtf->file_system_access_token = std::move(clones.first);
    vec.emplace_back(mojom::blink::DataTransferFile::New(
        dtf->path, dtf->display_name, std::move(clones.second)));
  }

  return mojom::blink::ClipboardFiles::New(std::move(vec),
                                           files->file_system_id);
}

void SystemClipboard::Snapshot::BindToBuffer(
    mojom::blink::ClipboardBuffer buffer) {
  if (!buffer_) {
    buffer_ = buffer;
  } else {
    DCHECK_EQ(*buffer_, buffer);
  }
}

ScopedSystemClipboardSnapshot::ScopedSystemClipboardSnapshot(
    SystemClipboard& clipboard)
    : clipboard_(clipboard) {
  clipboard.TakeSnapshot();
}

ScopedSystemClipboardSnapshot::~ScopedSystemClipboardSnapshot() {
  clipboard_.DropSnapshot();
}

}  // namespace blink
```