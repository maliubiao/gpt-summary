Response:
Let's break down the thought process for analyzing the given C++ test file.

1. **Understand the Goal:** The request is to analyze a C++ test file for a Chromium component related to the system clipboard. The key is to identify its functionality, its relation to web technologies, its testing methodology, and potential user/developer errors.

2. **Identify the Core Class Under Test:** The filename `system_clipboard_test.cc` and the class name `SystemClipboardTest` immediately point to `SystemClipboard` as the main class being tested. The `#include "third_party/blink/renderer/core/clipboard/system_clipboard.h"` confirms this.

3. **Examine the Test Structure:**  The code uses Google Test (`TEST_F`). This means each `TEST_F` function focuses on testing a specific aspect or method of the `SystemClipboard` class.

4. **Analyze Individual Tests (Iterative Process):**  Go through each `TEST_F` function and determine what it's testing. Look at the actions performed and the assertions made (`EXPECT_EQ`, `EXPECT_NE`, `EXPECT_TRUE`, `EXPECT_FALSE`).

   * **`Text`:** Tests reading plain text from the clipboard and the behavior of the `ScopedSystemClipboardSnapshot`. It checks that the snapshot remembers the clipboard state at the time of creation.

   * **`Html`:**  Similar to `Text`, but focuses on HTML content and also verifies the associated URL.

   * **`ReadHtml_SameFragmentArgs`:**  A more nuanced test for the `ReadHTML` function, specifically checking if using the same variable for start and end fragment indices causes issues within the snapshot.

   * **`Rtf`:** Tests reading RTF (Rich Text Format) content.

   * **`Png`:** Tests reading image data (PNG format). This involves encoding and decoding using `gfx::PNGCodec`.

   * **`Files`:** Tests reading lists of files from the clipboard.

   * **`CustomData`:** Tests reading custom data associated with clipboard content.

   * **`SnapshotNesting`:** Tests the behavior of nested `ScopedSystemClipboardSnapshot` objects. Confirms that the outer snapshot remains effective even when inner snapshots are created and destroyed.

   * **`ReadTextWithUnboundClipboardHost` (and similar tests for other data types):**  These tests are crucial. They simulate a scenario where the connection to the underlying clipboard host (via Mojo) is lost. This verifies the robustness of the `SystemClipboard` class in handling such disconnection. They check if read operations return default/empty values and if subsequent write operations fail gracefully.

   * **`IsFormatAvailableWithUnboundClipboardHost`:** Tests if the `IsFormatAvailable` method correctly handles a disconnected clipboard host.

   * **`ReadAvailableTypesWithUnboundClipboardHost`:**  Tests if the `ReadAvailableTypes` method behaves correctly when the host is unbound.

   * **`SequenceNumberWithUnboundClipboardHost`:** Tests the behavior of the clipboard sequence number, especially when the connection to the host is lost and re-established (implicitly by the test setup).

5. **Identify Functionality Based on Tests:**  From the individual test analysis, we can compile a list of functionalities of the `SystemClipboard` class:
    * Reading plain text, HTML, RTF, PNG images, and lists of files.
    * Reading custom data.
    * Checking if a specific format is available.
    * Getting a list of available formats.
    * Obtaining a sequence number for clipboard changes.
    * Providing a snapshot mechanism to preserve clipboard state.

6. **Relate to Web Technologies:** Consider how clipboard operations interact with JavaScript, HTML, and CSS in a web browser.

   * **JavaScript:** The primary way web pages interact with the clipboard is through the Clipboard API (`navigator.clipboard`). The `SystemClipboard` class is the underlying implementation that the browser's JavaScript engine interacts with. Think about `navigator.clipboard.readText()`, `navigator.clipboard.read()`, `navigator.clipboard.writeText()`, `navigator.clipboard.write()`. Drag-and-drop operations also involve the clipboard.

   * **HTML:** Copying and pasting content within an HTML document, or between different applications, relies on the clipboard. The format of the copied content (plain text, HTML with formatting) is crucial.

   * **CSS:** CSS styles might influence what gets copied (e.g., selecting styled text). However, the `SystemClipboard` itself primarily deals with the *data* being copied, not the visual styling.

7. **Identify Logical Reasoning and Assumptions:**

   * **Snapshot Mechanism:** The core logic of the `ScopedSystemClipboardSnapshot` is to capture the clipboard state at a specific point in time. This assumes that reading from the system clipboard is an operation that can be temporarily frozen.

   * **Unbound Clipboard Host:** The tests for unbound hosts assume that the underlying communication with the operating system's clipboard can fail. This is a realistic scenario (e.g., browser sandbox restrictions, inter-process communication issues).

8. **Consider User and Programming Errors:**

   * **User Errors:**  Think about common user actions related to copying and pasting and how they might interact with the clipboard. For example, trying to paste when nothing is copied, or unexpected data formats.

   * **Programming Errors:** Developers might incorrectly handle asynchronous clipboard operations, assume the clipboard always contains data in a specific format, or forget to handle potential errors when interacting with the Clipboard API.

9. **Trace User Operations (Debugging Clues):**  Think about the sequence of actions a user might take that would eventually lead to the execution of code involving the `SystemClipboard`. This helps understand the context and potential debugging paths. Standard copy/paste actions (Ctrl+C/Ctrl+V or Cmd+C/Cmd+V), context menu options, and drag-and-drop are the primary user interactions.

10. **Refine and Organize:**  Structure the findings clearly, using headings and bullet points to present the information in an easy-to-understand manner. Provide concrete examples to illustrate the concepts. Ensure the language is precise and avoids jargon where possible.

By following these steps, you can effectively analyze the given C++ test file and extract the requested information. The key is to understand the purpose of the tests, the functionality of the class being tested, and its role within the larger web browser architecture.
这个文件 `system_clipboard_test.cc` 是 Chromium Blink 引擎中用于测试 `SystemClipboard` 类的单元测试文件。`SystemClipboard` 类负责与操作系统级别的剪贴板进行交互，允许网页读取和写入剪贴板内容。

**功能列表:**

1. **测试读取纯文本剪贴板:** 验证 `SystemClipboard::ReadPlainText()` 方法能够正确读取系统剪贴板中的纯文本内容。
2. **测试读取 HTML 剪贴板:** 验证 `SystemClipboard::ReadHTML()` 方法能够正确读取系统剪贴板中的 HTML 内容，并能获取相关的 URL 信息。
3. **测试读取 RTF (Rich Text Format) 剪贴板:** 验证 `SystemClipboard::ReadRTF()` 方法能够正确读取系统剪贴板中的 RTF 内容。
4. **测试读取 PNG 图像剪贴板:** 验证 `SystemClipboard::ReadPng()` 方法能够正确读取系统剪贴板中的 PNG 图像数据。
5. **测试读取文件列表剪贴板:** 验证 `SystemClipboard::ReadFiles()` 方法能够正确读取系统剪贴板中的文件列表信息。
6. **测试读取自定义数据剪贴板:** 验证 `SystemClipboard::ReadDataTransferCustomData()` 方法能够读取系统剪贴板中特定类型的自定义数据。
7. **测试剪贴板快照功能 (Snapshot):** 验证 `ScopedSystemClipboardSnapshot` 类能够创建一个剪贴板状态的快照，在快照期间读取到的剪贴板内容保持不变，即使系统剪贴板内容发生变化。这对于某些需要读取一致性剪贴板数据的场景非常重要。
8. **测试嵌套剪贴板快照:** 验证 `ScopedSystemClipboardSnapshot` 可以嵌套使用，并且内外层的快照能够正确隔离。
9. **测试在与剪贴板宿主 (ClipboardHost) 断开连接时的行为:** 验证当与负责与操作系统交互的 `ClipboardHost` 断开连接时，`SystemClipboard` 的读取操作会返回默认值或空值，并且写入操作会失败。
10. **测试 `IsFormatAvailable()` 方法:** 验证 `IsFormatAvailable()` 方法能够正确判断系统剪贴板中是否存在指定格式的数据。
11. **测试 `ReadAvailableTypes()` 方法:** 验证 `ReadAvailableTypes()` 方法能够正确返回系统剪贴板中可用的数据类型列表。
12. **测试 `SequenceNumber()` 方法:** 验证 `SequenceNumber()` 方法能够获取剪贴板的序列号，并且在剪贴板内容发生变化时，序列号也会发生变化。

**与 JavaScript, HTML, CSS 的关系:**

`SystemClipboard` 类是浏览器底层实现的一部分，它直接服务于更高层的 Web API，例如 JavaScript 的 Clipboard API。

* **JavaScript:**
    * 当 JavaScript 代码使用 `navigator.clipboard.readText()` 读取剪贴板文本时，最终会调用到 `SystemClipboard::ReadPlainText()` 方法。
    * 当 JavaScript 代码使用 `navigator.clipboard.read()` 读取剪贴板的富文本或文件时，会涉及到 `SystemClipboard::ReadHTML()`, `SystemClipboard::ReadRTF()`, `SystemClipboard::ReadFiles()` 等方法。
    * 当 JavaScript 代码使用 `navigator.clipboard.writeText()` 或 `navigator.clipboard.write()` 写入剪贴板时，虽然这个测试文件没有直接测试写入功能，但 `SystemClipboard` 类肯定有相应的写入方法（在其他文件中实现），负责将数据传递给操作系统。
    * **举例说明:**
        ```javascript
        // JavaScript 代码读取剪贴板文本
        navigator.clipboard.readText().then(text => {
          console.log("剪贴板内容:", text); // 这里的 text 就是 SystemClipboard::ReadPlainText() 返回的值
        });

        // JavaScript 代码读取剪贴板 HTML
        navigator.clipboard.read().then(clipboardItems => {
          for (const clipboardItem of clipboardItems) {
            for (const type of clipboardItem.types) {
              if (type === 'text/html') {
                clipboardItem.getType(type).then(blob => {
                  blob.text().then(html => {
                    console.log("剪贴板 HTML:", html); // 这里的 html 就是 SystemClipboard::ReadHTML() 返回的值
                  });
                });
              }
            }
          }
        });
        ```

* **HTML:**
    * 用户在网页中进行复制操作（例如，选中一段文字或图片并按下 Ctrl+C），浏览器会将选中的内容以不同的格式（例如，纯文本、HTML、图片）放入系统剪贴板。`SystemClipboard` 类负责读取这些格式的数据。
    * 当用户在网页中进行粘贴操作（例如，按下 Ctrl+V），浏览器会从系统剪贴板读取数据，并根据上下文将数据插入到网页中。`SystemClipboard` 类负责读取剪贴板中的数据。
    * **举例说明:** 用户复制了一段包含格式的文本（例如，加粗、斜体），浏览器会将这段文本的 HTML 表示形式放入剪贴板。`SystemClipboard::ReadHTML()` 方法就负责读取这个 HTML 内容。

* **CSS:**
    * CSS 主要负责网页内容的样式呈现，它本身不直接参与剪贴板操作。但是，用户复制的内容的样式可能会影响浏览器放入剪贴板的数据格式。例如，复制一段加粗的文字，剪贴板中可能会包含带有 `<b>` 标签的 HTML。

**逻辑推理、假设输入与输出:**

以 `TEST_F(SystemClipboardTest, Text)` 为例：

* **假设输入:**
    1. 初始状态，剪贴板为空。
    2. 通过 `clipboard_host()->WriteText("first")` 将文本 "first" 写入模拟的剪贴板宿主。
    3. 进入快照作用域，此时剪贴板内容为 "first"。
    4. 在快照作用域内，通过 `clipboard_host()->WriteText("second")` 将文本 "second" 写入模拟的剪贴板宿主。
    5. 在快照作用域内，通过 `clipboard_host()->WriteText("third")` 将文本 "third" 写入模拟的剪贴板宿主。
    6. 退出快照作用域。

* **逻辑推理:**
    * 初始状态，`system_clipboard().ReadPlainText()` 应该返回空字符串。
    * 写入 "first" 后，`system_clipboard().ReadPlainText()` 应该返回 "first"。
    * 进入快照作用域后，第一次调用 `system_clipboard().ReadPlainText()` 会记录当时的剪贴板内容 "first"。
    * 在快照作用域内，即使剪贴板内容被修改为 "second" 和 "third"，由于快照的存在，`system_clipboard().ReadPlainText()` 仍然会返回快照时记录的值 "second"。
    * 退出快照作用域后，`system_clipboard().ReadPlainText()` 将反映当前的剪贴板内容 "third"。

* **预期输出:**
    ```
    EXPECT_EQ(system_clipboard().ReadPlainText(), ""); // 初始状态
    EXPECT_EQ(system_clipboard().ReadPlainText(), "first"); // 写入 "first" 后
    EXPECT_EQ(system_clipboard().ReadPlainText(), "second"); // 快照作用域内第一次读取
    EXPECT_EQ(system_clipboard().ReadPlainText(), "second"); // 快照作用域内第二次读取
    EXPECT_EQ(system_clipboard().ReadPlainText(), "third");  // 退出快照作用域后
    ```

**用户或编程常见的使用错误:**

1. **假设剪贴板总是有特定格式的数据:** 开发者可能会假设用户复制的一定是纯文本，而没有处理 HTML 或其他格式的情况。这会导致程序在遇到非预期格式的剪贴板内容时出错或显示不正确。
    * **示例:** 一个简单的文本编辑器可能只调用 `navigator.clipboard.readText()`，如果用户复制的是包含格式的文本（例如，从网页复制），编辑器可能无法正确显示格式。
2. **忘记处理异步操作:** 读取剪贴板是一个异步操作，开发者如果没有正确使用 Promise 或 async/await 来处理 `navigator.clipboard.readText()` 或 `navigator.clipboard.read()` 返回的 Promise，可能会导致读取到的数据为空或程序执行顺序错误。
    * **示例:**
        ```javascript
        // 错误的做法，可能在读取完成前就使用了 clipboardText
        let clipboardText;
        navigator.clipboard.readText().then(text => {
          clipboardText = text;
        });
        console.log(clipboardText); // 很有可能输出 undefined
        ```
3. **在没有用户手势的情况下尝试读取剪贴板:** 出于安全考虑，浏览器通常只允许在响应用户手势（例如，点击事件、键盘事件）时读取剪贴板。尝试在没有用户手势的情况下读取剪贴板可能会被浏览器阻止。
    * **示例:** 在页面加载时立即尝试读取剪贴板内容可能会失败。
4. **没有处理剪贴板读取的权限问题:** 在某些情况下，浏览器可能会要求用户授予网页读取剪贴板的权限。开发者需要处理权限被拒绝的情况。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户发起复制操作:** 用户在网页上选中一段文本或图片，然后按下 Ctrl+C (或 Cmd+C)。
2. **浏览器捕获复制事件:** 浏览器内核（Blink 引擎）捕获到用户的复制操作。
3. **创建 DataTransfer 对象:** Blink 引擎会创建一个 `DataTransfer` 对象，用于存储要放入剪贴板的数据。
4. **调用 Clipboard API (C++ 端):**  Blink 引擎会调用底层的 Clipboard API，最终会涉及到 `// Copyright 2023 The Chromium Authors` 注释之前的代码，将不同格式的数据写入到操作系统的剪贴板。这部分代码在 `SystemClipboard` 类的写入方法中实现（此测试文件未展示）。
5. **用户发起粘贴操作:** 用户在另一个应用程序或同一个网页的不同位置按下 Ctrl+V (或 Cmd+V)。
6. **浏览器捕获粘贴事件:** 浏览器内核捕获到用户的粘贴操作。
7. **调用 JavaScript Clipboard API:** 如果是网页内的粘贴操作，JavaScript 代码可能会调用 `navigator.clipboard.readText()` 或 `navigator.clipboard.read()` 来读取剪贴板内容.
8. **调用 SystemClipboard 的读取方法:** JavaScript Clipboard API 的底层实现会调用到 `blink/renderer/core/clipboard/system_clipboard.h` 中声明的 `SystemClipboard` 类的相应读取方法，例如 `ReadPlainText()`, `ReadHTML()` 等。
9. **SystemClipboard 与 ClipboardHost 交互:** `SystemClipboard` 类通过 `clipboard_` (一个 `mojom::blink::ClipboardHostPtr`) 与 `ClipboardHost` 通信，`ClipboardHost` 负责与操作系统级别的剪贴板进行实际的交互。
10. **操作系统返回剪贴板数据:** 操作系统将剪贴板中的数据返回给 `ClipboardHost`，然后传递给 `SystemClipboard`。
11. **数据返回给 JavaScript 或渲染引擎:** `SystemClipboard` 的读取方法将数据返回给调用者，最终可能传递给 JavaScript 的 Promise 回调函数或渲染引擎用于渲染粘贴的内容。

**调试线索:**

* 如果在读取剪贴板时遇到问题，可以设置断点在 `SystemClipboard` 类的读取方法（例如 `ReadPlainText()`, `ReadHTML()`）中，查看是否能正确连接到 `ClipboardHost`，以及 `ClipboardHost` 返回的数据是否正确。
* 可以检查 `ClipboardHost` 的实现，看它如何与操作系统的剪贴板 API 进行交互，以确定问题是否出在操作系统层面。
* 可以使用 Chromium 提供的 tracing 工具，查看与剪贴板操作相关的事件流，以便追踪用户操作到代码执行的路径。
* 检查浏览器的安全策略和权限设置，确保网页有权限读取剪贴板。

总而言之，`system_clipboard_test.cc` 文件通过一系列单元测试，确保了 `SystemClipboard` 类作为 Blink 引擎与操作系统剪贴板的桥梁，能够正确地读取各种格式的剪贴板数据，并且在各种情况下（例如，快照、断开连接）都能表现出预期的行为，从而保证了 Web 平台的剪贴板功能的稳定性和可靠性。

Prompt: 
```
这是目录为blink/renderer/core/clipboard/system_clipboard_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/clipboard/system_clipboard.h"

#include <memory>

#include "base/test/bind.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/clipboard/clipboard_mime_types.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/skia/include/core/SkBitmap.h"
#include "third_party/skia/include/core/SkImageInfo.h"
#include "ui/gfx/codec/png_codec.h"
#include "ui/gfx/geometry/size.h"

namespace blink {

namespace {

mojom::blink::ClipboardFilesPtr CreateFiles(int count) {
  WTF::Vector<mojom::blink::DataTransferFilePtr> vec;
  for (int i = 0; i < count; ++i) {
    vec.emplace_back(mojom::blink::DataTransferFile::New(
        base::FilePath(FILE_PATH_LITERAL("path")),
        base::FilePath(FILE_PATH_LITERAL("name")),
        mojo::PendingRemote<
            mojom::blink::FileSystemAccessDataTransferToken>()));
  }

  return mojom::blink::ClipboardFiles::New(std::move(vec), "file_system_id");
}

}  // namespace

class SystemClipboardTest : public testing::Test {
 public:
  SystemClipboardTest() {
    page_holder_ = std::make_unique<DummyPageHolder>(gfx::Size(1, 1));
    clipboard_provider_ =
        std::make_unique<PageTestBase::MockClipboardHostProvider>(
            page_holder_.get()->GetFrame().GetBrowserInterfaceBroker());
  }

 protected:
  MockClipboardHost* mock_clipboard_host() {
    return clipboard_provider_->clipboard_host();
  }
  mojom::blink::ClipboardHost* clipboard_host() {
    return clipboard_provider_->clipboard_host();
  }
  SystemClipboard& system_clipboard() {
    return *(page_holder_.get()->GetFrame().GetSystemClipboard());
  }
  void reset_remote_and_validate_buffer() {
    // Reset mojo remote to unbound.
    system_clipboard().clipboard_.reset();
    EXPECT_FALSE(system_clipboard().clipboard_.is_bound());
    // Check if the buffer is valid to make sure the read APIs return null
    // string because of unbound mojo remote and not because of invalid buffer.
    EXPECT_TRUE(
        system_clipboard().IsValidBufferType(system_clipboard().buffer_));
  }

  void RunUntilIdle() { test::RunPendingTasks(); }

 private:
  test::TaskEnvironment task_environment;

  std::unique_ptr<DummyPageHolder> page_holder_;
  std::unique_ptr<PageTestBase::MockClipboardHostProvider> clipboard_provider_;
};

TEST_F(SystemClipboardTest, Text) {
  // Clipboard starts empty.
  EXPECT_EQ(system_clipboard().ReadPlainText(), "");

  // Setting text in the host is visible in system.
  clipboard_host()->WriteText("first");
  EXPECT_EQ(system_clipboard().ReadPlainText(), "first");

  // Inside a snapshot scope, the first read from the system clipboard
  // remembers the result, even if the underlying clipboard host changes.
  {
    ScopedSystemClipboardSnapshot snapshot(system_clipboard());

    clipboard_host()->WriteText("second");
    EXPECT_EQ(system_clipboard().ReadPlainText(), "second");

    clipboard_host()->WriteText("third");
    EXPECT_EQ(system_clipboard().ReadPlainText(), "second");
  }

  // Now that the snapshot is out of scope, reads from the system clipboard
  // reflect the state of the clipboard host.
  EXPECT_EQ(system_clipboard().ReadPlainText(), "third");
}

TEST_F(SystemClipboardTest, Html) {
  KURL url;
  unsigned fragment_start;
  unsigned fragment_end;

  // Clipboard starts empty.
  EXPECT_EQ(system_clipboard().ReadHTML(url, fragment_start, fragment_end), "");

  // Setting text in the host is visible in system.
  clipboard_host()->WriteHtml("first", KURL("http://first.com"));
  EXPECT_EQ(system_clipboard().ReadHTML(url, fragment_start, fragment_end),
            "first");
  EXPECT_EQ(url, KURL("http://first.com"));

  // Inside a snapshot scope, the first read from the system clipboard
  // remembers the result, even if the underlying clipboard host changes.
  {
    ScopedSystemClipboardSnapshot snapshot(system_clipboard());

    clipboard_host()->WriteHtml("second", KURL("http://second.com"));
    EXPECT_EQ(system_clipboard().ReadHTML(url, fragment_start, fragment_end),
              "second");
    EXPECT_EQ(url, KURL("http://second.com"));

    clipboard_host()->WriteHtml("third", KURL("http://third.com"));
    EXPECT_EQ(system_clipboard().ReadHTML(url, fragment_start, fragment_end),
              "second");
    EXPECT_EQ(url, KURL("http://second.com"));
  }

  // Now that the snapshot is out of scope, reads from the system clipboard
  // reflect the state of the clipboard host.
  EXPECT_EQ(system_clipboard().ReadHTML(url, fragment_start, fragment_end),
            "third");
  EXPECT_EQ(url, KURL("http://third.com"));
}

TEST_F(SystemClipboardTest, ReadHtml_SameFragmentArgs) {
  KURL url;
  unsigned fragment_start;
  unsigned fragment_end;
  const String kHtmlText = "first";

  // Setting text in the host is visible in system.
  clipboard_host()->WriteHtml(kHtmlText, KURL("http://first.com"));

  EXPECT_EQ(system_clipboard().ReadHTML(url, fragment_start, fragment_end),
            kHtmlText);
  EXPECT_EQ(fragment_start, 0u);
  EXPECT_EQ(fragment_end, kHtmlText.length());

  ScopedSystemClipboardSnapshot snapshot(system_clipboard());

  // Inside a snapshot scope, the first read from the system clipboard
  // remembers the result.  Specify the same variable for start and end
  // to make sure this does not mess up the values stored in the
  // snapshot.
  unsigned ignore;
  EXPECT_EQ(system_clipboard().ReadHTML(url, ignore, ignore), kHtmlText);

  // Now perform a ReadHTML() with different variable for start and end.
  // This will read from the snapshot and should return expected values.
  unsigned fragment_start2;
  unsigned fragment_end2;
  EXPECT_EQ(system_clipboard().ReadHTML(url, fragment_start2, fragment_end2),
            kHtmlText);
  EXPECT_EQ(fragment_start2, 0u);
  EXPECT_EQ(fragment_end2, kHtmlText.length());
}

TEST_F(SystemClipboardTest, Rtf) {
  // Clipboard starts empty.
  EXPECT_EQ(system_clipboard().ReadRTF(), "");

  // Setting text in the host is visible in system.
  mock_clipboard_host()->WriteRtf("first");
  EXPECT_EQ(system_clipboard().ReadRTF(), "first");

  // Inside a snapshot scope, the first read from the system clipboard
  // remembers the result, even if the underlying clipboard host changes.
  {
    ScopedSystemClipboardSnapshot snapshot(system_clipboard());

    mock_clipboard_host()->WriteRtf("second");
    EXPECT_EQ(system_clipboard().ReadRTF(), "second");

    mock_clipboard_host()->WriteRtf("third");
    EXPECT_EQ(system_clipboard().ReadRTF(), "second");
  }

  // Now that the snapshot is out of scope, reads from the system clipboard
  // reflect the state of the clipboard host.
  EXPECT_EQ(system_clipboard().ReadRTF(), "third");
}

TEST_F(SystemClipboardTest, Png) {
  auto buf = mojom::blink::ClipboardBuffer::kStandard;

  // Clipboard starts empty.
  mojo_base::BigBuffer png = system_clipboard().ReadPng(buf);
  EXPECT_EQ(png.size(), 0u);

  // Create test bitmaps to put into the clipboard.
  SkBitmap bitmap1;
  SkBitmap bitmap2;
  SkBitmap bitmap3;
  ASSERT_TRUE(bitmap1.tryAllocPixelsFlags(
      SkImageInfo::Make(4, 3, kN32_SkColorType, kOpaque_SkAlphaType), 0));
  ASSERT_TRUE(bitmap2.tryAllocPixelsFlags(
      SkImageInfo::Make(40, 30, kN32_SkColorType, kOpaque_SkAlphaType), 0));
  ASSERT_TRUE(bitmap3.tryAllocPixelsFlags(
      SkImageInfo::Make(400, 300, kN32_SkColorType, kOpaque_SkAlphaType), 0));

  // Setting image in the host is visible in system.
  clipboard_host()->WriteImage(bitmap1);
  clipboard_host()->CommitWrite();

  png = system_clipboard().ReadPng(buf);
  SkBitmap bitmap = gfx::PNGCodec::Decode(png);
  ASSERT_FALSE(bitmap.isNull());
  EXPECT_EQ(bitmap.width(), 4);
  EXPECT_EQ(bitmap.height(), 3);

  // Inside a snapshot scope, the first read from the system clipboard
  // remembers the result, even if the underlying clipboard host changes.
  {
    ScopedSystemClipboardSnapshot snapshot(system_clipboard());

    clipboard_host()->WriteImage(bitmap2);
    clipboard_host()->CommitWrite();
    png = system_clipboard().ReadPng(buf);
    bitmap = gfx::PNGCodec::Decode(png);
    ASSERT_FALSE(bitmap.isNull());
    EXPECT_EQ(bitmap.width(), 40);
    EXPECT_EQ(bitmap.height(), 30);

    clipboard_host()->WriteImage(bitmap3);
    clipboard_host()->CommitWrite();
    png = system_clipboard().ReadPng(buf);
    bitmap = gfx::PNGCodec::Decode(png);
    ASSERT_FALSE(bitmap.isNull());
    EXPECT_EQ(bitmap.width(), 40);
    EXPECT_EQ(bitmap.height(), 30);
  }

  // Now that the snapshot is out of scope, reads from the system clipboard
  // reflect the state of the clipboard host.
  png = system_clipboard().ReadPng(buf);
  bitmap = gfx::PNGCodec::Decode(png);
  ASSERT_FALSE(bitmap.isNull());
  EXPECT_EQ(bitmap.width(), 400);
  EXPECT_EQ(bitmap.height(), 300);
}

TEST_F(SystemClipboardTest, Files) {
  // Clipboard starts empty.
  auto files = system_clipboard().ReadFiles();
  EXPECT_EQ(files->files.size(), 0u);

  // Setting file in the host is visible in system.
  mock_clipboard_host()->WriteFiles(CreateFiles(1));
  EXPECT_EQ(system_clipboard().ReadFiles()->files.size(), 1u);

  // Inside a snapshot scope, the first read from the system clipboard
  // remembers the result, even if the underlying clipboard host changes.
  {
    ScopedSystemClipboardSnapshot snapshot(system_clipboard());

    mock_clipboard_host()->WriteFiles(CreateFiles(2));
    EXPECT_EQ(system_clipboard().ReadFiles()->files.size(), 2u);

    mock_clipboard_host()->WriteFiles(CreateFiles(3));
    EXPECT_EQ(system_clipboard().ReadFiles()->files.size(), 2u);
  }

  // Now that the snapshot is out of scope, reads from the system clipboard
  // reflect the state of the clipboard host.
  EXPECT_EQ(system_clipboard().ReadFiles()->files.size(), 3u);
}

TEST_F(SystemClipboardTest, CustomData) {
  // Clipboard starts empty.
  EXPECT_EQ(system_clipboard().ReadDataTransferCustomData("a"), "");

  // Setting text in the host is visible in system.
  clipboard_host()->WriteDataTransferCustomData({{"a", "first"}});
  EXPECT_EQ(system_clipboard().ReadDataTransferCustomData("a"), "first");

  // Inside a snapshot scope, the first read from the system clipboard
  // remembers the result, even if the underlying clipboard host changes.
  {
    ScopedSystemClipboardSnapshot snapshot(system_clipboard());

    clipboard_host()->WriteDataTransferCustomData({{"a", "second"}});
    EXPECT_EQ(system_clipboard().ReadDataTransferCustomData("a"), "second");

    clipboard_host()->WriteDataTransferCustomData(
        {{"a", "third"}, {"b", "fourth"}});
    EXPECT_EQ(system_clipboard().ReadDataTransferCustomData("a"), "second");
    EXPECT_EQ(system_clipboard().ReadDataTransferCustomData("b"), "fourth");
  }

  // Now that the snapshot is out of scope, reads from the system clipboard
  // reflect the state of the clipboard host.
  EXPECT_EQ(system_clipboard().ReadDataTransferCustomData("a"), "third");
}

TEST_F(SystemClipboardTest, SnapshotNesting) {
  // Clipboard starts empty.
  EXPECT_EQ(system_clipboard().ReadPlainText(), "");

  // Setting text in the host is visible in system.
  clipboard_host()->WriteText("first");
  EXPECT_EQ(system_clipboard().ReadPlainText(), "first");

  // Inside a snapshot scope, the first read from the system clipboard
  // remembers the result, even if the underlying clipboard host changes.
  {
    ScopedSystemClipboardSnapshot snapshot(system_clipboard());

    clipboard_host()->WriteText("second");
    EXPECT_EQ(system_clipboard().ReadPlainText(), "second");

    clipboard_host()->WriteText("third");
    EXPECT_EQ(system_clipboard().ReadPlainText(), "second");

    // Nest another snapshot.  Things should remain stable.
    {
      ScopedSystemClipboardSnapshot snapshot2(system_clipboard());

      clipboard_host()->WriteText("fourth");
      EXPECT_EQ(system_clipboard().ReadPlainText(), "second");
    }

    // When second snapshot closes, the original one should still be be in
    // effect.
    clipboard_host()->WriteText("fifth");
    EXPECT_EQ(system_clipboard().ReadPlainText(), "second");
  }

  // Now that the snapshot is out of scope, reads from the system clipboard
  // reflect the final state of the clipboard host.
  EXPECT_EQ(system_clipboard().ReadPlainText(), "fifth");
}

TEST_F(SystemClipboardTest, ReadTextWithUnboundClipboardHost) {
  // Clipboard starts empty.
  EXPECT_EQ(system_clipboard().ReadPlainText(), "");

  // Setting text in the host is visible in system clipboard.
  clipboard_host()->WriteText("first");
  EXPECT_EQ(system_clipboard().ReadPlainText(), "first");

  reset_remote_and_validate_buffer();

  // Now the Reads should return null string.
  EXPECT_EQ(system_clipboard().ReadPlainText(), String());
  // Writes will fail since the mojo remote is unbound.
  clipboard_host()->WriteText("second");
  EXPECT_EQ(system_clipboard().ReadPlainText(), String());
}

TEST_F(SystemClipboardTest, ReadHtmlWithUnboundClipboardHost) {
  KURL url;
  unsigned fragment_start;
  unsigned fragment_end;

  // Clipboard starts empty.
  EXPECT_EQ(system_clipboard().ReadHTML(url, fragment_start, fragment_end), "");

  // Setting text in the host is visible in system clipboard.
  clipboard_host()->WriteHtml("first", KURL("http://first.com"));
  EXPECT_EQ(system_clipboard().ReadHTML(url, fragment_start, fragment_end),
            "first");
  EXPECT_EQ(url, KURL("http://first.com"));

  reset_remote_and_validate_buffer();

  // Now the Reads should return null string.
  EXPECT_EQ(system_clipboard().ReadHTML(url, fragment_start, fragment_end),
            String());
  // Writes will fail since the mojo remote is unbound.
  clipboard_host()->WriteHtml("first", KURL("http://first.com"));
  EXPECT_EQ(system_clipboard().ReadHTML(url, fragment_start, fragment_end),
            String());
  EXPECT_EQ(url, KURL(String()));
}

TEST_F(SystemClipboardTest, ReadRtfWithUnboundClipboardHost) {
  // Clipboard starts empty.
  EXPECT_EQ(system_clipboard().ReadRTF(), "");

  // Setting text in the host is visible in system clipboard.
  mock_clipboard_host()->WriteRtf("first");
  EXPECT_EQ(system_clipboard().ReadRTF(), "first");

  reset_remote_and_validate_buffer();

  // Now the Reads should return null string.
  EXPECT_EQ(system_clipboard().ReadRTF(), String());
  // Writes will fail since the mojo remote is unbound.
  mock_clipboard_host()->WriteRtf("second");
  EXPECT_EQ(system_clipboard().ReadRTF(), String());
}

TEST_F(SystemClipboardTest, ReadPngWithUnboundClipboardHost) {
  auto buf = mojom::blink::ClipboardBuffer::kStandard;

  // Clipboard starts empty.
  mojo_base::BigBuffer png = system_clipboard().ReadPng(buf);
  EXPECT_EQ(png.size(), 0u);

  // Create test bitmaps to put into the clipboard.
  SkBitmap bitmapIn;
  ASSERT_TRUE(bitmapIn.tryAllocPixelsFlags(
      SkImageInfo::Make(4, 3, kN32_SkColorType, kOpaque_SkAlphaType), 0));

  // Setting image in the host is visible in system clipboard.
  clipboard_host()->WriteImage(bitmapIn);
  clipboard_host()->CommitWrite();

  png = system_clipboard().ReadPng(buf);
  SkBitmap bitmapOut = gfx::PNGCodec::Decode(png);
  ASSERT_FALSE(bitmapOut.isNull());
  EXPECT_EQ(bitmapOut.width(), 4);
  EXPECT_EQ(bitmapOut.height(), 3);

  reset_remote_and_validate_buffer();

  // Now the Reads should return zero sized png.
  png = system_clipboard().ReadPng(buf);
  EXPECT_EQ(png.size(), 0u);

  // Setting image in the host will fail since the mojo remote is unbound.
  clipboard_host()->WriteImage(bitmapIn);
  clipboard_host()->CommitWrite();
  png = system_clipboard().ReadPng(buf);
  EXPECT_EQ(png.size(), 0u);
}

TEST_F(SystemClipboardTest, ReadFilesWithUnboundClipboardHost) {
  // Clipboard starts empty.
  auto files = system_clipboard().ReadFiles();
  EXPECT_EQ(files->files.size(), 0u);

  // Setting file in the host is visible in system clipboard.
  mock_clipboard_host()->WriteFiles(CreateFiles(1));
  EXPECT_EQ(system_clipboard().ReadFiles()->files.size(), 1u);

  reset_remote_and_validate_buffer();

  // Now the Reads should return null pointer to files.
  EXPECT_TRUE(system_clipboard().ReadFiles().is_null());
  // Writes will fail since the mojo remote is unbound.
  mock_clipboard_host()->WriteFiles(CreateFiles(1));
  EXPECT_TRUE(system_clipboard().ReadFiles().is_null());
}

TEST_F(SystemClipboardTest, IsFormatAvailableWithUnboundClipboardHost) {
  // Clipboard starts empty.
  EXPECT_FALSE(system_clipboard().IsFormatAvailable(
      blink::mojom::ClipboardFormat::kPlaintext));

  // Setting text in the host is visible in system clipboard.
  clipboard_host()->WriteText("first");
  EXPECT_TRUE(system_clipboard().IsFormatAvailable(
      blink::mojom::ClipboardFormat::kPlaintext));

  reset_remote_and_validate_buffer();

  // Now the Reads should return false.
  EXPECT_FALSE(system_clipboard().IsFormatAvailable(
      blink::mojom::ClipboardFormat::kPlaintext));
  // Writes will fail since the mojo remote is unbound.
  clipboard_host()->WriteText("second");
  EXPECT_FALSE(system_clipboard().IsFormatAvailable(
      blink::mojom::ClipboardFormat::kPlaintext));
}

TEST_F(SystemClipboardTest, ReadAvailableTypesWithUnboundClipboardHost) {
  // Clipboard starts empty.
  EXPECT_EQ(system_clipboard().ReadAvailableTypes().size(), 0u);

  // Setting text in the host is visible in system clipboard.
  clipboard_host()->WriteText("first");
  EXPECT_EQ(system_clipboard().ReadAvailableTypes().size(), 1u);

  reset_remote_and_validate_buffer();

  // Now the Reads should return no available types.
  EXPECT_EQ(system_clipboard().ReadAvailableTypes().size(), 0u);
  // Writes will fail since the mojo remote is unbound.
  clipboard_host()->WriteText("second");
  EXPECT_EQ(system_clipboard().ReadAvailableTypes().size(), 0u);
}

TEST_F(SystemClipboardTest, SequenceNumberWithUnboundClipboardHost) {
  // Clipboard starts empty.
  auto sequence_number = system_clipboard().SequenceNumber();
  // Setting text in the host is visible in system clipboard.
  clipboard_host()->WriteText("first");
  clipboard_host()->CommitWrite();
  auto sequence_number_after_write = system_clipboard().SequenceNumber();
  EXPECT_NE(sequence_number, sequence_number_after_write);

  reset_remote_and_validate_buffer();

  // After clipboard reset, sequenceNumber will be random.
  auto sequence_number_after_reset = system_clipboard().SequenceNumber();
  EXPECT_NE(sequence_number_after_write, sequence_number_after_reset);
}
}  // namespace blink

"""

```