Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Understanding the Goal:**

The request asks for an analysis of `file_input_type_test.cc`. This immediately signals that the file contains *tests* for the `FileInputType` class in the Chromium Blink rendering engine. The key is to identify *what* aspects of `FileInputType` are being tested.

**2. Initial Code Scan and Keyword Identification:**

A quick scan of the code reveals several important keywords and patterns:

* **`TEST(FileInputTypeTest, ...)`:**  This confirms the file's purpose as a test suite specifically for `FileInputType`. Each `TEST` macro represents an individual test case.
* **`#include "third_party/blink/renderer/core/html/forms/file_input_type.h"`:** This is the most important include. It tells us the tests are directly related to the `FileInputType` class definition.
* **`HTMLInputElement`:** This indicates interaction with the `<input type="file">` HTML element.
* **`FileList`:**  A core concept for file inputs, representing the selected files.
* **`FileChooserFileInfoList`:**  Data structure used when interacting with the native file selection dialog.
* **`DragData`:** Indicates testing of drag-and-drop functionality.
* **`event_type_names::kChange`, `event_type_names::kCancel`:**  Points to testing the event handling of the file input.
* **`MockFileChooser`:**  Suggests testing the interaction with the system's file selection dialog without actually opening it. This is crucial for automated testing.
* **`javascript`, `html`, `css` (mentioned in the request):**  These are areas to look for connections, even though the code itself is C++. The tests verify how `FileInputType` interacts with these web technologies.

**3. Analyzing Individual Test Cases:**

Now, the core of the analysis involves going through each `TEST` function and understanding its purpose:

* **`createFileList`:** This test focuses on how a `FileList` object is created from different types of file information (native paths and filesystem URLs). This directly relates to how the browser represents selected files internally, which is exposed to JavaScript.

* **`createFileListContentUri`:**  Specifically tests how content URIs (common on Android) are handled. This is a platform-specific detail related to how files are accessed.

* **`ignoreDroppedNonNativeFiles`:** Tests the behavior when files from a "non-native" source (like a sandboxed filesystem) are dragged and dropped. This relates to browser security and how different file sources are treated. The expected behavior is to ignore them, suggesting a security measure.

* **`setFilesFromPaths`:** Tests setting files programmatically using file paths. This has direct implications for JavaScript, where code can manipulate the file input. The test also checks the `multiple` attribute.

* **`DropTouchesNoPopupOpeningObserver`:**  This test is about ensuring that dropping files onto a `<input type="file" webkitdirectory>` element doesn't trigger unexpected calls related to popup windows. This is more of an internal implementation detail but ensures stability.

* **`BeforePseudoCrash`:** This test is a bit unusual. It sets up specific CSS conditions and verifies that the code doesn't crash. This is a form of robustness testing, likely targeting potential edge cases in the rendering engine.

* **`ChangeTypeDuringOpeningFileChooser`:**  Tests what happens if the `type` of the input element is changed while the file selection dialog is open. This checks how the system handles state changes during an asynchronous operation.

* **`SetFilesFireCorrectEventsForSameFile/Files`, `SetFilesFireCorrectEventsForDifferentFile/Files`, `SetFilesFireCorrectEventsCancelWithSelection`, `SetFilesFireCorrectEventsCancelWithoutSelection`:** These tests are all focused on verifying that the correct "change" and "cancel" events are fired on the file input element under various scenarios of selecting and deselecting the same or different files. This is crucial for JavaScript event handling.

**4. Connecting to Web Technologies:**

As each test is understood, the connections to JavaScript, HTML, and CSS become apparent:

* **HTML:** The tests directly manipulate `<input type="file">` elements and their attributes (`multiple`, `webkitdirectory`).
* **JavaScript:** The tests implicitly verify the behavior of JavaScript APIs related to file inputs, such as accessing `input.files`, and the firing of `change` and `cancel` events that JavaScript code can listen for.
* **CSS:** The `BeforePseudoCrash` test explicitly uses CSS to create specific rendering conditions.

**5. Identifying Logic and Assumptions:**

For tests involving logic, like the event firing tests, the underlying assumption is that the `FileInputType` correctly manages its internal state and dispatches events based on user interactions (or programmatic changes). The inputs are the file selections, and the outputs are the fired events.

**6. Identifying User and Programming Errors:**

By considering how developers use file inputs, potential errors become evident:

* Not handling the `cancel` event when the user closes the file chooser without selecting a new file.
* Assuming the `change` event will always fire when the same file is selected again.
* Not checking the `multiple` attribute when expecting multiple file selections.

**7. Structuring the Output:**

Finally, the information is organized into the requested categories:

* **Functionality:** A high-level overview of what the code does.
* **Relationship to Web Technologies:**  Specific examples of how the tests relate to HTML, JavaScript, and CSS.
* **Logic and Assumptions:** Describing the input/output of logical tests.
* **Common Errors:**  Listing potential mistakes developers might make.

This iterative process of scanning, analyzing, connecting, and structuring leads to the comprehensive analysis provided in the initial good answer.
这个文件 `file_input_type_test.cc` 是 Chromium Blink 引擎中用于测试 `FileInputType` 类的单元测试文件。 `FileInputType` 类是负责处理 HTML `<input type="file">` 元素的核心逻辑的。

以下是该文件的功能及其与 JavaScript, HTML, CSS 的关系，以及逻辑推理和常见错误：

**功能列举:**

1. **测试 `FileList` 的创建:**  测试 `FileInputType::CreateFileList` 函数，该函数负责根据选择的文件信息（本地文件路径、文件系统 URL 等）创建 `FileList` 对象。 `FileList` 对象在 JavaScript 中表示用户选择的文件列表。
2. **测试拖放文件的处理:** 测试当文件被拖放到 `<input type="file">` 元素时，`FileInputType` 如何接收和处理这些文件，特别是区分本地文件和非本地文件（例如来自沙箱文件系统的文件）。
3. **测试通过路径设置文件:** 测试 `FileInputType::SetFilesFromPaths` 函数，该函数允许通过文件路径列表来设置 `input` 元素的文件列表。这模拟了某些内部操作或测试场景。
4. **测试 `webkitdirectory` 属性:**  测试当 `<input type="file"` 元素带有 `webkitdirectory` 属性时，拖放文件夹的行为，并确保不会意外触发弹出窗口相关的逻辑。
5. **测试在打开文件选择器期间更改 `input` 类型:** 测试在用户点击 `<input type="file">` 并打开文件选择器后，如果 JavaScript 更改了该元素的 `type` 属性会发生什么，以及如何处理文件选择器的回调。
6. **测试文件选择事件的触发:**  详细测试在用户选择文件、选择相同文件、选择不同文件以及取消选择时，`change` 和 `cancel` 事件是否被正确触发。这是确保文件输入元素行为符合预期的关键部分。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**  `FileInputType` 紧密关联 HTML `<input type="file">` 元素。测试用例会创建和操作 `HTMLInputElement` 对象，设置其属性（如 `multiple` 和 `webkitdirectory`），并模拟用户交互（如拖放文件和点击）。
    * **例子:**  `doc.body()->setInnerHTML("<input type=file webkitdirectory>");`  这行代码在测试中动态创建了一个带有 `webkitdirectory` 属性的 `<input type="file">` 元素。

* **JavaScript:** `FileInputType` 的核心功能是为 JavaScript 提供用户选择的文件信息。`FileList` 对象是 JavaScript 可以访问的，用于获取选择的文件。测试用例会验证当用户进行文件选择操作时，是否会触发 JavaScript 的 `change` 和 `cancel` 事件。
    * **例子:** `input->addEventListener(event_type_names::kChange, listener_change);`  这行代码模拟了 JavaScript 为 `input` 元素添加 `change` 事件监听器。测试用例通过检查 `listener_change->invoked` 来判断事件是否被触发。
    * **例子:**  当用户在文件选择器中选择了文件后，`FileInputType` 会创建一个 `FileList` 对象，这个对象会通过 `input.files` 属性暴露给 JavaScript。

* **CSS:**  虽然这个测试文件本身不直接测试 CSS 的功能，但其中一个测试用例 (`BeforePseudoCrash`) 涉及到特定的 CSS 规则。这个测试用例的目的在于验证在特定的渲染条件下，`FileInputType` 不会引发崩溃或其他异常。这间接说明了 `FileInputType` 需要与渲染引擎的其他部分协同工作，包括 CSS 相关的渲染逻辑。
    * **例子:**  `doc.documentElement()->setInnerHTML(R"HTML(<style> ... </style> <input type=file class=c6> <input type=file class=c7>)HTML");` 这个测试用例设置了包含特定 CSS 规则的 HTML 结构，然后执行文件选择操作，以检测潜在的渲染问题。

**逻辑推理及假设输入与输出:**

* **测试 `createFileList`:**
    * **假设输入:**  一个 `FileChooserFileInfoList` 对象，包含不同类型的文件信息（本地路径和文件系统 URL）。
    * **预期输出:**  一个 `FileList` 对象，其中包含与输入文件信息对应的 `File` 对象。每个 `File` 对象应该具有正确的路径、名称、大小和最后修改时间等属性。

* **测试 `SetFilesFireCorrectEventsForSameFile`:**
    * **假设输入:** 用户第一次选择了一个名为 "A.txt" 的文件，然后第二次再次选择 "A.txt"。
    * **预期输出:** 第一次选择会触发 `change` 事件。第二次选择（因为文件相同）会触发 `cancel` 事件，因为文件没有实际改变。

* **测试 `SetFilesFireCorrectEventsCancelWithSelection`:**
    * **假设输入:** 用户第一次选择了一些文件，然后再次打开文件选择器并取消选择（不选择任何文件）。
    * **预期输出:** 第一次选择会触发 `change` 事件。第二次取消选择也会触发 `change` 事件，但此时 `FileList` 将为空。

**用户或编程常见的使用错误举例:**

1. **未监听 `change` 事件:** 开发者可能忘记为 `<input type="file">` 元素添加 `change` 事件监听器，导致用户选择文件后，JavaScript 代码无法及时获取到文件信息。
   ```html
   <input type="file" id="uploadFile">
   <script>
       const uploadFile = document.getElementById('uploadFile');
       // 缺少事件监听器，无法处理文件选择
   </script>
   ```

2. **错误地假设 `change` 事件在选择相同文件时总是触发:**  如测试用例所示，如果用户第二次选择与上次相同的文件，`change` 事件通常不会触发，而可能会触发 `cancel` 事件（表示文件没有变化）。开发者需要理解这种行为，并在必要时进行处理。
   ```javascript
   const uploadFile = document.getElementById('uploadFile');
   uploadFile.addEventListener('change', (event) => {
       console.log('文件已更改'); // 当选择相同文件时，这可能不会被打印
   });
   ```

3. **没有考虑 `multiple` 属性:** 当需要用户上传多个文件时，开发者需要在 `<input>` 标签中添加 `multiple` 属性。如果缺少该属性，即使选择了多个文件，JavaScript 中也只能获取到第一个文件。
   ```html
   <!-- 缺少 multiple 属性，只能选择一个文件 -->
   <input type="file" id="uploadFiles">
   <script>
       const uploadFiles = document.getElementById('uploadFiles');
       uploadFiles.addEventListener('change', (event) => {
           console.log(uploadFiles.files.length); // 即使选择了多个文件，长度也可能为 1
       });
   </script>
   ```

4. **错误地处理 `cancel` 事件:**  当用户打开文件选择器但最终取消选择时，会触发 `cancel` 事件。开发者可能没有考虑到这种情况，导致程序逻辑出现错误。例如，某些状态可能没有被正确重置。
   ```javascript
   const uploadFile = document.getElementById('uploadFile');
   uploadFile.addEventListener('cancel', (event) => {
       console.log('文件选择已取消');
       // 开发者可能忘记在这里重置某些状态
   });
   ```

总而言之，`file_input_type_test.cc` 文件通过各种测试用例，全面验证了 `FileInputType` 类的功能和行为，确保了 HTML 文件输入元素在不同场景下的正确运行，并且与 JavaScript 和 HTML 的交互符合预期。 这些测试有助于防止开发者在使用文件输入功能时遇到常见的错误。

### 提示词
```
这是目录为blink/renderer/core/html/forms/file_input_type_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/forms/file_input_type.h"

#include "base/run_loop.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/clipboard/data_object.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/fileapi/file_list.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/mock_file_chooser.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/page/drag_data.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/core/testing/wait_for_event.h"
#include "third_party/blink/renderer/platform/file_metadata.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/date_math.h"

namespace blink {

namespace {

class MockEventListener final : public NativeEventListener {
 public:
  bool invoked = false;
  void Invoke(ExecutionContext*, Event*) override { invoked = true; }
  void ClearInvoked() { invoked = false; }
};

class WebKitDirectoryChromeClient : public EmptyChromeClient {
 public:
  void RegisterPopupOpeningObserver(PopupOpeningObserver*) override {
    NOTREACHED() << "RegisterPopupOpeningObserver should not be called.";
  }
  void UnregisterPopupOpeningObserver(PopupOpeningObserver*) override {
    NOTREACHED() << "UnregisterPopupOpeningObserver should not be called.";
  }
};

}  // namespace

TEST(FileInputTypeTest, createFileList) {
  test::TaskEnvironment task_environment;
  FileChooserFileInfoList files;

  // Native file.
  files.push_back(CreateFileChooserFileInfoNative("/native/path/native-file",
                                                  "display-name"));

  // Non-native file.
  KURL url("filesystem:http://example.com/isolated/hash/non-native-file");
  files.push_back(CreateFileChooserFileInfoFileSystem(
      url, base::Time::FromMillisecondsSinceUnixEpoch(1.0 * kMsPerDay + 3),
      64));

  ScopedNullExecutionContext execution_context;
  FileList* list = FileInputType::CreateFileList(
      execution_context.GetExecutionContext(), files, base::FilePath());
  ASSERT_TRUE(list);
  ASSERT_EQ(2u, list->length());

  EXPECT_EQ("/native/path/native-file", list->item(0)->GetPath());
  EXPECT_EQ("display-name", list->item(0)->name());
  EXPECT_TRUE(list->item(0)->FileSystemURL().IsEmpty());

  EXPECT_TRUE(list->item(1)->GetPath().empty());
  EXPECT_EQ("non-native-file", list->item(1)->name());
  EXPECT_EQ(url, list->item(1)->FileSystemURL());
  EXPECT_EQ(64u, list->item(1)->size());
  EXPECT_EQ(1.0 * kMsPerDay + 3, list->item(1)->lastModified());
}

#if BUILDFLAG(IS_ANDROID)
TEST(FileInputTypeTest, createFileListContentUri) {
  test::TaskEnvironment task_environment;
  FileChooserFileInfoList files;

  files.push_back(CreateFileChooserFileInfoNative(
      "content://authority/id-123", "display-name",
      Vector<String>({"base", "subdir"})));

  ScopedNullExecutionContext execution_context;
  FileList* list = FileInputType::CreateFileList(
      execution_context.GetExecutionContext(), files,
      base::FilePath("content://authority/id-base"));
  ASSERT_TRUE(list);
  ASSERT_EQ(1u, list->length());

  EXPECT_EQ("content://authority/id-123", list->item(0)->GetPath());
  EXPECT_EQ("display-name", list->item(0)->name());
  EXPECT_EQ("base/subdir/display-name", list->item(0)->webkitRelativePath());
  EXPECT_TRUE(list->item(0)->FileSystemURL().IsEmpty());
}
#endif

TEST(FileInputTypeTest, ignoreDroppedNonNativeFiles) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  auto* input = MakeGarbageCollected<HTMLInputElement>(*document);
  InputType* file_input = MakeGarbageCollected<FileInputType>(*input);

  DataObject* native_file_raw_drag_data = DataObject::Create();
  const DragData native_file_drag_data(native_file_raw_drag_data, gfx::PointF(),
                                       gfx::PointF(), kDragOperationCopy,
                                       false);
  native_file_drag_data.PlatformData()->Add(MakeGarbageCollected<File>(
      &execution_context.GetExecutionContext(), "/native/path"));
  native_file_drag_data.PlatformData()->SetFilesystemId("fileSystemId");
  file_input->ReceiveDroppedFiles(&native_file_drag_data);
  EXPECT_EQ("fileSystemId", file_input->DroppedFileSystemId());
  ASSERT_EQ(1u, file_input->Files()->length());
  EXPECT_EQ(String("/native/path"), file_input->Files()->item(0)->GetPath());

  DataObject* non_native_file_raw_drag_data = DataObject::Create();
  const DragData non_native_file_drag_data(non_native_file_raw_drag_data,
                                           gfx::PointF(), gfx::PointF(),
                                           kDragOperationCopy, false);
  FileMetadata metadata;
  metadata.length = 1234;
  const KURL url("filesystem:http://example.com/isolated/hash/non-native-file");
  non_native_file_drag_data.PlatformData()->Add(File::CreateForFileSystemFile(
      url, metadata, File::kIsUserVisible, BlobDataHandle::Create()));
  non_native_file_drag_data.PlatformData()->SetFilesystemId("fileSystemId");
  file_input->ReceiveDroppedFiles(&non_native_file_drag_data);
  // Dropping non-native files should not change the existing files.
  EXPECT_EQ("fileSystemId", file_input->DroppedFileSystemId());
  ASSERT_EQ(1u, file_input->Files()->length());
  EXPECT_EQ(String("/native/path"), file_input->Files()->item(0)->GetPath());
}

TEST(FileInputTypeTest, setFilesFromPaths) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  auto* input = MakeGarbageCollected<HTMLInputElement>(*document);
  InputType* file_input = MakeGarbageCollected<FileInputType>(*input);
  Vector<String> paths;
  paths.push_back("/native/path");
  paths.push_back("/native/path2");
  file_input->SetFilesFromPaths(paths);
  ASSERT_EQ(1u, file_input->Files()->length());
  EXPECT_EQ(String("/native/path"), file_input->Files()->item(0)->GetPath());

  // Try to upload multiple files without multipleAttr
  paths.clear();
  paths.push_back("/native/path1");
  paths.push_back("/native/path2");
  file_input->SetFilesFromPaths(paths);
  ASSERT_EQ(1u, file_input->Files()->length());
  EXPECT_EQ(String("/native/path1"), file_input->Files()->item(0)->GetPath());

  // Try to upload multiple files with multipleAttr
  input->SetBooleanAttribute(html_names::kMultipleAttr, true);
  paths.clear();
  paths.push_back("/native/real/path1");
  paths.push_back("/native/real/path2");
  file_input->SetFilesFromPaths(paths);
  ASSERT_EQ(2u, file_input->Files()->length());
  EXPECT_EQ(String("/native/real/path1"),
            file_input->Files()->item(0)->GetPath());
  EXPECT_EQ(String("/native/real/path2"),
            file_input->Files()->item(1)->GetPath());
}

TEST(FileInputTypeTest, DropTouchesNoPopupOpeningObserver) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* chrome_client = MakeGarbageCollected<WebKitDirectoryChromeClient>();
  auto page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(), chrome_client);
  Document& doc = page_holder->GetDocument();

  doc.body()->setInnerHTML("<input type=file webkitdirectory>");
  auto& input = *To<HTMLInputElement>(doc.body()->firstChild());

  base::RunLoop run_loop;
  MockFileChooser chooser(doc.GetFrame()->GetBrowserInterfaceBroker(),
                          run_loop.QuitClosure());
  DragData drag_data(DataObject::Create(), gfx::PointF(), gfx::PointF(),
                     kDragOperationCopy, false);
  drag_data.PlatformData()->Add(MakeGarbageCollected<File>(
      &execution_context.GetExecutionContext(), "/foo/bar"));
  input.ReceiveDroppedFiles(&drag_data);
  run_loop.Run();

  chooser.ResponseOnOpenFileChooser(FileChooserFileInfoList());

  // The test passes if WebKitDirectoryChromeClient::
  // UnregisterPopupOpeningObserver() was not called.
}

TEST(FileInputTypeTest, BeforePseudoCrash) {
  test::TaskEnvironment task_environment;
  std::unique_ptr<DummyPageHolder> page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Document& doc = page_holder->GetDocument();
  doc.documentElement()->setInnerHTML(R"HTML(
<style>
.c6 {
  zoom: 0.01;
}

.c6::first-letter {
  position: fixed;
  border-style: groove;
}

.c6::before {
  content: 'c6';
}

.c7 {
  zoom: 0.1;
}

.c7::first-letter {
  position: fixed;
  border-style: groove;
}

.c7::before {
  content: 'c7';
}

</style>
<input type=file class=c6>
<input type=file class=c7>
)HTML");
  doc.View()->UpdateAllLifecyclePhasesForTest();
  // The test passes if no CHECK failures and no null pointer dereferences.
}

TEST(FileInputTypeTest, ChangeTypeDuringOpeningFileChooser) {
  test::TaskEnvironment task_environment;
  // We use WebViewHelper instead of DummyPageHolder, in order to use
  // ChromeClientImpl.
  frame_test_helpers::WebViewHelper helper;
  helper.Initialize();
  LocalFrame* frame = helper.LocalMainFrame()->GetFrame();

  Document& doc = *frame->GetDocument();
  doc.body()->setInnerHTML("<input type=file>");
  auto& input = *To<HTMLInputElement>(doc.body()->firstChild());

  base::RunLoop run_loop;
  MockFileChooser chooser(frame->GetBrowserInterfaceBroker(),
                          run_loop.QuitClosure());

  // Calls MockFileChooser::OpenFileChooser().
  LocalFrame::NotifyUserActivation(
      frame, mojom::blink::UserActivationNotificationType::kInteraction);
  input.click();
  run_loop.Run();

  input.setType(input_type_names::kColor);

  FileChooserFileInfoList list;
  list.push_back(CreateFileChooserFileInfoNative("/path/to/file.txt", ""));
  chooser.ResponseOnOpenFileChooser(std::move(list));

  // Receiving a FileChooser response should not alter a shadow tree
  // for another type.
  EXPECT_TRUE(IsA<HTMLElement>(
      input.EnsureShadowSubtree()->firstChild()->firstChild()));
}

// Tests selecting same file twice should fire cancel event second time.
TEST(FileInputTypeTest, SetFilesFireCorrectEventsForSameFile) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;

  auto* document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  auto* input = MakeGarbageCollected<HTMLInputElement>(*document);
  InputType* file_input = MakeGarbageCollected<FileInputType>(*input);
  auto* listener_change = MakeGarbageCollected<MockEventListener>();
  auto* listener_cancel = MakeGarbageCollected<MockEventListener>();
  input->addEventListener(event_type_names::kChange, listener_change);
  input->addEventListener(event_type_names::kCancel, listener_cancel);
  auto reset = [&] {
    listener_change->ClearInvoked();
    listener_cancel->ClearInvoked();
  };

  auto* const selection_1 = MakeGarbageCollected<FileList>();
  selection_1->Append(MakeGarbageCollected<File>(
      &execution_context.GetExecutionContext(), "/path/to/A.txt"));
  file_input->SetFilesAndDispatchEvents(selection_1);
  EXPECT_TRUE(listener_change->invoked);
  EXPECT_FALSE(listener_cancel->invoked);

  reset();
  auto* const selection_2 = MakeGarbageCollected<FileList>();
  selection_2->Append(MakeGarbageCollected<File>(
      &execution_context.GetExecutionContext(), "/path/to/A.txt"));
  file_input->SetFilesAndDispatchEvents(selection_2);
  EXPECT_FALSE(listener_change->invoked);
  EXPECT_TRUE(listener_cancel->invoked);
}

// Tests selecting same files twice should fire cancel event second time.
TEST(FileInputTypeTest, SetFilesFireCorrectEventsForSameFiles) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;

  auto* document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  auto* input = MakeGarbageCollected<HTMLInputElement>(*document);
  InputType* file_input = MakeGarbageCollected<FileInputType>(*input);
  auto* listener_change = MakeGarbageCollected<MockEventListener>();
  auto* listener_cancel = MakeGarbageCollected<MockEventListener>();
  input->addEventListener(event_type_names::kChange, listener_change);
  input->addEventListener(event_type_names::kCancel, listener_cancel);
  input->SetBooleanAttribute(html_names::kMultipleAttr, true);
  auto reset = [&] {
    listener_change->ClearInvoked();
    listener_cancel->ClearInvoked();
  };

  auto* const selection_1 = MakeGarbageCollected<FileList>();
  selection_1->Append(MakeGarbageCollected<File>(
      &execution_context.GetExecutionContext(), "/path/to/A.txt"));
  selection_1->Append(MakeGarbageCollected<File>(
      &execution_context.GetExecutionContext(), "/path/to/B.txt"));
  file_input->SetFilesAndDispatchEvents(selection_1);
  EXPECT_TRUE(listener_change->invoked);
  EXPECT_FALSE(listener_cancel->invoked);

  reset();
  auto* const selection_2 = MakeGarbageCollected<FileList>();
  selection_2->Append(MakeGarbageCollected<File>(
      &execution_context.GetExecutionContext(), "/path/to/A.txt"));
  selection_2->Append(MakeGarbageCollected<File>(
      &execution_context.GetExecutionContext(), "/path/to/B.txt"));
  file_input->SetFilesAndDispatchEvents(selection_2);
  EXPECT_FALSE(listener_change->invoked);
  EXPECT_TRUE(listener_cancel->invoked);
}

// Tests selecting different file after first selection should fire change
// event.
TEST(FileInputTypeTest, SetFilesFireCorrectEventsForDifferentFile) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;

  auto* document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  auto* input = MakeGarbageCollected<HTMLInputElement>(*document);
  InputType* file_input = MakeGarbageCollected<FileInputType>(*input);
  auto* listener_change = MakeGarbageCollected<MockEventListener>();
  auto* listener_cancel = MakeGarbageCollected<MockEventListener>();
  input->addEventListener(event_type_names::kChange, listener_change);
  input->addEventListener(event_type_names::kCancel, listener_cancel);
  auto reset = [&] {
    listener_change->ClearInvoked();
    listener_cancel->ClearInvoked();
  };

  auto* const selection_1 = MakeGarbageCollected<FileList>();
  selection_1->Append(MakeGarbageCollected<File>(
      &execution_context.GetExecutionContext(), "/path/to/A.txt"));
  file_input->SetFilesAndDispatchEvents(selection_1);
  EXPECT_TRUE(listener_change->invoked);
  EXPECT_FALSE(listener_cancel->invoked);

  reset();
  auto* const selection_2 = MakeGarbageCollected<FileList>();
  selection_2->Append(MakeGarbageCollected<File>(
      &execution_context.GetExecutionContext(), "/path/to/B.txt"));
  file_input->SetFilesAndDispatchEvents(selection_2);
  EXPECT_TRUE(listener_change->invoked);
  EXPECT_FALSE(listener_cancel->invoked);
}

// Tests selecting different files after first selection should fire change
// event.
TEST(FileInputTypeTest, SetFilesFireCorrectEventsForDifferentFiles) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;

  auto* document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  auto* input = MakeGarbageCollected<HTMLInputElement>(*document);
  InputType* file_input = MakeGarbageCollected<FileInputType>(*input);
  auto* listener_change = MakeGarbageCollected<MockEventListener>();
  auto* listener_cancel = MakeGarbageCollected<MockEventListener>();
  input->addEventListener(event_type_names::kChange, listener_change);
  input->addEventListener(event_type_names::kCancel, listener_cancel);
  input->SetBooleanAttribute(html_names::kMultipleAttr, true);
  auto reset = [&] {
    listener_change->ClearInvoked();
    listener_cancel->ClearInvoked();
  };

  auto* const selection_1 = MakeGarbageCollected<FileList>();
  selection_1->Append(MakeGarbageCollected<File>(
      &execution_context.GetExecutionContext(), "/path/to/A.txt"));
  selection_1->Append(MakeGarbageCollected<File>(
      &execution_context.GetExecutionContext(), "/path/to/B.txt"));
  file_input->SetFilesAndDispatchEvents(selection_1);
  EXPECT_TRUE(listener_change->invoked);
  EXPECT_FALSE(listener_cancel->invoked);

  reset();
  auto* const selection_2 = MakeGarbageCollected<FileList>();
  selection_2->Append(MakeGarbageCollected<File>(
      &execution_context.GetExecutionContext(), "/path/to/A.txt"));
  file_input->SetFilesAndDispatchEvents(selection_2);
  EXPECT_TRUE(listener_change->invoked);
  EXPECT_FALSE(listener_cancel->invoked);
}

// Tests clearing selection (click cancel in file chooser) after selection
// should fire change event.
TEST(FileInputTypeTest, SetFilesFireCorrectEventsCancelWithSelection) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;

  auto* document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  auto* input = MakeGarbageCollected<HTMLInputElement>(*document);
  InputType* file_input = MakeGarbageCollected<FileInputType>(*input);
  auto* listener_change = MakeGarbageCollected<MockEventListener>();
  auto* listener_cancel = MakeGarbageCollected<MockEventListener>();
  input->addEventListener(event_type_names::kChange, listener_change);
  input->addEventListener(event_type_names::kCancel, listener_cancel);
  input->SetBooleanAttribute(html_names::kMultipleAttr, true);
  auto reset = [&] {
    listener_change->ClearInvoked();
    listener_cancel->ClearInvoked();
  };

  auto* const selection_1 = MakeGarbageCollected<FileList>();
  selection_1->Append(MakeGarbageCollected<File>(
      &execution_context.GetExecutionContext(), "/path/to/A.txt"));
  selection_1->Append(MakeGarbageCollected<File>(
      &execution_context.GetExecutionContext(), "/path/to/B.txt"));
  file_input->SetFilesAndDispatchEvents(selection_1);
  EXPECT_TRUE(listener_change->invoked);
  EXPECT_FALSE(listener_cancel->invoked);

  reset();
  auto* const selection_2 = MakeGarbageCollected<FileList>();
  file_input->SetFilesAndDispatchEvents(selection_2);
  EXPECT_TRUE(listener_change->invoked);
  EXPECT_FALSE(listener_cancel->invoked);
}

// Tests clearing selection (click cancel in file chooser) without selection
// should fire cancel event.
TEST(FileInputTypeTest, SetFilesFireCorrectEventsCancelWithoutSelection) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;

  auto* document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  auto* input = MakeGarbageCollected<HTMLInputElement>(*document);
  InputType* file_input = MakeGarbageCollected<FileInputType>(*input);
  auto* listener_change = MakeGarbageCollected<MockEventListener>();
  auto* listener_cancel = MakeGarbageCollected<MockEventListener>();
  input->addEventListener(event_type_names::kChange, listener_change);
  input->addEventListener(event_type_names::kCancel, listener_cancel);
  input->SetBooleanAttribute(html_names::kMultipleAttr, true);

  auto* const selection = MakeGarbageCollected<FileList>();
  file_input->SetFilesAndDispatchEvents(selection);
  EXPECT_FALSE(listener_change->invoked);
  EXPECT_TRUE(listener_cancel->invoked);
}

}  // namespace blink
```