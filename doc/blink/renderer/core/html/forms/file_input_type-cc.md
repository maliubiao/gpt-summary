Response:
Let's break down the thought process for analyzing this C++ file and generating the structured response.

1. **Understand the Goal:** The request asks for a breakdown of the file's functionality, its relationship with web technologies, logical deductions, and common usage errors. Essentially, it's asking for a comprehensive explanation of the `FileInputType` class in Blink.

2. **Initial Skim and Identification of Key Areas:**  The first step is to quickly read through the code, paying attention to the included headers and the methods defined within the `FileInputType` class. This helps identify the core responsibilities. Keywords like "file", "form", "input", "chooser", "drag", and "shadow" stand out. The headers point to dependencies on file APIs, form handling, DOM events, accessibility, and styling.

3. **Categorize Functionality:**  As I read, I start mentally grouping related functionalities. For example:
    * **File Handling:**  Loading, saving, appending files to form data, getting file lists.
    * **User Interaction:** Opening the file chooser dialog, handling clicks, keyboard events, drag-and-drop.
    * **Form Integration:**  Saving and restoring state, validation, appending to `FormData`.
    * **Rendering/UI:** Creating the shadow DOM, updating the displayed file names.
    * **Accessibility:**  Hiding shadow elements from the AX tree.
    * **Security/Permissions:**  Checking for user activation, handling fake paths, restricted value setting.
    * **Configuration:** Handling `multiple`, `accept`, and `webkitdirectory` attributes.

4. **Detail Each Category:**  Once the major categories are identified, I go back and analyze the code within each category more deeply.

    * **File Handling:** I look at methods like `CreateFileList`, `SetFiles`, `AppendToFormData`, `SaveFormControlState`, and `RestoreFormControlState`. I note how they interact with the `FileList` object.
    * **User Interaction:** I examine `HandleDOMActivateEvent`, `OpenPopupView`, `ReceiveDroppedFiles`, `HandleKeypressEvent`, and `HandleKeyupEvent`. I pay attention to the conditions for opening the file chooser (user activation, feature flags).
    * **Form Integration:** I analyze `ValueMissing`, `ValueMissingText`, `AppendToFormData`, `SaveFormControlState`, and `RestoreFormControlState`.
    * **Rendering/UI:** I look at `CreateShadowSubtree`, `UpdateView`, `FileStatusText`, and `AdjustStyle`. I identify the button and the status display elements.
    * **Accessibility:** I note the `aria-hidden` attributes.
    * **Security/Permissions:** I analyze the checks in `HandleDOMActivateEvent` and the logic in `CanSetValue` and `ValueInFilenameValueMode`.
    * **Configuration:** I see how the `accept` and `multiple` attributes are used in `CollectAcceptTypes` and `OpenPopupView`.

5. **Connect to Web Technologies (HTML, CSS, JavaScript):**  As I understand the functionality, I think about how these features manifest in web development:

    * **HTML:** The `<input type="file">` element, the `multiple`, `accept`, and `webkitdirectory` attributes.
    * **CSS:**  The ability to style the file input (though limited due to the shadow DOM), and how Blink might apply default styles. The `AdjustStyle` method hints at specific styling concerns.
    * **JavaScript:**  The `input.files` property, the `change` and `input` events, and how developers interact with the selected files.

6. **Identify Logical Inferences and Examples:**  Based on the code, I can make logical deductions and create illustrative examples:

    * **Assumption:** The `accept` attribute restricts file types. **Input:** `<input type="file" accept="image/*">`. **Output:** The file chooser will (ideally) filter for image files.
    * **Assumption:** The `multiple` attribute allows multiple file selection. **Input:** `<input type="file" multiple>`. **Output:** The file chooser will allow selecting multiple files, and `input.files` will be a `FileList` with multiple entries.

7. **Identify Common Usage Errors:**  By understanding the constraints and security measures, I can pinpoint common mistakes developers might make:

    * Trying to programmatically set the `value` of a file input.
    * Not understanding the "fakepath" behavior.
    * Forgetting about user activation requirements.

8. **Structure the Output:**  Finally, I organize the gathered information into a clear and structured format, using headings and bullet points for readability. I address each part of the original request (functionality, relationships, inferences, errors).

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  I might initially focus too much on the individual methods.
* **Correction:** I realize it's more effective to group related methods by functionality to provide a higher-level understanding.
* **Initial Thought:** I might forget to mention the shadow DOM initially.
* **Correction:** Recognizing the `CreateShadowSubtree` method and the mention of shadow elements prompts me to add a section about the shadow DOM and its implications.
* **Initial Thought:**  I might not explicitly link each feature to HTML, CSS, or JavaScript.
* **Correction:** I review each functional area and make sure to connect it to the relevant web technologies and their APIs.

By following this structured analysis and incorporating self-correction, I can arrive at a comprehensive and accurate explanation of the `FileInputType` class.
这个文件 `blink/renderer/core/html/forms/file_input_type.cc` 是 Chromium Blink 渲染引擎中负责处理 `<input type="file">` 元素的核心代码。它定义了 `FileInputType` 类，该类实现了文件选择输入类型的具体行为和功能。

以下是该文件的主要功能：

**1. 表示和管理文件选择输入元素的状态和行为:**

*   **创建和管理 `FileList`:**  它维护一个 `FileList` 对象 (`file_list_`)，用于存储用户选择的文件。
*   **保存和恢复表单状态:** 实现了 `SaveFormControlState` 和 `RestoreFormControlState`，允许在页面导航或表单重置时保存和恢复已选择的文件。
*   **处理文件选择:**  负责响应用户与文件输入框的交互，例如点击打开文件选择对话框。
*   **与原生文件系统交互:**  通过调用平台相关的 API 打开文件选择器，并将用户选择的文件信息转换为 `File` 对象。
*   **处理拖放事件:** 实现了 `ReceiveDroppedFiles`，允许用户通过拖放文件到输入框来选择文件。
*   **处理程序化设置文件:** 实现了 `SetFiles` 和 `SetFilesAndDispatchEvents`，允许通过 JavaScript 代码设置或更新选择的文件。

**2. 与 HTML 的关系:**

*   **实现 `<input type="file">` 元素的特定行为:** 这是该类的核心目的。当浏览器解析到 `<input type="file">` 标签时，会创建 `FileInputType` 对象来管理该元素的行为。
*   **处理 `accept` 属性:** `CollectAcceptTypes` 函数根据 `<input>` 元素的 `accept` 属性（指定允许的文件类型）构建文件选择器的过滤条件。
    *   **举例:**  `<input type="file" accept="image/*">`  这将限制用户只能选择图片文件。
*   **处理 `multiple` 属性:** 决定文件选择器是否允许多选。
    *   **举例:** `<input type="file" multiple>` 允许用户选择多个文件。
*   **处理 `webkitdirectory` 属性:**  允许用户选择整个目录。
    *   **举例:** `<input type="file" webkitdirectory>`  用户可以选择一个文件夹，该文件夹下的所有文件会被包含在 `FileList` 中。
*   **处理 `capture` 属性:** (在支持的平台上) 允许直接使用设备的摄像头或麦克风捕获媒体文件。
    *   **举例:** `<input type="file" capture="camera">`  会尝试直接打开摄像头供用户拍摄照片或视频。

**3. 与 JavaScript 的关系:**

*   **暴露 `files` 属性:**  该类维护的 `FileList` 对象可以通过 JavaScript 访问 `<input>` 元素的 `files` 属性。
    *   **举例:**  `const selectedFiles = document.querySelector('input[type="file"]').files;`  这将获取用户选择的文件列表。
*   **触发事件:** 当用户选择或更改文件时，会触发 `input` 和 `change` 事件，JavaScript 可以监听这些事件来处理文件。
    *   **举例:**
        ```javascript
        document.querySelector('input[type="file"]').addEventListener('change', (event) => {
          const files = event.target.files;
          console.log('Selected files:', files);
        });
        ```
*   **程序化设置 `files`:** 虽然出于安全原因，JavaScript 不能直接设置文件的完整路径，但可以使用 `DataTransfer` 对象在拖放操作中设置文件。`FileInputType` 提供了 `SetFilesAndDispatchEvents` 等方法来处理这种情况。

**4. 与 CSS 的关系:**

*   **样式调整:** `AdjustStyle` 方法允许对文件输入框的默认样式进行调整，例如设置溢出属性。
*   **Shadow DOM:**  该文件创建了一个 Shadow DOM (`CreateShadowSubtree`)，包含一个按钮和一个显示文件名状态的区域。这允许浏览器控制文件输入框的基本外观和交互，而开发者只能有限地修改其样式。
*   **伪元素:**  可以通过 CSS 伪元素 (例如 `::-webkit-file-upload-button`) 来修改文件上传按钮的样式，尽管这种方式受到限制。

**5. 逻辑推理和假设输入/输出:**

*   **假设输入 (HTML):**
    ```html
    <form>
      <input type="file" id="myFile" name="uploadedFile" accept=".txt,image/*" multiple>
      <button type="submit">上传</button>
    </form>
    ```
*   **用户操作:** 用户点击 "选择文件" 按钮，在文件选择器中选择了两个文件：一个名为 `document.txt` 的文本文件和一个名为 `photo.jpg` 的图片文件。
*   **`FileInputType` 的处理:**
    *   `CollectAcceptTypes` 将根据 `accept` 属性生成 `[".txt", "image/*"]`。
    *   文件选择器会过滤掉不符合类型的文件。
    *   `CreateFileList` 将创建包含 `File` 对象的 `FileList`，每个 `File` 对象代表选择的文件，包含文件名、大小、类型等信息。
    *   当表单提交时，`AppendToFormData` 会将这些文件添加到 `FormData` 对象中，以便上传到服务器。
*   **JavaScript 输出 (假设监听了 `change` 事件):**
    ```javascript
    const inputElement = document.getElementById('myFile');
    inputElement.addEventListener('change', (event) => {
      const files = event.target.files;
      console.log(files);
      // 输出类似 FileList 对象：
      // FileList { 0: File, 1: File, length: 2 }
      // 0: File { name: "document.txt", ... }
      // 1: File { name: "photo.jpg", ... }
    });
    ```

**6. 用户或编程常见的使用错误:**

*   **尝试通过 JavaScript 设置 `value` 属性来设置文件:**  出于安全原因，浏览器不允许 JavaScript 直接设置 `<input type="file">` 的 `value` 属性来指定要上传的文件。这样做会被忽略或抛出异常。
    *   **错误示例:** `document.getElementById('myFile').value = 'C:\\path\\to\\my\\file.txt';`
*   **假设可以获取文件的完整路径:**  为了保护用户隐私，浏览器通常不会将选择文件的完整本地路径暴露给 JavaScript。`input.files[0].path` 属性在大多数浏览器中不可用或已弃用。
*   **忘记处理 `change` 事件:**  如果没有监听 `change` 事件，就无法获取用户选择的文件。
*   **在没有用户激活的情况下打开文件选择器:**  出于安全原因，只能在用户明确的操作（例如点击事件）中打开文件选择器。尝试在没有用户交互的情况下调用 `inputElement.click()` 通常会被浏览器阻止。
    *   **代码示例 (错误):**
        ```javascript
        setTimeout(() => {
          document.getElementById('myFile').click(); // 可能会被阻止
        }, 1000);
        ```
*   **混淆 `value` 和 `files` 属性:**  `value` 属性通常只包含一个伪造的文件名（例如 "C:\fakepath\文件名"），主要用于兼容旧代码。要获取实际的文件信息，需要使用 `files` 属性。
*   **没有正确处理 `multiple` 属性:**  如果希望用户上传多个文件，必须在 HTML 中添加 `multiple` 属性，并在 JavaScript 中正确处理返回的 `FileList` 对象。

总而言之，`file_input_type.cc` 文件是 Blink 引擎中实现文件选择输入框功能的核心，它连接了 HTML 元素的定义、JavaScript 的交互以及底层操作系统提供的文件选择能力，并考虑了安全性和用户体验。

### 提示词
```
这是目录为blink/renderer/core/html/forms/file_input_type.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011 Apple Inc. All
 * rights reserved.
 * Copyright (C) 2010 Google Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#include "third_party/blink/renderer/core/html/forms/file_input_type.h"

#include "third_party/blink/public/platform/file_path_conversion.h"
#include "third_party/blink/public/strings/grit/blink_strings.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/fileapi/file.h"
#include "third_party/blink/renderer/core/fileapi/file_list.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/forms/form_controller.h"
#include "third_party/blink/renderer/core/html/forms/form_data.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/keywords.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/drag_data.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/file_metadata.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/platform_locale.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

using mojom::blink::FileChooserParams;

namespace {

Vector<String> CollectAcceptTypes(const HTMLInputElement& input) {
  Vector<String> mime_types = input.AcceptMIMETypes();
  Vector<String> extensions = input.AcceptFileExtensions();

  Vector<String> accept_types;
  accept_types.reserve(mime_types.size() + extensions.size());
  accept_types.AppendVector(mime_types);
  accept_types.AppendVector(extensions);
  return accept_types;
}

}  // namespace

FileInputType::FileInputType(HTMLInputElement& element)
    : InputType(Type::kFile, element),
      KeyboardClickableInputTypeView(element),
      file_list_(MakeGarbageCollected<FileList>()) {}

void FileInputType::Trace(Visitor* visitor) const {
  visitor->Trace(file_list_);
  KeyboardClickableInputTypeView::Trace(visitor);
  InputType::Trace(visitor);
}

InputTypeView* FileInputType::CreateView() {
  return this;
}

template <typename ItemType, typename VectorType>
VectorType CreateFilesFrom(const FormControlState& state,
                           ItemType (*factory)(const FormControlState&,
                                               wtf_size_t&)) {
  VectorType files;
  files.ReserveInitialCapacity(state.ValueSize() / 3);
  for (wtf_size_t i = 0; i < state.ValueSize();) {
    files.push_back(factory(state, i));
  }
  return files;
}

template <typename ItemType, typename VectorType>
VectorType CreateFilesFrom(const FormControlState& state,
                           ExecutionContext* execution_context,
                           ItemType (*factory)(ExecutionContext*,
                                               const FormControlState&,
                                               wtf_size_t&)) {
  VectorType files;
  files.ReserveInitialCapacity(state.ValueSize() / 3);
  for (wtf_size_t i = 0; i < state.ValueSize();) {
    files.push_back(factory(execution_context, state, i));
  }
  return files;
}

Vector<String> FileInputType::FilesFromFormControlState(
    const FormControlState& state) {
  return CreateFilesFrom<String, Vector<String>>(state,
                                                 &File::PathFromControlState);
}

FormControlState FileInputType::SaveFormControlState() const {
  if (file_list_->IsEmpty() ||
      GetElement().GetDocument().GetFormController().DropReferencedFilePaths())
    return FormControlState();
  FormControlState state;
  unsigned num_files = file_list_->length();
  for (unsigned i = 0; i < num_files; ++i)
    file_list_->item(i)->AppendToControlState(state);
  return state;
}

void FileInputType::RestoreFormControlState(const FormControlState& state) {
  if (state.ValueSize() % 3)
    return;
  ExecutionContext* execution_context = GetElement().GetExecutionContext();
  HeapVector<Member<File>> file_vector =
      CreateFilesFrom<File*, HeapVector<Member<File>>>(
          state, execution_context, &File::CreateFromControlState);
  auto* file_list = MakeGarbageCollected<FileList>();
  for (const auto& file : file_vector)
    file_list->Append(file);
  SetFiles(file_list);
}

void FileInputType::AppendToFormData(FormData& form_data) const {
  FileList* file_list = GetElement().files();
  unsigned num_files = file_list->length();
  ExecutionContext* context = GetElement().GetExecutionContext();
  if (num_files == 0) {
    form_data.AppendFromElement(GetElement().GetName(),
                                MakeGarbageCollected<File>(context, ""));
    return;
  }

  for (unsigned i = 0; i < num_files; ++i) {
    form_data.AppendFromElement(GetElement().GetName(), file_list->item(i));
  }
}

bool FileInputType::ValueMissing(const String& value) const {
  return GetElement().IsRequired() && value.empty();
}

String FileInputType::ValueMissingText() const {
  return GetLocale().QueryString(
      GetElement().Multiple() ? IDS_FORM_VALIDATION_VALUE_MISSING_MULTIPLE_FILE
                              : IDS_FORM_VALIDATION_VALUE_MISSING_FILE);
}

void FileInputType::HandleDOMActivateEvent(Event& event) {
  if (GetElement().IsDisabledFormControl())
    return;

  HTMLInputElement& input = GetElement();
  Document& document = input.GetDocument();

  if (!LocalFrame::HasTransientUserActivation(document.GetFrame())) {
    String message =
        "File chooser dialog can only be shown with a user activation.";
    document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        mojom::ConsoleMessageLevel::kWarning, message));
    return;
  }

  OpenPopupView();
  event.SetDefaultHandled();
}

void FileInputType::OpenPopupView() {
  HTMLInputElement& input = GetElement();
  Document& document = input.GetDocument();

  bool intercepted = false;
  probe::FileChooserOpened(document.GetFrame(), &input, input.Multiple(),
                           &intercepted);
  if (intercepted) {
    return;
  }

  if (ChromeClient* chrome_client = GetChromeClient()) {
    FileChooserParams params;
    bool is_directory =
        input.FastHasAttribute(html_names::kWebkitdirectoryAttr);
    if (is_directory)
      params.mode = FileChooserParams::Mode::kUploadFolder;
    else if (input.FastHasAttribute(html_names::kMultipleAttr))
      params.mode = FileChooserParams::Mode::kOpenMultiple;
    else
      params.mode = FileChooserParams::Mode::kOpen;
    params.title = g_empty_string;
    params.need_local_path = is_directory;
    params.accept_types = CollectAcceptTypes(input);
    params.selected_files = file_list_->PathsForUserVisibleFiles();
    params.use_media_capture = RuntimeEnabledFeatures::MediaCaptureEnabled() &&
                               input.FastHasAttribute(html_names::kCaptureAttr);
    params.requestor = document.Url();

    UseCounter::Count(
        document, GetElement().GetExecutionContext()->IsSecureContext()
                      ? WebFeature::kInputTypeFileSecureOriginOpenChooser
                      : WebFeature::kInputTypeFileInsecureOriginOpenChooser);
    chrome_client->OpenFileChooser(document.GetFrame(), NewFileChooser(params));
  }
}

void FileInputType::AdjustStyle(ComputedStyleBuilder& builder) {
  builder.SetShouldIgnoreOverflowPropertyForInlineBlockBaseline();
}

LayoutObject* FileInputType::CreateLayoutObject(const ComputedStyle&) const {
  return MakeGarbageCollected<LayoutBlockFlow>(&GetElement());
}

InputType::ValueMode FileInputType::GetValueMode() const {
  return ValueMode::kFilename;
}

bool FileInputType::CanSetStringValue() const {
  return false;
}

FileList* FileInputType::Files() {
  return file_list_.Get();
}

bool FileInputType::CanSetValue(const String& value) {
  // For security reasons, we don't allow setting the filename, but we do allow
  // clearing it.  The HTML5 spec (as of the 10/24/08 working draft) says that
  // the value attribute isn't applicable to the file upload control at all, but
  // for now we are keeping this behavior to avoid breaking existing websites
  // that may be relying on this.
  return value.empty();
}

String FileInputType::ValueInFilenameValueMode() const {
  if (file_list_->IsEmpty())
    return String();

  // HTML5 tells us that we're supposed to use this goofy value for
  // file input controls. Historically, browsers revealed the real
  // file path, but that's a privacy problem. Code on the web
  // decided to try to parse the value by looking for backslashes
  // (because that's what Windows file paths use). To be compatible
  // with that code, we make up a fake path for the file.
  return "C:\\fakepath\\" + file_list_->item(0)->name();
}

void FileInputType::SetValue(const String&,
                             bool value_changed,
                             TextFieldEventBehavior,
                             TextControlSetValueSelection) {
  if (!value_changed)
    return;

  file_list_->clear();
  GetElement().SetNeedsValidityCheck();
  UpdateView();
}

FileList* FileInputType::CreateFileList(ExecutionContext& context,
                                        const FileChooserFileInfoList& files,
                                        const base::FilePath& base_dir) {
  auto* file_list(MakeGarbageCollected<FileList>());
  wtf_size_t size = files.size();

  // If a directory is being selected, the UI allows a directory to be chosen
  // and the paths provided here should start with |base_dir|.
  // We want to store only the relative path starting with the basename of
  // |base_dir|.
  if (size && !base_dir.empty()) {
    base::FilePath root_path = base_dir.DirName();
    int root_length = FilePathToString(root_path).length();
    DCHECK(root_length);
    if (!root_path.EndsWithSeparator())
      root_length += 1;
    if (base_dir == root_path)
      root_length = 0;
    for (const auto& file : files) {
      // Normalize backslashes to slashes before exposing the relative path to
      // script.
      String string_path = FilePathToString(file->get_native_file()->file_path);
      String display_name = file->get_native_file()->display_name;
      if (display_name.empty()) {
        display_name =
            FilePathToString(file->get_native_file()->file_path.BaseName());
      }
      String relative_path;
#if BUILDFLAG(IS_ANDROID)
      // Android content-URIs do not use tree paths with separators like posix
      // so we build relative path using base_subdirs.
      if (base_dir.IsContentUri()) {
        StringBuilder builder;
        for (const auto& subdir : file->get_native_file()->base_subdirs) {
          builder.Append(subdir);
          builder.Append("/");
        }
        builder.Append(display_name);
        relative_path = builder.ToString();
      }
#endif
      if (relative_path.empty()) {
        DCHECK(
            string_path.StartsWithIgnoringASCIICase(FilePathToString(base_dir)))
            << "A path in a FileChooserFileInfo " << string_path
            << " should start with " << FilePathToString(base_dir);
        relative_path = string_path.Substring(root_length).Replace('\\', '/');
      }
      file_list->Append(File::CreateWithRelativePath(
          &context, string_path, display_name, relative_path));
    }
    return file_list;
  }

  for (const auto& file : files) {
    if (file->is_native_file()) {
      file_list->Append(File::CreateForUserProvidedFile(
          &context, FilePathToString(file->get_native_file()->file_path),
          file->get_native_file()->display_name));
    } else {
      const auto& fs_info = file->get_file_system();
      FileMetadata metadata;
      metadata.modification_time =
          NullableTimeToOptionalTime(fs_info->modification_time);
      metadata.length = fs_info->length;
      metadata.type = FileMetadata::kTypeFile;
      file_list->Append(File::CreateForFileSystemFile(
          context, fs_info->url, metadata, File::kIsUserVisible));
    }
  }
  return file_list;
}

void FileInputType::CountUsage() {
  ExecutionContext* context = GetElement().GetExecutionContext();
  if (context->IsSecureContext())
    UseCounter::Count(context, WebFeature::kInputTypeFileSecureOrigin);
  else
    UseCounter::Count(context, WebFeature::kInputTypeFileInsecureOrigin);
}

void FileInputType::CreateShadowSubtree() {
  DCHECK(IsShadowHost(GetElement()));
  Document& document = GetElement().GetDocument();

  auto* button = MakeGarbageCollected<HTMLInputElement>(document);
  button->setType(input_type_names::kButton);
  button->setAttribute(
      html_names::kValueAttr,
      AtomicString(GetLocale().QueryString(
          GetElement().Multiple() ? IDS_FORM_MULTIPLE_FILES_BUTTON_LABEL
                                  : IDS_FORM_FILE_BUTTON_LABEL)));
  button->SetShadowPseudoId(shadow_element_names::kPseudoFileUploadButton);
  button->setAttribute(html_names::kIdAttr,
                       shadow_element_names::kIdFileUploadButton);
  button->SetActive(GetElement().CanReceiveDroppedFiles());
  GetElement().UserAgentShadowRoot()->AppendChild(button);

  auto* span = document.CreateRawElement(html_names::kSpanTag);
  GetElement().UserAgentShadowRoot()->AppendChild(span);

  // The file input element is presented to AX as one node with the role button,
  // instead of the individual button and text nodes. That's the reason we hide
  // the shadow root elements of the file input in the AX tree.
  button->setAttribute(html_names::kAriaHiddenAttr, keywords::kTrue);
  span->setAttribute(html_names::kAriaHiddenAttr, keywords::kTrue);

  UpdateView();
}

HTMLInputElement* FileInputType::UploadButton() const {
  Element* element = GetElement().EnsureShadowSubtree()->getElementById(
      shadow_element_names::kIdFileUploadButton);
  CHECK(!element || IsA<HTMLInputElement>(element));
  return To<HTMLInputElement>(element);
}

Node* FileInputType::FileStatusElement() const {
  return GetElement().EnsureShadowSubtree()->lastChild();
}

void FileInputType::DisabledAttributeChanged() {
  DCHECK(RuntimeEnabledFeatures::CreateInputShadowTreeDuringLayoutEnabled() ||
         IsShadowHost(GetElement()));
  if (Element* button = UploadButton()) {
    button->SetBooleanAttribute(html_names::kDisabledAttr,
                                GetElement().IsDisabledFormControl());
  }
}

void FileInputType::MultipleAttributeChanged() {
  DCHECK(RuntimeEnabledFeatures::CreateInputShadowTreeDuringLayoutEnabled() ||
         IsShadowHost(GetElement()));
  if (Element* button = UploadButton()) {
    button->setAttribute(
        html_names::kValueAttr,
        AtomicString(GetLocale().QueryString(
            GetElement().Multiple() ? IDS_FORM_MULTIPLE_FILES_BUTTON_LABEL
                                    : IDS_FORM_FILE_BUTTON_LABEL)));
  }
}

bool FileInputType::SetFiles(FileList* files) {
  if (!files)
    return false;

  bool files_changed = false;
  if (files->length() != file_list_->length()) {
    files_changed = true;
  } else {
    for (unsigned i = 0; i < files->length(); ++i) {
      if (!files->item(i)->HasSameSource(*file_list_->item(i))) {
        files_changed = true;
        break;
      }
    }
  }

  file_list_ = files;

  GetElement().NotifyFormStateChanged();
  GetElement().SetNeedsValidityCheck();
  UpdateView();
  return files_changed;
}

void FileInputType::SetFilesAndDispatchEvents(FileList* files) {
  if (SetFiles(files)) {
    // This call may cause destruction of this instance.
    // input instance is safe since it is ref-counted.
    GetElement().DispatchInputEvent();
    GetElement().DispatchChangeEvent();
    if (AXObjectCache* cache =
            GetElement().GetDocument().ExistingAXObjectCache()) {
      cache->HandleValueChanged(&GetElement());
    }
  } else {
    GetElement().DispatchCancelEvent();
  }
}

void FileInputType::FilesChosen(FileChooserFileInfoList files,
                                const base::FilePath& base_dir) {
  for (wtf_size_t i = 0; i < files.size();) {
    // Drop files of which names can not be converted to WTF String. We
    // can't expose such files via File API.
    if (files[i]->is_native_file() &&
        FilePathToString(files[i]->get_native_file()->file_path).empty()) {
      files.EraseAt(i);
      // Do not increment |i|.
      continue;
    }
    ++i;
  }
  if (!will_be_destroyed_) {
    SetFilesAndDispatchEvents(
        CreateFileList(*GetElement().GetExecutionContext(), files, base_dir));
  }
  if (HasConnectedFileChooser())
    DisconnectFileChooser();
}

LocalFrame* FileInputType::FrameOrNull() const {
  return GetElement().GetDocument().GetFrame();
}

void FileInputType::SetFilesFromDirectory(const String& path) {
  FileChooserParams params;
  params.mode = FileChooserParams::Mode::kUploadFolder;
  params.title = g_empty_string;
  params.selected_files.push_back(StringToFilePath(path));
  params.accept_types = CollectAcceptTypes(GetElement());
  params.requestor = GetElement().GetDocument().Url();
  NewFileChooser(params)->EnumerateChosenDirectory();
}

void FileInputType::SetFilesFromPaths(const Vector<String>& paths) {
  if (paths.empty())
    return;

  HTMLInputElement& input = GetElement();
  if (input.FastHasAttribute(html_names::kWebkitdirectoryAttr)) {
    SetFilesFromDirectory(paths[0]);
    return;
  }

  FileChooserFileInfoList files;
  for (const auto& path : paths)
    files.push_back(CreateFileChooserFileInfoNative(path));

  if (input.FastHasAttribute(html_names::kMultipleAttr)) {
    FilesChosen(std::move(files), base::FilePath());
  } else {
    FileChooserFileInfoList first_file_only;
    first_file_only.push_back(std::move(files[0]));
    FilesChosen(std::move(first_file_only), base::FilePath());
  }
}

bool FileInputType::ReceiveDroppedFiles(const DragData* drag_data) {
  Vector<String> paths;
  drag_data->AsFilePaths(paths);
  if (paths.empty())
    return false;

  if (!GetElement().FastHasAttribute(html_names::kWebkitdirectoryAttr)) {
    dropped_file_system_id_ = drag_data->DroppedFileSystemId();
  }
  SetFilesFromPaths(paths);
  return true;
}

String FileInputType::DroppedFileSystemId() {
  return dropped_file_system_id_;
}

String FileInputType::DefaultToolTip(const InputTypeView&) const {
  FileList* file_list = file_list_.Get();
  unsigned list_size = file_list->length();
  if (!list_size) {
    return GetLocale().QueryString(IDS_FORM_FILE_NO_FILE_LABEL);
  }

  StringBuilder names;
  for (wtf_size_t i = 0; i < list_size; ++i) {
    names.Append(file_list->item(i)->name());
    if (i != list_size - 1)
      names.Append('\n');
  }
  return names.ToString();
}

void FileInputType::CopyNonAttributeProperties(const HTMLInputElement& source) {
  DCHECK(file_list_->IsEmpty());
  const FileList* source_list = source.files();
  for (unsigned i = 0; i < source_list->length(); ++i)
    file_list_->Append(source_list->item(i)->Clone());
}

void FileInputType::HandleKeypressEvent(KeyboardEvent& event) {
  if (GetElement().FastHasAttribute(html_names::kWebkitdirectoryAttr)) {
    // Override to invoke the action on Enter key up (not press) to avoid
    // repeats committing the file chooser.
    if (event.key() == keywords::kCapitalEnter) {
      event.SetDefaultHandled();
      return;
    }
  }
  KeyboardClickableInputTypeView::HandleKeypressEvent(event);
}

void FileInputType::HandleKeyupEvent(KeyboardEvent& event) {
  if (GetElement().FastHasAttribute(html_names::kWebkitdirectoryAttr)) {
    // Override to invoke the action on Enter key up (not press) to avoid
    // repeats committing the file chooser.
    if (event.key() == keywords::kCapitalEnter) {
      GetElement().DispatchSimulatedClick(&event);
      event.SetDefaultHandled();
      return;
    }
  }
  KeyboardClickableInputTypeView::HandleKeyupEvent(event);
}

void FileInputType::WillOpenPopup() {
  // TODO(tkent): Should we disconnect the file chooser? crbug.com/637639
  if (HasConnectedFileChooser()) {
    UseCounter::Count(GetElement().GetDocument(),
                      WebFeature::kPopupOpenWhileFileChooserOpened);
  }
}

String FileInputType::FileStatusText() const {
  Locale& locale = GetLocale();

  if (file_list_->IsEmpty())
    return locale.QueryString(IDS_FORM_FILE_NO_FILE_LABEL);

  if (file_list_->length() == 1)
    return LayoutTheme::GetTheme().DisplayNameForFile(*file_list_->item(0));

  return locale.QueryString(
      IDS_FORM_FILE_MULTIPLE_UPLOAD,
      locale.ConvertToLocalizedNumber(String::Number(file_list_->length())));
}

void FileInputType::UpdateView() {
  if (auto* span = FileStatusElement())
    span->setTextContent(FileStatusText());
}

}  // namespace blink
```