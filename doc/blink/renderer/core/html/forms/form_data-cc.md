Response:
Let's break down the thought process for analyzing the `FormData.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the `FormData.cc` file, its relationship with web technologies (HTML, CSS, JavaScript), potential logical inferences, and common usage errors.

2. **Identify the Core Class:** The filename `form_data.cc` and the initial lines of the code immediately point to the central class: `blink::FormData`. This is the primary focus of the analysis.

3. **Scan for Key Methods:** Look for public methods of the `FormData` class. These are the actions users (both developers and the browser itself) can perform with `FormData` objects. Keywords like `Create`, `append`, `deleteEntry`, `get`, `getAll`, `has`, `set`, and `Encode` are good starting points.

4. **Group Functionality:** Categorize the identified methods based on their purpose. This leads to groups like:
    * **Creation:**  `Create` methods handle the instantiation of `FormData` objects.
    * **Modification:** `append`, `deleteEntry`, `set` methods allow changing the data within a `FormData` object.
    * **Access:** `get`, `getAll`, `has`, and iteration through the `FormData` provide ways to retrieve data.
    * **Encoding:** `EncodeFormData`, `EncodeMultiPartFormData` deal with converting the data into a format suitable for transmission.
    * **Internal/Supporting:**  Methods like `Trace`, the constructor, and the nested `Entry` class support the core functionality.

5. **Analyze Each Function Group:**
    * **Creation:**  Notice the different `Create` methods. One takes an `HTMLFormElement`, suggesting its role in capturing form data directly from the DOM. The other is a default constructor. The handling of the `submitter` element in one `Create` method is a detail worth noting.
    * **Modification:**  The `append` methods are overloaded to handle both strings and `Blob`/`File` objects. This signifies its role in handling various types of form data. `deleteEntry` and `set` provide standard ways to remove and update data.
    * **Access:** `get`, `getAll`, and `has` provide standard dictionary-like access to the form data. The iteration capability (`CreateIterationSource`) is also important for processing all entries.
    * **Encoding:** The presence of `EncodeFormData` and `EncodeMultiPartFormData` highlights how `FormData` prepares data for network requests (e.g., submitting a form). The difference between the two encoding types is crucial.
    * **Internal/Supporting:** The `Entry` class structure reveals how individual form fields (name-value pairs or name-file pairs) are stored.

6. **Connect to Web Technologies (HTML, CSS, JavaScript):**  This is where the "why" and "how" come in.
    * **HTML:** The `Create` method taking `HTMLFormElement` directly links `FormData` to HTML forms. The explanation should detail how JavaScript can use `FormData` to represent form data without a traditional form submission.
    * **JavaScript:** The API (`append`, `get`, etc.) is directly exposed to JavaScript. The example of using `FormData` with `fetch` demonstrates this interaction.
    * **CSS:**  The connection to CSS is indirect. CSS styles the form, but `FormData` deals with the *data* collected by the form. It's important to acknowledge this distinction.

7. **Identify Logical Inferences:**  Look for areas where the code makes decisions or performs actions based on input.
    * **Encoding Type:** The choice between URL-encoded and multipart/form-data encoding based on the presence of files is a key inference.
    * **Filename Handling:** How the filename is determined for `Blob` and `File` objects during encoding is a logical step.

8. **Consider Common Usage Errors:** Think about mistakes developers might make when working with `FormData`.
    * **Appending the same name multiple times:**  The behavior of `get` vs. `getAll` needs to be clarified.
    * **Incorrectly setting the filename for blobs:**  Highlight the importance of the `filename` parameter in `append`.
    * **Misunderstanding encoding types:** Explain when to use each encoding and the consequences of choosing the wrong one.
    * **Trying to modify a FormData object after it's been used in a request:**  While not explicitly enforced by the code *provided*,  it's a common misconception based on how requests work. (Though the current code doesn't show any mutability issues after creation,  it's good to consider potential implications in a larger context.)

9. **Provide Examples (Hypothetical Inputs and Outputs):** Concrete examples make the explanations clearer. Demonstrate how `append` adds data, how `get` retrieves it, and the different encoding outputs. Keep the examples simple and focused.

10. **Structure and Clarity:** Organize the information logically with clear headings and bullet points. Use concise language and avoid overly technical jargon where possible. Emphasize the key takeaways.

11. **Review and Refine:**  Read through the explanation to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that could be explained better. For example, initially, I might have forgotten to mention the iteration capabilities, but reviewing the code would bring it to my attention.

This systematic approach ensures that all aspects of the request are addressed comprehensively and that the explanation is informative and easy to understand.
好的，让我们来详细分析一下 `blink/renderer/core/html/forms/form_data.cc` 这个文件。

**文件功能概述:**

`FormData.cc` 文件定义了 `blink::FormData` 类，这个类在 Chromium Blink 引擎中用于表示 **HTML 表单的数据**。它的主要功能是：

1. **存储表单数据:**  `FormData` 对象可以存储表单中各种类型的数据，包括：
    * 文本输入框的值 (String)
    * 文件 (File, Blob)
    * 提交按钮的名称和值 (虽然通常不显式存储，但参与表单提交过程)
2. **构建表单数据:**  可以通过多种方式创建 `FormData` 对象：
    * 直接通过 JavaScript 的 `FormData` 构造函数创建。
    * 从 `HTMLFormElement` 对象中自动提取数据。
3. **操作表单数据:**  提供了一组方法来添加、删除、获取和设置表单数据中的条目 (name-value 对或 name-file 对)。
4. **编码表单数据:**  可以将 `FormData` 对象编码成不同的格式，用于网络传输，例如：
    * `application/x-www-form-urlencoded` (URL 编码)
    * `multipart/form-data` (多部分表单数据，用于上传文件)
5. **支持迭代:**  实现了迭代器接口，可以方便地遍历 `FormData` 中的所有条目。
6. **与表单元素的交互:**  与 `HTMLFormElement` 等表单相关元素紧密合作，用于获取表单的初始数据和处理表单提交。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:** `FormData` 对象是 JavaScript 中可直接访问的 API，用于在客户端处理表单数据。
    * **创建 `FormData` 对象:**
      ```javascript
      const formData = new FormData();
      formData.append('username', 'john_doe');
      formData.append('password', 'secret');
      ```
    * **从 HTML 表单获取数据:**
      ```javascript
      const formElement = document.getElementById('myForm');
      const formDataFromForm = new FormData(formElement);
      ```
    * **与 `fetch` 或 `XMLHttpRequest` 一起使用发送表单数据:**
      ```javascript
      fetch('/submit', {
        method: 'POST',
        body: formData,
      });
      ```
    * **`FormData.append()` 添加数据，对应 `FormData::append()` 方法:** JavaScript 的 `formData.append('name', 'value')` 会最终调用 C++ 层的 `FormData::append()` 方法来存储数据。
    * **`FormData.get()` 获取数据，对应 `FormData::get()` 方法:** JavaScript 的 `formData.get('username')` 会调用 C++ 层的 `FormData::get()` 来获取对应的值。

* **HTML:** `FormData` 对象表示 HTML 表单的数据。
    * **`<form>` 元素:** `FormData::Create(HTMLFormElement* form, ...)` 方法被调用时，会遍历 HTML 表单中的各种输入元素 (`<input>`, `<select>`, `<textarea>`, `<button>`, `<file>`)，提取它们的 `name` 和 `value` (或文件)。
    * **`<input type="file">`:** 当表单包含文件上传控件时，`FormData` 对象会存储 `File` 或 `Blob` 对象，这直接关联到 HTML 中的 `<input type="file">` 元素。
    * **表单提交:** 当 HTML 表单提交时，浏览器内部会使用 `FormData` 对象来构建请求体，然后发送到服务器。

* **CSS:** CSS 主要负责表单的样式和布局，与 `FormData` 的功能没有直接关系。`FormData` 关注的是表单的 *数据*，而不是数据的展示方式。

**逻辑推理 (假设输入与输出):**

假设我们有一个包含文本输入框和文件上传控件的 HTML 表单：

```html
<form id="myTestForm">
  <input type="text" name="name" value="Example Name">
  <input type="file" name="avatar">
</form>
```

**场景 1: 通过 JavaScript 创建 `FormData` 并添加数据:**

* **假设输入:**
  ```javascript
  const formData = new FormData();
  formData.append('username', 'testuser');
  const fileInput = document.querySelector('input[type="file"]');
  formData.append('profile', fileInput.files[0]);
  ```
* **逻辑推理:** `FormData` 对象将包含两个条目：
    * `name`: "username", `value`: "testuser" (String 类型)
    * `name`: "profile", `value`:  一个 `File` 对象 (或 `Blob` 对象，取决于文件 API)
* **预期输出 (C++ 层面 `FormData` 对象的内部状态):**  `entries_` 成员变量将包含两个 `Entry` 对象：
    * `Entry("username", "testuser")`
    * `Entry("profile", File 或 Blob 对象, filename)`

**场景 2: 从 HTML 表单创建 `FormData`:**

* **假设输入:**
  ```javascript
  const formElement = document.getElementById('myTestForm');
  const formDataFromForm = new FormData(formElement);
  ```
* **逻辑推理:** `FormData::Create()` 方法会被调用，遍历 `myTestForm` 中的元素，提取数据。
* **预期输出 (C++ 层面 `FormData` 对象的内部状态):** `entries_` 成员变量将包含：
    * `Entry("name", "Example Name")`
    * 如果用户选择了文件，则包含 `Entry("avatar", File 对象, filename)`；否则可能不包含此条目，或者包含一个空的 `File` 对象 (具体行为取决于浏览器实现)。

**用户或编程常见的使用错误举例说明:**

1. **尝试直接修改 `FormData` 对象中的文件内容:**  `FormData` 存储的是对 `File` 或 `Blob` 对象的引用，而不是文件内容的副本。直接修改这些对象会影响到其他引用它们的地方。应该创建新的 `Blob` 或 `File` 对象来修改内容。

2. **混淆 `FormData.append()` 和 `FormData.set()` 的行为:**
   * `append()` 会添加一个新的条目，即使已经存在同名的条目，也会添加多个。
   * `set()` 会更新或添加条目。如果存在同名的条目，它会删除所有旧的同名条目，并添加一个新的条目。

   ```javascript
   const formData = new FormData();
   formData.append('items', 'apple');
   formData.append('items', 'banana');
   console.log(formData.getAll('items')); // 输出: ["apple", "banana"]

   formData.set('items', 'orange');
   console.log(formData.getAll('items')); // 输出: ["orange"]
   ```

3. **忘记为 `Blob` 指定文件名:** 当使用 `FormData.append(name, blob)` 添加 `Blob` 对象时，可能需要显式指定文件名，尤其是在需要服务器正确处理文件时。可以使用 `FormData.append(name, blob, filename)`。

4. **在 `fetch` 或 `XMLHttpRequest` 中错误地设置 `Content-Type`:** 当 `body` 是 `FormData` 对象时，浏览器会自动设置正确的 `Content-Type` (通常是 `multipart/form-data` 或 `application/x-www-form-urlencoded`)。手动设置可能会导致发送失败或服务器解析错误。

5. **在处理文件上传时，服务器端没有正确处理 `multipart/form-data`:**  客户端使用 `FormData` 发送文件时，通常会使用 `multipart/form-data` 编码。服务器端需要相应的逻辑来解析这种格式的数据。如果服务器端只期望 `application/x-www-form-urlencoded`，则文件上传会失败。

6. **对 `FormData` 对象使用不支持的方法:** 例如，尝试使用数组的方法（如 `push`）来添加数据，这是不正确的，应该使用 `append()`。

7. **假设 `FormData` 的迭代顺序与添加顺序一致:** 虽然通常情况下是这样的，但规范并没有严格保证迭代顺序。如果对顺序有严格要求，可能需要在添加数据时进行额外的处理。

总而言之，`FormData.cc` 文件是 Blink 引擎中处理 HTML 表单数据的核心组件，它连接了 JavaScript API 和底层的表单数据表示和编码逻辑，使得浏览器能够有效地管理和传输表单数据。理解这个文件的功能有助于我们更好地理解浏览器如何处理表单提交以及如何在 JavaScript 中操作表单数据。

### 提示词
```
这是目录为blink/renderer/core/html/forms/form_data.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2010 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/html/forms/form_data.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_file_usvstring.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fileapi/blob.h"
#include "third_party/blink/renderer/core/fileapi/file.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/forms/form_controller.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/network/form_data_encoder.h"
#include "third_party/blink/renderer/platform/wtf/text/line_ending.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

class FormDataIterationSource final
    : public PairSyncIterable<FormData>::IterationSource {
 public:
  FormDataIterationSource(FormData* form_data)
      : form_data_(form_data), current_(0) {}

  bool FetchNextItem(ScriptState* script_state,
                     String& name,
                     V8FormDataEntryValue*& value,
                     ExceptionState& exception_state) override {
    if (current_ >= form_data_->size())
      return false;

    const FormData::Entry& entry = *form_data_->Entries()[current_++];
    name = entry.name();
    if (entry.IsString()) {
      value = MakeGarbageCollected<V8FormDataEntryValue>(entry.Value());
    } else {
      DCHECK(entry.isFile());
      value = MakeGarbageCollected<V8FormDataEntryValue>(entry.GetFile());
    }
    return true;
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(form_data_);
    PairSyncIterable<FormData>::IterationSource::Trace(visitor);
  }

 private:
  const Member<FormData> form_data_;
  wtf_size_t current_;
};

}  // namespace

FormData::FormData(const WTF::TextEncoding& encoding) : encoding_(encoding) {}

FormData::FormData(const FormData& form_data)
    : encoding_(form_data.encoding_),
      entries_(form_data.entries_),
      contains_password_data_(form_data.contains_password_data_) {}

FormData::FormData() : encoding_(UTF8Encoding()) {}

FormData* FormData::Create(HTMLFormElement* form,
                           ExceptionState& exception_state) {
  return FormData::Create(form, nullptr, exception_state);
}

// https://xhr.spec.whatwg.org/#dom-formdata
FormData* FormData::Create(HTMLFormElement* form,
                           HTMLElement* submitter,
                           ExceptionState& exception_state) {
  if (!form) {
    return MakeGarbageCollected<FormData>();
  }
  // 1. If form is given, then:
  HTMLFormControlElement* control = nullptr;
  // 1.1. If submitter is non-null, then:
  if (submitter) {
    // 1.1.1. If submitter is not a submit button, then throw a TypeError.
    control = DynamicTo<HTMLFormControlElement>(submitter);
    if (!control || !control->CanBeSuccessfulSubmitButton()) {
      exception_state.ThrowTypeError(
          "The specified element is not a submit button.");
      return nullptr;
    }
    // 1.1.2. If submitter's form owner is not this form element, then throw a
    // "NotFoundError" DOMException.
    if (control->formOwner() != form) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kNotFoundError,
          "The specified element is not owned by this form element.");
      return nullptr;
    }
  }
  // 1.2. Let list be the result of constructing the entry list for form and
  // submitter.
  FormData* form_data = form->ConstructEntryList(control, UTF8Encoding());
  // 1.3. If list is null, then throw an "InvalidStateError" DOMException.
  if (!form_data) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The form is constructing entry list.");
    return nullptr;
  }
  // 1.4. Set this’s entry list to list.
  // Return a shallow copy of |form_data| because |form_data| is visible in
  // "formdata" event, and the specification says it should be different from
  // the FormData object to be returned.
  return MakeGarbageCollected<FormData>(*form_data);
}

void FormData::Trace(Visitor* visitor) const {
  visitor->Trace(entries_);
  ScriptWrappable::Trace(visitor);
}

void FormData::append(const String& name, const String& value) {
  entries_.push_back(MakeGarbageCollected<Entry>(name, value));
}

void FormData::append(ScriptState* script_state,
                      const String& name,
                      Blob* blob,
                      const String& filename) {
  if (!blob) {
    UseCounter::Count(ExecutionContext::From(script_state),
                      WebFeature::kFormDataAppendNull);
  }
  append(name, blob, filename);
}

void FormData::deleteEntry(const String& name) {
  wtf_size_t i = 0;
  while (i < entries_.size()) {
    if (entries_[i]->name() == name) {
      entries_.EraseAt(i);
    } else {
      ++i;
    }
  }
}

V8FormDataEntryValue* FormData::get(const String& name) {
  for (const auto& entry : Entries()) {
    if (entry->name() == name) {
      if (entry->IsString()) {
        return MakeGarbageCollected<V8FormDataEntryValue>(entry->Value());
      } else {
        DCHECK(entry->isFile());
        return MakeGarbageCollected<V8FormDataEntryValue>(entry->GetFile());
      }
    }
  }
  return nullptr;
}

HeapVector<Member<V8FormDataEntryValue>> FormData::getAll(const String& name) {
  HeapVector<Member<V8FormDataEntryValue>> results;

  for (const auto& entry : Entries()) {
    if (entry->name() != name)
      continue;
    V8FormDataEntryValue* value;
    if (entry->IsString()) {
      value = MakeGarbageCollected<V8FormDataEntryValue>(entry->Value());
    } else {
      DCHECK(entry->isFile());
      value = MakeGarbageCollected<V8FormDataEntryValue>(entry->GetFile());
    }
    results.push_back(value);
  }
  return results;
}

bool FormData::has(const String& name) {
  for (const auto& entry : Entries()) {
    if (entry->name() == name)
      return true;
  }
  return false;
}

void FormData::set(const String& name, const String& value) {
  SetEntry(MakeGarbageCollected<Entry>(name, value));
}

void FormData::set(const String& name, Blob* blob, const String& filename) {
  SetEntry(MakeGarbageCollected<Entry>(name, blob, filename));
}

void FormData::SetEntry(const Entry* entry) {
  DCHECK(entry);
  bool found = false;
  wtf_size_t i = 0;
  while (i < entries_.size()) {
    if (entries_[i]->name() != entry->name()) {
      ++i;
    } else if (found) {
      entries_.EraseAt(i);
    } else {
      found = true;
      entries_[i] = entry;
      ++i;
    }
  }
  if (!found)
    entries_.push_back(entry);
}

void FormData::append(const String& name, Blob* blob, const String& filename) {
  entries_.push_back(MakeGarbageCollected<Entry>(name, blob, filename));
}

void FormData::AppendFromElement(const String& name, int value) {
  append(ReplaceUnmatchedSurrogates(name), String::Number(value));
}

void FormData::AppendFromElement(const String& name, File* file) {
  entries_.push_back(MakeGarbageCollected<Entry>(
      ReplaceUnmatchedSurrogates(name), file, String()));
}

void FormData::AppendFromElement(const String& name, const String& value) {
  entries_.push_back(MakeGarbageCollected<Entry>(
      ReplaceUnmatchedSurrogates(name), ReplaceUnmatchedSurrogates(value)));
}

std::string FormData::Encode(const String& string) const {
  return encoding_.Encode(string, WTF::kEntitiesForUnencodables);
}

scoped_refptr<EncodedFormData> FormData::EncodeFormData(
    EncodedFormData::EncodingType encoding_type) {
  scoped_refptr<EncodedFormData> form_data = EncodedFormData::Create();
  Vector<char> encoded_data;
  for (const auto& entry : Entries()) {
    FormDataEncoder::AddKeyValuePairAsFormData(
        encoded_data, Encode(entry->name()),
        entry->isFile()
            ? Encode(ReplaceUnmatchedSurrogates(entry->GetFile()->name()))
            : Encode(entry->Value()),
        encoding_type);
  }
  form_data->AppendData(encoded_data);
  return form_data;
}

scoped_refptr<EncodedFormData> FormData::EncodeMultiPartFormData() {
  scoped_refptr<EncodedFormData> form_data = EncodedFormData::Create();
  form_data->SetBoundary(FormDataEncoder::GenerateUniqueBoundaryString());
  Vector<char> encoded_data;
  for (const auto& entry : Entries()) {
    Vector<char> header;
    FormDataEncoder::BeginMultiPartHeader(header, form_data->Boundary().data(),
                                          Encode(entry->name()));

    // If the current type is blob, then we also need to include the
    // filename.
    if (entry->GetBlob()) {
      String name;
      if (auto* file = DynamicTo<File>(entry->GetBlob())) {
        // For file blob, use the filename (or relative path if it is
        // present) as the name.
        name = file->webkitRelativePath().empty() ? file->name()
                                                  : file->webkitRelativePath();

        // If a filename is passed in FormData.append(), use it instead
        // of the file blob's name.
        if (!entry->Filename().IsNull())
          name = entry->Filename();
      } else {
        // For non-file blob, use the filename if it is passed in
        // FormData.append().
        if (!entry->Filename().IsNull())
          name = entry->Filename();
        else
          name = "blob";
      }

      // We have to include the filename=".." part in the header, even if
      // the filename is empty.
      FormDataEncoder::AddFilenameToMultiPartHeader(header, Encoding(), name);

      // Add the content type if available, or "application/octet-stream"
      // otherwise (RFC 1867).
      String content_type;
      if (entry->GetBlob()->type().empty())
        content_type = "application/octet-stream";
      else
        content_type = entry->GetBlob()->type();
      FormDataEncoder::AddContentTypeToMultiPartHeader(header, content_type);
    }

    FormDataEncoder::FinishMultiPartHeader(header);

    // Append body
    form_data->AppendData(header);
    if (entry->GetBlob()) {
      if (entry->GetBlob()->HasBackingFile()) {
        auto* file = To<File>(entry->GetBlob());
        // Do not add the file if the path is empty.
        if (!file->GetPath().empty())
          form_data->AppendFile(file->GetPath(), file->LastModifiedTime());
      } else {
        form_data->AppendBlob(entry->GetBlob()->GetBlobDataHandle());
      }
    } else {
      std::string encoded_value =
          Encode(NormalizeLineEndingsToCRLF(entry->Value()));
      form_data->AppendData(encoded_value);
    }
    form_data->AppendData(base::span_from_cstring("\r\n"));
  }
  FormDataEncoder::AddBoundaryToMultiPartHeader(
      encoded_data, form_data->Boundary().data(), true);
  form_data->AppendData(encoded_data);
  return form_data;
}

PairSyncIterable<FormData>::IterationSource* FormData::CreateIterationSource(
    ScriptState*,
    ExceptionState&) {
  return MakeGarbageCollected<FormDataIterationSource>(this);
}

// ----------------------------------------------------------------

FormData::Entry::Entry(const String& name, const String& value)
    : name_(name), value_(value) {
  DCHECK_EQ(name, ReplaceUnmatchedSurrogates(name))
      << "'name' should be a USVString.";
  DCHECK_EQ(value, ReplaceUnmatchedSurrogates(value))
      << "'value' should be a USVString.";
}

FormData::Entry::Entry(const String& name, Blob* blob, const String& filename)
    : name_(name), blob_(blob), filename_(filename) {
  DCHECK_EQ(name, ReplaceUnmatchedSurrogates(name))
      << "'name' should be a USVString.";
}

void FormData::Entry::Trace(Visitor* visitor) const {
  visitor->Trace(blob_);
}

File* FormData::Entry::GetFile() const {
  DCHECK(GetBlob());
  // The spec uses the passed filename when inserting entries into the list.
  // Here, we apply the filename (if present) as an override when extracting
  // entries.
  // FIXME: Consider applying the name during insertion.

  if (auto* file = DynamicTo<File>(GetBlob())) {
    if (Filename().IsNull())
      return file;
    return file->Clone(Filename());
  }

  String filename = filename_;
  if (filename.IsNull())
    filename = "blob";
  return MakeGarbageCollected<File>(filename, base::Time::Now(),
                                    GetBlob()->GetBlobDataHandle());
}

void FormData::AppendToControlState(FormControlState& state) const {
  state.Append(String::Number(size()));
  for (const auto& entry : Entries()) {
    state.Append(entry->name());
    if (entry->isFile()) {
      state.Append("File");
      entry->GetFile()->AppendToControlState(state);
    } else {
      state.Append("USVString");
      state.Append(entry->Value());
    }
  }
}

FormData* FormData::CreateFromControlState(ExecutionContext& execution_context,
                                           const FormControlState& state,
                                           wtf_size_t& index) {
  bool ok = false;
  uint64_t length = state[index].ToUInt64Strict(&ok);
  if (!ok)
    return nullptr;
  auto* form_data = MakeGarbageCollected<FormData>();
  ++index;
  for (uint64_t j = 0; j < length; ++j) {
    // Need at least three items.
    if (index + 2 >= state.ValueSize())
      return nullptr;
    const String& name = state[index++];
    const String& entry_type = state[index++];
    if (entry_type == "File") {
      if (auto* file =
              File::CreateFromControlState(&execution_context, state, index)) {
        form_data->append(name, file);
      } else {
        return nullptr;
      }
    } else if (entry_type == "USVString") {
      form_data->append(name, state[index++]);
    } else {
      return nullptr;
    }
  }
  return form_data;
}

}  // namespace blink
```