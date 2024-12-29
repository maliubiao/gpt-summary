Response:
Let's break down the thought process to analyze the `ndef_record.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relation to web technologies, examples of logic, common errors, and debugging steps.

2. **Initial Scan for Keywords:** Look for immediately recognizable terms: `NFC`, `NDEF`, `javascript`, `html`, `css`, `v8`, `DOM`, `URL`, `MIME`, `text`, `SmartPoster`, `external`, `local`. This gives a high-level idea of the file's purpose.

3. **Identify Core Data Structures and Concepts:**  The code heavily uses `NDEFRecord`, `NDEFMessage`, and `NDEFRecordInit`. These are central to the NFC functionality. The `Init` suffix suggests a structure used to initialize or create the main object. `mojom::blink::NDEFRecordTypeCategory` hints at internal categorization.

4. **Map to Web Technologies:**
    * **`NFC`:**  Directly related to the Web NFC API, which allows websites to interact with NFC tags.
    * **`NDEF` (NFC Data Exchange Format):** The standard format for data stored on NFC tags. This file is clearly about handling these records.
    * **`javascript`:** The file interacts with JavaScript through Blink's binding system (`third_party/blink/renderer/bindings`). Keywords like `ScriptState`, `ExceptionState`, and the V8 includes are strong indicators.
    * **`html`:** The code retrieves document language via `document()->documentElement()->getAttribute(html_names::kLangAttr)`, showing a connection to HTML's `lang` attribute.
    * **`css`:**  Less directly related. While NFC could potentially trigger actions that *affect* CSS (e.g., changing styles based on scanned data), this file itself doesn't seem to manipulate CSS. It's about *data*, not *presentation*.

5. **Analyze Functionality - Focus on `Create` Methods:** The `NDEFRecord::Create` and `NDEFRecord::CreateForBindings` functions are key. They act as factories, taking `NDEFRecordInit` data and creating `NDEFRecord` objects. The different `Create*Record` helper functions within this main `Create` function handle specific record types.

6. **Categorize Record Types and Their Logic:**  Go through each record type (`empty`, `text`, `url`, `mime`, `unknown`, `smart-poster`, `external`, `local`). For each:
    * **Purpose:** What kind of data does it represent?
    * **Data Handling:** How is the input data (`NDEFRecordInit`) processed? Are there specific validation steps?
    * **Data Types:** What JavaScript types are expected for the data (string, ArrayBuffer, NDEFMessageInit)?
    * **Specific Logic:** Are there encoding considerations (UTF-8, UTF-16), URL parsing, MIME type handling, or recursive creation of nested messages (for `smart-poster`, `external`, `local`)?

7. **Identify Relationships with HTML, JavaScript, and CSS:**  As identified earlier, focus on the `lang` attribute interaction, the JavaScript binding mechanisms, and the lack of direct CSS manipulation.

8. **Infer Logic and Create Examples:** Choose a few representative record types (e.g., `text`, `url`, `external`) and construct hypothetical input (`NDEFRecordInit`) and output (`NDEFRecord` properties). Consider different valid and invalid inputs to illustrate error handling.

9. **Identify Common Usage Errors:** Look for places where the code throws exceptions (`exception_state.ThrowTypeError`, `exception_state.ThrowDOMException`). These often indicate potential user errors. Examples: providing the wrong data type, invalid URLs, incorrect encoding, using `id` on an `empty` record, using `mediaType` on non-`mime` records, using `local` records outside a parent.

10. **Trace User Operations (Debugging):**  Think about how a user would interact with the Web NFC API in JavaScript to trigger the creation of an `NDEFRecord`. The sequence would involve:
    * A website using the Web NFC API.
    * The website constructing an `NDEFMessage` containing `NDEFRecordInit` objects.
    * These `NDEFRecordInit` objects being passed to the `NDEFRecord::Create` methods.
    * A browser implementing the Web NFC API receiving data from an NFC interaction.
    * The browser's NFC handling code (potentially in other parts of Blink) creating `NDEFRecord` objects based on the tag's content.

11. **Structure the Answer:** Organize the findings into logical sections as requested: functionality, relationship to web techs, logic examples, user errors, and debugging. Use clear and concise language.

12. **Review and Refine:** Read through the generated analysis. Ensure accuracy, clarity, and completeness. Check for any missing aspects or areas that could be explained better. For instance, initially, I might have overlooked the buffer source handling, but a closer look at the `GetBytesOfBufferSource` function would highlight this. Similarly, the handling of nested `NDEFMessage` for `smart-poster`, `external`, and `local` records is a crucial detail to emphasize.这是Chromium Blink引擎中处理NFC（Near Field Communication）NDEF（NFC Data Exchange Format）记录的源代码文件 `ndef_record.cc`。它的主要功能是：

**核心功能：创建和管理 NDEF 记录**

1. **将 JavaScript 中的 NDEFRecordInit 对象转换为内部的 NDEFRecord 对象:**  该文件包含了 `NDEFRecord::CreateForBindings` 和 `NDEFRecord::Create` 静态方法，它们接收来自 JavaScript 的 `NDEFRecordInit` 对象（定义了 NDEF 记录的属性，如 `recordType`, `data`, `id` 等），并根据这些信息创建 C++ 内部使用的 `NDEFRecord` 对象。

2. **处理不同类型的 NDEF 记录:**  NDEF 记录有多种类型，例如 `text` (文本), `url` (URL), `mime` (MIME 类型数据), `empty` (空记录), `smart-poster` (智能海报), `external` (外部类型) 和 `local` (本地类型)。该文件针对每种类型实现了特定的创建逻辑 (`CreateTextRecord`, `CreateUrlRecord`, `CreateMimeRecord` 等)。

3. **数据类型转换和处理:**  从 JavaScript 传递过来的数据可以是字符串、ArrayBuffer 或 ArrayBufferView。该文件负责将这些 JavaScript 数据转换为 C++ 中用于表示 NDEF 记录 payload 的 `WTF::Vector<uint8_t>`。对于某些类型的记录，数据也可以是嵌套的 `NDEFMessageInit` 对象。

4. **验证 NDEF 记录的有效性:**  在创建记录时，该文件会进行一些基本的验证，例如：
    * 检查 `recordType` 是否是有效的类型。
    * 检查 `mediaType` 是否只用于 `mime` 类型的记录。
    * 检查 `id` 是否不用于 `empty` 类型的记录。
    * 验证 `external` 和 `local` 类型的格式。

5. **支持 NDEF 记录的各种属性:**  `NDEFRecord` 类存储了 NDEF 记录的各种属性，如 `recordType`, `id`, `mediaType`, `encoding`, `lang` 和 payload 数据。

**与 JavaScript, HTML, CSS 的关系**

这个文件是 Web NFC API 实现的一部分，因此与 JavaScript 有着直接的联系。它负责处理从 JavaScript 传递过来的数据，并最终将 NFC 设备读取到的 NDEF 记录数据转换成 JavaScript 可以理解的对象。

* **JavaScript:**
    * **API 接口:** Web NFC API 允许 JavaScript 代码创建 `NDEFMessage` 对象，其中包含 `NDEFRecordInit` 对象。例如，以下 JavaScript 代码创建了一个包含文本记录的 NDEF 消息：

    ```javascript
    const textRecord = {
      recordType: 'text',
      data: 'Hello, NFC!'
    };
    const message = new NDEFMessage(textRecord);
    ```

    Blink 引擎会调用 `ndef_record.cc` 中的代码来处理 `textRecord` 这个 `NDEFRecordInit` 对象，创建对应的 `NDEFRecord` C++ 对象。

    * **数据传递:** JavaScript 中的字符串或 `ArrayBuffer` 会被传递到 C++ 代码中，用于设置 NDEF 记录的 payload。

* **HTML:**
    * **文档语言:**  对于 `text` 类型的 NDEF 记录，如果用户没有明确指定语言，代码会尝试获取当前 HTML 文档的语言设置 (`document.documentElement.lang`) 作为默认语言。

    ```c++
    String getDocumentLanguage(const ExecutionContext* execution_context) {
      String document_language;
      if (execution_context) {
        Element* document_element =
            To<LocalDOMWindow>(execution_context)->document()->documentElement();
        if (document_element) {
          document_language = document_element->getAttribute(html_names::kLangAttr);
        }
        if (document_language.empty()) {
          document_language = "en";
        }
      }
      return document_language;
    }
    ```

* **CSS:**
    * **无直接关系:** 该文件主要处理数据格式和结构，不直接涉及到 CSS 样式。然而，当 NFC 事件触发时，JavaScript 代码可能会根据读取到的 NDEF 记录内容来修改 HTML 结构或 CSS 样式。例如，读取到一个包含特定 URL 的 NFC 标签后，JavaScript 可以修改页面内容或应用特定的 CSS 类。

**逻辑推理的例子**

假设 JavaScript 代码创建了一个 `url` 类型的 NDEF 记录：

**假设输入 (JavaScript):**

```javascript
const urlRecordInit = {
  recordType: 'url',
  data: 'https://www.example.com'
};
```

**逻辑推理 (C++ in `ndef_record.cc`):**

1. `NDEFRecord::Create` 方法被调用，传入 `urlRecordInit`。
2. 代码检查 `recordType` 是否为 "url" 或 "absolute-url"。
3. 调用 `CreateUrlRecord` 方法。
4. `CreateUrlRecord` 方法检查 `data` 属性是否存在且为字符串。
5. 将 JavaScript 字符串 'https://www.example.com' 转换为 C++ 的 `WTF::Vector<uint8_t>` (UTF-8 编码)。
6. 创建一个新的 `NDEFRecord` 对象，其 `category_` 为 `kStandardized`, `record_type_` 为 "url", `payload_data_` 包含 URL 的 UTF-8 编码。

**假设输出 (C++ `NDEFRecord` 对象的部分属性):**

```
category_: device::mojom::blink::NDEFRecordTypeCategory::kStandardized
record_type_: "url"
payload_data_: { 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d }
```

**用户或编程常见的使用错误**

1. **`TypeError`: 提供错误的数据类型:**
   * **错误示例 (JavaScript):**
     ```javascript
     const textRecord = {
       recordType: 'text',
       data: 123 // 应该是一个字符串
     };
     ```
   * **`ndef_record.cc` 中的错误处理:** `CreateTextRecord` 会检查 `record.data().V8Value()->IsString()`，如果不是字符串则抛出 `TypeError`。

2. **`TypeError`: 对特定类型的记录使用不适用的属性:**
   * **错误示例 (JavaScript):**
     ```javascript
     const emptyRecord = {
       recordType: 'empty',
       id: 'myEmptyRecord' // 'empty' 类型的记录不应该有 id
     };
     ```
   * **`ndef_record.cc` 中的错误处理:** `NDEFRecord::Create` 方法会检查 `record->hasId() && record_type == "empty"`，如果成立则抛出 `TypeError`。

3. **`DOMException`: 无效的 URL 数据:**
   * **错误示例 (JavaScript):**
     ```javascript
     const urlRecord = {
       recordType: 'url',
       data: 'invalid-url'
     };
     ```
   * **`ndef_record.cc` 中的错误处理:** `CreateUrlRecord` 会使用 `KURL` 解析 URL，如果解析失败则抛出 `DOMExceptionCode::kSyntaxError`。

4. **`TypeError`: 在非 'mime' 类型的记录中使用 `mediaType`:**
   * **错误示例 (JavaScript):**
     ```javascript
     const textRecord = {
       recordType: 'text',
       data: 'Some text',
       mediaType: 'text/plain' // 'mediaType' 只能用于 'mime' 类型
     };
     ```
   * **`ndef_record.cc` 中的错误处理:** `NDEFRecord::Create` 方法会检查 `record->hasMediaType() && record_type != "mime"`，如果成立则抛出 `TypeError`。

5. **`TypeError`: 尝试创建顶级的 `local` 类型记录:**
   * **错误示例 (JavaScript):**
     ```javascript
     const localRecord = {
       recordType: ':localType', // 假设 ':localType' 是一个有效的本地类型
       data: 'local data'
     };
     const message = new NDEFMessage(localRecord); // 顶级消息中包含 local 类型的记录
     ```
   * **`ndef_record.cc` 中的错误处理:** `NDEFRecord::Create` 方法会检查 `IsValidLocalType(record_type) && !is_embedded`，如果成立则抛出 `TypeError`。本地类型记录只能嵌入到其他记录（如 `smart-poster`, `external` 或其他 `local` 类型）的 payload 中。

**用户操作是如何一步步的到达这里 (调试线索)**

1. **用户与支持 Web NFC 的网站交互:** 用户访问一个使用了 Web NFC API 的网站。
2. **网站 JavaScript 代码尝试写入 NFC 标签或接收 NFC 标签数据:** 网站的 JavaScript 代码会创建 `NDEFMessage` 对象，其中包含 `NDEFRecordInit` 对象来描述要写入或接收的 NDEF 记录。例如，使用 `NDFWriter` 或处理 `NDEFReader` 的 `message` 事件。
3. **浏览器将 JavaScript 对象传递给 Blink 引擎:** 当 JavaScript 代码执行与 NFC 相关的操作时，例如调用 `NDEFWriter.write(message)` 或处理 `NDEFReader` 接收到的消息，浏览器会将 JavaScript 的 `NDEFMessage` 和其内部的 `NDEFRecordInit` 对象传递到 Blink 引擎的 C++ 代码。
4. **Blink 引擎调用 `NDEFRecord::CreateForBindings` 或 `NDEFRecord::Create`:**  Blink 引擎的 NFC 相关模块会调用 `ndef_record.cc` 中的这些静态方法，将 JavaScript 的 `NDEFRecordInit` 对象转换为内部的 `NDEFRecord` 对象。
5. **执行特定类型的记录创建逻辑:** 根据 `NDEFRecordInit` 中的 `recordType` 属性，会调用相应的 `Create*Record` 方法来处理该类型的记录。
6. **数据转换和验证:** 在创建过程中，会对数据进行类型转换和有效性检查。
7. **创建 `NDEFRecord` 对象:**  最终，会创建一个 `NDEFRecord` 对象，该对象包含了 NDEF 记录的所有信息，供 Blink 引擎的其他模块使用（例如，与操作系统进行 NFC 通信，或者将接收到的数据传递回 JavaScript）。

**调试线索:**

* **断点:** 在 `NDEFRecord::CreateForBindings` 和 `NDEFRecord::Create` 方法中设置断点，可以查看从 JavaScript 传递过来的 `NDEFRecordInit` 对象的内容。
* **检查 `recordType`:** 确认 `recordType` 的值是否与预期一致，并且拼写正确。
* **检查 `data` 属性:**  对于不同的 `recordType`，检查 `data` 属性的类型和内容是否正确。例如，`text` 类型的 `data` 应该是字符串，`url` 类型的 `data` 应该是有效的 URL 字符串。
* **查看异常信息:** 如果代码抛出了异常，仔细查看异常信息，它会指出错误的类型和原因。
* **日志输出:** 在关键的代码路径上添加日志输出，可以跟踪 NDEF 记录的创建过程和数据转换情况。
* **Web NFC API 使用情况:**  检查网站的 JavaScript 代码，确认 Web NFC API 的使用方式是否正确，例如 `NDEFMessage` 的构造和 `NDEFRecordInit` 对象的定义。

总而言之，`ndef_record.cc` 文件是 Blink 引擎中 Web NFC API 的关键组成部分，负责将 JavaScript 中定义的 NDEF 记录转换为内部表示，并处理不同类型的 NDEF 记录，为 Web 开发者使用 NFC 功能提供了底层的支持。

Prompt: 
```
这是目录为blink/renderer/modules/nfc/ndef_record.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/nfc/ndef_record.h"

#include <string_view>

#include "base/containers/contains.h"
#include "base/notreached.h"
#include "services/device/public/mojom/nfc.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_typedefs.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ndef_message_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ndef_record_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_typedefs.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_piece.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_data_view.h"
#include "third_party/blink/renderer/modules/nfc/ndef_message.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/text/ascii_ctype.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

WTF::Vector<uint8_t> GetUTF8DataFromString(const String& string) {
  StringUTF8Adaptor utf8_string(string);
  WTF::Vector<uint8_t> data;
  data.AppendSpan(base::span(utf8_string));
  return data;
}

// Retrieves a RecordInit's |data| as a v8::Local<V8::Value> or creates a new
// v8::Undefined if |data| is not set.
// This is necessary because an empty v8::Local<V8::Value> as created in an
// empty ScriptValue will cause calls to v8::Value methods such as IsString()
// to crash.
v8::Local<v8::Value> GetPayloadDataOrUndefined(
    v8::Isolate* isolate,
    const NDEFRecordInit& record_init) {
  return record_init.hasData() ? record_init.data().V8Value()
                               : v8::Undefined(isolate).As<v8::Value>();
}

// This reproduces the V8 type checks from
// V8UnionArrayBufferOrArrayBufferView::Create() without attempting the V8 ->
// native conversions that can trigger exceptions. We just want to know if the
// V8 type is potentially convertible to a V8BufferSource.
bool MaybeIsBufferSource(const ScriptValue& script_value) {
  if (script_value.IsEmpty())
    return false;
  const auto v8_value = script_value.V8Value();
  return v8_value->IsArrayBuffer() || v8_value->IsSharedArrayBuffer() ||
         v8_value->IsArrayBufferView();
}

bool GetBytesOfBufferSource(const V8BufferSource* buffer_source,
                            WTF::Vector<uint8_t>* target,
                            ExceptionState& exception_state) {
  DOMArrayPiece array_piece;
  if (buffer_source->IsArrayBuffer()) {
    array_piece = DOMArrayPiece(buffer_source->GetAsArrayBuffer());
  } else if (buffer_source->IsArrayBufferView()) {
    array_piece = DOMArrayPiece(buffer_source->GetAsArrayBufferView().Get());
  } else {
    NOTREACHED();
  }
  if (!base::CheckedNumeric<wtf_size_t>(array_piece.ByteLength()).IsValid()) {
    exception_state.ThrowRangeError(
        "The provided buffer source exceeds the maximum supported length");
    return false;
  }
  target->AppendSpan(array_piece.ByteSpan());
  return true;
}

// https://w3c.github.io/web-nfc/#dfn-validate-external-type
// Validates |input| as an external type.
bool IsValidExternalType(const String& input) {
  // Ensure |input| is an ASCII string.
  if (!input.ContainsOnlyASCIIOrEmpty())
    return false;

  // As all characters in |input| is ASCII, limiting its length within 255 just
  // limits the length of its utf-8 encoded bytes we finally write into the
  // record payload.
  if (input.empty() || input.length() > 255)
    return false;

  // Finds the first occurrence of ':'.
  wtf_size_t colon_index = input.find(':');
  if (colon_index == kNotFound)
    return false;

  // Validates the domain (the part before ':').
  String domain = input.Left(colon_index);
  if (domain.empty())
    return false;
  // TODO(https://crbug.com/520391): Validate |domain|.

  // Validates the type (the part after ':').
  String type = input.Substring(colon_index + 1);
  if (type.empty())
    return false;

  static constexpr std::string_view kOtherCharsForCustomType(":!()+,-=@;$_*'.");
  for (wtf_size_t i = 0; i < type.length(); i++) {
    if (!IsASCIIAlphanumeric(type[i]) &&
        !base::Contains(kOtherCharsForCustomType, type[i])) {
      return false;
    }
  }

  return true;
}

// https://w3c.github.io/web-nfc/#dfn-validate-local-type
// Validates |input| as an local type.
bool IsValidLocalType(const String& input) {
  // Ensure |input| is an ASCII string.
  if (!input.ContainsOnlyASCIIOrEmpty())
    return false;

  // The prefix ':' will be omitted when we actually write the record type into
  // the nfc tag. We're taking it into consideration for validating the length
  // here.
  if (input.length() < 2 || input.length() > 256)
    return false;
  if (input[0] != ':')
    return false;
  if (!IsASCIILower(input[1]) && !IsASCIIDigit(input[1]))
    return false;

  // TODO(https://crbug.com/520391): Validate |input| is not equal to the record
  // type of any NDEF record defined in its containing NDEF message.

  return true;
}

String getDocumentLanguage(const ExecutionContext* execution_context) {
  String document_language;
  if (execution_context) {
    Element* document_element =
        To<LocalDOMWindow>(execution_context)->document()->documentElement();
    if (document_element) {
      document_language = document_element->getAttribute(html_names::kLangAttr);
    }
    if (document_language.empty()) {
      document_language = "en";
    }
  }
  return document_language;
}

static NDEFRecord* CreateTextRecord(const ScriptState* script_state,
                                    const String& id,
                                    const NDEFRecordInit& record,
                                    ExceptionState& exception_state) {
  // https://w3c.github.io/web-nfc/#mapping-string-to-ndef
  if (!record.hasData() || !(record.data().V8Value()->IsString() ||
                             MaybeIsBufferSource(record.data()))) {
    exception_state.ThrowTypeError(
        "The data for 'text' NDEFRecords must be a String or a BufferSource.");
    return nullptr;
  }

  // Set language to lang if it exists, or the document element's lang
  // attribute, or 'en'.
  String language;
  if (record.hasLang()) {
    language = record.lang();
  } else {
    language = getDocumentLanguage(ExecutionContext::From(script_state));
  }

  // Bits 0 to 5 define the length of the language tag
  // https://w3c.github.io/web-nfc/#text-record
  if (language.length() > 63) {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "Lang length cannot be stored in 6 bit.");
    return nullptr;
  }

  const String& encoding_label = record.getEncodingOr("utf-8");
  WTF::Vector<uint8_t> bytes;

  if (MaybeIsBufferSource(record.data())) {
    if (encoding_label != "utf-8" && encoding_label != "utf-16" &&
        encoding_label != "utf-16be" && encoding_label != "utf-16le") {
      exception_state.ThrowTypeError(
          "Encoding must be either \"utf-8\", \"utf-16\", \"utf-16be\", or "
          "\"utf-16le\".");
      return nullptr;
    }
    auto* buffer_source = NativeValueTraits<V8BufferSource>::NativeValue(
        script_state->GetIsolate(), record.data().V8Value(), exception_state);
    if (exception_state.HadException())
      return nullptr;
    if (!GetBytesOfBufferSource(buffer_source, &bytes, exception_state))
      return nullptr;
  } else if (record.data().V8Value()->IsString()) {
    if (encoding_label != "utf-8") {
      exception_state.ThrowTypeError(
          "A DOMString data source is always encoded as \"utf-8\" so other "
          "encodings are not allowed.");
      return nullptr;
    }
    const String data = NativeValueTraits<IDLString>::NativeValue(
        script_state->GetIsolate(), record.data().V8Value(), exception_state);
    if (exception_state.HadException())
      return nullptr;
    bytes = GetUTF8DataFromString(data);
  } else {
    NOTREACHED();
  }

  return MakeGarbageCollected<NDEFRecord>(id, encoding_label, language,
                                          std::move(bytes));
}

// Create a 'url' record or an 'absolute-url' record.
NDEFRecord* CreateUrlRecord(const ScriptState* script_state,
                            const String& id,
                            const NDEFRecordInit& record,
                            ExceptionState& exception_state) {
  // https://w3c.github.io/web-nfc/#mapping-url-to-ndef
  // No need to check mediaType according to the spec.
  if (!record.hasData() || !record.data().V8Value()->IsString()) {
    // https://github.com/w3c/web-nfc/issues/623
    // This check could be removed if we threw a TypeError instead of a
    // SyntaxError below.
    exception_state.ThrowTypeError(
        "The data for url NDEFRecord must be a String.");
    return nullptr;
  }
  auto* isolate = script_state->GetIsolate();
  const String& url = NativeValueTraits<IDLString>::NativeValue(
      isolate, GetPayloadDataOrUndefined(isolate, record), exception_state);
  if (exception_state.HadException())
    return nullptr;
  if (!KURL(NullURL(), url).IsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "Cannot parse data for url record.");
    return nullptr;
  }

  return MakeGarbageCollected<NDEFRecord>(
      device::mojom::blink::NDEFRecordTypeCategory::kStandardized,
      record.recordType(), id, GetUTF8DataFromString(url));
}

NDEFRecord* CreateMimeRecord(const ScriptState* script_state,
                             const String& id,
                             const NDEFRecordInit& record,
                             ExceptionState& exception_state) {
  // https://w3c.github.io/web-nfc/#mapping-binary-data-to-ndef
  auto* isolate = script_state->GetIsolate();
  auto* buffer_source = NativeValueTraits<V8BufferSource>::NativeValue(
      isolate, GetPayloadDataOrUndefined(isolate, record), exception_state);
  if (exception_state.HadException())
    return nullptr;

  // ExtractMIMETypeFromMediaType() ignores parameters of the MIME type.
  String mime_type;
  if (record.hasMediaType() && !record.mediaType().empty()) {
    mime_type = ExtractMIMETypeFromMediaType(AtomicString(record.mediaType()));
  } else {
    mime_type = "application/octet-stream";
  }

  WTF::Vector<uint8_t> bytes;
  if (!GetBytesOfBufferSource(buffer_source, &bytes, exception_state))
    return nullptr;

  return MakeGarbageCollected<NDEFRecord>(id, mime_type, bytes);
}

NDEFRecord* CreateUnknownRecord(const ScriptState* script_state,
                                const String& id,
                                const NDEFRecordInit& record,
                                ExceptionState& exception_state) {
  auto* isolate = script_state->GetIsolate();
  auto* buffer_source = NativeValueTraits<V8BufferSource>::NativeValue(
      isolate, GetPayloadDataOrUndefined(isolate, record), exception_state);
  if (exception_state.HadException())
    return nullptr;

  WTF::Vector<uint8_t> bytes;
  if (!GetBytesOfBufferSource(buffer_source, &bytes, exception_state))
    return nullptr;

  return MakeGarbageCollected<NDEFRecord>(
      device::mojom::blink::NDEFRecordTypeCategory::kStandardized, "unknown",
      id, bytes);
}

NDEFRecord* CreateSmartPosterRecord(const ScriptState* script_state,
                                    const String& id,
                                    const NDEFRecordInit& record,
                                    uint8_t records_depth,
                                    ExceptionState& exception_state) {
  // https://w3c.github.io/web-nfc/#dfn-map-smart-poster-to-ndef
  auto* isolate = script_state->GetIsolate();
  auto* ndef_message_init = NativeValueTraits<NDEFMessageInit>::NativeValue(
      isolate, GetPayloadDataOrUndefined(isolate, record), exception_state);
  if (exception_state.HadException())
    return nullptr;

  NDEFMessage* payload_message = NDEFMessage::CreateAsPayloadOfSmartPoster(
      script_state, ndef_message_init, exception_state, records_depth);
  if (exception_state.HadException())
    return nullptr;
  DCHECK(payload_message);

  return MakeGarbageCollected<NDEFRecord>(
      device::mojom::blink::NDEFRecordTypeCategory::kStandardized,
      "smart-poster", id, payload_message);
}

NDEFRecord* CreateExternalRecord(const ScriptState* script_state,
                                 const String& id,
                                 const NDEFRecordInit& record,
                                 uint8_t records_depth,
                                 ExceptionState& exception_state) {
  // https://w3c.github.io/web-nfc/#dfn-map-external-data-to-ndef

  if (record.hasData()) {
    const String& record_type = record.recordType();

    if (MaybeIsBufferSource(record.data())) {
      auto* buffer_source = NativeValueTraits<V8BufferSource>::NativeValue(
          script_state->GetIsolate(), record.data().V8Value(), exception_state);
      if (exception_state.HadException())
        return nullptr;

      Vector<uint8_t> bytes;
      if (!GetBytesOfBufferSource(buffer_source, &bytes, exception_state))
        return nullptr;

      return MakeGarbageCollected<NDEFRecord>(
          device::mojom::blink::NDEFRecordTypeCategory::kExternal, record_type,
          id, bytes);
    } else if (record.data().IsObject()) {
      auto* ndef_message_init = NativeValueTraits<NDEFMessageInit>::NativeValue(
          script_state->GetIsolate(), record.data().V8Value(), exception_state);
      if (exception_state.HadException())
        return nullptr;

      NDEFMessage* payload_message = NDEFMessage::Create(
          script_state, ndef_message_init, exception_state,
          /*records_depth=*/records_depth, /*is_embedded=*/true);
      if (exception_state.HadException())
        return nullptr;
      DCHECK(payload_message);

      return MakeGarbageCollected<NDEFRecord>(
          device::mojom::blink::NDEFRecordTypeCategory::kExternal, record_type,
          id, payload_message);
    }
  }

  exception_state.ThrowTypeError(
      "The data for external type NDEFRecord must be a BufferSource or an "
      "NDEFMessageInit.");
  return nullptr;
}

NDEFRecord* CreateLocalRecord(const ScriptState* script_state,
                              const String& id,
                              const NDEFRecordInit& record,
                              uint8_t records_depth,
                              ExceptionState& exception_state) {
  // https://w3c.github.io/web-nfc/#dfn-map-local-type-to-ndef

  if (record.hasData()) {
    const String& record_type = record.recordType();

    if (MaybeIsBufferSource(record.data())) {
      auto* buffer_source = NativeValueTraits<V8BufferSource>::NativeValue(
          script_state->GetIsolate(), record.data().V8Value(), exception_state);
      if (exception_state.HadException())
        return nullptr;

      Vector<uint8_t> bytes;
      if (!GetBytesOfBufferSource(buffer_source, &bytes, exception_state))
        return nullptr;

      return MakeGarbageCollected<NDEFRecord>(
          device::mojom::blink::NDEFRecordTypeCategory::kLocal, record_type, id,
          bytes);
    } else if (record.data().IsObject()) {
      auto* ndef_message_init = NativeValueTraits<NDEFMessageInit>::NativeValue(
          script_state->GetIsolate(), record.data().V8Value(), exception_state);
      if (exception_state.HadException())
        return nullptr;

      NDEFMessage* payload_message = NDEFMessage::Create(
          script_state, ndef_message_init, exception_state,
          /*records_depth=*/records_depth, /*is_embedded=*/true);
      if (exception_state.HadException())
        return nullptr;
      DCHECK(payload_message);

      return MakeGarbageCollected<NDEFRecord>(
          device::mojom::blink::NDEFRecordTypeCategory::kLocal, record_type, id,
          payload_message);
    }
  }

  exception_state.ThrowTypeError(
      "The data for local type NDEFRecord must be a BufferSource or an "
      "NDEFMessageInit.");
  return nullptr;
}

}  // namespace

// static
NDEFRecord* NDEFRecord::CreateForBindings(const ScriptState* script_state,
                                          const NDEFRecordInit* record,
                                          ExceptionState& exception_state) {
  return Create(script_state, record, exception_state, /*records_depth=*/0U,
                /*is_embedded=*/false);
}

// static
NDEFRecord* NDEFRecord::Create(const ScriptState* script_state,
                               const NDEFRecordInit* record,
                               ExceptionState& exception_state,
                               uint8_t records_depth,
                               bool is_embedded) {
  // https://w3c.github.io/web-nfc/#creating-ndef-record
  const String& record_type = record->recordType();

  // https://w3c.github.io/web-nfc/#dom-ndefrecordinit-mediatype
  if (record->hasMediaType() && record_type != "mime") {
    exception_state.ThrowTypeError(
        "NDEFRecordInit#mediaType is only applicable for 'mime' records.");
    return nullptr;
  }

  // https://w3c.github.io/web-nfc/#dfn-map-empty-record-to-ndef
  if (record->hasId() && record_type == "empty") {
    exception_state.ThrowTypeError(
        "NDEFRecordInit#id is not applicable for 'empty' records.");
    return nullptr;
  }

  // TODO(crbug.com/1070871): Use IdOr(String()).
  String id;
  if (record->hasId())
    id = record->id();

  if (record_type == "empty") {
    // https://w3c.github.io/web-nfc/#mapping-empty-record-to-ndef
    return MakeGarbageCollected<NDEFRecord>(
        device::mojom::blink::NDEFRecordTypeCategory::kStandardized,
        record_type, /*id=*/String(), WTF::Vector<uint8_t>());
  } else if (record_type == "text") {
    return CreateTextRecord(script_state, id, *record, exception_state);
  } else if (record_type == "url" || record_type == "absolute-url") {
    return CreateUrlRecord(script_state, id, *record, exception_state);
  } else if (record_type == "mime") {
    return CreateMimeRecord(script_state, id, *record, exception_state);
  } else if (record_type == "unknown") {
    return CreateUnknownRecord(script_state, id, *record, exception_state);
  } else if (record_type == "smart-poster") {
    return CreateSmartPosterRecord(script_state, id, *record, records_depth,
                                   exception_state);
  } else if (IsValidExternalType(record_type)) {
    return CreateExternalRecord(script_state, id, *record, records_depth,
                                exception_state);
  } else if (IsValidLocalType(record_type)) {
    if (!is_embedded) {
      exception_state.ThrowTypeError(
          "Local type records are only supposed to be embedded in the payload "
          "of another record (smart-poster, external, or local).");
      return nullptr;
    }
    return CreateLocalRecord(script_state, id, *record, records_depth,
                             exception_state);
  }

  exception_state.ThrowTypeError("Invalid NDEFRecord type.");
  return nullptr;
}

NDEFRecord::NDEFRecord(device::mojom::blink::NDEFRecordTypeCategory category,
                       const String& record_type,
                       const String& id,
                       WTF::Vector<uint8_t> data)
    : category_(category),
      record_type_(record_type),
      id_(id),
      payload_data_(std::move(data)) {
  DCHECK_EQ(
      category_ == device::mojom::blink::NDEFRecordTypeCategory::kExternal,
      IsValidExternalType(record_type_));
  DCHECK_EQ(category_ == device::mojom::blink::NDEFRecordTypeCategory::kLocal,
            IsValidLocalType(record_type_));
}

NDEFRecord::NDEFRecord(device::mojom::blink::NDEFRecordTypeCategory category,
                       const String& record_type,
                       const String& id,
                       NDEFMessage* payload_message)
    : category_(category),
      record_type_(record_type),
      id_(id),
      payload_message_(payload_message) {
  DCHECK(record_type_ == "smart-poster" ||
         category_ == device::mojom::blink::NDEFRecordTypeCategory::kExternal ||
         category_ == device::mojom::blink::NDEFRecordTypeCategory::kLocal);
  DCHECK_EQ(
      category_ == device::mojom::blink::NDEFRecordTypeCategory::kExternal,
      IsValidExternalType(record_type_));
  DCHECK_EQ(category_ == device::mojom::blink::NDEFRecordTypeCategory::kLocal,
            IsValidLocalType(record_type_));
}

NDEFRecord::NDEFRecord(const String& id,
                       const String& encoding,
                       const String& lang,
                       WTF::Vector<uint8_t> data)
    : category_(device::mojom::blink::NDEFRecordTypeCategory::kStandardized),
      record_type_("text"),
      id_(id),
      encoding_(encoding),
      lang_(lang),
      payload_data_(std::move(data)) {}

NDEFRecord::NDEFRecord(const ScriptState* script_state, const String& text)
    : category_(device::mojom::blink::NDEFRecordTypeCategory::kStandardized),
      record_type_("text"),
      encoding_("utf-8"),
      lang_(getDocumentLanguage(ExecutionContext::From(script_state))),
      payload_data_(GetUTF8DataFromString(text)) {}

NDEFRecord::NDEFRecord(const String& id,
                       const String& media_type,
                       WTF::Vector<uint8_t> data)
    : category_(device::mojom::blink::NDEFRecordTypeCategory::kStandardized),
      record_type_("mime"),
      id_(id),
      media_type_(media_type),
      payload_data_(std::move(data)) {}

// Even if |record| is for a local type record, here we do not validate if it's
// in the context of a parent record but just expose to JS as is.
NDEFRecord::NDEFRecord(const device::mojom::blink::NDEFRecord& record)
    : category_(record.category),
      record_type_(record.record_type),
      id_(record.id),
      media_type_(record.media_type),
      encoding_(record.encoding),
      lang_(record.lang),
      payload_data_(record.data),
      payload_message_(
          record.payload_message
              ? MakeGarbageCollected<NDEFMessage>(*record.payload_message)
              : nullptr) {
  DCHECK_NE(record_type_ == "mime", media_type_.IsNull());
  DCHECK_EQ(
      category_ == device::mojom::blink::NDEFRecordTypeCategory::kExternal,
      IsValidExternalType(record_type_));
  DCHECK_EQ(category_ == device::mojom::blink::NDEFRecordTypeCategory::kLocal,
            IsValidLocalType(record_type_));
}

const String& NDEFRecord::mediaType() const {
  DCHECK_NE(record_type_ == "mime", media_type_.IsNull());
  return media_type_;
}

DOMDataView* NDEFRecord::data() const {
  // Step 4 in https://w3c.github.io/web-nfc/#dfn-parse-an-ndef-record
  if (record_type_ == "empty") {
    DCHECK(payload_data_.empty());
    return nullptr;
  }
  DOMArrayBuffer* dom_buffer = DOMArrayBuffer::Create(payload_data_);
  return DOMDataView::Create(dom_buffer, 0, payload_data_.size());
}

// https://w3c.github.io/web-nfc/#dfn-convert-ndefrecord-data-bytes
std::optional<HeapVector<Member<NDEFRecord>>> NDEFRecord::toRecords(
    ExceptionState& exception_state) const {
  if (record_type_ != "smart-poster" &&
      category_ != device::mojom::blink::NDEFRecordTypeCategory::kExternal &&
      category_ != device::mojom::blink::NDEFRecordTypeCategory::kLocal) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "Only {smart-poster, external, local} type records could have a ndef "
        "message as payload.");
    return std::nullopt;
  }

  if (!payload_message_)
    return std::nullopt;

  return payload_message_->records();
}

void NDEFRecord::Trace(Visitor* visitor) const {
  visitor->Trace(payload_message_);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink

"""

```