Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed response.

1. **Understand the Goal:** The core request is to understand the functionality of `v8_binding_for_modules.cc` within the Chromium Blink engine, especially its relation to JavaScript, HTML, and CSS, and to identify potential errors and debugging approaches.

2. **Initial Skim and Keywords:**  Quickly scan the code for prominent keywords and includes. This gives a high-level understanding. Immediately noticeable are:
    * `#include`:  Suggests dependencies and functionality grouping.
    * `namespace blink`:  Indicates this code is part of the Blink rendering engine.
    * `v8`: This is a strong indicator of interaction with the V8 JavaScript engine.
    * `IDB`:  Likely related to IndexedDB, a client-side storage mechanism.
    * `Blob`, `File`, `ArrayBuffer`: Web API related objects.
    * `Deserialize`, `CreateIDBKeyFromValue`: Serialization and data conversion.

3. **Focus on Core Functionality (Based on Includes and Function Names):**

    * **V8 Binding:** The file name itself is a big clue. It's about binding V8 (JavaScript engine) to Blink modules. This means the code is responsible for bridging the gap between JavaScript objects and Blink's internal C++ representations.

    * **IndexedDB:** The numerous includes related to `IDB` (e.g., `IDBCursor`, `IDBDatabase`, `IDBKey`, `IDBValue`) strongly suggest a primary focus on IndexedDB integration.

    * **Data Conversion:** Functions like `CreateIDBKeyFromValue` and `DeserializeIDBValue` point to the conversion of JavaScript values to IndexedDB keys and the reverse process (deserialization). This is crucial for storing and retrieving data.

4. **Analyze Key Functions:** Go through the functions that appear most central to the file's purpose.

    * **`CreateIDBKeyFromValue`:**  This function takes a V8 `Value` (JavaScript value) and converts it to an `IDBKey`. This is fundamental for IndexedDB, where keys are used to identify stored data. Pay attention to the different JavaScript types it handles (number, string, date, ArrayBuffer, ArrayBufferView, and arrays). The recursive array handling is an important detail.

    * **`CreateIDBKeyFromValueAndKeyPath`:** This function adds the concept of a "key path." This is how IndexedDB accesses nested properties within JavaScript objects to extract or create keys. Consider the string and array key path types.

    * **`DeserializeIDBValue` and `DeserializeIDBValueData`:** These are responsible for taking the stored `IDBValue` (likely a serialized representation) and turning it back into a usable JavaScript object within V8. The `InjectV8KeyIntoV8Value` function's role in injecting the primary key is a significant point.

5. **Relate to JavaScript, HTML, and CSS:**

    * **JavaScript:** The entire file is about bridging V8 and Blink. Provide concrete examples of how JavaScript code using IndexedDB interacts with the C++ code. Think about the API calls (`open()`, `transaction()`, `put()`, `get()`).

    * **HTML:** IndexedDB is a client-side storage mechanism used by JavaScript within a web page. Explain how a user action on an HTML page might trigger JavaScript code that then uses IndexedDB and ultimately reaches this C++ file.

    * **CSS:** While less direct, consider if IndexedDB data *could* indirectly affect CSS. For instance, a user preference stored in IndexedDB might determine the theme (and thus CSS) applied to the page. This is a more tangential connection.

6. **Identify Potential Errors:**  Based on the code and its purpose, think about common mistakes:

    * **Type Mismatches:** Trying to store a JavaScript value as an IndexedDB key when it's not a valid key type.
    * **Detached ArrayBuffers:**  A specific error case handled in the code.
    * **Circular References:**  The code explicitly checks for this in array key conversion.
    * **Incorrect Key Paths:**  Specifying a key path that doesn't exist in the JavaScript object.
    * **Data Corruption:** The comments about `InjectV8KeyIntoV8Value` indicate potential issues with data integrity.

7. **Construct Debugging Scenario:**  Trace a user action (e.g., clicking a button) that leads to an IndexedDB operation and how you might step through the code to debug an issue. Highlight key breakpoints (e.g., in the `CreateIDBKeyFromValue` or `DeserializeIDBValue` functions).

8. **Structure and Refine:** Organize the information logically. Start with a high-level overview of the file's purpose, then delve into specifics. Use clear headings and examples. Ensure the language is accessible and avoids overly technical jargon where possible. Refine the examples to be clear and concise.

9. **Self-Correction/Review:** After drafting the response, reread the original request and the generated answer. Did I address all the points? Are the explanations clear and accurate? Are the examples relevant?  For instance, did I adequately explain the "modules" part of the filename? (It signifies that this binding is specifically for features exposed as JavaScript modules.) Did I provide enough concrete examples?

By following this structured approach, combining code analysis with an understanding of web technologies and potential error scenarios, a comprehensive and helpful response can be generated.
这个文件 `v8_binding_for_modules.cc` 在 Chromium Blink 引擎中扮演着至关重要的角色，它的主要功能是**将 Blink 引擎中定义的一些模块（通常是 Web API）的接口绑定到 V8 JavaScript 引擎，使得 JavaScript 代码能够调用这些模块的功能。**  简单来说，它是一个“翻译器”，让 JavaScript 可以理解和使用 Blink 内部的 C++ 代码实现的 Web API。

让我们更详细地分解其功能，并联系 JavaScript, HTML, CSS：

**主要功能:**

1. **类型转换和绑定:**  它定义了如何将 Blink 内部的 C++ 对象（例如 `Blob`, `File`, `IDBDatabase` 等）转换为 V8 JavaScript 可以理解和操作的 JavaScript 对象。反之，也定义了如何将 JavaScript 对象转换回 Blink 的 C++ 对象。这涉及到数据类型的映射和转换。

2. **Web API 的暴露:**  对于定义在 Blink 模块中的 Web API，这个文件负责创建相应的 V8 接口，例如构造函数、方法、属性等，使得 JavaScript 代码可以通过这些接口来调用底层的 C++ 实现。

3. **IndexedDB 支持:**  从文件名和代码内容来看，这个文件尤其关注 IndexedDB API 的绑定。它包含了处理 `IDBKey`, `IDBValue`, `IDBCursor`, `IDBDatabase` 等 IndexedDB 相关类型的转换和操作的逻辑。

4. **序列化与反序列化:**  为了在 JavaScript 和 C++ 之间传递复杂的数据，例如存储在 IndexedDB 中的数据，这个文件包含了序列化（将 C++ 对象转换为可以存储或传输的格式）和反序列化（将存储或传输的格式转换回 C++ 对象）的逻辑。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **JavaScript:**  这是该文件最直接相关的部分。它使得 JavaScript 能够使用 Blink 引擎提供的各种 Web API。

    * **例子 (IndexedDB):**  当 JavaScript 代码中使用 IndexedDB API 来存储数据时，例如：
        ```javascript
        const request = indexedDB.open('myDatabase', 1);
        request.onsuccess = function(event) {
          const db = event.target.result;
          const transaction = db.transaction(['myData'], 'readwrite');
          const store = transaction.objectStore('myData');
          store.put({ id: 1, name: 'example' });
        };
        ```
        这段 JavaScript 代码最终会调用 Blink 引擎中与 IndexedDB 相关的 C++ 代码。`v8_binding_for_modules.cc` 就负责将 JavaScript 中对 `indexedDB.open`, `transaction`, `objectStore`, `put` 等方法的调用转换成对 Blink 内部 C++ 对象的相应操作。例如，`store.put({ id: 1, name: 'example' })`  可能涉及到 `CreateIDBKeyFromValue` 函数将 JavaScript 对象 `{ id: 1, name: 'example' }` 转换为 `IDBValue` 对象进行存储。

    * **例子 (File API):**  当 JavaScript 使用 `File` 或 `Blob` API 处理文件时：
        ```javascript
        const fileInput = document.getElementById('fileElem');
        const file = fileInput.files[0];
        const reader = new FileReader();
        reader.onload = function(e) {
          console.log(e.target.result); // 读取文件内容
        };
        reader.readAsText(file);
        ```
        `v8_binding_for_modules.cc` 包含了 `V8Blob` 和 `V8File` 相关的绑定，负责将 JavaScript 中的 `File` 对象与 Blink 内部的 `File` 对象关联起来，并允许 JavaScript 调用 `FileReader` 等 API 来操作文件。

* **HTML:**  HTML 提供了用户与网页交互的界面，用户操作可能触发 JavaScript 代码，进而使用到这个文件中绑定的 Web API。

    * **例子:** 用户在一个包含文件上传表单的 HTML 页面上选择了一个文件并点击“上传”按钮。这个操作会触发 JavaScript 代码去获取选中的 `File` 对象，并可能使用 `FileReader` 或 `XMLHttpRequest` 来读取或上传文件。这个过程中，`v8_binding_for_modules.cc` 负责确保 JavaScript 可以正确地访问和操作这个 `File` 对象。

* **CSS:**  CSS 本身与这个文件的关系相对间接。CSS 主要负责网页的样式和布局。但是，一些 Web API（例如，可能通过 IndexedDB 存储用户偏好设置）可能会间接地影响 CSS 的应用。

    * **例子 (间接关系):**  假设一个网页允许用户选择主题颜色，并将用户的选择存储在 IndexedDB 中。
        1. 用户在 HTML 页面上通过某个控件选择了“深色主题”。
        2. JavaScript 代码将用户的选择存储到 IndexedDB 中，这会涉及到 `v8_binding_for_modules.cc` 中 IndexedDB 相关的绑定逻辑。
        3. 当用户下次访问该网页时，JavaScript 代码会从 IndexedDB 中读取用户的偏好设置。
        4. 基于读取到的偏好设置，JavaScript 代码可能会动态地修改 HTML 元素的 class 属性，或者修改 CSS 变量的值，从而应用不同的 CSS 样式。

**逻辑推理的假设输入与输出:**

* **假设输入:**  JavaScript 代码尝试创建一个 IndexedDB 数据库并存储一个包含 `Date` 对象的记录：
    ```javascript
    const request = indexedDB.open('myDatabase', 1);
    request.onsuccess = function(event) {
      const db = event.target.result;
      const transaction = db.transaction(['myData'], 'readwrite');
      const store = transaction.objectStore('myData');
      store.put({ id: 1, timestamp: new Date() });
    };
    ```
* **输出 (在 `v8_binding_for_modules.cc` 中):**
    * `CreateIDBKeyFromValue` 函数会被调用，接收 JavaScript 的 `Date` 对象。
    * 该函数会将 JavaScript 的 `Date` 对象转换为 Blink 内部的 `IDBKey` 对象，其类型可能是 `IDBKey::Type::kDate`，并包含 `Date` 对象的时间戳值。
    * 这个 `IDBKey` 对象随后会被用于在 IndexedDB 中存储数据。

**用户或编程常见的使用错误及举例:**

1. **尝试存储不支持作为 IndexedDB 键的值:**  IndexedDB 的键必须是特定的类型（例如，数字，字符串，`Date`，`ArrayBuffer` 等）。如果 JavaScript 代码尝试将一个不能作为键的值（例如，一个普通的对象）传递给 `put` 方法的 `key` 参数，`CreateIDBKeyFromValue` 函数将返回一个 "Invalid" 的 `IDBKey`，并可能导致错误。

    ```javascript
    // 错误示例：尝试使用对象作为键
    store.put({ name: 'test' }, { key: 'invalid' });
    ```

2. **在 KeyPath 中使用错误的属性名:** 当使用 `keyPath` 定义索引或对象存储时，如果 JavaScript 对象中不存在指定的属性，`CreateIDBKeyFromValueAndKeyPath` 函数在评估 KeyPath 时会返回 `nullptr`，导致无法提取到键。

    ```javascript
    // 假设对象存储的 keyPath 是 'userId'，但存储的数据是：
    store.put({ id: 1, name: 'example' }); // 缺少 'userId' 属性
    ```

3. **尝试在已分离的 ArrayBuffer 上创建 IDBKey:** 代码中明确检查了 `ArrayBuffer` 是否已分离。如果在 JavaScript 中分离了一个 `ArrayBuffer` 后，尝试将其作为 IndexedDB 的键存储，将会抛出 `DOMException`。

    ```javascript
    const buffer = new ArrayBuffer(10);
    buffer.detached = true; // 模拟分离
    // 尝试将分离的 ArrayBuffer 作为键
    store.put(buffer, 'myKey'); // 这会导致错误
    ```

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在使用一个在线笔记应用，该应用使用 IndexedDB 来本地存储笔记。

1. **用户操作:** 用户在笔记编辑器中输入了一段文字，并点击了“保存”按钮。
2. **前端 JavaScript 代码:**  点击事件触发前端 JavaScript 代码。
3. **IndexedDB API 调用:** JavaScript 代码获取笔记内容（可能包含 `Date` 对象作为创建时间），并调用 IndexedDB 的 `put` 方法将笔记数据存储到数据库中。
   ```javascript
   const noteContent = document.getElementById('editor').value;
   const note = {
       content: noteContent,
       createdAt: new Date()
   };
   const request = db.transaction(['notes'], 'readwrite')
                     .objectStore('notes')
                     .put(note);
   ```
4. **V8 引擎执行:** V8 引擎执行这段 JavaScript 代码。
5. **`v8_binding_for_modules.cc` 介入:** 当执行到 `put(note)` 时，V8 引擎会调用 `v8_binding_for_modules.cc` 中与 IndexedDB 相关的绑定代码。
6. **类型转换和处理:**
   * `CreateIDBKeyFromValue` (如果 `notes` 对象存储定义了 `keyPath`) 或内部逻辑会分析 `note` 对象。
   * `DeserializeIDBValueData` 和 `InjectV8KeyIntoV8Value` (在存储前或读取时) 可能会处理数据的序列化和反序列化，特别是当涉及到 `Date` 对象或其他复杂类型时。
7. **Blink 内部 IndexedDB 实现:**  转换后的数据被传递给 Blink 引擎内部的 IndexedDB 实现，进行实际的存储操作。

**调试线索:**

如果开发者在调试这个场景时遇到问题，例如数据存储失败或数据类型不匹配，可以在以下地方设置断点进行调试：

* **`v8_binding_for_modules.cc` 中的关键函数:**
    * `CreateIDBKeyFromValue`:  检查 JavaScript 值是如何被转换为 `IDBKey` 的，特别关注 `Date` 对象的处理。
    * `CreateIDBKeyFromValueAndKeyPath`: 检查当对象存储定义了 `keyPath` 时，键是如何从 JavaScript 对象中提取的。
    * `DeserializeIDBValue` 和 `DeserializeIDBValueData`:  检查数据是如何被序列化和反序列化的，特别是在存储包含 `Date` 对象的数据时。
    * `InjectV8KeyIntoV8Value`: 检查在具有 `keyPath` 和键生成器的对象存储中，键是如何被注入到反序列化的 JavaScript 对象中的。
* **Blink 引擎内部的 IndexedDB 实现代码:**  如果问题不发生在 V8 绑定层，可能需要深入到 Blink 引擎的 IndexedDB 核心实现代码进行调试。

通过理解 `v8_binding_for_modules.cc` 的功能以及它在 JavaScript 和 Blink 引擎之间的桥梁作用，开发者可以更有效地调试涉及到 Web API（尤其是 IndexedDB）的问题。

Prompt: 
```
这是目录为blink/renderer/bindings/modules/v8/v8_binding_for_modules.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/bindings/modules/v8/v8_binding_for_modules.h"

#include "third_party/blink/public/common/indexeddb/indexeddb_key.h"
#include "third_party/blink/public/mojom/indexeddb/indexeddb.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value_factory.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_blob.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_string_list.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_file.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_string_resource.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_idb_cursor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_idb_cursor_with_value.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_idb_database.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_idb_index.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_idb_key_range.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_idb_object_store.h"
#include "third_party/blink/renderer/core/fileapi/blob.h"
#include "third_party/blink/renderer/core/fileapi/file.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer_view.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_any.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_cursor.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_cursor_with_value.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_database.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_key.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_key_path.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_key_range.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_value.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

static v8::Local<v8::Value> DeserializeIDBValueData(v8::Isolate*,
                                                    const IDBValue*);

// Convert a simple (non-Array) script value to an Indexed DB key. If the
// conversion fails due to a detached buffer, an exception is thrown. If
// the value can't be converted into a key, an 'Invalid' key is returned. This
// is used to implement part of the following spec algorithm:
// https://w3c.github.io/IndexedDB/#convert-value-to-key
// A V8 exception may be thrown on bad data or by script's getters; if so,
// callers should not make further V8 calls.
static std::unique_ptr<IDBKey> CreateIDBKeyFromSimpleValue(
    v8::Isolate* isolate,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  DCHECK(!value->IsArray());

  if (value->IsNumber() && !std::isnan(value.As<v8::Number>()->Value()))
    return IDBKey::CreateNumber(value.As<v8::Number>()->Value());

  if (value->IsString())
    return IDBKey::CreateString(ToCoreString(isolate, value.As<v8::String>()));

  if (value->IsDate() && !std::isnan(value.As<v8::Date>()->ValueOf()))
    return IDBKey::CreateDate(value.As<v8::Date>()->ValueOf());

  if (value->IsArrayBuffer()) {
    DOMArrayBuffer* buffer = NativeValueTraits<DOMArrayBuffer>::NativeValue(
        isolate, value, exception_state);
    if (exception_state.HadException())
      return IDBKey::CreateInvalid();
    if (buffer->IsDetached()) {
      exception_state.ThrowDOMException(DOMExceptionCode::kDataError,
                                        "The ArrayBuffer is detached.");
      return IDBKey::CreateInvalid();
    }
    const char* start = static_cast<const char*>(buffer->Data());
    size_t length = buffer->ByteLength();
    return IDBKey::CreateBinary(
        base::MakeRefCounted<base::RefCountedData<Vector<char>>>(
            Vector<char>(base::span(start, length))));
  }

  if (value->IsArrayBufferView()) {
    DOMArrayBufferView* view =
        NativeValueTraits<MaybeShared<DOMArrayBufferView>>::NativeValue(
            isolate, value, exception_state)
            .Get();
    if (exception_state.HadException())
      return IDBKey::CreateInvalid();
    if (view->buffer()->IsDetached()) {
      exception_state.ThrowDOMException(DOMExceptionCode::kDataError,
                                        "The viewed ArrayBuffer is detached.");
      return IDBKey::CreateInvalid();
    }
    const char* start = static_cast<const char*>(view->BaseAddress());
    size_t length = view->byteLength();
    return IDBKey::CreateBinary(
        base::MakeRefCounted<base::RefCountedData<Vector<char>>>(
            Vector<char>(base::span(start, length))));
  }

  return IDBKey::CreateInvalid();
}

// Convert a script value to an Indexed DB key. If the result cannot be
// converted, an 'Invalid' key is returned. If an array is being
// converted, and a potential subkey does not exist, then the array is
// returned but with an 'Invalid' entry; this is used for "multi-entry"
// indexes where an array with invalid members is permitted will later be
// sanitized. This is used to implement both of the following spec algorithms:
// https://w3c.github.io/IndexedDB/#convert-value-to-key
// https://w3c.github.io/IndexedDB/#convert-a-value-to-a-multientry-key
// A V8 exception may be thrown on bad data or by script's getters; if so,
// callers should not make further V8 calls.
std::unique_ptr<IDBKey> CreateIDBKeyFromValue(v8::Isolate* isolate,
                                              v8::Local<v8::Value> value,
                                              ExceptionState& exception_state) {
  // Simple case:
  if (!value->IsArray())
    return CreateIDBKeyFromSimpleValue(isolate, value, exception_state);

  // Recursion is done on the heap rather than the stack.
  struct Record {
    Record(v8::Local<v8::Array> array)
        : array(std::move(array)), length(array->Length()) {
      subkeys.ReserveInitialCapacity(length);
    }
    Record(const Record&) = delete;
    Record& operator=(const Record&) = delete;

    // Array being converted.
    v8::Local<v8::Array> array;
    // Length of |array|. Snapshotted (per spec), since getters may alter it.
    uint32_t length;
    // Converted sub-keys.
    IDBKey::KeyArray subkeys;
  };

  // Recursion stack.
  Vector<std::unique_ptr<Record>> stack;

  // Tracks seen arrays, to detect circular references and abort (per spec).
  v8::LocalVector<v8::Array> seen(isolate);

  // Initial state.
  {
    v8::Local<v8::Array> array = value.As<v8::Array>();
    if (array->Length() > IndexedDBKey::kMaximumArraySize)
      return IDBKey::CreateInvalid();

    stack.push_back(std::make_unique<Record>(array));
    seen.push_back(array);
  }

  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  TryRethrowScope rethrow_scope(isolate, exception_state);
  v8::MicrotasksScope microtasks_scope(
      isolate, context->GetMicrotaskQueue(),
      v8::MicrotasksScope::kDoNotRunMicrotasks);

  // Process stack - will return when complete.
  while (true) {
    DCHECK(!stack.empty());
    Record* top = stack.back().get();
    const wtf_size_t item_index = top->subkeys.size();

    // Done this array?
    if (item_index == top->length) {
      std::unique_ptr<IDBKey> key =
          IDBKey::CreateArray(std::move(top->subkeys));
      seen.pop_back();
      stack.pop_back();

      if (stack.empty())
        return key;
      top = stack.back().get();
      top->subkeys.push_back(std::move(key));
      continue;
    }

    // Process next item from current array.
    bool has_own_property;
    if (!top->array->HasOwnProperty(context, item_index)
             .To(&has_own_property)) {
      return IDBKey::CreateInvalid();
    }
    if (!has_own_property)
      return IDBKey::CreateInvalid();
    v8::Local<v8::Value> item;
    if (!top->array->Get(context, item_index).ToLocal(&item)) {
      return IDBKey::CreateInvalid();
    }

    if (!item->IsArray()) {
      // A non-array: convert it directly.
      auto key = CreateIDBKeyFromSimpleValue(isolate, item, exception_state);
      if (exception_state.HadException()) {
        DCHECK(!rethrow_scope.HasCaught());
        return IDBKey::CreateInvalid();
      }
      top->subkeys.push_back(std::move(key));
    } else {
      // A sub-array; push onto the stack and start processing it.
      v8::Local<v8::Array> array = item.As<v8::Array>();
      if (std::find(seen.begin(), seen.end(), array) != seen.end() ||
          stack.size() >= IndexedDBKey::kMaximumDepth ||
          array->Length() > IndexedDBKey::kMaximumArraySize) {
        return IDBKey::CreateInvalid();
      }

      stack.push_back(std::make_unique<Record>(array));
      seen.push_back(array);
    }
  }
}

// Indexed DB key paths should apply to explicitly copied properties (that
// will be "own" properties when deserialized) as well as the following.
// http://www.w3.org/TR/IndexedDB/#key-path-construct
static bool IsImplicitProperty(v8::Isolate* isolate,
                               v8::Local<v8::Value> value,
                               const String& name) {
  if (value->IsString() && name == "length")
    return true;
  if (value->IsArray() && name == "length")
    return true;
  if (V8Blob::HasInstance(isolate, value)) {
    return name == "size" || name == "type";
  }
  if (V8File::HasInstance(isolate, value)) {
    return name == "name" || name == "lastModified" ||
           name == "lastModifiedDate";
  }
  return false;
}

// Assumes a valid key path.
static Vector<String> ParseKeyPath(const String& key_path) {
  Vector<String> elements;
  IDBKeyPathParseError error;
  IDBParseKeyPath(key_path, elements, error);
  DCHECK_EQ(error, kIDBKeyPathParseErrorNone);
  return elements;
}

// Evaluate a key path string against a value and return a key. It must be
// called repeatedly for array-type key paths. Failure in the evaluation steps
// (per spec) is represented by returning nullptr. Failure to convert the result
// to a key is representing by returning an 'Invalid' key. (An array with
// invalid members will be returned if needed.)
// https://w3c.github.io/IndexedDB/#evaluate-a-key-path-on-a-value
// A V8 exception may be thrown on bad data or by script's getters; if so,
// callers should not make further V8 calls.
std::unique_ptr<IDBKey> CreateIDBKeyFromValueAndKeyPath(
    v8::Isolate* isolate,
    v8::Local<v8::Value> v8_value,
    const String& key_path,
    ExceptionState& exception_state) {
  Vector<String> key_path_elements = ParseKeyPath(key_path);
  DCHECK(isolate->InContext());

  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  TryRethrowScope rethrow_scope(isolate, exception_state);
  v8::MicrotasksScope microtasks_scope(
      isolate, context->GetMicrotaskQueue(),
      v8::MicrotasksScope::kDoNotRunMicrotasks);
  for (wtf_size_t i = 0; i < key_path_elements.size(); ++i) {
    const String& element = key_path_elements[i];

    // Special cases from https://w3c.github.io/IndexedDB/#key-path-construct
    // These access special or non-own properties directly, to avoid side
    // effects.

    if (v8_value->IsString() && element == "length") {
      int32_t length = v8_value.As<v8::String>()->Length();
      v8_value = v8::Number::New(isolate, length);
      continue;
    }

    if (v8_value->IsArray() && element == "length") {
      int32_t length = v8_value.As<v8::Array>()->Length();
      v8_value = v8::Number::New(isolate, length);
      continue;
    }

    if (!v8_value->IsObject())
      return nullptr;
    v8::Local<v8::Object> object = v8_value.As<v8::Object>();

    if (Blob* blob = V8Blob::ToWrappable(isolate, object)) {
      if (element == "size") {
        v8_value = v8::Number::New(isolate, blob->size());
        continue;
      }
      if (element == "type") {
        v8_value = V8String(isolate, blob->type());
        continue;
      }
      // Fall through.
    }

    if (File* file = V8File::ToWrappable(isolate, object)) {
      if (element == "name") {
        v8_value = V8String(isolate, file->name());
        continue;
      }
      if (element == "lastModified") {
        v8_value = v8::Number::New(isolate, file->lastModified());
        continue;
      }
      if (element == "lastModifiedDate") {
        ScriptState* script_state = ScriptState::From(isolate, context);
        v8_value = file->lastModifiedDate(script_state).V8Value();
        ExecutionContext* execution_context = ToExecutionContext(script_state);
        UseCounter::Count(execution_context,
                          WebFeature::kIndexedDBFileLastModifiedDate);
        continue;
      }
      // Fall through.
    }

    v8::Local<v8::String> key = V8String(isolate, element);
    bool has_own_property;
    if (!object->HasOwnProperty(context, key).To(&has_own_property)) {
      return nullptr;
    }
    if (!has_own_property)
      return nullptr;
    if (!object->Get(context, key).ToLocal(&v8_value)) {
      return nullptr;
    }
  }
  return CreateIDBKeyFromValue(isolate, v8_value, exception_state);
}

// Evaluate a key path against a value and return a key. For string-type
// paths, nullptr is returned if evaluation of the path fails, and an
// 'Invalid' key if evaluation succeeds but conversion fails. For array-type
// paths, nullptr is returned if evaluation of any sub-path fails, otherwise
// an array key is returned (with potentially 'Invalid' members).
// https://w3c.github.io/IndexedDB/#evaluate-a-key-path-on-a-value
// A V8 exception may be thrown on bad data or by script's getters; if so,
// callers should not make further V8 calls.
std::unique_ptr<IDBKey> CreateIDBKeyFromValueAndKeyPath(
    v8::Isolate* isolate,
    v8::Local<v8::Value> value,
    const IDBKeyPath& key_path,
    ExceptionState& exception_state) {
  DCHECK(!key_path.IsNull());
  v8::HandleScope handle_scope(isolate);
  if (key_path.GetType() == mojom::IDBKeyPathType::Array) {
    const Vector<String>& array = key_path.Array();
    IDBKey::KeyArray result;
    result.ReserveInitialCapacity(array.size());
    for (const String& path : array) {
      auto key = CreateIDBKeyFromValueAndKeyPath(isolate, value, path,
                                                 exception_state);
      if (exception_state.HadException())
        return nullptr;
      // Evaluation of path failed - overall failure.
      if (!key)
        return nullptr;
      result.emplace_back(std::move(key));
    }
    // An array key is always returned, even if members may be invalid.
    return IDBKey::CreateArray(std::move(result));
  }

  DCHECK_EQ(key_path.GetType(), mojom::IDBKeyPathType::String);
  return CreateIDBKeyFromValueAndKeyPath(isolate, value, key_path.GetString(),
                                         exception_state);
}

// Evaluate an index's key path against a value and return a key. This
// handles the special case for indexes where a compound key path
// may result in "holes", depending on the store's properties.
// Otherwise, nullptr is returned.
// https://w3c.github.io/IndexedDB/#evaluate-a-key-path-on-a-value
// A V8 exception may be thrown on bad data or by script's getters; if so,
// callers should not make further V8 calls.
std::unique_ptr<IDBKey> CreateIDBKeyFromValueAndKeyPaths(
    v8::Isolate* isolate,
    v8::Local<v8::Value> value,
    const IDBKeyPath& store_key_path,
    const IDBKeyPath& index_key_path,
    ExceptionState& exception_state) {
  DCHECK(!index_key_path.IsNull());
  v8::HandleScope handle_scope(isolate);
  if (index_key_path.GetType() == mojom::IDBKeyPathType::Array) {
    const Vector<String>& array = index_key_path.Array();
    const bool uses_inline_keys =
        store_key_path.GetType() == mojom::IDBKeyPathType::String;
    IDBKey::KeyArray result;
    result.ReserveInitialCapacity(array.size());
    for (const String& path : array) {
      auto key = CreateIDBKeyFromValueAndKeyPath(isolate, value, path,
                                                 exception_state);
      if (exception_state.HadException())
        return nullptr;
      if (!key && uses_inline_keys && store_key_path.GetString() == path) {
        // Compound keys that include the store's inline primary key which
        // will be generated lazily are represented as "holes".
        key = IDBKey::CreateNone();
      } else if (!key) {
        // Key path evaluation failed.
        return nullptr;
      } else if (!key->IsValid()) {
        // An Invalid key is returned if not valid in this case (but not the
        // other CreateIDBKeyFromValueAndKeyPath function) because:
        // * Invalid members are only allowed for multi-entry arrays.
        // * Array key paths can't be multi-entry.
        return IDBKey::CreateInvalid();
      }

      result.emplace_back(std::move(key));
    }
    return IDBKey::CreateArray(std::move(result));
  }

  DCHECK_EQ(index_key_path.GetType(), mojom::IDBKeyPathType::String);
  return CreateIDBKeyFromValueAndKeyPath(
      isolate, value, index_key_path.GetString(), exception_state);
}

// Deserialize just the value data & blobInfo from the given IDBValue.
//
// Primary key injection is performed in deserializeIDBValue() below.
v8::Local<v8::Value> DeserializeIDBValueData(v8::Isolate* isolate,
                                             const IDBValue* value) {
  DCHECK(isolate->InContext());
  if (!value) {
    return v8::Null(isolate);
  }

  scoped_refptr<SerializedScriptValue> serialized_value =
      value->CreateSerializedValue();

  serialized_value->FileSystemAccessTokens() =
      std::move(const_cast<IDBValue*>(value)->FileSystemAccessTokens());

  SerializedScriptValue::DeserializeOptions options;
  options.blob_info = &value->BlobInfo();

  // deserialize() returns null when serialization fails.  This is sub-optimal
  // because IndexedDB values can be null, so an application cannot distinguish
  // between a de-serialization failure and a legitimately stored null value.
  //
  // TODO(crbug.com/703704): Ideally, SerializedScriptValue should return an
  // empty handle on serialization errors, which should be handled by higher
  // layers. For example, IndexedDB could throw an exception, abort the
  // transaction, or close the database connection.
  return serialized_value->Deserialize(isolate, options);
}

// Deserialize the entire IDBValue.
//
// On top of deserializeIDBValueData(), this handles the special case of having
// to inject a key into the de-serialized value. See injectV8KeyIntoV8Value()
// for details.
v8::Local<v8::Value> DeserializeIDBValue(ScriptState* script_state,
                                         const IDBValue* value) {
  v8::Isolate* isolate = script_state->GetIsolate();
  DCHECK(isolate->InContext());
  if (!value) {
    return v8::Null(isolate);
  }

  v8::Local<v8::Value> v8_value = DeserializeIDBValueData(isolate, value);
  if (value->PrimaryKey()) {
    v8::Local<v8::Value> key = value->PrimaryKey()->ToV8(script_state);
    if (key.IsEmpty()) {
      return v8::Local<v8::Value>();
    }

    InjectV8KeyIntoV8Value(isolate, key, v8_value, value->KeyPath());

    // TODO(crbug.com/703704): Throw an error here or at a higher layer if
    // injectV8KeyIntoV8Value() returns false, which means that the serialized
    // value got corrupted while on disk.
  }

  return v8_value;
}

v8::Local<v8::Value> DeserializeIDBValueArray(
    ScriptState* script_state,
    const Vector<std::unique_ptr<IDBValue>>& values) {
  v8::Isolate* isolate = script_state->GetIsolate();
  DCHECK(isolate->InContext());

  v8::Local<v8::Array> array = v8::Array::New(isolate, values.size());
  v8::Local<v8::Context> current_context = isolate->GetCurrentContext();
  for (wtf_size_t i = 0; i < values.size(); ++i) {
    v8::Local<v8::Value> v8_value =
        DeserializeIDBValue(script_state, values[i].get());
    if (v8_value.IsEmpty())
      v8_value = v8::Undefined(isolate);
    bool created_property;
    if (!array->CreateDataProperty(current_context, i, v8_value)
             .To(&created_property) ||
        !created_property) {
      return v8::Local<v8::Value>();
    }
  }

  return array;
}

// Injects a primary key into a deserialized V8 value.
//
// In general, the value stored in IndexedDB is the serialized version of a
// value passed to the API. However, the specification has a special case of
// object stores that specify a key path and have a key generator. In this case,
// the conceptual description in the spec states that the key produced by the
// key generator is injected into the value before it is written to IndexedDB.
//
// We cannot implement the spec's conceptual description. We need to assign
// primary keys in the browser process, to ensure that multiple renderer
// processes talking to the same database receive sequential keys. At the same
// time, we want the value serialization code to live in the renderer process,
// because this type of code is a likely victim to security exploits.
//
// We handle this special case by serializing and writing values without the
// corresponding keys. At read time, we obtain the keys and the values
// separately, and we inject the keys into values.
bool InjectV8KeyIntoV8Value(v8::Isolate* isolate,
                            v8::Local<v8::Value> key,
                            v8::Local<v8::Value> value,
                            const IDBKeyPath& key_path) {
  TRACE_EVENT0("IndexedDB", "injectIDBV8KeyIntoV8Value");
  DCHECK(isolate->InContext());

  DCHECK_EQ(key_path.GetType(), mojom::IDBKeyPathType::String);
  Vector<String> key_path_elements = ParseKeyPath(key_path.GetString());

  // The conbination of a key generator and an empty key path is forbidden by
  // spec.
  if (!key_path_elements.size()) {
    NOTREACHED();
  }

  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::Context> context = isolate->GetCurrentContext();

  // For an object o = {} which should have keypath 'a.b.c' and key k, this
  // populates o to be {a:{b:{}}}. This is only applied to deserialized
  // values, so we can assume that there are no getters/setters on the
  // object itself (though there might be on the prototype chain).
  //
  // Previous versions of this code assumed that the deserialized value meets
  // the constraints checked by the serialization validation code. For example,
  // given a keypath of a.b.c, the code assumed that the de-serialized value
  // cannot possibly be {a:{b:42}}. This is not a safe assumption.
  //
  // IndexedDB's backing store (LevelDB) does use CRC32C to protect against disk
  // errors. However, this does not prevent corruption caused by bugs in the
  // higher level code writing invalid values. The following cases are
  // interesting here.
  //
  // (1) Deserialization failures, which are currently handled by returning
  // null. Disk errors aside, deserialization errors can also occur when a user
  // switches channels and receives an older build which does not support the
  // serialization format used by the previous (more recent) build that the user
  // had.
  //
  // (2) Bugs that write a value which is incompatible with the primary key
  // injection required by the object store. The simplest example is writing
  // numbers or booleans to an object store with an auto-incrementing primary
  // keys.
  for (wtf_size_t i = 0; i < key_path_elements.size() - 1; ++i) {
    if (!value->IsObject())
      return false;

    const String& key_path_element = key_path_elements[i];
    DCHECK(!IsImplicitProperty(isolate, value, key_path_element));
    v8::Local<v8::Object> object = value.As<v8::Object>();
    v8::Local<v8::String> property = V8String(isolate, key_path_element);
    bool has_own_property;
    if (!object->HasOwnProperty(context, property).To(&has_own_property))
      return false;
    if (has_own_property) {
      if (!object->Get(context, property).ToLocal(&value))
        return false;
    } else {
      value = v8::Object::New(isolate);
      bool created_property;
      if (!object->CreateDataProperty(context, property, value)
               .To(&created_property) ||
          !created_property)
        return false;
    }
  }

  // Implicit properties don't need to be set. The caller is not required to
  // be aware of this, so this is an expected no-op. The caller can verify
  // that the value is correct via assertPrimaryKeyValidOrInjectable.
  if (IsImplicitProperty(isolate, value, key_path_elements.back()))
    return true;

  // If the key path does not point to an implicit property, the value must be
  // an object. Previous code versions DCHECKed this, which is unsafe in the
  // event of database corruption or version skew in the serialization format.
  if (!value->IsObject())
    return false;

  v8::Local<v8::Object> object = value.As<v8::Object>();
  v8::Local<v8::String> property = V8String(isolate, key_path_elements.back());

  bool created_property;
  if (!object->CreateDataProperty(context, property, key).To(&created_property))
    return false;
  return created_property;
}

// Verify that an value can have an generated key inserted at the location
// specified by the key path (by injectV8KeyIntoV8Value) when the object is
// later deserialized.
bool CanInjectIDBKeyIntoScriptValue(v8::Isolate* isolate,
                                    const ScriptValue& script_value,
                                    const IDBKeyPath& key_path) {
  TRACE_EVENT0("IndexedDB", "canInjectIDBKeyIntoScriptValue");
  DCHECK_EQ(key_path.GetType(), mojom::IDBKeyPathType::String);
  Vector<String> key_path_elements = ParseKeyPath(key_path.GetString());

  if (!key_path_elements.size())
    return false;

  v8::Local<v8::Value> current(script_value.V8Value());
  if (!current->IsObject())
    return false;

  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  for (wtf_size_t i = 0; i < key_path_elements.size(); ++i) {
    const String& key_path_element = key_path_elements[i];
    // Can't overwrite properties like array or string length.
    if (IsImplicitProperty(isolate, current, key_path_element))
      return false;
    // Can't set properties on non-objects.
    if (!current->IsObject())
      return false;
    v8::Local<v8::Object> object = current.As<v8::Object>();
    v8::Local<v8::String> property = V8String(isolate, key_path_element);
    // If the value lacks an "own" property, it can be added - either as
    // an intermediate object or as the final value.
    bool has_own_property;
    if (!object->HasOwnProperty(context, property).To(&has_own_property))
      return false;
    if (!has_own_property)
      return true;
    // Otherwise, get it and keep traversing.
    if (!object->Get(context, property).ToLocal(&current))
      return false;
  }
  return true;
}

ScriptValue DeserializeScriptValue(ScriptState* script_state,
                                   SerializedScriptValue* serialized_value,
                                   const Vector<WebBlobInfo>* blob_info) {
  v8::Isolate* isolate = script_state->GetIsolate();
  v8::HandleScope handle_scope(isolate);
  if (!serialized_value)
    return ScriptValue::CreateNull(script_state->GetIsolate());

  SerializedScriptValue::DeserializeOptions options;
  options.blob_info = blob_info;
  return ScriptValue(isolate, serialized_value->Deserialize(isolate, options));
}

SQLValue NativeValueTraits<SQLValue>::NativeValue(
    v8::Isolate* isolate,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  if (value.IsEmpty() || value->IsNull())
    return SQLValue();
  if (value->IsNumber())
    return SQLValue(value.As<v8::Number>()->Value());
  V8StringResource<> string_value(isolate, value);
  if (!string_value.Prepare(exception_state)) {
    return SQLValue();
  }
  return SQLValue(string_value);
}


#if DCHECK_IS_ON()
// This assertion is used when a value has been retrieved from an object store
// with implicit keys (i.e. a key path). It verifies that either the value
// contains an implicit key matching the primary key (so it was correctly
// extracted when stored) or that the key can be inserted as an own property.
void AssertPrimaryKeyValidOrInjectable(ScriptState* script_state,
                                       const IDBValue* value) {
  ScriptState::Scope scope(script_state);
  v8::Isolate* isolate = script_state->GetIsolate();
  ScriptValue key_value(isolate, value->PrimaryKey()->ToV8(script_state));
  ScriptValue script_value(isolate, DeserializeIDBValueData(isolate, value));

  DummyExceptionStateForTesting exception_state;
  std::unique_ptr<IDBKey> expected_key = CreateIDBKeyFromValueAndKeyPath(
      isolate, script_value.V8Value(), value->KeyPath(), exception_state);
  DCHECK(!exception_state.HadException());
  if (expected_key && expected_key->IsEqual(value->PrimaryKey()))
    return;

  bool injected = InjectV8KeyIntoV8Value(
      isolate, key_value.V8Value(), script_value.V8Value(), value->KeyPath());
  DCHECK(injected);
}
#endif  // DCHECK_IS_ON()

}  // namespace blink

"""

```