Response:
Let's break down the thought process for analyzing this C++ file.

**1. Initial Reading and Identifying Key Areas:**

The first step is a quick skim to get a general idea. I see `#include` statements related to V8, serialization, core Blink types (like `ImageBitmap`, `MessagePort`), and platform utilities. The copyright notice and comments at the top confirm this is about serialization. The class name `SerializedScriptValue` is central.

**2. Focusing on the Class and its Methods:**

Next, I look at the `SerializedScriptValue` class definition and its public methods. Methods like `Serialize`, `Deserialize`, `Create`, `ToWireString`, and the `Transfer*` methods immediately stand out as core functionalities.

**3. Understanding the Core Functionality - Serialization and Deserialization:**

The names `Serialize` and `Deserialize` are self-explanatory. I see they interact with V8's `v8::Value` and involve `SerializeOptions` and `DeserializeOptions`. This strongly suggests the file is responsible for converting JavaScript values into a binary representation and vice versa.

**4. Examining `Create` Methods:**

The various `Create` methods tell me how `SerializedScriptValue` instances are created. I note the `Create(const String& data)` and `Create(base::span<const uint8_t> data)` overloads, indicating it can be created from existing string or raw byte data. The static `NullValue()` and `UndefinedValue()` methods show it can represent these specific JavaScript values.

**5. Analyzing `Transfer*` Methods:**

The `TransferImageBitmaps`, `TransferOffscreenCanvas`, `TransferReadableStreams`, etc., methods are crucial. The term "transfer" implies moving ownership of resources, which is important in web workers and inter-process communication. The arguments to these methods (like `ImageBitmapArray`, `OffscreenCanvasArray`) point to specific JavaScript/DOM types. The `ExceptionState&` parameter in many methods suggests error handling is a key concern.

**6. Identifying Relationships with JavaScript, HTML, and CSS:**

Based on the types being serialized and transferred (e.g., `ImageBitmap`, `OffscreenCanvas`, `ArrayBuffer`), it's clear this file plays a role in handling data related to HTML canvas, images, and potentially other web APIs. The mention of "transferables" strengthens the connection to JavaScript's structured cloning algorithm used for `postMessage`. CSS is less directly involved here, but styles can influence the *content* of things like canvas elements.

**7. Looking for Logical Reasoning and Assumptions:**

The code contains conditional logic (e.g., checking if an `ImageBitmap` is "neutered"). The byte-swapping logic based on the SSV version is an example of handling historical data formats. I infer that the developers needed to maintain backward compatibility. The `IsByteSwappedWiredData` function makes assumptions about the format of older serialized data.

**8. Identifying Potential User/Programming Errors:**

The `Transfer*` methods that throw `DOMExceptionCode::kDataCloneError` highlight common mistakes, like trying to transfer an already detached `ArrayBuffer` or `ImageBitmap`. The `kInvalidStateError` for an `OffscreenCanvas` with a rendering context points to another user error.

**9. Tracing User Actions to the Code (Debugging Clues):**

I consider scenarios where this code might be involved. `postMessage` is the prime example. Saving data to `IndexedDB` is another. The `Transfer*` methods link directly to the transfer list concept in `postMessage`.

**10. Considering the "Why":**

I ask myself *why* this file exists. The core reason is to enable safe and efficient communication of data between different execution contexts (e.g., main thread and web workers) and for persistence (like in IndexedDB). Serialization is essential for these operations.

**11. Structuring the Output:**

Finally, I organize my findings into logical sections: Functionality, Relationship to Web Technologies, Logical Reasoning, User Errors, Debugging, etc. I provide concrete examples wherever possible to illustrate the points. I make sure to highlight key assumptions and potential pitfalls.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe this file only handles basic JavaScript types.
* **Correction:**  The presence of `ImageBitmap`, `OffscreenCanvas`, and streams indicates it handles more complex objects.

* **Initial thought:** The byte-swapping logic is weird.
* **Clarification:** The comments explain it's for backward compatibility with older versions of the serialization format used by IndexedDB.

* **Initial thought:**  How does this relate to CSS?
* **Refinement:**  It's more about the *data* that might be visualized based on CSS, rather than directly manipulating CSS rules.

By following these steps, moving from a high-level overview to a detailed analysis of specific methods and their implications, I can generate a comprehensive explanation of the file's purpose and its interactions within the Chromium/Blink ecosystem.
This C++ source file, `serialized_script_value.cc`, within the Chromium Blink rendering engine, is responsible for **serializing and deserializing JavaScript values**. This process is crucial for various functionalities in a web browser, particularly when transferring data between different execution contexts or persisting data.

Here's a breakdown of its functionalities:

**Core Functionality:**

1. **Serialization:**  Converting JavaScript values (like numbers, strings, objects, arrays, `ArrayBuffer`, `ImageBitmap`, etc.) into a binary representation (a sequence of bytes). This allows these values to be stored, transmitted, or cloned.
2. **Deserialization:**  Reconstructing JavaScript values from their serialized binary representation. This is the reverse process of serialization.
3. **Handling Transferables:**  Managing special JavaScript objects known as "transferables" (like `ArrayBuffer`, `MessagePort`, `ImageBitmap`, `OffscreenCanvas`, streams). Serialization of transferables involves *moving* the underlying resource rather than just copying it, improving performance.
4. **Byte Swapping (for Legacy Support):**  Handling older versions of the serialization format that used byte swapping for representing data on the wire. This ensures backward compatibility with data stored by older browser versions (primarily in IndexedDB).
5. **Versioning:**  Including versioning information in the serialized data to ensure compatibility between different browser versions.
6. **Memory Management:**  Registering and unregistering the memory allocated for serialized data with the current script context's memory accounting system. This helps track memory usage and prevent leaks.
7. **Origin Security Checks:**  Identifying if the serialized data contains resources that require origin checks during deserialization (e.g., `FileSystemFileHandle`, `WebAssembly.Module`).
8. **Interface Exposure Checks:** Determining if the execution context where deserialization is happening has the necessary interfaces and features to handle the serialized data.

**Relationship with JavaScript, HTML, and CSS:**

This file is deeply intertwined with JavaScript and indirectly related to HTML and CSS:

* **JavaScript:** This file is the bridge between the C++ world of the browser engine and the JavaScript world. It allows JavaScript values to be manipulated and moved around within the browser's internal workings.
    * **Example:** When you use `postMessage` to send data between a main page and a web worker, the JavaScript values you send are serialized using this code before being transferred. On the receiving end, they are deserialized back into JavaScript values.
    * **Example:**  When you save data to `IndexedDB`, JavaScript values are serialized before being written to disk. When you retrieve data from `IndexedDB`, it's deserialized back into JavaScript values.
    * **Example:**  Transferring an `ArrayBuffer` using the transfer list in `postMessage`. This code handles the efficient transfer of the underlying memory buffer.

* **HTML:**  Objects created and manipulated within the context of an HTML page (like `ImageBitmap` from a `<canvas>` element or an `OffscreenCanvas`) are handled by this serialization/deserialization mechanism when they need to be transferred or stored.
    * **Example:**  Transferring the rendering results of an `OffscreenCanvas` to a web worker for further processing involves serializing the `OffscreenCanvas`.
    * **Example:**  Storing an `ImageBitmap` obtained from an `<img>` tag in `IndexedDB`.

* **CSS:** While CSS itself isn't directly serialized by this code, the *results* of CSS styling can be reflected in the content of objects that *are* serialized, such as canvas elements.
    * **Example:**  If you draw a styled shape on a `<canvas>` element and then transfer an `ImageBitmap` of that canvas, the CSS styles will have influenced the visual data being serialized.

**Logical Reasoning (Hypothetical Input and Output):**

**Scenario 1: Serializing a simple JavaScript object:**

* **Hypothetical Input (JavaScript):** `const myObject = { name: "Alice", age: 30 };`
* **Processing:** The `Serialize` method in `serialized_script_value.cc` would traverse the object, encoding its properties and values into a binary format according to the defined serialization scheme. This would involve encoding the string "name", the string "Alice", the string "age", and the number 30, along with type information for each.
* **Hypothetical Output (Binary):**  A sequence of bytes representing the structure and data of `myObject`. The exact byte sequence is an implementation detail but would include markers for object start, property names, value types, and the actual data.

**Scenario 2: Deserializing a transferable `ArrayBuffer`:**

* **Hypothetical Input (Binary):** A byte sequence representing a serialized `ArrayBuffer`, potentially received via `postMessage`.
* **Processing:** The `Deserialize` method would interpret the byte sequence. Recognizing the marker for an `ArrayBuffer`, it would create a new `ArrayBuffer` in the target execution context. If the `ArrayBuffer` was transferred (not just cloned), the underlying memory would be moved.
* **Hypothetical Output (JavaScript):** A new JavaScript `ArrayBuffer` object in the receiving context, containing the data from the original `ArrayBuffer`.

**User or Programming Common Usage Errors:**

1. **Attempting to transfer a detached `ArrayBuffer` or `ImageBitmap`:**
   * **Error:**  A `DOMException` with code `DataCloneError` will be thrown.
   * **User Action Leading to Error:**
      1. Create an `ArrayBuffer`.
      2. Transfer the `ArrayBuffer` to a worker using `postMessage`.
      3. On the main thread, attempt to use the transferred `ArrayBuffer` again (it's now detached).
      4. Later, attempt to serialize this already detached `ArrayBuffer` for another transfer or storage operation.
   * **Code in `serialized_script_value.cc`:** The `TransferArrayBufferContents` or `TransferImageBitmapContents` methods check for the detached state and throw the exception.

2. **Trying to transfer an `OffscreenCanvas` that has an active rendering context:**
   * **Error:** A `DOMException` with code `InvalidStateError` will be thrown.
   * **User Action Leading to Error:**
      1. Create an `OffscreenCanvas`.
      2. Get its 2D rendering context using `getContext('2d')`.
      3. Attempt to transfer this `OffscreenCanvas` to a worker using `postMessage`.
   * **Code in `serialized_script_value.cc`:** The `TransferOffscreenCanvas` method checks if the `OffscreenCanvas` has a rendering context.

3. **Incorrectly implementing custom serialization/deserialization (less common, but possible with certain APIs):** If developers try to bypass the standard serialization mechanisms and create their own, they can introduce errors in the binary format, leading to failures during deserialization.

**User Operation Steps Leading Here (Debugging Clues):**

1. **Using `postMessage`:**
   * A user action triggers a JavaScript call to `postMessage` with a complex object or a transferable object in the message.
   * The browser's internal logic calls the serialization functions in `serialized_script_value.cc` to prepare the message for transfer.

2. **Saving data to `IndexedDB`:**
   * A website's JavaScript code uses the `IndexedDB` API to store data.
   * The browser calls the serialization functions in `serialized_script_value.cc` to convert the JavaScript values into a format suitable for storage.

3. **Cloning objects in workers or service workers:**
   * When a worker needs a copy of an object from the main thread (or vice-versa), the structured cloning algorithm is used, which relies on serialization and deserialization.

4. **Using the `structuredClone` function:**
   * JavaScript code explicitly calls the `structuredClone` function to create a deep copy of an object. This function internally uses the serialization and deserialization mechanisms.

5. **Transferring data using Fetch API and ReadableStream/WritableStream:**
   * When transferring data using streams, the underlying data chunks might be serialized as part of the process if they involve complex JavaScript objects.

**In summary, `serialized_script_value.cc` is a fundamental component of the Blink rendering engine responsible for the critical tasks of converting JavaScript values into a portable binary format and back. It plays a vital role in enabling inter-process communication, data persistence, and the efficient transfer of resources within web browsers.**

Prompt: 
```
这是目录为blink/renderer/bindings/core/v8/serialization/serialized_script_value.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value.h"

#include <memory>

#include "base/containers/span.h"
#include "base/numerics/byte_conversions.h"
#include "base/numerics/checked_math.h"
#include "base/numerics/safe_conversions.h"
#include "base/ranges/algorithm.h"
#include "base/types/expected_macros.h"
#include "third_party/blink/public/web/web_serialized_script_value_version.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialization_tag.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value_factory.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/trailer_reader.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/transferables.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/unpacked_serialized_script_value.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/core/messaging/message_port.h"
#include "third_party/blink/renderer/core/offscreencanvas/offscreen_canvas.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/transform_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_shared_array_buffer.h"
#include "third_party/blink/renderer/platform/bindings/dom_data_store.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"

namespace blink {

namespace {

SerializedScriptValue::CanDeserializeInCallback& GetCanDeserializeInCallback() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(
      SerializedScriptValue::CanDeserializeInCallback, g_callback, ());
  return g_callback;
}

}  // namespace

scoped_refptr<SerializedScriptValue> SerializedScriptValue::Serialize(
    v8::Isolate* isolate,
    v8::Local<v8::Value> value,
    const SerializeOptions& options,
    ExceptionState& exception) {
  return SerializedScriptValueFactory::Instance().Create(isolate, value,
                                                         options, exception);
}

scoped_refptr<SerializedScriptValue>
SerializedScriptValue::SerializeAndSwallowExceptions(
    v8::Isolate* isolate,
    v8::Local<v8::Value> value) {
  DummyExceptionStateForTesting exception_state;
  scoped_refptr<SerializedScriptValue> serialized =
      Serialize(isolate, value, SerializeOptions(), exception_state);
  if (exception_state.HadException())
    return NullValue();
  return serialized;
}

scoped_refptr<SerializedScriptValue> SerializedScriptValue::Create() {
  return base::AdoptRef(new SerializedScriptValue);
}

scoped_refptr<SerializedScriptValue> SerializedScriptValue::Create(
    const String& data) {
  base::CheckedNumeric<size_t> data_buffer_size = data.length();
  data_buffer_size *= 2;
  if (!data_buffer_size.IsValid())
    return Create();

  DataBufferPtr data_buffer = AllocateBuffer(data_buffer_size.ValueOrDie());
  // TODO(danakj): This cast is valid, since it's at the start of the allocation
  // which will be aligned correctly for UChar. However the pattern of casting
  // byte pointers to other types is problematic and can cause UB. String should
  // provide a way to copy directly to a byte array without forcing the caller
  // to do this case.
  data.CopyTo(
      base::span(reinterpret_cast<UChar*>(data_buffer.data()), data.length()),
      0);

  return base::AdoptRef(new SerializedScriptValue(std::move(data_buffer)));
}

// Returns whether `tag` was a valid tag in the v0 serialization format.
inline static constexpr bool IsV0VersionTag(uint8_t tag) {
  // There were 13 tags supported in version 0:
  //
  //  35 - 0x23 - # - ImageDataTag
  //  64 - 0x40 - @ - SparseArrayTag
  //  68 - 0x44 - D - DateTag
  //  73 - 0x49 - I - Int32Tag
  //  78 - 0x4E - N - NumberTag
  //  82 - 0x52 - R - RegExpTag
  //  83 - 0x53 - S - StringTag
  //  85 - 0x55 - U - Uint32Tag
  //  91 - 0x5B - [ - ArrayTag
  //  98 - 0x62 - b - BlobTag
  // 102 - 0x66 - f - FileTag
  // 108 - 0x6C - l - FileListTag
  // 123 - 0x7B - { - ObjectTag
  return tag == 35 || tag == 64 || tag == 68 || tag == 73 || tag == 78 ||
         tag == 82 || tag == 83 || tag == 85 || tag == 91 || tag == 98 ||
         tag == 102 || tag == 108 || tag == 123;
}

// Versions 16 and below (prior to April 2017) used ntohs() to byte-swap SSV
// data when converting it to the wire format. This was a historical accient.
//
// As IndexedDB stores SSVs to disk indefinitely, we still need to keep around
// the code needed to deserialize the old format.
inline static bool IsByteSwappedWiredData(base::span<const uint8_t> data) {
  // TODO(pwnall): Return false early if we're on big-endian hardware. Chromium
  // doesn't currently support big-endian hardware, and there's no header
  // exposing endianness to Blink yet. ARCH_CPU_LITTLE_ENDIAN seems promising,
  // but Blink is not currently allowed to include files from build/.

  // The first SSV version without byte-swapping has two envelopes (Blink, V8),
  // each of which is at least 2 bytes long.
  if (data.size() < 4u) {
    return true;
  }

  // This code handles the following cases:
  //
  // v0 (byte-swapped)    - [d,    t,    ...], t = tag byte, d = first data byte
  // v1-16 (byte-swapped) - [v,    0xFF, ...], v = version (1 <= v <= 16)
  // v17+                 - [0xFF, v,    ...], v = first byte of version varint

  if (data[0] != kVersionTag) {
    // Pre-version 17, thus byte-swapped.
    return true;
  }

  // The only case where byte-swapped data can have 0xFF in byte zero is version
  // 0. This can only happen if byte one is a tag (supported in version 0) that
  // takes in extra data, and the first byte of extra data is 0xFF. These tags
  // cannot be used as version numbers in the Blink-side SSV envelope.
  //
  // Why we care about version 0:
  //
  // IndexedDB stores values using the SSV format. Currently, IndexedDB does not
  // do any sort of migration, so a value written with a SSV version will be
  // stored with that version until it is removed via an update or delete.
  //
  // IndexedDB was shipped in Chrome 11, which was released on April 27, 2011.
  // SSV version 1 was added in WebKit r91698, which was shipped in Chrome 14,
  // which was released on September 16, 2011.
  static_assert(
      !IsV0VersionTag(SerializedScriptValue::kWireFormatVersion),
      "Using a burned version will prevent us from reading SSV version 0");
  // TODO(pwnall): Add UMA metric here.
  return IsV0VersionTag(data[1]);
}

static void SwapWiredDataIfNeeded(base::span<uint8_t> buffer) {
  if (buffer.size() % sizeof(UChar)) {
    return;
  }

  if (!IsByteSwappedWiredData(buffer)) {
    return;
  }

  static_assert(sizeof(UChar) == 2);
  for (size_t i = 0; i < buffer.size(); i += 2) {
    std::swap(buffer[i], buffer[i + 1]);
  }
}

scoped_refptr<SerializedScriptValue> SerializedScriptValue::Create(
    base::span<const uint8_t> data) {
  if (data.empty())
    return Create();

  DataBufferPtr data_buffer = AllocateBuffer(data.size());
  data_buffer.as_span().copy_from(data);
  SwapWiredDataIfNeeded(data_buffer.as_span());

  return base::AdoptRef(new SerializedScriptValue(std::move(data_buffer)));
}

SerializedScriptValue::SerializedScriptValue()
    : has_registered_external_allocation_(false) {}

SerializedScriptValue::SerializedScriptValue(DataBufferPtr data)
    : data_buffer_(std::move(data)),
      has_registered_external_allocation_(false) {}

void SerializedScriptValue::SetImageBitmapContentsArray(
    ImageBitmapContentsArray contents) {
  image_bitmap_contents_array_ = std::move(contents);
}

SerializedScriptValue::DataBufferPtr SerializedScriptValue::AllocateBuffer(
    size_t buffer_size) {
  // SAFETY: BufferMalloc() always returns a pointer to at least
  // `buffer_size` bytes.
  return UNSAFE_BUFFERS(DataBufferPtr::FromOwningPointer(
      static_cast<uint8_t*>(WTF::Partitions::BufferMalloc(
          buffer_size, "SerializedScriptValue buffer")),
      buffer_size));
}

SerializedScriptValue::~SerializedScriptValue() {
  // If the allocated memory was not registered before, then this class is
  // likely used in a context other than Worker's onmessage environment and the
  // presence of current v8 context is not guaranteed. Avoid calling v8 then.
  if (has_registered_external_allocation_) {
    DCHECK_NE(isolate_, nullptr);
    external_memory_accounter_.Decrease(isolate_.get(), DataLengthInBytes());
  }
}

scoped_refptr<SerializedScriptValue> SerializedScriptValue::NullValue() {
  // The format here may fall a bit out of date, because we support
  // deserializing SSVs written by old browser versions.
  static const uint8_t kNullData[] = {0xFF, 17, 0xFF, 13, '0', 0x00};
  return Create(kNullData);
}

scoped_refptr<SerializedScriptValue> SerializedScriptValue::UndefinedValue() {
  // The format here may fall a bit out of date, because we support
  // deserializing SSVs written by old browser versions.
  static const uint8_t kUndefinedData[] = {0xFF, 17, 0xFF, 13, '_', 0x00};
  return Create(kUndefinedData);
}

String SerializedScriptValue::ToWireString() const {
  // Add the padding '\0', but don't put it in |data_buffer_|.
  // This requires direct use of uninitialized strings, though.
  auto string_size_bytes = base::checked_cast<wtf_size_t>(
      base::bits::AlignUp(data_buffer_.size(), sizeof(UChar)));
  base::span<UChar> backing;
  String wire_string =
      String::CreateUninitialized(string_size_bytes / sizeof(UChar), backing);
  auto [content, padding] =
      base::as_writable_bytes(backing).split_at(data_buffer_.size());
  content.copy_from(data_buffer_);
  if (!padding.empty()) {
    CHECK_EQ(padding.size(), 1u);
    padding[0u] = '\0';
  }
  return wire_string;
}

SerializedScriptValue::ImageBitmapContentsArray
SerializedScriptValue::TransferImageBitmapContents(
    v8::Isolate* isolate,
    const ImageBitmapArray& image_bitmaps,
    ExceptionState& exception_state) {
  ImageBitmapContentsArray contents;

  if (!image_bitmaps.size())
    return contents;

  for (wtf_size_t i = 0; i < image_bitmaps.size(); ++i) {
    if (image_bitmaps[i]->IsNeutered()) {
      exception_state.ThrowDOMException(DOMExceptionCode::kDataCloneError,
                                        "ImageBitmap at index " +
                                            String::Number(i) +
                                            " is already detached.");
      return contents;
    }
  }

  HeapHashSet<Member<ImageBitmap>> visited;
  for (wtf_size_t i = 0; i < image_bitmaps.size(); ++i) {
    if (visited.Contains(image_bitmaps[i]))
      continue;
    visited.insert(image_bitmaps[i]);
    contents.push_back(image_bitmaps[i]->Transfer());
  }
  return contents;
}

void SerializedScriptValue::TransferImageBitmaps(
    v8::Isolate* isolate,
    const ImageBitmapArray& image_bitmaps,
    ExceptionState& exception_state) {
  image_bitmap_contents_array_ =
      TransferImageBitmapContents(isolate, image_bitmaps, exception_state);
}

void SerializedScriptValue::TransferOffscreenCanvas(
    v8::Isolate* isolate,
    const OffscreenCanvasArray& offscreen_canvases,
    ExceptionState& exception_state) {
  if (!offscreen_canvases.size())
    return;

  HeapHashSet<Member<OffscreenCanvas>> visited;
  for (wtf_size_t i = 0; i < offscreen_canvases.size(); i++) {
    if (visited.Contains(offscreen_canvases[i].Get()))
      continue;
    if (offscreen_canvases[i]->IsNeutered()) {
      exception_state.ThrowDOMException(DOMExceptionCode::kDataCloneError,
                                        "OffscreenCanvas at index " +
                                            String::Number(i) +
                                            " is already detached.");
      return;
    }
    if (offscreen_canvases[i]->RenderingContext()) {
      exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                        "OffscreenCanvas at index " +
                                            String::Number(i) +
                                            " has an associated context.");
      return;
    }
    visited.insert(offscreen_canvases[i].Get());
    offscreen_canvases[i].Get()->SetNeutered();
    offscreen_canvases[i].Get()->RecordTransfer();
  }
}

void SerializedScriptValue::TransferReadableStreams(
    ScriptState* script_state,
    const ReadableStreamArray& readable_streams,
    ExceptionState& exception_state) {
  auto* execution_context = ExecutionContext::From(script_state);
  for (ReadableStream* readable_stream : readable_streams) {
    TransferReadableStream(script_state, execution_context, readable_stream,
                           exception_state);
    if (exception_state.HadException())
      return;
  }
}

void SerializedScriptValue::TransferReadableStream(
    ScriptState* script_state,
    ExecutionContext* execution_context,
    ReadableStream* readable_stream,
    ExceptionState& exception_state) {
  MessagePort* local_port = AddStreamChannel(execution_context);
  readable_stream->Serialize(script_state, local_port, exception_state);
  if (exception_state.HadException())
    return;
  // The last element is added by the above `AddStreamChannel()` call.
  streams_.back().readable_optimizer =
      readable_stream->TakeTransferringOptimizer();
}

void SerializedScriptValue::TransferWritableStreams(
    ScriptState* script_state,
    const WritableStreamArray& writable_streams,
    ExceptionState& exception_state) {
  auto* execution_context = ExecutionContext::From(script_state);
  for (WritableStream* writable_stream : writable_streams) {
    TransferWritableStream(script_state, execution_context, writable_stream,
                           exception_state);
    if (exception_state.HadException())
      return;
  }
}

void SerializedScriptValue::TransferWritableStream(
    ScriptState* script_state,
    ExecutionContext* execution_context,
    WritableStream* writable_stream,
    ExceptionState& exception_state) {
  MessagePort* local_port = AddStreamChannel(execution_context);
  writable_stream->Serialize(script_state, local_port, exception_state);
  if (exception_state.HadException())
    return;
  // The last element is added by the above `AddStreamChannel()` call.
  streams_.back().writable_optimizer =
      writable_stream->TakeTransferringOptimizer();
}

void SerializedScriptValue::TransferTransformStreams(
    ScriptState* script_state,
    const TransformStreamArray& transform_streams,
    ExceptionState& exception_state) {
  auto* execution_context = ExecutionContext::From(script_state);
  for (TransformStream* transform_stream : transform_streams) {
    TransferReadableStream(script_state, execution_context,
                           transform_stream->Readable(), exception_state);
    if (exception_state.HadException())
      return;
    TransferWritableStream(script_state, execution_context,
                           transform_stream->Writable(), exception_state);
    if (exception_state.HadException())
      return;
  }
}

// Creates an entangled pair of channels. Adds one end to |streams_| as
// a MessagePortChannel, and returns the other end as a MessagePort.
MessagePort* SerializedScriptValue::AddStreamChannel(
    ExecutionContext* execution_context) {
  // Used for both https://streams.spec.whatwg.org/#rs-transfer and
  // https://streams.spec.whatwg.org/#ws-transfer.
  // 2. Let port1 be a new MessagePort in the current Realm.
  // 3. Let port2 be a new MessagePort in the current Realm.
  MessagePortDescriptorPair pipe;
  auto* local_port = MakeGarbageCollected<MessagePort>(*execution_context);

  // 4. Entangle port1 and port2.
  // As these ports are only meant to transfer streams, we don't care about Task
  // Attribution for them, and hence can pass a nullptr as the MessagePort*
  // here.
  local_port->Entangle(pipe.TakePort0(), nullptr);

  // 9. Set dataHolder.[[port]] to ! StructuredSerializeWithTransfer(port2,
  //    « port2 »).
  streams_.push_back(Stream(pipe.TakePort1()));
  return local_port;
}

void SerializedScriptValue::TransferArrayBuffers(
    v8::Isolate* isolate,
    const ArrayBufferArray& array_buffers,
    ExceptionState& exception_state) {
  array_buffer_contents_array_ =
      TransferArrayBufferContents(isolate, array_buffers, exception_state);
}

void SerializedScriptValue::CloneSharedArrayBuffers(
    SharedArrayBufferArray& array_buffers) {
  if (!array_buffers.size())
    return;

  HeapHashSet<Member<DOMArrayBufferBase>> visited;
  shared_array_buffers_contents_.Grow(array_buffers.size());
  wtf_size_t i = 0;
  for (auto it = array_buffers.begin(); it != array_buffers.end(); ++it) {
    DOMSharedArrayBuffer* shared_array_buffer = *it;
    if (visited.Contains(shared_array_buffer))
      continue;
    visited.insert(shared_array_buffer);
    shared_array_buffer->ShareContentsWith(shared_array_buffers_contents_[i]);
    i++;
  }
}

v8::Local<v8::Value> SerializedScriptValue::Deserialize(
    v8::Isolate* isolate,
    const DeserializeOptions& options) {
  return SerializedScriptValueFactory::Instance().Deserialize(this, isolate,
                                                              options);
}

// static
UnpackedSerializedScriptValue* SerializedScriptValue::Unpack(
    scoped_refptr<SerializedScriptValue> value) {
  if (!value)
    return nullptr;
#if DCHECK_IS_ON()
  DCHECK(!value->was_unpacked_);
  value->was_unpacked_ = true;
#endif
  return MakeGarbageCollected<UnpackedSerializedScriptValue>(std::move(value));
}

bool SerializedScriptValue::HasPackedContents() const {
  return !array_buffer_contents_array_.empty() ||
         !shared_array_buffers_contents_.empty() ||
         !image_bitmap_contents_array_.empty();
}

bool SerializedScriptValue::ExtractTransferables(
    v8::Isolate* isolate,
    const HeapVector<ScriptValue>& object_sequence,
    Transferables& transferables,
    ExceptionState& exception_state) {
  auto& factory = SerializedScriptValueFactory::Instance();
  wtf_size_t i = 0;
  for (const auto& script_value : object_sequence) {
    v8::Local<v8::Value> value = script_value.V8Value();
    // Validation of non-null objects, per HTML5 spec 10.3.3.
    if (IsUndefinedOrNull(value)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "Value at index " + String::Number(i) + " is an untransferable " +
              (value->IsUndefined() ? "'undefined'" : "'null'") + " value.");
      return false;
    }
    if (!factory.ExtractTransferable(isolate, value, i, transferables,
                                     exception_state)) {
      if (!exception_state.HadException()) {
        exception_state.ThrowDOMException(
            DOMExceptionCode::kDataCloneError,
            "Value at index " + String::Number(i) +
                " does not have a transferable type.");
      }
      return false;
    }
    i++;
  }
  return true;
}

ArrayBufferArray SerializedScriptValue::ExtractNonSharedArrayBuffers(
    Transferables& transferables) {
  ArrayBufferArray& array_buffers = transferables.array_buffers;
  ArrayBufferArray result;
  // Partition array_buffers into [shared..., non_shared...], maintaining
  // relative ordering of elements with the same predicate value.
  auto non_shared_begin =
      std::stable_partition(array_buffers.begin(), array_buffers.end(),
                            [](Member<DOMArrayBufferBase>& array_buffer) {
                              return array_buffer->IsShared();
                            });
  // Copy the non-shared array buffers into result, and remove them from
  // array_buffers.
  result.AppendRange(non_shared_begin, array_buffers.end());
  array_buffers.EraseAt(
      static_cast<wtf_size_t>(non_shared_begin - array_buffers.begin()),
      static_cast<wtf_size_t>(array_buffers.end() - non_shared_begin));
  return result;
}

SerializedScriptValue::ArrayBufferContentsArray
SerializedScriptValue::TransferArrayBufferContents(
    v8::Isolate* isolate,
    const ArrayBufferArray& array_buffers,
    ExceptionState& exception_state) {
  ArrayBufferContentsArray contents;

  if (!array_buffers.size())
    return ArrayBufferContentsArray();

  for (auto it = array_buffers.begin(); it != array_buffers.end(); ++it) {
    DOMArrayBufferBase* array_buffer = *it;
    if (array_buffer->IsDetached()) {
      wtf_size_t index =
          static_cast<wtf_size_t>(std::distance(array_buffers.begin(), it));
      exception_state.ThrowDOMException(DOMExceptionCode::kDataCloneError,
                                        "ArrayBuffer at index " +
                                            String::Number(index) +
                                            " is already detached.");
      return ArrayBufferContentsArray();
    }
  }

  contents.Grow(array_buffers.size());
  HeapHashSet<Member<DOMArrayBufferBase>> visited;
  // The scope object to promptly free the backing store to avoid memory
  // regressions.
  // TODO(bikineev): Revisit after young generation is there.
  struct PromptlyFreeSet {
    // The void* is to avoid blink-gc-plugin error.
    void* buffer;
    ~PromptlyFreeSet() {
      static_cast<HeapHashSet<Member<DOMArrayBufferBase>>*>(buffer)->clear();
    }
  } promptly_free_array_buffers{&visited};
  for (auto it = array_buffers.begin(); it != array_buffers.end(); ++it) {
    DOMArrayBufferBase* array_buffer_base = *it;
    if (visited.Contains(array_buffer_base))
      continue;
    visited.insert(array_buffer_base);

    wtf_size_t index =
        static_cast<wtf_size_t>(std::distance(array_buffers.begin(), it));
    if (array_buffer_base->IsShared()) {
      exception_state.ThrowDOMException(DOMExceptionCode::kDataCloneError,
                                        "SharedArrayBuffer at index " +
                                            String::Number(index) +
                                            " is not transferable.");
      return ArrayBufferContentsArray();
    } else {
      DOMArrayBuffer* array_buffer =
          static_cast<DOMArrayBuffer*>(array_buffer_base);

      if (!array_buffer->IsDetachable(isolate)) {
        exception_state.ThrowTypeError(
            "ArrayBuffer at index " + String::Number(index) +
            " is not detachable and could not be transferred.");
        return ArrayBufferContentsArray();
      } else if (array_buffer->IsDetached()) {
        exception_state.ThrowDOMException(DOMExceptionCode::kDataCloneError,
                                          "ArrayBuffer at index " +
                                              String::Number(index) +
                                              " could not be transferred.");
        return ArrayBufferContentsArray();
      } else if (!array_buffer->Transfer(isolate, contents.at(index),
                                         exception_state)) {
        return ArrayBufferContentsArray();
      }
    }
  }
  return contents;
}

void SerializedScriptValue::
    UnregisterMemoryAllocatedWithCurrentScriptContext() {
  if (has_registered_external_allocation_) {
    DCHECK_NE(isolate_, nullptr);
    external_memory_accounter_.Decrease(isolate_.get(), DataLengthInBytes());
    has_registered_external_allocation_ = false;
  }
}

void SerializedScriptValue::RegisterMemoryAllocatedWithCurrentScriptContext() {
  if (has_registered_external_allocation_)
    return;
  DCHECK_EQ(isolate_, nullptr);
  DCHECK_NE(v8::Isolate::GetCurrent(), nullptr);
  has_registered_external_allocation_ = true;
  isolate_ = v8::Isolate::GetCurrent();
  int64_t diff = static_cast<int64_t>(DataLengthInBytes());
  DCHECK_GE(diff, 0);
  external_memory_accounter_.Increase(isolate_.get(), diff);
}

bool SerializedScriptValue::IsLockedToAgentCluster() const {
  return !wasm_modules_.empty() || !shared_array_buffers_contents_.empty() ||
         base::ranges::any_of(attachments_,
                              [](const auto& entry) {
                                return entry.value->IsLockedToAgentCluster();
                              }) ||
         shared_value_conveyor_.has_value();
}

bool SerializedScriptValue::IsOriginCheckRequired() const {
  return file_system_access_tokens_.size() > 0 || wasm_modules_.size() > 0;
}

bool SerializedScriptValue::CanDeserializeIn(
    ExecutionContext* execution_context) {
  TrailerReader reader(GetWireData());
  RETURN_IF_ERROR(reader.SkipToTrailer(), [](auto) { return false; });
  RETURN_IF_ERROR(reader.Read(), [](auto) { return false; });
  auto& factory = SerializedScriptValueFactory::Instance();
  bool result = base::ranges::all_of(
      reader.required_exposed_interfaces(), [&](SerializationTag tag) {
        return factory.ExecutionContextExposesInterface(execution_context, tag);
      });
  if (const auto& callback = GetCanDeserializeInCallback())
    result = callback.Run(*this, execution_context, result);
  return result;
}

// static
void SerializedScriptValue::OverrideCanDeserializeInForTesting(
    SerializedScriptValue::CanDeserializeInCallback callback) {
  auto& global = GetCanDeserializeInCallback();
  CHECK_NE(callback.is_null(), global.is_null());
  global = std::move(callback);
}

// This ensures that the version number published in
// WebSerializedScriptValueVersion.h matches the serializer's understanding.
// TODO(jbroman): Fix this to also account for the V8-side version. See
// https://crbug.com/704293.
static_assert(kSerializedScriptValueVersion ==
                  SerializedScriptValue::kWireFormatVersion,
              "Update WebSerializedScriptValueVersion.h.");

}  // namespace blink

"""

```