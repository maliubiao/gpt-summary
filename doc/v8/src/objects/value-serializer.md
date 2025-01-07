Response: My goal is to summarize the functionality of the provided C++ code snippet from `v8/src/objects/value-serializer.cc` and explain its relation to JavaScript, providing a JavaScript example if applicable. Since this is part 1 of 2, I will focus on the serialization aspect.

Here's my thought process:

1. **Identify the Core Purpose:** The filename `value-serializer.cc` and the initial comment about "serialization format" strongly suggest this code is responsible for converting JavaScript values into a binary representation. The comment mentioning "APIs to persist values to disk, e.g. IndexedDB" reinforces this.

2. **Examine Key Classes and Functions:** I look for central classes and their methods. The `ValueSerializer` class is immediately apparent. Its constructor, destructor, and methods like `WriteHeader`, `WriteTag`, `WriteVarint`, `WriteObject`, etc., are clues about its operations. The `Release` method suggests the final output is a byte stream.

3. **Analyze the Serialization Tags:** The `SerializationTag` enum is crucial. It defines the different types of JavaScript values that can be serialized (e.g., `kUndefined`, `kNull`, `kInt32`, `kUtf8String`, `kBeginJSObject`, `kBeginJSArray`, etc.). This helps understand the scope of what can be serialized. The comments within the enum provide valuable context about the serialized format.

4. **Understand Versioning:** The comments about backward compatibility and `kLatestVersion` are important. This highlights that the serialization format is stable and changes are carefully managed.

5. **Trace the `WriteObject` Method:** This method seems to be the central point for serializing different JavaScript value types. It has a `switch` statement based on the `instance_type` of the object. This helps map C++ types in V8 to the corresponding serialization logic.

6. **Consider Data Structures:** The use of `id_map_` (to track already serialized objects and prevent infinite recursion) and `array_buffer_transfer_map_` (for handling transferred `ArrayBuffer`s) indicates the code handles complex object graphs and resource management during serialization.

7. **Infer the Relationship with JavaScript:** The code deals with JavaScript concepts like `undefined`, `null`, booleans, numbers, strings, objects, arrays, dates, regular expressions, Maps, Sets, ArrayBuffers, TypedArrays, Errors, and even WebAssembly-related objects. This clearly establishes a strong connection to JavaScript. The inclusion of `#include "include/v8-value-serializer.h"` also confirms this is part of V8's API.

8. **Formulate the Summary:** Based on the above observations, I can start drafting the summary. I'll focus on:
    * The core function: serializing JavaScript values.
    * The purpose: persistence and data transfer (mention IndexedDB as an example).
    * The mechanism: using tags to represent different types.
    * Key classes: `ValueSerializer`.
    * The role of `WriteObject` and the `SerializationTag` enum.
    * The concept of versioning and backward compatibility.

9. **Develop the JavaScript Example (Conceptual for Part 1):** Since this is part 1, and the code focuses on *serialization*, the JavaScript example should demonstrate how one *would* use a serializer. It won't directly call the C++ code, but it will show the *JavaScript* API or scenario that relies on this underlying serialization mechanism. `structuredClone` is a perfect fit, as it's a standard JavaScript mechanism for deep copying and data transfer, which implicitly uses a serialization process similar to what this C++ code implements.

10. **Refine and Organize:** Review the summary and the JavaScript example for clarity and accuracy. Ensure the language is precise and reflects the technical aspects of the code. Highlight the fact that this is Part 1 and focuses on serialization.

By following these steps, I can systematically analyze the C++ code and generate a comprehensive and accurate summary of its functionality and its relationship to JavaScript. The focus on `ValueSerializer` and the different `Write` methods makes it clear that this part of the code is primarily concerned with the process of serializing JavaScript values.
这是目录为 `v8/src/objects/value-serializer.cc` 的一个 C++ 源代码文件，这个文件主要负责 **将 JavaScript 的值序列化成二进制格式**。

**功能归纳:**

* **核心功能：** 将 JavaScript 的各种数据类型（例如：undefined, null, 布尔值, 数字, 字符串, 对象, 数组, Date, RegExp, Map, Set, ArrayBuffer, TypedArray, Error 等）转换成一种可以存储或传输的二进制表示形式。
* **支持多种 JavaScript 数据类型：**  文件中定义了 `SerializationTag` 枚举，其中包含了各种 JavaScript 数据类型的标签，例如 `kUndefined`, `kNull`, `kInt32`, `kUtf8String`, `kBeginJSObject`, `kBeginJSArray` 等，这表明它可以处理多种不同的 JavaScript 值。
* **版本控制：**  代码中定义了 `kLatestVersion`，并有关于向后兼容性的警告和说明。这意味着序列化格式是有版本的，并且需要保持向后兼容，以便旧版本序列化的数据可以在新版本中正确反序列化。
* **使用 Varint 和 ZigZag 编码：**  为了有效地存储数字，代码使用了 Varint (可变长度整数编码) 和 ZigZag 编码。Varint 用于存储无符号整数，而 ZigZag 用于存储有符号整数。
* **处理对象引用：**  通过 `kObjectReference` 标签，序列化器可以处理循环引用的对象，避免无限递归。它会记录已经序列化的对象，并在后续遇到相同的对象时使用引用代替重新序列化。
* **支持 ArrayBuffer 的转移：** 代码中提到了 `kArrayBufferTransfer`，这表明它支持 `ArrayBuffer` 的转移 (transfer)，这是一种避免数据复制的优化技术。
* **处理宿主对象 (Host Objects)：** 通过 `kHostObject` 标签，该序列化器可以委托给外部代码来处理特定的宿主对象。
* **错误处理：**  `kError` 标签用于序列化 JavaScript 的 `Error` 对象，并包含错误类型、消息和堆栈信息。
* **共享对象 (Shared Objects) 支持：**  从版本 15 开始，支持使用 `kSharedObject` 标签来序列化跨 Isolate 共享的对象。
* **WebAssembly 支持：**  如果启用了 WebAssembly (`V8_ENABLE_WEBASSEMBLY`)，则支持 `WasmModuleTransfer` 和 `WasmMemoryTransfer` 等标签，用于序列化 WebAssembly 模块和内存对象。
* **使用 Delegate 模式：** `ValueSerializer` 接受一个 `Delegate` 对象，允许外部代码自定义某些序列化行为，例如宿主对象的处理、内存分配等。

**与 JavaScript 的关系以及 JavaScript 示例：**

这个 C++ 文件是 V8 引擎内部实现的一部分，直接与 JavaScript 的 `structuredClone()` 方法以及一些涉及到数据持久化或跨上下文传递的 API（例如：IndexedDB, MessageChannel 的 `postMessage()`）的功能息息相关。

`structuredClone()` 是一个 JavaScript 内置函数，它可以深拷贝一个 JavaScript 值。在底层实现中，V8 引擎很可能就使用了类似 `ValueSerializer` 这样的机制来将 JavaScript 值序列化成二进制数据，然后再反序列化以创建副本。

**JavaScript 示例 (使用 `structuredClone()`):**

```javascript
const obj = {
  a: 1,
  b: 'hello',
  c: [true, false],
  d: { nested: null }
};

// 使用 structuredClone 深拷贝对象
const clonedObj = structuredClone(obj);

console.log(clonedObj); // 输出: { a: 1, b: 'hello', c: [ true, false ], d: { nested: null } }
console.log(obj === clonedObj); // 输出: false (表明是不同的对象)
console.log(obj.d === clonedObj.d); // 输出: false (表明嵌套对象也是不同的对象)

// structuredClone 也可以用于传递数据到 Web Worker
const worker = new Worker('worker.js');
worker.postMessage(obj);

// 在 worker.js 中，数据会被反序列化
// self.onmessage = function(event) {
//   console.log('Worker 接收到的数据:', event.data);
// }
```

**解释:**

在上面的 JavaScript 示例中，`structuredClone(obj)` 会创建一个 `obj` 对象的深拷贝。V8 引擎在执行 `structuredClone()` 时，会使用类似 `value-serializer.cc` 中实现的序列化机制将 `obj` 转换为二进制数据，然后在内存中反序列化以创建新的 `clonedObj`。

同样，当使用 `worker.postMessage(obj)` 向 Web Worker 发送数据时，`structuredClone` 算法（或者类似的内部序列化机制）会被用来将 `obj` 序列化，并通过进程边界发送到 Worker 线程，Worker 线程再将其反序列化。

总而言之，`v8/src/objects/value-serializer.cc` 文件中的代码是 V8 引擎实现 JavaScript 值序列化功能的核心部分，它直接支撑着 JavaScript 中 `structuredClone()` 和其他需要序列化操作的 API 的正常工作。

Prompt: 
```
这是目录为v8/src/objects/value-serializer.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/value-serializer.h"

#include <type_traits>

#include "include/v8-maybe.h"
#include "include/v8-value-serializer-version.h"
#include "include/v8-value-serializer.h"
#include "include/v8-wasm.h"
#include "src/api/api-inl.h"
#include "src/base/logging.h"
#include "src/base/platform/memory.h"
#include "src/execution/isolate.h"
#include "src/flags/flags.h"
#include "src/handles/global-handles-inl.h"
#include "src/handles/handles-inl.h"
#include "src/handles/maybe-handles-inl.h"
#include "src/handles/shared-object-conveyor-handles.h"
#include "src/heap/factory.h"
#include "src/numbers/conversions.h"
#include "src/objects/heap-number-inl.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-array-buffer.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-collection-inl.h"
#include "src/objects/js-regexp-inl.h"
#include "src/objects/js-shared-array-inl.h"
#include "src/objects/js-struct-inl.h"
#include "src/objects/map-updater.h"
#include "src/objects/objects-inl.h"
#include "src/objects/objects.h"
#include "src/objects/oddball-inl.h"
#include "src/objects/ordered-hash-table-inl.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/property-details.h"
#include "src/objects/smi.h"
#include "src/objects/transitions-inl.h"
#include "src/regexp/regexp.h"
#include "src/snapshot/code-serializer.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-objects-inl.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

// WARNING: This serialization format MUST remain backward compatible!
//
// This format is used by APIs to persist values to disk, e.g. IndexedDB.
//
// Backward compatibility means that when the format changes, deserializing
// valid values in the older format must behave identically as before the
// change. To maintain compatibility, either a format change does not affect the
// deserializing behavior of valid values in the older format, or the
// kLatestVersion constant is bumped.
//
// Adding a new tag is backwards compatible because no valid serialized value in
// older formats would contain the new object tag.
//
// On the other hand, changing the format of a particular tag is backwards
// incompatible and the version must be bumped. For example, a JSArrayBufferView
// tag prior to version 14 was followed by the sub-tag, the byte offset, and the
// byte length. Starting with version 14, a JSArrayBufferView tag is followed by
// the sub-tag, the byte offset, the byte length, and flags. Due the addition of
// flags, older valid serialized values for JSArrayBufferViews would be
// misinterpreted by newer deserializers. This requires the version to be bumped
// and the deserializer to handle both the old and new formats depending on the
// version.

// Version 9: (imported from Blink)
// Version 10: one-byte (Latin-1) strings
// Version 11: properly separate undefined from the hole in arrays
// Version 12: regexp and string objects share normal string encoding
// Version 13: host objects have an explicit tag (rather than handling all
//             unknown tags)
// Version 14: flags for JSArrayBufferViews
// Version 15: support for shared objects with an explicit tag
//
// WARNING: Increasing this value is a change which cannot safely be rolled
// back without breaking compatibility with data stored on disk. It is
// strongly recommended that you do not make such changes near a release
// milestone branch point.
//
// Recent changes are routinely reverted in preparation for branch, and this
// has been the cause of at least one bug in the past.
static const uint32_t kLatestVersion = 15;
static_assert(kLatestVersion == v8::CurrentValueSerializerFormatVersion(),
              "Exported format version must match latest version.");

namespace {
// For serializing JSArrayBufferView flags. Instead of serializing /
// deserializing the flags directly, we serialize them bit by bit. This is for
// ensuring backwards compatibility in the case where the representation
// changes. Note that the ValueSerializer data can be stored on disk.
using JSArrayBufferViewIsLengthTracking = base::BitField<bool, 0, 1>;
using JSArrayBufferViewIsBackedByRab =
    JSArrayBufferViewIsLengthTracking::Next<bool, 1>;

}  // namespace

template <typename T>
static size_t BytesNeededForVarint(T value) {
  static_assert(std::is_integral<T>::value && std::is_unsigned<T>::value,
                "Only unsigned integer types can be written as varints.");
  size_t result = 0;
  do {
    result++;
    value >>= 7;
  } while (value);
  return result;
}

enum class SerializationTag : uint8_t {
  // version:uint32_t (if at beginning of data, sets version > 0)
  kVersion = 0xFF,
  // ignore
  kPadding = '\0',
  // refTableSize:uint32_t (previously used for sanity checks; safe to ignore)
  kVerifyObjectCount = '?',
  // Oddballs (no data).
  kTheHole = '-',
  kUndefined = '_',
  kNull = '0',
  kTrue = 'T',
  kFalse = 'F',
  // Number represented as 32-bit integer, ZigZag-encoded
  // (like sint32 in protobuf)
  kInt32 = 'I',
  // Number represented as 32-bit unsigned integer, varint-encoded
  // (like uint32 in protobuf)
  kUint32 = 'U',
  // Number represented as a 64-bit double.
  // Host byte order is used (N.B. this makes the format non-portable).
  kDouble = 'N',
  // BigInt. Bitfield:uint32_t, then raw digits storage.
  kBigInt = 'Z',
  // byteLength:uint32_t, then raw data
  kUtf8String = 'S',
  kOneByteString = '"',
  kTwoByteString = 'c',
  // Reference to a serialized object. objectID:uint32_t
  kObjectReference = '^',
  // Beginning of a JS object.
  kBeginJSObject = 'o',
  // End of a JS object. numProperties:uint32_t
  kEndJSObject = '{',
  // Beginning of a sparse JS array. length:uint32_t
  // Elements and properties are written as key/value pairs, like objects.
  kBeginSparseJSArray = 'a',
  // End of a sparse JS array. numProperties:uint32_t length:uint32_t
  kEndSparseJSArray = '@',
  // Beginning of a dense JS array. length:uint32_t
  // |length| elements, followed by properties as key/value pairs
  kBeginDenseJSArray = 'A',
  // End of a dense JS array. numProperties:uint32_t length:uint32_t
  kEndDenseJSArray = '$',
  // Date. millisSinceEpoch:double
  kDate = 'D',
  // Boolean object. No data.
  kTrueObject = 'y',
  kFalseObject = 'x',
  // Number object. value:double
  kNumberObject = 'n',
  // BigInt object. Bitfield:uint32_t, then raw digits storage.
  kBigIntObject = 'z',
  // String object, UTF-8 encoding. byteLength:uint32_t, then raw data.
  kStringObject = 's',
  // Regular expression, UTF-8 encoding. byteLength:uint32_t, raw data,
  // flags:uint32_t.
  kRegExp = 'R',
  // Beginning of a JS map.
  kBeginJSMap = ';',
  // End of a JS map. length:uint32_t.
  kEndJSMap = ':',
  // Beginning of a JS set.
  kBeginJSSet = '\'',
  // End of a JS set. length:uint32_t.
  kEndJSSet = ',',
  // Array buffer. byteLength:uint32_t, then raw data.
  kArrayBuffer = 'B',
  // Resizable ArrayBuffer.
  kResizableArrayBuffer = '~',
  // Array buffer (transferred). transferID:uint32_t
  kArrayBufferTransfer = 't',
  // View into an array buffer.
  // subtag:ArrayBufferViewTag, byteOffset:uint32_t, byteLength:uint32_t
  // For typed arrays, byteOffset and byteLength must be divisible by the size
  // of the element.
  // Note: kArrayBufferView is special, and should have an ArrayBuffer (or an
  // ObjectReference to one) serialized just before it. This is a quirk arising
  // from the previous stack-based implementation.
  kArrayBufferView = 'V',
  // Shared array buffer. transferID:uint32_t
  kSharedArrayBuffer = 'u',
  // A HeapObject shared across Isolates. sharedValueID:uint32_t
  kSharedObject = 'p',
  // A wasm module object transfer. next value is its index.
  kWasmModuleTransfer = 'w',
  // The delegate is responsible for processing all following data.
  // This "escapes" to whatever wire format the delegate chooses.
  kHostObject = '\\',
  // A transferred WebAssembly.Memory object. maximumPages:int32_t, then by
  // SharedArrayBuffer tag and its data.
  kWasmMemoryTransfer = 'm',
  // A list of (subtag: ErrorTag, [subtag dependent data]). See ErrorTag for
  // details.
  kError = 'r',

  // The following tags are reserved because they were in use in Chromium before
  // the kHostObject tag was introduced in format version 13, at
  //   v8           refs/heads/master@{#43466}
  //   chromium/src refs/heads/master@{#453568}
  //
  // They must not be reused without a version check to prevent old values from
  // starting to deserialize incorrectly. For simplicity, it's recommended to
  // avoid them altogether.
  //
  // This is the set of tags that existed in SerializationTag.h at that time and
  // still exist at the time of this writing (i.e., excluding those that were
  // removed on the Chromium side because there should be no real user data
  // containing them).
  //
  // It might be possible to also free up other tags which were never persisted
  // (e.g. because they were used only for transfer) in the future.
  kLegacyReservedMessagePort = 'M',
  kLegacyReservedBlob = 'b',
  kLegacyReservedBlobIndex = 'i',
  kLegacyReservedFile = 'f',
  kLegacyReservedFileIndex = 'e',
  kLegacyReservedDOMFileSystem = 'd',
  kLegacyReservedFileList = 'l',
  kLegacyReservedFileListIndex = 'L',
  kLegacyReservedImageData = '#',
  kLegacyReservedImageBitmap = 'g',
  kLegacyReservedImageBitmapTransfer = 'G',
  kLegacyReservedOffscreenCanvas = 'H',
  kLegacyReservedCryptoKey = 'K',
  kLegacyReservedRTCCertificate = 'k',
};

namespace {

enum class ArrayBufferViewTag : uint8_t {
  kInt8Array = 'b',
  kUint8Array = 'B',
  kUint8ClampedArray = 'C',
  kInt16Array = 'w',
  kUint16Array = 'W',
  kInt32Array = 'd',
  kUint32Array = 'D',
  kFloat16Array = 'h',
  kFloat32Array = 'f',
  kFloat64Array = 'F',
  kBigInt64Array = 'q',
  kBigUint64Array = 'Q',
  kDataView = '?',
};

// Sub-tags only meaningful for error serialization.
enum class ErrorTag : uint8_t {
  // The error is an EvalError. No accompanying data.
  kEvalErrorPrototype = 'E',
  // The error is a RangeError. No accompanying data.
  kRangeErrorPrototype = 'R',
  // The error is a ReferenceError. No accompanying data.
  kReferenceErrorPrototype = 'F',
  // The error is a SyntaxError. No accompanying data.
  kSyntaxErrorPrototype = 'S',
  // The error is a TypeError. No accompanying data.
  kTypeErrorPrototype = 'T',
  // The error is a URIError. No accompanying data.
  kUriErrorPrototype = 'U',
  // Followed by message: string.
  kMessage = 'm',
  // Followed by a JS object: cause.
  kCause = 'c',
  // Followed by stack: string.
  kStack = 's',
  // The end of this error information.
  kEnd = '.',
};

}  // namespace

ValueSerializer::ValueSerializer(Isolate* isolate,
                                 v8::ValueSerializer::Delegate* delegate)
    : isolate_(isolate),
      delegate_(delegate),
      zone_(isolate->allocator(), ZONE_NAME),
      id_map_(isolate->heap(), ZoneAllocationPolicy(&zone_)),
      array_buffer_transfer_map_(isolate->heap(),
                                 ZoneAllocationPolicy(&zone_)) {
  if (delegate_) {
    v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate_);
    has_custom_host_objects_ = delegate_->HasCustomHostObject(v8_isolate);
  }
}

ValueSerializer::~ValueSerializer() {
  if (buffer_) {
    if (delegate_) {
      delegate_->FreeBufferMemory(buffer_);
    } else {
      base::Free(buffer_);
    }
  }
}

void ValueSerializer::WriteHeader() {
  WriteTag(SerializationTag::kVersion);
  WriteVarint(kLatestVersion);
}

void ValueSerializer::SetTreatArrayBufferViewsAsHostObjects(bool mode) {
  treat_array_buffer_views_as_host_objects_ = mode;
}

void ValueSerializer::WriteTag(SerializationTag tag) {
  uint8_t raw_tag = static_cast<uint8_t>(tag);
  WriteRawBytes(&raw_tag, sizeof(raw_tag));
}

template <typename T>
void ValueSerializer::WriteVarint(T value) {
  // Writes an unsigned integer as a base-128 varint.
  // The number is written, 7 bits at a time, from the least significant to the
  // most significant 7 bits. Each byte, except the last, has the MSB set.
  // See also https://developers.google.com/protocol-buffers/docs/encoding
  static_assert(std::is_integral<T>::value && std::is_unsigned<T>::value,
                "Only unsigned integer types can be written as varints.");
  uint8_t stack_buffer[sizeof(T) * 8 / 7 + 1];
  uint8_t* next_byte = &stack_buffer[0];
  do {
    *next_byte = (value & 0x7F) | 0x80;
    next_byte++;
    value >>= 7;
  } while (value);
  *(next_byte - 1) &= 0x7F;
  WriteRawBytes(stack_buffer, next_byte - stack_buffer);
}

template <typename T>
void ValueSerializer::WriteZigZag(T value) {
  // Writes a signed integer as a varint using ZigZag encoding (i.e. 0 is
  // encoded as 0, -1 as 1, 1 as 2, -2 as 3, and so on).
  // See also https://developers.google.com/protocol-buffers/docs/encoding
  // Note that this implementation relies on the right shift being arithmetic.
  static_assert(std::is_integral<T>::value && std::is_signed<T>::value,
                "Only signed integer types can be written as zigzag.");
  using UnsignedT = typename std::make_unsigned<T>::type;
  WriteVarint((static_cast<UnsignedT>(value) << 1) ^
              (value >> (8 * sizeof(T) - 1)));
}

template EXPORT_TEMPLATE_DEFINE(
    V8_EXPORT_PRIVATE) void ValueSerializer::WriteZigZag(int32_t value);

void ValueSerializer::WriteDouble(double value) {
  // Warning: this uses host endianness.
  WriteRawBytes(&value, sizeof(value));
}

void ValueSerializer::WriteOneByteString(base::Vector<const uint8_t> chars) {
  WriteVarint<uint32_t>(chars.length());
  WriteRawBytes(chars.begin(), chars.length() * sizeof(uint8_t));
}

void ValueSerializer::WriteTwoByteString(base::Vector<const base::uc16> chars) {
  // Warning: this uses host endianness.
  WriteVarint<uint32_t>(chars.length() * sizeof(base::uc16));
  WriteRawBytes(chars.begin(), chars.length() * sizeof(base::uc16));
}

void ValueSerializer::WriteBigIntContents(Tagged<BigInt> bigint) {
  uint32_t bitfield = bigint->GetBitfieldForSerialization();
  size_t bytelength = BigInt::DigitsByteLengthForBitfield(bitfield);
  WriteVarint<uint32_t>(bitfield);
  uint8_t* dest;
  if (ReserveRawBytes(bytelength).To(&dest)) {
    bigint->SerializeDigits(dest, bytelength);
  }
}

void ValueSerializer::WriteRawBytes(const void* source, size_t length) {
  uint8_t* dest;
  if (ReserveRawBytes(length).To(&dest) && length > 0) {
    memcpy(dest, source, length);
  }
}

Maybe<uint8_t*> ValueSerializer::ReserveRawBytes(size_t bytes) {
  size_t old_size = buffer_size_;
  size_t new_size = old_size + bytes;
  if (V8_UNLIKELY(new_size > buffer_capacity_)) {
    bool ok;
    if (!ExpandBuffer(new_size).To(&ok)) {
      return Nothing<uint8_t*>();
    }
  }
  buffer_size_ = new_size;
  return Just(&buffer_[old_size]);
}

Maybe<bool> ValueSerializer::ExpandBuffer(size_t required_capacity) {
  DCHECK_GT(required_capacity, buffer_capacity_);
  size_t requested_capacity =
      std::max(required_capacity, buffer_capacity_ * 2) + 64;
  size_t provided_capacity = 0;
  void* new_buffer = nullptr;
  if (delegate_) {
    new_buffer = delegate_->ReallocateBufferMemory(buffer_, requested_capacity,
                                                   &provided_capacity);
  } else {
    new_buffer = base::Realloc(buffer_, requested_capacity);
    provided_capacity = requested_capacity;
  }
  if (new_buffer) {
    DCHECK(provided_capacity >= requested_capacity);
    buffer_ = reinterpret_cast<uint8_t*>(new_buffer);
    buffer_capacity_ = provided_capacity;
    return Just(true);
  } else {
    out_of_memory_ = true;
    return Nothing<bool>();
  }
}

void ValueSerializer::WriteByte(uint8_t value) {
  uint8_t* dest;
  if (ReserveRawBytes(sizeof(uint8_t)).To(&dest)) {
    *dest = value;
  }
}

void ValueSerializer::WriteUint32(uint32_t value) {
  WriteVarint<uint32_t>(value);
}

void ValueSerializer::WriteUint64(uint64_t value) {
  WriteVarint<uint64_t>(value);
}

std::pair<uint8_t*, size_t> ValueSerializer::Release() {
  auto result = std::make_pair(buffer_, buffer_size_);
  buffer_ = nullptr;
  buffer_size_ = 0;
  buffer_capacity_ = 0;
  return result;
}

void ValueSerializer::TransferArrayBuffer(
    uint32_t transfer_id, DirectHandle<JSArrayBuffer> array_buffer) {
  DCHECK(!array_buffer_transfer_map_.Find(array_buffer));
  DCHECK(!array_buffer->is_shared());
  array_buffer_transfer_map_.Insert(array_buffer, transfer_id);
}

Maybe<bool> ValueSerializer::WriteObject(Handle<Object> object) {
  // There is no sense in trying to proceed if we've previously run out of
  // memory. Bail immediately, as this likely implies that some write has
  // previously failed and so the buffer is corrupt.
  if (V8_UNLIKELY(out_of_memory_)) return ThrowIfOutOfMemory();

  if (IsSmi(*object)) {
    WriteSmi(Cast<Smi>(*object));
    return ThrowIfOutOfMemory();
  }

  DCHECK(IsHeapObject(*object));
  InstanceType instance_type =
      Cast<HeapObject>(*object)->map(isolate_)->instance_type();
  switch (instance_type) {
    case ODDBALL_TYPE:
      WriteOddball(Cast<Oddball>(*object));
      return ThrowIfOutOfMemory();
    case HEAP_NUMBER_TYPE:
      WriteHeapNumber(Cast<HeapNumber>(*object));
      return ThrowIfOutOfMemory();
    case BIGINT_TYPE:
      WriteBigInt(Cast<BigInt>(*object));
      return ThrowIfOutOfMemory();
    case JS_TYPED_ARRAY_TYPE:
    case JS_DATA_VIEW_TYPE:
    case JS_RAB_GSAB_DATA_VIEW_TYPE: {
      // Despite being JSReceivers, these have their wrapped buffer serialized
      // first. That makes this logic a little quirky, because it needs to
      // happen before we assign object IDs.
      // TODO(jbroman): It may be possible to avoid materializing a typed
      // array's buffer here.
      Handle<JSArrayBufferView> view = Cast<JSArrayBufferView>(object);
      if (!id_map_.Find(view) && !treat_array_buffer_views_as_host_objects_) {
        Handle<JSArrayBuffer> buffer(
            InstanceTypeChecker::IsJSTypedArray(instance_type)
                ? Cast<JSTypedArray>(view)->GetBuffer()
                : handle(Cast<JSArrayBuffer>(view->buffer()), isolate_));
        if (!WriteJSReceiver(buffer).FromMaybe(false)) return Nothing<bool>();
      }
      return WriteJSReceiver(view);
    }
    default:
      if (InstanceTypeChecker::IsString(instance_type)) {
        WriteString(Cast<String>(object));
        return ThrowIfOutOfMemory();
      } else if (InstanceTypeChecker::IsJSReceiver(instance_type)) {
        return WriteJSReceiver(Cast<JSReceiver>(object));
      } else {
        return ThrowDataCloneError(MessageTemplate::kDataCloneError, object);
      }
  }
}

void ValueSerializer::WriteOddball(Tagged<Oddball> oddball) {
  SerializationTag tag = SerializationTag::kUndefined;
  switch (oddball->kind()) {
    case Oddball::kUndefined:
      tag = SerializationTag::kUndefined;
      break;
    case Oddball::kFalse:
      tag = SerializationTag::kFalse;
      break;
    case Oddball::kTrue:
      tag = SerializationTag::kTrue;
      break;
    case Oddball::kNull:
      tag = SerializationTag::kNull;
      break;
    default:
      UNREACHABLE();
  }
  WriteTag(tag);
}

void ValueSerializer::WriteSmi(Tagged<Smi> smi) {
  static_assert(kSmiValueSize <= 32, "Expected SMI <= 32 bits.");
  WriteTag(SerializationTag::kInt32);
  WriteZigZag<int32_t>(smi.value());
}

void ValueSerializer::WriteHeapNumber(Tagged<HeapNumber> number) {
  WriteTag(SerializationTag::kDouble);
  WriteDouble(number->value());
}

void ValueSerializer::WriteBigInt(Tagged<BigInt> bigint) {
  WriteTag(SerializationTag::kBigInt);
  WriteBigIntContents(bigint);
}

void ValueSerializer::WriteString(Handle<String> string) {
  string = String::Flatten(isolate_, string);
  DisallowGarbageCollection no_gc;
  String::FlatContent flat = string->GetFlatContent(no_gc);
  DCHECK(flat.IsFlat());
  if (flat.IsOneByte()) {
    base::Vector<const uint8_t> chars = flat.ToOneByteVector();
    WriteTag(SerializationTag::kOneByteString);
    WriteOneByteString(chars);
  } else if (flat.IsTwoByte()) {
    base::Vector<const base::uc16> chars = flat.ToUC16Vector();
    uint32_t byte_length = chars.length() * sizeof(base::uc16);
    // The existing reading code expects 16-byte strings to be aligned.
    if ((buffer_size_ + 1 + BytesNeededForVarint(byte_length)) & 1)
      WriteTag(SerializationTag::kPadding);
    WriteTag(SerializationTag::kTwoByteString);
    WriteTwoByteString(chars);
  } else {
    UNREACHABLE();
  }
}

Maybe<bool> ValueSerializer::WriteJSReceiver(Handle<JSReceiver> receiver) {
  // If the object has already been serialized, just write its ID.
  auto find_result = id_map_.FindOrInsert(receiver);
  if (find_result.already_exists) {
    WriteTag(SerializationTag::kObjectReference);
    WriteVarint(*find_result.entry - 1);
    return ThrowIfOutOfMemory();
  }

  // Otherwise, allocate an ID for it.
  uint32_t id = next_id_++;
  *find_result.entry = id + 1;

  // Eliminate callable and exotic objects, which should not be serialized.
  InstanceType instance_type = receiver->map()->instance_type();
  if (IsCallable(*receiver) || (IsSpecialReceiverInstanceType(instance_type) &&
                                instance_type != JS_SPECIAL_API_OBJECT_TYPE)) {
    return ThrowDataCloneError(MessageTemplate::kDataCloneError, receiver);
  }

  // If we are at the end of the stack, abort. This function may recurse.
  STACK_CHECK(isolate_, Nothing<bool>());

  HandleScope scope(isolate_);
  switch (instance_type) {
    case JS_ARRAY_TYPE:
      return WriteJSArray(Cast<JSArray>(receiver));
    case JS_ARRAY_ITERATOR_PROTOTYPE_TYPE:
    case JS_ITERATOR_PROTOTYPE_TYPE:
    case JS_MAP_ITERATOR_PROTOTYPE_TYPE:
    case JS_OBJECT_PROTOTYPE_TYPE:
    case JS_OBJECT_TYPE:
    case JS_PROMISE_PROTOTYPE_TYPE:
    case JS_REG_EXP_PROTOTYPE_TYPE:
    case JS_SET_ITERATOR_PROTOTYPE_TYPE:
    case JS_SET_PROTOTYPE_TYPE:
    case JS_STRING_ITERATOR_PROTOTYPE_TYPE:
    case JS_TYPED_ARRAY_PROTOTYPE_TYPE:
    case JS_API_OBJECT_TYPE: {
      Handle<JSObject> js_object = Cast<JSObject>(receiver);
      Maybe<bool> is_host_object = IsHostObject(js_object);
      if (is_host_object.IsNothing()) {
        return is_host_object;
      }
      if (is_host_object.FromJust()) {
        return WriteHostObject(js_object);
      } else {
        return WriteJSObject(js_object);
      }
    }
    case JS_SPECIAL_API_OBJECT_TYPE:
      return WriteHostObject(Cast<JSObject>(receiver));
    case JS_DATE_TYPE:
      WriteJSDate(Cast<JSDate>(*receiver));
      return ThrowIfOutOfMemory();
    case JS_PRIMITIVE_WRAPPER_TYPE:
      return WriteJSPrimitiveWrapper(Cast<JSPrimitiveWrapper>(receiver));
    case JS_REG_EXP_TYPE:
      WriteJSRegExp(Cast<JSRegExp>(receiver));
      return ThrowIfOutOfMemory();
    case JS_MAP_TYPE:
      return WriteJSMap(Cast<JSMap>(receiver));
    case JS_SET_TYPE:
      return WriteJSSet(Cast<JSSet>(receiver));
    case JS_ARRAY_BUFFER_TYPE:
      return WriteJSArrayBuffer(Cast<JSArrayBuffer>(receiver));
    case JS_TYPED_ARRAY_TYPE:
    case JS_DATA_VIEW_TYPE:
    case JS_RAB_GSAB_DATA_VIEW_TYPE:
      return WriteJSArrayBufferView(Cast<JSArrayBufferView>(*receiver));
    case JS_ERROR_TYPE:
      return WriteJSError(Cast<JSObject>(receiver));
    case JS_SHARED_ARRAY_TYPE:
      return WriteJSSharedArray(Cast<JSSharedArray>(receiver));
    case JS_SHARED_STRUCT_TYPE:
      return WriteJSSharedStruct(Cast<JSSharedStruct>(receiver));
    case JS_ATOMICS_MUTEX_TYPE:
    case JS_ATOMICS_CONDITION_TYPE:
      return WriteSharedObject(receiver);
#if V8_ENABLE_WEBASSEMBLY
    case WASM_MODULE_OBJECT_TYPE:
      return WriteWasmModule(Cast<WasmModuleObject>(receiver));
    case WASM_MEMORY_OBJECT_TYPE:
      return WriteWasmMemory(Cast<WasmMemoryObject>(receiver));
#endif  // V8_ENABLE_WEBASSEMBLY
    default:
      break;
  }

  return ThrowDataCloneError(MessageTemplate::kDataCloneError, receiver);
}

Maybe<bool> ValueSerializer::WriteJSObject(Handle<JSObject> object) {
  DCHECK(!IsCustomElementsReceiverMap(object->map()));
  const bool can_serialize_fast =
      object->HasFastProperties(isolate_) && object->elements()->length() == 0;
  if (!can_serialize_fast) return WriteJSObjectSlow(object);

  DirectHandle<Map> map(object->map(), isolate_);
  WriteTag(SerializationTag::kBeginJSObject);

  // Write out fast properties as long as they are only data properties and the
  // map doesn't change.
  uint32_t properties_written = 0;
  bool map_changed = false;
  for (InternalIndex i : map->IterateOwnDescriptors()) {
    Handle<Name> key(map->instance_descriptors(isolate_)->GetKey(i), isolate_);
    if (!IsString(*key, isolate_)) continue;
    PropertyDetails details =
        map->instance_descriptors(isolate_)->GetDetails(i);
    if (details.IsDontEnum()) continue;

    Handle<Object> value;
    if (V8_LIKELY(!map_changed)) map_changed = *map != object->map();
    if (V8_LIKELY(!map_changed &&
                  details.location() == PropertyLocation::kField)) {
      DCHECK_EQ(PropertyKind::kData, details.kind());
      FieldIndex field_index = FieldIndex::ForDetails(*map, details);
      value = handle(object->RawFastPropertyAt(field_index), isolate_);
    } else {
      // This logic should essentially match WriteJSObjectPropertiesSlow.
      // If the property is no longer found, do not serialize it.
      // This could happen if a getter deleted the property.
      LookupIterator it(isolate_, object, key, LookupIterator::OWN);
      if (!it.IsFound()) continue;
      if (!Object::GetProperty(&it).ToHandle(&value)) return Nothing<bool>();
    }

    if (!WriteObject(key).FromMaybe(false) ||
        !WriteObject(value).FromMaybe(false)) {
      return Nothing<bool>();
    }
    properties_written++;
  }

  WriteTag(SerializationTag::kEndJSObject);
  WriteVarint<uint32_t>(properties_written);
  return ThrowIfOutOfMemory();
}

Maybe<bool> ValueSerializer::WriteJSObjectSlow(Handle<JSObject> object) {
  WriteTag(SerializationTag::kBeginJSObject);
  Handle<FixedArray> keys;
  uint32_t properties_written = 0;
  if (!KeyAccumulator::GetKeys(isolate_, object, KeyCollectionMode::kOwnOnly,
                               ENUMERABLE_STRINGS)
           .ToHandle(&keys) ||
      !WriteJSObjectPropertiesSlow(object, keys).To(&properties_written)) {
    return Nothing<bool>();
  }
  WriteTag(SerializationTag::kEndJSObject);
  WriteVarint<uint32_t>(properties_written);
  return ThrowIfOutOfMemory();
}

Maybe<bool> ValueSerializer::WriteJSArray(Handle<JSArray> array) {
  PtrComprCageBase cage_base(isolate_);
  uint32_t length = 0;
  bool valid_length = Object::ToArrayLength(array->length(), &length);
  DCHECK(valid_length);
  USE(valid_length);

  // To keep things simple, for now we decide between dense and sparse
  // serialization based on elements kind. A more principled heuristic could
  // count the elements, but would need to take care to note which indices
  // existed (as only indices which were enumerable own properties at this point
  // should be serialized).
  const bool should_serialize_densely =
      array->HasFastElements(cage_base) && !array->HasHoleyElements(cage_base);

  if (should_serialize_densely) {
    DCHECK_LE(length, static_cast<uint32_t>(FixedArray::kMaxLength));
    WriteTag(SerializationTag::kBeginDenseJSArray);
    WriteVarint<uint32_t>(length);
    uint32_t i = 0;

    // Fast paths. Note that PACKED_ELEMENTS in particular can bail due to the
    // structure of the elements changing.
    switch (array->GetElementsKind(cage_base)) {
      case PACKED_SMI_ELEMENTS: {
        DisallowGarbageCollection no_gc;
        Tagged<FixedArray> elements = Cast<FixedArray>(array->elements());
        for (i = 0; i < length; i++) {
          WriteSmi(Cast<Smi>(elements->get(i)));
        }
        break;
      }
      case PACKED_DOUBLE_ELEMENTS: {
        // Elements are empty_fixed_array, not a FixedDoubleArray, if the array
        // is empty. No elements to encode in this case anyhow.
        if (length == 0) break;
        DisallowGarbageCollection no_gc;
        Tagged<FixedDoubleArray> elements =
            Cast<FixedDoubleArray>(array->elements());
        for (i = 0; i < length; i++) {
          WriteTag(SerializationTag::kDouble);
          WriteDouble(elements->get_scalar(i));
        }
        break;
      }
      case PACKED_ELEMENTS: {
        DirectHandle<Object> old_length(array->length(cage_base), isolate_);
        for (; i < length; i++) {
          if (array->length(cage_base) != *old_length ||
              array->GetElementsKind(cage_base) != PACKED_ELEMENTS) {
            // Fall back to slow path.
            break;
          }
          Handle<Object> element(Cast<FixedArray>(array->elements())->get(i),
                                 isolate_);
          if (!WriteObject(element).FromMaybe(false)) return Nothing<bool>();
        }
        break;
      }
      default:
        break;
    }

    // If there are elements remaining, serialize them slowly.
    for (; i < length; i++) {
      // Serializing the array's elements can have arbitrary side effects, so we
      // cannot rely on still having fast elements, even if it did to begin
      // with.
      Handle<Object> element;
      LookupIterator it(isolate_, array, i, array, LookupIterator::OWN);
      if (!it.IsFound()) {
        // This can happen in the case where an array that was originally dense
        // became sparse during serialization. It's too late to switch to the
        // sparse format, but we can mark the elements as absent.
        WriteTag(SerializationTag::kTheHole);
        continue;
      }
      if (!Object::GetProperty(&it).ToHandle(&element) ||
          !WriteObject(element).FromMaybe(false)) {
        return Nothing<bool>();
      }
    }

    Handle<FixedArray> keys;
    if (!KeyAccumulator::GetKeys(isolate_, array, KeyCollectionMode::kOwnOnly,
                                 ENUMERABLE_STRINGS,
                                 GetKeysConversion::kKeepNumbers, false, true)
             .ToHandle(&keys)) {
      return Nothing<bool>();
    }

    uint32_t properties_written;
    if (!WriteJSObjectPropertiesSlow(array, keys).To(&properties_written)) {
      return Nothing<bool>();
    }
    WriteTag(SerializationTag::kEndDenseJSArray);
    WriteVarint<uint32_t>(properties_written);
    WriteVarint<uint32_t>(length);
  } else {
    WriteTag(SerializationTag::kBeginSparseJSArray);
    WriteVarint<uint32_t>(length);
    Handle<FixedArray> keys;
    uint32_t properties_written = 0;
    if (!KeyAccumulator::GetKeys(isolate_, array, KeyCollectionMode::kOwnOnly,
                                 ENUMERABLE_STRINGS)
             .ToHandle(&keys) ||
        !WriteJSObjectPropertiesSlow(array, keys).To(&properties_written)) {
      return Nothing<bool>();
    }
    WriteTag(SerializationTag::kEndSparseJSArray);
    WriteVarint<uint32_t>(properties_written);
    WriteVarint<uint32_t>(length);
  }
  return ThrowIfOutOfMemory();
}

void ValueSerializer::WriteJSDate(Tagged<JSDate> date) {
  WriteTag(SerializationTag::kDate);
  WriteDouble(date->value());
}

Maybe<bool> ValueSerializer::WriteJSPrimitiveWrapper(
    DirectHandle<JSPrimitiveWrapper> value) {
  PtrComprCageBase cage_base(isolate_);
  {
    DisallowGarbageCollection no_gc;
    Tagged<Object> inner_value = value->value();
    if (IsTrue(inner_value, isolate_)) {
      WriteTag(SerializationTag::kTrueObject);
    } else if (IsFalse(inner_value, isolate_)) {
      WriteTag(SerializationTag::kFalseObject);
    } else if (IsNumber(inner_value, cage_base)) {
      WriteTag(SerializationTag::kNumberObject);
      WriteDouble(Object::NumberValue(inner_value));
    } else if (IsBigInt(inner_value, cage_base)) {
      WriteTag(SerializationTag::kBigIntObject);
      WriteBigIntContents(Cast<BigInt>(inner_value));
    } else if (IsString(inner_value, cage_base)) {
      WriteTag(SerializationTag::kStringObject);
      WriteString(handle(Cast<String>(inner_value), isolate_));
    } else {
      AllowGarbageCollection allow_gc;
      DCHECK(IsSymbol(inner_value));
      return ThrowDataCloneError(MessageTemplate::kDataCloneError, value);
    }
  }
  return ThrowIfOutOfMemory();
}

void ValueSerializer::WriteJSRegExp(DirectHandle<JSRegExp> regexp) {
  WriteTag(SerializationTag::kRegExp);
  WriteString(handle(regexp->source(), isolate_));
  WriteVarint(static_cast<uint32_t>(regexp->flags()));
}

Maybe<bool> ValueSerializer::WriteJSMap(DirectHandle<JSMap> js_map) {
  // First copy the key-value pairs, since getters could mutate them.
  DirectHandle<OrderedHashMap> table(Cast<OrderedHashMap>(js_map->table()),
                                     isolate_);
  int length = table->NumberOfElements() * 2;
  DirectHandle<FixedArray> entries = isolate_->factory()->NewFixedArray(length);
  {
    DisallowGarbageCollection no_gc;
    Tagged<OrderedHashMap> raw_table = *table;
    Tagged<FixedArray> raw_entries = *entries;
    Tagged<Hole> hash_table_hole =
        ReadOnlyRoots(isolate_).hash_table_hole_value();
    int result_index = 0;
    for (InternalIndex entry : raw_table->IterateEntries()) {
      Tagged<Object> key = raw_table->KeyAt(entry);
      if (key == hash_table_hole) continue;
      raw_entries->set(result_index++, key);
      raw_entries->set(result_index++, raw_table->ValueAt(entry));
    }
    DCHECK_EQ(result_index, length);
  }

  // Then write it out.
  WriteTag(SerializationTag::kBeginJSMap);
  for (int i = 0; i < length; i++) {
    if (!WriteObject(handle(entries->get(i), isolate_)).FromMaybe(false)) {
      return Nothing<bool>();
    }
  }
  WriteTag(SerializationTag::kEndJSMap);
  WriteVarint<uint32_t>(length);
  return ThrowIfOutOfMemory();
}

Maybe<bool> ValueSerializer::WriteJSSet(DirectHandle<JSSet> js_set) {
  // First copy the element pointers, since getters could mutate them.
  DirectHandle<OrderedHashSet> table(Cast<OrderedHashSet>(js_set->table()),
                                     isolate_);
  int length = table->NumberOfElements();
  DirectHandle<FixedArray> entries = isolate_->factory()->NewFixedArray(length);
  {
    DisallowGarbageCollection no_gc;
    Tagged<OrderedHashSet> raw_table = *table;
    Tagged<FixedArray> raw_entries = *entries;
    Tagged<Hole> hash_table_hole =
        ReadOnlyRoots(isolate_).hash_table_hole_value();
    int result_index = 0;
    for (InternalIndex entry : raw_table->IterateEntries()) {
      Tagged<Object> key = raw_table->KeyAt(entry);
      if (key == hash_table_hole) continue;
      raw_entries->set(result_index++, key);
    }
    DCHECK_EQ(result_index, length);
  }

  // Then write it out.
  WriteTag(SerializationTag::kBeginJSSet);
  for (int i = 0; i < length; i++) {
    if (!WriteObject(handle(entries->get(i), isolate_)).FromMaybe(false)) {
      return Nothing<bool>();
    }
  }
  WriteTag(SerializationTag::kEndJSSet);
  WriteVarint<uint32_t>(length);
  return ThrowIfOutOfMemory();
}

Maybe<bool> ValueSerializer::WriteJSArrayBuffer(
    Handle<JSArrayBuffer> array_buffer) {
  if (array_buffer->is_shared()) {
    if (!delegate_) {
      return ThrowDataCloneError(MessageTemplate::kDataCloneError,
                                 array_buffer);
    }

    v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate_);
    Maybe<uint32_t> index = delegate_->GetSharedArrayBufferId(
        v8_isolate, Utils::ToLocalShared(array_buffer));
    RETURN_VALUE_IF_EXCEPTION(isolate_, Nothing<bool>());

    WriteTag(SerializationTag::kSharedArrayBuffer);
    WriteVarint(index.FromJust());
    return ThrowIfOutOfMemory();
  }

  uint32_t* transfer_entry = array_buffer_transfer_map_.Find(array_buffer);
  if (transfer_entry) {
    WriteTag(SerializationTag::kArrayBufferTransfer);
    WriteVarint(*transfer_entry);
    return ThrowIfOutOfMemory();
  }
  if (array_buffer->was_detached()) {
    return ThrowDataCloneError(
        MessageTemplate::kDataCloneErrorDetachedArrayBuffer);
  }
  size_t byte_length = array_buffer->byte_length();
  if (byte_length > std::numeric_limits<uint32_t>::max()) {
    return ThrowDataCloneError(MessageTemplate::kDataCloneError, array_buffer);
  }
  if (array_buffer->is_resizable_by_js()) {
    size_t max_byte_length = array_buffer->max_byte_length();
    if (max_byte_length > std::numeric_limits<uint32_t>::max()) {
      return ThrowDataCloneError(MessageTemplate::kDataCloneError,
                                 array_buffer);
    }

    WriteTag(SerializationTag::kResizableArrayBuffer);
    WriteVarint<uint32_t>(static_cast<uint32_t>(byte_length));
    WriteVarint<uint32_t>(static_cast<uint32_t>(max_byte_length));
    WriteRawBytes(array_buffer->backing_store(), byte_length);
    return ThrowIfOutOfMemory();
  }
  WriteTag(SerializationTag::kArrayBuffer);
  WriteVarint<uint32_t>(static_cast<uint32_t>(byte_length));
  WriteRawBytes(array_buffer->backing_store(), byte_length);
  return ThrowIfOutOfMemory();
}

Maybe<bool> ValueSerializer::WriteJSArrayBufferView(
    Tagged<JSArrayBufferView> view) {
  if (treat_array_buffer_views_as_host_objects_) {
    return WriteHostObject(handle(view, isolate_));
  }
  WriteTag(SerializationTag::kArrayBufferView);
  ArrayBufferViewTag tag = ArrayBufferViewTag::kInt8Array;
  if (IsJSTypedArray(view)) {
    if (Cast<JSTypedArray>(view)->IsOutOfBounds()) {
      return ThrowDataCloneError(MessageTemplate::kDataCloneError,
                                 handle(view, isolate_));
    }
    switch (Cast<JSTypedArray>(view)->type()) {
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) \
  case kExternal##Type##Array:                    \
    tag = ArrayBufferViewTag::k##Type##Array;     \
    break;
      TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
    }
  } else {
    DCHECK(IsJSDataViewOrRabGsabDataView(view));
    if (IsJSRabGsabDataView(view) &&
        Cast<JSRabGsabDataView>(view)->IsOutOfBounds()) {
      return ThrowDataCloneError(MessageTemplate::kDataCloneError,
                                 handle(view, isolate_));
    }

    tag = ArrayBufferViewTag::kDataView;
  }
  WriteVarint(static_cast<uint8_t>(tag));
  WriteVarint(static_cast<uint32_t>(view->byte_offset()));
  WriteVarint(static_cast<uint32_t>(view->byte_length()));
  uint32_t flags =
      JSArrayBufferViewIsLengthTracking::encode(view->is_length_tracking()) |
      JSArrayBufferViewIsBackedByRab::encode(view->is_backed_by_rab());
  WriteVarint(flags);
  return ThrowIfOutOfMemory();
}

Maybe<bool> ValueSerializer::WriteJSError(Handle<JSObject> error) {
  Handle<Object> stack;
  PropertyDescriptor message_desc;
  Maybe<bool> message_found = JSReceiver::GetOwnPropertyDescriptor(
      isolate_, error, isolate_->factory()->message_string(), &message_desc);
  MAYBE_RETURN(message_found, Nothing<bool>());
  PropertyDescriptor cause_desc;
  Maybe<bool> cause_found = JSReceiver::GetOwnPropertyDescriptor(
      isolate_, error, isolate_->factory()->cause_string(), &cause_desc);

  WriteTag(SerializationTag::kError);

  Handle<Object> name_object;
  if (!JSObject::GetProperty(isolate_, error, "name").ToHandle(&name_object)) {
    return Nothing<bool>();
  }
  Handle<String> name;
  if (!Object::ToString(isolate_, name_object).ToHandle(&name)) {
    return Nothing<bool>();
  }

  if (name->IsOneByteEqualTo(base::CStrVector("EvalError"))) {
    WriteVarint(static_cast<uint8_t>(ErrorTag::kEvalErrorPrototype));
  } else if (name->IsOneByteEqualTo(base::CStrVector("RangeError"))) {
    WriteVarint(static_cast<uint8_t>(ErrorTag::kRangeErrorPrototype));
  } else if (name->IsOneByteEqualTo(base::CStrVector("ReferenceError"))) {
    WriteVarint(static_cast<uint8_t>(ErrorTag::kReferenceErrorPrototype));
  } else if (name->IsOneByteEqualTo(base::CStrVector("SyntaxError"))) {
    WriteVarint(static_cast<uint8_t>(ErrorTag::kSyntaxErrorPrototype));
  } else if (name->IsOneByteEqualTo(base::CStrVector("TypeError"))) {
    WriteVarint(static_cast<uint8_t>(ErrorTag::kTypeErrorPrototype));
  } else if (name->IsOneByteEqualTo(base::CStrVector("URIError"))) {
    WriteVarint(static_cast<uint8_t>(ErrorTag::kUriErrorPrototype));
  } else {
    // The default prototype in the deserialization side is Error.prototype, so
    // we don't have to do anything here.
  }

  if (message_found.FromJust() &&
      PropertyDescriptor::IsDataDescriptor(&message_desc)) {
    Handle<String> message;
    if (!Object::ToString(isolate_, message_desc.value()).ToHandle(&message)) {
      return Nothing<bool>();
    }
    WriteVarint(static_cast<uint8_t>(ErrorTag::kMessage));
    WriteString(message);
  }

  if (!Object::GetProperty(isolate_, error, isolate_->factory()->stack_string())
           .ToHandle(&stack)) {
    return Nothing<bool>();
  }
  if (IsString(*stack)) {
    WriteVarint(static_cast<uint8_t>(ErrorTag::kStack));
    WriteString(Cast<String>(stack));
  }

  // The {cause} can self-reference the error. We add at the end, so that we can
  // create the Error first when deserializing.
  if (cause_found.FromJust() &&
      PropertyDescriptor::IsDataDescriptor(&cause_desc)) {
    Handle<Object> cause = cause_desc.value();
    WriteVarint(static_cast<uint8_t>(ErrorTag::kCause));
    if (!WriteObject(cause).FromMaybe(false)) {
      return Nothing<bool>();
    }
  }

  WriteVarint(static_cast<uint8_t>(ErrorTag::kEnd));
  return ThrowIfOutOfMemory();
}

Maybe<bool> ValueSerializer::WriteJSSharedStruct(
    DirectHandle<JSSharedStruct> shared_struct) {
  // TODO(v8:12547): Support copying serialization for shared structs as well.
  return WriteSharedObject(shared_struct);
}

Maybe<bool> ValueSerializer::WriteJSSharedArray(
    DirectHandle<JSSharedArray> shared_array) {
  return WriteSharedObject(shared_array);
}

#if V8_ENABLE_WEBASSEMBLY
Maybe<bool> ValueSerializer::WriteWasmModule(Handle<WasmModuleObject> object) {
  if (delegate_ == nullptr) {
    return ThrowDataCloneError(MessageTemplate::kDataCloneError, object);
  }

  Maybe<uint32_t> transfer_id = delegate_->GetWasmModuleTransferId(
      reinterpret_cast<v8::Isolate*>(isolate_), Utils::ToLocal(object));
  RETURN_VALUE_IF_EXCEPTION(isolate_, Nothing<bool>());
  uint32_t id = 0;
  if (transfer_id.To(&id)) {
    WriteTag(SerializationTag::kWasmModuleTransfer);
    WriteVarint<uint32_t>(id);
    return Just(true);
  }
  return ThrowIfOutOfMemory();
}

Maybe<bool> ValueSerializer::WriteWasmMemory(
    DirectHandle<WasmMemoryObject> object) {
  if (!object->array_buffer()->is_shared()) {
    return ThrowDataCloneError(MessageTemplate::kDataCloneError, object);
  }

  GlobalBackingStoreRegistry::Register(
      object->array_buffer()->GetBackingStore());

  WriteTag(SerializationTag::kWasmMemoryTransfer);
  WriteZigZag<int32_t>(object->maximum_pages());
  WriteByte(object->is_memory64() ? 1 : 0);
  return WriteJSReceiver(Handle<JSReceiver>(object->array_buffer(), isolate_));
}
#endif  // V8_ENABLE_WEBASSEMBLY

Maybe<bool> ValueSerializer::WriteSharedObject(
    DirectHandle<HeapObject> object) {
  if (!delegate_ || !isolate_->has_shared_space()) {
    return ThrowDataCloneError(MessageTemplate::kDataCloneError, object);
  }

  DCHECK(IsShared(*object));

  // The first time a shared object is serialized, a new conveyor is made. This
  // conveyor is used for every shared object in this serialization and
  // subsequent deserialization sessions. The embedder owns the lifetime of the
  // conveyor.
  if (!shared_object_conveyor_) {
    v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate_);
    v8::SharedValueConveyor v8_conveyor(v8_isolate);
    shared_object_conveyor_ = v8_conveyor.private_.get();
    if (!delegate_->AdoptSharedValueConveyor(v8_isolate,
                                             std::move(v8_conveyor))) {
      shared_object_conveyor_ = nullptr;
      RETURN_VALUE_IF_EXCEPTION(isolate_, Nothing<bool>());
      return Nothing<bool>();
    }
  }

  WriteTag(SerializationTag::kSharedObject);
  WriteVarint(shared_object_conveyor_->Persist(*object));

  return ThrowIfOutOfMemory();
}

Maybe<bool> ValueSerializer::WriteHostObject(Handle<JSObject> object) {
  WriteTag(SerializationTag::kHostObject);
  if (!delegate_) {
    isolate_->Throw(*isolate_->factory()->NewError(
        isolate_->error_function(), MessageTemplate::kDataCloneError, object));
    return Nothing<bool>();
  }
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate_);
  Maybe<bool> result =
      delegate_->WriteHostObject(v8_isolate, Utils::ToLocal(object));
  RETURN_VALUE_IF_EXCEPTION(isolate_, Nothing<bool>());
  USE(result);
  DCHECK(!result.IsNothing());
  DCHECK(result.ToChecked());
  return ThrowIfOutOfMemory();
}

Maybe<uint32_t> ValueSerializer::WriteJSObjectPropertiesSlow(
    Handle<JSObject> object, DirectHandle<FixedArray> keys) {
  uint32_t properties_written = 0;
  int length = keys->length();
  for (int i = 0; i < length; i++) {
    Handle<Object> key(keys->get(i), isolate_);

    PropertyKey lookup_key(isolate_, key);
    LookupIterator it(isolate_, object, lookup_key, LookupIterator::OWN);
    Handle<Object> value;
    if (!Object::GetProperty(&it).ToHandle(&value)) return Nothing<uint32_t>();

    // If the property is no longer found, do not serialize it.
    // This could happen if a getter deleted the property.
    if (!it.IsFound()) continue;

    if (!WriteObject(key).FromMaybe(false) ||
        !WriteObject(value).FromMaybe(false)) {
      return Nothing<uint32_t>();
    }

    properties_written++;
  }
  return Just(properties_written);
}

Maybe<bool> ValueSerializer::IsHostObject(Handle<JSObject> js_object) {
  if (!has_custom_host_objects_) {
    return Just<bool>(
        JSObject::GetEmbedderFieldCount(js_object->map(isolate_)));
  }
  DCHECK_NOT_NULL(delegate_);

  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate_);
  Maybe<bool> result =
      delegate_->IsHostObject(v8_isolate, Utils::ToLocal(js_object));
  RETURN_VALUE_IF_EXCEPTION(isolate_, Nothing<bool>());
  DCHECK(!result.IsNothing());

  if (V8_UNLIKELY(out_of_memory_)) return ThrowIfOutOfMemory();
  return result;
}

Maybe<bool> ValueSerializer::ThrowIfOutOfMemory() {
  if (out_of_memory_) {
    return ThrowDataCloneError(MessageTemplate::kDataCloneErrorOutOfMemory);
  }
  return Just(true);
}

Maybe<bool> ValueSerializer::ThrowDataCloneError(
    MessageTemplate template_index) {
  return ThrowDataCloneError(template_index,
                             isolate_->factory()->empty_string());
}

Maybe<bool> ValueSerializer::ThrowDataCloneError(MessageTemplate index,
                                                 DirectHandle<Object> arg0) {
  Handle<String> message =
      MessageFormatter::Format(isolate_, index, base::VectorOf({arg0}));
  if (delegate_) {
    delegate_->ThrowDataCloneError(Utils::ToLocal(message));
  } else {
    isolate_->Throw(
        *isolate_->factory()->NewError(isolate_->error_function(), message));
  }
  return Nothing<bool>();
}

ValueDeserializer::ValueDeserializer(Isolate* isolate,
                                     base::Vector<const uint8_t> data,
                                     v8::ValueDeserializer::Delegate* delegate)
    : isolate_(isolate),
      delegate_(delegate),
      position_(data.begin()),
      end_(data.end()),
      id_map_(isolate->global_handles()->Create(
          ReadOnlyRoots(isolate_).empty_fixed_array())) {}

ValueDeserializer::ValueDeserializer(Isolate* isolate, const uint8_t* data,
                                     size_t size)
    : isolate_(isolate),
      delegate_(nullptr),
      position_(data),
      end_(data + size),
      id_map_(isolate->global_handles()->Create(
          ReadOnlyRoots(isolate_).empty_fixed_array())) {}

ValueDeserializer::~ValueDeserializer() {
  DCHECK_LE(position_, end_);
  GlobalHandles::Destroy(id_map_.location());

  Handle<Object> transfer_map_handle;
  if (array_buffer_transfer_map_.ToHandle(&transfer_map_handle)) {
    GlobalHandles::Destroy(transfer_map_handle.location());
  }
}

Maybe<bool> ValueDeserializer::ReadHeader() {
  if (position_ < end_ &&
      *position_ == static_cast<uint8_t>(SerializationTag::kVersion)) {
    ReadTag().ToChecked();
    if (!ReadVarintLoop<uint32_t>().To(&version_) ||
        version_ > kLatestVersion) {
      isolate_->Throw(*isolate_->factory()->NewError(
          MessageTemplate::kDataCloneDeserializationVersionError));
      return Nothing<bool>();
    }
  }
  return Just(true);
}

Maybe<SerializationTag> ValueDeserializer::PeekTag() const {
  const uint8_t* peek_position = position_;
  SerializationTag tag;
  do {
    if (peek_position >= end_) return Nothing<SerializationTag>();
    tag = static_cast<SerializationTag>(*peek_position);
    peek_position++;
  } while (tag == SerializationTag::kPadding);
  return Just(tag);
}

void ValueDeserializer::ConsumeTag(SerializationTag peeked_tag) {
  SerializationTag actual_tag = ReadTag().ToChecked();
  DCHECK(actual_tag == peeked_tag);
  USE(actual_tag);
}

Maybe<SerializationTag> ValueDeserializer::ReadTag() {
  SerializationTag tag;
  do {
    if (position_ >= end_) return Nothing<SerializationTag>();
    tag = static_cast<SerializationTag>(*position_);
    position_++;
  } while (tag == SerializationTag::kPadding);
  return Just(tag);
}

template <typename T>
Maybe<T> ValueDeserializer::ReadVarint() {
  // Reads an unsigned integer as a base-128 varint.
  // The number is written, 7 bits at a time, from the least significant to the
  // most significant 7 bits. Each byte, except the last, has the MSB set.
  // If the varint is larger than T, any more significant bits are discarded.
  // See also https://developers.google.com/protocol-buffers/docs/encoding
  static_assert(std::is_integral<T>::value && std::is_unsigned<T>::value,
                "Only unsigned integer types can be read as varints.");
  if (sizeof(T) > 4) return ReadVarintLoop<T>();
  auto max_read_position = position_ + sizeof(T) + 1;
  if (V8_UNLIKELY(max_read_position >= end_)) return ReadVarintLoop<T>();
#ifdef DEBUG
  // DCHECK code to make sure the manually unrolled loop yields the exact
  // same end state and result.
  auto previous_position = position_;
  Maybe<T> maybe_expected_value = ReadVarintLoop<T>();
  // ReadVarintLoop can't return Nothing here; all such conditions have been
  // checked above.
  T expected_value = maybe_expected_value.ToChecked();
  auto expected_position = position_;
  position_ = previous_position;
#endif  // DEBUG
#define EXIT_DCHECK()                      \
  DCHECK_LE(position_, end_);              \
  DCHECK_EQ(position_, expected_position); \
  DCHECK_EQ(value, expected_value)

  T value = 0;
#define ITERATION_SHIFTED(shift)                     \
  if (shift < sizeof(T) * 8) {                       \
    uint8_t byte = *position_;                       \
    position_++;                                     \
    if (byte < 0x80) {                               \
      value |= static_cast<T>(byte) << shift;        \
      EXIT_DCHECK();                                 \
      return Just(value);                            \
    } else {                                         \
      value |= static_cast<T>(byte & 0x7F) << shift; \
    }                                                \
  }
  // Manually unroll the loop to achieve the best measured peformance.
  // This is ~15% faster than ReadVarintLoop.
  ITERATION_SHIFTED(0);
  ITERATION_SHIFTED(7);
  ITERATION_SHIFTED(14);
  ITERATION_SHIFTED(21);
  ITERATION_SHIFTED(28);

  EXIT_DCHECK();
  return Just(value);
#undef ITERATION_SHIFTED
#undef EXIT_DCHECK
}

template <typename T>
Maybe<T> ValueDeserializer::ReadVarintLoop() {
  static_assert(std::is_integral<T>::value && std::is_unsigned<T>::value,
                "Only unsigned integer types can be read as varints.");
  T value = 0;
  unsigned shift = 0;
  bool has_another_byte;
  do {
    if (position_ >= end_) return Nothing<T>();
    uint8_t byte = *position_;
    has_another_byte = byte & 0x80;
    if (V8_LIKELY(shift < sizeof(T) * 8)) {
      value |= static_cast<T>(byte & 0x7F) << shift;
      shift += 7;
    } else {
      // For consistency with the fast unrolled loop in ReadVarint we return
      // after we have read size(T) + 1 bytes.
#ifdef V8_VALUE_DESERIALIZER_HARD_FAIL
      CHECK(!has_another_byte);
#endif  // V8_VALUE_DESERIALIZER_HARD_FAIL
      return Just(value);
    }
    position_++;
  } while (has_another_byte);
  return Just(value);
}

template <typename T>
Maybe<T> ValueDeserializer::ReadZigZag() {
  // Writes a signed integer as a varint using ZigZag encoding (i.e. 0 is
  // encoded as 0, -1 as 1, 1 as 2, -2 as 3, and so on).
  // See also https://developers.google.com/protocol-buffers/docs/encoding
  static_assert(std::is_integral<T>::value && std::is_signed<T>::value,
                "Only signed integer types can be read as zigzag.");
  using UnsignedT = typename std::make_unsigned<T>::type;
  UnsignedT unsigned_value;
  if (!ReadVarint<UnsignedT>().To(&unsigned_value)) return Nothing<T>();
  return Just(static_cast<T>((unsigned_value >> 1) ^
                             -static_cast<T>(unsigned_value & 1)));
}

template EXPORT_TEMPLATE_DEFINE(
    V8_EXPORT_PRIVATE) Maybe<int32_t> ValueDeserializer::ReadZigZag();

Maybe<double> ValueDeserializer::ReadDouble() {
  // Warning: this uses host endianness.
  if (sizeof(double) > static_cast<unsigned>(end_ - position_)) {
    return Nothing<double>();
  }
  double value;
  memcpy(&value, position_, sizeof(double));
  position_ += sizeof(double);
  if (std::isnan(value)) value = std::numeric_limits<double>::quiet_NaN();
  return Just(value);
}

Maybe<base::Vector<const uint8_t>> ValueDeserializer::ReadRawBytes(
    size_t size) {
  if (size > static_cast<size_t>(end_ - position_)) {
    return Nothing<base::Vector<const uint8_t>>();
  }
  const uint8_t* start = position_;
  position_ += size;
  return Just(base::Vector<const uint8_t>(start, size));
}

Maybe<base::Vector<const base::uc16>> ValueDeserializer::ReadRawTwoBytes(
    size_t size) {
  if (size > static_cast<size_t>(end_ - position_) ||
      size % sizeof(base::uc16) != 0) {
    return Nothing<base::Vector<const base::uc16>>();
  }
  const base::uc16* start = (const base::uc16*)(position_);
  position_ += size;
  return Just(base::Vector<const base::uc16>(start, size / sizeof(base::uc16)));
}

bool ValueDeserializer::ReadByte(uint8_t* value) {
  if (static_cast<size_t>(end_ - position_) < sizeof(uint8_t)) return false;
  *value = *position_;
  position_++;
  return true;
}

bool ValueDeserializer::ReadUint32(uint32_t* value) {
  return ReadVarint<uint32_t>().To(value);
}

bool ValueDeserializer::ReadUint64(uint64_t* value) {
  return ReadVarint<uint64_t>().To(value);
}

bool ValueDeserializer::ReadDouble(double* value) {
  return ReadDouble().To(value);
}

bool ValueDeserializer::ReadRawBytes(size_t length, const void** data) {
  if (length > static_cast<size_t>(end_ - position_)) return false;
  *data = position_;
  position_ += length;
  return true;
}

void ValueDeserializer::TransferArrayBuffer(
    uint32_t transfer_id, Handle<JSArrayBuffer> array_buffer) {
  if (array_buffer_transfer_map_.is_null()) {
    array_buffer_transfer_map_ = isolate_->global_handles()->Create(
        *SimpleNumberDictionary::New(isolate_, 0));
  }
  Handle<SimpleNumberDictionary> dictionary =
      array_buffer_transfer_map_.ToHandleChecked();
  Handle<SimpleNumberDictionary> new_dictionary = SimpleNumberDictionary::Set(
      isolate_, dictionary, transfer_id, array_buffer);
  if (!new_dictionary.is_identical_to(dictionary)) {
    GlobalHandles::Destroy(dictionary.location());
    array_buffer_transfer_map_ =
        isolate_->global_handles()->Create(*new_dictionary);
  }
}

MaybeHandle<Object> ValueDeserializer::ReadObjectWrapper() {
  // We had a bug which produced invalid version 13 data (see
  // crbug.com/1284506). This compatibility mode tries to first read the data
  // normally, and if it fails, and the version is 13, tries to read the broken
  // format.
  const uint8_t* original_position = position_;
  suppress_deserialization_errors_ = true;
  MaybeHandle<Object> result = ReadObject();

  // The deserialization code doesn't throw errors for invalid data. It throws
  // errors for stack overflows, though, and in that case we won't retry.
  if (result.is_null() && version_ == 13 && !isolate_->has_exception()) {
    version_13_broken_data_mode_ = true;
    position_ = original_position;
    result = ReadObject();
  }

  if (result.is_null() && !isolate_->has_exception()) {
    isolate_->Throw(*isolate_->factory()->NewError(
        MessageTemplate::kDataCloneDeserializationError));
  }

  return result;
}

MaybeHandle<Object> ValueDeserializer::ReadObject() {
  DisallowJavascriptExecution no_js(isolate_);
  // If we are at the end of the stack, abort. This function may recurse.
  STACK_CHECK(isolate_, MaybeHandle<Object>());

  MaybeHandle<Object> result = ReadObjectInternal();

  // ArrayBufferView is special in that it consumes the value before it, even
  // after format version 0.
  Handle<Object> object;
  SerializationTag tag;
  if (result.ToHandle(&object) && V8_UNLIKELY(IsJSArrayBuffer(*object)) &&
      PeekTag().To(&tag) && tag == SerializationTag::kArrayBufferView) {
    ConsumeTag(SerializationTag::kArrayBufferView);
    result = ReadJSArrayBufferView(Cast<JSArrayBuffer>(object));
  }

  if (result.is_null() && !suppress_deserialization_errors_ &&
      !isolate_->has_exception()) {
    isolate_->Throw(*isolate_->factory()->NewError(
        MessageTemplate::kDataCloneDeserializationError));
  }
#if defined(DEBUG) && defined(VERIFY_HEAP)
  if (!result.is_null() && v8_flags.enable_slow_asserts &&
      v8_flags.verify_heap) {
    Object::ObjectVerify(*object, isolate_);
  }
#endif

  return result;
}

MaybeHandle<Object> ValueDeserializer::ReadObjectInternal() {
  SerializationTag tag;
  if (!ReadTag().To(&tag)) return MaybeHandle<Object>();
  switch (tag) {
    case SerializationTag::kVerifyObjectCount:
      // Read the count and ignore it.
      if (ReadVarint<uint32_t>().IsNothing()) return MaybeHandle<Object>();
      return ReadObject();
    case SerializationTag::kUndefined:
      return isolate_->factory()->undefined_value();
    case SerializationTag::kNull:
      return isolate_->factory()->null_value();
    case SerializationTag::kTrue:
      return isolate_->factory()->true_value();
    case SerializationTag::kFalse:
      return isolate_->factory()->false_value();
    case SerializationTag::kInt32: {
      Maybe<int32_t> number = ReadZigZag<int32_t>();
      if (number.IsNothing()) return MaybeHandle<Object>();
      return isolate_->factory()->NewNumberFromInt(number.FromJust());
    }
    case SerializationTag::kUint32: {
      Maybe<uint32_t> number = ReadVarint<uint32_t>();
      if (number.IsNothing()) return MaybeHandle<Object>();
      return isolate_->factory()->NewNumberFromUint(number.FromJust());
    }
    case SerializationTag::kDouble: {
      Maybe<double> number = ReadDouble();
      if (number.IsNothing()) return MaybeHandle<Object>();
      return isolate_->factory()->NewNumber(number.FromJust());
    }
    case SerializationTag::kBigInt:
      return ReadBigInt();
    case SerializationTag::kUtf8String:
      return ReadUtf8String();
    case SerializationTag::kOneByteString:
      return ReadOneByteString();
    case SerializationTag::kTwoByteString:
      return ReadTwoByteString();
    case SerializationTag::kObjectReference: {
      uint32_t id;
      if (!ReadVarint<uint32_t>().To(&id)) return MaybeHandle<Object>();
      return GetObjectWithID(id);
    }
    case SerializationTag::kBeginJSObject:
      return ReadJSObject();
    case SerializationTag::kBeginSparseJSArray:
      return ReadSparseJSArray();
    case SerializationTag::kBeginDenseJSArray:
      return ReadDenseJSArray();
    case SerializationTag::kDate:
      return ReadJSDate();
    case SerializationTag::kTrueObject:
    case SerializationTag::kFalseObject:
    case SerializationTag::kNumberObject:
    case SerializationTag::kBigIntObject:
    case SerializationTag::kStringObject:
      return ReadJSPrimitiveWrapper(tag);
    case SerializationTag::kRegExp:
      return ReadJSRegExp();
    case SerializationTag::kBeginJSMap:
      return ReadJSMap();
    case SerializationTag::kBeginJSSet:
      return ReadJSSet();
    case SerializationTag::kArrayBuffer: {
      constexpr bool is_shared = false;
      constexpr bool is_resizable = false;
      return ReadJSArrayBuffer(is_shared, is_resizable);
    }
    case SerializationTag::kResizableArrayBuffer: {
      constexpr bool is_shared = false;
      constexpr bool is_resizable = true;
      return ReadJSArrayBuffer(is_shared, is_resizable);
    }
    case SerializationTag::kArrayBufferTransfer: {
      return ReadTransferredJSArrayBuffer();
    }
    case SerializationTag::kSharedArrayBuffer: {
      constexpr bool is_shared = true;
      constexpr bool is_resizable = false;
      return ReadJSArrayBuffer(is_shared, is_resizable);
    }
    case SerializationTag::kError:
      return ReadJSError();
#if V8_ENABLE_WEBASSEMBLY
    case SerializationTag::kWasmModuleTransfer:
      return ReadWasmModuleTransfer();
    case SerializationTag::kWasmMemoryTransfer:
      return ReadWasmMemory();
#endif  // V8_ENABLE_WEBASSEMBLY
    case SerializationTag::kHostObject:
      return ReadHostObject();
    case SerializationTag::kSharedObject:
      if (version_ >= 15) return ReadSharedObject();
      // If the data doesn't support shared values because it is from an older
      // version, treat the tag as unknown.
      [[fallthrough]];
    default:
      // Before there was an explicit tag for host objects, all unknown tags
      // were delegated to the host.
      if (version_ < 13) {
        position_--;
        return ReadHostObject();
      }
      return MaybeHandle<Object>();
  }
}

MaybeHandle<String> ValueDeserializer::ReadString() {
  if (version_ < 12) return ReadUtf8String();
  Handle<Object> object;
  if (!ReadObject().ToHandle(&object) || !IsString(*object, isolate_)) {
    return MaybeHandle<String>();
  }
  return Cast<String>(object);
}

MaybeHandle<BigInt> ValueDeserializer::ReadBigInt() {
  uint32_t bitfield;
  if (!ReadVarint<uint32_t>().To(&bitfield)) return MaybeHandle<BigInt>();
  size_t bytelength = BigInt::DigitsByteLengthForBitfield(bitfield);
  base::Vector<const uint8_t> digits_storage;
  if (!ReadRawBytes(bytelength).To(&digits_storage)) {
    return MaybeHandle<BigInt>();
  }
  return BigInt::FromSerializedDigits(isolate_, bitfield, digits_storage);
}

MaybeHandle<String> ValueDeserializer::ReadUtf8String(
    AllocationType allocation) {
  uint32_t utf8_length;
  if (!ReadVarint<uint32_t>().To(&utf8_length)) return {};
  // utf8_length is checked in ReadRawBytes.
  base::Vector<const uint8_t> utf8_bytes;
  if (!ReadRawBytes(utf8_length).To(&utf8_bytes)) return {};
  return isolate_->factory()->NewStringFromUtf8(
      base::Vector<const char>::cast(utf8_bytes), allocation);
}

MaybeHandle<String> ValueDeserializer::ReadOneByteString(
    AllocationType allocation) {
  uint32_t byte_length;
  base::Vector<const uint8_t> bytes;
  if (!ReadVarint<uint32_t>().To(&byte_length)) return {};
  // byte_length is checked in ReadRawBytes.
  if (!ReadRawBytes(byte_length).To(&bytes)) return {};
  return isolate_->factory()->NewStringFromOneByte(bytes, allocation);
}

MaybeHandle<String> ValueDeserializer::ReadTwoByteString(
    AllocationType allocation) {
  uint32_t byte_length;
  base::Vector<const uint8_t> bytes;
  if (!ReadVarint<uint32_t>().To(&byte_length)) return {};
  // byte_length is checked in ReadRawBytes.
  if (byte_length % sizeof(base::uc16) != 0 ||
      !ReadRawBytes(byte_length).To(&bytes)) {
    return MaybeHandle<String>();
  }

  // Allocate an uninitialized string so that we can do a raw memcpy into the
  // string on the heap (regardless of alignment).
  if (byte_length == 0) return isolate_->factory()->empty_string();
  Handle<SeqTwoByteString> string;
  if (!isolate_->factory()
           ->NewRawTwoByteString(byte_length / sizeof(base::uc16), allocation)
           .ToHandle(&string)) {
    return MaybeHandle<String>();
  }

  // Copy the bytes directly into the new string.
  // Warning: this uses host endianness.
  DisallowGarbageCollection no_gc;
  memcpy(string->GetChars(no_gc), bytes.begin(), bytes.length());
  return string;
}

MaybeHandle<JSObject> ValueDeserializer::ReadJSObject() {
  // If we are at the end of the stack, abort. This function may recurse.
  STACK_CHECK(isolate_, MaybeHandle<JSObject>());

  uint32_t id = next_id_++;
  HandleScope scope(isolate_);
  Handle<JSObject> object =
      isolate_->factory()->NewJSObject(isolate_->object_function());
  AddObjectWithID(id, object);

  uint32_t num_properties;
  uint32_t expected_num_properties;
  if (!ReadJSObjectProperties(object, SerializationTag::kEndJSObject, true)
           .To(&num_properties) ||
      !ReadVarint<uint32_t>().To(&expected_num_properties) ||
      num_properties != expected_num_properties) {
    return MaybeHandle<JSObject>();
  }

  DCHECK(HasObjectWithID(id));
  return scope.CloseAndEscape(object);
}

MaybeHandle<JSArray> ValueDeserializer::ReadSparseJSArray() {
  // If we are at the end of the stack, abort. This function may r
"""


```