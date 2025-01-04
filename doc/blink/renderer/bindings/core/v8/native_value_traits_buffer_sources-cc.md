Response:
My thought process for analyzing the code and generating the response involved several steps:

1. **Understand the Core Purpose:** I first read the initial comments and the filename. "native_value_traits_buffer_sources.cc" strongly suggests that this code deals with converting JavaScript buffer-like objects (ArrayBuffer, ArrayBufferView, SharedArrayBuffer) into their C++ counterparts within the Blink rendering engine. The "native value traits" part hints at a system for defining how this conversion happens for different types.

2. **Identify Key Data Structures and Concepts:**  I scanned the code for recurring patterns and important terms. I noticed:
    * `DOMArrayBuffer`, `DOMSharedArrayBuffer`, `DOMArrayBufferView` (and specific view types like `DOMInt8Array`, `DOMDataView`): These are the C++ representations of JavaScript buffer types.
    * `v8::Local<v8::Value>`, `v8::ArrayBuffer`, `v8::SharedArrayBuffer`, `v8::ArrayBufferView`, etc.: These are V8 (the JavaScript engine) types representing the JavaScript objects.
    * `NativeValueTraits`: This is the central mechanism for conversion. It's a template that's specialized for different buffer types.
    * `ExceptionState`:  Used for reporting errors during the conversion process.
    * Template metaprogramming (using `template`, `typename`, `std::is_base_of_v`, `std::enable_if_t`):  This is used extensively to create generic conversion logic that can be adapted for different buffer types.
    * `RecipeTrait`: This struct appears to encapsulate common properties and operations for different buffer types (like getting the byte length or checking resizability).
    * `ToDOMArrayBuffer`, `ToDOMSharedArrayBuffer`, `ToDOMViewType`: These are functions responsible for the actual conversion from V8 values to Blink DOM objects.
    * `Nullablity`, `BufferSizeCheck`, `ResizableAllowance`: These enums represent configuration options for the conversion process.

3. **Trace the Conversion Flow:**  I examined the `NativeValueImpl` and `ArgumentValueImpl` functions. These seem to be the core logic for the `NativeValueTraits`. I noted the following steps:
    * Get the `blink_value` by calling a `ToBlinkValue` function (e.g., `ToDOMArrayBuffer`).
    * Check if the `blink_value` is valid (`RecipeTrait::IsNonNull`).
    * Check for resizability if `allow_resizable` is `kDisallowResizable`.
    * Check the buffer size if `buffer_size_check` is `kCheck`.
    * If all checks pass, return the converted `blink_value`.
    * Handle null/undefined values if `nullablity` is `kIsNullable`.
    * Check for `SharedArrayBuffer` if necessary.
    * If none of the above conditions are met, throw a `TypeError`.

4. **Identify Relationships with JavaScript, HTML, and CSS:** I considered how these buffer types are used in web development.
    * **JavaScript:**  Directly used for creating and manipulating binary data. Examples include `new ArrayBuffer(10)`, `new Uint8Array(buffer)`.
    * **HTML:** Used in APIs like `<canvas>` (for manipulating pixel data), `<audio>` and `<video>` (for media data), and for file uploads/downloads.
    * **CSS:**  Less directly related, but could potentially be used in advanced scenarios involving custom rendering or data visualization.

5. **Infer Potential User Errors:** I thought about common mistakes developers make when working with buffers:
    * Exceeding size limits.
    * Passing a `SharedArrayBuffer` when a regular `ArrayBuffer` is expected (or vice-versa).
    * Passing the wrong type of object altogether.
    * Trying to use a resizable buffer in a context that doesn't support it.

6. **Consider Debugging Scenarios:** I imagined how a developer might end up needing to look at this code. A likely scenario is an error being thrown during a JavaScript operation involving a buffer. The stack trace might lead them into the Blink rendering engine's code.

7. **Structure the Response:** I organized my findings into logical sections, addressing each part of the prompt:
    * **Functionality:**  A concise summary of the code's purpose.
    * **Relationship with Web Technologies:**  Specific examples of how the buffer types relate to JavaScript, HTML, and CSS.
    * **Logical Deduction:** Illustrative examples with hypothetical inputs and outputs.
    * **Common User Errors:** Concrete examples of mistakes developers might make.
    * **Debugging Clues:**  A step-by-step scenario of how a user might reach this code.
    * **Summary:** A brief recap of the file's role.

8. **Refine and Elaborate:** I reviewed my initial thoughts, adding more detail and clarity where needed. For example, I elaborated on the role of the template metaprogramming and the different `ToBlinkValue` functions. I also made sure the examples were clear and relevant.

By following these steps, I was able to break down the complex C++ code into understandable concepts and relate it to the broader context of web development, enabling me to generate a comprehensive and informative response.
好的，让我们来分析一下 `blink/renderer/bindings/core/v8/native_value_traits_buffer_sources.cc` 这个文件的功能。

**文件功能归纳：**

这个文件的核心功能是定义了 **NativeValueTraits** 模板类的特化版本，用于将 JavaScript 中的 **BufferSource** 类型（例如 `ArrayBuffer`, `SharedArrayBuffer`, 以及各种类型的 `ArrayBufferView`，如 `Uint8Array`, `Float32Array` 等）转换为 Blink 渲染引擎内部使用的 C++ 对象。

**更详细的功能点：**

1. **类型转换的核心逻辑：**
   - 文件中定义了 `NativeValueTraits<T>::NativeValue` 和 `NativeValueTraits<T>::ArgumentValue` 函数的实现，这些函数负责接收 V8 (Chrome 的 JavaScript 引擎) 的 `v8::Value` 对象，并将其转换为 Blink 内部的相应 C++ 对象，例如 `DOMArrayBuffer` 或 `DOMUint8Array`。
   - 它利用模板元编程技术，为不同的 BufferSource 类型提供了统一的转换接口。

2. **处理不同类型的 BufferSource：**
   - 文件为 `ArrayBuffer`、`SharedArrayBuffer` 以及各种 `ArrayBufferView` (Int8Array, Uint8Array, Float32Array, DataView 等) 提供了专门的转换逻辑。
   - 区分了可调整大小的 (Resizable) 和不可调整大小的 ArrayBuffer。
   - 区分了普通的 ArrayBuffer 和 SharedArrayBuffer。

3. **错误处理和异常抛出：**
   - 在类型转换过程中，如果 JavaScript 值不是预期的 BufferSource 类型，或者超出大小限制，或者尝试将 SharedArrayBuffer 用于不允许的场景，代码会抛出 `TypeError` 或 `RangeError` 类型的 JavaScript 异常。
   - 使用 `ExceptionState` 对象来管理异常状态。

4. **大小限制检查：**
   - 文件中包含了对 `ArrayBuffer` 和 `ArrayBufferView` 大小的检查，以防止创建过大的缓冲区，超出 Web API 的支持范围。
   - 可以通过 feature flag `features::kDisableArrayBufferSizeLimitsForTesting` 禁用此限制（仅用于测试）。

5. **SharedArrayBuffer 的处理：**
   - 代码显式地处理了 `SharedArrayBuffer`，并在某些情况下禁止使用 `SharedArrayBuffer`，例如当接口期望一个普通的 `ArrayBuffer` 时。

6. **可调整大小的 ArrayBuffer 的处理：**
   - 代码区分了可调整大小的 `ArrayBuffer`，并允许或禁止在特定的 API 中使用它们。

7. **与 V8 的交互：**
   - 代码直接与 V8 的 API 交互，例如使用 `value->IsArrayBuffer()`, `value.As<v8::ArrayBuffer>()` 等方法来检查和获取 JavaScript 值的类型和内容。

8. **内部数据结构的创建：**
   - 文件中定义了辅助函数，例如 `ToDOMArrayBuffer`, `ToDOMSharedArrayBuffer`, `ToDOMViewType`，用于从 V8 的对象创建 Blink 内部的 `DOMArrayBuffer` 和 `DOMArrayBufferView` 对象。

**与 JavaScript, HTML, CSS 的关系：**

这个文件直接关系到 JavaScript 中对二进制数据的处理。

**JavaScript:**

- **ArrayBuffer 和 TypedArrays：**  JavaScript 提供了 `ArrayBuffer` 用于表示原始的二进制数据缓冲区，以及各种 TypedArrays（例如 `Uint8Array`, `Float32Array`）用于以特定的数据类型操作 `ArrayBuffer` 的内容。`SharedArrayBuffer` 允许在不同的执行上下文（例如 Web Workers）之间共享内存。
   - **举例：** 当 JavaScript 代码创建一个 `new Uint8Array(1024)` 时，这个文件中的代码会被调用，将 V8 的 `Uint8Array` 对象转换为 Blink 内部的 `DOMUint8Array` 对象，以便 Blink 可以访问和操作其数据。
   - **假设输入：** JavaScript 代码 `const buffer = new ArrayBuffer(100);`  **输出：**  `NativeValueTraits<DOMArrayBuffer>::NativeValue` 函数接收到表示这个 `ArrayBuffer` 的 `v8::Value`，并返回一个指向新创建的 `DOMArrayBuffer` 对象的指针。

- **DataView：**  `DataView` 提供了更底层的接口来读写 `ArrayBuffer` 中的数据，可以控制字节序等。
   - **举例：**  JavaScript 代码使用 `new DataView(buffer)` 创建一个 `DataView` 对象时，此文件中的代码负责将其转换为 Blink 的 `DOMDataView` 对象。

**HTML:**

- **Canvas API：** `CanvasRenderingContext2D` 的 `getImageData()` 和 `putImageData()` 方法使用 `ImageData` 对象，其底层数据就是 `Uint8ClampedArray`。
   - **举例：** 当 JavaScript 代码调用 `ctx.getImageData(0, 0, 100, 100)` 获取画布像素数据时，返回的 `ImageData` 对象的 `data` 属性（一个 `Uint8ClampedArray`）的转换就会涉及到这个文件。
   - **用户操作：** 用户在网页上进行操作，触发 JavaScript 代码调用 Canvas API 获取图像数据。

- **File API：**  `FileReader` 的 `readAsArrayBuffer()` 方法可以将文件内容读取到 `ArrayBuffer` 中。
   - **举例：**  用户上传一个文件，JavaScript 使用 `FileReader` 读取文件内容为 `ArrayBuffer`，这个 `ArrayBuffer` 需要被转换为 Blink 内部的对象才能进一步处理。
   - **用户操作：** 用户点击 `<input type="file">` 选择文件，触发 `change` 事件，JavaScript 代码使用 `FileReader` 读取文件。

- **WebSockets 和 Fetch API：**  这些 API 可以发送和接收二进制数据，通常以 `ArrayBuffer` 或 `ArrayBufferView` 的形式存在。
   - **举例：** 当通过 WebSocket 接收到二进制消息时，消息内容可能是一个 `ArrayBuffer`，需要通过这里的代码转换为 Blink 内部的表示。

**CSS:**

- CSS 与此文件的直接关系较少。但理论上，如果涉及到使用 JavaScript 操作二进制数据并用于 CSS 的高级特性（例如，通过 Canvas 生成纹理或使用 Houdini API），那么间接地会涉及到这里。

**逻辑推理的假设输入与输出：**

**假设输入 1:**

- JavaScript 代码: `const byteArray = new Uint8Array([1, 2, 3]);`
- V8 输入: 一个表示 `Uint8Array` 的 `v8::Value` 对象。

**输出 1:**

- `NativeValueTraits<NotShared<DOMUint8Array>>::NativeValue` 被调用。
- 返回一个指向新创建的 `DOMUint8Array` 对象的指针，该对象在 Blink 内部表示了这个 `Uint8Array`，包含了数据 `[1, 2, 3]`。

**假设输入 2:**

- JavaScript 代码: `function foo(buffer) {}; foo(new ArrayBuffer(5));` (IDL 定义中 `buffer` 参数类型为 `ArrayBuffer`)
- V8 输入:  一个表示 `ArrayBuffer` 的 `v8::Value` 对象。

**输出 2:**

- `NativeValueTraits<DOMArrayBuffer>::ArgumentValue` 被调用。
- 返回一个指向新创建的 `DOMArrayBuffer` 对象的指针。

**用户或编程常见的使用错误举例说明：**

1. **大小超出限制：**
   - **JavaScript 代码：** `const hugeBuffer = new ArrayBuffer(Number.MAX_SAFE_INTEGER);`
   - **结果：** `DoesExceedSizeLimit` 函数会返回 `true`，`NativeValueImpl` 会抛出一个 `RangeError`，提示 ArrayBuffer 大小超出支持范围。

2. **类型不匹配：**
   - **JavaScript 代码：**  一个接口期望接收 `ArrayBuffer`，但传入了普通对象：`function bar(buffer) {}; bar({});`
   - **结果：** 在 `ToDOMArrayBuffer` 函数中，`value->IsArrayBuffer()` 会返回 `false`，导致转换失败，`NativeValueImpl` 会抛出一个 `TypeError`，提示类型不匹配。

3. **在不允许的上下文中使用 SharedArrayBuffer：**
   - **JavaScript 代码：** 一个 API 被设计为只能接收普通的 `ArrayBuffer`，但传入了 `SharedArrayBuffer`： `function process(buffer) {}; process(new SharedArrayBuffer(10));`
   - **结果：** `NativeValueImpl` 中的 `IsSharedBuffer(value)` 检查会返回 `true`，代码会抛出一个 `TypeError`，说明不允许使用 `SharedArrayBuffer`。

4. **在不允许的上下文中使用可调整大小的 ArrayBuffer：**
    - **JavaScript 代码：** 一个 API 期望一个不可调整大小的 `ArrayBuffer`，但传入了一个可调整大小的 `ArrayBuffer`。
    - **结果：** `RecipeTrait::IsResizable(blink_value)` 会返回 `true`，`NativeValueImpl` 会抛出一个 `TypeError`，说明不允许使用可调整大小的 `ArrayBuffer`。

**用户操作如何一步步的到达这里 (调试线索)：**

1. **用户在网页上执行了某些操作**，例如点击了一个按钮，上传了一个文件，或者网页上的 JavaScript 代码定期从服务器拉取数据。
2. **这些操作触发了 JavaScript 代码的执行**，这些代码涉及到创建或操作 `ArrayBuffer`, `SharedArrayBuffer` 或 `ArrayBufferView`。
3. **JavaScript 代码将这些 BufferSource 对象传递给浏览器的内部 API**，例如 Canvas API, File API, WebSockets API, Fetch API 等。
4. **当 Blink 接收到这些 JavaScript 对象时**，就需要将其转换为 C++ 对象以便在渲染引擎内部进行处理。
5. **`NativeValueTraits` 机制被调用**，根据 JavaScript 对象的类型，会调用这个文件中的相应特化版本，例如 `NativeValueTraits<DOMArrayBuffer>::ArgumentValue`。
6. **如果在转换过程中发生错误**（例如类型不匹配，大小超出限制），`ExceptionState` 会记录错误，并最终抛出一个 JavaScript 异常。
7. **作为调试人员**，你可能会在浏览器的开发者工具的 Console 面板中看到这个异常。通过查看调用栈，你可能会看到 V8 的代码调用了 Blink 的绑定代码，最终定位到这个 `native_value_traits_buffer_sources.cc` 文件中的相关函数。
8. **你可能会设置断点在这个文件中的 `NativeValueImpl` 或 `ArgumentValueImpl` 函数中**，来检查传入的 `v8::Value` 的类型和内容，以及转换过程中是否发生了错误。

**总结一下它的功能 (针对第1部分)：**

`blink/renderer/bindings/core/v8/native_value_traits_buffer_sources.cc` 文件的主要功能是 **定义了将 JavaScript 中的 BufferSource 类型安全且正确地转换为 Blink 渲染引擎内部使用的 C++ 对象的机制。** 它处理了不同类型的缓冲区，进行了必要的类型检查和大小限制检查，并在转换失败时抛出合适的 JavaScript 异常，从而保证了 Web API 的正确性和安全性。这是 Blink 渲染引擎与 V8 JavaScript 引擎之间关于二进制数据交互的关键桥梁。

Prompt: 
```
这是目录为blink/renderer/bindings/core/v8/native_value_traits_buffer_sources.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"

namespace blink {

namespace {

bool DoesExceedSizeLimitSlow(v8::Isolate* isolate,
                             ExceptionState& exception_state) {
  if (base::FeatureList::IsEnabled(
          features::kDisableArrayBufferSizeLimitsForTesting)) {
    return false;
  }

  UseCounter::Count(ExecutionContext::From(isolate->GetCurrentContext()),
                    WebFeature::kArrayBufferTooBigForWebAPI);
  exception_state.ThrowRangeError(
      "The ArrayBuffer/ArrayBufferView size exceeds the supported range.");
  return true;
}

// Throws a RangeError and returns true if the given byte_length exceeds the
// size limit.
//
// TODO(crbug.com/1201109): Remove check once Blink can handle bigger sizes.
inline bool DoesExceedSizeLimit(v8::Isolate* isolate,
                                size_t byte_length,
                                ExceptionState& exception_state) {
  if (byte_length <= ::partition_alloc::MaxDirectMapped()) [[likely]] {
    return false;
  }

  return DoesExceedSizeLimitSlow(isolate, exception_state);
}

enum class Nullablity {
  kIsNotNullable,
  kIsNullable,
};

enum class BufferSizeCheck {
  kCheck,
  kDoNotCheck,
};

enum class ResizableAllowance { kDisallowResizable, kAllowResizable };

// The basic recipe of NativeValueTraits<T>::NativeValue function
// implementation for buffer source types.
template <typename RecipeTrait,
          auto (*ToBlinkValue)(v8::Isolate*, v8::Local<v8::Value>),
          Nullablity nullablity,
          BufferSizeCheck buffer_size_check,
          ResizableAllowance allow_resizable,
          typename ScriptWrappableOrBufferSourceTypeName,
          bool (*IsSharedBuffer)(v8::Local<v8::Value>) = nullptr>
auto NativeValueImpl(v8::Isolate* isolate,
                     v8::Local<v8::Value> value,
                     ExceptionState& exception_state) {
  const char* buffer_source_type_name = nullptr;
  if constexpr (std::is_base_of_v<ScriptWrappable,
                                  ScriptWrappableOrBufferSourceTypeName>) {
    buffer_source_type_name =
        ScriptWrappableOrBufferSourceTypeName::GetStaticWrapperTypeInfo()
            ->interface_name;
  } else {
    buffer_source_type_name = ScriptWrappableOrBufferSourceTypeName::GetName();
  }

  auto blink_value = ToBlinkValue(isolate, value);
  if (RecipeTrait::IsNonNull(blink_value)) [[likely]] {
    if constexpr (allow_resizable == ResizableAllowance::kDisallowResizable) {
      if (RecipeTrait::IsResizable(blink_value)) {
        exception_state.ThrowTypeError(
            ExceptionMessages::ResizableArrayBufferNotAllowed(
                buffer_source_type_name));
        return RecipeTrait::NullValue();
      }
    }

    if constexpr (buffer_size_check == BufferSizeCheck::kCheck) {
      if (DoesExceedSizeLimit(isolate, RecipeTrait::ByteLength(blink_value),
                              exception_state)) {
        return RecipeTrait::NullValue();
      }
    }

    return RecipeTrait::ToReturnType(blink_value);
  }

  if constexpr (nullablity == Nullablity::kIsNullable) {
    if (value->IsNullOrUndefined()) [[likely]] {
      return RecipeTrait::NullValue();
    }
  }

  if constexpr (IsSharedBuffer != nullptr) {
    if (IsSharedBuffer(value)) {
      exception_state.ThrowTypeError(
          ExceptionMessages::SharedArrayBufferNotAllowed(
              buffer_source_type_name));
      return RecipeTrait::NullValue();
    }
  }

  exception_state.ThrowTypeError(
      ExceptionMessages::FailedToConvertJSValue(buffer_source_type_name));
  return RecipeTrait::NullValue();
}

// The basic recipe of NativeValueTraits<T>::ArgumentValue function
// implementation for buffer source types.
template <typename RecipeTrait,
          auto (*ToBlinkValue)(v8::Isolate*, v8::Local<v8::Value>),
          Nullablity nullablity,
          BufferSizeCheck buffer_size_check,
          ResizableAllowance allow_resizable,
          typename ScriptWrappableOrBufferSourceTypeName,
          bool (*IsSharedBuffer)(v8::Local<v8::Value>) = nullptr>
auto ArgumentValueImpl(v8::Isolate* isolate,
                       int argument_index,
                       v8::Local<v8::Value> value,
                       ExceptionState& exception_state) {
  const char* buffer_source_type_name = nullptr;
  if constexpr (std::is_base_of_v<ScriptWrappable,
                                  ScriptWrappableOrBufferSourceTypeName>) {
    buffer_source_type_name =
        ScriptWrappableOrBufferSourceTypeName::GetStaticWrapperTypeInfo()
            ->interface_name;
  } else {
    buffer_source_type_name = ScriptWrappableOrBufferSourceTypeName::GetName();
  }

  auto blink_value = ToBlinkValue(isolate, value);
  if (RecipeTrait::IsNonNull(blink_value)) [[likely]] {
    if constexpr (allow_resizable == ResizableAllowance::kDisallowResizable) {
      if (RecipeTrait::IsResizable(blink_value)) {
        exception_state.ThrowTypeError(
            ExceptionMessages::ResizableArrayBufferNotAllowed(
                buffer_source_type_name));
        return RecipeTrait::NullValue();
      }
    }

    if constexpr (buffer_size_check == BufferSizeCheck::kCheck) {
      if (DoesExceedSizeLimit(isolate, RecipeTrait::ByteLength(blink_value),
                              exception_state)) {
        return RecipeTrait::NullValue();
      }
    }

    return RecipeTrait::ToReturnType(blink_value);
  }

  if constexpr (nullablity == Nullablity::kIsNullable) {
    if (value->IsNullOrUndefined()) [[likely]] {
      return RecipeTrait::NullValue();
    }
  }

  if constexpr (IsSharedBuffer != nullptr) {
    if (IsSharedBuffer(value)) {
      exception_state.ThrowTypeError(
          ExceptionMessages::SharedArrayBufferNotAllowed(
              buffer_source_type_name));
      return RecipeTrait::NullValue();
    }
  }

  exception_state.ThrowTypeError(ExceptionMessages::ArgumentNotOfType(
      argument_index, buffer_source_type_name));
  return RecipeTrait::NullValue();
}

// ABVTrait implementation for type parameterization purposes

template <typename T>
struct ABVTrait;  // ABV = ArrayBufferView

template <typename DOMViewTypeArg,
          typename V8ViewTypeArg,
          bool (v8::Value::*IsV8ViewTypeMemFunc)() const>
struct ABVTraitImpl {
  using DOMViewType = DOMViewTypeArg;
  using V8ViewType = V8ViewTypeArg;

  static DOMViewType* CreateDOMViewType(DOMArrayBufferBase* blink_buffer,
                                        v8::Local<V8ViewType> v8_view) {
    return DOMViewType::Create(blink_buffer, v8_view->ByteOffset(),
                               v8_view->Length());
  }
  static bool IsV8ViewType(v8::Local<v8::Value> value) {
    return ((*value)->*IsV8ViewTypeMemFunc)();
  }
  static bool IsShared(v8::Local<v8::Value> value) {
    return IsV8ViewType(value) &&
           value.As<V8ViewType>()->Buffer()->IsSharedArrayBuffer();
  }
};

#define DEFINE_ABV_TRAIT(name)                                      \
  template <>                                                       \
  struct ABVTrait<DOM##name>                                        \
      : ABVTraitImpl<DOM##name, v8::name, &v8::Value::Is##name> {};

DEFINE_ABV_TRAIT(ArrayBufferView)
DEFINE_ABV_TRAIT(Int8Array)
DEFINE_ABV_TRAIT(Int16Array)
DEFINE_ABV_TRAIT(Int32Array)
DEFINE_ABV_TRAIT(Uint8Array)
DEFINE_ABV_TRAIT(Uint8ClampedArray)
DEFINE_ABV_TRAIT(Uint16Array)
DEFINE_ABV_TRAIT(Uint32Array)
DEFINE_ABV_TRAIT(BigInt64Array)
DEFINE_ABV_TRAIT(BigUint64Array)
DEFINE_ABV_TRAIT(Float16Array)
DEFINE_ABV_TRAIT(Float32Array)
DEFINE_ABV_TRAIT(Float64Array)
#undef DEFINE_ABV_TRAIT

template <>
struct ABVTrait<DOMDataView>
    : ABVTraitImpl<DOMDataView, v8::DataView, &v8::Value::IsDataView> {
  static DOMViewType* CreateDOMViewType(DOMArrayBufferBase* blink_buffer,
                                        v8::Local<V8ViewType> v8_view) {
    return DOMViewType::Create(blink_buffer, v8_view->ByteOffset(),
                               v8_view->ByteLength());
  }
};

// RecipeTrait implementation for the recipe functions

template <typename T, typename unused = void>
struct RecipeTrait {
  static bool IsNonNull(const T* buffer_view) { return buffer_view; }
  static T* NullValue() { return nullptr; }
  static T* ToReturnType(T* buffer_view) { return buffer_view; }
  static size_t ByteLength(const T* buffer_view) {
    return buffer_view->byteLength();
  }
  static bool IsResizable(const T* buffer_view) {
    return buffer_view->BufferBase()->IsResizableByUserJavaScript();
  }
};

template <typename T>
struct RecipeTrait<T,
                   std::enable_if_t<std::is_base_of_v<DOMArrayBufferBase, T>>> {
  static bool IsNonNull(const T* buffer) { return buffer; }
  static T* NullValue() { return nullptr; }
  static T* ToReturnType(T* buffer) { return buffer; }
  static size_t ByteLength(const T* buffer) { return buffer->ByteLength(); }
  static bool IsResizable(const T* buffer) {
    return buffer->IsResizableByUserJavaScript();
  }
};

template <typename T>
struct RecipeTrait<NotShared<T>, void> : public RecipeTrait<T> {
  static NotShared<T> NullValue() { return NotShared<T>(); }
  static NotShared<T> ToReturnType(T* buffer) { return NotShared<T>(buffer); }
};

template <typename T>
struct RecipeTrait<MaybeShared<T>, void> : public RecipeTrait<T> {
  static MaybeShared<T> NullValue() { return MaybeShared<T>(); }
  static MaybeShared<T> ToReturnType(T* buffer) {
    return MaybeShared<T>(buffer);
  }
};

// ToBlinkValue implementation for the recipe functions

DOMArrayBuffer* ToDOMArrayBuffer(v8::Isolate* isolate,
                                 v8::Local<v8::Value> value) {
  if (!value->IsArrayBuffer()) [[unlikely]] {
    return nullptr;
  }

  v8::Local<v8::ArrayBuffer> v8_array_buffer = value.As<v8::ArrayBuffer>();
  if (auto* array_buffer =
          ToScriptWrappable<DOMArrayBuffer>(isolate, v8_array_buffer)) {
    return array_buffer;
  }

  // Transfer the ownership of the allocated memory to a DOMArrayBuffer without
  // copying.
  ArrayBufferContents contents(v8_array_buffer->GetBackingStore());
  DOMArrayBuffer* array_buffer = DOMArrayBuffer::Create(contents);
  v8::Local<v8::Object> wrapper = array_buffer->AssociateWithWrapper(
      isolate, array_buffer->GetWrapperTypeInfo(), v8_array_buffer);
  DCHECK(wrapper == v8_array_buffer);
  return array_buffer;
}

DOMSharedArrayBuffer* ToDOMSharedArrayBuffer(v8::Isolate* isolate,
                                             v8::Local<v8::Value> value) {
  if (!value->IsSharedArrayBuffer()) [[unlikely]] {
    return nullptr;
  }

  v8::Local<v8::SharedArrayBuffer> v8_shared_array_buffer =
      value.As<v8::SharedArrayBuffer>();
  if (auto* shared_array_buffer = ToScriptWrappable<DOMSharedArrayBuffer>(
          isolate, v8_shared_array_buffer)) {
    return shared_array_buffer;
  }

  // Transfer the ownership of the allocated memory to a DOMArrayBuffer without
  // copying.
  ArrayBufferContents contents(v8_shared_array_buffer->GetBackingStore());
  DOMSharedArrayBuffer* shared_array_buffer =
      DOMSharedArrayBuffer::Create(contents);
  v8::Local<v8::Object> wrapper = shared_array_buffer->AssociateWithWrapper(
      isolate, shared_array_buffer->GetWrapperTypeInfo(),
      v8_shared_array_buffer);
  DCHECK(wrapper == v8_shared_array_buffer);
  return shared_array_buffer;
}

DOMArrayBufferBase* ToDOMArrayBufferBase(v8::Isolate* isolate,
                                         v8::Local<v8::Value> value) {
  if (auto* buffer = ToDOMArrayBuffer(isolate, value)) {
    return buffer;
  }
  return ToDOMSharedArrayBuffer(isolate, value);
}

constexpr bool kNotShared = false;
constexpr bool kMaybeShared = true;

template <typename DOMViewType, bool allow_shared>
DOMViewType* ToDOMViewType(v8::Isolate* isolate, v8::Local<v8::Value> value) {
  using Trait = ABVTrait<DOMViewType>;

  if (!Trait::IsV8ViewType(value)) [[unlikely]] {
    return nullptr;
  }

  v8::Local<typename Trait::V8ViewType> v8_view =
      value.As<typename Trait::V8ViewType>();
  if (auto* blink_view = ToScriptWrappable<DOMViewType>(isolate, v8_view)) {
    return blink_view;
  }

  v8::Local<v8::Object> v8_buffer = v8_view->Buffer();
  DOMArrayBufferBase* blink_buffer = nullptr;
  if constexpr (allow_shared) {
    if (v8_buffer->IsArrayBuffer())
      blink_buffer = ToDOMArrayBuffer(isolate, v8_buffer);
    else  // must be IsSharedArrayBuffer()
      blink_buffer = ToDOMSharedArrayBuffer(isolate, v8_buffer);
  } else {
    if (v8_buffer->IsArrayBuffer()) [[likely]] {
      blink_buffer = ToDOMArrayBuffer(isolate, v8_buffer);
    } else {  // must be IsSharedArrayBuffer()
      return nullptr;
    }
  }

  DOMViewType* blink_view = Trait::CreateDOMViewType(blink_buffer, v8_view);
  v8::Local<v8::Object> wrapper = blink_view->AssociateWithWrapper(
      isolate, blink_view->GetWrapperTypeInfo(), v8_view);
  DCHECK(wrapper == v8_view);
  return blink_view;
}

template <bool allow_shared>
DOMArrayBufferView* ToDOMArrayBufferView(v8::Isolate* isolate,
                                         v8::Local<v8::Value> value) {
  if (!value->IsArrayBufferView()) [[unlikely]] {
    return nullptr;
  }

  v8::Local<v8::ArrayBufferView> v8_view = value.As<v8::ArrayBufferView>();
  if (auto* blink_view =
          ToScriptWrappable<DOMArrayBufferView>(isolate, v8_view)) {
    return blink_view;
  }

  if (v8_view->IsInt8Array()) {
    return ToDOMViewType<DOMInt8Array, allow_shared>(isolate, value);
  }
  if (v8_view->IsInt16Array()) {
    return ToDOMViewType<DOMInt16Array, allow_shared>(isolate, value);
  }
  if (v8_view->IsInt32Array()) {
    return ToDOMViewType<DOMInt32Array, allow_shared>(isolate, value);
  }
  if (v8_view->IsUint8Array()) {
    return ToDOMViewType<DOMUint8Array, allow_shared>(isolate, value);
  }
  if (v8_view->IsUint8ClampedArray()) {
    return ToDOMViewType<DOMUint8ClampedArray, allow_shared>(isolate, value);
  }
  if (v8_view->IsUint16Array()) {
    return ToDOMViewType<DOMUint16Array, allow_shared>(isolate, value);
  }
  if (v8_view->IsUint32Array()) {
    return ToDOMViewType<DOMUint32Array, allow_shared>(isolate, value);
  }
  if (v8_view->IsBigInt64Array()) {
    return ToDOMViewType<DOMBigInt64Array, allow_shared>(isolate, value);
  }
  if (v8_view->IsBigUint64Array()) {
    return ToDOMViewType<DOMBigUint64Array, allow_shared>(isolate, value);
  }
  if (v8_view->IsFloat16Array()) {
    return ToDOMViewType<DOMFloat16Array, allow_shared>(isolate, value);
  }
  if (v8_view->IsFloat32Array()) {
    return ToDOMViewType<DOMFloat32Array, allow_shared>(isolate, value);
  }
  if (v8_view->IsFloat64Array()) {
    return ToDOMViewType<DOMFloat64Array, allow_shared>(isolate, value);
  }
  if (v8_view->IsDataView()) {
    return ToDOMViewType<DOMDataView, allow_shared>(isolate, value);
  }

  NOTREACHED();
}

template <>
DOMArrayBufferView* ToDOMViewType<DOMArrayBufferView, kNotShared>(
    v8::Isolate* isolate,
    v8::Local<v8::Value> value) {
  return ToDOMArrayBufferView<kNotShared>(isolate, value);
}

template <>
DOMArrayBufferView* ToDOMViewType<DOMArrayBufferView, kMaybeShared>(
    v8::Isolate* isolate,
    v8::Local<v8::Value> value) {
  return ToDOMArrayBufferView<kMaybeShared>(isolate, value);
}

// ScriptWrappableOrBufferSourceTypeName implementation for the recipe functions

struct BufferSourceTypeNameAllowSharedArrayBuffer {
  static constexpr const char* GetName() { return "[AllowShared] ArrayBuffer"; }
};

}  // namespace

// ArrayBuffer

DOMArrayBuffer* NativeValueTraits<DOMArrayBuffer>::NativeValue(
    v8::Isolate* isolate,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  return NativeValueImpl<RecipeTrait<DOMArrayBuffer>, ToDOMArrayBuffer,
                         Nullablity::kIsNotNullable, BufferSizeCheck::kCheck,
                         ResizableAllowance::kDisallowResizable,
                         DOMArrayBuffer>(isolate, value, exception_state);
}

DOMArrayBuffer* NativeValueTraits<DOMArrayBuffer>::ArgumentValue(
    v8::Isolate* isolate,
    int argument_index,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  return ArgumentValueImpl<RecipeTrait<DOMArrayBuffer>, ToDOMArrayBuffer,
                           Nullablity::kIsNotNullable, BufferSizeCheck::kCheck,
                           ResizableAllowance::kDisallowResizable,
                           DOMArrayBuffer>(isolate, argument_index, value,
                                           exception_state);
}

// Nullable ArrayBuffer

DOMArrayBuffer* NativeValueTraits<IDLNullable<DOMArrayBuffer>>::NativeValue(
    v8::Isolate* isolate,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  return NativeValueImpl<RecipeTrait<DOMArrayBuffer>, ToDOMArrayBuffer,
                         Nullablity::kIsNullable, BufferSizeCheck::kCheck,
                         ResizableAllowance::kDisallowResizable,
                         DOMArrayBuffer>(isolate, value, exception_state);
}

DOMArrayBuffer* NativeValueTraits<IDLNullable<DOMArrayBuffer>>::ArgumentValue(
    v8::Isolate* isolate,
    int argument_index,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  return ArgumentValueImpl<RecipeTrait<DOMArrayBuffer>, ToDOMArrayBuffer,
                           Nullablity::kIsNullable, BufferSizeCheck::kCheck,
                           ResizableAllowance::kDisallowResizable,
                           DOMArrayBuffer>(isolate, argument_index, value,
                                           exception_state);
}

// [AllowResizable] ArrayBuffer

DOMArrayBuffer*
NativeValueTraits<IDLAllowResizable<DOMArrayBuffer>>::NativeValue(
    v8::Isolate* isolate,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  return NativeValueImpl<RecipeTrait<DOMArrayBuffer>, ToDOMArrayBuffer,
                         Nullablity::kIsNotNullable, BufferSizeCheck::kCheck,
                         ResizableAllowance::kAllowResizable, DOMArrayBuffer>(
      isolate, value, exception_state);
}

DOMArrayBuffer*
NativeValueTraits<IDLAllowResizable<DOMArrayBuffer>>::ArgumentValue(
    v8::Isolate* isolate,
    int argument_index,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  return ArgumentValueImpl<RecipeTrait<DOMArrayBuffer>, ToDOMArrayBuffer,
                           Nullablity::kIsNotNullable, BufferSizeCheck::kCheck,
                           ResizableAllowance::kAllowResizable, DOMArrayBuffer>(
      isolate, argument_index, value, exception_state);
}

// SharedArrayBuffer

DOMSharedArrayBuffer* NativeValueTraits<DOMSharedArrayBuffer>::NativeValue(
    v8::Isolate* isolate,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  return NativeValueImpl<
      RecipeTrait<DOMSharedArrayBuffer>, ToDOMSharedArrayBuffer,
      Nullablity::kIsNotNullable, BufferSizeCheck::kCheck,
      ResizableAllowance::kDisallowResizable, DOMSharedArrayBuffer>(
      isolate, value, exception_state);
}

DOMSharedArrayBuffer* NativeValueTraits<DOMSharedArrayBuffer>::ArgumentValue(
    v8::Isolate* isolate,
    int argument_index,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  return ArgumentValueImpl<
      RecipeTrait<DOMSharedArrayBuffer>, ToDOMSharedArrayBuffer,
      Nullablity::kIsNotNullable, BufferSizeCheck::kCheck,
      ResizableAllowance::kDisallowResizable, DOMSharedArrayBuffer>(
      isolate, argument_index, value, exception_state);
}

// Nullable SharedArrayBuffer

DOMSharedArrayBuffer*
NativeValueTraits<IDLNullable<DOMSharedArrayBuffer>>::NativeValue(
    v8::Isolate* isolate,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  return NativeValueImpl<
      RecipeTrait<DOMSharedArrayBuffer>, ToDOMSharedArrayBuffer,
      Nullablity::kIsNullable, BufferSizeCheck::kCheck,
      ResizableAllowance::kDisallowResizable, DOMSharedArrayBuffer>(
      isolate, value, exception_state);
}

DOMSharedArrayBuffer*
NativeValueTraits<IDLNullable<DOMSharedArrayBuffer>>::ArgumentValue(
    v8::Isolate* isolate,
    int argument_index,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  return ArgumentValueImpl<
      RecipeTrait<DOMSharedArrayBuffer>, ToDOMSharedArrayBuffer,
      Nullablity::kIsNullable, BufferSizeCheck::kCheck,
      ResizableAllowance::kDisallowResizable, DOMSharedArrayBuffer>(
      isolate, argument_index, value, exception_state);
}

// [AllowResizable] SharedArrayBuffer

DOMSharedArrayBuffer*
NativeValueTraits<IDLAllowResizable<DOMSharedArrayBuffer>>::NativeValue(
    v8::Isolate* isolate,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  return NativeValueImpl<
      RecipeTrait<DOMSharedArrayBuffer>, ToDOMSharedArrayBuffer,
      Nullablity::kIsNotNullable, BufferSizeCheck::kCheck,
      ResizableAllowance::kAllowResizable, DOMSharedArrayBuffer>(
      isolate, value, exception_state);
}

DOMSharedArrayBuffer*
NativeValueTraits<IDLAllowResizable<DOMSharedArrayBuffer>>::ArgumentValue(
    v8::Isolate* isolate,
    int argument_index,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  return ArgumentValueImpl<
      RecipeTrait<DOMSharedArrayBuffer>, ToDOMSharedArrayBuffer,
      Nullablity::kIsNotNullable, BufferSizeCheck::kCheck,
      ResizableAllowance::kAllowResizable, DOMSharedArrayBuffer>(
      isolate, argument_index, value, exception_state);
}

// [AllowShared] ArrayBuffer

DOMArrayBufferBase* NativeValueTraits<DOMArrayBufferBase>::NativeValue(
    v8::Isolate* isolate,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  return NativeValueImpl<RecipeTrait<DOMArrayBufferBase>, ToDOMArrayBufferBase,
                         Nullablity::kIsNotNullable, BufferSizeCheck::kCheck,
                         ResizableAllowance::kDisallowResizable,
                         BufferSourceTypeNameAllowSharedArrayBuffer>(
      isolate, value, exception_state);
}

DOMArrayBufferBase* NativeValueTraits<DOMArrayBufferBase>::ArgumentValue(
    v8::Isolate* isolate,
    int argument_index,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  return ArgumentValueImpl<RecipeTrait<DOMArrayBufferBase>,
                           ToDOMArrayBufferBase, Nullablity::kIsNotNullable,
                           BufferSizeCheck::kCheck,
                           ResizableAllowance::kDisallowResizable,
                           BufferSourceTypeNameAllowSharedArrayBuffer>(
      isolate, argument_index, value, exception_state);
}

// [AllowShared, BufferSourceTypeNoSizeLimit] ArrayBuffer

DOMArrayBufferBase* NativeValueTraits<IDLBufferSourceTypeNoSizeLimit<
    DOMArrayBufferBase>>::ArgumentValue(v8::Isolate* isolate,
                                        int argument_index,
                                        v8::Local<v8::Value> value,
                                        ExceptionState& exception_state) {
  return ArgumentValueImpl<RecipeTrait<DOMArrayBufferBase>,
                           ToDOMArrayBufferBase, Nullablity::kIsNotNullable,
                           BufferSizeCheck::kDoNotCheck,
                           ResizableAllowance::kDisallowResizable,
                           BufferSourceTypeNameAllowSharedArrayBuffer>(
      isolate, argument_index, value, exception_state);
}

// Nullable [AllowShared] ArrayBuffer

DOMArrayBufferBase*
NativeValueTraits<IDLNullable<DOMArrayBufferBase>>::NativeValue(
    v8::Isolate* isolate,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  return NativeValueImpl<RecipeTrait<DOMArrayBufferBase>, ToDOMArrayBufferBase,
                         Nullablity::kIsNullable, BufferSizeCheck::kCheck,
                         ResizableAllowance::kDisallowResizable,
                         BufferSourceTypeNameAllowSharedArrayBuffer>(
      isolate, value, exception_state);
}

DOMArrayBufferBase*
NativeValueTraits<IDLNullable<DOMArrayBufferBase>>::ArgumentValue(
    v8::Isolate* isolate,
    int argument_index,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  return ArgumentValueImpl<RecipeTrait<DOMArrayBufferBase>,
                           ToDOMArrayBufferBase, Nullablity::kIsNullable,
                           BufferSizeCheck::kCheck,
                           ResizableAllowance::kDisallowResizable,
                           BufferSourceTypeNameAllowSharedArrayBuffer>(
      isolate, argument_index, value, exception_state);
}

// Nullable [AllowShared, BufferSourceTypeNoSizeLimit] ArrayBuffer

DOMArrayBufferBase* NativeValueTraits<
    IDLNullable<IDLBufferSourceTypeNoSizeLimit<DOMArrayBufferBase>>>::
    ArgumentValue(v8::Isolate* isolate,
                  int argument_index,
                  v8::Local<v8::Value> value,
                  ExceptionState& exception_state) {
  return ArgumentValueImpl<RecipeTrait<DOMArrayBufferBase>,
                           ToDOMArrayBufferBase, Nullablity::kIsNullable,
                           BufferSizeCheck::kDoNotCheck,
                           ResizableAllowance::kDisallowResizable,
                           BufferSourceTypeNameAllowSharedArrayBuffer>(
      isolate, argument_index, value, exception_state);
}

// ArrayBufferView

template <typename T>
  requires std::derived_from<T, DOMArrayBufferView>
NotShared<T> NativeValueTraits<NotShared<T>>::NativeValue(
    v8::Isolate* isolate,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  return NativeValueImpl<
      RecipeTrait<NotShared<T>>, ToDOMViewType<T, kNotShared>,
      Nullablity::kIsNotNullable, BufferSizeCheck::kCheck,
      ResizableAllowance::kDisallowResizable, T, ABVTrait<T>::IsShared>(
      isolate, value, exception_state);
}

template <typename T>
  requires std::derived_from<T, DOMArrayBufferView>
NotShared<T> NativeValueTraits<NotShared<T>>::ArgumentValue(
    v8::Isolate* isolate,
    int argument_index,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  return ArgumentValueImpl<
      RecipeTrait<NotShared<T>>, ToDOMViewType<T, kNotShared>,
      Nullablity::kIsNotNullable, BufferSizeCheck::kCheck,
      ResizableAllowance::kDisallowResizable, T, ABVTrait<T>::IsShared>(
      isolate, argument_index, value, exception_state);
}

// [AllowShared] ArrayBufferView

template <typename T>
  requires std::derived_from<T, DOMArrayBufferView>
MaybeShared<T> NativeValueTraits<MaybeShared<T>>::NativeValue(
    v8::Isolate* isolate,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  return NativeValueImpl<RecipeTrait<MaybeShared<T>>,
                         ToDOMViewType<T, kMaybeShared>,
                         Nullablity::kIsNotNullable, BufferSizeCheck::kCheck,
                         ResizableAllowance::kDisallowResizable, T>(
      isolate, value, exception_state);
}

template <typename T>
  requires std::derived_from<T, DOMArrayBufferView>
MaybeShared<T> NativeValueTraits<MaybeShared<T>>::ArgumentValue(
    v8::Isolate* isolate,
    int argument_index,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  return ArgumentValueImpl<RecipeTrait<MaybeShared<T>>,
                           ToDOMViewType<T, kMaybeShared>,
                           Nullablity::kIsNotNullable, BufferSizeCheck::kCheck,
                           ResizableAllowance::kDisallowResizable, T>(
      isolate, argument_index, value, exception_state);
}

// [AllowShared, BufferSourceTypeNoSizeLimit] ArrayBufferView

template <typename T>
  requires std::derived_from<T, DOMArrayBufferView>
MaybeShared<T> NativeValueTraits<IDLBufferSourceTypeNoSizeLimit<
    MaybeShared<T>>>::ArgumentValue(v8::Isolate* isolate,
                                    int argument_index,
                                    v8::Local<v8::Value> value,
                                    ExceptionState& exception_state) {
  return ArgumentValueImpl<
      RecipeTrait<MaybeShared<T>>, ToDOMViewType<T, kMaybeShared>,
      Nullablity::kIsNotNullable, BufferSizeCheck::kDoNotCheck,
      ResizableAllowance::kDisallowResizable, T>(isolate, argument_index, value,
                                                 exception_state);
}

// Nullable ArrayBufferView

template <typename T>
  requires std::derived_from<T, DOMArrayBufferView>
NotShared<T> NativeValueTraits<IDLNullable<NotShared<T>>>::NativeValue(
    v8::Isolate* isolate,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  return NativeValueImpl<
      RecipeTrait<NotShared<T>>, ToDOMViewType<T, kNotShared>,
      Nullablity::kIsNullable, BufferSizeCheck::kCheck,
      ResizableAllowance::kDisallowResizable, T, ABVTrait<T>::IsShared>(
      isolate, value, exception_state);
}

template <typename T>
  requires std::derived_from<T, DOMArrayBufferView>
NotShared<T> NativeValueTraits<IDLNullable<NotShared<T>>>::ArgumentValue(
    v8::Isolate* isolate,
    int argument_index,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  return ArgumentValueImpl<
      RecipeTrait<NotShared<T>>, ToDOMViewType<T, kNotShared>,
      Nullablity::kIsNullable, BufferSizeCheck::kCheck,
      ResizableAllowance::kDisallowResizable, T, ABVTrait<T>::IsShared>(
      isolate, argument_index, value, exception_state);
}

// Nullable [AllowShared] ArrayBufferView

template <typename T>
  requires std::derived_from<T, DOMArrayBufferView>
MaybeShared<T> NativeValueTraits<IDLNullable<MaybeShared<T>>>::NativeValue(
    v8::Isolate* isolate,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  return NativeValueImpl<RecipeTrait<MaybeShared<T>>,
                         ToDOMViewType<T, kMaybeShared>,
                         Nullablity::kIsNullable, BufferSizeCheck::kCheck,
                         ResizableAllowance::kDisallowResizable, T>(
      isolate, value, exception_state);
}

template <typename T>
  requires std::derived_from<T, DOMArrayBufferView>
MaybeShared<T> NativeValueTraits<IDLNullable<MaybeShared<T>>>::ArgumentValue(
    v8::Isolate* isolate,
    int argument_index,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  return ArgumentValueImpl<RecipeTrait<MaybeShared<T>>,
                           ToDOMViewType<T, kMaybeShared>,
                           Nullablity::kIsNullable, BufferSizeCheck::kCheck,
                           ResizableAllowance::kDisallowResizable, T>(
      isolate, argument_index, value, exception_state);
}

// Nullable [AllowShared, BufferSourceTypeNoSizeLimit] ArrayBufferView

template <typename T>
  requires std::derived_from<T, DOMArrayBufferView>
MaybeShared<T>
NativeValueTraits<IDLNullable<IDLBufferSourceTypeNoSizeLimit<MaybeShared<T>>>>::
    ArgumentValue(v8::Isolate* isolate,
                  int argument_index,
                  v8::Local<v8::Value> value,
                  ExceptionState& exception_state) {
  return ArgumentValueImpl<
      RecipeTrait<MaybeShared<T>>, ToDOMViewType<T, kMaybeShared>,
      Nullablity::kIsNullable, BufferSizeCheck::kDoNotCheck,
      ResizableAllowance::kDisallowResizable, T>(isolate, argument_index, value,
                                                 exception_state);
}

#define INSTANTIATE_NVT(type) \
  template struct CORE_EXPORT NativeValueTraits<type>;
// NotShared<T>
INSTANTIATE_NVT(NotShared<DOMArrayBufferView>)
INSTANTIATE_NVT(NotShared<DOMInt8Array>)
INSTANTIATE_NVT(NotShared<DOMInt16Array>)
INSTANTIATE_NVT(NotShared<DOMInt32Array>)
INSTANTIATE_NVT(NotShared<DOMUint8Array>)
INSTANTIATE_NVT(NotShared<DOMUint8ClampedArray>)
INSTANTIATE_NVT(NotShared<DOMUint16Array>)
INSTANTIATE_NVT(NotShared<DOMUint32Array>)
INSTANTIATE_NVT(NotShared<DOMBigInt64Array>)
INSTANTIATE_NVT(NotShared<DOMBigUint64Array>)
INSTANTIATE_NVT(NotShared<DOMFloat32Array>)
INSTANTIATE_NVT(NotShared<DOMFloat64Array>)
INSTANTIATE_NVT(NotShared<DOMDataView>)
// MaybeShared<T>
INSTANTIATE_NVT(MaybeShared<DOMArrayBufferView>)
INSTANTIATE_NVT(MaybeShared<DOMInt8Array>)
INSTANTIATE_NVT(MaybeShared<DOMInt16Array>)
INSTANTIATE_NVT(MaybeShared<DOMInt32Array>)
INSTANTIATE_NVT(MaybeShared<DOMUint8Array>)
INSTANTIATE_NVT(MaybeShared<DOMUint8ClampedArray>)
INSTANTIATE_NVT(MaybeShared<DOMUint16Array>)
INSTANTIATE_NVT(MaybeShared<DOMUint32Array>)
INSTANTIATE_NVT(MaybeShared<DOMBigInt64Array>)
INSTANTIATE_NVT(MaybeShared<DOMBigUint64Array>)
INSTANTIATE_NVT(MaybeShared<DOMFloat32Array>)
INSTANTIATE_NVT(MaybeShared<DO
"""


```