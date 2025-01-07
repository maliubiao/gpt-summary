Response:
My thought process to analyze the C++ header file `v8-wasm.h` and fulfill the user's request would be as follows:

1. **Understand the Request:** The user wants to know the functionality of the header file, whether it's related to Torque (based on file extension), its connection to JavaScript, examples, code logic inference with input/output, and common programming errors.

2. **Initial Assessment:** The filename `v8-wasm.h` strongly suggests this header defines interfaces and data structures related to WebAssembly integration within the V8 JavaScript engine. The `#ifndef INCLUDE_V8_WASM_H_` guard confirms it's a header file. The includes point to core V8 and standard library components. The `namespace v8` and `namespace internal::wasm` further reinforce its purpose.

3. **Analyze Class by Class:** I'd go through each defined class and struct:

    * **`OwnedBuffer`:**  This looks like a simple utility for holding a dynamically allocated byte buffer. The constructor and `size` member are key.
    * **`CompiledWasmModule`:** This is clearly about representing a compiled WebAssembly module. The `Serialize()` and `GetWireBytesRef()` methods are crucial for understanding its purpose: managing the compiled bytecode and the original source. The private constructor hints at internal V8 mechanisms for creating instances.
    * **`WasmMemoryObject`:**  The name and the `Buffer()` method suggest it represents a `WebAssembly.Memory` instance in JavaScript. The inheritance from `Object` is a V8 convention. The `Cast` method is a standard V8 pattern for downcasting.
    * **`WasmModuleObject`:** Similar to `WasmMemoryObject`, this represents a `WebAssembly.Module`. The static `FromCompiledModule()` and `Compile()` methods are key:  one for creating a module from already compiled code, and the other for initiating compilation. The `GetCompiledModule()` method links it back to `CompiledWasmModule`.
    * **`WasmStreaming`:** This class is central to asynchronous WebAssembly compilation (streaming). The methods like `OnBytesReceived()`, `Finish()`, `Abort()`, `SetCompiledModuleBytes()`, and `SetUrl()` describe the lifecycle of a streaming compilation process. The static `Unpack()` method suggests interaction with V8's internal managed objects.

4. **Address Specific Questions:**

    * **Functionality:** Summarize the purpose of each class, focusing on the interaction with WebAssembly concepts like modules, memory, and compilation.
    * **Torque:** The `.h` extension immediately tells me it's a C++ header, not a Torque file (which would end in `.tq`). State this clearly.
    * **JavaScript Relationship:**  Connect the C++ classes to their corresponding JavaScript APIs (`WebAssembly.Module`, `WebAssembly.Memory`, `WebAssembly.compileStreaming`). Provide concrete JavaScript examples showing how these APIs are used and how they relate to the C++ structures (even if the internal mechanisms aren't directly exposed in the JavaScript API).
    * **Code Logic Inference:** For classes with clear methods, propose a scenario with input and output. For example, for `CompiledWasmModule`, the input is the compiled module, and the output of `Serialize()` is the serialized byte buffer. For `WasmStreaming`, trace the flow of bytes and the eventual output (a `WasmModuleObject` or an error).
    * **Common Programming Errors:** Think about how a user might misuse these APIs *from the JavaScript side* since this header is about the V8 implementation. Focus on errors related to WebAssembly usage: invalid bytecode, instantiation errors, etc. While the header itself doesn't *directly* cause user errors, it defines the underlying mechanisms.

5. **Structure the Response:** Organize the information clearly, using headings and bullet points. Start with a general summary, then delve into the details of each class. Keep the JavaScript examples separate and focused.

6. **Refine and Review:** Read through the generated response to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas where more explanation might be needed. For instance, explicitly stating that users don't directly interact with these C++ classes in their JavaScript code is important.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe I should explain the internal details of how V8 handles WebAssembly. **Correction:** The request is about the *interface* defined in the header, not the implementation details. Keep the focus on the public API.
* **Initial thought:** Should I try to provide C++ examples of using these classes? **Correction:** The user's context is likely a JavaScript developer. Focus on the JavaScript side to make the explanation relevant.
* **Initial thought:** The `Cast` methods are just internal V8 stuff. **Correction:** Briefly explain their purpose as a standard V8 pattern for type checking.
* **Concern:** The `WasmStreaming` class seems complex. How can I explain it simply? **Refinement:** Focus on the high-level workflow of streaming compilation: receiving chunks, finishing, and aborting. Relate it to the JavaScript `WebAssembly.compileStreaming()` function.

By following these steps, breaking down the problem into smaller parts, and iteratively refining my understanding, I can generate a comprehensive and accurate answer to the user's request.
```cpp
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDE_V8_WASM_H_
#define INCLUDE_V8_WASM_H_

#include <functional>
#include <memory>
#include <string>

#include "v8-internal.h"      // NOLINT(build/include_directory)
#include "v8-local-handle.h"  // NOLINT(build/include_directory)
#include "v8-memory-span.h"   // NOLINT(build/include_directory)
#include "v8-object.h"        // NOLINT(build/include_directory)
#include "v8config.h"         // NOLINT(build/include_directory)

namespace v8 {

class ArrayBuffer;
class Promise;

namespace internal {
namespace wasm {
class NativeModule;
class StreamingDecoder;
}  // namespace wasm
}  // namespace internal

/**
 * An owned byte buffer with associated size.
 */
struct OwnedBuffer {
  std::unique_ptr<const uint8_t[]> buffer;
  size_t size = 0;
  OwnedBuffer(std::unique_ptr<const uint8_t[]> buffer, size_t size)
      : buffer(std::move(buffer)), size(size) {}
  OwnedBuffer() = default;
};

// Wrapper around a compiled WebAssembly module, which is potentially shared by
// different WasmModuleObjects.
class V8_EXPORT CompiledWasmModule {
 public:
  /**
   * Serialize the compiled module. The serialized data does not include the
   * wire bytes.
   */
  OwnedBuffer Serialize();

  /**
   * Get the (wasm-encoded) wire bytes that were used to compile this module.
   */
  MemorySpan<const uint8_t> GetWireBytesRef();

  const std::string& source_url() const { return source_url_; }

 private:
  friend class WasmModuleObject;
  friend class WasmStreaming;

  explicit CompiledWasmModule(std::shared_ptr<internal::wasm::NativeModule>,
                              const char* source_url, size_t url_length);

  const std::shared_ptr<internal::wasm::NativeModule> native_module_;
  const std::string source_url_;
};

// An instance of WebAssembly.Memory.
class V8_EXPORT WasmMemoryObject : public Object {
 public:
  WasmMemoryObject() = delete;

  /**
   * Returns underlying ArrayBuffer.
   */
  Local<ArrayBuffer> Buffer();

  V8_INLINE static WasmMemoryObject* Cast(Value* value) {
#ifdef V8_ENABLE_CHECKS
    CheckCast(value);
#endif
    return static_cast<WasmMemoryObject*>(value);
  }

 private:
  static void CheckCast(Value* object);
};

// An instance of WebAssembly.Module.
class V8_EXPORT WasmModuleObject : public Object {
 public:
  WasmModuleObject() = delete;

  /**
   * Efficiently re-create a WasmModuleObject, without recompiling, from
   * a CompiledWasmModule.
   */
  static MaybeLocal<WasmModuleObject> FromCompiledModule(
      Isolate* isolate, const CompiledWasmModule&);

  /**
   * Get the compiled module for this module object. The compiled module can be
   * shared by several module objects.
   */
  CompiledWasmModule GetCompiledModule();

  /**
   * Compile a Wasm module from the provided uncompiled bytes.
   */
  static MaybeLocal<WasmModuleObject> Compile(
      Isolate* isolate, MemorySpan<const uint8_t> wire_bytes);

  V8_INLINE static WasmModuleObject* Cast(Value* value) {
#ifdef V8_ENABLE_CHECKS
    CheckCast(value);
#endif
    return static_cast<WasmModuleObject*>(value);
  }

 private:
  static void CheckCast(Value* obj);
};

/**
 * The V8 interface for WebAssembly streaming compilation. When streaming
 * compilation is initiated, V8 passes a {WasmStreaming} object to the embedder
 * such that the embedder can pass the input bytes for streaming compilation to
 * V8.
 */
class V8_EXPORT WasmStreaming final {
 public:
  static constexpr internal::ExternalPointerTag kManagedTag =
      internal::kWasmWasmStreamingTag;
  class WasmStreamingImpl;

  explicit WasmStreaming(std::unique_ptr<WasmStreamingImpl> impl);

  ~WasmStreaming();

  /**
   * Pass a new chunk of bytes to WebAssembly streaming compilation.
   * The buffer passed into {OnBytesReceived} is owned by the caller.
   */
  void OnBytesReceived(const uint8_t* bytes, size_t size);

  /**
   * {Finish} should be called after all received bytes where passed to
   * {OnBytesReceived} to tell V8 that there will be no more bytes. {Finish}
   * must not be called after {Abort} has been called already.
   * If {can_use_compiled_module} is true and {SetCompiledModuleBytes} was
   * previously called, the compiled module bytes can be used.
   * If {can_use_compiled_module} is false, the compiled module bytes previously
   * set by {SetCompiledModuleBytes} should not be used.
   */
  void Finish(bool can_use_compiled_module = true);

  /**
   * Abort streaming compilation. If {exception} has a value, then the promise
   * associated with streaming compilation is rejected with that value. If
   * {exception} does not have value, the promise does not get rejected.
   * {Abort} must not be called repeatedly, or after {Finish}.
   */
  void Abort(MaybeLocal<Value> exception);

  /**
   * Passes previously compiled module bytes. This must be called before
   * {OnBytesReceived}, {Finish}, or {Abort}. Returns true if the module bytes
   * can be used, false otherwise. The buffer passed via {bytes} and {size}
   * is owned by the caller. If {SetCompiledModuleBytes} returns true, the
   * buffer must remain valid until either {Finish} or {Abort} completes.
   * The compiled module bytes should not be used until {Finish(true)} is
   * called, because they can be invalidated later by {Finish(false)}.
   */
  bool SetCompiledModuleBytes(const uint8_t* bytes, size_t size);

  /**
   * Sets a callback which is called whenever a significant number of new
   * functions are ready for serialization.
   */
  void SetMoreFunctionsCanBeSerializedCallback(
      std::function<void(CompiledWasmModule)>);

  /*
   * Sets the UTF-8 encoded source URL for the {Script} object. This must be
   * called before {Finish}.
   */
  void SetUrl(const char* url, size_t length);

  /**
   * Unpacks a {WasmStreaming} object wrapped in a  {Managed} for the embedder.
   * Since the embedder is on the other side of the API, it cannot unpack the
   * {Managed} itself.
   */
  static std::shared_ptr<WasmStreaming> Unpack(Isolate* isolate,
                                               Local<Value> value);

 private:
  std::unique_ptr<WasmStreamingImpl> impl_;
};

}  // namespace v8

#endif  // INCLUDE_V8_WASM_H_
```

### 功能列举

`v8/include/v8-wasm.h` 是 V8 JavaScript 引擎中关于 WebAssembly 集成的头文件。它定义了用于与 WebAssembly 模块进行交互的 C++ 接口。其主要功能包括：

1. **`OwnedBuffer`**: 表示拥有所有权的字节缓冲区，用于存储例如序列化后的 WebAssembly 模块数据。
2. **`CompiledWasmModule`**:  代表一个编译后的 WebAssembly 模块。它提供了序列化编译后模块的能力，并能获取原始的 WebAssembly 字节码。这允许 V8 在不同 `WasmModuleObject` 之间共享编译结果，提高效率。
3. **`WasmMemoryObject`**: 代表 JavaScript 中的 `WebAssembly.Memory` 对象。它允许访问底层的 `ArrayBuffer`。
4. **`WasmModuleObject`**: 代表 JavaScript 中的 `WebAssembly.Module` 对象。它提供了从编译后的模块重新创建 `WasmModuleObject` 的方法，以及编译 WebAssembly 字节码的能力。
5. **`WasmStreaming`**:  提供 WebAssembly 模块的流式编译接口。这允许在下载 WebAssembly 字节码的同时进行编译，提高加载速度。它允许接收字节块、完成编译或中止编译，并能设置编译模块的元数据。

### 文件类型判断

`v8/include/v8-wasm.h` 的文件扩展名是 `.h`，这是一个标准的 C++ 头文件扩展名。因此，它不是一个 Torque 源代码文件，Torque 文件的扩展名是 `.tq`。

### 与 JavaScript 的关系及举例

`v8/include/v8-wasm.h` 中定义的类和方法直接对应于 JavaScript 中 WebAssembly API 的实现。V8 引擎使用这些 C++ 接口来处理 JavaScript 代码中对 WebAssembly 模块的操作。

**JavaScript 示例:**

```javascript
// 编译一个 WebAssembly 模块
WebAssembly.compile(Uint8Array.from([0, 97, 115, 109, 1, 0, 0, 0]))
  .then(module => {
    console.log("WebAssembly 模块编译成功", module);
    // module 是一个 WasmModuleObject 的 JavaScript 表示
  });

// 实例化一个 WebAssembly 模块
WebAssembly.instantiate(Uint8Array.from([0, 97, 115, 109, 1, 0, 0, 0]))
  .then(instance => {
    console.log("WebAssembly 模块实例化成功", instance);
    // instance 是一个包含导出的 WebAssembly 实例
  });

// 创建一个 WebAssembly 内存
const memory = new WebAssembly.Memory({ initial: 1 });
console.log("WebAssembly 内存创建成功", memory);
// memory 是一个 WasmMemoryObject 的 JavaScript 表示

// 流式编译 WebAssembly 模块
fetch('module.wasm')
  .then(response => WebAssembly.compileStreaming(response))
  .then(module => {
    console.log("WebAssembly 模块流式编译成功", module);
  });
```

* `WebAssembly.compile()` 对应于 `WasmModuleObject::Compile()`。
* `WebAssembly.Module` 在 V8 内部由 `WasmModuleObject` 表示。
* `WebAssembly.Memory` 在 V8 内部由 `WasmMemoryObject` 表示。
* `WebAssembly.compileStreaming()` 的底层实现会使用 `WasmStreaming` 接口。

### 代码逻辑推理及假设输入输出

**场景：使用 `CompiledWasmModule` 进行序列化和反序列化**

**假设输入：**

1. 一个已经成功编译的 WebAssembly 模块，由 `CompiledWasmModule` 对象 `compiledModule` 表示。

**代码逻辑：**

1. 调用 `compiledModule.Serialize()` 方法。
2. `Serialize()` 方法会将编译后的模块数据转换为一个 `OwnedBuffer` 对象。
3. 可以将 `OwnedBuffer` 中的数据存储起来。
4. 未来，可以通过某种机制（不在本头文件中定义）将存储的数据反序列化回一个 `CompiledWasmModule` 对象，然后用于创建新的 `WasmModuleObject`，避免重新编译。

**假设输出：**

1. `compiledModule.Serialize()` 的输出是一个 `OwnedBuffer` 对象，其 `buffer` 成员指向包含序列化后模块数据的内存，`size` 成员表示数据大小。

**场景：使用 `WasmStreaming` 进行流式编译**

**假设输入：**

1. 一个 `WasmStreaming` 对象 `streaming`。
2. WebAssembly 模块的字节码分成了两个部分：`bytes1` 和 `bytes2`。

**代码逻辑：**

1. 调用 `streaming.OnBytesReceived(bytes1, size1)`，将第一部分字节码传递给 V8。
2. 调用 `streaming.OnBytesReceived(bytes2, size2)`，将第二部分字节码传递给 V8。
3. 调用 `streaming.Finish()`，告知 V8 所有字节已接收完毕。

**假设输出：**

1. 如果字节码是有效的 WebAssembly 模块，并且编译成功，则与此 `WasmStreaming` 对象关联的 Promise 将会被 resolve，其结果是一个 `WasmModuleObject`。
2. 如果字节码无效，或者在流式处理过程中发生错误，则 Promise 将会被 reject。

### 用户常见的编程错误

虽然用户不会直接操作 `v8/include/v8-wasm.h` 中定义的 C++ 类，但理解这些底层的概念有助于避免在使用 JavaScript WebAssembly API 时犯错。以下是一些与这些概念相关的常见编程错误：

1. **尝试编译无效的 WebAssembly 字节码：**

   ```javascript
   // 错误的魔数
   WebAssembly.compile(Uint8Array.from([1, 2, 3, 4]))
     .catch(error => console.error("编译错误:", error));
   ```
   V8 的 `WasmModuleObject::Compile()` 方法会检测字节码的有效性，如果无效则抛出错误。

2. **在流式编译中过早或错误地调用 `Finish()` 或 `Abort()`：**

   * 过早调用 `Finish()` 可能导致模块编译不完整。
   * 在已经 `Finish()` 或 `Abort()` 后再次调用会导致未定义的行为。
   * `Abort()` 应该在发生错误时调用，以清理资源并拒绝相关的 Promise。

3. **假设 `WebAssembly.Memory` 的 `buffer` 会自动增长：**

   ```javascript
   const memory = new WebAssembly.Memory({ initial: 1 });
   const buffer = new Uint8Array(memory.buffer);
   // 如果 WebAssembly 代码尝试写入超出初始大小的内存，会导致错误。
   ```
   用户需要显式地增长内存，通过 `WebAssembly.Memory.grow()` 方法，这对应于 V8 内部对内存的管理。

4. **混淆 `WebAssembly.compile()` 和 `WebAssembly.instantiate()`：**

   * `compile()` 只负责编译，生成 `WebAssembly.Module` 对象。
   * `instantiate()` 负责编译并实例化，生成包含导出函数的对象。
   * 用户需要根据需求选择合适的方法。

5. **在流式编译中使用不完整的字节流：**

   ```javascript
   fetch('module.wasm')
     .then(response => response.body.getReader().read()) // 只读取一部分
     .then(result => WebAssembly.compile(result.value)); // 可能导致编译失败
   ```
   流式编译需要完整的字节流才能成功，`WasmStreaming` 接口的 `OnBytesReceived` 方法被设计为逐步接收字节。

理解 `v8/include/v8-wasm.h` 中定义的接口有助于理解 V8 引擎如何处理 WebAssembly，从而更好地理解和调试 JavaScript WebAssembly 代码。

Prompt: 
```
这是目录为v8/include/v8-wasm.h的一个v8源代码， 请列举一下它的功能, 
如果v8/include/v8-wasm.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDE_V8_WASM_H_
#define INCLUDE_V8_WASM_H_

#include <functional>
#include <memory>
#include <string>

#include "v8-internal.h"      // NOLINT(build/include_directory)
#include "v8-local-handle.h"  // NOLINT(build/include_directory)
#include "v8-memory-span.h"   // NOLINT(build/include_directory)
#include "v8-object.h"        // NOLINT(build/include_directory)
#include "v8config.h"         // NOLINT(build/include_directory)

namespace v8 {

class ArrayBuffer;
class Promise;

namespace internal {
namespace wasm {
class NativeModule;
class StreamingDecoder;
}  // namespace wasm
}  // namespace internal

/**
 * An owned byte buffer with associated size.
 */
struct OwnedBuffer {
  std::unique_ptr<const uint8_t[]> buffer;
  size_t size = 0;
  OwnedBuffer(std::unique_ptr<const uint8_t[]> buffer, size_t size)
      : buffer(std::move(buffer)), size(size) {}
  OwnedBuffer() = default;
};

// Wrapper around a compiled WebAssembly module, which is potentially shared by
// different WasmModuleObjects.
class V8_EXPORT CompiledWasmModule {
 public:
  /**
   * Serialize the compiled module. The serialized data does not include the
   * wire bytes.
   */
  OwnedBuffer Serialize();

  /**
   * Get the (wasm-encoded) wire bytes that were used to compile this module.
   */
  MemorySpan<const uint8_t> GetWireBytesRef();

  const std::string& source_url() const { return source_url_; }

 private:
  friend class WasmModuleObject;
  friend class WasmStreaming;

  explicit CompiledWasmModule(std::shared_ptr<internal::wasm::NativeModule>,
                              const char* source_url, size_t url_length);

  const std::shared_ptr<internal::wasm::NativeModule> native_module_;
  const std::string source_url_;
};

// An instance of WebAssembly.Memory.
class V8_EXPORT WasmMemoryObject : public Object {
 public:
  WasmMemoryObject() = delete;

  /**
   * Returns underlying ArrayBuffer.
   */
  Local<ArrayBuffer> Buffer();

  V8_INLINE static WasmMemoryObject* Cast(Value* value) {
#ifdef V8_ENABLE_CHECKS
    CheckCast(value);
#endif
    return static_cast<WasmMemoryObject*>(value);
  }

 private:
  static void CheckCast(Value* object);
};

// An instance of WebAssembly.Module.
class V8_EXPORT WasmModuleObject : public Object {
 public:
  WasmModuleObject() = delete;

  /**
   * Efficiently re-create a WasmModuleObject, without recompiling, from
   * a CompiledWasmModule.
   */
  static MaybeLocal<WasmModuleObject> FromCompiledModule(
      Isolate* isolate, const CompiledWasmModule&);

  /**
   * Get the compiled module for this module object. The compiled module can be
   * shared by several module objects.
   */
  CompiledWasmModule GetCompiledModule();

  /**
   * Compile a Wasm module from the provided uncompiled bytes.
   */
  static MaybeLocal<WasmModuleObject> Compile(
      Isolate* isolate, MemorySpan<const uint8_t> wire_bytes);

  V8_INLINE static WasmModuleObject* Cast(Value* value) {
#ifdef V8_ENABLE_CHECKS
    CheckCast(value);
#endif
    return static_cast<WasmModuleObject*>(value);
  }

 private:
  static void CheckCast(Value* obj);
};

/**
 * The V8 interface for WebAssembly streaming compilation. When streaming
 * compilation is initiated, V8 passes a {WasmStreaming} object to the embedder
 * such that the embedder can pass the input bytes for streaming compilation to
 * V8.
 */
class V8_EXPORT WasmStreaming final {
 public:
  static constexpr internal::ExternalPointerTag kManagedTag =
      internal::kWasmWasmStreamingTag;
  class WasmStreamingImpl;

  explicit WasmStreaming(std::unique_ptr<WasmStreamingImpl> impl);

  ~WasmStreaming();

  /**
   * Pass a new chunk of bytes to WebAssembly streaming compilation.
   * The buffer passed into {OnBytesReceived} is owned by the caller.
   */
  void OnBytesReceived(const uint8_t* bytes, size_t size);

  /**
   * {Finish} should be called after all received bytes where passed to
   * {OnBytesReceived} to tell V8 that there will be no more bytes. {Finish}
   * must not be called after {Abort} has been called already.
   * If {can_use_compiled_module} is true and {SetCompiledModuleBytes} was
   * previously called, the compiled module bytes can be used.
   * If {can_use_compiled_module} is false, the compiled module bytes previously
   * set by {SetCompiledModuleBytes} should not be used.
   */
  void Finish(bool can_use_compiled_module = true);

  /**
   * Abort streaming compilation. If {exception} has a value, then the promise
   * associated with streaming compilation is rejected with that value. If
   * {exception} does not have value, the promise does not get rejected.
   * {Abort} must not be called repeatedly, or after {Finish}.
   */
  void Abort(MaybeLocal<Value> exception);

  /**
   * Passes previously compiled module bytes. This must be called before
   * {OnBytesReceived}, {Finish}, or {Abort}. Returns true if the module bytes
   * can be used, false otherwise. The buffer passed via {bytes} and {size}
   * is owned by the caller. If {SetCompiledModuleBytes} returns true, the
   * buffer must remain valid until either {Finish} or {Abort} completes.
   * The compiled module bytes should not be used until {Finish(true)} is
   * called, because they can be invalidated later by {Finish(false)}.
   */
  bool SetCompiledModuleBytes(const uint8_t* bytes, size_t size);

  /**
   * Sets a callback which is called whenever a significant number of new
   * functions are ready for serialization.
   */
  void SetMoreFunctionsCanBeSerializedCallback(
      std::function<void(CompiledWasmModule)>);

  /*
   * Sets the UTF-8 encoded source URL for the {Script} object. This must be
   * called before {Finish}.
   */
  void SetUrl(const char* url, size_t length);

  /**
   * Unpacks a {WasmStreaming} object wrapped in a  {Managed} for the embedder.
   * Since the embedder is on the other side of the API, it cannot unpack the
   * {Managed} itself.
   */
  static std::shared_ptr<WasmStreaming> Unpack(Isolate* isolate,
                                               Local<Value> value);

 private:
  std::unique_ptr<WasmStreamingImpl> impl_;
};

}  // namespace v8

#endif  // INCLUDE_V8_WASM_H_

"""

```