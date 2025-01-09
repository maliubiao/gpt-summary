Response:
Let's break down the thought process for analyzing this `api.h` file.

1. **Understanding the Goal:** The request asks for the functionality of the header file, whether it's related to Torque, its relation to JavaScript, code logic, and common programming errors.

2. **Initial Scan and High-Level Overview:**  The `#ifndef V8_API_API_H_` and `#define V8_API_API_H_` tell us this is a header guard, preventing multiple inclusions. The `#include` directives give us clues about the file's purpose. It includes various `v8-*.h` files (likely public API headers) and internal V8 headers (`src/...`). This suggests `api.h` bridges the public API with the internal V8 implementation. The copyright notice confirms it's part of the V8 project.

3. **Keyword/Structure Identification:**  Start looking for key classes, structs, enums, macros, and function declarations. This helps categorize the functionalities.

    * **Namespaces:**  `v8` and `v8::internal`, `v8::debug`. This indicates different levels of API exposure and debugging utilities.
    * **Classes:** `ApiFunction`, `RegisteredExtension`, `Utils`, `HandleScopeImplementer`, `ExternalMemoryAccounterBase`. These are central building blocks, each with specific responsibilities.
    * **Macros:** `TO_LOCAL_LIST`, `TO_LOCAL_NAME_LIST`, `OPEN_HANDLE_LIST`. Macros that generate code are important for understanding patterns and common operations.
    * **Templates:**  `ToCData`, `FromCData`. These suggest dealing with raw data pointers and type conversions.
    * **Function Declarations:** Lots of `static inline` functions within `Utils`. These are likely helper functions for converting between different V8 object representations.
    * **Friend Classes:** The `HandleScopeImplementer` section uses `friend class`, indicating tight coupling with `HandleScope` and `PersistentHandlesScope`.

4. **Analyzing Key Components:**  Dive deeper into the purpose of the identified classes and macros.

    * **`ApiFunction`:**  Holds a raw memory address. Likely used to represent native functions exposed to JavaScript.
    * **`RegisteredExtension`:**  Manages V8 extensions. Extensions add custom functionality.
    * **`Utils`:**  A collection of static helper functions. The `ToLocal*` and `OpenHandle*` functions are crucial for converting between internal and external representations of V8 objects (like `internal::JSObject` to `v8::Object`). The `ApiCheck` function points towards API usage validation.
    * **`TO_LOCAL_LIST` and `OPEN_HANDLE_LIST`:** These macros define a pattern for converting various internal V8 types to their public API counterparts. This reveals a core mechanism for exposing internal data to the external API.
    * **`HandleScopeImplementer`:** This class is more complex and manages the lifetime of V8 objects within a scope. Concepts like `EnteredContext`, `SavedContext`, and `blocks_` (for memory management) are key. The threading support is also notable.
    * **Templates `ToCData` and `FromCData`:**  These deal with converting V8 objects to and from raw C data pointers, often used for interacting with external C/C++ code.
    * **`ExternalMemoryAccounterBase`:**  Related to tracking external memory allocated by V8 embeddings, important for memory management and avoiding leaks.

5. **Connecting to JavaScript Functionality:** Now, link the analyzed components to JavaScript concepts.

    * **`ApiFunction` and `FunctionCallbackInfo`:** Directly relate to how native C++ functions are exposed as JavaScript functions.
    * **`RegisteredExtension`:** Allows embedding custom JavaScript functions or objects.
    * **`Template`, `FunctionTemplate`, `ObjectTemplate`:** These are used in the V8 C++ API to define the structure and behavior of JavaScript objects and functions.
    * **`Local<>` and Handles:** The conversion functions in `Utils` and the concepts in `HandleScopeImplementer` are fundamental to managing the lifetime of JavaScript objects created or accessed from C++. The explanation of automatic garbage collection and the need for handles is crucial here.
    * **`Promise`, `Map`, `Set`, `ArrayBuffer`, etc.:** The `TO_LOCAL_LIST` includes many of these, demonstrating how C++ code can interact with these fundamental JavaScript data structures.

6. **Considering Torque:** The prompt specifically asks about Torque. The file name `api.h` doesn't end in `.tq`, so it's not a Torque source file. However, Torque often generates C++ code that might use these API elements.

7. **Identifying Code Logic and Examples:** Look for specific functions or patterns that suggest logical operations. The conversion functions in `Utils` are examples of code logic. Illustrate this with JavaScript examples demonstrating the interaction between the C++ API and JavaScript.

8. **Thinking About Common Programming Errors:**  Based on the functionality identified, consider common pitfalls:

    * **Incorrect Handle Usage:**  Forgetting to use `Local` or handles correctly, leading to dangling pointers or crashes.
    * **Memory Leaks:**  Not properly accounting for external memory.
    * **Context Issues:** Incorrectly entering or leaving contexts.
    * **Type Mismatches:**  Using the wrong conversion functions.

9. **Structuring the Output:** Organize the findings logically, covering the requested points:

    * **Functionality:** Provide a high-level summary and then detail the purpose of key components.
    * **Torque:**  Address the specific question.
    * **JavaScript Relationship:** Explain the connections and provide illustrative JavaScript examples.
    * **Code Logic:**  Focus on the conversion functions and give input/output examples (even if conceptual).
    * **Common Errors:** Provide concrete examples of programming mistakes.

10. **Review and Refine:** Read through the analysis, ensuring clarity, accuracy, and completeness. Check for any missed points or areas that could be explained better. For instance, initially, I might have just listed the classes, but the deeper analysis involves understanding their *purpose* and how they interact. Similarly, simply saying "converts types" for the `Utils` functions isn't enough; explaining the *why* and *how* of these conversions is important.
好的，让我们来分析一下 `v8/src/api/api.h` 这个 V8 源代码文件。

**文件类型判断:**

首先，文件名是 `api.h`，以 `.h` 结尾，这表明它是一个 C++ 头文件，而不是以 `.tq` 结尾的 Torque 源代码文件。因此，这个文件不是 V8 Torque 源代码。

**功能列举:**

`v8/src/api/api.h` 是 V8 JavaScript 引擎的公共 API 的核心头文件之一。它定义了 V8 提供的各种 C++ 接口，供外部程序（例如 Node.js、Chromium 等）嵌入和使用 V8 引擎的功能。其主要功能包括：

1. **定义 V8 的核心类和概念:**  它声明了许多代表 V8 内部对象的 C++ 类，例如：
   - `v8::Value`:  表示 JavaScript 中的值（数字、字符串、对象等）。
   - `v8::Object`: 表示 JavaScript 对象。
   - `v8::Function`: 表示 JavaScript 函数。
   - `v8::String`: 表示 JavaScript 字符串。
   - `v8::Context`: 表示 JavaScript 的执行上下文。
   - `v8::Isolate`: 表示一个独立的 V8 引擎实例。
   - `v8::Template`, `v8::FunctionTemplate`, `v8::ObjectTemplate`: 用于创建 JavaScript 对象和函数的模板。
   - `v8::Array`, `v8::Map`, `v8::Set`, `v8::Promise`, `v8::BigInt`, `v8::ArrayBuffer`, `v8::TypedArray`:  表示 JavaScript 内置对象。
   - 以及与 WebAssembly 相关的类 (通过 `IF_WASM` 宏)。

2. **提供类型转换和操作的工具函数:**  它包含 `v8::Utils` 类，其中定义了许多静态内联函数，用于在 V8 的内部表示和外部 API 表示之间进行类型转换，例如：
   - `Utils::ToLocal<T>(...)`: 将 V8 内部对象转换为 `v8::Local<T>`，`v8::Local` 是一个智能指针，用于管理 V8 堆上的对象生命周期。
   - `Utils::OpenHandle(...)`: 将 V8 内部对象指针包装成 `v8::internal::Handle` 或 `v8::internal::DirectHandle`，用于 V8 内部操作。

3. **定义与 C++ 回调相关的接口:**  它包含了与 C++ 函数作为 JavaScript 回调函数使用的相关类，例如 `v8::FunctionCallbackInfo`。

4. **定义扩展机制:**  `v8::Extension` 和 `v8::RegisteredExtension` 允许开发者向 V8 引擎添加自定义的功能。

5. **定义作用域管理:** `v8::internal::HandleScopeImplementer` 是 V8 内部用于管理对象生命周期和作用域的关键类。虽然它在 `internal` 命名空间下，但 `api.h` 中定义了一些与其交互的接口。

6. **定义内存管理相关的接口:**  `v8::internal::ExternalMemoryAccounterBase` 用于跟踪 V8 引擎外部分配的内存。

**与 JavaScript 功能的关系及举例:**

`v8/src/api/api.h` 中定义的类和函数是连接 C++ 代码和 JavaScript 代码的桥梁。通过这些接口，C++ 代码可以：

- **创建和操作 JavaScript 对象:**
  ```javascript
  // C++ 代码中使用 v8 API 创建一个 JavaScript 对象
  v8::Local<v8::ObjectTemplate> object_template = v8::ObjectTemplate::New(isolate);
  v8::Local<v8::Object> obj = object_template->NewInstance(context).ToLocalChecked();

  // C++ 代码中获取或设置 JavaScript 对象的属性
  v8::Local<v8::String> key = v8::String::NewFromUtf8Literal(isolate, "name");
  v8::Local<v8::String> value = v8::String::NewFromUtf8Literal(isolate, "V8");
  obj->Set(context, key, value).Check();
  ```

- **调用 JavaScript 函数:**
  ```javascript
  // 假设 JavaScript 中有这样一个函数
  // function add(a, b) { return a + b; }

  // C++ 代码中获取该函数
  v8::Local<v8::String> function_name = v8::String::NewFromUtf8Literal(isolate, "add");
  v8::Local<v8::Value> function_value;
  context->Global()->Get(context, function_name).ToLocal(&function_value);
  v8::Local<v8::Function> function = v8::Local<v8::Function>::Cast(function_value);

  // C++ 代码中调用该函数
  v8::Local<v8::Value> args[2];
  args[0] = v8::Number::New(isolate, 10);
  args[1] = v8::Number::New(isolate, 5);
  v8::Local<v8::Value> result;
  function->Call(context, context->Global(), 2, args).ToLocal(&result);
  double sum = result->NumberValue(context).FromJust();
  ```

- **将 C++ 函数暴露给 JavaScript:**
  ```c++
  // C++ 函数
  void PrintHello(const v8::FunctionCallbackInfo<v8::Value>& args) {
    v8::Isolate* isolate = args.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    v8::Local<v8::String> message = v8::String::NewFromUtf8Literal(isolate, "Hello from C++!");
    v8::Local<v8::Value> console_log = context->Global()->Get(context, v8::String::NewFromUtf8Literal(isolate, "console")).ToLocalChecked()->ToObject(context).ToLocalChecked()->Get(context, v8::String::NewFromUtf8Literal(isolate, "log")).ToLocalChecked();
    v8::Function::Cast(*console_log)->Call(context, context->Global(), 1, &message).Check();
  }

  // 在 C++ 中注册该函数到 JavaScript 环境
  v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate);
  global->Set(v8::String::NewFromUtf8Literal(isolate, "printHello"), v8::FunctionTemplate::New(isolate, PrintHello));
  ```
  然后在 JavaScript 中就可以调用 `printHello()`。

**代码逻辑推理（假设输入与输出）:**

让我们以 `Utils::ToLocal` 函数为例，假设有以下 C++ 代码：

```c++
v8::internal::Isolate* i_isolate = ...; // 获取 V8 内部的 Isolate
v8::internal::Handle<v8::internal::JSObject> internal_obj = i_isolate->factory()->NewJSObject(nullptr);

// 将内部的 JSObject 转换为 v8::Local<v8::Object>
v8::Local<v8::Object> public_obj = v8::Utils::ToLocal(internal_obj);
```

**假设输入:**

- `internal_obj`: 一个指向 V8 内部堆上的 `v8::internal::JSObject` 对象的句柄。

**输出:**

- `public_obj`: 一个 `v8::Local<v8::Object>` 对象，它是一个智能指针，指向与 `internal_obj` 指向的同一个 JavaScript 对象。这个 `public_obj` 可以安全地在 V8 的公共 API 中使用。

**代码逻辑:**

`Utils::ToLocal` 函数的内部逻辑会涉及到：

1. **类型转换:** 将内部的 `v8::internal::JSObject` 指针转换为公共 API 的 `v8::Object` 指针。
2. **`v8::Local` 的创建:**  创建一个 `v8::Local<v8::Object>` 智能指针，并将转换后的指针存储在其中。`v8::Local` 会将其指向的对象注册到当前的作用域中，以便 V8 的垃圾回收器知道这个对象正在被使用，从而避免过早回收。

**用户常见的编程错误举例:**

1. **忘记使用 `v8::Local` 或不正确地管理 `v8::Local` 的生命周期:**

   ```c++
   v8::Isolate* isolate = ...;
   v8::Local<v8::String> str = v8::String::NewFromUtf8Literal(isolate, "hello");
   // ... 一些代码 ...
   // 忘记让 str 超出作用域，或者错误地使用了 str 指向的内存
   ```
   **错误:**  直接使用原始指针或在 `v8::Local` 超出作用域后继续使用它，可能导致访问已释放的内存或引起其他内存安全问题。V8 的垃圾回收器可能会在 `v8::Local` 不再存在时回收对象。

2. **在错误的 `v8::Context` 中操作对象:**

   ```c++
   v8::Isolate* isolate = ...;
   v8::Local<v8::Context> context1 = ...;
   v8::Local<v8::Context> context2 = ...;

   v8::Context::Scope scope1(context1);
   v8::Local<v8::Object> obj = v8::Object::New(isolate);

   // 尝试在 context2 中操作 context1 中创建的对象
   v8::Context::Scope scope2(context2);
   v8::Local<v8::String> key = v8::String::NewFromUtf8Literal(isolate, "name");
   // 错误：obj 是在 context1 中创建的
   obj->Set(context2, key, v8::String::NewFromUtf8Literal(isolate, "value"));
   ```
   **错误:** JavaScript 对象属于特定的上下文。尝试在错误的上下文中访问或修改对象会导致错误或未定义的行为。

3. **类型转换错误:**

   ```c++
   v8::Isolate* isolate = ...;
   v8::Local<v8::Value> value = v8::String::NewFromUtf8Literal(isolate, "123");
   // 错误地将字符串转换为数字，可能抛出异常或返回错误值
   int number = value->Int32Value(isolate->GetCurrentContext()).FromJust();
   ```
   **错误:**  必须确保 `v8::Value` 实际包含期望的类型，否则类型转换函数（如 `Int32Value`）可能会失败。应该先使用 `IsNumber()`, `IsString()` 等方法进行类型检查。

4. **不正确地使用 C++ 回调:**

   ```c++
   void MyCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
       // 忘记检查参数数量
       v8::Local<v8::Value> arg0 = args[0];
       // ...
   }
   ```
   **错误:**  在 C++ 回调函数中，必须仔细检查传入的参数数量和类型，以避免访问越界或类型错误。

总结来说，`v8/src/api/api.h` 是 V8 引擎与外部 C++ 代码交互的关键接口定义文件，它定义了用于创建、操作 JavaScript 对象和与 V8 引擎进行通信所需的各种类和函数。理解这个文件对于嵌入和使用 V8 引擎至关重要。

Prompt: 
```
这是目录为v8/src/api/api.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/api/api.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_API_API_H_
#define V8_API_API_H_

#include <memory>

#include "include/v8-container.h"
#include "include/v8-external.h"
#include "include/v8-function-callback.h"
#include "include/v8-proxy.h"
#include "include/v8-typed-array.h"
#include "include/v8-wasm.h"
#include "src/base/contextual.h"
#include "src/execution/isolate.h"
#include "src/objects/bigint.h"
#include "src/objects/contexts.h"
#include "src/objects/js-array-buffer.h"
#include "src/objects/js-collection.h"
#include "src/objects/js-generator.h"
#include "src/objects/js-promise.h"
#include "src/objects/js-proxy.h"
#include "src/objects/objects.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/source-text-module.h"
#include "src/objects/templates.h"
#include "src/utils/detachable-vector.h"

namespace v8 {

class DictionaryTemplate;
class Extension;
class Signature;
class Template;

namespace internal {
class JSArrayBufferView;
class JSFinalizationRegistry;
}  // namespace internal

namespace debug {
class AccessorPair;
class GeneratorObject;
class ScriptSource;
class Script;
class EphemeronTable;
}  // namespace debug

template <typename T, internal::ExternalPointerTag tag>
inline T ToCData(i::Isolate* isolate,
                 v8::internal::Tagged<v8::internal::Object> obj);
template <internal::ExternalPointerTag tag>
inline v8::internal::Address ToCData(
    v8::internal::Isolate* isolate,
    v8::internal::Tagged<v8::internal::Object> obj);

template <internal::ExternalPointerTag tag, typename T>
inline v8::internal::Handle<
    v8::internal::UnionOf<v8::internal::Smi, v8::internal::Foreign>>
FromCData(v8::internal::Isolate* isolate, T obj);

template <internal::ExternalPointerTag tag>
inline v8::internal::Handle<
    v8::internal::UnionOf<v8::internal::Smi, v8::internal::Foreign>>
FromCData(v8::internal::Isolate* isolate, v8::internal::Address obj);

class ApiFunction {
 public:
  explicit ApiFunction(v8::internal::Address addr) : addr_(addr) {}
  v8::internal::Address address() { return addr_; }

 private:
  v8::internal::Address addr_;
};

class RegisteredExtension {
 public:
  static void Register(std::unique_ptr<Extension>);
  static void UnregisterAll();
  Extension* extension() const { return extension_.get(); }
  RegisteredExtension* next() const { return next_; }
  static RegisteredExtension* first_extension() { return first_extension_; }

 private:
  explicit RegisteredExtension(Extension*);
  explicit RegisteredExtension(std::unique_ptr<Extension>);
  std::unique_ptr<Extension> extension_;
  RegisteredExtension* next_ = nullptr;
  static RegisteredExtension* first_extension_;
};

#define TO_LOCAL_LIST(V)                                 \
  V(ToLocal, AccessorPair, debug::AccessorPair)          \
  V(ToLocal, NativeContext, Context)                     \
  V(ToLocal, Object, Value)                              \
  V(ToLocal, Module, Module)                             \
  V(ToLocal, Name, Name)                                 \
  V(ToLocal, String, String)                             \
  V(ToLocal, Symbol, Symbol)                             \
  V(ToLocal, JSRegExp, RegExp)                           \
  V(ToLocal, JSReceiver, Object)                         \
  V(ToLocal, JSObject, Object)                           \
  V(ToLocal, JSFunction, Function)                       \
  V(ToLocal, JSArray, Array)                             \
  V(ToLocal, JSMap, Map)                                 \
  V(ToLocal, JSSet, Set)                                 \
  V(ToLocal, JSProxy, Proxy)                             \
  V(ToLocal, JSArrayBuffer, ArrayBuffer)                 \
  V(ToLocal, JSArrayBufferView, ArrayBufferView)         \
  V(ToLocal, JSDataView, DataView)                       \
  V(ToLocal, JSRabGsabDataView, DataView)                \
  V(ToLocal, JSTypedArray, TypedArray)                   \
  V(ToLocalShared, JSArrayBuffer, SharedArrayBuffer)     \
  V(ToLocal, FunctionTemplateInfo, FunctionTemplate)     \
  V(ToLocal, ObjectTemplateInfo, ObjectTemplate)         \
  V(ToLocal, DictionaryTemplateInfo, DictionaryTemplate) \
  V(SignatureToLocal, FunctionTemplateInfo, Signature)   \
  V(MessageToLocal, Object, Message)                     \
  V(PromiseToLocal, JSObject, Promise)                   \
  V(StackTraceToLocal, StackTraceInfo, StackTrace)       \
  V(StackFrameToLocal, StackFrameInfo, StackFrame)       \
  V(NumberToLocal, Object, Number)                       \
  V(IntegerToLocal, Object, Integer)                     \
  V(Uint32ToLocal, Object, Uint32)                       \
  V(ToLocal, BigInt, BigInt)                             \
  V(ExternalToLocal, JSObject, External)                 \
  V(CallableToLocal, JSReceiver, Function)               \
  V(ToLocalPrimitive, Object, Primitive)                 \
  V(FixedArrayToLocal, FixedArray, FixedArray)           \
  V(PrimitiveArrayToLocal, FixedArray, PrimitiveArray)   \
  V(ToLocal, ScriptOrModule, ScriptOrModule)             \
  IF_WASM(V, ToLocal, WasmModuleObject, WasmModuleObject)

#define TO_LOCAL_NAME_LIST(V) \
  V(ToLocal)                  \
  V(ToLocalShared)            \
  V(SignatureToLocal)         \
  V(MessageToLocal)           \
  V(PromiseToLocal)           \
  V(StackTraceToLocal)        \
  V(StackFrameToLocal)        \
  V(NumberToLocal)            \
  V(IntegerToLocal)           \
  V(Uint32ToLocal)            \
  V(ExternalToLocal)          \
  V(CallableToLocal)          \
  V(ToLocalPrimitive)         \
  V(FixedArrayToLocal)        \
  V(PrimitiveArrayToLocal)

#define OPEN_HANDLE_LIST(V)                     \
  V(Template, TemplateInfo)                     \
  V(FunctionTemplate, FunctionTemplateInfo)     \
  V(ObjectTemplate, ObjectTemplateInfo)         \
  V(DictionaryTemplate, DictionaryTemplateInfo) \
  V(Signature, FunctionTemplateInfo)            \
  V(Data, Object)                               \
  V(Number, Number)                             \
  V(RegExp, JSRegExp)                           \
  V(Object, JSReceiver)                         \
  V(Array, JSArray)                             \
  V(Map, JSMap)                                 \
  V(Set, JSSet)                                 \
  V(ArrayBuffer, JSArrayBuffer)                 \
  V(ArrayBufferView, JSArrayBufferView)         \
  V(TypedArray, JSTypedArray)                   \
  V(Uint8Array, JSTypedArray)                   \
  V(Uint8ClampedArray, JSTypedArray)            \
  V(Int8Array, JSTypedArray)                    \
  V(Uint16Array, JSTypedArray)                  \
  V(Int16Array, JSTypedArray)                   \
  V(Uint32Array, JSTypedArray)                  \
  V(Int32Array, JSTypedArray)                   \
  V(Float16Array, JSTypedArray)                 \
  V(Float32Array, JSTypedArray)                 \
  V(Float64Array, JSTypedArray)                 \
  V(DataView, JSDataViewOrRabGsabDataView)      \
  V(SharedArrayBuffer, JSArrayBuffer)           \
  V(Name, Name)                                 \
  V(String, String)                             \
  V(Symbol, Symbol)                             \
  V(Script, JSFunction)                         \
  V(UnboundModuleScript, SharedFunctionInfo)    \
  V(UnboundScript, SharedFunctionInfo)          \
  V(Module, Module)                             \
  V(Function, JSReceiver)                       \
  V(CompileHintsCollector, Script)              \
  V(Message, JSMessageObject)                   \
  V(Context, NativeContext)                     \
  V(External, Object)                           \
  V(StackTrace, StackTraceInfo)                 \
  V(StackFrame, StackFrameInfo)                 \
  V(Proxy, JSProxy)                             \
  V(debug::GeneratorObject, JSGeneratorObject)  \
  V(debug::ScriptSource, HeapObject)            \
  V(debug::Script, Script)                      \
  V(debug::EphemeronTable, EphemeronHashTable)  \
  V(debug::AccessorPair, AccessorPair)          \
  V(Promise, JSPromise)                         \
  V(Primitive, Object)                          \
  V(PrimitiveArray, FixedArray)                 \
  V(BigInt, BigInt)                             \
  V(ScriptOrModule, ScriptOrModule)             \
  V(FixedArray, FixedArray)                     \
  V(ModuleRequest, ModuleRequest)               \
  IF_WASM(V, WasmMemoryObject, WasmMemoryObject)

class Utils {
 public:
  static V8_INLINE bool ApiCheck(bool condition, const char* location,
                                 const char* message) {
    if (V8_UNLIKELY(!condition)) {
      Utils::ReportApiFailure(location, message);
    }
    return condition;
  }
  static void ReportOOMFailure(v8::internal::Isolate* isolate,
                               const char* location, const OOMDetails& details);

  // TODO(42203211): It would be nice if we could keep only a version with
  // direct handles. But the implicit conversion from handles to direct handles
  // combined with the heterogeneous copy constructor for direct handles make
  // this ambiguous.
  // TODO(42203211): Use C++20 concepts instead of the enable_if trait, when
  // they are fully supported in V8.
#define DECLARE_TO_LOCAL(Name)                                   \
  template <template <typename> typename HandleType, typename T, \
            typename = std::enable_if_t<std::is_convertible_v<   \
                HandleType<T>, v8::internal::DirectHandle<T>>>>  \
  static inline auto Name(HandleType<T> obj);

  TO_LOCAL_NAME_LIST(DECLARE_TO_LOCAL)

#define DECLARE_TO_LOCAL_TYPED_ARRAY(Type, typeName, TYPE, ctype) \
  static inline Local<v8::Type##Array> ToLocal##Type##Array(      \
      v8::internal::DirectHandle<v8::internal::JSTypedArray> obj);

  TYPED_ARRAYS(DECLARE_TO_LOCAL_TYPED_ARRAY)

#define DECLARE_OPEN_HANDLE(From, To)                                          \
  static inline v8::internal::Handle<v8::internal::To> OpenHandle(             \
      const From* that, bool allow_empty_handle = false);                      \
  static inline v8::internal::DirectHandle<v8::internal::To> OpenDirectHandle( \
      const From* that, bool allow_empty_handle = false);                      \
  static inline v8::internal::IndirectHandle<v8::internal::To>                 \
  OpenIndirectHandle(const From* that, bool allow_empty_handle = false);

  OPEN_HANDLE_LIST(DECLARE_OPEN_HANDLE)

#undef DECLARE_OPEN_HANDLE
#undef DECLARE_TO_LOCAL_TYPED_ARRAY
#undef DECLARE_TO_LOCAL

  template <class From, class To>
  static inline Local<To> Convert(v8::internal::DirectHandle<From> obj);

  template <class T>
  static inline v8::internal::Handle<v8::internal::Object> OpenPersistent(
      const v8::PersistentBase<T>& persistent) {
    return v8::internal::Handle<v8::internal::Object>(persistent.slot());
  }

  template <class T>
  static inline v8::internal::Handle<v8::internal::Object> OpenPersistent(
      v8::Persistent<T>* persistent) {
    return OpenPersistent(*persistent);
  }

  template <class From, class To>
  static inline v8::internal::Handle<To> OpenHandle(v8::Local<From> handle) {
    return OpenHandle(*handle);
  }

  template <class From, class To>
  static inline v8::internal::DirectHandle<To> OpenDirectHandle(
      v8::Local<From> handle) {
    return OpenDirectHandle(*handle);
  }

 private:
  V8_NOINLINE V8_PRESERVE_MOST static void ReportApiFailure(
      const char* location, const char* message);

#define DECLARE_TO_LOCAL_PRIVATE(Name, From, To) \
  static inline Local<v8::To> Name##_helper(     \
      v8::internal::DirectHandle<v8::internal::From> obj);

  TO_LOCAL_LIST(DECLARE_TO_LOCAL_PRIVATE)
#undef DECLARE_TO_LOCAL_PRIVATE
};

template <class T>
inline T* ToApi(v8::internal::Handle<v8::internal::Object> obj) {
  return reinterpret_cast<T*>(obj.location());
}

template <class T>
inline v8::Local<T> ToApiHandle(
    v8::internal::DirectHandle<v8::internal::Object> obj) {
  return Utils::Convert<v8::internal::Object, T>(obj);
}

template <class T>
inline bool ToLocal(v8::internal::MaybeHandle<v8::internal::Object> maybe,
                    Local<T>* local) {
  v8::internal::Handle<v8::internal::Object> handle;
  if (maybe.ToHandle(&handle)) {
    *local = Utils::Convert<v8::internal::Object, T>(handle);
    return true;
  }
  return false;
}

namespace internal {

class PersistentHandles;

// This class is here in order to be able to declare it a friend of
// HandleScope.  Moving these methods to be members of HandleScope would be
// neat in some ways, but it would expose internal implementation details in
// our public header file, which is undesirable.
//
// An isolate has a single instance of this class to hold the current thread's
// data. In multithreaded V8 programs this data is copied in and out of storage
// so that the currently executing thread always has its own copy of this
// data.
class HandleScopeImplementer {
 public:
  class V8_NODISCARD EnteredContextRewindScope {
   public:
    explicit EnteredContextRewindScope(HandleScopeImplementer* hsi)
        : hsi_(hsi), saved_entered_context_count_(hsi->EnteredContextCount()) {}

    ~EnteredContextRewindScope() {
      DCHECK_LE(saved_entered_context_count_, hsi_->EnteredContextCount());
      while (saved_entered_context_count_ < hsi_->EnteredContextCount())
        hsi_->LeaveContext();
    }

   private:
    HandleScopeImplementer* hsi_;
    size_t saved_entered_context_count_;
  };

  explicit HandleScopeImplementer(Isolate* isolate)
      : isolate_(isolate), spare_(nullptr) {}

  ~HandleScopeImplementer() { DeleteArray(spare_); }

  HandleScopeImplementer(const HandleScopeImplementer&) = delete;
  HandleScopeImplementer& operator=(const HandleScopeImplementer&) = delete;

  // Threading support for handle data.
  static int ArchiveSpacePerThread();
  char* RestoreThread(char* from);
  char* ArchiveThread(char* to);
  void FreeThreadResources();

  // Garbage collection support.
  V8_EXPORT_PRIVATE void Iterate(v8::internal::RootVisitor* v);
  V8_EXPORT_PRIVATE static char* Iterate(v8::internal::RootVisitor* v,
                                         char* data);

  inline internal::Address* GetSpareOrNewBlock();
  inline void DeleteExtensions(internal::Address* prev_limit);

  inline void EnterContext(Tagged<NativeContext> context);
  inline void LeaveContext();
  inline bool LastEnteredContextWas(Tagged<NativeContext> context);
  inline size_t EnteredContextCount() const { return entered_contexts_.size(); }

  // Returns the last entered context or an empty handle if no
  // contexts have been entered.
  inline Handle<NativeContext> LastEnteredContext();

  inline void SaveContext(Tagged<Context> context);
  inline Tagged<Context> RestoreContext();
  inline bool HasSavedContexts();

  inline DetachableVector<Address*>* blocks() { return &blocks_; }
  Isolate* isolate() const { return isolate_; }

  void ReturnBlock(Address* block) {
    DCHECK_NOT_NULL(block);
    if (spare_ != nullptr) DeleteArray(spare_);
    spare_ = block;
  }

  static const size_t kEnteredContextsOffset;

 private:
  void ResetAfterArchive() {
    blocks_.detach();
    entered_contexts_.detach();
    saved_contexts_.detach();
    spare_ = nullptr;
    last_handle_before_persistent_block_.reset();
  }

  void Free() {
    DCHECK(blocks_.empty());
    DCHECK(entered_contexts_.empty());
    DCHECK(saved_contexts_.empty());

    blocks_.free();
    entered_contexts_.free();
    saved_contexts_.free();
    if (spare_ != nullptr) {
      DeleteArray(spare_);
      spare_ = nullptr;
    }
    DCHECK(isolate_->thread_local_top()->CallDepthIsZero());
  }

  void BeginPersistentScope() {
    DCHECK(!last_handle_before_persistent_block_.has_value());
    last_handle_before_persistent_block_ = isolate()->handle_scope_data()->next;
  }
  bool HasPersistentScope() const {
    return last_handle_before_persistent_block_.has_value();
  }
  std::unique_ptr<PersistentHandles> DetachPersistent(Address* first_block);

  Isolate* isolate_;
  DetachableVector<Address*> blocks_;

  // Used as a stack to keep track of entered contexts.
  DetachableVector<Tagged<NativeContext>> entered_contexts_;

  // Used as a stack to keep track of saved contexts.
  DetachableVector<Tagged<Context>> saved_contexts_;
  Address* spare_;
  std::optional<Address*> last_handle_before_persistent_block_;
  // This is only used for threading support.
  HandleScopeData handle_scope_data_;

  void IterateThis(RootVisitor* v);
  char* RestoreThreadHelper(char* from);
  char* ArchiveThreadHelper(char* to);

  friend class HandleScopeImplementerOffsets;
  friend class PersistentHandlesScope;
};

const int kHandleBlockSize = v8::internal::KB - 2;  // fit in one page

void HandleScopeImplementer::SaveContext(Tagged<Context> context) {
  saved_contexts_.push_back(context);
}

Tagged<Context> HandleScopeImplementer::RestoreContext() {
  Tagged<Context> last_context = saved_contexts_.back();
  saved_contexts_.pop_back();
  return last_context;
}

bool HandleScopeImplementer::HasSavedContexts() {
  return !saved_contexts_.empty();
}

void HandleScopeImplementer::LeaveContext() {
  DCHECK(!entered_contexts_.empty());
  entered_contexts_.pop_back();
}

bool HandleScopeImplementer::LastEnteredContextWas(
    Tagged<NativeContext> context) {
  return !entered_contexts_.empty() && entered_contexts_.back() == context;
}

// If there's a spare block, use it for growing the current scope.
internal::Address* HandleScopeImplementer::GetSpareOrNewBlock() {
  internal::Address* block =
      (spare_ != nullptr) ? spare_
                          : NewArray<internal::Address>(kHandleBlockSize);
  spare_ = nullptr;
  return block;
}

void HandleScopeImplementer::DeleteExtensions(internal::Address* prev_limit) {
  while (!blocks_.empty()) {
    internal::Address* block_start = blocks_.back();
    internal::Address* block_limit = block_start + kHandleBlockSize;

    // SealHandleScope may make the prev_limit to point inside the block.
    // Cast possibly-unrelated pointers to plain Address before comparing them
    // to avoid undefined behavior.
    if (reinterpret_cast<Address>(block_start) <
            reinterpret_cast<Address>(prev_limit) &&
        reinterpret_cast<Address>(prev_limit) <=
            reinterpret_cast<Address>(block_limit)) {
#ifdef ENABLE_HANDLE_ZAPPING
      internal::HandleScope::ZapRange(prev_limit, block_limit);
#endif
      break;
    }

    blocks_.pop_back();
#ifdef ENABLE_HANDLE_ZAPPING
    internal::HandleScope::ZapRange(block_start, block_limit);
#endif
    if (spare_ != nullptr) {
      DeleteArray(spare_);
    }
    spare_ = block_start;
  }
  DCHECK((blocks_.empty() && prev_limit == nullptr) ||
         (!blocks_.empty() && prev_limit != nullptr));
}

// This is a wrapper function called from CallApiGetter builtin when profiling
// or side-effect checking is enabled. It's supposed to set up the runtime
// call stats scope and check if the getter has side-effects in case debugger
// enabled the side-effects checking mode.
// It gets additional argument, the AccessorInfo object, via
// IsolateData::api_callback_thunk_argument slot.
void InvokeAccessorGetterCallback(
    v8::Local<v8::Name> property,
    const v8::PropertyCallbackInfo<v8::Value>& info);

// This is a wrapper function called from CallApiCallback builtin when profiling
// or side-effect checking is enabled. It's supposed to set up the runtime
// call stats scope and check if the callback has side-effects in case debugger
// enabled the side-effects checking mode.
// It gets additional argument, the v8::FunctionCallback address, via
// IsolateData::api_callback_thunk_argument slot.
void InvokeFunctionCallbackGeneric(
    const v8::FunctionCallbackInfo<v8::Value>& info);
void InvokeFunctionCallbackOptimized(
    const v8::FunctionCallbackInfo<v8::Value>& info);

void InvokeFinalizationRegistryCleanupFromTask(
    Handle<NativeContext> native_context,
    Handle<JSFinalizationRegistry> finalization_registry,
    Handle<Object> callback);

template <typename T>
EXPORT_TEMPLATE_DECLARE(V8_EXPORT_PRIVATE)
T ConvertDouble(double d);

template <typename T>
EXPORT_TEMPLATE_DECLARE(V8_EXPORT_PRIVATE)
bool ValidateCallbackInfo(const FunctionCallbackInfo<T>& info);

template <typename T>
EXPORT_TEMPLATE_DECLARE(V8_EXPORT_PRIVATE)
bool ValidateCallbackInfo(const PropertyCallbackInfo<T>& info);

DECLARE_CONTEXTUAL_VARIABLE_WITH_DEFAULT(StackAllocatedCheck, const bool, true);

// TODO(crbug.com/42203776): This should move to the API and be integrated into
// `AdjustAmountOfExternalAllocatedMemory()` to make sure there are no
// unbalanced bytes floating around.
class V8_EXPORT_PRIVATE ExternalMemoryAccounterBase {
 public:
  ExternalMemoryAccounterBase() = default;
  ~ExternalMemoryAccounterBase();
  ExternalMemoryAccounterBase(ExternalMemoryAccounterBase&&) V8_NOEXCEPT;
  ExternalMemoryAccounterBase& operator=(ExternalMemoryAccounterBase&&)
      V8_NOEXCEPT;
  ExternalMemoryAccounterBase(const ExternalMemoryAccounterBase&) = delete;
  ExternalMemoryAccounterBase& operator=(const ExternalMemoryAccounterBase&) =
      delete;

  void Increase(Isolate* isolate, size_t size);
  void Update(Isolate* isolate, int64_t delta);
  void Decrease(Isolate* isolate, size_t size);

 private:
#ifdef DEBUG
  size_t amount_of_external_memory_ = 0;
  Isolate* isolate_ = nullptr;
#endif
};

}  // namespace internal
}  // namespace v8

#endif  // V8_API_API_H_

"""

```