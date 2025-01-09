Response:
The user wants to understand the functionality of the provided C++ code snippet from V8's `api.cc` file. They are particularly interested in:

1. **General Functionality:** What does this code do?
2. **Torque Source:**  Does the `.cc` extension mean it's not Torque?
3. **JavaScript Relationship:** How does this C++ code relate to JavaScript functionality, providing examples.
4. **Code Logic and Inference:**  Presenting examples of input and output for specific functions.
5. **Common Programming Errors:**  Illustrating potential mistakes developers might make when using this API.
6. **Summary:** A concise overview of the code's purpose.

Let's break down the code snippet and address each point.

**1. General Functionality:**

The code defines various methods for the `v8::` namespace, which is the public API of the V8 JavaScript engine. It focuses on operations related to:

* **Type Checking (`CheckCast`):**  Ensuring that a `v8::Value*` can be safely cast to a specific V8 type (e.g., `Promise`, `ArrayBuffer`). These checks are essential for type safety when interacting with V8's object model.
* **`BackingStore` Management:**  Dealing with the underlying memory buffers used by `ArrayBuffer` and `SharedArrayBuffer`. This includes getting data, length, max length, and reallocating the buffer.
* **`ArrayBuffer` and `SharedArrayBuffer` Operations:**  Accessing the underlying data of these buffer types.
* **`TypedArray` Handling:**  Type checking for different kinds of typed arrays (e.g., `Uint8Array`, `Float64Array`).
* **Primitive Object Wrappers:** Type checking for wrapper objects around primitive types like `String`, `Symbol`, `Number`, `BigInt`, `Boolean`.
* **Value Conversions:** Converting `v8::Value` to primitive JavaScript types like `double`, `int64_t`, `int32_t`, `uint32_t`.
* **Value Comparisons:**  Checking for equality (`Equals`, `StrictEquals`, `SameValue`).
* **Typeof Operator:** Implementing the JavaScript `typeof` operator.
* **InstanceOf Operator:** Implementing the JavaScript `instanceof` operator.
* **Object Property Manipulation:**  Setting (`Set`, `CreateDataProperty`), defining (`DefineOwnProperty`, `DefineProperty`), and getting (`Get`, `GetOwnPropertyDescriptor`) object properties. This includes handling private properties.
* **Prototype Chain Operations:** Getting and setting the prototype of an object.
* **Property Enumeration:** Getting the names of properties on an object.
* **Object `toString()`:** Implementing the default `Object.prototype.toString()` method.

**2. Torque Source:**

The code snippet has a `.cc` extension. The user's prompt correctly states that if it had a `.tq` extension, it would be a Torque source file. Therefore, this is **not** a Torque source file. It's standard C++.

**3. JavaScript Relationship:**

This C++ code directly implements the functionality that JavaScript code uses when interacting with V8's API. Here are some JavaScript examples illustrating the C++ functions:

* **`Promise::CheckCast`:**

   ```javascript
   const myPromise = new Promise((resolve, reject) => { resolve(1); });
   // In C++, when a V8 API function receives 'myPromise', it might use
   // Promise::CheckCast to ensure it's a valid Promise object before
   // attempting Promise-specific operations.
   ```

* **`ArrayBuffer::CheckCast` and `ArrayBuffer::Data`:**

   ```javascript
   const buffer = new ArrayBuffer(10);
   // In C++, ArrayBuffer::CheckCast verifies 'buffer' is an ArrayBuffer.
   // ArrayBuffer::Data would return a pointer to the underlying memory.
   const dataPtr = // ... (C++ would get this via ArrayBuffer::Data)
   ```

* **`Object::Set` and `Object::Get`:**

   ```javascript
   const obj = {};
   obj.name = "V8"; // Corresponds to Object::Set in C++
   const engineName = obj.name; // Corresponds to Object::Get in C++
   ```

* **`Object::DefineProperty`:**

   ```javascript
   const obj = {};
   Object.defineProperty(obj, 'version', {
       value: '9.0',
       writable: false,
       enumerable: true,
       configurable: false
   }); // Directly relates to Object::DefineProperty in C++
   ```

* **`Value::NumberValue`, `Value::IntegerValue`, etc.:**

   ```javascript
   const value = "42";
   const num = Number(value); // Relates to Value::NumberValue in C++
   const intVal = parseInt(value); // Relates to Value::IntegerValue in C++
   ```

* **`Value::InstanceOf`:**

   ```javascript
   const arr = [];
   const isArray = arr instanceof Array; // Relates to Value::InstanceOf in C++
   ```

* **`Object::GetPrototypeOf` and `Object::SetPrototypeOf` (related to `Object::GetPrototype`, `Object::SetPrototype`):**

   ```javascript
   const proto = {};
   const obj = Object.create(proto); // Implies setting the prototype
   const currentProto = Object.getPrototypeOf(obj); // Implies getting the prototype
   ```

**4. Code Logic and Inference:**

Let's take the `v8::BackingStore::Reallocate` function as an example:

**Assumptions:**

* `v8_isolate` is a valid pointer to a V8 isolate.
* `backing_store` is a valid `std::unique_ptr` to a `v8::BackingStore`.
* `byte_length` is a non-negative integer representing the desired new size of the backing store.

**Input:**

* `v8_isolate`: A pointer representing the V8 execution environment.
* `backing_store`: A unique pointer to a backing store with, for example, an initial size of 1024 bytes.
* `byte_length`: 2048 (the desired new size).

**Output:**

* The `backing_store`'s underlying memory buffer is reallocated to 2048 bytes.
* The function returns the `backing_store` (potentially with a new underlying pointer if reallocation happened).

**Error Condition:**

* **Input:** `byte_length` is greater than `i::JSArrayBuffer::kMaxByteLength`.
* **Output:** The `Utils::ApiCheck` will likely trigger an error or assertion failure, halting execution or throwing an exception.

**5. Common Programming Errors:**

* **Incorrect Type Casting:**  Forgetting to check the type of a `v8::Value*` before casting it.

   ```c++
   void processValue(v8::Local<v8::Value> val) {
       // Potential error: assuming val is always an Object
       v8::Local<v8::Object> obj = val.As<v8::Object>();
       // ... access properties of obj ...
   }

   // JavaScript:
   // processValue(42); // This will likely crash or lead to unexpected behavior
   ```
   The `CheckCast` functions are designed to prevent these kinds of errors. The correct way would be:

   ```c++
   void processValue(v8::Local<v8::Value> val) {
       if (val->IsObject()) {
           v8::Local<v8::Object> obj = val.As<v8::Object>();
           // ... access properties of obj ...
       } else {
           // Handle the case where val is not an object
       }
   }
   ```

* **Memory Management Issues with `BackingStore`:**  Incorrectly managing the lifetime of `BackingStore` objects or accessing the data pointer after the `BackingStore` has been destroyed. V8's smart pointer usage (`std::unique_ptr`, `std::shared_ptr`) helps mitigate this, but manual operations can still be error-prone.

* **Not Handling Exceptions:** Many V8 API calls can potentially throw exceptions (indicated by `Maybe` return types and checking `has_exception`). Ignoring these exceptions can lead to undefined behavior.

   ```c++
   v8::Maybe<int32_t> result = value->Int32Value(context);
   // Potential error: not checking if the conversion succeeded
   int32_t intValue = result.FromJust(); // If result is Nothing, this is bad
   ```
   The correct approach:
   ```c++
   v8::Maybe<int32_t> result = value->Int32Value(context);
   if (result.IsJust()) {
       int32_t intValue = result.FromJust();
       // ... use intValue ...
   } else {
       // Handle the error case
   }
   ```

**6. Summary of Functionality (for Part 6):**

This section of `v8/src/api/api.cc` primarily focuses on **type checking and basic operations for various V8 value types and object properties**. It provides functions to:

* **Safely cast between different V8 value types.**
* **Manage the underlying memory of ArrayBuffers.**
* **Access and manipulate object properties (get, set, define).**
* **Convert V8 values to primitive JavaScript types.**
* **Compare V8 values.**
* **Determine the type of a V8 value.**
* **Check if an object is an instance of a constructor.**
* **Work with the prototype chain of objects.**
* **Retrieve property names of objects.**

Essentially, it lays the groundwork for interacting with JavaScript objects and values from C++ within the V8 engine. The code emphasizes type safety through its `CheckCast` functions and provides core functionalities for manipulating the fundamental building blocks of JavaScript within V8.

这是 `v8/src/api/api.cc` 源代码的第 6 部分，主要功能是定义和实现 V8 API 中用于**类型检查、类型转换以及基础对象操作**的相关函数。

以下是更详细的功能归纳：

**1. 类型检查 (Type Checking):**

*   提供了一系列 `CheckCast` 函数，用于在 C++ 代码中安全地将 `v8::Value*` 指针转换为更具体的 V8 类型，例如 `v8::Promise`、`v8::Proxy`、`v8::ArrayBuffer` 等。
*   这些 `CheckCast` 函数内部使用 `Utils::ApiCheck` 来断言类型是否匹配，如果类型不匹配，则会触发一个 API 错误。
*   涵盖了 Promise、Promise 解析器、Proxy、Wasm 内存对象、Wasm 模块对象、各种 ArrayBuffer 类型（ArrayBuffer、SharedArrayBuffer）、各种 TypedArray 类型（Uint8Array、Int32Array 等）、DataView、Date、各种包装对象类型（StringObject、SymbolObject、NumberObject 等）以及 RegExp 类型的检查。

**2. `v8::BackingStore` 操作:**

*   定义了 `v8::BackingStore` 的析构函数，手动调用内部析构函数。
*   提供了访问 `BackingStore` 底层数据 (`Data()`)、字节长度 (`ByteLength()`)、最大字节长度 (`MaxByteLength()`) 以及共享状态 (`IsShared()`) 和是否可由 JavaScript 调整大小 (`IsResizableByUserJavaScript()`) 的方法。
*   实现了静态方法 `Reallocate`，用于重新分配 `BackingStore` 的内存大小。该方法会进行大小限制检查，并在内存分配失败时抛出致命错误。
*   定义了一个空的 `EmptyDeleter`，用于创建不需要自定义释放器的 `BackingStore`。

**3. `v8::ArrayBuffer` 和 `v8::SharedArrayBuffer` 操作:**

*   提供了 `GetBackingStore()` 方法来获取 `ArrayBuffer` 和 `SharedArrayBuffer` 的 `BackingStore`。如果 `BackingStore` 不存在，则创建一个空的 `BackingStore`（`ArrayBuffer` 是非共享的，`SharedArrayBuffer` 是共享的）。
*   提供了 `Data()` 方法来获取 `ArrayBuffer` 和 `SharedArrayBuffer` 的底层数据指针。
*   提供了 `IsResizableByUserJavaScript()` 方法来检查 `ArrayBuffer` 是否可由 JavaScript 调整大小。
*   提供了针对 `ArrayBuffer` 和 `SharedArrayBuffer` 的 `CheckCast` 函数，用于确保 `Value` 是正确的类型，并区分共享和非共享的 ArrayBuffer。

**4. 其他类型的 `CheckCast`:**

*   为 `v8::ArrayBufferView`、`v8::TypedArray` 以及各种具体的 `TypedArray` 子类型（例如 `v8::Uint8Array`、`v8::Int32Array` 等）提供了 `CheckCast` 函数。
*   特别地，`v8::Float16Array::CheckCast` 会检查 V8 引擎是否启用了 `js_float16array` 特性。
*   为 `v8::DataView`、`v8::Date`、`v8::StringObject`、`v8::SymbolObject`、`v8::NumberObject`、`v8::BigIntObject`、`v8::BooleanObject` 和 `v8::RegExp` 提供了相应的 `CheckCast` 函数。

**5. 值类型转换 (Value Conversion):**

*   提供了将 `v8::Value` 转换为数字类型的方法，例如 `NumberValue` (转换为 `double`)、`IntegerValue` (转换为 `int64_t`)、`Int32Value` (转换为 `int32_t`) 和 `Uint32Value` (转换为 `uint32_t`)。
*   这些转换方法会先尝试直接转换，如果失败则会调用 JavaScript 的类型转换操作 (例如 `ToNumber`, `ToInteger` 等)。
*   提供了 `ToArrayIndex` 方法，尝试将 `v8::Value` 转换为数组索引。

**6. 值比较 (Value Comparison):**

*   提供了 `Equals` 方法，用于执行 JavaScript 的相等比较 (抽象相等，`==`)。
*   提供了 `StrictEquals` 方法，用于执行 JavaScript 的严格相等比较 (`===`)。
*   提供了 `SameValue` 方法，用于执行 JavaScript 的 SameValue 比较 (与 `Object.is()` 类似)。

**7. `typeof` 和 `instanceof` 操作:**

*   提供了 `TypeOf` 方法，用于获取 `v8::Value` 的 JavaScript 类型字符串 (对应 JavaScript 的 `typeof` 运算符)。
*   提供了 `InstanceOf` 方法，用于执行 JavaScript 的 `instanceof` 运算符。

**8. 对象属性操作:**

*   提供了 `Set` 方法的多个重载，用于设置对象的属性值，包括通过键名 (字符串或 Symbol) 和索引来设置。
*   提供了 `CreateDataProperty` 方法的多个重载，用于在对象上创建新的数据属性。
*   定义了 `v8::PropertyDescriptor` 结构体，用于描述对象属性的特性（值、可写、可枚举、可配置、getter、setter）。
*   提供了 `DefineOwnProperty` 方法的多个重载，用于定义或修改对象的自有属性，可以指定属性的特性。
*   提供了 `SetPrivate` 方法，用于设置对象的私有属性 (通常使用 Symbol 作为键)。
*   提供了 `Get` 方法的多个重载，用于获取对象的属性值。
*   提供了 `GetPrivate` 方法，用于获取对象的私有属性值。
*   提供了 `GetPropertyAttributes` 方法，用于获取对象属性的特性。
*   提供了 `GetOwnPropertyDescriptor` 方法，用于获取对象自有属性的描述符。

**9. 原型链操作:**

*   提供了 `GetPrototype` 和 `GetPrototypeV2` 方法，用于获取对象的原型。`GetPrototypeV2` 会跳过全局代理对象上的隐藏原型。
*   提供了 `SetPrototype` 和 `SetPrototypeV2` 方法，用于设置对象的原型。`SetPrototypeV2` 假设是从 JavaScript 代码调用的。
*   提供了 `FindInstanceInPrototypeChain` 方法，用于在对象的原型链中查找特定 `FunctionTemplate` 的实例。

**10. 属性枚举:**

*   提供了 `GetPropertyNames` 方法的多个重载，用于获取对象的可枚举属性名，可以控制是否包含原型链上的属性、过滤属性类型（仅可枚举、跳过 Symbols 等）以及是否包含索引。
*   提供了 `GetOwnPropertyNames` 方法的多个重载，用于获取对象的自有属性名。

**11. `Object.prototype.toString()`:**

*   提供了 `ObjectProtoToString` 方法，用于模拟调用 `Object.prototype.toString()` 方法。

**关于 .tq 后缀:**

你提到的 `.tq` 后缀是用于 V8 的 **Torque** 语言编写的源代码。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。由于 `v8/src/api/api.cc` 的后缀是 `.cc`，这意味着它是用 **C++** 编写的，而不是 Torque。

**与 JavaScript 的关系及示例:**

上述列举的每个功能都直接对应着 JavaScript 中可以进行的操作。例如：

*   **类型检查:** JavaScript 的 `typeof` 运算符和 `instanceof` 运算符在 V8 内部会使用类似的类型检查机制。
*   **`ArrayBuffer`:** JavaScript 中创建和操作 `ArrayBuffer` 对象时，V8 内部会使用 `v8::ArrayBuffer` 及其相关函数来管理内存。
*   **对象属性操作:** JavaScript 中访问、设置、定义对象属性的行为（例如 `obj.prop = value`, `Object.defineProperty()`) 都直接映射到 `v8::Object` 提供的 `Set`, `CreateDataProperty`, `DefineOwnProperty` 等方法。
*   **原型链:** JavaScript 的原型继承机制（例如 `Object.getPrototypeOf()`, `Object.setPrototypeOf()`) 在 V8 内部由 `GetPrototype`, `SetPrototype` 等方法实现。

**JavaScript 示例:**

```javascript
const promise = new Promise((resolve, reject) => {});
// 在 C++ 中，可以使用 v8::Promise::CheckCast 来检查 promise 是否是一个 Promise 对象。

const buffer = new ArrayBuffer(1024);
// 在 C++ 中，可以使用 v8::ArrayBuffer::Data() 获取 buffer 的底层数据指针。

const obj = { name: "V8" };
obj.version = "9.0"; // 对应 C++ 中的 v8::Object::Set()
const engineName = obj.name; // 对应 C++ 中的 v8::Object::Get()

Object.defineProperty(obj, 'hidden', {
  value: 'secret',
  enumerable: false
}); // 对应 C++ 中的 v8::Object::DefineOwnProperty()

const proto = {};
const myObj = Object.create(proto); // 对应 C++ 中的 v8::Object::SetPrototype()
const currentProto = Object.getPrototypeOf(myObj); // 对应 C++ 中的 v8::Object::GetPrototype()
```

**代码逻辑推理和假设输入/输出:**

**示例： `v8::BackingStore::Reallocate`**

**假设输入:**

*   `v8_isolate`: 一个指向 V8 隔离环境的有效指针。
*   `backing_store`: 一个指向现有 `v8::BackingStore` 对象的 `std::unique_ptr`，假设其当前大小为 1024 字节。
*   `byte_length`: `2048` (新的目标大小)。

**预期输出:**

*   如果内存分配成功，`backing_store` 指向的内存块将被重新分配为 2048 字节。
*   该函数返回 `backing_store`，它仍然指向（可能重新分配的）内存。

**错误情况:**

*   如果 `byte_length` 大于 `i::JSArrayBuffer::kMaxByteLength`，`Utils::ApiCheck` 将会失败，并可能导致程序终止或抛出异常。

**用户常见的编程错误:**

*   **类型转换错误:** 在 C++ 中直接将 `v8::Value*` 转换为特定类型而不进行 `CheckCast` 检查，可能导致程序崩溃或未定义的行为。例如，将一个字符串 `Value` 直接转换为 `Object`。
*   **忘记处理 `Maybe` 返回值:** 许多 V8 API 函数返回 `v8::Maybe` 类型，表示操作可能成功或失败。忘记检查 `IsJust()` 或 `IsNothing()` 可能导致程序使用无效的值。
*   **生命周期管理错误:**  不正确地管理 V8 对象的生命周期，例如在对象被销毁后仍然尝试访问其数据。

**总结:**

第 6 部分的 `v8/src/api/api.cc` 代码主要负责实现 V8 公开 API 中关于类型处理和基础对象操作的关键功能。它提供了类型检查机制，允许 C++ 代码安全地与 JavaScript 对象交互，并实现了诸如属性访问、修改、原型链操作等核心的 JavaScript 语义。这部分代码是 V8 引擎与外部 C++ 代码交互的重要桥梁。

Prompt: 
```
这是目录为v8/src/api/api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/api/api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共15部分，请归纳一下它的功能

"""
::Promise::Cast",
                  "Value is not a Promise");
}

void v8::Promise::Resolver::CheckCast(Value* that) {
  Utils::ApiCheck(that->IsPromise(), "v8::Promise::Resolver::Cast",
                  "Value is not a Promise::Resolver");
}

void v8::Proxy::CheckCast(Value* that) {
  Utils::ApiCheck(that->IsProxy(), "v8::Proxy::Cast", "Value is not a Proxy");
}

void v8::WasmMemoryObject::CheckCast(Value* that) {
  Utils::ApiCheck(that->IsWasmMemoryObject(), "v8::WasmMemoryObject::Cast",
                  "Value is not a WasmMemoryObject");
}

void v8::WasmModuleObject::CheckCast(Value* that) {
  Utils::ApiCheck(that->IsWasmModuleObject(), "v8::WasmModuleObject::Cast",
                  "Value is not a WasmModuleObject");
}

v8::BackingStore::~BackingStore() {
  auto i_this = reinterpret_cast<const i::BackingStore*>(this);
  i_this->~BackingStore();  // manually call internal destructor
}

void* v8::BackingStore::Data() const {
  return reinterpret_cast<const i::BackingStore*>(this)->buffer_start();
}

size_t v8::BackingStore::ByteLength() const {
  return reinterpret_cast<const i::BackingStore*>(this)->byte_length();
}

size_t v8::BackingStore::MaxByteLength() const {
  return reinterpret_cast<const i::BackingStore*>(this)->max_byte_length();
}

bool v8::BackingStore::IsShared() const {
  return reinterpret_cast<const i::BackingStore*>(this)->is_shared();
}

bool v8::BackingStore::IsResizableByUserJavaScript() const {
  return reinterpret_cast<const i::BackingStore*>(this)->is_resizable_by_js();
}

// static
std::unique_ptr<v8::BackingStore> v8::BackingStore::Reallocate(
    v8::Isolate* v8_isolate, std::unique_ptr<v8::BackingStore> backing_store,
    size_t byte_length) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, ArrayBuffer, BackingStore_Reallocate);
  Utils::ApiCheck(byte_length <= i::JSArrayBuffer::kMaxByteLength,
                  "v8::BackingStore::Reallocate", "byte_length is too large");
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::BackingStore* i_backing_store =
      reinterpret_cast<i::BackingStore*>(backing_store.get());
  if (!i_backing_store->Reallocate(i_isolate, byte_length)) {
    i::V8::FatalProcessOutOfMemory(i_isolate, "v8::BackingStore::Reallocate");
  }
  return backing_store;
}

// static
void v8::BackingStore::EmptyDeleter(void* data, size_t length,
                                    void* deleter_data) {
  DCHECK_NULL(deleter_data);
}

std::shared_ptr<v8::BackingStore> v8::ArrayBuffer::GetBackingStore() {
  auto self = Utils::OpenDirectHandle(this);
  std::shared_ptr<i::BackingStore> backing_store = self->GetBackingStore();
  if (!backing_store) {
    backing_store =
        i::BackingStore::EmptyBackingStore(i::SharedFlag::kNotShared);
  }
  std::shared_ptr<i::BackingStoreBase> bs_base = backing_store;
  return std::static_pointer_cast<v8::BackingStore>(bs_base);
}

void* v8::ArrayBuffer::Data() const {
  return Utils::OpenDirectHandle(this)->backing_store();
}

bool v8::ArrayBuffer::IsResizableByUserJavaScript() const {
  return Utils::OpenDirectHandle(this)->is_resizable_by_js();
}

std::shared_ptr<v8::BackingStore> v8::SharedArrayBuffer::GetBackingStore() {
  auto self = Utils::OpenDirectHandle(this);
  std::shared_ptr<i::BackingStore> backing_store = self->GetBackingStore();
  if (!backing_store) {
    backing_store = i::BackingStore::EmptyBackingStore(i::SharedFlag::kShared);
  }
  std::shared_ptr<i::BackingStoreBase> bs_base = backing_store;
  return std::static_pointer_cast<v8::BackingStore>(bs_base);
}

void* v8::SharedArrayBuffer::Data() const {
  return Utils::OpenDirectHandle(this)->backing_store();
}

void v8::ArrayBuffer::CheckCast(Value* that) {
  auto obj = *Utils::OpenDirectHandle(that);
  Utils::ApiCheck(
      IsJSArrayBuffer(obj) && !i::Cast<i::JSArrayBuffer>(obj)->is_shared(),
      "v8::ArrayBuffer::Cast()", "Value is not an ArrayBuffer");
}

void v8::ArrayBufferView::CheckCast(Value* that) {
  auto obj = *Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsJSArrayBufferView(obj), "v8::ArrayBufferView::Cast()",
                  "Value is not an ArrayBufferView");
}

void v8::TypedArray::CheckCast(Value* that) {
  auto obj = *Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsJSTypedArray(obj), "v8::TypedArray::Cast()",
                  "Value is not a TypedArray");
}

#define CHECK_TYPED_ARRAY_CAST(Type, typeName, TYPE, ctype)                \
  void v8::Type##Array::CheckCast(Value* that) {                           \
    auto obj = *Utils::OpenDirectHandle(that);                             \
    Utils::ApiCheck(                                                       \
        i::IsJSTypedArray(obj) && i::Cast<i::JSTypedArray>(obj)->type() == \
                                      i::kExternal##Type##Array,           \
        "v8::" #Type "Array::Cast()", "Value is not a " #Type "Array");    \
  }

TYPED_ARRAYS_BASE(CHECK_TYPED_ARRAY_CAST)
#undef CHECK_TYPED_ARRAY_CAST

void v8::Float16Array::CheckCast(Value* that) {
  Utils::ApiCheck(i::v8_flags.js_float16array, "v8::Float16Array::Cast",
                  "Float16Array is not supported");
  auto obj = *Utils::OpenHandle(that);
  Utils::ApiCheck(
      i::IsJSTypedArray(obj) &&
          i::Cast<i::JSTypedArray>(obj)->type() == i::kExternalFloat16Array,
      "v8::Float16Array::Cast()", "Value is not a Float16Array");
}

void v8::DataView::CheckCast(Value* that) {
  auto obj = *Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsJSDataView(obj) || IsJSRabGsabDataView(obj),
                  "v8::DataView::Cast()", "Value is not a DataView");
}

void v8::SharedArrayBuffer::CheckCast(Value* that) {
  auto obj = *Utils::OpenDirectHandle(that);
  Utils::ApiCheck(
      IsJSArrayBuffer(obj) && i::Cast<i::JSArrayBuffer>(obj)->is_shared(),
      "v8::SharedArrayBuffer::Cast()", "Value is not a SharedArrayBuffer");
}

void v8::Date::CheckCast(v8::Value* that) {
  auto obj = *Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsJSDate(obj), "v8::Date::Cast()", "Value is not a Date");
}

void v8::StringObject::CheckCast(v8::Value* that) {
  auto obj = *Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsStringWrapper(obj), "v8::StringObject::Cast()",
                  "Value is not a StringObject");
}

void v8::SymbolObject::CheckCast(v8::Value* that) {
  auto obj = *Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsSymbolWrapper(obj), "v8::SymbolObject::Cast()",
                  "Value is not a SymbolObject");
}

void v8::NumberObject::CheckCast(v8::Value* that) {
  auto obj = *Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsNumberWrapper(obj), "v8::NumberObject::Cast()",
                  "Value is not a NumberObject");
}

void v8::BigIntObject::CheckCast(v8::Value* that) {
  auto obj = *Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsBigIntWrapper(obj), "v8::BigIntObject::Cast()",
                  "Value is not a BigIntObject");
}

void v8::BooleanObject::CheckCast(v8::Value* that) {
  auto obj = *Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsBooleanWrapper(obj), "v8::BooleanObject::Cast()",
                  "Value is not a BooleanObject");
}

void v8::RegExp::CheckCast(v8::Value* that) {
  auto obj = *Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsJSRegExp(obj), "v8::RegExp::Cast()",
                  "Value is not a RegExp");
}

Maybe<double> Value::NumberValue(Local<Context> context) const {
  auto obj = Utils::OpenHandle(this);
  if (i::IsNumber(*obj)) {
    return Just(i::Object::NumberValue(i::Cast<i::Number>(*obj)));
  }
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Value, NumberValue, i::HandleScope);
  i::Handle<i::Number> num;
  has_exception = !i::Object::ToNumber(i_isolate, obj).ToHandle(&num);
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(double);
  return Just(i::Object::NumberValue(*num));
}

Maybe<int64_t> Value::IntegerValue(Local<Context> context) const {
  auto obj = Utils::OpenHandle(this);
  if (i::IsNumber(*obj)) {
    return Just(NumberToInt64(*obj));
  }
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Value, IntegerValue, i::HandleScope);
  i::Handle<i::Object> num;
  has_exception = !i::Object::ToInteger(i_isolate, obj).ToHandle(&num);
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(int64_t);
  return Just(NumberToInt64(*num));
}

Maybe<int32_t> Value::Int32Value(Local<Context> context) const {
  auto obj = Utils::OpenHandle(this);
  if (i::IsNumber(*obj)) return Just(NumberToInt32(*obj));
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Value, Int32Value, i::HandleScope);
  i::Handle<i::Object> num;
  has_exception = !i::Object::ToInt32(i_isolate, obj).ToHandle(&num);
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(int32_t);
  return Just(IsSmi(*num) ? i::Smi::ToInt(*num)
                          : static_cast<int32_t>(
                                i::Cast<i::HeapNumber>(*num)->value()));
}

Maybe<uint32_t> Value::Uint32Value(Local<Context> context) const {
  auto obj = Utils::OpenHandle(this);
  if (i::IsNumber(*obj)) return Just(NumberToUint32(*obj));
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Value, Uint32Value, i::HandleScope);
  i::Handle<i::Object> num;
  has_exception = !i::Object::ToUint32(i_isolate, obj).ToHandle(&num);
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(uint32_t);
  return Just(IsSmi(*num) ? static_cast<uint32_t>(i::Smi::ToInt(*num))
                          : static_cast<uint32_t>(
                                i::Cast<i::HeapNumber>(*num)->value()));
}

MaybeLocal<Uint32> Value::ToArrayIndex(Local<Context> context) const {
  auto self = Utils::OpenHandle(this);
  if (i::IsSmi(*self)) {
    if (i::Smi::ToInt(*self) >= 0) return Utils::Uint32ToLocal(self);
    return Local<Uint32>();
  }
  PREPARE_FOR_EXECUTION(context, Object, ToArrayIndex);
  i::Handle<i::Object> string_obj;
  has_exception = !i::Object::ToString(i_isolate, self).ToHandle(&string_obj);
  RETURN_ON_FAILED_EXECUTION(Uint32);
  auto str = i::Cast<i::String>(string_obj);
  uint32_t index;
  if (str->AsArrayIndex(&index)) {
    i::Handle<i::Object> value;
    if (index <= static_cast<uint32_t>(i::Smi::kMaxValue)) {
      value = i::Handle<i::Object>(i::Smi::FromInt(index), i_isolate);
    } else {
      value = i_isolate->factory()->NewNumber(index);
    }
    RETURN_ESCAPED(Utils::Uint32ToLocal(value));
  }
  return Local<Uint32>();
}

Maybe<bool> Value::Equals(Local<Context> context, Local<Value> that) const {
  i::Isolate* i_isolate = Utils::OpenDirectHandle(*context)->GetIsolate();
  ENTER_V8(i_isolate, context, Value, Equals, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  auto other = Utils::OpenHandle(*that);
  Maybe<bool> result = i::Object::Equals(i_isolate, self, other);
  has_exception = result.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return result;
}

bool Value::StrictEquals(Local<Value> that) const {
  auto self = Utils::OpenHandle(this);
  auto other = Utils::OpenHandle(*that);
  return i::Object::StrictEquals(*self, *other);
}

bool Value::SameValue(Local<Value> that) const {
  auto self = Utils::OpenHandle(this);
  auto other = Utils::OpenHandle(*that);
  return i::Object::SameValue(*self, *other);
}

Local<String> Value::TypeOf(v8::Isolate* external_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(external_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  API_RCS_SCOPE(i_isolate, Value, TypeOf);
  return Utils::ToLocal(i::Object::TypeOf(i_isolate, Utils::OpenHandle(this)));
}

Maybe<bool> Value::InstanceOf(v8::Local<v8::Context> context,
                              v8::Local<v8::Object> object) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Value, InstanceOf, i::HandleScope);
  i::Handle<i::JSAny> left;
  if (!Utils::ApiCheck(i::TryCast<i::JSAny>(Utils::OpenHandle(this), &left),
                       "Value::InstanceOf",
                       "Invalid type, must be a JS primitive or object.")) {
    return Nothing<bool>();
  }
  auto right = Utils::OpenHandle(*object);
  i::Handle<i::Object> result;
  has_exception =
      !i::Object::InstanceOf(i_isolate, left, right).ToHandle(&result);
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return Just(i::IsTrue(*result, i_isolate));
}

Maybe<bool> v8::Object::Set(v8::Local<v8::Context> context,
                            v8::Local<Value> key, v8::Local<Value> value) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Object, Set, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  auto key_obj = Utils::OpenHandle(*key);
  auto value_obj = Utils::OpenHandle(*value);
  has_exception =
      i::Runtime::SetObjectProperty(i_isolate, self, key_obj, value_obj,
                                    i::StoreOrigin::kMaybeKeyed,
                                    Just(i::ShouldThrow::kDontThrow))
          .is_null();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return Just(true);
}

Maybe<bool> v8::Object::Set(v8::Local<v8::Context> context,
                            v8::Local<Value> key, v8::Local<Value> value,
                            MaybeLocal<Object> receiver) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Object, Set, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  auto key_obj = Utils::OpenHandle(*key);
  auto value_obj = Utils::OpenHandle(*value);
  i::MaybeHandle<i::JSReceiver> receiver_obj;
  if (!receiver.IsEmpty()) {
    receiver_obj = Utils::OpenHandle(*receiver.ToLocalChecked());
  }
  has_exception =
      i::Runtime::SetObjectProperty(i_isolate, self, key_obj, value_obj,
                                    receiver_obj, i::StoreOrigin::kMaybeKeyed,
                                    Just(i::ShouldThrow::kDontThrow))
          .is_null();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return Just(true);
}

Maybe<bool> v8::Object::Set(v8::Local<v8::Context> context, uint32_t index,
                            v8::Local<Value> value) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Object, Set, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  auto value_obj = Utils::OpenHandle(*value);
  has_exception = i::Object::SetElement(i_isolate, self, index, value_obj,
                                        i::ShouldThrow::kDontThrow)
                      .is_null();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return Just(true);
}

Maybe<bool> v8::Object::CreateDataProperty(v8::Local<v8::Context> context,
                                           v8::Local<Name> key,
                                           v8::Local<Value> value) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  auto self = Utils::OpenHandle(this);
  auto key_obj = Utils::OpenHandle(*key);
  auto value_obj = Utils::OpenHandle(*value);

  i::PropertyKey lookup_key(i_isolate, key_obj);
  if (i::IsJSObject(*self)) {
    ENTER_V8_NO_SCRIPT(i_isolate, context, Object, CreateDataProperty,
                       i::HandleScope);
    Maybe<bool> result = i::JSObject::CreateDataProperty(
        i_isolate, i::Cast<i::JSObject>(self), lookup_key, value_obj,
        Just(i::kDontThrow));
    has_exception = result.IsNothing();
    RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
    return result;
  }
  // JSProxy or WasmObject or other non-JSObject.
  ENTER_V8(i_isolate, context, Object, CreateDataProperty, i::HandleScope);
  Maybe<bool> result = i::JSReceiver::CreateDataProperty(
      i_isolate, self, lookup_key, value_obj, Just(i::kDontThrow));
  has_exception = result.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return result;
}

Maybe<bool> v8::Object::CreateDataProperty(v8::Local<v8::Context> context,
                                           uint32_t index,
                                           v8::Local<Value> value) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  auto self = Utils::OpenHandle(this);
  auto value_obj = Utils::OpenHandle(*value);

  i::PropertyKey lookup_key(i_isolate, index);
  if (i::IsJSObject(*self)) {
    ENTER_V8_NO_SCRIPT(i_isolate, context, Object, CreateDataProperty,
                       i::HandleScope);
    Maybe<bool> result = i::JSObject::CreateDataProperty(
        i_isolate, i::Cast<i::JSObject>(self), lookup_key, value_obj,
        Just(i::kDontThrow));
    has_exception = result.IsNothing();
    RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
    return result;
  }
  // JSProxy or WasmObject or other non-JSObject.
  ENTER_V8(i_isolate, context, Object, CreateDataProperty, i::HandleScope);
  Maybe<bool> result = i::JSReceiver::CreateDataProperty(
      i_isolate, self, lookup_key, value_obj, Just(i::kDontThrow));
  has_exception = result.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return result;
}

struct v8::PropertyDescriptor::PrivateData {
  PrivateData() : desc() {}
  i::PropertyDescriptor desc;
};

v8::PropertyDescriptor::PropertyDescriptor() : private_(new PrivateData()) {}

// DataDescriptor
v8::PropertyDescriptor::PropertyDescriptor(v8::Local<v8::Value> value)
    : private_(new PrivateData()) {
  private_->desc.set_value(Cast<i::JSAny>(Utils::OpenHandle(*value, true)));
}

// DataDescriptor with writable field
v8::PropertyDescriptor::PropertyDescriptor(v8::Local<v8::Value> value,
                                           bool writable)
    : private_(new PrivateData()) {
  private_->desc.set_value(Cast<i::JSAny>(Utils::OpenHandle(*value, true)));
  private_->desc.set_writable(writable);
}

// AccessorDescriptor
v8::PropertyDescriptor::PropertyDescriptor(v8::Local<v8::Value> get,
                                           v8::Local<v8::Value> set)
    : private_(new PrivateData()) {
  DCHECK(get.IsEmpty() || get->IsUndefined() || get->IsFunction());
  DCHECK(set.IsEmpty() || set->IsUndefined() || set->IsFunction());
  private_->desc.set_get(Cast<i::JSAny>(Utils::OpenHandle(*get, true)));
  private_->desc.set_set(Cast<i::JSAny>(Utils::OpenHandle(*set, true)));
}

v8::PropertyDescriptor::~PropertyDescriptor() { delete private_; }

v8::Local<Value> v8::PropertyDescriptor::value() const {
  DCHECK(private_->desc.has_value());
  return Utils::ToLocal(private_->desc.value());
}

v8::Local<Value> v8::PropertyDescriptor::get() const {
  DCHECK(private_->desc.has_get());
  return Utils::ToLocal(private_->desc.get());
}

v8::Local<Value> v8::PropertyDescriptor::set() const {
  DCHECK(private_->desc.has_set());
  return Utils::ToLocal(private_->desc.set());
}

bool v8::PropertyDescriptor::has_value() const {
  return private_->desc.has_value();
}
bool v8::PropertyDescriptor::has_get() const {
  return private_->desc.has_get();
}
bool v8::PropertyDescriptor::has_set() const {
  return private_->desc.has_set();
}

bool v8::PropertyDescriptor::writable() const {
  DCHECK(private_->desc.has_writable());
  return private_->desc.writable();
}

bool v8::PropertyDescriptor::has_writable() const {
  return private_->desc.has_writable();
}

void v8::PropertyDescriptor::set_enumerable(bool enumerable) {
  private_->desc.set_enumerable(enumerable);
}

bool v8::PropertyDescriptor::enumerable() const {
  DCHECK(private_->desc.has_enumerable());
  return private_->desc.enumerable();
}

bool v8::PropertyDescriptor::has_enumerable() const {
  return private_->desc.has_enumerable();
}

void v8::PropertyDescriptor::set_configurable(bool configurable) {
  private_->desc.set_configurable(configurable);
}

bool v8::PropertyDescriptor::configurable() const {
  DCHECK(private_->desc.has_configurable());
  return private_->desc.configurable();
}

bool v8::PropertyDescriptor::has_configurable() const {
  return private_->desc.has_configurable();
}

Maybe<bool> v8::Object::DefineOwnProperty(v8::Local<v8::Context> context,
                                          v8::Local<Name> key,
                                          v8::Local<Value> value,
                                          v8::PropertyAttribute attributes) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  auto self = Utils::OpenHandle(this);
  auto key_obj = Utils::OpenHandle(*key);
  auto value_obj = Utils::OpenHandle(*value);

  i::PropertyDescriptor desc;
  desc.set_writable(!(attributes & v8::ReadOnly));
  desc.set_enumerable(!(attributes & v8::DontEnum));
  desc.set_configurable(!(attributes & v8::DontDelete));
  desc.set_value(i::Cast<i::JSAny>(value_obj));

  if (i::IsJSObject(*self)) {
    // If it's not a JSProxy, i::JSReceiver::DefineOwnProperty should never run
    // a script.
    ENTER_V8_NO_SCRIPT(i_isolate, context, Object, DefineOwnProperty,
                       i::HandleScope);
    Maybe<bool> success = i::JSReceiver::DefineOwnProperty(
        i_isolate, self, key_obj, &desc, Just(i::kDontThrow));
    has_exception = success.IsNothing();
    RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
    return success;
  }
  // JSProxy or WasmObject or other non-JSObject.
  ENTER_V8(i_isolate, context, Object, DefineOwnProperty, i::HandleScope);
  Maybe<bool> success = i::JSReceiver::DefineOwnProperty(
      i_isolate, self, key_obj, &desc, Just(i::kDontThrow));
  // Even though we said kDontThrow, there might be accessors that do throw.
  has_exception = success.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return success;
}

Maybe<bool> v8::Object::DefineProperty(v8::Local<v8::Context> context,
                                       v8::Local<Name> key,
                                       PropertyDescriptor& descriptor) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Object, DefineOwnProperty, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  auto key_obj = Utils::OpenHandle(*key);

  Maybe<bool> success = i::JSReceiver::DefineOwnProperty(
      i_isolate, self, key_obj, &descriptor.get_private()->desc,
      Just(i::kDontThrow));
  has_exception = success.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return success;
}

Maybe<bool> v8::Object::SetPrivate(Local<Context> context, Local<Private> key,
                                   Local<Value> value) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8_NO_SCRIPT(i_isolate, context, Object, SetPrivate, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  auto key_obj = Utils::OpenHandle(reinterpret_cast<Name*>(*key));
  auto value_obj = Utils::OpenHandle(*value);
  if (i::IsJSObject(*self)) {
    auto js_object = i::Cast<i::JSObject>(self);
    i::LookupIterator it(i_isolate, js_object, key_obj, js_object);
    has_exception = i::JSObject::DefineOwnPropertyIgnoreAttributes(
                        &it, value_obj, i::DONT_ENUM)
                        .is_null();
    RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
    return Just(true);
  }
  if (i::IsJSProxy(*self)) {
    i::PropertyDescriptor desc;
    desc.set_writable(true);
    desc.set_enumerable(false);
    desc.set_configurable(true);
    desc.set_value(i::Cast<i::JSAny>(value_obj));
    return i::JSProxy::SetPrivateSymbol(i_isolate, i::Cast<i::JSProxy>(self),
                                        i::Cast<i::Symbol>(key_obj), &desc,
                                        Just(i::kDontThrow));
  }
  // Wasm object, or other kind of special object not supported here.
  return Just(false);
}

MaybeLocal<Value> v8::Object::Get(Local<v8::Context> context,
                                  Local<Value> key) {
  PREPARE_FOR_EXECUTION(context, Object, Get);
  auto self = Utils::OpenHandle(this);
  auto key_obj = Utils::OpenHandle(*key);
  i::Handle<i::Object> result;
  has_exception = !i::Runtime::GetObjectProperty(i_isolate, self, key_obj)
                       .ToHandle(&result);
  RETURN_ON_FAILED_EXECUTION(Value);
  RETURN_ESCAPED(Utils::ToLocal(result));
}

MaybeLocal<Value> v8::Object::Get(Local<v8::Context> context, Local<Value> key,
                                  MaybeLocal<Object> receiver) {
  PREPARE_FOR_EXECUTION(context, Object, Get);
  auto self = Utils::OpenHandle(this);
  auto key_obj = Utils::OpenHandle(*key);
  i::Handle<i::JSReceiver> receiver_obj;
  if (!receiver.IsEmpty()) {
    receiver_obj = Utils::OpenHandle(*receiver.ToLocalChecked());
  }
  i::Handle<i::Object> result;
  has_exception =
      !i::Runtime::GetObjectProperty(i_isolate, self, key_obj, receiver_obj)
           .ToHandle(&result);
  RETURN_ON_FAILED_EXECUTION(Value);
  RETURN_ESCAPED(Utils::ToLocal(result));
}

MaybeLocal<Value> v8::Object::Get(Local<Context> context, uint32_t index) {
  PREPARE_FOR_EXECUTION(context, Object, Get);
  auto self = Utils::OpenHandle(this);
  i::Handle<i::Object> result;
  has_exception =
      !i::JSReceiver::GetElement(i_isolate, self, index).ToHandle(&result);
  RETURN_ON_FAILED_EXECUTION(Value);
  RETURN_ESCAPED(Utils::ToLocal(result));
}

MaybeLocal<Value> v8::Object::GetPrivate(Local<Context> context,
                                         Local<Private> key) {
  return Get(context, key.UnsafeAs<Value>());
}

Maybe<PropertyAttribute> v8::Object::GetPropertyAttributes(
    Local<Context> context, Local<Value> key) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Object, GetPropertyAttributes, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  auto key_obj = Utils::OpenHandle(*key);
  if (!i::IsName(*key_obj)) {
    has_exception = !i::Object::ToString(i_isolate, key_obj).ToHandle(&key_obj);
    RETURN_ON_FAILED_EXECUTION_PRIMITIVE(PropertyAttribute);
  }
  auto key_name = i::Cast<i::Name>(key_obj);
  auto result = i::JSReceiver::GetPropertyAttributes(self, key_name);
  has_exception = result.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(PropertyAttribute);
  if (result.FromJust() == i::ABSENT) {
    return Just(static_cast<PropertyAttribute>(i::NONE));
  }
  return Just(static_cast<PropertyAttribute>(result.FromJust()));
}

MaybeLocal<Value> v8::Object::GetOwnPropertyDescriptor(Local<Context> context,
                                                       Local<Name> key) {
  PREPARE_FOR_EXECUTION(context, Object, GetOwnPropertyDescriptor);
  auto obj = Utils::OpenHandle(this);
  auto key_name = Utils::OpenHandle(*key);

  i::PropertyDescriptor desc;
  Maybe<bool> found =
      i::JSReceiver::GetOwnPropertyDescriptor(i_isolate, obj, key_name, &desc);
  has_exception = found.IsNothing();
  RETURN_ON_FAILED_EXECUTION(Value);
  if (!found.FromJust()) {
    return v8::Undefined(reinterpret_cast<v8::Isolate*>(i_isolate));
  }
  RETURN_ESCAPED(Utils::ToLocal(desc.ToObject(i_isolate)));
}

Local<Value> v8::Object::GetPrototype() {
  auto self = Utils::OpenHandle(this);
  auto i_isolate = self->GetIsolate();
  i::PrototypeIterator iter(i_isolate, self);
  return Utils::ToLocal(i::PrototypeIterator::GetCurrent(iter));
}

Local<Value> v8::Object::GetPrototypeV2() {
  auto self = Utils::OpenHandle(this);
  auto i_isolate = self->GetIsolate();
  i::PrototypeIterator iter(i_isolate, self);
  if (i::IsJSGlobalProxy(*self)) {
    // Skip hidden prototype (i.e. JSGlobalObject).
    iter.Advance();
  }
  DCHECK(!i::IsJSGlobalObject(*i::PrototypeIterator::GetCurrent(iter)));
  return Utils::ToLocal(i::PrototypeIterator::GetCurrent(iter));
}

namespace {

Maybe<bool> SetPrototypeImpl(v8::Object* this_, Local<Context> context,
                             Local<Value> value, bool from_javascript) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  auto self = Utils::OpenHandle(this_);
  auto value_obj = Utils::OpenHandle(*value);
  // TODO(333672197): turn this to DCHECK once it's no longer possible
  // to get JSGlobalObject via API.
  CHECK_IMPLIES(from_javascript, !i::IsJSGlobalObject(*value_obj));
  if (i::IsJSObject(*self)) {
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
    // TODO(333672197): turn this to DCHECK once it's no longer possible
    // to get JSGlobalObject via API.
    CHECK_IMPLIES(from_javascript, !i::IsJSGlobalObject(*self));
    auto result =
        i::JSObject::SetPrototype(i_isolate, i::Cast<i::JSObject>(self),
                                  value_obj, from_javascript, i::kDontThrow);
    if (!result.FromJust()) return Nothing<bool>();
    return Just(true);
  }
  if (i::IsJSProxy(*self)) {
    ENTER_V8(i_isolate, context, Object, SetPrototype, i::HandleScope);
    // We do not allow exceptions thrown while setting the prototype
    // to propagate outside.
    TryCatch try_catch(reinterpret_cast<v8::Isolate*>(i_isolate));
    auto result =
        i::JSProxy::SetPrototype(i_isolate, i::Cast<i::JSProxy>(self),
                                 value_obj, from_javascript, i::kThrowOnError);
    has_exception = result.IsNothing();
    RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
    return Just(true);
  }
  // Wasm object or other kind of special object not supported here.
  return Nothing<bool>();
}

}  // namespace

Maybe<bool> v8::Object::SetPrototype(Local<Context> context,
                                     Local<Value> value) {
  static constexpr bool from_javascript = false;
  return SetPrototypeImpl(this, context, value, from_javascript);
}

Maybe<bool> v8::Object::SetPrototypeV2(Local<Context> context,
                                       Local<Value> value) {
  static constexpr bool from_javascript = true;
  return SetPrototypeImpl(this, context, value, from_javascript);
}

Local<Object> v8::Object::FindInstanceInPrototypeChain(
    v8::Local<FunctionTemplate> tmpl) {
  auto self = Utils::OpenDirectHandle(this);
  auto i_isolate = self->GetIsolate();
  i::PrototypeIterator iter(i_isolate, *self, i::kStartAtReceiver);
  i::Tagged<i::FunctionTemplateInfo> tmpl_info =
      *Utils::OpenDirectHandle(*tmpl);
  if (!IsJSObject(iter.GetCurrent())) return Local<Object>();
  while (!tmpl_info->IsTemplateFor(iter.GetCurrent<i::JSObject>())) {
    iter.Advance();
    if (iter.IsAtEnd()) return Local<Object>();
    if (!IsJSObject(iter.GetCurrent())) return Local<Object>();
  }
  // IsTemplateFor() ensures that iter.GetCurrent() can't be a Proxy here.
  return Utils::ToLocal(i::handle(iter.GetCurrent<i::JSObject>(), i_isolate));
}

MaybeLocal<Array> v8::Object::GetPropertyNames(Local<Context> context) {
  return GetPropertyNames(
      context, v8::KeyCollectionMode::kIncludePrototypes,
      static_cast<v8::PropertyFilter>(ONLY_ENUMERABLE | SKIP_SYMBOLS),
      v8::IndexFilter::kIncludeIndices);
}

MaybeLocal<Array> v8::Object::GetPropertyNames(
    Local<Context> context, KeyCollectionMode mode,
    PropertyFilter property_filter, IndexFilter index_filter,
    KeyConversionMode key_conversion) {
  PREPARE_FOR_EXECUTION(context, Object, GetPropertyNames);
  auto self = Utils::OpenHandle(this);
  i::DirectHandle<i::FixedArray> value;
  i::KeyAccumulator accumulator(
      i_isolate, static_cast<i::KeyCollectionMode>(mode),
      static_cast<i::PropertyFilter>(property_filter));
  accumulator.set_skip_indices(index_filter == IndexFilter::kSkipIndices);
  has_exception = accumulator.CollectKeys(self, self).IsNothing();
  RETURN_ON_FAILED_EXECUTION(Array);
  value =
      accumulator.GetKeys(static_cast<i::GetKeysConversion>(key_conversion));
  DCHECK(self->map()->EnumLength() == i::kInvalidEnumCacheSentinel ||
         self->map()->EnumLength() == 0 ||
         self->map()->instance_descriptors(i_isolate)->enum_cache()->keys() !=
             *value);
  auto result = i_isolate->factory()->NewJSArrayWithElements(value);
  RETURN_ESCAPED(Utils::ToLocal(result));
}

MaybeLocal<Array> v8::Object::GetOwnPropertyNames(Local<Context> context) {
  return GetOwnPropertyNames(
      context, static_cast<v8::PropertyFilter>(ONLY_ENUMERABLE | SKIP_SYMBOLS));
}

MaybeLocal<Array> v8::Object::GetOwnPropertyNames(
    Local<Context> context, PropertyFilter filter,
    KeyConversionMode key_conversion) {
  return GetPropertyNames(context, KeyCollectionMode::kOwnOnly, filter,
                          v8::IndexFilter::kIncludeIndices, key_conversion);
}

MaybeLocal<String> v8::Object::ObjectProtoToString(Local<Context> context) {
  PREPARE_FOR_EXECUTION(context, Object, ObjectProtoToString);
  auto self = Utils::OpenHandle(this);
  Local<Value> result;
  has_exception = !ToLocal<Value>(
      i::Execution::CallBuiltin(i_isolate, i_isolate->object_to_string(), self,
                                0, nullptr),
      &result);
  RETURN_ON_FAILED_EXECUTION(String);
  RETURN_ESCAPED(Local<String>::Cast(result));
}

Local<String> v8::Object:
"""


```