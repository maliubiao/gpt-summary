Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine's WebAssembly C API implementation.

Here's a breakdown of how to approach this:

1. **Identify the Core Components:** Look for classes and structs that represent key concepts in WebAssembly, like `Trap`, `Frame`, `Foreign`, `Module`, `Shared<Module>`, `Extern`, `Func`, `Global`.

2. **Analyze Each Component's Functionality:** Read the methods within each class to understand what operations they perform. For example, `Trap::origin()` and `Trap::trace()` likely deal with stack information after a trap. `Module::validate()`, `Module::make()`, `Module::imports()`, `Module::exports()`, `Module::serialize()`, `Module::deserialize()`, `Module::share()`, and `Module::obtain()` clearly relate to managing WebAssembly modules. `Func::make()` and `Func::call()` are about creating and invoking WebAssembly functions.

3. **Look for Relationships:**  Notice how different components interact. For example, `Func` objects have a `FuncType`, and `Module` objects have imports and exports, which are of `ImportType` and `ExportType`.

4. **Pay Attention to V8 Integration:** The code uses V8's internal APIs (`i::Isolate`, `i::HandleScope`, `i::FixedArray`, `i::WasmModuleObject`, etc.). This indicates the code's role in bridging the C API with V8's internal WebAssembly representation.

5. **Note Specific Operations:** Identify actions like validation, compilation, instantiation, function calls, accessing globals, and managing memory.

6. **Address the Specific Instructions:**
    * **`.tq` check:**  The code does not end in `.tq`, so it's not Torque code.
    * **JavaScript relation:** If the C++ code interacts with JavaScript concepts or can be demonstrated via JavaScript, provide an example. The interaction with callbacks is a strong candidate here.
    * **Logic Inference:** Look for methods that perform calculations or transformations based on input. The `Func::call()` method involves argument packing and unpacking.
    * **Common Errors:** Think about potential issues developers might face when using these APIs. Incorrect argument types in function calls are a common problem.

7. **Synthesize the Summary:** Combine the identified functionalities into a concise description of the code's purpose.

**Pre-computation/Analysis of the Snippet:**

* **Traps and Frames:**  Deals with capturing and representing the call stack when a WebAssembly trap occurs.
* **Foreign Objects:** Represents external objects passed to WebAssembly.
* **Modules:** Provides functionalities for creating, validating, inspecting (imports/exports), serializing, and deserializing WebAssembly modules. The `share()` and `obtain()` methods suggest a mechanism for sharing compiled module data.
* **Shared Modules:** A way to hold serialized module data for sharing.
* **Externs:** A generic base class for external WebAssembly entities (functions, globals, tables, memories).
* **Functions:**  Allows creation of WebAssembly functions from C++ callbacks and calling both exported WebAssembly functions and C API functions. It handles argument marshalling and exception handling.
* **Globals:** Enables the creation and manipulation of WebAssembly global variables.

By following this process, we can accurately summarize the provided code's functionality.
这是 v8 源代码 `v8/src/wasm/c-api.cc` 的一部分，它主要负责实现 **WebAssembly C API** 的相关功能。

**功能归纳:**

这部分代码主要实现了以下功能：

1. **错误处理 (`Trap`, `Frame`)**:
   - `Trap`: 表示 WebAssembly 执行过程中发生的错误或异常。
   - `Trap::origin()`: 返回导致 trap 的栈帧信息。
   - `Trap::trace()`: 返回完整的 trap 堆栈跟踪信息。
   - `Frame`:  表示堆栈中的一个帧，包含模块、函数和偏移量等信息。

2. **外部对象 (`Foreign`)**:
   - `Foreign`:  表示从外部（非 WebAssembly 环境）传递给 WebAssembly 的对象。它提供了一种通用的方式来包装外部数据。

3. **模块 (`Module`)**:
   - `Module`:  代表一个已编译的 WebAssembly 模块。
   - `Module::validate()`: 验证 WebAssembly 字节码是否合法。
   - `Module::make()`:  根据 WebAssembly 字节码创建 `Module` 对象。
   - `Module::imports()`: 获取模块的导入声明信息（模块名、导入名、类型）。
   - `Module::exports()`: 获取模块的导出声明信息（导出名、类型）。
   - `Module::serialize()`: 将编译后的模块序列化为字节数组，用于持久化或传输。
   - `Module::deserialize()`: 从字节数组反序列化创建 `Module` 对象。
   - `Module::share()`:  创建一个可共享的模块表示，通常用于跨线程或进程共享。
   - `Module::obtain()`:  从共享的模块表示中获取 `Module` 对象。

4. **共享模块 (`Shared<Module>`)**:
   - `Shared<Module>`:  用于存储和管理可共享的模块数据（序列化后的字节码）。

5. **外部项 (`Extern`)**:
   - `Extern`:  表示 WebAssembly 模块的外部项，可以是函数、全局变量、表或内存。这是一个基类。
   - `Extern::kind()`:  获取外部项的类型（函数、全局变量等）。
   - `Extern::type()`:  获取外部项的类型信息。
   - `Extern::func()`, `Extern::global()`, `Extern::table()`, `Extern::memory()`:  将 `Extern` 对象转换为具体的子类型指针。
   - `extern_to_v8()`:  将 C API 的 `Extern` 对象转换为 V8 内部的表示。

6. **函数实例 (`Func`)**:
   - `Func`:  表示一个 WebAssembly 函数实例。
   - `Func::make()`:  创建 `Func` 对象，可以从 C++ 回调函数创建。
   - `Func::type()`:  获取函数的类型信息（参数和返回值类型）。
   - `Func::param_arity()`:  获取函数参数的数量。
   - `Func::result_arity()`:  获取函数返回值的数量。
   - `Func::call()`:  调用 WebAssembly 函数。

7. **全局变量实例 (`Global`)**:
   - `Global`:  表示一个 WebAssembly 全局变量实例。
   - `Global::make()`:  创建 `Global` 对象并初始化值。
   - `Global::type()`:  获取全局变量的类型信息（值类型和可变性）。
   - `Global::get()`:  获取全局变量的值。
   - `Global::set()`:  设置全局变量的值。

**关于代码特性:**

* **非 Torque 代码:** 代码以 `.cc` 结尾，表明它是 C++ 源代码，而不是以 `.tq` 结尾的 Torque 代码。
* **与 JavaScript 的关系:** 虽然这段代码是 C++ 实现的 WebAssembly C API，但它直接影响着 JavaScript 中如何使用 WebAssembly。例如，`Func::make()` 允许将 JavaScript 函数或 C++ 函数作为 WebAssembly 的导入函数使用，`Func::call()`  使得 JavaScript 可以调用 WebAssembly 函数。

**JavaScript 示例 (与 `Func` 相关):**

```javascript
// 假设我们有一个编译好的 WebAssembly 模块的字节码 'wasm_bytes'

// 1. 创建一个 Store
const store = new WebAssembly.Store();

// 2. 创建一个 Module
const module = new WebAssembly.Module(store, wasm_bytes);

// 3. 创建一个 Instance (需要 imports，这里假设没有 imports)
const instance = new WebAssembly.Instance(module, {});

// 4. 获取导出的函数
const exportedFunction = instance.exports.my_function;

// 5. 调用导出的函数
const result = exportedFunction(10, 20);

console.log(result);
```

这段 JavaScript 代码演示了如何加载、实例化 WebAssembly 模块以及调用导出的函数。在 `v8/src/wasm/c-api.cc` 中实现的 C API 就是为 JavaScript 的 `WebAssembly` 对象提供底层支持的。例如，`WebAssembly.Module` 的创建最终会调用到 `Module::make()` 这样的 C++ 函数。

**代码逻辑推理 (以 `Func::call()` 为例):**

**假设输入:**

* `func`: 一个 `Func` 对象的指针，代表要调用的 WebAssembly 函数。
* `args`: 一个 `Val` 类型的数组，包含传递给函数的参数。
* `results`: 一个 `Val` 类型的数组，用于存储函数执行的返回值。

**输出:**

* 如果函数调用成功，返回 `nullptr`。
* 如果函数调用过程中发生 trap，返回一个指向 `Trap` 对象的指针，包含错误信息。

**代码逻辑:**

`Func::call()` 方法的主要逻辑是：

1. **获取函数信息:** 从 `Func` 对象中获取 V8 内部的函数表示 (`i::JSFunction`) 和相关的元数据（例如，是否是 C API 函数，参数类型等）。
2. **参数准备:** 将 C API 的 `Val` 类型的参数转换为 V8 内部调用所需的格式。对于 WebAssembly 导出函数，这可能涉及到将参数打包到连续的内存区域。
3. **函数调用:**
   - 如果是 C API 函数 (`WasmCapiFunction`)，则直接调用其对应的 C++ 回调函数。
   - 如果是 WebAssembly 导出函数 (`WasmExportedFunction`)，则准备调用环境（例如，编译 wrapper 代码），然后使用 V8 的执行机制 (`i::Execution::CallWasm`) 来调用该函数。
4. **结果处理:** 将函数执行的结果（或 trap 信息）转换回 C API 的 `Val` 类型或 `Trap` 对象。
5. **异常处理:** 如果在调用过程中发生 JavaScript 异常，将其转换为 `Trap` 对象。

**用户常见的编程错误 (与 `Func::call()` 相关):**

1. **参数类型不匹配:**  传递给 `Func::call()` 的参数类型与函数签名不符，例如，传递了一个字符串给一个期望整数的参数。

   ```c++
   // 假设 func 指向一个接受 i32 参数的 WebAssembly 函数
   Val arg(ValKind::I32, "not an integer"); // 错误：类型不匹配
   Val result;
   own<Trap> trap = func->call(&arg, &result);
   ```

2. **参数数量不正确:**  传递的参数数量与函数定义的参数数量不符。

   ```c++
   // 假设 func 指向一个接受两个 i32 参数的 WebAssembly 函数
   Val arg1(ValKind::I32, 10);
   Val result;
   own<Trap> trap = func->call(&arg1, &result); // 错误：缺少一个参数
   ```

3. **返回值处理不当:**  没有正确分配或接收函数执行后的返回值。

   ```c++
   // 假设 func 指向一个返回 i32 的 WebAssembly 函数
   Val arg;
   // 没有为 result 分配空间
   own<Trap> trap = func->call(&arg, nullptr); // 潜在错误：尝试写入空指针
   ```

这段代码是 WebAssembly C API 的核心实现部分，它提供了在 C++ 中创建、管理和执行 WebAssembly 代码的关键接口。

### 提示词
```
这是目录为v8/src/wasm/c-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/c-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
stance), func_index, func_offset, module_offset)));
}

}  // namespace

own<Frame> Trap::origin() const {
  i::Isolate* isolate = impl(this)->isolate();
  PtrComprCageAccessScope ptr_compr_cage_access_scope(impl(this)->isolate());
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  i::HandleScope handle_scope(isolate);

  i::DirectHandle<i::FixedArray> frames =
      isolate->GetSimpleStackTrace(impl(this)->v8_object());
  if (frames->length() == 0) {
    return own<Frame>();
  }
  return CreateFrameFromInternal(frames, 0, isolate, impl(this)->store());
}

ownvec<Frame> Trap::trace() const {
  i::Isolate* isolate = impl(this)->isolate();
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate);
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  i::HandleScope handle_scope(isolate);

  i::DirectHandle<i::FixedArray> frames =
      isolate->GetSimpleStackTrace(impl(this)->v8_object());
  int num_frames = frames->length();
  // {num_frames} can be 0; the code below can handle that case.
  ownvec<Frame> result = ownvec<Frame>::make_uninitialized(num_frames);
  for (int i = 0; i < num_frames; i++) {
    result[i] =
        CreateFrameFromInternal(frames, i, isolate, impl(this)->store());
  }
  return result;
}

// Foreign Objects

template <>
struct implement<Foreign> {
  using type = RefImpl<Foreign, i::JSReceiver>;
};

Foreign::~Foreign() = default;

auto Foreign::copy() const -> own<Foreign> { return impl(this)->copy(); }

auto Foreign::make(Store* store_abs) -> own<Foreign> {
  StoreImpl* store = impl(store_abs);
  v8::Isolate::Scope isolate_scope(store->isolate());
  i::Isolate* isolate = store->i_isolate();
  i::HandleScope handle_scope(isolate);

  i::Handle<i::JSObject> obj =
      isolate->factory()->NewJSObject(isolate->object_function());
  return implement<Foreign>::type::make(store, obj);
}

// Modules

template <>
struct implement<Module> {
  using type = RefImpl<Module, i::WasmModuleObject>;
};

Module::~Module() = default;

auto Module::copy() const -> own<Module> { return impl(this)->copy(); }

auto Module::validate(Store* store_abs, const vec<byte_t>& binary) -> bool {
  i::wasm::ModuleWireBytes bytes(
      {reinterpret_cast<const uint8_t*>(binary.get()), binary.size()});
  i::Isolate* isolate = impl(store_abs)->i_isolate();
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate);
  i::HandleScope scope(isolate);
  i::wasm::WasmEnabledFeatures features =
      i::wasm::WasmEnabledFeatures::FromIsolate(isolate);
  i::wasm::CompileTimeImports imports;
  return i::wasm::GetWasmEngine()->SyncValidate(isolate, features,
                                                std::move(imports), bytes);
}

auto Module::make(Store* store_abs, const vec<byte_t>& binary) -> own<Module> {
  StoreImpl* store = impl(store_abs);
  i::Isolate* isolate = store->i_isolate();
  v8::Isolate::Scope isolate_scope(store->isolate());
  i::HandleScope scope(isolate);
  CheckAndHandleInterrupts(isolate);
  i::wasm::ModuleWireBytes bytes(
      {reinterpret_cast<const uint8_t*>(binary.get()), binary.size()});
  i::wasm::WasmEnabledFeatures features =
      i::wasm::WasmEnabledFeatures::FromIsolate(isolate);
  i::wasm::CompileTimeImports imports;
  i::wasm::ErrorThrower thrower(isolate, "ignored");
  i::Handle<i::WasmModuleObject> module;
  if (!i::wasm::GetWasmEngine()
           ->SyncCompile(isolate, features, std::move(imports), &thrower, bytes)
           .ToHandle(&module)) {
    thrower.Reset();  // The API provides no way to expose the error.
    return nullptr;
  }
  return implement<Module>::type::make(store, module);
}

auto Module::imports() const -> ownvec<ImportType> {
  const i::wasm::NativeModule* native_module =
      impl(this)->v8_object()->native_module();
  const i::wasm::WasmModule* module = native_module->module();
  const v8::base::Vector<const uint8_t> wire_bytes =
      native_module->wire_bytes();
  const std::vector<i::wasm::WasmImport>& import_table = module->import_table;
  size_t size = import_table.size();
  ownvec<ImportType> imports = ownvec<ImportType>::make_uninitialized(size);
  for (uint32_t i = 0; i < size; i++) {
    const i::wasm::WasmImport& imp = import_table[i];
    Name module_name = GetNameFromWireBytes(imp.module_name, wire_bytes);
    Name name = GetNameFromWireBytes(imp.field_name, wire_bytes);
    own<ExternType> type = GetImportExportType(module, imp.kind, imp.index);
    imports[i] = ImportType::make(std::move(module_name), std::move(name),
                                  std::move(type));
  }
  return imports;
}

ownvec<ExportType> ExportsImpl(
    i::DirectHandle<i::WasmModuleObject> module_obj) {
  const i::wasm::NativeModule* native_module = module_obj->native_module();
  const i::wasm::WasmModule* module = native_module->module();
  const v8::base::Vector<const uint8_t> wire_bytes =
      native_module->wire_bytes();
  const std::vector<i::wasm::WasmExport>& export_table = module->export_table;
  size_t size = export_table.size();
  ownvec<ExportType> exports = ownvec<ExportType>::make_uninitialized(size);
  for (uint32_t i = 0; i < size; i++) {
    const i::wasm::WasmExport& exp = export_table[i];
    Name name = GetNameFromWireBytes(exp.name, wire_bytes);
    own<ExternType> type = GetImportExportType(module, exp.kind, exp.index);
    exports[i] = ExportType::make(std::move(name), std::move(type));
  }
  return exports;
}

auto Module::exports() const -> ownvec<ExportType> {
  i::Isolate* isolate = impl(this)->isolate();
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate);
  return ExportsImpl(impl(this)->v8_object());
}

// We tier up all functions to TurboFan, and then serialize all TurboFan code.
// If no TurboFan code existed before calling this function, then the call to
// {serialize} may take a long time.
auto Module::serialize() const -> vec<byte_t> {
  i::Isolate* isolate = impl(this)->isolate();
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate);
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  i::wasm::NativeModule* native_module =
      impl(this)->v8_object()->native_module();
  native_module->compilation_state()->TierUpAllFunctions();
  v8::base::Vector<const uint8_t> wire_bytes = native_module->wire_bytes();
  size_t binary_size = wire_bytes.size();
  i::wasm::WasmSerializer serializer(native_module);
  size_t serial_size = serializer.GetSerializedNativeModuleSize();
  size_t size_size = i::wasm::LEBHelper::sizeof_u64v(binary_size);
  vec<byte_t> buffer =
      vec<byte_t>::make_uninitialized(size_size + binary_size + serial_size);
  byte_t* ptr = buffer.get();
  i::wasm::LEBHelper::write_u64v(reinterpret_cast<uint8_t**>(&ptr),
                                 binary_size);
  std::memcpy(ptr, wire_bytes.begin(), binary_size);
  ptr += binary_size;
  if (!serializer.SerializeNativeModule(
          {reinterpret_cast<uint8_t*>(ptr), serial_size})) {
    // Serialization fails if no TurboFan code is present. This may happen
    // because the module does not have any functions, or because another thread
    // modifies the {NativeModule} concurrently. In this case, the serialized
    // module just contains the wire bytes.
    buffer = vec<byte_t>::make_uninitialized(size_size + binary_size);
    byte_t* ptr = buffer.get();
    i::wasm::LEBHelper::write_u64v(reinterpret_cast<uint8_t**>(&ptr),
                                   binary_size);
    std::memcpy(ptr, wire_bytes.begin(), binary_size);
  }
  return buffer;
}

auto Module::deserialize(Store* store_abs, const vec<byte_t>& serialized)
    -> own<Module> {
  StoreImpl* store = impl(store_abs);
  i::Isolate* isolate = store->i_isolate();
  v8::Isolate::Scope isolate_scope(store->isolate());
  i::HandleScope handle_scope(isolate);
  const byte_t* ptr = serialized.get();
  uint64_t binary_size = ReadLebU64(&ptr);
  ptrdiff_t size_size = ptr - serialized.get();
  size_t serial_size = serialized.size() - size_size - binary_size;
  i::Handle<i::WasmModuleObject> module_obj;
  if (serial_size > 0) {
    size_t data_size = static_cast<size_t>(binary_size);
    i::wasm::CompileTimeImports compile_imports{};
    if (!i::wasm::DeserializeNativeModule(
             isolate,
             {reinterpret_cast<const uint8_t*>(ptr + data_size), serial_size},
             {reinterpret_cast<const uint8_t*>(ptr), data_size},
             compile_imports, {})
             .ToHandle(&module_obj)) {
      // We were given a serialized module, but failed to deserialize. Report
      // this as an error.
      return nullptr;
    }
  } else {
    // No serialized module was given. This is fine, just create a module from
    // scratch.
    vec<byte_t> binary = vec<byte_t>::make_uninitialized(binary_size);
    std::memcpy(binary.get(), ptr, binary_size);
    return make(store_abs, binary);
  }
  return implement<Module>::type::make(store, module_obj);
}

// TODO(v8): do better when V8 can do better.
template <>
struct implement<Shared<Module>> {
  using type = vec<byte_t>;
};

template <>
Shared<Module>::~Shared() {
  impl(this)->~vec();
}

template <>
void Shared<Module>::operator delete(void* p) {
  ::operator delete(p);
}

auto Module::share() const -> own<Shared<Module>> {
  auto shared = seal<Shared<Module>>(new vec<byte_t>(serialize()));
  return make_own(shared);
}

auto Module::obtain(Store* store, const Shared<Module>* shared) -> own<Module> {
  return Module::deserialize(store, *impl(shared));
}

// Externals

template <>
struct implement<Extern> {
  using type = RefImpl<Extern, i::JSReceiver>;
};

Extern::~Extern() = default;

auto Extern::copy() const -> own<Extern> { return impl(this)->copy(); }

auto Extern::kind() const -> ExternKind {
  i::Isolate* isolate = impl(this)->isolate();
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate);
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));

  i::DirectHandle<i::JSReceiver> obj = impl(this)->v8_object();
  if (i::WasmExternalFunction::IsWasmExternalFunction(*obj)) {
    return wasm::EXTERN_FUNC;
  }
  if (IsWasmGlobalObject(*obj)) return wasm::EXTERN_GLOBAL;
  if (IsWasmTableObject(*obj)) return wasm::EXTERN_TABLE;
  if (IsWasmMemoryObject(*obj)) return wasm::EXTERN_MEMORY;
  UNREACHABLE();
}

auto Extern::type() const -> own<ExternType> {
  switch (kind()) {
    case EXTERN_FUNC:
      return func()->type();
    case EXTERN_GLOBAL:
      return global()->type();
    case EXTERN_TABLE:
      return table()->type();
    case EXTERN_MEMORY:
      return memory()->type();
  }
}

auto Extern::func() -> Func* {
  return kind() == EXTERN_FUNC ? static_cast<Func*>(this) : nullptr;
}

auto Extern::global() -> Global* {
  return kind() == EXTERN_GLOBAL ? static_cast<Global*>(this) : nullptr;
}

auto Extern::table() -> Table* {
  return kind() == EXTERN_TABLE ? static_cast<Table*>(this) : nullptr;
}

auto Extern::memory() -> Memory* {
  return kind() == EXTERN_MEMORY ? static_cast<Memory*>(this) : nullptr;
}

auto Extern::func() const -> const Func* {
  return kind() == EXTERN_FUNC ? static_cast<const Func*>(this) : nullptr;
}

auto Extern::global() const -> const Global* {
  return kind() == EXTERN_GLOBAL ? static_cast<const Global*>(this) : nullptr;
}

auto Extern::table() const -> const Table* {
  return kind() == EXTERN_TABLE ? static_cast<const Table*>(this) : nullptr;
}

auto Extern::memory() const -> const Memory* {
  return kind() == EXTERN_MEMORY ? static_cast<const Memory*>(this) : nullptr;
}

auto extern_to_v8(const Extern* ex) -> i::Handle<i::JSReceiver> {
  return impl(ex)->v8_object();
}

// Function Instances

template <>
struct implement<Func> {
  using type = RefImpl<Func, i::JSFunction>;
};

Func::~Func() = default;

auto Func::copy() const -> own<Func> { return impl(this)->copy(); }

struct FuncData {
  static constexpr i::ExternalPointerTag kManagedTag = i::kWasmFuncDataTag;

  Store* store;
  own<FuncType> type;
  enum Kind { kCallback, kCallbackWithEnv } kind;
  union {
    Func::callback callback;
    Func::callback_with_env callback_with_env;
  };
  void (*finalizer)(void*);
  void* env;

  FuncData(Store* store, const FuncType* type, Kind kind)
      : store(store),
        type(type->copy()),
        kind(kind),
        finalizer(nullptr),
        env(nullptr) {}

  ~FuncData() {
    if (finalizer) (*finalizer)(env);
  }

  static i::Address v8_callback(i::Address host_data_foreign, i::Address argv);
};

namespace {

class SignatureHelper : public i::AllStatic {
 public:
  static const i::wasm::CanonicalTypeIndex Canonicalize(FuncType* type) {
    std::vector<i::wasm::ValueType> types;
    types.reserve(type->results().size() + type->params().size());

    // TODO(jkummerow): Consider making vec<> range-based for-iterable.
    for (size_t i = 0; i < type->results().size(); i++) {
      types.push_back(WasmValKindToV8(type->results()[i]->kind()));
    }
    for (size_t i = 0; i < type->params().size(); i++) {
      types.push_back(WasmValKindToV8(type->params()[i]->kind()));
    }

    i::wasm::FunctionSig non_canonical_sig{type->results().size(),
                                           type->params().size(), types.data()};
    return i::wasm::GetTypeCanonicalizer()->AddRecursiveGroup(
        &non_canonical_sig);
  }

  static own<FuncType> FromV8Sig(const i::wasm::CanonicalSig* sig) {
    int result_arity = static_cast<int>(sig->return_count());
    int param_arity = static_cast<int>(sig->parameter_count());
    ownvec<ValType> results = ownvec<ValType>::make_uninitialized(result_arity);
    ownvec<ValType> params = ownvec<ValType>::make_uninitialized(param_arity);

    for (int i = 0; i < result_arity; ++i) {
      results[i] = ValType::make(V8ValueTypeToWasm(sig->GetReturn(i)));
    }
    for (int i = 0; i < param_arity; ++i) {
      params[i] = ValType::make(V8ValueTypeToWasm(sig->GetParam(i)));
    }
    return FuncType::make(std::move(params), std::move(results));
  }

  static const i::wasm::CanonicalSig* GetSig(
      i::DirectHandle<i::JSFunction> function) {
    return i::Cast<i::WasmCapiFunction>(*function)->sig();
  }

#if V8_ENABLE_SANDBOX
  // Wraps {FuncType} so it has the same interface as {v8::internal::Signature}.
  struct FuncTypeAdapter {
    const FuncType* type = nullptr;
    size_t parameter_count() const { return type->params().size(); }
    size_t return_count() const { return type->results().size(); }
    i::wasm::ValueType GetParam(size_t i) const {
      return WasmValKindToV8(type->params()[i]->kind());
    }
    i::wasm::ValueType GetReturn(size_t i) const {
      return WasmValKindToV8(type->results()[i]->kind());
    }
  };
  static uint64_t Hash(FuncType* type) {
    FuncTypeAdapter adapter{type};
    return i::wasm::SignatureHasher::Hash(&adapter);
  }
#endif
};

auto make_func(Store* store_abs, std::shared_ptr<FuncData> data) -> own<Func> {
  auto store = impl(store_abs);
  i::Isolate* isolate = store->i_isolate();
  v8::Isolate::Scope isolate_scope(store->isolate());
  i::HandleScope handle_scope(isolate);
  CheckAndHandleInterrupts(isolate);
  i::DirectHandle<i::Managed<FuncData>> embedder_data =
      i::Managed<FuncData>::From(isolate, sizeof(FuncData), data);
#if V8_ENABLE_SANDBOX
  uint64_t signature_hash = SignatureHelper::Hash(data->type.get());
#else
  uintptr_t signature_hash = 0;
#endif  // V8_ENABLE_SANDBOX
  i::wasm::CanonicalTypeIndex sig_index =
      SignatureHelper::Canonicalize(data->type.get());
  const i::wasm::CanonicalSig* sig =
      i::wasm::GetTypeCanonicalizer()->LookupFunctionSignature(sig_index);
  i::Handle<i::WasmCapiFunction> function = i::WasmCapiFunction::New(
      isolate, reinterpret_cast<i::Address>(&FuncData::v8_callback),
      embedder_data, sig_index, sig, signature_hash);
  i::Cast<i::WasmImportData>(
      function->shared()->wasm_capi_function_data()->internal()->implicit_arg())
      ->set_callable(*function);
  auto func = implement<Func>::type::make(store, function);
  return func;
}

}  // namespace

auto Func::make(Store* store, const FuncType* type, Func::callback callback)
    -> own<Func> {
  auto data = std::make_shared<FuncData>(store, type, FuncData::kCallback);
  data->callback = callback;
  return make_func(store, data);
}

auto Func::make(Store* store, const FuncType* type, callback_with_env callback,
                void* env, void (*finalizer)(void*)) -> own<Func> {
  auto data =
      std::make_shared<FuncData>(store, type, FuncData::kCallbackWithEnv);
  data->callback_with_env = callback;
  data->env = env;
  data->finalizer = finalizer;
  return make_func(store, data);
}

auto Func::type() const -> own<FuncType> {
  i::Isolate* isolate = impl(this)->isolate();
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate);
  i::DirectHandle<i::JSFunction> func = impl(this)->v8_object();
  if (i::WasmCapiFunction::IsWasmCapiFunction(*func)) {
    return SignatureHelper::FromV8Sig(SignatureHelper::GetSig(func));
  }
  DCHECK(i::WasmExportedFunction::IsWasmExportedFunction(*func));
  auto function = i::Cast<i::WasmExportedFunction>(func);
  auto data = function->shared()->wasm_exported_function_data();
  return FunctionSigToFuncType(
      data->instance_data()->module()->functions[data->function_index()].sig);
}

auto Func::param_arity() const -> size_t {
  i::Isolate* isolate = impl(this)->isolate();
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate);
  i::DirectHandle<i::JSFunction> func = impl(this)->v8_object();
  if (i::WasmCapiFunction::IsWasmCapiFunction(*func)) {
    return SignatureHelper::GetSig(func)->parameter_count();
  }
  DCHECK(i::WasmExportedFunction::IsWasmExportedFunction(*func));
  auto function = i::Cast<i::WasmExportedFunction>(func);
  auto data = function->shared()->wasm_exported_function_data();
  const i::wasm::FunctionSig* sig =
      data->instance_data()->module()->functions[data->function_index()].sig;
  return sig->parameter_count();
}

auto Func::result_arity() const -> size_t {
  i::Isolate* isolate = impl(this)->isolate();
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate);
  i::DirectHandle<i::JSFunction> func = impl(this)->v8_object();
  if (i::WasmCapiFunction::IsWasmCapiFunction(*func)) {
    return SignatureHelper::GetSig(func)->return_count();
  }
  DCHECK(i::WasmExportedFunction::IsWasmExportedFunction(*func));
  auto function = i::Cast<i::WasmExportedFunction>(func);
  auto data = function->shared()->wasm_exported_function_data();
  const i::wasm::FunctionSig* sig =
      data->instance_data()->module()->functions[data->function_index()].sig;
  return sig->return_count();
}

namespace {

own<Ref> V8RefValueToWasm(StoreImpl* store, i::Handle<i::Object> value) {
  if (IsNull(*value, store->i_isolate())) return nullptr;
  return implement<Ref>::type::make(store, i::Cast<i::JSReceiver>(value));
}

i::Handle<i::Object> WasmRefToV8(i::Isolate* isolate, const Ref* ref) {
  if (ref == nullptr) return i::ReadOnlyRoots(isolate).null_value_handle();
  return impl(ref)->v8_object();
}

void PrepareFunctionData(
    i::Isolate* isolate,
    i::DirectHandle<i::WasmExportedFunctionData> function_data,
    const i::wasm::CanonicalSig* sig) {
  // If the data is already populated, return immediately.
  // TODO(saelo): We need to use full pointer comparison here while not all Code
  // objects have migrated into trusted space.
  static_assert(!i::kAllCodeObjectsLiveInTrustedSpace);
  if (!function_data->c_wrapper_code(isolate).SafeEquals(
          *BUILTIN_CODE(isolate, Illegal))) {
    return;
  }
  // Compile wrapper code.
  i::DirectHandle<i::Code> wrapper_code =
      i::compiler::CompileCWasmEntry(isolate, sig);
  function_data->set_c_wrapper_code(*wrapper_code);
  // Compute packed args size.
  function_data->set_packed_args_size(
      i::wasm::CWasmArgumentsPacker::TotalSize(sig));
}

void PushArgs(const i::wasm::CanonicalSig* sig, const Val args[],
              i::wasm::CWasmArgumentsPacker* packer, StoreImpl* store) {
  for (size_t i = 0; i < sig->parameter_count(); i++) {
    i::wasm::CanonicalValueType type = sig->GetParam(i);
    switch (type.kind()) {
      case i::wasm::kI32:
        packer->Push(args[i].i32());
        break;
      case i::wasm::kI64:
        packer->Push(args[i].i64());
        break;
      case i::wasm::kF32:
        packer->Push(args[i].f32());
        break;
      case i::wasm::kF64:
        packer->Push(args[i].f64());
        break;
      case i::wasm::kRef:
      case i::wasm::kRefNull:
        // TODO(14034): Make sure this works for all heap types.
        packer->Push((*WasmRefToV8(store->i_isolate(), args[i].ref())).ptr());
        break;
      case i::wasm::kS128:
        // TODO(14034): Implement.
        UNIMPLEMENTED();
      case i::wasm::kRtt:
      case i::wasm::kI8:
      case i::wasm::kI16:
      case i::wasm::kF16:
      case i::wasm::kVoid:
      case i::wasm::kTop:
      case i::wasm::kBottom:
        UNREACHABLE();
    }
  }
}

void PopArgs(const i::wasm::CanonicalSig* sig, Val results[],
             i::wasm::CWasmArgumentsPacker* packer, StoreImpl* store) {
  packer->Reset();
  for (size_t i = 0; i < sig->return_count(); i++) {
    i::wasm::CanonicalValueType type = sig->GetReturn(i);
    switch (type.kind()) {
      case i::wasm::kI32:
        results[i] = Val(packer->Pop<int32_t>());
        break;
      case i::wasm::kI64:
        results[i] = Val(packer->Pop<int64_t>());
        break;
      case i::wasm::kF32:
        results[i] = Val(packer->Pop<float>());
        break;
      case i::wasm::kF64:
        results[i] = Val(packer->Pop<double>());
        break;
      case i::wasm::kRef:
      case i::wasm::kRefNull: {
        // TODO(14034): Make sure this works for all heap types.
        i::Address raw = packer->Pop<i::Address>();
        i::Handle<i::Object> obj(i::Tagged<i::Object>(raw), store->i_isolate());
        results[i] = Val(V8RefValueToWasm(store, obj));
        break;
      }
      case i::wasm::kS128:
        // TODO(14034): Implement.
        UNIMPLEMENTED();
      case i::wasm::kRtt:
      case i::wasm::kI8:
      case i::wasm::kI16:
      case i::wasm::kF16:
      case i::wasm::kVoid:
      case i::wasm::kTop:
      case i::wasm::kBottom:
        UNREACHABLE();
    }
  }
}

own<Trap> CallWasmCapiFunction(i::Tagged<i::WasmCapiFunctionData> data,
                               const Val args[], Val results[]) {
  FuncData* func_data =
      i::Cast<i::Managed<FuncData>>(data->embedder_data())->raw();
  if (func_data->kind == FuncData::kCallback) {
    return (func_data->callback)(args, results);
  }
  DCHECK(func_data->kind == FuncData::kCallbackWithEnv);
  return (func_data->callback_with_env)(func_data->env, args, results);
}

i::Handle<i::JSReceiver> GetProperException(
    i::Isolate* isolate, i::Handle<i::Object> maybe_exception) {
  if (IsJSReceiver(*maybe_exception)) {
    return i::Cast<i::JSReceiver>(maybe_exception);
  }
  if (v8::internal::IsTerminationException(*maybe_exception)) {
    i::DirectHandle<i::String> string =
        isolate->factory()->NewStringFromAsciiChecked("TerminationException");
    return isolate->factory()->NewError(isolate->error_function(), string);
  }
  i::MaybeHandle<i::String> maybe_string =
      i::Object::ToString(isolate, maybe_exception);
  i::Handle<i::String> string = isolate->factory()->empty_string();
  if (!maybe_string.ToHandle(&string)) {
    // If converting the {maybe_exception} to string threw another exception,
    // just give up and leave {string} as the empty string.
    isolate->clear_exception();
  }
  // {NewError} cannot fail when its input is a plain String, so we always
  // get an Error object here.
  return i::Cast<i::JSReceiver>(
      isolate->factory()->NewError(isolate->error_function(), string));
}

}  // namespace

auto Func::call(const Val args[], Val results[]) const -> own<Trap> {
  auto func = impl(this);
  auto store = func->store();
  auto isolate = store->i_isolate();
  v8::Isolate::Scope isolate_scope(store->isolate());
  i::HandleScope handle_scope(isolate);
  i::Tagged<i::Object> raw_function_data =
      func->v8_object()->shared()->GetTrustedData(isolate);

  // WasmCapiFunctions can be called directly.
  if (IsWasmCapiFunctionData(raw_function_data)) {
    return CallWasmCapiFunction(
        i::Cast<i::WasmCapiFunctionData>(raw_function_data), args, results);
  }

  SBXCHECK(IsWasmExportedFunctionData(raw_function_data));
  i::DirectHandle<i::WasmExportedFunctionData> function_data{
      i::Cast<i::WasmExportedFunctionData>(raw_function_data), isolate};
  i::DirectHandle<i::WasmTrustedInstanceData> instance_data{
      function_data->instance_data(), isolate};
  int function_index = function_data->function_index();
  const i::wasm::WasmModule* module = instance_data->module();
  // Caching {sig} would reduce overhead substantially.
  const i::wasm::CanonicalSig* sig =
      i::wasm::GetTypeCanonicalizer()->LookupFunctionSignature(
          module->canonical_sig_id(
              module->functions[function_index].sig_index));
  PrepareFunctionData(isolate, function_data, sig);
  i::DirectHandle<i::Code> wrapper_code(function_data->c_wrapper_code(isolate),
                                        isolate);
  i::WasmCodePointer call_target = function_data->internal()->call_target();

  i::wasm::CWasmArgumentsPacker packer(function_data->packed_args_size());
  PushArgs(sig, args, &packer, store);

  i::DirectHandle<i::Object> object_ref;
  if (function_index < static_cast<int>(module->num_imported_functions)) {
    object_ref =
        i::handle(instance_data->dispatch_table_for_imports()->implicit_arg(
                      function_index),
                  isolate);
    if (IsWasmImportData(*object_ref)) {
      i::Tagged<i::JSFunction> jsfunc = i::Cast<i::JSFunction>(
          i::Cast<i::WasmImportData>(*object_ref)->callable());
      i::Tagged<i::Object> data = jsfunc->shared()->GetTrustedData(isolate);
      if (IsWasmCapiFunctionData(data)) {
        return CallWasmCapiFunction(i::Cast<i::WasmCapiFunctionData>(data),
                                    args, results);
      }
      // TODO(jkummerow): Imported and then re-exported JavaScript functions
      // are not supported yet. If we support C-API + JavaScript, we'll need
      // to call those here.
      UNIMPLEMENTED();
    } else {
      // A WasmFunction from another module.
      DCHECK(IsWasmInstanceObject(*object_ref));
    }
  } else {
    // TODO(42204563): Avoid crashing if the instance object is not available.
    CHECK(instance_data->has_instance_object());
    object_ref = handle(instance_data->instance_object(), isolate);
  }

  i::Execution::CallWasm(isolate, wrapper_code, call_target, object_ref,
                         packer.argv());

  if (isolate->has_exception()) {
    i::Handle<i::Object> exception(isolate->exception(), isolate);
    isolate->clear_exception();
    return implement<Trap>::type::make(store,
                                       GetProperException(isolate, exception));
  }

  PopArgs(sig, results, &packer, store);
  return nullptr;
}

i::Address FuncData::v8_callback(i::Address host_data_foreign,
                                 i::Address argv) {
  FuncData* self =
      i::Cast<i::Managed<FuncData>>(i::Tagged<i::Object>(host_data_foreign))
          ->raw();
  StoreImpl* store = impl(self->store);
  i::Isolate* isolate = store->i_isolate();
  v8::Isolate::Scope isolate_scope(store->isolate());
  i::HandleScope scope(isolate);

  isolate->set_context(*v8::Utils::OpenDirectHandle(*store->context()));

  const ownvec<ValType>& param_types = self->type->params();
  const ownvec<ValType>& result_types = self->type->results();

  int num_param_types = static_cast<int>(param_types.size());
  int num_result_types = static_cast<int>(result_types.size());

  std::unique_ptr<Val[]> params(new Val[num_param_types]);
  std::unique_ptr<Val[]> results(new Val[num_result_types]);
  i::Address p = argv;
  for (int i = 0; i < num_param_types; ++i) {
    switch (param_types[i]->kind()) {
      case I32:
        params[i] = Val(v8::base::ReadUnalignedValue<int32_t>(p));
        p += 4;
        break;
      case I64:
        params[i] = Val(v8::base::ReadUnalignedValue<int64_t>(p));
        p += 8;
        break;
      case F32:
        params[i] = Val(v8::base::ReadUnalignedValue<float32_t>(p));
        p += 4;
        break;
      case F64:
        params[i] = Val(v8::base::ReadUnalignedValue<float64_t>(p));
        p += 8;
        break;
      case ANYREF:
      case FUNCREF: {
        i::Address raw = v8::base::ReadUnalignedValue<i::Address>(p);
        p += sizeof(raw);
        i::Handle<i::Object> obj(i::Tagged<i::Object>(raw), isolate);
        params[i] = Val(V8RefValueToWasm(store, obj));
        break;
      }
    }
  }

  own<Trap> trap;
  if (self->kind == kCallbackWithEnv) {
    trap = self->callback_with_env(self->env, params.get(), results.get());
  } else {
    trap = self->callback(params.get(), results.get());
  }

  if (trap) {
    isolate->Throw(*impl(trap.get())->v8_object());
    i::Tagged<i::Object> ex = isolate->exception();
    isolate->clear_exception();
    return ex.ptr();
  }

  p = argv;
  for (int i = 0; i < num_result_types; ++i) {
    switch (result_types[i]->kind()) {
      case I32:
        v8::base::WriteUnalignedValue(p, results[i].i32());
        p += 4;
        break;
      case I64:
        v8::base::WriteUnalignedValue(p, results[i].i64());
        p += 8;
        break;
      case F32:
        v8::base::WriteUnalignedValue(p, results[i].f32());
        p += 4;
        break;
      case F64:
        v8::base::WriteUnalignedValue(p, results[i].f64());
        p += 8;
        break;
      case ANYREF:
      case FUNCREF: {
        v8::base::WriteUnalignedValue(
            p, (*WasmRefToV8(isolate, results[i].ref())).ptr());
        p += sizeof(i::Address);
        break;
      }
    }
  }
  return i::kNullAddress;
}

// Global Instances

template <>
struct implement<Global> {
  using type = RefImpl<Global, i::WasmGlobalObject>;
};

Global::~Global() = default;

auto Global::copy() const -> own<Global> { return impl(this)->copy(); }

auto Global::make(Store* store_abs, const GlobalType* type, const Val& val)
    -> own<Global> {
  StoreImpl* store = impl(store_abs);
  v8::Isolate::Scope isolate_scope(store->isolate());
  i::Isolate* isolate = store->i_isolate();
  i::HandleScope handle_scope(isolate);
  CheckAndHandleInterrupts(isolate);

  DCHECK_EQ(type->content()->kind(), val.kind());

  i::wasm::ValueType i_type = WasmValKindToV8(type->content()->kind());
  bool is_mutable = (type->mutability() == VAR);
  const int32_t offset = 0;
  i::Handle<i::WasmGlobalObject> obj =
      i::WasmGlobalObject::New(isolate, i::Handle<i::WasmTrustedInstanceData>(),
                               i::MaybeHandle<i::JSArrayBuffer>(),
                               i::MaybeHandle<i::FixedArray>(), i_type, offset,
                               is_mutable)
          .ToHandleChecked();

  auto global = implement<Global>::type::make(store, obj);
  assert(global);
  global->set(val);
  return global;
}

auto Global::type() const -> own<GlobalType> {
  i::DirectHandle<i::WasmGlobalObject> v8_global = impl(this)->v8_object();
  ValKind kind = V8ValueTypeToWasm(v8_global->type());
  Mutability mutability = v8_global->is_mutable() ? VAR : CONST;
  return GlobalType::make(ValType::make(kind), mutability);
}

auto Global::get() const -> Val {
  i::Isolate* isolate = impl(this)->isolate();
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate);
  i::DirectHandle<i::WasmGlobalObject> v8_global = impl(this)->v8_object();
  switch (v8_global->type().kind()) {
    case i::wasm::kI32:
      return Val(v8_global->GetI32());
    case i::wasm::kI64:
      return Val(v8_global->GetI64());
    case i::wasm::kF32:
      return Val(v8_global->GetF32());
    case i::wasm::kF64:
      return Val(v8_global->GetF64());
    case i::wasm::kRef:
    case i::wasm::kRefNull: {
      // TODO(14034): Handle types other than funcref and externref if needed.
      StoreImpl* store = impl(this)->store();
      i::HandleScope scope(store->i_isolate());
      v8::Isolate::Scope isolate_scope(store->isolate());
      i::Handle<i::Object> result = v8_global->GetRef();
      if (IsWasmFuncR
```