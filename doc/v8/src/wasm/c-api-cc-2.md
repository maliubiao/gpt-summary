Response:
Let's break down the thought process for analyzing this V8 C++ code snippet.

1. **Understanding the Goal:** The request asks for a functional summary of the provided C++ code, specifically targeting the `v8/src/wasm/c-api.cc` file. It also includes conditions related to file extensions, JavaScript interaction, logical inference, and common programming errors. The "Part 3 of 4" indicates this is a piece of a larger file.

2. **Initial Scan for Keywords:**  A quick skim reveals terms like `Global`, `Table`, `Memory`, `Instance`, `Module`, `Store`, `Engine`, `Val`, `Ref`, `Type`, and various C API-style function names (starting with `wasm_`). This strongly suggests this code implements the C API for interacting with WebAssembly within V8.

3. **Identifying Key Classes/Structures:**  The code defines C++ structures and classes like `Global`, `Table`, `Memory`, and `Instance`. The `implement<>` template pattern is a clue that these C++ classes are wrappers or implementations of internal V8 objects (e.g., `i::WasmGlobalObject`).

4. **Analyzing Individual Components:**  The next step is to analyze the functionality of each of these classes:

    * **`Global`:**  The `get()` method retrieves a value from a Wasm global, handling different value types (I32, I64, F32, F64, ANYREF, FUNCREF). The `set()` method does the opposite, setting the value of a Wasm global. This clearly relates to accessing and modifying global variables in Wasm modules.

    * **`Table`:** The code deals with creating (`make`), copying (`copy`), and inspecting table types (`type`). Crucially, `get()` and `set()` allow access to individual elements in the table. `grow()` increases the table size. This strongly indicates it's managing Wasm tables, which are dynamically sized arrays of references.

    * **`Memory`:** Similar to `Table`, it has `make` and `copy`. `data()` and `data_size()` provide access to the underlying memory buffer. `size()` returns the size in pages, and `grow()` allows increasing the memory size. This is clearly about managing the linear memory of a Wasm module.

    * **`Instance`:** The `make()` method takes a `Module` and imports to create a Wasm instance. `exports()` retrieves the exported functions, globals, tables, and memories from an instance. This is the central part of instantiating and interacting with a loaded Wasm module.

5. **Connecting to V8 Internals:** The code uses `i::` prefixes (e.g., `i::WasmGlobalObject`, `i::Isolate`). This signifies direct interaction with V8's internal representation of Wasm objects. The conversions between `Val` and internal V8 handles (`WasmRefToV8`, `V8RefValueToWasm`) are essential for bridging the C API and the internal V8 implementation.

6. **Identifying C API Bindings:** The section starting with `extern "C" {` and the `wasm_` prefixed function names (e.g., `wasm_global_get`, `wasm_table_set`) confirm that this code is defining the C API for Wasm in V8. The macros like `WASM_DEFINE_OWN`, `WASM_DEFINE_VEC_OWN` are clearly for generating boilerplate code to manage the C API structures and their corresponding C++ objects.

7. **Addressing Specific Requirements:**

    * **`.tq` Extension:** The code is `.cc`, so this condition is false.

    * **JavaScript Relation:** The interaction with `FUNCREF` and `ANYREF` and the conversion between Wasm references and JavaScript objects demonstrate the connection. The `Instance::make` function uses a JavaScript object for imports. This calls for a JavaScript example.

    * **Logical Inference:**  The `Global::get()` and `set()` methods provide a simple example of input (a `Global` object and optionally a `Val`) and output (a `Val` or void). The `Table::get()` and `set()` methods offer similar opportunities.

    * **Common Programming Errors:**  The checks for out-of-bounds access in `Table::get()` and `Table::set()`, and potential errors during instantiation in `Instance::make()` are good candidates. Also, incorrect type usage when setting global values.

8. **Synthesizing the Summary:**  Based on the analysis, the core functionality is providing a C API for interacting with WebAssembly within V8. This involves creating, accessing, and manipulating various Wasm entities (globals, tables, memories, instances).

9. **Structuring the Output:** The final step is to organize the findings into the requested format:

    * **Functionality:**  List the key capabilities derived from the code analysis.
    * **`.tq` Check:** Explicitly state that the condition is false.
    * **JavaScript Example:**  Craft a simple JavaScript example demonstrating interaction.
    * **Logical Inference:** Provide a concrete example with input and output for `Global`.
    * **Common Errors:** Illustrate potential mistakes with code examples.
    * **Overall Summary:** Concisely summarize the purpose of this code segment.

**Self-Correction/Refinement:**  During the process, I might initially focus too much on the low-level details of the V8 internal objects. I would then need to pull back and focus on the *user-facing* functionality provided by the C API. Similarly, ensuring the JavaScript example is clear and directly relevant to the C++ code is important. The request for "Part 3 of 4" reminds me that this is not the entire API and to keep the scope limited to the provided snippet.
这是v8/src/wasm/c-api.cc的第三部分源代码，它主要负责定义了 WebAssembly C API 中关于**实例 (Instance)**、**导出 (Export)**以及一些辅助结构体的实现。

**功能归纳:**

这部分代码主要实现了以下功能：

1. **`Instance` 类型的操作:**
   - **创建实例 (`Instance::make`)**:  根据给定的模块 (Module) 和导入值 (imports) 创建 WebAssembly 实例。这涉及到将 C API 的 `Extern` 对象转换为 V8 内部的表示，并调用 V8 的 WebAssembly 引擎进行实例化。它还处理了实例化过程中可能发生的陷阱 (Trap)。
   - **获取实例的导出 (`Instance::exports`)**:  检索 WebAssembly 实例导出的所有外部对象 (函数、全局变量、表、内存)。它将 V8 内部的导出对象转换为 C API 的 `Extern` 对象。

2. **C API 的定义和绑定:**
   - 使用宏 (如 `WASM_DEFINE_OWN`, `WASM_DEFINE_VEC_OWN`) 定义了 C API 的结构体 (`wasm_instance_t`, `wasm_extern_vec_t` 等) 以及相关的创建、删除、拷贝函数。
   - 提供了将 C++ 的 `wasm::Instance` 和 `wasm::Extern` 对象转换为 C API 结构体的机制 (`hide_instance`, `reveal_instance`, `get_instance`, `release_instance`, `adopt_instance` 等)。
   - 定义了 `wasm_instance_new` 和 `wasm_instance_exports` 等 C API 函数，供外部 C/C++ 代码调用。

**关于 .tq 结尾:**

`v8/src/wasm/c-api.cc` 以 `.cc` 结尾，所以它是一个 **C++** 源代码文件，而不是 Torque 源代码。Torque 源代码文件以 `.tq` 结尾。

**与 JavaScript 的关系 (以 `Instance::make` 为例):**

`Instance::make` 函数在创建 WebAssembly 实例时，需要将导入值从 C API 的 `Extern` 对象转换为 V8 内部的表示。如果导入的是 JavaScript 函数，则需要将其包装成 V8 的 `WasmExternalFunction` 对象。

**JavaScript 示例:**

假设有一个 WebAssembly 模块需要导入一个 JavaScript 函数：

```javascript
// JavaScript 代码
const importObject = {
  module: {
    imported_func: (arg) => {
      console.log("JavaScript function called with:", arg);
      return arg * 2;
    },
  },
};

// 加载 WebAssembly 模块 (假设已经编译)
WebAssembly.instantiateStreaming(fetch('module.wasm'), importObject)
  .then(result => {
    const instance = result.instance;
    instance.exports.exported_func(5); // 调用 WebAssembly 导出的函数，可能会调用导入的 JavaScript 函数
  });
```

在 V8 的 C++ 代码中，`Instance::make` 需要将 `importObject.module.imported_func` 这个 JavaScript 函数转换为 `wasm::Func` 对象，以便 WebAssembly 代码可以调用它。

**代码逻辑推理 (以 `Global::get` 为例):**

**假设输入:**

- `global`: 一个指向 `Global` 对象的指针，该对象代表一个 WebAssembly 全局变量，类型为 `i32`，值为 `100`。
- `store`:  该 `Global` 对象所属的 `Store` 对象。

**输出:**

- 返回一个 `Val` 对象，其 `kind()` 为 `I32`，`i32()` 的值为 `100`。

**推理过程:**

1. `Global::get` 函数首先获取与该 `Global` 对象关联的 V8 内部的 `WasmGlobalObject`。
2. 根据全局变量的类型 (`val.kind()`)，使用 `v8_global->value()` 获取其值。
3. 如果全局变量是引用类型 (`ANYREF` 或 `FUNCREF`)，则需要进行额外的转换，将 V8 内部的引用对象转换为 C API 的 `Ref` 对象。
4. 最后，将获取到的值包装成 `Val` 对象并返回。

**用户常见的编程错误 (以 `Table::set` 为例):**

一个常见的编程错误是在设置表元素时，提供了错误类型的 `Ref` 对象。

**C++ 示例 (错误用法):**

```c++
// 假设 table 是一个 wasm_table_t*，其元素类型为 funcref
wasm_val_t val;
val.kind = WASM_I32;
val.of.i32 = 123;
wasm_ref_t* ref = wasm_ref_new(&val); // 错误：尝试将 i32 设置为 funcref 表的元素

// 获取一个函数类型的引用 (假设 get_wasm_func_ref 返回一个有效的 wasm_ref_t*，其内部是 funcref)
wasm_ref_t* func_ref = get_wasm_func_ref();

// 设置表元素
if (index < wasm_table_size(table)) {
  // 错误示例：类型不匹配
  // wasm_table_set(table, index, ref);

  // 正确示例：设置函数类型的引用
  wasm_table_set(table, index, func_ref);
}

wasm_ref_delete(ref); // 释放不再需要的引用
wasm_ref_delete(func_ref);
```

**错误说明:**  如果表的元素类型是 `funcref`，那么尝试将一个 `i32` 类型的值 (包装在 `wasm_ref_t` 中) 设置到表中将会导致类型错误。V8 会在内部进行类型检查，如果类型不匹配，可能会抛出异常或导致程序崩溃。

**总结第 3 部分的功能:**

这部分代码是 V8 WebAssembly C API 的核心组成部分，它提供了创建和操作 WebAssembly 实例以及访问实例导出的功能。它定义了 C API 的接口，并将其与 V8 内部的 WebAssembly 实现连接起来。通过这部分代码，外部 C/C++ 代码可以加载、实例化 WebAssembly 模块，并与模块中的函数、全局变量、表和内存进行交互。

### 提示词
```
这是目录为v8/src/wasm/c-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/c-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
ef(*result)) {
        result = i::WasmInternalFunction::GetOrCreateExternal(i::handle(
            i::Cast<i::WasmFuncRef>(*result)->internal(store->i_isolate()),
            store->i_isolate()));
      }
      if (IsWasmNull(*result)) {
        result = v8_global->GetIsolate()->factory()->null_value();
      }
      return Val(V8RefValueToWasm(store, result));
    }
    case i::wasm::kS128:
      // TODO(14034): Implement these.
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

void Global::set(const Val& val) {
  v8::Isolate::Scope isolate_scope(impl(this)->store()->isolate());
  i::DirectHandle<i::WasmGlobalObject> v8_global = impl(this)->v8_object();
  switch (val.kind()) {
    case I32:
      return v8_global->SetI32(val.i32());
    case I64:
      return v8_global->SetI64(val.i64());
    case F32:
      return v8_global->SetF32(val.f32());
    case F64:
      return v8_global->SetF64(val.f64());
    case ANYREF:
      return v8_global->SetRef(
          WasmRefToV8(impl(this)->store()->i_isolate(), val.ref()));
    case FUNCREF: {
      i::Isolate* isolate = impl(this)->store()->i_isolate();
      auto external = WasmRefToV8(impl(this)->store()->i_isolate(), val.ref());
      const char* error_message;
      auto internal = i::wasm::JSToWasmObject(isolate, nullptr, external,
                                              v8_global->type(), &error_message)
                          .ToHandleChecked();
      v8_global->SetRef(internal);
      return;
    }
    default:
      // TODO(wasm+): support new value types
      UNREACHABLE();
  }
}

// Table Instances

template <>
struct implement<Table> {
  using type = RefImpl<Table, i::WasmTableObject>;
};

Table::~Table() = default;

auto Table::copy() const -> own<Table> { return impl(this)->copy(); }

auto Table::make(Store* store_abs, const TableType* type, const Ref* ref)
    -> own<Table> {
  StoreImpl* store = impl(store_abs);
  i::Isolate* isolate = store->i_isolate();
  v8::Isolate::Scope isolate_scope(store->isolate());
  i::HandleScope scope(isolate);
  CheckAndHandleInterrupts(isolate);

  // Get "element".
  i::wasm::ValueType i_type;
  switch (type->element()->kind()) {
    case FUNCREF:
      i_type = i::wasm::kWasmFuncRef;
      break;
    case ANYREF:
      // See Engine::make().
      i_type = i::wasm::kWasmExternRef;
      break;
    default:
      UNREACHABLE();
  }

  const Limits& limits = type->limits();
  uint32_t minimum = limits.min;
  if (minimum > i::wasm::max_table_init_entries()) return nullptr;
  uint32_t maximum = limits.max;
  bool has_maximum = false;
  if (maximum != Limits(0).max) {
    has_maximum = true;
    if (maximum < minimum) return nullptr;
    if (maximum > i::wasm::max_table_init_entries()) return nullptr;
  }

  i::Handle<i::WasmTableObject> table_obj = i::WasmTableObject::New(
      isolate, i::Handle<i::WasmTrustedInstanceData>(), i_type, minimum,
      has_maximum, maximum, isolate->factory()->null_value(),
      i::wasm::AddressType::kI32);

  if (ref) {
    i::DirectHandle<i::FixedArray> entries{table_obj->entries(), isolate};
    i::DirectHandle<i::JSReceiver> init = impl(ref)->v8_object();
    DCHECK(i::wasm::max_table_init_entries() <= i::kMaxInt);
    for (int i = 0; i < static_cast<int>(minimum); i++) {
      // This doesn't call WasmTableObject::Set because the table has
      // just been created, so it can't be imported by any instances
      // yet that might require updating.
      DCHECK_EQ(table_obj->uses()->length(), 0);
      entries->set(i, *init);
    }
  }
  return implement<Table>::type::make(store, table_obj);
}

auto Table::type() const -> own<TableType> {
  i::DirectHandle<i::WasmTableObject> table = impl(this)->v8_object();
  uint32_t min = table->current_length();
  // Note: The C-API is not updated for memory64 yet; limits use uint32_t. Thus
  // truncate the actual declared maximum to kMaxUint32.
  uint32_t max = static_cast<uint32_t>(std::min<uint64_t>(
      i::kMaxUInt32, table->maximum_length_u64().value_or(i::kMaxUInt32)));
  ValKind kind;
  switch (table->type().heap_representation()) {
    case i::wasm::HeapType::kFunc:
      kind = FUNCREF;
      break;
    case i::wasm::HeapType::kExtern:
      kind = ANYREF;
      break;
    default:
      UNREACHABLE();
  }
  return TableType::make(ValType::make(kind), Limits(min, max));
}

// TODO(14034): Handle types other than funcref and externref if needed.
auto Table::get(size_t index) const -> own<Ref> {
  i::Isolate* isolate = impl(this)->isolate();
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  i::DirectHandle<i::WasmTableObject> table = impl(this)->v8_object();
  if (index >= static_cast<size_t>(table->current_length())) return own<Ref>();
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate);
  i::HandleScope handle_scope(isolate);
  i::Handle<i::Object> result =
      i::WasmTableObject::Get(isolate, table, static_cast<uint32_t>(index));
  if (IsWasmFuncRef(*result)) {
    result = i::WasmInternalFunction::GetOrCreateExternal(i::handle(
        i::Cast<i::WasmFuncRef>(*result)->internal(isolate), isolate));
  }
  if (IsWasmNull(*result)) {
    result = isolate->factory()->null_value();
  }
  DCHECK(IsNull(*result, isolate) || IsJSReceiver(*result));
  return V8RefValueToWasm(impl(this)->store(), result);
}

auto Table::set(size_t index, const Ref* ref) -> bool {
  i::Isolate* isolate = impl(this)->isolate();
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  i::DirectHandle<i::WasmTableObject> table = impl(this)->v8_object();
  if (index >= static_cast<size_t>(table->current_length())) return false;
  i::HandleScope handle_scope(isolate);
  i::Handle<i::Object> obj = WasmRefToV8(isolate, ref);
  const char* error_message;
  i::DirectHandle<i::Object> obj_as_wasm =
      i::wasm::JSToWasmObject(isolate, nullptr, obj, table->type(),
                              &error_message)
          .ToHandleChecked();
  i::WasmTableObject::Set(isolate, table, static_cast<uint32_t>(index),
                          obj_as_wasm);
  return true;
}

// TODO(jkummerow): Having Table::size_t shadowing "std" size_t is ugly.
auto Table::size() const -> size_t {
  i::Isolate* isolate = impl(this)->isolate();
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate);
  return impl(this)->v8_object()->current_length();
}

auto Table::grow(size_t delta, const Ref* ref) -> bool {
  i::Isolate* isolate = impl(this)->isolate();
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  i::DirectHandle<i::WasmTableObject> table = impl(this)->v8_object();
  i::HandleScope scope(isolate);
  i::Handle<i::Object> obj = WasmRefToV8(isolate, ref);
  const char* error_message;
  i::DirectHandle<i::Object> obj_as_wasm =
      i::wasm::JSToWasmObject(isolate, nullptr, obj, table->type(),
                              &error_message)
          .ToHandleChecked();
  int result = i::WasmTableObject::Grow(
      isolate, table, static_cast<uint32_t>(delta), obj_as_wasm);
  return result >= 0;
}

// Memory Instances

template <>
struct implement<Memory> {
  using type = RefImpl<Memory, i::WasmMemoryObject>;
};

Memory::~Memory() = default;

auto Memory::copy() const -> own<Memory> { return impl(this)->copy(); }

auto Memory::make(Store* store_abs, const MemoryType* type) -> own<Memory> {
  StoreImpl* store = impl(store_abs);
  i::Isolate* isolate = store->i_isolate();
  v8::Isolate::Scope isolate_scope(store->isolate());
  i::HandleScope scope(isolate);
  CheckAndHandleInterrupts(isolate);

  const Limits& limits = type->limits();
  uint32_t minimum = limits.min;
  // The max_mem_pages limit is only spec'ed for JS embeddings, so we'll
  // directly use the maximum pages limit here.
  if (minimum > i::wasm::kSpecMaxMemory32Pages) return nullptr;
  uint32_t maximum = limits.max;
  if (maximum != Limits(0).max) {
    if (maximum < minimum) return nullptr;
    if (maximum > i::wasm::kSpecMaxMemory32Pages) return nullptr;
  }
  // TODO(wasm+): Support shared memory and memory64.
  i::SharedFlag shared = i::SharedFlag::kNotShared;
  i::wasm::AddressType address_type = i::wasm::AddressType::kI32;
  i::Handle<i::WasmMemoryObject> memory_obj;
  if (!i::WasmMemoryObject::New(isolate, minimum, maximum, shared, address_type)
           .ToHandle(&memory_obj)) {
    return own<Memory>();
  }
  return implement<Memory>::type::make(store, memory_obj);
}

auto Memory::type() const -> own<MemoryType> {
  PtrComprCageAccessScope ptr_compr_cage_access_scope(impl(this)->isolate());
  i::DirectHandle<i::WasmMemoryObject> memory = impl(this)->v8_object();
  uint32_t min = static_cast<uint32_t>(memory->array_buffer()->byte_length() /
                                       i::wasm::kWasmPageSize);
  uint32_t max =
      memory->has_maximum_pages() ? memory->maximum_pages() : 0xFFFFFFFFu;
  return MemoryType::make(Limits(min, max));
}

auto Memory::data() const -> byte_t* {
  i::Isolate* isolate = impl(this)->isolate();
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate);
  return reinterpret_cast<byte_t*>(
      impl(this)->v8_object()->array_buffer()->backing_store());
}

auto Memory::data_size() const -> size_t {
  i::Isolate* isolate = impl(this)->isolate();
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate);
  return impl(this)->v8_object()->array_buffer()->byte_length();
}

auto Memory::size() const -> pages_t {
  i::Isolate* isolate = impl(this)->isolate();
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate);
  return static_cast<pages_t>(
      impl(this)->v8_object()->array_buffer()->byte_length() /
      i::wasm::kWasmPageSize);
}

auto Memory::grow(pages_t delta) -> bool {
  i::Isolate* isolate = impl(this)->isolate();
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  i::HandleScope handle_scope(isolate);
  i::Handle<i::WasmMemoryObject> memory = impl(this)->v8_object();
  int32_t old = i::WasmMemoryObject::Grow(isolate, memory, delta);
  return old != -1;
}

// Module Instances

template <>
struct implement<Instance> {
  using type = RefImpl<Instance, i::WasmInstanceObject>;
};

Instance::~Instance() = default;

auto Instance::copy() const -> own<Instance> { return impl(this)->copy(); }

own<Instance> Instance::make(Store* store_abs, const Module* module_abs,
                             const Extern* const imports[], own<Trap>* trap) {
  StoreImpl* store = impl(store_abs);
  const implement<Module>::type* module = impl(module_abs);
  i::Isolate* isolate = store->i_isolate();
  v8::Isolate::Scope isolate_scope(store->isolate());
  i::HandleScope handle_scope(isolate);
  CheckAndHandleInterrupts(isolate);

  DCHECK_EQ(module->v8_object()->GetIsolate(), isolate);

  if (trap) *trap = nullptr;
  ownvec<ImportType> import_types = module_abs->imports();
  i::Handle<i::JSObject> imports_obj =
      isolate->factory()->NewJSObject(isolate->object_function());
  for (size_t i = 0; i < import_types.size(); ++i) {
    ImportType* type = import_types[i].get();
    i::Handle<i::String> module_str = VecToString(isolate, type->module());
    i::Handle<i::String> name_str = VecToString(isolate, type->name());

    i::Handle<i::JSObject> module_obj;
    i::LookupIterator module_it(isolate, imports_obj, module_str,
                                i::LookupIterator::OWN_SKIP_INTERCEPTOR);
    if (i::JSObject::HasProperty(&module_it).ToChecked()) {
      module_obj = i::Cast<i::JSObject>(
          i::Object::GetProperty(&module_it).ToHandleChecked());
    } else {
      module_obj = isolate->factory()->NewJSObject(isolate->object_function());
      ignore(
          i::Object::SetProperty(isolate, imports_obj, module_str, module_obj));
    }
    ignore(i::Object::SetProperty(isolate, module_obj, name_str,
                                  impl(imports[i])->v8_object()));
  }
  i::wasm::ErrorThrower thrower(isolate, "instantiation");
  i::MaybeHandle<i::WasmInstanceObject> instance_obj =
      i::wasm::GetWasmEngine()->SyncInstantiate(
          isolate, &thrower, module->v8_object(), imports_obj,
          i::MaybeHandle<i::JSArrayBuffer>());
  if (trap) {
    if (thrower.error()) {
      *trap = implement<Trap>::type::make(
          store, GetProperException(isolate, thrower.Reify()));
      DCHECK(!thrower.error());                   // Reify() called Reset().
      DCHECK(!isolate->has_exception());          // Hasn't been thrown yet.
      return own<Instance>();
    } else if (isolate->has_exception()) {
      i::Handle<i::Object> maybe_exception(isolate->exception(), isolate);
      *trap = implement<Trap>::type::make(
          store, GetProperException(isolate, maybe_exception));
      isolate->clear_exception();
      return own<Instance>();
    }
  } else if (instance_obj.is_null()) {
    // If no {trap} output is specified, silently swallow all errors.
    thrower.Reset();
    isolate->clear_exception();
    return own<Instance>();
  }
  return implement<Instance>::type::make(store, instance_obj.ToHandleChecked());
}

namespace {

own<Instance> GetInstance(StoreImpl* store,
                          i::Handle<i::WasmInstanceObject> instance) {
  return implement<Instance>::type::make(store, instance);
}

}  // namespace

auto Instance::exports() const -> ownvec<Extern> {
  const implement<Instance>::type* instance = impl(this);
  StoreImpl* store = instance->store();
  i::Isolate* isolate = store->i_isolate();
  v8::Isolate::Scope isolate_scope(store->isolate());
  i::HandleScope handle_scope(isolate);
  CheckAndHandleInterrupts(isolate);
  i::DirectHandle<i::WasmInstanceObject> instance_obj = instance->v8_object();
  i::DirectHandle<i::WasmModuleObject> module_obj(instance_obj->module_object(),
                                                  isolate);
  i::Handle<i::JSObject> exports_obj(instance_obj->exports_object(), isolate);

  ownvec<ExportType> export_types = ExportsImpl(module_obj);
  ownvec<Extern> exports =
      ownvec<Extern>::make_uninitialized(export_types.size());
  if (!exports) return ownvec<Extern>::invalid();

  for (size_t i = 0; i < export_types.size(); ++i) {
    auto& name = export_types[i]->name();
    i::Handle<i::String> name_str = VecToString(isolate, name);
    i::Handle<i::Object> obj =
        i::Object::GetProperty(isolate, exports_obj, name_str)
            .ToHandleChecked();

    const ExternType* type = export_types[i]->type();
    switch (type->kind()) {
      case EXTERN_FUNC: {
        DCHECK(i::WasmExternalFunction::IsWasmExternalFunction(*obj));
        exports[i] = implement<Func>::type::make(
            store, i::Cast<i::WasmExternalFunction>(obj));
      } break;
      case EXTERN_GLOBAL: {
        exports[i] = implement<Global>::type::make(
            store, i::Cast<i::WasmGlobalObject>(obj));
      } break;
      case EXTERN_TABLE: {
        exports[i] = implement<Table>::type::make(
            store, i::Cast<i::WasmTableObject>(obj));
      } break;
      case EXTERN_MEMORY: {
        exports[i] = implement<Memory>::type::make(
            store, i::Cast<i::WasmMemoryObject>(obj));
      } break;
    }
  }

  return exports;
}

///////////////////////////////////////////////////////////////////////////////

}  // namespace wasm

// BEGIN FILE wasm-c.cc

extern "C" {

///////////////////////////////////////////////////////////////////////////////
// Auxiliaries

// Backing implementation

extern "C++" {

template <class T>
struct borrowed_vec {
  wasm::vec<T> it;
  explicit borrowed_vec(wasm::vec<T>&& v) : it(std::move(v)) {}
  borrowed_vec(borrowed_vec<T>&& that) : it(std::move(that.it)) {}
  ~borrowed_vec() { it.release(); }
};

}  // extern "C++"

#define WASM_DEFINE_OWN(name, Name)                                            \
  struct wasm_##name##_t : Name {};                                            \
                                                                               \
  void wasm_##name##_delete(wasm_##name##_t* x) { delete x; }                  \
                                                                               \
  extern "C++" inline auto hide_##name(Name* x)->wasm_##name##_t* {            \
    return static_cast<wasm_##name##_t*>(x);                                   \
  }                                                                            \
  extern "C++" inline auto hide_##name(const Name* x)                          \
      ->const wasm_##name##_t* {                                               \
    return static_cast<const wasm_##name##_t*>(x);                             \
  }                                                                            \
  extern "C++" inline auto reveal_##name(wasm_##name##_t* x)->Name* {          \
    return x;                                                                  \
  }                                                                            \
  extern "C++" inline auto reveal_##name(const wasm_##name##_t* x)             \
      ->const Name* {                                                          \
    return x;                                                                  \
  }                                                                            \
  extern "C++" inline auto get_##name(wasm::own<Name>& x)->wasm_##name##_t* {  \
    return hide_##name(x.get());                                               \
  }                                                                            \
  extern "C++" inline auto get_##name(const wasm::own<Name>& x)                \
      ->const wasm_##name##_t* {                                               \
    return hide_##name(x.get());                                               \
  }                                                                            \
  extern "C++" inline auto release_##name(wasm::own<Name>&& x)                 \
      ->wasm_##name##_t* {                                                     \
    return hide_##name(x.release());                                           \
  }                                                                            \
  extern "C++" inline auto adopt_##name(wasm_##name##_t* x)->wasm::own<Name> { \
    return make_own(x);                                                        \
  }

// Vectors

#ifdef V8_GC_MOLE
#define ASSERT_VEC_BASE_SIZE(name, Name, vec, ptr_or_none)

#else
#define ASSERT_VEC_BASE_SIZE(name, Name, vec, ptr_or_none)                 \
  static_assert(sizeof(wasm_##name##_vec_t) == sizeof(vec<Name>),          \
                "C/C++ incompatibility");                                  \
  static_assert(                                                           \
      sizeof(wasm_##name##_t ptr_or_none) == sizeof(vec<Name>::elem_type), \
      "C/C++ incompatibility");
#endif

#define WASM_DEFINE_VEC_BASE(name, Name, vec, ptr_or_none)                     \
  ASSERT_VEC_BASE_SIZE(name, Name, vec, ptr_or_none)                           \
  extern "C++" inline auto hide_##name##_vec(vec<Name>& v)                     \
      ->wasm_##name##_vec_t* {                                                 \
    return reinterpret_cast<wasm_##name##_vec_t*>(&v);                         \
  }                                                                            \
  extern "C++" inline auto hide_##name##_vec(const vec<Name>& v)               \
      ->const wasm_##name##_vec_t* {                                           \
    return reinterpret_cast<const wasm_##name##_vec_t*>(&v);                   \
  }                                                                            \
  extern "C++" inline auto hide_##name##_vec(vec<Name>::elem_type* v)          \
      ->wasm_##name##_t ptr_or_none* {                                         \
    return reinterpret_cast<wasm_##name##_t ptr_or_none*>(v);                  \
  }                                                                            \
  extern "C++" inline auto hide_##name##_vec(const vec<Name>::elem_type* v)    \
      ->wasm_##name##_t ptr_or_none const* {                                   \
    return reinterpret_cast<wasm_##name##_t ptr_or_none const*>(v);            \
  }                                                                            \
  extern "C++" inline auto reveal_##name##_vec(wasm_##name##_t ptr_or_none* v) \
      ->vec<Name>::elem_type* {                                                \
    return reinterpret_cast<vec<Name>::elem_type*>(v);                         \
  }                                                                            \
  extern "C++" inline auto reveal_##name##_vec(                                \
      wasm_##name##_t ptr_or_none const* v)                                    \
      ->const vec<Name>::elem_type* {                                          \
    return reinterpret_cast<const vec<Name>::elem_type*>(v);                   \
  }                                                                            \
  extern "C++" inline auto get_##name##_vec(vec<Name>& v)                      \
      ->wasm_##name##_vec_t {                                                  \
    wasm_##name##_vec_t v2 = {v.size(), hide_##name##_vec(v.get())};           \
    return v2;                                                                 \
  }                                                                            \
  extern "C++" inline auto get_##name##_vec(const vec<Name>& v)                \
      ->const wasm_##name##_vec_t {                                            \
    wasm_##name##_vec_t v2 = {                                                 \
        v.size(),                                                              \
        const_cast<wasm_##name##_t ptr_or_none*>(hide_##name##_vec(v.get()))}; \
    return v2;                                                                 \
  }                                                                            \
  extern "C++" inline auto release_##name##_vec(vec<Name>&& v)                 \
      ->wasm_##name##_vec_t {                                                  \
    wasm_##name##_vec_t v2 = {v.size(), hide_##name##_vec(v.release())};       \
    return v2;                                                                 \
  }                                                                            \
  extern "C++" inline auto adopt_##name##_vec(wasm_##name##_vec_t* v)          \
      ->vec<Name> {                                                            \
    return vec<Name>::adopt(v->size, reveal_##name##_vec(v->data));            \
  }                                                                            \
  extern "C++" inline auto borrow_##name##_vec(const wasm_##name##_vec_t* v)   \
      ->borrowed_vec<vec<Name>::elem_type> {                                   \
    return borrowed_vec<vec<Name>::elem_type>(                                 \
        vec<Name>::adopt(v->size, reveal_##name##_vec(v->data)));              \
  }                                                                            \
                                                                               \
  void wasm_##name##_vec_new_uninitialized(wasm_##name##_vec_t* out,           \
                                           size_t size) {                      \
    *out = release_##name##_vec(vec<Name>::make_uninitialized(size));          \
  }                                                                            \
  void wasm_##name##_vec_new_empty(wasm_##name##_vec_t* out) {                 \
    wasm_##name##_vec_new_uninitialized(out, 0);                               \
  }                                                                            \
                                                                               \
  void wasm_##name##_vec_delete(wasm_##name##_vec_t* v) {                      \
    adopt_##name##_vec(v);                                                     \
  }

// Vectors with no ownership management of elements
#define WASM_DEFINE_VEC_PLAIN(name, Name)                           \
  WASM_DEFINE_VEC_BASE(name, Name,                                  \
                       wasm::vec, ) /* NOLINT(whitespace/parens) */ \
                                                                    \
  void wasm_##name##_vec_new(wasm_##name##_vec_t* out, size_t size, \
                             const wasm_##name##_t data[]) {        \
    auto v2 = wasm::vec<Name>::make_uninitialized(size);            \
    if (v2.size() != 0) {                                           \
      memcpy(v2.get(), data, size * sizeof(wasm_##name##_t));       \
    }                                                               \
    *out = release_##name##_vec(std::move(v2));                     \
  }                                                                 \
                                                                    \
  void wasm_##name##_vec_copy(wasm_##name##_vec_t* out,             \
                              wasm_##name##_vec_t* v) {             \
    wasm_##name##_vec_new(out, v->size, v->data);                   \
  }

// Vectors that own their elements
#define WASM_DEFINE_VEC_OWN(name, Name)                             \
  WASM_DEFINE_VEC_BASE(name, Name, wasm::ownvec, *)                 \
                                                                    \
  void wasm_##name##_vec_new(wasm_##name##_vec_t* out, size_t size, \
                             wasm_##name##_t* const data[]) {       \
    auto v2 = wasm::ownvec<Name>::make_uninitialized(size);         \
    for (size_t i = 0; i < v2.size(); ++i) {                        \
      v2[i] = adopt_##name(data[i]);                                \
    }                                                               \
    *out = release_##name##_vec(std::move(v2));                     \
  }                                                                 \
                                                                    \
  void wasm_##name##_vec_copy(wasm_##name##_vec_t* out,             \
                              wasm_##name##_vec_t* v) {             \
    auto v2 = wasm::ownvec<Name>::make_uninitialized(v->size);      \
    for (size_t i = 0; i < v2.size(); ++i) {                        \
      v2[i] = adopt_##name(wasm_##name##_copy(v->data[i]));         \
    }                                                               \
    *out = release_##name##_vec(std::move(v2));                     \
  }

extern "C++" {
template <class T>
inline auto is_empty(T* p) -> bool {
  return !p;
}
}

// Byte vectors

WASM_DEFINE_VEC_PLAIN(byte, byte_t)

///////////////////////////////////////////////////////////////////////////////
// Runtime Environment

// Configuration

WASM_DEFINE_OWN(config, wasm::Config)

wasm_config_t* wasm_config_new() {
  return release_config(wasm::Config::make());
}

// Engine

WASM_DEFINE_OWN(engine, wasm::Engine)

wasm_engine_t* wasm_engine_new() {
  return release_engine(wasm::Engine::make());
}

wasm_engine_t* wasm_engine_new_with_config(wasm_config_t* config) {
  return release_engine(wasm::Engine::make(adopt_config(config)));
}

// Stores

WASM_DEFINE_OWN(store, wasm::Store)

wasm_store_t* wasm_store_new(wasm_engine_t* engine) {
  return release_store(wasm::Store::make(engine));
}

///////////////////////////////////////////////////////////////////////////////
// Type Representations

// Type attributes

extern "C++" inline auto hide_mutability(wasm::Mutability mutability)
    -> wasm_mutability_t {
  return static_cast<wasm_mutability_t>(mutability);
}

extern "C++" inline auto reveal_mutability(wasm_mutability_t mutability)
    -> wasm::Mutability {
  return static_cast<wasm::Mutability>(mutability);
}

extern "C++" inline auto hide_limits(const wasm::Limits& limits)
    -> const wasm_limits_t* {
  return reinterpret_cast<const wasm_limits_t*>(&limits);
}

extern "C++" inline auto reveal_limits(wasm_limits_t limits) -> wasm::Limits {
  return wasm::Limits(limits.min, limits.max);
}

extern "C++" inline auto hide_valkind(wasm::ValKind kind) -> wasm_valkind_t {
  return static_cast<wasm_valkind_t>(kind);
}

extern "C++" inline auto reveal_valkind(wasm_valkind_t kind) -> wasm::ValKind {
  return static_cast<wasm::ValKind>(kind);
}

extern "C++" inline auto hide_externkind(wasm::ExternKind kind)
    -> wasm_externkind_t {
  return static_cast<wasm_externkind_t>(kind);
}

extern "C++" inline auto reveal_externkind(wasm_externkind_t kind)
    -> wasm::ExternKind {
  return static_cast<wasm::ExternKind>(kind);
}

// Generic

#define WASM_DEFINE_TYPE(name, Name)                        \
  WASM_DEFINE_OWN(name, Name)                               \
  WASM_DEFINE_VEC_OWN(name, Name)                           \
                                                            \
  wasm_##name##_t* wasm_##name##_copy(wasm_##name##_t* t) { \
    return release_##name(t->copy());                       \
  }

// Value Types

WASM_DEFINE_TYPE(valtype, wasm::ValType)

wasm_valtype_t* wasm_valtype_new(wasm_valkind_t k) {
  return release_valtype(wasm::ValType::make(reveal_valkind(k)));
}

wasm_valkind_t wasm_valtype_kind(const wasm_valtype_t* t) {
  return hide_valkind(t->kind());
}

// Function Types

WASM_DEFINE_TYPE(functype, wasm::FuncType)

wasm_functype_t* wasm_functype_new(wasm_valtype_vec_t* params,
                                   wasm_valtype_vec_t* results) {
  return release_functype(wasm::FuncType::make(adopt_valtype_vec(params),
                                               adopt_valtype_vec(results)));
}

const wasm_valtype_vec_t* wasm_functype_params(const wasm_functype_t* ft) {
  return hide_valtype_vec(ft->params());
}

const wasm_valtype_vec_t* wasm_functype_results(const wasm_functype_t* ft) {
  return hide_valtype_vec(ft->results());
}

// Global Types

WASM_DEFINE_TYPE(globaltype, wasm::GlobalType)

wasm_globaltype_t* wasm_globaltype_new(wasm_valtype_t* content,
                                       wasm_mutability_t mutability) {
  return release_globaltype(wasm::GlobalType::make(
      adopt_valtype(content), reveal_mutability(mutability)));
}

const wasm_valtype_t* wasm_globaltype_content(const wasm_globaltype_t* gt) {
  return hide_valtype(gt->content());
}

wasm_mutability_t wasm_globaltype_mutability(const wasm_globaltype_t* gt) {
  return hide_mutability(gt->mutability());
}

// Table Types

WASM_DEFINE_TYPE(tabletype, wasm::TableType)

wasm_tabletype_t* wasm_tabletype_new(wasm_valtype_t* element,
                                     const wasm_limits_t* limits) {
  return release_tabletype(
      wasm::TableType::make(adopt_valtype(element), reveal_limits(*limits)));
}

const wasm_valtype_t* wasm_tabletype_element(const wasm_tabletype_t* tt) {
  return hide_valtype(tt->element());
}

const wasm_limits_t* wasm_tabletype_limits(const wasm_tabletype_t* tt) {
  return hide_limits(tt->limits());
}

// Memory Types

WASM_DEFINE_TYPE(memorytype, wasm::MemoryType)

wasm_memorytype_t* wasm_memorytype_new(const wasm_limits_t* limits) {
  return release_memorytype(wasm::MemoryType::make(reveal_limits(*limits)));
}

const wasm_limits_t* wasm_memorytype_limits(const wasm_memorytype_t* mt) {
  return hide_limits(mt->limits());
}

// Extern Types

WASM_DEFINE_TYPE(externtype, wasm::ExternType)

wasm_externkind_t wasm_externtype_kind(const wasm_externtype_t* et) {
  return hide_externkind(et->kind());
}

wasm_externtype_t* wasm_functype_as_externtype(wasm_functype_t* ft) {
  return hide_externtype(static_cast<wasm::ExternType*>(ft));
}
wasm_externtype_t* wasm_globaltype_as_externtype(wasm_globaltype_t* gt) {
  return hide_externtype(static_cast<wasm::ExternType*>(gt));
}
wasm_externtype_t* wasm_tabletype_as_externtype(wasm_tabletype_t* tt) {
  return hide_externtype(static_cast<wasm::ExternType*>(tt));
}
wasm_externtype_t* wasm_memorytype_as_externtype(wasm_memorytype_t* mt) {
  return hide_externtype(static_cast<wasm::ExternType*>(mt));
}

const wasm_externtype_t* wasm_functype_as_externtype_const(
    const wasm_functype_t* ft) {
  return hide_externtype(static_cast<const wasm::ExternType*>(ft));
}
const wasm_externtype_t* wasm_globaltype_as_externtype_const(
    const wasm_globaltype_t* gt) {
  return hide_externtype(static_cas
```