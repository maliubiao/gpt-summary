Response: The user is asking for a summary of the C++ source code file `v8/src/wasm/c-api.cc`, specifically the second part of the file. This file seems to be implementing the C API for WebAssembly in V8.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The filename `c-api.cc` strongly suggests this file implements the C API for interacting with the V8 WebAssembly engine. The presence of `extern "C"` blocks confirms this.

2. **Examine the structure:** The code is organized into sections for different WebAssembly concepts like `Runtime Environment`, `Type Representations`, and `Runtime Values`. This organization provides a natural structure for the summary.

3. **Analyze the `extern "C"` blocks:** These blocks define the functions that are part of the public C API. They are the key elements to summarize.

4. **Focus on the macros:** The code heavily uses macros like `WASM_DEFINE_OWN`, `WASM_DEFINE_VEC_*`, `WASM_DEFINE_TYPE`, and `WASM_DEFINE_REF`. Understanding these macros is crucial. They automate the creation of C API wrappers around the internal C++ classes.

5. **Trace the macros' purpose:**
    * `WASM_DEFINE_OWN`:  Handles the creation, deletion, and casting of single WebAssembly objects.
    * `WASM_DEFINE_VEC_*`: Deals with vectors (arrays) of WebAssembly objects, including different ownership semantics.
    * `WASM_DEFINE_TYPE`:  Combines `WASM_DEFINE_OWN` and `WASM_DEFINE_VEC_OWN` for type-related objects.
    * `WASM_DEFINE_REF`:  Handles reference-counted objects.

6. **Map C API functions to WebAssembly concepts:**  Go through each section within the `extern "C"` block and map the defined functions to their corresponding WebAssembly concepts (e.g., `wasm_store_new` creates a `Store`, `wasm_module_validate` validates a `Module`).

7. **Identify relationships to JavaScript:** While this part of the file primarily deals with the C API, recall that V8 is a JavaScript engine. The C API allows external (non-JavaScript) code to interact with WebAssembly modules loaded in V8. Think about scenarios where a C/C++ application might want to:
    * Compile a WebAssembly module.
    * Instantiate a WebAssembly module.
    * Call WebAssembly functions.
    * Access WebAssembly memory, globals, and tables.
    * Embed V8 and run WebAssembly within a native application.

8. **Construct the JavaScript examples:** Create simple JavaScript snippets that demonstrate the *JavaScript equivalent* of the C API functionality. For example, `WebAssembly.compile()` is the JavaScript equivalent of the C API's module compilation process. `WebAssembly.instantiate()` maps to the C API's instance creation.

9. **Refine the summary:** Organize the findings logically, grouping related functions. Use clear and concise language. Highlight the core functionality: creating, manipulating, and interacting with WebAssembly objects. Mention the purpose of the C API as a bridge between native code and the V8 WebAssembly engine.

10. **Review and iterate:** Read through the generated summary to ensure accuracy, clarity, and completeness. Check if the JavaScript examples are illustrative and easy to understand. Make sure the connection between the C API and JavaScript functionality is clear.
Based on the provided C++ code snippet from `v8/src/wasm/c-api.cc`, this second part of the file primarily focuses on **implementing the C API for interacting with WebAssembly modules and instances within the V8 JavaScript engine**.

Here's a breakdown of its functionalities:

**1. Defining C API Structures and Functions:**

* **Macros for C API Definition:** It uses a series of macros (`WASM_DEFINE_OWN`, `WASM_DEFINE_VEC_*`, `WASM_DEFINE_TYPE`, `WASM_DEFINE_REF`) to automatically generate the necessary C API structures (`wasm_name_t`, `wasm_module_t`, `wasm_instance_t`, etc.) and their associated creation, deletion, and manipulation functions (`wasm_module_new`, `wasm_instance_exports`, etc.). These macros streamline the process of creating the C API bindings.
* **Organization by WebAssembly Concepts:** The code is structured around fundamental WebAssembly concepts like:
    * **Runtime Environment:**  Handles engine and store creation (`wasm_engine_new`, `wasm_store_new`).
    * **Type Representations:** Defines C structures and functions for representing WebAssembly types (value types, function types, global types, etc.) (`wasm_valtype_new`, `wasm_functype_params`).
    * **Runtime Values:**  Provides ways to create and manipulate WebAssembly values (integers, floats, references) (`wasm_val_new`, `wasm_global_get`).
    * **Runtime Objects:** Implements the C API for interacting with core WebAssembly runtime objects:
        * **Frames:** Information about the call stack (`wasm_frame_func_index`).
        * **Traps:** Represent runtime errors (`wasm_trap_new`, `wasm_trap_message`).
        * **Foreign Objects:**  A way to pass host-defined data into WebAssembly (`wasm_foreign_new`).
        * **Modules:**  Loading, validating, sharing, and serializing WebAssembly bytecode (`wasm_module_validate`, `wasm_module_new`, `wasm_module_imports`).
        * **Functions:** Creating, calling, and getting type information about WebAssembly functions, including support for callbacks from WebAssembly to the host (`wasm_func_new`, `wasm_func_call`).
        * **Globals:** Creating, getting, and setting WebAssembly global variables (`wasm_global_new`, `wasm_global_get`, `wasm_global_set`).
        * **Tables:** Creating, getting, setting, growing, and getting type information about WebAssembly tables (`wasm_table_new`, `wasm_table_get`, `wasm_table_grow`).
        * **Memories:** Creating, accessing data, getting size, and growing WebAssembly linear memory (`wasm_memory_new`, `wasm_memory_data`, `wasm_memory_grow`).
        * **Externals:** A generic type representing any exported entity from a WebAssembly module (functions, globals, tables, memories), along with functions to cast between specific external types (`wasm_func_as_extern`, `wasm_extern_as_func`).
        * **Instances:**  Creating and accessing exports of instantiated WebAssembly modules (`wasm_instance_new`, `wasm_instance_exports`).

**2. Relationship to JavaScript and Examples:**

This C API provides a way for non-JavaScript (e.g., C/C++) code to interact with the V8 WebAssembly engine. The core functionalities exposed by this C API have direct equivalents in the JavaScript WebAssembly API.

Here are some examples illustrating the relationship:

* **Module Compilation:**
    * **C++ (via C API):**
      ```c++
      wasm_byte_vec_t binary;
      // ... load WebAssembly binary into 'binary' ...
      wasm_store_t* store = wasm_store_new(wasm_engine_new());
      wasm_module_t* module = wasm_module_new(store, &binary);
      wasm_byte_vec_delete(&binary);
      // ... use the module ...
      wasm_module_delete(module);
      wasm_store_delete(store);
      ```
    * **JavaScript:**
      ```javascript
      const wasmBytes = new Uint8Array([...]); // Load WebAssembly binary
      const module = await WebAssembly.compile(wasmBytes);
      ```

* **Module Instantiation:**
    * **C++ (via C API):**
      ```c++
      // ... assuming 'module' is a valid wasm_module_t* ...
      wasm_store_t* store = wasm_store_new(wasm_engine_new());
      wasm_extern_t* imports[] = { /* ... define imports ... */ };
      wasm_trap_t* trap = nullptr;
      wasm_instance_t* instance = wasm_instance_new(store, module, imports, &trap);
      if (trap) {
        // Handle the trap
        wasm_trap_delete(trap);
      } else {
        // Use the instance
      }
      // ... cleanup ...
      wasm_instance_delete(instance);
      wasm_store_delete(store);
      ```
    * **JavaScript:**
      ```javascript
      // ... assuming 'module' is a compiled WebAssembly.Module ...
      const imports = { /* ... define imports ... */ };
      const instance = await WebAssembly.instantiate(module, imports);
      ```

* **Calling a WebAssembly Function:**
    * **C++ (via C API):**
      ```c++
      // ... assuming 'instance' is a valid wasm_instance_t* ...
      wasm_extern_vec_t exports;
      wasm_instance_exports(instance, &exports);
      for (size_t i = 0; i < exports.size; ++i) {
        const wasm_exporttype_t* export_type = wasm_extern_type(exports.data[i]);
        if (wasm_externtype_kind(export_type) == WASM_EXTERN_FUNC) {
          wasm_func_t* func = wasm_extern_as_func(exports.data[i]);
          if (func) {
            wasm_val_t args[1];
            args[0].kind = WASM_I32;
            args[0].of.i32 = 42;
            wasm_val_t results[1];
            wasm_trap_t* trap = wasm_func_call(func, args, results);
            if (trap) {
              // Handle the trap
              wasm_trap_delete(trap);
            } else {
              // Access the results
              if (results[0].kind == WASM_I32) {
                printf("Result: %d\n", results[0].of.i32);
              }
            }
          }
        }
      }
      wasm_extern_vec_delete(&exports);
      ```
    * **JavaScript:**
      ```javascript
      // ... assuming 'instance' is an instantiated WebAssembly.Instance ...
      const exportedFunction = instance.exports.myFunction;
      if (exportedFunction) {
        const result = exportedFunction(42);
        console.log("Result:", result);
      }
      ```

* **Accessing WebAssembly Memory:**
    * **C++ (via C API):**
      ```c++
      // ... assuming 'instance' is a valid wasm_instance_t* and has a memory export ...
      wasm_extern_vec_t exports;
      wasm_instance_exports(instance, &exports);
      for (size_t i = 0; i < exports.size; ++i) {
        const wasm_exporttype_t* export_type = wasm_extern_type(exports.data[i]);
        if (wasm_externtype_kind(export_type) == WASM_EXTERN_MEMORY) {
          wasm_memory_t* memory = wasm_extern_as_memory(exports.data[i]);
          if (memory) {
            wasm_byte_t* data = wasm_memory_data(memory);
            size_t size = wasm_memory_data_size(memory);
            // ... access memory data ...
          }
        }
      }
      wasm_extern_vec_delete(&exports);
      ```
    * **JavaScript:**
      ```javascript
      // ... assuming 'instance' is an instantiated WebAssembly.Instance with memory export 'memory' ...
      const memory = instance.exports.memory;
      if (memory) {
        const buffer = memory.buffer;
        const view = new Uint8Array(buffer);
        // ... access memory data through the view ...
      }
      ```

In summary, this part of `v8/src/wasm/c-api.cc` provides the low-level C interface that allows external applications and libraries to interact with the V8 WebAssembly engine, mirroring the functionalities available through the standard JavaScript WebAssembly API. This is crucial for embedding V8 and running WebAssembly in non-browser environments or for creating native extensions that interact with WebAssembly.

Prompt: 
```
这是目录为v8/src/wasm/c-api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
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
  return hide_externtype(static_cast<const wasm::ExternType*>(gt));
}
const wasm_externtype_t* wasm_tabletype_as_externtype_const(
    const wasm_tabletype_t* tt) {
  return hide_externtype(static_cast<const wasm::ExternType*>(tt));
}
const wasm_externtype_t* wasm_memorytype_as_externtype_const(
    const wasm_memorytype_t* mt) {
  return hide_externtype(static_cast<const wasm::ExternType*>(mt));
}

wasm_functype_t* wasm_externtype_as_functype(wasm_externtype_t* et) {
  return et->kind() == wasm::EXTERN_FUNC
             ? hide_functype(
                   static_cast<wasm::FuncType*>(reveal_externtype(et)))
             : nullptr;
}
wasm_globaltype_t* wasm_externtype_as_globaltype(wasm_externtype_t* et) {
  return et->kind() == wasm::EXTERN_GLOBAL
             ? hide_globaltype(
                   static_cast<wasm::GlobalType*>(reveal_externtype(et)))
             : nullptr;
}
wasm_tabletype_t* wasm_externtype_as_tabletype(wasm_externtype_t* et) {
  return et->kind() == wasm::EXTERN_TABLE
             ? hide_tabletype(
                   static_cast<wasm::TableType*>(reveal_externtype(et)))
             : nullptr;
}
wasm_memorytype_t* wasm_externtype_as_memorytype(wasm_externtype_t* et) {
  return et->kind() == wasm::EXTERN_MEMORY
             ? hide_memorytype(
                   static_cast<wasm::MemoryType*>(reveal_externtype(et)))
             : nullptr;
}

const wasm_functype_t* wasm_externtype_as_functype_const(
    const wasm_externtype_t* et) {
  return et->kind() == wasm::EXTERN_FUNC
             ? hide_functype(
                   static_cast<const wasm::FuncType*>(reveal_externtype(et)))
             : nullptr;
}
const wasm_globaltype_t* wasm_externtype_as_globaltype_const(
    const wasm_externtype_t* et) {
  return et->kind() == wasm::EXTERN_GLOBAL
             ? hide_globaltype(
                   static_cast<const wasm::GlobalType*>(reveal_externtype(et)))
             : nullptr;
}
const wasm_tabletype_t* wasm_externtype_as_tabletype_const(
    const wasm_externtype_t* et) {
  return et->kind() == wasm::EXTERN_TABLE
             ? hide_tabletype(
                   static_cast<const wasm::TableType*>(reveal_externtype(et)))
             : nullptr;
}
const wasm_memorytype_t* wasm_externtype_as_memorytype_const(
    const wasm_externtype_t* et) {
  return et->kind() == wasm::EXTERN_MEMORY
             ? hide_memorytype(
                   static_cast<const wasm::MemoryType*>(reveal_externtype(et)))
             : nullptr;
}

// Import Types

WASM_DEFINE_TYPE(importtype, wasm::ImportType)

wasm_importtype_t* wasm_importtype_new(wasm_name_t* module, wasm_name_t* name,
                                       wasm_externtype_t* type) {
  return release_importtype(wasm::ImportType::make(
      adopt_byte_vec(module), adopt_byte_vec(name), adopt_externtype(type)));
}

const wasm_name_t* wasm_importtype_module(const wasm_importtype_t* it) {
  return hide_byte_vec(it->module());
}

const wasm_name_t* wasm_importtype_name(const wasm_importtype_t* it) {
  return hide_byte_vec(it->name());
}

const wasm_externtype_t* wasm_importtype_type(const wasm_importtype_t* it) {
  return hide_externtype(it->type());
}

// Export Types

WASM_DEFINE_TYPE(exporttype, wasm::ExportType)

wasm_exporttype_t* wasm_exporttype_new(wasm_name_t* name,
                                       wasm_externtype_t* type) {
  return release_exporttype(
      wasm::ExportType::make(adopt_byte_vec(name), adopt_externtype(type)));
}

const wasm_name_t* wasm_exporttype_name(const wasm_exporttype_t* et) {
  return hide_byte_vec(et->name());
}

const wasm_externtype_t* wasm_exporttype_type(const wasm_exporttype_t* et) {
  return hide_externtype(et->type());
}

///////////////////////////////////////////////////////////////////////////////
// Runtime Values

// References

#define WASM_DEFINE_REF_BASE(name, Name)                             \
  WASM_DEFINE_OWN(name, Name)                                        \
                                                                     \
  wasm_##name##_t* wasm_##name##_copy(const wasm_##name##_t* t) {    \
    return release_##name(t->copy());                                \
  }                                                                  \
                                                                     \
  bool wasm_##name##_same(const wasm_##name##_t* t1,                 \
                          const wasm_##name##_t* t2) {               \
    return t1->same(t2);                                             \
  }                                                                  \
                                                                     \
  void* wasm_##name##_get_host_info(const wasm_##name##_t* r) {      \
    return r->get_host_info();                                       \
  }                                                                  \
  void wasm_##name##_set_host_info(wasm_##name##_t* r, void* info) { \
    r->set_host_info(info);                                          \
  }                                                                  \
  void wasm_##name##_set_host_info_with_finalizer(                   \
      wasm_##name##_t* r, void* info, void (*finalizer)(void*)) {    \
    r->set_host_info(info, finalizer);                               \
  }

#define WASM_DEFINE_REF(name, Name)                                        \
  WASM_DEFINE_REF_BASE(name, Name)                                         \
                                                                           \
  wasm_ref_t* wasm_##name##_as_ref(wasm_##name##_t* r) {                   \
    return hide_ref(static_cast<wasm::Ref*>(reveal_##name(r)));            \
  }                                                                        \
  wasm_##name##_t* wasm_ref_as_##name(wasm_ref_t* r) {                     \
    return hide_##name(static_cast<Name*>(reveal_ref(r)));                 \
  }                                                                        \
                                                                           \
  const wasm_ref_t* wasm_##name##_as_ref_const(const wasm_##name##_t* r) { \
    return hide_ref(static_cast<const wasm::Ref*>(reveal_##name(r)));      \
  }                                                                        \
  const wasm_##name##_t* wasm_ref_as_##name##_const(const wasm_ref_t* r) { \
    return hide_##name(static_cast<const Name*>(reveal_ref(r)));           \
  }

#define WASM_DEFINE_SHARABLE_REF(name, Name) \
  WASM_DEFINE_REF(name, Name)                \
  WASM_DEFINE_OWN(shared_##name, wasm::Shared<Name>)

WASM_DEFINE_REF_BASE(ref, wasm::Ref)

// Values

extern "C++" {

inline auto is_empty(wasm_val_t v) -> bool {
  return !is_ref(reveal_valkind(v.kind)) || !v.of.ref;
}

inline auto hide_val(wasm::Val v) -> wasm_val_t {
  wasm_val_t v2 = {hide_valkind(v.kind()), {}};
  switch (v.kind()) {
    case wasm::I32:
      v2.of.i32 = v.i32();
      break;
    case wasm::I64:
      v2.of.i64 = v.i64();
      break;
    case wasm::F32:
      v2.of.f32 = v.f32();
      break;
    case wasm::F64:
      v2.of.f64 = v.f64();
      break;
    case wasm::ANYREF:
    case wasm::FUNCREF:
      v2.of.ref = hide_ref(v.ref());
      break;
    default:
      UNREACHABLE();
  }
  return v2;
}

inline auto release_val(wasm::Val v) -> wasm_val_t {
  wasm_val_t v2 = {hide_valkind(v.kind()), {}};
  switch (v.kind()) {
    case wasm::I32:
      v2.of.i32 = v.i32();
      break;
    case wasm::I64:
      v2.of.i64 = v.i64();
      break;
    case wasm::F32:
      v2.of.f32 = v.f32();
      break;
    case wasm::F64:
      v2.of.f64 = v.f64();
      break;
    case wasm::ANYREF:
    case wasm::FUNCREF:
      v2.of.ref = release_ref(v.release_ref());
      break;
    default:
      UNREACHABLE();
  }
  return v2;
}

inline auto adopt_val(wasm_val_t v) -> wasm::Val {
  switch (reveal_valkind(v.kind)) {
    case wasm::I32:
      return wasm::Val(v.of.i32);
    case wasm::I64:
      return wasm::Val(v.of.i64);
    case wasm::F32:
      return wasm::Val(v.of.f32);
    case wasm::F64:
      return wasm::Val(v.of.f64);
    case wasm::ANYREF:
    case wasm::FUNCREF:
      return wasm::Val(adopt_ref(v.of.ref));
    default:
      UNREACHABLE();
  }
}

struct borrowed_val {
  wasm::Val it;
  explicit borrowed_val(wasm::Val&& v) : it(std::move(v)) {}
  borrowed_val(borrowed_val&& that) : it(std::move(that.it)) {}
  ~borrowed_val() {
    if (it.is_ref()) it.release_ref().release();
  }
};

inline auto borrow_val(const wasm_val_t* v) -> borrowed_val {
  wasm::Val v2;
  switch (reveal_valkind(v->kind)) {
    case wasm::I32:
      v2 = wasm::Val(v->of.i32);
      break;
    case wasm::I64:
      v2 = wasm::Val(v->of.i64);
      break;
    case wasm::F32:
      v2 = wasm::Val(v->of.f32);
      break;
    case wasm::F64:
      v2 = wasm::Val(v->of.f64);
      break;
    case wasm::ANYREF:
    case wasm::FUNCREF:
      v2 = wasm::Val(adopt_ref(v->of.ref));
      break;
    default:
      UNREACHABLE();
  }
  return borrowed_val(std::move(v2));
}

}  // extern "C++"

WASM_DEFINE_VEC_BASE(val, wasm::Val, wasm::vec, )

void wasm_val_vec_new(wasm_val_vec_t* out, size_t size,
                      wasm_val_t const data[]) {
  auto v2 = wasm::vec<wasm::Val>::make_uninitialized(size);
  for (size_t i = 0; i < v2.size(); ++i) {
    v2[i] = adopt_val(data[i]);
  }
  *out = release_val_vec(std::move(v2));
}

void wasm_val_vec_copy(wasm_val_vec_t* out, wasm_val_vec_t* v) {
  auto v2 = wasm::vec<wasm::Val>::make_uninitialized(v->size);
  for (size_t i = 0; i < v2.size(); ++i) {
    wasm_val_t val;
    wasm_val_copy(&v->data[i], &val);
    v2[i] = adopt_val(val);
  }
  *out = release_val_vec(std::move(v2));
}

void wasm_val_delete(wasm_val_t* v) {
  if (is_ref(reveal_valkind(v->kind))) {
    adopt_ref(v->of.ref);
  }
}

void wasm_val_copy(wasm_val_t* out, const wasm_val_t* v) {
  *out = *v;
  if (is_ref(reveal_valkind(v->kind))) {
    out->of.ref = v->of.ref ? release_ref(v->of.ref->copy()) : nullptr;
  }
}

///////////////////////////////////////////////////////////////////////////////
// Runtime Objects

// Frames

WASM_DEFINE_OWN(frame, wasm::Frame)
WASM_DEFINE_VEC_OWN(frame, wasm::Frame)

wasm_frame_t* wasm_frame_copy(const wasm_frame_t* frame) {
  return release_frame(frame->copy());
}

wasm_instance_t* wasm_frame_instance(const wasm_frame_t* frame);
// Defined below along with wasm_instance_t.

uint32_t wasm_frame_func_index(const wasm_frame_t* frame) {
  return reveal_frame(frame)->func_index();
}

size_t wasm_frame_func_offset(const wasm_frame_t* frame) {
  return reveal_frame(frame)->func_offset();
}

size_t wasm_frame_module_offset(const wasm_frame_t* frame) {
  return reveal_frame(frame)->module_offset();
}

// Traps

WASM_DEFINE_REF(trap, wasm::Trap)

wasm_trap_t* wasm_trap_new(wasm_store_t* store, const wasm_message_t* message) {
  auto message_ = borrow_byte_vec(message);
  return release_trap(wasm::Trap::make(store, message_.it));
}

void wasm_trap_message(const wasm_trap_t* trap, wasm_message_t* out) {
  *out = release_byte_vec(reveal_trap(trap)->message());
}

wasm_frame_t* wasm_trap_origin(const wasm_trap_t* trap) {
  return release_frame(reveal_trap(trap)->origin());
}

void wasm_trap_trace(const wasm_trap_t* trap, wasm_frame_vec_t* out) {
  *out = release_frame_vec(reveal_trap(trap)->trace());
}

// Foreign Objects

WASM_DEFINE_REF(foreign, wasm::Foreign)

wasm_foreign_t* wasm_foreign_new(wasm_store_t* store) {
  return release_foreign(wasm::Foreign::make(store));
}

// Modules

WASM_DEFINE_SHARABLE_REF(module, wasm::Module)

bool wasm_module_validate(wasm_store_t* store, const wasm_byte_vec_t* binary) {
  auto binary_ = borrow_byte_vec(binary);
  return wasm::Module::validate(store, binary_.it);
}

wasm_module_t* wasm_module_new(wasm_store_t* store,
                               const wasm_byte_vec_t* binary) {
  auto binary_ = borrow_byte_vec(binary);
  return release_module(wasm::Module::make(store, binary_.it));
}

void wasm_module_imports(const wasm_module_t* module,
                         wasm_importtype_vec_t* out) {
  *out = release_importtype_vec(reveal_module(module)->imports());
}

void wasm_module_exports(const wasm_module_t* module,
                         wasm_exporttype_vec_t* out) {
  *out = release_exporttype_vec(reveal_module(module)->exports());
}

void wasm_module_serialize(const wasm_module_t* module, wasm_byte_vec_t* out) {
  *out = release_byte_vec(reveal_module(module)->serialize());
}

wasm_module_t* wasm_module_deserialize(wasm_store_t* store,
                                       const wasm_byte_vec_t* binary) {
  auto binary_ = borrow_byte_vec(binary);
  return release_module(wasm::Module::deserialize(store, binary_.it));
}

wasm_shared_module_t* wasm_module_share(const wasm_module_t* module) {
  return release_shared_module(reveal_module(module)->share());
}

wasm_module_t* wasm_module_obtain(wasm_store_t* store,
                                  const wasm_shared_module_t* shared) {
  return release_module(wasm::Module::obtain(store, shared));
}

// Function Instances

WASM_DEFINE_REF(func, wasm::Func)

extern "C++" {

auto wasm_callback(void* env, const wasm::Val args[], wasm::Val results[])
    -> wasm::own<wasm::Trap> {
  auto f = reinterpret_cast<wasm_func_callback_t>(env);
  return adopt_trap(f(hide_val_vec(args), hide_val_vec(results)));
}

struct wasm_callback_env_t {
  wasm_func_callback_with_env_t callback;
  void* env;
  void (*finalizer)(void*);
};

auto wasm_callback_with_env(void* env, const wasm::Val args[],
                            wasm::Val results[]) -> wasm::own<wasm::Trap> {
  auto t = static_cast<wasm_callback_env_t*>(env);
  return adopt_trap(
      t->callback(t->env, hide_val_vec(args), hide_val_vec(results)));
}

void wasm_callback_env_finalizer(void* env) {
  auto t = static_cast<wasm_callback_env_t*>(env);
  if (t->finalizer) t->finalizer(t->env);
  delete t;
}

}  // extern "C++"

wasm_func_t* wasm_func_new(wasm_store_t* store, const wasm_functype_t* type,
                           wasm_func_callback_t callback) {
  return release_func(wasm::Func::make(store, type, wasm_callback,
                                       reinterpret_cast<void*>(callback)));
}

wasm_func_t* wasm_func_new_with_env(wasm_store_t* store,
                                    const wasm_functype_t* type,
                                    wasm_func_callback_with_env_t callback,
                                    void* env, void (*finalizer)(void*)) {
  auto env2 = new wasm_callback_env_t{callback, env, finalizer};
  return release_func(wasm::Func::make(store, type, wasm_callback_with_env,
                                       env2, wasm_callback_env_finalizer));
}

wasm_functype_t* wasm_func_type(const wasm_func_t* func) {
  return release_functype(func->type());
}

size_t wasm_func_param_arity(const wasm_func_t* func) {
  return func->param_arity();
}

size_t wasm_func_result_arity(const wasm_func_t* func) {
  return func->result_arity();
}

wasm_trap_t* wasm_func_call(const wasm_func_t* func, const wasm_val_t args[],
                            wasm_val_t results[]) {
  return release_trap(
      func->call(reveal_val_vec(args), reveal_val_vec(results)));
}

// Global Instances

WASM_DEFINE_REF(global, wasm::Global)

wasm_global_t* wasm_global_new(wasm_store_t* store,
                               const wasm_globaltype_t* type,
                               const wasm_val_t* val) {
  auto val_ = borrow_val(val);
  return release_global(wasm::Global::make(store, type, val_.it));
}

wasm_globaltype_t* wasm_global_type(const wasm_global_t* global) {
  return release_globaltype(global->type());
}

void wasm_global_get(const wasm_global_t* global, wasm_val_t* out) {
  *out = release_val(global->get());
}

void wasm_global_set(wasm_global_t* global, const wasm_val_t* val) {
  auto val_ = borrow_val(val);
  global->set(val_.it);
}

// Table Instances

WASM_DEFINE_REF(table, wasm::Table)

wasm_table_t* wasm_table_new(wasm_store_t* store, const wasm_tabletype_t* type,
                             wasm_ref_t* ref) {
  return release_table(wasm::Table::make(store, type, ref));
}

wasm_tabletype_t* wasm_table_type(const wasm_table_t* table) {
  return release_tabletype(table->type());
}

wasm_ref_t* wasm_table_get(const wasm_table_t* table, wasm_table_size_t index) {
  return release_ref(table->get(index));
}

bool wasm_table_set(wasm_table_t* table, wasm_table_size_t index,
                    wasm_ref_t* ref) {
  return table->set(index, ref);
}

wasm_table_size_t wasm_table_size(const wasm_table_t* table) {
  return table->size();
}

bool wasm_table_grow(wasm_table_t* table, wasm_table_size_t delta,
                     wasm_ref_t* ref) {
  return table->grow(delta, ref);
}

// Memory Instances

WASM_DEFINE_REF(memory, wasm::Memory)

wasm_memory_t* wasm_memory_new(wasm_store_t* store,
                               const wasm_memorytype_t* type) {
  return release_memory(wasm::Memory::make(store, type));
}

wasm_memorytype_t* wasm_memory_type(const wasm_memory_t* memory) {
  return release_memorytype(memory->type());
}

wasm_byte_t* wasm_memory_data(wasm_memory_t* memory) { return memory->data(); }

size_t wasm_memory_data_size(const wasm_memory_t* memory) {
  return memory->data_size();
}

wasm_memory_pages_t wasm_memory_size(const wasm_memory_t* memory) {
  return memory->size();
}

bool wasm_memory_grow(wasm_memory_t* memory, wasm_memory_pages_t delta) {
  return memory->grow(delta);
}

// Externals

WASM_DEFINE_REF(extern, wasm::Extern)
WASM_DEFINE_VEC_OWN(extern, wasm::Extern)

wasm_externkind_t wasm_extern_kind(const wasm_extern_t* external) {
  return hide_externkind(external->kind());
}
wasm_externtype_t* wasm_extern_type(const wasm_extern_t* external) {
  return release_externtype(external->type());
}

wasm_extern_t* wasm_func_as_extern(wasm_func_t* func) {
  return hide_extern(static_cast<wasm::Extern*>(reveal_func(func)));
}
wasm_extern_t* wasm_global_as_extern(wasm_global_t* global) {
  return hide_extern(static_cast<wasm::Extern*>(reveal_global(global)));
}
wasm_extern_t* wasm_table_as_extern(wasm_table_t* table) {
  return hide_extern(static_cast<wasm::Extern*>(reveal_table(table)));
}
wasm_extern_t* wasm_memory_as_extern(wasm_memory_t* memory) {
  return hide_extern(static_cast<wasm::Extern*>(reveal_memory(memory)));
}

const wasm_extern_t* wasm_func_as_extern_const(const wasm_func_t* func) {
  return hide_extern(static_cast<const wasm::Extern*>(reveal_func(func)));
}
const wasm_extern_t* wasm_global_as_extern_const(const wasm_global_t* global) {
  return hide_extern(static_cast<const wasm::Extern*>(reveal_global(global)));
}
const wasm_extern_t* wasm_table_as_extern_const(const wasm_table_t* table) {
  return hide_extern(static_cast<const wasm::Extern*>(reveal_table(table)));
}
const wasm_extern_t* wasm_memory_as_extern_const(const wasm_memory_t* memory) {
  return hide_extern(static_cast<const wasm::Extern*>(reveal_memory(memory)));
}

wasm_func_t* wasm_extern_as_func(wasm_extern_t* external) {
  return hide_func(external->func());
}
wasm_global_t* wasm_extern_as_global(wasm_extern_t* external) {
  return hide_global(external->global());
}
wasm_table_t* wasm_extern_as_table(wasm_extern_t* external) {
  return hide_table(external->table());
}
wasm_memory_t* wasm_extern_as_memory(wasm_extern_t* external) {
  return hide_memory(external->memory());
}

const wasm_func_t* wasm_extern_as_func_const(const wasm_extern_t* external) {
  return hide_func(external->func());
}
const wasm_global_t* wasm_extern_as_global_const(
    const wasm_extern_t* external) {
  return hide_global(external->global());
}
const wasm_table_t* wasm_extern_as_table_const(const wasm_extern_t* external) {
  return hide_table(external->table());
}
const wasm_memory_t* wasm_extern_as_memory_const(
    const wasm_extern_t* external) {
  return hide_memory(external->memory());
}

// Module Instances

WASM_DEFINE_REF(instance, wasm::Instance)

wasm_instance_t* wasm_instance_new(wasm_store_t* store,
                                   const wasm_module_t* module,
                                   const wasm_extern_t* const imports[],
                                   wasm_trap_t** trap) {
  wasm::own<wasm::Trap> error;
  wasm_instance_t* instance = release_instance(wasm::Instance::make(
      store, module, reinterpret_cast<const wasm::Extern* const*>(imports),
      &error));
  if (trap) *trap = hide_trap(error.release());
  return instance;
}

void wasm_instance_exports(const wasm_instance_t* instance,
                           wasm_extern_vec_t* out) {
  *out = release_extern_vec(instance->exports());
}

wasm_instance_t* wasm_frame_instance(const wasm_frame_t* frame) {
  return hide_instance(reveal_frame(frame)->instance());
}

#undef WASM_DEFINE_OWN
#undef WASM_DEFINE_VEC_BASE
#undef WASM_DEFINE_VEC_PLAIN
#undef WASM_DEFINE_VEC_OWN
#undef WASM_DEFINE_TYPE
#undef WASM_DEFINE_REF_BASE
#undef WASM_DEFINE_REF
#undef WASM_DEFINE_SHARABLE_REF

}  // extern "C"

"""


```