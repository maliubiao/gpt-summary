Response:
My thinking process to answer the request went something like this:

1. **Understand the Core Request:** The user wants a summary of the functionality of the provided C++ code snippet (`v8/src/wasm/module-instantiate.cc`), considering specific V8 conventions and potential connections to JavaScript.

2. **Initial Skim for Keywords and Concepts:** I scanned the code for recurring terms and familiar concepts related to WebAssembly instantiation in V8. Keywords like `InstanceBuilder`, `ExecuteStartFunction`, `LookupImport`, `LoadDataSegments`, `WriteGlobalValue`, `ProcessImportedFunction`, `ProcessImportedTable`, `ProcessImportedGlobal`, `WasmModuleObject`, `WasmInstanceObject`, `imports`, `exports`, and error handling (`thrower_`) immediately stood out. These suggest the code is involved in the process of creating and linking a WebAssembly module instance.

3. **Break Down Functionality by Class/Method:**  I mentally (or could have done it with annotations) grouped the code by the `InstanceBuilder` class's methods. This helps organize the functionality into logical steps.

4. **Analyze Key Methods:**  I focused on the most prominent methods and deduced their roles:
    * `Build`:  Likely the main entry point for creating the instance.
    * `ExecuteStartFunction`: Handles the execution of the optional `start` function.
    * `LookupImport`:  Deals with resolving imported values from the provided JavaScript imports object. The separate `LookupImportAsm` hints at special handling for asm.js modules.
    * `LoadDataSegments`:  Responsible for initializing the module's linear memory with data from data segments.
    * `WriteGlobalValue`:  Writes initial values to the module's global variables.
    * `SanitizeImports`: Processes and validates the imported values.
    * `ProcessImportedFunction`, `ProcessImportedTable`, `ProcessImportedGlobal`:  Specific handlers for different types of imports (functions, tables, and globals), including type checking and linking.

5. **Infer the Overall Process:** Based on the analyzed methods, I pieced together the instantiation process:
    * Start with a `WasmModuleObject`.
    * Optionally take an imports object (`ffi_`).
    * Resolve imports.
    * Create a `WasmInstanceObject`.
    * Initialize globals.
    * Load data segments into memory.
    * Execute the start function (if present).

6. **Address Specific Questions:**  I revisited the user's specific questions:
    * **Functionality Listing:**  I created a numbered list summarizing the key actions performed by the code.
    * **Torque Source:** I noted that the `.cc` extension indicates C++, not Torque (`.tq`).
    * **JavaScript Relationship:** I focused on the interaction with the imports object. I realized that the imports are JavaScript values being passed into the WebAssembly module. This led to the example of a simple JavaScript object serving as the `imports` argument in `WebAssembly.instantiate`.
    * **Code Logic Inference (Input/Output):** I considered the inputs (the `WasmModuleObject`, the imports object) and the output (the `WasmInstanceObject`). I also thought about the conditional execution of the start function and the possibility of errors during import resolution or instantiation. This led to the example with a function import.
    * **Common Programming Errors:** I considered typical issues when working with WebAssembly imports, such as incorrect types, missing imports, or size mismatches for tables and memories.
    * **Summary (Part 3 of 5):** I emphasized that this section focuses on the *core instantiation logic*, specifically the resolution of imports, initialization of memory and globals, and the execution of the start function. I explicitly mentioned that other parts likely handle module loading/compilation and export handling.

7. **Refine and Organize:** I reviewed my notes and structured the answer logically, using clear headings and formatting for readability. I made sure to connect the C++ code to its impact on the JavaScript API.

8. **Self-Correction/Improvements:**  Initially, I might have focused too much on individual lines of code. I then shifted to a higher-level understanding of the workflow. I also made sure to explicitly address *all* parts of the user's request, including the Torque question and the "part 3 of 5" context. I ensured that the JavaScript examples were simple and directly relevant to the C++ functionality being described. I also made sure to connect the "common programming errors" back to the actions described in the C++ code (e.g., type errors in `ProcessImportedFunction`).
这是 `v8/src/wasm/module-instantiate.cc` 源代码的第三部分，主要负责 **完成 WebAssembly 模块实例化过程中的核心步骤**。

**核心功能归纳:**

基于提供的代码片段，我们可以归纳出以下主要功能：

1. **完成实例构建并返回实例对象:**
   - 在成功完成所有必要的初始化后，`InstanceBuilder::Build()` 方法会返回新创建的 `WasmInstanceObject`。
   - 它会记录实例化成功的跟踪信息和性能指标。

2. **执行 Start 函数 (如果存在):**
   - `InstanceBuilder::ExecuteStartFunction()` 负责执行模块中定义的 `start` 函数（如果有）。
   - 它会设置正确的执行上下文，并调用该函数。
   - 如果 `start` 函数执行过程中发生异常，该方法会返回 `false`。

3. **查找导入值:**
   - `InstanceBuilder::LookupImport()` 方法用于在提供的 `ffi_` 对象（通常是 JavaScript 传递的 imports 对象）中查找指定模块和导入名称的值。
   - 它会进行类型检查，确保导入的模块和成员是对象或函数。
   - 如果找不到导入，则会抛出 `LinkError`。

4. **查找 Asm.js 模块的导入值 (特殊处理):**
   - `InstanceBuilder::LookupImportAsm()` 针对 Asm.js 模块的导入进行特殊处理，执行非观察性的查找。
   - 它只接受数据属性，并且对导入的全局变量函数有特定的类型检查（确保其 `ToNumber` 行为是默认的）。

5. **加载数据段到内存:**
   - `InstanceBuilder::LoadDataSegments()` 方法负责将模块的数据段内容复制到实例的线性内存中。
   - 它会计算目标地址，并进行边界检查，防止越界访问。

6. **写入全局变量值:**
   - `InstanceBuilder::WriteGlobalValue()` 方法用于初始化模块的全局变量。
   - 它会根据全局变量的类型和可变性，将初始值写入到相应的内存位置。

7. **创建编译时导入的函数:**
   - `CreateFunctionForCompileTimeImport()` 函数用于创建一些预定义的、用于编译时导入的 JavaScript 函数（例如字符串操作相关的函数）。

8. **清理和验证导入:**
   - `InstanceBuilder::SanitizeImports()` 方法负责处理和验证模块的导入。
   - 它会根据导入的类型，从提供的 `ffi_` 对象中查找对应的值。
   - 对于特定的编译时导入，会创建相应的 JavaScript 函数。
   - 它还会处理模块内部的字符串常量导入。

9. **处理导入的函数:**
   - `InstanceBuilder::ProcessImportedFunction()` 方法处理函数类型的导入。
   - 它会检查导入的值是否可调用。
   - 它会根据导入函数的类型和签名，创建相应的调用入口点（例如，Wasm 到 JS 的桥接函数，或者直接指向另一个 Wasm 函数）。

10. **初始化导入的间接函数表:**
    - `InstanceBuilder::InitializeImportedIndirectFunctionTable()` 处理导入的 WebAssembly 表格（`WebAssembly.Table`），特别是用于 `funcref` 类型的表格。
    - 它会分配新的分发表格，并将导入表格中的函数引用复制到新的分发表格中。

11. **处理导入的表格:**
    - `InstanceBuilder::ProcessImportedTable()` 方法处理表格类型的导入。
    - 它会检查导入的值是否是 `WebAssembly.Table` 对象，并进行大小和类型兼容性检查。

12. **处理导入的 WebAssembly 全局对象:**
    - `InstanceBuilder::ProcessImportedWasmGlobalObject()` 处理导入的 `WebAssembly.Global` 对象。
    - 它会检查导入的全局变量的可变性和类型是否与模块定义匹配。

13. **处理导入的全局变量:**
    - `InstanceBuilder::ProcessImportedGlobal()` 方法处理全局变量类型的导入。
    - 对于不可变的全局变量，它会将其转换为数字并存储在实例的内存中。
    - 对于可变的全局变量，它会引用导入的 `WebAssembly.Global` 对象的底层存储。

**关于问题中的其他点：**

* **`.tq` 结尾:** `v8/src/wasm/module-instantiate.cc` 以 `.cc` 结尾，表示它是 **C++ 源代码**，而不是 Torque 源代码（Torque 源代码以 `.tq` 结尾）。

* **与 JavaScript 的关系:** 这个文件的功能与 JavaScript 的 `WebAssembly.instantiate()` API 密切相关。`WebAssembly.instantiate()` 负责创建一个 WebAssembly 模块的实例。提供的代码片段就是 V8 引擎内部实现模块实例化逻辑的一部分。

   **JavaScript 示例:**

   ```javascript
   const wasmCode = new Uint8Array([
     0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
     // ... (Wasm 模块的二进制代码) ...
   ]);

   const importObject = {
     env: {
       // 这是导入的 JavaScript 函数
       external_func: (arg) => {
         console.log("来自 WebAssembly 的调用:", arg);
       },
       memory: new WebAssembly.Memory({ initial: 1 }),
       global_var: 42
     }
   };

   WebAssembly.instantiate(wasmCode, importObject)
     .then(result => {
       // result.instance 是创建的 WebAssembly 实例
       result.instance.exports.exported_func();
     });
   ```

   在这个例子中，`importObject` 就类似于代码中的 `ffi_`，用于提供 WebAssembly 模块所需的导入值。`v8/src/wasm/module-instantiate.cc` 中的代码负责在 `importObject` 中查找 `external_func`、`memory` 和 `global_var` 的值，并将它们链接到 WebAssembly 模块的实例中。

* **代码逻辑推理 (假设输入与输出):**

   **假设输入:**

   - `module_object_`: 一个已经加载和编译的 WebAssembly 模块对象，包含了模块的结构信息、代码等。
   - `ffi_`: 一个 JavaScript 对象，包含了模块所需的导入值（函数、内存、全局变量等）。例如：
     ```javascript
     {
       env: {
         imported_function: () => console.log("Hello from import"),
         memory: new WebAssembly.Memory({ initial: 1 })
       }
     }
     ```

   **假设输出:**

   - `instance_object`: 一个 `WasmInstanceObject`，代表了 WebAssembly 模块的实例。这个对象包含了模块的线性内存、全局变量、函数表等的状态，并且链接了导入的值。如果实例化过程中出现错误（例如找不到导入），则可能会抛出异常或返回错误指示。

* **用户常见的编程错误:**

   1. **导入类型不匹配:**  在 JavaScript 中提供的导入值的类型与 WebAssembly 模块声明的导入类型不符。例如，WebAssembly 期望导入一个函数，但 JavaScript 提供了数字。

      ```javascript
      // WebAssembly 期望导入一个函数
      const importObject = {
        env: {
          imported_func: 123 // 错误：提供了数字而不是函数
        }
      };
      ```

   2. **缺少必需的导入:**  JavaScript 中没有提供 WebAssembly 模块声明的某个导入。

      ```javascript
      // WebAssembly 期望导入名为 'missing_func' 的函数
      const importObject = {
        env: {
          // 没有提供 'missing_func'
        }
      };
      ```

   3. **表格或内存大小不匹配:** 导入的表格或内存对象的大小与 WebAssembly 模块声明的初始或最大大小不一致。

      ```javascript
      // WebAssembly 声明了一个初始大小为 10 的内存
      const importObject = {
        env: {
          memory: new WebAssembly.Memory({ initial: 5 }) // 错误：初始大小不匹配
        }
      };
      ```

   4. **可变全局变量的导入问题:** 尝试导入一个不可变的 JavaScript 变量作为 WebAssembly 的可变全局变量（或反之）。

**总结 (第 3 部分功能):**

这部分代码主要负责 WebAssembly 模块实例化的核心链接和初始化阶段。它处理以下关键任务：

- **查找并验证导入的值 (函数、内存、全局变量、表格)。**
- **将导入的值链接到新创建的 WebAssembly 实例。**
- **初始化模块的全局变量。**
- **将数据段加载到实例的线性内存中。**
- **执行模块的 `start` 函数 (如果存在)。**
- **最终构建并返回可用的 WebAssembly 实例对象。**

简而言之，这是将编译好的 WebAssembly 模块和外部提供的导入值组合成一个可执行实例的关键步骤。

### 提示词
```
这是目录为v8/src/wasm/module-instantiate.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/module-instantiate.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
has_exception());
  TRACE("Successfully built instance for module %p\n",
        module_object_->native_module());
  wasm_module_instantiated.success = true;
  if (timer.IsStarted()) {
    base::TimeDelta instantiation_time = timer.Elapsed();
    wasm_module_instantiated.wall_clock_duration_in_us =
        instantiation_time.InMicroseconds();
    SELECT_WASM_COUNTER(isolate_->counters(), module_->origin, wasm_instantiate,
                        module_time)
        ->AddTimedSample(instantiation_time);
    isolate_->metrics_recorder()->DelayMainThreadEvent(wasm_module_instantiated,
                                                       context_id_);
  }

#if V8_ENABLE_DRUMBRAKE
  // Skip this event because not (yet) supported by Chromium.

  // v8::metrics::WasmInterpreterJitStatus jit_status;
  // jit_status.jitless = v8_flags.wasm_jitless;
  // isolate_->metrics_recorder()->DelayMainThreadEvent(jit_status,
  // context_id_);
#endif  // V8_ENABLE_DRUMBRAKE

  return instance_object;
}

bool InstanceBuilder::ExecuteStartFunction() {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
               "wasm.ExecuteStartFunction");
  if (start_function_.is_null()) return true;  // No start function.

  HandleScope scope(isolate_);
  // In case the start function calls out to Blink, we have to make sure that
  // the correct "entered context" is available. This is the equivalent of
  // v8::Context::Enter() and must happen in addition to the function call
  // sequence doing the compiled version of "isolate->set_context(...)".
  HandleScopeImplementer* hsi = isolate_->handle_scope_implementer();
  hsi->EnterContext(start_function_->native_context());

  // Call the JS function.
  Handle<Object> undefined = isolate_->factory()->undefined_value();
  MaybeHandle<Object> retval =
      Execution::Call(isolate_, start_function_, undefined, 0, nullptr);
  hsi->LeaveContext();
  // {start_function_} has to be called only once.
  start_function_ = {};

  if (retval.is_null()) {
    DCHECK(isolate_->has_exception());
    return false;
  }
  return true;
}

// Look up an import value in the {ffi_} object.
MaybeHandle<Object> InstanceBuilder::LookupImport(uint32_t index,
                                                  Handle<String> module_name,
                                                  Handle<String> import_name) {
  // The caller checked that the ffi object is present; and we checked in
  // the JS-API layer that the ffi object, if present, is a JSObject.
  DCHECK(!ffi_.is_null());
  // Look up the module first.
  Handle<Object> module;
  Handle<JSReceiver> module_recv;
  if (!Object::GetPropertyOrElement(isolate_, ffi_.ToHandleChecked(),
                                    module_name)
           .ToHandle(&module) ||
      !TryCast<JSReceiver>(module, &module_recv)) {
    const char* error = module.is_null()
                            ? "module not found"
                            : "module is not an object or function";
    thrower_->TypeError("%s: %s", ImportName(index, module_name).c_str(),
                        error);
    return {};
  }

  MaybeHandle<Object> value =
      Object::GetPropertyOrElement(isolate_, module_recv, import_name);
  if (value.is_null()) {
    thrower_->LinkError("%s: import not found", ImportName(index).c_str());
    return {};
  }

  return value;
}

namespace {
bool HasDefaultToNumberBehaviour(Isolate* isolate,
                                 Handle<JSFunction> function) {
  // Disallow providing a [Symbol.toPrimitive] member.
  LookupIterator to_primitive_it{isolate, function,
                                 isolate->factory()->to_primitive_symbol()};
  if (to_primitive_it.state() != LookupIterator::NOT_FOUND) return false;

  // The {valueOf} member must be the default "ObjectPrototypeValueOf".
  LookupIterator value_of_it{isolate, function,
                             isolate->factory()->valueOf_string()};
  if (value_of_it.state() != LookupIterator::DATA) return false;
  Handle<Object> value_of = value_of_it.GetDataValue();
  if (!IsJSFunction(*value_of)) return false;
  Builtin value_of_builtin_id =
      Cast<JSFunction>(value_of)->code(isolate)->builtin_id();
  if (value_of_builtin_id != Builtin::kObjectPrototypeValueOf) return false;

  // The {toString} member must be the default "FunctionPrototypeToString".
  LookupIterator to_string_it{isolate, function,
                              isolate->factory()->toString_string()};
  if (to_string_it.state() != LookupIterator::DATA) return false;
  Handle<Object> to_string = to_string_it.GetDataValue();
  if (!IsJSFunction(*to_string)) return false;
  Builtin to_string_builtin_id =
      Cast<JSFunction>(to_string)->code(isolate)->builtin_id();
  if (to_string_builtin_id != Builtin::kFunctionPrototypeToString) return false;

  // Just a default function, which will convert to "Nan". Accept this.
  return true;
}

bool MaybeMarkError(ValueOrError value, ErrorThrower* thrower) {
  if (is_error(value)) {
    thrower->RuntimeError("%s",
                          MessageFormatter::TemplateString(to_error(value)));
    return true;
  }
  return false;
}
}  // namespace

// Look up an import value in the {ffi_} object specifically for linking an
// asm.js module. This only performs non-observable lookups, which allows
// falling back to JavaScript proper (and hence re-executing all lookups) if
// module instantiation fails.
MaybeHandle<Object> InstanceBuilder::LookupImportAsm(
    uint32_t index, Handle<String> import_name) {
  // The caller checked that the ffi object is present.
  DCHECK(!ffi_.is_null());

  // Perform lookup of the given {import_name} without causing any observable
  // side-effect. We only accept accesses that resolve to data properties,
  // which is indicated by the asm.js spec in section 7 ("Linking") as well.
  PropertyKey key(isolate_, Cast<Name>(import_name));
  LookupIterator it(isolate_, ffi_.ToHandleChecked(), key);
  switch (it.state()) {
    case LookupIterator::ACCESS_CHECK:
    case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
    case LookupIterator::INTERCEPTOR:
    case LookupIterator::JSPROXY:
    case LookupIterator::WASM_OBJECT:
    case LookupIterator::ACCESSOR:
    case LookupIterator::TRANSITION:
      thrower_->LinkError("%s: not a data property",
                          ImportName(index, import_name).c_str());
      return {};
    case LookupIterator::NOT_FOUND:
      // Accepting missing properties as undefined does not cause any
      // observable difference from JavaScript semantics, we are lenient.
      return isolate_->factory()->undefined_value();
    case LookupIterator::DATA: {
      Handle<Object> value = it.GetDataValue();
      // For legacy reasons, we accept functions for imported globals (see
      // {ProcessImportedGlobal}), but only if we can easily determine that
      // their Number-conversion is side effect free and returns NaN (which is
      // the case as long as "valueOf" (or others) are not overwritten).
      if (IsJSFunction(*value) &&
          module_->import_table[index].kind == kExternalGlobal &&
          !HasDefaultToNumberBehaviour(isolate_, Cast<JSFunction>(value))) {
        thrower_->LinkError("%s: function has special ToNumber behaviour",
                            ImportName(index, import_name).c_str());
        return {};
      }
      return value;
    }
  }
}

// Load data segments into the memory.
// TODO(14616): Consider what to do with shared memories.
void InstanceBuilder::LoadDataSegments(
    Handle<WasmTrustedInstanceData> trusted_instance_data,
    Handle<WasmTrustedInstanceData> shared_trusted_instance_data) {
  base::Vector<const uint8_t> wire_bytes =
      module_object_->native_module()->wire_bytes();
  for (const WasmDataSegment& segment : module_->data_segments) {
    uint32_t size = segment.source.length();

    // Passive segments are not copied during instantiation.
    if (!segment.active) continue;

    const WasmMemory& dst_memory = module_->memories[segment.memory_index];
    size_t dest_offset;
    ValueOrError result = EvaluateConstantExpression(
        &init_expr_zone_, segment.dest_addr,
        dst_memory.is_memory64() ? kWasmI64 : kWasmI32, module_, isolate_,
        trusted_instance_data, shared_trusted_instance_data);
    if (MaybeMarkError(result, thrower_)) return;
    if (dst_memory.is_memory64()) {
      uint64_t dest_offset_64 = to_value(result).to_u64();

      // Clamp to {std::numeric_limits<size_t>::max()}, which is always an
      // invalid offset, so we always fail the bounds check below.
      DCHECK_GT(std::numeric_limits<size_t>::max(), dst_memory.max_memory_size);
      dest_offset = static_cast<size_t>(std::min(
          dest_offset_64, uint64_t{std::numeric_limits<size_t>::max()}));
    } else {
      dest_offset = to_value(result).to_u32();
    }

    size_t memory_size =
        trusted_instance_data->memory_size(segment.memory_index);
    if (!base::IsInBounds<size_t>(dest_offset, size, memory_size)) {
      size_t segment_index = &segment - module_->data_segments.data();
      thrower_->RuntimeError(
          "data segment %zu is out of bounds (offset %zu, "
          "length %u, memory size %zu)",
          segment_index, dest_offset, size, memory_size);
      return;
    }

    uint8_t* memory_base =
        trusted_instance_data->memory_base(segment.memory_index);
    std::memcpy(memory_base + dest_offset,
                wire_bytes.begin() + segment.source.offset(), size);
  }
}

void InstanceBuilder::WriteGlobalValue(const WasmGlobal& global,
                                       const WasmValue& value) {
  TRACE("init [globals_start=%p + %u] = %s, type = %s\n",
        global.type.is_reference()
            ? reinterpret_cast<uint8_t*>(tagged_globals_->address())
            : raw_buffer_ptr(untagged_globals_, 0),
        global.offset, value.to_string().c_str(), global.type.name().c_str());
  DCHECK(
      global.mutability
          ? EquivalentTypes(value.type(), global.type, value.module(), module_)
          : IsSubtypeOf(value.type(), global.type, value.module(), module_));
  if (global.type.is_numeric()) {
    value.CopyTo(GetRawUntaggedGlobalPtr<uint8_t>(global));
  } else {
    tagged_globals_->set(global.offset, *value.to_ref());
  }
}

// Returns the name, Builtin ID, and "length" (in the JSFunction sense, i.e.
// number of parameters) for the function representing the given import.
std::tuple<const char*, Builtin, int> NameBuiltinLength(WellKnownImport wki) {
#define CASE(CamelName, name, length)       \
  case WellKnownImport::kString##CamelName: \
    return std::make_tuple(name, Builtin::kWebAssemblyString##CamelName, length)
  switch (wki) {
    CASE(Cast, "cast", 1);
    CASE(CharCodeAt, "charCodeAt", 2);
    CASE(CodePointAt, "codePointAt", 2);
    CASE(Compare, "compare", 2);
    CASE(Concat, "concat", 2);
    CASE(Equals, "equals", 2);
    CASE(FromCharCode, "fromCharCode", 1);
    CASE(FromCodePoint, "fromCodePoint", 1);
    CASE(FromUtf8Array, "decodeStringFromUTF8Array", 3);
    CASE(FromWtf16Array, "fromCharCodeArray", 3);
    CASE(IntoUtf8Array, "encodeStringIntoUTF8Array", 3);
    CASE(Length, "length", 1);
    CASE(MeasureUtf8, "measureStringAsUTF8", 1);
    CASE(Substring, "substring", 3);
    CASE(Test, "test", 1);
    CASE(ToUtf8Array, "encodeStringToUTF8Array", 1);
    CASE(ToWtf16Array, "intoCharCodeArray", 3);
    default:
      UNREACHABLE();  // Only call this for compile-time imports.
  }
#undef CASE
}

Handle<JSFunction> CreateFunctionForCompileTimeImport(Isolate* isolate,
                                                      WellKnownImport wki) {
  auto [name, builtin, length] = NameBuiltinLength(wki);
  Factory* factory = isolate->factory();
  Handle<NativeContext> context(isolate->native_context());
  Handle<Map> map = isolate->strict_function_without_prototype_map();
  Handle<String> name_str = factory->InternalizeUtf8String(name);
  Handle<SharedFunctionInfo> info = factory->NewSharedFunctionInfoForBuiltin(
      name_str, builtin, length, kAdapt);
  info->set_native(true);
  info->set_language_mode(LanguageMode::kStrict);
  Handle<JSFunction> fun =
      Factory::JSFunctionBuilder{isolate, info, context}.set_map(map).Build();
  return fun;
}

void InstanceBuilder::SanitizeImports() {
  NativeModule* native_module = module_object_->native_module();
  base::Vector<const uint8_t> wire_bytes = native_module->wire_bytes();
  const WellKnownImportsList& well_known_imports =
      module_->type_feedback.well_known_imports;
  const std::string& magic_string_constants =
      native_module->compile_imports().constants_module();
  const bool has_magic_string_constants =
      native_module->compile_imports().contains(
          CompileTimeImport::kStringConstants);
  for (uint32_t index = 0; index < module_->import_table.size(); ++index) {
    const WasmImport& import = module_->import_table[index];

    if (import.kind == kExternalGlobal && has_magic_string_constants &&
        import.module_name.length() == magic_string_constants.size() &&
        std::equal(magic_string_constants.begin(), magic_string_constants.end(),
                   wire_bytes.begin() + import.module_name.offset())) {
      Handle<String> value = WasmModuleObject::ExtractUtf8StringFromModuleBytes(
          isolate_, wire_bytes, import.field_name, kNoInternalize);
      sanitized_imports_.push_back(value);
      continue;
    }

    if (import.kind == kExternalFunction) {
      WellKnownImport wki = well_known_imports.get(import.index);
      if (IsCompileTimeImport(wki)) {
        Handle<JSFunction> fun =
            CreateFunctionForCompileTimeImport(isolate_, wki);
        sanitized_imports_.push_back(fun);
        continue;
      }
    }

    if (ffi_.is_null()) {
      // No point in continuing if we don't have an imports object.
      thrower_->TypeError(
          "Imports argument must be present and must be an object");
      return;
    }

    Handle<String> module_name =
        WasmModuleObject::ExtractUtf8StringFromModuleBytes(
            isolate_, wire_bytes, import.module_name, kInternalize);

    Handle<String> import_name =
        WasmModuleObject::ExtractUtf8StringFromModuleBytes(
            isolate_, wire_bytes, import.field_name, kInternalize);

    MaybeHandle<Object> result =
        is_asmjs_module(module_)
            ? LookupImportAsm(index, import_name)
            : LookupImport(index, module_name, import_name);
    if (thrower_->error()) {
      return;
    }
    Handle<Object> value = result.ToHandleChecked();
    sanitized_imports_.push_back(value);
  }
}

bool InstanceBuilder::ProcessImportedFunction(
    Handle<WasmTrustedInstanceData> trusted_instance_data, int import_index,
    int func_index, Handle<Object> value, WellKnownImport preknown_import) {
  // Function imports must be callable.
  if (!IsCallable(*value)) {
    if (!IsWasmSuspendingObject(*value)) {
      thrower_->LinkError("%s: function import requires a callable",
                          ImportName(import_index).c_str());
      return false;
    }
    DCHECK(IsCallable(Cast<WasmSuspendingObject>(*value)->callable()));
  }
  // Store any {WasmExternalFunction} callable in the instance before the call
  // is resolved to preserve its identity. This handles exported functions as
  // well as functions constructed via other means (e.g. WebAssembly.Function).
  if (WasmExternalFunction::IsWasmExternalFunction(*value)) {
    trusted_instance_data->func_refs()->set(
        func_index, Cast<WasmExternalFunction>(*value)->func_ref());
  }
  auto js_receiver = Cast<JSReceiver>(value);
  CanonicalTypeIndex sig_index =
      module_->canonical_sig_id(module_->functions[func_index].sig_index);
  const CanonicalSig* expected_sig =
      GetTypeCanonicalizer()->LookupFunctionSignature(sig_index);
  ResolvedWasmImport resolved(trusted_instance_data, func_index, js_receiver,
                              expected_sig, sig_index, preknown_import);
  if (resolved.well_known_status() != WellKnownImport::kGeneric &&
      v8_flags.trace_wasm_inlining) {
    PrintF("[import %d is well-known built-in %s]\n", import_index,
           WellKnownImportName(resolved.well_known_status()));
  }
  well_known_imports_.push_back(resolved.well_known_status());
  ImportCallKind kind = resolved.kind();
  js_receiver = resolved.callable();
  Handle<WasmFunctionData> trusted_function_data =
      resolved.trusted_function_data();
  ImportedFunctionEntry imported_entry(trusted_instance_data, func_index);
  switch (kind) {
    case ImportCallKind::kRuntimeTypeError:
      imported_entry.SetGenericWasmToJs(isolate_, js_receiver,
                                        resolved.suspend(), expected_sig);
      break;
    case ImportCallKind::kLinkError:
      thrower_->LinkError(
          "%s: imported function does not match the expected type",
          ImportName(import_index).c_str());
      return false;
    case ImportCallKind::kWasmToWasm: {
      // The imported function is a Wasm function from another instance.
      auto function_data =
          Cast<WasmExportedFunctionData>(trusted_function_data);
      // The import reference is the trusted instance data itself.
      Tagged<WasmTrustedInstanceData> instance_data =
          function_data->instance_data();
      WasmCodePointer imported_target =
          instance_data->GetCallTarget(function_data->function_index());
      imported_entry.SetWasmToWasm(instance_data, imported_target
#if V8_ENABLE_DRUMBRAKE
                                   ,
                                   function_data->function_index()
#endif  // V8_ENABLE_DRUMBRAKE
      );
      break;
    }
    case ImportCallKind::kWasmToCapi: {
      int expected_arity = static_cast<int>(expected_sig->parameter_count());
      WasmImportWrapperCache* cache = GetWasmImportWrapperCache();
      WasmCodeRefScope code_ref_scope;
      WasmCode* wasm_code =
          cache->MaybeGet(kind, sig_index, expected_arity, kNoSuspend);
      if (wasm_code == nullptr) {
        {
          WasmImportWrapperCache::ModificationScope cache_scope(cache);
          WasmCompilationResult result =
              compiler::CompileWasmCapiCallWrapper(expected_sig);
          WasmImportWrapperCache::CacheKey key(kind, sig_index, expected_arity,
                                               kNoSuspend);
          wasm_code = cache_scope.AddWrapper(
              key, std::move(result), WasmCode::Kind::kWasmToCapiWrapper);
        }
        // To avoid lock order inversion, code printing must happen after the
        // end of the {cache_scope}.
        wasm_code->MaybePrint();
        isolate_->counters()->wasm_generated_code_size()->Increment(
            wasm_code->instructions().length());
        isolate_->counters()->wasm_reloc_size()->Increment(
            wasm_code->reloc_info().length());
      }

      // We re-use the SetCompiledWasmToJs infrastructure because it passes the
      // callable to the wrapper, which we need to get the function data.
      imported_entry.SetCompiledWasmToJs(isolate_, js_receiver, wasm_code,
                                         kNoSuspend, expected_sig);
      break;
    }
    case ImportCallKind::kWasmToJSFastApi: {
      DCHECK(IsJSFunction(*js_receiver) || IsJSBoundFunction(*js_receiver));
      WasmCodeRefScope code_ref_scope;
      // Note: the wrapper we're about to compile is specific to this
      // instantiation, so it cannot be shared. However, its lifetime must
      // be managed by the WasmImportWrapperCache, so that it can be used
      // in WasmDispatchTables whose lifetime might exceed that of this
      // instance's NativeModule.
      // So the {CacheKey} is a dummy, and we don't look for an existing
      // wrapper. Key collisions are not a concern because lifetimes are
      // determined by refcounting.
      WasmCompilationResult result =
          compiler::CompileWasmJSFastCallWrapper(expected_sig, js_receiver);
      WasmCode* wasm_code;
      {
        WasmImportWrapperCache::ModificationScope cache_scope(
            GetWasmImportWrapperCache());
        WasmImportWrapperCache::CacheKey dummy_key(kind, CanonicalTypeIndex{0},
                                                   0, kNoSuspend);
        wasm_code = cache_scope.AddWrapper(dummy_key, std::move(result),
                                           WasmCode::Kind::kWasmToJsWrapper);
      }
      // To avoid lock order inversion, code printing must happen after the
      // end of the {cache_scope}.
      wasm_code->MaybePrint();
      imported_entry.SetCompiledWasmToJs(isolate_, js_receiver, wasm_code,
                                         kNoSuspend, expected_sig);
      break;
    }
    default: {
      // The imported function is a callable.
      if (UseGenericWasmToJSWrapper(kind, expected_sig, resolved.suspend())) {
        DCHECK(kind == ImportCallKind::kJSFunctionArityMatch ||
               kind == ImportCallKind::kJSFunctionArityMismatch);
        imported_entry.SetGenericWasmToJs(isolate_, js_receiver,
                                          resolved.suspend(), expected_sig);
        break;
      }
      if (v8_flags.wasm_jitless) {
        WasmCode* no_code = nullptr;
        imported_entry.SetCompiledWasmToJs(isolate_, js_receiver, no_code,
                                           resolved.suspend(), expected_sig);
        break;
      }
      int expected_arity = static_cast<int>(expected_sig->parameter_count());
      if (kind == ImportCallKind::kJSFunctionArityMismatch) {
        auto function = Cast<JSFunction>(js_receiver);
        Tagged<SharedFunctionInfo> shared = function->shared();
        expected_arity =
            shared->internal_formal_parameter_count_without_receiver();
      }

      WasmImportWrapperCache* cache = GetWasmImportWrapperCache();
      WasmCodeRefScope code_ref_scope;
      WasmCode* wasm_code =
          cache->MaybeGet(kind, sig_index, expected_arity, resolved.suspend());
      if (!wasm_code) {
        // This should be a very rare fallback case. We expect that the
        // generic wrapper will be used (see above).
        bool source_positions =
            is_asmjs_module(trusted_instance_data->module());
        wasm_code = cache->CompileWasmImportCallWrapper(
            isolate_, kind, expected_sig, sig_index, source_positions,
            expected_arity, resolved.suspend());
      }

      DCHECK_NOT_NULL(wasm_code);
      if (wasm_code->kind() == WasmCode::kWasmToJsWrapper) {
        // Wasm to JS wrappers are treated specially in the import table.
        imported_entry.SetCompiledWasmToJs(isolate_, js_receiver, wasm_code,
                                           resolved.suspend(), expected_sig);
      } else {
        // Wasm math intrinsics are compiled as regular Wasm functions.
        DCHECK(kind >= ImportCallKind::kFirstMathIntrinsic &&
               kind <= ImportCallKind::kLastMathIntrinsic);
        imported_entry.SetWasmToWasm(*trusted_instance_data,
                                     wasm_code->code_pointer()
#if V8_ENABLE_DRUMBRAKE
                                         ,
                                     -1
#endif  // V8_ENABLE_DRUMBRAKE
        );
      }
      break;
    }
  }
  return true;
}

bool InstanceBuilder::InitializeImportedIndirectFunctionTable(
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
    int table_index, int import_index,
    DirectHandle<WasmTableObject> table_object) {
  int imported_table_size = table_object->current_length();
  // Allocate a new dispatch table.
  WasmTrustedInstanceData::EnsureMinimumDispatchTableSize(
      isolate_, trusted_instance_data, table_index, imported_table_size);
  // Initialize the dispatch table with the (foreign) JS functions
  // that are already in the table.
  for (int i = 0; i < imported_table_size; ++i) {
    bool is_valid;
    bool is_null;
    MaybeHandle<WasmTrustedInstanceData> maybe_target_instance_data;
    int function_index;
    MaybeDirectHandle<WasmJSFunction> maybe_js_function;
    WasmTableObject::GetFunctionTableEntry(
        isolate_, table_object, i, &is_valid, &is_null,
        &maybe_target_instance_data, &function_index, &maybe_js_function);
    if (!is_valid) {
      thrower_->LinkError("table import %d[%d] is not a wasm function",
                          import_index, i);
      return false;
    }
    if (is_null) continue;
    DirectHandle<WasmJSFunction> js_function;
    if (maybe_js_function.ToHandle(&js_function)) {
      WasmTrustedInstanceData::ImportWasmJSFunctionIntoTable(
          isolate_, trusted_instance_data, table_index, i, js_function);
      continue;
    }

    Handle<WasmTrustedInstanceData> target_instance_data =
        maybe_target_instance_data.ToHandleChecked();
    const WasmModule* target_module = target_instance_data->module();
    const WasmFunction& function = target_module->functions[function_index];

    FunctionTargetAndImplicitArg entry(isolate_, target_instance_data,
                                       function_index);
    Handle<Object> implicit_arg = entry.implicit_arg();
    if (v8_flags.wasm_generic_wrapper && IsWasmImportData(*implicit_arg)) {
      auto orig_import_data = Cast<WasmImportData>(implicit_arg);
      Handle<WasmImportData> new_import_data =
          isolate_->factory()->NewWasmImportData(orig_import_data);
      // TODO(42204563): Avoid crashing if the instance object is not available.
      CHECK(trusted_instance_data->has_instance_object());
      WasmImportData::SetCrossInstanceTableIndexAsCallOrigin(
          isolate_, new_import_data,
          direct_handle(trusted_instance_data->instance_object(), isolate_), i);
      implicit_arg = new_import_data;
    }

    CanonicalTypeIndex sig_index =
        target_module->canonical_sig_id(function.sig_index);
    SBXCHECK(FunctionSigMatchesTable(sig_index, trusted_instance_data->module(),
                                     table_index));

    trusted_instance_data->dispatch_table(table_index)
        ->Set(i, *implicit_arg, entry.call_target(), sig_index,
#if V8_ENABLE_DRUMBRAKE
              entry.target_func_index(),
#endif  // V8_ENABLE_DRUMBRAKE
              nullptr, IsAWrapper::kMaybe, WasmDispatchTable::kNewEntry);
  }
  return true;
}

bool InstanceBuilder::ProcessImportedTable(
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
    int import_index, int table_index, Handle<Object> value) {
  if (!IsWasmTableObject(*value)) {
    thrower_->LinkError("%s: table import requires a WebAssembly.Table",
                        ImportName(import_index).c_str());
    return false;
  }
  const WasmTable& table = module_->tables[table_index];

  DirectHandle<WasmTableObject> table_object = Cast<WasmTableObject>(value);

  uint32_t imported_table_size =
      static_cast<uint32_t>(table_object->current_length());
  if (imported_table_size < table.initial_size) {
    thrower_->LinkError("table import %d is smaller than initial %u, got %u",
                        import_index, table.initial_size, imported_table_size);
    return false;
  }

  if (table.has_maximum_size) {
    std::optional<uint64_t> max_size = table_object->maximum_length_u64();
    if (!max_size) {
      thrower_->LinkError(
          "table import %d has no maximum length; required: %" PRIu64,
          import_index, table.maximum_size);
      return false;
    }
    if (*max_size > table.maximum_size) {
      thrower_->LinkError("table import %d has a larger maximum size %" PRIx64
                          " than the module's declared maximum %" PRIu64,
                          import_index, *max_size, table.maximum_size);
      return false;
    }
  }

  if (table.address_type != table_object->address_type()) {
    thrower_->LinkError("cannot import %s table as %s",
                        AddressTypeToStr(table_object->address_type()),
                        AddressTypeToStr(table.address_type));
    return false;
  }

  const WasmModule* table_type_module =
      table_object->has_trusted_data()
          ? table_object->trusted_data(isolate_)->module()
          : trusted_instance_data->module();

  if (!EquivalentTypes(table.type, table_object->type(), module_,
                       table_type_module)) {
    thrower_->LinkError("%s: imported table does not match the expected type",
                        ImportName(import_index).c_str());
    return false;
  }

  if (IsSubtypeOf(table.type, kWasmFuncRef, module_) &&
      !InitializeImportedIndirectFunctionTable(
          trusted_instance_data, table_index, import_index, table_object)) {
    return false;
  }

  trusted_instance_data->tables()->set(table_index, *value);
  return true;
}

bool InstanceBuilder::ProcessImportedWasmGlobalObject(
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
    int import_index, const WasmGlobal& global,
    DirectHandle<WasmGlobalObject> global_object) {
  if (static_cast<bool>(global_object->is_mutable()) != global.mutability) {
    thrower_->LinkError(
        "%s: imported global does not match the expected mutability",
        ImportName(import_index).c_str());
    return false;
  }

  const WasmModule* global_type_module =
      global_object->has_trusted_data()
          ? global_object->trusted_data(isolate_)->module()
          : trusted_instance_data->module();

  bool valid_type =
      global.mutability
          ? EquivalentTypes(global_object->type(), global.type,
                            global_type_module, trusted_instance_data->module())
          : IsSubtypeOf(global_object->type(), global.type, global_type_module,
                        trusted_instance_data->module());

  if (!valid_type) {
    thrower_->LinkError("%s: imported global does not match the expected type",
                        ImportName(import_index).c_str());
    return false;
  }
  if (global.mutability) {
    DCHECK_LT(global.index, module_->num_imported_mutable_globals);
    Handle<Object> buffer;
    if (global.type.is_reference()) {
      static_assert(sizeof(global_object->offset()) <= sizeof(Address),
                    "The offset into the globals buffer does not fit into "
                    "the imported_mutable_globals array");
      buffer = handle(global_object->tagged_buffer(), isolate_);
      // For externref globals we use a relative offset, not an absolute
      // address.
      trusted_instance_data->imported_mutable_globals()->set(
          global.index, global_object->offset());
    } else {
      buffer = handle(global_object->untagged_buffer(), isolate_);
      // It is safe in this case to store the raw pointer to the buffer
      // since the backing store of the JSArrayBuffer will not be
      // relocated.
      Address address = reinterpret_cast<Address>(
          raw_buffer_ptr(Cast<JSArrayBuffer>(buffer), global_object->offset()));
      trusted_instance_data->imported_mutable_globals()->set_sandboxed_pointer(
          global.index, address);
    }
    trusted_instance_data->imported_mutable_globals_buffers()->set(global.index,
                                                                   *buffer);
    return true;
  }

  WasmValue value;
  switch (global_object->type().kind()) {
    case kI32:
      value = WasmValue(global_object->GetI32());
      break;
    case kI64:
      value = WasmValue(global_object->GetI64());
      break;
    case kF32:
      value = WasmValue(global_object->GetF32());
      break;
    case kF64:
      value = WasmValue(global_object->GetF64());
      break;
    case kS128:
      value = WasmValue(global_object->GetS128RawBytes(), kWasmS128);
      break;
    case kRef:
    case kRefNull:
      value = WasmValue(global_object->GetRef(), global.type, module_);
      break;
    case kVoid:
    case kTop:
    case kBottom:
    case kRtt:
    case kI8:
    case kI16:
    case kF16:
      UNREACHABLE();
  }

  WriteGlobalValue(global, value);
  return true;
}

bool InstanceBuilder::ProcessImportedGlobal(
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
    int import_index, int global_index, Handle<Object> value) {
  // Immutable global imports are converted to numbers and written into
  // the {untagged_globals_} array buffer.
  //
  // Mutable global imports instead have their backing array buffers
  // referenced by this instance, and store the address of the imported
  // global in the {imported_mutable_globals_} array.
  const WasmGlobal& global = module_->globals[global_index];

  // SIMD proposal allows modules to define an imported v128 global, and only
  // supports importing a WebAssembly.Global object for this global, but also
  // defines constructing a WebAssembly.Global of v128 to be a TypeError.
  // We *should* never hit t
```