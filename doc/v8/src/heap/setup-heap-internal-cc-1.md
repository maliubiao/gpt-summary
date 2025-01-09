Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/heap/setup-heap-internal.cc`. The request also includes some specific constraints and questions.

Here's a breakdown of the thinking process to generate the response:

1. **Identify the Core Purpose:**  The code is within the `Heap` class and deals with creating and initializing various objects within the V8 heap. The function names like `CreateMaps`, `CreateLateReadOnlyJSReceiverMaps`, `CreateImportantReadOnlyObjects`, `CreateReadOnlyObjects`, `CreateMutableApiObjects`, `CreateReadOnlyApiObjects`, and `CreateInitialMutableObjects` strongly suggest this. The numerous `ALLOCATE_MAP` calls confirm that object map creation is a central activity.

2. **Break Down by Function:**  Analyze each function individually to determine its specific role:
    * `CreateMaps`:  Focuses on creating maps for various object types, especially Wasm-related ones and some general utility types (like `WeakCell`, `InterpreterData`).
    * `CreateLateReadOnlyJSReceiverMaps`:  Specifically creates maps for `JSSharedArray`, `JSAtomicsMutex`, and `JSAtomicsCondition`, placing them in read-only space. The presence of "Late" in the name suggests these are created after some initial setup.
    * `StaticRootsEnsureAllocatedSize`:  This function seems related to ensuring a specific size for objects in read-only space, likely for static root stability across different architectures.
    * `CreateImportantReadOnlyObjects`:  Handles the creation of fundamental read-only objects like the hash seed, important strings and symbols, empty data structures (dictionaries, arrays), and crucial number values (NaN, Infinity).
    * `CreateReadOnlyObjects`: Creates more read-only objects, including empty collections (`ArrayList`, `ObjectBoilerplateDescription`), single-character strings, and oddball values (`undefined`, `null`, `true`, `false`, `the_hole`). It also initializes protector objects.
    * `CreateMutableApiObjects`: Creates mutable objects related to the API, like message listeners.
    * `CreateReadOnlyApiObjects`:  Creates read-only API-related objects, like the no-op interceptor info.
    * `CreateInitialMutableObjects`: Creates initially mutable objects, including internal state (current microtask), caches (number string cache, regexp caches), and various lists and protectors. It also sets up internal `SharedFunctionInfo` objects for asynchronous and promise-related functionalities.

3. **Address Specific Constraints:**
    * **`.tq` Extension:**  The code is in `.cc`, so it's C++, not Torque.
    * **JavaScript Relationship:**  Many of the created objects are fundamental to JavaScript execution. Examples include Maps (used in objects), Arrays, Strings, Symbols, and the special values (`undefined`, `null`, etc.). The `CreateLateReadOnlyJSReceiverMaps` function deals directly with `JSSharedArray`, which has a direct JavaScript counterpart. Promise and async function-related objects are also directly tied to JavaScript features.
    * **JavaScript Examples:**  For each relevant function, come up with simple JavaScript code that would rely on the objects being created. For example, creating an object relies on the creation of object maps, creating an array relies on array maps, and using `SharedArrayBuffer` relates to the `js_shared_array_map`.
    * **Code Logic Reasoning (Hypothetical Input/Output):**  The `StaticRootsEnsureAllocatedSize` function offers the clearest opportunity for this. Assume an object and a required size, then explain how it pads the object.
    * **Common Programming Errors:** Consider errors that might relate to the initialized objects. Trying to modify read-only objects or incorrectly using `SharedArrayBuffer` are good examples.

4. **Synthesize and Structure the Response:**  Organize the findings logically:
    * Start with a general overview of the file's purpose.
    * Address the `.tq` extension question.
    * Explain the JavaScript relationship with relevant examples.
    * Provide the hypothetical input/output for `StaticRootsEnsureAllocatedSize`.
    * Give examples of common programming errors.
    * Finally, provide a concise summary of the file's overall function, as requested in "part 2 of 3."

5. **Refine and Review:**  Check for clarity, accuracy, and completeness. Ensure the JavaScript examples are correct and illustrative. Make sure the language is precise and avoids jargon where possible, or explains it when necessary. For the "part 2 of 3" summary, ensure it accurately reflects the content covered in the provided snippet.

**Self-Correction/Refinement During Thought Process:**

* Initially, I might have focused too much on the low-level details of memory allocation. I realized it's more important to explain the *purpose* of the allocated objects and their connection to JavaScript.
* I considered providing more technical details about maps and object layouts but decided to keep the JavaScript examples and explanations high-level for better understanding.
* I made sure to clearly distinguish between read-only and mutable objects in the explanation, as this is a key aspect of the code.
* I double-checked the constraints about `.tq` and the structure of the response to ensure I was addressing all parts of the request.
好的，根据您提供的代码片段，我们来归纳一下 `v8/src/heap/setup-heap-internal.cc` 的这一部分的功能。

**功能归纳（基于提供的代码片段）：**

这段代码的主要功能是 **创建和初始化 V8 堆中各种类型的对象 Map（用于描述对象的结构和属性）以及一些重要的只读对象**。  具体来说，它负责以下几个方面：

1. **创建对象 Map:**
   - 为多种内置对象类型创建 Map，这些 Map 定义了这些对象的布局、大小和属性。
   - 特别关注了 WebAssembly (Wasm) 相关的对象类型的 Map 的创建（通过 `IF_WASM` 宏）。
   - 创建了用于支持解释器（`InterpreterData`）和共享函数信息包装器（`SharedFunctionInfoWrapper`）的 Map。
   - 创建了用于弱引用（`WeakCell`）和字典模板信息（`DictionaryTemplateInfo`）的 Map。
   - 创建了稍后才需要的、常驻共享空间的 JavaScript 对象 Map，例如 `JSSharedArray`, `JSAtomicsMutex`, 和 `JSAtomicsCondition` 的 Map。这些 Map 通常用于性能优化，且是只读的。

2. **确保静态根对象的大小:**
   - `StaticRootsEnsureAllocatedSize` 函数确保某些静态的根对象在不同编译目标上具有一致的布局和大小，通过填充使其达到预期的尺寸。这对于保证 V8 的跨平台兼容性和稳定性非常重要。

3. **创建重要的只读对象:**
   - 初始化用于字符串哈希的种子 (`hash_seed`)。
   - 创建并存储一些重要的常量字符串和符号 (symbols)，这些字符串和符号在 V8 内部被频繁使用。
   - 创建并存储空的数据结构，例如空的属性字典 (`empty_property_dictionary`)、有序属性字典 (`empty_ordered_property_dictionary`)、字节数组 (`empty_byte_array`)、作用域信息 (`empty_scope_info`) 和属性数组 (`empty_property_array`)。
   - 创建并存储特殊的数值，例如负零 (`minus_zero_value`)、NaN (`nan_value`, `hole_nan_value`)、正负无穷 (`infinity_value`, `minus_infinity_value`)、最大安全整数 (`max_safe_integer`)、最大无符号 32 位整数 (`max_uint_32`) 以及 Smi 的最小值和最大值加一 (`smi_min_value`, `smi_max_value_plus_one`)。

4. **创建其他的只读对象:**
   - 创建空的 `ArrayList`, `ObjectBoilerplateDescription`, `ArrayBoilerplateDescription`, `ClosureFeedbackCellArray`。
   - 创建空的 `SwissNameDictionary`。
   - 初始化 BigInt 的 Map 的构造函数索引。
   - 创建并初始化单字符字符串表 (`single_character_string_table`)。
   - 创建并存储一些非重要的常量字符串。
   - 初始化特殊的“怪异值” (oddballs)，例如 `undefined`, `null`, `true`, `false`, 和 `the_hole`。
   - 初始化用于标记的特殊值，例如 `property_cell_hole_value`, `hash_table_hole_value`, 等等。
   - 创建并存储非重要的私有符号和公共符号。
   - 创建空的 `NumberDictionary`, `RegisteredSymbolTable`, `OrderedHashMap`, `OrderedHashSet`, `FeedbackMetadata`。
   - 创建规范的作用域数组，例如 `global_this_binding_scope_info`, `empty_function_scope_info`, `native_scope_info`, `shadow_realm_scope_info`。
   - 初始化 WebAssembly 的 `null_value` (如果启用了 WebAssembly)。

5. **创建可变的 API 对象:**
   - 创建用于存储消息监听器的 `ArrayList` (`message_listeners`)。

6. **创建只读的 API 对象:**
   - 创建无操作的拦截器信息 (`noop_interceptor_info`)。

7. **创建初始的可变对象:**
   - 初始化一些初始状态，例如当前微任务 (`current_microtask`)。
   - 创建并存储空的符号表 (`public_symbol_table`, `api_symbol_table`, `api_private_symbol_table`)。
   - 创建数字到字符串的缓存 (`number_string_cache`)。
   - 初始化性能分析数据 (`basic_block_profiling_data`)。
   - 创建正则表达式缓存 (`string_split_cache`, `regexp_multiple_cache`, `regexp_match_global_atom_cache`)。
   - 创建用于内置函数的 `FeedbackCell` (`many_closures_cell`)。
   - 初始化断开连接的上下文列表 (`detached_contexts`)。
   - 初始化用于性能分析工具的反馈向量列表 (`feedback_vectors_for_profiling_tools`)，以及标记为手动优化的函数列表 (`functions_marked_for_manual_optimization`)。
   - 初始化 WebAssembly 相关的列表 (`shared_wasm_memories`, `js_to_wasm_wrappers`, `wasm_canonical_rtts`) 和状态 (`active_continuation`, `active_suspender`)。
   - 初始化脚本列表 (`script_list`)。
   - 创建空的固定数组 (`materialized_objects`)。
   - 初始化脚本 ID 和调试 ID 生成器。
   - 创建空脚本 (`empty_script`)。
   - 创建各种保护器 (protectors)，这些保护器用于优化和安全检查。
   - 初始化序列化对象和全局代理大小的列表。
   - 确保零字符串和一字符串的哈希值已被计算。
   - 初始化内置常量表 (`builtins_constants_table`)。
   - 清理描述符查找缓存和编译缓存。
   - 创建 `Error.stack` 访问器的函数模板。
   - 创建内部使用的 `SharedFunctionInfo` 对象，特别是用于异步函数、异步生成器、异步迭代器和 Promise 的回调函数。

**关于问题中的其他点：**

- **`.tq` 结尾：** 您是对的，如果文件以 `.tq` 结尾，它就是 V8 Torque 源代码。然而，`v8/src/heap/setup-heap-internal.cc` 是一个 `.cc` 文件，因此是 C++ 源代码。
- **与 JavaScript 功能的关系：** 这段代码与 JavaScript 的功能息息相关。它初始化了 V8 引擎运行 JavaScript 代码所需的核心数据结构和对象。例如：
    - **Maps:**  用于表示 JavaScript 对象。
    - **Strings 和 Symbols:**  用于 JavaScript 代码中的标识符和字符串字面量。
    - **Arrays:**  用于表示 JavaScript 数组。
    - **特殊值 (`undefined`, `null`, `true`, `false`)：**  JavaScript 语言中的基本值。
    - **Promises 和 Async 函数相关的对象：**  支持 JavaScript 的异步编程特性。

**JavaScript 示例说明:**

```javascript
// 依赖于对象 Map 的创建
const obj = {};

// 依赖于字符串和符号的创建
const str = "hello";
const sym = Symbol("mySymbol");

// 依赖于数组 Map 的创建
const arr = [1, 2, 3];

// 依赖于特殊值的创建
console.log(undefined);
console.log(null);

// 依赖于 Promise 相关的 SharedFunctionInfo 的创建
const promise = new Promise((resolve, reject) => {
  setTimeout(resolve, 100);
});

async function myFunction() {
  await promise;
  return "done";
}
```

**代码逻辑推理（假设输入与输出）：**

**函数：`StaticRootsEnsureAllocatedSize(DirectHandle<HeapObject> obj, int required)`**

**假设输入：**
- `obj`: 一个指向堆上某个只读对象的句柄，假设该对象当前大小为 16 字节。
- `required`:  整数值 32，表示该对象需要被填充到 32 字节。

**输出：**
- 该函数会检查 `obj` 的大小是否小于 `required`。
- 由于 16 < 32，它会在只读空间分配一个大小为 `32 - 16 = 16` 字节的填充对象 (filler object)。
- 这个填充对象会被放置在 `obj` 的后面，紧挨着 `obj` 的内存区域。
- 最终，`obj` 及其后面的填充对象共同占据 32 字节的内存空间。

**常见编程错误（与此代码功能相关的）：**

- **尝试修改只读对象：**  这段代码创建了很多只读对象。如果在 JavaScript 代码中或 V8 内部尝试修改这些只读对象（例如，修改只读 Map 的属性），会导致错误或未定义的行为。V8 的内存保护机制会阻止这种修改。

  ```javascript
  // 假设 'undefined' 在 V8 内部对应一个只读对象
  try {
    undefined.myProperty = 10; // 严格模式下会抛出 TypeError
  } catch (e) {
    console.error(e);
  }
  ```

- **不当使用 `SharedArrayBuffer`：**  `CreateLateReadOnlyJSReceiverMaps` 中创建了 `JSSharedArray` 的 Map，这与 JavaScript 的 `SharedArrayBuffer` 相关。 如果在多线程环境中使用 `SharedArrayBuffer` 时没有正确地进行同步操作，可能会导致数据竞争和不可预测的结果。

**总结（第 2 部分）：**

总而言之，`v8/src/heap/setup-heap-internal.cc` 的这一部分主要负责 **在 V8 堆的初始化阶段，构建和配置构成 JavaScript 运行时环境基础的各种元数据结构（主要是对象 Map）以及关键的只读对象**。 这些对象为 V8 引擎执行 JavaScript 代码提供了必要的类型信息、常量值和初始状态。 这部分代码是 V8 引擎启动和正常运行的基石。

Prompt: 
```
这是目录为v8/src/heap/setup-heap-internal.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/setup-heap-internal.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
DER_OBJECT_TYPE,
            WasmSuspenderObject::kSize, wasm_suspender_object)
    IF_WASM(ALLOCATE_MAP, WASM_TYPE_INFO_TYPE, kVariableSizeSentinel,
            wasm_type_info)
    IF_WASM(ALLOCATE_MAP, WASM_CONTINUATION_OBJECT_TYPE,
            WasmContinuationObject::kSize, wasm_continuation_object)
    IF_WASM(ALLOCATE_MAP, WASM_NULL_TYPE, kVariableSizeSentinel, wasm_null);
    IF_WASM(ALLOCATE_MAP, WASM_TRUSTED_INSTANCE_DATA_TYPE,
            WasmTrustedInstanceData::kSize, wasm_trusted_instance_data);
    IF_WASM(ALLOCATE_VARSIZE_MAP, WASM_DISPATCH_TABLE_TYPE,
            wasm_dispatch_table);

    ALLOCATE_MAP(WEAK_CELL_TYPE, WeakCell::kSize, weak_cell)
    ALLOCATE_MAP(INTERPRETER_DATA_TYPE, InterpreterData::kSize,
                 interpreter_data)
    ALLOCATE_MAP(SHARED_FUNCTION_INFO_WRAPPER_TYPE,
                 SharedFunctionInfoWrapper::kSize, shared_function_info_wrapper)

    ALLOCATE_MAP(DICTIONARY_TEMPLATE_INFO_TYPE, DictionaryTemplateInfo::kSize,
                 dictionary_template_info)
  }

  return true;
}

bool Heap::CreateLateReadOnlyJSReceiverMaps() {
#define ALLOCATE_ALWAYS_SHARED_SPACE_JSOBJECT_MAP(instance_type, size, \
                                                  field_name)          \
  {                                                                    \
    Tagged<Map> map;                                                   \
    if (!AllocateMap(AllocationType::kReadOnly, (instance_type), size, \
                     DICTIONARY_ELEMENTS)                              \
             .To(&map)) {                                              \
      return false;                                                    \
    }                                                                  \
    AlwaysSharedSpaceJSObject::PrepareMapNoEnumerableProperties(map);  \
    set_##field_name##_map(map);                                       \
  }

  HandleScope late_jsreceiver_maps_handle_scope(isolate());
  Factory* factory = isolate()->factory();
  ReadOnlyRoots roots(this);

  // Shared space object maps are immutable and can be in RO space.
  {
    Tagged<Map> shared_array_map;
    if (!AllocateMap(AllocationType::kReadOnly, JS_SHARED_ARRAY_TYPE,
                     JSSharedArray::kSize, SHARED_ARRAY_ELEMENTS,
                     JSSharedArray::kInObjectFieldCount)
             .To(&shared_array_map)) {
      return false;
    }
    AlwaysSharedSpaceJSObject::PrepareMapNoEnumerableProperties(
        shared_array_map);
    DirectHandle<DescriptorArray> descriptors =
        factory->NewDescriptorArray(1, 0, AllocationType::kReadOnly);
    Descriptor length_descriptor = Descriptor::DataField(
        factory->length_string(), JSSharedArray::kLengthFieldIndex,
        ALL_ATTRIBUTES_MASK, PropertyConstness::kConst, Representation::Smi(),
        MaybeObjectHandle(FieldType::Any(isolate())));
    descriptors->Set(InternalIndex(0), &length_descriptor);
    shared_array_map->InitializeDescriptors(isolate(), *descriptors);
    set_js_shared_array_map(shared_array_map);
  }

  ALLOCATE_ALWAYS_SHARED_SPACE_JSOBJECT_MAP(
      JS_ATOMICS_MUTEX_TYPE, JSAtomicsMutex::kHeaderSize, js_atomics_mutex)
  ALLOCATE_ALWAYS_SHARED_SPACE_JSOBJECT_MAP(JS_ATOMICS_CONDITION_TYPE,
                                            JSAtomicsCondition::kHeaderSize,
                                            js_atomics_condition)

#undef ALLOCATE_ALWAYS_SHARED_SPACE_JSOBJECT_MAP
#undef ALLOCATE_PRIMITIVE_MAP
#undef ALLOCATE_VARSIZE_MAP
#undef ALLOCATE_MAP

  return true;
}

// For static roots we need the r/o space to have identical layout on all
// compile targets. Varying objects are padded to their biggest size.
void Heap::StaticRootsEnsureAllocatedSize(DirectHandle<HeapObject> obj,
                                          int required) {
  if (V8_STATIC_ROOTS_BOOL || V8_STATIC_ROOTS_GENERATION_BOOL) {
    int obj_size = obj->Size();
    if (required == obj_size) return;
    CHECK_LT(obj_size, required);
    int filler_size = required - obj_size;

    Tagged<HeapObject> filler =
        allocator()->AllocateRawWith<HeapAllocator::kRetryOrFail>(
            filler_size, AllocationType::kReadOnly, AllocationOrigin::kRuntime,
            AllocationAlignment::kTaggedAligned);
    CreateFillerObjectAt(filler.address(), filler_size,
                         ClearFreedMemoryMode::kClearFreedMemory);

    CHECK_EQ(filler.address(), obj->address() + obj_size);
    CHECK_EQ(filler.address() + filler->Size(), obj->address() + required);
  }
}

bool Heap::CreateImportantReadOnlyObjects() {
  // Allocate some objects early to get addresses to fit as arm64 immediates.
  Tagged<HeapObject> obj;
  ReadOnlyRoots roots(isolate());
  HandleScope initial_objects_handle_scope(isolate());

  // Hash seed for strings

  Factory* factory = isolate()->factory();
  set_hash_seed(*factory->NewByteArray(kInt64Size, AllocationType::kReadOnly));
  InitializeHashSeed();

  // Important strings and symbols
  for (const ConstantStringInit& entry : kImportantConstantStringTable) {
    if (entry.index == RootIndex::kempty_string) {
      // Special case the empty string, since it's allocated and initialised in
      // the initial section.
      isolate()->string_table()->InsertEmptyStringForBootstrapping(isolate());
    } else {
      DirectHandle<String> str = factory->InternalizeUtf8String(entry.contents);
      roots_table()[entry.index] = str->ptr();
    }
  }

  {
#define SYMBOL_INIT(_, name)                                                \
  {                                                                         \
    DirectHandle<Symbol> symbol(                                            \
        isolate()->factory()->NewPrivateSymbol(AllocationType::kReadOnly)); \
    roots_table()[RootIndex::k##name] = symbol->ptr();                      \
  }
      IMPORTANT_PRIVATE_SYMBOL_LIST_GENERATOR(SYMBOL_INIT, /* not used */)}
  // SYMBOL_INIT used again later.

  // Empty elements
  DirectHandle<NameDictionary>
      empty_property_dictionary = NameDictionary::New(
          isolate(), 1, AllocationType::kReadOnly, USE_CUSTOM_MINIMUM_CAPACITY);
  DCHECK(!empty_property_dictionary->HasSufficientCapacityToAdd(1));

  set_empty_property_dictionary(*empty_property_dictionary);

  // Allocate the empty OrderedNameDictionary
  DirectHandle<OrderedNameDictionary> empty_ordered_property_dictionary =
      OrderedNameDictionary::AllocateEmpty(isolate(), AllocationType::kReadOnly)
          .ToHandleChecked();
  set_empty_ordered_property_dictionary(*empty_ordered_property_dictionary);

  {
    if (!AllocateRaw(ByteArray::SizeFor(0), AllocationType::kReadOnly)
             .To(&obj)) {
      return false;
    }
    obj->set_map_after_allocation(isolate(), roots.byte_array_map(),
                                  SKIP_WRITE_BARRIER);
    Cast<ByteArray>(obj)->set_length(0);
    set_empty_byte_array(Cast<ByteArray>(obj));
  }

  {
    AllocationResult alloc =
        AllocateRaw(ScopeInfo::SizeFor(ScopeInfo::kVariablePartIndex),
                    AllocationType::kReadOnly);
    if (!alloc.To(&obj)) return false;
    obj->set_map_after_allocation(isolate(), roots.scope_info_map(),
                                  SKIP_WRITE_BARRIER);
    int flags = ScopeInfo::IsEmptyBit::encode(true);
    DCHECK_EQ(ScopeInfo::LanguageModeBit::decode(flags), LanguageMode::kSloppy);
    DCHECK_EQ(ScopeInfo::ReceiverVariableBits::decode(flags),
              VariableAllocationInfo::NONE);
    DCHECK_EQ(ScopeInfo::FunctionVariableBits::decode(flags),
              VariableAllocationInfo::NONE);
    Cast<ScopeInfo>(obj)->set_flags(flags, kRelaxedStore);
    Cast<ScopeInfo>(obj)->set_context_local_count(0);
    Cast<ScopeInfo>(obj)->set_parameter_count(0);
    Cast<ScopeInfo>(obj)->set_position_info_start(0);
    Cast<ScopeInfo>(obj)->set_position_info_end(0);
  }
  set_empty_scope_info(Cast<ScopeInfo>(obj));

  {
    if (!AllocateRaw(FixedArray::SizeFor(0), AllocationType::kReadOnly)
             .To(&obj)) {
      return false;
    }
    obj->set_map_after_allocation(isolate(), roots.property_array_map(),
                                  SKIP_WRITE_BARRIER);
    Cast<PropertyArray>(obj)->initialize_length(0);
    set_empty_property_array(Cast<PropertyArray>(obj));
  }

  // Heap Numbers
  // The -0 value must be set before NewNumber works.
  set_minus_zero_value(
      *factory->NewHeapNumber<AllocationType::kReadOnly>(-0.0));
  DCHECK(std::signbit(Object::NumberValue(roots.minus_zero_value())));

  set_nan_value(*factory->NewHeapNumber<AllocationType::kReadOnly>(
      std::numeric_limits<double>::quiet_NaN()));
  set_hole_nan_value(*factory->NewHeapNumberFromBits<AllocationType::kReadOnly>(
      kHoleNanInt64));
  set_infinity_value(
      *factory->NewHeapNumber<AllocationType::kReadOnly>(V8_INFINITY));
  set_minus_infinity_value(
      *factory->NewHeapNumber<AllocationType::kReadOnly>(-V8_INFINITY));
  set_max_safe_integer(
      *factory->NewHeapNumber<AllocationType::kReadOnly>(kMaxSafeInteger));
  set_max_uint_32(
      *factory->NewHeapNumber<AllocationType::kReadOnly>(kMaxUInt32));
  set_smi_min_value(
      *factory->NewHeapNumber<AllocationType::kReadOnly>(kSmiMinValue));
  set_smi_max_value_plus_one(
      *factory->NewHeapNumber<AllocationType::kReadOnly>(0.0 - kSmiMinValue));

  return true;
}

bool Heap::CreateReadOnlyObjects() {
  HandleScope initial_objects_handle_scope(isolate());
  Factory* factory = isolate()->factory();
  ReadOnlyRoots roots(this);
  Tagged<HeapObject> obj;

  {
    AllocationResult alloc =
        AllocateRaw(ArrayList::SizeFor(0), AllocationType::kReadOnly);
    if (!alloc.To(&obj)) return false;
    obj->set_map_after_allocation(isolate(), roots.array_list_map(),
                                  SKIP_WRITE_BARRIER);
    // Unchecked to skip failing checks since required roots are uninitialized.
    UncheckedCast<ArrayList>(obj)->set_capacity(0);
    UncheckedCast<ArrayList>(obj)->set_length(0);
  }
  set_empty_array_list(UncheckedCast<ArrayList>(obj));

  {
    AllocationResult alloc = AllocateRaw(
        ObjectBoilerplateDescription::SizeFor(0), AllocationType::kReadOnly);
    if (!alloc.To(&obj)) return false;
    obj->set_map_after_allocation(isolate(),
                                  roots.object_boilerplate_description_map(),
                                  SKIP_WRITE_BARRIER);

    Cast<ObjectBoilerplateDescription>(obj)->set_capacity(0);
    Cast<ObjectBoilerplateDescription>(obj)->set_backing_store_size(0);
    Cast<ObjectBoilerplateDescription>(obj)->set_flags(0);
  }
  set_empty_object_boilerplate_description(
      Cast<ObjectBoilerplateDescription>(obj));

  {
    // Empty array boilerplate description
    AllocationResult alloc =
        Allocate(roots.array_boilerplate_description_map_handle(),
                 AllocationType::kReadOnly);
    if (!alloc.To(&obj)) return false;

    Cast<ArrayBoilerplateDescription>(obj)->set_constant_elements(
        roots.empty_fixed_array());
    Cast<ArrayBoilerplateDescription>(obj)->set_elements_kind(
        ElementsKind::PACKED_SMI_ELEMENTS);
  }
  set_empty_array_boilerplate_description(
      Cast<ArrayBoilerplateDescription>(obj));

  // Empty arrays.
  {
    if (!AllocateRaw(ClosureFeedbackCellArray::SizeFor(0),
                     AllocationType::kReadOnly)
             .To(&obj)) {
      return false;
    }
    obj->set_map_after_allocation(
        isolate(), roots.closure_feedback_cell_array_map(), SKIP_WRITE_BARRIER);
    Cast<ClosureFeedbackCellArray>(obj)->set_length(0);
    set_empty_closure_feedback_cell_array(Cast<ClosureFeedbackCellArray>(obj));
  }

  DCHECK(!HeapLayout::InYoungGeneration(roots.empty_fixed_array()));

  // Allocate the empty SwissNameDictionary
  DirectHandle<SwissNameDictionary> empty_swiss_property_dictionary =
      factory->CreateCanonicalEmptySwissNameDictionary();
  set_empty_swiss_property_dictionary(*empty_swiss_property_dictionary);
  StaticRootsEnsureAllocatedSize(empty_swiss_property_dictionary,
                                 8 * kTaggedSize);

  roots.bigint_map()->SetConstructorFunctionIndex(
      Context::BIGINT_FUNCTION_INDEX);

  // Allocate and initialize table for single character one byte strings.
  int table_size = String::kMaxOneByteCharCode + 1;
  set_single_character_string_table(
      *factory->NewFixedArray(table_size, AllocationType::kReadOnly));
  for (int i = 0; i < table_size; ++i) {
    uint8_t code = static_cast<uint8_t>(i);
    DirectHandle<String> str =
        factory->InternalizeString(base::Vector<const uint8_t>(&code, 1));
    DCHECK(ReadOnlyHeap::Contains(*str));
    single_character_string_table()->set(i, *str);
  }

  for (const ConstantStringInit& entry : kNotImportantConstantStringTable) {
    DirectHandle<String> str = factory->InternalizeUtf8String(entry.contents);
    roots_table()[entry.index] = str->ptr();
  }

  // Finish initializing oddballs after creating the string table.
  Oddball::Initialize(isolate(), factory->undefined_value(), "undefined",
                      factory->nan_value(), "undefined", Oddball::kUndefined);

  // Initialize the null_value.
  Oddball::Initialize(isolate(), factory->null_value(), "null",
                      handle(Smi::zero(), isolate()), "object", Oddball::kNull);

  // Initialize the true_value.
  Oddball::Initialize(isolate(), factory->true_value(), "true",
                      handle(Smi::FromInt(1), isolate()), "boolean",
                      Oddball::kTrue);

  // Initialize the false_value.
  Oddball::Initialize(isolate(), factory->false_value(), "false",
                      handle(Smi::zero(), isolate()), "boolean",
                      Oddball::kFalse);

  // Initialize the_hole_value.
  Hole::Initialize(isolate(), factory->the_hole_value(),
                   factory->hole_nan_value());

  set_property_cell_hole_value(*factory->NewHole());
  set_hash_table_hole_value(*factory->NewHole());
  set_promise_hole_value(*factory->NewHole());
  set_uninitialized_value(*factory->NewHole());
  set_arguments_marker(*factory->NewHole());
  set_termination_exception(*factory->NewHole());
  set_exception(*factory->NewHole());
  set_optimized_out(*factory->NewHole());
  set_stale_register(*factory->NewHole());

  // Initialize marker objects used during compilation.
  set_self_reference_marker(*factory->NewHole());
  set_basic_block_counters_marker(*factory->NewHole());

  {
    HandleScope handle_scope(isolate());
    NOT_IMPORTANT_PRIVATE_SYMBOL_LIST_GENERATOR(SYMBOL_INIT, /* not used */)
#undef SYMBOL_INIT
  }

  {
    HandleScope handle_scope(isolate());
#define PUBLIC_SYMBOL_INIT(_, name, description)                               \
  DirectHandle<Symbol> name = factory->NewSymbol(AllocationType::kReadOnly);   \
  DirectHandle<String> name##d = factory->InternalizeUtf8String(#description); \
  name->set_description(*name##d);                                             \
  roots_table()[RootIndex::k##name] = name->ptr();

    PUBLIC_SYMBOL_LIST_GENERATOR(PUBLIC_SYMBOL_INIT, /* not used */)

#define WELL_KNOWN_SYMBOL_INIT(_, name, description)                           \
  DirectHandle<Symbol> name = factory->NewSymbol(AllocationType::kReadOnly);   \
  DirectHandle<String> name##d = factory->InternalizeUtf8String(#description); \
  name->set_is_well_known_symbol(true);                                        \
  name->set_description(*name##d);                                             \
  roots_table()[RootIndex::k##name] = name->ptr();

    WELL_KNOWN_SYMBOL_LIST_GENERATOR(WELL_KNOWN_SYMBOL_INIT, /* not used */)

    // Mark "Interesting Symbols" appropriately.
    to_string_tag_symbol->set_is_interesting_symbol(true);
  }

  {
    // All Names that can cause protector invalidation have to be allocated
    // consecutively to allow for fast checks

    // Allocate the symbols's internal strings first, so we don't get
    // interleaved string allocations for the symbols later.
#define ALLOCATE_SYMBOL_STRING(_, name, description) \
  Handle<String> name##symbol_string =               \
      factory->InternalizeUtf8String(#description);  \
  USE(name##symbol_string);

    SYMBOL_FOR_PROTECTOR_LIST_GENERATOR(ALLOCATE_SYMBOL_STRING,
                                        /* not used */)
    PUBLIC_SYMBOL_FOR_PROTECTOR_LIST_GENERATOR(ALLOCATE_SYMBOL_STRING,
                                               /* not used */)
    WELL_KNOWN_SYMBOL_FOR_PROTECTOR_LIST_GENERATOR(ALLOCATE_SYMBOL_STRING,
                                                   /* not used */)
#undef ALLOCATE_SYMBOL_STRING

#define INTERNALIZED_STRING_INIT(_, name, description)                     \
  DirectHandle<String> name = factory->InternalizeUtf8String(description); \
  roots_table()[RootIndex::k##name] = name->ptr();

    INTERNALIZED_STRING_FOR_PROTECTOR_LIST_GENERATOR(INTERNALIZED_STRING_INIT,
                                                     /* not used */)
    SYMBOL_FOR_PROTECTOR_LIST_GENERATOR(PUBLIC_SYMBOL_INIT,
                                        /* not used */)
    PUBLIC_SYMBOL_FOR_PROTECTOR_LIST_GENERATOR(PUBLIC_SYMBOL_INIT,
                                               /* not used */)
    WELL_KNOWN_SYMBOL_FOR_PROTECTOR_LIST_GENERATOR(WELL_KNOWN_SYMBOL_INIT,
                                                   /* not used */)

    // Mark "Interesting Symbols" appropriately.
    to_primitive_symbol->set_is_interesting_symbol(true);

#ifdef DEBUG
    roots.VerifyNameForProtectors();
#endif
    roots.VerifyNameForProtectorsPages();

#undef INTERNALIZED_STRING_INIT
#undef PUBLIC_SYMBOL_INIT
#undef WELL_KNOWN_SYMBOL_INIT
  }

  DirectHandle<NumberDictionary> slow_element_dictionary =
      NumberDictionary::New(isolate(), 1, AllocationType::kReadOnly,
                            USE_CUSTOM_MINIMUM_CAPACITY);
  DCHECK(!slow_element_dictionary->HasSufficientCapacityToAdd(1));
  set_empty_slow_element_dictionary(*slow_element_dictionary);

  DirectHandle<RegisteredSymbolTable> empty_symbol_table =
      RegisteredSymbolTable::New(isolate(), 1, AllocationType::kReadOnly,
                                 USE_CUSTOM_MINIMUM_CAPACITY);
  DCHECK(!empty_symbol_table->HasSufficientCapacityToAdd(1));
  set_empty_symbol_table(*empty_symbol_table);

  // Allocate the empty OrderedHashMap.
  DirectHandle<OrderedHashMap> empty_ordered_hash_map =
      OrderedHashMap::AllocateEmpty(isolate(), AllocationType::kReadOnly)
          .ToHandleChecked();
  set_empty_ordered_hash_map(*empty_ordered_hash_map);

  // Allocate the empty OrderedHashSet.
  DirectHandle<OrderedHashSet> empty_ordered_hash_set =
      OrderedHashSet::AllocateEmpty(isolate(), AllocationType::kReadOnly)
          .ToHandleChecked();
  set_empty_ordered_hash_set(*empty_ordered_hash_set);

  // Allocate the empty FeedbackMetadata.
  DirectHandle<FeedbackMetadata> empty_feedback_metadata =
      factory->NewFeedbackMetadata(0, 0, AllocationType::kReadOnly);
  set_empty_feedback_metadata(*empty_feedback_metadata);

  // Canonical scope arrays.
  DirectHandle<ScopeInfo> global_this_binding =
      ScopeInfo::CreateGlobalThisBinding(isolate());
  set_global_this_binding_scope_info(*global_this_binding);

  DirectHandle<ScopeInfo> empty_function =
      ScopeInfo::CreateForEmptyFunction(isolate());
  set_empty_function_scope_info(*empty_function);

  DirectHandle<ScopeInfo> native_scope_info =
      ScopeInfo::CreateForNativeContext(isolate());
  set_native_scope_info(*native_scope_info);

  DirectHandle<ScopeInfo> shadow_realm_scope_info =
      ScopeInfo::CreateForShadowRealmNativeContext(isolate());
  set_shadow_realm_scope_info(*shadow_realm_scope_info);

  // Initialize the wasm null_value.

#ifdef V8_ENABLE_WEBASSEMBLY
  // Allocate the wasm-null object. It is a regular V8 heap object contained in
  // a V8 page.
  // In static-roots builds, it is large enough so that its payload (other than
  // its map word) can be mprotected on OS page granularity. We adjust the
  // layout such that we have a filler object in the current OS page, and the
  // wasm-null map word at the end of the current OS page. The payload then is
  // contained on a separate OS page which can be protected.
  // In non-static-roots builds, it is a regular object of size {kTaggedSize}
  // and does not need padding.

  constexpr size_t kLargestPossibleOSPageSize = 64 * KB;
  static_assert(kLargestPossibleOSPageSize >= kMinimumOSPageSize);

  if (V8_STATIC_ROOTS_BOOL || V8_STATIC_ROOTS_GENERATION_BOOL) {
    // Ensure all of the following lands on the same V8 page.
    constexpr int kOffsetAfterMapWord = HeapObject::kMapOffset + kTaggedSize;
    static_assert(kOffsetAfterMapWord % kObjectAlignment == 0);
    read_only_space_->EnsureSpaceForAllocation(
        kLargestPossibleOSPageSize + WasmNull::kSize - kOffsetAfterMapWord);
    Address next_page = RoundUp(read_only_space_->top() + kOffsetAfterMapWord,
                                kLargestPossibleOSPageSize);

    // Add some filler to end up right before an OS page boundary.
    int filler_size = static_cast<int>(next_page - read_only_space_->top() -
                                       kOffsetAfterMapWord);
    // TODO(v8:7748) Depending on where we end up this might actually not hold,
    // in which case we would need to use a one or two-word filler.
    CHECK(filler_size > 2 * kTaggedSize);
    Tagged<HeapObject> filler =
        allocator()->AllocateRawWith<HeapAllocator::kRetryOrFail>(
            filler_size, AllocationType::kReadOnly, AllocationOrigin::kRuntime,
            AllocationAlignment::kTaggedAligned);
    CreateFillerObjectAt(filler.address(), filler_size,
                         ClearFreedMemoryMode::kClearFreedMemory);
    set_wasm_null_padding(filler);
    CHECK_EQ(read_only_space_->top() + kOffsetAfterMapWord, next_page);
  } else {
    set_wasm_null_padding(roots.undefined_value());
  }

  // Finally, allocate the wasm-null object.
  {
    Tagged<HeapObject> obj;
    CHECK(AllocateRaw(WasmNull::kSize, AllocationType::kReadOnly).To(&obj));
    // No need to initialize the payload since it's either empty or unmapped.
    CHECK_IMPLIES(!(V8_STATIC_ROOTS_BOOL || V8_STATIC_ROOTS_GENERATION_BOOL),
                  WasmNull::kSize == sizeof(Tagged_t));
    obj->set_map_after_allocation(isolate(), roots.wasm_null_map(),
                                  SKIP_WRITE_BARRIER);
    set_wasm_null(Cast<WasmNull>(obj));
    if (V8_STATIC_ROOTS_BOOL || V8_STATIC_ROOTS_GENERATION_BOOL) {
      CHECK_EQ(read_only_space_->top() % kLargestPossibleOSPageSize, 0);
    }
  }
#endif

  return true;
}

void Heap::CreateMutableApiObjects() {
  HandleScope scope(isolate());
  set_message_listeners(*ArrayList::New(isolate(), 2, AllocationType::kOld));
}

void Heap::CreateReadOnlyApiObjects() {
  HandleScope scope(isolate());
  auto info = Cast<InterceptorInfo>(isolate()->factory()->NewStruct(
      INTERCEPTOR_INFO_TYPE, AllocationType::kReadOnly));
  info->set_flags(0);
  set_noop_interceptor_info(*info);
}

void Heap::CreateInitialMutableObjects() {
  HandleScope initial_objects_handle_scope(isolate());
  Factory* factory = isolate()->factory();
  ReadOnlyRoots roots(this);

  // There's no "current microtask" in the beginning.
  set_current_microtask(roots.undefined_value());

  set_weak_refs_keep_during_job(roots.undefined_value());

  set_public_symbol_table(roots.empty_symbol_table());
  set_api_symbol_table(roots.empty_symbol_table());
  set_api_private_symbol_table(roots.empty_symbol_table());

  set_number_string_cache(*factory->NewFixedArray(
      kInitialNumberStringCacheSize * 2, AllocationType::kOld));

  // Unchecked to skip failing checks since required roots are uninitialized.
  set_basic_block_profiling_data(roots.unchecked_empty_array_list());

  // Allocate regexp caches.
  set_string_split_cache(*factory->NewFixedArray(
      RegExpResultsCache::kRegExpResultsCacheSize, AllocationType::kOld));
  set_regexp_multiple_cache(*factory->NewFixedArray(
      RegExpResultsCache::kRegExpResultsCacheSize, AllocationType::kOld));
  set_regexp_match_global_atom_cache(*factory->NewFixedArray(
      RegExpResultsCache_MatchGlobalAtom::kSize, AllocationType::kOld));

  // Allocate FeedbackCell for builtins.
  DirectHandle<FeedbackCell> many_closures_cell =
      factory->NewManyClosuresCell();
  set_many_closures_cell(*many_closures_cell);

  set_detached_contexts(roots.empty_weak_array_list());

  set_feedback_vectors_for_profiling_tools(roots.undefined_value());
  set_functions_marked_for_manual_optimization(roots.undefined_value());
  set_shared_wasm_memories(roots.empty_weak_array_list());
  set_locals_block_list_cache(roots.undefined_value());
#ifdef V8_ENABLE_WEBASSEMBLY
  set_active_continuation(roots.undefined_value());
  set_active_suspender(roots.undefined_value());
  set_js_to_wasm_wrappers(roots.empty_weak_fixed_array());
  set_wasm_canonical_rtts(roots.empty_weak_fixed_array());
#endif  // V8_ENABLE_WEBASSEMBLY

  set_script_list(roots.empty_weak_array_list());

  set_materialized_objects(*factory->NewFixedArray(0, AllocationType::kOld));

  // Handling of script id generation is in Heap::NextScriptId().
  set_last_script_id(Smi::FromInt(v8::UnboundScript::kNoScriptId));
  set_last_debugging_id(Smi::FromInt(DebugInfo::kNoDebuggingId));
  set_last_stack_trace_id(Smi::zero());
  set_next_template_serial_number(Smi::zero());

  // Allocate the empty script.
  DirectHandle<Script> script = factory->NewScript(factory->empty_string());
  script->set_type(Script::Type::kNative);
  // This is used for exceptions thrown with no stack frames. Such exceptions
  // can be shared everywhere.
  script->set_origin_options(ScriptOriginOptions(true, false));
  set_empty_script(*script);

  // Protectors
  set_array_buffer_detaching_protector(*factory->NewProtector());
  set_array_constructor_protector(*factory->NewProtector());
  set_array_iterator_protector(*factory->NewProtector());
  set_array_species_protector(*factory->NewProtector());
  set_is_concat_spreadable_protector(*factory->NewProtector());
  set_map_iterator_protector(*factory->NewProtector());
  set_no_elements_protector(*factory->NewProtector());
  set_mega_dom_protector(*factory->NewProtector());
  set_no_profiling_protector(*factory->NewProtector());
  set_no_undetectable_objects_protector(*factory->NewProtector());
  set_promise_hook_protector(*factory->NewProtector());
  set_promise_resolve_protector(*factory->NewProtector());
  set_promise_species_protector(*factory->NewProtector());
  set_promise_then_protector(*factory->NewProtector());
  set_regexp_species_protector(*factory->NewProtector());
  set_set_iterator_protector(*factory->NewProtector());
  set_string_iterator_protector(*factory->NewProtector());
  set_string_length_protector(*factory->NewProtector());
  set_string_wrapper_to_primitive_protector(*factory->NewProtector());
  set_number_string_not_regexp_like_protector(*factory->NewProtector());
  set_typed_array_species_protector(*factory->NewProtector());

  set_serialized_objects(roots.empty_fixed_array());
  set_serialized_global_proxy_sizes(roots.empty_fixed_array());

  // Evaluate the hash values which will then be cached in the strings.
  isolate()->factory()->zero_string()->EnsureHash();
  isolate()->factory()->one_string()->EnsureHash();

  // Initialize builtins constants table.
  set_builtins_constants_table(roots.empty_fixed_array());

  // Initialize descriptor cache.
  isolate_->descriptor_lookup_cache()->Clear();

  // Initialize compilation cache.
  isolate_->compilation_cache()->Clear();

  // Error.stack accessor callbacks:
  {
    DirectHandle<FunctionTemplateInfo> function_template;
    function_template = ApiNatives::CreateAccessorFunctionTemplateInfo(
        isolate_, Accessors::ErrorStackGetter, 0,
        SideEffectType::kHasSideEffect);
    set_error_stack_getter_fun_template(*function_template);

    function_template = ApiNatives::CreateAccessorFunctionTemplateInfo(
        isolate_, Accessors::ErrorStackSetter, 1,
        SideEffectType::kHasSideEffectToReceiver);
    set_error_stack_setter_fun_template(*function_template);
  }

  // Create internal SharedFunctionInfos.
  // Async functions:
  {
    DirectHandle<SharedFunctionInfo> info = CreateSharedFunctionInfo(
        isolate(), Builtin::kAsyncFunctionAwaitRejectClosure, 1);
    set_async_function_await_reject_closure_shared_fun(*info);

    info = CreateSharedFunctionInfo(
        isolate(), Builtin::kAsyncFunctionAwaitResolveClosure, 1);
    set_async_function_await_resolve_closure_shared_fun(*info);
  }

  // Async generators:
  {
    DirectHandle<SharedFunctionInfo> info = CreateSharedFunctionInfo(
        isolate(), Builtin::kAsyncGeneratorAwaitResolveClosure, 1);
    set_async_generator_await_resolve_closure_shared_fun(*info);

    info = CreateSharedFunctionInfo(
        isolate(), Builtin::kAsyncGeneratorAwaitRejectClosure, 1);
    set_async_generator_await_reject_closure_shared_fun(*info);

    info = CreateSharedFunctionInfo(
        isolate(), Builtin::kAsyncGeneratorYieldWithAwaitResolveClosure, 1);
    set_async_generator_yield_with_await_resolve_closure_shared_fun(*info);

    info = CreateSharedFunctionInfo(
        isolate(), Builtin::kAsyncGeneratorReturnResolveClosure, 1);
    set_async_generator_return_resolve_closure_shared_fun(*info);

    info = CreateSharedFunctionInfo(
        isolate(), Builtin::kAsyncGeneratorReturnClosedResolveClosure, 1);
    set_async_generator_return_closed_resolve_closure_shared_fun(*info);

    info = CreateSharedFunctionInfo(
        isolate(), Builtin::kAsyncGeneratorReturnClosedRejectClosure, 1);
    set_async_generator_return_closed_reject_closure_shared_fun(*info);
  }

  // AsyncIterator:
  {
    DirectHandle<SharedFunctionInfo> info = CreateSharedFunctionInfo(
        isolate_, Builtin::kAsyncIteratorValueUnwrap, 1);
    set_async_iterator_value_unwrap_shared_fun(*info);

    info = CreateSharedFunctionInfo(
        isolate_, Builtin::kAsyncIteratorPrototypeAsyncDisposeResolveClosure,
        1);
    set_async_iterator_prototype_async_dispose_resolve_closure_shared_fun(
        *info);
  }

  // AsyncFromSyncIterator:
  {
    DirectHandle<SharedFunctionInfo> info = CreateSharedFunctionInfo(
        isolate_, Builtin::kAsyncFromSyncIteratorCloseSyncAndRethrow, 1);
    set_async_from_sync_iterator_close_sync_and_rethrow_shared_fun(*info);
  }

  // Promises:
  {
    DirectHandle<SharedFunctionInfo> info = CreateSharedFunctionInfo(
        isolate_, Builtin::kPromiseCapabilityDefaultResolve, 1,
        FunctionKind::kConciseMethod);
    info->set_native(true);
    info->set_function_map_index(
        Context::STRICT_FUNCTION_WITHOUT_PROTOTYPE_MAP_INDEX);
    set_promise_capability_default_resolve_shared_fun(*info);

    info = CreateSharedFunctionInfo(isolate_,
                                    Builtin::kPromiseCapabilityDefaultReject, 1,
                                    FunctionKind::kConciseMethod);
    info->set_native(true);
    info->set_function_map_index(
        Context::STRICT_FUNCTION_WITHOUT_PROTOTYPE_MAP_INDEX);
    set_promise_capability_default_reject_shared_fun(*info);

    info = CreateSharedFunctionInfo(
        isolate_, Builtin::kPromiseGetCapabilitiesExecutor, 2);
    set_promise_get_capabilities_executor_shared_fun(*info);
  }

  // Promises / finally:
  {
    DirectHandle<SharedFunctionInfo> info =
        CreateSharedFunctionInfo(isolate(), Builtin::kPromiseThenFinally, 1);
    info->set_native(true);
    set_promise_then_finally_shared_fun(*info);

    info =
        CreateSharedFunctionInfo(isolate(), Builtin::kPromiseCatchFinally, 1);
    info->set_native(true);
    set_promise_catch_finally_shared_fun(*info);

    info = CreateSharedFunctionInfo(isolate(),
                                    Builtin::kPromiseValueThunkFinally, 0);
    set_promise_value_thunk_finally_shared_fun(*info);

    info =
        CreateSharedFunctionInfo(isolate(), Builtin::kPromiseThrowerFinally, 0);
    set_promise_thrower_finally_shared_fun(*info);
  }

  // Promise combinators:
  {
    DirectHandle<SharedFunctionInfo> info = CreateSharedFunctionInfo(
        isolate_, Builtin::kPromiseAllResolveElementClosure, 1);
    set_promise_all_resolve_element_closure_shared_fun(*info);

    info = CreateSharedFunctionInfo(
        isolate_, Builtin::kPromiseAllSettledResolveElementClosure, 1);
    set_promise_all_settled_resolve_element_closure_shared_fun(*info);

    info = CreateSharedFunctionInfo(
        isolate_, Builtin::kPromiseAllSettledRejectElementClosure, 1);
    set_promise_all_settled_reject_element_closure_shared_fun(*info);

    info = CreateSharedFunctionInfo(
        isolate_, Builtin::kPromiseAnyRejectElementClosure, 1);
    set_promise_any_reject_element_closure_sh
"""


```