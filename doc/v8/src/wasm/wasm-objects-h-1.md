Response:
The user wants a summary of the functionality described in the C++ header file `v8/src/wasm/wasm-objects.h`.

Here's a breakdown of the content and how to structure the summary:

1. **Overall Purpose:** The file defines C++ classes representing various WebAssembly objects within the V8 JavaScript engine. These objects are used to bridge the gap between JavaScript and WebAssembly.

2. **Key Categories of Objects:**  The defined classes can be grouped into functional categories:
    * **Code Management:** `WasmCodeObjects`, `WasmCodeWrappers`, `WasmDispatchTable`
    * **Function Representation:** `WasmExportedFunction`, `WasmJSFunction`, `WasmCapiFunction`, `WasmExternalFunction`, `WasmInternalFunction`, `WasmFuncRef`, `WasmFunctionData`, `WasmExportedFunctionData`, `WasmJSFunctionData`, `WasmCapiFunctionData`
    * **Instance Management:** `WasmInstanceObject`, `WasmTableObject`, `WasmMemoryObject`, `WasmGlobalObject`, `WasmExceptionTag`
    * **Exception Handling:** `WasmExceptionPackage`
    * **Debugging:** `WasmScript`
    * **Data Structures:** `WasmImportData`, `WasmTypeInfo`
    * **GC Integration:** `WasmNull`
    * **Continuation and Suspension:** `WasmContinuationObject`, `WasmSuspenderObject`, `WasmSuspendingObject`, `WasmResumeData`
    * **Heap Objects:** `WasmObject`, `WasmStruct`, `WasmArray`
    * **Special Data:** `AsmWasmData`

3. **Relationships to JavaScript:** Many of these objects have direct counterparts or are used in the implementation of WebAssembly features accessible from JavaScript.

4. **Torque Consideration:** The presence of `TorqueGenerated...` classes indicates the use of V8's Torque language for generating parts of the object definitions. If the file ended in `.tq`, it *would* be a Torque source file, but since it ends in `.h`, it's a regular C++ header that *uses* Torque.

5. **Code Logic and Assumptions:**  The code includes assertions and constants, providing insights into assumptions about sizes, alignment, and limits.

6. **Common Programming Errors:**  While the header doesn't directly *cause* user errors, understanding these objects is crucial for debugging WebAssembly interactions. Misunderstandings about memory management, function calls, and object representations could lead to errors.

7. **Structure of the Summary:** Organize the summary by the key categories of objects, explaining the purpose and functionality of each group and individual classes within those groups. Highlight the connections to JavaScript and any notable aspects like Torque usage.

**Plan:**

* Start with a high-level overview of the file's purpose.
* Address the `.tq` file name question.
* Go through each category of objects and summarize their roles.
* Provide JavaScript examples where relevant.
* Mention the presence of constants and assertions and their implications.
* Discuss the potential for user errors indirectly related to these objects.
这是对 `v8/src/wasm/wasm-objects.h` 文件中剩余部分的功能归纳：

**总体功能归纳：**

这部分 `wasm-objects.h` 文件主要定义了 V8 引擎中用于表示和管理 WebAssembly 实例内部各种数据和结构的 C++ 类。它涵盖了以下几个关键方面：

1. **间接调用表 (Dispatch Table):** `WasmDispatchTable` 类定义了用于处理 WebAssembly 间接函数调用的数据结构。它存储了函数指针、隐式参数和签名信息，允许在运行时根据索引查找并调用相应的函数。

2. **异常处理 (Exception Handling):**  `WasmExceptionPackage` 类表示从 WebAssembly 代码抛出的异常。它包含了异常标签和携带的值。同时提供了一些辅助函数用于编码和解码异常值。

3. **函数表示 (Function Representation):**
    * `WasmExportedFunction`: 表示从 WebAssembly 模块导出到 JavaScript 的函数。
    * `WasmJSFunction`: 表示由 JavaScript 创建并包装成 WebAssembly 函数的 callable 对象。
    * `WasmCapiFunction`: 表示通过 C/C++ API 暴露给 WebAssembly 的外部函数。
    * `WasmExternalFunction`: 作为一个抽象基类，统一了以上三种不同类型的外部函数。
    * `WasmFunctionData`: 存储 WebAssembly 函数的元数据，如 wrapper 代码和内部函数信息。
    * `WasmExportedFunctionData`: 存储导出函数的额外信息，如实例数据和 C wrapper 代码。
    * `WasmJSFunctionData`: 存储 JS 函数的额外信息，包括对原始 JavaScript callable 的引用。
    * `WasmCapiFunctionData`: 存储 C API 函数的额外信息。
    * `WasmInternalFunction`: 表示 WebAssembly 内部函数。
    * `WasmFuncRef`: 表示对 WebAssembly 函数的引用。

4. **导入数据 (Import Data):** `WasmImportData` 类存储有关导入函数的信息，例如所属的实例和调用来源。

5. **调试支持 (Debugging Support):** `WasmScript` 类提供了一系列静态方法，用于在 WebAssembly 模块中设置和清除断点。

6. **异常标签 (Exception Tags):** `WasmExceptionTag` 类表示在 WebAssembly 模块中定义的异常标签。

7. **Asm.js 数据 (Asm.js Data):** `AsmWasmData` 类存储与 asm.js 模块相关的数据。

8. **类型信息 (Type Information):** `WasmTypeInfo` 类存储 WebAssembly 类型的相关信息。

9. **GC 对象 (GC Objects):**
    * `WasmObject`:  作为所有 Wasm GC 对象的基类。
    * `WasmStruct`: 表示 WebAssembly 的结构体类型。
    * `WasmArray`: 表示 WebAssembly 的数组类型。
    * `WasmNull`:  表示 WebAssembly 的 `null` 值，在某些配置下可能占用较大内存。

10. **控制流 (Control Flow):**
    * `WasmContinuationObject`:  表示 WebAssembly 的 delimited continuation（一种高级控制流机制）。
    * `WasmSuspenderObject`:  用于支持 WebAssembly 的异步操作，例如使用 Promise。
    * `WasmSuspendingObject`:  表示正在挂起的 WebAssembly 操作。
    * `WasmResumeData`:  存储恢复被挂起 WebAssembly 执行所需的数据。

11. **类型转换工具 (Type Conversion Utilities):** 提供了 `JSToWasmObject` 和 `WasmToJSObject` 函数，用于在 JavaScript 和 WebAssembly 对象之间进行类型转换。

**与 JavaScript 的关系 (用 JavaScript 举例):**

* **间接调用表:** 当你在 WebAssembly 中定义一个 `table` 并尝试通过 JavaScript 调用 `WebAssembly.Table.prototype.get()` 获取表中的函数时，V8 内部就会使用 `WasmDispatchTable` 来管理这些函数引用。

  ```javascript
  const wasmCode = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x07, 0x01, 0x60,
    0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b,
    0x07, 0x05, 0x04, 0x65, 0x78, 0x70, 0x31, 0x00, 0x00
  ]);
  const wasmModule = new WebAssembly.Module(wasmCode);
  const wasmInstance = new WebAssembly.Instance(wasmModule, {});
  const exportedFunction = wasmInstance.exports.exp1; // exportedFunction 是一个 WasmExportedFunction 的实例
  ```

* **异常处理:** 当 WebAssembly 代码抛出一个异常时，V8 会将其包装成一个 `WasmExceptionPackage` 对象，以便在 JavaScript 中捕获和处理。

  ```javascript
  const wasmCodeWithException = new Uint8Array([
    // ... 包含抛出异常的 WASM 代码 ...
  ]);
  const wasmModuleWithException = new WebAssembly.Module(wasmCodeWithException);
  const wasmInstanceWithException = new WebAssembly.Instance(wasmModuleWithException, {});
  try {
    wasmInstanceWithException.exports.throwingFunction();
  } catch (e) {
    // e 可能是一个 WasmExceptionPackage 的表示
    console.error("Caught a WASM exception:", e);
  }
  ```

* **函数引用:**  `WebAssembly.Function` API 可以创建 `WasmJSFunction` 的实例。

  ```javascript
  const jsFunction = (x) => x * 2;
  const wasmFunc = new WebAssembly.Function({ parameters: ['i32'], results: ['i32'] }, jsFunction); // wasmFunc 是一个 WasmJSFunction 的实例
  ```

**代码逻辑推理 (假设输入与输出):**

以 `WasmDispatchTable::Set` 方法为例，假设输入：

* `index`:  `5` (要设置的表条目索引)
* `implicit_arg`: 指向某个 `WasmImportData` 对象的指针
* `call_target`:  指向一个 WebAssembly 函数代码的指针
* `sig_id`:  一个表示函数签名的索引
* `wrapper_if_known`:  一个指向已知 wrapper 代码的指针 (假设为 `nullptr`)
* `contextual_knowledge`:  `kIsNotAWrapper`
* `new_or_existing`: `kNewEntry`

输出 (预期行为):

1. `WasmDispatchTable` 对象内部的第 5 个条目将被更新。
2. 该条目的 `target` 字段将被设置为 `call_target`。
3. 该条目的 `implicit_arg` 字段将被设置为 `implicit_arg`。
4. 该条目的签名信息将被设置为 `sig_id`。
5. 由于 `wrapper_if_known` 是 `nullptr`，并且 `contextual_knowledge` 是 `kIsNotAWrapper`，因此不会添加或更新 wrapper 信息。
6. 如果这是新的条目，`new_or_existing` 为 `kNewEntry`，则可能需要更新表的长度。

**用户常见的编程错误 (与这些对象间接相关):**

用户通常不会直接操作这些 C++ 对象，但对它们背后概念的误解可能导致错误：

* **类型不匹配:** 在 JavaScript 调用 WebAssembly 函数时，如果传递的参数类型与 WebAssembly 函数的签名不匹配，V8 内部的类型转换逻辑 (可能涉及到 `JSToWasmObject`) 会抛出错误。
* **访问越界:**  尝试访问 `WebAssembly.Memory` 或 `WebAssembly.Table` 的越界索引会导致错误。 这与 `WasmMemoryObject` 和 `WasmTableObject` 的内部管理有关。
* **错误的函数调用:** 在使用函数表进行间接调用时，如果表中的函数签名与调用时提供的参数不匹配，会导致运行时错误。这涉及到 `WasmDispatchTable` 的正确配置。
* **未捕获的 WebAssembly 异常:** 如果 WebAssembly 代码抛出异常但 JavaScript 没有捕获，程序可能会崩溃。理解 `WasmExceptionPackage` 的作用有助于调试这类问题。

总而言之，`v8/src/wasm/wasm-objects.h` 定义了 V8 引擎用于表示和操作 WebAssembly 内部结构的蓝图，它对于理解 V8 如何执行 WebAssembly 代码至关重要。虽然开发者通常不直接操作这些对象，但理解它们的功能有助于调试和优化 WebAssembly 应用。

Prompt: 
```
这是目录为v8/src/wasm/wasm-objects.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-objects.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
 //    wrapper is added to the table, we increment the ref count. When we
  //    remove the last reference, we decrement the ref count, which potentially
  //    triggers code GC.
  struct WrapperEntry {
    wasm::WasmCode* code;  // {nullptr} if this is not a wrapper.
    int count = 1;         // irrelevant if this is not a wrapper.
  };
  std::unordered_map<WasmCodePointer, WrapperEntry> wrappers_;
};

// The dispatch table is referenced from a WasmTableObject and from every
// WasmTrustedInstanceData which uses the table. It is used from generated code
// for executing indirect calls.
class WasmDispatchTable : public TrustedObject {
 public:
#if V8_ENABLE_DRUMBRAKE
  static const uint32_t kInvalidFunctionIndex = UINT_MAX;
#endif  // V8_ENABLE_DRUMBRAKE

  enum NewOrExistingEntry : bool { kNewEntry, kExistingEntry };

  class BodyDescriptor;

  static constexpr size_t kLengthOffset = kHeaderSize;
  static constexpr size_t kCapacityOffset = kLengthOffset + kUInt32Size;
  static constexpr size_t kProtectedOffheapDataOffset =
      kCapacityOffset + kUInt32Size;
  static constexpr size_t kEntriesOffset =
      kProtectedOffheapDataOffset + kTaggedSize;

  // Entries consist of
  // - target (pointer)
#if V8_ENABLE_DRUMBRAKE
  // - function_index (uint32_t) (located in place of target pointer).
#endif  // V8_ENABLE_DRUMBRAKE
  // - implicit_arg (protected pointer, tagged sized)
  // - sig (int32_t); unused for imports which check the signature statically.
  static constexpr size_t kTargetBias = 0;
#if V8_ENABLE_DRUMBRAKE
  // In jitless mode, reuse the 'target' field storage to hold the (uint32_t)
  // function index.
  static constexpr size_t kFunctionIndexBias = kTargetBias;
#endif  // V8_ENABLE_DRUMBRAKE
  static constexpr size_t kImplicitArgBias = kTargetBias + kSystemPointerSize;
  static constexpr size_t kSigBias = kImplicitArgBias + kTaggedSize;
  static constexpr size_t kEntryPaddingOffset = kSigBias + kInt32Size;
  static constexpr size_t kEntryPaddingBytes =
      kEntryPaddingOffset % kTaggedSize;
  static_assert(kEntryPaddingBytes == 4 || kEntryPaddingBytes == 0);
  static constexpr size_t kEntrySize = kEntryPaddingOffset + kEntryPaddingBytes;

  // Tagged and system-pointer-sized fields must be tagged-size-aligned.
  static_assert(IsAligned(kEntriesOffset, kTaggedSize));
  static_assert(IsAligned(kEntrySize, kTaggedSize));
  static_assert(IsAligned(kTargetBias, kTaggedSize));
  static_assert(IsAligned(kImplicitArgBias, kTaggedSize));

  // TODO(clemensb): If we ever enable allocation alignment we will needs to add
  // more padding to make the "target" fields system-pointer-size aligned.
  static_assert(!USE_ALLOCATION_ALIGNMENT_BOOL);

  // The total byte size must still fit in an integer.
  static constexpr int kMaxLength = (kMaxInt - kEntriesOffset) / kEntrySize;

  static constexpr int SizeFor(int length) {
    DCHECK_LE(length, kMaxLength);
    return kEntriesOffset + length * kEntrySize;
  }

  static constexpr int OffsetOf(int index) {
    DCHECK_LT(index, kMaxLength);
    return SizeFor(index);
  }

  // Clear uninitialized padding space for deterministic object content.
  // Depending on the V8 build mode there could be no padding.
  inline void clear_entry_padding(int index);

  // The current length of this dispatch table. This is always <= the capacity.
  inline int length() const;
  inline int length(AcquireLoadTag) const;
  // The current capacity. Can be bigger than the current length to allow for
  // more efficient growing.
  inline int capacity() const;

  DECL_PROTECTED_POINTER_ACCESSORS(protected_offheap_data,
                                   TrustedManaged<WasmDispatchTableData>)
  inline WasmDispatchTableData* offheap_data() const;

  // Accessors.
  // {implicit_arg} will be a WasmImportData, a WasmTrustedInstanceData, or
  // Smi::zero() (if the entry was cleared).
  inline Tagged<Object> implicit_arg(int index) const;
  inline WasmCodePointer target(int index) const;
  inline wasm::CanonicalTypeIndex sig(int index) const;

  // Set an entry for indirect calls.
  // {implicit_arg} has to be a WasmImportData, a WasmTrustedInstanceData, or
  // Smi::zero().
  void V8_EXPORT_PRIVATE Set(int index, Tagged<Object> implicit_arg,
                             WasmCodePointer call_target,
                             wasm::CanonicalTypeIndex sig_id,
#if V8_ENABLE_DRUMBRAKE
                             uint32_t function_index,
#endif  // V8_ENABLE_DRUMBRAKE
                             wasm::WasmCode* wrapper_if_known,
                             IsAWrapper contextual_knowledge,
                             NewOrExistingEntry new_or_existing);
#if V8_ENABLE_DRUMBRAKE
  inline uint32_t function_index(int index) const;
#endif  // V8_ENABLE_DRUMBRAKE

  // Set an entry for an import. We check signatures statically there, so the
  // signature is not updated in the dispatch table.
  // {implicit_arg} has to be a WasmImportData or a WasmTrustedInstanceData.
  void V8_EXPORT_PRIVATE SetForImport(int index,
                                      Tagged<TrustedObject> implicit_arg,
                                      WasmCodePointer call_target,
                                      wasm::WasmCode* wrapper_if_known,
                                      IsAWrapper contextual_knowledge);

  void Clear(int index, NewOrExistingEntry new_or_existing);
  void InstallCompiledWrapper(int index, wasm::WasmCode* wrapper);

  static V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT Handle<WasmDispatchTable> New(
      Isolate* isolate, int length);
  static V8_WARN_UNUSED_RESULT Handle<WasmDispatchTable> Grow(
      Isolate*, Handle<WasmDispatchTable>, int new_length);

  DECL_PRINTER(WasmDispatchTable)
  DECL_VERIFIER(WasmDispatchTable)
  OBJECT_CONSTRUCTORS(WasmDispatchTable, TrustedObject);
};

// A Wasm exception that has been thrown out of Wasm code.
class V8_EXPORT_PRIVATE WasmExceptionPackage : public JSObject {
 public:
  static Handle<WasmExceptionPackage> New(
      Isolate* isolate, DirectHandle<WasmExceptionTag> exception_tag,
      int encoded_size);

  static Handle<WasmExceptionPackage> New(
      Isolate* isolate, DirectHandle<WasmExceptionTag> exception_tag,
      DirectHandle<FixedArray> values);

  // The below getters return {undefined} in case the given exception package
  // does not carry the requested values (i.e. is of a different type).
  static Handle<Object> GetExceptionTag(
      Isolate* isolate, Handle<WasmExceptionPackage> exception_package);
  static Handle<Object> GetExceptionValues(
      Isolate* isolate, Handle<WasmExceptionPackage> exception_package);

  // Determines the size of the array holding all encoded exception values.
  static uint32_t GetEncodedSize(const wasm::WasmTagSig* tag);
  static uint32_t GetEncodedSize(const wasm::WasmTag* tag);

  // In-object fields.
  enum { kTagIndex, kValuesIndex, kInObjectFieldCount };
  static constexpr int kSize =
      kHeaderSize + (kTaggedSize * kInObjectFieldCount);

  DECL_PRINTER(WasmExceptionPackage)
  DECL_VERIFIER(WasmExceptionPackage)
  OBJECT_CONSTRUCTORS(WasmExceptionPackage, JSObject);
};

void V8_EXPORT_PRIVATE
EncodeI32ExceptionValue(DirectHandle<FixedArray> encoded_values,
                        uint32_t* encoded_index, uint32_t value);

void V8_EXPORT_PRIVATE
EncodeI64ExceptionValue(DirectHandle<FixedArray> encoded_values,
                        uint32_t* encoded_index, uint64_t value);

void V8_EXPORT_PRIVATE
DecodeI32ExceptionValue(DirectHandle<FixedArray> encoded_values,
                        uint32_t* encoded_index, uint32_t* value);

void V8_EXPORT_PRIVATE
DecodeI64ExceptionValue(DirectHandle<FixedArray> encoded_values,
                        uint32_t* encoded_index, uint64_t* value);

bool UseGenericWasmToJSWrapper(wasm::ImportCallKind kind,
                               const wasm::CanonicalSig* sig,
                               wasm::Suspend suspend);

// A Wasm function that is wrapped and exported to JavaScript.
// Representation of WebAssembly.Function JavaScript-level object.
class WasmExportedFunction : public JSFunction {
 public:
  V8_EXPORT_PRIVATE static bool IsWasmExportedFunction(Tagged<Object> object);

  V8_EXPORT_PRIVATE static Handle<WasmExportedFunction> New(
      Isolate* isolate, DirectHandle<WasmTrustedInstanceData> instance_data,
      DirectHandle<WasmFuncRef> func_ref,
      DirectHandle<WasmInternalFunction> internal_function, int arity,
      DirectHandle<Code> export_wrapper);

  // Return a null-terminated string with the debug name in the form
  // 'js-to-wasm:<sig>'.
  static std::unique_ptr<char[]> GetDebugName(const wasm::CanonicalSig* sig);

  OBJECT_CONSTRUCTORS(WasmExportedFunction, JSFunction);
};

// A Wasm function that was created by wrapping a JavaScript callable.
// Representation of WebAssembly.Function JavaScript-level object.
class WasmJSFunction : public JSFunction {
 public:
  static bool IsWasmJSFunction(Tagged<Object> object);

  static Handle<WasmJSFunction> New(Isolate* isolate,
                                    const wasm::FunctionSig* sig,
                                    Handle<JSReceiver> callable,
                                    wasm::Suspend suspend);

  OBJECT_CONSTRUCTORS(WasmJSFunction, JSFunction);
};

// An external function exposed to Wasm via the C/C++ API.
class WasmCapiFunction : public JSFunction {
 public:
  static bool IsWasmCapiFunction(Tagged<Object> object);

  static Handle<WasmCapiFunction> New(Isolate* isolate, Address call_target,
                                      DirectHandle<Foreign> embedder_data,
                                      wasm::CanonicalTypeIndex sig_index,
                                      const wasm::CanonicalSig* sig,
                                      uintptr_t signature_hash);

  const wasm::CanonicalSig* sig() const;

  // Checks whether the given {sig} has the same parameter types as the
  // serialized signature stored within this C-API function object.
  bool MatchesSignature(
      wasm::CanonicalTypeIndex other_canonical_sig_index) const;

  OBJECT_CONSTRUCTORS(WasmCapiFunction, JSFunction);
};

// Any external function that can be imported/exported in modules. This abstract
// class just dispatches to the following concrete classes:
//  - {WasmExportedFunction}: A proper Wasm function exported from a module.
//  - {WasmJSFunction}: A function constructed via WebAssembly.Function in JS.
//  - {WasmCapiFunction}: A function constructed via the C/C++ API.
class WasmExternalFunction : public JSFunction {
 public:
  static bool IsWasmExternalFunction(Tagged<Object> object);

  inline Tagged<WasmFuncRef> func_ref() const;

  OBJECT_CONSTRUCTORS(WasmExternalFunction, JSFunction);
};

class WasmFunctionData
    : public TorqueGeneratedWasmFunctionData<WasmFunctionData,
                                             ExposedTrustedObject> {
 public:
  DECL_CODE_POINTER_ACCESSORS(wrapper_code)
  DECL_PROTECTED_POINTER_ACCESSORS(internal, WasmInternalFunction)

  DECL_PRINTER(WasmFunctionData)

  using BodyDescriptor = StackedBodyDescriptor<
      FixedExposedTrustedObjectBodyDescriptor<
          WasmFunctionData, kWasmFunctionDataIndirectPointerTag>,
      WithStrongCodePointer<kWrapperCodeOffset>,
      WithProtectedPointer<kProtectedInternalOffset>>;

  using SuspendField = base::BitField<wasm::Suspend, 0, 1>;
  using PromiseField = SuspendField::Next<wasm::Promise, 1>;

  TQ_OBJECT_CONSTRUCTORS(WasmFunctionData)
};

// Information for a WasmExportedFunction which is referenced as the function
// data of the SharedFunctionInfo underlying the function. For details please
// see the {SharedFunctionInfo::HasWasmExportedFunctionData} predicate.
class WasmExportedFunctionData
    : public TorqueGeneratedWasmExportedFunctionData<WasmExportedFunctionData,
                                                     WasmFunctionData> {
 public:
  DECL_PROTECTED_POINTER_ACCESSORS(instance_data, WasmTrustedInstanceData)
  DECL_CODE_POINTER_ACCESSORS(c_wrapper_code)

  DECL_PRIMITIVE_ACCESSORS(sig, const wasm::CanonicalSig*)
  // Prefer to use this convenience wrapper of the Torque-generated
  // {canonical_type_index()}.
  inline wasm::CanonicalTypeIndex sig_index() const;

  inline bool is_promising() const;

  bool MatchesSignature(wasm::CanonicalTypeIndex other_canonical_sig_index);

  // Dispatched behavior.
  DECL_PRINTER(WasmExportedFunctionData)
  DECL_VERIFIER(WasmExportedFunctionData)

  using BodyDescriptor = StackedBodyDescriptor<
      SubclassBodyDescriptor<WasmFunctionData::BodyDescriptor,
                             FixedBodyDescriptorFor<WasmExportedFunctionData>>,
      WithProtectedPointer<kProtectedInstanceDataOffset>,
      WithStrongCodePointer<kCWrapperCodeOffset>>;

  TQ_OBJECT_CONSTRUCTORS(WasmExportedFunctionData)
};

class WasmImportData
    : public TorqueGeneratedWasmImportData<WasmImportData, TrustedObject> {
 public:
  // Dispatched behavior.
  DECL_PRINTER(WasmImportData)

  DECL_PROTECTED_POINTER_ACCESSORS(instance_data, WasmTrustedInstanceData)

  static constexpr int kInvalidCallOrigin = 0;

  static void SetImportIndexAsCallOrigin(
      DirectHandle<WasmImportData> import_data, int entry_index);

  static bool CallOriginIsImportIndex(Tagged<Smi> call_origin);

  static bool CallOriginIsIndexInTable(Tagged<Smi> call_origin);

  static int CallOriginAsIndex(Tagged<Smi> call_origin);

  static void SetIndexInTableAsCallOrigin(
      DirectHandle<WasmImportData> import_data, int entry_index);

  static void SetCrossInstanceTableIndexAsCallOrigin(
      Isolate* isolate, DirectHandle<WasmImportData> import_data,
      DirectHandle<WasmInstanceObject> instance_object, int entry_index);

  static void SetFuncRefAsCallOrigin(DirectHandle<WasmImportData> import_data,
                                     DirectHandle<WasmFuncRef> func_ref);

  using BodyDescriptor =
      StackedBodyDescriptor<FixedBodyDescriptorFor<WasmImportData>,
                            WithProtectedPointer<kProtectedInstanceDataOffset>>;

  TQ_OBJECT_CONSTRUCTORS(WasmImportData)
};

class WasmInternalFunction
    : public TorqueGeneratedWasmInternalFunction<WasmInternalFunction,
                                                 ExposedTrustedObject> {
 public:
  // Get the external function if it exists. Returns true and writes to the
  // output parameter if an external function exists. Returns false otherwise.
  bool try_get_external(Tagged<JSFunction>* result);

  V8_EXPORT_PRIVATE static Handle<JSFunction> GetOrCreateExternal(
      DirectHandle<WasmInternalFunction> internal);

  DECL_PROTECTED_POINTER_ACCESSORS(implicit_arg, TrustedObject)

  // Dispatched behavior.
  DECL_PRINTER(WasmInternalFunction)

  using BodyDescriptor = StackedBodyDescriptor<
      FixedExposedTrustedObjectBodyDescriptor<
          WasmInternalFunction, kWasmInternalFunctionIndirectPointerTag>,
      WithProtectedPointer<kProtectedImplicitArgOffset>>;

  TQ_OBJECT_CONSTRUCTORS(WasmInternalFunction)
};

class WasmFuncRef : public TorqueGeneratedWasmFuncRef<WasmFuncRef, HeapObject> {
 public:
  DECL_TRUSTED_POINTER_ACCESSORS(internal, WasmInternalFunction)

  DECL_PRINTER(WasmFuncRef)

  using BodyDescriptor = StackedBodyDescriptor<
      FixedBodyDescriptorFor<WasmFuncRef>,
      WithStrongTrustedPointer<kTrustedInternalOffset,
                               kWasmInternalFunctionIndirectPointerTag>>;

  TQ_OBJECT_CONSTRUCTORS(WasmFuncRef)
};

// Information for a WasmJSFunction which is referenced as the function data of
// the SharedFunctionInfo underlying the function. For details please see the
// {SharedFunctionInfo::HasWasmJSFunctionData} predicate.
class WasmJSFunctionData
    : public TorqueGeneratedWasmJSFunctionData<WasmJSFunctionData,
                                               WasmFunctionData> {
 public:
  // The purpose of this class is to provide lifetime management for compiled
  // wrappers: the {WasmJSFunction} owns an {OffheapData} via {TrustedManaged},
  // which decrements the wrapper's refcount when the {WasmJSFunction} is
  // garbage-collected.
  class OffheapData {
   public:
    OffheapData() = default;
    ~OffheapData();

    void set_wrapper(wasm::WasmCode* wrapper);

   private:
    wasm::WasmCode* wrapper_{nullptr};
  };

  DECL_PROTECTED_POINTER_ACCESSORS(protected_offheap_data,
                                   TrustedManaged<OffheapData>)
  inline OffheapData* offheap_data() const;

  Tagged<JSReceiver> GetCallable() const;
  wasm::Suspend GetSuspend() const;
  const wasm::CanonicalSig* GetSignature() const;
  // Prefer to use this convenience wrapper of the Torque-generated
  // {canonical_sig_index()}.
  inline wasm::CanonicalTypeIndex sig_index() const;
  bool MatchesSignature(
      wasm::CanonicalTypeIndex other_canonical_sig_index) const;

  // Dispatched behavior.
  DECL_PRINTER(WasmJSFunctionData)

  using BodyDescriptor = StackedBodyDescriptor<
      SubclassBodyDescriptor<WasmFunctionData::BodyDescriptor,
                             FixedBodyDescriptorFor<WasmJSFunctionData>>,
      WithProtectedPointer<kProtectedOffheapDataOffset>>;

 private:
  TQ_OBJECT_CONSTRUCTORS(WasmJSFunctionData)
};

class WasmCapiFunctionData
    : public TorqueGeneratedWasmCapiFunctionData<WasmCapiFunctionData,
                                                 WasmFunctionData> {
 public:
  // Prefer to use this convenience wrapper of the Torque-generated
  // {canonical_sig_index()}.
  inline wasm::CanonicalTypeIndex sig_index() const;

  DECL_PRINTER(WasmCapiFunctionData)

  using BodyDescriptor =
      SubclassBodyDescriptor<WasmFunctionData::BodyDescriptor,
                             FixedBodyDescriptorFor<WasmCapiFunctionData>>;

  TQ_OBJECT_CONSTRUCTORS(WasmCapiFunctionData)
};

class WasmResumeData
    : public TorqueGeneratedWasmResumeData<WasmResumeData, HeapObject> {
 public:
  using BodyDescriptor =
      FlexibleBodyDescriptor<WasmResumeData::kStartOfStrongFieldsOffset>;
  DECL_PRINTER(WasmResumeData)
  TQ_OBJECT_CONSTRUCTORS(WasmResumeData)
};

class WasmScript : public AllStatic {
 public:
  // Position used for storing "on entry" breakpoints (a.k.a. instrumentation
  // breakpoints). This would be an illegal position for any other breakpoint.
  static constexpr int kOnEntryBreakpointPosition = -1;

  // Set a breakpoint on the given byte position inside the given module.
  // This will affect all live and future instances of the module.
  // The passed position might be modified to point to the next breakable
  // location inside the same function.
  // If it points outside a function, or behind the last breakable location,
  // this function returns false and does not set any breakpoint.
  V8_EXPORT_PRIVATE static bool SetBreakPoint(
      DirectHandle<Script>, int* position,
      DirectHandle<BreakPoint> break_point);

  // Set an "on entry" breakpoint (a.k.a. instrumentation breakpoint) inside
  // the given module. This will affect all live and future instances of the
  // module.
  V8_EXPORT_PRIVATE static void SetInstrumentationBreakpoint(
      DirectHandle<Script>, DirectHandle<BreakPoint> break_point);

  // Set a breakpoint on first breakable position of the given function index
  // inside the given module. This will affect all live and future instances of
  // the module.
  V8_EXPORT_PRIVATE static bool SetBreakPointOnFirstBreakableForFunction(
      DirectHandle<Script>, int function_index,
      DirectHandle<BreakPoint> break_point);

  // Set a breakpoint at the breakable offset of the given function index
  // inside the given module. This will affect all live and future instances of
  // the module.
  V8_EXPORT_PRIVATE static bool SetBreakPointForFunction(
      DirectHandle<Script>, int function_index, int breakable_offset,
      DirectHandle<BreakPoint> break_point);

  // Remove a previously set breakpoint at the given byte position inside the
  // given module. If this breakpoint is not found this function returns false.
  V8_EXPORT_PRIVATE static bool ClearBreakPoint(
      DirectHandle<Script>, int position, DirectHandle<BreakPoint> break_point);

  // Remove a previously set breakpoint by id. If this breakpoint is not found,
  // returns false.
  V8_EXPORT_PRIVATE static bool ClearBreakPointById(DirectHandle<Script>,
                                                    int breakpoint_id);

  // Remove all set breakpoints.
  static void ClearAllBreakpoints(Tagged<Script>);

  // Get a list of all possible breakpoints within a given range of this module.
  V8_EXPORT_PRIVATE static bool GetPossibleBreakpoints(
      wasm::NativeModule* native_module, const debug::Location& start,
      const debug::Location& end, std::vector<debug::BreakLocation>* locations);

  // Return an empty handle if no breakpoint is hit at that location, or a
  // FixedArray with all hit breakpoint objects.
  static MaybeHandle<FixedArray> CheckBreakPoints(Isolate*,
                                                  DirectHandle<Script>,
                                                  int position,
                                                  StackFrameId stack_frame_id);

 private:
  // Helper functions that update the breakpoint info list.
  static void AddBreakpointToInfo(DirectHandle<Script>, int position,
                                  DirectHandle<BreakPoint> break_point);
};

// Tags provide an object identity for each exception defined in a wasm module
// header. They are referenced by the following fields:
//  - {WasmTagObject::tag}: The tag of the {Tag} object.
//  - {WasmInstanceObject::tags_table}: List of tags used by an instance.
class WasmExceptionTag
    : public TorqueGeneratedWasmExceptionTag<WasmExceptionTag, Struct> {
 public:
  V8_EXPORT_PRIVATE static Handle<WasmExceptionTag> New(Isolate* isolate,
                                                        int index);

  using BodyDescriptor = StructBodyDescriptor;

  TQ_OBJECT_CONSTRUCTORS(WasmExceptionTag)
};

// Data annotated to the asm.js Module function. Used for later instantiation of
// that function.
class AsmWasmData : public TorqueGeneratedAsmWasmData<AsmWasmData, Struct> {
 public:
  static Handle<AsmWasmData> New(
      Isolate* isolate, std::shared_ptr<wasm::NativeModule> native_module,
      DirectHandle<HeapNumber> uses_bitset);

  DECL_PRINTER(AsmWasmData)

  using BodyDescriptor = StructBodyDescriptor;

  TQ_OBJECT_CONSTRUCTORS(AsmWasmData)
};

class WasmTypeInfo
    : public TorqueGeneratedWasmTypeInfo<WasmTypeInfo, HeapObject> {
 public:
  DECL_EXTERNAL_POINTER_ACCESSORS(native_type, Address)
  inline wasm::ModuleTypeIndex type_index() const;
  DECL_TRUSTED_POINTER_ACCESSORS(trusted_data, WasmTrustedInstanceData)

  DECL_PRINTER(WasmTypeInfo)

  class BodyDescriptor;

  TQ_OBJECT_CONSTRUCTORS(WasmTypeInfo)
};

class WasmObject : public TorqueGeneratedWasmObject<WasmObject, JSReceiver> {
 protected:
  // Returns boxed value of the object's field/element with given type and
  // offset.
  static inline Handle<Object> ReadValueAt(Isolate* isolate,
                                           DirectHandle<HeapObject> obj,
                                           wasm::ValueType type,
                                           uint32_t offset);

 private:
  template <typename ElementType>
  static ElementType FromNumber(Tagged<Object> value);

  TQ_OBJECT_CONSTRUCTORS(WasmObject)
};

class WasmStruct : public TorqueGeneratedWasmStruct<WasmStruct, WasmObject> {
 public:
  static inline wasm::StructType* type(Tagged<Map> map);
  inline wasm::StructType* type() const;
  static inline wasm::StructType* GcSafeType(Tagged<Map> map);
  static inline int Size(const wasm::StructType* type);
  static inline int GcSafeSize(Tagged<Map> map);
  inline const wasm::WasmModule* module();
  static inline void EncodeInstanceSizeInMap(int instance_size,
                                             Tagged<Map> map);
  static inline int DecodeInstanceSizeFromMap(Tagged<Map> map);

  // Returns the address of the field at given offset.
  inline Address RawFieldAddress(int raw_offset);

  // Returns the ObjectSlot for tagged value at given offset.
  inline ObjectSlot RawField(int raw_offset);

  V8_EXPORT_PRIVATE wasm::WasmValue GetFieldValue(uint32_t field_index);

  static inline void SetField(Isolate* isolate, Handle<WasmStruct> obj,
                              uint32_t field_index, Handle<Object> value);

  DECL_PRINTER(WasmStruct)

  class BodyDescriptor;

  TQ_OBJECT_CONSTRUCTORS(WasmStruct)
};

int WasmStruct::Size(const wasm::StructType* type) {
  // Object size must fit into a Smi (because of filler objects), and its
  // computation must not overflow.
  static_assert(Smi::kMaxValue <= kMaxInt);
  DCHECK_LE(type->total_fields_size(), Smi::kMaxValue - kHeaderSize);
  return std::max(kHeaderSize + static_cast<int>(type->total_fields_size()),
                  Heap::kMinObjectSizeInTaggedWords * kTaggedSize);
}

class WasmArray : public TorqueGeneratedWasmArray<WasmArray, WasmObject> {
 public:
  static inline wasm::ArrayType* type(Tagged<Map> map);
  inline wasm::ArrayType* type() const;
  static inline wasm::ArrayType* GcSafeType(Tagged<Map> map);
  inline const wasm::WasmModule* module();

  // Get the {ObjectSlot} corresponding to the element at {index}. Requires that
  // this is a reference array.
  inline ObjectSlot ElementSlot(uint32_t index);
  V8_EXPORT_PRIVATE wasm::WasmValue GetElement(uint32_t index);

  static inline int SizeFor(Tagged<Map> map, int length);

  // Returns boxed value of the array's element.
  static inline Handle<Object> GetElement(Isolate* isolate,
                                          DirectHandle<WasmArray> array,
                                          uint32_t index);

  void SetTaggedElement(uint32_t index, DirectHandle<Object> value,
                        WriteBarrierMode mode = UPDATE_WRITE_BARRIER);

  // Returns the offset/Address of the element at {index}.
  inline uint32_t element_offset(uint32_t index);
  inline Address ElementAddress(uint32_t index);

  static constexpr int MaxLength(uint32_t element_size_bytes) {
    // The total object size must fit into a Smi, for filler objects. To make
    // the behavior of Wasm programs independent from the Smi configuration,
    // we hard-code the smaller of the two supported ranges.
    return (SmiTagging<4>::kSmiMaxValue - kHeaderSize) / element_size_bytes;
  }

  static int MaxLength(const wasm::ArrayType* type) {
    return MaxLength(type->element_type().value_kind_size());
  }

  static inline void EncodeElementSizeInMap(int element_size, Tagged<Map> map);
  static inline int DecodeElementSizeFromMap(Tagged<Map> map);

  DECL_PRINTER(WasmArray)

  class BodyDescriptor;

  TQ_OBJECT_CONSTRUCTORS(WasmArray)
};

// A wasm delimited continuation.
class WasmContinuationObject
    : public TorqueGeneratedWasmContinuationObject<WasmContinuationObject,
                                                   HeapObject> {
 public:
  static Handle<WasmContinuationObject> New(
      Isolate* isolate, wasm::StackMemory* stack,
      wasm::JumpBuffer::StackState state,
      AllocationType allocation_type = AllocationType::kYoung);
  static Handle<WasmContinuationObject> New(
      Isolate* isolate, wasm::StackMemory* stack,
      wasm::JumpBuffer::StackState state, DirectHandle<HeapObject> parent,
      AllocationType allocation_type = AllocationType::kYoung);

  DECL_EXTERNAL_POINTER_ACCESSORS(jmpbuf, Address)
  DECL_EXTERNAL_POINTER_ACCESSORS(stack, Address)

  DECL_PRINTER(WasmContinuationObject)

  using BodyDescriptor = StackedBodyDescriptor<
      FixedBodyDescriptorFor<WasmContinuationObject>,
      WithExternalPointer<kStackOffset, kWasmStackMemoryTag>,
      WithExternalPointer<kJmpbufOffset, kWasmContinuationJmpbufTag>>;

 private:
  TQ_OBJECT_CONSTRUCTORS(WasmContinuationObject)
};

// The suspender object provides an API to suspend and resume wasm code using
// promises. See: https://github.com/WebAssembly/js-promise-integration.
class WasmSuspenderObject
    : public TorqueGeneratedWasmSuspenderObject<WasmSuspenderObject,
                                                HeapObject> {
 public:
  using BodyDescriptor = FixedBodyDescriptorFor<WasmSuspenderObject>;
  enum State : int { kInactive = 0, kActive, kSuspended };
  DECL_PRINTER(WasmSuspenderObject)
  TQ_OBJECT_CONSTRUCTORS(WasmSuspenderObject)
};

class WasmSuspendingObject
    : public TorqueGeneratedWasmSuspendingObject<WasmSuspendingObject,
                                                 JSObject> {
 public:
  V8_EXPORT_PRIVATE static Handle<WasmSuspendingObject> New(
      Isolate* isolate, DirectHandle<JSReceiver> callable);
  DECL_PRINTER(WasmSuspendingObject)
  TQ_OBJECT_CONSTRUCTORS(WasmSuspendingObject)
};

class WasmNull : public TorqueGeneratedWasmNull<WasmNull, HeapObject> {
 public:
#if V8_STATIC_ROOTS_BOOL || V8_STATIC_ROOTS_GENERATION_BOOL
  // TODO(manoskouk): Make it smaller if able and needed.
  static constexpr int kSize = 64 * KB + kTaggedSize;
  // Payload should be a multiple of page size.
  static_assert((kSize - kTaggedSize) % kMinimumOSPageSize == 0);
  // Any wasm struct offset should fit in the object.
  static_assert(kSize >=
                WasmStruct::kHeaderSize +
                    (wasm::kMaxStructFieldIndexForImplicitNullCheck + 1) *
                        kSimd128Size);

  Address payload() { return ptr() + kHeaderSize - kHeapObjectTag; }
  static constexpr size_t kPayloadSize = kSize - kTaggedSize;
#else
  static constexpr int kSize = kTaggedSize;
#endif

  // WasmNull cannot use `FixedBodyDescriptorFor()` as its map is variable size
  // (not fixed size) as kSize is too large for a fixed-size map.
  class BodyDescriptor;

  TQ_OBJECT_CONSTRUCTORS(WasmNull)
};

#undef DECL_OPTIONAL_ACCESSORS

Handle<Map> CreateFuncRefMap(Isolate* isolate, Handle<Map> opt_rtt_parent);

namespace wasm {
// Takes a {value} in the JS representation and typechecks it according to
// {expected}. If the typecheck succeeds, returns the wasm representation of the
// object; otherwise, returns the empty handle.
MaybeHandle<Object> JSToWasmObject(Isolate* isolate, Handle<Object> value,
                                   CanonicalValueType expected,
                                   const char** error_message);

// Utility which canonicalizes {expected} in addition.
MaybeHandle<Object> JSToWasmObject(Isolate* isolate, const WasmModule* module,
                                   Handle<Object> value, ValueType expected,
                                   const char** error_message);

// Takes a {value} in the Wasm representation and transforms it to the
// respective JS representation. The caller is responsible for not providing an
// object which cannot be transformed to JS.
Handle<Object> WasmToJSObject(Isolate* isolate, Handle<Object> value);
}  // namespace wasm
}  // namespace internal
}  // namespace v8

#include "src/objects/object-macros-undef.h"

#endif  // V8_WASM_WASM_OBJECTS_H_

"""


```