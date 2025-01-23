Response:
My thinking process to analyze the provided V8 code snippet goes like this:

1. **Understand the Goal:** The request asks for a functional summary of `v8/src/codegen/code-stub-assembler.cc`, mentions `.tq` files (Torque), seeks JavaScript relevance, asks for logical reasoning examples, common programming errors, and a final summary given its position in a larger series.

2. **Initial Scan for Keywords and Patterns:** I quickly scan the code for recognizable patterns and keywords related to V8's internals:
    * `CodeStubAssembler`: This is the central class, so understanding its methods is key.
    * `TNode`:  Indicates this is within the TurboFan compiler pipeline (TNodes represent compiler IR).
    * `Label`, `Goto`, `Branch`, `BIND`: Control flow constructs within the assembler.
    * `Load`, `Store`: Memory access operations.
    * `IsSetWord32`, `Int32GreaterThan`, etc.: Bitwise and integer operations, likely for manipulating flags and comparing values.
    * `ElementsKind`: Related to JavaScript array types and optimizations.
    * `PromiseHookFlags`, `Isolate::PromiseHookFields`: Features related to asynchronous operations and debugging.
    * `Builtins`: References to built-in JavaScript functions.
    * `SharedFunctionInfo`, `Code`: Core V8 concepts for function representation and compiled code.
    * `Context`, `NativeContext`:  JavaScript execution environments.
    * `Map`: V8's object layout descriptor.
    * `JSArray`, `JSFunction`, `JSReceiver`:  Representations of JavaScript objects.
    * `Runtime::k...`: Calls to V8's runtime functions.
    * `Print`, `PrintErr`: Debugging and logging utilities.
    * `StackCheck`: Security mechanism to prevent stack overflow.
    * `ArrayCreate`, `SetPropertyLength`: Operations related to JavaScript arrays.
    * `TaggedToDirectString`: String conversion logic.
    * `PrototypeCheckAssembler`:  A helper class for optimizing property access based on prototype structure.

3. **Categorize Functionality:** Based on the keywords and patterns, I start grouping the methods into functional categories:
    * **Elements Kind Handling:** Functions like `IsHoleyElementsKind`, `IsElementsKindGreaterThan`, `GetNonRabGsabElementsKind` are clearly about optimizing array operations based on their element types (packed, holey, etc.).
    * **Debugging and Asynchronous Operations:** `IsDebugActive`, `HasAsyncEventDelegate`, `PromiseHookFlags`, and related methods deal with debugging features and asynchronous promise handling.
    * **Builtin Function Loading:** `LoadBuiltin`, `LoadBuiltinDispatchHandle` are for retrieving pointers to pre-compiled V8 functions.
    * **Shared Function Info and Code Retrieval:** `GetSharedFunctionInfoCode` is crucial for understanding how V8 determines the executable code for a function, handling different compilation states (bytecode, compiled code, lazy compilation).
    * **Code Object Manipulation:** `LoadCodeInstructionStart`, `IsMarkedForDeoptimization` deal with properties of compiled code objects.
    * **Object Allocation:** `AllocateRootFunctionWithContext` shows how built-in functions are created.
    * **Prototype Chain Optimization:** `CheckPrototypeEnumCache`, `CheckEnumCache`, `PrototypeCheckAssembler` are dedicated to optimizing property access by verifying the structure and immutability of the prototype chain.
    * **Argument Handling:** `GetArgumentValue`, `SetArgumentValue`, `GetFrameArguments` are for managing function arguments within the assembler.
    * **Debugging and Printing:** `Print`, `PrintErr`, `PrintToStream` provide debugging output.
    * **Stack Management:** `PerformStackCheck` is a security feature.
    * **Array Creation:** `ArrayCreate`, `SetPropertyLength` are for creating and manipulating JavaScript arrays.
    * **Random Number Generation:** `RefillMathRandom` handles the internal state of `Math.random()`.
    * **String Conversion:** `TaggedToDirectString` converts tagged string representations to direct pointers.
    * **Finalization Registry:** `RemoveFinalizationRegistryCellFromUnregisterTokenMap` is related to garbage collection and finalizers.

4. **Address Specific Questions:** Now I go through each specific requirement of the prompt:

    * **Functionality Listing:**  This is the direct outcome of the categorization step. I list the main areas of functionality.
    * **`.tq` Extension:** I note that if the file ended in `.tq`, it would be a Torque file, a higher-level language for writing V8 builtins. This snippet is C++.
    * **JavaScript Relevance:** For each functional category, I consider if and how it relates to JavaScript behavior. For instance, array element kinds directly impact how JavaScript arrays are optimized. Promise hooks are relevant to asynchronous JavaScript code. I then try to create simple JavaScript examples that demonstrate the underlying concepts (e.g., creating arrays with different element types, using Promises).
    * **Code Logic Reasoning:** I pick a few representative functions (like `IsHoleyElementsKind` or `GetSharedFunctionInfoCode`) and illustrate their logic with hypothetical inputs and outputs. This helps demonstrate the conditional nature of the code.
    * **Common Programming Errors:** I think about how the functionality exposed by `CodeStubAssembler` can relate to common JavaScript errors. For example, understanding element kinds helps explain performance differences when working with arrays. Incorrectly assuming prototype immutability could lead to unexpected behavior if optimizations rely on those assumptions.
    * **Part 21 of 23 Summary:** Given that this is the later part of a series, I assume previous parts have established the basic structure and core concepts of the `CodeStubAssembler`. This part seems to focus on higher-level utilities and specific optimizations. Therefore, the summary emphasizes these aspects and their role in efficient JavaScript execution.

5. **Refine and Structure:** Finally, I organize my thoughts into a clear and structured answer, using headings, bullet points, and code examples where appropriate. I try to use precise language and avoid jargon where possible, while still accurately reflecting the technical details. I make sure to explicitly address all the points raised in the original request.

By following these steps, I can systematically analyze the provided C++ code, understand its purpose within the V8 engine, and address all the specific requirements of the prompt. The key is to break down the complex codebase into smaller, manageable functional units and then relate those units back to observable JavaScript behavior.
这是 V8 源代码文件 `v8/src/codegen/code-stub-assembler.cc` 的第 21 部分，共 23 部分。从代码片段来看，它定义了 `CodeStubAssembler` 类的一些方法，这些方法提供了在 V8 的代码生成过程中进行底层操作的能力。

**`CodeStubAssembler` 的主要功能（基于此片段）：**

1. **处理 JavaScript 数组的元素类型 (ElementsKind):**
   - 提供了一系列方法来检查和比较数组的元素类型，例如 `IsHoleyElementsKind`、`IsElementsKindGreaterThan` 等。这对于 V8 优化数组操作非常重要，因为不同类型的数组（例如，存储整数、浮点数、对象等）有不同的内存布局和访问方式。
   - `GetNonRabGsabElementsKind` 看起来是用于处理 `RAB_GSAB`（Resizable ArrayBuffer/Growable SharedArrayBuffer）相关的元素类型。

2. **检查调试和异步事件状态:**
   - `IsDebugActive()` 用于检查调试器是否激活。
   - `HasAsyncEventDelegate()` 用于检查是否存在异步事件委托。

3. **处理 Promise Hook:**
   - 提供了一系列方法来检查 Promise hook 的状态，例如 `PromiseHookFlags`、`IsAnyPromiseHookEnabled`、`IsIsolatePromiseHookEnabled` 等。这些 hook 允许在 Promise 的生命周期中执行自定义代码，用于调试、监控或其他目的。

4. **加载内置函数 (Builtins):**
   - `LoadBuiltin(TNode<Smi> builtin_id)` 用于加载指定 ID 的内置函数的代码。内置函数是 V8 引擎预先编译好的 JavaScript 核心功能实现。
   - `#ifdef V8_ENABLE_LEAPTIERING` 部分的代码 `LoadBuiltinDispatchHandle` 看起来与 V8 的分层编译优化 (Leaptiering) 有关，用于加载内置函数的调度句柄。

5. **获取共享函数信息 (SharedFunctionInfo) 的代码:**
   - `GetSharedFunctionInfoCode` 是一个关键方法，用于根据 `SharedFunctionInfo` 的状态（例如，是否已编译、是字节码还是机器码）来获取函数的执行代码。它处理了多种情况，包括：
     - 解释执行字节码
     - 执行基线代码 (Baseline Code)
     - 执行解释器数据 (Interpreter Data)
     - 延迟编译 (CompileLazy)
     - WebAssembly 函数
     - API 调用
     - `asm.js` 和 WebAssembly 模块的实例化

6. **操作代码对象 (Code Object):**
   - `LoadCodeInstructionStart` 用于加载代码对象的指令起始地址。
   - `IsMarkedForDeoptimization` 用于检查代码是否被标记为需要反优化。

7. **分配根函数 (Root Function):**
   - `AllocateRootFunctionWithContext` 用于分配内置的根级别函数，并将其与特定的上下文关联起来。

8. **检查原型链的枚举缓存:**
   - `CheckPrototypeEnumCache` 和 `CheckEnumCache` 用于优化对象属性枚举过程，通过检查原型链上的枚举缓存来避免不必要的查找。

9. **处理函数参数:**
   - `GetArgumentValue` 和 `SetArgumentValue` 用于获取和设置传递给函数的参数值。
   - `GetFrameArguments` 用于从调用栈帧中获取参数。

10. **打印调试信息:**
    - 提供了一系列 `Print` 和 `PrintErr` 方法，用于在代码生成过程中输出调试信息到标准输出或标准错误。

11. **执行栈检查:**
    - `PerformStackCheck` 用于执行栈溢出检查。

12. **调用运行时函数 (Runtime Functions):**
    - `CallRuntimeNewArray` 和 `TailCallRuntimeNewArray` 用于调用 V8 的运行时函数来创建新的数组。
    - 其他 `CallRuntime` 的调用（例如在 `Print` 方法中）用于执行特定的运行时操作。

13. **创建数组:**
    - `ArrayCreate` 用于创建新的 JavaScript 数组。

14. **设置属性长度:**
    - `SetPropertyLength` 用于设置对象的 `length` 属性。

15. **填充 Math.random 缓存:**
    - `RefillMathRandom` 用于填充 `Math.random()` 使用的随机数缓存。

16. **转换为直接字符串:**
    - `TaggedToDirectString` 用于将 V8 的Tagged表示的字符串转换为可以直接访问的字符串。

17. **操作 FinalizationRegistry:**
    - `RemoveFinalizationRegistryCellFromUnregisterTokenMap` 用于从 `FinalizationRegistry` 中移除相关的弱引用单元。

18. **原型检查助手类 (`PrototypeCheckAssembler`):**
    - 这是一个辅助类，用于检查原型对象是否被修改，常用于优化对象属性访问。它可以检查原型对象的 map 是否相同以及特定属性是否仍然是常量。

**如果 `v8/src/codegen/code-stub-assembler.cc` 以 `.tq` 结尾：**

那么它将是一个 **V8 Torque 源代码**。Torque 是 V8 开发的一种用于定义运行时内置函数和代码存根的领域特定语言。Torque 代码会被编译成 C++ 代码。

**与 JavaScript 的功能关系及示例：**

`CodeStubAssembler` 的功能与 JavaScript 的执行息息相关。它提供了构建执行 JavaScript 代码所需的底层操作。以下是一些与 JavaScript 功能相关的示例：

**1. 数组元素类型优化:**

```javascript
// JavaScript 引擎会尝试根据数组中存储的元素类型进行优化
const arr1 = [1, 2, 3]; // Packed Smi 数组
const arr2 = [1.1, 2.2, 3.3]; // Packed Double 数组
const arr3 = [1, 2, , 4]; // Holey Smi 数组 (存在空洞)
const arr4 = [{}, {}, {}]; // Packed Object 数组

// CodeStubAssembler 中的方法 (如 IsHoleyElementsKind) 用于判断这些数组的类型，
// 并根据类型生成优化的机器码来访问数组元素。
```

**2. Promise Hook:**

```javascript
// 可以使用 Promise hook 来监控 Promise 的状态变化
// (这通常是在 V8 内部或使用特定的调试工具实现的，JavaScript 代码通常不直接访问这些底层 hook)
const promise = Promise.resolve(10);
promise.then(value => console.log("Promise resolved with:", value));

// CodeStubAssembler 中的 Promise hook 相关方法允许 V8 在 Promise 的不同阶段执行额外的操作。
```

**3. 加载内置函数:**

```javascript
// JavaScript 中的一些核心功能，如 Array.prototype.push, Object.prototype.toString 等
// 都是由 V8 的内置函数实现的。

const arr = [];
arr.push(5); // 内部会调用 V8 预先编译好的 Array.prototype.push 的内置函数。

// CodeStubAssembler 中的 LoadBuiltin 方法用于获取这些内置函数的代码指针。
```

**4. 获取共享函数信息和代码:**

```javascript
function foo() {
  return 1 + 2;
}

foo(); // 当 JavaScript 引擎执行 foo() 函数时，
     // CodeStubAssembler 会使用 GetSharedFunctionInfoCode 来决定如何执行：
     // - 如果是第一次执行，可能会编译成机器码。
     // - 如果已经编译，则直接执行已编译的代码。
     // - 如果需要反优化，可能会回退到解释执行。
```

**5. 原型链枚举优化:**

```javascript
const obj = { a: 1 };
const proto = { b: 2 };
Object.setPrototypeOf(obj, proto);

for (let key in obj) {
  console.log(key); // 输出 "a" 和 "b"
}

// CodeStubAssembler 中的 CheckPrototypeEnumCache 等方法用于优化这个枚举过程，
// 尤其是在原型链结构稳定且没有被修改的情况下。
```

**代码逻辑推理示例（`IsHoleyElementsKind`）：**

**假设输入:** `elements_kind` 是一个表示数组元素类型的整数，例如 `PACKED_SMI_ELEMENTS` 或 `HOLEY_ELEMENTS`。

**输出:**  一个布尔值，指示该元素类型是否是 "holely" 的（即允许存在空洞）。

**逻辑:**  `IsHoleyElementsKind` 通过检查 `elements_kind` 的最低位是否为 1 来判断。这是因为 V8 的元素类型常量被设计成 holey 类型的值比对应的 packed 类型的值大 1。

例如：
- 如果 `elements_kind` 是 `HOLEY_SMI_ELEMENTS` (假设其值为 2)，则 `2 | 1 = 3`，`3 & 1 = 1`，返回 `true`。
- 如果 `elements_kind` 是 `PACKED_SMI_ELEMENTS` (假设其值为 0)，则 `0 | 1 = 1`，`1 & 1 = 1`，返回 `true`。  **这里需要注意，代码逻辑的 `IsSetWord32(elements_kind, 1)` 实际上是检查最低位是否为 1，这意味着 `PACKED_SMI_ELEMENTS` 的最低位应该是 0，`HOLEY_SMI_ELEMENTS` 的最低位是 1。**

**更正后的代码逻辑推理（`IsHoleyElementsKind`）：**

**假设输入:** `elements_kind` 是一个表示数组元素类型的整数，例如 `PACKED_SMI_ELEMENTS` 或 `HOLEY_SMI_ELEMENTS`.

**输出:**  一个布尔值，指示该元素类型是否是 "holely" 的。

**逻辑:** `IsHoleyElementsKind` 使用 `IsSetWord32(elements_kind, 1)` 来检查 `elements_kind` 的最低位是否为 1。根据 `static_assert` 的断言，holely 类型的元素种类的最低位是 1。

例如：
- 如果 `elements_kind` 是 `HOLEY_SMI_ELEMENTS` (假设其二进制表示的最低位是 1)，则 `IsSetWord32` 返回 `true`。
- 如果 `elements_kind` 是 `PACKED_SMI_ELEMENTS` (假设其二进制表示的最低位是 0)，则 `IsSetWord32` 返回 `false`。

**用户常见的编程错误示例：**

1. **不理解数组元素类型带来的性能影响:**

   ```javascript
   const arr = [];
   arr.push(1);
   arr.push("hello"); // 导致数组元素类型从 Smi 变为 Object，可能影响性能

   // V8 内部会根据数组的元素类型选择不同的优化策略。
   // 频繁地改变数组中元素的类型可能会导致性能下降。
   ```

2. **过度依赖原型链上的动态修改:**

   ```javascript
   function MyClass() {}
   MyClass.prototype.getValue = function() { return this.value; };

   const obj1 = new MyClass();
   obj1.value = 10;
   console.log(obj1.getValue()); // 10

   // 在运行时修改原型可能会使 V8 的原型链枚举缓存失效，
   // 导致后续的属性访问变慢。
   MyClass.prototype.getValue = function() { return this.value * 2; };
   const obj2 = new MyClass();
   obj2.value = 5;
   console.log(obj2.getValue()); // 10

   // CodeStubAssembler 中的原型检查机制旨在优化稳定的原型链结构。
   ```

**作为第 21 部分的功能归纳:**

作为系列的一部分，`v8/src/codegen/code-stub-assembler.cc` 的第 21 部分着重于提供 **高级的辅助功能和优化手段**，用于在 V8 的代码生成过程中处理更复杂的场景，例如：

- **针对特定 JavaScript 特性的优化:** 例如，针对不同元素类型数组和 Promise 的优化。
- **与 V8 内部机制的交互:** 例如，加载内置函数、访问共享函数信息、进行栈检查等。
- **支持调试和监控:** 例如，检查调试状态和 Promise hook。
- **提供构建复杂代码存根的基础:**  这些方法可以被其他代码生成逻辑调用，以实现更精细的控制和优化。

总而言之，这部分代码展示了 `CodeStubAssembler` 在 V8 代码生成过程中扮演的关键角色，它封装了许多底层的操作和优化策略，使得 V8 能够高效地执行 JavaScript 代码。它连接了高级的 JavaScript 概念（如数组、Promise、函数）与底层的机器码生成过程。

### 提示词
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第21部分，共23部分，请归纳一下它的功能
```

### 源代码
```cpp
(PACKED_NONEXTENSIBLE_ELEMENTS | 1));
  static_assert(HOLEY_SEALED_ELEMENTS == (PACKED_SEALED_ELEMENTS | 1));
  static_assert(HOLEY_FROZEN_ELEMENTS == (PACKED_FROZEN_ELEMENTS | 1));
  return IsSetWord32(elements_kind, 1);
}

TNode<BoolT> CodeStubAssembler::IsElementsKindGreaterThan(
    TNode<Int32T> target_kind, ElementsKind reference_kind) {
  return Int32GreaterThan(target_kind, Int32Constant(reference_kind));
}

TNode<BoolT> CodeStubAssembler::IsElementsKindGreaterThanOrEqual(
    TNode<Int32T> target_kind, ElementsKind reference_kind) {
  return Int32GreaterThanOrEqual(target_kind, Int32Constant(reference_kind));
}

TNode<BoolT> CodeStubAssembler::IsElementsKindLessThanOrEqual(
    TNode<Int32T> target_kind, ElementsKind reference_kind) {
  return Int32LessThanOrEqual(target_kind, Int32Constant(reference_kind));
}

TNode<Int32T> CodeStubAssembler::GetNonRabGsabElementsKind(
    TNode<Int32T> elements_kind) {
  Label is_rab_gsab(this), end(this);
  TVARIABLE(Int32T, result);
  result = elements_kind;
  Branch(Int32GreaterThanOrEqual(elements_kind,
                                 Int32Constant(RAB_GSAB_UINT8_ELEMENTS)),
         &is_rab_gsab, &end);
  BIND(&is_rab_gsab);
  result = Int32Sub(elements_kind,
                    Int32Constant(RAB_GSAB_UINT8_ELEMENTS - UINT8_ELEMENTS));
  Goto(&end);
  BIND(&end);
  return result.value();
}

TNode<BoolT> CodeStubAssembler::IsDebugActive() {
  TNode<Uint8T> is_debug_active = Load<Uint8T>(
      ExternalConstant(ExternalReference::debug_is_active_address(isolate())));
  return Word32NotEqual(is_debug_active, Int32Constant(0));
}

TNode<BoolT> CodeStubAssembler::HasAsyncEventDelegate() {
  const TNode<RawPtrT> async_event_delegate = Load<RawPtrT>(ExternalConstant(
      ExternalReference::async_event_delegate_address(isolate())));
  return WordNotEqual(async_event_delegate, IntPtrConstant(0));
}

TNode<Uint32T> CodeStubAssembler::PromiseHookFlags() {
  return Load<Uint32T>(ExternalConstant(
    ExternalReference::promise_hook_flags_address(isolate())));
}

TNode<BoolT> CodeStubAssembler::IsAnyPromiseHookEnabled(TNode<Uint32T> flags) {
  uint32_t mask = Isolate::PromiseHookFields::HasContextPromiseHook::kMask |
                  Isolate::PromiseHookFields::HasIsolatePromiseHook::kMask;
  return IsSetWord32(flags, mask);
}

TNode<BoolT> CodeStubAssembler::IsIsolatePromiseHookEnabled(
    TNode<Uint32T> flags) {
  return IsSetWord32<Isolate::PromiseHookFields::HasIsolatePromiseHook>(flags);
}

#ifdef V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
TNode<BoolT> CodeStubAssembler::IsContextPromiseHookEnabled(
    TNode<Uint32T> flags) {
  return IsSetWord32<Isolate::PromiseHookFields::HasContextPromiseHook>(flags);
}
#endif

TNode<BoolT>
CodeStubAssembler::IsIsolatePromiseHookEnabledOrHasAsyncEventDelegate(
    TNode<Uint32T> flags) {
  uint32_t mask = Isolate::PromiseHookFields::HasIsolatePromiseHook::kMask |
                  Isolate::PromiseHookFields::HasAsyncEventDelegate::kMask;
  return IsSetWord32(flags, mask);
}

TNode<BoolT> CodeStubAssembler::
    IsIsolatePromiseHookEnabledOrDebugIsActiveOrHasAsyncEventDelegate(
        TNode<Uint32T> flags) {
  uint32_t mask = Isolate::PromiseHookFields::HasIsolatePromiseHook::kMask |
                  Isolate::PromiseHookFields::HasAsyncEventDelegate::kMask |
                  Isolate::PromiseHookFields::IsDebugActive::kMask;
  return IsSetWord32(flags, mask);
}

TNode<BoolT> CodeStubAssembler::NeedsAnyPromiseHooks(TNode<Uint32T> flags) {
  return Word32NotEqual(flags, Int32Constant(0));
}

TNode<Code> CodeStubAssembler::LoadBuiltin(TNode<Smi> builtin_id) {
  CSA_DCHECK(this, SmiBelow(builtin_id, SmiConstant(Builtins::kBuiltinCount)));

  TNode<IntPtrT> offset =
      ElementOffsetFromIndex(SmiToBInt(builtin_id), SYSTEM_POINTER_ELEMENTS);

  TNode<ExternalReference> table = IsolateField(IsolateFieldId::kBuiltinTable);

  return CAST(BitcastWordToTagged(Load<RawPtrT>(table, offset)));
}

#ifdef V8_ENABLE_LEAPTIERING
TNode<JSDispatchHandleT> CodeStubAssembler::LoadBuiltinDispatchHandle(
    JSBuiltinDispatchHandleRoot::Idx dispatch_root_idx) {
  static_assert(Isolate::kBuiltinDispatchHandlesAreStatic);
  DCHECK_LT(dispatch_root_idx, JSBuiltinDispatchHandleRoot::Idx::kCount);
  return ReinterpretCast<JSDispatchHandleT>(
      Uint32Constant(isolate()->builtin_dispatch_handle(dispatch_root_idx)));
}
#endif  // V8_ENABLE_LEAPTIERING

TNode<Code> CodeStubAssembler::GetSharedFunctionInfoCode(
    TNode<SharedFunctionInfo> shared_info, TVariable<Uint16T>* data_type_out,
    Label* if_compile_lazy) {

  Label done(this);
  Label use_untrusted_data(this);
  Label unknown_data(this);
  TVARIABLE(Code, sfi_code);

  TNode<Object> sfi_data = LoadSharedFunctionInfoTrustedData(shared_info);
  GotoIf(TaggedEqual(sfi_data, SmiConstant(0)), &use_untrusted_data);
  {
    TNode<Uint16T> data_type = LoadInstanceType(CAST(sfi_data));
    if (data_type_out) {
      *data_type_out = data_type;
    }

    int32_t case_values[] = {
        BYTECODE_ARRAY_TYPE,
        CODE_TYPE,
        INTERPRETER_DATA_TYPE,
        UNCOMPILED_DATA_WITHOUT_PREPARSE_DATA_TYPE,
        UNCOMPILED_DATA_WITH_PREPARSE_DATA_TYPE,
        UNCOMPILED_DATA_WITHOUT_PREPARSE_DATA_WITH_JOB_TYPE,
        UNCOMPILED_DATA_WITH_PREPARSE_DATA_AND_JOB_TYPE,
#if V8_ENABLE_WEBASSEMBLY
        WASM_CAPI_FUNCTION_DATA_TYPE,
        WASM_EXPORTED_FUNCTION_DATA_TYPE,
        WASM_JS_FUNCTION_DATA_TYPE,
#endif  // V8_ENABLE_WEBASSEMBLY
    };
    Label check_is_bytecode_array(this);
    Label check_is_baseline_data(this);
    Label check_is_interpreter_data(this);
    Label check_is_uncompiled_data(this);
    Label check_is_wasm_function_data(this);
    Label* case_labels[] = {
        &check_is_bytecode_array,     &check_is_baseline_data,
        &check_is_interpreter_data,   &check_is_uncompiled_data,
        &check_is_uncompiled_data,    &check_is_uncompiled_data,
        &check_is_uncompiled_data,
#if V8_ENABLE_WEBASSEMBLY
        &check_is_wasm_function_data, &check_is_wasm_function_data,
        &check_is_wasm_function_data,
#endif  // V8_ENABLE_WEBASSEMBLY
    };
    static_assert(arraysize(case_values) == arraysize(case_labels));
    Switch(data_type, &unknown_data, case_values, case_labels,
           arraysize(case_labels));

    // IsBytecodeArray: Interpret bytecode
    BIND(&check_is_bytecode_array);
    sfi_code =
        HeapConstantNoHole(BUILTIN_CODE(isolate(), InterpreterEntryTrampoline));
    Goto(&done);

    // IsBaselineData: Execute baseline code
    BIND(&check_is_baseline_data);
    {
      TNode<Code> baseline_code = CAST(sfi_data);
      sfi_code = baseline_code;
      Goto(&done);
    }

    // IsInterpreterData: Interpret bytecode
    BIND(&check_is_interpreter_data);
    {
      TNode<Code> trampoline = CAST(LoadProtectedPointerField(
          CAST(sfi_data), InterpreterData::kInterpreterTrampolineOffset));
      sfi_code = trampoline;
    }
    Goto(&done);

    // IsUncompiledDataWithPreparseData | IsUncompiledDataWithoutPreparseData:
    // Compile lazy
    BIND(&check_is_uncompiled_data);
    sfi_code = HeapConstantNoHole(BUILTIN_CODE(isolate(), CompileLazy));
    Goto(if_compile_lazy ? if_compile_lazy : &done);

#if V8_ENABLE_WEBASSEMBLY
    // IsWasmFunctionData: Use the wrapper code
    BIND(&check_is_wasm_function_data);
    sfi_code = CAST(LoadObjectField(
        CAST(sfi_data), WasmExportedFunctionData::kWrapperCodeOffset));
    Goto(&done);
#endif  // V8_ENABLE_WEBASSEMBLY
  }

  BIND(&use_untrusted_data);
  {
    sfi_data = LoadSharedFunctionInfoUntrustedData(shared_info);
    Label check_instance_type(this);

    // IsSmi: Is builtin
    GotoIf(TaggedIsNotSmi(sfi_data), &check_instance_type);
    if (data_type_out) {
      *data_type_out = Uint16Constant(0);
    }
    if (if_compile_lazy) {
      GotoIf(SmiEqual(CAST(sfi_data), SmiConstant(Builtin::kCompileLazy)),
             if_compile_lazy);
    }
    sfi_code = LoadBuiltin(CAST(sfi_data));
    Goto(&done);

    // Switch on data's instance type.
    BIND(&check_instance_type);
    TNode<Uint16T> data_type = LoadInstanceType(CAST(sfi_data));
    if (data_type_out) {
      *data_type_out = data_type;
    }

    int32_t case_values[] = {
        FUNCTION_TEMPLATE_INFO_TYPE,
#if V8_ENABLE_WEBASSEMBLY
        ASM_WASM_DATA_TYPE,
        WASM_RESUME_DATA_TYPE,
#endif  // V8_ENABLE_WEBASSEMBLY
    };
    Label check_is_function_template_info(this);
    Label check_is_asm_wasm_data(this);
    Label check_is_wasm_resume(this);
    Label* case_labels[] = {
        &check_is_function_template_info,
#if V8_ENABLE_WEBASSEMBLY
        &check_is_asm_wasm_data,
        &check_is_wasm_resume,
#endif  // V8_ENABLE_WEBASSEMBLY
    };
    static_assert(arraysize(case_values) == arraysize(case_labels));
    Switch(data_type, &unknown_data, case_values, case_labels,
           arraysize(case_labels));

    // IsFunctionTemplateInfo: API call
    BIND(&check_is_function_template_info);
    sfi_code =
        HeapConstantNoHole(BUILTIN_CODE(isolate(), HandleApiCallOrConstruct));
    Goto(&done);

#if V8_ENABLE_WEBASSEMBLY
    // IsAsmWasmData: Instantiate using AsmWasmData
    BIND(&check_is_asm_wasm_data);
    sfi_code = HeapConstantNoHole(BUILTIN_CODE(isolate(), InstantiateAsmJs));
    Goto(&done);

    // IsWasmResumeData: Resume the suspended wasm continuation.
    BIND(&check_is_wasm_resume);
    sfi_code = HeapConstantNoHole(BUILTIN_CODE(isolate(), WasmResume));
    Goto(&done);
#endif  // V8_ENABLE_WEBASSEMBLY
  }

  BIND(&unknown_data);
  Unreachable();

  BIND(&done);
  return sfi_code.value();
}

TNode<RawPtrT> CodeStubAssembler::LoadCodeInstructionStart(
    TNode<Code> code, CodeEntrypointTag tag) {
#ifdef V8_ENABLE_SANDBOX
  // In this case, the entrypoint is stored in the code pointer table entry
  // referenced via the Code object's 'self' indirect pointer.
  return LoadCodeEntrypointViaCodePointerField(
      code, Code::kSelfIndirectPointerOffset, tag);
#else
  return LoadObjectField<RawPtrT>(code, Code::kInstructionStartOffset);
#endif
}

TNode<BoolT> CodeStubAssembler::IsMarkedForDeoptimization(TNode<Code> code) {
  static_assert(FIELD_SIZE(Code::kFlagsOffset) * kBitsPerByte == 32);
  return IsSetWord32<Code::MarkedForDeoptimizationField>(
      LoadObjectField<Int32T>(code, Code::kFlagsOffset));
}

TNode<JSFunction> CodeStubAssembler::AllocateRootFunctionWithContext(
    RootIndex function, TNode<Context> context,
    std::optional<TNode<NativeContext>> maybe_native_context) {
  DCHECK_GE(function, RootIndex::kFirstBuiltinWithSfiRoot);
  DCHECK_LE(function, RootIndex::kLastBuiltinWithSfiRoot);
  DCHECK(v8::internal::IsSharedFunctionInfo(
      isolate()->root(function).GetHeapObject()));
  Tagged<SharedFunctionInfo> sfi = v8::internal::Cast<SharedFunctionInfo>(
      isolate()->root(function).GetHeapObject());
  const TNode<SharedFunctionInfo> sfi_obj =
      UncheckedCast<SharedFunctionInfo>(LoadRoot(function));
  const TNode<NativeContext> native_context =
      maybe_native_context ? *maybe_native_context : LoadNativeContext(context);
  const TNode<Map> map = CAST(LoadContextElement(
      native_context, Context::STRICT_FUNCTION_WITHOUT_PROTOTYPE_MAP_INDEX));
  const TNode<HeapObject> fun = Allocate(JSFunction::kSizeWithoutPrototype);
  static_assert(JSFunction::kSizeWithoutPrototype == 7 * kTaggedSize);
  StoreMapNoWriteBarrier(fun, map);
  StoreObjectFieldRoot(fun, JSObject::kPropertiesOrHashOffset,
                       RootIndex::kEmptyFixedArray);
  StoreObjectFieldRoot(fun, JSObject::kElementsOffset,
                       RootIndex::kEmptyFixedArray);
  StoreObjectFieldRoot(fun, JSFunction::kFeedbackCellOffset,
                       RootIndex::kManyClosuresCell);
  StoreObjectFieldNoWriteBarrier(fun, JSFunction::kSharedFunctionInfoOffset,
                                 sfi_obj);
  StoreObjectFieldNoWriteBarrier(fun, JSFunction::kContextOffset, context);
  // For the native closures that are initialized here we statically know their
  // builtin id, so there's no need to use
  // CodeStubAssembler::GetSharedFunctionInfoCode().
  DCHECK(sfi->HasBuiltinId());
#ifdef V8_ENABLE_LEAPTIERING
  const TNode<JSDispatchHandleT> dispatch_handle =
      LoadBuiltinDispatchHandle(function);
  CSA_DCHECK(this,
             TaggedEqual(LoadBuiltin(SmiConstant(sfi->builtin_id())),
                         LoadCodeObjectFromJSDispatchTable(dispatch_handle)));
  StoreObjectFieldNoWriteBarrier(fun, JSFunction::kDispatchHandleOffset,
                                 dispatch_handle);
  USE(sfi);
#else
  const TNode<Code> code = LoadBuiltin(SmiConstant(sfi->builtin_id()));
  StoreCodePointerFieldNoWriteBarrier(fun, JSFunction::kCodeOffset, code);
#endif  // V8_ENABLE_LEAPTIERING

  return CAST(fun);
}

void CodeStubAssembler::CheckPrototypeEnumCache(TNode<JSReceiver> receiver,
                                                TNode<Map> receiver_map,
                                                Label* if_fast,
                                                Label* if_slow) {
  TVARIABLE(JSReceiver, var_object, receiver);
  TVARIABLE(Map, object_map, receiver_map);

  Label loop(this, {&var_object, &object_map}), done_loop(this);
  Goto(&loop);
  BIND(&loop);
  {
    // Check that there are no elements on the current {var_object}.
    Label if_no_elements(this);

    // The following relies on the elements only aliasing with JSProxy::target,
    // which is a JavaScript value and hence cannot be confused with an elements
    // backing store.
    static_assert(static_cast<int>(JSObject::kElementsOffset) ==
                  static_cast<int>(JSProxy::kTargetOffset));
    TNode<Object> object_elements =
        LoadObjectField(var_object.value(), JSObject::kElementsOffset);
    GotoIf(IsEmptyFixedArray(object_elements), &if_no_elements);
    GotoIf(IsEmptySlowElementDictionary(object_elements), &if_no_elements);

    // It might still be an empty JSArray.
    GotoIfNot(IsJSArrayMap(object_map.value()), if_slow);
    TNode<Number> object_length = LoadJSArrayLength(CAST(var_object.value()));
    Branch(TaggedEqual(object_length, SmiConstant(0)), &if_no_elements,
           if_slow);

    // Continue with {var_object}'s prototype.
    BIND(&if_no_elements);
    TNode<HeapObject> object = LoadMapPrototype(object_map.value());
    GotoIf(IsNull(object), if_fast);

    // For all {object}s but the {receiver}, check that the cache is empty.
    var_object = CAST(object);
    object_map = LoadMap(object);
    TNode<Uint32T> object_enum_length = LoadMapEnumLength(object_map.value());
    Branch(Word32Equal(object_enum_length, Uint32Constant(0)), &loop, if_slow);
  }
}

TNode<Map> CodeStubAssembler::CheckEnumCache(TNode<JSReceiver> receiver,
                                             Label* if_empty,
                                             Label* if_runtime) {
  Label if_fast(this), if_cache(this), if_no_cache(this, Label::kDeferred);
  TNode<Map> receiver_map = LoadMap(receiver);

  // Check if the enum length field of the {receiver} is properly initialized,
  // indicating that there is an enum cache.
  TNode<Uint32T> receiver_enum_length = LoadMapEnumLength(receiver_map);
  Branch(Word32Equal(receiver_enum_length,
                     Uint32Constant(kInvalidEnumCacheSentinel)),
         &if_no_cache, &if_cache);

  BIND(&if_no_cache);
  {
    // Avoid runtime-call for empty dictionary receivers.
    GotoIfNot(IsDictionaryMap(receiver_map), if_runtime);
    TNode<Smi> length;
    TNode<HeapObject> properties = LoadSlowProperties(receiver);

    // g++ version 8 has a bug when using `if constexpr(false)` with a lambda:
    // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=85149
    // TODO(miladfarca): Use `if constexpr` once all compilers handle this
    // properly.
    CSA_DCHECK(this, Word32Or(IsPropertyDictionary(properties),
                              IsGlobalDictionary(properties)));
    if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      length = Select<Smi>(
          IsPropertyDictionary(properties),
          [=, this] {
            return GetNumberOfElements(
                UncheckedCast<PropertyDictionary>(properties));
          },
          [=, this] {
            return GetNumberOfElements(
                UncheckedCast<GlobalDictionary>(properties));
          });

    } else {
      static_assert(static_cast<int>(NameDictionary::kNumberOfElementsIndex) ==
                    static_cast<int>(GlobalDictionary::kNumberOfElementsIndex));
      length = GetNumberOfElements(UncheckedCast<HashTableBase>(properties));
    }

    GotoIfNot(TaggedEqual(length, SmiConstant(0)), if_runtime);
    // Check that there are no elements on the {receiver} and its prototype
    // chain. Given that we do not create an EnumCache for dict-mode objects,
    // directly jump to {if_empty} if there are no elements and no properties
    // on the {receiver}.
    CheckPrototypeEnumCache(receiver, receiver_map, if_empty, if_runtime);
  }

  // Check that there are no elements on the fast {receiver} and its
  // prototype chain.
  BIND(&if_cache);
  CheckPrototypeEnumCache(receiver, receiver_map, &if_fast, if_runtime);

  BIND(&if_fast);
  return receiver_map;
}

TNode<Object> CodeStubAssembler::GetArgumentValue(TorqueStructArguments args,
                                                  TNode<IntPtrT> index) {
  return CodeStubArguments(this, args).GetOptionalArgumentValue(index);
}

void CodeStubAssembler::SetArgumentValue(TorqueStructArguments args,
                                         TNode<IntPtrT> index,
                                         TNode<Object> value) {
  CodeStubArguments(this, args).SetArgumentValue(index, value);
}

TorqueStructArguments CodeStubAssembler::GetFrameArguments(
    TNode<RawPtrT> frame, TNode<IntPtrT> argc,
    FrameArgumentsArgcType argc_type) {
  if (argc_type == FrameArgumentsArgcType::kCountExcludesReceiver) {
    argc = IntPtrAdd(argc, IntPtrConstant(kJSArgcReceiverSlots));
  }
  return CodeStubArguments(this, argc, frame).GetTorqueArguments();
}

void CodeStubAssembler::Print(const char* s) {
  PrintToStream(s, fileno(stdout));
}

void CodeStubAssembler::PrintErr(const char* s) {
  PrintToStream(s, fileno(stderr));
}

void CodeStubAssembler::PrintToStream(const char* s, int stream) {
  std::string formatted(s);
  formatted += "\n";
  CallRuntime(Runtime::kGlobalPrint, NoContextConstant(),
              StringConstant(formatted.c_str()), SmiConstant(stream));
}

void CodeStubAssembler::Print(const char* prefix,
                              TNode<MaybeObject> tagged_value) {
  PrintToStream(prefix, tagged_value, fileno(stdout));
}

void CodeStubAssembler::Print(const char* prefix, TNode<UintPtrT> value) {
  PrintToStream(prefix, value, fileno(stdout));
}

void CodeStubAssembler::Print(const char* prefix, TNode<Float64T> value) {
  PrintToStream(prefix, value, fileno(stdout));
}

void CodeStubAssembler::PrintErr(const char* prefix,
                                 TNode<MaybeObject> tagged_value) {
  PrintToStream(prefix, tagged_value, fileno(stderr));
}

void CodeStubAssembler::PrintToStream(const char* prefix,
                                      TNode<MaybeObject> tagged_value,
                                      int stream) {
  if (prefix != nullptr) {
    std::string formatted(prefix);
    formatted += ": ";
    Handle<String> string =
        isolate()->factory()->InternalizeString(formatted.c_str());
    CallRuntime(Runtime::kGlobalPrint, NoContextConstant(),
                HeapConstantNoHole(string), SmiConstant(stream));
  }
  // CallRuntime only accepts Objects, so do an UncheckedCast to object.
  // DebugPrint explicitly checks whether the tagged value is a
  // Tagged<MaybeObject>.
  TNode<Object> arg = UncheckedCast<Object>(tagged_value);
  CallRuntime(Runtime::kDebugPrint, NoContextConstant(), arg,
              SmiConstant(stream));
}

void CodeStubAssembler::PrintToStream(const char* prefix, TNode<UintPtrT> value,
                                      int stream) {
  if (prefix != nullptr) {
    std::string formatted(prefix);
    formatted += ": ";
    Handle<String> string =
        isolate()->factory()->InternalizeString(formatted.c_str());
    CallRuntime(Runtime::kGlobalPrint, NoContextConstant(),
                HeapConstantNoHole(string), SmiConstant(stream));
  }

  // We use 16 bit per chunk.
  TNode<Smi> chunks[4];
  for (int i = 0; i < 4; ++i) {
    chunks[i] = SmiFromUint32(ReinterpretCast<Uint32T>(Word32And(
        TruncateIntPtrToInt32(ReinterpretCast<IntPtrT>(value)), 0xFFFF)));
    value = WordShr(value, IntPtrConstant(16));
  }

  // Args are: <bits 63-48>, <bits 47-32>, <bits 31-16>, <bits 15-0>, stream.
  CallRuntime(Runtime::kDebugPrintWord, NoContextConstant(), chunks[3],
              chunks[2], chunks[1], chunks[0], SmiConstant(stream));
}

void CodeStubAssembler::PrintToStream(const char* prefix, TNode<Float64T> value,
                                      int stream) {
  if (prefix != nullptr) {
    std::string formatted(prefix);
    formatted += ": ";
    Handle<String> string =
        isolate()->factory()->InternalizeString(formatted.c_str());
    CallRuntime(Runtime::kGlobalPrint, NoContextConstant(),
                HeapConstantNoHole(string), SmiConstant(stream));
  }

  // We use word32 extraction instead of `BitcastFloat64ToInt64` to support 32
  // bit architectures, too.
  TNode<Uint32T> high = Float64ExtractHighWord32(value);
  TNode<Uint32T> low = Float64ExtractLowWord32(value);

  // We use 16 bit per chunk.
  TNode<Smi> chunks[4];
  chunks[0] = SmiFromUint32(ReinterpretCast<Uint32T>(Word32And(low, 0xFFFF)));
  chunks[1] = SmiFromUint32(ReinterpretCast<Uint32T>(
      Word32And(Word32Shr(low, Int32Constant(16)), 0xFFFF)));
  chunks[2] = SmiFromUint32(ReinterpretCast<Uint32T>(Word32And(high, 0xFFFF)));
  chunks[3] = SmiFromUint32(ReinterpretCast<Uint32T>(
      Word32And(Word32Shr(high, Int32Constant(16)), 0xFFFF)));

  // Args are: <bits 63-48>, <bits 47-32>, <bits 31-16>, <bits 15-0>, stream.
  CallRuntime(Runtime::kDebugPrintFloat, NoContextConstant(), chunks[3],
              chunks[2], chunks[1], chunks[0], SmiConstant(stream));
}

IntegerLiteral CodeStubAssembler::ConstexprIntegerLiteralAdd(
    const IntegerLiteral& lhs, const IntegerLiteral& rhs) {
  return lhs + rhs;
}
IntegerLiteral CodeStubAssembler::ConstexprIntegerLiteralLeftShift(
    const IntegerLiteral& lhs, const IntegerLiteral& rhs) {
  return lhs << rhs;
}
IntegerLiteral CodeStubAssembler::ConstexprIntegerLiteralBitwiseOr(
    const IntegerLiteral& lhs, const IntegerLiteral& rhs) {
  return lhs | rhs;
}

void CodeStubAssembler::PerformStackCheck(TNode<Context> context) {
  Label ok(this), stack_check_interrupt(this, Label::kDeferred);

  TNode<UintPtrT> stack_limit = UncheckedCast<UintPtrT>(
      Load(MachineType::Pointer(),
           ExternalConstant(ExternalReference::address_of_jslimit(isolate()))));
  TNode<BoolT> sp_within_limit = StackPointerGreaterThan(stack_limit);

  Branch(sp_within_limit, &ok, &stack_check_interrupt);

  BIND(&stack_check_interrupt);
  CallRuntime(Runtime::kStackGuard, context);
  Goto(&ok);

  BIND(&ok);
}

TNode<Object> CodeStubAssembler::CallRuntimeNewArray(
    TNode<Context> context, TNode<Object> receiver, TNode<Object> length,
    TNode<Object> new_target, TNode<Object> allocation_site) {
  // Runtime_NewArray receives arguments in the JS order (to avoid unnecessary
  // copy). Except the last two (new_target and allocation_site) which are add
  // on top of the stack later.
  return CallRuntime(Runtime::kNewArray, context, length, receiver, new_target,
                     allocation_site);
}

void CodeStubAssembler::TailCallRuntimeNewArray(TNode<Context> context,
                                                TNode<Object> receiver,
                                                TNode<Object> length,
                                                TNode<Object> new_target,
                                                TNode<Object> allocation_site) {
  // Runtime_NewArray receives arguments in the JS order (to avoid unnecessary
  // copy). Except the last two (new_target and allocation_site) which are add
  // on top of the stack later.
  return TailCallRuntime(Runtime::kNewArray, context, length, receiver,
                         new_target, allocation_site);
}

TNode<JSArray> CodeStubAssembler::ArrayCreate(TNode<Context> context,
                                              TNode<Number> length) {
  TVARIABLE(JSArray, array);
  Label allocate_js_array(this);

  Label done(this), next(this), runtime(this, Label::kDeferred);
  TNode<Smi> limit = SmiConstant(JSArray::kInitialMaxFastElementArray);
  CSA_DCHECK_BRANCH(this, ([=, this](Label* ok, Label* not_ok) {
                      BranchIfNumberRelationalComparison(
                          Operation::kGreaterThanOrEqual, length,
                          SmiConstant(0), ok, not_ok);
                    }));
  // This check also transitively covers the case where length is too big
  // to be representable by a SMI and so is not usable with
  // AllocateJSArray.
  BranchIfNumberRelationalComparison(Operation::kGreaterThanOrEqual, length,
                                     limit, &runtime, &next);

  BIND(&runtime);
  {
    TNode<NativeContext> native_context = LoadNativeContext(context);
    TNode<JSFunction> array_function =
        CAST(LoadContextElement(native_context, Context::ARRAY_FUNCTION_INDEX));
    array = CAST(CallRuntimeNewArray(context, array_function, length,
                                     array_function, UndefinedConstant()));
    Goto(&done);
  }

  BIND(&next);
  TNode<Smi> length_smi = CAST(length);

  TNode<Map> array_map = CAST(LoadContextElement(
      context, Context::JS_ARRAY_PACKED_SMI_ELEMENTS_MAP_INDEX));

  // TODO(delphick): Consider using
  // AllocateUninitializedJSArrayWithElements to avoid initializing an
  // array and then writing over it.
  array = AllocateJSArray(PACKED_SMI_ELEMENTS, array_map, length_smi,
                          SmiConstant(0));
  Goto(&done);

  BIND(&done);
  return array.value();
}

void CodeStubAssembler::SetPropertyLength(TNode<Context> context,
                                          TNode<Object> array,
                                          TNode<Number> length) {
  SetPropertyStrict(context, array, CodeStubAssembler::LengthStringConstant(),
                    length);
}

TNode<Smi> CodeStubAssembler::RefillMathRandom(
    TNode<NativeContext> native_context) {
  // Cache exhausted, populate the cache. Return value is the new index.
  const TNode<ExternalReference> refill_math_random =
      ExternalConstant(ExternalReference::refill_math_random());
  const TNode<ExternalReference> isolate_ptr =
      ExternalConstant(ExternalReference::isolate_address());
  MachineType type_tagged = MachineType::AnyTagged();
  MachineType type_ptr = MachineType::Pointer();

  return CAST(CallCFunction(refill_math_random, type_tagged,
                            std::make_pair(type_ptr, isolate_ptr),
                            std::make_pair(type_tagged, native_context)));
}

TNode<String> CodeStubAssembler::TaggedToDirectString(TNode<Object> value,
                                                      Label* fail) {
  ToDirectStringAssembler to_direct(state(), CAST(value));
  to_direct.TryToDirect(fail);
  to_direct.PointerToData(fail);
  return CAST(value);
}

void CodeStubAssembler::RemoveFinalizationRegistryCellFromUnregisterTokenMap(
    TNode<JSFinalizationRegistry> finalization_registry,
    TNode<WeakCell> weak_cell) {
  const TNode<ExternalReference> remove_cell = ExternalConstant(
      ExternalReference::
          js_finalization_registry_remove_cell_from_unregister_token_map());
  const TNode<ExternalReference> isolate_ptr =
      ExternalConstant(ExternalReference::isolate_address());

  CallCFunction(remove_cell, MachineType::Pointer(),
                std::make_pair(MachineType::Pointer(), isolate_ptr),
                std::make_pair(MachineType::AnyTagged(), finalization_registry),
                std::make_pair(MachineType::AnyTagged(), weak_cell));
}

PrototypeCheckAssembler::PrototypeCheckAssembler(
    compiler::CodeAssemblerState* state, Flags flags,
    TNode<NativeContext> native_context, TNode<Map> initial_prototype_map,
    base::Vector<DescriptorIndexNameValue> properties)
    : CodeStubAssembler(state),
      flags_(flags),
      native_context_(native_context),
      initial_prototype_map_(initial_prototype_map),
      properties_(properties) {}

void PrototypeCheckAssembler::CheckAndBranch(TNode<HeapObject> prototype,
                                             Label* if_unmodified,
                                             Label* if_modified) {
  TNode<Map> prototype_map = LoadMap(prototype);
  TNode<DescriptorArray> descriptors = LoadMapDescriptors(prototype_map);

  // The continuation of a failed fast check: if property identity checks are
  // enabled, we continue there (since they may still classify the prototype as
  // fast), otherwise we bail out.
  Label property_identity_check(this, Label::kDeferred);
  Label* if_fast_check_failed =
      ((flags_ & kCheckPrototypePropertyIdentity) == 0)
          ? if_modified
          : &property_identity_check;

  if ((flags_ & kCheckPrototypePropertyConstness) != 0) {
    // A simple prototype map identity check. Note that map identity does not
    // guarantee unmodified properties. It does guarantee that no new properties
    // have been added, or old properties deleted.

    GotoIfNot(TaggedEqual(prototype_map, initial_prototype_map_),
              if_fast_check_failed);

    // We need to make sure that relevant properties in the prototype have
    // not been tampered with. We do this by checking that their slots
    // in the prototype's descriptor array are still marked as const.

    TNode<Uint32T> combined_details;
    for (int i = 0; i < properties_.length(); i++) {
      // Assert the descriptor index is in-bounds.
      int descriptor = properties_[i].descriptor_index;
      CSA_DCHECK(this, Int32LessThan(Int32Constant(descriptor),
                                     LoadNumberOfDescriptors(descriptors)));

      // Assert that the name is correct. This essentially checks that
      // the descriptor index corresponds to the insertion order in
      // the bootstrapper.
      CSA_DCHECK(
          this,
          TaggedEqual(LoadKeyByDescriptorEntry(descriptors, descriptor),
                      CodeAssembler::LoadRoot(properties_[i].name_root_index)));

      TNode<Uint32T> details =
          DescriptorArrayGetDetails(descriptors, Uint32Constant(descriptor));

      if (i == 0) {
        combined_details = details;
      } else {
        combined_details = Word32And(combined_details, details);
      }
    }

    TNode<Uint32T> constness =
        DecodeWord32<PropertyDetails::ConstnessField>(combined_details);

    Branch(
        Word32Equal(constness,
                    Int32Constant(static_cast<int>(PropertyConstness::kConst))),
        if_unmodified, if_fast_check_failed);
  }

  if ((flags_ & kCheckPrototypePropertyIdentity) != 0) {
    // The above checks have failed, for whatever reason (maybe the prototype
    // map has changed, or a property is no longer const). This block implements
    // a more thorough check that can also accept maps which 1. do not have the
    // initial map, 2. have mutable relevant properties, but 3. still match the
    // expected value for all relevant properties.

    BIND(&property_identity_check);

    int max_descriptor_index = -1;
    for (int i = 0; i < properties_.length(); i++) {
      max_descriptor_index =
          std::max(max_descriptor_index, properties_[i].descriptor_index);
    }

    // If the greatest descriptor index is out of bounds, the map cannot be
    // fast.
    GotoIfNot(Int32LessThan(Int32Constant(max_descriptor_index),
                            LoadNumberOfDescriptors(descriptors)),
              if_modified);

    // Logic below only handles maps with fast properties.
    GotoIfMapHasSlowProperties(prototype_map, if_modified);

    for (int i = 0; i < properties_.length(); i++) {
      const DescriptorIndexNameValue& p = properties_[i];
      const int descriptor = p.descriptor_index;

      // Check if the name is correct. This essentially checks that
      // the descriptor index corresponds to the insertion order in
      // the bootstrapper.
      GotoIfNot(TaggedEqual(LoadKeyByDescriptorEntry(descriptors, descriptor),
                            CodeAssembler::LoadRoot(p.name_root_index)),
                if_modified);

      // Finally, check whether the actual value equals the expected value.
      TNode<Uint32T> details =
          Desc
```