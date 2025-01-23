Response:
My thinking process to analyze the provided C++ code snippet goes like this:

1. **Identify the Core Purpose:** The filename `assembler.h` and the presence of functions like `StoreElement`, `Allocate`, `CallBuiltin`, `LoadField`, etc., strongly suggest this header defines an abstraction layer for generating machine code instructions. It's an "assembler" in the context of a compiler. The `turboshaft` namespace hints at a specific compilation pipeline within V8.

2. **Scan for Key Functionality Areas:** I look for groups of related functions or patterns. This helps to categorize the functionality. I see:
    * **Memory Operations:**  `LoadField`, `StoreElement`, `Allocate`, `InitializeElement`. These are clearly related to reading and writing data in memory.
    * **Function Calls:** `Call`, `CallBuiltin`, `CallRuntime`. This indicates support for invoking functions (both built-in and runtime).
    * **Control Flow:** `Select`, `Conditional`, `Switch`, `Return`, `Unreachable`. These manipulate the execution path of the generated code.
    * **Stack Management:** `StackSlot`, `AdaptLocalArgument`, `StackPointerGreaterThan`. Functions for allocating and checking stack space.
    * **Type Checks/Conversions:** `ArrayBufferIsDetached`. Though limited in this snippet, the naming suggests operations related to object types.
    * **Debugging/Diagnostics:** `WasmStackCheck`, `JSStackCheck`, `CallBuiltin_DebugPrintFloat64`, `CallBuiltin_DebugPrintWordPtr`. These are likely for ensuring correct execution and debugging.
    * **Parameters and Return Values:** `Parameter`, `Return`. Mechanisms for handling function inputs and outputs.
    * **Constants:** `Word32Constant`, `HeapConstant`, `IntPtrConstant`. Ways to represent constant values.

3. **Analyze Templates and Generics:**  The extensive use of templates (`template <typename T>`) indicates a design that aims for type safety and code reuse. The `V<T>` likely represents a "Value" of type `T` within the Turboshaft intermediate representation. `ConstOrV<T>` suggests a value can be either a compile-time constant or a runtime value.

4. **Look for V8-Specific Concepts:** Terms like `HeapObject`, `JSArrayBufferView`, `Smi`, `Context`, `SharedFunctionInfo`, `FeedbackCell` are strong indicators of V8's internal object model and runtime environment. This confirms the code's context within the V8 JavaScript engine.

5. **Address Specific Instructions:** I go through the prompt's specific requirements:
    * **Function Listing:**  This is largely covered by step 2. I list the identified functionalities.
    * **`.tq` Check:**  I explicitly state that the `.h` extension means it's C++, not Torque.
    * **JavaScript Relevance:** I look for functions that directly relate to JavaScript concepts. Memory access, function calls, and type conversions are all fundamental to executing JavaScript. I try to come up with simple JavaScript examples that would necessitate these underlying operations (e.g., accessing array elements, calling functions).
    * **Code Logic Inference:** I pick a few representative functions (like `StoreElement` or `Allocate`) and provide hypothetical inputs and outputs, explaining what the function would do.
    * **Common Programming Errors:**  I consider how the assembler's features could be misused or lead to errors. For instance, incorrect type handling in `StoreElement`, or memory leaks if `Allocate` isn't paired with a mechanism for eventual deallocation.
    * **Function Summarization:** This reiterates the core purpose identified in step 1, emphasizing the role of this header in the Turboshaft compiler.

6. **Structure the Output:** I organize the findings into clear sections as requested by the prompt, using headings and bullet points for readability. I make sure to connect the C++ code back to JavaScript concepts where appropriate. I also pay attention to the prompt's constraint of this being "part 5 of 8" and ensure the summary reflects a partial view of the overall assembler functionality.

7. **Refine and Review:** I reread my analysis to ensure accuracy, clarity, and completeness based on the provided code snippet. I check if I've addressed all aspects of the prompt. For example, ensuring the JavaScript examples are simple and illustrative, and the hypothetical inputs/outputs are reasonable.

By following these steps, I can systematically analyze the C++ header file and provide a comprehensive summary of its functionality within the context of the V8 JavaScript engine. The key is to combine general programming knowledge with specific understanding of compiler design and V8's architecture.
好的，让我们来分析一下 `v8/src/compiler/turboshaft/assembler.h` 这个 V8 源代码文件的功能。

**功能归纳：**

从提供的代码片段来看，`assembler.h` 定义了一个用于在 Turboshaft 编译管道中生成机器码的抽象层。它提供了一系列方法，用于执行诸如内存访问、函数调用、控制流操作、以及与 V8 运行时环境交互等底层操作。

**具体功能列举：**

1. **内存操作:**
   - **存储元素 (`StoreElement`, `StoreArrayBufferElement`, `StoreNonArrayBufferElement`):**  用于将值存储到对象的属性中，区分了 ArrayBuffer 和非 ArrayBuffer 的存储。
   - **初始化元素 (`InitializeElement`, `InitializeArrayBufferElement`, `InitializeNonArrayBufferElement`):** 用于初始化新分配对象的属性。
   - **加载字段 (`LoadField`):** 用于从对象中加载字段的值。
   - **分配内存 (`Allocate`):**  用于在堆上分配指定大小和类型的内存。
   - **完成初始化 (`FinishInitialization`):** 标记对象的初始化完成。

2. **ArrayBuffer 相关操作:**
   - **检查 ArrayBuffer 是否分离 (`ArrayBufferIsDetached`):**  用于判断一个 `JSArrayBufferView` 对象关联的 ArrayBuffer 是否已被分离。

3. **函数调用:**
   - **调用 (`Call`):** 用于生成函数调用指令，可以调用一般的代码对象。
   - **调用内置函数 (`CallBuiltin`):** 提供多种重载形式，用于方便地调用 V8 的内置函数，支持传递帧状态、上下文等参数。
   - **调用运行时函数 (`CallRuntime`):**  （代码片段未完全展示，但从命名可以推断）用于调用 V8 的运行时函数。
   - **Wasm 调用内置函数 (`WasmCallBuiltinThroughJumptable`):** 用于调用 WebAssembly 的内置函数。

4. **控制流:**
   - **条件选择 (`Select`, `Word32Select`, `Word64Select`, `WordPtrSelect`, `Float32Select`, `Float64Select`, `Conditional`):**  根据条件选择不同的值或执行路径。
   - **分支 (`Switch`):**  实现类似 switch 语句的多路分支。
   - **不可达代码 (`Unreachable`):**  标记代码为不可达。
   - **返回 (`Return`):**  生成函数返回指令。

5. **栈操作:**
   - **分配栈槽 (`StackSlot`):**  在栈上分配指定大小和对齐方式的槽位。
   - **调整本地参数 (`AdaptLocalArgument`):**  将参数放置到栈上，以便后续访问。
   - **栈指针比较 (`StackPointerGreaterThan`):**  比较栈指针与限制值。
   - **获取栈帧相关信息 (`StackCheckOffset`, `FramePointer`, `ParentFramePointer`):**  获取当前栈帧的偏移、帧指针、父帧指针等信息。

6. **参数和返回值处理:**
   - **获取参数 (`Parameter`):**  获取传递给当前函数的参数。
   - **OSR 值 (`OsrValue`):**  获取 On-Stack Replacement (OSR) 过程中的值。

7. **常量:**
   - **加载根寄存器 (`LoadRootRegister`):**  获取根寄存器的值。
   - **帧常量 (`ReduceIfReachableFrameConstant`):** 用于获取栈帧相关的常量。
   - **常量值生成 (`Word32Constant`, `IntPtrConstant`, `HeapConstant`):**  生成不同类型的常量值。

8. **WebAssembly 支持 (`V8_ENABLE_WEBASSEMBLY`):**
   - **Wasm 栈检查 (`WasmStackCheck`):**  执行 WebAssembly 栈溢出检查。
   - **Wasm 内置函数调用 (`WasmCallBuiltinThroughJumptable`):**

9. **JavaScript 栈检查 (`JSStackCheck`, `JSLoopStackCheck`, `JSFunctionEntryStackCheck`):** 用于执行 JavaScript 栈溢出检查。

10. **其他操作:**
    - **外部指针解码 (`DecodeExternalPointer`):**  解码外部指针。
    - **保留对象 (`Retain`):**  防止对象被过早回收。

**关于文件扩展名和 Torque：**

你说的对。如果 `v8/src/compiler/turboshaft/assembler.h` 的扩展名是 `.tq`，那么它会是一个 Torque 源代码文件。但由于它的扩展名是 `.h`，这表明它是一个 **C++ 头文件**，其中声明了 `Assembler` 类和相关的接口。

**与 JavaScript 的关系及示例：**

`assembler.h` 中定义的功能是 JavaScript 代码执行的基础。Turboshaft 编译器会将 JavaScript 代码转换成使用这些功能描述的中间表示，最终生成机器码。

例如，考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}
let result = add(5, 10);
```

在 Turboshaft 编译 `add` 函数时，`assembler.h` 中定义的功能会被用到：

- **参数获取 (`Parameter`):** 获取 `a` 和 `b` 的值。
- **加法运算 (可能通过 `CallBuiltin` 调用内置的加法函数):** 执行 `a + b` 的运算。
- **返回值处理 (`Return`):** 返回计算结果。

在调用 `add(5, 10)` 时：

- **常量生成 (`Word32Constant`):**  生成常量 `5` 和 `10`。
- **函数调用 (`Call` 或 `CallBuiltin`):** 调用 `add` 函数。

再比如，访问数组元素：

```javascript
const arr = [1, 2, 3];
const value = arr[1];
```

编译这段代码时，可能会用到：

- **加载字段 (`LoadField`):** 加载数组对象。
- **存储元素 (`StoreElement`):**  如果涉及到修改数组元素。
- **检查 ArrayBuffer (`ArrayBufferIsDetached`):** 如果数组是 TypedArray。

**代码逻辑推理和假设输入/输出：**

让我们以 `StoreElement` 为例：

```c++
template <typename Base>
void StoreArrayBufferElement(V<Base> object, const ElementAccess& access,
                                V<WordPtr> index, V<Any> value) {
  return StoreElement(object, access, index, value, true);
}
```

**假设输入：**

- `object`: 一个表示 `ArrayBuffer` 或 `TypedArray` 对象的 `V<Base>`。假设它指向一个 `Uint8Array`，内容为 `[0, 0, 0, 0]`.
- `access`: 一个描述元素访问方式的 `ElementAccess` 对象，例如指定了元素的大小和类型（uint8）。
- `index`: 一个 `V<WordPtr>`，值为指向索引 `2` 的指针。
- `value`: 一个 `V<Any>`，表示要存储的值，假设为整数 `100`。

**预期输出：**

调用 `StoreArrayBufferElement` 后，`object` 指向的 `Uint8Array` 的内容将被修改为 `[0, 0, 100, 0]`。

**用户常见的编程错误：**

使用 `assembler.h` 涉及底层代码生成，用户直接操作的机会较少。但理解其背后的原理有助于理解 V8 编译器的行为，从而避免一些 JavaScript 编程错误，例如：

- **类型错误:**  例如，尝试将一个非数字的值存储到数字类型的数组中，这可能会导致类型转换或运行时错误。`StoreElement` 的模板机制在一定程度上可以帮助编译器进行类型检查，但最终的正确性还是依赖于编译器的分析和优化。
- **越界访问:**  访问数组时超出其边界。虽然 `assembler.h` 本身不直接处理边界检查，但编译器生成的代码会包含相应的检查，这与 `assembler.h` 中定义的内存访问操作密切相关。
- **ArrayBuffer 分离后访问:** 尝试访问一个已经被分离的 `ArrayBuffer`，`ArrayBufferIsDetached` 这样的函数就是用于在编译时生成检查这类情况的代码。

**第 5 部分的功能归纳：**

提供的代码片段是 `assembler.h` 的一部分，主要涵盖了：

- **内存的存储和初始化操作，特别是针对 ArrayBuffer 的处理。**
- **类型化的元素访问 (`ElementAccessTS`) 的使用。**
- **ArrayBuffer 分离状态的检查。**
- **对象的分配和初始化流程。**
- **堆数字的分配和初始化。**
- **外部指针的解码。**
- **WebAssembly 栈检查。**
- **JavaScript 栈检查的不同类型。**
- **保留对象的操作。**
- **栈指针比较。**
- **获取栈帧相关常量的操作。**
- **栈槽的分配。**
- **本地参数的调整。**
- **加载根寄存器。**
- **条件选择的不同实现方式。**

总而言之，这部分代码提供了构建 Turboshaft 编译器生成机器码所需的基本 building blocks，专注于内存管理、类型化访问、栈操作和控制流选择等关键功能。

### 提示词
```
这是目录为v8/src/compiler/turboshaft/assembler.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/assembler.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共8部分，请归纳一下它的功能
```

### 源代码
```c
ct, access, index, value, true);
  }
  template <typename Base>
  void StoreNonArrayBufferElement(V<Base> object, const ElementAccess& access,
                                  V<WordPtr> index, V<Any> value) {
    return StoreElement(object, access, index, value, false);
  }

  template <typename Class, typename T>
  void StoreElement(V<Class> object, const ElementAccessTS<Class, T>& access,
                    ConstOrV<WordPtr> index, V<T> value) {
    StoreElement(object, access, index, value, access.is_array_buffer_load);
  }

  template <typename Class, typename T>
  void InitializeElement(Uninitialized<Class>& object,
                         const ElementAccessTS<Class, T>& access,
                         ConstOrV<WordPtr> index, V<T> value) {
    StoreElement(object.object(), access, index, value,
                 access.is_array_buffer_load);
  }

  // TODO(nicohartmann): Remove `InitializeArrayBufferElement` once fully
  // transitioned to `ElementAccess`.
  template <typename Base>
  void InitializeArrayBufferElement(Uninitialized<Base>& object,
                                    const ElementAccess& access,
                                    V<WordPtr> index, V<Any> value) {
    StoreArrayBufferElement(object.object(), access, index, value);
  }
  // TODO(nicohartmann): Remove `InitializeNoneArrayBufferElement` once fully
  // transitioned to `ElementAccess`.
  template <typename Base>
  void InitializeNonArrayBufferElement(Uninitialized<Base>& object,
                                       const ElementAccess& access,
                                       V<WordPtr> index, V<Any> value) {
    StoreNonArrayBufferElement(object.object(), access, index, value);
  }

  V<Word32> ArrayBufferIsDetached(V<JSArrayBufferView> object) {
    V<HeapObject> buffer = __ template LoadField<HeapObject>(
        object, compiler::AccessBuilder::ForJSArrayBufferViewBuffer());
    V<Word32> bitfield = __ template LoadField<Word32>(
        buffer, compiler::AccessBuilder::ForJSArrayBufferBitField());
    return __ Word32BitwiseAnd(bitfield, JSArrayBuffer::WasDetachedBit::kMask);
  }

  template <typename T = HeapObject>
  Uninitialized<T> Allocate(ConstOrV<WordPtr> size, AllocationType type) {
    static_assert(is_subtype_v<T, HeapObject>);
    DCHECK(!in_object_initialization_);
    in_object_initialization_ = true;
    return Uninitialized<T>{ReduceIfReachableAllocate(resolve(size), type)};
  }

  template <typename T>
  V<T> FinishInitialization(Uninitialized<T>&& uninitialized) {
    DCHECK(in_object_initialization_);
    in_object_initialization_ = false;
    return uninitialized.ReleaseObject();
  }

  V<HeapNumber> AllocateHeapNumberWithValue(V<Float64> value,
                                            Factory* factory) {
    auto result = __ template Allocate<HeapNumber>(
        __ IntPtrConstant(sizeof(HeapNumber)), AllocationType::kYoung);
    __ InitializeField(result, AccessBuilder::ForMap(),
                       __ HeapConstant(factory->heap_number_map()));
    __ InitializeField(result, AccessBuilder::ForHeapNumberValue(), value);
    return __ FinishInitialization(std::move(result));
  }

  OpIndex DecodeExternalPointer(OpIndex handle, ExternalPointerTag tag) {
    return ReduceIfReachableDecodeExternalPointer(handle, tag);
  }

#if V8_ENABLE_WEBASSEMBLY
  void WasmStackCheck(WasmStackCheckOp::Kind kind) {
    ReduceIfReachableWasmStackCheck(kind);
  }
#endif

  void JSStackCheck(V<Context> context,
                    OptionalV<turboshaft::FrameState> frame_state,
                    JSStackCheckOp::Kind kind) {
    ReduceIfReachableJSStackCheck(context, frame_state, kind);
  }

  void JSLoopStackCheck(V<Context> context,
                        V<turboshaft::FrameState> frame_state) {
    JSStackCheck(context, frame_state, JSStackCheckOp::Kind::kLoop);
  }
  void JSFunctionEntryStackCheck(V<Context> context,
                                 V<turboshaft::FrameState> frame_state) {
    JSStackCheck(context, frame_state, JSStackCheckOp::Kind::kFunctionEntry);
  }

  void Retain(V<Object> value) { ReduceIfReachableRetain(value); }

  V<Word32> StackPointerGreaterThan(V<WordPtr> limit, StackCheckKind kind) {
    return ReduceIfReachableStackPointerGreaterThan(limit, kind);
  }

  V<Smi> StackCheckOffset() {
    return ReduceIfReachableFrameConstant(
        FrameConstantOp::Kind::kStackCheckOffset);
  }
  V<WordPtr> FramePointer() {
    return ReduceIfReachableFrameConstant(FrameConstantOp::Kind::kFramePointer);
  }
  V<WordPtr> ParentFramePointer() {
    return ReduceIfReachableFrameConstant(
        FrameConstantOp::Kind::kParentFramePointer);
  }

  V<WordPtr> StackSlot(int size, int alignment, bool is_tagged = false) {
    return ReduceIfReachableStackSlot(size, alignment, is_tagged);
  }

  V<WordPtr> AdaptLocalArgument(V<Object> argument) {
#ifdef V8_ENABLE_DIRECT_HANDLE
    // With direct locals, the argument can be passed directly.
    return BitcastTaggedToWordPtr(argument);
#else
    // With indirect locals, the argument has to be stored on the stack and the
    // slot address is passed.
    V<WordPtr> stack_slot =
        StackSlot(sizeof(uintptr_t), alignof(uintptr_t), true);
    StoreOffHeap(stack_slot, __ BitcastTaggedToWordPtr(argument),
                 MemoryRepresentation::UintPtr());
    return stack_slot;
#endif
  }

  OpIndex LoadRootRegister() { return ReduceIfReachableLoadRootRegister(); }

  template <typename T = Any, typename U = T>
  V<std::common_type_t<T, U>> Select(ConstOrV<Word32> cond, V<T> vtrue,
                                     V<U> vfalse, RegisterRepresentation rep,
                                     BranchHint hint,
                                     SelectOp::Implementation implem) {
    return ReduceIfReachableSelect(resolve(cond), vtrue, vfalse, rep, hint,
                                   implem);
  }

  // TODO(chromium:331100916): remove this overload once Turboshaft has been
  // entirely V<>ified.
  OpIndex Select(ConstOrV<Word32> cond, OpIndex vtrue, OpIndex vfalse,
                 RegisterRepresentation rep, BranchHint hint,
                 SelectOp::Implementation implem) {
    return Select(cond, V<Any>::Cast(vtrue), V<Any>::Cast(vfalse), rep, hint,
                  implem);
  }

#define DEF_SELECT(Rep)                                                  \
  V<Rep> Rep##Select(ConstOrV<Word32> cond, ConstOrV<Rep> vtrue,         \
                     ConstOrV<Rep> vfalse) {                             \
    return Select<Rep>(resolve(cond), resolve(vtrue), resolve(vfalse),   \
                       RegisterRepresentation::Rep(), BranchHint::kNone, \
                       SelectOp::Implementation::kCMove);                \
  }
  DEF_SELECT(Word32)
  DEF_SELECT(Word64)
  DEF_SELECT(WordPtr)
  DEF_SELECT(Float32)
  DEF_SELECT(Float64)
#undef DEF_SELECT

  template <typename T, typename U>
  V<std::common_type_t<T, U>> Conditional(ConstOrV<Word32> cond, V<T> vtrue,
                                          V<U> vfalse,
                                          BranchHint hint = BranchHint::kNone) {
    return Select(resolve(cond), vtrue, vfalse,
                  V<std::common_type_t<T, U>>::rep, hint,
                  SelectOp::Implementation::kBranch);
  }
  void Switch(V<Word32> input, base::Vector<SwitchOp::Case> cases,
              Block* default_case,
              BranchHint default_hint = BranchHint::kNone) {
    ReduceIfReachableSwitch(input, cases, default_case, default_hint);
  }
  void Unreachable() { ReduceIfReachableUnreachable(); }

  OpIndex Parameter(int index, RegisterRepresentation rep,
                    const char* debug_name = nullptr) {
    // Parameter indices might be negative.
    int cache_location = index - kMinParameterIndex;
    DCHECK_GE(cache_location, 0);
    if (static_cast<size_t>(cache_location) >= cached_parameters_.size()) {
      cached_parameters_.resize_and_init(cache_location + 1);
    }
    OpIndex& cached_param = cached_parameters_[cache_location];
    if (!cached_param.valid()) {
      // Note: When in unreachable code, this will return OpIndex::Invalid, so
      // the cached state is unchanged.
      cached_param = ReduceIfReachableParameter(index, rep, debug_name);
    } else {
      DCHECK_EQ(Asm().output_graph().Get(cached_param).outputs_rep(),
                base::VectorOf({rep}));
    }
    return cached_param;
  }
  template <typename T>
  V<T> Parameter(int index, const char* debug_name = nullptr) {
    return Parameter(index, V<T>::rep, debug_name);
  }
  V<Object> OsrValue(int index) { return ReduceIfReachableOsrValue(index); }
  void Return(V<Word32> pop_count, base::Vector<const OpIndex> return_values,
              bool spill_caller_frame_slots = false) {
    ReduceIfReachableReturn(pop_count, return_values, spill_caller_frame_slots);
  }
  void Return(OpIndex result) {
    Return(Word32Constant(0), base::VectorOf({result}));
  }

  template <typename R = AnyOrNone>
  V<R> Call(V<CallTarget> callee, OptionalV<turboshaft::FrameState> frame_state,
            base::Vector<const OpIndex> arguments,
            const TSCallDescriptor* descriptor,
            OpEffects effects = OpEffects().CanCallAnything()) {
    return ReduceIfReachableCall(callee, frame_state, arguments, descriptor,
                                 effects);
  }
  template <typename R = AnyOrNone>
  V<R> Call(V<CallTarget> callee, std::initializer_list<OpIndex> arguments,
            const TSCallDescriptor* descriptor,
            OpEffects effects = OpEffects().CanCallAnything()) {
    return Call<R>(callee, OptionalV<turboshaft::FrameState>::Nullopt(),
                   base::VectorOf(arguments), descriptor, effects);
  }

  template <typename Descriptor>
  std::enable_if_t<Descriptor::kNeedsFrameState && Descriptor::kNeedsContext,
                   detail::index_type_for_t<typename Descriptor::results_t>>
  CallBuiltin(Isolate* isolate, V<turboshaft::FrameState> frame_state,
              V<Context> context, const typename Descriptor::arguments_t& args,
              LazyDeoptOnThrow lazy_deopt_on_throw = LazyDeoptOnThrow::kNo) {
    using result_t = detail::index_type_for_t<typename Descriptor::results_t>;
    if (V8_UNLIKELY(Asm().generating_unreachable_operations())) {
      return result_t::Invalid();
    }
    DCHECK(frame_state.valid());
    DCHECK(context.valid());
    auto arguments = std::apply(
        [context](auto&&... as) {
          return base::SmallVector<
              OpIndex, std::tuple_size_v<typename Descriptor::arguments_t> + 1>{
              std::forward<decltype(as)>(as)..., context};
        },
        args);
    return result_t::Cast(CallBuiltinImpl(
        isolate, Descriptor::kFunction, frame_state, base::VectorOf(arguments),
        Descriptor::Create(StubCallMode::kCallCodeObject,
                           Asm().output_graph().graph_zone(),
                           lazy_deopt_on_throw),
        Descriptor::kEffects));
  }

  template <typename Descriptor>
  std::enable_if_t<!Descriptor::kNeedsFrameState && Descriptor::kNeedsContext,
                   detail::index_type_for_t<typename Descriptor::results_t>>
  CallBuiltin(Isolate* isolate, V<Context> context,
              const typename Descriptor::arguments_t& args) {
    using result_t = detail::index_type_for_t<typename Descriptor::results_t>;
    if (V8_UNLIKELY(Asm().generating_unreachable_operations())) {
      return result_t::Invalid();
    }
    DCHECK(context.valid());
    auto arguments = std::apply(
        [context](auto&&... as) {
          return base::SmallVector<
              OpIndex, std::tuple_size_v<typename Descriptor::arguments_t> + 1>{
              std::forward<decltype(as)>(as)..., context};
        },
        args);
    return result_t::Cast(CallBuiltinImpl(
        isolate, Descriptor::kFunction,
        OptionalV<turboshaft::FrameState>::Nullopt(), base::VectorOf(arguments),
        Descriptor::Create(StubCallMode::kCallCodeObject,
                           Asm().output_graph().graph_zone()),
        Descriptor::kEffects));
  }
  template <typename Descriptor>
  std::enable_if_t<Descriptor::kNeedsFrameState && !Descriptor::kNeedsContext,
                   detail::index_type_for_t<typename Descriptor::results_t>>
  CallBuiltin(Isolate* isolate, V<turboshaft::FrameState> frame_state,
              const typename Descriptor::arguments_t& args,
              LazyDeoptOnThrow lazy_deopt_on_throw = LazyDeoptOnThrow::kNo) {
    using result_t = detail::index_type_for_t<typename Descriptor::results_t>;
    if (V8_UNLIKELY(Asm().generating_unreachable_operations())) {
      return result_t::Invalid();
    }
    DCHECK(frame_state.valid());
    auto arguments = std::apply(
        [](auto&&... as) {
          return base::SmallVector<OpIndex, std::tuple_size_v<decltype(args)>>{
              std::forward<decltype(as)>(as)...};
        },
        args);
    return result_t::Cast(CallBuiltinImpl(
        isolate, Descriptor::kFunction, frame_state, base::VectorOf(arguments),
        Descriptor::Create(StubCallMode::kCallCodeObject,
                           Asm().output_graph().graph_zone(),
                           lazy_deopt_on_throw),
        Descriptor::kEffects));
  }
  template <typename Descriptor>
  std::enable_if_t<!Descriptor::kNeedsFrameState && !Descriptor::kNeedsContext,
                   detail::index_type_for_t<typename Descriptor::results_t>>
  CallBuiltin(Isolate* isolate, const typename Descriptor::arguments_t& args) {
    using result_t = detail::index_type_for_t<typename Descriptor::results_t>;
    if (V8_UNLIKELY(Asm().generating_unreachable_operations())) {
      return result_t::Invalid();
    }
    auto arguments = std::apply(
        [](auto&&... as) {
          return base::SmallVector<
              OpIndex, std::tuple_size_v<typename Descriptor::arguments_t>>{
              std::forward<decltype(as)>(as)...};
        },
        args);
    return result_t::Cast(CallBuiltinImpl(
        isolate, Descriptor::kFunction,
        OptionalV<turboshaft::FrameState>::Nullopt(), base::VectorOf(arguments),
        Descriptor::Create(StubCallMode::kCallCodeObject,
                           Asm().output_graph().graph_zone()),
        Descriptor::kEffects));
  }

#if V8_ENABLE_WEBASSEMBLY

  template <typename Descriptor>
  std::enable_if_t<!Descriptor::kNeedsContext,
                   detail::index_type_for_t<typename Descriptor::results_t>>
  WasmCallBuiltinThroughJumptable(
      const typename Descriptor::arguments_t& args) {
    static_assert(!Descriptor::kNeedsFrameState);
    using result_t = detail::index_type_for_t<typename Descriptor::results_t>;
    if (V8_UNLIKELY(Asm().generating_unreachable_operations())) {
      return result_t::Invalid();
    }
    auto arguments = std::apply(
        [](auto&&... as) {
          return base::SmallVector<
              OpIndex, std::tuple_size_v<typename Descriptor::arguments_t>>{
              std::forward<decltype(as)>(as)...};
        },
        args);
    V<WordPtr> call_target =
        RelocatableWasmBuiltinCallTarget(Descriptor::kFunction);
    return result_t::Cast(
        Call(call_target, OptionalV<turboshaft::FrameState>::Nullopt(),
             base::VectorOf(arguments),
             Descriptor::Create(StubCallMode::kCallWasmRuntimeStub,
                                Asm().output_graph().graph_zone()),
             Descriptor::kEffects));
  }

  template <typename Descriptor>
  std::enable_if_t<Descriptor::kNeedsContext,
                   detail::index_type_for_t<typename Descriptor::results_t>>
  WasmCallBuiltinThroughJumptable(
      V<Context> context, const typename Descriptor::arguments_t& args) {
    static_assert(!Descriptor::kNeedsFrameState);
    using result_t = detail::index_type_for_t<typename Descriptor::results_t>;
    if (V8_UNLIKELY(Asm().generating_unreachable_operations())) {
      return result_t::Invalid();
    }
    DCHECK(context.valid());
    auto arguments = std::apply(
        [context](auto&&... as) {
          return base::SmallVector<
              OpIndex, std::tuple_size_v<typename Descriptor::arguments_t> + 1>{
              std::forward<decltype(as)>(as)..., context};
        },
        args);
    V<WordPtr> call_target =
        RelocatableWasmBuiltinCallTarget(Descriptor::kFunction);
    return result_t::Cast(
        Call(call_target, OptionalV<turboshaft::FrameState>::Nullopt(),
             base::VectorOf(arguments),
             Descriptor::Create(StubCallMode::kCallWasmRuntimeStub,
                                Asm().output_graph().graph_zone()),
             Descriptor::kEffects));
  }

#endif  // V8_ENABLE_WEBASSEMBLY

  V<Any> CallBuiltinImpl(Isolate* isolate, Builtin builtin,
                         OptionalV<turboshaft::FrameState> frame_state,
                         base::Vector<const OpIndex> arguments,
                         const TSCallDescriptor* desc, OpEffects effects) {
    Callable callable = Builtins::CallableFor(isolate, builtin);
    return Call(HeapConstant(callable.code()), frame_state, arguments, desc,
                effects);
  }

#define DECL_GENERIC_BINOP_BUILTIN_CALL(Name)                            \
  V<Object> CallBuiltin_##Name(                                          \
      Isolate* isolate, V<turboshaft::FrameState> frame_state,           \
      V<Context> context, V<Object> lhs, V<Object> rhs,                  \
      LazyDeoptOnThrow lazy_deopt_on_throw) {                            \
    return CallBuiltin<typename BuiltinCallDescriptor::Name>(            \
        isolate, frame_state, context, {lhs, rhs}, lazy_deopt_on_throw); \
  }
  GENERIC_BINOP_LIST(DECL_GENERIC_BINOP_BUILTIN_CALL)
#undef DECL_GENERIC_BINOP_BUILTIN_CALL

#define DECL_GENERIC_UNOP_BUILTIN_CALL(Name)                           \
  V<Object> CallBuiltin_##Name(Isolate* isolate,                       \
                               V<turboshaft::FrameState> frame_state,  \
                               V<Context> context, V<Object> input,    \
                               LazyDeoptOnThrow lazy_deopt_on_throw) { \
    return CallBuiltin<typename BuiltinCallDescriptor::Name>(          \
        isolate, frame_state, context, {input}, lazy_deopt_on_throw);  \
  }
  GENERIC_UNOP_LIST(DECL_GENERIC_UNOP_BUILTIN_CALL)
#undef DECL_GENERIC_UNOP_BUILTIN_CALL

  V<Number> CallBuiltin_ToNumber(Isolate* isolate,
                                 V<turboshaft::FrameState> frame_state,
                                 V<Context> context, V<Object> input,
                                 LazyDeoptOnThrow lazy_deopt_on_throw) {
    return CallBuiltin<typename BuiltinCallDescriptor::ToNumber>(
        isolate, frame_state, context, {input}, lazy_deopt_on_throw);
  }
  V<Numeric> CallBuiltin_ToNumeric(Isolate* isolate,
                                   V<turboshaft::FrameState> frame_state,
                                   V<Context> context, V<Object> input,
                                   LazyDeoptOnThrow lazy_deopt_on_throw) {
    return CallBuiltin<typename BuiltinCallDescriptor::ToNumeric>(
        isolate, frame_state, context, {input}, lazy_deopt_on_throw);
  }

  void CallBuiltin_CheckTurbofanType(Isolate* isolate, V<Context> context,
                                     V<Object> object,
                                     V<TurbofanType> allocated_type,
                                     V<Smi> node_id) {
    CallBuiltin<typename BuiltinCallDescriptor::CheckTurbofanType>(
        isolate, context, {object, allocated_type, node_id});
  }
  V<Object> CallBuiltin_CopyFastSmiOrObjectElements(Isolate* isolate,
                                                    V<Object> object) {
    return CallBuiltin<
        typename BuiltinCallDescriptor::CopyFastSmiOrObjectElements>(isolate,
                                                                     {object});
  }
  void CallBuiltin_DebugPrintFloat64(Isolate* isolate, V<Context> context,
                                     V<Float64> value) {
    CallBuiltin<typename BuiltinCallDescriptor::DebugPrintFloat64>(
        isolate, context, {value});
  }
  void CallBuiltin_DebugPrintWordPtr(Isolate* isolate, V<Context> context,
                                     V<WordPtr> value) {
    CallBuiltin<typename BuiltinCallDescriptor::DebugPrintWordPtr>(
        isolate, context, {value});
  }
  V<Smi> CallBuiltin_FindOrderedHashMapEntry(Isolate* isolate,
                                             V<Context> context,
                                             V<Object> table, V<Smi> key) {
    return CallBuiltin<typename BuiltinCallDescriptor::FindOrderedHashMapEntry>(
        isolate, context, {table, key});
  }
  V<Smi> CallBuiltin_FindOrderedHashSetEntry(Isolate* isolate,
                                             V<Context> context, V<Object> set,
                                             V<Smi> key) {
    return CallBuiltin<typename BuiltinCallDescriptor::FindOrderedHashSetEntry>(
        isolate, context, {set, key});
  }
  V<Object> CallBuiltin_GrowFastDoubleElements(Isolate* isolate,
                                               V<Object> object, V<Smi> size) {
    return CallBuiltin<typename BuiltinCallDescriptor::GrowFastDoubleElements>(
        isolate, {object, size});
  }
  V<Object> CallBuiltin_GrowFastSmiOrObjectElements(Isolate* isolate,
                                                    V<Object> object,
                                                    V<Smi> size) {
    return CallBuiltin<
        typename BuiltinCallDescriptor::GrowFastSmiOrObjectElements>(
        isolate, {object, size});
  }
  V<FixedArray> CallBuiltin_NewSloppyArgumentsElements(
      Isolate* isolate, V<WordPtr> frame, V<WordPtr> formal_parameter_count,
      V<Smi> arguments_count) {
    return CallBuiltin<
        typename BuiltinCallDescriptor::NewSloppyArgumentsElements>(
        isolate, {frame, formal_parameter_count, arguments_count});
  }
  V<FixedArray> CallBuiltin_NewStrictArgumentsElements(
      Isolate* isolate, V<WordPtr> frame, V<WordPtr> formal_parameter_count,
      V<Smi> arguments_count) {
    return CallBuiltin<
        typename BuiltinCallDescriptor::NewStrictArgumentsElements>(
        isolate, {frame, formal_parameter_count, arguments_count});
  }
  V<FixedArray> CallBuiltin_NewRestArgumentsElements(
      Isolate* isolate, V<WordPtr> frame, V<WordPtr> formal_parameter_count,
      V<Smi> arguments_count) {
    return CallBuiltin<
        typename BuiltinCallDescriptor::NewRestArgumentsElements>(
        isolate, {frame, formal_parameter_count, arguments_count});
  }
  V<String> CallBuiltin_NumberToString(Isolate* isolate, V<Number> input) {
    return CallBuiltin<typename BuiltinCallDescriptor::NumberToString>(isolate,
                                                                       {input});
  }
  V<String> CallBuiltin_ToString(Isolate* isolate,
                                 V<turboshaft::FrameState> frame_state,
                                 V<Context> context, V<Object> input,
                                 LazyDeoptOnThrow lazy_deopt_on_throw) {
    return CallBuiltin<typename BuiltinCallDescriptor::ToString>(
        isolate, frame_state, context, {input}, lazy_deopt_on_throw);
  }
  V<Number> CallBuiltin_PlainPrimitiveToNumber(Isolate* isolate,
                                               V<PlainPrimitive> input) {
    return CallBuiltin<typename BuiltinCallDescriptor::PlainPrimitiveToNumber>(
        isolate, {input});
  }
  V<Boolean> CallBuiltin_SameValue(Isolate* isolate, V<Object> left,
                                   V<Object> right) {
    return CallBuiltin<typename BuiltinCallDescriptor::SameValue>(
        isolate, {left, right});
  }
  V<Boolean> CallBuiltin_SameValueNumbersOnly(Isolate* isolate, V<Object> left,
                                              V<Object> right) {
    return CallBuiltin<typename BuiltinCallDescriptor::SameValueNumbersOnly>(
        isolate, {left, right});
  }
  V<String> CallBuiltin_StringAdd_CheckNone(Isolate* isolate,
                                            V<Context> context, V<String> left,
                                            V<String> right) {
    return CallBuiltin<typename BuiltinCallDescriptor::StringAdd_CheckNone>(
        isolate, context, {left, right});
  }
  V<Boolean> CallBuiltin_StringEqual(Isolate* isolate, V<String> left,
                                     V<String> right, V<WordPtr> length) {
    return CallBuiltin<typename BuiltinCallDescriptor::StringEqual>(
        isolate, {left, right, length});
  }
  V<Boolean> CallBuiltin_StringLessThan(Isolate* isolate, V<String> left,
                                        V<String> right) {
    return CallBuiltin<typename BuiltinCallDescriptor::StringLessThan>(
        isolate, {left, right});
  }
  V<Boolean> CallBuiltin_StringLessThanOrEqual(Isolate* isolate, V<String> left,
                                               V<String> right) {
    return CallBuiltin<typename BuiltinCallDescriptor::StringLessThanOrEqual>(
        isolate, {left, right});
  }
  V<Smi> CallBuiltin_StringIndexOf(Isolate* isolate, V<String> string,
                                   V<String> search, V<Smi> position) {
    return CallBuiltin<typename BuiltinCallDescriptor::StringIndexOf>(
        isolate, {string, search, position});
  }
  V<String> CallBuiltin_StringFromCodePointAt(Isolate* isolate,
                                              V<String> string,
                                              V<WordPtr> index) {
    return CallBuiltin<typename BuiltinCallDescriptor::StringFromCodePointAt>(
        isolate, {string, index});
  }
#ifdef V8_INTL_SUPPORT
  V<String> CallBuiltin_StringToLowerCaseIntl(Isolate* isolate,
                                              V<Context> context,
                                              V<String> string) {
    return CallBuiltin<typename BuiltinCallDescriptor::StringToLowerCaseIntl>(
        isolate, context, {string});
  }
#endif  // V8_INTL_SUPPORT
  V<Number> CallBuiltin_StringToNumber(Isolate* isolate, V<String> input) {
    return CallBuiltin<typename BuiltinCallDescriptor::StringToNumber>(isolate,
                                                                       {input});
  }
  V<String> CallBuiltin_StringSubstring(Isolate* isolate, V<String> string,
                                        V<WordPtr> start, V<WordPtr> end) {
    return CallBuiltin<typename BuiltinCallDescriptor::StringSubstring>(
        isolate, {string, start, end});
  }
  V<Boolean> CallBuiltin_ToBoolean(Isolate* isolate, V<Object> object) {
    return CallBuiltin<typename BuiltinCallDescriptor::ToBoolean>(isolate,
                                                                  {object});
  }
  V<JSReceiver> CallBuiltin_ToObject(Isolate* isolate, V<Context> context,
                                     V<JSPrimitive> object) {
    return CallBuiltin<typename BuiltinCallDescriptor::ToObject>(
        isolate, context, {object});
  }
  V<Context> CallBuiltin_FastNewFunctionContextFunction(
      Isolate* isolate, OpIndex frame_state, V<Context> context,
      V<ScopeInfo> scope_info, ConstOrV<Word32> slot_count,
      LazyDeoptOnThrow lazy_deopt_on_throw) {
    return CallBuiltin<
        typename BuiltinCallDescriptor::FastNewFunctionContextFunction>(
        isolate, frame_state, context, {scope_info, resolve(slot_count)},
        lazy_deopt_on_throw);
  }
  V<Context> CallBuiltin_FastNewFunctionContextEval(
      Isolate* isolate, OpIndex frame_state, V<Context> context,
      V<ScopeInfo> scope_info, ConstOrV<Word32> slot_count,
      LazyDeoptOnThrow lazy_deopt_on_throw) {
    return CallBuiltin<
        typename BuiltinCallDescriptor::FastNewFunctionContextEval>(
        isolate, frame_state, context, {scope_info, resolve(slot_count)},
        lazy_deopt_on_throw);
  }
  V<JSFunction> CallBuiltin_FastNewClosure(
      Isolate* isolate, V<turboshaft::FrameState> frame_state,
      V<Context> context, V<SharedFunctionInfo> shared_function_info,
      V<FeedbackCell> feedback_cell) {
    return CallBuiltin<typename BuiltinCallDescriptor::FastNewClosure>(
        isolate, frame_state, context, {shared_function_info, feedback_cell});
  }
  V<String> CallBuiltin_Typeof(Isolate* isolate, V<Object> object) {
    return CallBuiltin<typename BuiltinCallDescriptor::Typeof>(isolate,
                                                               {object});
  }

  V<Object> CallBuiltinWithVarStackArgs(Isolate* isolate, Zone* graph_zone,
                                        Builtin builtin,
                                        V<turboshaft::FrameState> frame_state,
                                        int num_stack_args,
                                        base::Vector<OpIndex> arguments,
                                        LazyDeoptOnThrow lazy_deopt_on_throw) {
    Callable callable = Builtins::CallableFor(isolate, builtin);
    const CallInterfaceDescriptor& descriptor = callable.descriptor();
    CallDescriptor* call_descriptor =
        Linkage::GetStubCallDescriptor(graph_zone, descriptor, num_stack_args,
                                       CallDescriptor::kNeedsFrameState);
    V<Code> stub_code = __ HeapConstant(callable.code());

    return Call<Object>(
        stub_code, frame_state, arguments,
        TSCallDescriptor::Create(call_descriptor, CanThrow::kYes,
                                 lazy_deopt_on_throw, graph_zone));
  }

  V<Object> CallBuiltin_CallWithSpread(Isolate* isolate, Zone* graph_zone,
                                       V<turboshaft::FrameState> frame_state,
                                       V<Context> context, V<Object> function,
                                       int num_args_no_spread, V<Object> spread,
                                       base::Vector<V<Object>> args_no_spread,
                                       LazyDeoptOnThrow lazy_deopt_on_throw) {
    base::SmallVector<OpIndex, 16> arguments;
    arguments.push_back(function);
    arguments.push_back(Word32Constant(num_args_no_spread));
    arguments.push_back(spread);
    arguments.insert(arguments.end(), args_no_spread.begin(),
                     args_no_spread.end());

    arguments.push_back(context);

    return CallBuiltinWithVarStackArgs(
        isolate, graph_zone, Builtin::kCallWithSpread, frame_state,
        num_args_no_spread, base::VectorOf(arguments), lazy_deopt_on_throw);
  }
  V<Object> CallBuiltin_CallWithArrayLike(
      Isolate* isolate, Zone* graph_zone, V<turboshaft::FrameState> frame_state,
      V<Context> context, V<Object> receiver, V<Object> function,
      V<Object> arguments_list, LazyDeoptOnThrow lazy_deopt_on_throw) {
    // CallWithArrayLike is a weird builtin that expects a receiver as top of
    // the stack, but doesn't explicitly list it as an extra argument. We thus
    // manually create the call descriptor with 1 stack argument.
    constexpr int kNumberOfStackArguments = 1;

    OpIndex arguments[] = {function, arguments_list, receiver, context};

    return CallBuiltinWithVarStackArgs(
        isolate, graph_zone, Builtin::kCallWithArrayLike, frame_state,
        kNumberOfStackArguments, base::VectorOf(arguments),
        lazy_deopt_on_throw);
  }
  V<Object> CallBuiltin_CallForwardVarargs(
      Isolate* isolate, Zone* graph_zone, Builtin builtin,
      V<turboshaft::FrameState> frame_state, V<Context> context,
      V<JSFunction> function, int num_args, int start_index,
      base::Vector<V<Object>> args, LazyDeoptOnThrow lazy_deopt_on_throw) {
    DCHECK(builtin == Builtin::kCallFunctionForwardVarargs ||
           builtin == Builtin::kCallForwardVarargs);
    base::SmallVector<OpIndex, 16> arguments;
    arguments.push_back(function);
    arguments.push_back(__ Word32Constant(num_args));
    arguments.push_back(__ Word32Constant(start_index));
    arguments.insert(arguments.end(), args.begin(), args.end());
    arguments.push_back(context);

    return CallBuiltinWithVarStackArgs(
        isolate, graph_zone, builtin, frame_state, num_args,
        base::VectorOf(arguments), lazy_deopt_on_throw);
  }

  template <typename Descriptor>
  std::enable_if_t<Descriptor::kNeedsFrameState, typename Descriptor::result_t>
  CallRuntime(Isolate* isolate, V<turboshaft::FrameState> frame_state,
              V<Context> context, LazyDeoptOnThrow lazy_deopt_on_throw,
              const typename Descriptor::arguments_t& args) {
    if (V8_UNLIKELY(Asm().generating_unreachable_operations())) {
      return OpIndex::Invalid();
    }
    DCHECK(frame_state.valid());
    DCHECK(context.valid());
    return CallRuntimeImpl<typename Descriptor::result_t>(
        isolate, Descriptor::kFunction,
        Descriptor::Create(Asm().output
```