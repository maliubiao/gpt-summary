Response:
The user wants to understand the purpose of the `v8/src/codegen/interface-descriptors.h` file in the V8 JavaScript engine. They are providing a snippet of its content. I need to:

1. **Identify the core functionality:** Based on the code, this file defines classes that act as *descriptors* for various function calls within V8's code generation process. These descriptors specify the parameters and return types of these calls. They seem particularly relevant for calls between different parts of the V8 engine, including interaction with WebAssembly.

2. **Check for Torque:** The prompt asks if the file ends in `.tq`. Based on the provided content, it ends in `.h`. Therefore, it's a C++ header file, not a Torque file.

3. **Relate to JavaScript (if applicable):**  Some of these descriptors relate to operations that have direct JavaScript counterparts, especially those involving WebAssembly or basic operations like addition. I should provide JavaScript examples to illustrate this.

4. **Provide code logic/reasoning with examples:**  The descriptors specify the types of data being passed and returned. I can create scenarios where incorrect types would lead to issues, demonstrating the importance of these descriptors.

5. **Illustrate common programming errors:**  Incorrectly using the parameters defined in the descriptors could lead to crashes or unexpected behavior. I should give examples of such errors.

6. **Summarize the overall functionality:**  Combine the individual points into a concise summary.

**Plan:**

*   **Core Functionality:** Explain that it defines interface descriptors for function calls within V8's code generation.
*   **Torque Check:**  State that the file is a `.h` file, not a `.tq` file.
*   **JavaScript Relationship:** Focus on `WasmFloat32ToNumberDescriptor`, `WasmFloat64ToTaggedDescriptor`, `I64ToBigIntDescriptor`, `BigIntToI64Descriptor`, and binary/unary operations as they have the most direct connections to JavaScript.
*   **Code Logic/Reasoning:** Use `WasmFloat32ToNumberDescriptor` as an example: If you try to pass a string instead of a float, the conversion would fail. Similarly for `I64ToBigIntDescriptor`.
*   **Common Errors:**  Show how passing the wrong number of arguments or arguments of the wrong type to a function that relies on these descriptors can cause problems.
*   **Summary:**  Reiterate that the file defines the structure of internal function calls, ensuring type safety and proper data handling within V8.
这是 `v8/src/codegen/interface-descriptors.h` 文件的第 4 部分，是对之前未列出的接口描述符的补充。让我们归纳一下这部分的功能，并结合之前的分析进行总结。

**归纳第 4 部分的功能:**

这部分定义了一系列用于描述特定函数调用接口的 C++ 类，这些函数调用主要用于 V8 引擎内部的不同组件交互，尤其是在代码生成和运行时环境中。  这些描述符明确了函数的参数类型、返回类型以及一些调用约定（例如，哪些参数通过寄存器传递）。

具体来说，这部分包含了以下类型的描述符：

*   **WebAssembly 相关描述符:**  `WasmSuspendDescriptor` 用于描述 WebAssembly 暂停操作的接口。
*   **BigInt 相关描述符:**  `I64ToBigIntDescriptor` (64位整数转 BigInt), `I32PairToBigIntDescriptor` (两个 32 位整数转 BigInt), `BigIntToI64Descriptor` (BigInt 转 64 位整数), `BigIntToI32PairDescriptor` (BigInt 转两个 32 位整数)。
*   **对象克隆描述符:**  `CloneObjectWithVectorDescriptor` 和 `CloneObjectBaselineDescriptor` 用于描述对象克隆操作的接口，可能涉及到快照或优化。
*   **带反馈的二元和一元操作描述符:** `BinaryOp_WithFeedbackDescriptor` 和 `UnaryOp_WithFeedbackDescriptor` 用于描述带有类型反馈的二元和一元操作的接口，这些反馈用于优化后续的执行。
*   **调用跳转描述符:** `CallTrampoline_Baseline_CompactDescriptor`, `CallTrampoline_BaselineDescriptor`, `CallTrampoline_WithFeedbackDescriptor` 用于描述不同类型的函数调用跳转（trampoline）的接口，可能涉及到优化后的代码调用。
*   **比较操作描述符:** `Compare_WithFeedbackDescriptor` 和 `Compare_BaselineDescriptor` 用于描述带有或不带有反馈的比较操作的接口。
*   **构造函数描述符:** `Construct_BaselineDescriptor` 和 `Construct_WithFeedbackDescriptor` 用于描述构造函数调用的接口，也可能涉及到反馈机制。
*   **类型检查描述符:** `CheckTurboshaftFloat32TypeDescriptor` 和 `CheckTurboshaftFloat64TypeDescriptor` 可能用于 Turboshaft 编译器中的类型检查。
*   **调试打印描述符:** `DebugPrintWordPtrDescriptor` 和 `DebugPrintFloat64Descriptor` 用于在调试时打印指针和浮点数。
*   **通过宏定义的内置函数描述符:**  使用 `DEFINE_TFS_BUILTIN_DESCRIPTOR` 宏定义了一系列内置函数的描述符，这些内置函数可能在 Torque 中定义。

**总结 `v8/src/codegen/interface-descriptors.h` 的功能:**

总的来说，`v8/src/codegen/interface-descriptors.h` 文件的核心功能是 **定义了 V8 引擎内部不同组件之间进行函数调用的接口规范**。它充当了一个蓝图，描述了哪些函数可以被调用，以及调用这些函数需要提供哪些参数以及期望的返回类型。

**关于 .tq 后缀:**

正如你之前分析的，如果 `v8/src/codegen/interface-descriptors.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是一种用于定义 V8 内部实现细节的领域特定语言。然而，根据提供的内容，该文件以 `.h` 结尾，这意味着它是一个 **C++ 头文件**。  它 *可能* 包含由 Torque 生成的代码或者与 Torque 定义的接口相关联，但其本身不是 Torque 源代码。

**与 JavaScript 的关系:**

这个头文件中定义的许多接口描述符都与 JavaScript 的功能有着密切的关系，尽管它们是在 V8 引擎的底层实现的。以下是一些例子：

1. **WebAssembly 支持:** `WasmFloat32ToNumberDescriptor`, `WasmFloat64ToTaggedDescriptor`, `WasmJSToWasmWrapperDescriptor`, `WasmToJSWrapperDescriptor`, `WasmSuspendDescriptor` 等描述了 JavaScript 和 WebAssembly 模块之间相互调用的接口。

    ```javascript
    // JavaScript 调用 WebAssembly 函数 (WasmJSToWasmWrapperDescriptor 描述了这个过程)
    const wasmInstance = // ... 获取 WebAssembly 实例
    const result = wasmInstance.exports.someFunction(42);

    // WebAssembly 调用 JavaScript 函数 (WasmToJSWrapperDescriptor 描述了这个过程)
    // 在 WebAssembly 模块中导入一个 JavaScript 函数
    // (import "env" "jsFunction" (func $jsFunction (param i32) (result i32)))
    ```

2. **BigInt 支持:** `I64ToBigIntDescriptor`, `I32PairToBigIntDescriptor`, `BigIntToI64Descriptor`, `BigIntToI32PairDescriptor` 描述了 JavaScript 中 BigInt 类型和底层 64 位整数之间的转换。

    ```javascript
    // JavaScript 中使用 BigInt
    const bigIntValue = 9007199254740991n;
    const regularNumber = Number(bigIntValue); // 需要进行转换，底层会用到 BigIntToI64Descriptor

    const largeNumber = 2**53;
    const bigIntFromNumber = BigInt(largeNumber); // 底层可能会用到 I64ToBigIntDescriptor
    ```

3. **基本操作和类型转换:** `WasmFloat32ToNumberDescriptor`, `WasmFloat64ToTaggedDescriptor` 涉及到 WebAssembly 中的浮点数转换为 JavaScript 中的 Number 类型。虽然直接的 JavaScript 代码看不到这些描述符，但它们在引擎内部处理类型转换时起作用。

4. **对象操作:** `CloneObjectWithVectorDescriptor`, `CloneObjectBaselineDescriptor` 关联到 JavaScript 中对象的克隆操作，例如使用扩展运算符创建新对象。

    ```javascript
    const obj1 = { a: 1, b: 2 };
    const obj2 = { ...obj1, c: 3 }; // 对象克隆，底层可能用到相关描述符
    ```

5. **运算符和函数调用:** `BinaryOp_WithFeedbackDescriptor`, `UnaryOp_WithFeedbackDescriptor`, `CallTrampoline_BaselineDescriptor`, `Construct_WithFeedbackDescriptor` 等描述了 JavaScript 中运算符操作和函数调用的底层实现，包括类型反馈的收集和优化。

    ```javascript
    const sum = 1 + 2; // BinaryOp_WithFeedbackDescriptor 可能描述了这个加法操作
    function foo(x) { return -x; } // UnaryOp_WithFeedbackDescriptor 可能描述了这个取负操作
    foo(5);

    function MyClass() {}
    const instance = new MyClass(); // Construct_WithFeedbackDescriptor 描述了构造函数调用
    ```

**代码逻辑推理（假设输入与输出）:**

以 `WasmFloat32ToNumberDescriptor` 为例：

*   **假设输入:** 一个 `float` 类型的 WebAssembly 值，例如 `3.14f`。
*   **预期输出:**  一个 V8 的 `Tagged<Number>` 对象，其值为 `3.14`。

V8 的代码生成器会使用 `WasmFloat32ToNumberDescriptor` 来了解如何调用执行实际转换的内部函数。它知道需要传递一个 `float`，并且期望返回一个表示 JavaScript Number 的 `Tagged` 指针。

**用户常见的编程错误:**

虽然用户通常不会直接操作这些底层的接口描述符，但理解它们有助于理解一些编程错误背后的原因：

1. **类型错误:**  在与 WebAssembly 交互时，如果 JavaScript 代码传递了错误类型的数据给 WebAssembly 函数（与 WebAssembly 模块的签名不匹配），V8 引擎会抛出 `TypeError`。这部分是由于 V8 遵循了接口描述符中定义的类型约束。

    ```javascript
    // 假设 WebAssembly 函数期望一个 float 参数
    // (func $wasmFunction (param f32) (result i32))
    const wasmInstance = // ...
    try {
      wasmInstance.exports.wasmFunction("hello"); // 错误：传递了字符串而不是 float
    } catch (e) {
      console.error(e); // 可能抛出 TypeError
    }
    ```

2. **BigInt 溢出或精度丢失:** 在 Number 和 BigInt 之间进行不安全的转换可能会导致溢出或精度丢失。

    ```javascript
    const bigIntValue = 2n**100n;
    const numberValue = Number(bigIntValue); // 精度丢失，因为 Number 无法精确表示这么大的整数
    console.log(numberValue); // 输出 Infinity 或一个近似值

    const largeNumber = Number.MAX_SAFE_INTEGER + 1;
    const bigIntFromNumber = BigInt(largeNumber); //  bigIntFromNumber 可能不等于 largeNumber，因为 largeNumber 的精度已经丢失
    console.log(bigIntFromNumber === BigInt(Number.MAX_SAFE_INTEGER + 1)); // 可能是 false
    ```

3. **不正确的函数调用参数:**  在更底层的 V8 开发中，如果手动构建函数调用而不遵循接口描述符的定义（例如，传递了错误数量或类型的参数），会导致程序崩溃或未定义的行为。虽然普通 JavaScript 用户不会遇到这种情况，但 V8 开发者需要严格遵守这些描述符。

总而言之，`v8/src/codegen/interface-descriptors.h` 是 V8 代码生成过程中的关键组成部分，它确保了引擎内部函数调用的类型安全和正确性，同时也为 JavaScript 的各种功能（特别是与 WebAssembly 和 BigInt 相关的）提供了底层的接口定义。

### 提示词
```
这是目录为v8/src/codegen/interface-descriptors.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/interface-descriptors.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kValue)
  DEFINE_RESULT_AND_PARAMETER_TYPES(MachineType::AnyTagged(),  // result
                                    MachineType::Float32())    // value
  DECLARE_DESCRIPTOR(WasmFloat32ToNumberDescriptor)
};

class WasmFloat64ToTaggedDescriptor final
    : public StaticCallInterfaceDescriptor<WasmFloat64ToTaggedDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kValue)
  DEFINE_RESULT_AND_PARAMETER_TYPES(MachineType::AnyTagged(),  // result
                                    MachineType::Float64())    // value
  DECLARE_DESCRIPTOR(WasmFloat64ToTaggedDescriptor)
};

class WasmJSToWasmWrapperDescriptor final
    : public StaticCallInterfaceDescriptor<WasmJSToWasmWrapperDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kWrapperBuffer, kInstance, kResultJSArray)
  DEFINE_RESULT_AND_PARAMETER_TYPES(MachineType::AnyTagged(),  // result
                                    MachineType::IntPtr(),     // ParamBuffer
                                    MachineType::AnyTagged(),  // Instance
                                    MachineType::AnyTagged())  // Result jsarray
  DECLARE_DESCRIPTOR(WasmJSToWasmWrapperDescriptor)

  static constexpr int kMaxRegisterParams = 1;
  // Only the first parameter, `WrapperBuffer` gets passed over a register, the
  // instance and the js-array get passed over the stack. The reason is that
  // these parameters get forwarded to another function, and GC's may happen
  // until this other function gets called. By passing these parameters over the
  // stack the references get scanned as part of the caller frame, and the GC
  // does not have to scan anything on the `WasmJSToWasmWrapper` frame.
  static constexpr inline auto registers();
  static constexpr inline Register WrapperBufferRegister();
};

class WasmToJSWrapperDescriptor final
    : public StaticCallInterfaceDescriptor<WasmToJSWrapperDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_RESULT_AND_PARAMETERS_NO_CONTEXT(4, kWasmImportData)
  DEFINE_RESULT_AND_PARAMETER_TYPES(MachineType::IntPtr(),     // GP return 1
                                    MachineType::IntPtr(),     // GP return 2
                                    MachineType::Float64(),    // FP return 1
                                    MachineType::Float64(),    // FP return 2
                                    MachineType::AnyTagged())  // WasmImportData
  DECLARE_DESCRIPTOR(WasmToJSWrapperDescriptor)

  static constexpr int kMaxRegisterParams = 1;
  static constexpr inline auto registers();
  static constexpr inline auto return_registers();
  static constexpr inline auto return_double_registers();
};

class WasmSuspendDescriptor final
    : public StaticCallInterfaceDescriptor<WasmSuspendDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_RESULT_AND_PARAMETERS_NO_CONTEXT(1, kArg0)
  DEFINE_RESULT_AND_PARAMETER_TYPES(MachineType::AnyTagged(),  // result
                                    MachineType::AnyTagged())  // value
  DECLARE_DESCRIPTOR(WasmSuspendDescriptor)
};

class V8_EXPORT_PRIVATE I64ToBigIntDescriptor final
    : public StaticCallInterfaceDescriptor<I64ToBigIntDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kArgument)
  DEFINE_PARAMETER_TYPES(MachineType::Int64())  // kArgument
  DECLARE_DESCRIPTOR(I64ToBigIntDescriptor)
};

// 32 bits version of the I64ToBigIntDescriptor call interface descriptor
class V8_EXPORT_PRIVATE I32PairToBigIntDescriptor final
    : public StaticCallInterfaceDescriptor<I32PairToBigIntDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kLow, kHigh)
  DEFINE_PARAMETER_TYPES(MachineType::Uint32(),  // kLow
                         MachineType::Uint32())  // kHigh
  DECLARE_DESCRIPTOR(I32PairToBigIntDescriptor)
};

class V8_EXPORT_PRIVATE BigIntToI64Descriptor final
    : public StaticCallInterfaceDescriptor<BigIntToI64Descriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kArgument)
  DEFINE_RESULT_AND_PARAMETER_TYPES(MachineType::Int64(),      // result 1
                                    MachineType::AnyTagged())  // kArgument
  DECLARE_DESCRIPTOR(BigIntToI64Descriptor)
};

class V8_EXPORT_PRIVATE BigIntToI32PairDescriptor final
    : public StaticCallInterfaceDescriptor<BigIntToI32PairDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_RESULT_AND_PARAMETERS(2, kArgument)
  DEFINE_RESULT_AND_PARAMETER_TYPES(MachineType::Uint32(),     // result 1
                                    MachineType::Uint32(),     // result 2
                                    MachineType::AnyTagged())  // kArgument
  DECLARE_DESCRIPTOR(BigIntToI32PairDescriptor)
};

class CloneObjectWithVectorDescriptor final
    : public StaticCallInterfaceDescriptor<CloneObjectWithVectorDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kSource, kFlags, kSlot, kVector)
  DEFINE_RESULT_AND_PARAMETER_TYPES(MachineType::TaggedPointer(),  // result 1
                                    MachineType::AnyTagged(),      // kSource
                                    MachineType::TaggedSigned(),   // kFlags
                                    MachineType::TaggedSigned(),   // kSlot
                                    MachineType::AnyTagged())      // kVector
  DECLARE_DESCRIPTOR(CloneObjectWithVectorDescriptor)
};

class CloneObjectBaselineDescriptor final
    : public StaticCallInterfaceDescriptor<CloneObjectBaselineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kSource, kFlags, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kSource
                         MachineType::TaggedSigned(),  // kFlags
                         MachineType::TaggedSigned())  // kSlot
  DECLARE_DESCRIPTOR(CloneObjectBaselineDescriptor)
};

class BinaryOp_WithFeedbackDescriptor
    : public StaticCallInterfaceDescriptor<BinaryOp_WithFeedbackDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kLeft, kRight, kSlot, kFeedbackVector)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kLeft
                         MachineType::AnyTagged(),  // kRight
                         MachineType::UintPtr(),    // kSlot
                         MachineType::AnyTagged())  // kFeedbackVector
  DECLARE_DESCRIPTOR(BinaryOp_WithFeedbackDescriptor)
};

class CallTrampoline_Baseline_CompactDescriptor
    : public StaticCallInterfaceDescriptor<
          CallTrampoline_Baseline_CompactDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  using ArgumentCountField = base::BitField<uint32_t, 0, 8>;
  using SlotField = base::BitField<uintptr_t, 8, 24>;

  static bool EncodeBitField(uint32_t argc, uintptr_t slot, uint32_t* out) {
    if (ArgumentCountField::is_valid(argc) && SlotField::is_valid(slot)) {
      *out = ArgumentCountField::encode(argc) | SlotField::encode(slot);
      return true;
    }
    return false;
  }

  DEFINE_PARAMETERS_NO_CONTEXT_VARARGS(kFunction, kBitField)
  DEFINE_PARAMETER_TYPES(
      MachineType::AnyTagged(),  // kFunction
      MachineType::Uint32())     // kBitField = ArgumentCountField | SlotField
  DECLARE_DESCRIPTOR(CallTrampoline_Baseline_CompactDescriptor)
};

class CallTrampoline_BaselineDescriptor
    : public StaticCallInterfaceDescriptor<CallTrampoline_BaselineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT_VARARGS(kFunction, kActualArgumentsCount, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kFunction
                         MachineType::Int32(),      // kActualArgumentsCount
                         MachineType::UintPtr())    // kSlot
  DECLARE_DESCRIPTOR(CallTrampoline_BaselineDescriptor)
};

class CallTrampoline_WithFeedbackDescriptor
    : public StaticCallInterfaceDescriptor<
          CallTrampoline_WithFeedbackDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_VARARGS(kFunction, kActualArgumentsCount, kSlot,
                            kFeedbackVector, kReceiver)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kFunction
                         MachineType::Int32(),      // kActualArgumentsCount
                         MachineType::UintPtr(),    // kSlot
                         MachineType::AnyTagged(),  // kFeedbackVector
                         MachineType::AnyTagged())  // kReceiver
  DECLARE_DESCRIPTOR(CallTrampoline_WithFeedbackDescriptor)
};

class Compare_WithFeedbackDescriptor
    : public StaticCallInterfaceDescriptor<Compare_WithFeedbackDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kLeft, kRight, kSlot, kFeedbackVector)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kLeft
                         MachineType::AnyTagged(),  // kRight
                         MachineType::UintPtr(),    // kSlot
                         MachineType::AnyTagged())  // kFeedbackVector
  DECLARE_DESCRIPTOR(Compare_WithFeedbackDescriptor)
};

class Compare_BaselineDescriptor
    : public StaticCallInterfaceDescriptor<Compare_BaselineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kLeft, kRight, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kLeft
                         MachineType::AnyTagged(),  // kRight
                         MachineType::UintPtr())    // kSlot
  DECLARE_DESCRIPTOR(Compare_BaselineDescriptor)

  static constexpr inline auto registers();
};

class Construct_BaselineDescriptor
    : public StaticJSCallInterfaceDescriptor<Construct_BaselineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_JS_PARAMETERS_NO_CONTEXT(kSlot)
  DEFINE_JS_PARAMETER_TYPES(MachineType::UintPtr())  // kSlot
  DECLARE_JS_COMPATIBLE_DESCRIPTOR(Construct_BaselineDescriptor)
};

class Construct_WithFeedbackDescriptor
    : public StaticJSCallInterfaceDescriptor<Construct_WithFeedbackDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  // kSlot is passed in a register, kFeedbackVector on the stack.
  DEFINE_JS_PARAMETERS(kSlot, kFeedbackVector)
  DEFINE_JS_PARAMETER_TYPES(MachineType::UintPtr(),    // kSlot
                            MachineType::AnyTagged())  // kFeedbackVector
  DECLARE_JS_COMPATIBLE_DESCRIPTOR(Construct_WithFeedbackDescriptor)
};

class UnaryOp_WithFeedbackDescriptor
    : public StaticCallInterfaceDescriptor<UnaryOp_WithFeedbackDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kValue, kSlot, kFeedbackVector)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kValue
                         MachineType::UintPtr(),    // kSlot
                         MachineType::AnyTagged())  // kFeedbackVector
  DECLARE_DESCRIPTOR(UnaryOp_WithFeedbackDescriptor)
};

class UnaryOp_BaselineDescriptor
    : public StaticCallInterfaceDescriptor<UnaryOp_BaselineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kValue, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kValue
                         MachineType::UintPtr())    // kSlot
  DECLARE_DESCRIPTOR(UnaryOp_BaselineDescriptor)
};

class CheckTurboshaftFloat32TypeDescriptor
    : public StaticCallInterfaceDescriptor<
          CheckTurboshaftFloat32TypeDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_RESULT_AND_PARAMETERS(1, kValue, kExpectedType, kNodeId)
  DEFINE_RESULT_AND_PARAMETER_TYPES(MachineType::TaggedPointer(),
                                    MachineTypeOf<Float32T>::value,
                                    MachineType::TaggedPointer(),
                                    MachineType::TaggedSigned())
  DECLARE_DEFAULT_DESCRIPTOR(CheckTurboshaftFloat32TypeDescriptor)
};

class CheckTurboshaftFloat64TypeDescriptor
    : public StaticCallInterfaceDescriptor<
          CheckTurboshaftFloat64TypeDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_RESULT_AND_PARAMETERS(1, kValue, kExpectedType, kNodeId)
  DEFINE_RESULT_AND_PARAMETER_TYPES(MachineType::TaggedPointer(),
                                    MachineTypeOf<Float64T>::value,
                                    MachineType::TaggedPointer(),
                                    MachineType::TaggedSigned())
  DECLARE_DEFAULT_DESCRIPTOR(CheckTurboshaftFloat64TypeDescriptor)
};

class DebugPrintWordPtrDescriptor
    : public StaticCallInterfaceDescriptor<DebugPrintWordPtrDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_RESULT_AND_PARAMETERS(1, kValue)
  DEFINE_RESULT_AND_PARAMETER_TYPES(MachineType::TaggedPointer(),
                                    MachineType::UintPtr())
  DECLARE_DEFAULT_DESCRIPTOR(DebugPrintWordPtrDescriptor)
};

class DebugPrintFloat64Descriptor
    : public StaticCallInterfaceDescriptor<DebugPrintFloat64Descriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_RESULT_AND_PARAMETERS(1, kValue)
  DEFINE_RESULT_AND_PARAMETER_TYPES(MachineType::TaggedPointer(),
                                    MachineType::Float64())
  DECLARE_DEFAULT_DESCRIPTOR(DebugPrintFloat64Descriptor)
};

#define DEFINE_TFS_BUILTIN_DESCRIPTOR(Name, DoesNeedContext, ...)            \
  class Name##Descriptor                                                     \
      : public StaticCallInterfaceDescriptor<Name##Descriptor> {             \
   public:                                                                   \
    INTERNAL_DESCRIPTOR()                                                    \
    DEFINE_PARAMETERS(__VA_ARGS__)                                           \
    static constexpr bool kNoContext = DoesNeedContext == NeedsContext::kNo; \
    DECLARE_DEFAULT_DESCRIPTOR(Name##Descriptor)                             \
  };
BUILTIN_LIST_TFS(DEFINE_TFS_BUILTIN_DESCRIPTOR)
#undef DEFINE_TFS_BUILTIN_DESCRIPTOR

// This file contains interface descriptor class definitions for builtins
// defined in Torque. It is included here because the class definitions need to
// precede the definition of name##Descriptor::key() below.
#include "torque-generated/interface-descriptors.inc"

#undef DECLARE_DEFAULT_DESCRIPTOR
#undef DECLARE_DESCRIPTOR_WITH_BASE
#undef DECLARE_DESCRIPTOR
#undef DECLARE_JS_COMPATIBLE_DESCRIPTOR
#undef DEFINE_RESULT_AND_PARAMETERS
#undef DEFINE_PARAMETERS_ENTRY
#undef DEFINE_PARAMETERS
#undef DEFINE_PARAMETERS_VARARGS
#undef DEFINE_PARAMETERS_NO_CONTEXT
#undef DEFINE_RESULT_AND_PARAMETERS_NO_CONTEXT
#undef DEFINE_RESULT_AND_PARAMETER_TYPES
#undef DEFINE_PARAMETER_TYPES
#undef DEFINE_JS_PARAMETERS
#undef DEFINE_JS_PARAMETER_TYPES

// We define the association between CallDescriptors::Key and the specialized
// descriptor here to reduce boilerplate and mistakes.
#define DEF_KEY(name, ...) \
  CallDescriptors::Key name##Descriptor::key() { return CallDescriptors::name; }
INTERFACE_DESCRIPTOR_LIST(DEF_KEY)
#undef DEF_KEY
}  // namespace internal
}  // namespace v8

#endif  // V8_CODEGEN_INTERFACE_DESCRIPTORS_H_
```