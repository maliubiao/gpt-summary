Response:
The user wants a summary of the C++ header file `v8/src/codegen/interface-descriptors.h`. I need to identify its purpose and key functionalities.

Here's a breakdown of the code:

1. **Macros for Descriptor Definition:**  The code uses macros like `DEFINE_PARAMETERS`, `DEFINE_PARAMETER_TYPES`, `DECLARE_DESCRIPTOR`, `SANDBOX_EXPOSED_DESCRIPTOR`, and `INTERNAL_DESCRIPTOR`. These seem to be helper macros for defining call interface descriptors.

2. **Base Classes:** It defines base classes like `StaticCallInterfaceDescriptor` and `StaticJSCallInterfaceDescriptor`. This suggests a hierarchy for defining different types of call interfaces.

3. **Specific Descriptor Classes:**  The majority of the code defines various descriptor classes like `VoidDescriptor`, `CCallDescriptor`, `AllocateDescriptor`, `JSTrampolineDescriptor`, `LoadDescriptor`, `StoreDescriptor`, `FastNewObjectDescriptor`, `WriteBarrierDescriptor`, etc. Each of these likely represents a specific calling convention or interface for certain internal V8 functions or builtins.

4. **Parameter Definitions:**  Within each descriptor, `DEFINE_PARAMETERS` and `DEFINE_PARAMETER_TYPES` specify the arguments and their types for the corresponding call interface.

5. **Sandbox Exposure:** The `SANDBOX_EXPOSED_DESCRIPTOR` and `INTERNAL_DESCRIPTOR` macros indicate whether a particular call interface is accessible from the V8 sandbox.

Based on this, the core function of this header file is to **define the calling conventions and parameter structures for various internal V8 functions and builtins**. It acts as a blueprint for how different parts of the V8 engine communicate with each other.

Considering the prompt's additional instructions:

* **`.tq` extension:** The file ends in `.h`, not `.tq`, so it's C++ not Torque.
* **Relationship to JavaScript:** These descriptors define how JavaScript operations are handled at a lower level. For example, `LoadDescriptor` and `StoreDescriptor` relate to accessing properties of JavaScript objects. `JSTrampolineDescriptor` is crucial for calling JavaScript functions.
* **Code logic reasoning:**  The descriptors specify the expected input and output types for different internal calls. For instance, `AllocateDescriptor` takes a size (`kRequestedSize`) and returns a pointer (`result`).
* **Common programming errors:** Incorrectly assuming the calling convention or the order/types of arguments when interacting with V8 internals (which is generally not something typical JavaScript developers do directly).

**Plan for the summary:**

1. State the main function: defining call interfaces.
2. Explain the role of descriptors.
3. Give examples of how these relate to JavaScript operations.
4. Briefly touch upon the C++ nature and sandbox exposure.
好的，让我们来归纳一下 `v8/src/codegen/interface-descriptors.h` 的功能。

**功能归纳:**

`v8/src/codegen/interface-descriptors.h`  的主要功能是**定义了 V8 引擎内部各种函数调用接口的描述符 (Descriptors)**。

更具体地说，它定义了一系列 C++ 类，每个类都代表一种特定的调用约定和参数结构，用于在 V8 的不同组件之间进行函数调用，特别是涉及到代码生成和内置函数调用时。

**具体功能点:**

1. **定义调用约定:** 这些描述符规定了函数调用时参数的传递方式（例如，通过寄存器还是堆栈）、参数的类型以及返回值的类型。

2. **定义参数列表:**  每个描述符都明确列出了调用该接口所需的参数及其类型。

3. **区分内部调用和沙箱暴露:**  通过 `SANDBOX_EXPOSED_DESCRIPTOR` 和 `INTERNAL_DESCRIPTOR` 宏，区分了哪些内置函数可以通过代码指针表（CPT）从沙箱内部访问，哪些只能在 V8 内部直接调用。这对于安全至关重要。

4. **支持不同的调用场景:** 涵盖了各种调用场景，例如：
    * 常规的 JavaScript 函数调用 (`JSTrampolineDescriptor`)
    * RegExp 相关操作 (`RegExpTrampolineDescriptor`)
    * 属性加载和存储 (`LoadDescriptor`, `StoreDescriptor`)
    * 对象分配 (`AllocateDescriptor`)
    * 类型转换 (`TypeConversionDescriptor`)
    * 内存屏障 (`WriteBarrierDescriptor`)
    * WebAssembly 相关调用 (`WasmDummyDescriptor`, `WasmHandleStackOverflowDescriptor`)
    * 以及其他各种内部操作。

5. **为代码生成器提供信息:** 这些描述符为 V8 的代码生成器（例如，TurboFan 和 CodeStubAssembler）提供了必要的信息，以便正确地生成函数调用的汇编代码。

**与 JavaScript 的关系:**

`v8/src/codegen/interface-descriptors.h` 中定义的描述符是 V8 执行 JavaScript 代码的基础。当 JavaScript 代码执行到需要调用内置函数或者进行底层操作时，V8 会使用这些描述符来生成相应的机器码。

例如，当我们访问一个 JavaScript 对象的属性时，V8 内部可能会使用类似 `LoadDescriptor` 的描述符来调用相应的加载逻辑。当我们为一个对象的属性赋值时，可能会使用 `StoreDescriptor`。

**如果 `v8/src/codegen/interface-descriptors.h` 以 `.tq` 结尾:**

如果该文件以 `.tq` 结尾，那么它将是一个 **Torque 源代码文件**。 Torque 是 V8 使用的一种领域特定语言 (DSL)，用于更安全、更易于维护地定义内置函数和运行时调用的实现。 Torque 文件会被编译成 C++ 代码。

**JavaScript 示例 (概念性):**

虽然我们不能直接在 JavaScript 中操作这些描述符，但 JavaScript 的行为会受到它们的影响。

```javascript
const obj = { x: 10 };
const value = obj.x; //  V8 内部可能涉及到 LoadDescriptor 的调用

obj.y = 20; // V8 内部可能涉及到 StoreDescriptor 的调用

function add(a, b) {
  return a + b;
}
add(5, 3); // V8 内部可能涉及到 JSTrampolineDescriptor 的调用来处理函数调用
```

**代码逻辑推理 (假设输入与输出):**

以 `AllocateDescriptor` 为例：

* **假设输入:**  `kRequestedSize = 64` (表示请求分配 64 字节的内存)
* **预期输出:**  一个指向新分配的堆内存块的指针 (`result`)。

**用户常见的编程错误 (与 V8 内部实现交互的错误，通常开发者不会直接遇到):**

通常的 JavaScript 开发者不会直接与这些描述符交互。但如果有人尝试 hack V8 或者编写 V8 扩展，可能会犯以下错误：

* **假设了错误的调用约定:**  错误地估计了内置函数期望的参数类型或顺序。
* **直接修改或绕过这些描述符:**  这可能会导致 V8 的不稳定或安全漏洞。

**总结:**

`v8/src/codegen/interface-descriptors.h`  是 V8 引擎中一个关键的头文件，它详细定义了 V8 内部函数调用的接口规范，确保了 V8 各个组件之间能够正确、高效地通信和协作，从而支撑 JavaScript 代码的执行。它就像一份内部 API 文档，定义了 V8 引擎的低级调用协议。

### 提示词
```
这是目录为v8/src/codegen/interface-descriptors.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/interface-descriptors.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
kTarget */               \
                         MachineType::AnyTagged(), /* kNewTarget */            \
                         MachineType::Int32(),     /* kActualArgumentsCount */ \
                         ##__VA_ARGS__)

// Code/Builtins using this descriptor are referenced from inside the sandbox
// through a code pointer and must therefore be exposed via the code pointer
// table (CPT). They should use a code entrypoint tag which will be used to tag
// the entry in the CPT and will be checked to match the tag expected at the
// callsite. Only "compatible" builtins should use the same code entrypoint tag
// as it must be assumed that an attacker can swap code pointers (the indices
// into the CPT) and therefore can invoke all builtins that use the same tag
// from a given callsite.
#define SANDBOX_EXPOSED_DESCRIPTOR(tag) \
  static constexpr CodeEntrypointTag kEntrypointTag = tag;

// Code/Builtins using this descriptor are not referenced from inside the
// sandbox but only called directly from other code. They are therefore not
// exposed to the sandbox via the CPT and so use the kInvalidEntrypointTag.
#define INTERNAL_DESCRIPTOR() \
  static constexpr CodeEntrypointTag kEntrypointTag = kInvalidEntrypointTag;

#define DECLARE_DESCRIPTOR(name)                                    \
  DECLARE_DESCRIPTOR_WITH_BASE(name, StaticCallInterfaceDescriptor) \
 protected:                                                         \
  explicit name(CallDescriptors::Key key)                           \
      : StaticCallInterfaceDescriptor(key) {}                       \
                                                                    \
 public:

class V8_EXPORT_PRIVATE VoidDescriptor
    : public StaticCallInterfaceDescriptor<VoidDescriptor> {
 public:
  // The void descriptor could (and indeed probably should) also be NO_CONTEXT,
  // but this breaks some code assembler unittests.
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS()
  DEFINE_PARAMETER_TYPES()
  DECLARE_DESCRIPTOR(VoidDescriptor)

  static constexpr auto registers();
};

// Marks deoptimization entry builtins. Precise calling conventions currently
// differ based on the platform.
// TODO(jgruber): Once this is unified, we could create a better description
// here.
using DeoptimizationEntryDescriptor = VoidDescriptor;

// TODO(jgruber): Consider filling in the details here; however, this doesn't
// make too much sense as long as the descriptor isn't used or verified.
using JSEntryDescriptor = VoidDescriptor;

// TODO(jgruber): Consider filling in the details here; however, this doesn't
// make too much sense as long as the descriptor isn't used or verified.
using ContinueToBuiltinDescriptor = VoidDescriptor;

// Dummy descriptor that marks builtins with C calling convention.
// TODO(jgruber): Define real descriptors for C calling conventions.
class CCallDescriptor : public StaticCallInterfaceDescriptor<CCallDescriptor> {
 public:
  SANDBOX_EXPOSED_DESCRIPTOR(kDefaultCodeEntrypointTag)
  DEFINE_PARAMETERS()
  DEFINE_PARAMETER_TYPES()
  DECLARE_DESCRIPTOR(CCallDescriptor)
};

// TODO(jgruber): Consider filling in the details here; however, this doesn't
// make too much sense as long as the descriptor isn't used or verified.
class CEntryDummyDescriptor
    : public StaticCallInterfaceDescriptor<CEntryDummyDescriptor> {
 public:
  SANDBOX_EXPOSED_DESCRIPTOR(kDefaultCodeEntrypointTag)
  DEFINE_PARAMETERS()
  DEFINE_PARAMETER_TYPES()
  DECLARE_DESCRIPTOR(CEntryDummyDescriptor)
};

// TODO(wasm): Consider filling in details / defining real descriptors for all
// builtins still using this placeholder descriptor.
class WasmDummyDescriptor
    : public StaticCallInterfaceDescriptor<WasmDummyDescriptor> {
 public:
  SANDBOX_EXPOSED_DESCRIPTOR(kWasmEntrypointTag)
  DEFINE_PARAMETERS()
  DEFINE_PARAMETER_TYPES()
  DECLARE_DESCRIPTOR(WasmDummyDescriptor)
};

// TODO(wasm): Consider filling in details / defining real descriptors for all
// builtins still using this placeholder descriptor.
class WasmDummyWithJSLinkageDescriptor
    : public StaticCallInterfaceDescriptor<WasmDummyWithJSLinkageDescriptor> {
 public:
  SANDBOX_EXPOSED_DESCRIPTOR(kJSEntrypointTag)
  DEFINE_PARAMETERS()
  DEFINE_PARAMETER_TYPES()
  DECLARE_DESCRIPTOR(WasmDummyWithJSLinkageDescriptor)
};

class WasmHandleStackOverflowDescriptor
    : public StaticCallInterfaceDescriptor<WasmHandleStackOverflowDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kFrameBase, kGap)
  DEFINE_RESULT_AND_PARAMETER_TYPES(MachineType::AnyTagged(),  // result
                                    MachineType::Pointer(),    // kFrameBase
                                    MachineType::Uint32())     // kGap
  DECLARE_DESCRIPTOR(WasmHandleStackOverflowDescriptor)

  static constexpr inline Register FrameBaseRegister();
  static constexpr inline Register GapRegister();
};

class AllocateDescriptor
    : public StaticCallInterfaceDescriptor<AllocateDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kRequestedSize)
  DEFINE_RESULT_AND_PARAMETER_TYPES(MachineType::TaggedPointer(),  // result 1
                                    MachineType::IntPtr())  // kRequestedSize
  DECLARE_DESCRIPTOR(AllocateDescriptor)

  static constexpr auto registers();
};

class NewHeapNumberDescriptor
    : public StaticCallInterfaceDescriptor<NewHeapNumberDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kValue)
  DEFINE_RESULT_AND_PARAMETER_TYPES(MachineType::TaggedPointer(),  // Result
                                    MachineType::Float64())        // kValue
  DECLARE_DESCRIPTOR(NewHeapNumberDescriptor)
};

// This descriptor defines the JavaScript calling convention and is used by all
// code that can be installed on a JSFunction. Target, new.target, argc,
// context and potentially the dispatch entry are passed in registers while
// receiver and the rest of the JS arguments are passed on the stack.
#ifdef V8_ENABLE_LEAPTIERING
class JSTrampolineDescriptor
    : public StaticJSCallInterfaceDescriptor<JSTrampolineDescriptor> {
 public:
  SANDBOX_EXPOSED_DESCRIPTOR(kJSEntrypointTag)
  DEFINE_JS_PARAMETERS(kDispatchHandle)
  DEFINE_JS_PARAMETER_TYPES(MachineType::Int32())

  DECLARE_JS_COMPATIBLE_DESCRIPTOR(JSTrampolineDescriptor)

  static constexpr auto registers();
};
#else
class JSTrampolineDescriptor
    : public StaticJSCallInterfaceDescriptor<JSTrampolineDescriptor> {
 public:
  SANDBOX_EXPOSED_DESCRIPTOR(kJSEntrypointTag)
  DEFINE_JS_PARAMETERS()
  DEFINE_JS_PARAMETER_TYPES()

  DECLARE_JS_COMPATIBLE_DESCRIPTOR(JSTrampolineDescriptor)

  static constexpr auto registers();
};
#endif

// Descriptor used for code using the RegExp calling convention, in particular
// the RegExp interpreter trampolines.
class RegExpTrampolineDescriptor
    : public StaticCallInterfaceDescriptor<RegExpTrampolineDescriptor> {
 public:
  SANDBOX_EXPOSED_DESCRIPTOR(kRegExpEntrypointTag)
  DEFINE_PARAMETERS()
  DEFINE_PARAMETER_TYPES()
  DECLARE_DESCRIPTOR(RegExpTrampolineDescriptor)
};

class ContextOnlyDescriptor
    : public StaticCallInterfaceDescriptor<ContextOnlyDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS()
  DEFINE_PARAMETER_TYPES()
  DECLARE_DESCRIPTOR(ContextOnlyDescriptor)

  static constexpr auto registers();
};

class NoContextDescriptor
    : public StaticCallInterfaceDescriptor<NoContextDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT()
  DEFINE_PARAMETER_TYPES()
  DECLARE_DESCRIPTOR(NoContextDescriptor)

  static constexpr auto registers();
};

// LoadDescriptor is used by all stubs that implement Load ICs.
class LoadDescriptor : public StaticCallInterfaceDescriptor<LoadDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kReceiver, kName, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kReceiver
                         MachineType::AnyTagged(),     // kName
                         MachineType::TaggedSigned())  // kSlot
  DECLARE_DESCRIPTOR(LoadDescriptor)

  static constexpr inline Register ReceiverRegister();
  static constexpr inline Register NameRegister();
  static constexpr inline Register SlotRegister();

  static constexpr auto registers();
};

// LoadBaselineDescriptor is a load descriptor that does not take a context as
// input.
class LoadBaselineDescriptor
    : public StaticCallInterfaceDescriptor<LoadBaselineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kReceiver, kName, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kReceiver
                         MachineType::AnyTagged(),     // kName
                         MachineType::TaggedSigned())  // kSlot
  DECLARE_DESCRIPTOR(LoadBaselineDescriptor)

  static constexpr auto registers();
};

class LoadGlobalNoFeedbackDescriptor
    : public StaticCallInterfaceDescriptor<LoadGlobalNoFeedbackDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kName, kICKind)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kName
                         MachineType::TaggedSigned())  // kICKind
  DECLARE_DESCRIPTOR(LoadGlobalNoFeedbackDescriptor)

  static constexpr inline Register ICKindRegister();

  static constexpr auto registers();
};

class LoadNoFeedbackDescriptor
    : public StaticCallInterfaceDescriptor<LoadNoFeedbackDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kReceiver, kName, kICKind)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kReceiver
                         MachineType::AnyTagged(),     // kName
                         MachineType::TaggedSigned())  // kICKind
  DECLARE_DESCRIPTOR(LoadNoFeedbackDescriptor)

  static constexpr inline Register ICKindRegister();

  static constexpr auto registers();
};

class LoadGlobalDescriptor
    : public StaticCallInterfaceDescriptor<LoadGlobalDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kName, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kName
                         MachineType::TaggedSigned())  // kSlot
  DECLARE_DESCRIPTOR(LoadGlobalDescriptor)

  static constexpr auto registers();
};

class LoadGlobalBaselineDescriptor
    : public StaticCallInterfaceDescriptor<LoadGlobalBaselineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kName, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kName
                         MachineType::TaggedSigned())  // kSlot
  DECLARE_DESCRIPTOR(LoadGlobalBaselineDescriptor)

  static constexpr auto registers();
};

class LookupWithVectorDescriptor
    : public StaticCallInterfaceDescriptor<LookupWithVectorDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kName, kDepth, kSlot, kVector)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kName
                         MachineType::AnyTagged(),  // kDepth
                         MachineType::AnyTagged(),  // kSlot
                         MachineType::AnyTagged())  // kVector
  DECLARE_DESCRIPTOR(LookupWithVectorDescriptor)
};

class LookupTrampolineDescriptor
    : public StaticCallInterfaceDescriptor<LookupTrampolineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kName, kDepth, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kName
                         MachineType::AnyTagged(),  // kDepth
                         MachineType::AnyTagged())  // kSlot
  DECLARE_DESCRIPTOR(LookupTrampolineDescriptor)
};

class LookupBaselineDescriptor
    : public StaticCallInterfaceDescriptor<LookupBaselineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kName, kDepth, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kName
                         MachineType::AnyTagged(),  // kDepth
                         MachineType::AnyTagged())  // kSlot
  DECLARE_DESCRIPTOR(LookupBaselineDescriptor)
};

class MaglevOptimizeCodeOrTailCallOptimizedCodeSlotDescriptor
    : public StaticCallInterfaceDescriptor<
          MaglevOptimizeCodeOrTailCallOptimizedCodeSlotDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kFlags, kFeedbackVector, kTemporary)
  DEFINE_PARAMETER_TYPES(MachineType::Int32(),          // kFlags
                         MachineType::TaggedPointer(),  // kFeedbackVector
                         MachineType::AnyTagged())      // kTemporary
  DECLARE_DESCRIPTOR(MaglevOptimizeCodeOrTailCallOptimizedCodeSlotDescriptor)

  static constexpr inline Register FlagsRegister();
  static constexpr inline Register FeedbackVectorRegister();

  static constexpr inline Register TemporaryRegister();

  static constexpr inline auto registers();
};

class StoreDescriptor : public StaticCallInterfaceDescriptor<StoreDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kReceiver, kName, kValue, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kReceiver
                         MachineType::AnyTagged(),     // kName
                         MachineType::AnyTagged(),     // kValue
                         MachineType::TaggedSigned())  // kSlot
  DECLARE_DESCRIPTOR(StoreDescriptor)

  static constexpr inline Register ReceiverRegister();
  static constexpr inline Register NameRegister();
  static constexpr inline Register ValueRegister();
  static constexpr inline Register SlotRegister();

  static constexpr auto registers();
};

class StoreNoFeedbackDescriptor
    : public StaticCallInterfaceDescriptor<StoreNoFeedbackDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kReceiver, kName, kValue)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kReceiver
                         MachineType::AnyTagged(),  // kName
                         MachineType::AnyTagged())  // kValue
  DECLARE_DESCRIPTOR(StoreNoFeedbackDescriptor)

  static constexpr auto registers();
};

class StoreBaselineDescriptor
    : public StaticCallInterfaceDescriptor<StoreBaselineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kReceiver, kName, kValue, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kReceiver
                         MachineType::AnyTagged(),     // kName
                         MachineType::AnyTagged(),     // kValue
                         MachineType::TaggedSigned())  // kSlot
  DECLARE_DESCRIPTOR(StoreBaselineDescriptor)

  static constexpr auto registers();
};

class StoreTransitionDescriptor
    : public StaticCallInterfaceDescriptor<StoreTransitionDescriptor> {
 public:
  SANDBOX_EXPOSED_DESCRIPTOR(kStoreTransitionICHandlerEntrypointTag)
  DEFINE_PARAMETERS(kReceiver, kName, kMap, kValue, kSlot, kVector)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kReceiver
                         MachineType::AnyTagged(),     // kName
                         MachineType::AnyTagged(),     // kMap
                         MachineType::AnyTagged(),     // kValue
                         MachineType::TaggedSigned(),  // kSlot
                         MachineType::AnyTagged())     // kVector
  DECLARE_DESCRIPTOR(StoreTransitionDescriptor)

  static constexpr inline Register MapRegister();

  static constexpr auto registers();
};

class StoreWithVectorDescriptor
    : public StaticCallInterfaceDescriptor<StoreWithVectorDescriptor> {
 public:
  SANDBOX_EXPOSED_DESCRIPTOR(kStoreWithVectorICHandlerEntrypointTag)
  DEFINE_PARAMETERS(kReceiver, kName, kValue, kSlot, kVector)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kReceiver
                         MachineType::AnyTagged(),     // kName
                         MachineType::AnyTagged(),     // kValue
                         MachineType::TaggedSigned(),  // kSlot
                         MachineType::AnyTagged())     // kVector
  DECLARE_DESCRIPTOR(StoreWithVectorDescriptor)

  static constexpr inline Register VectorRegister();

  static constexpr auto registers();
};

class StoreGlobalDescriptor
    : public StaticCallInterfaceDescriptor<StoreGlobalDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kName, kValue, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kName
                         MachineType::AnyTagged(),     // kValue
                         MachineType::TaggedSigned())  // kSlot
  DECLARE_DESCRIPTOR(StoreGlobalDescriptor)

  static constexpr auto registers();
};

class StoreGlobalBaselineDescriptor
    : public StaticCallInterfaceDescriptor<StoreGlobalBaselineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kName, kValue, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kName
                         MachineType::AnyTagged(),     // kValue
                         MachineType::TaggedSigned())  // kSlot
  DECLARE_DESCRIPTOR(StoreGlobalBaselineDescriptor)

  static constexpr auto registers();
};

class StoreGlobalWithVectorDescriptor
    : public StaticCallInterfaceDescriptor<StoreGlobalWithVectorDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kName, kValue, kSlot, kVector)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kName
                         MachineType::AnyTagged(),     // kValue
                         MachineType::TaggedSigned(),  // kSlot
                         MachineType::AnyTagged())     // kVector
  DECLARE_DESCRIPTOR(StoreGlobalWithVectorDescriptor)

  static constexpr auto registers();
};

class DefineKeyedOwnDescriptor
    : public StaticCallInterfaceDescriptor<DefineKeyedOwnDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kReceiver, kName, kValue, kFlags, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kReceiver
                         MachineType::AnyTagged(),     // kName
                         MachineType::AnyTagged(),     // kValue
                         MachineType::TaggedSigned(),  // kFlags
                         MachineType::TaggedSigned())  // kSlot
  DECLARE_DESCRIPTOR(DefineKeyedOwnDescriptor)

  static constexpr inline Register FlagsRegister();

  static constexpr auto registers();
};

class DefineKeyedOwnBaselineDescriptor
    : public StaticCallInterfaceDescriptor<DefineKeyedOwnBaselineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kReceiver, kName, kValue, kFlags, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kReceiver
                         MachineType::AnyTagged(),     // kName
                         MachineType::AnyTagged(),     // kValue
                         MachineType::TaggedSigned(),  // kFlags
                         MachineType::TaggedSigned())  // kSlot
  DECLARE_DESCRIPTOR(DefineKeyedOwnBaselineDescriptor)

  static constexpr auto registers();
};

class DefineKeyedOwnWithVectorDescriptor
    : public StaticCallInterfaceDescriptor<DefineKeyedOwnWithVectorDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kReceiver, kName, kValue, kFlags,
                    kSlot,   // register argument
                    kVector  // stack argument
  )
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kReceiver
                         MachineType::AnyTagged(),     // kName
                         MachineType::AnyTagged(),     // kValue
                         MachineType::TaggedSigned(),  // kFlags
                         MachineType::TaggedSigned(),  // kSlot
                         MachineType::AnyTagged())     // kVector
  DECLARE_DESCRIPTOR(DefineKeyedOwnWithVectorDescriptor)

  static constexpr auto registers();
};

class LoadWithVectorDescriptor
    : public StaticCallInterfaceDescriptor<LoadWithVectorDescriptor> {
 public:
  SANDBOX_EXPOSED_DESCRIPTOR(kLoadWithVectorICHandlerEntrypointTag)
  // TODO(v8:9497): Revert the Machine type for kSlot to the
  // TaggedSigned once Torque can emit better call descriptors
  DEFINE_PARAMETERS(kReceiver, kName, kSlot, kVector)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kReceiver
                         MachineType::AnyTagged(),  // kName
                         MachineType::AnyTagged(),  // kSlot
                         MachineType::AnyTagged())  // kVector
  DECLARE_DESCRIPTOR(LoadWithVectorDescriptor)

  static constexpr inline Register VectorRegister();

  static constexpr auto registers();
};

class KeyedLoadBaselineDescriptor
    : public StaticCallInterfaceDescriptor<KeyedLoadBaselineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kReceiver, kName, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kReceiver
                         MachineType::AnyTagged(),     // kName
                         MachineType::TaggedSigned())  // kSlot
  DECLARE_DESCRIPTOR(KeyedLoadBaselineDescriptor)

  static constexpr inline Register ReceiverRegister();
  static constexpr inline Register NameRegister();
  static constexpr inline Register SlotRegister();

  static constexpr auto registers();
};

class KeyedLoadDescriptor
    : public StaticCallInterfaceDescriptor<KeyedLoadDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kReceiver, kName, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kReceiver
                         MachineType::AnyTagged(),     // kName
                         MachineType::TaggedSigned())  // kSlot
  DECLARE_DESCRIPTOR(KeyedLoadDescriptor)

  static constexpr auto registers();
};

class KeyedLoadWithVectorDescriptor
    : public StaticCallInterfaceDescriptor<KeyedLoadWithVectorDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kReceiver, kName, kSlot, kVector)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kReceiver
                         MachineType::AnyTagged(),     // kName
                         MachineType::TaggedSigned(),  // kSlot
                         MachineType::AnyTagged())     // kVector
  DECLARE_DESCRIPTOR(KeyedLoadWithVectorDescriptor)

  static constexpr inline Register VectorRegister();

  static constexpr auto registers();
};

class EnumeratedKeyedLoadBaselineDescriptor
    : public StaticCallInterfaceDescriptor<
          EnumeratedKeyedLoadBaselineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kReceiver, kName, kEnumIndex, kCacheType, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kReceiver
                         MachineType::AnyTagged(),     // kName
                         MachineType::TaggedSigned(),  // kEnumIndex
                         MachineType::AnyTagged(),     // kCacheType
                         MachineType::TaggedSigned())  // kSlot
  DECLARE_DESCRIPTOR(EnumeratedKeyedLoadBaselineDescriptor)

  static constexpr inline Register EnumIndexRegister();
  static constexpr inline Register CacheTypeRegister();
  static constexpr inline Register SlotRegister();

  static constexpr auto registers();
};

class EnumeratedKeyedLoadDescriptor
    : public StaticCallInterfaceDescriptor<EnumeratedKeyedLoadDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kReceiver, kName, kEnumIndex, kCacheType, kSlot, kVector)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kReceiver
                         MachineType::AnyTagged(),     // kName
                         MachineType::TaggedSigned(),  // kEnumIndex
                         MachineType::AnyTagged(),     // kCacheType
                         MachineType::TaggedSigned(),  // kSlot
                         MachineType::AnyTagged())     // kVector
  DECLARE_DESCRIPTOR(EnumeratedKeyedLoadDescriptor)

  static constexpr auto registers();
};

class KeyedHasICBaselineDescriptor
    : public StaticCallInterfaceDescriptor<KeyedHasICBaselineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kReceiver, kName, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kReceiver
                         MachineType::AnyTagged(),     // kName
                         MachineType::TaggedSigned())  // kSlot
  DECLARE_DESCRIPTOR(KeyedHasICBaselineDescriptor)

  static constexpr inline Register ReceiverRegister();
  static constexpr inline Register NameRegister();
  static constexpr inline Register SlotRegister();

  static constexpr auto registers();
};

class KeyedHasICWithVectorDescriptor
    : public StaticCallInterfaceDescriptor<KeyedHasICWithVectorDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kReceiver, kName, kSlot, kVector)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kReceiver
                         MachineType::AnyTagged(),     // kName
                         MachineType::TaggedSigned(),  // kSlot
                         MachineType::AnyTagged())     // kVector
  DECLARE_DESCRIPTOR(KeyedHasICWithVectorDescriptor)

  static constexpr inline Register VectorRegister();

  static constexpr auto registers();
};

// Like LoadWithVectorDescriptor, except we pass the receiver (the object which
// should be used as the receiver for accessor function calls) and the lookup
// start object separately.
class LoadWithReceiverAndVectorDescriptor
    : public StaticCallInterfaceDescriptor<
          LoadWithReceiverAndVectorDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  // TODO(v8:9497): Revert the Machine type for kSlot to the
  // TaggedSigned once Torque can emit better call descriptors
  DEFINE_PARAMETERS(kReceiver, kLookupStartObject, kName, kSlot, kVector)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kReceiver
                         MachineType::AnyTagged(),  // kLookupStartObject
                         MachineType::AnyTagged(),  // kName
                         MachineType::AnyTagged(),  // kSlot
                         MachineType::AnyTagged())  // kVector
  DECLARE_DESCRIPTOR(LoadWithReceiverAndVectorDescriptor)

  static constexpr inline Register LookupStartObjectRegister();

  static constexpr auto registers();
};

class LoadWithReceiverBaselineDescriptor
    : public StaticCallInterfaceDescriptor<LoadWithReceiverBaselineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  // TODO(v8:9497): Revert the Machine type for kSlot to the
  // TaggedSigned once Torque can emit better call descriptors
  DEFINE_PARAMETERS_NO_CONTEXT(kReceiver, kLookupStartObject, kName, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kReceiver
                         MachineType::AnyTagged(),  // kLookupStartObject
                         MachineType::AnyTagged(),  // kName
                         MachineType::AnyTagged())  // kSlot
  DECLARE_DESCRIPTOR(LoadWithReceiverBaselineDescriptor)

  static constexpr auto registers();
};

class LoadGlobalWithVectorDescriptor
    : public StaticCallInterfaceDescriptor<LoadGlobalWithVectorDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kName, kSlot, kVector)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kName
                         MachineType::TaggedSigned(),  // kSlot
                         MachineType::AnyTagged())     // kVector
  DECLARE_DESCRIPTOR(LoadGlobalWithVectorDescriptor)

  static constexpr inline Register VectorRegister();

  static constexpr auto registers();
};

class FastNewObjectDescriptor
    : public StaticCallInterfaceDescriptor<FastNewObjectDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kTarget, kNewTarget)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kTarget
                         MachineType::AnyTagged())  // kNewTarget
  DECLARE_DESCRIPTOR(FastNewObjectDescriptor)

  static constexpr inline Register TargetRegister();
  static constexpr inline Register NewTargetRegister();

  static constexpr auto registers();
};

class WriteBarrierDescriptor final
    : public StaticCallInterfaceDescriptor<WriteBarrierDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kObject, kSlotAddress)
  DEFINE_PARAMETER_TYPES(MachineType::TaggedPointer(),  // kObject
                         MachineType::Pointer())        // kSlotAddress

  DECLARE_DESCRIPTOR(WriteBarrierDescriptor)
  static constexpr auto registers();
  static constexpr bool kRestrictAllocatableRegisters = true;
  static constexpr bool kCalleeSaveRegisters = true;
  static constexpr inline Register ObjectRegister();
  static constexpr inline Register SlotAddressRegister();
  // A temporary register used in helpers.
  static constexpr inline Register ValueRegister();
  static constexpr inline RegList ComputeSavedRegisters(
      Register object, Register slot_address = no_reg);
#if DEBUG
  static void Verify(CallInterfaceDescriptorData* data);
#endif
};

// Write barriers for indirect pointer field writes require one additional
// parameter (the IndirectPointerTag associated with the stored field).
// Otherwise, they are identical to the other write barriers.
class IndirectPointerWriteBarrierDescriptor final
    : public StaticCallInterfaceDescriptor<
          IndirectPointerWriteBarrierDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kObject, kSlotAddress, kIndirectPointerTag)
  DEFINE_PARAMETER_TYPES(MachineType::TaggedPointer(),  // kObject
                         MachineType::Pointer(),        // kSlotAddress
                         MachineType::Uint64())         // kIndirectPointerTag

  DECLARE_DESCRIPTOR(IndirectPointerWriteBarrierDescriptor)
  static constexpr auto registers();
  static constexpr bool kRestrictAllocatableRegisters = true;
  static constexpr bool kCalleeSaveRegisters = true;
  static constexpr inline Register ObjectRegister();
  static constexpr inline Register SlotAddressRegister();
  static constexpr inline Register IndirectPointerTagRegister();
  static constexpr inline RegList ComputeSavedRegisters(
      Register object, Register slot_address = no_reg);
#if DEBUG
  static void Verify(CallInterfaceDescriptorData* data);
#endif
};

#ifdef V8_IS_TSAN
class TSANStoreDescriptor final
    : public StaticCallInterfaceDescriptor<TSANStoreDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kAddress, kValue)
  DEFINE_PARAMETER_TYPES(MachineType::Pointer(),    // kAddress
                         MachineType::AnyTagged())  // kValue

  DECLARE_DESCRIPTOR(TSANStoreDescriptor)

  static constexpr auto registers();
  static constexpr bool kRestrictAllocatableRegisters = true;
};

class TSANLoadDescriptor final
    : public StaticCallInterfaceDescriptor<TSANLoadDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kAddress)
  DEFINE_PARAMETER_TYPES(MachineType::Pointer())  // kAddress

  DECLARE_DESCRIPTOR(TSANLoadDescriptor)

  static constexpr auto registers();
  static constexpr bool kRestrictAllocatableRegisters = true;
};

#endif  // V8_IS_TSAN

class TypeConversionDescriptor final
    : public StaticCallInterfaceDescriptor<TypeConversionDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kArgument)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged())
  DECLARE_DESCRIPTOR(TypeConversionDescriptor)

  static constexpr inline Register ArgumentRegister();

  static constexpr auto registers();
};

class TypeConversionNoContextDescriptor final
    : public StaticCallInterfaceDescriptor<TypeConversionNoContextDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kArgument)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged())
  DECLARE_DESCRIPTOR(TypeConversionNoContextDescriptor)

  static constexpr auto registers();
};

class TypeConversion_BaselineDescriptor final
    : public StaticCallInterfaceDescriptor<TypeConversion_BaselineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kArgument, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(), MachineType::UintPtr())
  DECLARE_DESCRIPTOR(TypeConversion_BaselineDescriptor)
};

class SingleParameterOnStackDescriptor final
    : public StaticCallInterfaceDescriptor<SingleParameterOnStackDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kArgument)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged())
  DECLARE_DESCRIPTOR(SingleParameterOnStackDescriptor)

  static constexpr auto registers();
};

class AsyncFunctionStackParameterDescriptor final
    : public StaticCallInterfaceDescriptor<
          AsyncFunctionStackParameterDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kPromise, kResult)
  DEFINE_PARAMETER_TYPES(MachineType::TaggedPointer(), MachineType::AnyTagged())
  DECLARE_DESCRIPTOR(AsyncFunctionStackParameterDescriptor)

  static constexpr auto registers();
};

class GetIteratorStackParameterDescriptor final
    : public StaticCallInterfaceDescriptor<
          GetIteratorStackParameterDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kReceiver, kCallSlot, kFeedback, kResult)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(), MachineType::AnyTagged(),
                         MachineT
```