Response:
The user wants a summary of the provided C++ header file.

Here's a breakdown of the thought process:

1. **Identify the Core Function:** The filename "interface-descriptors.h" and the content (classes with `DECLARE_DESCRIPTOR`) strongly suggest this file defines interfaces for calling functions within the V8 engine. These "descriptors" likely describe the expected arguments and return values of these internal functions.

2. **Categorize Descriptors:** Scan through the listed classes and try to group them based on their names. Notice patterns like:
    * `Get...Descriptor`:  Likely related to accessing properties.
    * `Call...Descriptor`:  Related to function calls. Subcategories exist, like `CallVarargs`, `CallWithSpread`, `CallWithArrayLike`.
    * `Construct...Descriptor`: Related to object creation using `new`. Similar subcategories as `Call...Descriptor`.
    * `...BaselineDescriptor`, `...WithFeedbackDescriptor`: These seem to be variations of other descriptors, possibly related to optimization or performance monitoring.
    * `Array...ConstructorDescriptor`: Specifically for array construction.
    * `Compare...Descriptor`: For comparisons.
    * `BinaryOp...Descriptor`: For binary operations.
    * `String...Descriptor`: For string manipulation.
    * `...EntryDescriptor`: These might be entry points for specific parts of the engine.
    * `Interpreter...Descriptor`: Related to the interpreter.
    * `ResumeGeneratorDescriptor`, `SuspendGeneratorDescriptor`: For managing generator functions.

3. **Relate to JavaScript (if applicable):** Consider how these internal functions relate to JavaScript concepts. For example:
    * `GetPropertyDescriptor`:  Corresponds to accessing object properties (e.g., `obj.prop` or `obj['prop']`).
    * `CallTrampolineDescriptor`, `CallVarargsDescriptor`, etc.: Relate to calling functions in JavaScript. The variations likely handle different argument scenarios (e.g., spread syntax).
    * `ConstructStubDescriptor`, `ConstructVarargsDescriptor`, etc.: Relate to the `new` operator in JavaScript.
    * `TypeofDescriptor`:  Corresponds to the `typeof` operator.
    * `CompareDescriptor`: Relates to comparison operators like `==`, `!=`, `<`, `>`, etc.
    * `BinaryOpDescriptor`:  Relates to binary operators like `+`, `-`, `*`, `/`.
    * `StringAtAsStringDescriptor`, `StringSubstringDescriptor`:  Relate to string methods like `charAt` and `substring`.

4. **Consider Potential Programming Errors:** Think about common mistakes developers make that might involve these internal operations.
    * Incorrect number of arguments when calling a function.
    * Trying to access a property that doesn't exist.
    * Using the `new` keyword incorrectly.
    * Passing the wrong type of arguments to functions.

5. **Hypothesize Inputs and Outputs (if applicable):** For some descriptors, it's possible to imagine simple input/output scenarios. For instance, for `GetPropertyDescriptor`, the input could be an object and a key, and the output would be the value associated with that key.

6. **Address the ".tq" Check:** Explicitly state that based on the filename ending, this is *not* a Torque file.

7. **Structure the Summary:** Organize the findings logically, covering the functionality, relationship to JavaScript, potential errors, and the ".tq" point.

8. **Review and Refine:** Read through the generated summary to ensure clarity, accuracy, and completeness, given the provided code snippet. Make sure to address all parts of the user's request. For this "part 3" instruction,  emphasize the cumulative understanding gained so far.
好的，根据你提供的 `v8/src/codegen/interface-descriptors.h` 的代码片段，我们可以归纳一下它的功能：

**功能归纳：**

`v8/src/codegen/interface-descriptors.h` 文件定义了一系列的**接口描述符 (Interface Descriptors)**。这些描述符是 V8 引擎内部用于定义和描述各种运行时（runtime）或内置函数（built-in functions）的调用接口的蓝图。

具体来说，每个描述符类（例如 `GetPropertyDescriptor`, `CallTrampolineDescriptor` 等）都代表了一个特定的操作或函数的调用规范，它主要包含以下信息：

* **参数定义 (`DEFINE_PARAMETERS` / `DEFINE_PARAMETERS_VARARGS` / `DEFINE_JS_PARAMETERS`)：**  指定了调用该操作或函数时需要传递的参数名称。例如，`GetPropertyDescriptor` 定义了 `kObject` 和 `kKey` 两个参数。
* **参数类型 (`DEFINE_PARAMETER_TYPES` / `DEFINE_JS_PARAMETER_TYPES`)：**  定义了这些参数的预期类型，使用的是 V8 内部的 `MachineType` 枚举，例如 `MachineType::AnyTagged()` 表示可以是任何 V8 托管的对象，`MachineType::Int32()` 表示 32 位整数。
* **返回值类型 (`DEFINE_RESULT_AND_PARAMETER_TYPES` / `DEFINE_RESULT_AND_PARAMETERS`)：**  定义了操作或函数的返回值类型，以及在某些情况下，如何通过参数返回多个值。
* **寄存器分配 (`static constexpr inline auto registers();`)：**  在底层代码生成阶段，这些描述符也会影响参数和返回值的寄存器分配。
* **描述符声明 (`DECLARE_DESCRIPTOR` / `DECLARE_DEFAULT_DESCRIPTOR` / `DECLARE_JS_COMPATIBLE_DESCRIPTOR`)：** 用于注册和标识该描述符。

**与 JavaScript 功能的关系：**

这些接口描述符直接关联着 V8 引擎执行 JavaScript 代码的过程。当 JavaScript 代码执行到某个操作（例如访问属性、调用函数、进行运算等）时，V8 引擎会使用相应的接口描述符来生成底层的机器码，以便高效地执行这些操作。

**如果 `v8/src/codegen/interface-descriptors.h` 以 `.tq` 结尾：**

你提供的代码片段是 C++ 头文件 (`.h`)，所以它不是 Torque 源代码。如果以 `.tq` 结尾，那它将会是一个用 V8 的 Torque 语言编写的文件，Torque 是一种用于定义 V8 内置函数的领域特定语言，它会生成类似于这里定义的接口描述符以及相关的 C++ 代码。

**JavaScript 示例：**

以下是一些 JavaScript 例子，以及它们可能对应到的接口描述符：

1. **访问对象属性：**

   ```javascript
   const obj = { a: 1 };
   const value = obj.a; // 对应 GetPropertyDescriptor
   ```

   在这个例子中，访问 `obj.a` 属性的操作在 V8 内部可能会使用 `GetPropertyDescriptor` 来描述其调用规范，包括 `obj` 作为 `kObject` 参数，`"a"` (或其内部表示) 作为 `kKey` 参数。

2. **调用函数：**

   ```javascript
   function add(x, y) {
     return x + y;
   }
   const sum = add(2, 3); // 对应 CallTrampolineDescriptor 或其他 Call...Descriptor
   ```

   调用 `add(2, 3)` 这个函数调用操作，V8 可能会使用 `CallTrampolineDescriptor` 或其他以 `Call` 开头的描述符来描述，其中 `add` 函数作为 `kFunction`，参数 `2` 和 `3` 作为后续的实际参数传递。对于变长参数的函数，可能会使用 `CallVarargsDescriptor`。

3. **使用 `typeof` 运算符：**

   ```javascript
   const type = typeof 10; // 对应 TypeofDescriptor
   ```

   `typeof 10` 这个操作会对应 `TypeofDescriptor`，其中 `10` 作为 `kObject` 参数。

4. **使用 `new` 关键字创建对象：**

   ```javascript
   class MyClass {}
   const instance = new MyClass(); // 对应 ConstructStubDescriptor 或其他 Construct...Descriptor
   ```

   使用 `new` 关键字创建对象的操作会使用 `ConstructStubDescriptor` 或其他以 `Construct` 开头的描述符，例如 `ConstructVarargsDescriptor` 处理构造函数参数的情况。

**代码逻辑推理示例 (假设)：**

假设我们有一个简化的 `GetPropertyDescriptor` 的实现（这只是一个概念性的例子，实际实现会更复杂）：

**假设输入：**

* `kObject`: 一个 JavaScript 对象 `{ a: 1, b: 2 }`
* `kKey`: 一个 JavaScript 字符串 `"a"`

**可能的输出：**

* 返回值：JavaScript 数值 `1`

**代码逻辑推理：**

底层的代码会根据 `kObject` 和 `kKey` 找到对象中名为 `"a"` 的属性，并返回其对应的值 `1`。

**用户常见的编程错误示例：**

1. **调用函数时传递错误数量的参数：**

   ```javascript
   function greet(name) {
     console.log(`Hello, ${name}!`);
   }
   greet(); // 错误：缺少参数
   ```

   这种错误可能导致 V8 内部的调用机制与定义的接口描述符不匹配，最终抛出异常或产生未定义的行为。

2. **访问不存在的属性：**

   ```javascript
   const obj = { a: 1 };
   console.log(obj.b); // 错误：属性 'b' 不存在
   ```

   当尝试访问不存在的属性时，`GetPropertyDescriptor` 对应的底层实现会返回 `undefined`。

**总结 (针对第 3 部分)：**

到目前为止，我们了解到 `v8/src/codegen/interface-descriptors.h` 文件是 V8 代码生成部分的关键组成，它定义了描述 V8 内部函数调用规范的接口描述符。这些描述符与 JavaScript 的各种操作（属性访问、函数调用、对象创建等）紧密相关，指导着 V8 如何生成高效的机器码来执行这些操作。虽然这个文件本身不是 Torque 源代码，但它描述的接口与 Torque 定义的内置函数息息相关。理解这些描述符有助于深入了解 V8 引擎的内部工作机制。

Prompt: 
```
这是目录为v8/src/codegen/interface-descriptors.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/interface-descriptors.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
ype::AnyTagged(), MachineType::AnyTagged())
  DECLARE_DESCRIPTOR(GetIteratorStackParameterDescriptor)

  static constexpr auto registers();
};

class GetPropertyDescriptor final
    : public StaticCallInterfaceDescriptor<GetPropertyDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kObject, kKey)
  DECLARE_DEFAULT_DESCRIPTOR(GetPropertyDescriptor)
};

class TypeofDescriptor
    : public StaticCallInterfaceDescriptor<TypeofDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kObject)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged())
  DECLARE_DESCRIPTOR(TypeofDescriptor)

  static constexpr inline auto registers();
};

class CallTrampolineDescriptor
    : public StaticCallInterfaceDescriptor<CallTrampolineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_VARARGS(kFunction, kActualArgumentsCount)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kFunction
                         MachineType::Int32())      // kActualArgumentsCount
  DECLARE_DESCRIPTOR(CallTrampolineDescriptor)

  static constexpr inline auto registers();
};

class CopyDataPropertiesWithExcludedPropertiesDescriptor
    : public StaticCallInterfaceDescriptor<
          CopyDataPropertiesWithExcludedPropertiesDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_VARARGS(kSource, kExcludedPropertyCount)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kSource
                         MachineType::AnyTagged())  // kExcludedPropertyCount
  DECLARE_DESCRIPTOR(CopyDataPropertiesWithExcludedPropertiesDescriptor)

  static constexpr inline auto registers();
};

class CopyDataPropertiesWithExcludedPropertiesOnStackDescriptor
    : public StaticCallInterfaceDescriptor<
          CopyDataPropertiesWithExcludedPropertiesOnStackDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kSource, kExcludedPropertyCount, kExcludedPropertyBase)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kSource
                         MachineType::IntPtr(),
                         MachineType::IntPtr())  // kExcludedPropertyCount
  DECLARE_DESCRIPTOR(CopyDataPropertiesWithExcludedPropertiesOnStackDescriptor)

  static constexpr inline auto registers();
};

class CallVarargsDescriptor
    : public StaticCallInterfaceDescriptor<CallVarargsDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_VARARGS(kTarget, kActualArgumentsCount, kArgumentsLength,
                            kArgumentsList)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kTarget
                         MachineType::Int32(),      // kActualArgumentsCount
                         MachineType::Int32(),      // kArgumentsLength
                         MachineType::AnyTagged())  // kArgumentsList
  DECLARE_DESCRIPTOR(CallVarargsDescriptor)

  static constexpr inline auto registers();
};

class CallForwardVarargsDescriptor
    : public StaticCallInterfaceDescriptor<CallForwardVarargsDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_VARARGS(kTarget, kActualArgumentsCount, kStartIndex)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kTarget
                         MachineType::Int32(),      // kActualArgumentsCount
                         MachineType::Int32())      // kStartIndex
  DECLARE_DESCRIPTOR(CallForwardVarargsDescriptor)

  static constexpr inline auto registers();
};

class CallFunctionTemplateDescriptor
    : public StaticCallInterfaceDescriptor<CallFunctionTemplateDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_VARARGS(kFunctionTemplateInfo, kArgumentsCount)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kFunctionTemplateInfo
                         MachineType::Int32())      // kArgumentsCount
  DECLARE_DESCRIPTOR(CallFunctionTemplateDescriptor)

  static constexpr inline auto registers();
};

class CallFunctionTemplateGenericDescriptor
    : public StaticCallInterfaceDescriptor<
          CallFunctionTemplateGenericDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_VARARGS(kFunctionTemplateInfo, kArgumentsCount,
                            kTopmostScriptHavingContext)
  DEFINE_PARAMETER_TYPES(
      MachineType::AnyTagged(),  // kFunctionTemplateInfo
      MachineType::Int32(),      // kArgumentsCount
      MachineType::AnyTagged())  // kTopmostScriptHavingContext
  DECLARE_DESCRIPTOR(CallFunctionTemplateGenericDescriptor)

  static constexpr inline auto registers();
};

class CallWithSpreadDescriptor
    : public StaticCallInterfaceDescriptor<CallWithSpreadDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_VARARGS(kTarget, kArgumentsCount, kSpread)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kTarget
                         MachineType::Int32(),      // kArgumentsCount
                         MachineType::AnyTagged())  // kSpread
  DECLARE_DESCRIPTOR(CallWithSpreadDescriptor)

  static constexpr inline auto registers();
};

class CallWithSpread_BaselineDescriptor
    : public StaticCallInterfaceDescriptor<CallWithSpread_BaselineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT_VARARGS(kTarget, kArgumentsCount, kSpread, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kTarget
                         MachineType::Int32(),      // kArgumentsCount
                         MachineType::AnyTagged(),  // kSpread
                         MachineType::UintPtr())    // kSlot
  DECLARE_DESCRIPTOR(CallWithSpread_BaselineDescriptor)
};

class CallWithSpread_WithFeedbackDescriptor
    : public StaticCallInterfaceDescriptor<
          CallWithSpread_WithFeedbackDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_VARARGS(kTarget, kArgumentsCount, kSpread, kSlot,
                            kFeedbackVector, kReceiver)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kTarget
                         MachineType::Int32(),      // kArgumentsCount
                         MachineType::AnyTagged(),  // kSpread
                         MachineType::UintPtr(),    // kSlot
                         MachineType::AnyTagged(),  // kFeedbackVector
                         MachineType::AnyTagged())  // kReceiver
  DECLARE_DESCRIPTOR(CallWithSpread_WithFeedbackDescriptor)
};

class CallWithArrayLikeDescriptor
    : public StaticCallInterfaceDescriptor<CallWithArrayLikeDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kTarget, kArgumentsList)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kTarget
                         MachineType::AnyTagged())  // kArgumentsList
  DECLARE_DESCRIPTOR(CallWithArrayLikeDescriptor)

  static constexpr inline auto registers();
};

class CallWithArrayLike_WithFeedbackDescriptor
    : public StaticCallInterfaceDescriptor<
          CallWithArrayLike_WithFeedbackDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kTarget, kArgumentsList, kSlot, kFeedbackVector, kReceiver)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kTarget
                         MachineType::AnyTagged(),  // kArgumentsList
                         MachineType::UintPtr(),    // kSlot
                         MachineType::AnyTagged(),  // kFeedbackVector
                         MachineType::AnyTagged())  // kReceiver
  DECLARE_DESCRIPTOR(CallWithArrayLike_WithFeedbackDescriptor)
};

// TODO(ishell): consider merging this with ArrayConstructorDescriptor
class ConstructStubDescriptor
    : public StaticCallInterfaceDescriptor<ConstructStubDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_JS_PARAMETERS()
  DEFINE_JS_PARAMETER_TYPES()

  // TODO(ishell): Use DECLARE_JS_COMPATIBLE_DESCRIPTOR if registers match
  DECLARE_DESCRIPTOR(ConstructStubDescriptor)

  static constexpr inline auto registers();
};

class ConstructVarargsDescriptor
    : public StaticCallInterfaceDescriptor<ConstructVarargsDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_JS_PARAMETERS(kArgumentsLength, kArgumentsList)
  DEFINE_JS_PARAMETER_TYPES(MachineType::Int32(),      // kArgumentsLength
                            MachineType::AnyTagged())  // kArgumentsList

  DECLARE_DESCRIPTOR(ConstructVarargsDescriptor)

  static constexpr inline auto registers();
};

class ConstructForwardVarargsDescriptor
    : public StaticCallInterfaceDescriptor<ConstructForwardVarargsDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_JS_PARAMETERS(kStartIndex)
  DEFINE_JS_PARAMETER_TYPES(MachineType::Int32())
  DECLARE_DESCRIPTOR(ConstructForwardVarargsDescriptor)

  static constexpr inline auto registers();
};

class ConstructWithSpreadDescriptor
    : public StaticCallInterfaceDescriptor<ConstructWithSpreadDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_JS_PARAMETERS(kSpread)
  DEFINE_JS_PARAMETER_TYPES(MachineType::AnyTagged())
  DECLARE_DESCRIPTOR(ConstructWithSpreadDescriptor)

  static constexpr inline auto registers();
};

class ConstructWithSpread_BaselineDescriptor
    : public StaticCallInterfaceDescriptor<
          ConstructWithSpread_BaselineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_JS_PARAMETERS_NO_CONTEXT(kSpread, kSlot)
  DEFINE_JS_PARAMETER_TYPES(MachineType::AnyTagged(),  // kSpread
                            MachineType::AnyTagged())  // kSlot
  DECLARE_DESCRIPTOR(ConstructWithSpread_BaselineDescriptor)
};

class ConstructWithSpread_WithFeedbackDescriptor
    : public StaticCallInterfaceDescriptor<
          ConstructWithSpread_WithFeedbackDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_JS_PARAMETERS(kSpread, kSlot, kVector)
  DEFINE_JS_PARAMETER_TYPES(MachineType::AnyTagged(),  // kSpread
                            MachineType::AnyTagged(),  // kSlot
                            MachineType::AnyTagged())  // kVector
  DECLARE_DESCRIPTOR(ConstructWithSpread_WithFeedbackDescriptor)
};

class ConstructWithArrayLikeDescriptor
    : public StaticCallInterfaceDescriptor<ConstructWithArrayLikeDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kTarget, kNewTarget, kArgumentsList)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kTarget
                         MachineType::AnyTagged(),  // kNewTarget
                         MachineType::AnyTagged())  // kArgumentsList
  DECLARE_DESCRIPTOR(ConstructWithArrayLikeDescriptor)

  static constexpr inline auto registers();
};

class ConstructForwardAllArgsDescriptor
    : public StaticCallInterfaceDescriptor<ConstructForwardAllArgsDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kConstructor, kNewTarget)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kConstructor
                         MachineType::AnyTagged())  // kNewTarget
  DECLARE_DESCRIPTOR(ConstructForwardAllArgsDescriptor)

  static constexpr inline auto registers();
};

class ConstructForwardAllArgs_BaselineDescriptor
    : public StaticCallInterfaceDescriptor<
          ConstructForwardAllArgs_BaselineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kTarget, kNewTarget, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kTarget
                         MachineType::AnyTagged(),  // kNewTarget
                         MachineType::AnyTagged())  // kSlot
  DECLARE_DESCRIPTOR(ConstructForwardAllArgs_BaselineDescriptor)
};

class ConstructForwardAllArgs_WithFeedbackDescriptor
    : public StaticCallInterfaceDescriptor<
          ConstructForwardAllArgs_WithFeedbackDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kTarget, kNewTarget, kSlot, kVector)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kTarget
                         MachineType::AnyTagged(),  // kNewTarget
                         MachineType::AnyTagged(),  // kSlot
                         MachineType::AnyTagged())  // kVector
  DECLARE_DESCRIPTOR(ConstructForwardAllArgs_WithFeedbackDescriptor)
};

class AbortDescriptor : public StaticCallInterfaceDescriptor<AbortDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kMessageOrMessageId)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged())
  DECLARE_DESCRIPTOR(AbortDescriptor)

  static constexpr inline auto registers();
};

class ArrayConstructorDescriptor
    : public StaticJSCallInterfaceDescriptor<ArrayConstructorDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_JS_PARAMETERS(kAllocationSite)
  DEFINE_JS_PARAMETER_TYPES(MachineType::AnyTagged())

  DECLARE_JS_COMPATIBLE_DESCRIPTOR(ArrayConstructorDescriptor)
};

class ArrayNArgumentsConstructorDescriptor
    : public StaticCallInterfaceDescriptor<
          ArrayNArgumentsConstructorDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  // This descriptor declares only register arguments while respective number
  // of JS arguments stay on the expression stack.
  // The ArrayNArgumentsConstructor builtin does not access stack arguments
  // directly it just forwards them to the runtime function.
  DEFINE_PARAMETERS(kFunction, kAllocationSite, kActualArgumentsCount)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kFunction,
                         MachineType::AnyTagged(),  // kAllocationSite
                         MachineType::Int32())      // kActualArgumentsCount
  DECLARE_DESCRIPTOR(ArrayNArgumentsConstructorDescriptor)

  static constexpr auto registers();
};

class ArrayNoArgumentConstructorDescriptor
    : public StaticCallInterfaceDescriptor<
          ArrayNoArgumentConstructorDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  // This descriptor declares same register arguments as the parent
  // ArrayNArgumentsConstructorDescriptor and it declares indices for
  // JS arguments passed on the expression stack.
  DEFINE_PARAMETERS(kFunction, kAllocationSite, kActualArgumentsCount,
                    kFunctionParameter)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kFunction
                         MachineType::AnyTagged(),  // kAllocationSite
                         MachineType::Int32(),      // kActualArgumentsCount
                         MachineType::AnyTagged())  // kFunctionParameter
  DECLARE_DESCRIPTOR(ArrayNoArgumentConstructorDescriptor)

  static constexpr auto registers();
};

class ArraySingleArgumentConstructorDescriptor
    : public StaticCallInterfaceDescriptor<
          ArraySingleArgumentConstructorDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  // This descriptor declares same register arguments as the parent
  // ArrayNArgumentsConstructorDescriptor and it declares indices for
  // JS arguments passed on the expression stack.
  DEFINE_PARAMETERS(kFunction, kAllocationSite, kActualArgumentsCount,
                    kArraySizeSmiParameter, kReceiverParameter)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kFunction
                         MachineType::AnyTagged(),  // kAllocationSite
                         MachineType::Int32(),      // kActualArgumentsCount
                         // JS arguments on the stack
                         MachineType::AnyTagged(),  // kArraySizeSmiParameter
                         MachineType::AnyTagged())  // kReceiverParameter
  DECLARE_DESCRIPTOR(ArraySingleArgumentConstructorDescriptor)

  static constexpr auto registers();
};

class CompareDescriptor
    : public StaticCallInterfaceDescriptor<CompareDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kLeft, kRight)
  DECLARE_DESCRIPTOR(CompareDescriptor)

  static constexpr inline auto registers();
};

class CompareNoContextDescriptor
    : public StaticCallInterfaceDescriptor<CompareNoContextDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kLeft, kRight)
  DECLARE_DESCRIPTOR(CompareNoContextDescriptor)

  static constexpr inline auto registers();
};

class StringEqualDescriptor
    : public StaticCallInterfaceDescriptor<StringEqualDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kLeft, kRight, kLength)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kLeft
                         MachineType::AnyTagged(),  // kRight
                         MachineType::IntPtr())     // kLength
  DECLARE_DEFAULT_DESCRIPTOR(StringEqualDescriptor)
};

class BinaryOpDescriptor
    : public StaticCallInterfaceDescriptor<BinaryOpDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kLeft, kRight)
  DECLARE_DESCRIPTOR(BinaryOpDescriptor)

  static constexpr inline auto registers();
};

class BinaryOp_BaselineDescriptor
    : public StaticCallInterfaceDescriptor<BinaryOp_BaselineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kLeft, kRight, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kLeft
                         MachineType::AnyTagged(),  // kRight
                         MachineType::UintPtr())    // kSlot
  DECLARE_DESCRIPTOR(BinaryOp_BaselineDescriptor)

  static constexpr inline auto registers();
};

class BinarySmiOp_BaselineDescriptor
    : public StaticCallInterfaceDescriptor<BinarySmiOp_BaselineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kLeft, kRight, kSlot)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),     // kLeft
                         MachineType::TaggedSigned(),  // kRight
                         MachineType::UintPtr())       // kSlot
  DECLARE_DESCRIPTOR(BinarySmiOp_BaselineDescriptor)

  static constexpr inline auto registers();
};

class StringAtAsStringDescriptor final
    : public StaticCallInterfaceDescriptor<StringAtAsStringDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kReceiver, kPosition)
  // TODO(turbofan): Return untagged value here.
  DEFINE_RESULT_AND_PARAMETER_TYPES(
      MachineType::TaggedPointer(),  // result string
      MachineType::AnyTagged(),      // kReceiver
      MachineType::IntPtr())         // kPosition
  DECLARE_DESCRIPTOR(StringAtAsStringDescriptor)
};

class StringSubstringDescriptor final
    : public StaticCallInterfaceDescriptor<StringSubstringDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kString, kFrom, kTo)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kString
                         MachineType::IntPtr(),     // kFrom
                         MachineType::IntPtr())     // kTo

  // TODO(turbofan): Allow builtins to return untagged values.
  DECLARE_DESCRIPTOR(StringSubstringDescriptor)
};

class CppBuiltinAdaptorDescriptor
    : public StaticJSCallInterfaceDescriptor<CppBuiltinAdaptorDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_JS_PARAMETERS(kCFunction)
  DEFINE_JS_PARAMETER_TYPES(MachineType::Pointer())
  DECLARE_JS_COMPATIBLE_DESCRIPTOR(CppBuiltinAdaptorDescriptor)
};

class CreateFromSlowBoilerplateHelperDescriptor
    : public StaticCallInterfaceDescriptor<
          CreateFromSlowBoilerplateHelperDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_RESULT_AND_PARAMETERS(2, kAllocationSite, kBoilerplate)
  DEFINE_RESULT_AND_PARAMETER_TYPES(
      MachineType::AnyTagged(),  // result 1 (object)
      MachineType::AnyTagged(),  // result 2 (allocation site)
      MachineType::AnyTagged(),  // kAllocationSite
      MachineType::AnyTagged())  // kBoilerplate
  DECLARE_DESCRIPTOR(CreateFromSlowBoilerplateHelperDescriptor)
};

class CEntry1ArgvOnStackDescriptor
    : public StaticCallInterfaceDescriptor<CEntry1ArgvOnStackDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kArity,          // register argument
                    kCFunction,      // register argument
                    kPadding,        // stack argument 1 (just padding)
                    kArgcSmi,        // stack argument 2
                    kTargetCopy,     // stack argument 3
                    kNewTargetCopy)  // stack argument 4
  DEFINE_PARAMETER_TYPES(MachineType::Int32(),      // kArity
                         MachineType::Pointer(),    // kCFunction
                         MachineType::AnyTagged(),  // kPadding
                         MachineType::AnyTagged(),  // kArgcSmi
                         MachineType::AnyTagged(),  // kTargetCopy
                         MachineType::AnyTagged())  // kNewTargetCopy
  DECLARE_DESCRIPTOR(CEntry1ArgvOnStackDescriptor)

  static constexpr auto registers();
};

class CallApiCallbackOptimizedDescriptor
    : public StaticCallInterfaceDescriptor<CallApiCallbackOptimizedDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_VARARGS(kApiFunctionAddress, kActualArgumentsCount,
                            kFunctionTemplateInfo, kHolder)
  //                           receiver is implicit stack argument 1
  //                           argv are implicit stack arguments [2, 2 + kArgc[
  DEFINE_PARAMETER_TYPES(MachineType::Pointer(),    // kApiFunctionAddress
                         MachineType::Int32(),      // kActualArgumentsCount
                         MachineType::AnyTagged(),  // kFunctionTemplateInfo
                         MachineType::AnyTagged())  // kHolder
  DECLARE_DESCRIPTOR(CallApiCallbackOptimizedDescriptor)

  static constexpr inline Register ApiFunctionAddressRegister();
  static constexpr inline Register ActualArgumentsCountRegister();
  static constexpr inline Register FunctionTemplateInfoRegister();
  static constexpr inline Register HolderRegister();

  static constexpr inline auto registers();
};

class CallApiCallbackGenericDescriptor
    : public StaticCallInterfaceDescriptor<CallApiCallbackGenericDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_VARARGS(kActualArgumentsCount, kTopmostScriptHavingContext,
                            kFunctionTemplateInfo, kHolder)
  //                           receiver is implicit stack argument 1
  //                           argv are implicit stack arguments [2, 2 + kArgc[
  DEFINE_PARAMETER_TYPES(
      MachineType::Int32(),      // kActualArgumentsCount
      MachineType::AnyTagged(),  // kTopmostScriptHavingContext
      MachineType::AnyTagged(),  // kFunctionTemplateInfo
      MachineType::AnyTagged())  // kHolder
  DECLARE_DESCRIPTOR(CallApiCallbackGenericDescriptor)

  static constexpr inline Register ActualArgumentsCountRegister();
  static constexpr inline Register TopmostScriptHavingContextRegister();
  static constexpr inline Register FunctionTemplateInfoRegister();
  static constexpr inline Register HolderRegister();

  static constexpr inline auto registers();
};

class ApiGetterDescriptor
    : public StaticCallInterfaceDescriptor<ApiGetterDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kReceiver, kHolder, kCallback)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kReceiver
                         MachineType::AnyTagged(),  // kHolder
                         MachineType::AnyTagged())  // kCallback
  DECLARE_DESCRIPTOR(ApiGetterDescriptor)

  static constexpr inline Register ReceiverRegister();
  static constexpr inline Register HolderRegister();
  static constexpr inline Register CallbackRegister();

  static constexpr auto registers();
};

// TODO(turbofan): We should probably rename this to GrowFastElementsDescriptor.
class GrowArrayElementsDescriptor
    : public StaticCallInterfaceDescriptor<GrowArrayElementsDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kObject, kKey)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kObject
                         MachineType::AnyTagged())  // kKey
  DECLARE_DESCRIPTOR(GrowArrayElementsDescriptor)

  static constexpr inline Register ObjectRegister();
  static constexpr inline Register KeyRegister();

  static constexpr auto registers();
};

class BaselineOutOfLinePrologueDescriptor
    : public StaticCallInterfaceDescriptor<
          BaselineOutOfLinePrologueDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kCalleeContext, kClosure,
                               kJavaScriptCallArgCount, kStackFrameSize,
                               kJavaScriptCallNewTarget,
                               kInterpreterBytecodeArray)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kCalleeContext
                         MachineType::AnyTagged(),  // kClosure
                         MachineType::Int32(),      // kJavaScriptCallArgCount
                         MachineType::Int32(),      // kStackFrameSize
                         MachineType::AnyTagged(),  // kJavaScriptCallNewTarget
                         MachineType::AnyTagged())  // kInterpreterBytecodeArray
  DECLARE_DESCRIPTOR(BaselineOutOfLinePrologueDescriptor)

  static constexpr inline auto registers();

  // We pass the context manually, so we have one extra register.
  static constexpr int kMaxRegisterParams =
      StaticCallInterfaceDescriptor::kMaxRegisterParams + 1;
};

class BaselineLeaveFrameDescriptor
    : public StaticCallInterfaceDescriptor<BaselineLeaveFrameDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kParamsSize, kWeight)
  DEFINE_PARAMETER_TYPES(MachineType::Int32(),  // kParamsSize
                         MachineType::Int32())  // kWeight
  DECLARE_DESCRIPTOR(BaselineLeaveFrameDescriptor)

  static constexpr inline Register ParamsSizeRegister();
  static constexpr inline Register WeightRegister();

  static constexpr inline auto registers();
};

class OnStackReplacementDescriptor
    : public StaticCallInterfaceDescriptor<OnStackReplacementDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kMaybeTargetCode)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged())  // kMaybeTargetCode
  DECLARE_DESCRIPTOR(OnStackReplacementDescriptor)

  static constexpr inline Register MaybeTargetCodeRegister();

  static constexpr inline auto registers();
};

class V8_EXPORT_PRIVATE InterpreterDispatchDescriptor
    : public StaticCallInterfaceDescriptor<InterpreterDispatchDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kAccumulator, kBytecodeOffset, kBytecodeArray,
                    kDispatchTable)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kAccumulator
                         MachineType::IntPtr(),     // kBytecodeOffset
                         MachineType::AnyTagged(),  // kBytecodeArray
                         MachineType::IntPtr())     // kDispatchTable
  DECLARE_DESCRIPTOR(InterpreterDispatchDescriptor)

  static constexpr inline auto registers();
};

class InterpreterPushArgsThenCallDescriptor
    : public StaticCallInterfaceDescriptor<
          InterpreterPushArgsThenCallDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kNumberOfArguments, kFirstArgument, kFunction)
  DEFINE_PARAMETER_TYPES(MachineType::Int32(),      // kNumberOfArguments
                         MachineType::Pointer(),    // kFirstArgument
                         MachineType::AnyTagged())  // kFunction
  DECLARE_DESCRIPTOR(InterpreterPushArgsThenCallDescriptor)

  static constexpr inline auto registers();
};

class InterpreterPushArgsThenConstructDescriptor
    : public StaticCallInterfaceDescriptor<
          InterpreterPushArgsThenConstructDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kNumberOfArguments, kFirstArgument, kConstructor,
                    kNewTarget, kFeedbackElement)
  DEFINE_PARAMETER_TYPES(MachineType::Int32(),      // kNumberOfArguments
                         MachineType::Pointer(),    // kFirstArgument
                         MachineType::AnyTagged(),  // kConstructor
                         MachineType::AnyTagged(),  // kNewTarget
                         MachineType::AnyTagged())  // kFeedbackElement
  DECLARE_DESCRIPTOR(InterpreterPushArgsThenConstructDescriptor)

  static constexpr inline auto registers();
};

class InterpreterCEntry1Descriptor
    : public StaticCallInterfaceDescriptor<InterpreterCEntry1Descriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_RESULT_AND_PARAMETERS(1, kNumberOfArguments, kFirstArgument,
                               kFunctionEntry)
  DEFINE_RESULT_AND_PARAMETER_TYPES(MachineType::AnyTagged(),  // result 1
                                    MachineType::Int32(),  // kNumberOfArguments
                                    MachineType::Pointer(),  // kFirstArgument
                                    MachineType::Pointer())  // kFunctionEntry
  DECLARE_DESCRIPTOR(InterpreterCEntry1Descriptor)

  static constexpr auto registers();
};

class InterpreterCEntry2Descriptor
    : public StaticCallInterfaceDescriptor<InterpreterCEntry2Descriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_RESULT_AND_PARAMETERS(2, kNumberOfArguments, kFirstArgument,
                               kFunctionEntry)
  DEFINE_RESULT_AND_PARAMETER_TYPES(MachineType::AnyTagged(),  // result 1
                                    MachineType::AnyTagged(),  // result 2
                                    MachineType::Int32(),  // kNumberOfArguments
                                    MachineType::Pointer(),  // kFirstArgument
                                    MachineType::Pointer())  // kFunctionEntry
  DECLARE_DESCRIPTOR(InterpreterCEntry2Descriptor)

  static constexpr auto registers();
};

class FindNonDefaultConstructorOrConstructDescriptor
    : public StaticCallInterfaceDescriptor<
          FindNonDefaultConstructorOrConstructDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_RESULT_AND_PARAMETERS(2, kThisFunction, kNewTarget)
  DEFINE_RESULT_AND_PARAMETER_TYPES(
      MachineType::AnyTagged(),  // result 1 (true / false)
      MachineType::AnyTagged(),  // result 2 (constructor_or_instance)
      MachineType::AnyTagged(),  // kThisFunction
      MachineType::AnyTagged())  // kNewTarget
  DECLARE_DESCRIPTOR(FindNonDefaultConstructorOrConstructDescriptor)
};

class ForInPrepareDescriptor
    : public StaticCallInterfaceDescriptor<ForInPrepareDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_RESULT_AND_PARAMETERS(2, kEnumerator, kVectorIndex, kFeedbackVector)
  DEFINE_RESULT_AND_PARAMETER_TYPES(
      MachineType::AnyTagged(),     // result 1 (cache array)
      MachineType::AnyTagged(),     // result 2 (cache length)
      MachineType::AnyTagged(),     // kEnumerator
      MachineType::TaggedSigned(),  // kVectorIndex
      MachineType::AnyTagged())     // kFeedbackVector
  DECLARE_DESCRIPTOR(ForInPrepareDescriptor)
};

class ResumeGeneratorDescriptor final
    : public StaticCallInterfaceDescriptor<ResumeGeneratorDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kValue, kGenerator)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kValue
                         MachineType::AnyTagged())  // kGenerator
  DECLARE_DESCRIPTOR(ResumeGeneratorDescriptor)

  static constexpr inline auto registers();
};

class ResumeGeneratorBaselineDescriptor final
    : public StaticCallInterfaceDescriptor<ResumeGeneratorBaselineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kGeneratorObject, kRegisterCount)
  DEFINE_RESULT_AND_PARAMETER_TYPES(
      MachineType::TaggedSigned(),  // return type
      MachineType::AnyTagged(),     // kGeneratorObject
      MachineType::IntPtr(),        // kRegisterCount
  )
  DECLARE_DESCRIPTOR(ResumeGeneratorBaselineDescriptor)
};

class SuspendGeneratorBaselineDescriptor final
    : public StaticCallInterfaceDescriptor<SuspendGeneratorBaselineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_NO_CONTEXT(kGeneratorObject, kSuspendId, kBytecodeOffset,
                               kRegisterCount)
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(),  // kGeneratorObject
                         MachineType::IntPtr(),     // kSuspendId
                         MachineType::IntPtr(),     // kBytecodeOffset
                         MachineType::IntPtr(),     // kRegisterCount
  )
  DECLARE_DESCRIPTOR(SuspendGeneratorBaselineDescriptor)
};

class RestartFrameTrampolineDescriptor final
    : public StaticCallInterfaceDescriptor<RestartFrameTrampolineDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS()
  DECLARE_DESCRIPTOR(RestartFrameTrampolineDescriptor)
};

class RunMicrotasksEntryDescriptor final
    : public StaticCallInterfaceDescriptor<RunMicrotasksEntryDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS_ENTRY(kRootRegisterValue, kMicrotaskQueue)
  DEFINE_PARAMETER_TYPES(MachineType::Pointer(),  // kRootRegisterValue
                         MachineType::Pointer())  // kMicrotaskQueue
  DECLARE_DESCRIPTOR(RunMicrotasksEntryDescriptor)

  static constexpr inline auto registers();
};

class RunMicrotasksDescriptor final
    : public StaticCallInterfaceDescriptor<RunMicrotasksDescriptor> {
 public:
  INTERNAL_DESCRIPTOR()
  DEFINE_PARAMETERS(kMicrotaskQueue)
  DEFINE_PARAMETER_TYPES(MachineType::Pointer())
  DECLARE_DESCRIPTOR(RunMicrotasksDescriptor)

  static constexpr inline Register MicrotaskQueueRegister();
};

class WasmFloat32ToNumberDescriptor final
    : public StaticCallInterfaceDescriptor<WasmFloat32ToNumberDescriptor> {
 public:
"""


```