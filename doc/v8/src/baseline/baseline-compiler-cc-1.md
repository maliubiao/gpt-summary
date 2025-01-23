Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/baseline/baseline-compiler.cc`.

Here's a breakdown of the thought process to achieve the desired summary:

1. **Identify the core purpose:** The filename and the presence of `Visit` methods strongly suggest that this code is part of a compiler. Specifically, it seems to be handling bytecode instructions for a "baseline" compiler in V8.

2. **Analyze the `Visit` methods:** Each `Visit` method corresponds to a specific bytecode instruction. The code within each method usually performs one of two actions:
    * Calls a built-in function (using `CallBuiltin`).
    * Calls a runtime function (using `CallRuntime`).
    * Performs direct assembly-level operations (using `__`).

3. **Categorize the functionalities based on bytecode instructions:** Group the `Visit` methods by the type of operation they perform. This helps in creating a logical structure for the summary. Obvious categories emerge:
    * Property access (get and set)
    * Module variable access
    * Arithmetic and bitwise operations
    * Logical operations
    * Type checking
    * Object creation and manipulation (including `delete`)
    * Function calls and construction
    * Comparisons
    * Intrinsics

4. **Infer the purpose of built-ins and runtime functions:** While the internal implementation of built-ins and runtime functions isn't shown, their names often suggest their purpose (e.g., `kLoadICBaseline`, `kStoreICBaseline`, `kAdd_Baseline`, `kTypeof_Baseline`). This inference helps explain the high-level functionality.

5. **Address the specific questions in the prompt:**
    * **Torque source:** Check if the filename ends in `.tq`. In this case, it doesn't.
    * **Relation to JavaScript:**  The operations directly correspond to JavaScript language features (property access, arithmetic, function calls, etc.).
    * **JavaScript examples:** For some key functionalities, provide simple JavaScript code that would trigger the corresponding bytecode and thus the C++ code execution.
    * **Code logic reasoning:**  Look for specific logic within the `Visit` methods, particularly those involving assembly instructions or conditional jumps. If a clear input/output relationship can be defined, create an example.
    * **Common programming errors:**  Relate the operations to common JavaScript errors, like trying to access properties of `null` or `undefined`.

6. **Structure the summary:** Organize the categorized functionalities into a clear and readable format. Use headings and bullet points.

7. **Address the "part 2 of 3" aspect:**  Acknowledge that this is a partial view and the complete picture would involve other parts of the compiler. Conclude that this part focuses on the *implementation* of bytecode instructions within the baseline compiler.

8. **Review and refine:** Check for accuracy and clarity. Ensure the JavaScript examples are correct and the explanations are easy to understand. Make sure all points in the prompt have been addressed.

**Self-Correction Example during the process:**

Initially, I might have just listed all the `Visit` methods and their corresponding built-in/runtime calls. However, this would be a very low-level and not particularly insightful summary. Recognizing this, the next step is to group these methods into higher-level categories based on their semantic meaning in JavaScript. This leads to the more organized summary based on operations like "Property Access," "Arithmetic Operations," etc. This categorization makes the information much more digestible and useful. Similarly, initially I might forget to provide JavaScript examples. Realizing the prompt specifically asks for this, I would go back and add relevant examples for the key functionalities.
好的，让我们分析一下 `v8/src/baseline/baseline-compiler.cc` 这个文件的部分代码，并归纳其功能。

**代码功能列举:**

这段代码是 V8 JavaScript 引擎中 Baseline 编译器的核心部分，负责将解释器（Ignition）生成的字节码转换为机器码。 具体来说，它定义了 `BaselineCompiler` 类的方法，每个方法对应一个或多个字节码指令，用于实现这些指令的功能。

以下是代码中各个 `Visit` 方法的主要功能：

* **访问和操作变量:**
    * `VisitLdaModuleVariable`: 加载模块变量。
    * `VisitStaModuleVariable`: 存储模块变量。
    * `VisitMov`: 将一个寄存器的值移动到另一个寄存器。

* **属性访问:**
    * `VisitGetNamedProperty`: 获取对象的命名属性。
    * `VisitGetNamedPropertyFromSuper`: 从父类获取命名属性。
    * `VisitGetKeyedProperty`: 获取对象的键值属性。
    * `VisitGetEnumeratedKeyedProperty`: 获取可枚举的键值属性。
    * `VisitSetNamedProperty`: 设置对象的命名属性。
    * `VisitDefineNamedOwnProperty`: 定义对象的自有命名属性。
    * `VisitSetKeyedProperty`: 设置对象的键值属性。
    * `VisitDefineKeyedOwnProperty`: 定义对象的自有键值属性。
    * `VisitStaInArrayLiteral`: 在数组字面量中存储属性。
    * `VisitDefineKeyedOwnPropertyInLiteral`: 在数组字面量中定义自有键值属性。

* **算术和位运算:**
    * `VisitAdd`, `VisitSub`, `VisitMul`, `VisitDiv`, `VisitMod`, `VisitExp`: 加法、减法、乘法、除法、取模、幂运算。
    * `VisitBitwiseOr`, `VisitBitwiseXor`, `VisitBitwiseAnd`: 位或、位异或、位与运算。
    * `VisitShiftLeft`, `VisitShiftRight`, `VisitShiftRightLogical`: 左移、右移、无符号右移运算。
    * 针对Smi (Small Integer) 的类似运算： `VisitAddSmi`, `VisitSubSmi` 等。

* **递增和递减:**
    * `VisitInc`: 递增。
    * `VisitDec`: 递减。

* **一元运算:**
    * `VisitNegate`: 取反。
    * `VisitBitwiseNot`: 位非运算。
    * `VisitToBooleanLogicalNot`: 逻辑非运算 (转换为布尔值后取反)。
    * `VisitLogicalNot`: 逻辑非运算。
    * `VisitTypeOf`: 获取类型。

* **删除属性:**
    * `VisitDeletePropertyStrict`: 在严格模式下删除属性。
    * `VisitDeletePropertySloppy`: 在非严格模式下删除属性。

* **Super 调用:**
    * `VisitGetSuperConstructor`: 获取父类构造函数。
    * `VisitFindNonDefaultConstructorOrConstruct`: 查找非默认构造函数或执行构造。

* **函数调用:**
    * `VisitCallAnyReceiver`: 调用函数，接收者可以是任意值。
    * `VisitCallProperty`: 调用对象的方法。
    * `VisitCallProperty0`, `VisitCallProperty1`, `VisitCallProperty2`: 调用对象的方法，参数数量分别为 0, 1, 2。
    * `VisitCallUndefinedReceiver`: 调用函数，接收者是 undefined。
    * `VisitCallUndefinedReceiver0`, `VisitCallUndefinedReceiver1`, `VisitCallUndefinedReceiver2`: 调用函数，接收者是 undefined，参数数量分别为 0, 1, 2。
    * `VisitCallWithSpread`: 使用 Spread 语法调用函数。
    * `VisitCallRuntime`: 调用运行时函数。
    * `VisitCallRuntimeForPair`: 调用返回一对值的运行时函数。
    * `VisitCallJSRuntime`: 调用 JavaScript 运行时函数。
    * `VisitInvokeIntrinsic`: 调用内联函数 (Intrinsic)。

* **对象构造:**
    * `VisitConstruct`: 调用构造函数创建对象。
    * `VisitConstructWithSpread`: 使用 Spread 语法调用构造函数。
    * `VisitConstructForwardAllArgs`: 转发所有参数调用构造函数。

* **比较运算:**
    * `VisitTestEqual`: 相等比较 (==)。
    * `VisitTestEqualStrict`: 严格相等比较 (===)。
    * `VisitTestLessThan`, `VisitTestGreaterThan`, `VisitTestLessThanOrEqual`, `VisitTestGreaterThanOrEqual`: 小于、大于、小于等于、大于等于比较。
    * `VisitTestReferenceEqual`: 引用相等比较。
    * `VisitTestInstanceOf`: `instanceof` 运算符。
    * `VisitTestIn`: `in` 运算符。
    * `VisitTestUndetectable`: 判断对象是否不可检测 (通常与 `undefined` 行为相关)。
    * `VisitTestNull`: 判断是否为 `null`。
    * `VisitTestUndefined`: 判断是否为 `undefined`。
    * `VisitTestTypeOf`: 判断类型。

* **内联函数 (Intrinsics):**
    * 代码中定义了一些 `VisitIntrinsic...` 方法，用于处理特定的内联函数调用，例如 `VisitIntrinsicCopyDataProperties` (复制数据属性)、`VisitIntrinsicCreateIterResultObject` (创建迭代器结果对象) 等。 这些通常是 V8 引擎内部优化的函数。

**关于 `.tq` 结尾:**

正如代码注释所说，如果 `v8/src/baseline/baseline-compiler.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。 Torque 是一种用于编写 V8 内部函数的领域特定语言，可以生成高效的 C++ 代码。 然而，当前提供的文件名是 `.cc`，表明这是一个标准的 C++ 源文件。

**与 JavaScript 功能的关系及 JavaScript 示例:**

这段 C++ 代码直接对应着 JavaScript 的各种语法和操作。 每一种 `Visit` 方法都在底层实现了 JavaScript 的一个特性。

例如：

* **`VisitGetNamedProperty()`** 对应于 JavaScript 中的属性访问：
  ```javascript
  const obj = { name: 'example' };
  const propertyValue = obj.name; // 会触发 GetNamedProperty 相关的字节码
  ```

* **`VisitAdd()`** 对应于 JavaScript 中的加法运算：
  ```javascript
  const sum = 5 + 3; // 会触发 Add 相关的字节码
  ```

* **`VisitCallProperty()`** 对应于 JavaScript 中的方法调用：
  ```javascript
  const obj = {
    greet(name) {
      console.log(`Hello, ${name}!`);
    }
  };
  obj.greet('World'); // 会触发 CallProperty 相关的字节码
  ```

* **`VisitTestEqualStrict()`** 对应于 JavaScript 中的严格相等比较：
  ```javascript
  const isEqual = 5 === '5'; // 会触发 TestEqualStrict 相关的字节码
  ```

**代码逻辑推理 (假设输入与输出):**

以 `VisitAdd(RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1))` 为例：

**假设输入:**

* 寄存器 `RegisterOperand(0)` 存储着数值 `10`。
* 累加器寄存器 `kInterpreterAccumulatorRegister` 存储着数值 `5`。

**输出:**

* 执行 `CallBuiltin<Builtin::kAdd_Baseline>(RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1))` 后， `Builtin::kAdd_Baseline` 这个内置函数会被调用，它会将 `RegisterOperand(0)` 的值（10）和 `kInterpreterAccumulatorRegister` 的值（5）相加。
* 最终，累加器寄存器 `kInterpreterAccumulatorRegister` 将存储结果 `15`。

**涉及用户常见的编程错误:**

许多 `Visit` 方法都与 JavaScript 中常见的编程错误有关。例如：

* **`VisitGetNamedProperty()` 和 `VisitGetKeyedProperty()`:**  如果尝试访问 `null` 或 `undefined` 对象的属性，会导致运行时错误 (TypeError)。
  ```javascript
  let obj = null;
  console.log(obj.name); // TypeError: Cannot read properties of null (reading 'name')
  ```

* **算术运算相关的 `Visit` 方法:**  对非数字类型进行算术运算可能导致 `NaN` (Not a Number) 的结果。
  ```javascript
  const result = "hello" * 5; // result is NaN
  ```

* **`VisitCallProperty()`:** 尝试调用非函数类型的属性会引发 TypeError。
  ```javascript
  const obj = { name: 'example' };
  obj.name(); // TypeError: obj.name is not a function
  ```

**第2部分功能归纳:**

总的来说，这段 `v8/src/baseline/baseline-compiler.cc` 的代码片段是 V8 引擎 Baseline 编译器的核心组成部分，它：

1. **实现了多种 JavaScript 字节码指令的功能。** 每个 `Visit` 方法负责将特定的字节码操作转换为底层的机器码执行。
2. **涵盖了 JavaScript 语言的核心特性，** 包括变量访问、属性操作、算术运算、逻辑运算、函数调用、对象构造和比较运算等。
3. **通过调用内置函数 (`CallBuiltin`) 和运行时函数 (`CallRuntime`) 来完成复杂的任务。**  这些内置函数和运行时函数是 V8 引擎内部实现的关键部分。
4. **是 Baseline 编译器将高级 JavaScript 代码转换为可执行机器码的关键步骤。**  它在性能上优于解释器，但不如优化编译器 (如 TurboFan) 生成的代码高效。

因此，这段代码的功能可以归纳为： **实现 V8 JavaScript 引擎 Baseline 编译器的字节码处理逻辑，将解释器生成的字节码转换为机器码，从而执行相应的 JavaScript 操作。**

### 提示词
```
这是目录为v8/src/baseline/baseline-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/baseline/baseline-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
\
        interpreter::Register::FromShortStar(interpreter::Bytecode::k##Name), \
        kInterpreterAccumulatorRegister);                                     \
  }
SHORT_STAR_BYTECODE_LIST(SHORT_STAR_VISITOR)
#undef SHORT_STAR_VISITOR

void BaselineCompiler::VisitMov() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register scratch = scratch_scope.AcquireScratch();
  LoadRegister(scratch, 0);
  StoreRegister(1, scratch);
}

void BaselineCompiler::VisitGetNamedProperty() {
  CallBuiltin<Builtin::kLoadICBaseline>(RegisterOperand(0),  // object
                                        Constant<Name>(1),   // name
                                        IndexAsTagged(2));   // slot
}

void BaselineCompiler::VisitGetNamedPropertyFromSuper() {
  __ LoadPrototype(
      LoadWithReceiverAndVectorDescriptor::LookupStartObjectRegister(),
      kInterpreterAccumulatorRegister);

  CallBuiltin<Builtin::kLoadSuperICBaseline>(
      RegisterOperand(0),  // object
      LoadWithReceiverAndVectorDescriptor::
          LookupStartObjectRegister(),  // lookup start
      Constant<Name>(1),                // name
      IndexAsTagged(2));                // slot
}

void BaselineCompiler::VisitGetKeyedProperty() {
  CallBuiltin<Builtin::kKeyedLoadICBaseline>(
      RegisterOperand(0),               // object
      kInterpreterAccumulatorRegister,  // key
      IndexAsTagged(1));                // slot
}

void BaselineCompiler::VisitGetEnumeratedKeyedProperty() {
  DCHECK(v8_flags.enable_enumerated_keyed_access_bytecode);
  CallBuiltin<Builtin::kEnumeratedKeyedLoadICBaseline>(
      RegisterOperand(0),               // object
      kInterpreterAccumulatorRegister,  // key
      RegisterOperand(1),               // enum index
      RegisterOperand(2),               // cache type
      IndexAsTagged(3));                // slot
}

void BaselineCompiler::VisitLdaModuleVariable() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register scratch = scratch_scope.AcquireScratch();
  __ LoadContext(scratch);
  int cell_index = Int(0);
  int depth = Uint(1);
  __ LdaModuleVariable(scratch, cell_index, depth);
}

void BaselineCompiler::VisitStaModuleVariable() {
  int cell_index = Int(0);
  if (V8_UNLIKELY(cell_index < 0)) {
    // Not supported (probably never).
    CallRuntime(Runtime::kAbort,
                Smi::FromInt(static_cast<int>(
                    AbortReason::kUnsupportedModuleOperation)));
    __ Trap();
  }
  Register value = WriteBarrierDescriptor::ValueRegister();
  Register scratch = WriteBarrierDescriptor::ObjectRegister();
  DCHECK(!AreAliased(value, scratch, kInterpreterAccumulatorRegister));
  __ Move(value, kInterpreterAccumulatorRegister);
  __ LoadContext(scratch);
  int depth = Uint(1);
  __ StaModuleVariable(scratch, value, cell_index, depth);
}

void BaselineCompiler::VisitSetNamedProperty() {
  // StoreIC is currently a base class for multiple property store operations
  // and contains mixed logic for named and keyed, set and define operations,
  // the paths are controlled by feedback.
  // TODO(v8:12548): refactor SetNamedIC as a subclass of StoreIC, which can be
  // called here.
  CallBuiltin<Builtin::kStoreICBaseline>(
      RegisterOperand(0),               // object
      Constant<Name>(1),                // name
      kInterpreterAccumulatorRegister,  // value
      IndexAsTagged(2));                // slot
}

void BaselineCompiler::VisitDefineNamedOwnProperty() {
  CallBuiltin<Builtin::kDefineNamedOwnICBaseline>(
      RegisterOperand(0),               // object
      Constant<Name>(1),                // name
      kInterpreterAccumulatorRegister,  // value
      IndexAsTagged(2));                // slot
}

void BaselineCompiler::VisitSetKeyedProperty() {
  // KeyedStoreIC is currently a base class for multiple keyed property store
  // operations and contains mixed logic for set and define operations,
  // the paths are controlled by feedback.
  // TODO(v8:12548): refactor SetKeyedIC as a subclass of KeyedStoreIC, which
  // can be called here.
  CallBuiltin<Builtin::kKeyedStoreICBaseline>(
      RegisterOperand(0),               // object
      RegisterOperand(1),               // key
      kInterpreterAccumulatorRegister,  // value
      IndexAsTagged(2));                // slot
}

void BaselineCompiler::VisitDefineKeyedOwnProperty() {
  CallBuiltin<Builtin::kDefineKeyedOwnICBaseline>(
      RegisterOperand(0),               // object
      RegisterOperand(1),               // key
      kInterpreterAccumulatorRegister,  // value
      Flag8AsSmi(2),                    // flags
      IndexAsTagged(3));                // slot
}

void BaselineCompiler::VisitStaInArrayLiteral() {
  CallBuiltin<Builtin::kStoreInArrayLiteralICBaseline>(
      RegisterOperand(0),               // object
      RegisterOperand(1),               // name
      kInterpreterAccumulatorRegister,  // value
      IndexAsTagged(2));                // slot
}

void BaselineCompiler::VisitDefineKeyedOwnPropertyInLiteral() {
  // Here we should save the accumulator, since
  // DefineKeyedOwnPropertyInLiteral doesn't write the accumulator, but
  // Runtime::kDefineKeyedOwnPropertyInLiteral returns the value that we got
  // from the accumulator so this still works.
  CallRuntime(Runtime::kDefineKeyedOwnPropertyInLiteral,
              RegisterOperand(0),               // object
              RegisterOperand(1),               // name
              kInterpreterAccumulatorRegister,  // value
              Flag8AsSmi(2),                    // flags
              FeedbackVector(),                 // feedback vector
              IndexAsTagged(3));                // slot
}

void BaselineCompiler::VisitAdd() {
  CallBuiltin<Builtin::kAdd_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitSub() {
  CallBuiltin<Builtin::kSubtract_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitMul() {
  CallBuiltin<Builtin::kMultiply_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitDiv() {
  CallBuiltin<Builtin::kDivide_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitMod() {
  CallBuiltin<Builtin::kModulus_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitExp() {
  CallBuiltin<Builtin::kExponentiate_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitBitwiseOr() {
  CallBuiltin<Builtin::kBitwiseOr_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitBitwiseXor() {
  CallBuiltin<Builtin::kBitwiseXor_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitBitwiseAnd() {
  CallBuiltin<Builtin::kBitwiseAnd_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitShiftLeft() {
  CallBuiltin<Builtin::kShiftLeft_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitShiftRight() {
  CallBuiltin<Builtin::kShiftRight_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitShiftRightLogical() {
  CallBuiltin<Builtin::kShiftRightLogical_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitAddSmi() {
  CallBuiltin<Builtin::kAddSmi_Baseline>(kInterpreterAccumulatorRegister,
                                         IntAsSmi(0), Index(1));
}

void BaselineCompiler::VisitSubSmi() {
  CallBuiltin<Builtin::kSubtractSmi_Baseline>(kInterpreterAccumulatorRegister,
                                              IntAsSmi(0), Index(1));
}

void BaselineCompiler::VisitMulSmi() {
  CallBuiltin<Builtin::kMultiplySmi_Baseline>(kInterpreterAccumulatorRegister,
                                              IntAsSmi(0), Index(1));
}

void BaselineCompiler::VisitDivSmi() {
  CallBuiltin<Builtin::kDivideSmi_Baseline>(kInterpreterAccumulatorRegister,
                                            IntAsSmi(0), Index(1));
}

void BaselineCompiler::VisitModSmi() {
  CallBuiltin<Builtin::kModulusSmi_Baseline>(kInterpreterAccumulatorRegister,
                                             IntAsSmi(0), Index(1));
}

void BaselineCompiler::VisitExpSmi() {
  CallBuiltin<Builtin::kExponentiateSmi_Baseline>(
      kInterpreterAccumulatorRegister, IntAsSmi(0), Index(1));
}

void BaselineCompiler::VisitBitwiseOrSmi() {
  CallBuiltin<Builtin::kBitwiseOrSmi_Baseline>(kInterpreterAccumulatorRegister,
                                               IntAsSmi(0), Index(1));
}

void BaselineCompiler::VisitBitwiseXorSmi() {
  CallBuiltin<Builtin::kBitwiseXorSmi_Baseline>(kInterpreterAccumulatorRegister,
                                                IntAsSmi(0), Index(1));
}

void BaselineCompiler::VisitBitwiseAndSmi() {
  CallBuiltin<Builtin::kBitwiseAndSmi_Baseline>(kInterpreterAccumulatorRegister,
                                                IntAsSmi(0), Index(1));
}

void BaselineCompiler::VisitShiftLeftSmi() {
  CallBuiltin<Builtin::kShiftLeftSmi_Baseline>(kInterpreterAccumulatorRegister,
                                               IntAsSmi(0), Index(1));
}

void BaselineCompiler::VisitShiftRightSmi() {
  CallBuiltin<Builtin::kShiftRightSmi_Baseline>(kInterpreterAccumulatorRegister,
                                                IntAsSmi(0), Index(1));
}

void BaselineCompiler::VisitShiftRightLogicalSmi() {
  CallBuiltin<Builtin::kShiftRightLogicalSmi_Baseline>(
      kInterpreterAccumulatorRegister, IntAsSmi(0), Index(1));
}

void BaselineCompiler::VisitInc() {
  CallBuiltin<Builtin::kIncrement_Baseline>(kInterpreterAccumulatorRegister,
                                            Index(0));
}

void BaselineCompiler::VisitDec() {
  CallBuiltin<Builtin::kDecrement_Baseline>(kInterpreterAccumulatorRegister,
                                            Index(0));
}

void BaselineCompiler::VisitNegate() {
  CallBuiltin<Builtin::kNegate_Baseline>(kInterpreterAccumulatorRegister,
                                         Index(0));
}

void BaselineCompiler::VisitBitwiseNot() {
  CallBuiltin<Builtin::kBitwiseNot_Baseline>(kInterpreterAccumulatorRegister,
                                             Index(0));
}

void BaselineCompiler::VisitToBooleanLogicalNot() {
  SelectBooleanConstant(kInterpreterAccumulatorRegister,
                        [&](Label* if_true, Label::Distance distance) {
                          JumpIfToBoolean(false, if_true, distance);
                        });
}

void BaselineCompiler::VisitLogicalNot() {
  SelectBooleanConstant(kInterpreterAccumulatorRegister,
                        [&](Label* if_true, Label::Distance distance) {
                          __ JumpIfRoot(kInterpreterAccumulatorRegister,
                                        RootIndex::kFalseValue, if_true,
                                        distance);
                        });
}

void BaselineCompiler::VisitTypeOf() {
  CallBuiltin<Builtin::kTypeof_Baseline>(kInterpreterAccumulatorRegister,
                                         Index(0));
}

void BaselineCompiler::VisitDeletePropertyStrict() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register scratch = scratch_scope.AcquireScratch();
  __ Move(scratch, kInterpreterAccumulatorRegister);
  CallBuiltin<Builtin::kDeleteProperty>(RegisterOperand(0), scratch,
                                        Smi::FromEnum(LanguageMode::kStrict));
}

void BaselineCompiler::VisitDeletePropertySloppy() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register scratch = scratch_scope.AcquireScratch();
  __ Move(scratch, kInterpreterAccumulatorRegister);
  CallBuiltin<Builtin::kDeleteProperty>(RegisterOperand(0), scratch,
                                        Smi::FromEnum(LanguageMode::kSloppy));
}

void BaselineCompiler::VisitGetSuperConstructor() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register prototype = scratch_scope.AcquireScratch();
  __ LoadPrototype(prototype, kInterpreterAccumulatorRegister);
  StoreRegister(0, prototype);
}

void BaselineCompiler::VisitFindNonDefaultConstructorOrConstruct() {
  SaveAccumulatorScope accumulator_scope(this, &basm_);
  CallBuiltin<Builtin::kFindNonDefaultConstructorOrConstruct>(
      RegisterOperand(0), RegisterOperand(1));
  StoreRegisterPair(2, kReturnRegister0, kReturnRegister1);
}

namespace {
constexpr Builtin ConvertReceiverModeToCompactBuiltin(
    ConvertReceiverMode mode) {
  switch (mode) {
    case ConvertReceiverMode::kAny:
      return Builtin::kCall_ReceiverIsAny_Baseline_Compact;
    case ConvertReceiverMode::kNullOrUndefined:
      return Builtin::kCall_ReceiverIsNullOrUndefined_Baseline_Compact;
    case ConvertReceiverMode::kNotNullOrUndefined:
      return Builtin::kCall_ReceiverIsNotNullOrUndefined_Baseline_Compact;
  }
}
constexpr Builtin ConvertReceiverModeToBuiltin(ConvertReceiverMode mode) {
  switch (mode) {
    case ConvertReceiverMode::kAny:
      return Builtin::kCall_ReceiverIsAny_Baseline;
    case ConvertReceiverMode::kNullOrUndefined:
      return Builtin::kCall_ReceiverIsNullOrUndefined_Baseline;
    case ConvertReceiverMode::kNotNullOrUndefined:
      return Builtin::kCall_ReceiverIsNotNullOrUndefined_Baseline;
  }
}
}  // namespace

template <ConvertReceiverMode kMode, typename... Args>
void BaselineCompiler::BuildCall(uint32_t slot, uint32_t arg_count,
                                 Args... args) {
  uint32_t bitfield;
  if (CallTrampoline_Baseline_CompactDescriptor::EncodeBitField(arg_count, slot,
                                                                &bitfield)) {
    CallBuiltin<ConvertReceiverModeToCompactBuiltin(kMode)>(
        RegisterOperand(0),  // kFunction
        bitfield,            // kActualArgumentsCount | kSlot
        args...);            // Arguments
  } else {
    CallBuiltin<ConvertReceiverModeToBuiltin(kMode)>(
        RegisterOperand(0),  // kFunction
        arg_count,           // kActualArgumentsCount
        slot,                // kSlot
        args...);            // Arguments
  }
}

void BaselineCompiler::VisitCallAnyReceiver() {
  interpreter::RegisterList args = iterator().GetRegisterListOperand(1);
  uint32_t arg_count = args.register_count();
  BuildCall<ConvertReceiverMode::kAny>(Index(3), arg_count, args);
}

void BaselineCompiler::VisitCallProperty() {
  interpreter::RegisterList args = iterator().GetRegisterListOperand(1);
  uint32_t arg_count = args.register_count();
  BuildCall<ConvertReceiverMode::kNotNullOrUndefined>(Index(3), arg_count,
                                                      args);
}

void BaselineCompiler::VisitCallProperty0() {
  BuildCall<ConvertReceiverMode::kNotNullOrUndefined>(
      Index(2), JSParameterCount(0), RegisterOperand(1));
}

void BaselineCompiler::VisitCallProperty1() {
  BuildCall<ConvertReceiverMode::kNotNullOrUndefined>(
      Index(3), JSParameterCount(1), RegisterOperand(1), RegisterOperand(2));
}

void BaselineCompiler::VisitCallProperty2() {
  BuildCall<ConvertReceiverMode::kNotNullOrUndefined>(
      Index(4), JSParameterCount(2), RegisterOperand(1), RegisterOperand(2),
      RegisterOperand(3));
}

void BaselineCompiler::VisitCallUndefinedReceiver() {
  interpreter::RegisterList args = iterator().GetRegisterListOperand(1);
  uint32_t arg_count = JSParameterCount(args.register_count());
  BuildCall<ConvertReceiverMode::kNullOrUndefined>(
      Index(3), arg_count, RootIndex::kUndefinedValue, args);
}

void BaselineCompiler::VisitCallUndefinedReceiver0() {
  BuildCall<ConvertReceiverMode::kNullOrUndefined>(
      Index(1), JSParameterCount(0), RootIndex::kUndefinedValue);
}

void BaselineCompiler::VisitCallUndefinedReceiver1() {
  BuildCall<ConvertReceiverMode::kNullOrUndefined>(
      Index(2), JSParameterCount(1), RootIndex::kUndefinedValue,
      RegisterOperand(1));
}

void BaselineCompiler::VisitCallUndefinedReceiver2() {
  BuildCall<ConvertReceiverMode::kNullOrUndefined>(
      Index(3), JSParameterCount(2), RootIndex::kUndefinedValue,
      RegisterOperand(1), RegisterOperand(2));
}

void BaselineCompiler::VisitCallWithSpread() {
  interpreter::RegisterList args = iterator().GetRegisterListOperand(1);

  // Do not push the spread argument
  interpreter::Register spread_register = args.last_register();
  args = args.Truncate(args.register_count() - 1);

  uint32_t arg_count = args.register_count();

  CallBuiltin<Builtin::kCallWithSpread_Baseline>(
      RegisterOperand(0),  // kFunction
      arg_count,           // kActualArgumentsCount
      spread_register,     // kSpread
      Index(3),            // kSlot
      args);
}

void BaselineCompiler::VisitCallRuntime() {
  CallRuntime(iterator().GetRuntimeIdOperand(0),
              iterator().GetRegisterListOperand(1));
}

void BaselineCompiler::VisitCallRuntimeForPair() {
  auto builtin = iterator().GetRuntimeIdOperand(0);
  switch (builtin) {
    case Runtime::kLoadLookupSlotForCall: {
      // TODO(olivf) Once we have more builtins to support here we should find
      // out how to do this generically.
      auto in = iterator().GetRegisterListOperand(1);
      auto out = iterator().GetRegisterPairOperand(3);
      BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
      Register out_reg = scratch_scope.AcquireScratch();
      __ RegisterFrameAddress(out.first, out_reg);
      DCHECK_EQ(in.register_count(), 1);
      CallRuntime(Runtime::kLoadLookupSlotForCall_Baseline, in.first_register(),
                  out_reg);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void BaselineCompiler::VisitCallJSRuntime() {
  interpreter::RegisterList args = iterator().GetRegisterListOperand(1);
  uint32_t arg_count = JSParameterCount(args.register_count());

  // Load context for LoadNativeContextSlot.
  __ LoadContext(kContextRegister);
  __ LoadNativeContextSlot(kJavaScriptCallTargetRegister,
                           iterator().GetNativeContextIndexOperand(0));
  CallBuiltin<Builtin::kCall_ReceiverIsNullOrUndefined>(
      kJavaScriptCallTargetRegister,  // kFunction
      arg_count,                      // kActualArgumentsCount
      RootIndex::kUndefinedValue,     // kReceiver
      args);
}

void BaselineCompiler::VisitInvokeIntrinsic() {
  Runtime::FunctionId intrinsic_id = iterator().GetIntrinsicIdOperand(0);
  interpreter::RegisterList args = iterator().GetRegisterListOperand(1);
  switch (intrinsic_id) {
#define CASE(Name, ...)         \
  case Runtime::kInline##Name:  \
    VisitIntrinsic##Name(args); \
    break;
    INTRINSICS_LIST(CASE)
#undef CASE

    default:
      UNREACHABLE();
  }
}

void BaselineCompiler::VisitIntrinsicCopyDataProperties(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kCopyDataProperties>(args);
}

void BaselineCompiler::
    VisitIntrinsicCopyDataPropertiesWithExcludedPropertiesOnStack(
        interpreter::RegisterList args) {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register rscratch = scratch_scope.AcquireScratch();
  // Use an offset from args[0] instead of args[1] to pass a valid "end of"
  // pointer in the case where args.register_count() == 1.
  basm_.RegisterFrameAddress(interpreter::Register(args[0].index() + 1),
                             rscratch);
  CallBuiltin<Builtin::kCopyDataPropertiesWithExcludedPropertiesOnStack>(
      args[0], args.register_count() - 1, rscratch);
}

void BaselineCompiler::VisitIntrinsicCreateIterResultObject(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kCreateIterResultObject>(args);
}

void BaselineCompiler::VisitIntrinsicCreateAsyncFromSyncIterator(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kCreateAsyncFromSyncIteratorBaseline>(args[0]);
}

void BaselineCompiler::VisitIntrinsicCreateJSGeneratorObject(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kCreateGeneratorObject>(args);
}

void BaselineCompiler::VisitIntrinsicGeneratorGetResumeMode(
    interpreter::RegisterList args) {
  __ LoadRegister(kInterpreterAccumulatorRegister, args[0]);
  __ LoadTaggedField(kInterpreterAccumulatorRegister,
                     kInterpreterAccumulatorRegister,
                     JSGeneratorObject::kResumeModeOffset);
}

void BaselineCompiler::VisitIntrinsicGeneratorClose(
    interpreter::RegisterList args) {
  __ LoadRegister(kInterpreterAccumulatorRegister, args[0]);
  __ StoreTaggedSignedField(kInterpreterAccumulatorRegister,
                            JSGeneratorObject::kContinuationOffset,
                            Smi::FromInt(JSGeneratorObject::kGeneratorClosed));
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
}

void BaselineCompiler::VisitIntrinsicGetImportMetaObject(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kGetImportMetaObjectBaseline>();
}

void BaselineCompiler::VisitIntrinsicAsyncFunctionAwait(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kAsyncFunctionAwait>(args);
}

void BaselineCompiler::VisitIntrinsicAsyncFunctionEnter(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kAsyncFunctionEnter>(args);
}

void BaselineCompiler::VisitIntrinsicAsyncFunctionReject(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kAsyncFunctionReject>(args);
}

void BaselineCompiler::VisitIntrinsicAsyncFunctionResolve(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kAsyncFunctionResolve>(args);
}

void BaselineCompiler::VisitIntrinsicAsyncGeneratorAwait(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kAsyncGeneratorAwait>(args);
}

void BaselineCompiler::VisitIntrinsicAsyncGeneratorReject(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kAsyncGeneratorReject>(args);
}

void BaselineCompiler::VisitIntrinsicAsyncGeneratorResolve(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kAsyncGeneratorResolve>(args);
}

void BaselineCompiler::VisitIntrinsicAsyncGeneratorYieldWithAwait(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kAsyncGeneratorYieldWithAwait>(args);
}

void BaselineCompiler::VisitConstruct() {
  interpreter::RegisterList args = iterator().GetRegisterListOperand(1);
  uint32_t arg_count = JSParameterCount(args.register_count());
  CallBuiltin<Builtin::kConstruct_Baseline>(
      RegisterOperand(0),               // kFunction
      kInterpreterAccumulatorRegister,  // kNewTarget
      arg_count,                        // kActualArgumentsCount
      Index(3),                         // kSlot
      RootIndex::kUndefinedValue,       // kReceiver
      args);
}

void BaselineCompiler::VisitConstructWithSpread() {
  interpreter::RegisterList args = iterator().GetRegisterListOperand(1);

  // Do not push the spread argument
  interpreter::Register spread_register = args.last_register();
  args = args.Truncate(args.register_count() - 1);

  uint32_t arg_count = JSParameterCount(args.register_count());

  using Descriptor =
      CallInterfaceDescriptorFor<Builtin::kConstructWithSpread_Baseline>::type;
  Register new_target =
      Descriptor::GetRegisterParameter(Descriptor::kNewTarget);
  __ Move(new_target, kInterpreterAccumulatorRegister);

  CallBuiltin<Builtin::kConstructWithSpread_Baseline>(
      RegisterOperand(0),          // kFunction
      new_target,                  // kNewTarget
      arg_count,                   // kActualArgumentsCount
      spread_register,             // kSpread
      IndexAsTagged(3),            // kSlot
      RootIndex::kUndefinedValue,  // kReceiver
      args);
}

void BaselineCompiler::VisitConstructForwardAllArgs() {
  using Descriptor = CallInterfaceDescriptorFor<
      Builtin::kConstructForwardAllArgs_Baseline>::type;
  Register new_target =
      Descriptor::GetRegisterParameter(Descriptor::kNewTarget);
  __ Move(new_target, kInterpreterAccumulatorRegister);

  CallBuiltin<Builtin::kConstructForwardAllArgs_Baseline>(
      RegisterOperand(0),  // kFunction
      new_target,          // kNewTarget
      IndexAsTagged(1));   // kSlot
}

void BaselineCompiler::VisitTestEqual() {
  CallBuiltin<Builtin::kEqual_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitTestEqualStrict() {
  CallBuiltin<Builtin::kStrictEqual_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitTestLessThan() {
  CallBuiltin<Builtin::kLessThan_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitTestGreaterThan() {
  CallBuiltin<Builtin::kGreaterThan_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitTestLessThanOrEqual() {
  CallBuiltin<Builtin::kLessThanOrEqual_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitTestGreaterThanOrEqual() {
  CallBuiltin<Builtin::kGreaterThanOrEqual_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitTestReferenceEqual() {
  SelectBooleanConstant(
      kInterpreterAccumulatorRegister,
      [&](Label* is_true, Label::Distance distance) {
        __ JumpIfTagged(kEqual, __ RegisterFrameOperand(RegisterOperand(0)),
                        kInterpreterAccumulatorRegister, is_true, distance);
      });
}

void BaselineCompiler::VisitTestInstanceOf() {
  using Descriptor =
      CallInterfaceDescriptorFor<Builtin::kInstanceOf_Baseline>::type;
  Register callable = Descriptor::GetRegisterParameter(Descriptor::kRight);
  __ Move(callable, kInterpreterAccumulatorRegister);

  CallBuiltin<Builtin::kInstanceOf_Baseline>(RegisterOperand(0),  // object
                                             callable,            // callable
                                             Index(1));           // slot
}

void BaselineCompiler::VisitTestIn() {
  CallBuiltin<Builtin::kKeyedHasICBaseline>(
      kInterpreterAccumulatorRegister,  // object
      RegisterOperand(0),               // name
      IndexAsTagged(1));                // slot
}

void BaselineCompiler::VisitTestUndetectable() {
  Label done, is_smi, not_undetectable;
  __ JumpIfSmi(kInterpreterAccumulatorRegister, &is_smi, Label::kNear);

  Register map_bit_field = kInterpreterAccumulatorRegister;
  __ LoadMap(map_bit_field, kInterpreterAccumulatorRegister);
  __ LoadWord8Field(map_bit_field, map_bit_field, Map::kBitFieldOffset);
  __ TestAndBranch(map_bit_field, Map::Bits1::IsUndetectableBit::kMask, kZero,
                   &not_undetectable, Label::kNear);

  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kTrueValue);
  __ Jump(&done, Label::kNear);

  __ Bind(&is_smi);
  __ Bind(&not_undetectable);
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kFalseValue);
  __ Bind(&done);
}

void BaselineCompiler::VisitTestNull() {
  SelectBooleanConstant(kInterpreterAccumulatorRegister,
                        [&](Label* is_true, Label::Distance distance) {
                          __ JumpIfRoot(kInterpreterAccumulatorRegister,
                                        RootIndex::kNullValue, is_true,
                                        distance);
                        });
}

void BaselineCompiler::VisitTestUndefined() {
  SelectBooleanConstant(kInterpreterAccumulatorRegister,
                        [&](Label* is_true, Label::Distance distance) {
                          __ JumpIfRoot(kInterpreterAccumulatorRegister,
                                        RootIndex::kUndefinedValue, is_true,
                                        distance);
                        });
}

void BaselineCompiler::VisitTestTypeOf() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);

  auto literal_flag =
      static_cast<interpreter::TestTypeOfFlags::LiteralFlag>(Flag8(0));

  Label done;
  switch (literal_flag) {
    case interpreter::TestTypeOfFlags::LiteralFlag::kNumber: {
      Label is_smi, is_heap_number;
      __ JumpIfSmi(kInterpreterAccumulatorRegister, &is_smi, Label::kNear);
      __ JumpIfObjectTypeFast(kEqual, kInterpreterAccumulatorRegister,
                              HEAP_NUMBER_TYPE, &is_heap_number, Label::kNear);

      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kFalseValue);
      __ Jump(&done, Label::kNear);

      __ Bind(&is_smi);
      __ Bind(&is_heap_number);
      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kTrueValue);
      break;
    }
    case interpreter::TestTypeOfFlags::LiteralFlag::kString: {
      Label is_smi, bad_instance_type;
      __ JumpIfSmi(kInterpreterAccumulatorRegister, &is_smi, Label::kNear);
      static_assert(INTERNALIZED_TWO_BYTE_STRING_TYPE == FIRST_TYPE);
      __ JumpIfObjectType(kGreaterThanEqual, kInterpreterAccumulatorRegister,
                          FIRST_NONSTRING_TYPE, scratch_scope.AcquireScratch(),
                          &bad_instance_type, Label::kNear);

      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kTrueValue);
      __ Jump(&done, Label::kNear);

      __ Bind(&is_smi);
      __ Bind(&bad_instance_type);
      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kFalseValue);
      break;
    }
    case interpreter::TestTypeOfFlags::LiteralFlag::kSymbol: {
      Label is_smi, bad_instance_type;
      __ JumpIfSmi(kInterpreterAccumulatorRegister, &is_smi, Label::kNear);
      __ JumpIfObjectTypeFast(kNotEqual, kInterpreterAccumulatorRegister,
                              SYMBOL_TYPE, &bad_instance_type, Label::kNear);

      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kTrueValue);
      __ Jump(&done, Label::kNear);

      __ Bind(&is_smi);
      __ Bind(&bad_instance_type);
      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kFalseValue);
      break;
    }
    case interpreter::TestTypeOfFlags::LiteralFlag::kBoolean: {
      Label is_true, is_false;
      __ JumpIfRoot(kInterpreterAccumulatorRegister, RootIndex::kTrueValue,
                    &is_true, Label::kNear);
      __ JumpIfRoot(kInterpreterAccumulatorRegister, RootIndex::kFalseValue,
                    &is_false, Label::kNear);

      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kFalseValue);
      __ Jump(&done, Label::kNear);

      __ Bind(&is_true);
      __ Bind(&is_false);
      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kTrueValue);
      break;
    }
    case interpreter::TestTypeOfFlags::LiteralFlag::kBigInt: {
      Label is_smi, bad_instance_type;
      __ JumpIfSmi(kInterpreterAccumulatorRegister, &is_smi, Label::kNear);
      __ JumpIfObjectTypeFast(kNotEqual, kInterpreterAccumulatorRegister,
                              BIGINT_TYPE, &bad_instance_type, Label::kNear);

      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kTrueValue);
      __ Jump(&done, Label::kNear);

      __ Bind(&is_smi);
      __ Bind(&bad_instance_type);
      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kFalseValue);
      break;
    }
    case interpreter::TestTypeOfFlags::LiteralFlag::kUndefined: {
      Label is_smi, is_null, not_undetectable;
      __ JumpIfSmi(kInterpreterAccumulatorRegister, &is_smi, Label::kNear);

      // null is undetectable, so test it explicitly, and return false.
      __ JumpIfRoot(kInterpreterAccumulatorRegister, RootIndex::kNullValue,
                    &is_null, Label::kNear);

      // All other undetectable maps are typeof undefined.
      Register map_bit_field = kInterpreterAccumulatorRegister;
      __ LoadMap(map_bit_field, kInterpreterAccumulatorRegister);
      __ LoadWord8Field(map_bit_field, map_bit_field, Map::kBitFieldOffset);
      __ TestAndBranch(map_bit_field, Map::Bits1::IsUndetectableBit::kMask,
                       kZero, &not_undetectable, Label::kNear);

      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kTrueValue);
      __ Jump(&done, Label::kNear);

      __ Bind(&is_smi);
      __ Bind(&is_null);
      __ Bind(&not_undetectable);
      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kFalseValue);
      break;
    }
    case interpreter::TestTypeOfFlags::LiteralFlag::kFunction: {
      Label is_smi, not_callable, undetectable;
      __ JumpIfSmi(kInterpreterAccumulatorRegister, &is_smi, Label::kNear);

      // Check if the map is callable but not undetectable.
      Register map_bit_field = kInterpreterAccumulatorRegister;
      __ LoadMap(m
```