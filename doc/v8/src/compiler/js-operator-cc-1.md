Response:
Let's break down the thought process for analyzing the provided C++ code snippet and generating the summary.

**1. Understanding the Goal:**

The request asks for a functional summary of the provided C++ code, specifically targeting the `v8/src/compiler/js-operator.cc` file. It also includes specific instructions about how to handle potential Torque files, JavaScript relevance, code logic, and common errors. Crucially, it marks this as "Part 2," implying there's a prior context (which we don't have, but we can infer general knowledge about V8).

**2. Initial Scan and Keyword Recognition:**

The first step is a quick scan of the code looking for recurring patterns and keywords. Immediately noticeable are:

* `JSOperatorBuilder`: This strongly suggests the code is about building or defining operators related to JavaScript operations.
* `const Operator*`:  This confirms that the functions are returning pointers to `Operator` objects, which likely represent individual operations within V8's intermediate representation (IR).
* `IrOpcode::kJS...`:  This is a clear indicator of different JavaScript-specific opcodes (like `kJSCall`, `kJSLoadNamed`, `kJSCreateArray`, etc.).
* `parameters`: Many functions take a `parameters` argument, often a structure or class holding details specific to the operation.
* `zone()->New<Operator1<...>>`: This is memory allocation within V8's zone system, suggesting the creation of new operator objects.
* Function names like `Call`, `Construct`, `Load`, `Store`, `Create`, `Delete`, etc., directly correspond to common JavaScript actions.
* Comments like `// --` visually separate the core logic of creating the operator.

**3. Identifying Core Functionality:**

Based on the keywords and function names, the primary function of this code is clearly to define and create various operators that represent JavaScript operations at a lower level within the V8 compiler. Each function seems to correspond to a specific JavaScript construct or operation.

**4. Addressing the ".tq" Check:**

The request specifically asks about `.tq` files. The code provided is `.cc`, so this part is straightforward: the file is *not* a Torque file.

**5. Linking to JavaScript Functionality:**

This is a crucial step. For each category of operators (Call, Construct, Load, Store, Create, etc.), the goal is to provide a simple, illustrative JavaScript example. The thinking here is:

* **Call/Construct:** These are directly related to function invocation and object creation. Simple examples like calling a function or using `new` are appropriate. Distinguish between regular calls and those with spread syntax.
* **Load/Store:** These correspond to accessing and modifying object properties and variables. Examples with dot notation, bracket notation, and global variable access are relevant.
* **Create:**  This covers various object creation scenarios like arrays, objects, functions, etc. Simple literal creations and constructor calls work well.
* **Delete:** The `delete` operator in JavaScript.
* **Iteration:** The `for...in` loop.
* **Context:**  Less directly visible in basic JavaScript, but related to variable scope and closures. A simple closure example demonstrates the concept.

**6. Handling Code Logic and Assumptions:**

The request asks for assumptions, inputs, and outputs. Since this code *defines* operators rather than *executing* them, the "input" is the parameters passed to the `JSOperatorBuilder` methods, and the "output" is the created `Operator` object. The logic is the instantiation of these objects with specific properties based on the input parameters.

An example of a specific operator like `LoadNamed` helps illustrate this. We can assume a `NameRef` (the property name) and `FeedbackSource`. The output is a `JSLoadNamed` operator configured with this information.

**7. Identifying Common Programming Errors:**

Here, the focus shifts to how these low-level operations relate to common mistakes JavaScript developers make:

* **`Call`/`Construct`:**  `TypeError` when calling non-functions or trying to construct non-constructors.
* **`LoadNamed`/`StoreNamed`:**  `ReferenceError` for accessing non-existent variables or properties, and issues with strict mode assignments.
* **`DeleteProperty`:**  Trying to delete non-configurable properties.
* **Context:**  Accidental global variable creation due to missing `var`, `let`, or `const`.

**8. Synthesizing the Summary (Part 2):**

Since this is "Part 2," the summary should build upon the understanding established in "Part 1" (even though we don't have it explicitly). The key is to reiterate the core function (defining JS operators) and then summarize the *categories* of operators covered. Avoid getting bogged down in the details of each specific operator. Emphasize the connection to JavaScript semantics.

**9. Refinement and Clarity:**

After drafting the initial response, review it for clarity, accuracy, and completeness. Ensure the JavaScript examples are simple and directly relevant. Check for any jargon that needs explanation. Make sure the structure logically flows and addresses all parts of the original request. For instance, initially, I might have listed *every* operator individually, but realizing the request is for a *summary*, grouping them by functionality is more effective. Also, double-check the assumptions, inputs, and outputs to make sure they accurately reflect what the code is doing.
这是对 v8 源代码文件 `v8/src/compiler/js-operator.cc` 的分析，它定义了表示 JavaScript 操作的中间表示 (IR) 操作符。

**功能归纳:**

`v8/src/compiler/js-operator.cc` 文件的主要功能是提供一个构建器 (`JSOperatorBuilder`)，用于创建表示各种 JavaScript 操作的 `Operator` 对象。这些 `Operator` 对象是 V8 编译器在将 JavaScript 代码转换为机器码的过程中使用的中间表示的一部分。

**详细功能列表:**

该文件定义了用于创建以下类型 JavaScript 操作的 `Operator` 的方法：

* **函数调用 (Call):**
    * `Call`: 普通函数调用。
    * `CallWithSpread`: 使用展开语法 (`...`) 的函数调用。
    * `CallRuntime`: 调用 V8 运行时函数。
    * `CallWasm`: 调用 WebAssembly 函数。
* **构造函数调用 (Construct):**
    * `Construct`: 普通构造函数调用。
    * `ConstructForwardVarargs`: 转发可变参数的构造函数调用。
    * `ConstructWithArrayLike`: 使用类数组对象作为参数的构造函数调用。
    * `ConstructWithSpread`: 使用展开语法的构造函数调用。
    * `ConstructForwardAllArgs`: 转发所有参数的构造函数调用。
* **属性访问 (Property Access):**
    * `LoadNamed`: 加载命名属性。
    * `LoadNamedFromSuper`: 从父类加载命名属性。
    * `LoadProperty`: 加载计算属性（通过表达式）。
    * `SetNamedProperty`: 设置命名属性。
    * `SetKeyedProperty`: 设置计算属性。
    * `DefineKeyedOwnProperty`: 定义键控自有属性。
    * `DefineNamedOwnProperty`: 定义命名自有属性。
    * `DeleteProperty`: 删除属性。
    * `HasProperty`: 检查对象是否拥有指定属性。
* **迭代 (Iteration):**
    * `GetIterator`: 获取迭代器。
    * `ForInNext`: `for...in` 循环的下一步迭代。
    * `ForInPrepare`: 准备 `for...in` 循环。
* **全局变量访问 (Global Access):**
    * `LoadGlobal`: 加载全局变量。
    * `StoreGlobal`: 存储全局变量。
* **上下文 (Context) 访问:**
    * `HasContextExtension`: 检查上下文是否有扩展。
    * `LoadContext`: 加载上下文变量。
    * `LoadScriptContext`: 加载脚本上下文变量。
    * `StoreContext`: 存储上下文变量。
    * `StoreScriptContext`: 存储脚本上下文变量。
* **模块 (Module) 访问:**
    * `LoadModule`: 加载模块变量。
    * `StoreModule`: 存储模块变量。
    * `GetImportMeta`: 获取 `import.meta` 对象。
* **对象和数组创建 (Object and Array Creation):**
    * `CreateArguments`: 创建 `arguments` 对象。
    * `CreateArray`: 创建数组。
    * `CreateArrayIterator`: 创建数组迭代器。
    * `CreateCollectionIterator`: 创建集合迭代器（Map, Set 等）迭代器。
    * `CreateBoundFunction`: 创建绑定函数。
    * `CreateClosure`: 创建闭包。
    * `CreateLiteralArray`: 创建数组字面量。
    * `CreateEmptyLiteralArray`: 创建空数组字面量。
    * `CreateArrayFromIterable`: 从可迭代对象创建数组。
    * `CreateLiteralObject`: 创建对象字面量。
    * `CreateEmptyLiteralObject`: 创建空对象字面量。
    * `CreateLiteralRegExp`: 创建正则表达式字面量。
    * `CloneObject`: 克隆对象。
* **生成器 (Generator) 和异步函数 (Async Function):**
    * `CreateGeneratorObject`: 创建生成器对象。
    * `GeneratorStore`: 存储生成器状态。
    * `GeneratorRestoreRegister`: 恢复生成器寄存器。
    * `CreateAsyncFunctionObject`: 创建异步函数对象。
* **作用域 (Scope) 和上下文 (Context) 创建:**
    * `CreateFunctionContext`: 创建函数上下文。
    * `CreateCatchContext`: 创建 `catch` 块上下文。
    * `CreateWithContext`: 创建 `with` 语句上下文。
    * `CreateBlockContext`: 创建块级作用域上下文。
* **其他:**
    * `StackCheck`: 执行堆栈检查。
    * `GetTemplateObject`: 获取模板对象 (用于模板字面量)。

**关于 Torque 源代码:**

如果 `v8/src/compiler/js-operator.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。 Torque 是一种用于编写 V8 内部组件的高级领域特定语言。 Torque 代码通常用于定义内置函数和操作的语义。由于该文件以 `.cc` 结尾，它是一个标准的 C++ 文件。

**与 JavaScript 功能的关系及示例:**

`v8/src/compiler/js-operator.cc` 中定义的每个操作符都直接对应于 JavaScript 语言的某个功能。以下是一些示例：

* **`JSOperatorBuilder::Call`**:  对应 JavaScript 中的函数调用。

   ```javascript
   function myFunction(a, b) {
     return a + b;
   }
   let result = myFunction(1, 2); // 这会对应一个 JSCall 操作
   ```

* **`JSOperatorBuilder::Construct`**: 对应 JavaScript 中的 `new` 关键字进行对象构造。

   ```javascript
   class MyClass {
     constructor(value) {
       this.value = value;
     }
   }
   let myObject = new MyClass(5); // 这会对应一个 JSConstruct 操作
   ```

* **`JSOperatorBuilder::LoadNamed`**: 对应 JavaScript 中访问对象的属性。

   ```javascript
   const obj = { name: 'example' };
   console.log(obj.name); // 这会对应一个 JSLoadNamed 操作
   ```

* **`JSOperatorBuilder::StoreNamed` (虽然代码中是 `SetNamedProperty`)**: 对应 JavaScript 中设置对象的属性。

   ```javascript
   const obj = {};
   obj.name = 'new value'; // 这会对应一个 JSSetNamedProperty 操作
   ```

* **`JSOperatorBuilder::CreateArray`**: 对应 JavaScript 中创建数组。

   ```javascript
   const arr = [1, 2, 3]; // 这会对应一个 JSCreateArray 操作
   const arr2 = new Array(5); // 这也会对应一个 JSCreateArray 操作
   ```

* **`JSOperatorBuilder::LoadGlobal`**: 对应 JavaScript 中访问全局变量。

   ```javascript
   console.log(globalThis.Math); // 这会对应一个 JSLoadGlobal 操作
   ```

**代码逻辑推理、假设输入与输出:**

以 `JSOperatorBuilder::LoadNamed` 为例进行推理：

**假设输入:**

* `name`: 一个 `NameRef` 对象，表示要加载的属性名称，例如字符串 "length"。
* `feedback`: 一个 `FeedbackSource` 对象，用于提供优化反馈信息。

**代码逻辑:**

1. `static constexpr int kObject = 1;`  //  加载属性需要一个对象作为输入
2. `static constexpr int kFeedbackVector = 1;` // 加载属性需要一个反馈向量作为输入
3. `static constexpr int kArity = kObject + kFeedbackVector;` // 总共需要两个输入
4. `NamedAccess access(LanguageMode::kSloppy, name, feedback);` // 创建一个 `NamedAccess` 对象，包含语言模式、属性名和反馈信息。
5. `return zone()->New<Operator1<NamedAccess>>( ... );` // 在内存区域中创建一个新的 `Operator1` 对象，类型为 `JSLoadNamed`，并将 `NamedAccess` 对象作为参数存储在其中。

**输出:**

* 一个指向 `Operator` 对象的指针，该对象表示一个加载命名属性的操作。这个 `Operator` 对象包含了操作码 `IrOpcode::kJSLoadNamed` 和参数 `NamedAccess`。

**涉及用户常见的编程错误:**

这些操作符的生成和使用与用户在编写 JavaScript 代码时可能犯的错误密切相关。以下是一些例子：

* **调用非函数 (`JSOperatorBuilder::Call`)**: 如果用户尝试调用一个不是函数的变量，V8 在执行到对应的 `JSCall` 操作时会抛出 `TypeError`。

   ```javascript
   let notAFunction = 10;
   notAFunction(); // TypeError: notAFunction is not a function
   ```

* **访问未定义的属性 (`JSOperatorBuilder::LoadNamed`)**: 如果用户尝试访问一个对象上不存在的属性，通常会返回 `undefined`，但在某些情况下（例如在严格模式下访问未声明的变量）可能会导致 `ReferenceError`。

   ```javascript
   const obj = {};
   console.log(obj.nonExistentProperty); // 输出: undefined

   "use strict";
   console.log(undeclaredVariable); // ReferenceError: undeclaredVariable is not defined
   ```

* **尝试 `new` 一个非构造函数 (`JSOperatorBuilder::Construct`)**: 如果用户尝试使用 `new` 关键字调用一个普通函数（不是构造函数），V8 可能会抛出 `TypeError`。

   ```javascript
   function normalFunction() {
     return 10;
   }
   new normalFunction(); // TypeError: normalFunction is not a constructor
   ```

* **在不应该的地方使用 `delete` (`JSOperatorBuilder::DeleteProperty`)**: 用户可能会尝试删除不可配置的属性，这在严格模式下会抛出 `TypeError`，在非严格模式下则会静默失败。

   ```javascript
   "use strict";
   const obj = {};
   Object.defineProperty(obj, 'prop', { configurable: false, value: 10 });
   delete obj.prop; // TypeError: Cannot delete property 'prop' of #<Object>
   ```

* **作用域错误 (`JSOperatorBuilder::LoadContext`, `JSOperatorBuilder::StoreContext`)**:  错误地访问或修改了闭包中的变量，或者在意外的作用域中创建了变量。

   ```javascript
   function outer() {
     let count = 0;
     function inner() {
       count++; // 对外部作用域的变量进行操作
       console.log(count);
     }
     return inner;
   }

   const myInner = outer();
   myInner(); // 输出 1
   myInner(); // 输出 2
   ```

**总结 (第 2 部分):**

`v8/src/compiler/js-operator.cc` 是 V8 编译器中至关重要的组成部分，它定义了用于表示各种 JavaScript 语言构造和操作的底层操作符。`JSOperatorBuilder` 提供了一种结构化的方式来创建这些操作符，每个操作符都封装了执行特定 JavaScript 功能所需的信息。 这些操作符是 V8 编译器将高级 JavaScript 代码转换为高效机器码的关键中间步骤，并且它们的设计直接反映了 JavaScript 语言的语义和潜在的运行时错误。 理解这些操作符有助于深入了解 V8 引擎的工作原理以及 JavaScript 代码的执行过程。

Prompt: 
```
这是目录为v8/src/compiler/js-operator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-operator.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
",                                    // name
      parameters.arity(), 1, 1, 1, 1, 2,                        // counts
      parameters);                                              // parameter
}

const Operator* JSOperatorBuilder::CallWithSpread(
    uint32_t arity, CallFrequency const& frequency,
    FeedbackSource const& feedback, SpeculationMode speculation_mode,
    CallFeedbackRelation feedback_relation) {
  DCHECK_IMPLIES(speculation_mode == SpeculationMode::kAllowSpeculation,
                 feedback.IsValid());
  CallParameters parameters(arity, frequency, feedback,
                            ConvertReceiverMode::kAny, speculation_mode,
                            feedback_relation);
  return zone()->New<Operator1<CallParameters>>(             // --
      IrOpcode::kJSCallWithSpread, Operator::kNoProperties,  // opcode
      "JSCallWithSpread",                                    // name
      parameters.arity(), 1, 1, 1, 1, 2,                     // counts
      parameters);                                           // parameter
}

const Operator* JSOperatorBuilder::CallRuntime(Runtime::FunctionId id) {
  const Runtime::Function* f = Runtime::FunctionForId(id);
  return CallRuntime(f, f->nargs);
}

const Operator* JSOperatorBuilder::CallRuntime(
    Runtime::FunctionId id, size_t arity, Operator::Properties properties) {
  const Runtime::Function* f = Runtime::FunctionForId(id);
  return CallRuntime(f, arity, properties);
}

const Operator* JSOperatorBuilder::CallRuntime(
    const Runtime::Function* f, size_t arity, Operator::Properties properties) {
  CallRuntimeParameters parameters(f->function_id, arity);
  DCHECK(f->nargs == -1 || f->nargs == static_cast<int>(parameters.arity()));
  return zone()->New<Operator1<CallRuntimeParameters>>(  // --
      IrOpcode::kJSCallRuntime, properties,              // opcode
      "JSCallRuntime",                                   // name
      parameters.arity(), 1, 1, f->result_size, 1, 2,    // inputs/outputs
      parameters);                                       // parameter
}

#if V8_ENABLE_WEBASSEMBLY
const Operator* JSOperatorBuilder::CallWasm(
    const wasm::WasmModule* wasm_module,
    const wasm::CanonicalSig* wasm_signature, int wasm_function_index,
    SharedFunctionInfoRef shared_fct_info, wasm::NativeModule* native_module,
    FeedbackSource const& feedback) {
  // TODO(clemensb): Drop wasm_module.
  DCHECK_EQ(wasm_module, native_module->module());
  JSWasmCallParameters parameters(wasm_module, wasm_signature,
                                  wasm_function_index, shared_fct_info,
                                  native_module, feedback);
  return zone()->New<Operator1<JSWasmCallParameters>>(
      IrOpcode::kJSWasmCall, Operator::kNoProperties,  // opcode
      "JSWasmCall",                                    // name
      parameters.input_count(), 1, 1, 1, 1, 2,         // inputs/outputs
      parameters);                                     // parameter
}
#endif  // V8_ENABLE_WEBASSEMBLY

const Operator* JSOperatorBuilder::ConstructForwardVarargs(
    size_t arity, uint32_t start_index) {
  ConstructForwardVarargsParameters parameters(arity, start_index);
  return zone()->New<Operator1<ConstructForwardVarargsParameters>>(   // --
      IrOpcode::kJSConstructForwardVarargs, Operator::kNoProperties,  // opcode
      "JSConstructForwardVarargs",                                    // name
      parameters.arity(), 1, 1, 1, 1, 2,                              // counts
      parameters);  // parameter
}

// Note: frequency is taken by reference to work around a GCC bug
// on AIX (v8:8193).
const Operator* JSOperatorBuilder::Construct(uint32_t arity,
                                             CallFrequency const& frequency,
                                             FeedbackSource const& feedback) {
  ConstructParameters parameters(arity, frequency, feedback);
  return zone()->New<Operator1<ConstructParameters>>(   // --
      IrOpcode::kJSConstruct, Operator::kNoProperties,  // opcode
      "JSConstruct",                                    // name
      parameters.arity(), 1, 1, 1, 1, 2,                // counts
      parameters);                                      // parameter
}

const Operator* JSOperatorBuilder::ConstructWithArrayLike(
    CallFrequency const& frequency, FeedbackSource const& feedback) {
  static constexpr int kTheArrayLikeObject = 1;
  ConstructParameters parameters(
      JSConstructWithArrayLikeNode::ArityForArgc(kTheArrayLikeObject),
      frequency, feedback);
  return zone()->New<Operator1<ConstructParameters>>(  // --
      IrOpcode::kJSConstructWithArrayLike,             // opcode
      Operator::kNoProperties,                         // properties
      "JSConstructWithArrayLike",                      // name
      parameters.arity(), 1, 1, 1, 1, 2,               // counts
      parameters);                                     // parameter
}

const Operator* JSOperatorBuilder::ConstructWithSpread(
    uint32_t arity, CallFrequency const& frequency,
    FeedbackSource const& feedback) {
  ConstructParameters parameters(arity, frequency, feedback);
  return zone()->New<Operator1<ConstructParameters>>(             // --
      IrOpcode::kJSConstructWithSpread, Operator::kNoProperties,  // opcode
      "JSConstructWithSpread",                                    // name
      parameters.arity(), 1, 1, 1, 1, 2,                          // counts
      parameters);                                                // parameter
}

const Operator* JSOperatorBuilder::ConstructForwardAllArgs(
    CallFrequency const& frequency, FeedbackSource const& feedback) {
  // Use 0 as a fake arity. This operator will be reduced away to either a call
  // to Builtin::kConstructForwardAllArgs or an ordinary
  // JSConstruct.
  ConstructParameters parameters(JSConstructForwardAllArgsNode::ArityForArgc(0),
                                 frequency, feedback);
  return zone()->New<Operator1<ConstructParameters>>(                 // --
      IrOpcode::kJSConstructForwardAllArgs, Operator::kNoProperties,  // opcode
      "JSConstructForwardAllArgs",                                    // name
      parameters.arity(), 1, 1, 1, 1, 2,                              // counts
      parameters);  // parameter
}

const Operator* JSOperatorBuilder::LoadNamed(NameRef name,
                                             const FeedbackSource& feedback) {
  static constexpr int kObject = 1;
  static constexpr int kFeedbackVector = 1;
  static constexpr int kArity = kObject + kFeedbackVector;
  NamedAccess access(LanguageMode::kSloppy, name, feedback);
  return zone()->New<Operator1<NamedAccess>>(           // --
      IrOpcode::kJSLoadNamed, Operator::kNoProperties,  // opcode
      "JSLoadNamed",                                    // name
      kArity, 1, 1, 1, 1, 2,                            // counts
      access);                                          // parameter
}

const Operator* JSOperatorBuilder::LoadNamedFromSuper(
    NameRef name, const FeedbackSource& feedback) {
  static constexpr int kReceiver = 1;
  static constexpr int kHomeObject = 1;
  static constexpr int kFeedbackVector = 1;
  static constexpr int kArity = kReceiver + kHomeObject + kFeedbackVector;
  NamedAccess access(LanguageMode::kSloppy, name, feedback);
  return zone()->New<Operator1<NamedAccess>>(                    // --
      IrOpcode::kJSLoadNamedFromSuper, Operator::kNoProperties,  // opcode
      "JSLoadNamedFromSuper",                                    // name
      kArity, 1, 1, 1, 1, 2,                                     // counts
      access);                                                   // parameter
}

const Operator* JSOperatorBuilder::LoadProperty(
    FeedbackSource const& feedback) {
  PropertyAccess access(LanguageMode::kSloppy, feedback);
  return zone()->New<Operator1<PropertyAccess>>(           // --
      IrOpcode::kJSLoadProperty, Operator::kNoProperties,  // opcode
      "JSLoadProperty",                                    // name
      3, 1, 1, 1, 1, 2,                                    // counts
      access);                                             // parameter
}

const Operator* JSOperatorBuilder::GetIterator(
    FeedbackSource const& load_feedback, FeedbackSource const& call_feedback) {
  GetIteratorParameters access(load_feedback, call_feedback);
  return zone()->New<Operator1<GetIteratorParameters>>(   // --
      IrOpcode::kJSGetIterator, Operator::kNoProperties,  // opcode
      "JSGetIterator",                                    // name
      2, 1, 1, 1, 1, 2,                                   // counts
      access);                                            // parameter
}

const Operator* JSOperatorBuilder::HasProperty(FeedbackSource const& feedback) {
  PropertyAccess access(LanguageMode::kSloppy, feedback);
  return zone()->New<Operator1<PropertyAccess>>(          // --
      IrOpcode::kJSHasProperty, Operator::kNoProperties,  // opcode
      "JSHasProperty",                                    // name
      3, 1, 1, 1, 1, 2,                                   // counts
      access);                                            // parameter
}

const Operator* JSOperatorBuilder::ForInNext(ForInMode mode,
                                             const FeedbackSource& feedback) {
  return zone()->New<Operator1<ForInParameters>>(       // --
      IrOpcode::kJSForInNext, Operator::kNoProperties,  // opcode
      "JSForInNext",                                    // name
      5, 1, 1, 1, 1, 2,                                 // counts
      ForInParameters{feedback, mode});                 // parameter
}

const Operator* JSOperatorBuilder::ForInPrepare(
    ForInMode mode, const FeedbackSource& feedback) {
  return zone()->New<Operator1<ForInParameters>>(  // --
      IrOpcode::kJSForInPrepare,                   // opcode
      Operator::kNoWrite | Operator::kNoThrow,     // flags
      "JSForInPrepare",                            // name
      2, 1, 1, 3, 1, 1,                            // counts
      ForInParameters{feedback, mode});            // parameter
}

const Operator* JSOperatorBuilder::GeneratorStore(int register_count) {
  return zone()->New<Operator1<int>>(                   // --
      IrOpcode::kJSGeneratorStore, Operator::kNoThrow,  // opcode
      "JSGeneratorStore",                               // name
      3 + register_count, 1, 1, 0, 1, 0,                // counts
      register_count);                                  // parameter
}

int RegisterCountOf(Operator const* op) {
  DCHECK_EQ(IrOpcode::kJSCreateAsyncFunctionObject, op->opcode());
  return OpParameter<int>(op);
}

int GeneratorStoreValueCountOf(const Operator* op) {
  DCHECK_EQ(IrOpcode::kJSGeneratorStore, op->opcode());
  return OpParameter<int>(op);
}

const Operator* JSOperatorBuilder::GeneratorRestoreRegister(int index) {
  return zone()->New<Operator1<int>>(                             // --
      IrOpcode::kJSGeneratorRestoreRegister, Operator::kNoThrow,  // opcode
      "JSGeneratorRestoreRegister",                               // name
      1, 1, 1, 1, 1, 0,                                           // counts
      index);                                                     // parameter
}

int RestoreRegisterIndexOf(const Operator* op) {
  DCHECK_EQ(IrOpcode::kJSGeneratorRestoreRegister, op->opcode());
  return OpParameter<int>(op);
}

const Operator* JSOperatorBuilder::SetNamedProperty(
    LanguageMode language_mode, NameRef name, FeedbackSource const& feedback) {
  static constexpr int kObject = 1;
  static constexpr int kValue = 1;
  static constexpr int kFeedbackVector = 1;
  static constexpr int kArity = kObject + kValue + kFeedbackVector;
  NamedAccess access(language_mode, name, feedback);
  return zone()->New<Operator1<NamedAccess>>(                  // --
      IrOpcode::kJSSetNamedProperty, Operator::kNoProperties,  // opcode
      "JSSetNamedProperty",                                    // name
      kArity, 1, 1, 0, 1, 2,                                   // counts
      access);                                                 // parameter
}

const Operator* JSOperatorBuilder::SetKeyedProperty(
    LanguageMode language_mode, FeedbackSource const& feedback) {
  PropertyAccess access(language_mode, feedback);
  return zone()->New<Operator1<PropertyAccess>>(               // --
      IrOpcode::kJSSetKeyedProperty, Operator::kNoProperties,  // opcode
      "JSSetKeyedProperty",                                    // name
      4, 1, 1, 0, 1, 2,                                        // counts
      access);                                                 // parameter
}

const Operator* JSOperatorBuilder::DefineKeyedOwnProperty(
    LanguageMode language_mode, FeedbackSource const& feedback) {
  PropertyAccess access(language_mode, feedback);
  return zone()->New<Operator1<PropertyAccess>>(                     // --
      IrOpcode::kJSDefineKeyedOwnProperty, Operator::kNoProperties,  // opcode
      "JSDefineKeyedOwnProperty",                                    // name
      5, 1, 1, 0, 1, 2,                                              // counts
      access);  // parameter
}

const Operator* JSOperatorBuilder::DefineNamedOwnProperty(
    NameRef name, FeedbackSource const& feedback) {
  static constexpr int kObject = 1;
  static constexpr int kValue = 1;
  static constexpr int kFeedbackVector = 1;
  static constexpr int kArity = kObject + kValue + kFeedbackVector;
  DefineNamedOwnPropertyParameters parameters(name, feedback);
  return zone()->New<Operator1<DefineNamedOwnPropertyParameters>>(   // --
      IrOpcode::kJSDefineNamedOwnProperty, Operator::kNoProperties,  // opcode
      "JSDefineNamedOwnProperty",                                    // name
      kArity, 1, 1, 0, 1, 2,                                         // counts
      parameters);  // parameter
}

const Operator* JSOperatorBuilder::DeleteProperty() {
  return zone()->New<Operator>(                              // --
      IrOpcode::kJSDeleteProperty, Operator::kNoProperties,  // opcode
      "JSDeleteProperty",                                    // name
      3, 1, 1, 1, 1, 2);                                     // counts
}

const Operator* JSOperatorBuilder::CreateGeneratorObject() {
  return zone()->New<Operator>(                                     // --
      IrOpcode::kJSCreateGeneratorObject, Operator::kEliminatable,  // opcode
      "JSCreateGeneratorObject",                                    // name
      2, 1, 1, 1, 1, 0);                                            // counts
}

const Operator* JSOperatorBuilder::LoadGlobal(NameRef name,
                                              const FeedbackSource& feedback,
                                              TypeofMode typeof_mode) {
  static constexpr int kFeedbackVector = 1;
  static constexpr int kArity = kFeedbackVector;
  LoadGlobalParameters parameters(name, feedback, typeof_mode);
  return zone()->New<Operator1<LoadGlobalParameters>>(   // --
      IrOpcode::kJSLoadGlobal, Operator::kNoProperties,  // opcode
      "JSLoadGlobal",                                    // name
      kArity, 1, 1, 1, 1, 2,                             // counts
      parameters);                                       // parameter
}

const Operator* JSOperatorBuilder::StoreGlobal(LanguageMode language_mode,
                                               NameRef name,
                                               const FeedbackSource& feedback) {
  static constexpr int kValue = 1;
  static constexpr int kFeedbackVector = 1;
  static constexpr int kArity = kValue + kFeedbackVector;
  StoreGlobalParameters parameters(language_mode, feedback, name);
  return zone()->New<Operator1<StoreGlobalParameters>>(   // --
      IrOpcode::kJSStoreGlobal, Operator::kNoProperties,  // opcode
      "JSStoreGlobal",                                    // name
      kArity, 1, 1, 0, 1, 2,                              // counts
      parameters);                                        // parameter
}

const Operator* JSOperatorBuilder::HasContextExtension(size_t depth) {
  return zone()->New<Operator1<size_t>>(        // --
      IrOpcode::kJSHasContextExtension,         // opcode
      Operator::kNoWrite | Operator::kNoThrow,  // flags
      "JSHasContextExtension",                  // name
      0, 1, 0, 1, 1, 0,                         // counts
      depth);                                   // parameter
}

const Operator* JSOperatorBuilder::LoadContext(size_t depth, size_t index,
                                               bool immutable) {
  ContextAccess access(depth, index, immutable);
  return zone()->New<Operator1<ContextAccess>>(  // --
      IrOpcode::kJSLoadContext,                  // opcode
      Operator::kNoWrite | Operator::kNoThrow,   // flags
      "JSLoadContext",                           // name
      0, 1, 0, 1, 1, 0,                          // counts
      access);                                   // parameter
}

const Operator* JSOperatorBuilder::LoadScriptContext(size_t depth,
                                                     size_t index) {
  ContextAccess access(depth, index, false);
  return zone()->New<Operator1<ContextAccess>>(  // --
      IrOpcode::kJSLoadScriptContext,            // opcode
      Operator::kNoWrite | Operator::kNoThrow,   // flags
      "JSLoadScriptContext",                     // name
      0, 1, 1, 1, 1, 1,                          // counts
      access);                                   // parameter
}

const Operator* JSOperatorBuilder::StoreContext(size_t depth, size_t index) {
  ContextAccess access(depth, index, false);
  return zone()->New<Operator1<ContextAccess>>(  // --
      IrOpcode::kJSStoreContext,                 // opcode
      Operator::kNoRead | Operator::kNoThrow,    // flags
      "JSStoreContext",                          // name
      1, 1, 1, 0, 1, 0,                          // counts
      access);                                   // parameter
}

const Operator* JSOperatorBuilder::StoreScriptContext(size_t depth,
                                                      size_t index) {
  ContextAccess access(depth, index, false);
  return zone()->New<Operator1<ContextAccess>>(  // --
      IrOpcode::kJSStoreScriptContext,           // opcode
      Operator::kNoRead | Operator::kNoThrow,    // flags
      "JSStoreScriptContext",                    // name
      1, 1, 1, 0, 1, 1,                          // counts
      access);                                   // parameter
}

const Operator* JSOperatorBuilder::LoadModule(int32_t cell_index) {
  return zone()->New<Operator1<int32_t>>(       // --
      IrOpcode::kJSLoadModule,                  // opcode
      Operator::kNoWrite | Operator::kNoThrow,  // flags
      "JSLoadModule",                           // name
      1, 1, 1, 1, 1, 0,                         // counts
      cell_index);                              // parameter
}

const Operator* JSOperatorBuilder::GetImportMeta() {
  return zone()->New<Operator>(    // --
      IrOpcode::kJSGetImportMeta,  // opcode
      Operator::kNoProperties,     // flags
      "JSGetImportMeta",           // name
      0, 1, 1, 1, 1, 2);           // counts
}

const Operator* JSOperatorBuilder::StoreModule(int32_t cell_index) {
  return zone()->New<Operator1<int32_t>>(      // --
      IrOpcode::kJSStoreModule,                // opcode
      Operator::kNoRead | Operator::kNoThrow,  // flags
      "JSStoreModule",                         // name
      2, 1, 1, 0, 1, 0,                        // counts
      cell_index);                             // parameter
}

const Operator* JSOperatorBuilder::CreateArguments(CreateArgumentsType type) {
  return zone()->New<Operator1<CreateArgumentsType>>(         // --
      IrOpcode::kJSCreateArguments, Operator::kEliminatable,  // opcode
      "JSCreateArguments",                                    // name
      1, 1, 0, 1, 1, 0,                                       // counts
      type);                                                  // parameter
}

const Operator* JSOperatorBuilder::CreateArray(size_t arity,
                                               OptionalAllocationSiteRef site) {
  // constructor, new_target, arg1, ..., argN
  int const value_input_count = static_cast<int>(arity) + 2;
  CreateArrayParameters parameters(arity, site);
  return zone()->New<Operator1<CreateArrayParameters>>(   // --
      IrOpcode::kJSCreateArray, Operator::kNoProperties,  // opcode
      "JSCreateArray",                                    // name
      value_input_count, 1, 1, 1, 1, 2,                   // counts
      parameters);                                        // parameter
}

const Operator* JSOperatorBuilder::CreateArrayIterator(IterationKind kind) {
  CreateArrayIteratorParameters parameters(kind);
  return zone()->New<Operator1<CreateArrayIteratorParameters>>(   // --
      IrOpcode::kJSCreateArrayIterator, Operator::kEliminatable,  // opcode
      "JSCreateArrayIterator",                                    // name
      1, 1, 1, 1, 1, 0,                                           // counts
      parameters);                                                // parameter
}

const Operator* JSOperatorBuilder::CreateAsyncFunctionObject(
    int register_count) {
  return zone()->New<Operator1<int>>(          // --
      IrOpcode::kJSCreateAsyncFunctionObject,  // opcode
      Operator::kEliminatable,                 // flags
      "JSCreateAsyncFunctionObject",           // name
      3, 1, 1, 1, 1, 0,                        // counts
      register_count);                         // parameter
}

const Operator* JSOperatorBuilder::CreateCollectionIterator(
    CollectionKind collection_kind, IterationKind iteration_kind) {
  CreateCollectionIteratorParameters parameters(collection_kind,
                                                iteration_kind);
  return zone()->New<Operator1<CreateCollectionIteratorParameters>>(
      IrOpcode::kJSCreateCollectionIterator, Operator::kEliminatable,
      "JSCreateCollectionIterator", 1, 1, 1, 1, 1, 0, parameters);
}

const Operator* JSOperatorBuilder::CreateBoundFunction(size_t arity,
                                                       MapRef map) {
  // bound_target_function, bound_this, arg1, ..., argN
  int const value_input_count = static_cast<int>(arity) + 2;
  CreateBoundFunctionParameters parameters(arity, map);
  return zone()->New<Operator1<CreateBoundFunctionParameters>>(   // --
      IrOpcode::kJSCreateBoundFunction, Operator::kEliminatable,  // opcode
      "JSCreateBoundFunction",                                    // name
      value_input_count, 1, 1, 1, 1, 0,                           // counts
      parameters);                                                // parameter
}

const Operator* JSOperatorBuilder::CreateClosure(
    SharedFunctionInfoRef shared_info, CodeRef code,
    AllocationType allocation) {
  static constexpr int kFeedbackCell = 1;
  static constexpr int kArity = kFeedbackCell;
  CreateClosureParameters parameters(shared_info, code, allocation);
  return zone()->New<Operator1<CreateClosureParameters>>(   // --
      IrOpcode::kJSCreateClosure, Operator::kEliminatable,  // opcode
      "JSCreateClosure",                                    // name
      kArity, 1, 1, 1, 1, 0,                                // counts
      parameters);                                          // parameter
}

const Operator* JSOperatorBuilder::CreateLiteralArray(
    ArrayBoilerplateDescriptionRef description, FeedbackSource const& feedback,
    int literal_flags, int number_of_elements) {
  CreateLiteralParameters parameters(description, feedback, number_of_elements,
                                     literal_flags);
  return zone()->New<Operator1<CreateLiteralParameters>>(  // --
      IrOpcode::kJSCreateLiteralArray,                     // opcode
      Operator::kNoProperties,                             // properties
      "JSCreateLiteralArray",                              // name
      1, 1, 1, 1, 1, 2,                                    // counts
      parameters);                                         // parameter
}

const Operator* JSOperatorBuilder::CreateEmptyLiteralArray(
    FeedbackSource const& feedback) {
  static constexpr int kFeedbackVector = 1;
  static constexpr int kArity = kFeedbackVector;
  FeedbackParameter parameters(feedback);
  return zone()->New<Operator1<FeedbackParameter>>(  // --
      IrOpcode::kJSCreateEmptyLiteralArray,          // opcode
      Operator::kEliminatable,                       // properties
      "JSCreateEmptyLiteralArray",                   // name
      kArity, 1, 1, 1, 1, 0,                         // counts
      parameters);                                   // parameter
}

const Operator* JSOperatorBuilder::CreateArrayFromIterable() {
  return zone()->New<Operator>(              // --
      IrOpcode::kJSCreateArrayFromIterable,  // opcode
      Operator::kNoProperties,               // properties
      "JSCreateArrayFromIterable",           // name
      1, 1, 1, 1, 1, 2);                     // counts
}

const Operator* JSOperatorBuilder::CreateLiteralObject(
    ObjectBoilerplateDescriptionRef constant_properties,
    FeedbackSource const& feedback, int literal_flags,
    int number_of_properties) {
  CreateLiteralParameters parameters(constant_properties, feedback,
                                     number_of_properties, literal_flags);
  return zone()->New<Operator1<CreateLiteralParameters>>(  // --
      IrOpcode::kJSCreateLiteralObject,                    // opcode
      Operator::kNoProperties,                             // properties
      "JSCreateLiteralObject",                             // name
      1, 1, 1, 1, 1, 2,                                    // counts
      parameters);                                         // parameter
}

const Operator* JSOperatorBuilder::GetTemplateObject(
    TemplateObjectDescriptionRef description, SharedFunctionInfoRef shared,
    FeedbackSource const& feedback) {
  GetTemplateObjectParameters parameters(description, shared, feedback);
  return zone()->New<Operator1<GetTemplateObjectParameters>>(  // --
      IrOpcode::kJSGetTemplateObject,                          // opcode
      Operator::kEliminatable,                                 // properties
      "JSGetTemplateObject",                                   // name
      1, 1, 1, 1, 1, 0,                                        // counts
      parameters);                                             // parameter
}

const Operator* JSOperatorBuilder::CloneObject(FeedbackSource const& feedback,
                                               int literal_flags) {
  CloneObjectParameters parameters(feedback, literal_flags);
  return zone()->New<Operator1<CloneObjectParameters>>(  // --
      IrOpcode::kJSCloneObject,                          // opcode
      Operator::kNoProperties,                           // properties
      "JSCloneObject",                                   // name
      2, 1, 1, 1, 1, 2,                                  // counts
      parameters);                                       // parameter
}

const Operator* JSOperatorBuilder::StackCheck(StackCheckKind kind) {
  Operator::Properties properties;
  switch (kind) {
    case StackCheckKind::kJSFunctionEntry:
    case StackCheckKind::kCodeStubAssembler:
    case StackCheckKind::kWasm:
      properties = Operator::kNoProperties;
      break;
    case StackCheckKind::kJSIterationBody:
      properties = Operator::kNoWrite;
      break;
  }
  return zone()->New<Operator1<StackCheckKind>>(  // --
      IrOpcode::kJSStackCheck,                    // opcode
      properties,                                 // properties
      "JSStackCheck",                             // name
      0, 1, 1, 0, 1, 2,                           // counts
      kind);                                      // parameter
}

const Operator* JSOperatorBuilder::CreateEmptyLiteralObject() {
  return zone()->New<Operator>(               // --
      IrOpcode::kJSCreateEmptyLiteralObject,  // opcode
      Operator::kNoProperties,                // properties
      "JSCreateEmptyLiteralObject",           // name
      0, 1, 1, 1, 1, 2);                      // counts
}

const Operator* JSOperatorBuilder::CreateLiteralRegExp(
    StringRef constant_pattern, FeedbackSource const& feedback,
    int literal_flags) {
  CreateLiteralParameters parameters(constant_pattern, feedback, -1,
                                     literal_flags);
  return zone()->New<Operator1<CreateLiteralParameters>>(  // --
      IrOpcode::kJSCreateLiteralRegExp,                    // opcode
      Operator::kNoProperties,                             // properties
      "JSCreateLiteralRegExp",                             // name
      1, 1, 1, 1, 1, 2,                                    // counts
      parameters);                                         // parameter
}

const Operator* JSOperatorBuilder::CreateFunctionContext(
    ScopeInfoRef scope_info, int slot_count, ScopeType scope_type) {
  CreateFunctionContextParameters parameters(scope_info, slot_count,
                                             scope_type);
  return zone()->New<Operator1<CreateFunctionContextParameters>>(   // --
      IrOpcode::kJSCreateFunctionContext, Operator::kNoProperties,  // opcode
      "JSCreateFunctionContext",                                    // name
      0, 1, 1, 1, 1, 2,                                             // counts
      parameters);                                                  // parameter
}

const Operator* JSOperatorBuilder::CreateCatchContext(ScopeInfoRef scope_info) {
  return zone()->New<Operator1<ScopeInfoRef>>(
      IrOpcode::kJSCreateCatchContext, Operator::kNoProperties,  // opcode
      "JSCreateCatchContext",                                    // name
      1, 1, 1, 1, 1, 2,                                          // counts
      ScopeInfoRef{scope_info});                                 // parameter
}

const Operator* JSOperatorBuilder::CreateWithContext(ScopeInfoRef scope_info) {
  return zone()->New<Operator1<ScopeInfoRef>>(
      IrOpcode::kJSCreateWithContext, Operator::kNoProperties,  // opcode
      "JSCreateWithContext",                                    // name
      1, 1, 1, 1, 1, 2,                                         // counts
      ScopeInfoRef{scope_info});                                // parameter
}

const Operator* JSOperatorBuilder::CreateBlockContext(ScopeInfoRef scope_info) {
  return zone()->New<Operator1<ScopeInfoRef>>(                   // --
      IrOpcode::kJSCreateBlockContext, Operator::kNoProperties,  // opcode
      "JSCreateBlockContext",                                    // name
      0, 1, 1, 1, 1, 2,                                          // counts
      ScopeInfoRef{scope_info});                                 // parameter
}

ScopeInfoRef ScopeInfoOf(const Operator* op) {
  DCHECK(IrOpcode::kJSCreateBlockContext == op->opcode() ||
         IrOpcode::kJSCreateWithContext == op->opcode() ||
         IrOpcode::kJSCreateCatchContext == op->opcode());
  return OpParameter<ScopeInfoRef>(op);
}

bool operator==(ScopeInfoRef lhs, ScopeInfoRef rhs) {
  return lhs.object().location() == rhs.object().location();
}

bool operator!=(ScopeInfoRef lhs, ScopeInfoRef rhs) { return !(lhs == rhs); }

size_t hash_value(ScopeInfoRef ref) {
  return reinterpret_cast<size_t>(ref.object().location());
}

std::ostream& operator<<(std::ostream& os, ScopeInfoRef ref) {
  return os << Brief(*ref.object());
}

#undef CACHED_OP_LIST

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```