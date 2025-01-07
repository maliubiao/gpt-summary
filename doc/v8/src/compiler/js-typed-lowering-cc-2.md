Response:
Let's break down the thought process for analyzing the provided V8 C++ code snippet.

1. **Understand the Goal:** The primary goal is to analyze the functionality of the given C++ code from `v8/src/compiler/js-typed-lowering.cc`. The prompt also includes specific constraints (Torque, JavaScript examples, logic inference, common errors, and a summary).

2. **Initial Scan and Keyword Recognition:**  Quickly read through the code, looking for familiar V8-related keywords and structures. Things that jump out:
    * `JSTypedLowering`: This class name immediately suggests a compiler optimization or transformation phase. "Lowering" usually implies converting higher-level constructs to lower-level ones. "Typed" hints that type information plays a crucial role.
    * `ReduceJS...`:  Methods like `ReduceJSLoadContext`, `ReduceJSStoreContext`, `ReduceJSCall`, `ReduceJSConstruct`, etc., strongly suggest that this code is involved in transforming JavaScript-specific operations. The `Reduce` prefix hints at a pattern often used in compiler optimization passes.
    * `Node* node`:  The presence of `Node*` as a parameter confirms this is part of V8's intermediate representation (IR).
    * `simplified()->...`, `common()->...`: These are accessing different IR instruction sets within V8. `simplified` likely represents a lowered form closer to machine instructions.
    * `JSGraphAssembler gasm`: This indicates the use of a helper class for building IR graphs in a more convenient way, especially for conditional logic.
    * `gasm.LoadField`, `gasm.StoreField`, `gasm.SelectIf`, `gasm.ReferenceEqual`: These are common operations when working with objects and memory in V8's internal representation.
    * Specific V8 object types: `Context`, `HeapNumber`, `FixedArray`, `JSFunction`, `Map`, `Module`, `Cell`.
    * Deoptimization reasons: `DeoptimizeReason::kWrongMap`, `DeoptimizeReason::kWrongValue`.
    * Builtins: `Builtin::kForInFilter`, `Builtin::kJSBuiltinsConstructStub`, `Builtin::kJSConstructStubGeneric`.
    * CodeFactory: `CodeFactory::CallFunction`, `CodeFactory::ConstructFunctionForwardVarargs`.
    * Constants: `jsgraph()->UndefinedConstant()`, `jsgraph()->ConstantNoHole(...)`.

3. **Function-by-Function Analysis:**  Go through each `ReduceJS...` function individually and try to understand its purpose:

    * **`ReduceJSLoadContext` and `ReduceJSStoreContext`:** These clearly deal with accessing and modifying variables in JavaScript scopes (contexts). The depth parameter and the loop involving `Context::PREVIOUS_INDEX` point to traversing the scope chain. The special handling of `HeapNumber` in `ReduceJSLoadContext` is interesting and likely related to performance optimizations for mutable numbers in contexts.

    * **`ReduceJSStoreScriptContext`:**  This is a specialized version of `ReduceJSStoreContext`, specifically for script-level contexts. The added complexity with `ContextSidePropertyCell` and handling of `kConst`, `kSmi`, and mutable heap numbers suggests finer-grained control over how script variables are stored and updated.

    * **`ReduceJSLoadModule` and `ReduceJSStoreModule`:**  These functions are related to ECMAScript modules. The `BuildGetModuleCell` helper function isolates the logic for finding the actual storage location of a module variable. The indexing into exports and imports is a key detail.

    * **`ReduceJSConstructForwardVarargs`, `ReduceJSConstruct`, `ReduceJSCallForwardVarargs`, `ReduceJSCall`:** These are all about optimizing function calls and constructor invocations. The checks for `JSFunction` constants, built-in functions, and the manipulation of call descriptors are central to this optimization. The "ForwardVarargs" versions hint at handling spread syntax or `apply`-like scenarios.

    * **`ReduceJSForInNext` and `ReduceJSForInPrepare`:** These functions handle the `for...in` loop construct. The use of enum caches, map checks, and the `ForInFilter` builtin suggest optimizations related to iterating over object properties.

4. **Identify Core Functionality:** Based on the function analysis, the primary function of `js-typed-lowering.cc` is **to perform type-aware lowering of JavaScript-specific operations in V8's intermediate representation.** This means transforming high-level JavaScript concepts (like context access, function calls, module access, and `for...in` loops) into more primitive operations, potentially taking advantage of type information to generate more efficient code.

5. **Address Specific Constraints:**

    * **Torque:** The code uses C++ and V8's internal APIs, not Torque. So, the answer is that it's not a Torque file.
    * **JavaScript Examples:**  For each key area (context, modules, calls, `for...in`), create simple JavaScript code snippets that would trigger the corresponding lowering logic. This helps illustrate the connection between the C++ code and the JavaScript language.
    * **Logic Inference (Input/Output):** For more complex functions like context loading/storing and module access, define hypothetical inputs (e.g., a specific context chain, module structure) and describe the expected output (the lowered IR operations).
    * **Common Programming Errors:** Think about typical mistakes developers make related to the JavaScript features being optimized (e.g., accessing undeclared variables, calling non-constructor functions, incorrect `for...in` usage).
    * **Summary:**  Condense the core functionality into a concise summary statement.

6. **Review and Refine:** Read through the analysis, ensuring clarity, accuracy, and completeness. Check if all parts of the prompt have been addressed. For example, ensure the explanations of deoptimization reasons, builtins, and code factory usage are clear.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe this file just handles type checking. **Correction:**  While types are important, the "lowering" aspect suggests more than just validation; it's about code transformation.
* **Realization:** The `ReduceJS...` naming convention is significant. It's likely part of a larger optimization pipeline where each `Reduce` function handles a specific JavaScript construct.
* **Aha moment:** The `JSGraphAssembler` is used for building conditional IR more easily, reflecting how type information allows for conditional code generation.
* **Focus shift:** Initially, I might have focused too much on the low-level IR details. It's important to connect those details back to the higher-level JavaScript concepts they represent.

By following this structured approach, breaking down the code into manageable parts, and continuously refining the understanding, it's possible to effectively analyze and explain the functionality of a complex piece of compiler code like the provided V8 snippet.
好的，这是对 `v8/src/compiler/js-typed-lowering.cc` 代码的功能分析：

**功能归纳:**

`v8/src/compiler/js-typed-lowering.cc` 文件是 V8 JavaScript 引擎编译器管道中的一个关键组件，其主要功能是**将类型化的 JavaScript 代码的抽象语法树（AST）节点降低（Lowering）到更接近机器码的、更底层的中间表示（IR）。**  这个过程是类型感知的，也就是说，它会利用类型信息来执行更优化的转换。

**具体功能分解:**

该文件中的代码主要定义了一个名为 `JSTypedLowering` 的类，它继承自 `OptimizationPhase`。这个类包含了一系列的 `ReduceJS...` 方法，每个方法负责处理特定类型的 JavaScript 节点，并将其转换为更底层的操作。

以下是对代码片段中涉及到的主要 `ReduceJS...` 方法的功能解释：

* **`ReduceJSLoadContext(Node* node)`:**
    * **功能:**  降低对上下文中变量的加载操作。
    * **原理:**  根据上下文访问的深度，生成一系列加载上下文槽位的操作，最终获取变量的值。
    * **特殊处理:**  如果上下文槽位中存储的是可变的堆数字（Mutable Heap Number），并且当前存储的是一个 SMI（小整数），则会分配一个新的堆数字来存储该值，确保其可变性。
    * **JavaScript 示例:**
      ```javascript
      function outer() {
        let x = 10;
        function inner() {
          return x; // 这里会触发 ReduceJSLoadContext
        }
        return inner();
      }
      ```
    * **假设输入与输出:**
        * **假设输入:** 一个表示加载 `x` 的 `JSLoadContext` 节点，以及 `x` 所在的上下文。
        * **假设输出:** 一系列 `LoadField` 节点，用于遍历上下文链并加载 `x` 的值。如果 `x` 是可变堆数字且当前是 SMI，则会生成分配新堆数字的代码。

* **`ReduceJSStoreContext(Node* node)`:**
    * **功能:** 降低对上下文中变量的存储操作。
    * **原理:**  类似于 `ReduceJSLoadContext`，根据上下文访问的深度，生成一系列遍历上下文链的操作，最终将值存储到目标槽位。
    * **JavaScript 示例:**
      ```javascript
      function outer() {
        let x = 10;
        function inner(newValue) {
          x = newValue; // 这里会触发 ReduceJSStoreContext
        }
        inner(20);
        return x;
      }
      ```
    * **假设输入与输出:**
        * **假设输入:** 一个表示存储 `newValue` 到 `x` 的 `JSStoreContext` 节点，以及 `x` 所在的上下文和 `newValue` 的值。
        * **假设输出:** 一系列 `LoadField` 节点用于遍历上下文链，以及一个 `StoreField` 节点用于存储值。

* **`ReduceJSStoreScriptContext(Node* node)`:**
    * **功能:**  降低对脚本上下文中变量的存储操作，与 `ReduceJSStoreContext` 类似，但针对脚本上下文有更细致的处理。
    * **原理:** 除了基本的存储操作外，还会检查该槽位是否是常量、是否是可变的堆数字等，并根据情况进行不同的处理，例如，如果是常量则会触发去优化（Deoptimize）。
    * **JavaScript 示例:**
      ```javascript
      const y = 30;
      y = 40; // 这里会尝试触发 ReduceJSStoreScriptContext，但因为是常量会报错
      ```
    * **假设输入与输出:**
        * **假设输入:** 一个表示存储值的 `JSStoreScriptContext` 节点，以及目标脚本上下文和要存储的值。
        * **假设输出:**  包含条件判断的 IR 图，用于检查是否为常量、是否为可变堆数字等，并最终生成存储操作或去优化操作。

* **`ReduceJSLoadModule(Node* node)`:**
    * **功能:** 降低对 ES 模块中变量的加载操作。
    * **原理:** 通过 `BuildGetModuleCell` 函数获取模块变量的存储位置（Cell），然后加载 Cell 中的值。
    * **JavaScript 示例:**
      ```javascript
      // module.js
      export let count = 0;

      // main.js
      import { count } from './module.js';
      console.log(count); // 这里会触发 ReduceJSLoadModule
      ```
    * **假设输入与输出:**
        * **假设输入:** 一个表示加载模块变量的 `JSLoadModule` 节点，以及对应的模块对象。
        * **假设输出:**  `LoadField` 节点用于加载模块的 exports/imports 数组，再加载指定索引的 Cell，最后加载 Cell 的值。

* **`ReduceJSStoreModule(Node* node)`:**
    * **功能:** 降低对 ES 模块中变量的存储操作。
    * **原理:**  类似于 `ReduceJSLoadModule`，先通过 `BuildGetModuleCell` 找到 Cell，然后将新值存储到 Cell 中。
    * **JavaScript 示例:**
      ```javascript
      // module.js
      export let count = 0;

      // main.js
      import { count } from './module.js';
      count++; // 这里会触发 ReduceJSStoreModule
      ```
    * **假设输入与输出:**
        * **假设输入:** 一个表示存储模块变量的 `JSStoreModule` 节点，对应的模块对象和要存储的值。
        * **假设输出:**  `LoadField` 节点用于加载模块的 exports 数组，再加载指定索引的 Cell，最后使用 `StoreField` 节点存储新值。

* **`ReduceJSConstructForwardVarargs(Node* node)` 和 `ReduceJSConstruct(Node* node)`:**
    * **功能:** 降低构造函数调用操作 (`new` 关键字)。
    * **原理:**  会尝试优化构造函数调用，例如，如果目标是一个已知的 JSFunction，并且是构造函数，则会直接调用其构造存根（Construct Stub）。对于可变参数的情况，会使用 `ConstructFunctionForwardVarargs`。
    * **JavaScript 示例:**
      ```javascript
      class MyClass {}
      const instance = new MyClass(); // 这里会触发 ReduceJSConstruct
      ```
    * **假设输入与输出:**
        * **假设输入:** 一个 `JSConstruct` 节点，包含目标构造函数和参数。
        * **假设输出:** 如果可以优化，则会转换为对构造存根的 `Call` 节点。

* **`ReduceJSCallForwardVarargs(Node* node)` 和 `ReduceJSCall(Node* node)`:**
    * **功能:** 降低普通函数调用操作。
    * **原理:**  会尝试优化函数调用，例如，如果目标是一个已知的 JSFunction，则会直接调用该函数。对于内置函数，会直接调用其 C++ 实现或者 JS 代码实现。对于需要处理 `this` 绑定的情况，会使用 `CallFunction` 内置函数。
    * **JavaScript 示例:**
      ```javascript
      function greet(name) {
        console.log(`Hello, ${name}!`);
      }
      greet("World"); // 这里会触发 ReduceJSCall
      ```
    * **假设输入与输出:**
        * **假设输入:** 一个 `JSCall` 节点，包含目标函数、接收者（this）和参数。
        * **假设输出:** 如果可以优化，则会转换为直接调用或者对特定内置函数的 `Call` 节点。

* **`ReduceJSForInNext(Node* node)` 和 `ReduceJSForInPrepare(Node* node)`:**
    * **功能:** 降低 `for...in` 循环的迭代过程。
    * **原理:**  `ReduceJSForInPrepare` 负责准备 `for...in` 循环所需的数据，例如枚举缓存。`ReduceJSForInNext` 负责获取循环的下一个属性名，并进行类型检查和过滤。
    * **JavaScript 示例:**
      ```javascript
      const obj = { a: 1, b: 2 };
      for (let key in obj) { // 这里会触发 ReduceJSForInPrepare 和 ReduceJSForInNext
        console.log(key);
      }
      ```
    * **假设输入与输出:**
        * **`ReduceJSForInPrepare` 输入:**  一个 `JSForInPrepare` 节点，包含要迭代的对象。
        * **`ReduceJSForInPrepare` 输出:**  加载枚举缓存、对象 Map 等信息的 IR 节点。
        * **`ReduceJSForInNext` 输入:** 一个 `JSForInNext` 节点，包含接收者、缓存数组、当前索引等。
        * **`ReduceJSForInNext` 输出:** 加载下一个属性名的 IR 节点，可能包含类型检查和过滤。

**关于代码格式和推断:**

* 提供的代码片段确实是 C++ 源代码，因为它包含了 C++ 的语法结构，例如类定义 (`class JSTypedLowering`)、方法定义、模板 (`TNode<Object>`)、以及 V8 内部的 API 调用 (`gasm.LoadField`, `simplified()->LoadField`).
* 如果文件以 `.tq` 结尾，那它才是 V8 Torque 源代码。Torque 是一种 V8 内部使用的领域特定语言，用于生成高效的 C++ 代码。

**用户常见的编程错误示例:**

* **在 `const` 声明的变量赋值:**  `ReduceJSStoreScriptContext` 中会检查常量赋值并触发去优化。
  ```javascript
  const MAX_VALUE = 100;
  MAX_VALUE = 200; // TypeError: Assignment to constant variable.
  ```
* **调用非构造函数的对象作为构造函数:** `ReduceJSConstruct` 中会检查目标是否是构造函数。
  ```javascript
  function notAConstructor() { return {}; }
  const obj = new notAConstructor(); // TypeError: notAConstructor is not a constructor
  ```
* **不恰当的 `for...in` 循环使用:**  迭代非对象或 `null`/`undefined` 可能会导致错误，或者迭代顺序不确定。V8 的 `ReduceJSForIn` 系列方法会尝试优化常见的 `for...in` 用法，但如果模式复杂或对象结构特殊，可能无法进行有效优化。
  ```javascript
  const num = 10;
  for (let key in num) { // 不会执行，因为原始类型没有可枚举属性
    console.log(key);
  }
  ```

**总结 `v8/src/compiler/js-typed-lowering.cc` 的功能:**

总而言之，`v8/src/compiler/js-typed-lowering.cc` 是 V8 编译器中负责**类型化降低**的关键阶段。它将高级的、类型化的 JavaScript 操作转换为更底层的、更接近机器指令的操作序列。这个过程利用类型信息进行优化，例如，直接调用已知函数的存根，避免不必要的类型转换和检查。通过降低各种 JavaScript 结构（如变量访问、函数调用、模块加载和 `for...in` 循环），它为后续的优化和代码生成阶段奠定了基础，最终生成高效的机器码。

这是第三部分，总共四部分。 从这个部分来看，主要关注的是 **将各种 JavaScript 语言结构降低到更底层的 IR 表示，并针对特定情况进行优化**。它处理了变量的加载和存储（包括上下文和模块），函数调用和构造，以及 `for...in` 循环等关键的语言特性。

Prompt: 
```
这是目录为v8/src/compiler/js-typed-lowering.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-typed-lowering.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
text);
  }

  TNode<Object> value = gasm.LoadField<Object>(
      AccessBuilder::ForContextSlot(access.index()), context);
  TNode<Object> result =
      gasm.SelectIf<Object>(gasm.ObjectIsSmi(value))
          .Then([&] { return value; })
          .Else([&] {
            TNode<Map> value_map =
                gasm.LoadMap(TNode<HeapObject>::UncheckedCast(value));
            return gasm.SelectIf<Object>(gasm.IsHeapNumberMap(value_map))
                .Then([&] {
                  size_t side_data_index =
                      access.index() - Context::MIN_CONTEXT_EXTENDED_SLOTS;
                  TNode<FixedArray> side_data = gasm.LoadField<FixedArray>(
                      AccessBuilder::ForContextSlot(
                          Context::CONTEXT_SIDE_TABLE_PROPERTY_INDEX),
                      context);
                  TNode<Object> data = gasm.LoadField<Object>(
                      AccessBuilder::ForFixedArraySlot(side_data_index),
                      side_data);
                  TNode<Object> property =
                      gasm.SelectIf<Object>(gasm.ObjectIsSmi(data))
                          .Then([&] { return data; })
                          .Else([&] {
                            return gasm.LoadField<Object>(
                                AccessBuilder::ForContextSideProperty(),
                                TNode<HeapObject>::UncheckedCast(data));
                          })
                          .Value();
                  return gasm
                      .SelectIf<Object>(gasm.ReferenceEqual(
                          property,
                          TNode<Object>::UncheckedCast(gasm.SmiConstant(
                              ContextSidePropertyCell::kMutableHeapNumber))))
                      .Then([&] {
                        Node* number = gasm.LoadHeapNumberValue(value);
                        // Allocate a new HeapNumber.
                        AllocationBuilder a(jsgraph(), broker(), gasm.effect(),
                                            gasm.control());
                        a.Allocate(sizeof(HeapNumber), AllocationType::kYoung,
                                   Type::OtherInternal());
                        a.Store(AccessBuilder::ForMap(),
                                broker()->heap_number_map());
                        a.Store(AccessBuilder::ForHeapNumberValue(), number);
                        Node* new_heap_number = a.Finish();
                        gasm.UpdateEffectControlWith(new_heap_number);
                        return TNode<Object>::UncheckedCast(new_heap_number);
                      })
                      .Else([&] { return value; })
                      .Value();
                })
                .Else([&] { return value; })
                .ExpectFalse()
                .Value();
          })
          .Value();

  ReplaceWithValue(node, result, gasm.effect(), gasm.control());
  return Changed(node);
}

Reduction JSTypedLowering::ReduceJSStoreContext(Node* node) {
  DCHECK_EQ(IrOpcode::kJSStoreContext, node->opcode());
  ContextAccess const& access = ContextAccessOf(node->op());
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* context = NodeProperties::GetContextInput(node);
  Node* control = graph()->start();
  Node* value = NodeProperties::GetValueInput(node, 0);
  for (size_t i = 0; i < access.depth(); ++i) {
    context = effect = graph()->NewNode(
        simplified()->LoadField(
            AccessBuilder::ForContextSlotKnownPointer(Context::PREVIOUS_INDEX)),
        context, effect, control);
  }
  node->ReplaceInput(0, context);
  node->ReplaceInput(1, value);
  node->ReplaceInput(2, effect);
  NodeProperties::ChangeOp(
      node,
      simplified()->StoreField(AccessBuilder::ForContextSlot(access.index())));
  return Changed(node);
}

Reduction JSTypedLowering::ReduceJSStoreScriptContext(Node* node) {
  DCHECK_EQ(IrOpcode::kJSStoreScriptContext, node->opcode());
  ContextAccess const& access = ContextAccessOf(node->op());
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  JSGraphAssembler gasm(broker(), jsgraph(), jsgraph()->zone(),
                        BranchSemantics::kJS);
  gasm.InitializeEffectControl(effect, control);

  TNode<Context> context =
      TNode<Context>::UncheckedCast(NodeProperties::GetContextInput(node));
  for (size_t i = 0; i < access.depth(); ++i) {
    context = gasm.LoadField<Context>(
        AccessBuilder::ForContextSlotKnownPointer(Context::PREVIOUS_INDEX),
        context);
  }

  TNode<Object> old_value = gasm.LoadField<Object>(
      AccessBuilder::ForContextSlot(access.index()), context);
  TNode<Object> new_value =
      TNode<Object>::UncheckedCast(NodeProperties::GetValueInput(node, 0));

  gasm.IfNot(gasm.ReferenceEqual(old_value, new_value)).Then([&] {
    size_t side_data_index =
        access.index() - Context::MIN_CONTEXT_EXTENDED_SLOTS;
    TNode<FixedArray> side_data = gasm.LoadField<FixedArray>(
        AccessBuilder::ForContextSlot(
            Context::CONTEXT_SIDE_TABLE_PROPERTY_INDEX),
        context);
    TNode<Object> data = gasm.LoadField<Object>(
        AccessBuilder::ForFixedArraySlot(side_data_index), side_data);

    TNode<Boolean> is_other = gasm.ReferenceEqual(
        data, TNode<Object>::UncheckedCast(
                  gasm.SmiConstant(ContextSidePropertyCell::kOther)));
    gasm.If(is_other)
        .Then([&] {
          gasm.StoreField(AccessBuilder::ForContextSlot(access.index()),
                          context, new_value);
        })
        .Else([&] {
          gasm.CheckIf(gasm.BooleanNot(gasm.IsUndefined(data)),
                       DeoptimizeReason::kWrongValue);
          TNode<Object> property =
              gasm.SelectIf<Object>(gasm.ObjectIsSmi(data))
                  .Then([&] { return data; })
                  .Else([&] {
                    return gasm.LoadField<Object>(
                        AccessBuilder::ForContextSideProperty(),
                        TNode<HeapObject>::UncheckedCast(data));
                  })
                  .Value();
          TNode<Boolean> is_const = gasm.ReferenceEqual(
              property, TNode<Object>::UncheckedCast(
                            gasm.SmiConstant(ContextSidePropertyCell::kConst)));
          gasm.CheckIf(gasm.BooleanNot(is_const),
                       DeoptimizeReason::kWrongValue);
          if (v8_flags.script_context_mutable_heap_number) {
            TNode<Boolean> is_smi_marker = gasm.ReferenceEqual(
                property, TNode<Object>::UncheckedCast(
                              gasm.SmiConstant(ContextSidePropertyCell::kSmi)));
            gasm.If(is_smi_marker)
                .Then([&] {
                  Node* smi_value = gasm.CheckSmi(new_value);
                  gasm.StoreField(
                      AccessBuilder::ForContextSlotSmi(access.index()), context,
                      smi_value);
                })
                .Else([&] {
                  // It must be a mutable heap number in this case.
                  Node* number_value = gasm.CheckNumber(new_value);
                  gasm.StoreField(AccessBuilder::ForHeapNumberValue(),
                                  old_value, number_value);
                });
          } else {
            gasm.StoreField(AccessBuilder::ForContextSlot(access.index()),
                            context, new_value);
          }
        })
        .ExpectTrue();
  });
  ReplaceWithValue(node, gasm.effect(), gasm.effect(), gasm.control());
  return Changed(node);
}

Node* JSTypedLowering::BuildGetModuleCell(Node* node) {
  DCHECK(node->opcode() == IrOpcode::kJSLoadModule ||
         node->opcode() == IrOpcode::kJSStoreModule);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  int32_t cell_index = OpParameter<int32_t>(node->op());
  Node* module = NodeProperties::GetValueInput(node, 0);
  Type module_type = NodeProperties::GetType(module);

  if (module_type.IsHeapConstant()) {
    SourceTextModuleRef module_constant =
        module_type.AsHeapConstant()->Ref().AsSourceTextModule();
    OptionalCellRef cell_constant =
        module_constant.GetCell(broker(), cell_index);
    if (cell_constant.has_value())
      return jsgraph()->ConstantNoHole(*cell_constant, broker());
  }

  FieldAccess field_access;
  int index;
  if (SourceTextModuleDescriptor::GetCellIndexKind(cell_index) ==
      SourceTextModuleDescriptor::kExport) {
    field_access = AccessBuilder::ForModuleRegularExports();
    index = cell_index - 1;
  } else {
    DCHECK_EQ(SourceTextModuleDescriptor::GetCellIndexKind(cell_index),
              SourceTextModuleDescriptor::kImport);
    field_access = AccessBuilder::ForModuleRegularImports();
    index = -cell_index - 1;
  }
  Node* array = effect = graph()->NewNode(simplified()->LoadField(field_access),
                                          module, effect, control);
  return graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForFixedArraySlot(index)), array,
      effect, control);
}

Reduction JSTypedLowering::ReduceJSLoadModule(Node* node) {
  DCHECK_EQ(IrOpcode::kJSLoadModule, node->opcode());
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  Node* cell = BuildGetModuleCell(node);
  if (cell->op()->EffectOutputCount() > 0) effect = cell;
  Node* value = effect =
      graph()->NewNode(simplified()->LoadField(AccessBuilder::ForCellValue()),
                       cell, effect, control);

  ReplaceWithValue(node, value, effect, control);
  return Changed(value);
}

Reduction JSTypedLowering::ReduceJSStoreModule(Node* node) {
  DCHECK_EQ(IrOpcode::kJSStoreModule, node->opcode());
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  Node* value = NodeProperties::GetValueInput(node, 1);
  DCHECK_EQ(SourceTextModuleDescriptor::GetCellIndexKind(
                OpParameter<int32_t>(node->op())),
            SourceTextModuleDescriptor::kExport);

  Node* cell = BuildGetModuleCell(node);
  if (cell->op()->EffectOutputCount() > 0) effect = cell;
  effect =
      graph()->NewNode(simplified()->StoreField(AccessBuilder::ForCellValue()),
                       cell, value, effect, control);

  ReplaceWithValue(node, effect, effect, control);
  return Changed(value);
}

namespace {

void ReduceBuiltin(JSGraph* jsgraph, Node* node, Builtin builtin, int arity,
                   CallDescriptor::Flags flags) {
  // Patch {node} to a direct CEntry call.
  // ----------- A r g u m e n t s -----------
  // -- 0: CEntry
  // --- Stack args ---
  // -- 1: new_target
  // -- 2: target
  // -- 3: argc, including the receiver and implicit args (Smi)
  // -- 4: padding
  // -- 5: receiver
  // -- [6, 6 + n[: the n actual arguments passed to the builtin
  // --- Register args ---
  // -- 6 + n: the C entry point
  // -- 6 + n + 1: argc (Int32)
  // -----------------------------------

  // The logic contained here is mirrored in Builtins::Generate_Adaptor.
  // Keep these in sync.

  Node* target = node->InputAt(JSCallOrConstructNode::TargetIndex());

  // Unify representations between construct and call nodes. For construct
  // nodes, the receiver is undefined. For call nodes, the new_target is
  // undefined.
  Node* new_target;
  Zone* zone = jsgraph->zone();
  if (node->opcode() == IrOpcode::kJSConstruct) {
    static_assert(JSCallNode::ReceiverIndex() ==
                  JSConstructNode::NewTargetIndex());
    new_target = JSConstructNode{node}.new_target();
    node->ReplaceInput(JSConstructNode::NewTargetIndex(),
                       jsgraph->UndefinedConstant());
    node->RemoveInput(JSConstructNode{node}.FeedbackVectorIndex());
  } else {
    new_target = jsgraph->UndefinedConstant();
    node->RemoveInput(JSCallNode{node}.FeedbackVectorIndex());
  }

  // CPP builtins are implemented in C++, and we can inline it.
  // CPP builtins create a builtin exit frame.
  DCHECK(Builtins::IsCpp(builtin));
  const bool has_builtin_exit_frame = true;

  Node* stub =
      jsgraph->CEntryStubConstant(1, ArgvMode::kStack, has_builtin_exit_frame);
  node->ReplaceInput(0, stub);

  const int argc = arity + BuiltinArguments::kNumExtraArgsWithReceiver;
  Node* argc_node = jsgraph->ConstantNoHole(argc);

  static const int kStub = 1;
  static_assert(BuiltinArguments::kNewTargetIndex == 0);
  static_assert(BuiltinArguments::kTargetIndex == 1);
  static_assert(BuiltinArguments::kArgcIndex == 2);
  static_assert(BuiltinArguments::kPaddingIndex == 3);
  node->InsertInput(zone, 1, new_target);
  node->InsertInput(zone, 2, target);
  node->InsertInput(zone, 3, argc_node);
  node->InsertInput(zone, 4, jsgraph->PaddingConstant());
  int cursor = arity + kStub + BuiltinArguments::kNumExtraArgsWithReceiver;

  Address entry = Builtins::CppEntryOf(builtin);
  ExternalReference entry_ref = ExternalReference::Create(entry);
  Node* entry_node = jsgraph->ExternalConstant(entry_ref);

  node->InsertInput(zone, cursor++, entry_node);
  node->InsertInput(zone, cursor++, argc_node);

  static const int kReturnCount = 1;
  const char* debug_name = Builtins::name(builtin);
  Operator::Properties properties = node->op()->properties();
  auto call_descriptor = Linkage::GetCEntryStubCallDescriptor(
      zone, kReturnCount, argc, debug_name, properties, flags,
      StackArgumentOrder::kJS);

  NodeProperties::ChangeOp(node, jsgraph->common()->Call(call_descriptor));
}
}  // namespace

Reduction JSTypedLowering::ReduceJSConstructForwardVarargs(Node* node) {
  DCHECK_EQ(IrOpcode::kJSConstructForwardVarargs, node->opcode());
  ConstructForwardVarargsParameters p =
      ConstructForwardVarargsParametersOf(node->op());
  DCHECK_LE(2u, p.arity());
  int const arity = static_cast<int>(p.arity() - 2);
  int const start_index = static_cast<int>(p.start_index());
  Node* target = NodeProperties::GetValueInput(node, 0);
  Type target_type = NodeProperties::GetType(target);

  // Check if {target} is a JSFunction.
  if (target_type.IsHeapConstant() &&
      target_type.AsHeapConstant()->Ref().IsJSFunction()) {
    // Only optimize [[Construct]] here if {function} is a Constructor.
    JSFunctionRef function = target_type.AsHeapConstant()->Ref().AsJSFunction();
    if (!function.map(broker()).is_constructor()) return NoChange();
    // Patch {node} to an indirect call via ConstructFunctionForwardVarargs.
    Callable callable = CodeFactory::ConstructFunctionForwardVarargs(isolate());
    node->InsertInput(graph()->zone(), 0,
                      jsgraph()->HeapConstantNoHole(callable.code()));
    node->InsertInput(graph()->zone(), 3,
                      jsgraph()->ConstantNoHole(JSParameterCount(arity)));
    node->InsertInput(graph()->zone(), 4,
                      jsgraph()->ConstantNoHole(start_index));
    node->InsertInput(graph()->zone(), 5, jsgraph()->UndefinedConstant());
    NodeProperties::ChangeOp(
        node, common()->Call(Linkage::GetStubCallDescriptor(
                  graph()->zone(), callable.descriptor(), arity + 1,
                  CallDescriptor::kNeedsFrameState)));
    return Changed(node);
  }

  return NoChange();
}

Reduction JSTypedLowering::ReduceJSConstruct(Node* node) {
  JSConstructNode n(node);
  ConstructParameters const& p = n.Parameters();
  int const arity = p.arity_without_implicit_args();
  Node* target = n.target();
  Type target_type = NodeProperties::GetType(target);

  // Check if {target} is a known JSFunction.
  if (target_type.IsHeapConstant() &&
      target_type.AsHeapConstant()->Ref().IsJSFunction()) {
    JSFunctionRef function = target_type.AsHeapConstant()->Ref().AsJSFunction();

    // Only optimize [[Construct]] here if {function} is a Constructor.
    if (!function.map(broker()).is_constructor()) return NoChange();

    // Patch {node} to an indirect call via the {function}s construct stub.
    Callable callable = Builtins::CallableFor(
        isolate(), function.shared(broker()).construct_as_builtin()
                       ? Builtin::kJSBuiltinsConstructStub
                       : Builtin::kJSConstructStubGeneric);
    static_assert(JSConstructNode::TargetIndex() == 0);
    static_assert(JSConstructNode::NewTargetIndex() == 1);
    node->RemoveInput(n.FeedbackVectorIndex());
    node->InsertInput(graph()->zone(), 0,
                      jsgraph()->HeapConstantNoHole(callable.code()));
    node->InsertInput(graph()->zone(), 3,
                      jsgraph()->ConstantNoHole(JSParameterCount(arity)));
    node->InsertInput(graph()->zone(), 4, jsgraph()->UndefinedConstant());
    NodeProperties::ChangeOp(
        node, common()->Call(Linkage::GetStubCallDescriptor(
                  graph()->zone(), callable.descriptor(), 1 + arity,
                  CallDescriptor::kNeedsFrameState)));
    return Changed(node);
  }

  return NoChange();
}

Reduction JSTypedLowering::ReduceJSCallForwardVarargs(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCallForwardVarargs, node->opcode());
  CallForwardVarargsParameters p = CallForwardVarargsParametersOf(node->op());
  DCHECK_LE(2u, p.arity());
  int const arity = static_cast<int>(p.arity() - 2);
  int const start_index = static_cast<int>(p.start_index());
  Node* target = NodeProperties::GetValueInput(node, 0);
  Type target_type = NodeProperties::GetType(target);

  // Check if {target} is a directly callable JSFunction.
  if (target_type.Is(Type::CallableFunction())) {
    // Compute flags for the call.
    CallDescriptor::Flags flags = CallDescriptor::kNeedsFrameState;
    // Patch {node} to an indirect call via CallFunctionForwardVarargs.
    Callable callable = CodeFactory::CallFunctionForwardVarargs(isolate());
    node->InsertInput(graph()->zone(), 0,
                      jsgraph()->HeapConstantNoHole(callable.code()));
    node->InsertInput(graph()->zone(), 2,
                      jsgraph()->ConstantNoHole(JSParameterCount(arity)));
    node->InsertInput(graph()->zone(), 3,
                      jsgraph()->ConstantNoHole(start_index));
    NodeProperties::ChangeOp(
        node, common()->Call(Linkage::GetStubCallDescriptor(
                  graph()->zone(), callable.descriptor(), arity + 1, flags)));
    return Changed(node);
  }

  return NoChange();
}

Reduction JSTypedLowering::ReduceJSCall(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  int arity = p.arity_without_implicit_args();
  ConvertReceiverMode convert_mode = p.convert_mode();
  Node* target = n.target();
  Type target_type = NodeProperties::GetType(target);
  Node* receiver = n.receiver();
  Type receiver_type = NodeProperties::GetType(receiver);
  Effect effect = n.effect();
  Control control = n.control();

  // Try to infer receiver {convert_mode} from {receiver} type.
  if (receiver_type.Is(Type::NullOrUndefined())) {
    convert_mode = ConvertReceiverMode::kNullOrUndefined;
  } else if (!receiver_type.Maybe(Type::NullOrUndefined())) {
    convert_mode = ConvertReceiverMode::kNotNullOrUndefined;
  }

  // Check if we know the SharedFunctionInfo of {target}.
  OptionalJSFunctionRef function;
  OptionalSharedFunctionInfoRef shared;

  if (target_type.IsHeapConstant() &&
      target_type.AsHeapConstant()->Ref().IsJSFunction()) {
    function = target_type.AsHeapConstant()->Ref().AsJSFunction();
    shared = function->shared(broker());
  } else if (target->opcode() == IrOpcode::kJSCreateClosure) {
    CreateClosureParameters const& ccp =
        JSCreateClosureNode{target}.Parameters();
    shared = ccp.shared_info();
  } else if (target->opcode() == IrOpcode::kCheckClosure) {
    FeedbackCellRef cell = MakeRef(broker(), FeedbackCellOf(target->op()));
    shared = cell.shared_function_info(broker());
  }

  if (shared.has_value()) {
    // Do not inline the call if we need to check whether to break at entry.
    // If this state changes during background compilation, the compilation
    // job will be aborted from the main thread (see
    // Debug::PrepareFunctionForDebugExecution()).
    if (shared->HasBreakInfo(broker())) return NoChange();

    // Class constructors are callable, but [[Call]] will raise an exception.
    // See ES6 section 9.2.1 [[Call]] ( thisArgument, argumentsList ).
    // We need to check here in addition to JSCallReducer for Realms.
    // TODO(pthier): Consolidate all the class constructor checks.
    if (IsClassConstructor(shared->kind())) return NoChange();

    // Check if we need to convert the {receiver}, but bailout if it would
    // require data from a foreign native context.
    if (is_sloppy(shared->language_mode()) && !shared->native() &&
        !receiver_type.Is(Type::Receiver())) {
      if (!function.has_value() || !function->native_context(broker()).equals(
                                       broker()->target_native_context())) {
        return NoChange();
      }
      NativeContextRef native_context = function->native_context(broker());
      Node* global_proxy = jsgraph()->ConstantNoHole(
          native_context.global_proxy_object(broker()), broker());
      receiver = effect = graph()->NewNode(
          simplified()->ConvertReceiver(convert_mode), receiver,
          jsgraph()->ConstantNoHole(native_context, broker()), global_proxy,
          effect, control);
      NodeProperties::ReplaceValueInput(node, receiver, 1);
    }

    // Load the context from the {target}.
    Node* context = effect = graph()->NewNode(
        simplified()->LoadField(AccessBuilder::ForJSFunctionContext()), target,
        effect, control);
    NodeProperties::ReplaceContextInput(node, context);

    // Update the effect dependency for the {node}.
    NodeProperties::ReplaceEffectInput(node, effect);

    // Compute flags for the call.
    CallDescriptor::Flags flags = CallDescriptor::kNeedsFrameState;
    Node* new_target = jsgraph()->UndefinedConstant();

    int formal_count =
        shared->internal_formal_parameter_count_without_receiver();
    if (formal_count > arity) {
      node->RemoveInput(n.FeedbackVectorIndex());
      // Underapplication. Massage the arguments to match the expected number of
      // arguments.
      for (int i = arity; i < formal_count; i++) {
        node->InsertInput(graph()->zone(), arity + 2,
                          jsgraph()->UndefinedConstant());
      }

      // Patch {node} to a direct call.
      node->InsertInput(graph()->zone(), formal_count + 2, new_target);
      node->InsertInput(graph()->zone(), formal_count + 3,
                        jsgraph()->ConstantNoHole(JSParameterCount(arity)));
#ifdef V8_ENABLE_LEAPTIERING
      node->InsertInput(graph()->zone(), formal_count + 4,
                        jsgraph()->ConstantNoHole(kPlaceholderDispatchHandle));
#endif
      NodeProperties::ChangeOp(node,
                               common()->Call(Linkage::GetJSCallDescriptor(
                                   graph()->zone(), false, 1 + formal_count,
                                   flags | CallDescriptor::kCanUseRoots)));
    } else if (shared->HasBuiltinId() &&
               Builtins::IsCpp(shared->builtin_id())) {
      // Patch {node} to a direct CEntry call.
      ReduceBuiltin(jsgraph(), node, shared->builtin_id(), arity, flags);
    } else if (shared->HasBuiltinId()) {
      DCHECK(Builtins::HasJSLinkage(shared->builtin_id()));
      // Patch {node} to a direct code object call.
      Callable callable =
          Builtins::CallableFor(isolate(), shared->builtin_id());

      const CallInterfaceDescriptor& descriptor = callable.descriptor();
      auto call_descriptor = Linkage::GetStubCallDescriptor(
          graph()->zone(), descriptor, 1 + arity, flags);
      Node* stub_code = jsgraph()->HeapConstantNoHole(callable.code());
      node->RemoveInput(n.FeedbackVectorIndex());
      node->InsertInput(graph()->zone(), 0, stub_code);  // Code object.
      node->InsertInput(graph()->zone(), 2, new_target);
      node->InsertInput(graph()->zone(), 3,
                        jsgraph()->ConstantNoHole(JSParameterCount(arity)));
#ifdef V8_ENABLE_LEAPTIERING
      node->InsertInput(graph()->zone(), 4,
                        jsgraph()->ConstantNoHole(kPlaceholderDispatchHandle));
#endif
      NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
    } else {
      // Patch {node} to a direct call.
      node->RemoveInput(n.FeedbackVectorIndex());
      node->InsertInput(graph()->zone(), arity + 2, new_target);
      node->InsertInput(graph()->zone(), arity + 3,
                        jsgraph()->ConstantNoHole(JSParameterCount(arity)));
#ifdef V8_ENABLE_LEAPTIERING
      node->InsertInput(graph()->zone(), arity + 4,
                        jsgraph()->ConstantNoHole(kPlaceholderDispatchHandle));
#endif
      NodeProperties::ChangeOp(node,
                               common()->Call(Linkage::GetJSCallDescriptor(
                                   graph()->zone(), false, 1 + arity,
                                   flags | CallDescriptor::kCanUseRoots)));
    }
    return Changed(node);
  }

  // Check if {target} is a directly callable JSFunction.
  if (target_type.Is(Type::CallableFunction())) {
    // The node will change operators, remove the feedback vector.
    node->RemoveInput(n.FeedbackVectorIndex());
    // Compute flags for the call.
    CallDescriptor::Flags flags = CallDescriptor::kNeedsFrameState;
    // Patch {node} to an indirect call via the CallFunction builtin.
    Callable callable = CodeFactory::CallFunction(isolate(), convert_mode);
    node->InsertInput(graph()->zone(), 0,
                      jsgraph()->HeapConstantNoHole(callable.code()));
    node->InsertInput(graph()->zone(), 2,
                      jsgraph()->ConstantNoHole(JSParameterCount(arity)));
    NodeProperties::ChangeOp(
        node, common()->Call(Linkage::GetStubCallDescriptor(
                  graph()->zone(), callable.descriptor(), 1 + arity, flags)));
    return Changed(node);
  }

  // Maybe we did at least learn something about the {receiver}.
  if (p.convert_mode() != convert_mode) {
    NodeProperties::ChangeOp(
        node,
        javascript()->Call(p.arity(), p.frequency(), p.feedback(), convert_mode,
                           p.speculation_mode(), p.feedback_relation()));
    return Changed(node);
  }

  return NoChange();
}

Reduction JSTypedLowering::ReduceJSForInNext(Node* node) {
  JSForInNextNode n(node);
  Node* receiver = n.receiver();
  Node* cache_array = n.cache_array();
  Node* cache_type = n.cache_type();
  Node* index = n.index();
  Node* context = n.context();
  FrameState frame_state = n.frame_state();
  Effect effect = n.effect();
  Control control = n.control();

  // Load the map of the {receiver}.
  Node* receiver_map = effect =
      graph()->NewNode(simplified()->LoadField(AccessBuilder::ForMap()),
                       receiver, effect, control);

  switch (n.Parameters().mode()) {
    case ForInMode::kUseEnumCacheKeys:
    case ForInMode::kUseEnumCacheKeysAndIndices: {
      // Ensure that the expected map still matches that of the {receiver}.
      Node* check = graph()->NewNode(simplified()->ReferenceEqual(),
                                     receiver_map, cache_type);
      effect =
          graph()->NewNode(simplified()->CheckIf(DeoptimizeReason::kWrongMap),
                           check, effect, control);

      // Since the change to LoadElement() below is effectful, we connect
      // node to all effect uses.
      ReplaceWithValue(node, node, node, control);

      // Morph the {node} into a LoadElement.
      node->ReplaceInput(0, cache_array);
      node->ReplaceInput(1, index);
      node->ReplaceInput(2, effect);
      node->ReplaceInput(3, control);
      node->TrimInputCount(4);
      ElementAccess access =
          AccessBuilder::ForJSForInCacheArrayElement(n.Parameters().mode());
      NodeProperties::ChangeOp(node, simplified()->LoadElement(access));
      NodeProperties::SetType(node, access.type);
      break;
    }
    case ForInMode::kGeneric: {
      // Load the next {key} from the {cache_array}.
      Node* key = effect = graph()->NewNode(
          simplified()->LoadElement(AccessBuilder::ForJSForInCacheArrayElement(
              n.Parameters().mode())),
          cache_array, index, effect, control);

      // Check if the expected map still matches that of the {receiver}.
      Node* check = graph()->NewNode(simplified()->ReferenceEqual(),
                                     receiver_map, cache_type);
      Node* branch =
          graph()->NewNode(common()->Branch(BranchHint::kTrue), check, control);

      Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
      Node* etrue;
      Node* vtrue;
      {
        // Don't need filtering since expected map still matches that of the
        // {receiver}.
        etrue = effect;
        vtrue = key;
      }

      Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
      Node* efalse;
      Node* vfalse;
      {
        // Filter the {key} to check if it's still a valid property of the
        // {receiver} (does the ToName conversion implicitly).
        Callable const callable =
            Builtins::CallableFor(isolate(), Builtin::kForInFilter);
        auto call_descriptor = Linkage::GetStubCallDescriptor(
            graph()->zone(), callable.descriptor(),
            callable.descriptor().GetStackParameterCount(),
            CallDescriptor::kNeedsFrameState);
        vfalse = efalse = if_false = graph()->NewNode(
            common()->Call(call_descriptor),
            jsgraph()->HeapConstantNoHole(callable.code()), key, receiver,
            context, frame_state, effect, if_false);
        NodeProperties::SetType(
            vfalse,
            Type::Union(Type::String(), Type::Undefined(), graph()->zone()));

        // Update potential {IfException} uses of {node} to point to the above
        // ForInFilter stub call node instead.
        Node* if_exception = nullptr;
        if (NodeProperties::IsExceptionalCall(node, &if_exception)) {
          if_false = graph()->NewNode(common()->IfSuccess(), vfalse);
          NodeProperties::ReplaceControlInput(if_exception, vfalse);
          NodeProperties::ReplaceEffectInput(if_exception, efalse);
          Revisit(if_exception);
        }
      }

      control = graph()->NewNode(common()->Merge(2), if_true, if_false);
      effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
      ReplaceWithValue(node, node, effect, control);

      // Morph the {node} into a Phi.
      node->ReplaceInput(0, vtrue);
      node->ReplaceInput(1, vfalse);
      node->ReplaceInput(2, control);
      node->TrimInputCount(3);
      NodeProperties::ChangeOp(
          node, common()->Phi(MachineRepresentation::kTagged, 2));
    }
  }

  return Changed(node);
}

Reduction JSTypedLowering::ReduceJSForInPrepare(Node* node) {
  JSForInPrepareNode n(node);
  Node* enumerator = n.enumerator();
  Effect effect = n.effect();
  Control control = n.control();
  Node* cache_type = enumerator;
  Node* cache_array = nullptr;
  Node* cache_length = nullptr;

  switch (n.Parameters().mode()) {
    case ForInMode::kUseEnumCacheKeys:
    case ForInMode::kUseEnumCacheKeysAndIndices: {
      // Check that the {enumerator} is a Map.
      // The direct IsMap check requires reading of an instance type, so we
      // compare its map against fixed_array_map instead (by definition,
      // the {enumerator} is either the receiver's Map or a FixedArray).
      Node* check_for_fixed_array = effect =
          graph()->NewNode(simplified()->CompareMaps(
                               ZoneRefSet<Map>(broker()->fixed_array_map())),
                           enumerator, effect, control);
      Node* check_for_not_fixed_array =
          graph()->NewNode(simplified()->BooleanNot(), check_for_fixed_array);
      effect =
          graph()->NewNode(simplified()->CheckIf(DeoptimizeReason::kWrongMap),
                           check_for_not_fixed_array, effect, control);

      // Load the enum cache from the {enumerator} map.
      Node* descriptor_array = effect = graph()->NewNode(
          simplified()->LoadField(AccessBuilder::ForMapDescriptors()),
          enumerator, effect, control);
      Node* enum_cache = effect = graph()->NewNode(
          simplified()->LoadField(AccessBuilder::ForDescriptorArrayEnumCache()),
          descriptor_array, effect, control);
      cache_array = effect = graph()->NewNode(
          simplified()->LoadField(AccessBuilder::ForEnumCacheKeys()),
          enum_cache, effect, control);

      // Load the enum length of the {enumerator} map.
      Node* bit_field3 = effect = graph()->NewNode(
          simplified()->Lo
"""


```