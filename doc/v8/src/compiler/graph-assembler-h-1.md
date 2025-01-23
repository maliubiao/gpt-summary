Response:
Let's break down the thought process for analyzing this V8 C++ header file.

1. **Understand the Goal:** The request is to analyze the functionality of the provided C++ header file (`v8/src/compiler/graph-assembler.h`). Specifically, it asks for:
    * Functionality listing.
    * Identification as Torque if the filename ends in `.tq` (it doesn't).
    * Relationship to JavaScript with examples.
    * Code logic inference with examples.
    * Common programming errors related to it.
    * A summary of its functionality (since this is part 2).

2. **Initial Scan and Keywords:** Quickly scan the code for important keywords and patterns:
    * `template`: Indicates generic programming, likely used for type safety and flexibility.
    * `class GraphAssembler`, `class JSGraphAssembler`:  These are the core classes. The `JSGraphAssembler` inherits from `GraphAssembler`, suggesting a specialized version for JavaScript.
    * `TNode<>`, `Node*`: These are likely node types in the compiler's intermediate representation (IR) graph.
    * `Branch`, `Goto`, `IfTrue`, `IfFalse`, `Merge`:  Control flow constructs in the IR.
    * `Call`, `JSCallRuntime`: Mechanisms for calling functions/runtime functions.
    * `Load`, `Store`: Operations for accessing memory/object properties.
    * `Constant`:  Creating constant values.
    * `Check`: Assertions and type checks.
    * `CatchScope`:  Exception handling mechanism.
    * `IfBuilder`:  A helper class for building conditional logic.
    * `JSHeapBroker`, `JSGraph`:  V8-specific components, confirming this is V8 compiler code.

3. **Deconstruct Class by Class:**

    * **`GraphAssembler`:** This appears to be the base class, providing fundamental graph manipulation capabilities. Focus on the methods within this class in the provided snippet:
        * **Control Flow:** `Branch`, `JSBranch`, `BranchImpl`, `Goto`, `GotoIf`, `GotoIfNot`. These are clearly about managing the flow of execution in the generated code graph. The `BranchSemantics` suggests different branching behaviors (e.g., machine-level vs. JavaScript level).
        * **Labels:** The use of `GraphAssemblerLabel` indicates the ability to mark locations in the graph for branching and jumping.
        * **Function Calls:** `Call`. This is how functions (potentially built-in or user-defined) are invoked in the generated code.
        * **`MergeState`:**  This likely combines the state (variables, etc.) when control flow paths converge.

    * **`JSGraphAssembler`:** This class extends `GraphAssembler` with JavaScript-specific functionality. Notice the dependencies on `JSHeapBroker` and `JSGraph`.
        * **Constants:** Methods like `SmiConstant`, `HeapConstant`, `Constant`, `NumberConstant`, and the `SINGLETON_CONST_DECL` macros are for creating various JavaScript constant values.
        * **Memory Access:** `Allocate`, `LoadMap`, `LoadField`, `LoadElement`, `StoreField`, `StoreElement`. These are essential for interacting with JavaScript objects in memory.
        * **String Operations:** `StringLength`, `StringSubstring`, `StringCharCodeAt`, `StringFromSingleCharCode`.
        * **Comparison Operators:** `ReferenceEqual`, `NumberEqual`, `NumberLessThan`, etc.
        * **Type Checks and Conversions:** `ObjectIsCallable`, `ObjectIsSmi`, `PlainPrimitiveToNumber`, `ToBoolean`, `ConvertTaggedHoleToUndefined`.
        * **Array Operations:** `MaybeGrowFastElements`, `DoubleArrayMax`, `DoubleArrayMin`, `ArrayBufferViewByteLength`, `TypedArrayLength`, `CheckIfTypedArrayWasDetached`.
        * **Runtime Calls:** `JSCallRuntime1`, `JSCallRuntime2`. This is how the generated code interacts with the V8 runtime for operations not directly implementable as simple machine instructions.
        * **Exception Handling:** The `CatchScope` nested class and the `MayThrow` method are crucial for handling JavaScript exceptions.
        * **Conditional Logic Builders:** The `IfBuilder0` and `IfBuilder1` classes provide a more structured way to generate conditional code blocks.
        * **Machine Graph Integration:** `EnterMachineGraph`, `ExitMachineGraph` suggest a way to interface with a lower-level machine code generation phase.

4. **Relate to JavaScript:**  For each significant function or group of functions, think about the corresponding JavaScript operations. This is where the JavaScript examples come in.

    * **Control Flow:**  JavaScript `if`, `else`, `goto` (though not directly exposed), loops.
    * **Constants:** Literal values like `10`, `"hello"`, `true`, `null`.
    * **Memory Access:**  Accessing object properties (`object.property`), array elements (`array[index]`).
    * **String Operations:** `string.length`, `string.substring()`, `string.charCodeAt()`, `String.fromCharCode()`.
    * **Comparison Operators:** `===`, `==`, `<`, `>`, `<=`, `>=`.
    * **Type Checks and Conversions:** `typeof`, implicit type conversions (e.g., in comparisons), `Boolean()`, `Number()`.
    * **Array Operations:** Array creation, access, modification, methods like `push`, `pop`, etc.
    * **Runtime Calls:** Many built-in JavaScript functions rely on runtime calls (e.g., `Math.sin()`, `parseInt()`). Exception handling (`try...catch`).

5. **Infer Code Logic (with Examples):**  Choose a few key methods and illustrate their behavior with simple hypothetical inputs and outputs. Focus on control flow and the transformation of inputs. For example, the `Branch` function takes a condition and jumps to different labels.

6. **Identify Common Programming Errors:** Think about how developers might misuse the functionality provided by these classes. Consider:

    * **Incorrect Branching:**  Logic errors in conditions, forgetting to handle both `if_true` and `if_false` cases.
    * **Type Mismatches:** Passing the wrong type of `TNode` to a function.
    * **Uninitialized Labels:** Trying to jump to a label that hasn't been bound.
    * **Exception Handling:** Forgetting to wrap potentially throwing operations in `MayThrow`.
    * **Incorrect `IfBuilder` Usage:** Not providing both `Then` and `Else` blocks for `IfBuilder1`.

7. **Structure the Output:** Organize the findings logically, grouping related functionalities together. Use clear headings and bullet points. Provide concise explanations.

8. **Refine and Review:**  Read through the generated analysis, ensuring accuracy and clarity. Check that the JavaScript examples are relevant and easy to understand. Make sure the assumed inputs and outputs for the code logic examples are sensible.

**Self-Correction Example During the Process:**

* **Initial thought:**  "The `TNode<>` seems like just a simple pointer wrapper."
* **Correction:** "Wait, the template parameter suggests it's type-aware. It probably enforces type safety at the compiler level for the IR graph nodes. This prevents accidentally passing a string node where a number node is expected." This leads to a more accurate understanding of `TNode`'s role.

By following this detailed breakdown, and iteratively refining understanding, we can generate a comprehensive analysis like the example provided in the initial prompt.
这是对 V8 源代码文件 `v8/src/compiler/graph-assembler.h` 的第二部分分析，延续了前一部分对该文件功能的探讨。本部分主要关注 `GraphAssembler` 和 `JSGraphAssembler` 类中用于控制流、函数调用以及 JavaScript 特有操作的方法。

**功能归纳：**

本部分延续了 `GraphAssembler` 提供的构建控制流图的能力，并深入探讨了 `JSGraphAssembler` 针对 JavaScript 语言特性提供的更高级抽象。其主要功能可以归纳为：

1. **条件分支 (Conditional Branching):**
   - `BranchImpl`:  实现基于条件进行分支跳转的核心逻辑，可以区分机器级分支 (`kMachine`) 和 JavaScript 语义分支 (`kJS`)。
   - `JSBranch`:  专门用于 JavaScript 布尔条件的分支操作。
   - `Branch`:  用于机器级布尔条件的分支操作。

2. **无条件跳转 (Unconditional Jump):**
   - `Goto`:  实现无条件跳转到指定的标签。

3. **带条件的跳转 (Conditional Jump with Goto):**
   - `GotoIf`:  如果条件为真，则跳转到指定标签。
   - `GotoIfNot`: 如果条件为假，则跳转到指定标签。
   - 提供了基于标签是否延迟 (`IsDeferred`) 来自动设置 `BranchHint` 的重载。

4. **函数调用 (Function Calls):**
   - `Call`:  用于生成函数调用节点的通用方法，可以接受不同数量的参数。
   - 区分了接收 `CallDescriptor` 和 `Operator` 的重载，提供了灵活性。

5. **JavaScript 特有操作 (JavaScript Specific Operations in `JSGraphAssembler`):**
   - **常量 (Constants):**  提供了创建各种 JavaScript 常量的方法，例如 `SmiConstant` (小整数), `HeapConstant` (堆对象), `NumberConstant` (数字), 以及各种单例常量 (如 `UndefinedConstant`, `NullConstant` 等)。
   - **类型检查 (Type Checks):**  提供了检查对象类型的便捷方法，例如 `IsName` 系列方法 (如 `IsUndefined`, `IsNull`)。
   - **内存操作 (Memory Operations):**
     - `Allocate`:  分配内存。
     - `LoadMap`:  加载对象的 Map (用于获取对象类型信息)。
     - `LoadField`:  加载对象的字段。
     - `LoadElement`:  加载数组元素。
     - `StoreField`:  存储对象的字段。
     - `StoreElement`: 存储数组元素。
     - `TransitionAndStoreElement`:  在存储元素时进行类型转换。
   - **字符串操作 (String Operations):**
     - `StringLength`:  获取字符串长度。
     - `StringSubstring`:  获取子字符串。
     - `StringCharCodeAt`: 获取指定位置字符的 Unicode 编码。
     - `StringFromSingleCharCode`:  从单个 Unicode 编码创建字符串。
   - **数值操作 (Number Operations):**
     - `PlainPrimitiveToNumber`: 将原始类型转换为数字。
     - `NumberMin`, `NumberMax`:  获取最小值和最大值。
     - `NumberEqual`, `NumberLessThan`, `NumberLessThanOrEqual`:  数值比较。
     - `NumberAdd`, `NumberSubtract`, `NumberShiftRightLogical`, `NumberBitwiseAnd`, `NumberBitwiseOr`, `NumberDivide`:  数值运算。
     - `NumberFloor`:  向下取整。
     - `NumberIsFloat64Hole`: 检查是否为 Float64 的空洞值。
   - **对象操作 (Object Operations):**
     - `ReferenceEqual`:  检查对象引用是否相等。
     - `ObjectIsCallable`:  检查对象是否可调用。
     - `ObjectIsSmi`:  检查对象是否为小整数。
     - `ObjectIsUndetectable`: 检查对象是否不可检测。
     - `ToBoolean`:  将对象转换为布尔值。
     - `ConvertTaggedHoleToUndefined`: 将标记的空洞值转换为 undefined。
   - **数组操作 (Array Operations):**
     - `MaybeGrowFastElements`:  可能增长快速元素数组。
     - `DoubleArrayMax`, `DoubleArrayMin`: 获取双精度浮点数组的最大值和最小值。
     - `ArrayBufferViewByteLength`, `TypedArrayLength`:  获取 `ArrayBufferView` 和 `TypedArray` 的长度。
     - `CheckIfTypedArrayWasDetached`:  检查 `TypedArray` 是否已分离。
     - `LookupByteShiftForElementsKind`, `LookupByteSizeForElementsKind`:  查找元素类型的字节偏移和大小。
   - **运行时调用 (Runtime Calls):**
     - `JSCallRuntime1`, `JSCallRuntime2`:  调用 V8 运行时函数的便捷方法。
   - **其他 (Others):**
     - `BooleanNot`:  布尔取反。
     - `CheckSmi`, `CheckNumber`, `CheckIf`:  插入运行时检查。
     - `Assert`:  插入断言。
     - `ClearPendingMessage`: 清除待处理的消息。
     - `Chained`:  创建一个链式操作节点。
     - `EnterMachineGraph`, `ExitMachineGraph`:  进入和退出机器图（可能用于与 Turbofan 的低级优化集成）。

6. **异常处理 (Exception Handling):**
   - `CatchScope`:  用于管理异常处理作用域的嵌套类，跟踪可能的异常分支。
   - `MayThrow`:  标记可能抛出异常的操作，并处理控制流跳转到异常处理逻辑。

7. **条件语句构建器 (Conditional Statement Builders):**
   - `IfBuilder0`:  用于构建不返回值的 `if` 语句块。
   - `IfBuilder1`:  用于构建返回值的 `if` 表达式（类似于三元运算符）。
   - 提供了 `ExpectTrue` 和 `ExpectFalse` 来设置分支预测提示。

**如果 `v8/src/compiler/graph-assembler.h` 以 `.tq` 结尾：**

如果该文件以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**。Torque 是一种 V8 内部使用的领域特定语言 (DSL)，用于定义内置函数和运行时函数的实现。Torque 代码会被编译成 C++ 代码，然后参与 V8 的编译过程。

**与 JavaScript 功能的关系及示例：**

`JSGraphAssembler` 中的许多方法都直接对应于 JavaScript 的语言特性和操作。以下是一些示例：

- **条件分支：** JavaScript 的 `if...else` 语句对应于 `JSBranch` 和 `Goto` 等方法。
  ```javascript
  let x = 10;
  if (x > 5) {
    console.log("x is greater than 5");
  } else {
    console.log("x is not greater than 5");
  }
  ```
  在 `JSGraphAssembler` 中，这会涉及生成一个 `JSBranch` 节点，根据 `x > 5` 的结果跳转到不同的标签。

- **函数调用：** JavaScript 的函数调用 `myFunction(arg1, arg2)` 对应于 `Call` 方法。
  ```javascript
  function myFunction(a, b) {
    return a + b;
  }
  let result = myFunction(3, 4);
  ```
  `JSGraphAssembler` 会使用 `Call` 生成调用 `myFunction` 的节点，并将参数传递进去。

- **对象属性访问：** JavaScript 的对象属性访问 `object.property` 对应于 `LoadField` 方法。
  ```javascript
  const obj = { name: "Alice" };
  console.log(obj.name);
  ```
  `JSGraphAssembler` 会使用 `LoadField` 加载 `obj` 对象的 `name` 字段。

- **数组元素访问：** JavaScript 的数组元素访问 `array[index]` 对应于 `LoadElement` 方法。
  ```javascript
  const arr = [1, 2, 3];
  console.log(arr[1]);
  ```
  `JSGraphAssembler` 会使用 `LoadElement` 加载 `arr` 索引为 1 的元素。

- **数值运算：** JavaScript 的数值运算，如 `a + b`，对应于 `NumberAdd` 等方法。
  ```javascript
  let sum = 5 + 7;
  ```
  `JSGraphAssembler` 会使用 `NumberAdd` 生成加法运算的节点.

- **类型检查：** JavaScript 的 `typeof` 运算符对应于 `ObjectIsSmi` 等方法。
  ```javascript
  let value = 10;
  if (typeof value === 'number') {
    console.log("value is a number");
  }
  ```
  `JSGraphAssembler` 可能会使用 `ObjectIsSmi` 或更通用的类型检查方法来判断 `value` 的类型。

**代码逻辑推理（假设输入与输出）：**

**示例：`JSBranch`**

**假设输入：**
- `condition`: 一个表示 `x > 5` 的 `TNode<Boolean>`，其中 `x` 是一个变量。
- `if_true`: 指向 "x is greater than 5" 代码块的 `GraphAssemblerLabel`。
- `if_false`: 指向 "x is not greater than 5" 代码块的 `GraphAssemblerLabel`。
- `hint`: `BranchHint::kNone` (没有分支预测提示)。

**输出：**
- 生成一个 `Branch` 节点，该节点会根据 `condition` 的真假，将控制流分别导向 `if_true` 或 `if_false` 对应的代码块。

**示例：`NumberAdd`**

**假设输入：**
- `lhs`: 一个表示数值 5 的 `TNode<Number>`。
- `rhs`: 一个表示数值 7 的 `TNode<Number>`。

**输出：**
- 生成一个新的 `TNode<Number>`，它代表了 5 + 7 的结果 (数值 12)。这个节点在后续的图构建中可以被其他操作使用。

**涉及用户常见的编程错误：**

1. **类型错误：**  在 `JSGraphAssembler` 中，类型是很重要的。如果用户在生成代码时，例如，将一个字符串类型的 `TNode` 传递给一个期望数字类型 `TNode` 的操作，就会导致类型错误。

   ```c++
   // 错误示例：假设 name_node 是一个 TNode<String>
   TNode<Number> length = StringLength(name_node); // 错误：StringLength 期望 TNode<String>，但赋值给了 TNode<Number>
   ```

2. **控制流错误：**  不正确地使用 `Goto` 和标签可能导致无限循环或代码无法到达。例如，忘记为所有可能的分支提供目标标签。

   ```c++
   GraphAssemblerLabel<> loop_start;
   Bind(&loop_start);
   // ... 一些代码 ...
   Goto(&loop_start); // 永远跳转回 loop_start，形成无限循环
   ```

3. **未处理异常：**  如果 JavaScript 代码可能抛出异常，但在 `JSGraphAssembler` 中没有使用 `MayThrow` 或 `CatchScope` 来处理，那么异常可能会导致程序崩溃或行为异常。

   ```c++
   // 可能抛出异常的操作，但没有使用 MayThrow
   TNode<Object> result = Call(...);
   ```

4. **不正确的内存管理：** 虽然 `GraphAssembler` 主要处理图的构建，但在涉及到内存分配 (`Allocate`) 和对象字段/元素访问时，需要确保操作的正确性，避免访问越界或使用已释放的内存。

**总结：**

作为第二部分，这部分代码深入展现了 `GraphAssembler` 和 `JSGraphAssembler` 在 V8 编译器中构建控制流图和实现 JavaScript 语义的关键作用。`GraphAssembler` 提供了基础的图操作和控制流机制，而 `JSGraphAssembler` 则在其基础上，针对 JavaScript 语言的特性，提供了丰富的操作方法，涵盖了常量创建、类型检查、内存访问、数值运算、字符串操作、对象操作、数组操作以及与 V8 运行时环境的交互。`CatchScope` 和 `MayThrow` 的引入使得能够处理 JavaScript 中的异常情况。条件语句构建器 `IfBuilder0` 和 `IfBuilder1` 提供了更便捷的方式来生成条件代码。 掌握这些功能对于理解 V8 如何将 JavaScript 代码转换为可执行的机器码至关重要。

### 提示词
```
这是目录为v8/src/compiler/graph-assembler.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/graph-assembler.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
TNode<Word32T> condition, GraphAssemblerLabel<sizeof...(Vars)>* if_true,
    GraphAssemblerLabel<sizeof...(Vars)>* if_false, BranchHint hint,
    Vars... vars) {
  BranchImpl(BranchSemantics::kMachine, condition, if_true, if_false, hint,
             vars...);
}

template <typename... Vars>
void GraphAssembler::JSBranch(TNode<Boolean> condition,
                              GraphAssemblerLabel<sizeof...(Vars)>* if_true,
                              GraphAssemblerLabel<sizeof...(Vars)>* if_false,
                              BranchHint hint, Vars... vars) {
  BranchImpl(BranchSemantics::kJS, condition, if_true, if_false, hint, vars...);
}

template <typename... Vars>
void GraphAssembler::BranchImpl(BranchSemantics semantics, Node* condition,
                                GraphAssemblerLabel<sizeof...(Vars)>* if_true,
                                GraphAssemblerLabel<sizeof...(Vars)>* if_false,
                                BranchHint hint, Vars... vars) {
  DCHECK_NOT_NULL(control());

  Node* branch =
      graph()->NewNode(common()->Branch(hint, semantics), condition, control());

  control_ = graph()->NewNode(common()->IfTrue(), branch);
  MergeState(if_true, vars...);

  control_ = graph()->NewNode(common()->IfFalse(), branch);
  MergeState(if_false, vars...);

  control_ = nullptr;
  effect_ = nullptr;
}

template <typename... Vars>
void GraphAssembler::Goto(detail::GraphAssemblerLabelForVars<Vars...>* label,
                          Vars... vars) {
  DCHECK_NOT_NULL(control());
  DCHECK_NOT_NULL(effect());
  MergeState(label, vars...);

  control_ = nullptr;
  effect_ = nullptr;
}

template <typename... Vars>
void GraphAssembler::GotoIf(Node* condition,
                            detail::GraphAssemblerLabelForVars<Vars...>* label,
                            BranchHint hint, Vars... vars) {
  Node* branch = graph()->NewNode(
      common()->Branch(hint, default_branch_semantics_), condition, control());

  control_ = graph()->NewNode(common()->IfTrue(), branch);
  MergeState(label, vars...);

  control_ = AddNode(graph()->NewNode(common()->IfFalse(), branch));
}

template <typename... Vars>
void GraphAssembler::GotoIfNot(
    Node* condition, detail::GraphAssemblerLabelForVars<Vars...>* label,
    BranchHint hint, Vars... vars) {
  Node* branch = graph()->NewNode(
      common()->Branch(hint, default_branch_semantics_), condition, control());

  control_ = graph()->NewNode(common()->IfFalse(), branch);
  MergeState(label, vars...);

  control_ = AddNode(graph()->NewNode(common()->IfTrue(), branch));
}

template <typename... Vars>
void GraphAssembler::GotoIf(Node* condition,
                            detail::GraphAssemblerLabelForVars<Vars...>* label,
                            Vars... vars) {
  BranchHint hint =
      label->IsDeferred() ? BranchHint::kFalse : BranchHint::kNone;
  return GotoIf(condition, label, hint, vars...);
}

template <typename... Vars>
void GraphAssembler::GotoIfNot(
    Node* condition, detail::GraphAssemblerLabelForVars<Vars...>* label,
    Vars... vars) {
  BranchHint hint = label->IsDeferred() ? BranchHint::kTrue : BranchHint::kNone;
  return GotoIfNot(condition, label, hint, vars...);
}

template <typename... Args>
TNode<Object> GraphAssembler::Call(const CallDescriptor* call_descriptor,
                                   Node* first_arg, Args... args) {
  const Operator* op = common()->Call(call_descriptor);
  return Call(op, first_arg, args...);
}

template <typename... Args>
TNode<Object> GraphAssembler::Call(const Operator* op, Node* first_arg,
                                   Args... args) {
  Node* args_array[] = {first_arg, args..., effect(), control()};
  int size = static_cast<int>(1 + sizeof...(args)) + op->EffectInputCount() +
             op->ControlInputCount();
  return Call(op, size, args_array);
}

class V8_EXPORT_PRIVATE JSGraphAssembler : public GraphAssembler {
 public:
  // Constructs a JSGraphAssembler. If {schedule} is not null, the graph
  // assembler will maintain the schedule as it updates blocks.
  JSGraphAssembler(
      JSHeapBroker* broker, JSGraph* jsgraph, Zone* zone,
      BranchSemantics branch_semantics,
      std::optional<NodeChangedCallback> node_changed_callback = std::nullopt,
      bool mark_loop_exits = false)
      : GraphAssembler(jsgraph, zone, branch_semantics, node_changed_callback,
                       mark_loop_exits),
        broker_(broker),
        jsgraph_(jsgraph),
        outermost_catch_scope_(CatchScope::Outermost(zone)),
        catch_scope_(&outermost_catch_scope_) {
    outermost_catch_scope_.set_gasm(this);
  }

  Node* SmiConstant(int32_t value);
  TNode<HeapObject> HeapConstant(Handle<HeapObject> object);
  TNode<Object> Constant(ObjectRef ref);
  TNode<Number> NumberConstant(double value);
  Node* CEntryStubConstant(int result_size);

#define SINGLETON_CONST_DECL(Name, Type) TNode<Type> Name##Constant();
  JSGRAPH_SINGLETON_CONSTANT_LIST(SINGLETON_CONST_DECL)
#undef SINGLETON_CONST_DECL

#define SINGLETON_CONST_TEST_DECL(Name, ...) \
  TNode<Boolean> Is##Name(TNode<Object> value);
  JSGRAPH_SINGLETON_CONSTANT_LIST(SINGLETON_CONST_TEST_DECL)
#undef SINGLETON_CONST_TEST_DECL

  Node* Allocate(AllocationType allocation, Node* size);
  TNode<Map> LoadMap(TNode<HeapObject> object);
  Node* LoadField(FieldAccess const&, Node* object);
  template <typename T>
  TNode<T> LoadField(FieldAccess const& access, TNode<HeapObject> object) {
    // TODO(jgruber): Investigate issues on ptr compression bots and enable.
    // DCHECK(IsMachineRepresentationOf<T>(
    //     access.machine_type.representation()));
    return TNode<T>::UncheckedCast(LoadField(access, object));
  }
  TNode<Uint32T> LoadElementsKind(TNode<Map> map);
  Node* LoadElement(ElementAccess const&, Node* object, Node* index);
  template <typename T>
  TNode<T> LoadElement(ElementAccess const& access, TNode<HeapObject> object,
                       TNode<Number> index) {
    // TODO(jgruber): Investigate issues on ptr compression bots and enable.
    // DCHECK(IsMachineRepresentationOf<T>(
    //     access.machine_type.representation()));
    return TNode<T>::UncheckedCast(LoadElement(access, object, index));
  }
  Node* StoreField(FieldAccess const&, Node* object, Node* value);
  Node* StoreElement(ElementAccess const&, Node* object, Node* index,
                     Node* value);
  Node* ClearPendingMessage();

  void TransitionAndStoreElement(MapRef double_map, MapRef fast_map,
                                 TNode<HeapObject> object, TNode<Number> index,
                                 TNode<Object> value);
  TNode<Number> StringLength(TNode<String> string);
  TNode<Boolean> ReferenceEqual(TNode<Object> lhs, TNode<Object> rhs);
  TNode<Number> PlainPrimitiveToNumber(TNode<Object> value);
  TNode<Number> NumberMin(TNode<Number> lhs, TNode<Number> rhs);
  TNode<Number> NumberMax(TNode<Number> lhs, TNode<Number> rhs);
  TNode<Boolean> NumberEqual(TNode<Number> lhs, TNode<Number> rhs);
  TNode<Boolean> NumberLessThan(TNode<Number> lhs, TNode<Number> rhs);
  TNode<Boolean> NumberLessThanOrEqual(TNode<Number> lhs, TNode<Number> rhs);
  TNode<Number> NumberAdd(TNode<Number> lhs, TNode<Number> rhs);
  TNode<Number> NumberSubtract(TNode<Number> lhs, TNode<Number> rhs);
  TNode<Number> NumberShiftRightLogical(TNode<Number> lhs, TNode<Number> rhs);
  TNode<Number> NumberBitwiseAnd(TNode<Number> lhs, TNode<Number> rhs);
  TNode<Number> NumberBitwiseOr(TNode<Number> lhs, TNode<Number> rhs);
  TNode<Number> NumberDivide(TNode<Number> lhs, TNode<Number> rhs);
  TNode<Number> NumberFloor(TNode<Number> value);
  TNode<String> StringSubstring(TNode<String> string, TNode<Number> from,
                                TNode<Number> to);
  TNode<Boolean> ObjectIsCallable(TNode<Object> value);
  TNode<Boolean> ObjectIsSmi(TNode<Object> value);
  TNode<Boolean> ObjectIsUndetectable(TNode<Object> value);
  Node* BooleanNot(Node* cond);
  Node* CheckSmi(Node* value, const FeedbackSource& feedback = {});
  Node* CheckNumber(Node* value, const FeedbackSource& feedback = {});
  Node* CheckIf(Node* cond, DeoptimizeReason reason,
                const FeedbackSource& feedback = {});
  Node* Assert(Node* cond, const char* condition_string = "",
               const char* file = "", int line = -1);
  void Assert(TNode<Word32T> cond, const char* condition_string = "",
              const char* file = "", int line = -1);
  TNode<Boolean> NumberIsFloat64Hole(TNode<Number> value);
  TNode<Boolean> ToBoolean(TNode<Object> value);
  TNode<Object> ConvertTaggedHoleToUndefined(TNode<Object> value);
  TNode<FixedArrayBase> MaybeGrowFastElements(ElementsKind kind,
                                              const FeedbackSource& feedback,
                                              TNode<JSArray> array,
                                              TNode<FixedArrayBase> elements,
                                              TNode<Number> new_length,
                                              TNode<Number> old_length);
  Node* StringCharCodeAt(TNode<String> string, TNode<Number> position);
  TNode<String> StringFromSingleCharCode(TNode<Number> code);
  TNode<Object> DoubleArrayMax(TNode<JSArray> array);
  TNode<Object> DoubleArrayMin(TNode<JSArray> array);
  // Computes the byte length for a given {array_buffer_view}. If the set of
  // possible ElementsKinds is known statically pass as
  // {elements_kinds_candidates} to allow the assembler to generate more
  // efficient code. Pass an empty {elements_kinds_candidates} to generate code
  // that is generic enough to handle all ElementsKinds.
  TNode<Number> ArrayBufferViewByteLength(
      TNode<JSArrayBufferView> array_buffer_view, InstanceType instance_type,
      std::set<ElementsKind> elements_kinds_candidates, TNode<Context> context);
  // Computes the length for a given {typed_array}. If the set of possible
  // ElementsKinds is known statically pass as {elements_kinds_candidates} to
  // allow the assembler to generate more efficient code. Pass an empty
  // {elements_kinds_candidates} to generate code that is generic enough to
  // handle all ElementsKinds.
  TNode<Number> TypedArrayLength(
      TNode<JSTypedArray> typed_array,
      std::set<ElementsKind> elements_kinds_candidates, TNode<Context> context);
  // Performs the full detached check. This includes fixed-length RABs whos
  // underlying buffer has been shrunk OOB.
  void CheckIfTypedArrayWasDetached(
      TNode<JSTypedArray> typed_array,
      std::set<ElementsKind> elements_kinds_candidates,
      const FeedbackSource& feedback);
  TNode<Uint32T> LookupByteShiftForElementsKind(TNode<Uint32T> elements_kind);
  TNode<Uint32T> LookupByteSizeForElementsKind(TNode<Uint32T> elements_kind);

  TNode<Object> JSCallRuntime1(
      Runtime::FunctionId function_id, TNode<Object> arg0,
      TNode<Context> context, std::optional<FrameState> frame_state,
      Operator::Properties properties = Operator::kNoProperties);
  TNode<Object> JSCallRuntime2(Runtime::FunctionId function_id,
                               TNode<Object> arg0, TNode<Object> arg1,
                               TNode<Context> context, FrameState frame_state);
  Node* Chained(const Operator* op, Node* input);

  JSHeapBroker* broker() const { return broker_; }
  JSGraph* jsgraph() const { return jsgraph_; }
  Isolate* isolate() const { return jsgraph()->isolate(); }
  SimplifiedOperatorBuilder* simplified() override {
    return jsgraph()->simplified();
  }
  JSOperatorBuilder* javascript() const { return jsgraph()->javascript(); }

  template <typename T, typename U>
  TNode<T> EnterMachineGraph(TNode<U> input, UseInfo use_info) {
    DCHECK_EQ(use_info.type_check(), TypeCheckKind::kNone);
    return AddNode<T>(
        graph()->NewNode(common()->EnterMachineGraph(use_info), input));
  }

  template <typename T, typename U>
  TNode<T> ExitMachineGraph(TNode<U> input,
                            MachineRepresentation output_representation,
                            Type output_type) {
    return AddNode<T>(graph()->NewNode(
        common()->ExitMachineGraph(output_representation, output_type), input));
  }

  // A catch scope represents a single catch handler. The handler can be
  // custom catch logic within the reduction itself; or a catch handler in the
  // outside graph into which the reduction will be integrated (in this case
  // the scope is called 'outermost').
  class V8_NODISCARD CatchScope {
   private:
    // Only used to partially construct the outermost scope.
    explicit CatchScope(Zone* zone) : if_exception_nodes_(zone) {}

    // For all inner scopes.
    CatchScope(Zone* zone, JSGraphAssembler* gasm)
        : gasm_(gasm),
          parent_(gasm->catch_scope_),
          has_handler_(true),
          if_exception_nodes_(zone) {
      DCHECK_NOT_NULL(gasm_);
      gasm_->catch_scope_ = this;
    }

   public:
    ~CatchScope() { gasm_->catch_scope_ = parent_; }

    static CatchScope Outermost(Zone* zone) { return CatchScope{zone}; }
    static CatchScope Inner(Zone* zone, JSGraphAssembler* gasm) {
      return {zone, gasm};
    }

    bool has_handler() const { return has_handler_; }
    bool is_outermost() const { return parent_ == nullptr; }
    CatchScope* parent() const { return parent_; }

    // Should only be used to initialize the outermost scope (inner scopes
    // always have a handler and are passed the gasm pointer at construction).
    void set_has_handler(bool v) {
      DCHECK(is_outermost());
      has_handler_ = v;
    }
    void set_gasm(JSGraphAssembler* v) {
      DCHECK(is_outermost());
      DCHECK_NOT_NULL(v);
      gasm_ = v;
    }

    bool has_exceptional_control_flow() const {
      return !if_exception_nodes_.empty();
    }

    void RegisterIfExceptionNode(Node* if_exception) {
      DCHECK(has_handler());
      if_exception_nodes_.push_back(if_exception);
    }

    void MergeExceptionalPaths(TNode<Object>* exception_out, Effect* effect_out,
                               Control* control_out) {
      DCHECK(has_handler());
      DCHECK(has_exceptional_control_flow());

      const int size = static_cast<int>(if_exception_nodes_.size());

      if (size == 1) {
        // No merge needed.
        Node* e = if_exception_nodes_.at(0);
        *exception_out = TNode<Object>::UncheckedCast(e);
        *effect_out = Effect(e);
        *control_out = Control(e);
      } else {
        DCHECK_GT(size, 1);

        Node* merge = gasm_->graph()->NewNode(gasm_->common()->Merge(size),
                                              size, if_exception_nodes_.data());

        // These phis additionally take {merge} as an input. Temporarily add
        // it to the list.
        if_exception_nodes_.push_back(merge);
        const int size_with_merge =
            static_cast<int>(if_exception_nodes_.size());

        Node* ephi = gasm_->graph()->NewNode(gasm_->common()->EffectPhi(size),
                                             size_with_merge,
                                             if_exception_nodes_.data());
        Node* phi = gasm_->graph()->NewNode(
            gasm_->common()->Phi(MachineRepresentation::kTagged, size),
            size_with_merge, if_exception_nodes_.data());
        if_exception_nodes_.pop_back();

        *exception_out = TNode<Object>::UncheckedCast(phi);
        *effect_out = Effect(ephi);
        *control_out = Control(merge);
      }
    }

   private:
    JSGraphAssembler* gasm_ = nullptr;
    CatchScope* const parent_ = nullptr;
    bool has_handler_ = false;
    NodeVector if_exception_nodes_;
  };

  CatchScope* catch_scope() const { return catch_scope_; }
  Node* outermost_handler() const { return outermost_handler_; }

  using NodeGenerator0 = std::function<TNode<Object>()>;
  // TODO(jgruber): Currently, it's the responsibility of the developer to note
  // which operations may throw and appropriately wrap these in a call to
  // MayThrow (see e.g. JSCall3 and CallRuntime2). A more methodical approach
  // would be good.
  TNode<Object> MayThrow(const NodeGenerator0& body) {
    TNode<Object> result = body();

    if (catch_scope()->has_handler()) {
      // The IfException node is later merged into the outer graph.
      // Note: AddNode is intentionally not called since effect and control
      // should not be updated.
      Node* if_exception =
          graph()->NewNode(common()->IfException(), effect(), control());
      catch_scope()->RegisterIfExceptionNode(if_exception);

      // Control resumes here.
      AddNode(graph()->NewNode(common()->IfSuccess(), control()));
    }

    return result;
  }

  using VoidGenerator0 = std::function<void()>;
  // TODO(jgruber): Currently IfBuilder0 and IfBuilder1 are implemented as
  // separate classes. If, in the future, we encounter additional use cases that
  // return more than 1 value, we should merge these back into a single variadic
  // implementation.
  class IfBuilder0 final {
   public:
    IfBuilder0(JSGraphAssembler* gasm, TNode<Boolean> cond, bool negate_cond)
        : gasm_(gasm),
          cond_(cond),
          negate_cond_(negate_cond),
          initial_effect_(gasm->effect()),
          initial_control_(gasm->control()) {}

    IfBuilder0& ExpectTrue() {
      DCHECK_EQ(hint_, BranchHint::kNone);
      hint_ = BranchHint::kTrue;
      return *this;
    }
    IfBuilder0& ExpectFalse() {
      DCHECK_EQ(hint_, BranchHint::kNone);
      hint_ = BranchHint::kFalse;
      return *this;
    }

    IfBuilder0& Then(const VoidGenerator0& body) {
      then_body_ = body;
      return *this;
    }
    IfBuilder0& Else(const VoidGenerator0& body) {
      else_body_ = body;
      return *this;
    }

    ~IfBuilder0() {
      // Ensure correct usage: effect/control must not have been modified while
      // the IfBuilder0 instance is alive.
      DCHECK_EQ(gasm_->effect(), initial_effect_);
      DCHECK_EQ(gasm_->control(), initial_control_);

      // Unlike IfBuilder1, this supports an empty then or else body. This is
      // possible since the merge does not take any value inputs.
      DCHECK(then_body_ || else_body_);

      if (negate_cond_) std::swap(then_body_, else_body_);

      auto if_true = (hint_ == BranchHint::kFalse) ? gasm_->MakeDeferredLabel()
                                                   : gasm_->MakeLabel();
      auto if_false = (hint_ == BranchHint::kTrue) ? gasm_->MakeDeferredLabel()
                                                   : gasm_->MakeLabel();
      auto merge = gasm_->MakeLabel();
      gasm_->Branch(cond_, &if_true, &if_false);

      gasm_->Bind(&if_true);
      if (then_body_) then_body_();
      if (gasm_->HasActiveBlock()) gasm_->Goto(&merge);

      gasm_->Bind(&if_false);
      if (else_body_) else_body_();
      if (gasm_->HasActiveBlock()) gasm_->Goto(&merge);

      gasm_->Bind(&merge);
    }

    IfBuilder0(const IfBuilder0&) = delete;
    IfBuilder0& operator=(const IfBuilder0&) = delete;

   private:
    JSGraphAssembler* const gasm_;
    const TNode<Boolean> cond_;
    const bool negate_cond_;
    const Effect initial_effect_;
    const Control initial_control_;
    BranchHint hint_ = BranchHint::kNone;
    VoidGenerator0 then_body_;
    VoidGenerator0 else_body_;
  };

  IfBuilder0 If(TNode<Boolean> cond) { return {this, cond, false}; }
  IfBuilder0 IfNot(TNode<Boolean> cond) { return {this, cond, true}; }

  template <typename T, typename Cond>
  class IfBuilder1 {
    using If1BodyFunction = std::function<TNode<T>()>;

   public:
    IfBuilder1(JSGraphAssembler* gasm, TNode<Cond> cond, bool negate_cond)
        : gasm_(gasm), cond_(cond), negate_cond_(negate_cond) {}

    V8_WARN_UNUSED_RESULT IfBuilder1& ExpectTrue() {
      DCHECK_EQ(hint_, BranchHint::kNone);
      hint_ = BranchHint::kTrue;
      return *this;
    }

    V8_WARN_UNUSED_RESULT IfBuilder1& ExpectFalse() {
      DCHECK_EQ(hint_, BranchHint::kNone);
      hint_ = BranchHint::kFalse;
      return *this;
    }

    V8_WARN_UNUSED_RESULT IfBuilder1& Then(const If1BodyFunction& body) {
      then_body_ = body;
      return *this;
    }
    V8_WARN_UNUSED_RESULT IfBuilder1& Else(const If1BodyFunction& body) {
      else_body_ = body;
      return *this;
    }

    V8_WARN_UNUSED_RESULT TNode<T> Value() {
      DCHECK(then_body_);
      DCHECK(else_body_);

      if (negate_cond_) std::swap(then_body_, else_body_);

      auto if_true = (hint_ == BranchHint::kFalse) ? gasm_->MakeDeferredLabel()
                                                   : gasm_->MakeLabel();
      auto if_false = (hint_ == BranchHint::kTrue) ? gasm_->MakeDeferredLabel()
                                                   : gasm_->MakeLabel();
      auto merge = gasm_->MakeLabel(PhiMachineRepresentationOf<T>);
      if constexpr (std::is_same_v<Cond, Word32T>) {
        gasm_->MachineBranch(cond_, &if_true, &if_false, hint_);
      } else {
        static_assert(std::is_same_v<Cond, Boolean>);
        if (hint_ != BranchHint::kNone) {
          gasm_->BranchWithHint(cond_, &if_true, &if_false, hint_);
        } else {
          gasm_->Branch(cond_, &if_true, &if_false);
        }
      }

      gasm_->Bind(&if_true);
      TNode<T> then_result = then_body_();
      if (gasm_->HasActiveBlock()) gasm_->Goto(&merge, then_result);

      gasm_->Bind(&if_false);
      TNode<T> else_result = else_body_();
      if (gasm_->HasActiveBlock()) {
        gasm_->Goto(&merge, else_result);
      }

      gasm_->Bind(&merge);
      return merge.template PhiAt<T>(0);
    }

   private:
    static constexpr MachineRepresentation kPhiRepresentation =
        MachineRepresentation::kTagged;

    JSGraphAssembler* const gasm_;
    const TNode<Cond> cond_;
    const bool negate_cond_;
    BranchHint hint_ = BranchHint::kNone;
    If1BodyFunction then_body_;
    If1BodyFunction else_body_;
  };

  template <typename T>
  IfBuilder1<T, Boolean> SelectIf(TNode<Boolean> cond) {
    return {this, cond, false};
  }
  template <typename T>
  IfBuilder1<T, Boolean> SelectIfNot(TNode<Boolean> cond) {
    return {this, cond, true};
  }
  template <typename T>
  IfBuilder1<T, Word32T> MachineSelectIf(TNode<Word32T> cond) {
    return {this, cond, false};
  }

 protected:
  Operator const* PlainPrimitiveToNumberOperator();

 private:
  JSHeapBroker* broker_;
  JSGraph* jsgraph_;
  SetOncePointer<Operator const> to_number_operator_;

 protected:
  CatchScope outermost_catch_scope_;
  Node* outermost_handler_;
  CatchScope* catch_scope_;
  friend class CatchScope;
};

}  // namespace compiler
}  // namespace internal
}  // namespace v8

#endif  // V8_COMPILER_GRAPH_ASSEMBLER_H_
```