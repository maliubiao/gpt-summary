Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Identify the Core Purpose:** The filename `operations.h` within a `compiler/turboshaft` directory strongly suggests this file defines the *operations* that Turboshaft, the V8 compiler component, performs. These operations are likely the building blocks of the intermediate representation (IR) used by the compiler.

2. **Scan for Key Structures:** Quickly glance through the code and identify the major structures defined. In this case, they are all `struct` definitions, mostly with names ending in `Op`. This reinforces the idea that these represent different kinds of operations.

3. **Examine Individual Operations:** For each `struct`, analyze its key members:
    * **Inheritance:** Most structures inherit from `FixedArityOperationT` or `OperationT`. This indicates a base class providing common functionality for operations. The template arguments to `FixedArityOperationT` likely specify the number of input operands.
    * **`OpEffects`:**  This static member provides information about the side effects of the operation (e.g., can change control flow, allocate memory, deoptimize). This is crucial for compiler optimizations and scheduling.
    * **`inputs_rep()` and `outputs_rep()`:** These methods define the expected register representations (types) of the input and output operands. This is important for register allocation and type checking.
    * **Input Accessors:** Methods like `input()`, `condition()`, `pop_count()`, etc., provide convenient ways to access the input operands. They often use template magic like `input<Word32>(0)` to specify the expected type and index.
    * **Constructor:** The constructor initializes the operation's state, including its inputs and specific properties.
    * **`Validate()`:**  This method likely performs sanity checks on the operation's state, often in the context of the overall compilation graph.
    * **`options()`:** This method returns a tuple of the operation's specific parameters. This is often used for hashing and equality checking.
    * **Static `New()`:** This static factory method is used to create new instances of the operation and add them to the compilation graph.

4. **Categorize the Operations:** As you examine the operations, try to group them by their general functionality. Common categories that emerge here are:
    * **Control Flow:** `ReturnOp`, `GotoOp`, `BranchOp`, `SwitchOp`, `CheckExceptionOp`. These operations control the execution order of the code.
    * **Data Manipulation:** Operations that transform or check data, such as type checks (`CheckTurboshaftTypeOfOp`, `ObjectIsOp`, `Float64IsOp`, `ObjectIsNumericValueOp`), conversions (`ConvertOp`, `ConvertUntaggedToJSPrimitiveOp`, `ConvertJSPrimitiveToUntaggedOp`, `TruncateJSPrimitiveToUntaggedOp`), and basic operations (not explicitly shown in this snippet, but likely exist in the full file).
    * **Object Creation:** `NewConsStringOp`, `NewArrayOp`.
    * **Meta-Operations:** `TupleOp`, `ProjectionOp`. These are more about structuring the IR than performing direct computations.

5. **Infer High-Level Functionality:** Based on the identified operations, deduce the overall purpose of the file: it defines the set of fundamental operations that the Turboshaft compiler uses to represent code. It's a core part of the compiler's IR.

6. **Address Specific Questions:** Now, go through the specific questions in the prompt:
    * **Functionality Listing:**  Summarize the categories and provide a brief description of each operation.
    * **`.tq` Extension:** Note that the file ends in `.h`, not `.tq`, so it's C++, not Torque.
    * **JavaScript Relationship:** Look for operations that directly correspond to JavaScript concepts. Examples include array creation, string manipulation, type checks, and control flow (like `return`). Provide simple JavaScript examples to illustrate.
    * **Code Logic Inference:** For control flow operations like `BranchOp` and `SwitchOp`, create simple examples with assumed inputs and outputs to demonstrate how the control flow would change.
    * **Common Programming Errors:** Connect certain operations to potential JavaScript errors. Type checking operations relate to `TypeError`, and incorrect assumptions in conversions can lead to unexpected results.
    * **Overall Function Summary:**  Reiterate the main purpose: defining the building blocks of the Turboshaft compiler's IR.

7. **Structure the Output:** Organize the findings clearly and concisely, using headings and bullet points to enhance readability. Address each point of the prompt systematically.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "These might be low-level machine instructions."  **Correction:** The presence of high-level concepts like `String`, `Array`, and `Context` suggests this is a higher-level IR than direct machine code. It's still relatively low-level compared to the source code, but not machine code.
* **Realization:** "The `effects` member is important." **Refinement:** Pay close attention to the `OpEffects` for each operation, as this provides valuable insight into what the operation does and how the compiler can optimize it.
* **Clarification:** "What's the difference between `TupleOp` and other operations?" **Refinement:** Recognize that `TupleOp` is a special kind of operation for handling multiple outputs, which are then accessed via `ProjectionOp`. This clarifies the purpose of these seemingly less "computational" operations.
* **Example Selection:** When providing JavaScript examples, choose simple and clear cases that directly illustrate the corresponding operation's function.

By following this structured analysis, combining code examination with an understanding of compiler principles, one can effectively determine the functionality of a complex header file like this.
这是对V8源代码文件 `v8/src/compiler/turboshaft/operations.h` 的分析。

**功能归纳:**

这个头文件定义了 Turboshaft 编译器（V8 的新一代编译器）中使用的各种操作 (Operations)。这些操作是 Turboshaft 中间表示 (IR) 的基本构建块，用于表示代码的不同行为和计算。它们涵盖了控制流、数据处理、类型检查、对象创建以及与其他编译阶段交互等方面。

**具体功能列举:**

这个文件定义了多种不同的操作结构体 (struct)，每种结构体代表一种特定的操作。以下列举了一些主要的操作及其功能：

* **控制流操作 (Control Flow Operations):**
    * `ReturnOp`: 表示函数返回操作。它指定要弹出的栈帧数量以及要返回的值。
    * `GotoOp`:  表示无条件跳转到指定的代码块。可以标记为后向边 (backedge)，用于循环优化。
    * `BranchOp`: 表示条件分支操作。根据一个布尔条件跳转到 `if_true` 或 `if_false` 代码块。
    * `SwitchOp`: 表示多路分支操作。根据输入值跳转到不同的 `case` 或 `default_case` 代码块。
    * `CheckExceptionOp`: 检查是否发生了异常，并根据结果跳转到不同的代码块。

* **元操作 (Meta Operations):**
    * `TupleOp`:  表示一个包含多个值的元组。通常用于表示具有多个输出的操作。
    * `ProjectionOp`: 用于从 `TupleOp` 中提取特定的值。

* **类型检查操作 (Type Checking Operations):**
    * `CheckTurboshaftTypeOfOp`: 检查值的 Turboshaft 类型。
    * `ObjectIsOp`: 检查对象是否属于特定的类型 (例如，数组缓冲区视图，BigInt，可调用对象等)。
    * `Float64IsOp`: 检查一个浮点数是否具有特定的属性 (例如，有限，整数，NaN 等)。
    * `ObjectIsNumericValueOp`: 检查一个对象是否是特定的数值类型。

* **类型转换操作 (Type Conversion Operations):**
    * `ConvertOp`:  在不同的 JavaScript 类型之间进行转换 (例如，Object 到 Boolean，String 到 Number)。
    * `ConvertUntaggedToJSPrimitiveOp`: 将未标记的 (untagged) 数据转换为 JavaScript 原始类型。
    * `ConvertUntaggedToJSPrimitiveOrDeoptOp`: 将未标记的数据转换为 JavaScript 原始类型，如果转换失败则进行去优化 (deoptimization)。
    * `ConvertJSPrimitiveToUntaggedOp`: 将 JavaScript 原始类型转换为未标记的数据。
    * `ConvertJSPrimitiveToUntaggedOrDeoptOp`: 将 JavaScript 原始类型转换为未标记的数据，如果转换失败则进行去优化。
    * `TruncateJSPrimitiveToUntaggedOp`: 将 JavaScript 原始类型截断为未标记的整数类型。
    * `TruncateJSPrimitiveToUntaggedOrDeoptOp`: 将 JavaScript 原始类型截断为未标记的整数类型，如果转换失败则进行去优化。
    * `ConvertJSPrimitiveToObjectOp`: 将 JavaScript 原始类型转换为对象。

* **对象创建操作 (Object Creation Operations):**
    * `NewConsStringOp`: 创建一个新的拼接字符串 (ConsString)。
    * `NewArrayOp`: 创建一个新的数组。
    * `DoubleArrayMinMaxOp`:  查找双精度浮点数数组中的最小值或最大值。

* **内存访问操作 (Memory Access Operations):**
    * `LoadFieldByIndexOp`:  根据索引加载对象的字段。

**关于文件扩展名和 Torque:**

`v8/src/compiler/turboshaft/operations.h` 的扩展名是 `.h`，这意味着它是一个 C++ 头文件，而不是 Torque 源代码文件（Torque 文件的扩展名通常是 `.tq`）。

**与 JavaScript 功能的关系和示例:**

这些操作直接对应于 JavaScript 语言的各种功能。以下是一些示例：

* **`ReturnOp`:** 对应于 JavaScript 中的 `return` 语句。
  ```javascript
  function foo(x) {
    return x + 1;
  }
  ```
* **`GotoOp` 和 `BranchOp`:** 对应于 JavaScript 中的控制流结构，如 `if`, `else`, `while`, `for` 等。
  ```javascript
  let i = 0;
  while (i < 10) { // 对应 `GotoOp` (回到循环开始) 和 `BranchOp` (判断循环条件)
    i++;
  }

  if (x > 5) { // 对应 `BranchOp`
    console.log("x is greater than 5");
  } else {
    console.log("x is not greater than 5");
  }
  ```
* **`SwitchOp`:** 对应于 JavaScript 中的 `switch` 语句。
  ```javascript
  let color = "red";
  switch (color) { // 对应 `SwitchOp`
    case "red":
      console.log("The color is red");
      break;
    case "blue":
      console.log("The color is blue");
      break;
    default:
      console.log("The color is something else");
  }
  ```
* **`CheckTurboshaftTypeOfOp` 和 `ObjectIsOp`:** 对应于 JavaScript 中的 `typeof` 运算符和各种类型检查操作。
  ```javascript
  let a = 10;
  console.log(typeof a); // "number"

  let arr = [];
  console.log(arr instanceof Array); // true
  ```
* **`ConvertOp`:** 对应于 JavaScript 中的类型转换，例如隐式转换或显式转换。
  ```javascript
  let str = "5";
  let num = str * 2; // 隐式字符串到数字的转换

  let bool = Boolean(0); // 显式转换为布尔值
  ```
* **`NewConsStringOp` 和 `NewArrayOp`:** 对应于 JavaScript 中创建字符串和数组的操作。
  ```javascript
  let greeting = "Hello" + " " + "World"; // 对应 `NewConsStringOp`
  let numbers = [1, 2, 3]; // 对应 `NewArrayOp`
  ```

**代码逻辑推理的假设输入与输出:**

以 `BranchOp` 为例：

**假设输入:**
* `condition()` (输入 0):  一个表示布尔值的 `OpIndex`，假设其计算结果为 `true`。
* `if_true`: 指向代码块 A 的指针。
* `if_false`: 指向代码块 B 的指针。
* `hint`: 分支预测提示 (例如，`kUnlikely`，`kLikely` 等)。

**输出:**
控制流将跳转到 `if_true` 指向的代码块 A 执行。

以 `SwitchOp` 为例：

**假设输入:**
* `input()`: 一个表示整数值的 `V<Word32>`，假设其值为 `2`。
* `cases`: 一个包含多个 `Case` 结构的向量，其中一个 `Case` 的 `value` 为 `2`，`destination` 指向代码块 C。
* `default_case`: 指向代码块 D 的指针。
* `default_hint`: 默认分支预测提示。

**输出:**
控制流将跳转到 `cases` 中 `value` 为 `2` 的 `Case` 的 `destination` 指向的代码块 C 执行。

**涉及用户常见的编程错误:**

* **类型错误 (TypeError):**  与类型检查和类型转换操作密切相关。例如，尝试对非数字类型执行算术运算，或者调用不存在的方法。Turboshaft 中的 `CheckTurboshaftTypeOfOp` 和 `ObjectIsOp` 等操作有助于在编译时或运行时发现这些错误。
  ```javascript
  let obj = {};
  let result = obj.toUpperCase(); // TypeError: obj.toUpperCase is not a function
  ```
* **控制流错误:**  例如，无限循环或意外的分支行为。`GotoOp`, `BranchOp`, 和 `SwitchOp` 的不当使用可能导致这些问题。
  ```javascript
  // 潜在的无限循环
  let x = 5;
  while (x > 0) {
    console.log(x);
    // 忘记修改 x 的值
  }
  ```
* **假设类型错误:** 在进行类型转换时，如果假设的输入类型不正确，可能会导致意外的结果或错误。 Turboshaft 中的各种类型转换操作如果无法安全执行，可能会触发去优化。
  ```javascript
  function processNumber(input) {
    let num = parseInt(input); // 如果 input 不是字符串，parseInt 可能返回 NaN
    return num + 10;
  }
  console.log(processNumber("5")); // 15
  console.log(processNumber(5));  // NaN (因为 parseInt(5) 返回 5，但通常期望字符串)
  ```

总而言之，`v8/src/compiler/turboshaft/operations.h` 是 Turboshaft 编译器的核心组成部分，它定义了编译器用于表示和操作代码的关键指令集，直接反映了 JavaScript 语言的各种特性和行为。

### 提示词
```
这是目录为v8/src/compiler/turboshaft/operations.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/operations.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共11部分，请归纳一下它的功能
```

### 源代码
```c
nt() const { return input<Word32>(0); }

  base::Vector<const OpIndex> return_values() const {
    return inputs().SubVector(1, input_count);
  }

  ReturnOp(V<Word32> pop_count, base::Vector<const OpIndex> return_values,
           bool spill_caller_frame_slots)
      : Base(1 + return_values.size()),
        spill_caller_frame_slots(spill_caller_frame_slots) {
    base::Vector<OpIndex> inputs = this->inputs();
    inputs[0] = pop_count;
    inputs.SubVector(1, inputs.size()).OverwriteWith(return_values);
  }

  template <typename Fn, typename Mapper>
  V8_INLINE auto Explode(Fn fn, Mapper& mapper) const {
    OpIndex mapped_pop_count = mapper.Map(pop_count());
    auto mapped_return_values = mapper.template Map<4>(return_values());
    return fn(mapped_pop_count, base::VectorOf(mapped_return_values),
              spill_caller_frame_slots);
  }

  void Validate(const Graph& graph) const {
  }
  static ReturnOp& New(Graph* graph, V<Word32> pop_count,
                       base::Vector<const OpIndex> return_values,
                       bool spill_caller_frame_slots) {
    return Base::New(graph, 1 + return_values.size(), pop_count, return_values,
                     spill_caller_frame_slots);
  }
  auto options() const { return std::tuple{spill_caller_frame_slots}; }
};

struct GotoOp : FixedArityOperationT<0, GotoOp> {
  bool is_backedge;
  Block* destination;

  static constexpr OpEffects effects = OpEffects().CanChangeControlFlow();
  base::Vector<const RegisterRepresentation> outputs_rep() const { return {}; }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return {};
  }

  explicit GotoOp(Block* destination, bool is_backedge)
      : Base(), is_backedge(is_backedge), destination(destination) {}
  void Validate(const Graph& graph) const {}
  size_t hash_value(HashingStrategy strategy = HashingStrategy::kDefault) const;
  auto options() const { return std::tuple{destination, is_backedge}; }
};

struct BranchOp : FixedArityOperationT<1, BranchOp> {
  BranchHint hint;
  Block* if_true;
  Block* if_false;

  static constexpr OpEffects effects = OpEffects().CanChangeControlFlow();
  base::Vector<const RegisterRepresentation> outputs_rep() const { return {}; }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return MaybeRepVector<MaybeRegisterRepresentation::Word32()>();
  }

  OpIndex condition() const { return input(0); }

  BranchOp(OpIndex condition, Block* if_true, Block* if_false, BranchHint hint)
      : Base(condition), hint(hint), if_true(if_true), if_false(if_false) {}

  void Validate(const Graph& graph) const {
  }
  size_t hash_value(HashingStrategy strategy = HashingStrategy::kDefault) const;
  auto options() const { return std::tuple{if_true, if_false, hint}; }
};

struct SwitchOp : FixedArityOperationT<1, SwitchOp> {
  struct Case {
    BranchHint hint;
    int32_t value;
    Block* destination;

    Case(int32_t value, Block* destination, BranchHint hint)
        : hint(hint), value(value), destination(destination) {}

    bool operator==(const Case& other) const {
      return value == other.value && destination == other.destination &&
             hint == other.hint;
    }
  };
  BranchHint default_hint;
  base::Vector<Case> cases;
  Block* default_case;

  static constexpr OpEffects effects = OpEffects().CanChangeControlFlow();
  base::Vector<const RegisterRepresentation> outputs_rep() const { return {}; }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return MaybeRepVector<MaybeRegisterRepresentation::Word32()>();
  }

  V<Word32> input() const { return Base::input<Word32>(0); }

  SwitchOp(V<Word32> input, base::Vector<Case> cases, Block* default_case,
           BranchHint default_hint)
      : Base(input),
        default_hint(default_hint),
        cases(cases),
        default_case(default_case) {}

  void Validate(const Graph& graph) const {}
  void PrintOptions(std::ostream& os) const;
  size_t hash_value(HashingStrategy strategy = HashingStrategy::kDefault) const;
  auto options() const { return std::tuple{cases, default_case, default_hint}; }
};

template <>
struct fast_hash<SwitchOp::Case> {
  size_t operator()(SwitchOp::Case v) {
    return fast_hash_combine(v.value, v.destination);
  }
};

inline base::SmallVector<Block*, 4> SuccessorBlocks(const Operation& op) {
  switch (op.opcode) {
    case Opcode::kCheckException: {
      auto& casted = op.Cast<CheckExceptionOp>();
      return {casted.didnt_throw_block, casted.catch_block};
    }
    case Opcode::kGoto: {
      auto& casted = op.Cast<GotoOp>();
      return {casted.destination};
    }
    case Opcode::kBranch: {
      auto& casted = op.Cast<BranchOp>();
      return {casted.if_true, casted.if_false};
    }
    case Opcode::kReturn:
    case Opcode::kTailCall:
    case Opcode::kDeoptimize:
    case Opcode::kUnreachable:
      return base::SmallVector<Block*, 4>{};
    case Opcode::kSwitch: {
      auto& casted = op.Cast<SwitchOp>();
      base::SmallVector<Block*, 4> result;
      for (const SwitchOp::Case& c : casted.cases) {
        result.push_back(c.destination);
      }
      result.push_back(casted.default_case);
      return result;
    }
#define NON_TERMINATOR_CASE(op) case Opcode::k##op:
      TURBOSHAFT_OPERATION_LIST_NOT_BLOCK_TERMINATOR(NON_TERMINATOR_CASE)
      UNREACHABLE();
#undef NON_TERMINATOR_CASE
  }
}

V8_EXPORT_PRIVATE base::SmallVector<Block*, 4> SuccessorBlocks(
    const Block& block, const Graph& graph);

// Tuples are only used to lower operations with multiple outputs.
// `TupleOp` should be folded away by subsequent `ProjectionOp`s.
struct TupleOp : OperationT<TupleOp> {
  static constexpr OpEffects effects = OpEffects();
  base::Vector<const RegisterRepresentation> outputs_rep() const { return {}; }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return {};
  }

  explicit TupleOp(base::Vector<const V<Any>> inputs) : Base(inputs) {}

  template <typename Fn, typename Mapper>
  V8_INLINE auto Explode(Fn fn, Mapper& mapper) const {
    auto mapped_inputs = mapper.template Map<4>(inputs());
    return fn(base::VectorOf(mapped_inputs));
  }

  void Validate(const Graph& graph) const {}
  auto options() const { return std::tuple{}; }
};

// For operations that produce multiple results, we use `ProjectionOp` to
// distinguish them.
struct ProjectionOp : FixedArityOperationT<1, ProjectionOp> {
  uint16_t index;
  RegisterRepresentation rep;

  static constexpr OpEffects effects = OpEffects();
  base::Vector<const RegisterRepresentation> outputs_rep() const {
    return base::VectorOf(&rep, 1);
  }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return {};
  }

  V<Any> input() const { return Base::input<Any>(0); }

  ProjectionOp(V<Any> input, uint16_t index, RegisterRepresentation rep)
      : Base(input), index(index), rep(rep) {}

  void Validate(const Graph& graph) const {
    DCHECK(ValidOpInputRep(graph, input(), rep, index));
  }
  auto options() const { return std::tuple{index, rep}; }
};

struct CheckTurboshaftTypeOfOp
    : FixedArityOperationT<1, CheckTurboshaftTypeOfOp> {
  RegisterRepresentation rep;
  Type type;
  bool successful;

  static constexpr OpEffects effects = OpEffects()
                                           .CanDependOnChecks()
                                           .CanReadImmutableMemory()
                                           .RequiredWhenUnused();
  base::Vector<const RegisterRepresentation> outputs_rep() const { return {}; }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return InputsRepFactory::SingleRep(rep);
  }

  OpIndex input() const { return Base::input(0); }

  CheckTurboshaftTypeOfOp(OpIndex input, RegisterRepresentation rep, Type type,
                          bool successful)
      : Base(input), rep(rep), type(std::move(type)), successful(successful) {}

  void Validate(const Graph& graph) const {
  }
  auto options() const { return std::tuple{rep, type, successful}; }
};

struct ObjectIsOp : FixedArityOperationT<1, ObjectIsOp> {
  enum class Kind : uint8_t {
    kArrayBufferView,
    kBigInt,
    kBigInt64,
    kCallable,
    kConstructor,
    kDetectableCallable,
    kInternalizedString,
    kNonCallable,
    kNumber,
    kNumberOrBigInt,
    kReceiver,
    kReceiverOrNullOrUndefined,
    kSmi,
    kString,
    kStringOrStringWrapper,
    kSymbol,
    kUndetectable,
  };
  enum class InputAssumptions : uint8_t {
    kNone,
    kHeapObject,
    kBigInt,
  };
  Kind kind;
  InputAssumptions input_assumptions;

  // All type checks performed by this operator are regarding immutable
  // properties. Therefore, it can be considered pure. Input assumptions,
  // howerever, can rely on being scheduled after checks.
  static constexpr OpEffects effects =
      OpEffects().CanDependOnChecks().CanReadImmutableMemory();
  base::Vector<const RegisterRepresentation> outputs_rep() const {
    return RepVector<RegisterRepresentation::Word32()>();
  }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return MaybeRepVector<MaybeRegisterRepresentation::Tagged()>();
  }

  V<Object> input() const { return Base::input<Object>(0); }

  ObjectIsOp(V<Object> input, Kind kind, InputAssumptions input_assumptions)
      : Base(input), kind(kind), input_assumptions(input_assumptions) {}

  void Validate(const Graph& graph) const {}
  auto options() const { return std::tuple{kind, input_assumptions}; }
};
V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                           ObjectIsOp::Kind kind);
V8_EXPORT_PRIVATE std::ostream& operator<<(
    std::ostream& os, ObjectIsOp::InputAssumptions input_assumptions);

enum class NumericKind : uint8_t {
  kFloat64Hole,
  kFinite,
  kInteger,
  kSafeInteger,
  kSmi,
  kMinusZero,
  kNaN,
};
V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os, NumericKind kind);

struct Float64IsOp : FixedArityOperationT<1, Float64IsOp> {
  NumericKind kind;

  Float64IsOp(V<Float64> input, NumericKind kind) : Base(input), kind(kind) {}

  static constexpr OpEffects effects = OpEffects();
  base::Vector<const RegisterRepresentation> outputs_rep() const {
    return RepVector<RegisterRepresentation::Word32()>();
  }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return MaybeRepVector<MaybeRegisterRepresentation::Float64()>();
  }

  V<Float64> input() const { return Base::input<Float64>(0); }

  void Validate(const Graph& graph) const {}
  auto options() const { return std::tuple{kind}; }
};

struct ObjectIsNumericValueOp
    : FixedArityOperationT<1, ObjectIsNumericValueOp> {
  NumericKind kind;
  FloatRepresentation input_rep;

  ObjectIsNumericValueOp(V<Object> input, NumericKind kind,
                         FloatRepresentation input_rep)
      : Base(input), kind(kind), input_rep(input_rep) {}

  // Heap numbers are immutable, so reading from them is pure. We might rely on
  // checks to assume that the input is a heap number.
  static constexpr OpEffects effects =
      OpEffects().CanDependOnChecks().CanReadImmutableMemory();
  base::Vector<const RegisterRepresentation> outputs_rep() const {
    return RepVector<RegisterRepresentation::Word32()>();
  }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return MaybeRepVector<MaybeRegisterRepresentation::Tagged()>();
  }

  V<Object> input() const { return Base::input<Object>(0); }

  void Validate(const Graph& graph) const {
  }
  auto options() const { return std::tuple{kind, input_rep}; }
};

struct ConvertOp : FixedArityOperationT<1, ConvertOp> {
  enum class Kind : uint8_t {
    kObject,
    kBoolean,
    kNumber,
    kNumberOrOddball,
    kPlainPrimitive,
    kString,
    kSmi,
  };
  Kind from;
  Kind to;

  // All properties/values we read are immutable.
  static constexpr OpEffects effects =
      OpEffects()
          // We only allocate identityless primitives here.
          .CanAllocateWithoutIdentity()
          // We might use preceding checks to ensure the input has the right
          // type.
          .CanDependOnChecks()
          .CanReadImmutableMemory();
  base::Vector<const RegisterRepresentation> outputs_rep() const {
    return RepVector<RegisterRepresentation::Tagged()>();
  }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return MaybeRepVector<MaybeRegisterRepresentation::Tagged()>();
  }

  V<Object> input() const { return Base::input<Object>(0); }

  ConvertOp(V<Object> input, Kind from, Kind to)
      : Base(input), from(from), to(to) {}

  void Validate(const Graph& graph) const {}
  auto options() const { return std::tuple{from, to}; }
};
V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                           ConvertOp::Kind kind);

struct ConvertUntaggedToJSPrimitiveOp
    : FixedArityOperationT<1, ConvertUntaggedToJSPrimitiveOp> {
  enum class JSPrimitiveKind : uint8_t {
    kBigInt,
    kBoolean,
    kHeapNumber,
    kHeapNumberOrUndefined,
    kNumber,
    kSmi,
    kString,
  };
  enum class InputInterpretation : uint8_t {
    kSigned,
    kUnsigned,
    kCharCode,
    kCodePoint,
  };
  JSPrimitiveKind kind;
  RegisterRepresentation input_rep;
  InputInterpretation input_interpretation;
  CheckForMinusZeroMode minus_zero_mode;

  // The input is untagged and the results are identityless primitives.
  static constexpr OpEffects effects = OpEffects().CanAllocateWithoutIdentity();
  base::Vector<const RegisterRepresentation> outputs_rep() const {
    return RepVector<RegisterRepresentation::Tagged()>();
  }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return InputsRepFactory::SingleRep(input_rep);
  }

  V<Untagged> input() const { return Base::input<Untagged>(0); }

  ConvertUntaggedToJSPrimitiveOp(V<Untagged> input, JSPrimitiveKind kind,
                                 RegisterRepresentation input_rep,
                                 InputInterpretation input_interpretation,
                                 CheckForMinusZeroMode minus_zero_mode)
      : Base(input),
        kind(kind),
        input_rep(input_rep),
        input_interpretation(input_interpretation),
        minus_zero_mode(minus_zero_mode) {}

  void Validate(const Graph& graph) const {
    switch (kind) {
      case JSPrimitiveKind::kBigInt:
        DCHECK_EQ(input_rep, RegisterRepresentation::Word64());
        DCHECK_EQ(minus_zero_mode,
                  CheckForMinusZeroMode::kDontCheckForMinusZero);
        break;
      case JSPrimitiveKind::kBoolean:
        DCHECK_EQ(input_rep, RegisterRepresentation::Word32());
        DCHECK_EQ(minus_zero_mode,
                  CheckForMinusZeroMode::kDontCheckForMinusZero);
        break;
      case JSPrimitiveKind::kNumber:
      case JSPrimitiveKind::kHeapNumber:
        DCHECK_IMPLIES(
            minus_zero_mode == CheckForMinusZeroMode::kCheckForMinusZero,
            input_rep == RegisterRepresentation::Float64());
        break;
      case JSPrimitiveKind::kHeapNumberOrUndefined:
        DCHECK_IMPLIES(
            minus_zero_mode == CheckForMinusZeroMode::kDontCheckForMinusZero,
            input_rep == RegisterRepresentation::Float64());
        break;
      case JSPrimitiveKind::kSmi:
        DCHECK_EQ(input_rep, WordRepresentation::Word32());
        DCHECK_EQ(minus_zero_mode,
                  CheckForMinusZeroMode::kDontCheckForMinusZero);
        break;
      case JSPrimitiveKind::kString:
        DCHECK_EQ(input_rep, WordRepresentation::Word32());
        DCHECK_EQ(input_interpretation,
                  any_of(InputInterpretation::kCharCode,
                         InputInterpretation::kCodePoint));
        break;
    }
  }

  auto options() const {
    return std::tuple{kind, input_rep, input_interpretation, minus_zero_mode};
  }
};
V8_EXPORT_PRIVATE std::ostream& operator<<(
    std::ostream& os, ConvertUntaggedToJSPrimitiveOp::JSPrimitiveKind kind);

struct ConvertUntaggedToJSPrimitiveOrDeoptOp
    : FixedArityOperationT<2, ConvertUntaggedToJSPrimitiveOrDeoptOp> {
  enum class JSPrimitiveKind : uint8_t {
    kSmi,
  };
  enum class InputInterpretation : uint8_t {
    kSigned,
    kUnsigned,
  };
  JSPrimitiveKind kind;
  RegisterRepresentation input_rep;
  InputInterpretation input_interpretation;
  FeedbackSource feedback;

  // We currently only convert Word representations to Smi or deopt. We need to
  // change the effects if we add more kinds.
  static constexpr OpEffects effects = OpEffects().CanDeopt();
  base::Vector<const RegisterRepresentation> outputs_rep() const {
    return RepVector<RegisterRepresentation::Tagged()>();
  }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return InputsRepFactory::SingleRep(input_rep);
  }

  V<Untagged> input() const { return Base::input<Untagged>(0); }
  V<FrameState> frame_state() const { return Base::input<FrameState>(1); }

  ConvertUntaggedToJSPrimitiveOrDeoptOp(
      V<Untagged> input, V<FrameState> frame_state, JSPrimitiveKind kind,
      RegisterRepresentation input_rep,
      InputInterpretation input_interpretation, const FeedbackSource& feedback)
      : Base(input, frame_state),
        kind(kind),
        input_rep(input_rep),
        input_interpretation(input_interpretation),
        feedback(feedback) {}

  void Validate(const Graph& graph) const {
    DCHECK(Get(graph, frame_state()).Is<FrameStateOp>());
  }

  auto options() const {
    return std::tuple{kind, input_rep, input_interpretation, feedback};
  }
};
V8_EXPORT_PRIVATE std::ostream& operator<<(
    std::ostream& os,
    ConvertUntaggedToJSPrimitiveOrDeoptOp::JSPrimitiveKind kind);
V8_EXPORT_PRIVATE std::ostream& operator<<(
    std::ostream& os, ConvertUntaggedToJSPrimitiveOrDeoptOp::InputInterpretation
                          input_interpretation);

struct ConvertJSPrimitiveToUntaggedOp
    : FixedArityOperationT<1, ConvertJSPrimitiveToUntaggedOp> {
  enum class UntaggedKind : uint8_t {
    kInt32,
    kInt64,
    kUint32,
    kBit,
    kFloat64,
  };
  enum class InputAssumptions : uint8_t {
    kBoolean,
    kSmi,
    kNumberOrOddball,
    kPlainPrimitive,
  };
  UntaggedKind kind;
  InputAssumptions input_assumptions;

  // This operation can read memory, but only immutable aspects, so it counts as
  // pure.
  static constexpr OpEffects effects =
      OpEffects()
          // We might rely on preceding checks to avoid deopts.
          .CanDependOnChecks();
  base::Vector<const RegisterRepresentation> outputs_rep() const {
    switch (kind) {
      case UntaggedKind::kInt32:
      case UntaggedKind::kUint32:
      case UntaggedKind::kBit:
        return RepVector<RegisterRepresentation::Word32()>();
      case UntaggedKind::kInt64:
        return RepVector<RegisterRepresentation::Word64()>();
      case UntaggedKind::kFloat64:
        return RepVector<RegisterRepresentation::Float64()>();
    }
  }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return MaybeRepVector<MaybeRegisterRepresentation::Tagged()>();
  }

  V<JSPrimitive> input() const { return Base::input<JSPrimitive>(0); }

  ConvertJSPrimitiveToUntaggedOp(V<JSPrimitive> input, UntaggedKind kind,
                                 InputAssumptions input_assumptions)
      : Base(input), kind(kind), input_assumptions(input_assumptions) {}
  void Validate(const Graph& graph) const {
  }

  auto options() const { return std::tuple{kind, input_assumptions}; }
};
V8_EXPORT_PRIVATE std::ostream& operator<<(
    std::ostream& os, ConvertJSPrimitiveToUntaggedOp::UntaggedKind kind);
V8_EXPORT_PRIVATE std::ostream& operator<<(
    std::ostream& os,
    ConvertJSPrimitiveToUntaggedOp::InputAssumptions input_assumptions);

struct ConvertJSPrimitiveToUntaggedOrDeoptOp
    : FixedArityOperationT<2, ConvertJSPrimitiveToUntaggedOrDeoptOp> {
  enum class UntaggedKind : uint8_t {
    kInt32,
    kInt64,
    kFloat64,
    kArrayIndex,
  };
  enum class JSPrimitiveKind : uint8_t {
    kNumber,
    kNumberOrBoolean,
    kNumberOrOddball,
    kNumberOrString,
    kSmi,
  };
  JSPrimitiveKind from_kind;
  UntaggedKind to_kind;
  CheckForMinusZeroMode minus_zero_mode;
  FeedbackSource feedback;

  // This operation can read memory, but only immutable aspects, so it counts as
  // pure.
  static constexpr OpEffects effects = OpEffects().CanDeopt();
  base::Vector<const RegisterRepresentation> outputs_rep() const {
    switch (to_kind) {
      case UntaggedKind::kInt32:
        return RepVector<RegisterRepresentation::Word32()>();
      case UntaggedKind::kInt64:
        return RepVector<RegisterRepresentation::Word64()>();
      case UntaggedKind::kFloat64:
        return RepVector<RegisterRepresentation::Float64()>();
      case UntaggedKind::kArrayIndex:
        return Is64() ? RepVector<RegisterRepresentation::Word64()>()
                      : RepVector<RegisterRepresentation::Word32()>();
    }
  }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return MaybeRepVector<MaybeRegisterRepresentation::Tagged()>();
  }

  V<Object> input() const { return Base::input<Object>(0); }
  V<FrameState> frame_state() const { return Base::input<FrameState>(1); }

  ConvertJSPrimitiveToUntaggedOrDeoptOp(V<Object> input,
                                        V<FrameState> frame_state,
                                        JSPrimitiveKind from_kind,
                                        UntaggedKind to_kind,
                                        CheckForMinusZeroMode minus_zero_mode,
                                        const FeedbackSource& feedback)
      : Base(input, frame_state),
        from_kind(from_kind),
        to_kind(to_kind),
        minus_zero_mode(minus_zero_mode),
        feedback(feedback) {}
  void Validate(const Graph& graph) const {
    DCHECK(Get(graph, frame_state()).Is<FrameStateOp>());
  }

  auto options() const {
    return std::tuple{from_kind, to_kind, minus_zero_mode, feedback};
  }
};
V8_EXPORT_PRIVATE std::ostream& operator<<(
    std::ostream& os,
    ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind kind);
V8_EXPORT_PRIVATE std::ostream& operator<<(
    std::ostream& os, ConvertJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind kind);

struct TruncateJSPrimitiveToUntaggedOp
    : FixedArityOperationT<1, TruncateJSPrimitiveToUntaggedOp> {
  enum class UntaggedKind : uint8_t {
    kInt32,
    kInt64,
    kBit,
  };
  enum class InputAssumptions : uint8_t {
    kBigInt,
    kNumberOrOddball,
    kHeapObject,
    kObject,
  };
  UntaggedKind kind;
  InputAssumptions input_assumptions;

  // This operation can read memory, but only immutable aspects, so it counts as
  // pure.
  static constexpr OpEffects effects =
      OpEffects()
          // We might rely on preceding checks to ensure the input type.
          .CanDependOnChecks();
  base::Vector<const RegisterRepresentation> outputs_rep() const {
    switch (kind) {
      case UntaggedKind::kInt32:
      case UntaggedKind::kBit:
        return RepVector<RegisterRepresentation::Word32()>();
      case UntaggedKind::kInt64:
        return RepVector<RegisterRepresentation::Word64()>();
    }
  }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return MaybeRepVector<MaybeRegisterRepresentation::Tagged()>();
  }

  V<JSPrimitive> input() const { return Base::input<JSPrimitive>(0); }

  TruncateJSPrimitiveToUntaggedOp(V<JSPrimitive> input, UntaggedKind kind,
                                  InputAssumptions input_assumptions)
      : Base(input), kind(kind), input_assumptions(input_assumptions) {}
  void Validate(const Graph& graph) const {
  }

  auto options() const { return std::tuple{kind, input_assumptions}; }
};
V8_EXPORT_PRIVATE std::ostream& operator<<(
    std::ostream& os, TruncateJSPrimitiveToUntaggedOp::UntaggedKind kind);
V8_EXPORT_PRIVATE std::ostream& operator<<(
    std::ostream& os,
    TruncateJSPrimitiveToUntaggedOp::InputAssumptions input_assumptions);

struct TruncateJSPrimitiveToUntaggedOrDeoptOp
    : FixedArityOperationT<2, TruncateJSPrimitiveToUntaggedOrDeoptOp> {
  enum class UntaggedKind : uint8_t {
    kInt32,
  };
  using InputRequirement =
      ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind;
  UntaggedKind kind;
  InputRequirement input_requirement;
  FeedbackSource feedback;

  static constexpr OpEffects effects = OpEffects().CanDeopt();
  base::Vector<const RegisterRepresentation> outputs_rep() const {
    switch (kind) {
      case UntaggedKind::kInt32:
        return RepVector<RegisterRepresentation::Word32()>();
    }
  }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return MaybeRepVector<MaybeRegisterRepresentation::Tagged()>();
  }

  V<JSPrimitive> input() const { return Base::input<JSPrimitive>(0); }
  V<FrameState> frame_state() const { return Base::input<FrameState>(1); }

  TruncateJSPrimitiveToUntaggedOrDeoptOp(V<JSPrimitive> input,
                                         V<FrameState> frame_state,
                                         UntaggedKind kind,
                                         InputRequirement input_requirement,
                                         const FeedbackSource& feedback)
      : Base(input, frame_state),
        kind(kind),
        input_requirement(input_requirement),
        feedback(feedback) {}
  void Validate(const Graph& graph) const {
    DCHECK(Get(graph, frame_state()).Is<FrameStateOp>());
  }

  auto options() const { return std::tuple{kind, input_requirement, feedback}; }
};
V8_EXPORT_PRIVATE std::ostream& operator<<(
    std::ostream& os,
    TruncateJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind kind);

struct ConvertJSPrimitiveToObjectOp
    : FixedArityOperationT<3, ConvertJSPrimitiveToObjectOp> {
  ConvertReceiverMode mode;

  static constexpr OpEffects effects = OpEffects().CanCallAnything();
  base::Vector<const RegisterRepresentation> outputs_rep() const {
    return RepVector<RegisterRepresentation::Tagged()>();
  }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return MaybeRepVector<MaybeRegisterRepresentation::Tagged(),
                          MaybeRegisterRepresentation::Tagged()>();
  }

  V<JSPrimitive> value() const { return Base::input<JSPrimitive>(0); }
  V<Context> native_context() const { return Base::input<Context>(1); }
  V<JSGlobalProxy> global_proxy() const {
    return Base::input<JSGlobalProxy>(2);
  }

  ConvertJSPrimitiveToObjectOp(V<JSPrimitive> value, V<Context> native_context,
                               V<JSGlobalProxy> global_proxy,
                               ConvertReceiverMode mode)
      : Base(value, native_context, global_proxy), mode(mode) {}

  void Validate(const Graph& graph) const {}

  auto options() const { return std::tuple{mode}; }
};

struct NewConsStringOp : FixedArityOperationT<3, NewConsStringOp> {
  static constexpr OpEffects effects =
      OpEffects()
          // Strings are conceptually immutable and don't have identity.
          .CanAllocateWithoutIdentity()
          // We might rely on preceding checks to ensure the input is a string
          // and on their combined length being between ConsString::kMinLength
          // and ConsString::kMaxLength.
          .CanDependOnChecks();
  base::Vector<const RegisterRepresentation> outputs_rep() const {
    return RepVector<RegisterRepresentation::Tagged()>();
  }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return MaybeRepVector<MaybeRegisterRepresentation::Word32(),
                          MaybeRegisterRepresentation::Tagged(),
                          MaybeRegisterRepresentation::Tagged()>();
  }

  V<Word32> length() const { return Base::input<Word32>(0); }
  V<String> first() const { return Base::input<String>(1); }
  V<String> second() const { return Base::input<String>(2); }

  NewConsStringOp(V<Word32> length, V<String> first, V<String> second)
      : Base(length, first, second) {}
  void Validate(const Graph& graph) const {
  }

  auto options() const { return std::tuple{}; }
};

struct NewArrayOp : FixedArityOperationT<1, NewArrayOp> {
  enum class Kind : uint8_t {
    kDouble,
    kObject,
  };
  Kind kind;
  AllocationType allocation_type;

  static constexpr OpEffects effects =
      OpEffects()
          // Allocate the result, which has identity.
          .CanAllocate()
          // We might have checks to ensure the array length is valid and not
          // too big.
          .CanDependOnChecks();
  base::Vector<const RegisterRepresentation> outputs_rep() const {
    return RepVector<RegisterRepresentation::Tagged()>();
  }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return MaybeRepVector<MaybeRegisterRepresentation::WordPtr()>();
  }

  OpIndex length() const { return Base::input(0); }

  NewArrayOp(OpIndex length, Kind kind, AllocationType allocation_type)
      : Base(length), kind(kind), allocation_type(allocation_type) {}
  void Validate(const Graph& graph) const {
  }

  auto options() const { return std::tuple{kind, allocation_type}; }
};
V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                           NewArrayOp::Kind kind);

struct DoubleArrayMinMaxOp : FixedArityOperationT<1, DoubleArrayMinMaxOp> {
  enum class Kind : uint8_t {
    kMin,
    kMax,
  };
  Kind kind;

  static constexpr OpEffects effects =
      OpEffects()
          // Read the array contents.
          .CanReadHeapMemory()
          // Allocate the HeapNumber result.
          .CanAllocateWithoutIdentity()
          // We might depend on checks to ensure the input is an array.
          .CanDependOnChecks();
  base::Vector<const RegisterRepresentation> outputs_rep() const {
    return RepVector<RegisterRepresentation::Tagged()>();
  }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return MaybeRepVector<MaybeRegisterRepresentation::Tagged()>();
  }

  OpIndex array() const { return Base::input(0); }

  DoubleArrayMinMaxOp(OpIndex array, Kind kind) : Base(array), kind(kind) {}
  void Validate(const Graph& graph) const {
  }

  auto options() const { return std::tuple{kind}; }
};
V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                           DoubleArrayMinMaxOp::Kind kind);

// TODO(nicohartmann@): We should consider getting rid of the LoadFieldByIndex
// operation.
struct LoadFieldByIndexOp : FixedArityOperationT<2, LoadFieldByIndexOp> {
  static constexpr OpEffects effects =
      OpEffects()
          // Read the possibly mutable property.
          .CanReadHeapMemory()
          // We may allocate heap number for the result.
          .CanAllocateWithoutIdentity()
          // We assume the input is an object.
          .CanDependOnChecks();
  base::Vector<const RegisterRepresentation> outputs_rep() const {
    return RepVector<RegisterRepresentation::Tagged()>();
  }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return MaybeRepVector<MaybeRegisterRepresentation::Tagged(),
                          MaybeRegisterRepresentation::Word32()>();
  }

  OpIndex object() const { return Base::input(0); }
  // Index encoding (see `src/objects/field-index-inl.h`):
  // For efficiency, the LoadByFieldIndex instruction takes an index that is
  // optimized for quick access. If the property is inline, the index is
  // positive. If it's out-of-line, the encoded index is -raw_index - 1 to
  // disambiguate the zero out-of-line index fro
```