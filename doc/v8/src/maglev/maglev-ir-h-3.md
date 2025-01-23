Response:
Let's break down the thought process for analyzing this C++ header file.

**1. Initial Scan and Keyword Spotting:**

The first step is a quick skim of the code, looking for recurring patterns and keywords. I see:

* `class`:  Indicates the definition of classes, which are the fundamental building blocks of object-oriented C++.
* `public`, `protected`:  Access modifiers indicating visibility of members.
* `static constexpr`:  Declares compile-time constants, often used for configuration or properties.
* `Input&`:  References to `Input` objects, suggesting a data flow or dependency relationship.
* `GenerateCode`:  A strong hint that this code is involved in code generation or compilation.
* `MaglevAssembler`:  This is a very specific term related to V8's Maglev compiler, confirming the file's context.
* `FeedbackSource`:  Indicates the importance of type feedback in the compilation process.
* `Int32`, `Float64`, `Smi`, `Tagged`:  These are V8's internal representations of JavaScript data types.
* `Operation`:  Suggests that the code defines various operations or instructions within the Maglev IR.
* Macros like `DEF_OPERATION_WITH_FEEDBACK_NODE`, `DEF_INT32_BINARY_NODE`:  These are code generation tools, expanding into repetitive class definitions.
* `template`:  Indicates generic programming, allowing the creation of classes that work with different data types.

**2. Identifying Core Components:**

Based on the keywords, I can start to identify the main components:

* **Nodes:** The numerous classes with names like `BinaryWithFeedbackNode`, `Int32BinaryNode`, `Float64Constant` clearly represent nodes in an Intermediate Representation (IR) graph. The `<Derived, Operation kOperation>` template pattern further reinforces this.
* **Operations:** The `Operation` enum (not explicitly shown but heavily implied by `Operation::kOpName`) defines the different kinds of actions these nodes represent (e.g., addition, subtraction, comparison).
* **Data Types/Representations:**  The mention of `Int32`, `Float64`, `Smi`, `Tagged`, and `ValueRepresentation` highlights how data is represented within the IR.
* **Feedback:** The presence of `FeedbackSource` and nodes like `BinaryWithFeedbackNode` shows that the IR utilizes type feedback for optimization.
* **Code Generation:**  The `GenerateCode` methods and `MaglevAssembler` point towards the phase where the IR is translated into machine code.

**3. Understanding the Purpose of Macros:**

The macros are a crucial part of the file's structure. They are used to avoid writing repetitive code for defining similar node types. I can deduce their purpose by looking at their expansion:

* `DEF_OPERATION_WITH_FEEDBACK_NODE`: Creates a class for an operation that uses feedback.
* `DEF_UNARY_WITH_FEEDBACK_NODE`, `DEF_BINARY_WITH_FEEDBACK_NODE`:  Specialize the previous macro for unary and binary operations, respectively.
* `DEF_OPERATION_NODE`: Creates a class for a general operation.
* `DEF_INT32_BINARY_WITH_OVERFLOW_NODE`, `DEF_INT32_BINARY_NODE`: Create node classes specifically for integer operations, with and without overflow checks.

**4. Inferring Relationships and Structure:**

The inheritance relationships (e.g., `class Name : public Super<Name, Operation::k##OpName>`) reveal a hierarchy of node types. Base classes like `FixedInputValueNodeT` provide common functionality, and derived classes specialize them for specific operations and data types.

**5. Connecting to JavaScript Functionality:**

Now, I start thinking about how these IR nodes relate to JavaScript. The node names are often direct counterparts to JavaScript operators and functions:

* `Int32AddWithOverflow`:  JavaScript's `+` operator for numbers, especially when there's a possibility of integer overflow.
* `Float64Multiply`: JavaScript's `*` operator for floating-point numbers.
* `Int32Compare`:  JavaScript's comparison operators like `===`, `!==`, `<`, `>`, etc.
* `Int32ToBoolean`:  Implicit type coercion in JavaScript (e.g., `if (1) {}`).
* `Float64Ieee754Unary`:  `Math.sin()`, `Math.cos()`, etc.

**6. Considering Potential Issues and Errors:**

The "with overflow" nodes and the "checked" nodes (e.g., `CheckedSmiIncrement`, `CheckedNumberToUint8Clamped`) suggest mechanisms for handling potential runtime errors or type mismatches. This leads to the idea of common programming errors:

* Integer overflow:  Performing arithmetic on very large integers in JavaScript.
* Type coercion issues:  Implicitly relying on JavaScript's loose typing, which can sometimes lead to unexpected behavior.
* Incorrect type assumptions:  Assuming a variable is a Smi when it might be a heap number.

**7. Formulating the Summary:**

Finally, I synthesize the observations into a concise summary, focusing on the key functionalities:

* Defining the Maglev IR.
* Representing operations and data.
* Incorporating feedback for optimization.
* Being a C++ representation of JavaScript operations.
* Providing mechanisms for handling errors.

**Self-Correction/Refinement:**

During the process, I might encounter ambiguities or need to refine my understanding. For example, initially, I might not fully grasp the significance of the "feedback" aspect. But by seeing it repeatedly in node definitions and macros, I'd realize its importance in the Maglev compiler's optimization strategy. Similarly, the `Checked...` and `Unsafe...` prefixes on node names would prompt me to think about the different levels of safety and performance trade-offs in the compiler. The constant nodes (`Int32Constant`, `Float64Constant`) highlight how literal values are represented in the IR.

By following this iterative process of scanning, identifying, inferring, connecting, and refining, I can arrive at a comprehensive understanding of the provided C++ header file.
好的，这是对提供的 C++ 头文件 `v8/src/maglev/maglev-ir.h` 的功能归纳：

**功能归纳:**

这个头文件定义了 V8 引擎中 Maglev 编译器的中间表示 (IR) 的各种节点类型。 这些节点代表了在 JavaScript 代码执行过程中进行的各种操作，涵盖了算术运算、比较、类型转换、内存访问以及与反馈信息相关的操作。  这个 IR 是 Maglev 编译器将 JavaScript 代码转换为机器码的关键抽象层。

**详细功能列表:**

1. **定义带反馈信息的节点类型:**
   - `BinaryWithFeedbackNode`:  表示带有类型反馈信息的二元操作（例如加法、减法等）。
   - 提供了宏 `DEF_OPERATION_WITH_FEEDBACK_NODE`、`DEF_UNARY_WITH_FEEDBACK_NODE` 和 `DEF_BINARY_WITH_FEEDBACK_NODE` 来简化此类节点的定义。
   - `feedback()` 方法用于获取与此节点关联的反馈信息源。
   - 这些节点允许 Maglev 利用运行时收集的类型信息进行优化。

2. **定义基于 Int32 的运算节点类型:**
   - `Int32BinaryWithOverflowNode`: 表示可能发生溢出的 Int32 二元运算（加法、减法、乘法、除法、取模）。
   - `Int32BinaryNode`: 表示 Int32 的二元位运算（与、或、异或、左移、右移）。
   - `Int32BitwiseNot`: 表示 Int32 的按位取反运算。
   - `Int32UnaryWithOverflowNode`: 表示可能发生溢出的 Int32 一元运算（取负、递增、递减）。
   - `Int32ShiftRightLogical`: 表示 Int32 的逻辑右移运算（结果为 Uint32）。
   - `Int32Compare`: 表示 Int32 的比较运算。
   - `Int32ToBoolean`: 表示将 Int32 转换为布尔值的操作。

3. **定义处理 Smi (Small Integer) 的节点类型:**
   - `CheckedSmiIncrement`:  表示带溢出检查的 Smi 递增操作。
   - `CheckedSmiDecrement`:  表示带溢出检查的 Smi 递减操作。
   - `CheckedSmiTagInt32`: 表示带检查的将 Int32 标记为 Smi 的操作。
   - `CheckedSmiSizedInt32`:  表示带检查的 Int32，保证其大小适合 Smi。
   - `CheckedSmiTagUint32`: 表示带检查的将 Uint32 标记为 Smi 的操作。
   - `UnsafeSmiTagInt32`: 表示不安全地将 Int32 标记为 Smi 的操作 (假设输入始终适合 Smi)。
   - `UnsafeSmiTagUint32`: 表示不安全地将 Uint32 标记为 Smi 的操作 (假设输入始终适合 Smi)。
   - `CheckedSmiUntag`: 表示带检查的将 Smi 解除标记为 Int32 的操作。
   - `UnsafeSmiUntag`: 表示不安全地将 Smi 解除标记为 Int32 的操作。

4. **定义基于 Float64 的运算节点类型:**
   - `Float64BinaryNode`: 表示 Float64 的二元运算（加法、减法、乘法、除法）。
   - `Float64BinaryNodeWithCall`: 表示需要调用 C++ 函数实现的 Float64 二元运算（取模、幂运算，在某些架构上取模也可能需要调用）。
   - `Float64Compare`: 表示 Float64 的比较运算。
   - `Float64ToBoolean`: 表示将 Float64 转换为布尔值的操作。
   - `Float64Negate`: 表示 Float64 的取负运算。
   - `Float64Ieee754Unary`:  表示需要调用 IEEE 754 标准数学函数的 Float64 一元运算（例如 `Math.sin`, `Math.cos` 等）。

5. **定义类型检查节点类型:**
   - `CheckInt32IsSmi`: 检查 Int32 是否能安全地表示为 Smi。
   - `CheckUint32IsSmi`: 检查 Uint32 是否能安全地表示为 Smi。
   - `CheckHoleyFloat64IsSmi`: 检查 HoleyFloat64 是否能安全地表示为 Smi。

6. **定义常量节点类型:**
   - `Int32Constant`: 表示 Int32 类型的常量。
   - `Uint32Constant`: 表示 Uint32 类型的常量。
   - `Float64Constant`: 表示 Float64 类型的常量。

7. **定义类型转换节点类型:**
   - `Int32ToUint8Clamped`: 将 Int32 转换为 Uint8 并进行钳位 (限制在 0-255 范围内)。
   - `Uint32ToUint8Clamped`: 将 Uint32 转换为 Uint8 并进行钳位。
   - `Float64ToUint8Clamped`: 将 Float64 转换为 Uint8 并进行钳位。
   - `CheckedNumberToUint8Clamped`:  带检查的将 Number 类型转换为 Uint8 并进行钳位。
   - `Int32ToNumber`: 将 Int32 转换为 Number 类型。
   - `Uint32ToNumber`: 将 Uint32 转换为 Number 类型。
   - `Float64ToTagged`: 将 Float64 转换为 V8 的 Tagged 指针表示 (可能装箱为 HeapNumber)。
   - `Float64ToHeapNumberForField`: 将 Float64 转换为堆上的 HeapNumber (用于字段存储)。

**与 JavaScript 的关系及示例:**

这些节点直接对应 JavaScript 中的各种操作。例如：

* **`Int32AddWithOverflow`:**  对应 JavaScript 中的加法运算，如果参与运算的是整数并且可能超出 Int32 的范围。
   ```javascript
   let a = 2147483647; // 最大的 Int32
   let b = 1;
   let sum = a + b; // JavaScript 会自动处理溢出，但 Maglev 需要识别并处理潜在的溢出
   ```

* **`Float64Multiply`:** 对应 JavaScript 中的浮点数乘法运算。
   ```javascript
   let x = 3.14;
   let y = 2.0;
   let product = x * y;
   ```

* **`Int32ToBoolean`:** 对应 JavaScript 中的类型转换，例如在 `if` 语句中的使用。
   ```javascript
   let count = 5;
   if (count) { // count 被隐式转换为布尔值 (非零为 true)
       console.log("Count is not zero");
   }
   ```

* **`Float64Ieee754Unary` (例如 `MathCos`):** 对应 `Math.cos()` 等数学函数。
   ```javascript
   let angle = 0;
   let cosine = Math.cos(angle);
   ```

**代码逻辑推理 (假设输入与输出):**

以 `Int32AddWithOverflow` 为例：

**假设输入:**
- 左操作数 (left_input):  一个指向表示整数 `2147483647` 的节点的引用。
- 右操作数 (right_input): 一个指向表示整数 `1` 的节点的引用。

**输出:**
- 如果没有溢出，则生成表示结果 `2147483648` 的新节点。
- 如果发生溢出，则可能需要生成一个 deoptimization (回退到解释器) 的指令，因为 JavaScript 的数字类型可以表示超出 Int32 范围的值。

**用户常见的编程错误:**

* **整数溢出:**  在 JavaScript 中进行大量整数运算时，虽然 JavaScript 可以处理大整数，但在 Maglev 编译的上下文中，需要考虑 Int32 的限制。程序员可能没有意识到在特定场景下会发生溢出。
   ```javascript
   let largeNumber = 2 ** 31 - 1;
   let incremented = largeNumber + 1; // 在某些编译路径下可能触发溢出处理
   ```

* **类型假设错误:**  假设一个变量总是整数，但实际上可能是浮点数，导致生成的 Maglev 代码出现问题。
   ```javascript
   function add(a, b) {
       return a + b;
   }

   add(5, 3);      // Maglev 可能优化为整数加法
   add(5, 3.14);   // 如果之前假设是整数，则可能需要 deoptimization
   ```

**总结 (作为第 4 部分):**

作为 Maglev IR 定义的第 4 部分，这部分主要关注 **数值运算和类型转换** 的节点定义。它详细描述了如何在 Maglev 的中间表示中表示各种 Int32 和 Float64 上的算术、位运算、比较以及到布尔值的转换。此外，还包含了对 Smi 这种特殊整数类型的处理，以及各种类型之间的安全和非安全转换。这些节点是构建 Maglev IR 图的关键组成部分，用于表示 JavaScript 代码中与数字相关的操作，并为后续的代码生成阶段提供基础。

### 提示词
```
这是目录为v8/src/maglev/maglev-ir.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-ir.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共12部分，请归纳一下它的功能
```

### 源代码
```c
r::FeedbackSource feedback() const { return feedback_; }

 protected:
  BinaryWithFeedbackNode(uint64_t bitfield,
                         const compiler::FeedbackSource& feedback)
      : Base(bitfield), feedback_(feedback) {}

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}

  const compiler::FeedbackSource feedback_;
};

#define DEF_OPERATION_WITH_FEEDBACK_NODE(Name, Super, OpName)         \
  class Name : public Super<Name, Operation::k##OpName> {             \
    using Base = Super<Name, Operation::k##OpName>;                   \
                                                                      \
   public:                                                            \
    Name(uint64_t bitfield, const compiler::FeedbackSource& feedback) \
        : Base(bitfield, feedback) {}                                 \
    int MaxCallStackArgs() const { return 0; }                        \
    void SetValueLocationConstraints();                               \
    void GenerateCode(MaglevAssembler*, const ProcessingState&);      \
    void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}    \
  };

#define DEF_UNARY_WITH_FEEDBACK_NODE(Name) \
  DEF_OPERATION_WITH_FEEDBACK_NODE(Generic##Name, UnaryWithFeedbackNode, Name)
#define DEF_BINARY_WITH_FEEDBACK_NODE(Name) \
  DEF_OPERATION_WITH_FEEDBACK_NODE(Generic##Name, BinaryWithFeedbackNode, Name)
UNARY_OPERATION_LIST(DEF_UNARY_WITH_FEEDBACK_NODE)
ARITHMETIC_OPERATION_LIST(DEF_BINARY_WITH_FEEDBACK_NODE)
COMPARISON_OPERATION_LIST(DEF_BINARY_WITH_FEEDBACK_NODE)
#undef DEF_UNARY_WITH_FEEDBACK_NODE
#undef DEF_BINARY_WITH_FEEDBACK_NODE
#undef DEF_OPERATION_WITH_FEEDBACK_NODE

template <class Derived, Operation kOperation>
class Int32BinaryWithOverflowNode : public FixedInputValueNodeT<2, Derived> {
  using Base = FixedInputValueNodeT<2, Derived>;

 public:
  static constexpr OpProperties kProperties =
      OpProperties::EagerDeopt() | OpProperties::Int32();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kInt32, ValueRepresentation::kInt32};

  static constexpr int kLeftIndex = 0;
  static constexpr int kRightIndex = 1;
  Input& left_input() { return Node::input(kLeftIndex); }
  Input& right_input() { return Node::input(kRightIndex); }

 protected:
  explicit Int32BinaryWithOverflowNode(uint64_t bitfield) : Base(bitfield) {}

  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

#define DEF_OPERATION_NODE(Name, Super, OpName)                    \
  class Name : public Super<Name, Operation::k##OpName> {          \
    using Base = Super<Name, Operation::k##OpName>;                \
                                                                   \
   public:                                                         \
    explicit Name(uint64_t bitfield) : Base(bitfield) {}           \
    void SetValueLocationConstraints();                            \
    void GenerateCode(MaglevAssembler*, const ProcessingState&);   \
    void PrintParams(std::ostream&, MaglevGraphLabeller*) const {} \
  };

#define DEF_INT32_BINARY_WITH_OVERFLOW_NODE(Name)                            \
  DEF_OPERATION_NODE(Int32##Name##WithOverflow, Int32BinaryWithOverflowNode, \
                     Name)
DEF_INT32_BINARY_WITH_OVERFLOW_NODE(Add)
DEF_INT32_BINARY_WITH_OVERFLOW_NODE(Subtract)
DEF_INT32_BINARY_WITH_OVERFLOW_NODE(Multiply)
DEF_INT32_BINARY_WITH_OVERFLOW_NODE(Divide)
DEF_INT32_BINARY_WITH_OVERFLOW_NODE(Modulus)
#undef DEF_INT32_BINARY_WITH_OVERFLOW_NODE

template <class Derived, Operation kOperation>
class Int32BinaryNode : public FixedInputValueNodeT<2, Derived> {
  using Base = FixedInputValueNodeT<2, Derived>;

 public:
  static constexpr OpProperties kProperties = OpProperties::Int32();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kInt32, ValueRepresentation::kInt32};

  static constexpr int kLeftIndex = 0;
  static constexpr int kRightIndex = 1;
  Input& left_input() { return Node::input(kLeftIndex); }
  Input& right_input() { return Node::input(kRightIndex); }

 protected:
  explicit Int32BinaryNode(uint64_t bitfield) : Base(bitfield) {}
};

#define DEF_INT32_BINARY_NODE(Name) \
  DEF_OPERATION_NODE(Int32##Name, Int32BinaryNode, Name)
DEF_INT32_BINARY_NODE(BitwiseAnd)
DEF_INT32_BINARY_NODE(BitwiseOr)
DEF_INT32_BINARY_NODE(BitwiseXor)
DEF_INT32_BINARY_NODE(ShiftLeft)
DEF_INT32_BINARY_NODE(ShiftRight)
#undef DEF_INT32_BINARY_NODE

class Int32BitwiseNot : public FixedInputValueNodeT<1, Int32BitwiseNot> {
  using Base = FixedInputValueNodeT<1, Int32BitwiseNot>;

 public:
  explicit Int32BitwiseNot(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::Int32();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kInt32};

  static constexpr int kValueIndex = 0;
  Input& value_input() { return Node::input(kValueIndex); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

template <class Derived, Operation kOperation>
class Int32UnaryWithOverflowNode : public FixedInputValueNodeT<1, Derived> {
  using Base = FixedInputValueNodeT<1, Derived>;

 public:
  static constexpr OpProperties kProperties =
      OpProperties::EagerDeopt() | OpProperties::Int32();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kInt32};

  static constexpr int kValueIndex = 0;
  Input& value_input() { return Node::input(kValueIndex); }

 protected:
  explicit Int32UnaryWithOverflowNode(uint64_t bitfield) : Base(bitfield) {}
};

#define DEF_INT32_UNARY_WITH_OVERFLOW_NODE(Name)                            \
  DEF_OPERATION_NODE(Int32##Name##WithOverflow, Int32UnaryWithOverflowNode, \
                     Name)

DEF_INT32_UNARY_WITH_OVERFLOW_NODE(Negate)
DEF_INT32_UNARY_WITH_OVERFLOW_NODE(Increment)
DEF_INT32_UNARY_WITH_OVERFLOW_NODE(Decrement)
#undef DEF_INT32_UNARY_WITH_OVERFLOW_NODE

class Int32ShiftRightLogical
    : public FixedInputValueNodeT<2, Int32ShiftRightLogical> {
  using Base = FixedInputValueNodeT<2, Int32ShiftRightLogical>;

 public:
  explicit Int32ShiftRightLogical(uint64_t bitfield) : Base(bitfield) {}

  // Unlike the other Int32 nodes, logical right shift returns a Uint32.
  static constexpr OpProperties kProperties = OpProperties::Uint32();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kInt32, ValueRepresentation::kInt32};

  static constexpr int kLeftIndex = 0;
  static constexpr int kRightIndex = 1;
  Input& left_input() { return Node::input(kLeftIndex); }
  Input& right_input() { return Node::input(kRightIndex); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class Int32Compare : public FixedInputValueNodeT<2, Int32Compare> {
  using Base = FixedInputValueNodeT<2, Int32Compare>;

 public:
  explicit Int32Compare(uint64_t bitfield, Operation operation)
      : Base(OperationBitField::update(bitfield, operation)) {}

  static constexpr Base::InputTypes kInputTypes{ValueRepresentation::kInt32,
                                                ValueRepresentation::kInt32};

  static constexpr int kLeftIndex = 0;
  static constexpr int kRightIndex = 1;
  Input& left_input() { return Node::input(kLeftIndex); }
  Input& right_input() { return Node::input(kRightIndex); }

  constexpr Operation operation() const {
    return OperationBitField::decode(bitfield());
  }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

  auto options() const { return std::tuple{operation()}; }

 private:
  using OperationBitField = NextBitField<Operation, 5>;
};

class Int32ToBoolean : public FixedInputValueNodeT<1, Int32ToBoolean> {
  using Base = FixedInputValueNodeT<1, Int32ToBoolean>;

 public:
  explicit Int32ToBoolean(uint64_t bitfield, bool flip)
      : Base(FlipBitField::update(bitfield, flip)) {}

  static constexpr Base::InputTypes kInputTypes{ValueRepresentation::kInt32};

  Input& value() { return Node::input(0); }

  constexpr bool flip() const { return FlipBitField::decode(bitfield()); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

  auto options() const { return std::tuple{flip()}; }

 private:
  using FlipBitField = NextBitField<bool, 1>;
};

class CheckedSmiIncrement
    : public FixedInputValueNodeT<1, CheckedSmiIncrement> {
  using Base = FixedInputValueNodeT<1, CheckedSmiIncrement>;

 public:
  explicit CheckedSmiIncrement(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::EagerDeopt();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kTagged};

  static constexpr int kValueIndex = 0;
  Input& value_input() { return Node::input(kValueIndex); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class CheckedSmiDecrement
    : public FixedInputValueNodeT<1, CheckedSmiDecrement> {
  using Base = FixedInputValueNodeT<1, CheckedSmiDecrement>;

 public:
  explicit CheckedSmiDecrement(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::EagerDeopt();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kTagged};

  static constexpr int kValueIndex = 0;
  Input& value_input() { return Node::input(kValueIndex); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

template <class Derived, Operation kOperation>
class Float64BinaryNode : public FixedInputValueNodeT<2, Derived> {
  using Base = FixedInputValueNodeT<2, Derived>;

 public:
  static constexpr OpProperties kProperties = OpProperties::Float64();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kHoleyFloat64, ValueRepresentation::kHoleyFloat64};

  static constexpr int kLeftIndex = 0;
  static constexpr int kRightIndex = 1;
  Input& left_input() { return Node::input(kLeftIndex); }
  Input& right_input() { return Node::input(kRightIndex); }

 protected:
  explicit Float64BinaryNode(uint64_t bitfield) : Base(bitfield) {}

  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

#define DEF_OPERATION_NODE_WITH_CALL(Name, Super, OpName)          \
  class Name : public Super<Name, Operation::k##OpName> {          \
    using Base = Super<Name, Operation::k##OpName>;                \
                                                                   \
   public:                                                         \
    explicit Name(uint64_t bitfield) : Base(bitfield) {}           \
    int MaxCallStackArgs() const;                                  \
    void SetValueLocationConstraints();                            \
    void GenerateCode(MaglevAssembler*, const ProcessingState&);   \
    void PrintParams(std::ostream&, MaglevGraphLabeller*) const {} \
  };

template <class Derived, Operation kOperation>
class Float64BinaryNodeWithCall : public FixedInputValueNodeT<2, Derived> {
  using Base = FixedInputValueNodeT<2, Derived>;

 public:
  static constexpr OpProperties kProperties =
      OpProperties::Float64() | OpProperties::Call();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kHoleyFloat64, ValueRepresentation::kHoleyFloat64};

  static constexpr int kLeftIndex = 0;
  static constexpr int kRightIndex = 1;
  Input& left_input() { return Node::input(kLeftIndex); }
  Input& right_input() { return Node::input(kRightIndex); }

 protected:
  explicit Float64BinaryNodeWithCall(uint64_t bitfield) : Base(bitfield) {}

  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

#define DEF_FLOAT64_BINARY_NODE(Name) \
  DEF_OPERATION_NODE(Float64##Name, Float64BinaryNode, Name)
#define DEF_FLOAT64_BINARY_NODE_WITH_CALL(Name) \
  DEF_OPERATION_NODE_WITH_CALL(Float64##Name, Float64BinaryNodeWithCall, Name)
DEF_FLOAT64_BINARY_NODE(Add)
DEF_FLOAT64_BINARY_NODE(Subtract)
DEF_FLOAT64_BINARY_NODE(Multiply)
DEF_FLOAT64_BINARY_NODE(Divide)
#if defined(V8_TARGET_ARCH_ARM64) || defined(V8_TARGET_ARCH_ARM) || \
    defined(V8_TARGET_ARCH_RISCV64)
// On Arm/Arm64/Riscv64, floating point modulus is implemented with a call to a
// C++ function, while on x64, it's implemented natively without call.
DEF_FLOAT64_BINARY_NODE_WITH_CALL(Modulus)
#else
DEF_FLOAT64_BINARY_NODE(Modulus)
#endif
DEF_FLOAT64_BINARY_NODE_WITH_CALL(Exponentiate)
#undef DEF_FLOAT64_BINARY_NODE
#undef DEF_FLOAT64_BINARY_NODE_WITH_CALL

#undef DEF_OPERATION_NODE
#undef DEF_OPERATION_NODE_WITH_CALL

class Float64Compare : public FixedInputValueNodeT<2, Float64Compare> {
  using Base = FixedInputValueNodeT<2, Float64Compare>;

 public:
  explicit Float64Compare(uint64_t bitfield, Operation operation)
      : Base(OperationBitField::update(bitfield, operation)) {}

  static constexpr Base::InputTypes kInputTypes{ValueRepresentation::kFloat64,
                                                ValueRepresentation::kFloat64};

  static constexpr int kLeftIndex = 0;
  static constexpr int kRightIndex = 1;
  Input& left_input() { return Node::input(kLeftIndex); }
  Input& right_input() { return Node::input(kRightIndex); }

  constexpr Operation operation() const {
    return OperationBitField::decode(bitfield());
  }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

  auto options() const { return std::tuple{operation()}; }

 private:
  using OperationBitField = NextBitField<Operation, 5>;
};

class Float64ToBoolean : public FixedInputValueNodeT<1, Float64ToBoolean> {
  using Base = FixedInputValueNodeT<1, Float64ToBoolean>;

 public:
  explicit Float64ToBoolean(uint64_t bitfield, bool flip)
      : Base(FlipBitField::update(bitfield, flip)) {}

  static constexpr Base::InputTypes kInputTypes{
      ValueRepresentation::kHoleyFloat64};

  Input& value() { return Node::input(0); }

  constexpr bool flip() const { return FlipBitField::decode(bitfield()); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

  auto options() const { return std::tuple{flip()}; }

 private:
  using FlipBitField = NextBitField<bool, 1>;
};

class Float64Negate : public FixedInputValueNodeT<1, Float64Negate> {
  using Base = FixedInputValueNodeT<1, Float64Negate>;

 public:
  explicit Float64Negate(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::Float64();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kHoleyFloat64};

  Input& input() { return Node::input(0); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

#define IEEE_754_UNARY_LIST(V) \
  V(MathAcos, acos, Acos)      \
  V(MathAcosh, acosh, Acosh)   \
  V(MathAsin, asin, Asin)      \
  V(MathAsinh, asinh, Asinh)   \
  V(MathAtan, atan, Atan)      \
  V(MathAtanh, atanh, Atanh)   \
  V(MathCbrt, cbrt, Cbrt)      \
  V(MathCos, cos, Cos)         \
  V(MathCosh, cosh, Cosh)      \
  V(MathExp, exp, Exp)         \
  V(MathExpm1, expm1, Expm1)   \
  V(MathLog, log, Log)         \
  V(MathLog1p, log1p, Log1p)   \
  V(MathLog10, log10, Log10)   \
  V(MathLog2, log2, Log2)      \
  V(MathSin, sin, Sin)         \
  V(MathSinh, sinh, Sinh)      \
  V(MathTan, tan, Tan)         \
  V(MathTanh, tanh, Tanh)
class Float64Ieee754Unary
    : public FixedInputValueNodeT<1, Float64Ieee754Unary> {
  using Base = FixedInputValueNodeT<1, Float64Ieee754Unary>;

 public:
  enum class Ieee754Function : uint8_t {
#define DECL_ENUM(MathName, ExtName, EnumName) k##EnumName,
    IEEE_754_UNARY_LIST(DECL_ENUM)
#undef DECL_ENUM
  };
  explicit Float64Ieee754Unary(uint64_t bitfield, Ieee754Function ieee_function)
      : Base(bitfield), ieee_function_(ieee_function) {}

  static constexpr OpProperties kProperties =
      OpProperties::Float64() | OpProperties::Call();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kHoleyFloat64};

  Input& input() { return Node::input(0); }

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

  auto options() const { return std::tuple{ieee_function_}; }

  Ieee754Function ieee_function() const { return ieee_function_; }
  ExternalReference ieee_function_ref() const;

 private:
  Ieee754Function ieee_function_;
};

class CheckInt32IsSmi : public FixedInputNodeT<1, CheckInt32IsSmi> {
  using Base = FixedInputNodeT<1, CheckInt32IsSmi>;

 public:
  explicit CheckInt32IsSmi(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::EagerDeopt();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kInt32};

  Input& input() { return Node::input(0); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class CheckUint32IsSmi : public FixedInputNodeT<1, CheckUint32IsSmi> {
  using Base = FixedInputNodeT<1, CheckUint32IsSmi>;

 public:
  explicit CheckUint32IsSmi(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::EagerDeopt();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kUint32};

  Input& input() { return Node::input(0); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class CheckHoleyFloat64IsSmi
    : public FixedInputNodeT<1, CheckHoleyFloat64IsSmi> {
  using Base = FixedInputNodeT<1, CheckHoleyFloat64IsSmi>;

 public:
  explicit CheckHoleyFloat64IsSmi(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::EagerDeopt();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kHoleyFloat64};

  Input& input() { return Node::input(0); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class CheckedSmiTagInt32 : public FixedInputValueNodeT<1, CheckedSmiTagInt32> {
  using Base = FixedInputValueNodeT<1, CheckedSmiTagInt32>;

 public:
  explicit CheckedSmiTagInt32(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties =
      OpProperties::EagerDeopt() | OpProperties::ConversionNode();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kInt32};

  Input& input() { return Node::input(0); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

// This is a check disguised as a conversion node so we can use it to override
// untagging conversions.
// TODO(olivf): Support overriding bigger with smaller instruction so we can use
// CheckInt32IsSmi instead.
class CheckedSmiSizedInt32
    : public FixedInputValueNodeT<1, CheckedSmiSizedInt32> {
  using Base = FixedInputValueNodeT<1, CheckedSmiSizedInt32>;

 public:
  explicit CheckedSmiSizedInt32(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::EagerDeopt() |
                                              OpProperties::Int32() |
                                              OpProperties::ConversionNode();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kInt32};

  Input& input() { return Node::input(0); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class CheckedSmiTagUint32
    : public FixedInputValueNodeT<1, CheckedSmiTagUint32> {
  using Base = FixedInputValueNodeT<1, CheckedSmiTagUint32>;

 public:
  explicit CheckedSmiTagUint32(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties =
      OpProperties::EagerDeopt() | OpProperties::ConversionNode();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kUint32};

  Input& input() { return Node::input(0); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

// Input must guarantee to fit in a Smi.
class UnsafeSmiTagInt32 : public FixedInputValueNodeT<1, UnsafeSmiTagInt32> {
  using Base = FixedInputValueNodeT<1, UnsafeSmiTagInt32>;

 public:
  explicit UnsafeSmiTagInt32(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::ConversionNode();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kInt32};

  Input& input() { return Node::input(0); }

#ifdef V8_COMPRESS_POINTERS
  void MarkTaggedInputsAsDecompressing() {
    // No tagged inputs.
  }
#endif

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

// Input must guarantee to fit in a Smi.
class UnsafeSmiTagUint32 : public FixedInputValueNodeT<1, UnsafeSmiTagUint32> {
  using Base = FixedInputValueNodeT<1, UnsafeSmiTagUint32>;

 public:
  explicit UnsafeSmiTagUint32(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::ConversionNode();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kUint32};

  Input& input() { return Node::input(0); }

#ifdef V8_COMPRESS_POINTERS
  void MarkTaggedInputsAsDecompressing() {
    // No tagged inputs.
  }
#endif

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class CheckedSmiUntag : public FixedInputValueNodeT<1, CheckedSmiUntag> {
  using Base = FixedInputValueNodeT<1, CheckedSmiUntag>;

 public:
  explicit CheckedSmiUntag(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::EagerDeopt() |
                                              OpProperties::Int32() |
                                              OpProperties::ConversionNode();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kTagged};

  Input& input() { return Node::input(0); }

#ifdef V8_COMPRESS_POINTERS
  void MarkTaggedInputsAsDecompressing() {
    // Don't need to decompress to untag.
  }
#endif

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class UnsafeSmiUntag : public FixedInputValueNodeT<1, UnsafeSmiUntag> {
  using Base = FixedInputValueNodeT<1, UnsafeSmiUntag>;

 public:
  explicit UnsafeSmiUntag(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties =
      OpProperties::Int32() | OpProperties::ConversionNode();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kTagged};

  Input& input() { return Node::input(0); }

#ifdef V8_COMPRESS_POINTERS
  void MarkTaggedInputsAsDecompressing() {
    // Don't need to decompress to untag.
  }
#endif

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class Int32Constant : public FixedInputValueNodeT<0, Int32Constant> {
  using Base = FixedInputValueNodeT<0, Int32Constant>;

 public:
  using OutputRegister = Register;

  explicit Int32Constant(uint64_t bitfield, int32_t value)
      : Base(bitfield), value_(value) {}

  static constexpr OpProperties kProperties = OpProperties::Int32();

  int32_t value() const { return value_; }

  bool ToBoolean(LocalIsolate* local_isolate) const { return value_ != 0; }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

  void DoLoadToRegister(MaglevAssembler*, OutputRegister);
  Handle<Object> DoReify(LocalIsolate* isolate) const;

 private:
  const int32_t value_;
};

class Uint32Constant : public FixedInputValueNodeT<0, Uint32Constant> {
  using Base = FixedInputValueNodeT<0, Uint32Constant>;

 public:
  using OutputRegister = Register;

  explicit Uint32Constant(uint64_t bitfield, uint32_t value)
      : Base(bitfield), value_(value) {}

  static constexpr OpProperties kProperties = OpProperties::Uint32();

  uint32_t value() const { return value_; }

  bool ToBoolean(LocalIsolate* local_isolate) const { return value_ != 0; }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

  void DoLoadToRegister(MaglevAssembler*, OutputRegister);
  Handle<Object> DoReify(LocalIsolate* isolate) const;

 private:
  const uint32_t value_;
};

class Float64Constant : public FixedInputValueNodeT<0, Float64Constant> {
  using Base = FixedInputValueNodeT<0, Float64Constant>;

 public:
  using OutputRegister = DoubleRegister;

  explicit Float64Constant(uint64_t bitfield, Float64 value)
      : Base(bitfield), value_(value) {}

  static constexpr OpProperties kProperties = OpProperties::Float64();

  Float64 value() const { return value_; }

  bool ToBoolean(LocalIsolate* local_isolate) const {
    return value_.get_scalar() != 0.0 && !value_.is_nan();
  }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

  void DoLoadToRegister(MaglevAssembler*, OutputRegister);
  Handle<Object> DoReify(LocalIsolate* isolate) const;

 private:
  const Float64 value_;
};

class Int32ToUint8Clamped
    : public FixedInputValueNodeT<1, Int32ToUint8Clamped> {
  using Base = FixedInputValueNodeT<1, Int32ToUint8Clamped>;

 public:
  explicit Int32ToUint8Clamped(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::Int32();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kInt32};

  Input& input() { return Node::input(0); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class Uint32ToUint8Clamped
    : public FixedInputValueNodeT<1, Uint32ToUint8Clamped> {
  using Base = FixedInputValueNodeT<1, Uint32ToUint8Clamped>;

 public:
  explicit Uint32ToUint8Clamped(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::Int32();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kUint32};

  Input& input() { return Node::input(0); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class Float64ToUint8Clamped
    : public FixedInputValueNodeT<1, Float64ToUint8Clamped> {
  using Base = FixedInputValueNodeT<1, Float64ToUint8Clamped>;

 public:
  explicit Float64ToUint8Clamped(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::Int32();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kHoleyFloat64};

  Input& input() { return Node::input(0); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class CheckedNumberToUint8Clamped
    : public FixedInputValueNodeT<1, CheckedNumberToUint8Clamped> {
  using Base = FixedInputValueNodeT<1, CheckedNumberToUint8Clamped>;

 public:
  explicit CheckedNumberToUint8Clamped(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties =
      OpProperties::EagerDeopt() | OpProperties::Int32();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kTagged};

  Input& input() { return Node::input(0); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class Int32ToNumber : public FixedInputValueNodeT<1, Int32ToNumber> {
  using Base = FixedInputValueNodeT<1, Int32ToNumber>;

 public:
  explicit Int32ToNumber(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::CanAllocate() |
                                              OpProperties::DeferredCall() |
                                              OpProperties::ConversionNode();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kInt32};

  Input& input() { return Node::input(0); }

  int MaxCallStackArgs() const { return 0; }
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class Uint32ToNumber : public FixedInputValueNodeT<1, Uint32ToNumber> {
  using Base = FixedInputValueNodeT<1, Uint32ToNumber>;

 public:
  explicit Uint32ToNumber(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::CanAllocate() |
                                              OpProperties::DeferredCall() |
                                              OpProperties::ConversionNode();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kUint32};

  Input& input() { return Node::input(0); }

  int MaxCallStackArgs() const { return 0; }
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class Float64ToTagged : public FixedInputValueNodeT<1, Float64ToTagged> {
  using Base = FixedInputValueNodeT<1, Float64ToTagged>;

 public:
  enum class ConversionMode { kCanonicalizeSmi, kForceHeapNumber };
  explicit Float64ToTagged(uint64_t bitfield, ConversionMode mode)
      : Base(ConversionModeBitField::update(bitfield, mode)) {}
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kFloat64};

  static constexpr OpProperties kProperties = OpProperties::CanAllocate() |
                                              OpProperties::DeferredCall() |
                                              OpProperties::ConversionNode();

  Input& input() { return Node::input(0); }

  int MaxCallStackArgs() const { return 0; }
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}

  auto options() const { return std::tuple{conversion_mode()}; }

  ConversionMode conversion_mode() const {
    return ConversionModeBitField::decode(bitfield());
  }

 private:
  bool canonicalize_smi() {
    return ConversionModeBitField::decode(bitfield()) ==
           ConversionMode::kCanonicalizeSmi;
  }

  using ConversionModeBitField = NextBitField<ConversionMode, 1>;
};

// Essentially the same as Float64ToTagged but the result cannot be shared as it
// will be used as a mutable heap number by a store.
class Float64ToHeapNumberForField
    : public FixedInputValueNodeT<1, Float64ToHeapNumberForField> {
  using Base = FixedInputValueNodeT<1, Float64ToHeapNumberForField>;

 public:
  explicit Float64ToHeapNumberForField(uint64_t bitfield) : Base(bitfield) {}
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation:
```