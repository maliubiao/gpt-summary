Response:
Let's break down the thought process for analyzing this V8 source code snippet.

**1. Initial Scan and Keyword Identification:**

The first step is to quickly scan the code looking for keywords and patterns that give clues about its functionality. I see things like:

* `#include`:  Indicates C++ header files being included. These hint at dependencies and areas the code interacts with (`src/compiler/graph-assembler.h`, `src/codegen/callable.h`, etc.).
* `namespace v8 { namespace internal { namespace compiler {`:  Confirms the location within the V8 codebase.
* `class GraphAssembler`, `class JSGraphAssembler`:  These are the main entities. The name "Assembler" strongly suggests code generation or manipulation of some underlying representation. "Graph" suggests it's working with a graph-based intermediate representation (IR).
* Member variables like `mcgraph_`, `effect_`, `control_`, `inline_reducers_`, `loop_headers_`: These provide more hints about internal state and responsibilities. `effect_` and `control_` are common in compiler IRs.
* Methods with names like `IntPtrConstant`, `Uint32Constant`, `Float64Constant`, `LoadField`, `StoreElement`, `Branch`, `Return`: These clearly point to operations for building and manipulating the IR graph.
* Macros like `PURE_UNOP_DEF`, `PURE_BINOP_DEF`, `JSGRAPH_SINGLETON_CONSTANT_LIST`: These are code generation patterns to create similar functions.

**2. High-Level Functionality Deduction:**

Based on the initial scan, I can form a preliminary hypothesis:

* **Core Purpose:** This code seems to be about constructing and manipulating a graph representation, likely used in the V8 compiler. It provides an interface for generating nodes in this graph.
* **`GraphAssembler` vs. `JSGraphAssembler`:** The distinction suggests that `GraphAssembler` is a more general-purpose graph builder, while `JSGraphAssembler` is specialized for JavaScript-related operations and likely builds upon `GraphAssembler`.

**3. Deeper Dive into Specific Features (Iterative Process):**

Now, I start looking at specific code blocks and try to understand their purpose. This is an iterative process:

* **Constants:**  The `*Constant` methods (`IntPtrConstant`, `SmiConstant`, `Float64Constant`, etc.) are straightforward. They create constant nodes in the graph. The presence of `JSGraphAssembler::SmiConstant` and `GraphAssembler::IntPtrConstant` reinforces the specialization idea.
* **Parameters:** `Parameter(int index)` gets parameters passed to the current function/code being generated.
* **Memory Operations:** `Load*` and `Store*` methods (`LoadField`, `StoreElement`) are clearly for accessing memory, a fundamental operation in compilation. The `AccessBuilder` suggests a way to describe memory layouts.
* **Control Flow:** Methods like `Branch`, `Goto`, `Return`, `If` are for managing the flow of execution in the generated code. The `Block` construct is related to scoping.
* **Arithmetic and Logical Operations:** The `PURE_UNOP_DEF` and `PURE_BINOP_DEF` macros define a lot of basic arithmetic and logical operations. The naming convention (`Int32Add`, `WordEqual`, etc.) is informative.
* **JavaScript-Specific Operations:**  `JSGraphAssembler` has methods like `LoadMap`, `StringLength`, `ObjectIsCallable`, `CheckSmi`, `ToBoolean`, which are directly related to JavaScript semantics.
* **ArrayBufferView Handling:** The `ArrayBufferViewAccessBuilder` is a more complex piece, handling the intricacies of accessing data in typed arrays and DataViews, including considerations for resizable and growable buffers (RAB/GSAB). This part requires careful reading to grasp the different scenarios.
* **Assertions and Checks:** `Assert` and `CheckIf` are for runtime verification and potential deoptimization.

**4. Answering Specific Questions (Applying the Knowledge):**

With a good understanding of the code, I can address the specific questions in the prompt:

* **Functionality:** Summarize the key capabilities identified in the previous steps.
* **Torque:** Check the file extension. It's `.cc`, so it's C++, not Torque.
* **JavaScript Relationship:**  Identify the methods in `JSGraphAssembler` that directly correspond to JavaScript concepts and provide illustrative JavaScript examples. Focus on the *effect* of the generated code, not the low-level implementation.
* **Code Logic Reasoning:** Select a simpler example (like `IntPtrAdd`) and demonstrate how it creates a node in the graph. Provide simple input and the expected output *in terms of the graph node created*. For more complex logic like `ArrayBufferViewAccessBuilder`, the "input" would be the state of the `JSArrayBufferView`, and the "output" would be the computed length.
* **Common Programming Errors:** Think about what kinds of errors this code helps *prevent* or *detect* during compilation. Type errors and invalid memory access are good examples. Illustrate with hypothetical JavaScript code that might trigger these issues.

**5. Structuring the Answer:**

Finally, organize the findings into a clear and structured answer, addressing each point in the prompt. Use headings and bullet points to improve readability.

**Self-Correction/Refinement During the Process:**

* **Initial Misinterpretations:**  I might initially misinterpret a method's purpose. Reading the code carefully and looking at the context of its usage can correct this.
* **Overlooking Details:** I might miss some nuances on the first pass. Rereading specific sections, especially around more complex logic like `ArrayBufferViewAccessBuilder`, is crucial.
* **Clarity of Explanation:**  I need to ensure the explanations are clear and concise, avoiding overly technical jargon where possible, while still being accurate. The JavaScript examples should be easy to understand.

By following this kind of systematic approach, combining scanning, deduction, detailed analysis, and targeted question answering, I can effectively analyze and explain the functionality of a complex piece of source code like `graph-assembler.cc`.
这是对V8源代码文件 `v8/src/compiler/graph-assembler.cc` 的分析。

**功能归纳:**

`v8/src/compiler/graph-assembler.cc` 文件的主要功能是提供一个高级接口，用于在 V8 的编译器中构建中间表示 (IR) 图。这个图是代码优化的基础，最终会被转换成机器码。`GraphAssembler` 和 `JSGraphAssembler` 类提供了各种方法来创建表示不同操作和数据的节点，以及管理控制流。

**具体功能点:**

1. **创建常量节点:**
   - 提供创建各种类型常量节点的方法，如整数 (`IntPtrConstant`, `Int32Constant`, `Int64Constant`, `UintPtrConstant`, `Uint32Constant`, `Uint64Constant`), 浮点数 (`Float64Constant`), Smi (`SmiConstant`), 堆对象 (`HeapConstant`), 常量对象引用 (`Constant`),  外部引用 (`ExternalConstant`)等。

2. **访问运行时环境:**
   - 提供访问 Isolate 字段 (`IsolateField`)、函数参数 (`Parameter`)、C 入口桩 (`CEntryStubConstant`)、帧指针 (`LoadFramePointer`)、根寄存器 (`LoadRootRegister`) 和栈指针 (`LoadStackPointer`, `SetStackPointer`) 的方法。

3. **加载和存储操作:**
   - 提供加载堆对象字段 (`LoadField`)、加载数组元素 (`LoadElement`)、存储堆对象字段 (`StoreField`) 和存储数组元素 (`StoreElement`) 的方法。这些方法需要 `AccessBuilder` 和 `ElementAccess` 对象来描述访问的细节。
   - 提供加载 HeapNumber 的值 (`LoadHeapNumberValue`)。

4. **单例常量:**
   - 定义并提供访问各种 V8 单例常量的方法，例如 `UndefinedConstant`, `NullConstant`, `TrueConstant`, `FalseConstant`, `TheHoleConstant` 等。并提供检查对象是否为这些单例的方法，例如 `IsUndefined`, `IsNull` 等。

5. **基本运算:**
   - 提供各种一元和二元运算的节点创建方法，包括算术运算 (`Int32Add`, `Int64Sub`, `Float64Mul` 等), 位运算 (`Word32And`, `Word64Or`), 比较运算 (`Int32LessThan`, `Float64Equal`), 类型转换 (`ChangeFloat64ToInt32`) 等。

6. **类型转换和检查:**
   - 提供创建类型转换节点的方法，例如将浮点数截断为整数 (`TruncateFloat64ToInt64`)。
   - 提供创建类型检查节点的方法，例如检查是否为 Smi (`CheckSmi`), 检查是否为 Number (`CheckNumber`), 以及通用的条件检查 (`CheckIf`)。

7. **控制流操作:**
   - 提供创建投影节点 (`Projection`)，用于从具有多个输出的节点中提取特定的输出。
   - 虽然这段代码没有直接展示分支和循环的创建，但 `GraphAssembler` 的设计支持构建复杂的控制流图。

8. **内存分配:**
   - 提供分配内存的节点创建方法 (`Allocate`).

9. **JavaScript 特有操作:**
   - `JSGraphAssembler` 继承自 `GraphAssembler`，并添加了更多与 JavaScript 语义相关的操作，例如：
     - 加载 Map (`LoadMap`) 和 ElementsKind (`LoadElementsKind`).
     - 获取字符串长度 (`StringLength`) 和子字符串 (`StringSubstring`).
     - 比较对象引用 (`ReferenceEqual`) 和数值 (`NumberEqual`).
     - 执行数值运算 (`NumberAdd`, `NumberSubtract`, `NumberMin`, `NumberMax` 等)。
     - 类型转换 (`ToBoolean`, `ConvertTaggedHoleToUndefined`).
     - 对象类型检查 (`ObjectIsCallable`, `ObjectIsSmi`, `ObjectIsUndetectable`).
     - 数组操作 (`MaybeGrowFastElements`, `DoubleArrayMax`, `DoubleArrayMin`).
     - 字符串操作 (`StringCharCodeAt`, `StringFromSingleCharCode`).

10. **断言:**
    - 提供创建断言节点的方法 (`Assert`)，用于在编译后的代码中插入运行时检查。

11. **ArrayBufferView 处理:**
    - `ArrayBufferViewAccessBuilder` 类提供了一组用于构建访问 `JSArrayBufferView` 对象（例如 TypedArray 和 DataView）的逻辑。这包括计算长度、字节长度，并处理不同类型的 ArrayBufferView（包括支持 ResizableArrayBuffer 和 GrowableSharedArrayBuffer 的情况）。

**关于文件类型和 JavaScript 关系:**

- `v8/src/compiler/graph-assembler.cc` 的文件扩展名是 `.cc`，这意味着它是一个 **C++ 源代码文件**，而不是 Torque 源代码。
- **它与 JavaScript 的功能有密切关系**。`JSGraphAssembler` 类构建的图直接对应 JavaScript 代码的语义。编译器使用这个图进行优化，最终生成执行 JavaScript 代码的机器码。

**JavaScript 举例说明:**

假设有以下 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}
```

当 V8 编译这个 `add` 函数时，`JSGraphAssembler` 可能会生成类似以下的节点来表示 `a + b` 这个操作：

```c++
// 假设 gasm 是 JSGraphAssembler 的实例， parameter0 代表参数 a， parameter1 代表参数 b
TNode<Number> left = gasm->Parameter(0); // 获取参数 a
TNode<Number> right = gasm->Parameter(1); // 获取参数 b
TNode<Number> sum = gasm->NumberAdd(left, right); // 创建 NumberAdd 节点
gasm->Return(sum); // 创建 Return 节点返回结果
```

在这个例子中，`NumberAdd` 方法创建了一个表示 JavaScript 加法运算的节点。

**代码逻辑推理和假设输入/输出:**

考虑 `GraphAssembler::Int32Constant(int32_t value)` 方法：

**假设输入:** `value = 10`

**代码逻辑:**  `Int32Constant` 方法会调用 `mcgraph()->Int32Constant(value)` 来创建一个表示 32 位整数常量的节点，并将其添加到当前的图中。

**输出:**  返回一个指向新创建的 `Node` 对象的指针，该节点表示值为 10 的 32 位整数常量。这个节点的类型可能是 `IrOpcode::kInt32Constant`。

考虑 `JSGraphAssembler::NumberAdd(TNode<Number> lhs, TNode<Number> rhs)` 方法：

**假设输入:** `lhs` 是一个表示变量 `a` 的 `TNode<Number>`，`rhs` 是一个表示变量 `b` 的 `TNode<Number>`.

**代码逻辑:** `NumberAdd` 方法会创建一个新的 `Node` 对象，其操作码是 `IrOpcode::kNumberAdd`，并将 `lhs` 和 `rhs` 作为输入连接到这个新节点。

**输出:** 返回一个指向新创建的 `Node` 对象的指针，该节点表示将 `lhs` 和 `rhs` 相加的 JavaScript 数值加法运算。

**涉及用户常见的编程错误:**

`GraphAssembler` 和 `JSGraphAssembler` 本身是编译器内部使用的工具，开发者不会直接编写这些代码。然而，它们的设计目标之一是正确地表示 JavaScript 的语义，包括处理用户可能犯的错误。例如：

1. **类型错误:**  如果 JavaScript 代码尝试将一个非数值类型的值与数值相加，编译器生成的图会包含相应的类型检查节点 (`CheckNumber`)。如果类型检查失败，可能会导致 deoptimization。

   ```javascript
   function addOne(x) {
     return x + 1;
   }
   addOne("hello"); // 常见的类型错误
   ```

   在编译 `addOne` 时，`JSGraphAssembler` 可能会生成 `CheckNumber` 节点来确保 `x` 是一个数值。

2. **未定义的属性访问:**  如果代码尝试访问未定义对象的属性，编译器可能会生成加载属性的节点，但后续的优化或执行过程会处理 `undefined` 值。

   ```javascript
   const obj = {};
   console.log(obj.name.length); // 访问未定义属性
   ```

   虽然 `GraphAssembler` 不直接处理这种错误，但它构建的图会表示属性访问，并且后续的编译器阶段和运行时系统会处理 `obj.name` 为 `undefined` 的情况。

**总结 `v8/src/compiler/graph-assembler.cc` 的功能 (第 1 部分):**

`v8/src/compiler/graph-assembler.cc` 的第 1 部分主要定义了 `GraphAssembler` 和 `JSGraphAssembler` 类的基础架构和核心功能，用于创建和操作编译器中间表示图中的各种节点。它提供了创建常量、访问运行时环境、执行基本运算、加载/存储数据以及处理 JavaScript 特有操作的方法。`ArrayBufferViewAccessBuilder` 的定义表明了对 TypedArray 和 DataView 等复杂数据结构的特殊处理。这个文件的目的是为 V8 编译器提供一个方便且类型安全的方式来构建用于代码优化和生成的图表示。

### 提示词
```
这是目录为v8/src/compiler/graph-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/graph-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/graph-assembler.h"

#include <optional>

#include "src/base/container-utils.h"
#include "src/codegen/callable.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/tnode.h"
#include "src/common/globals.h"
#include "src/compiler/access-builder.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/graph-reducer.h"
#include "src/compiler/linkage.h"
#include "src/compiler/type-cache.h"
// For TNode types.
#include "src/deoptimizer/deoptimize-reason.h"
#include "src/objects/elements-kind.h"
#include "src/objects/heap-number.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-array-buffer.h"
#include "src/objects/oddball.h"
#include "src/objects/string.h"

namespace v8 {
namespace internal {
namespace compiler {

class V8_NODISCARD GraphAssembler::BlockInlineReduction {
 public:
  explicit BlockInlineReduction(GraphAssembler* gasm) : gasm_(gasm) {
    DCHECK(!gasm_->inline_reductions_blocked_);
    gasm_->inline_reductions_blocked_ = true;
  }
  ~BlockInlineReduction() {
    DCHECK(gasm_->inline_reductions_blocked_);
    gasm_->inline_reductions_blocked_ = false;
  }

 private:
  GraphAssembler* gasm_;
};

GraphAssembler::GraphAssembler(
    MachineGraph* mcgraph, Zone* zone, BranchSemantics default_branch_semantics,
    std::optional<NodeChangedCallback> node_changed_callback,
    bool mark_loop_exits)
    : temp_zone_(zone),
      mcgraph_(mcgraph),
      default_branch_semantics_(default_branch_semantics),
      effect_(nullptr),
      control_(nullptr),
      node_changed_callback_(node_changed_callback),
      inline_reducers_(zone),
      inline_reductions_blocked_(false),
      loop_headers_(zone),
      mark_loop_exits_(mark_loop_exits) {
  DCHECK_NE(default_branch_semantics_, BranchSemantics::kUnspecified);
}

GraphAssembler::~GraphAssembler() { DCHECK_EQ(loop_nesting_level_, 0); }

Node* GraphAssembler::IntPtrConstant(intptr_t value) {
  return AddClonedNode(mcgraph()->IntPtrConstant(value));
}

TNode<UintPtrT> GraphAssembler::UintPtrConstant(uintptr_t value) {
  return TNode<UintPtrT>::UncheckedCast(mcgraph()->UintPtrConstant(value));
}

Node* GraphAssembler::Int32Constant(int32_t value) {
  return AddClonedNode(mcgraph()->Int32Constant(value));
}

TNode<Uint32T> GraphAssembler::Uint32Constant(uint32_t value) {
  return TNode<Uint32T>::UncheckedCast(mcgraph()->Uint32Constant(value));
}

Node* GraphAssembler::Int64Constant(int64_t value) {
  return AddClonedNode(mcgraph()->Int64Constant(value));
}

Node* GraphAssembler::Uint64Constant(uint64_t value) {
  return AddClonedNode(mcgraph()->Uint64Constant(value));
}

Node* GraphAssembler::UniqueIntPtrConstant(intptr_t value) {
  return AddNode(graph()->NewNode(
      machine()->Is64()
          ? common()->Int64Constant(value)
          : common()->Int32Constant(static_cast<int32_t>(value))));
}

Node* JSGraphAssembler::SmiConstant(int32_t value) {
  return AddClonedNode(jsgraph()->SmiConstant(value));
}

Node* GraphAssembler::Float64Constant(double value) {
  return AddClonedNode(mcgraph()->Float64Constant(value));
}

TNode<HeapObject> JSGraphAssembler::HeapConstant(Handle<HeapObject> object) {
  return TNode<HeapObject>::UncheckedCast(
      AddClonedNode(jsgraph()->HeapConstantNoHole(object)));
}

TNode<Object> JSGraphAssembler::Constant(ObjectRef ref) {
  return TNode<Object>::UncheckedCast(
      AddClonedNode(jsgraph()->ConstantNoHole(ref, broker())));
}

TNode<Number> JSGraphAssembler::NumberConstant(double value) {
  return TNode<Number>::UncheckedCast(
      AddClonedNode(jsgraph()->ConstantNoHole(value)));
}

Node* GraphAssembler::ExternalConstant(ExternalReference ref) {
  return AddClonedNode(mcgraph()->ExternalConstant(ref));
}

Node* GraphAssembler::IsolateField(IsolateFieldId id) {
  return ExternalConstant(ExternalReference::Create(id));
}

Node* GraphAssembler::Parameter(int index) {
  return AddNode(
      graph()->NewNode(common()->Parameter(index), graph()->start()));
}

Node* JSGraphAssembler::CEntryStubConstant(int result_size) {
  return AddClonedNode(jsgraph()->CEntryStubConstant(result_size));
}

Node* GraphAssembler::LoadFramePointer() {
  return AddNode(graph()->NewNode(machine()->LoadFramePointer()));
}

Node* GraphAssembler::LoadRootRegister() {
  return AddNode(graph()->NewNode(machine()->LoadRootRegister()));
}

#if V8_ENABLE_WEBASSEMBLY
Node* GraphAssembler::LoadStackPointer() {
  return AddNode(graph()->NewNode(machine()->LoadStackPointer(), effect()));
}

Node* GraphAssembler::SetStackPointer(Node* node) {
  return AddNode(
      graph()->NewNode(machine()->SetStackPointer(), node, effect()));
}
#endif

Node* GraphAssembler::LoadHeapNumberValue(Node* heap_number) {
  return Load(MachineType::Float64(), heap_number,
              IntPtrConstant(offsetof(HeapNumber, value_) - kHeapObjectTag));
}

#define SINGLETON_CONST_DEF(Name, Type)              \
  TNode<Type> JSGraphAssembler::Name##Constant() {   \
    return TNode<Type>::UncheckedCast(               \
        AddClonedNode(jsgraph()->Name##Constant())); \
  }
JSGRAPH_SINGLETON_CONSTANT_LIST(SINGLETON_CONST_DEF)
#undef SINGLETON_CONST_DEF

#define SINGLETON_CONST_TEST_DEF(Name, ...)                        \
  TNode<Boolean> JSGraphAssembler::Is##Name(TNode<Object> value) { \
    return TNode<Boolean>::UncheckedCast(                          \
        ReferenceEqual(value, Name##Constant()));                  \
  }
JSGRAPH_SINGLETON_CONSTANT_LIST(SINGLETON_CONST_TEST_DEF)
#undef SINGLETON_CONST_TEST_DEF

#define PURE_UNOP_DEF(Name)                                     \
  Node* GraphAssembler::Name(Node* input) {                     \
    return AddNode(graph()->NewNode(machine()->Name(), input)); \
  }
PURE_ASSEMBLER_MACH_UNOP_LIST(PURE_UNOP_DEF)
#undef PURE_UNOP_DEF

#define PURE_BINOP_DEF(Name)                                          \
  Node* GraphAssembler::Name(Node* left, Node* right) {               \
    return AddNode(graph()->NewNode(machine()->Name(), left, right)); \
  }
#define PURE_BINOP_DEF_TNODE(Name, Result, Left, Right)                       \
  TNode<Result> GraphAssembler::Name(SloppyTNode<Left> left,                  \
                                     SloppyTNode<Right> right) {              \
    return AddNode<Result>(graph()->NewNode(machine()->Name(), left, right)); \
  }
PURE_ASSEMBLER_MACH_BINOP_LIST(PURE_BINOP_DEF, PURE_BINOP_DEF_TNODE)
#undef PURE_BINOP_DEF
#undef PURE_BINOP_DEF_TNODE

TNode<BoolT> GraphAssembler::UintPtrLessThan(TNode<UintPtrT> left,
                                             TNode<UintPtrT> right) {
  return kSystemPointerSize == 8
             ? Uint64LessThan(TNode<Uint64T>::UncheckedCast(left),
                              TNode<Uint64T>::UncheckedCast(right))
             : Uint32LessThan(TNode<Uint32T>::UncheckedCast(left),
                              TNode<Uint32T>::UncheckedCast(right));
}

TNode<BoolT> GraphAssembler::UintPtrLessThanOrEqual(TNode<UintPtrT> left,
                                                    TNode<UintPtrT> right) {
  return kSystemPointerSize == 8
             ? Uint64LessThanOrEqual(TNode<Uint64T>::UncheckedCast(left),
                                     TNode<Uint64T>::UncheckedCast(right))
             : Uint32LessThanOrEqual(TNode<Uint32T>::UncheckedCast(left),
                                     TNode<Uint32T>::UncheckedCast(right));
}

TNode<UintPtrT> GraphAssembler::UintPtrAdd(TNode<UintPtrT> left,
                                           TNode<UintPtrT> right) {
  return kSystemPointerSize == 8
             ? TNode<UintPtrT>::UncheckedCast(Int64Add(left, right))
             : TNode<UintPtrT>::UncheckedCast(Int32Add(left, right));
}
TNode<UintPtrT> GraphAssembler::UintPtrSub(TNode<UintPtrT> left,
                                           TNode<UintPtrT> right) {
  return kSystemPointerSize == 8
             ? TNode<UintPtrT>::UncheckedCast(Int64Sub(left, right))
             : TNode<UintPtrT>::UncheckedCast(Int32Sub(left, right));
}

TNode<UintPtrT> GraphAssembler::UintPtrDiv(TNode<UintPtrT> left,
                                           TNode<UintPtrT> right) {
  return kSystemPointerSize == 8
             ? TNode<UintPtrT>::UncheckedCast(Uint64Div(left, right))
             : TNode<UintPtrT>::UncheckedCast(Uint32Div(left, right));
}

TNode<UintPtrT> GraphAssembler::ChangeUint32ToUintPtr(
    SloppyTNode<Uint32T> value) {
  return kSystemPointerSize == 8
             ? TNode<UintPtrT>::UncheckedCast(ChangeUint32ToUint64(value))
             : TNode<UintPtrT>::UncheckedCast(value);
}

#define CHECKED_BINOP_DEF(Name)                                       \
  Node* GraphAssembler::Name(Node* left, Node* right) {               \
    return AddNode(                                                   \
        graph()->NewNode(machine()->Name(), left, right, control())); \
  }
CHECKED_ASSEMBLER_MACH_BINOP_LIST(CHECKED_BINOP_DEF)
#undef CHECKED_BINOP_DEF

Node* GraphAssembler::IntPtrEqual(Node* left, Node* right) {
  return WordEqual(left, right);
}

Node* GraphAssembler::TaggedEqual(Node* left, Node* right) {
  if (COMPRESS_POINTERS_BOOL) {
    return Word32Equal(left, right);
  } else {
    return WordEqual(left, right);
  }
}

Node* GraphAssembler::SmiSub(Node* left, Node* right) {
  if (COMPRESS_POINTERS_BOOL) {
    return BitcastWord32ToWord64(Int32Sub(left, right));
  } else {
    return IntSub(left, right);
  }
}

Node* GraphAssembler::SmiLessThan(Node* left, Node* right) {
  if (COMPRESS_POINTERS_BOOL) {
    return Int32LessThan(left, right);
  } else {
    return IntLessThan(left, right);
  }
}

Node* GraphAssembler::Float64RoundDown(Node* value) {
  CHECK(machine()->Float64RoundDown().IsSupported());
  return AddNode(graph()->NewNode(machine()->Float64RoundDown().op(), value));
}

Node* GraphAssembler::Float64RoundTruncate(Node* value) {
  CHECK(machine()->Float64RoundTruncate().IsSupported());
  return AddNode(
      graph()->NewNode(machine()->Float64RoundTruncate().op(), value));
}

Node* GraphAssembler::TruncateFloat64ToInt64(Node* value, TruncateKind kind) {
  return AddNode(
      graph()->NewNode(machine()->TruncateFloat64ToInt64(kind), value));
}

Node* GraphAssembler::Projection(int index, Node* value, Node* ctrl) {
  return AddNode(graph()->NewNode(common()->Projection(index), value,
                                  ctrl ? ctrl : control()));
}

Node* JSGraphAssembler::Allocate(AllocationType allocation, Node* size) {
  return AddNode(
      graph()->NewNode(simplified()->AllocateRaw(Type::Any(), allocation), size,
                       effect(), control()));
}

TNode<Map> JSGraphAssembler::LoadMap(TNode<HeapObject> object) {
  return TNode<Map>::UncheckedCast(LoadField(AccessBuilder::ForMap(), object));
}

Node* JSGraphAssembler::LoadField(FieldAccess const& access, Node* object) {
  Node* value = AddNode(graph()->NewNode(simplified()->LoadField(access),
                                         object, effect(), control()));
  return value;
}

TNode<Uint32T> JSGraphAssembler::LoadElementsKind(TNode<Map> map) {
  TNode<Uint8T> bit_field2 = EnterMachineGraph<Uint8T>(
      LoadField<Uint8T>(AccessBuilder::ForMapBitField2(), map),
      UseInfo::TruncatingWord32());
  return TNode<Uint32T>::UncheckedCast(
      Word32Shr(TNode<Word32T>::UncheckedCast(bit_field2),
                Uint32Constant(Map::Bits2::ElementsKindBits::kShift)));
}

Node* JSGraphAssembler::LoadElement(ElementAccess const& access, Node* object,
                                    Node* index) {
  Node* value = AddNode(graph()->NewNode(simplified()->LoadElement(access),
                                         object, index, effect(), control()));
  return value;
}

Node* JSGraphAssembler::StoreField(FieldAccess const& access, Node* object,
                                   Node* value) {
  return AddNode(graph()->NewNode(simplified()->StoreField(access), object,
                                  value, effect(), control()));
}

Node* JSGraphAssembler::ClearPendingMessage() {
  ExternalReference const ref =
      ExternalReference::address_of_pending_message(isolate());
  return AddNode(graph()->NewNode(
      simplified()->StoreMessage(), jsgraph()->ExternalConstant(ref),
      jsgraph()->TheHoleConstant(), effect(), control()));
}

#ifdef V8_MAP_PACKING
TNode<Map> GraphAssembler::UnpackMapWord(Node* map_word) {
  map_word = BitcastTaggedToWordForTagAndSmiBits(map_word);
  // TODO(wenyuzhao): Clear header metadata.
  Node* map = WordXor(map_word, IntPtrConstant(Internals::kMapWordXorMask));
  return TNode<Map>::UncheckedCast(BitcastWordToTagged(map));
}

Node* GraphAssembler::PackMapWord(TNode<Map> map) {
  Node* map_word = BitcastTaggedToWordForTagAndSmiBits(map);
  Node* packed = WordXor(map_word, IntPtrConstant(Internals::kMapWordXorMask));
  return BitcastWordToTaggedSigned(packed);
}
#endif

TNode<Map> GraphAssembler::LoadMap(Node* object) {
  Node* map_word = Load(MachineType::TaggedPointer(), object,
                        HeapObject::kMapOffset - kHeapObjectTag);
#ifdef V8_MAP_PACKING
  return UnpackMapWord(map_word);
#else
  return TNode<Map>::UncheckedCast(map_word);
#endif
}

Node* JSGraphAssembler::StoreElement(ElementAccess const& access, Node* object,
                                     Node* index, Node* value) {
  return AddNode(graph()->NewNode(simplified()->StoreElement(access), object,
                                  index, value, effect(), control()));
}

void JSGraphAssembler::TransitionAndStoreElement(MapRef double_map,
                                                 MapRef fast_map,
                                                 TNode<HeapObject> object,
                                                 TNode<Number> index,
                                                 TNode<Object> value) {
  AddNode(graph()->NewNode(
      simplified()->TransitionAndStoreElement(double_map, fast_map), object,
      index, value, effect(), control()));
}

TNode<Number> JSGraphAssembler::StringLength(TNode<String> string) {
  return AddNode<Number>(
      graph()->NewNode(simplified()->StringLength(), string));
}

TNode<Boolean> JSGraphAssembler::ReferenceEqual(TNode<Object> lhs,
                                                TNode<Object> rhs) {
  return AddNode<Boolean>(
      graph()->NewNode(simplified()->ReferenceEqual(), lhs, rhs));
}

TNode<Boolean> JSGraphAssembler::NumberEqual(TNode<Number> lhs,
                                             TNode<Number> rhs) {
  return AddNode<Boolean>(
      graph()->NewNode(simplified()->NumberEqual(), lhs, rhs));
}

TNode<Number> JSGraphAssembler::NumberMin(TNode<Number> lhs,
                                          TNode<Number> rhs) {
  return AddNode<Number>(graph()->NewNode(simplified()->NumberMin(), lhs, rhs));
}

TNode<Number> JSGraphAssembler::NumberMax(TNode<Number> lhs,
                                          TNode<Number> rhs) {
  return AddNode<Number>(graph()->NewNode(simplified()->NumberMax(), lhs, rhs));
}

TNode<Number> JSGraphAssembler::NumberAdd(TNode<Number> lhs,
                                          TNode<Number> rhs) {
  return AddNode<Number>(graph()->NewNode(simplified()->NumberAdd(), lhs, rhs));
}

TNode<Number> JSGraphAssembler::NumberSubtract(TNode<Number> lhs,
                                               TNode<Number> rhs) {
  return AddNode<Number>(
      graph()->NewNode(simplified()->NumberSubtract(), lhs, rhs));
}

TNode<Boolean> JSGraphAssembler::NumberLessThan(TNode<Number> lhs,
                                                TNode<Number> rhs) {
  return AddNode<Boolean>(
      graph()->NewNode(simplified()->NumberLessThan(), lhs, rhs));
}

TNode<Boolean> JSGraphAssembler::NumberLessThanOrEqual(TNode<Number> lhs,
                                                       TNode<Number> rhs) {
  return AddNode<Boolean>(
      graph()->NewNode(simplified()->NumberLessThanOrEqual(), lhs, rhs));
}

TNode<Number> JSGraphAssembler::NumberShiftRightLogical(TNode<Number> lhs,
                                                        TNode<Number> rhs) {
  return AddNode<Number>(
      graph()->NewNode(simplified()->NumberShiftRightLogical(), lhs, rhs));
}

TNode<Number> JSGraphAssembler::NumberBitwiseAnd(TNode<Number> lhs,
                                                 TNode<Number> rhs) {
  return AddNode<Number>(
      graph()->NewNode(simplified()->NumberBitwiseAnd(), lhs, rhs));
}

TNode<Number> JSGraphAssembler::NumberBitwiseOr(TNode<Number> lhs,
                                                TNode<Number> rhs) {
  return AddNode<Number>(
      graph()->NewNode(simplified()->NumberBitwiseOr(), lhs, rhs));
}

TNode<String> JSGraphAssembler::StringSubstring(TNode<String> string,
                                                TNode<Number> from,
                                                TNode<Number> to) {
  return AddNode<String>(graph()->NewNode(
      simplified()->StringSubstring(), string, from, to, effect(), control()));
}

TNode<Boolean> JSGraphAssembler::ObjectIsCallable(TNode<Object> value) {
  return AddNode<Boolean>(
      graph()->NewNode(simplified()->ObjectIsCallable(), value));
}

TNode<Boolean> JSGraphAssembler::ObjectIsSmi(TNode<Object> value) {
  return AddNode<Boolean>(graph()->NewNode(simplified()->ObjectIsSmi(), value));
}

TNode<Boolean> JSGraphAssembler::ObjectIsUndetectable(TNode<Object> value) {
  return AddNode<Boolean>(
      graph()->NewNode(simplified()->ObjectIsUndetectable(), value));
}

Node* JSGraphAssembler::BooleanNot(Node* cond) {
  return AddNode(graph()->NewNode(simplified()->BooleanNot(), cond));
}

Node* JSGraphAssembler::CheckSmi(Node* value, const FeedbackSource& feedback) {
  return AddNode(graph()->NewNode(simplified()->CheckSmi(feedback), value,
                                  effect(), control()));
}

Node* JSGraphAssembler::CheckNumber(Node* value,
                                    const FeedbackSource& feedback) {
  return AddNode(graph()->NewNode(simplified()->CheckNumber(feedback), value,
                                  effect(), control()));
}

Node* JSGraphAssembler::CheckIf(Node* cond, DeoptimizeReason reason,
                                const FeedbackSource& feedback) {
  return AddNode(graph()->NewNode(simplified()->CheckIf(reason, feedback), cond,
                                  effect(), control()));
}

Node* JSGraphAssembler::Assert(Node* cond, const char* condition_string,
                               const char* file, int line) {
  return AddNode(graph()->NewNode(
      common()->Assert(BranchSemantics::kJS, condition_string, file, line),
      cond, effect(), control()));
}

void JSGraphAssembler::Assert(TNode<Word32T> cond, const char* condition_string,
                              const char* file, int line) {
  AddNode(graph()->NewNode(
      common()->Assert(BranchSemantics::kMachine, condition_string, file, line),
      cond, effect(), control()));
}

TNode<Boolean> JSGraphAssembler::NumberIsFloat64Hole(TNode<Number> value) {
  return AddNode<Boolean>(
      graph()->NewNode(simplified()->NumberIsFloat64Hole(), value));
}

TNode<Boolean> JSGraphAssembler::ToBoolean(TNode<Object> value) {
  return AddNode<Boolean>(graph()->NewNode(simplified()->ToBoolean(), value));
}

TNode<Object> JSGraphAssembler::ConvertTaggedHoleToUndefined(
    TNode<Object> value) {
  return AddNode<Object>(
      graph()->NewNode(simplified()->ConvertTaggedHoleToUndefined(), value));
}

TNode<FixedArrayBase> JSGraphAssembler::MaybeGrowFastElements(
    ElementsKind kind, const FeedbackSource& feedback, TNode<JSArray> array,
    TNode<FixedArrayBase> elements, TNode<Number> index_needed,
    TNode<Number> old_length) {
  GrowFastElementsMode mode = IsDoubleElementsKind(kind)
                                  ? GrowFastElementsMode::kDoubleElements
                                  : GrowFastElementsMode::kSmiOrObjectElements;
  return AddNode<FixedArrayBase>(graph()->NewNode(
      simplified()->MaybeGrowFastElements(mode, feedback), array, elements,
      index_needed, old_length, effect(), control()));
}

TNode<Object> JSGraphAssembler::DoubleArrayMax(TNode<JSArray> array) {
  return AddNode<Object>(graph()->NewNode(simplified()->DoubleArrayMax(), array,
                                          effect(), control()));
}

TNode<Object> JSGraphAssembler::DoubleArrayMin(TNode<JSArray> array) {
  return AddNode<Object>(graph()->NewNode(simplified()->DoubleArrayMin(), array,
                                          effect(), control()));
}

Node* JSGraphAssembler::StringCharCodeAt(TNode<String> string,
                                         TNode<Number> position) {
  return AddNode(graph()->NewNode(simplified()->StringCharCodeAt(), string,
                                  position, effect(), control()));
}

TNode<String> JSGraphAssembler::StringFromSingleCharCode(TNode<Number> code) {
  return AddNode<String>(
      graph()->NewNode(simplified()->StringFromSingleCharCode(), code));
}

class ArrayBufferViewAccessBuilder {
 public:
  explicit ArrayBufferViewAccessBuilder(JSGraphAssembler* assembler,
                                        InstanceType instance_type,
                                        std::set<ElementsKind> candidates)
      : assembler_(assembler),
        instance_type_(instance_type),
        candidates_(std::move(candidates)) {
    DCHECK_NOT_NULL(assembler_);
    // TODO(v8:11111): Optimize for JS_RAB_GSAB_DATA_VIEW_TYPE too.
    DCHECK(instance_type_ == JS_DATA_VIEW_TYPE ||
           instance_type_ == JS_TYPED_ARRAY_TYPE);
  }

  bool maybe_rab_gsab() const {
    if (candidates_.empty()) return true;
    return !base::all_of(candidates_, [](auto e) {
      return !IsRabGsabTypedArrayElementsKind(e);
    });
  }

  std::optional<int> TryComputeStaticElementShift() {
    DCHECK(instance_type_ != JS_RAB_GSAB_DATA_VIEW_TYPE);
    if (instance_type_ == JS_DATA_VIEW_TYPE) return 0;
    if (candidates_.empty()) return std::nullopt;
    int shift = ElementsKindToShiftSize(*candidates_.begin());
    if (!base::all_of(candidates_, [shift](auto e) {
          return ElementsKindToShiftSize(e) == shift;
        })) {
      return std::nullopt;
    }
    return shift;
  }

  std::optional<int> TryComputeStaticElementSize() {
    DCHECK(instance_type_ != JS_RAB_GSAB_DATA_VIEW_TYPE);
    if (instance_type_ == JS_DATA_VIEW_TYPE) return 1;
    if (candidates_.empty()) return std::nullopt;
    int size = ElementsKindToByteSize(*candidates_.begin());
    if (!base::all_of(candidates_, [size](auto e) {
          return ElementsKindToByteSize(e) == size;
        })) {
      return std::nullopt;
    }
    return size;
  }

  TNode<UintPtrT> BuildLength(TNode<JSArrayBufferView> view,
                              TNode<Context> context) {
    auto& a = *assembler_;

    // Case 1: Normal (backed by AB/SAB) or non-length tracking backed by GSAB
    // (can't go oob once constructed)
    auto GsabFixedOrNormal = [&]() {
      return MachineLoadField<UintPtrT>(AccessBuilder::ForJSTypedArrayLength(),
                                        view, UseInfo::Word());
    };

    // If we statically know we cannot have rab/gsab backed, we can simply
    // load from the view.
    if (!maybe_rab_gsab()) {
      return GsabFixedOrNormal();
    }

    // Otherwise, we need to generate the checks for the view's bitfield.
    TNode<Word32T> bitfield = a.EnterMachineGraph<Word32T>(
        a.LoadField<Word32T>(AccessBuilder::ForJSArrayBufferViewBitField(),
                             view),
        UseInfo::TruncatingWord32());
    TNode<Word32T> length_tracking_bit = a.Word32And(
        bitfield, a.Uint32Constant(JSArrayBufferView::kIsLengthTracking));
    TNode<Word32T> backed_by_rab_bit = a.Word32And(
        bitfield, a.Uint32Constant(JSArrayBufferView::kIsBackedByRab));

    // Load the underlying buffer.
    TNode<HeapObject> buffer = a.LoadField<HeapObject>(
        AccessBuilder::ForJSArrayBufferViewBuffer(), view);

    // Compute the element size.
    TNode<Uint32T> element_size;
    if (auto size_opt = TryComputeStaticElementSize()) {
      element_size = a.Uint32Constant(*size_opt);
    } else {
      DCHECK_EQ(instance_type_, JS_TYPED_ARRAY_TYPE);
      TNode<Map> typed_array_map = a.LoadField<Map>(
          AccessBuilder::ForMap(WriteBarrierKind::kNoWriteBarrier), view);
      TNode<Uint32T> elements_kind = a.LoadElementsKind(typed_array_map);
      element_size = a.LookupByteSizeForElementsKind(elements_kind);
    }

    // 2) Fixed length backed by RAB (can go oob once constructed)
    auto RabFixed = [&]() {
      TNode<UintPtrT> unchecked_byte_length = MachineLoadField<UintPtrT>(
          AccessBuilder::ForJSArrayBufferViewByteLength(), view,
          UseInfo::Word());
      TNode<UintPtrT> underlying_byte_length = MachineLoadField<UintPtrT>(
          AccessBuilder::ForJSArrayBufferByteLength(), buffer, UseInfo::Word());
      TNode<UintPtrT> byte_offset = MachineLoadField<UintPtrT>(
          AccessBuilder::ForJSArrayBufferViewByteOffset(), view,
          UseInfo::Word());

      TNode<UintPtrT> byte_length =
          a
              .MachineSelectIf<UintPtrT>(a.UintPtrLessThanOrEqual(
                  a.UintPtrAdd(byte_offset, unchecked_byte_length),
                  underlying_byte_length))
              .Then([&]() { return unchecked_byte_length; })
              .Else([&]() { return a.UintPtrConstant(0); })
              .Value();
      return a.UintPtrDiv(byte_length, a.ChangeUint32ToUintPtr(element_size));
    };

    // 3) Length-tracking backed by RAB (JSArrayBuffer stores the length)
    auto RabTracking = [&]() {
      TNode<UintPtrT> byte_length = MachineLoadField<UintPtrT>(
          AccessBuilder::ForJSArrayBufferByteLength(), buffer, UseInfo::Word());
      TNode<UintPtrT> byte_offset = MachineLoadField<UintPtrT>(
          AccessBuilder::ForJSArrayBufferViewByteOffset(), view,
          UseInfo::Word());

      return a
          .MachineSelectIf<UintPtrT>(
              a.UintPtrLessThanOrEqual(byte_offset, byte_length))
          .Then([&]() {
            // length = floor((byte_length - byte_offset) / element_size)
            return a.UintPtrDiv(a.UintPtrSub(byte_length, byte_offset),
                                a.ChangeUint32ToUintPtr(element_size));
          })
          .Else([&]() { return a.UintPtrConstant(0); })
          .ExpectTrue()
          .Value();
    };

    // 4) Length-tracking backed by GSAB (BackingStore stores the length)
    auto GsabTracking = [&]() {
      TNode<Number> temp = TNode<Number>::UncheckedCast(a.TypeGuard(
          TypeCache::Get()->kJSArrayBufferViewByteLengthType,
          a.JSCallRuntime1(Runtime::kGrowableSharedArrayBufferByteLength,
                           buffer, context, std::nullopt, Operator::kNoWrite)));
      TNode<UintPtrT> byte_length =
          a.EnterMachineGraph<UintPtrT>(temp, UseInfo::Word());
      TNode<UintPtrT> byte_offset = MachineLoadField<UintPtrT>(
          AccessBuilder::ForJSArrayBufferViewByteOffset(), view,
          UseInfo::Word());

      return a
          .MachineSelectIf<UintPtrT>(
              a.UintPtrLessThanOrEqual(byte_offset, byte_length))
          .Then([&]() {
            // length = floor((byte_length - byte_offset) / element_size)
            return a.UintPtrDiv(a.UintPtrSub(byte_length, byte_offset),
                                a.ChangeUint32ToUintPtr(element_size));
          })
          .Else([&]() { return a.UintPtrConstant(0); })
          .ExpectTrue()
          .Value();
    };

    return a.MachineSelectIf<UintPtrT>(length_tracking_bit)
        .Then([&]() {
          return a.MachineSelectIf<UintPtrT>(backed_by_rab_bit)
              .Then(RabTracking)
              .Else(GsabTracking)
              .Value();
        })
        .Else([&]() {
          return a.MachineSelectIf<UintPtrT>(backed_by_rab_bit)
              .Then(RabFixed)
              .Else(GsabFixedOrNormal)
              .Value();
        })
        .Value();
  }

  TNode<UintPtrT> BuildByteLength(TNode<JSArrayBufferView> view,
                                  TNode<Context> context) {
    auto& a = *assembler_;

    // Case 1: Normal (backed by AB/SAB) or non-length tracking backed by GSAB
    // (can't go oob once constructed)
    auto GsabFixedOrNormal = [&]() {
      return MachineLoadField<UintPtrT>(
          AccessBuilder::ForJSArrayBufferViewByteLength(), view,
          UseInfo::Word());
    };

    // If we statically know we cannot have rab/gsab backed, we can simply
    // use load from the view.
    if (!maybe_rab_gsab()) {
      return GsabFixedOrNormal();
    }

    // Otherwise, we need to generate the checks for the view's bitfield.
    TNode<Word32T> bitfield = a.EnterMachineGraph<Word32T>(
        a.LoadField<Word32T>(AccessBuilder::ForJSArrayBufferViewBitField(),
                             view),
        UseInfo::TruncatingWord32());
    TNode<Word32T> length_tracking_bit = a.Word32And(
        bitfield, a.Uint32Constant(JSArrayBufferView::kIsLengthTracking));
    TNode<Word32T> backed_by_rab_bit = a.Word32And(
        bitfield, a.Uint32Constant(JSArrayBufferView::kIsBackedByRab));

    // Load the underlying buffer.
    TNode<HeapObject> buffer = a.LoadField<HeapObject>(
        AccessBuilder::ForJSArrayBufferViewBuffer(), view);

    // Case 2: Fixed length backed by RAB (can go oob once constructed)
    auto RabFixed = [&]() {
      TNode<UintPtrT> unchecked_byte_length = MachineLoadField<UintPtrT>(
          AccessBuilder::ForJSArrayBufferViewByteLength(), view,
          UseInfo::Word());
      TNode<UintPtrT> underlying_byte_length = MachineLoadField<UintPtrT>(
          AccessBuilder::ForJSArrayBufferByteLength(), buffer, UseInfo::Word());
      TNode<UintPtrT> byte_offset = MachineLoadField<UintPtrT>(
          AccessBuilder::ForJSArrayBufferViewByteOffset(), view,
          UseInfo::Word());

      return a
          .MachineSelectIf<UintPtrT>(a.UintPtrLessThanOrEqual(
              a.UintPtrAdd(byte_offset, unchecked_byte_length),
              underlying_byte_length))
          .Then([&]() { return unchecked_byte_length; })
          .Else([&]() { return a.UintPtrConstant(0); })
          .Value();
    };

    auto RoundDownToElementSize = [&](TNode<UintPtrT> byte_size) {
      if (auto shift_opt = TryComputeStaticElementShift()) {
        constexpr uintptr_t all_bits = static_cast<uintptr_t>(-1);
        if (*shift_opt == 0) return byte_size;
        return TNode<UintPtrT>::UncheckedCast(
            a.WordAnd(byte_size, a.UintPtrConstant(all_bits << (*shift_opt))));
      }
      DCHECK_EQ(instance_type_, JS_TYPED_ARRAY_TYPE);
      TNode<Map> typed_array_map = a.LoadField<Map>(
          AccessBuilder::ForMap(WriteBarrierKind::kNoWriteBarrier), view);
      TNode<Uint32T> elements_kind = a.LoadElementsKind(typed_array_map);
      TNode<Uint32T> element_shift =
          a.LookupByteShiftForElementsKind(elements_kind);
      return TNode<UintPtrT>::UncheckedCast(
          a.WordShl(a.WordShr(byte_size, element_shift), element_shift));
    };

    // Case 3: Length-tracking backed by RAB (JSArrayBuffer stores the length)
    auto RabTracking = [&]() {
      TNode<UintPtrT> byte_length = MachineLoadField<UintPtrT>(
          AccessBuilder::ForJSArrayBufferByteLength(), buffer, UseInfo::Word());
      TNode<UintPtrT> byte_offset = MachineLoadField<UintPtrT>(
          AccessBuilder::ForJSArrayBufferViewByteOffset(), view,
          UseInfo::Word());

      return a
          .MachineSelectIf<UintPtrT>(
              a.UintPtrLessThanOrEqual(byte_offset, byte_length))
          .Then([&]() {
            return RoundDownToElementSize(
                a.UintPtrSub(byte_length, byte_offset));
          })
          .Else([&]() { return a.UintPtrConstant(0); })
          .ExpectTrue()
          .Value();
    };

    // Case 4: Length-tracking backed by GSAB (BackingStore stores the length)
    auto GsabTracking = [&]() {
      TNode<Number> temp = TNode<Number>::UncheckedCast(a.TypeGuard(
          TypeCache::Get()->kJSArrayBufferViewByteLengthType,
          a.JSCallRuntime1(Runtime::kGrowableSharedArrayBufferByteLength,
                           buffer, context, std::nullopt, Operator::kNoWrite)));
      TNode<UintPtrT> byte_length =
          a.EnterMachineGraph<UintPtrT>(temp, UseInfo::Word());
      TNode<UintPtrT> byte_offset = MachineLoadField<UintPtrT>(
          AccessBuilder::ForJSArrayBufferViewByteOffset(), view,
          UseInfo::Word());

      return a
          .MachineSelectIf<UintPtrT>(
              a.UintPtrLessThanOrEqual(byte_offset, byte_length))
          .Then([&]() {
```