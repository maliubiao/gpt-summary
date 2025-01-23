Response:
Let's break down the thought process for analyzing the provided C++ header file.

**1. Initial Understanding of the Context:**

The first thing I noticed is the file path: `v8/src/torque/implementation-visitor.h`. This immediately tells me it's part of the V8 JavaScript engine and specifically within the "torque" directory. The `.h` extension indicates a C++ header file. The name "implementation-visitor" suggests a design pattern (Visitor) and a focus on code generation or transformation (implementation). The comment at the beginning confirms this is part of the Torque project within V8.

**2. Identifying Key Components and Data Structures:**

I started scanning the file for significant data structures and classes. My focus was on understanding their purpose and relationships. Here's a breakdown of how I identified and interpreted the key elements:

* **`LocationReference`:** This class appears early and is heavily used. The comments within the class are very helpful, explaining that it represents "l-values" (things that can be assigned to). The different `static` factory methods (`VariableAccess`, `Temporary`, `HeapReference`, etc.) hint at the various ways a value can be referenced. This class seems central to how Torque tracks and manipulates values.

* **`InitializerResults` and `LayoutForInitialization`:** These structures suggest the handling of object creation and initialization. `InitializerResults` likely stores the results of evaluating initializers, and `LayoutForInitialization` seems to deal with the memory layout and sizing during initialization.

* **`Binding<T>` and `BindingsManager<T>`:**  These templated classes strongly suggest a mechanism for managing named entities (variables, labels, etc.). The names "Binding" and "BindingsManager" are common patterns for symbol tables or environments. The `TryLookup` method in `BindingsManager` confirms this. The `Binding` class itself stores information about the bound entity (name, usage, whether it's been written to).

* **`LocalValue` and `LocalLabel`:** These classes represent specific types of bound entities. `LocalValue` seems to encapsulate a `LocationReference` or a mechanism to get one lazily. `LocalLabel` represents jump targets within the generated code.

* **`Arguments`:**  This structure clearly holds information about function or method arguments, including both value parameters and labels (for control flow).

* **`ImplementationVisitor` Class:** This is the main class of the header. As the name suggests, it's responsible for visiting the Torque AST (Abstract Syntax Tree) and generating the corresponding implementation (likely C++ code). The numerous `Visit` methods, each taking a different AST node type, reinforce the Visitor pattern. The methods prefixed with "Generate" indicate code generation actions.

* **`StackScope`:** This nested class appears to manage the stack during code generation. The comments about "deleting temporary slots" and "Yield" provide clues about its purpose in optimizing stack usage.

* **Contextual Variables (using `DECLARE_CONTEXTUAL_VARIABLE`):**  These macros indicate thread-local or context-specific storage for things like the current bindings managers, the current callable being processed, and output file streams. This suggests the visitor maintains state as it traverses the AST.

**3. Identifying the Overall Functionality:**

Based on the identified components, I started piecing together the high-level functionality:

* **Torque Code Processing:** The file is part of the Torque compiler. It takes Torque code as input (represented by the AST nodes).
* **Code Generation:** The core responsibility of `ImplementationVisitor` is to translate Torque code into C++ code. The "Generate" methods are key here.
* **Symbol Management:** `Binding` and `BindingsManager` handle the creation, lookup, and tracking of variables, labels, and other named entities. This is essential for resolving references and ensuring correct scoping.
* **Value Representation:** `LocationReference` is crucial for representing how values are stored and accessed (variables, temporaries, heap locations, etc.).
* **Control Flow:** `LocalLabel` and the "goto" and label-related methods manage control flow within the generated code.
* **Object Initialization:** `InitializerResults` and `LayoutForInitialization` handle the process of creating and initializing objects.
* **Stack Management:** `StackScope` optimizes stack usage during code generation.

**4. Connecting to JavaScript Functionality (Hypothetical):**

Since Torque is used within V8, I considered how the concepts in this header might relate to JavaScript features. I looked for keywords or concepts that had parallels:

* **Variables:**  The `Binding<LocalValue>` clearly maps to JavaScript variables (both `let` and `const`).
* **Object Properties:**  `LocationReference::FieldAccess` relates to accessing properties of JavaScript objects.
* **Array Elements:** `LocationReference::ArrayAccess` relates to accessing elements of JavaScript arrays.
* **Function Calls:** The `Visit(CallExpression*)` method handles the generation of code for JavaScript function calls.
* **Control Flow:** `if`, `while`, `break`, `continue`, and `return` statements in JavaScript have corresponding structures in Torque, as evidenced by the `Visit` methods for these statement types.
* **Object Creation:**  The `Visit(NewExpression*)` and the initialization-related structures map to the `new` operator in JavaScript.

**5. Considering Potential Errors:**

I thought about common programming errors that Torque might catch or that could occur in the generated C++ code:

* **Unused variables:** The linting logic in the `Binding` destructor directly addresses this.
* **Assignment to constants:** While not explicitly enforced by the provided code, the `IsConst()` method in `LocationReference` suggests Torque tracks constness.
* **Redeclaration of variables:** The `ReportErrorIfAlreadyBound` method in `BlockBindings` handles this.
* **Type errors:** While not explicitly visible in this header, the interactions with `TypeOracle` suggest type checking is a part of Torque's functionality.

**6. Structuring the Explanation:**

Finally, I organized my findings into a clear and structured explanation, addressing each of the user's requests:

* **Listing the functions:** I went through the header and summarized the purpose of each significant class and method.
* **Connecting to JavaScript:** I provided concrete JavaScript examples to illustrate how the Torque concepts map to JavaScript features.
* **Illustrating code logic:**  I created a hypothetical example of variable assignment to demonstrate the flow of information.
* **Identifying common errors:** I listed examples of programming errors that the code helps to prevent.
* **Summarizing the overall functionality:** I provided a concise summary of the header's role.

This iterative process of examining the code, understanding its components, relating it to the broader context of V8 and JavaScript, and considering potential issues allowed me to generate a comprehensive and accurate explanation of the provided header file.
好的，这是对 `v8/src/torque/implementation-visitor.h` 文件功能的详细分析：

**核心功能归纳：**

`implementation-visitor.h` 定义了 `ImplementationVisitor` 类，它是 Torque 编译器的核心组件之一。其主要功能是：

1. **将 Torque 抽象语法树 (AST) 转换为底层的 C++ 代码**：`ImplementationVisitor` 遍历 Torque 的 AST，并根据 AST 节点的类型生成相应的 C++ 代码，这些代码最终会被编译成 V8 引擎的一部分。
2. **管理变量和标签的绑定关系**：它维护了当前作用域内变量和标签的绑定信息，用于在代码生成过程中查找和引用它们。
3. **处理类型信息**：它利用 `TypeOracle` 来处理类型相关的操作，例如类型检查、类型转换等。
4. **生成内置函数和接口描述符**：它负责生成 V8 内置函数和接口的 C++ 定义。
5. **处理控制流语句**：它负责生成 `if`，`while`，`for`，`return`，`goto` 等控制流语句的 C++ 代码。
6. **处理表达式**：它负责生成各种 Torque 表达式的 C++ 代码，包括算术运算、逻辑运算、函数调用等。
7. **支持宏内联**：它能够将 Torque 宏内联到生成的 C++ 代码中。
8. **生成调试信息**：它可以生成用于调试的宏定义。
9. **管理栈帧**：通过 `StackScope` 类，它负责在生成代码时管理栈帧的分配和释放。

**更详细的功能分解：**

**1. `LocationReference` 类：**

*   **功能**：表示一个可以被赋值的左值（l-value），或者一个不可赋值的临时值。它统一了对不同类型内存位置的访问方式。
*   **类型**：
    *   `VariableAccess`:  表示栈上的变量。
    *   `Temporary`: 表示一个临时值，不可赋值。
    *   `HeapReference`: 表示堆上的对象及其内部偏移量。
    *   `HeapSlice`: 表示堆上的数组切片。
    *   `ArrayAccess`: 表示数组元素的访问。
    *   `FieldAccess`: 表示对象字段的访问。
    *   `BitFieldAccess`: 表示位域的访问。
*   **重要方法**：
    *   `IsConst()`: 判断引用是否是常量。
    *   `GetVisitResult()`: 获取引用对应的 `VisitResult`（包含类型和位置信息）。

**2. `InitializerResults` 和 `LayoutForInitialization` 结构体：**

*   **功能**：用于处理结构体或类的初始化。
*   **`InitializerResults`**: 存储初始化表达式的结果，将字段名映射到其对应的 `VisitResult`。
*   **`LayoutForInitialization`**:  存储初始化时需要的布局信息，如数组长度、字段偏移量和总大小。

**3. `Binding<T>` 和 `BindingsManager<T>` 模板类：**

*   **功能**：用于管理作用域内的变量和标签的绑定关系。
*   **`BindingsManager`**: 维护一个映射，将名称与 `Binding` 对象关联起来。
*   **`Binding`**: 表示一个绑定，存储了名称、值、是否被使用、是否被写入等信息。用于进行变量查找和生命周期管理。

**4. `LocalValue` 类：**

*   **功能**：表示一个局部变量的值。它可以直接包含一个 `LocationReference`，或者是一个延迟计算 `LocationReference` 的函数，或者表示该值不可访问。

**5. `LocalLabel` 结构体：**

*   **功能**：表示一个局部标签，用于控制流跳转。包含标签对应的 `Block` 和参数类型。

**6. `Arguments` 结构体：**

*   **功能**：表示函数或宏调用的参数，包括值参数和标签参数。

**7. `ImplementationVisitor` 类：**

*   **核心功能**：如上所述，负责将 Torque AST 转换为 C++ 代码。
*   **重要的成员变量**：
    *   `assembler_`:  一个 `CfgAssembler` 对象，用于构建控制流图 (CFG) 和生成低级指令。
    *   各种 `BindingsManager` 实例：用于管理不同类型的绑定。
*   **重要的成员方法（部分列举）**：
    *   `Visit(Expression* expr)` 和 `Visit(Statement* stmt)`:  核心的访问者模式方法，用于遍历 AST 节点并生成代码。
    *   `GetLocationReference(Expression* location)`:  根据表达式获取其对应的 `LocationReference`。
    *   `GenerateFetchFromLocation(const LocationReference& reference)`:  生成从指定位置加载值的代码。
    *   `GenerateAssignToLocation(const LocationReference& reference, const VisitResult& assignment_value)`: 生成将值赋值到指定位置的代码。
    *   `GenerateCall(...)`: 生成函数或宏调用的代码。
    *   `GenerateBranch(...)`: 生成条件分支的代码。
    *   `GenerateLabelGoto(...)`: 生成跳转到标签的代码。
    *   `StackScope`:  内部类，用于管理栈帧。

**与 JavaScript 功能的关系及示例：**

`ImplementationVisitor` 生成的 C++ 代码最终实现了 JavaScript 的各种功能。以下是一些对应关系和示例：

*   **变量声明和赋值：**
    *   Torque 代码可能包含变量声明，例如 `let x: Number;` 或 `const y: String = "hello";`。
    *   `ImplementationVisitor` 会为这些声明在栈上分配空间（通过 `LocationReference::VariableAccess`），并生成相应的 C++ 代码进行初始化和赋值。
    *   **JavaScript 示例：**
        ```javascript
        let a = 10;
        const message = "Hello";
        a = a + 5;
        ```

*   **对象属性访问：**
    *   Torque 代码可能包含对对象属性的访问，例如 `object.field`。
    *   `ImplementationVisitor` 会生成使用偏移量访问对象内存的代码（通过 `LocationReference::FieldAccess` 和 `HeapReference`）。
    *   **JavaScript 示例：**
        ```javascript
        const obj = { name: "Alice", age: 30 };
        console.log(obj.name);
        obj.age = 31;
        ```

*   **数组元素访问：**
    *   Torque 代码可能包含对数组元素的访问，例如 `array[i]`。
    *   `ImplementationVisitor` 会生成计算数组元素地址并访问的代码（通过 `LocationReference::ArrayAccess` 和 `HeapSlice`）。
    *   **JavaScript 示例：**
        ```javascript
        const numbers = [1, 2, 3];
        console.log(numbers[1]);
        numbers[0] = 0;
        ```

*   **函数调用：**
    *   Torque 代码会描述 JavaScript 内置函数和用户定义函数的实现。
    *   `ImplementationVisitor` 会生成函数调用的 C++ 代码，包括参数传递、栈帧管理等。
    *   **JavaScript 示例：**
        ```javascript
        function add(a, b) {
          return a + b;
        }
        let sum = add(5, 3);
        console.log(sum);
        ```

*   **控制流语句：**
    *   Torque 代码使用 `if`，`while`，`for` 等语句来实现 JavaScript 的控制流。
    *   `ImplementationVisitor` 会生成相应的 C++ 分支和循环代码。
    *   **JavaScript 示例：**
        ```javascript
        if (x > 10) {
          console.log("x is greater than 10");
        } else {
          console.log("x is not greater than 10");
        }

        for (let i = 0; i < 5; i++) {
          console.log(i);
        }
        ```

**代码逻辑推理示例（假设）：**

假设 Torque 代码中有以下赋值语句：

```torque
let x: Int32;
x = 10;
```

**假设输入：**

*   `VarDeclarationStatement` AST 节点，表示 `let x: Int32;`。
*   `AssignmentExpression` AST 节点，表示 `x = 10;`。

**`ImplementationVisitor` 的处理步骤：**

1. **处理变量声明：**
    *   在 `Visit(VarDeclarationStatement* stmt)` 中，`ImplementationVisitor` 会调用 `assembler().AllocateStackSlot(TypeOracle::GetInt32())` 在栈上为 `x` 分配一个 `Int32` 大小的空间。
    *   创建一个 `LocationReference::VariableAccess` 对象，指向该栈上的位置，并将其绑定到变量名 `x`（通过 `BlockBindings`）。

2. **处理赋值语句：**
    *   在 `Visit(AssignmentExpression* expr)` 中：
        *   调用 `GetLocationReference(expr->target)` 获取左值 `x` 的 `LocationReference`。
        *   调用 `Visit(expr->value)` 处理右值 `10`，生成表示常量 10 的 `VisitResult`。
        *   调用 `GenerateAssignToLocation(location_reference_for_x, visit_result_for_10)`，生成将常量 10 写入 `x` 对应栈位置的 C++ 代码。

**假设输出（生成的 C++ 代码片段）：**

```c++
  // ... (代码片段上下文) ...
  TNode<Int32T> x;
  // ...
  TNode<Int32T> tmp_0 = Int32Constant(10);
  x = tmp_0;
  // ...
```

**用户常见的编程错误示例：**

*   **使用未声明的变量：** 如果 Torque 代码中使用了未声明的变量，`ImplementationVisitor` 在查找绑定时会失败，并抛出错误。这对应于 JavaScript 中的 `ReferenceError`。

    ```javascript
    // JavaScript
    console.log(undeclaredVariable); // ReferenceError: undeclaredVariable is not defined
    ```

*   **类型不匹配的赋值：** 如果尝试将一个类型的值赋给另一个不兼容类型的变量，`ImplementationVisitor` 会进行类型检查，并可能生成类型转换代码，或者在无法转换时抛出错误。这对应于 JavaScript 中可能发生的隐式类型转换或 `TypeError`。

    ```javascript
    // JavaScript
    let num = 10;
    num = "hello"; // JavaScript 会进行隐式类型转换，但 Torque 可能会进行更严格的检查
    ```

*   **重复声明变量：** 在同一作用域内重复声明相同名称的变量，`ImplementationVisitor` 会通过 `BlockBindings` 检测到并报错。这对应于 JavaScript 中的 `SyntaxError`（在严格模式下或使用 `let` 和 `const` 时）。

    ```javascript
    // JavaScript
    let a = 1;
    let a = 2; // SyntaxError: Identifier 'a' has already been declared
    ```

**总结 `implementation-visitor.h` 的功能（针对第 1 部分）：**

`implementation-visitor.h` 定义了 `ImplementationVisitor` 类以及其辅助类和结构体，它是 Torque 编译器的核心，负责将 Torque 语言描述的程序（例如内置函数和运行时代码）转换成底层的 C++ 代码。它管理变量和标签的绑定，处理类型信息，并提供了生成各种 C++ 代码结构（如变量访问、赋值、函数调用、控制流等）的能力。`LocationReference` 是一个关键的抽象，用于统一表示不同类型的内存位置。该头文件是 Torque 编译器实现代码生成逻辑的基础。

### 提示词
```
这是目录为v8/src/torque/implementation-visitor.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/torque/implementation-visitor.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_TORQUE_IMPLEMENTATION_VISITOR_H_
#define V8_TORQUE_IMPLEMENTATION_VISITOR_H_

#include <memory>
#include <optional>
#include <string>

#include "src/base/macros.h"
#include "src/torque/ast.h"
#include "src/torque/cfg.h"
#include "src/torque/cpp-builder.h"
#include "src/torque/declarations.h"
#include "src/torque/global-context.h"
#include "src/torque/type-oracle.h"
#include "src/torque/types.h"
#include "src/torque/utils.h"

namespace v8::internal::torque {

template <typename T>
class Binding;
class LocalValue;
class ImplementationVisitor;

// LocationReference is the representation of an l-value, so a value that might
// allow for assignment. For uniformity, this class can also represent
// unassignable temporaries. Assignable values fall in two categories:
//   - stack ranges that represent mutable variables, including structs.
//   - field or element access expressions that generate operator calls.
class LocationReference {
 public:
  // An assignable stack range.
  static LocationReference VariableAccess(
      VisitResult variable,
      std::optional<Binding<LocalValue>*> binding = std::nullopt) {
    DCHECK(variable.IsOnStack());
    LocationReference result;
    result.variable_ = std::move(variable);
    result.binding_ = binding;
    return result;
  }
  // An unassignable value. {description} is only used for error messages.
  static LocationReference Temporary(VisitResult temporary,
                                     std::string description) {
    LocationReference result;
    result.temporary_ = std::move(temporary);
    result.temporary_description_ = std::move(description);
    return result;
  }
  // A heap reference, that is, a tagged value and an offset to encode an inner
  // pointer.
  static LocationReference HeapReference(
      VisitResult heap_reference,
      FieldSynchronization synchronization = FieldSynchronization::kNone) {
    LocationReference result;
    DCHECK(TypeOracle::MatchReferenceGeneric(heap_reference.type()));
    result.heap_reference_ = std::move(heap_reference);
    result.heap_reference_synchronization_ = synchronization;
    return result;
  }
  // A reference to an array on the heap. That is, a tagged value, an offset to
  // encode an inner pointer, and the number of elements.
  static LocationReference HeapSlice(VisitResult heap_slice) {
    LocationReference result;
    DCHECK(Type::MatchUnaryGeneric(heap_slice.type(),
                                   TypeOracle::GetConstSliceGeneric()) ||
           Type::MatchUnaryGeneric(heap_slice.type(),
                                   TypeOracle::GetMutableSliceGeneric()));
    result.heap_slice_ = std::move(heap_slice);
    return result;
  }
  static LocationReference ArrayAccess(VisitResult base, VisitResult offset) {
    LocationReference result;
    result.eval_function_ = std::string{"[]"};
    result.assign_function_ = std::string{"[]="};
    result.call_arguments_ = {base, offset};
    return result;
  }
  static LocationReference FieldAccess(VisitResult object,
                                       std::string fieldname) {
    LocationReference result;
    result.eval_function_ = "." + fieldname;
    result.assign_function_ = "." + fieldname + "=";
    result.call_arguments_ = {object};
    return result;
  }
  static LocationReference BitFieldAccess(const LocationReference& object,
                                          BitField field) {
    LocationReference result;
    result.bit_field_struct_ = std::make_shared<LocationReference>(object);
    result.bit_field_ = std::move(field);
    return result;
  }

  bool IsConst() const {
    if (IsHeapReference()) {
      bool is_const;
      bool success =
          TypeOracle::MatchReferenceGeneric(heap_reference().type(), &is_const)
              .has_value();
      CHECK(success);
      return is_const;
    }
    return IsTemporary();
  }

  bool IsVariableAccess() const { return variable_.has_value(); }
  const VisitResult& variable() const {
    DCHECK(IsVariableAccess());
    return *variable_;
  }
  bool IsTemporary() const { return temporary_.has_value(); }
  const VisitResult& temporary() const {
    DCHECK(IsTemporary());
    return *temporary_;
  }
  bool IsHeapReference() const { return heap_reference_.has_value(); }
  const VisitResult& heap_reference() const {
    DCHECK(IsHeapReference());
    return *heap_reference_;
  }
  FieldSynchronization heap_reference_synchronization() const {
    DCHECK(IsHeapReference());
    return heap_reference_synchronization_;
  }
  bool IsHeapSlice() const { return heap_slice_.has_value(); }
  const VisitResult& heap_slice() const {
    DCHECK(IsHeapSlice());
    return *heap_slice_;
  }
  bool IsBitFieldAccess() const {
    bool is_bitfield_access = bit_field_struct_ != nullptr;
    DCHECK_EQ(is_bitfield_access, bit_field_.has_value());
    return is_bitfield_access;
  }
  const LocationReference& bit_field_struct_location() const {
    DCHECK(IsBitFieldAccess());
    return *bit_field_struct_;
  }
  const BitField& bit_field() const {
    DCHECK(IsBitFieldAccess());
    return *bit_field_;
  }

  std::optional<const Type*> ReferencedType() const {
    if (IsHeapReference()) {
      return *TypeOracle::MatchReferenceGeneric(heap_reference().type());
    }
    if (IsHeapSlice()) {
      if (auto type = Type::MatchUnaryGeneric(
              heap_slice().type(), TypeOracle::GetMutableSliceGeneric())) {
        return *type;
      }
      return Type::MatchUnaryGeneric(heap_slice().type(),
                                     TypeOracle::GetConstSliceGeneric());
    }
    if (IsBitFieldAccess()) {
      return bit_field_->name_and_type.type;
    }
    if (IsVariableAccess() || IsHeapSlice() || IsTemporary()) {
      return GetVisitResult().type();
    }
    return std::nullopt;
  }

  const VisitResult& GetVisitResult() const {
    if (IsVariableAccess()) return variable();
    if (IsHeapSlice()) return heap_slice();
    DCHECK(IsTemporary());
    return temporary();
  }

  // For error reporting.
  const std::string& temporary_description() const {
    DCHECK(IsTemporary());
    return *temporary_description_;
  }

  bool IsCallAccess() const {
    bool is_call_access = eval_function_.has_value();
    DCHECK_EQ(is_call_access, assign_function_.has_value());
    return is_call_access;
  }
  const VisitResultVector& call_arguments() const {
    DCHECK(IsCallAccess());
    return call_arguments_;
  }
  const std::string& eval_function() const {
    DCHECK(IsCallAccess());
    return *eval_function_;
  }
  const std::string& assign_function() const {
    DCHECK(IsCallAccess());
    return *assign_function_;
  }
  std::optional<Binding<LocalValue>*> binding() const {
    DCHECK(IsVariableAccess());
    return binding_;
  }

 private:
  std::optional<VisitResult> variable_;
  std::optional<VisitResult> temporary_;
  std::optional<std::string> temporary_description_;
  std::optional<VisitResult> heap_reference_;
  FieldSynchronization heap_reference_synchronization_ =
      FieldSynchronization::kNone;
  std::optional<VisitResult> heap_slice_;
  std::optional<std::string> eval_function_;
  std::optional<std::string> assign_function_;
  VisitResultVector call_arguments_;
  std::optional<Binding<LocalValue>*> binding_;

  // The location of the bitfield struct that contains this bitfield, if this
  // reference is a bitfield access. Uses a shared_ptr so that LocationReference
  // is copyable, allowing us to set this field equal to a copy of a
  // stack-allocated LocationReference.
  std::shared_ptr<const LocationReference> bit_field_struct_;
  std::optional<BitField> bit_field_;

  LocationReference() = default;
};

struct InitializerResults {
  std::vector<Identifier*> names;
  std::map<std::string, VisitResult> field_value_map;
};

struct LayoutForInitialization {
  std::map<std::string, VisitResult> array_lengths;
  std::map<std::string, VisitResult> offsets;
  VisitResult size;
};

extern uint64_t next_unique_binding_index;

template <class T>
class Binding;

template <class T>
class BindingsManager {
 public:
  std::optional<Binding<T>*> TryLookup(const std::string& name) {
    if (StartsWithSingleUnderscore(name)) {
      Error("Trying to reference '", name, "' which is marked as unused.")
          .Throw();
    }
    auto binding = current_bindings_[name];
    if (binding) {
      (*binding)->SetUsed();
    }
    return binding;
  }

 private:
  friend class Binding<T>;
  std::unordered_map<std::string, std::optional<Binding<T>*>> current_bindings_;
};

template <class T>
class Binding : public T {
 public:
  template <class... Args>
  Binding(BindingsManager<T>* manager, const std::string& name, Args&&... args)
      : T(std::forward<Args>(args)...),
        manager_(manager),
        name_(name),
        previous_binding_(this),
        used_(false),
        written_(false),
        unique_index_(next_unique_binding_index++) {
    std::swap(previous_binding_, manager_->current_bindings_[name]);
  }
  template <class... Args>
  Binding(BindingsManager<T>* manager, const Identifier* name, Args&&... args)
      : Binding(manager, name->value, std::forward<Args>(args)...) {
    declaration_position_ = name->pos;
  }
  ~Binding() {
    if (!used_ && !SkipLintCheck()) {
      Lint(BindingTypeString(), "'", name_,
           "' is never used. Prefix with '_' if this is intentional.")
          .Position(declaration_position_);
    }

    if (CheckWritten() && !written_ && !SkipLintCheck()) {
      Lint(BindingTypeString(), "'", name_,
           "' is never assigned to. Use 'const' instead of 'let'.")
          .Position(declaration_position_);
    }

    manager_->current_bindings_[name_] = previous_binding_;
  }
  Binding(const Binding&) = delete;
  Binding& operator=(const Binding&) = delete;

  std::string BindingTypeString() const;
  bool CheckWritten() const;

  const std::string& name() const { return name_; }
  SourcePosition declaration_position() const { return declaration_position_; }

  bool Used() const { return used_; }
  void SetUsed() { used_ = true; }

  bool Written() const { return written_; }
  void SetWritten() { written_ = true; }

  uint64_t unique_index() const { return unique_index_; }

 private:
  bool SkipLintCheck() const { return name_.length() > 0 && name_[0] == '_'; }

  BindingsManager<T>* manager_;
  const std::string name_;
  std::optional<Binding*> previous_binding_;
  SourcePosition declaration_position_ = CurrentSourcePosition::Get();
  bool used_;
  bool written_;
  uint64_t unique_index_;
};

template <class T>
class BlockBindings {
 public:
  explicit BlockBindings(BindingsManager<T>* manager) : manager_(manager) {}
  Binding<T>* Add(std::string name, T value, bool mark_as_used = false) {
    ReportErrorIfAlreadyBound(name);
    auto binding =
        std::make_unique<Binding<T>>(manager_, name, std::move(value));
    Binding<T>* result = binding.get();
    if (mark_as_used) binding->SetUsed();
    bindings_.push_back(std::move(binding));
    return result;
  }

  Binding<T>* Add(const Identifier* name, T value, bool mark_as_used = false) {
    ReportErrorIfAlreadyBound(name->value);
    auto binding =
        std::make_unique<Binding<T>>(manager_, name, std::move(value));
    Binding<T>* result = binding.get();
    if (mark_as_used) binding->SetUsed();
    bindings_.push_back(std::move(binding));
    return result;
  }

  std::vector<Binding<T>*> bindings() const {
    std::vector<Binding<T>*> result;
    result.reserve(bindings_.size());
    for (auto& b : bindings_) {
      result.push_back(b.get());
    }
    return result;
  }

 private:
  void ReportErrorIfAlreadyBound(const std::string& name) {
    for (const auto& binding : bindings_) {
      if (binding->name() == name) {
        ReportError(
            "redeclaration of name \"", name,
            "\" in the same block is illegal, previous declaration at: ",
            binding->declaration_position());
      }
    }
  }

  BindingsManager<T>* manager_;
  std::vector<std::unique_ptr<Binding<T>>> bindings_;
};

class LocalValue {
 public:
  explicit LocalValue(LocationReference reference)
      : value(std::move(reference)) {}
  explicit LocalValue(std::string inaccessible_explanation)
      : inaccessible_explanation(std::move(inaccessible_explanation)) {}
  explicit LocalValue(std::function<LocationReference()> lazy)
      : lazy(std::move(lazy)) {}

  LocationReference GetLocationReference(Binding<LocalValue>* binding) {
    if (value) {
      const LocationReference& ref = *value;
      if (ref.IsVariableAccess()) {
        // Attach the binding to enable the never-assigned-to lint check.
        return LocationReference::VariableAccess(ref.GetVisitResult(), binding);
      }
      return ref;
    } else if (lazy) {
      return (*lazy)();
    } else {
      Error("Cannot access ", binding->name(), ": ", inaccessible_explanation)
          .Throw();
    }
  }

  bool IsAccessibleNonLazy() const { return value.has_value(); }

 private:
  std::optional<LocationReference> value;
  std::optional<std::function<LocationReference()>> lazy;
  std::string inaccessible_explanation;
};

struct LocalLabel {
  Block* block;
  std::vector<const Type*> parameter_types;

  explicit LocalLabel(Block* block,
                      std::vector<const Type*> parameter_types = {})
      : block(block), parameter_types(std::move(parameter_types)) {}
};

template <>
inline std::string Binding<LocalValue>::BindingTypeString() const {
  return "Variable ";
}
template <>
inline bool Binding<LocalValue>::CheckWritten() const {
  // Do the check only for non-const variables and non struct types.
  auto binding = *manager_->current_bindings_[name_];
  if (!binding->IsAccessibleNonLazy()) return false;
  const LocationReference& ref = binding->GetLocationReference(binding);
  if (!ref.IsVariableAccess()) return false;
  return !ref.GetVisitResult().type()->StructSupertype();
}
template <>
inline std::string Binding<LocalLabel>::BindingTypeString() const {
  return "Label ";
}
template <>
inline bool Binding<LocalLabel>::CheckWritten() const {
  return false;
}

struct Arguments {
  VisitResultVector parameters;
  std::vector<Binding<LocalLabel>*> labels;
};

// Determine if a callable should be considered as an overload.
bool IsCompatibleSignature(const Signature& sig, const TypeVector& types,
                           size_t label_count);

class ImplementationVisitor {
 public:
  void GenerateBuiltinDefinitionsAndInterfaceDescriptors(
      const std::string& output_directory);
  void GenerateVisitorLists(const std::string& output_directory);
  void GenerateBitFields(const std::string& output_directory);
  void GeneratePrintDefinitions(const std::string& output_directory);
  void GenerateClassDefinitions(const std::string& output_directory);
  void GenerateBodyDescriptors(const std::string& output_directory);
  void GenerateInstanceTypes(const std::string& output_directory);
  void GenerateClassVerifiers(const std::string& output_directory);
  void GenerateEnumVerifiers(const std::string& output_directory);
  void GenerateClassDebugReaders(const std::string& output_directory);
  void GenerateExportedMacrosAssembler(const std::string& output_directory);
  void GenerateCSATypes(const std::string& output_directory);

  VisitResult Visit(Expression* expr);
  const Type* Visit(Statement* stmt);

  template <typename T>
  void CheckInitializersWellformed(
      const std::string& aggregate_name, const std::vector<T>& aggregate_fields,
      const std::vector<NameAndExpression>& initializers,
      bool ignore_first_field = false) {
    size_t fields_offset = ignore_first_field ? 1 : 0;
    size_t fields_size = aggregate_fields.size() - fields_offset;
    for (size_t i = 0; i < std::min(fields_size, initializers.size()); i++) {
      const std::string& field_name =
          aggregate_fields[i + fields_offset].name_and_type.name;
      Identifier* found_name = initializers[i].name;
      if (field_name != found_name->value) {
        Error("Expected field name \"", field_name, "\" instead of \"",
              found_name->value, "\"")
            .Position(found_name->pos)
            .Throw();
      }
    }
    if (fields_size != initializers.size()) {
      ReportError("expected ", fields_size, " initializers for ",
                  aggregate_name, " found ", initializers.size());
    }
  }

  InitializerResults VisitInitializerResults(
      const ClassType* class_type,
      const std::vector<NameAndExpression>& expressions);
  LocationReference GenerateFieldReference(
      VisitResult object, const Field& field, const ClassType* class_type,
      bool treat_optional_as_indexed = false);
  LocationReference GenerateFieldReferenceForInit(
      VisitResult object, const Field& field,
      const LayoutForInitialization& layout);
  VisitResult GenerateArrayLength(
      Expression* array_length, Namespace* nspace,
      const std::map<std::string, LocalValue>& bindings);
  VisitResult GenerateArrayLength(VisitResult object, const Field& field);
  VisitResult GenerateArrayLength(const ClassType* class_type,
                                  const InitializerResults& initializer_results,
                                  const Field& field);
  LayoutForInitialization GenerateLayoutForInitialization(
      const ClassType* class_type,
      const InitializerResults& initializer_results);

  void InitializeClass(const ClassType* class_type, VisitResult allocate_result,
                       const InitializerResults& initializer_results,
                       const LayoutForInitialization& layout);

  VisitResult Visit(StructExpression* decl);

  LocationReference GetLocationReference(Expression* location);
  LocationReference LookupLocalValue(const std::string& name);
  LocationReference GetLocationReference(IdentifierExpression* expr);
  LocationReference GetLocationReference(DereferenceExpression* expr);
  LocationReference GetLocationReference(FieldAccessExpression* expr);
  LocationReference GenerateFieldAccess(
      LocationReference reference, const std::string& fieldname,
      bool ignore_stuct_field_constness = false,
      std::optional<SourcePosition> pos = {});
  LocationReference GetLocationReference(ElementAccessExpression* expr);
  LocationReference GenerateReferenceToItemInHeapSlice(LocationReference slice,
                                                       VisitResult index);

  VisitResult GenerateFetchFromLocation(const LocationReference& reference);

  VisitResult GetBuiltinCode(Builtin* builtin);

  VisitResult Visit(LocationExpression* expr);
  VisitResult Visit(FieldAccessExpression* expr);

  void VisitAllDeclarables();
  void Visit(Declarable* delarable, std::optional<SourceId> file = {});
  void Visit(TypeAlias* decl);
  VisitResult InlineMacro(Macro* macro,
                          std::optional<LocationReference> this_reference,
                          const std::vector<VisitResult>& arguments,
                          const std::vector<Block*> label_blocks);
  void VisitMacroCommon(Macro* macro);
  void Visit(ExternMacro* macro) {}
  void Visit(TorqueMacro* macro);
  void Visit(Method* macro);
  void Visit(Builtin* builtin);
  void Visit(NamespaceConstant* decl);

  VisitResult Visit(CallExpression* expr, bool is_tail = false);
  VisitResult Visit(CallMethodExpression* expr);
  VisitResult Visit(IntrinsicCallExpression* intrinsic);
  const Type* Visit(TailCallStatement* stmt);

  VisitResult Visit(ConditionalExpression* expr);

  VisitResult Visit(LogicalOrExpression* expr);
  VisitResult Visit(LogicalAndExpression* expr);

  VisitResult Visit(IncrementDecrementExpression* expr);
  VisitResult Visit(AssignmentExpression* expr);
  VisitResult Visit(StringLiteralExpression* expr);
  VisitResult Visit(FloatingPointLiteralExpression* expr);
  VisitResult Visit(IntegerLiteralExpression* expr);
  VisitResult Visit(AssumeTypeImpossibleExpression* expr);
  VisitResult Visit(TryLabelExpression* expr);
  VisitResult Visit(StatementExpression* expr);
  VisitResult Visit(NewExpression* expr);
  VisitResult Visit(SpreadExpression* expr);

  const Type* Visit(ReturnStatement* stmt);
  const Type* Visit(GotoStatement* stmt);
  const Type* Visit(IfStatement* stmt);
  const Type* Visit(WhileStatement* stmt);
  const Type* Visit(BreakStatement* stmt);
  const Type* Visit(ContinueStatement* stmt);
  const Type* Visit(ForLoopStatement* stmt);
  const Type* Visit(VarDeclarationStatement* stmt);
  const Type* Visit(VarDeclarationStatement* stmt,
                    BlockBindings<LocalValue>* block_bindings);
  const Type* Visit(BlockStatement* block);
  const Type* Visit(ExpressionStatement* stmt);
  const Type* Visit(DebugStatement* stmt);
  const Type* Visit(AssertStatement* stmt);

  void BeginGeneratedFiles();
  void EndGeneratedFiles();
  void BeginDebugMacrosFile();
  void EndDebugMacrosFile();

  void GenerateImplementation(const std::string& dir);

  DECLARE_CONTEXTUAL_VARIABLE(ValueBindingsManager,
                              BindingsManager<LocalValue>);
  DECLARE_CONTEXTUAL_VARIABLE(LabelBindingsManager,
                              BindingsManager<LocalLabel>);
  DECLARE_CONTEXTUAL_VARIABLE(CurrentCallable, Callable*);
  DECLARE_CONTEXTUAL_VARIABLE(CurrentFileStreams,
                              GlobalContext::PerFileStreams*);
  DECLARE_CONTEXTUAL_VARIABLE(CurrentReturnValue, std::optional<VisitResult>);

  // A BindingsManagersScope has to be active for local bindings to be created.
  // Shadowing an existing BindingsManagersScope by creating a new one hides all
  // existing bindings while the additional BindingsManagersScope is active.
  struct BindingsManagersScope {
    ValueBindingsManager::Scope value_bindings_manager;
    LabelBindingsManager::Scope label_bindings_manager;
  };

  void SetDryRun(bool is_dry_run) { is_dry_run_ = is_dry_run; }

 private:
  std::optional<Block*> GetCatchBlock();
  void GenerateCatchBlock(std::optional<Block*> catch_block);

  // {StackScope} records the stack height at creation time and reconstructs it
  // when being destructed by emitting a {DeleteRangeInstruction}, except for
  // the slots protected by {StackScope::Yield}. Calling {Yield(v)} deletes all
  // slots above the initial stack height except for the slots of {v}, which are
  // moved to form the only slots above the initial height and marks them to
  // survive destruction of the {StackScope}. A typical pattern is the
  // following:
  //
  // VisitResult result;
  // {
  //   StackScope stack_scope(this);
  //   // ... create temporary slots ...
  //   result = stack_scope.Yield(surviving_slots);
  // }
  class V8_NODISCARD StackScope {
   public:
    explicit StackScope(ImplementationVisitor* visitor) : visitor_(visitor) {
      base_ = visitor_->assembler().CurrentStack().AboveTop();
    }
    VisitResult Yield(VisitResult result) {
      DCHECK(!closed_);
      closed_ = true;
      if (!result.IsOnStack()) {
        if (!visitor_->assembler().CurrentBlockIsComplete()) {
          visitor_->assembler().DropTo(base_);
        }
        return result;
      }
      DCHECK_LE(base_, result.stack_range().begin());
      DCHECK_LE(result.stack_range().end(),
                visitor_->assembler().CurrentStack().AboveTop());
      visitor_->assembler().DropTo(result.stack_range().end());
      visitor_->assembler().DeleteRange(
          StackRange{base_, result.stack_range().begin()});
      base_ = visitor_->assembler().CurrentStack().AboveTop();
      return VisitResult(result.type(), visitor_->assembler().TopRange(
                                            result.stack_range().Size()));
    }

    void Close() {
      DCHECK(!closed_);
      closed_ = true;
      if (!visitor_->assembler().CurrentBlockIsComplete()) {
        visitor_->assembler().DropTo(base_);
      }
    }

    ~StackScope() {
      if (closed_) {
        DCHECK_IMPLIES(
            !visitor_->assembler().CurrentBlockIsComplete(),
            base_ == visitor_->assembler().CurrentStack().AboveTop());
      } else {
        Close();
      }
    }

   private:
    ImplementationVisitor* visitor_;
    BottomOffset base_;
    bool closed_ = false;
  };

  class BreakContinueActivator {
   public:
    BreakContinueActivator(Block* break_block, Block* continue_block)
        : break_binding_{&LabelBindingsManager::Get(), kBreakLabelName,
                         LocalLabel{break_block}},
          continue_binding_{&LabelBindingsManager::Get(), kContinueLabelName,
                            LocalLabel{continue_block}} {}

   private:
    Binding<LocalLabel> break_binding_;
    Binding<LocalLabel> continue_binding_;
  };

  std::optional<Binding<LocalValue>*> TryLookupLocalValue(
      const std::string& name);
  std::optional<Binding<LocalLabel>*> TryLookupLabel(const std::string& name);
  Binding<LocalLabel>* LookupLabel(const std::string& name);
  Block* LookupSimpleLabel(const std::string& name);
  template <class Container>
  Callable* LookupCallable(const QualifiedName& name,
                           const Container& declaration_container,
                           const TypeVector& types,
                           const std::vector<Binding<LocalLabel>*>& labels,
                           const TypeVector& specialization_types,
                           bool silence_errors = false);
  bool TestLookupCallable(const QualifiedName& name,
                          const TypeVector& parameter_types);

  template <class Container>
  Callable* LookupCallable(const QualifiedName& name,
                           const Container& declaration_container,
                           const Arguments& arguments,
                           const TypeVector& specialization_types);

  Method* LookupMethod(const std::string& name,
                       const AggregateType* receiver_type,
                       const Arguments& arguments,
                       const TypeVector& specialization_types);

  TypeArgumentInference InferSpecializationTypes(
      GenericCallable* generic, const TypeVector& explicit_specialization_types,
      const TypeVector& explicit_arguments);

  const Type* GetCommonType(const Type* left, const Type* right);

  VisitResult GenerateCopy(const VisitResult& to_copy);

  void GenerateAssignToLocation(const LocationReference& reference,
                                const VisitResult& assignment_value);

  void AddCallParameter(Callable* callable, VisitResult parameter,
                        const Type* parameter_type,
                        std::vector<VisitResult>* converted_arguments,
                        StackRange* argument_range,
                        std::vector<std::string>* constexpr_arguments,
                        bool inline_macro);

  VisitResult GenerateCall(Callable* callable,
                           std::optional<LocationReference> this_parameter,
                           Arguments parameters,
                           const TypeVector& specialization_types = {},
                           bool tail_call = false);
  VisitResult GenerateCall(const QualifiedName& callable_name,
                           Arguments parameters,
                           const TypeVector& specialization_types = {},
                           bool tail_call = false);
  VisitResult GenerateCall(std::string callable_name, Arguments parameters,
                           const TypeVector& specialization_types = {},
                           bool tail_call = false) {
    return GenerateCall(QualifiedName(std::move(callable_name)),
                        std::move(parameters), specialization_types, tail_call);
  }
  VisitResult GeneratePointerCall(Expression* callee,
                                  const Arguments& parameters, bool tail_call);

  void GenerateBranch(const VisitResult& condition, Block* true_block,
                      Block* false_block);

  VisitResult GenerateBoolConstant(bool constant);

  void GenerateExpressionBranch(Expression* expression, Block* true_block,
                                Block* false_block);

  cpp::Function GenerateMacroFunctionDeclaration(Macro* macro);

  cpp::Function GenerateFunction(
      cpp::Class* owner, const std::string& name, const Signature& signature,
      const NameVector& parameter_names, bool pass_code_assembler_state = true,
      std::vector<std::string>* generated_parameter_names = nullptr);

  VisitResult GenerateImplicitConvert(const Type* destination_type,
                                      VisitResult source);

  StackRange GenerateLabelGoto(LocalLabel* label,
                               std::optional<StackRange> arguments = {});

  VisitResult GenerateSetBitField(const Type* bitfield_struct_type,
                                  const BitField& bitfield,
                                  VisitResult bitfield_struct,
                                  VisitResult value,
                                  bool starts_as_zero = false);

  std::vector<Binding<LocalLabel>*> LabelsFromIdentifiers(
      const std::vector<Identifier*>& names);

  StackRange LowerParameter(const Type* type, const std::string& parameter_name,
                            Stack<std::string>* lowered_parameters);

  void LowerLabelParameter(const Type* type, const std::string& parameter_name,
                           std::vector<std::string>* lowered_parameters);

  std::string ExternalLabelName(const std::string& label_name);
  std::string ExternalLabelParameterName(const std::string& label_name,
                                         size_t i);
  std::string ExternalParameterName(const std::string& name);

  std::ostream& csa_ccfile() {
    if (auto* streams = CurrentFileStreams::Get()) {
      switch (output_type_) {
        case OutputType::kCSA:
          return streams->csa_ccfile;
        case OutputType::kCC:
          return streams->class_definition_inline_headerfile_macro_definitions;
        case OutputType::kCCDebug:
          return debug_macros_cc_;
        default:
          UNREACHABLE();
      }
    }
    return null_stream_;
  }
  std::ostream& csa_headerfile() {
    if (auto* streams = CurrentFileStreams::Get()) {
      switch (output_type_) {
        case OutputType::kCSA:
          return streams->csa_headerfile;
        case OutputType::kCC:
          return streams->class_definition_inline_headerfile_macro_declarations;
        case OutputType::kCCDebug:
          return debug_macros_h_;
        default:
          UNREACHABLE();
      }
    }
    return null_stream_;
  }

  CfgAssembler& assembler() { return *assembler_; }

  void SetReturnValue(VisitResult return_value) {
    std::optional<VisitResult>& current_return_value =
        CurrentReturnValue::Get();
    DCHECK_IMPLIES(current_return_value, *current_return_value == return_value);
    current_return_value = std::move(return_value);
  }

  VisitResult GetAndClearReturnValue() {
    VisitResult return_value = *CurrentReturnValue::Get();
    CurrentReturnValue::Get() = std::nullopt;
    return return_value;
  }

  void WriteFile(const std::string& file, const std::string& content) {
    if (is_dry_run_) return;
    ReplaceFileContentsIfDifferent(file, content);
  }

  const Identifier* TryGetSourceForBitfieldExpression(
      const Expression* expr) const {
    auto it = bitfield_expressions_.find(expr);
    if (it == bitfield_expressions_.end()) return nullptr;
    return it->second;
  }

  void PropagateBitfieldMark(const Expression* original,
                             const Expression* derived) {
    if (const Identifier* source =
            TryGetSourceForBitfieldExpression(original)) {
      bitfield_expressions_[derived] = source;
    }
  }

  class MacroInliningScope;

  std::optional<CfgAssembler> assembler_;
  NullOStream null_stream_;
  bool is_dry_run_;

  // Just for allowing us to emit warnings. After visiting an Expression, if
  // that Expression is a bitfield load, plus an optional inversion or an
  // equality check with a constant, then that Expression will be present in
  // this map. The Identifier associated is the bitfield struct that contains
  // the value to load.
  std::unordered_map<const Expression*, const Identifier*>
      bitfield_expressions_;

  // For emitting warnings. Contains the current set of macros being inlined in
  // calls to InlineMacro.
  std::unordered_set<const Macro*> inlining_macros_;

  // The contents of the debug macros output files. These contain all Torque
  // macros that have been generated using the C++ backend with debug purpose.
  std::stringstream debug_macros_cc_;
```