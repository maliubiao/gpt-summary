Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/test/unittests/compiler/node-test-utils.cc`. The request also includes several specific constraints:

1. **List Functionalities:**  Identify what the code does.
2. **Torque Source Check:** Determine if the file could be a Torque file (it's not, based on the `.cc` extension).
3. **JavaScript Relevance:** Explain any connection to JavaScript functionality, providing examples if applicable.
4. **Code Logic Inference:** If there's logical deduction, provide example inputs and outputs.
5. **Common Programming Errors:**  Point out if the code relates to typical programming mistakes.
6. **Part of a Series:** Acknowledge that this is part 2 of 4.
7. **Summarize Functionality (Part 2):**  Specifically summarize the functionality of *this* snippet.

**Mental Model:**

The code defines a series of C++ classes that inherit from `TestNodeMatcher`. These classes appear to be used for matching specific types of nodes in V8's intermediate representation (IR). Each class seems to correspond to a particular IR node opcode (e.g., `kLoadField`, `kStoreElement`). They take `Matcher` objects as arguments to specify criteria for the node's properties (like inputs, access type, representation).

**Step-by-step Analysis:**

1. **Iterate through each class:**  Analyze the purpose of `IsLoadFieldMatcher`, `IsStoreFieldMatcher`, `IsLoadElementMatcher`, `IsStoreElementMatcher`, and the `LOAD_MATCHER` and `STORE_MATCHER` macros.
2. **Identify common patterns:**  Notice the `DescribeTo` and `MatchAndExplain` methods in each class, suggesting a pattern for describing and matching IR nodes.
3. **Connect to IR concepts:** Recognize terms like "opcode," "control," "effect," "base," "index," "value," "representation," "access," which are all core concepts in compiler IRs.
4. **Relate to testing:** The file path (`v8/test/unittests/...`) and class names (like `TestNodeMatcher`) strongly suggest these are utilities for writing compiler tests.
5. **Address specific constraints:**
    * **Functionalities:**  The primary function is creating matchers for specific IR node types with customizable criteria.
    * **Torque:** The `.cc` extension indicates C++, not Torque (`.tq`).
    * **JavaScript Relevance:** These matchers are used to verify the correctness of the compiler's output when processing JavaScript code.
    * **Code Logic Inference:** The `MatchAndExplain` methods implement the matching logic. Input would be an IR node, and output would be `true` if it matches the criteria, `false` otherwise, along with an explanation of any mismatches.
    * **Common Programming Errors:** While these aren't directly *fixing* user errors, they help ensure the compiler handles different JavaScript constructs correctly, including potentially error-prone ones (like accessing undefined properties).
    * **Summarize Part 2:** Focus on the specific node types covered in this snippet (loads, stores, stack slots, type conversions, context loads, binary/unary/ternary/quad operations, string concatenation, and parameters).

**Pre-computation/Pre-analysis:**

* **Familiarity with Compiler IR:**  Having a basic understanding of compiler intermediate representations (nodes, opcodes, control flow, data flow) is crucial.
* **V8's Architecture (Optional but helpful):** Knowing that V8 uses an optimizing compiler and has an IR simplifies understanding the context.
* **C++ Basics:**  Understanding class inheritance, methods, and templates in C++ is necessary to parse the code.

**Self-Correction/Refinement:**

Initially, I might have focused too much on the individual details of each matcher. However, realizing the overarching pattern of "matching IR nodes" is key to a concise summary. Also, remembering the context of "testing" is important. The examples for JavaScript relevance should be simple and illustrate the *kind* of operations these nodes represent, not necessarily the exact IR structure for a complex case.

By following these steps, I can generate a comprehensive and accurate answer that addresses all the user's requirements.
这是 `v8/test/unittests/compiler/node-test-utils.cc` 源代码的第二部分，它定义了一系列的 C++ 类，这些类被称为 "Matchers" (匹配器)。这些匹配器的主要功能是用于在 V8 编译器生成的中间表示 (IR) 图中查找和验证特定的节点。

**功能归纳 (基于提供的代码片段):**

这部分代码定义了用于匹配特定类型 IR 节点的匹配器，主要关注以下操作：

* **内存访问 (Load/Store)：**
    * `IsLoadFieldMatcher`: 匹配加载对象字段的节点。
    * `IsStoreFieldMatcher`: 匹配存储对象字段的节点。
    * `IsLoadElementMatcher`: 匹配加载数组元素的节点。
    * `IsStoreElementMatcher`: 匹配存储数组元素的节点。
    * 使用宏 `LOAD_MATCHER` 和 `STORE_MATCHER` 定义了更多通用的加载和存储操作的匹配器，例如 `IsLoadMatcher`, `IsUnalignedLoadMatcher`, `IsLoadFromObjectMatcher`, `IsStoreMatcher`, `IsUnalignedStoreMatcher`, `IsStoreToObjectMatcher`。这些宏允许指定更细粒度的属性，如数据表示 (representation)。
    * `IsLoadImmutableMatcher`: 匹配加载不可变值的节点。
* **栈操作：**
    * `IsStackSlotMatcher`: 匹配表示栈槽的节点。
* **类型转换：**
    * `IsToNumberMatcher`: 匹配将值转换为数字的节点。
* **上下文操作：**
    * `IsLoadContextMatcher`: 匹配加载上下文变量的节点。
* **通用操作符：**
    * `IsQuadopMatcher`: 匹配具有四个输入值的操作符节点。
    * `IsTernopMatcher`: 匹配具有三个输入值的操作符节点。
    * `IsBinopMatcher`: 匹配具有两个输入值的操作符节点。
    * `IsStringConcatMatcher`: 匹配字符串连接操作的节点。
    * `IsUnopMatcher`: 匹配具有一个输入值的操作符节点。
* **参数：**
    * `IsParameterMatcher`: 匹配函数参数节点。
* **控制流：**
    * `IsDead()`: 匹配死代码节点。
    * `IsUnreachable()`: 匹配不可达代码节点。
    * `IsThrow()`: 匹配抛出异常的节点。
    * `IsStart()`: 匹配控制流的起始节点。
    * `IsEnd()`: 匹配控制流的结束节点，可以有多个控制输入。
    * `IsBranch()`: 匹配分支节点。
    * `IsMerge()`: 匹配合并控制流的节点。

**关于文件类型和 JavaScript 功能的关系：**

`v8/test/unittests/compiler/node-test-utils.cc` 以 `.cc` 结尾，这表明它是一个 **C++ 源代码文件**。`.tq` 结尾的文件是 V8 的 **Torque 源代码文件**，Torque 是一种用于定义 V8 内部函数的领域特定语言。

虽然这个文件本身不是 Torque 代码，但它与 JavaScript 的功能密切相关。 这些匹配器用于测试 V8 编译器在将 JavaScript 代码编译成机器码的过程中，是否正确地生成了预期的 IR 图。

**JavaScript 举例说明:**

假设我们有以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}
```

当 V8 编译这个函数时，会生成一个 IR 图。 `node-test-utils.cc` 中定义的匹配器可以用来断言这个 IR 图中是否存在特定的节点。例如，可能会有以下类型的匹配器被使用：

* `IsParameterMatcher(0)`: 匹配表示参数 `a` 的节点。
* `IsParameterMatcher(1)`: 匹配表示参数 `b` 的节点。
* `IsBinopMatcher(IrOpcode::kNumberAdd, /* matcher for 'a' */, /* matcher for 'b' */)`: 匹配执行数字加法操作的节点，其输入是参数 `a` 和 `b` 对应的节点。
* `IsEnd(/* matcher for the add operation */)`: 匹配函数的结束节点，其控制输入是加法操作对应的节点。

**代码逻辑推理 (以 `IsLoadFieldMatcher` 为例):**

假设我们有一个 `IsLoadFieldMatcher` 的实例，用于匹配加载对象 `obj` 的字段 `property` 的操作。

**假设输入:**

* `node`: 一个表示 IR `LoadField` 操作的节点。
* `access_matcher_`: 一个匹配 `FieldAccess` 对象，且该对象表示访问 `obj.property` 的匹配器。
* `base_matcher_`: 一个匹配表示 `obj` 的节点的匹配器。
* `effect_matcher_`: 一个匹配表示加载操作的副作用链的节点的匹配器。
* `control_matcher_`: 一个匹配表示控制流的节点的匹配器。

**输出:**

* 如果 `node` 的操作码是 `IrOpcode::kLoadField`，并且其 `FieldAccess`、基础对象、副作用和控制流输入分别与 `access_matcher_`、`base_matcher_`、`effect_matcher_` 和 `control_matcher_` 匹配，则 `MatchAndExplain` 方法返回 `true`。
* 否则，返回 `false`，并且 `MatchResultListener` 会记录不匹配的原因。

**涉及用户常见的编程错误 (间接相关):**

虽然这些匹配器不是直接用于捕获用户编写 JavaScript 代码时的错误，但它们在测试编译器的正确性时非常重要。 编译器需要能够正确处理各种合法的 JavaScript 代码，包括可能导致运行时错误的模式。 例如：

* **访问未定义的属性:**  编译器需要为这种情况生成合适的代码，而测试可以使用 `IsLoadFieldMatcher` 来验证是否生成了正确的加载操作。
* **类型错误:** 编译器需要处理不同类型之间的运算，例如字符串和数字的相加。 `IsBinopMatcher` 可以用来验证编译器是否为这些操作生成了正确的 IR 节点。

**总结第 2 部分的功能:**

总而言之，这部分 `node-test-utils.cc` 代码的核心功能是 **定义了一系列 C++ 匹配器，用于在 V8 编译器的 IR 图中查找和验证特定类型的节点及其属性。** 这些匹配器是 V8 编译器单元测试的基础设施，用于确保编译器能够正确地将 JavaScript 代码转换为高效的机器码。它们覆盖了各种常见的 IR 节点类型，包括内存访问、栈操作、类型转换、上下文访问和通用操作符。

Prompt: 
```
这是目录为v8/test/unittests/compiler/node-test-utils.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/node-test-utils.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
    PrintMatchAndExplain(NodeProperties::GetControlInput(node),
                                 "control", control_matcher_, listener));
  }

 private:
  const Matcher<Node*> size_matcher_;
  const Matcher<Node*> effect_matcher_;
  const Matcher<Node*> control_matcher_;
};

class IsLoadFieldMatcher final : public TestNodeMatcher {
 public:
  IsLoadFieldMatcher(const Matcher<FieldAccess>& access_matcher,
                     const Matcher<Node*>& base_matcher,
                     const Matcher<Node*>& effect_matcher,
                     const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(IrOpcode::kLoadField),
        access_matcher_(access_matcher),
        base_matcher_(base_matcher),
        effect_matcher_(effect_matcher),
        control_matcher_(control_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose access (";
    access_matcher_.DescribeTo(os);
    *os << "), base (";
    base_matcher_.DescribeTo(os);
    *os << "), effect (";
    effect_matcher_.DescribeTo(os);
    *os << ") and control (";
    control_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(FieldAccessOf(node->op()), "access",
                                 access_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0), "base",
                                 base_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetEffectInput(node), "effect",
                                 effect_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node),
                                 "control", control_matcher_, listener));
  }

 private:
  const Matcher<FieldAccess> access_matcher_;
  const Matcher<Node*> base_matcher_;
  const Matcher<Node*> effect_matcher_;
  const Matcher<Node*> control_matcher_;
};

class IsStoreFieldMatcher final : public TestNodeMatcher {
 public:
  IsStoreFieldMatcher(const Matcher<FieldAccess>& access_matcher,
                      const Matcher<Node*>& base_matcher,
                      const Matcher<Node*>& value_matcher,
                      const Matcher<Node*>& effect_matcher,
                      const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(IrOpcode::kStoreField),
        access_matcher_(access_matcher),
        base_matcher_(base_matcher),
        value_matcher_(value_matcher),
        effect_matcher_(effect_matcher),
        control_matcher_(control_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose access (";
    access_matcher_.DescribeTo(os);
    *os << "), base (";
    base_matcher_.DescribeTo(os);
    *os << "), value (";
    value_matcher_.DescribeTo(os);
    *os << "), effect (";
    effect_matcher_.DescribeTo(os);
    *os << ") and control (";
    control_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(FieldAccessOf(node->op()), "access",
                                 access_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0), "base",
                                 base_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1),
                                 "value", value_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetEffectInput(node), "effect",
                                 effect_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node),
                                 "control", control_matcher_, listener));
  }

 private:
  const Matcher<FieldAccess> access_matcher_;
  const Matcher<Node*> base_matcher_;
  const Matcher<Node*> value_matcher_;
  const Matcher<Node*> effect_matcher_;
  const Matcher<Node*> control_matcher_;
};

class IsLoadElementMatcher final : public TestNodeMatcher {
 public:
  IsLoadElementMatcher(const Matcher<ElementAccess>& access_matcher,
                       const Matcher<Node*>& base_matcher,
                       const Matcher<Node*>& index_matcher,
                       const Matcher<Node*>& effect_matcher,
                       const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(IrOpcode::kLoadElement),
        access_matcher_(access_matcher),
        base_matcher_(base_matcher),
        index_matcher_(index_matcher),
        effect_matcher_(effect_matcher),
        control_matcher_(control_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose access (";
    access_matcher_.DescribeTo(os);
    *os << "), base (";
    base_matcher_.DescribeTo(os);
    *os << "), index (";
    index_matcher_.DescribeTo(os);
    *os << "), effect (";
    effect_matcher_.DescribeTo(os);
    *os << ") and control (";
    control_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(ElementAccessOf(node->op()), "access",
                                 access_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0), "base",
                                 base_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1),
                                 "index", index_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetEffectInput(node), "effect",
                                 effect_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node),
                                 "control", control_matcher_, listener));
  }

 private:
  const Matcher<ElementAccess> access_matcher_;
  const Matcher<Node*> base_matcher_;
  const Matcher<Node*> index_matcher_;
  const Matcher<Node*> effect_matcher_;
  const Matcher<Node*> control_matcher_;
};

class IsStoreElementMatcher final : public TestNodeMatcher {
 public:
  IsStoreElementMatcher(const Matcher<ElementAccess>& access_matcher,
                        const Matcher<Node*>& base_matcher,
                        const Matcher<Node*>& index_matcher,
                        const Matcher<Node*>& value_matcher,
                        const Matcher<Node*>& effect_matcher,
                        const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(IrOpcode::kStoreElement),
        access_matcher_(access_matcher),
        base_matcher_(base_matcher),
        index_matcher_(index_matcher),
        value_matcher_(value_matcher),
        effect_matcher_(effect_matcher),
        control_matcher_(control_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose access (";
    access_matcher_.DescribeTo(os);
    *os << "), base (";
    base_matcher_.DescribeTo(os);
    *os << "), index (";
    index_matcher_.DescribeTo(os);
    *os << "), value (";
    value_matcher_.DescribeTo(os);
    *os << "), effect (";
    effect_matcher_.DescribeTo(os);
    *os << ") and control (";
    control_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(ElementAccessOf(node->op()), "access",
                                 access_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0), "base",
                                 base_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1),
                                 "index", index_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 2),
                                 "value", value_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetEffectInput(node), "effect",
                                 effect_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node),
                                 "control", control_matcher_, listener));
  }

 private:
  const Matcher<ElementAccess> access_matcher_;
  const Matcher<Node*> base_matcher_;
  const Matcher<Node*> index_matcher_;
  const Matcher<Node*> value_matcher_;
  const Matcher<Node*> effect_matcher_;
  const Matcher<Node*> control_matcher_;
};

#define LOAD_MATCHER(kLoad)                                                   \
  class Is##kLoad##Matcher final : public TestNodeMatcher {                   \
   public:                                                                    \
    Is##kLoad##Matcher(const Matcher<LoadRepresentation>& rep_matcher,        \
                       const Matcher<Node*>& base_matcher,                    \
                       const Matcher<Node*>& index_matcher,                   \
                       const Matcher<Node*>& effect_matcher,                  \
                       const Matcher<Node*>& control_matcher)                 \
        : TestNodeMatcher(IrOpcode::k##kLoad),                                \
          rep_matcher_(rep_matcher),                                          \
          base_matcher_(base_matcher),                                        \
          index_matcher_(index_matcher),                                      \
          effect_matcher_(effect_matcher),                                    \
          control_matcher_(control_matcher) {}                                \
                                                                              \
    void DescribeTo(std::ostream* os) const final {                           \
      TestNodeMatcher::DescribeTo(os);                                        \
      *os << " whose rep (";                                                  \
      rep_matcher_.DescribeTo(os);                                            \
      *os << "), base (";                                                     \
      base_matcher_.DescribeTo(os);                                           \
      *os << "), index (";                                                    \
      index_matcher_.DescribeTo(os);                                          \
      *os << "), effect (";                                                   \
      effect_matcher_.DescribeTo(os);                                         \
      *os << ") and control (";                                               \
      control_matcher_.DescribeTo(os);                                        \
      *os << ")";                                                             \
    }                                                                         \
                                                                              \
    bool MatchAndExplain(Node* node,                                          \
                         MatchResultListener* listener) const final {         \
      Node* effect_node = nullptr;                                            \
      Node* control_node = nullptr;                                           \
      if (NodeProperties::FirstEffectIndex(node) < node->InputCount()) {      \
        effect_node = NodeProperties::GetEffectInput(node);                   \
      }                                                                       \
      if (NodeProperties::FirstControlIndex(node) < node->InputCount()) {     \
        control_node = NodeProperties::GetControlInput(node);                 \
      }                                                                       \
      LoadRepresentation rep = IrOpcode::kLoadFromObject == node->opcode()    \
                                   ? ObjectAccessOf(node->op()).machine_type  \
                                   : LoadRepresentationOf(node->op());        \
      return (TestNodeMatcher::MatchAndExplain(node, listener) &&             \
              PrintMatchAndExplain(rep, "rep", rep_matcher_, listener) &&     \
              PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0),    \
                                   "base", base_matcher_, listener) &&        \
              PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1),    \
                                   "index", index_matcher_, listener) &&      \
              PrintMatchAndExplain(effect_node, "effect", effect_matcher_,    \
                                   listener) &&                               \
              PrintMatchAndExplain(control_node, "control", control_matcher_, \
                                   listener));                                \
    }                                                                         \
                                                                              \
   private:                                                                   \
    const Matcher<LoadRepresentation> rep_matcher_;                           \
    const Matcher<Node*> base_matcher_;                                       \
    const Matcher<Node*> index_matcher_;                                      \
    const Matcher<Node*> effect_matcher_;                                     \
    const Matcher<Node*> control_matcher_;                                    \
  };

LOAD_MATCHER(Load)
LOAD_MATCHER(UnalignedLoad)
LOAD_MATCHER(LoadFromObject)

class IsLoadImmutableMatcher final : public TestNodeMatcher {
 public:
  IsLoadImmutableMatcher(const Matcher<LoadRepresentation>& rep_matcher,
                         const Matcher<Node*>& base_matcher,
                         const Matcher<Node*>& index_matcher)
      : TestNodeMatcher(IrOpcode::kLoadImmutable),
        rep_matcher_(rep_matcher),
        base_matcher_(base_matcher),
        index_matcher_(index_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose rep (";
    rep_matcher_.DescribeTo(os);
    *os << "), base (";
    base_matcher_.DescribeTo(os);
    *os << ") and index (";
    index_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    LoadRepresentation rep = LoadRepresentationOf(node->op());
    return TestNodeMatcher::MatchAndExplain(node, listener) &&
           PrintMatchAndExplain(rep, "rep", rep_matcher_, listener) &&
           PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0), "base",
                                base_matcher_, listener) &&
           PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1), "index",
                                index_matcher_, listener);
  }

 private:
  const Matcher<LoadRepresentation> rep_matcher_;
  const Matcher<Node*> base_matcher_;
  const Matcher<Node*> index_matcher_;
};

#define STORE_MATCHER(kStore, representation)                                 \
  class Is##kStore##Matcher final : public TestNodeMatcher {                  \
   public:                                                                    \
    Is##kStore##Matcher(const Matcher<representation>& rep_matcher,           \
                        const Matcher<Node*>& base_matcher,                   \
                        const Matcher<Node*>& index_matcher,                  \
                        const Matcher<Node*>& value_matcher,                  \
                        const Matcher<Node*>& effect_matcher,                 \
                        const Matcher<Node*>& control_matcher)                \
        : TestNodeMatcher(IrOpcode::k##kStore),                               \
          rep_matcher_(rep_matcher),                                          \
          base_matcher_(base_matcher),                                        \
          index_matcher_(index_matcher),                                      \
          value_matcher_(value_matcher),                                      \
          effect_matcher_(effect_matcher),                                    \
          control_matcher_(control_matcher) {}                                \
                                                                              \
    void DescribeTo(std::ostream* os) const final {                           \
      TestNodeMatcher::DescribeTo(os);                                        \
      *os << " whose rep (";                                                  \
      rep_matcher_.DescribeTo(os);                                            \
      *os << "), base (";                                                     \
      base_matcher_.DescribeTo(os);                                           \
      *os << "), index (";                                                    \
      index_matcher_.DescribeTo(os);                                          \
      *os << "), value (";                                                    \
      value_matcher_.DescribeTo(os);                                          \
      *os << "), effect (";                                                   \
      effect_matcher_.DescribeTo(os);                                         \
      *os << ") and control (";                                               \
      control_matcher_.DescribeTo(os);                                        \
      *os << ")";                                                             \
    }                                                                         \
                                                                              \
    bool MatchAndExplain(Node* node,                                          \
                         MatchResultListener* listener) const final {         \
      Node* effect_node = nullptr;                                            \
      Node* control_node = nullptr;                                           \
      if (NodeProperties::FirstEffectIndex(node) < node->InputCount()) {      \
        effect_node = NodeProperties::GetEffectInput(node);                   \
      }                                                                       \
      if (NodeProperties::FirstControlIndex(node) < node->InputCount()) {     \
        control_node = NodeProperties::GetControlInput(node);                 \
      }                                                                       \
      return (TestNodeMatcher::MatchAndExplain(node, listener) &&             \
              PrintMatchAndExplain(OpParameter<representation>(node->op()),   \
                                   "rep", rep_matcher_, listener) &&          \
              PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0),    \
                                   "base", base_matcher_, listener) &&        \
              PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1),    \
                                   "index", index_matcher_, listener) &&      \
              PrintMatchAndExplain(NodeProperties::GetValueInput(node, 2),    \
                                   "value", value_matcher_, listener) &&      \
              PrintMatchAndExplain(effect_node, "effect", effect_matcher_,    \
                                   listener) &&                               \
              PrintMatchAndExplain(control_node, "control", control_matcher_, \
                                   listener));                                \
    }                                                                         \
                                                                              \
   private:                                                                   \
    const Matcher<representation> rep_matcher_;                               \
    const Matcher<Node*> base_matcher_;                                       \
    const Matcher<Node*> index_matcher_;                                      \
    const Matcher<Node*> value_matcher_;                                      \
    const Matcher<Node*> effect_matcher_;                                     \
    const Matcher<Node*> control_matcher_;                                    \
  };

STORE_MATCHER(Store, StoreRepresentation)
STORE_MATCHER(UnalignedStore, UnalignedStoreRepresentation)
STORE_MATCHER(StoreToObject, ObjectAccess)

class IsStackSlotMatcher final : public TestNodeMatcher {
 public:
  explicit IsStackSlotMatcher(
      const Matcher<StackSlotRepresentation>& rep_matcher)
      : TestNodeMatcher(IrOpcode::kStackSlot), rep_matcher_(rep_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose rep (";
    rep_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(StackSlotRepresentationOf(node->op()), "rep",
                                 rep_matcher_, listener));
  }

 private:
  const Matcher<StackSlotRepresentation> rep_matcher_;
};

class IsToNumberMatcher final : public TestNodeMatcher {
 public:
  IsToNumberMatcher(const Matcher<Node*>& base_matcher,
                    const Matcher<Node*>& context_matcher,
                    const Matcher<Node*>& effect_matcher,
                    const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(IrOpcode::kJSToNumber),
        base_matcher_(base_matcher),
        context_matcher_(context_matcher),
        effect_matcher_(effect_matcher),
        control_matcher_(control_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose base (";
    base_matcher_.DescribeTo(os);
    *os << "), context (";
    context_matcher_.DescribeTo(os);
    *os << "), effect (";
    effect_matcher_.DescribeTo(os);
    *os << ") and control (";
    control_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0), "base",
                                 base_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetContextInput(node),
                                 "context", context_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetEffectInput(node), "effect",
                                 effect_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node),
                                 "control", control_matcher_, listener));
  }

 private:
  const Matcher<Node*> base_matcher_;
  const Matcher<Node*> context_matcher_;
  const Matcher<Node*> effect_matcher_;
  const Matcher<Node*> control_matcher_;
};

class IsLoadContextMatcher final : public TestNodeMatcher {
 public:
  IsLoadContextMatcher(const Matcher<ContextAccess>& access_matcher,
                       const Matcher<Node*>& context_matcher)
      : TestNodeMatcher(IrOpcode::kJSLoadContext),
        access_matcher_(access_matcher),
        context_matcher_(context_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose access (";
    access_matcher_.DescribeTo(os);
    *os << ") and context (";
    context_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(ContextAccessOf(node->op()), "access",
                                 access_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetContextInput(node),
                                 "context", context_matcher_, listener));
  }

 private:
  const Matcher<ContextAccess> access_matcher_;
  const Matcher<Node*> context_matcher_;
};

class IsQuadopMatcher final : public TestNodeMatcher {
 public:
  IsQuadopMatcher(IrOpcode::Value opcode, const Matcher<Node*>& a_matcher,
                  const Matcher<Node*>& b_matcher,
                  const Matcher<Node*>& c_matcher,
                  const Matcher<Node*>& d_matcher)
      : TestNodeMatcher(opcode),
        a_matcher_(a_matcher),
        b_matcher_(b_matcher),
        c_matcher_(c_matcher),
        d_matcher_(d_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose a (";
    a_matcher_.DescribeTo(os);
    *os << ") and b (";
    b_matcher_.DescribeTo(os);
    *os << ") and c (";
    c_matcher_.DescribeTo(os);
    *os << ") and d (";
    d_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0), "a",
                                 a_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1), "b",
                                 b_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 2), "c",
                                 c_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 3), "d",
                                 d_matcher_, listener));
  }

 private:
  const Matcher<Node*> a_matcher_;
  const Matcher<Node*> b_matcher_;
  const Matcher<Node*> c_matcher_;
  const Matcher<Node*> d_matcher_;
};

class IsTernopMatcher final : public TestNodeMatcher {
 public:
  IsTernopMatcher(IrOpcode::Value opcode, const Matcher<Node*>& lhs_matcher,
                  const Matcher<Node*>& mid_matcher,
                  const Matcher<Node*>& rhs_matcher)
      : TestNodeMatcher(opcode),
        lhs_matcher_(lhs_matcher),
        mid_matcher_(mid_matcher),
        rhs_matcher_(rhs_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose lhs (";
    lhs_matcher_.DescribeTo(os);
    *os << ") and mid (";
    mid_matcher_.DescribeTo(os);
    *os << ") and rhs (";
    rhs_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0), "lhs",
                                 lhs_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1), "mid",
                                 mid_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 2), "rhs",
                                 rhs_matcher_, listener));
  }

 private:
  const Matcher<Node*> lhs_matcher_;
  const Matcher<Node*> mid_matcher_;
  const Matcher<Node*> rhs_matcher_;
};

class IsBinopMatcher final : public TestNodeMatcher {
 public:
  IsBinopMatcher(IrOpcode::Value opcode, const Matcher<Node*>& lhs_matcher,
                 const Matcher<Node*>& rhs_matcher)
      : TestNodeMatcher(opcode),
        lhs_matcher_(lhs_matcher),
        rhs_matcher_(rhs_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose lhs (";
    lhs_matcher_.DescribeTo(os);
    *os << ") and rhs (";
    rhs_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0), "lhs",
                                 lhs_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1), "rhs",
                                 rhs_matcher_, listener));
  }

 private:
  const Matcher<Node*> lhs_matcher_;
  const Matcher<Node*> rhs_matcher_;
};

class IsStringConcatMatcher final : public TestNodeMatcher {
 public:
  IsStringConcatMatcher(const Matcher<Node*>& length_matcher,
                        const Matcher<Node*>& lhs_matcher,
                        const Matcher<Node*>& rhs_matcher)
      : TestNodeMatcher(IrOpcode::kStringConcat),
        length_matcher_(length_matcher),
        lhs_matcher_(lhs_matcher),
        rhs_matcher_(rhs_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose length (";
    length_matcher_.DescribeTo(os);
    *os << ") and lhs (";
    lhs_matcher_.DescribeTo(os);
    *os << ") and rhs (";
    rhs_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0),
                                 "length", length_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1), "lhs",
                                 lhs_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 2), "rhs",
                                 rhs_matcher_, listener));
  }

 private:
  const Matcher<Node*> length_matcher_;
  const Matcher<Node*> lhs_matcher_;
  const Matcher<Node*> rhs_matcher_;
};

class IsUnopMatcher final : public TestNodeMatcher {
 public:
  IsUnopMatcher(IrOpcode::Value opcode, const Matcher<Node*>& input_matcher)
      : TestNodeMatcher(opcode), input_matcher_(input_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose input (";
    input_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0),
                                 "input", input_matcher_, listener));
  }

 private:
  const Matcher<Node*> input_matcher_;
};

class IsParameterMatcher final : public TestNodeMatcher {
 public:
  explicit IsParameterMatcher(const Matcher<int>& index_matcher)
      : TestNodeMatcher(IrOpcode::kParameter), index_matcher_(index_matcher) {}

  void DescribeTo(std::ostream* os) const override {
    *os << "is a Parameter node with index(";
    index_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(ParameterIndexOf(node->op()), "index",
                                 index_matcher_, listener));
  }

 private:
  const Matcher<int> index_matcher_;
};

}  // namespace

Matcher<Node*> IsDead() {
  return MakeMatcher(new TestNodeMatcher(IrOpcode::kDead));
}

Matcher<Node*> IsUnreachable() {
  return MakeMatcher(new TestNodeMatcher(IrOpcode::kUnreachable));
}

Matcher<Node*> IsThrow() {
  return MakeMatcher(new TestNodeMatcher(IrOpcode::kThrow));
}

Matcher<Node*> IsStart() {
  return MakeMatcher(new TestNodeMatcher(IrOpcode::kStart));
}

Matcher<Node*> IsEnd(const Matcher<Node*>& control0_matcher) {
  return MakeMatcher(new IsControl1Matcher(IrOpcode::kEnd, control0_matcher));
}


Matcher<Node*> IsEnd(const Matcher<Node*>& control0_matcher,
                     const Matcher<Node*>& control1_matcher) {
  return MakeMatcher(new IsControl2Matcher(IrOpcode::kEnd, control0_matcher,
                                           control1_matcher));
}


Matcher<Node*> IsEnd(const Matcher<Node*>& control0_matcher,
                     const Matcher<Node*>& control1_matcher,
                     const Matcher<Node*>& control2_matcher) {
  return MakeMatcher(new IsControl3Matcher(IrOpcode::kEnd, control0_matcher,
                                           control1_matcher, control2_matcher));
}


Matcher<Node*> IsBranch(const Matcher<Node*>& value_matcher,
                        const Matcher<Node*>& control_matcher) {
  return MakeMatcher(new IsBranchMatcher(value_matcher, control_matcher));
}


Matcher<Node*> IsMerge(const Matcher<Node*>& control0_matcher,
                       const Matcher<Node*>& control1_matcher) {
  return MakeMatcher(new IsControl2Matcher(IrOpcode::kMerge, control0_matcher,
                                           control1_matcher));
}


Matcher<Node*> 
"""


```