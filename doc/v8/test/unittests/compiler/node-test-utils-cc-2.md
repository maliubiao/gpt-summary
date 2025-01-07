Response:
The user wants me to analyze a C++ source code file related to V8 compiler testing.

My plan is to:
1. **Identify the core functionality:** Determine what this code does. It seems to define a set of functions that create "matchers" for different types of nodes in V8's intermediate representation (IR).
2. **Check for Torque:**  Verify if the filename ends with ".tq". It doesn't.
3. **Relate to JavaScript:** Explain how these matchers are used in the context of testing JavaScript code compilation.
4. **Provide examples:** Illustrate how these matchers can be used with hypothetical inputs and outputs.
5. **Identify common errors:** Explain potential mistakes developers might make when using or extending this code.
6. **Summarize the functionality:** Condense the overall purpose of the code.
这是 V8 源代码文件 `v8/test/unittests/compiler/node-test-utils.cc` 的一部分，它定义了一系列的辅助函数，用于创建**Node 匹配器 (Matcher)**。

这些匹配器主要用于在 V8 编译器单元测试中，断言生成的**中间表示 (IR) 图**是否符合预期。 换句话说，它们允许测试代码检查编译过程中产生的节点，并验证这些节点是否具有特定的属性和连接关系。

**功能归纳：**

这部分代码定义了各种 `Is...` 函数，每个函数都对应一种特定的 IR 节点类型或属性。这些函数接受一个或多个 `Matcher` 对象作为参数，并返回一个新的 `Matcher` 对象。这个返回的 `Matcher` 可以用来检查目标节点是否具有特定的操作码 (IrOpcode) 以及其输入节点是否满足给定的匹配器。

**是否为 Torque 代码：**

`v8/test/unittests/compiler/node-test-utils.cc` 以 `.cc` 结尾，而不是 `.tq`，因此它不是一个 V8 Torque 源代码文件。

**与 JavaScript 的关系：**

这个文件中的功能与 JavaScript 代码的编译过程密切相关。V8 编译器会将 JavaScript 代码转换成一种中间表示（IR 图）。这些 `Is...` 匹配器用于测试生成的 IR 图是否符合预期，从而确保 JavaScript 代码被正确地编译。

例如，当测试一个简单的加法操作 `a + b` 时，我们可能期望生成的 IR 图中包含一个 `Int32Add` 节点。 这时就可以使用 `IsInt32Add` 匹配器来断言这个节点的出现。

**JavaScript 示例：**

假设我们有以下 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}
```

在 V8 的编译器单元测试中，我们可能会使用类似下面的伪代码来断言生成的 IR 中包含一个 `Int32Add` 节点，并且它的两个输入分别是 `a` 和 `b` 对应的节点：

```c++
// 假设 'graph' 是生成的 IR 图， 'node_a' 和 'node_b' 是 'a' 和 'b' 对应的节点
EXPECT_THAT(graph->return_node()->InputAt(0),
            IsInt32Add(IsParameter(0), IsParameter(1)));
```

在这个例子中：

* `IsInt32Add` 是该文件中定义的一个匹配器，用于匹配 `Int32Add` 类型的节点。
* `IsParameter(0)` 和 `IsParameter(1)` 也是匹配器，用于匹配函数参数对应的节点。

**代码逻辑推理与假设输入输出：**

以 `IsInt32Add` 函数为例：

```c++
Matcher<Node*> IsInt32Add(const Matcher<Node*>& lhs_matcher,
                          const Matcher<Node*>& rhs_matcher) {
  return MakeMatcher(
      new IsBinopMatcher(IrOpcode::kInt32Add, lhs_matcher, rhs_matcher));
}
```

* **假设输入：** 两个 `Matcher<Node*>` 对象，分别用于匹配 `Int32Add` 节点的左操作数和右操作数。 例如，`IsParameter(0)` 和 `IsInt32Constant(5)`.
* **预期输出：** 一个新的 `Matcher<Node*>` 对象，这个匹配器会检查一个节点是否是 `Int32Add` 类型，并且其左输入节点匹配 `IsParameter(0)`，右输入节点匹配 `IsInt32Constant(5)`。

**用户常见的编程错误：**

在使用这些匹配器时，一个常见的错误是**匹配器组合不当**，导致断言失败或者遗漏了某些情况。

**例如：** 假设开发者想断言一个节点是 `NumberAdd`，并且它的左操作数是参数 0，右操作数是参数 1。 他们可能会错误地写成：

```c++
// 错误的用法
EXPECT_THAT(node, IsNumberAdd(IsParameter(1), IsParameter(0)));
```

这里左右操作数的顺序与实际 IR 图中的顺序相反，导致断言失败。 正确的用法应该是：

```c++
// 正确的用法
EXPECT_THAT(node, IsNumberAdd(IsParameter(0), IsParameter(1)));
```

另一个常见的错误是**使用了过于宽泛或过于严格的匹配器**。例如，如果期望一个输入是特定的常量值，却使用了 `IsParameter` 这样的匹配器，断言肯定会失败。 反之，如果仅仅需要判断一个节点是某种类型的运算，却匹配了其具体的输入，当输入发生变化时，测试就会失效。

**总结：**

这部分 `node-test-utils.cc` 代码定义了一套用于描述和匹配 V8 编译器中间表示（IR）图中节点的工具。 这些 `Is...` 函数创建的匹配器可以方便地在单元测试中断言生成的 IR 结构是否符合预期，从而保证 JavaScript 代码编译的正确性。 开发者需要理解各种匹配器的功能和正确组合方式，避免常见的匹配错误，才能编写出可靠的编译器测试。

Prompt: 
```
这是目录为v8/test/unittests/compiler/node-test-utils.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/node-test-utils.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
IsMerge(const Matcher<Node*>& control0_matcher,
                       const Matcher<Node*>& control1_matcher,
                       const Matcher<Node*>& control2_matcher) {
  return MakeMatcher(new IsControl3Matcher(IrOpcode::kMerge, control0_matcher,
                                           control1_matcher, control2_matcher));
}


Matcher<Node*> IsLoop(const Matcher<Node*>& control0_matcher,
                      const Matcher<Node*>& control1_matcher) {
  return MakeMatcher(new IsControl2Matcher(IrOpcode::kLoop, control0_matcher,
                                           control1_matcher));
}


Matcher<Node*> IsLoop(const Matcher<Node*>& control0_matcher,
                      const Matcher<Node*>& control1_matcher,
                      const Matcher<Node*>& control2_matcher) {
  return MakeMatcher(new IsControl3Matcher(IrOpcode::kLoop, control0_matcher,
                                           control1_matcher, control2_matcher));
}

Matcher<Node*> IsLoopExitValue(const Matcher<MachineRepresentation> rep_matcher,
                               const Matcher<Node*>& value_matcher) {
  return MakeMatcher(new IsLoopExitValueMatcher(rep_matcher, value_matcher));
}

Matcher<Node*> IsIfTrue(const Matcher<Node*>& control_matcher) {
  return MakeMatcher(new IsControl1Matcher(IrOpcode::kIfTrue, control_matcher));
}


Matcher<Node*> IsIfFalse(const Matcher<Node*>& control_matcher) {
  return MakeMatcher(
      new IsControl1Matcher(IrOpcode::kIfFalse, control_matcher));
}


Matcher<Node*> IsIfSuccess(const Matcher<Node*>& control_matcher) {
  return MakeMatcher(
      new IsControl1Matcher(IrOpcode::kIfSuccess, control_matcher));
}


Matcher<Node*> IsSwitch(const Matcher<Node*>& value_matcher,
                        const Matcher<Node*>& control_matcher) {
  return MakeMatcher(new IsSwitchMatcher(value_matcher, control_matcher));
}

Matcher<Node*> IsIfValue(const Matcher<IfValueParameters>& value_matcher,
                         const Matcher<Node*>& control_matcher) {
  return MakeMatcher(new IsIfValueMatcher(value_matcher, control_matcher));
}


Matcher<Node*> IsIfDefault(const Matcher<Node*>& control_matcher) {
  return MakeMatcher(
      new IsControl1Matcher(IrOpcode::kIfDefault, control_matcher));
}


Matcher<Node*> IsBeginRegion(const Matcher<Node*>& effect_matcher) {
  return MakeMatcher(new IsBeginRegionMatcher(effect_matcher));
}


Matcher<Node*> IsFinishRegion(const Matcher<Node*>& value_matcher,
                              const Matcher<Node*>& effect_matcher) {
  return MakeMatcher(new IsFinishRegionMatcher(value_matcher, effect_matcher));
}


Matcher<Node*> IsReturn(const Matcher<Node*>& value_matcher,
                        const Matcher<Node*>& effect_matcher,
                        const Matcher<Node*>& control_matcher) {
  return MakeMatcher(
      new IsReturnMatcher(value_matcher, effect_matcher, control_matcher));
}

Matcher<Node*> IsReturn2(const Matcher<Node*>& value_matcher,
                         const Matcher<Node*>& value2_matcher,
                         const Matcher<Node*>& effect_matcher,
                         const Matcher<Node*>& control_matcher) {
  return MakeMatcher(new IsReturnMatcher(value_matcher, value2_matcher,
                                         effect_matcher, control_matcher));
}

Matcher<Node*> IsTerminate(const Matcher<Node*>& effect_matcher,
                           const Matcher<Node*>& control_matcher) {
  return MakeMatcher(new IsTerminateMatcher(effect_matcher, control_matcher));
}

Matcher<Node*> IsTypeGuard(const Matcher<Node*>& value_matcher,
                           const Matcher<Node*>& control_matcher) {
  return MakeMatcher(new IsTypeGuardMatcher(value_matcher, control_matcher));
}

Matcher<Node*> IsExternalConstant(
    const Matcher<ExternalReference>& value_matcher) {
  return MakeMatcher(new IsConstantMatcher<ExternalReference>(
      IrOpcode::kExternalConstant, value_matcher));
}


Matcher<Node*> IsHeapConstant(Handle<HeapObject> value) {
  return MakeMatcher(new IsConstantMatcher<Handle<HeapObject>>(
      IrOpcode::kHeapConstant, value));
}


Matcher<Node*> IsInt32Constant(const Matcher<int32_t>& value_matcher) {
  return MakeMatcher(
      new IsConstantMatcher<int32_t>(IrOpcode::kInt32Constant, value_matcher));
}


Matcher<Node*> IsInt64Constant(const Matcher<int64_t>& value_matcher) {
  return MakeMatcher(
      new IsConstantMatcher<int64_t>(IrOpcode::kInt64Constant, value_matcher));
}


Matcher<Node*> IsFloat32Constant(const Matcher<float>& value_matcher) {
  return MakeMatcher(
      new IsConstantMatcher<float>(IrOpcode::kFloat32Constant, value_matcher));
}


Matcher<Node*> IsFloat64Constant(const Matcher<double>& value_matcher) {
  return MakeMatcher(
      new IsConstantMatcher<double>(IrOpcode::kFloat64Constant, value_matcher));
}


Matcher<Node*> IsNumberConstant(const Matcher<double>& value_matcher) {
  return MakeMatcher(
      new IsConstantMatcher<double>(IrOpcode::kNumberConstant, value_matcher));
}

Matcher<Node*> IsPointerConstant(const Matcher<intptr_t>& value_matcher) {
  return MakeMatcher(new IsConstantMatcher<intptr_t>(IrOpcode::kPointerConstant,
                                                     value_matcher));
}

Matcher<Node*> IsSelect(const Matcher<MachineRepresentation>& type_matcher,
                        const Matcher<Node*>& value0_matcher,
                        const Matcher<Node*>& value1_matcher,
                        const Matcher<Node*>& value2_matcher) {
  return MakeMatcher(new IsSelectMatcher(type_matcher, value0_matcher,
                                         value1_matcher, value2_matcher));
}


Matcher<Node*> IsPhi(const Matcher<MachineRepresentation>& type_matcher,
                     const Matcher<Node*>& value0_matcher,
                     const Matcher<Node*>& value1_matcher,
                     const Matcher<Node*>& merge_matcher) {
  return MakeMatcher(new IsPhiMatcher(type_matcher, value0_matcher,
                                      value1_matcher, merge_matcher));
}


Matcher<Node*> IsPhi(const Matcher<MachineRepresentation>& type_matcher,
                     const Matcher<Node*>& value0_matcher,
                     const Matcher<Node*>& value1_matcher,
                     const Matcher<Node*>& value2_matcher,
                     const Matcher<Node*>& merge_matcher) {
  return MakeMatcher(new IsPhi2Matcher(type_matcher, value0_matcher,
                                       value1_matcher, value2_matcher,
                                       merge_matcher));
}


Matcher<Node*> IsEffectPhi(const Matcher<Node*>& effect0_matcher,
                           const Matcher<Node*>& effect1_matcher,
                           const Matcher<Node*>& merge_matcher) {
  return MakeMatcher(
      new IsEffectPhiMatcher(effect0_matcher, effect1_matcher, merge_matcher));
}


Matcher<Node*> IsProjection(const Matcher<size_t>& index_matcher,
                            const Matcher<Node*>& base_matcher) {
  return MakeMatcher(new IsProjectionMatcher(index_matcher, base_matcher));
}

Matcher<Node*> IsCall(const Matcher<const CallDescriptor*>& descriptor_matcher,
                      const Matcher<Node*>& value0_matcher,
                      const Matcher<Node*>& effect_matcher,
                      const Matcher<Node*>& control_matcher) {
  std::vector<Matcher<Node*>> value_matchers;
  value_matchers.push_back(value0_matcher);
  return MakeMatcher(new IsCallMatcher(descriptor_matcher, value_matchers,
                                       effect_matcher, control_matcher));
}

Matcher<Node*> IsCall(const Matcher<const CallDescriptor*>& descriptor_matcher,
                      const Matcher<Node*>& value0_matcher,
                      const Matcher<Node*>& value1_matcher,
                      const Matcher<Node*>& effect_matcher,
                      const Matcher<Node*>& control_matcher) {
  std::vector<Matcher<Node*>> value_matchers;
  value_matchers.push_back(value0_matcher);
  value_matchers.push_back(value1_matcher);
  return MakeMatcher(new IsCallMatcher(descriptor_matcher, value_matchers,
                                       effect_matcher, control_matcher));
}


Matcher<Node*> IsCall(const Matcher<const CallDescriptor*>& descriptor_matcher,
                      const Matcher<Node*>& value0_matcher,
                      const Matcher<Node*>& value1_matcher,
                      const Matcher<Node*>& value2_matcher,
                      const Matcher<Node*>& effect_matcher,
                      const Matcher<Node*>& control_matcher) {
  std::vector<Matcher<Node*>> value_matchers;
  value_matchers.push_back(value0_matcher);
  value_matchers.push_back(value1_matcher);
  value_matchers.push_back(value2_matcher);
  return MakeMatcher(new IsCallMatcher(descriptor_matcher, value_matchers,
                                       effect_matcher, control_matcher));
}


Matcher<Node*> IsCall(const Matcher<const CallDescriptor*>& descriptor_matcher,
                      const Matcher<Node*>& value0_matcher,
                      const Matcher<Node*>& value1_matcher,
                      const Matcher<Node*>& value2_matcher,
                      const Matcher<Node*>& value3_matcher,
                      const Matcher<Node*>& effect_matcher,
                      const Matcher<Node*>& control_matcher) {
  std::vector<Matcher<Node*>> value_matchers;
  value_matchers.push_back(value0_matcher);
  value_matchers.push_back(value1_matcher);
  value_matchers.push_back(value2_matcher);
  value_matchers.push_back(value3_matcher);
  return MakeMatcher(new IsCallMatcher(descriptor_matcher, value_matchers,
                                       effect_matcher, control_matcher));
}


Matcher<Node*> IsCall(const Matcher<const CallDescriptor*>& descriptor_matcher,
                      const Matcher<Node*>& value0_matcher,
                      const Matcher<Node*>& value1_matcher,
                      const Matcher<Node*>& value2_matcher,
                      const Matcher<Node*>& value3_matcher,
                      const Matcher<Node*>& value4_matcher,
                      const Matcher<Node*>& effect_matcher,
                      const Matcher<Node*>& control_matcher) {
  std::vector<Matcher<Node*>> value_matchers;
  value_matchers.push_back(value0_matcher);
  value_matchers.push_back(value1_matcher);
  value_matchers.push_back(value2_matcher);
  value_matchers.push_back(value3_matcher);
  value_matchers.push_back(value4_matcher);
  return MakeMatcher(new IsCallMatcher(descriptor_matcher, value_matchers,
                                       effect_matcher, control_matcher));
}


Matcher<Node*> IsCall(const Matcher<const CallDescriptor*>& descriptor_matcher,
                      const Matcher<Node*>& value0_matcher,
                      const Matcher<Node*>& value1_matcher,
                      const Matcher<Node*>& value2_matcher,
                      const Matcher<Node*>& value3_matcher,
                      const Matcher<Node*>& value4_matcher,
                      const Matcher<Node*>& value5_matcher,
                      const Matcher<Node*>& effect_matcher,
                      const Matcher<Node*>& control_matcher) {
  std::vector<Matcher<Node*>> value_matchers;
  value_matchers.push_back(value0_matcher);
  value_matchers.push_back(value1_matcher);
  value_matchers.push_back(value2_matcher);
  value_matchers.push_back(value3_matcher);
  value_matchers.push_back(value4_matcher);
  value_matchers.push_back(value5_matcher);
  return MakeMatcher(new IsCallMatcher(descriptor_matcher, value_matchers,
                                       effect_matcher, control_matcher));
}


Matcher<Node*> IsCall(
    const Matcher<const CallDescriptor*>& descriptor_matcher,
    const Matcher<Node*>& value0_matcher, const Matcher<Node*>& value1_matcher,
    const Matcher<Node*>& value2_matcher, const Matcher<Node*>& value3_matcher,
    const Matcher<Node*>& value4_matcher, const Matcher<Node*>& value5_matcher,
    const Matcher<Node*>& value6_matcher, const Matcher<Node*>& effect_matcher,
    const Matcher<Node*>& control_matcher) {
  std::vector<Matcher<Node*>> value_matchers;
  value_matchers.push_back(value0_matcher);
  value_matchers.push_back(value1_matcher);
  value_matchers.push_back(value2_matcher);
  value_matchers.push_back(value3_matcher);
  value_matchers.push_back(value4_matcher);
  value_matchers.push_back(value5_matcher);
  value_matchers.push_back(value6_matcher);
  return MakeMatcher(new IsCallMatcher(descriptor_matcher, value_matchers,
                                       effect_matcher, control_matcher));
}


Matcher<Node*> IsTailCall(
    const Matcher<CallDescriptor const*>& descriptor_matcher,
    const Matcher<Node*>& value0_matcher, const Matcher<Node*>& value1_matcher,
    const Matcher<Node*>& effect_matcher,
    const Matcher<Node*>& control_matcher) {
  std::vector<Matcher<Node*>> value_matchers;
  value_matchers.push_back(value0_matcher);
  value_matchers.push_back(value1_matcher);
  return MakeMatcher(new IsTailCallMatcher(descriptor_matcher, value_matchers,
                                           effect_matcher, control_matcher));
}


Matcher<Node*> IsTailCall(
    const Matcher<CallDescriptor const*>& descriptor_matcher,
    const Matcher<Node*>& value0_matcher, const Matcher<Node*>& value1_matcher,
    const Matcher<Node*>& value2_matcher, const Matcher<Node*>& effect_matcher,
    const Matcher<Node*>& control_matcher) {
  std::vector<Matcher<Node*>> value_matchers;
  value_matchers.push_back(value0_matcher);
  value_matchers.push_back(value1_matcher);
  value_matchers.push_back(value2_matcher);
  return MakeMatcher(new IsTailCallMatcher(descriptor_matcher, value_matchers,
                                           effect_matcher, control_matcher));
}


Matcher<Node*> IsTailCall(
    const Matcher<CallDescriptor const*>& descriptor_matcher,
    const Matcher<Node*>& value0_matcher, const Matcher<Node*>& value1_matcher,
    const Matcher<Node*>& value2_matcher, const Matcher<Node*>& value3_matcher,
    const Matcher<Node*>& effect_matcher,
    const Matcher<Node*>& control_matcher) {
  std::vector<Matcher<Node*>> value_matchers;
  value_matchers.push_back(value0_matcher);
  value_matchers.push_back(value1_matcher);
  value_matchers.push_back(value2_matcher);
  value_matchers.push_back(value3_matcher);
  return MakeMatcher(new IsTailCallMatcher(descriptor_matcher, value_matchers,
                                           effect_matcher, control_matcher));
}


Matcher<Node*> IsTailCall(
    const Matcher<CallDescriptor const*>& descriptor_matcher,
    const Matcher<Node*>& value0_matcher, const Matcher<Node*>& value1_matcher,
    const Matcher<Node*>& value2_matcher, const Matcher<Node*>& value3_matcher,
    const Matcher<Node*>& value4_matcher, const Matcher<Node*>& effect_matcher,
    const Matcher<Node*>& control_matcher) {
  std::vector<Matcher<Node*>> value_matchers;
  value_matchers.push_back(value0_matcher);
  value_matchers.push_back(value1_matcher);
  value_matchers.push_back(value2_matcher);
  value_matchers.push_back(value3_matcher);
  value_matchers.push_back(value4_matcher);
  return MakeMatcher(new IsTailCallMatcher(descriptor_matcher, value_matchers,
                                           effect_matcher, control_matcher));
}


Matcher<Node*> IsTailCall(
    const Matcher<CallDescriptor const*>& descriptor_matcher,
    const Matcher<Node*>& value0_matcher, const Matcher<Node*>& value1_matcher,
    const Matcher<Node*>& value2_matcher, const Matcher<Node*>& value3_matcher,
    const Matcher<Node*>& value4_matcher, const Matcher<Node*>& value5_matcher,
    const Matcher<Node*>& effect_matcher,
    const Matcher<Node*>& control_matcher) {
  std::vector<Matcher<Node*>> value_matchers;
  value_matchers.push_back(value0_matcher);
  value_matchers.push_back(value1_matcher);
  value_matchers.push_back(value2_matcher);
  value_matchers.push_back(value3_matcher);
  value_matchers.push_back(value4_matcher);
  value_matchers.push_back(value5_matcher);
  return MakeMatcher(new IsTailCallMatcher(descriptor_matcher, value_matchers,
                                           effect_matcher, control_matcher));
}


Matcher<Node*> IsTailCall(
    const Matcher<CallDescriptor const*>& descriptor_matcher,
    const Matcher<Node*>& value0_matcher, const Matcher<Node*>& value1_matcher,
    const Matcher<Node*>& value2_matcher, const Matcher<Node*>& value3_matcher,
    const Matcher<Node*>& value4_matcher, const Matcher<Node*>& value5_matcher,
    const Matcher<Node*>& value6_matcher, const Matcher<Node*>& effect_matcher,
    const Matcher<Node*>& control_matcher) {
  std::vector<Matcher<Node*>> value_matchers;
  value_matchers.push_back(value0_matcher);
  value_matchers.push_back(value1_matcher);
  value_matchers.push_back(value2_matcher);
  value_matchers.push_back(value3_matcher);
  value_matchers.push_back(value4_matcher);
  value_matchers.push_back(value5_matcher);
  value_matchers.push_back(value6_matcher);
  return MakeMatcher(new IsTailCallMatcher(descriptor_matcher, value_matchers,
                                           effect_matcher, control_matcher));
}


Matcher<Node*> IsTailCall(
    const Matcher<CallDescriptor const*>& descriptor_matcher,
    const Matcher<Node*>& value0_matcher, const Matcher<Node*>& value1_matcher,
    const Matcher<Node*>& value2_matcher, const Matcher<Node*>& value3_matcher,
    const Matcher<Node*>& value4_matcher, const Matcher<Node*>& value5_matcher,
    const Matcher<Node*>& value6_matcher, const Matcher<Node*>& value7_matcher,
    const Matcher<Node*>& effect_matcher,
    const Matcher<Node*>& control_matcher) {
  std::vector<Matcher<Node*>> value_matchers;
  value_matchers.push_back(value0_matcher);
  value_matchers.push_back(value1_matcher);
  value_matchers.push_back(value2_matcher);
  value_matchers.push_back(value3_matcher);
  value_matchers.push_back(value4_matcher);
  value_matchers.push_back(value5_matcher);
  value_matchers.push_back(value6_matcher);
  value_matchers.push_back(value7_matcher);
  return MakeMatcher(new IsTailCallMatcher(descriptor_matcher, value_matchers,
                                           effect_matcher, control_matcher));
}

#define DEFINE_SPECULATIVE_BINOP_MATCHER(opcode)                              \
  Matcher<Node*> Is##opcode(const Matcher<NumberOperationHint>& hint_matcher, \
                            const Matcher<Node*>& lhs_matcher,                \
                            const Matcher<Node*>& rhs_matcher,                \
                            const Matcher<Node*>& effect_matcher,             \
                            const Matcher<Node*>& control_matcher) {          \
    return MakeMatcher(new IsSpeculativeBinopMatcher(                         \
        IrOpcode::k##opcode, hint_matcher, lhs_matcher, rhs_matcher,          \
        effect_matcher, control_matcher));                                    \
  }
SIMPLIFIED_SPECULATIVE_NUMBER_BINOP_LIST(DEFINE_SPECULATIVE_BINOP_MATCHER)
DEFINE_SPECULATIVE_BINOP_MATCHER(SpeculativeNumberEqual)
DEFINE_SPECULATIVE_BINOP_MATCHER(SpeculativeNumberLessThan)
DEFINE_SPECULATIVE_BINOP_MATCHER(SpeculativeNumberLessThanOrEqual)
#undef DEFINE_SPECULATIVE_BINOP_MATCHER

Matcher<Node*> IsStringConcat(const Matcher<Node*>& length_matcher,
                              const Matcher<Node*>& lhs_matcher,
                              const Matcher<Node*>& rhs_matcher) {
  return MakeMatcher(
      new IsStringConcatMatcher(length_matcher, lhs_matcher, rhs_matcher));
}

Matcher<Node*> IsAllocate(const Matcher<Node*>& size_matcher,
                          const Matcher<Node*>& effect_matcher,
                          const Matcher<Node*>& control_matcher) {
  return MakeMatcher(
      new IsAllocateMatcher(size_matcher, effect_matcher, control_matcher));
}


Matcher<Node*> IsLoadField(const Matcher<FieldAccess>& access_matcher,
                           const Matcher<Node*>& base_matcher,
                           const Matcher<Node*>& effect_matcher,
                           const Matcher<Node*>& control_matcher) {
  return MakeMatcher(new IsLoadFieldMatcher(access_matcher, base_matcher,
                                            effect_matcher, control_matcher));
}


Matcher<Node*> IsStoreField(const Matcher<FieldAccess>& access_matcher,
                            const Matcher<Node*>& base_matcher,
                            const Matcher<Node*>& value_matcher,
                            const Matcher<Node*>& effect_matcher,
                            const Matcher<Node*>& control_matcher) {
  return MakeMatcher(new IsStoreFieldMatcher(access_matcher, base_matcher,
                                             value_matcher, effect_matcher,
                                             control_matcher));
}

Matcher<Node*> IsLoadElement(const Matcher<ElementAccess>& access_matcher,
                             const Matcher<Node*>& base_matcher,
                             const Matcher<Node*>& index_matcher,
                             const Matcher<Node*>& effect_matcher,
                             const Matcher<Node*>& control_matcher) {
  return MakeMatcher(new IsLoadElementMatcher(access_matcher, base_matcher,
                                              index_matcher, effect_matcher,
                                              control_matcher));
}


Matcher<Node*> IsStoreElement(const Matcher<ElementAccess>& access_matcher,
                              const Matcher<Node*>& base_matcher,
                              const Matcher<Node*>& index_matcher,
                              const Matcher<Node*>& value_matcher,
                              const Matcher<Node*>& effect_matcher,
                              const Matcher<Node*>& control_matcher) {
  return MakeMatcher(new IsStoreElementMatcher(
      access_matcher, base_matcher, index_matcher, value_matcher,
      effect_matcher, control_matcher));
}

Matcher<Node*> IsLoad(const Matcher<LoadRepresentation>& rep_matcher,
                      const Matcher<Node*>& base_matcher,
                      const Matcher<Node*>& index_matcher,
                      const Matcher<Node*>& effect_matcher,
                      const Matcher<Node*>& control_matcher) {
  return MakeMatcher(new IsLoadMatcher(rep_matcher, base_matcher, index_matcher,
                                       effect_matcher, control_matcher));
}

Matcher<Node*> IsUnalignedLoad(const Matcher<LoadRepresentation>& rep_matcher,
                               const Matcher<Node*>& base_matcher,
                               const Matcher<Node*>& index_matcher,
                               const Matcher<Node*>& effect_matcher,
                               const Matcher<Node*>& control_matcher) {
  return MakeMatcher(new IsUnalignedLoadMatcher(rep_matcher, base_matcher,
                                                index_matcher, effect_matcher,
                                                control_matcher));
}

Matcher<Node*> IsLoadFromObject(const Matcher<LoadRepresentation>& rep_matcher,
                                const Matcher<Node*>& base_matcher,
                                const Matcher<Node*>& index_matcher,
                                const Matcher<Node*>& effect_matcher,
                                const Matcher<Node*>& control_matcher) {
  return MakeMatcher(new IsLoadFromObjectMatcher(rep_matcher, base_matcher,
                                                 index_matcher, effect_matcher,
                                                 control_matcher));
}

Matcher<Node*> IsLoadImmutable(const Matcher<LoadRepresentation>& rep_matcher,
                               const Matcher<Node*>& base_matcher,
                               const Matcher<Node*>& index_matcher) {
  return MakeMatcher(
      new IsLoadImmutableMatcher(rep_matcher, base_matcher, index_matcher));
}

Matcher<Node*> IsStore(const Matcher<StoreRepresentation>& rep_matcher,
                       const Matcher<Node*>& base_matcher,
                       const Matcher<Node*>& index_matcher,
                       const Matcher<Node*>& value_matcher,
                       const Matcher<Node*>& effect_matcher,
                       const Matcher<Node*>& control_matcher) {
  return MakeMatcher(new IsStoreMatcher(rep_matcher, base_matcher,
                                        index_matcher, value_matcher,
                                        effect_matcher, control_matcher));
}

Matcher<Node*> IsUnalignedStore(
    const Matcher<UnalignedStoreRepresentation>& rep_matcher,
    const Matcher<Node*>& base_matcher, const Matcher<Node*>& index_matcher,
    const Matcher<Node*>& value_matcher, const Matcher<Node*>& effect_matcher,
    const Matcher<Node*>& control_matcher) {
  return MakeMatcher(new IsUnalignedStoreMatcher(
      rep_matcher, base_matcher, index_matcher, value_matcher, effect_matcher,
      control_matcher));
}

Matcher<Node*> IsStoreToObject(const Matcher<ObjectAccess>& rep_matcher,
                               const Matcher<Node*>& base_matcher,
                               const Matcher<Node*>& index_matcher,
                               const Matcher<Node*>& value_matcher,
                               const Matcher<Node*>& effect_matcher,
                               const Matcher<Node*>& control_matcher) {
  return MakeMatcher(new IsStoreToObjectMatcher(
      rep_matcher, base_matcher, index_matcher, value_matcher, effect_matcher,
      control_matcher));
}

Matcher<Node*> IsStackSlot(
    const Matcher<StackSlotRepresentation>& rep_matcher) {
  return MakeMatcher(new IsStackSlotMatcher(rep_matcher));
}

Matcher<Node*> IsToNumber(const Matcher<Node*>& base_matcher,
                          const Matcher<Node*>& context_matcher,
                          const Matcher<Node*>& effect_matcher,
                          const Matcher<Node*>& control_matcher) {
  return MakeMatcher(new IsToNumberMatcher(base_matcher, context_matcher,
                                           effect_matcher, control_matcher));
}


Matcher<Node*> IsLoadContext(const Matcher<ContextAccess>& access_matcher,
                             const Matcher<Node*>& context_matcher) {
  return MakeMatcher(new IsLoadContextMatcher(access_matcher, context_matcher));
}


Matcher<Node*> IsParameter(const Matcher<int> index_matcher) {
  return MakeMatcher(new IsParameterMatcher(index_matcher));
}

Matcher<Node*> IsLoadFramePointer() {
  return MakeMatcher(new TestNodeMatcher(IrOpcode::kLoadFramePointer));
}

Matcher<Node*> IsLoadParentFramePointer() {
  return MakeMatcher(new TestNodeMatcher(IrOpcode::kLoadParentFramePointer));
}

#define IS_QUADOP_MATCHER(Name)                                               \
  Matcher<Node*> Is##Name(                                                    \
      const Matcher<Node*>& a_matcher, const Matcher<Node*>& b_matcher,       \
      const Matcher<Node*>& c_matcher, const Matcher<Node*>& d_matcher) {     \
    return MakeMatcher(new IsQuadopMatcher(IrOpcode::k##Name, a_matcher,      \
                                           b_matcher, c_matcher, d_matcher)); \
  }

IS_QUADOP_MATCHER(Int32PairAdd)
IS_QUADOP_MATCHER(Int32PairSub)
IS_QUADOP_MATCHER(Int32PairMul)

#define IS_TERNOP_MATCHER(Name)                                            \
  Matcher<Node*> Is##Name(const Matcher<Node*>& lhs_matcher,               \
                          const Matcher<Node*>& mid_matcher,               \
                          const Matcher<Node*>& rhs_matcher) {             \
    return MakeMatcher(new IsTernopMatcher(IrOpcode::k##Name, lhs_matcher, \
                                           mid_matcher, rhs_matcher));     \
  }

IS_TERNOP_MATCHER(Word32PairShl)
IS_TERNOP_MATCHER(Word32PairShr)
IS_TERNOP_MATCHER(Word32PairSar)

#define IS_BINOP_MATCHER(Name)                                            \
  Matcher<Node*> Is##Name(const Matcher<Node*>& lhs_matcher,              \
                          const Matcher<Node*>& rhs_matcher) {            \
    return MakeMatcher(                                                   \
        new IsBinopMatcher(IrOpcode::k##Name, lhs_matcher, rhs_matcher)); \
  }
IS_BINOP_MATCHER(NumberEqual)
IS_BINOP_MATCHER(NumberLessThan)
IS_BINOP_MATCHER(NumberSubtract)
IS_BINOP_MATCHER(NumberMultiply)
IS_BINOP_MATCHER(NumberShiftLeft)
IS_BINOP_MATCHER(NumberShiftRight)
IS_BINOP_MATCHER(NumberShiftRightLogical)
IS_BINOP_MATCHER(NumberImul)
IS_BINOP_MATCHER(NumberAtan2)
IS_BINOP_MATCHER(NumberMax)
IS_BINOP_MATCHER(NumberMin)
IS_BINOP_MATCHER(NumberPow)
IS_BINOP_MATCHER(ReferenceEqual)
IS_BINOP_MATCHER(Word32And)
IS_BINOP_MATCHER(Word32Or)
IS_BINOP_MATCHER(Word32Xor)
IS_BINOP_MATCHER(Word32Sar)
IS_BINOP_MATCHER(Word32Shl)
IS_BINOP_MATCHER(Word32Shr)
IS_BINOP_MATCHER(Word32Ror)
IS_BINOP_MATCHER(Word32Equal)
IS_BINOP_MATCHER(Word64And)
IS_BINOP_MATCHER(Word64Or)
IS_BINOP_MATCHER(Word64Xor)
IS_BINOP_MATCHER(Word64Sar)
IS_BINOP_MATCHER(Word64Shl)
IS_BINOP_MATCHER(Word64Shr)
IS_BINOP_MATCHER(Word64Equal)
IS_BINOP_MATCHER(Int32AddWithOverflow)
IS_BINOP_MATCHER(Int32SubWithOverflow)
IS_BINOP_MATCHER(Int32Add)
IS_BINOP_MATCHER(Int32Div)
IS_BINOP_MATCHER(Int32Sub)
IS_BINOP_MATCHER(Int32Mul)
IS_BINOP_MATCHER(Int32MulHigh)
IS_BINOP_MATCHER(Int32LessThan)
IS_BINOP_MATCHER(Uint32LessThan)
IS_BINOP_MATCHER(Uint32LessThanOrEqual)
IS_BINOP_MATCHER(Int64Add)
IS_BINOP_MATCHER(Int64Div)
IS_BINOP_MATCHER(Int64Sub)
IS_BINOP_MATCHER(Int64Mul)
IS_BINOP_MATCHER(Int64MulHigh)
IS_BINOP_MATCHER(Int64LessThan)
IS_BINOP_MATCHER(Uint64LessThan)
IS_BINOP_MATCHER(JSAdd)
IS_BINOP_MATCHER(JSParseInt)
IS_BINOP_MATCHER(Float32Equal)
IS_BINOP_MATCHER(Float32LessThan)
IS_BINOP_MATCHER(Float32LessThanOrEqual)
IS_BINOP_MATCHER(Float64Max)
IS_BINOP_MATCHER(Float64Min)
IS_BINOP_MATCHER(Float64Add)
IS_BINOP_MATCHER(Float64Sub)
IS_BINOP_MATCHER(Float64Mul)
IS_BINOP_MATCHER(Float64InsertLowWord32)
IS_BINOP_MATCHER(Float64InsertHighWord32)
#undef IS_BINOP_MATCHER


#define IS_UNOP_MATCHER(Name)                                                \
  Matcher<Node*> Is##Name(const Matcher<Node*>& input_matcher) {             \
    return MakeMatcher(new IsUnopMatcher(IrOpcode::k##Name, input_matcher)); \
  }
IS_UNOP_MATCHER(BooleanNot)
IS_UNOP_MATCHER(BitcastWordToTagged)
IS_UNOP_MATCHER(TruncateFloat64ToWord32)
IS_UNOP_MATCHER(ChangeFloat64ToInt32)
IS_UNOP_MATCHER(ChangeFloat64ToUint32)
IS_UNOP_MATCHER(ChangeInt32ToFloat64)
IS_UNOP_MATCHER(ChangeInt32ToInt64)
IS_UNOP_MATCHER(ChangeUint32ToFloat64)
IS_UNOP_MATCHER(ChangeUint32ToUint64)
IS_UNOP_MATCHER(TruncateFloat64ToFloat32)
IS_UNOP_MATCHER(TruncateInt64ToInt32)
IS_UNOP_MATCHER(Float32Abs)
IS_UNOP_MATCHER(Float32Neg)
IS_UNOP_MATCHER(Float64Abs)
IS_UNOP_MATCHER(Float64Neg)
IS_UNOP_MATCHER(Float64Sqrt)
IS_UNOP_MATCHER(Float64RoundDown)
IS_UNOP_MATCHER(Float64RoundTruncate)
IS_UNOP_MATCHER(Float64RoundTiesAway)
IS_UNOP_MATCHER(Float64ExtractLowWord32)
IS_UNOP_MATCHER(Float64ExtractHighWord32)
IS_UNOP_MATCHER(NumberAbs)
IS_UNOP_MATCHER(NumberAcos)
IS_UNOP_MATCHER(NumberAcosh)
IS_UNOP_MATCHER(NumberAsin)
IS_UNOP_MATCHER(NumberAsinh)
IS_UNOP_MATCHER(NumberAtan)
IS_UNOP_MATCHER(NumberAtanh)
IS_UNOP_MATCHER(NumberCeil)
IS_UNOP_MATCHER(NumberClz32)
IS_UNOP_MATCHER(NumberCbrt)
IS_UNOP_MATCHER(NumberCos)
IS_UNOP_MATCHER(NumberCosh)
IS_UNOP_MATCHER(NumberExp)
IS_UNOP_MATCHER(NumberExpm1)
IS_UNOP_MATCHER(NumberFloor)
IS_UNOP_MATCHER(NumberFround)
IS_UNOP_MATCHER(NumberLog)
IS_UNOP_MATCHER(NumberLog1p)
IS_UNOP_MATCHER(NumberLog10)
IS_UNOP_MATCHER(NumberLog2)
IS_UNOP_MATCHER(NumberRound)
IS_UNOP_MATCHER(NumberSign)
IS_UNOP_MATCHER(NumberSin)
IS_UNOP_MATCHER(NumberSinh)
IS_UNOP_MATCHER(NumberSqrt)
IS_UNOP_MATCHER(NumberTan)
IS_UNOP_MATCHER(NumberTanh)
IS_UNOP_MATCHER(NumberTrunc)
IS_UNOP_MATCHER(NumberToBoolean)
IS_UNOP_MATCHER(NumberToInt32)
IS_UNOP_MATCHER(NumberToUint32)
IS_UNOP_MATCHER(PlainPrimitiveToNumber)
IS_UNOP_MATCHER(ObjectIsFiniteNumber)
IS_UNOP_MATCHER(NumberIsFinite)
IS_UNOP_MATCHER(ObjectIsInteger)
IS_UNOP_MATCHER(ObjectIsSafeInteger)
IS_UNOP_MATCHER(ObjectIsNaN)
IS_UNOP_MATCHER(NumberIsNaN)
IS_UNOP_MATCHER(ObjectIsReceiver)
IS_UNOP_MATCHER(ObjectIsSmi)
IS_UNOP_MATCHER(ObjectIsUndetectable)
IS_UNOP_MATCHER(StringFromSingleCharCode)
IS_UNOP_MATCHER(StringLength)
IS_UNOP_MATCHER(Word32Clz)
IS_UNOP_MATCHER(Word32Ctz)
IS_UNOP_MATCHER(Word32Popcnt)
IS_UNOP_MATCHER(Word32ReverseBytes)
IS_UNOP_MATCHER(SpeculativeToNumber)
#undef IS_UNOP_MATCHER

// Special-case Bitcast operators which are disabled when ENABLE_VERIFY_CSA is
// not enabled.
Matcher<Node*> IsBitcastTaggedToWord(const Matcher<Node*>& input_matcher) {
  return MakeMatcher(
      new IsUnopMatcher(IrOpcode::kBitcastTaggedToWord, input_matcher));
}

Matcher<Node*> IsBitcastWordToTa
"""


```