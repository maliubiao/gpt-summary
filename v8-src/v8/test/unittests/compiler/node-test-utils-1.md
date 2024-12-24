Response: The user has provided the second part of a C++ header file. The first part was already processed. The goal is to summarize the functionality of this code and illustrate its connection to JavaScript using examples if any exist.

**Thinking Process:**

1. **Identify the Core Pattern:** Scan the code for repeated structures. Notice the extensive use of macros like `IS_BINOP_MATCHER`, `IS_UNOP_MATCHER`, `DEFINE_SPECULATIVE_BINOP_MATCHER`, and the repeated function signatures of the form `Matcher<Node*> IsSomething(...)`.

2. **Recognize the Purpose:** The consistent return type `Matcher<Node*>` suggests that these functions are creating "matchers". The `Is` prefix of the function names further reinforces this idea. The arguments to these functions often include other matchers, implying a composable matching system.

3. **Infer the Target:** The names of the matchers (e.g., `IsMerge`, `IsLoop`, `IsInt32Constant`, `IsCall`, `IsAdd`, `IsBooleanNot`) strongly suggest that these matchers are designed to check properties of *nodes* within a compiler's intermediate representation (IR). Specifically, the `IrOpcode` enum being passed to some of the underlying matcher classes confirms this.

4. **Connect to the Broader Context:**  Knowing this file is part of V8's compiler unit tests, these matchers are likely used to *assert* the structure of the generated IR in tests. This allows developers to verify that the compiler is producing the expected sequence of operations for given JavaScript code.

5. **Categorize the Matchers:**  Group the matchers based on the kind of IR node they represent. Examples:
    * **Control Flow:** `IsMerge`, `IsLoop`, `IsIfTrue`, `IsIfFalse`, `IsSwitch`
    * **Constants:** `IsInt32Constant`, `IsFloat64Constant`, `IsHeapConstant`
    * **Operations (OpCodes):** `IsAdd`, `IsSubtract`, `IsBooleanNot`, `IsCall`, `IsLoadField`, `IsStoreElement`
    * **Memory Access:** `IsLoad`, `IsStore`
    * **Special Operations:** `IsPhi`, `IsEffectPhi`, `IsProjection`
    * **Speculative Operations:** `IsSpeculativeNumberAdd`

6. **Explain the "Matcher" Concept:** Describe what a matcher is in this context – a way to check if a given IR node has specific properties. Highlight the composability using the passed-in matchers as arguments.

7. **Illustrate with JavaScript Examples:**  For the operation-related matchers, provide simple JavaScript code snippets that would likely lead to the generation of those IR opcodes. Focus on the core concept being tested by the matcher. For example:
    * `IsInt32Constant` -> `const x = 5;`
    * `IsAdd` -> `const sum = a + b;`
    * `IsBooleanNot` -> `const isFalse = !true;`
    * `IsCall` -> `function myFunction() {}; myFunction();`

8. **Address the "Part 2" Aspect:**  Acknowledge that this is the second part and that it builds upon the foundation laid in the first part (likely the base matcher classes).

9. **Refine and Organize:**  Ensure the summary is clear, concise, and well-organized. Use bullet points or similar formatting to improve readability. Use precise language related to compiler concepts (IR, opcodes).

**Self-Correction/Refinement During Thinking:**

* **Initial thought:** "These might be related to some kind of data structure."  **Correction:** The `IrOpcode` connection points directly to the compiler's IR.
* **Consideration:** "Should I explain each matcher individually?" **Correction:**  That would be too verbose. Focus on the general functionality and provide examples for representative categories.
* **JavaScript examples:** Initially considered more complex examples, but simpler examples are better for illustrating the direct relationship between the JavaScript and the basic IR operations being tested.
Based on the provided C++ code snippet, this part of the `node-test-utils.cc` file focuses on defining a large set of **matcher functions** for various **compiler IR (Intermediate Representation) nodes**.

Here's a breakdown of its functionality:

* **Creating Specific Node Matchers:**  This code defines numerous functions, all starting with `Is`, that create matchers for specific types of IR nodes within the V8 compiler. These matchers are used in unit tests to assert that the compiler generates the expected IR structure for given JavaScript code.

* **Matching Node Properties:** Each `Is...` function takes matchers as arguments, which specify constraints on the properties of the node being matched. These properties include:
    * **Opcode:** The type of operation the node represents (e.g., `kMerge`, `kLoop`, `kInt32Constant`, `kCall`).
    * **Inputs:**  Matchers for the input nodes of the current node. For example, an `IsAdd` matcher will take matchers for the two nodes being added.
    * **Control Flow:** Matchers for control flow edges (e.g., for `IsMerge`, `IsLoop`, `IsIfTrue`, `IsIfFalse`).
    * **Effects:** Matchers for effect edges, representing side effects of operations.
    * **Values:** Matchers for constant values (e.g., `IsInt32Constant`, `IsFloat64Constant`).
    * **Machine Representation:** The underlying data type of the value.
    * **Call Descriptors:**  Information about function calls.
    * **Memory Access Details:**  Information about memory loads and stores (e.g., `FieldAccess`, `ElementAccess`, `LoadRepresentation`, `StoreRepresentation`).

* **Composability of Matchers:** The key feature is that these matchers are composable. You can build complex matching rules by combining simpler matchers. For instance, you can assert that an addition node (`IsAdd`) has specific constant values as its inputs (`IsInt32Constant`).

* **Macros for Code Generation:** The code utilizes macros like `DEFINE_SPECULATIVE_BINOP_MATCHER`, `IS_QUADOP_MATCHER`, `IS_TERNOP_MATCHER`, `IS_BINOP_MATCHER`, and `IS_UNOP_MATCHER` to reduce code duplication and generate matchers for various operations with similar structures.

**Relationship to JavaScript and Examples:**

This C++ code directly relates to how the V8 JavaScript engine compiles JavaScript code into machine code. The IR nodes being matched represent the internal steps and operations the compiler performs.

Here are some examples of how these matchers can be conceptually linked to JavaScript code:

**1. Arithmetic Operations:**

* **C++ Matcher:** `IsInt32Add(IsInt32Constant(5), IsInt32Constant(3))`
* **JavaScript Equivalent (conceptual):** When the JavaScript code `const sum = 5 + 3;` is compiled, the V8 compiler might generate IR nodes representing the addition of the integer constants 5 and 3. The C++ matcher would verify this structure in a unit test.

**2. Control Flow:**

* **C++ Matcher:** `IsIfTrue(Is...)` (where `Is...` matches the condition node)
* **JavaScript Equivalent:**
```javascript
if (x > 10) {
  // ... code to execute if true
}
```
The `IsIfTrue` matcher would be used to check the IR node that represents the branch taken when the condition `x > 10` is true.

* **C++ Matcher:** `IsLoop(Is..., Is...)` (matching the loop header and potentially an exit condition)
* **JavaScript Equivalent:**
```javascript
for (let i = 0; i < 5; i++) {
  // ... loop body
}
```
The `IsLoop` matcher would be used to verify the IR structure representing the loop construct.

**3. Function Calls:**

* **C++ Matcher:** `IsCall(Is..., Is..., Is...)` (matching the call descriptor and argument nodes)
* **JavaScript Equivalent:**
```javascript
function myFunction(a, b) {
  return a + b;
}
const result = myFunction(2, 4);
```
The `IsCall` matcher would check the IR node representing the call to `myFunction`, ensuring the correct arguments are passed.

**4. Memory Access (Conceptual):**

* **C++ Matcher:** `IsLoadField(Is..., Is...)` (matching the field access information and the base object node)
* **JavaScript Equivalent (simplified):**  Accessing a property of an object:
```javascript
const obj = { name: "example" };
const n = obj.name;
```
The `IsLoadField` matcher would verify the IR node that loads the `name` field from the `obj` object.

**In summary, this part of the `node-test-utils.cc` file provides a powerful and flexible way to write unit tests for the V8 compiler by allowing developers to precisely describe and verify the structure of the generated intermediate representation.** It serves as a crucial component for ensuring the correctness and reliability of the JavaScript compilation process. The matchers directly correspond to the internal operations and control flow mechanisms used by the V8 engine when executing JavaScript code.

Prompt: 
```
这是目录为v8/test/unittests/compiler/node-test-utils.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

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

Matcher<Node*> IsBitcastWordToTaggedSigned(
    const Matcher<Node*>& input_matcher) {
  return MakeMatcher(
      new IsUnopMatcher(IrOpcode::kBitcastWordToTaggedSigned, input_matcher));
}

#undef LOAD_MATCHER
#undef STORE_MATCHER
#undef IS_QUADOP_MATCHER
#undef IS_TERNOP_MATCHER

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```