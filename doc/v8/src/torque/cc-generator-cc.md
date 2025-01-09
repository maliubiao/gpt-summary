Response:
Let's break down the thought process for analyzing the provided C++ code.

**1. Initial Understanding of the Context:**

The first line `// Copyright 2020 the V8 project authors.` immediately tells us this is part of the V8 JavaScript engine. The filename `v8/src/torque/cc-generator.cc` is highly informative. "Torque" suggests a domain-specific language or tool used in V8 development. "cc-generator" strongly implies this code is responsible for generating C++ code from some input. The `.cc` extension confirms it's a C++ source file.

**2. High-Level Functionality Guess:**

Based on the filename, I'd hypothesize that this code takes some kind of intermediate representation (likely from the Torque language) and translates it into C++ source code. This generated C++ code would then be compiled and linked into the V8 engine.

**3. Examining Includes:**

The `#include` directives provide clues about the dependencies and related modules:

* `"src/torque/cc-generator.h"`:  The corresponding header file, likely defining the `CCGenerator` class.
* `<optional>`: Standard C++ for handling potentially absent values.
* `"src/common/globals.h"`:  Likely contains global definitions and configurations for V8.
* `"src/torque/global-context.h"`, `"src/torque/type-oracle.h"`, `"src/torque/types.h"`: These strongly suggest this code is heavily involved with type systems and global context within the Torque environment.
* `"src/torque/utils.h"`:  Contains utility functions specific to Torque.

**4. Analyzing the `CCGenerator` Class:**

The core of the code is the `CCGenerator` class. I'd look at its public methods to understand its primary responsibilities.

* **`EmitGraph`:** This sounds like it processes the main control flow graph of a Torque procedure. The `parameters` argument suggests it handles input values. The return type `std::optional<Stack<std::string>>` likely represents the generated C++ code, or perhaps the final output of a block. The use of `GotoInstruction` hints at basic block structure.
* **`EmitBlock`:**  Processes a single basic block within the control flow graph.
* **`EmitInstruction` (overloaded):** This is the most crucial part. The overloaded nature indicates it handles different kinds of Torque instructions. The parameters include the specific instruction type and a `Stack<std::string>*`, suggesting that intermediate results and variables are managed on a stack.
* **`EmitSourcePosition`:**  Handles emitting source code location information, useful for debugging.
* **`ProcessArgumentsCommon`:**  A helper for handling arguments to function/macro calls, taking into account constexpr values.

**5. Deep Dive into `EmitInstruction` Overloads:**

This is where the specific functionality for translating Torque constructs to C++ resides. I'd go through each overload and try to understand what Torque construct it handles and how it translates it. Here's a sample of the thought process for a few of them:

* **`PushUninitializedInstruction`:** The `ReportError` indicates that this Torque instruction doesn't have a direct C++ equivalent in this generation process. This implies that uninitialized values are handled differently at the C++ level.
* **`CallIntrinsicInstruction`:** This clearly handles calls to "intrinsics," which are likely built-in functions or operations within V8. The code deals with argument processing, return types, and special cases like `%RawDownCast` and `%FromConstexpr`. This gives insight into how certain low-level operations are represented in Torque and mapped to C++.
* **`CallCsaMacroInstruction`:** Similar to intrinsics, but for "CSA macros" (likely CodeStubAssembler macros, a lower-level V8 assembly-like language). The code shows how these macros are invoked in the generated C++.
* **`BranchInstruction`:**  A standard conditional branch, translated to a C++ `if` statement with `goto` for jumping to the target blocks.
* **`GotoInstruction`:**  Directly translates to a C++ `goto`.
* **`ReturnInstruction`:** The `ReportError` suggests that the C++ generation might handle returns differently, perhaps by setting up return values before a final jump.
* **`LoadReferenceInstruction`:**  Handles loading values from memory locations. The code distinguishes between tagged (managed by the garbage collector) and untagged values and uses appropriate C++ access methods (like `TaggedField::load` or `ReadField`).
* **`LoadBitFieldInstruction`:**  Handles accessing bitfields within structures using bit manipulation techniques in C++.

**6. Identifying Relationships to JavaScript:**

As I analyze the `EmitInstruction` overloads, I look for connections to JavaScript concepts. For example:

* The handling of tagged values (like in `LoadReferenceInstruction`) directly relates to how JavaScript objects and values are represented in V8's heap.
* Intrinsics like `%RawDownCast` and `%FromConstexpr` are low-level operations that might be used to implement various JavaScript features efficiently.
* The generation of code for function calls (intrinsics and CSA macros) is fundamental to how JavaScript functions are executed.

**7. Code Logic Inference and Examples:**

For instructions like `BranchInstruction` and `ConstexprBranchInstruction`, it's straightforward to infer the logic and provide simple examples.

**8. Identifying Potential User Errors:**

Looking at the constraints and error handling within the `EmitInstruction` methods helps identify potential user errors in the Torque code that would lead to issues during C++ code generation. For instance, using `%RawDownCast` incorrectly or using unsupported instructions in the C++ backend.

**9. Iterative Refinement:**

My initial understanding might be a bit fuzzy. As I delve deeper into the code, I refine my understanding and correct any initial misinterpretations. For example, the use of `goto` might initially seem unusual in modern C++, but it makes sense in the context of generating code that mirrors a control flow graph.

By following this systematic approach – starting with the high-level context and progressively digging into the details, especially the `EmitInstruction` overloads – I can effectively analyze the functionality of the `cc-generator.cc` file and answer the prompt's questions.
This C++ source file, `v8/src/torque/cc-generator.cc`, is a crucial component of the V8 JavaScript engine's Torque infrastructure. Its primary function is to **translate Torque code into C++ code**.

Let's break down its functionalities:

**1. Torque to C++ Code Generation:**

* **Input:** The `CCGenerator` class takes a control flow graph (`cfg_`) representing the compiled Torque code as input. This graph contains blocks of instructions.
* **Output:** It generates corresponding C++ code that implements the logic defined in the Torque code. This C++ code is designed to be used within V8's CodeStubAssembler (CSA) framework, which is a low-level code generation mechanism in V8.
* **Key Methods:**
    * **`EmitGraph(Stack<std::string> parameters)`:**  This is the main entry point for generating C++ code for an entire Torque function or procedure. It iterates through the control flow graph's blocks and calls `EmitBlock` for each.
    * **`EmitBlock(const Block* block)`:** Generates C++ code for a single basic block within the control flow graph. It handles setting up variables for block inputs (phi nodes) and iterates through the instructions within the block, calling `EmitInstruction` for each.
    * **`EmitInstruction(const Instruction& instruction, Stack<std::string>* stack)` (overloaded):** This set of overloaded methods is the workhorse of the generator. Each overload handles a specific type of Torque instruction, translating it into equivalent C++ code.

**2. Handling Torque Instructions:**

The `CCGenerator` has specific logic to translate various Torque instructions into C++:

* **Control Flow:**
    * **`GotoInstruction`:** Translates to a C++ `goto` statement.
    * **`BranchInstruction`:** Translates to a C++ `if` statement with `goto` for the branches.
    * **`ConstexprBranchInstruction`:** Similar to `BranchInstruction`, but the condition is a compile-time constant expression.
* **Function/Macro Calls:**
    * **`CallIntrinsicInstruction`:** Handles calls to built-in V8 intrinsics (low-level functions). It manages argument passing and result handling. It has special logic for intrinsics like `%RawDownCast` and `%FromConstexpr`.
    * **`CallCsaMacroInstruction`:** Handles calls to CSA macros.
    * **`CallBuiltinInstruction`, `CallBuiltinPointerInstruction`, `CallRuntimeInstruction`:** These are currently not supported in the C++ output and will `ReportError`. This likely means these types of calls are handled differently or inlined at an earlier stage.
* **Data Manipulation:**
    * **`LoadReferenceInstruction`:** Generates C++ code to load a value from memory (e.g., loading a field from an object). It handles both tagged (garbage-collected) and untagged values.
    * **`LoadBitFieldInstruction`:** Generates C++ code to read a bitfield from a structure.
    * **`UnsafeCastInstruction`:** Generates a C++ `static_cast`.
    * **`PushUninitializedInstruction`, `PushBuiltinPointerInstruction`, `NamespaceConstantInstruction`, `StoreReferenceInstruction`, `StoreBitFieldInstruction`:** These are currently not supported in the C++ output.
* **Error Handling:**
    * **`PrintErrorInstruction`:** Generates C++ code to print an error message to `std::cerr`.
    * **`AbortInstruction`:** Generates C++ code for different kinds of aborts (unreachable, debug break, assertion failure).
* **Other:**
    * **`MakeLazyNodeInstruction`:** Not supported in C++ output.
    * **`GotoExternalInstruction`:** Not supported in C++ output.
    * **`ReturnInstruction`:** Not supported in C++ output.

**If `v8/src/torque/cc-generator.cc` ended with `.tq`:**

If the file ended with `.tq`, it would indeed be a **Torque source file**. Torque files define the language used to specify type-safe and performance-critical code within V8. The `cc-generator.cc` takes these `.tq` files (after they are processed and converted to the intermediate representation) as its input to generate C++ code.

**Relationship to JavaScript and Examples:**

The C++ code generated by `cc-generator.cc` directly implements the semantics of JavaScript features. Here are some examples illustrating the connection:

**Example 1:  `%RawDownCast` intrinsic (related to type casting)**

* **Torque Code (hypothetical):**  Let's say you have Torque code that needs to perform a downcast (treat an object of a supertype as its subtype). Torque might use something like an intrinsic for this.
* **Generated C++ (from `EmitInstruction` for `CallIntrinsicInstruction`):**
   ```c++
   // Assuming 'object' is a variable holding the supertype object
   Handle<SuperType> object = ...;
   Handle<SubType> result;
   if (object->IsSubType()) { // Hypothetical check
     result = Handle<SubType>::cast(object);
   } else {
     // Handle error
   }
   ```
   The `cc-generator.cc` might generate a call to a CSA macro or inline C++ code that performs a type check and then a cast, potentially using `static_cast` or `reinterpret_cast` depending on the types involved. The `%RawDownCast` intrinsic in Torque allows for potentially unsafe downcasts (hence "raw"), and the C++ generator needs to handle this.

* **JavaScript Connection:**  When you perform a type cast or when the V8 engine needs to determine the specific type of an object at runtime (e.g., during method dispatch), the generated C++ code for intrinsics like `%RawDownCast` might be involved.

**Example 2: `LoadReferenceInstruction` (related to object property access)**

* **Torque Code (hypothetical):** Accessing a property of an object:
   ```torque
   let name: String = object.name;
   ```
* **Generated C++ (from `EmitInstruction` for `LoadReferenceInstruction`):**
   ```c++
   // Assuming 'object' is a variable of type HeapObject
   Handle<HeapObject> object = ...;
   int offset = String::kNameOffset; // Offset of the 'name' field
   Handle<String> name;
   name = Handle<String>::cast(LoadObjectField(object, offset));
   ```
   The `cc-generator.cc` would generate code to calculate the memory offset of the `name` field within the `String` object and then use a low-level V8 function (`LoadObjectField`) to read the value from that memory location.

* **JavaScript Connection:** When you access a property of a JavaScript object (e.g., `obj.name`), the generated C++ code for `LoadReferenceInstruction` (or similar mechanisms) is executed to retrieve the value of that property from the object's memory representation.

**Code Logic Inference and Examples:**

**Example: `BranchInstruction`**

* **Hypothetical Input (Torque):**
   ```torque
   if (condition) goto block_true; else goto block_false;
   ```
* **Assumptions:**
    * `condition` is a variable holding a boolean value.
    * `block_true` and `block_false` are labels of other blocks in the control flow graph.
* **Generated Output (C++):**
   ```c++
   if (condition_variable) {
     goto block_true_label;
   } else {
     goto block_false_label;
   }
   ```
   The `EmitInstruction` for `BranchInstruction` takes the condition and the target blocks and generates a standard C++ `if` statement with `goto` to the corresponding block labels.

**User Programming Errors and Examples:**

Since `cc-generator.cc` is part of the V8 engine's internal build process, it doesn't directly deal with errors in *user* JavaScript code. Instead, it focuses on errors in the *Torque* code written by V8 developers. However, errors in Torque code can lead to issues in the generated C++ code, which could eventually manifest as bugs or performance problems in JavaScript execution.

Here are some examples of potential Torque programming errors that the `cc-generator.cc` might encounter (and potentially report or fail to compile):

1. **Type Mismatches:** If the Torque code attempts to assign a value of one type to a variable of an incompatible type, the `cc-generator.cc` might generate C++ code that results in a compilation error or runtime crash due to type safety violations.

   * **Example (Torque):**
     ```torque
     let number: Number = "hello"; // Incorrect type assignment
     ```
   * **Possible Consequence in Generated C++:** The generated C++ might try an invalid cast or assignment, leading to a compiler error.

2. **Incorrect Intrinsic Usage:** If a Torque developer uses an intrinsic with the wrong number or type of arguments, the `cc-generator.cc` might generate C++ code that calls the intrinsic incorrectly.

   * **Example (Torque):**  Assuming an intrinsic `%Add` that takes two numbers.
     ```torque
     let sum: Number = %Add(1, "two"); // String argument is wrong
     ```
   * **Possible Consequence in Generated C++:** The generated C++ call to the underlying C++ function for `%Add` would have a type mismatch, leading to a compilation error or undefined behavior.

3. **Control Flow Errors:** If the Torque code has incorrect control flow (e.g., jumping to a non-existent block or missing a return statement where one is expected), the `cc-generator.cc` might generate C++ code with `goto` statements that jump to invalid labels or have missing return values.

   * **Example (Torque):**
     ```torque
     goto non_existent_block;
     ```
   * **Possible Consequence in Generated C++:** The generated C++ would have a `goto` to an undefined label, resulting in a compilation error.

In summary, `v8/src/torque/cc-generator.cc` is a critical translation layer in V8. It takes high-level, type-safe Torque code and transforms it into efficient, low-level C++ code that forms the core of V8's execution engine. While it doesn't directly deal with user JavaScript errors, it plays a vital role in ensuring the correctness and performance of the JavaScript runtime by correctly translating the internal logic defined in Torque.

Prompt: 
```
这是目录为v8/src/torque/cc-generator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/torque/cc-generator.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/torque/cc-generator.h"

#include <optional>

#include "src/common/globals.h"
#include "src/torque/global-context.h"
#include "src/torque/type-oracle.h"
#include "src/torque/types.h"
#include "src/torque/utils.h"

namespace v8::internal::torque {

std::optional<Stack<std::string>> CCGenerator::EmitGraph(
    Stack<std::string> parameters) {
  for (BottomOffset i = {0}; i < parameters.AboveTop(); ++i) {
    SetDefinitionVariable(DefinitionLocation::Parameter(i.offset),
                          parameters.Peek(i));
  }

  // Redirect the output of non-declarations into a buffer and only output
  // declarations right away.
  std::stringstream out_buffer;
  std::ostream* old_out = out_;
  out_ = &out_buffer;

  EmitInstruction(GotoInstruction{cfg_.start()}, &parameters);

  for (Block* block : cfg_.blocks()) {
    if (cfg_.end() && *cfg_.end() == block) continue;
    if (block->IsDead()) continue;
    EmitBlock(block);
  }

  std::optional<Stack<std::string>> result;
  if (cfg_.end()) {
    result = EmitBlock(*cfg_.end());
  }

  // All declarations have been printed now, so we can append the buffered
  // output and redirect back to the original output stream.
  out_ = old_out;
  out() << out_buffer.str();

  return result;
}

Stack<std::string> CCGenerator::EmitBlock(const Block* block) {
  out() << "\n";
  out() << "  " << BlockName(block) << ":\n";

  Stack<std::string> stack;

  for (BottomOffset i = {0}; i < block->InputTypes().AboveTop(); ++i) {
    const auto& def = block->InputDefinitions().Peek(i);
    stack.Push(DefinitionToVariable(def));
    if (def.IsPhiFromBlock(block)) {
      decls() << "  "
              << (is_cc_debug_ ? block->InputTypes().Peek(i)->GetDebugType()
                               : block->InputTypes().Peek(i)->GetRuntimeType())
              << " " << stack.Top() << "{}; USE(" << stack.Top() << ");\n";
    }
  }

  for (const Instruction& instruction : block->instructions()) {
    TorqueCodeGenerator::EmitInstruction(instruction, &stack);
  }
  return stack;
}

void CCGenerator::EmitSourcePosition(SourcePosition pos, bool always_emit) {
  const std::string& file = SourceFileMap::AbsolutePath(pos.source);
  if (always_emit || !previous_position_.CompareStartIgnoreColumn(pos)) {
    // Lines in Torque SourcePositions are zero-based, while the
    // CodeStubAssembler and downwind systems are one-based.
    out() << "  // " << file << ":" << (pos.start.line + 1) << "\n";
    previous_position_ = pos;
  }
}

void CCGenerator::EmitInstruction(
    const PushUninitializedInstruction& instruction,
    Stack<std::string>* stack) {
  ReportError("Not supported in C++ output: PushUninitialized");
}

void CCGenerator::EmitInstruction(
    const PushBuiltinPointerInstruction& instruction,
    Stack<std::string>* stack) {
  ReportError("Not supported in C++ output: PushBuiltinPointer");
}

void CCGenerator::EmitInstruction(
    const NamespaceConstantInstruction& instruction,
    Stack<std::string>* stack) {
  ReportError("Not supported in C++ output: NamespaceConstantInstruction");
}

std::vector<std::string> CCGenerator::ProcessArgumentsCommon(
    const TypeVector& parameter_types,
    std::vector<std::string> constexpr_arguments, Stack<std::string>* stack) {
  std::vector<std::string> args;
  for (auto it = parameter_types.rbegin(); it != parameter_types.rend(); ++it) {
    const Type* type = *it;
    if (type->IsConstexpr()) {
      args.push_back(std::move(constexpr_arguments.back()));
      constexpr_arguments.pop_back();
    } else {
      std::stringstream s;
      size_t slot_count = LoweredSlotCount(type);
      VisitResult arg = VisitResult(type, stack->TopRange(slot_count));
      EmitCCValue(arg, *stack, s);
      args.push_back(s.str());
      stack->PopMany(slot_count);
    }
  }
  std::reverse(args.begin(), args.end());
  return args;
}

void CCGenerator::EmitInstruction(const CallIntrinsicInstruction& instruction,
                                  Stack<std::string>* stack) {
  TypeVector parameter_types =
      instruction.intrinsic->signature().parameter_types.types;
  std::vector<std::string> args = ProcessArgumentsCommon(
      parameter_types, instruction.constexpr_arguments, stack);

  Stack<std::string> pre_call_stack = *stack;
  const Type* return_type = instruction.intrinsic->signature().return_type;
  std::vector<std::string> results;

  const auto lowered = LowerType(return_type);
  for (std::size_t i = 0; i < lowered.size(); ++i) {
    results.push_back(DefinitionToVariable(instruction.GetValueDefinition(i)));
    stack->Push(results.back());
    decls() << "  "
            << (is_cc_debug_ ? lowered[i]->GetDebugType()
                             : lowered[i]->GetRuntimeType())
            << " " << stack->Top() << "{}; USE(" << stack->Top() << ");\n";
  }

  out() << "  ";
  if (return_type->StructSupertype()) {
    out() << "std::tie(";
    PrintCommaSeparatedList(out(), results);
    out() << ") = ";
  } else {
    if (results.size() == 1) {
      out() << results[0] << " = ";
    }
  }

  if (instruction.intrinsic->ExternalName() == "%RawDownCast") {
    if (parameter_types.size() != 1) {
      ReportError("%RawDownCast must take a single parameter");
    }
    const Type* original_type = parameter_types[0];
    bool is_subtype =
        return_type->IsSubtypeOf(original_type) ||
        (original_type == TypeOracle::GetUninitializedHeapObjectType() &&
         return_type->IsSubtypeOf(TypeOracle::GetHeapObjectType()));
    if (!is_subtype) {
      ReportError("%RawDownCast error: ", *return_type, " is not a subtype of ",
                  *original_type);
    }
    if (!original_type->StructSupertype() &&
        return_type->GetRuntimeType() != original_type->GetRuntimeType()) {
      out() << "static_cast<" << return_type->GetRuntimeType() << ">";
    }
  } else if (instruction.intrinsic->ExternalName() == "%GetClassMapConstant") {
    ReportError("C++ generator doesn't yet support %GetClassMapConstant");
  } else if (instruction.intrinsic->ExternalName() == "%FromConstexpr") {
    if (parameter_types.size() != 1 || !parameter_types[0]->IsConstexpr()) {
      ReportError(
          "%FromConstexpr must take a single parameter with constexpr "
          "type");
    }
    if (return_type->IsConstexpr()) {
      ReportError("%FromConstexpr must return a non-constexpr type");
    }
    if (return_type->IsSubtypeOf(TypeOracle::GetSmiType())) {
      if (is_cc_debug_) {
        out() << "Internals::IntToSmi";
      } else {
        out() << "Smi::FromInt";
      }
    }
    // Wrap the raw constexpr value in a static_cast to ensure that
    // enums get properly casted to their backing integral value.
    out() << "(CastToUnderlyingTypeIfEnum";
  } else {
    ReportError("no built in intrinsic with name " +
                instruction.intrinsic->ExternalName());
  }

  out() << "(";
  PrintCommaSeparatedList(out(), args);
  if (instruction.intrinsic->ExternalName() == "%FromConstexpr") {
    out() << ")";
  }
  out() << ");\n";
}

void CCGenerator::EmitInstruction(const CallCsaMacroInstruction& instruction,
                                  Stack<std::string>* stack) {
  TypeVector parameter_types =
      instruction.macro->signature().parameter_types.types;
  std::vector<std::string> args = ProcessArgumentsCommon(
      parameter_types, instruction.constexpr_arguments, stack);

  Stack<std::string> pre_call_stack = *stack;
  const Type* return_type = instruction.macro->signature().return_type;
  std::vector<std::string> results;

  const auto lowered = LowerType(return_type);
  for (std::size_t i = 0; i < lowered.size(); ++i) {
    results.push_back(DefinitionToVariable(instruction.GetValueDefinition(i)));
    stack->Push(results.back());
    decls() << "  "
            << (is_cc_debug_ ? lowered[i]->GetDebugType()
                             : lowered[i]->GetRuntimeType())
            << " " << stack->Top() << "{}; USE(" << stack->Top() << ");\n";
  }

  // We should have inlined any calls requiring complex control flow.
  CHECK(!instruction.catch_block);
  out() << (is_cc_debug_ ? "  ASSIGN_OR_RETURN(" : "  ");
  if (return_type->StructSupertype().has_value()) {
    out() << "std::tie(";
    PrintCommaSeparatedList(out(), results);
    out() << (is_cc_debug_ ? "), " : ") = ");
  } else {
    if (results.size() == 1) {
      out() << results[0] << (is_cc_debug_ ? ", " : " = ");
    } else {
      DCHECK_EQ(0, results.size());
    }
  }

  if (is_cc_debug_) {
    out() << instruction.macro->CCDebugName() << "(accessor";
    if (!args.empty()) out() << ", ";
  } else {
    out() << instruction.macro->CCName() << "(";
  }
  PrintCommaSeparatedList(out(), args);
  if (is_cc_debug_) {
    out() << "));\n";
  } else {
    out() << ");\n";
  }
}

void CCGenerator::EmitInstruction(
    const CallCsaMacroAndBranchInstruction& instruction,
    Stack<std::string>* stack) {
  ReportError("Not supported in C++ output: CallCsaMacroAndBranch");
}

void CCGenerator::EmitInstruction(const MakeLazyNodeInstruction& instruction,
                                  Stack<std::string>* stack) {
  ReportError("Not supported in C++ output: MakeLazyNode");
}

void CCGenerator::EmitInstruction(const CallBuiltinInstruction& instruction,
                                  Stack<std::string>* stack) {
  ReportError("Not supported in C++ output: CallBuiltin");
}

void CCGenerator::EmitInstruction(
    const CallBuiltinPointerInstruction& instruction,
    Stack<std::string>* stack) {
  ReportError("Not supported in C++ output: CallBuiltinPointer");
}

void CCGenerator::EmitInstruction(const CallRuntimeInstruction& instruction,
                                  Stack<std::string>* stack) {
  ReportError("Not supported in C++ output: CallRuntime");
}

void CCGenerator::EmitInstruction(const BranchInstruction& instruction,
                                  Stack<std::string>* stack) {
  out() << "  if (" << stack->Pop() << ") {\n";
  EmitGoto(instruction.if_true, stack, "    ");
  out() << "  } else {\n";
  EmitGoto(instruction.if_false, stack, "    ");
  out() << "  }\n";
}

void CCGenerator::EmitInstruction(const ConstexprBranchInstruction& instruction,
                                  Stack<std::string>* stack) {
  out() << "  if ((" << instruction.condition << ")) {\n";
  EmitGoto(instruction.if_true, stack, "    ");
  out() << "  } else {\n";
  EmitGoto(instruction.if_false, stack, "    ");
  out() << "  }\n";
}

void CCGenerator::EmitGoto(const Block* destination, Stack<std::string>* stack,
                           std::string indentation) {
  const auto& destination_definitions = destination->InputDefinitions();
  DCHECK_EQ(stack->Size(), destination_definitions.Size());
  for (BottomOffset i = {0}; i < stack->AboveTop(); ++i) {
    DefinitionLocation def = destination_definitions.Peek(i);
    if (def.IsPhiFromBlock(destination)) {
      out() << indentation << DefinitionToVariable(def) << " = "
            << stack->Peek(i) << ";\n";
    }
  }
  out() << indentation << "goto " << BlockName(destination) << ";\n";
}

void CCGenerator::EmitInstruction(const GotoInstruction& instruction,
                                  Stack<std::string>* stack) {
  EmitGoto(instruction.destination, stack, "  ");
}

void CCGenerator::EmitInstruction(const GotoExternalInstruction& instruction,
                                  Stack<std::string>* stack) {
  ReportError("Not supported in C++ output: GotoExternal");
}

void CCGenerator::EmitInstruction(const ReturnInstruction& instruction,
                                  Stack<std::string>* stack) {
  ReportError("Not supported in C++ output: Return");
}

void CCGenerator::EmitInstruction(const PrintErrorInstruction& instruction,
                                  Stack<std::string>* stack) {
  out() << "  std::cerr << " << StringLiteralQuote(instruction.message)
        << ";\n";
}

void CCGenerator::EmitInstruction(const AbortInstruction& instruction,
                                  Stack<std::string>* stack) {
  switch (instruction.kind) {
    case AbortInstruction::Kind::kUnreachable:
      DCHECK(instruction.message.empty());
      out() << "  UNREACHABLE();\n";
      break;
    case AbortInstruction::Kind::kDebugBreak:
      DCHECK(instruction.message.empty());
      out() << "  base::OS::DebugBreak();\n";
      break;
    case AbortInstruction::Kind::kAssertionFailure: {
      std::string file = StringLiteralQuote(
          SourceFileMap::PathFromV8Root(instruction.pos.source));
      out() << "  CHECK(false, \"Failed Torque assertion: '\""
            << StringLiteralQuote(instruction.message) << "\"' at \"" << file
            << "\":\""
            << StringLiteralQuote(
                   std::to_string(instruction.pos.start.line + 1))
            << ");\n";
      break;
    }
  }
}

void CCGenerator::EmitInstruction(const UnsafeCastInstruction& instruction,
                                  Stack<std::string>* stack) {
  const std::string str = "static_cast<" +
                          instruction.destination_type->GetRuntimeType() +
                          ">(" + stack->Top() + ")";
  stack->Poke(stack->AboveTop() - 1, str);
  SetDefinitionVariable(instruction.GetValueDefinition(), str);
}

void CCGenerator::EmitInstruction(const LoadReferenceInstruction& instruction,
                                  Stack<std::string>* stack) {
  std::string result_name =
      DefinitionToVariable(instruction.GetValueDefinition());

  std::string offset = stack->Pop();
  std::string object = stack->Pop();
  stack->Push(result_name);

  if (!is_cc_debug_) {
    std::string result_type = instruction.type->GetRuntimeType();
    decls() << "  " << result_type << " " << result_name << "{}; USE("
            << result_name << ");\n";
    out() << "  " << result_name << " = ";
    if (instruction.type->IsSubtypeOf(TypeOracle::GetTaggedType())) {
      // Currently, all of the tagged loads we emit are for smi values, so there
      // is no point in providing an PtrComprCageBase. If at some point we start
      // emitting loads for tagged fields which might be HeapObjects, then we
      // should plumb an PtrComprCageBase through the generated functions that
      // need it.
      if (!instruction.type->IsSubtypeOf(TypeOracle::GetSmiType())) {
        Error(
            "Not supported in C++ output: LoadReference on non-smi tagged "
            "value");
      }
      if (instruction.synchronization != FieldSynchronization::kNone) {
        // TODO(ishell): generate proper TaggedField<..>::load() call once
        // there's a real use case.
        ReportError(
            "Torque doesn't support @cppRelaxedLoad/@cppAcquireLoad on tagged "
            "data");
      }
      // References and slices can cause some values to have the Torque type
      // HeapObject|TaggedZeroPattern, which is output as "Object". TaggedField
      // requires HeapObject, so we need a cast.
      out() << "TaggedField<" << result_type
            << ">::load(UncheckedCast<HeapObject>(" << object
            << "), static_cast<int>(" << offset << "));\n";
    } else {
      // This code replicates the way we load the field in accessors, see
      // CppClassGenerator::EmitLoadFieldStatement().
      const char* load;
      switch (instruction.synchronization) {
        case FieldSynchronization::kNone:
          load = "ReadField";
          break;
        case FieldSynchronization::kRelaxed:
          load = "Relaxed_ReadField";
          break;
        case FieldSynchronization::kAcquireRelease:
          ReportError(
              "Torque doesn't support @cppAcquireLoad on untagged data");
      }
      out() << "(" << object << ")->" << load << "<" << result_type << ">("
            << offset << ");\n";
    }
  } else {
    std::string result_type = instruction.type->GetDebugType();
    decls() << "  " << result_type << " " << result_name << "{}; USE("
            << result_name << ");\n";
    if (instruction.type->IsSubtypeOf(TypeOracle::GetTaggedType())) {
      out() << "  READ_TAGGED_FIELD_OR_FAIL(" << result_name << ", accessor, "
            << object << ", static_cast<int>(" << offset << "));\n";
    } else {
      out() << "  READ_FIELD_OR_FAIL(" << result_type << ", " << result_name
            << ", accessor, " << object << ", " << offset << ");\n";
    }
  }
}

void CCGenerator::EmitInstruction(const StoreReferenceInstruction& instruction,
                                  Stack<std::string>* stack) {
  ReportError("Not supported in C++ output: StoreReference");
}

namespace {
std::string GetBitFieldSpecialization(const Type* container,
                                      const BitField& field) {
  std::stringstream stream;
  stream << "base::BitField<"
         << field.name_and_type.type->GetConstexprGeneratedTypeName() << ", "
         << field.offset << ", " << field.num_bits << ", "
         << container->GetConstexprGeneratedTypeName() << ">";
  return stream.str();
}
}  // namespace

void CCGenerator::EmitInstruction(const LoadBitFieldInstruction& instruction,
                                  Stack<std::string>* stack) {
  std::string result_name =
      DefinitionToVariable(instruction.GetValueDefinition());

  std::string bit_field_struct = stack->Pop();
  stack->Push(result_name);

  const Type* struct_type = instruction.bit_field_struct_type;

  decls() << "  " << instruction.bit_field.name_and_type.type->GetRuntimeType()
          << " " << result_name << "{}; USE(" << result_name << ");\n";

  std::optional<const Type*> smi_tagged_type =
      Type::MatchUnaryGeneric(struct_type, TypeOracle::GetSmiTaggedGeneric());
  if (smi_tagged_type) {
    // Get the untagged value and its type.
    if (is_cc_debug_) {
      bit_field_struct = "Internals::SmiValue(" + bit_field_struct + ")";
    } else {
      bit_field_struct = bit_field_struct + ".value()";
    }
    struct_type = *smi_tagged_type;
  }

  out() << "  " << result_name << " = CastToUnderlyingTypeIfEnum("
        << GetBitFieldSpecialization(struct_type, instruction.bit_field)
        << "::decode(" << bit_field_struct << "));\n";
}

void CCGenerator::EmitInstruction(const StoreBitFieldInstruction& instruction,
                                  Stack<std::string>* stack) {
  ReportError("Not supported in C++ output: StoreBitField");
}

namespace {

void CollectAllFields(const VisitResult& result,
                      const Stack<std::string>& values,
                      std::vector<std::string>& all_fields) {
  if (!result.IsOnStack()) {
    all_fields.push_back(result.constexpr_value());
  } else if (auto struct_type = result.type()->StructSupertype()) {
    for (const Field& field : (*struct_type)->fields()) {
      CollectAllFields(ProjectStructField(result, field.name_and_type.name),
                       values, all_fields);
    }
  } else {
    DCHECK_EQ(1, result.stack_range().Size());
    all_fields.push_back(values.Peek(result.stack_range().begin()));
  }
}

}  // namespace

// static
void CCGenerator::EmitCCValue(VisitResult result,
                              const Stack<std::string>& values,
                              std::ostream& out) {
  std::vector<std::string> all_fields;
  CollectAllFields(result, values, all_fields);
  if (all_fields.size() == 1) {
    out << all_fields[0];
  } else {
    out << "std::make_tuple(";
    PrintCommaSeparatedList(out, all_fields);
    out << ")";
  }
}

}  // namespace v8::internal::torque

"""

```