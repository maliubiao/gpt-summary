Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/regexp/regexp-compiler.cc`. I need to analyze the code and extract its key responsibilities within the V8 regular expression engine.

Here's a breakdown of the code's purpose:

1. **RegExp Compilation Process:** The comments clearly outline the three-step process of Irregexp compilation: parsing (handled elsewhere), creating a node network, and generating bytecode or native code. This file seems primarily focused on the code generation phase.

2. **RegExpNode Structure:**  The code defines different types of `RegExpNode` (Choice, Action, Matching, End). These represent states in the regular expression execution.

3. **Code Generation Strategies:** The comments detail how different node types are translated into executable code, including handling backtracking and state management. It also mentions optimizations like 1-character lookahead (not yet implemented), reduced backtracking for simple loops, and execution state virtualization.

4. **Execution State Virtualization (Trace):**  The `Trace` class is central to this file. It manages a virtual execution state, allowing for deferred actions and optimized code generation. The comments explain how `Trace` postpones expensive operations and allows for specialized code versions.

5. **Deferred Actions:** The `Trace` class uses `DeferredAction` to store state modifications. This is a key aspect of the virtualization strategy.

6. **Case-Insensitive Matching:** The `GetCaseIndependentLetters` function suggests functionality for handling case-insensitive matching, potentially involving Unicode support via ICU (if enabled).

7. **Node Emission:**  The `Emit` methods for various `RegExpNode` types define how these nodes are translated into macro assembler instructions.

Based on this, I can formulate the summary and address the user's specific requirements.
这是 v8 JavaScript 引擎中用于将正则表达式抽象语法树（AST）编译成可执行代码的关键部分。它属于 Irregexp 引擎，是 V8 中主要的正则表达式引擎。

**功能归纳:**

`v8/src/regexp/regexp-compiler.cc` 的主要功能是将正则表达式的内部表示形式（由解析器生成的抽象语法树）转换为实际可以执行的代码。这个过程包括：

1. **构建节点网络:** 将 AST 转换为一个由 `RegExpNode` 子类组成的网络。这些节点代表正则表达式执行过程中的不同状态，例如选择、动作、匹配和结束。
2. **代码生成:**  根据节点网络生成字节码或机器码。代码生成过程会维护执行状态，包括捕获寄存器、其他寄存器、当前位置和回溯信息栈。
3. **状态管理:** 使用 `Trace` 类来虚拟化执行状态，延迟某些操作，并允许为节点生成多次代码以实现优化。`Trace` 记录了位置偏移、回溯位置和寄存器变化。
4. **回溯处理:**  实现正则表达式的回溯机制，当匹配失败时，可以尝试其他的匹配路径。
5. **优化:**  实现多种优化技术，例如：
    * 简单的贪婪循环减少回溯信息存储。
    * 执行状态虚拟化。
6. **处理不同类型的节点:**  针对不同类型的 `RegExpNode`（如 ChoiceNode, ActionNode, MatchingNode, EndNode）生成相应的代码。
7. **处理捕获:**  管理捕获组的寄存器分配和状态更新。
8. **支持 Unicode 和国际化:**  包含对 Unicode 字符和大小写不敏感匹配的支持（通过 ICU 库，如果启用）。

**关于 .tq 结尾:**

如果 `v8/src/regexp/regexp-compiler.cc` 以 `.tq` 结尾，那么它将是使用 **Torque** 编写的 V8 源代码。 Torque 是一种 V8 内部使用的领域特定语言，用于生成高效的 C++ 代码。  提供的代码片段是 `.cc` 文件，表明它是用 C++ 编写的。

**与 JavaScript 功能的关系 (示例):**

`v8/src/regexp/regexp-compiler.cc` 的工作直接关系到 JavaScript 中 `RegExp` 对象的使用。每当你创建一个 `RegExp` 对象或在一个字符串上调用 `match`, `replace`, `search`, 或 `split` 方法并传入正则表达式时，V8 都会使用这个编译器来将你的正则表达式转换为可执行的引擎代码。

**JavaScript 示例:**

```javascript
const regex = /ab*c/g;
const str = 'abbc abc ac';
const matches = str.match(regex);
console.log(matches); // 输出: [ 'abbc', 'abc' ]
```

在这个例子中，当你创建 `regex` 对象时，V8 内部会调用 `regexp-compiler.cc` 中的代码来编译 `/ab*c/g` 这个正则表达式。然后，当你调用 `str.match(regex)` 时，V8 会执行由编译器生成的代码来查找匹配项。

**代码逻辑推理 (假设输入与输出):**

由于代码涉及复杂的编译过程，直接给出明确的 "假设输入与输出" 可能比较困难。但是，我们可以考虑一个简化的场景。

**假设输入:**  一个简单的正则表达式节点，表示匹配字符 'a' 的操作。

**处理过程:** `RegExpCompiler` 中的相关逻辑（可能是 `MatchingNode` 的 `Emit` 方法）会生成代码，指示正则表达式引擎检查当前输入位置的字符是否为 'a'。

**可能的输出 (伪代码，表示生成的指令):**

```
// 假设当前位置寄存器为 R1，匹配成功跳转标签为 L1，匹配失败跳转标签为 L2
LoadCharacter(R1)  // 加载当前位置的字符到某个临时寄存器
CompareCharacter(临时寄存器, 'a') // 将加载的字符与 'a' 进行比较
JumpIfEqual(L1)    // 如果相等，跳转到 L1 (匹配成功)
Jump(L2)           // 如果不相等，跳转到 L2 (匹配失败)
L1:
  // ... 匹配成功的后续操作
L2:
  // ... 匹配失败的回溯操作
```

**用户常见的编程错误 (与正则表达式相关，编译器会处理):**

1. **语法错误:** 正则表达式字符串中存在语法错误，例如未闭合的括号、无效的量词等。编译器在解析阶段会检测到这些错误并抛出 `SyntaxError`。

   ```javascript
   try {
     const regex = /ab[c/; // 缺少闭合括号
   } catch (e) {
     console.error(e); // 输出 SyntaxError
   }
   ```

2. **回溯失控 (Catastrophic Backtracking):**  编写的正则表达式在某些输入下会导致大量的回溯，使得匹配过程非常缓慢甚至卡死。编译器本身可能不会直接阻止所有这类情况，但 V8 的正则表达式引擎有回溯限制来防止无限循环。

   ```javascript
   const regex = /(a+)+b/.compile(); // 容易导致回溯失控的模式
   const str = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaac';
   // str.match(regex); // 可能会非常慢
   ```

3. **逻辑错误:**  正则表达式的逻辑不符合预期，导致匹配到错误的结果或无法匹配到期望的结果。这通常不是编译器能直接检测到的错误，而是需要开发者仔细测试和调试。

   ```javascript
   const regex = /ca/;
   const str = 'abc';
   const matches = str.match(regex);
   console.log(matches); // 输出 null，因为字符串中没有 "ca"
   ```

**总结:**

`v8/src/regexp/regexp-compiler.cc` 是 V8 引擎中将正则表达式编译成可执行代码的核心组件。它负责构建节点网络、生成代码、管理执行状态、处理回溯和进行优化。它的功能直接影响着 JavaScript 中正则表达式的执行效率和正确性。

### 提示词
```
这是目录为v8/src/regexp/regexp-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/regexp-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/regexp/regexp-compiler.h"

#include <optional>

#include "src/base/safe_conversions.h"
#include "src/execution/isolate.h"
#include "src/objects/fixed-array-inl.h"
#include "src/regexp/regexp-macro-assembler-arch.h"
#include "src/strings/unicode-inl.h"
#include "src/zone/zone-list-inl.h"

#ifdef V8_INTL_SUPPORT
#include "src/regexp/special-case.h"
#include "unicode/locid.h"
#include "unicode/uniset.h"
#include "unicode/utypes.h"
#endif  // V8_INTL_SUPPORT

namespace v8::internal {

using namespace regexp_compiler_constants;  // NOLINT(build/namespaces)

// -------------------------------------------------------------------
// Implementation of the Irregexp regular expression engine.
//
// The Irregexp regular expression engine is intended to be a complete
// implementation of ECMAScript regular expressions.  It generates either
// bytecodes or native code.

//   The Irregexp regexp engine is structured in three steps.
//   1) The parser generates an abstract syntax tree.  See ast.cc.
//   2) From the AST a node network is created.  The nodes are all
//      subclasses of RegExpNode.  The nodes represent states when
//      executing a regular expression.  Several optimizations are
//      performed on the node network.
//   3) From the nodes we generate either byte codes or native code
//      that can actually execute the regular expression (perform
//      the search).  The code generation step is described in more
//      detail below.

// Code generation.
//
//   The nodes are divided into four main categories.
//   * Choice nodes
//        These represent places where the regular expression can
//        match in more than one way.  For example on entry to an
//        alternation (foo|bar) or a repetition (*, +, ? or {}).
//   * Action nodes
//        These represent places where some action should be
//        performed.  Examples include recording the current position
//        in the input string to a register (in order to implement
//        captures) or other actions on register for example in order
//        to implement the counters needed for {} repetitions.
//   * Matching nodes
//        These attempt to match some element part of the input string.
//        Examples of elements include character classes, plain strings
//        or back references.
//   * End nodes
//        These are used to implement the actions required on finding
//        a successful match or failing to find a match.
//
//   The code generated (whether as byte codes or native code) maintains
//   some state as it runs.  This consists of the following elements:
//
//   * The capture registers.  Used for string captures.
//   * Other registers.  Used for counters etc.
//   * The current position.
//   * The stack of backtracking information.  Used when a matching node
//     fails to find a match and needs to try an alternative.
//
// Conceptual regular expression execution model:
//
//   There is a simple conceptual model of regular expression execution
//   which will be presented first.  The actual code generated is a more
//   efficient simulation of the simple conceptual model:
//
//   * Choice nodes are implemented as follows:
//     For each choice except the last {
//       push current position
//       push backtrack code location
//       <generate code to test for choice>
//       backtrack code location:
//       pop current position
//     }
//     <generate code to test for last choice>
//
//   * Actions nodes are generated as follows
//     <push affected registers on backtrack stack>
//     <generate code to perform action>
//     push backtrack code location
//     <generate code to test for following nodes>
//     backtrack code location:
//     <pop affected registers to restore their state>
//     <pop backtrack location from stack and go to it>
//
//   * Matching nodes are generated as follows:
//     if input string matches at current position
//       update current position
//       <generate code to test for following nodes>
//     else
//       <pop backtrack location from stack and go to it>
//
//   Thus it can be seen that the current position is saved and restored
//   by the choice nodes, whereas the registers are saved and restored by
//   by the action nodes that manipulate them.
//
//   The other interesting aspect of this model is that nodes are generated
//   at the point where they are needed by a recursive call to Emit().  If
//   the node has already been code generated then the Emit() call will
//   generate a jump to the previously generated code instead.  In order to
//   limit recursion it is possible for the Emit() function to put the node
//   on a work list for later generation and instead generate a jump.  The
//   destination of the jump is resolved later when the code is generated.
//
// Actual regular expression code generation.
//
//   Code generation is actually more complicated than the above.  In order to
//   improve the efficiency of the generated code some optimizations are
//   performed
//
//   * Choice nodes have 1-character lookahead.
//     A choice node looks at the following character and eliminates some of
//     the choices immediately based on that character.  This is not yet
//     implemented.
//   * Simple greedy loops store reduced backtracking information.
//     A quantifier like /.*foo/m will greedily match the whole input.  It will
//     then need to backtrack to a point where it can match "foo".  The naive
//     implementation of this would push each character position onto the
//     backtracking stack, then pop them off one by one.  This would use space
//     proportional to the length of the input string.  However since the "."
//     can only match in one way and always has a constant length (in this case
//     of 1) it suffices to store the current position on the top of the stack
//     once.  Matching now becomes merely incrementing the current position and
//     backtracking becomes decrementing the current position and checking the
//     result against the stored current position.  This is faster and saves
//     space.
//   * The current state is virtualized.
//     This is used to defer expensive operations until it is clear that they
//     are needed and to generate code for a node more than once, allowing
//     specialized an efficient versions of the code to be created. This is
//     explained in the section below.
//
// Execution state virtualization.
//
//   Instead of emitting code, nodes that manipulate the state can record their
//   manipulation in an object called the Trace.  The Trace object can record a
//   current position offset, an optional backtrack code location on the top of
//   the virtualized backtrack stack and some register changes.  When a node is
//   to be emitted it can flush the Trace or update it.  Flushing the Trace
//   will emit code to bring the actual state into line with the virtual state.
//   Avoiding flushing the state can postpone some work (e.g. updates of capture
//   registers).  Postponing work can save time when executing the regular
//   expression since it may be found that the work never has to be done as a
//   failure to match can occur.  In addition it is much faster to jump to a
//   known backtrack code location than it is to pop an unknown backtrack
//   location from the stack and jump there.
//
//   The virtual state found in the Trace affects code generation.  For example
//   the virtual state contains the difference between the actual current
//   position and the virtual current position, and matching code needs to use
//   this offset to attempt a match in the correct location of the input
//   string.  Therefore code generated for a non-trivial trace is specialized
//   to that trace.  The code generator therefore has the ability to generate
//   code for each node several times.  In order to limit the size of the
//   generated code there is an arbitrary limit on how many specialized sets of
//   code may be generated for a given node.  If the limit is reached, the
//   trace is flushed and a generic version of the code for a node is emitted.
//   This is subsequently used for that node.  The code emitted for non-generic
//   trace is not recorded in the node and so it cannot currently be reused in
//   the event that code generation is requested for an identical trace.

namespace {

constexpr base::uc32 MaxCodeUnit(const bool one_byte) {
  static_assert(String::kMaxOneByteCharCodeU <=
                std::numeric_limits<uint16_t>::max());
  static_assert(String::kMaxUtf16CodeUnitU <=
                std::numeric_limits<uint16_t>::max());
  return one_byte ? String::kMaxOneByteCharCodeU : String::kMaxUtf16CodeUnitU;
}

constexpr uint32_t CharMask(const bool one_byte) {
  static_assert(base::bits::IsPowerOfTwo(String::kMaxOneByteCharCodeU + 1));
  static_assert(base::bits::IsPowerOfTwo(String::kMaxUtf16CodeUnitU + 1));
  return MaxCodeUnit(one_byte);
}

}  // namespace

void RegExpTree::AppendToText(RegExpText* text, Zone* zone) { UNREACHABLE(); }

void RegExpAtom::AppendToText(RegExpText* text, Zone* zone) {
  text->AddElement(TextElement::Atom(this), zone);
}

void RegExpClassRanges::AppendToText(RegExpText* text, Zone* zone) {
  text->AddElement(TextElement::ClassRanges(this), zone);
}

void RegExpText::AppendToText(RegExpText* text, Zone* zone) {
  for (int i = 0; i < elements()->length(); i++)
    text->AddElement(elements()->at(i), zone);
}

TextElement TextElement::Atom(RegExpAtom* atom) {
  return TextElement(ATOM, atom);
}

TextElement TextElement::ClassRanges(RegExpClassRanges* class_ranges) {
  return TextElement(CLASS_RANGES, class_ranges);
}

int TextElement::length() const {
  switch (text_type()) {
    case ATOM:
      return atom()->length();

    case CLASS_RANGES:
      return 1;
  }
  UNREACHABLE();
}

class RecursionCheck {
 public:
  explicit RecursionCheck(RegExpCompiler* compiler) : compiler_(compiler) {
    compiler->IncrementRecursionDepth();
  }
  ~RecursionCheck() { compiler_->DecrementRecursionDepth(); }

 private:
  RegExpCompiler* compiler_;
};

// Attempts to compile the regexp using an Irregexp code generator.  Returns
// a fixed array or a null handle depending on whether it succeeded.
RegExpCompiler::RegExpCompiler(Isolate* isolate, Zone* zone, int capture_count,
                               RegExpFlags flags, bool one_byte)
    : next_register_(JSRegExp::RegistersForCaptureCount(capture_count)),
      unicode_lookaround_stack_register_(kNoRegister),
      unicode_lookaround_position_register_(kNoRegister),
      work_list_(nullptr),
      recursion_depth_(0),
      flags_(flags),
      one_byte_(one_byte),
      reg_exp_too_big_(false),
      limiting_recursion_(false),
      optimize_(v8_flags.regexp_optimization),
      read_backward_(false),
      current_expansion_factor_(1),
      frequency_collator_(),
      isolate_(isolate),
      zone_(zone) {
  accept_ = zone->New<EndNode>(EndNode::ACCEPT, zone);
  DCHECK_GE(RegExpMacroAssembler::kMaxRegister, next_register_ - 1);
}

RegExpCompiler::CompilationResult RegExpCompiler::Assemble(
    Isolate* isolate, RegExpMacroAssembler* macro_assembler, RegExpNode* start,
    int capture_count, Handle<String> pattern) {
  macro_assembler_ = macro_assembler;

  ZoneVector<RegExpNode*> work_list(zone());
  work_list_ = &work_list;
  Label fail;
  macro_assembler_->PushBacktrack(&fail);
  Trace new_trace;
  start->Emit(this, &new_trace);
  macro_assembler_->BindJumpTarget(&fail);
  macro_assembler_->Fail();
  while (!work_list.empty()) {
    RegExpNode* node = work_list.back();
    work_list.pop_back();
    node->set_on_work_list(false);
    if (!node->label()->is_bound()) node->Emit(this, &new_trace);
  }
  if (reg_exp_too_big_) {
    if (v8_flags.correctness_fuzzer_suppressions) {
      FATAL("Aborting on excess zone allocation");
    }
    macro_assembler_->AbortedCodeGeneration();
    return CompilationResult::RegExpTooBig();
  }

  Handle<HeapObject> code = macro_assembler_->GetCode(pattern, flags_);
  isolate->IncreaseTotalRegexpCodeGenerated(code);
  work_list_ = nullptr;

  return {code, next_register_};
}

bool Trace::DeferredAction::Mentions(int that) {
  if (action_type() == ActionNode::CLEAR_CAPTURES) {
    Interval range = static_cast<DeferredClearCaptures*>(this)->range();
    return range.Contains(that);
  } else {
    return reg() == that;
  }
}

bool Trace::mentions_reg(int reg) {
  for (DeferredAction* action = actions_; action != nullptr;
       action = action->next()) {
    if (action->Mentions(reg)) return true;
  }
  return false;
}

bool Trace::GetStoredPosition(int reg, int* cp_offset) {
  DCHECK_EQ(0, *cp_offset);
  for (DeferredAction* action = actions_; action != nullptr;
       action = action->next()) {
    if (action->Mentions(reg)) {
      if (action->action_type() == ActionNode::STORE_POSITION) {
        *cp_offset = static_cast<DeferredCapture*>(action)->cp_offset();
        return true;
      } else {
        return false;
      }
    }
  }
  return false;
}

// A (dynamically-sized) set of unsigned integers that behaves especially well
// on small integers (< kFirstLimit). May do zone-allocation.
class DynamicBitSet : public ZoneObject {
 public:
  V8_EXPORT_PRIVATE bool Get(unsigned value) const {
    if (value < kFirstLimit) {
      return (first_ & (1 << value)) != 0;
    } else if (remaining_ == nullptr) {
      return false;
    } else {
      return remaining_->Contains(value);
    }
  }

  // Destructively set a value in this set.
  void Set(unsigned value, Zone* zone) {
    if (value < kFirstLimit) {
      first_ |= (1 << value);
    } else {
      if (remaining_ == nullptr)
        remaining_ = zone->New<ZoneList<unsigned>>(1, zone);
      if (remaining_->is_empty() || !remaining_->Contains(value))
        remaining_->Add(value, zone);
    }
  }

 private:
  static constexpr unsigned kFirstLimit = 32;

  uint32_t first_ = 0;
  ZoneList<unsigned>* remaining_ = nullptr;
};

int Trace::FindAffectedRegisters(DynamicBitSet* affected_registers,
                                 Zone* zone) {
  int max_register = RegExpCompiler::kNoRegister;
  for (DeferredAction* action = actions_; action != nullptr;
       action = action->next()) {
    if (action->action_type() == ActionNode::CLEAR_CAPTURES) {
      Interval range = static_cast<DeferredClearCaptures*>(action)->range();
      for (int i = range.from(); i <= range.to(); i++)
        affected_registers->Set(i, zone);
      if (range.to() > max_register) max_register = range.to();
    } else {
      affected_registers->Set(action->reg(), zone);
      if (action->reg() > max_register) max_register = action->reg();
    }
  }
  return max_register;
}

void Trace::RestoreAffectedRegisters(RegExpMacroAssembler* assembler,
                                     int max_register,
                                     const DynamicBitSet& registers_to_pop,
                                     const DynamicBitSet& registers_to_clear) {
  for (int reg = max_register; reg >= 0; reg--) {
    if (registers_to_pop.Get(reg)) {
      assembler->PopRegister(reg);
    } else if (registers_to_clear.Get(reg)) {
      int clear_to = reg;
      while (reg > 0 && registers_to_clear.Get(reg - 1)) {
        reg--;
      }
      assembler->ClearRegisters(reg, clear_to);
    }
  }
}

void Trace::PerformDeferredActions(RegExpMacroAssembler* assembler,
                                   int max_register,
                                   const DynamicBitSet& affected_registers,
                                   DynamicBitSet* registers_to_pop,
                                   DynamicBitSet* registers_to_clear,
                                   Zone* zone) {
  // Count pushes performed to force a stack limit check occasionally.
  int pushes = 0;

  for (int reg = 0; reg <= max_register; reg++) {
    if (!affected_registers.Get(reg)) continue;

    // The chronologically first deferred action in the trace
    // is used to infer the action needed to restore a register
    // to its previous state (or not, if it's safe to ignore it).
    enum DeferredActionUndoType { IGNORE, RESTORE, CLEAR };
    DeferredActionUndoType undo_action = IGNORE;

    int value = 0;
    bool absolute = false;
    bool clear = false;
    static const int kNoStore = kMinInt;
    int store_position = kNoStore;
    // This is a little tricky because we are scanning the actions in reverse
    // historical order (newest first).
    for (DeferredAction* action = actions_; action != nullptr;
         action = action->next()) {
      if (action->Mentions(reg)) {
        switch (action->action_type()) {
          case ActionNode::SET_REGISTER_FOR_LOOP: {
            Trace::DeferredSetRegisterForLoop* psr =
                static_cast<Trace::DeferredSetRegisterForLoop*>(action);
            if (!absolute) {
              value += psr->value();
              absolute = true;
            }
            // SET_REGISTER_FOR_LOOP is only used for newly introduced loop
            // counters. They can have a significant previous value if they
            // occur in a loop. TODO(lrn): Propagate this information, so
            // we can set undo_action to IGNORE if we know there is no value to
            // restore.
            undo_action = RESTORE;
            DCHECK_EQ(store_position, kNoStore);
            DCHECK(!clear);
            break;
          }
          case ActionNode::INCREMENT_REGISTER:
            if (!absolute) {
              value++;
            }
            DCHECK_EQ(store_position, kNoStore);
            DCHECK(!clear);
            undo_action = RESTORE;
            break;
          case ActionNode::STORE_POSITION: {
            Trace::DeferredCapture* pc =
                static_cast<Trace::DeferredCapture*>(action);
            if (!clear && store_position == kNoStore) {
              store_position = pc->cp_offset();
            }

            // For captures we know that stores and clears alternate.
            // Other register, are never cleared, and if the occur
            // inside a loop, they might be assigned more than once.
            if (reg <= 1) {
              // Registers zero and one, aka "capture zero", is
              // always set correctly if we succeed. There is no
              // need to undo a setting on backtrack, because we
              // will set it again or fail.
              undo_action = IGNORE;
            } else {
              undo_action = pc->is_capture() ? CLEAR : RESTORE;
            }
            DCHECK(!absolute);
            DCHECK_EQ(value, 0);
            break;
          }
          case ActionNode::CLEAR_CAPTURES: {
            // Since we're scanning in reverse order, if we've already
            // set the position we have to ignore historically earlier
            // clearing operations.
            if (store_position == kNoStore) {
              clear = true;
            }
            undo_action = RESTORE;
            DCHECK(!absolute);
            DCHECK_EQ(value, 0);
            break;
          }
          default:
            UNREACHABLE();
        }
      }
    }
    // Prepare for the undo-action (e.g., push if it's going to be popped).
    if (undo_action == RESTORE) {
      pushes++;
      RegExpMacroAssembler::StackCheckFlag stack_check =
          RegExpMacroAssembler::kNoStackLimitCheck;
      DCHECK_GT(assembler->stack_limit_slack_slot_count(), 0);
      if (pushes == assembler->stack_limit_slack_slot_count()) {
        stack_check = RegExpMacroAssembler::kCheckStackLimit;
        pushes = 0;
      }

      assembler->PushRegister(reg, stack_check);
      registers_to_pop->Set(reg, zone);
    } else if (undo_action == CLEAR) {
      registers_to_clear->Set(reg, zone);
    }
    // Perform the chronologically last action (or accumulated increment)
    // for the register.
    if (store_position != kNoStore) {
      assembler->WriteCurrentPositionToRegister(reg, store_position);
    } else if (clear) {
      assembler->ClearRegisters(reg, reg);
    } else if (absolute) {
      assembler->SetRegister(reg, value);
    } else if (value != 0) {
      assembler->AdvanceRegister(reg, value);
    }
  }
}

// This is called as we come into a loop choice node and some other tricky
// nodes.  It normalizes the state of the code generator to ensure we can
// generate generic code.
void Trace::Flush(RegExpCompiler* compiler, RegExpNode* successor) {
  RegExpMacroAssembler* assembler = compiler->macro_assembler();

  DCHECK(!is_trivial());

  if (actions_ == nullptr && backtrack() == nullptr) {
    // Here we just have some deferred cp advances to fix and we are back to
    // a normal situation.  We may also have to forget some information gained
    // through a quick check that was already performed.
    if (cp_offset_ != 0) assembler->AdvanceCurrentPosition(cp_offset_);
    // Create a new trivial state and generate the node with that.
    Trace new_state;
    successor->Emit(compiler, &new_state);
    return;
  }

  // Generate deferred actions here along with code to undo them again.
  DynamicBitSet affected_registers;

  if (backtrack() != nullptr) {
    // Here we have a concrete backtrack location.  These are set up by choice
    // nodes and so they indicate that we have a deferred save of the current
    // position which we may need to emit here.
    assembler->PushCurrentPosition();
  }

  int max_register =
      FindAffectedRegisters(&affected_registers, compiler->zone());
  DynamicBitSet registers_to_pop;
  DynamicBitSet registers_to_clear;
  PerformDeferredActions(assembler, max_register, affected_registers,
                         &registers_to_pop, &registers_to_clear,
                         compiler->zone());
  if (cp_offset_ != 0) {
    assembler->AdvanceCurrentPosition(cp_offset_);
  }

  // Create a new trivial state and generate the node with that.
  Label undo;
  assembler->PushBacktrack(&undo);
  if (successor->KeepRecursing(compiler)) {
    Trace new_state;
    successor->Emit(compiler, &new_state);
  } else {
    compiler->AddWork(successor);
    assembler->GoTo(successor->label());
  }

  // On backtrack we need to restore state.
  assembler->BindJumpTarget(&undo);
  RestoreAffectedRegisters(assembler, max_register, registers_to_pop,
                           registers_to_clear);
  if (backtrack() == nullptr) {
    assembler->Backtrack();
  } else {
    assembler->PopCurrentPosition();
    assembler->GoTo(backtrack());
  }
}

void NegativeSubmatchSuccess::Emit(RegExpCompiler* compiler, Trace* trace) {
  RegExpMacroAssembler* assembler = compiler->macro_assembler();

  // Omit flushing the trace. We discard the entire stack frame anyway.

  if (!label()->is_bound()) {
    // We are completely independent of the trace, since we ignore it,
    // so this code can be used as the generic version.
    assembler->Bind(label());
  }

  // Throw away everything on the backtrack stack since the start
  // of the negative submatch and restore the character position.
  assembler->ReadCurrentPositionFromRegister(current_position_register_);
  assembler->ReadStackPointerFromRegister(stack_pointer_register_);
  if (clear_capture_count_ > 0) {
    // Clear any captures that might have been performed during the success
    // of the body of the negative look-ahead.
    int clear_capture_end = clear_capture_start_ + clear_capture_count_ - 1;
    assembler->ClearRegisters(clear_capture_start_, clear_capture_end);
  }
  // Now that we have unwound the stack we find at the top of the stack the
  // backtrack that the BeginNegativeSubmatch node got.
  assembler->Backtrack();
}

void EndNode::Emit(RegExpCompiler* compiler, Trace* trace) {
  if (!trace->is_trivial()) {
    trace->Flush(compiler, this);
    return;
  }
  RegExpMacroAssembler* assembler = compiler->macro_assembler();
  if (!label()->is_bound()) {
    assembler->Bind(label());
  }
  switch (action_) {
    case ACCEPT:
      assembler->Succeed();
      return;
    case BACKTRACK:
      assembler->GoTo(trace->backtrack());
      return;
    case NEGATIVE_SUBMATCH_SUCCESS:
      // This case is handled in a different virtual method.
      UNREACHABLE();
  }
  UNIMPLEMENTED();
}

void GuardedAlternative::AddGuard(Guard* guard, Zone* zone) {
  if (guards_ == nullptr) guards_ = zone->New<ZoneList<Guard*>>(1, zone);
  guards_->Add(guard, zone);
}

ActionNode* ActionNode::SetRegisterForLoop(int reg, int val,
                                           RegExpNode* on_success) {
  ActionNode* result =
      on_success->zone()->New<ActionNode>(SET_REGISTER_FOR_LOOP, on_success);
  result->data_.u_store_register.reg = reg;
  result->data_.u_store_register.value = val;
  return result;
}

ActionNode* ActionNode::IncrementRegister(int reg, RegExpNode* on_success) {
  ActionNode* result =
      on_success->zone()->New<ActionNode>(INCREMENT_REGISTER, on_success);
  result->data_.u_increment_register.reg = reg;
  return result;
}

ActionNode* ActionNode::StorePosition(int reg, bool is_capture,
                                      RegExpNode* on_success) {
  ActionNode* result =
      on_success->zone()->New<ActionNode>(STORE_POSITION, on_success);
  result->data_.u_position_register.reg = reg;
  result->data_.u_position_register.is_capture = is_capture;
  return result;
}

ActionNode* ActionNode::ClearCaptures(Interval range, RegExpNode* on_success) {
  ActionNode* result =
      on_success->zone()->New<ActionNode>(CLEAR_CAPTURES, on_success);
  result->data_.u_clear_captures.range_from = range.from();
  result->data_.u_clear_captures.range_to = range.to();
  return result;
}

ActionNode* ActionNode::BeginPositiveSubmatch(int stack_reg, int position_reg,
                                              RegExpNode* body,
                                              ActionNode* success_node) {
  ActionNode* result =
      body->zone()->New<ActionNode>(BEGIN_POSITIVE_SUBMATCH, body);
  result->data_.u_submatch.stack_pointer_register = stack_reg;
  result->data_.u_submatch.current_position_register = position_reg;
  result->data_.u_submatch.success_node = success_node;
  return result;
}

ActionNode* ActionNode::BeginNegativeSubmatch(int stack_reg, int position_reg,
                                              RegExpNode* on_success) {
  ActionNode* result =
      on_success->zone()->New<ActionNode>(BEGIN_NEGATIVE_SUBMATCH, on_success);
  result->data_.u_submatch.stack_pointer_register = stack_reg;
  result->data_.u_submatch.current_position_register = position_reg;
  return result;
}

ActionNode* ActionNode::PositiveSubmatchSuccess(int stack_reg, int position_reg,
                                                int clear_register_count,
                                                int clear_register_from,
                                                RegExpNode* on_success) {
  ActionNode* result = on_success->zone()->New<ActionNode>(
      POSITIVE_SUBMATCH_SUCCESS, on_success);
  result->data_.u_submatch.stack_pointer_register = stack_reg;
  result->data_.u_submatch.current_position_register = position_reg;
  result->data_.u_submatch.clear_register_count = clear_register_count;
  result->data_.u_submatch.clear_register_from = clear_register_from;
  return result;
}

ActionNode* ActionNode::EmptyMatchCheck(int start_register,
                                        int repetition_register,
                                        int repetition_limit,
                                        RegExpNode* on_success) {
  ActionNode* result =
      on_success->zone()->New<ActionNode>(EMPTY_MATCH_CHECK, on_success);
  result->data_.u_empty_match_check.start_register = start_register;
  result->data_.u_empty_match_check.repetition_register = repetition_register;
  result->data_.u_empty_match_check.repetition_limit = repetition_limit;
  return result;
}

ActionNode* ActionNode::ModifyFlags(RegExpFlags flags, RegExpNode* on_success) {
  ActionNode* result =
      on_success->zone()->New<ActionNode>(MODIFY_FLAGS, on_success);
  result->data_.u_modify_flags.flags = flags;
  return result;
}

#define DEFINE_ACCEPT(Type) \
  void Type##Node::Accept(NodeVisitor* visitor) { visitor->Visit##Type(this); }
FOR_EACH_NODE_TYPE(DEFINE_ACCEPT)
#undef DEFINE_ACCEPT

// -------------------------------------------------------------------
// Emit code.

void ChoiceNode::GenerateGuard(RegExpMacroAssembler* macro_assembler,
                               Guard* guard, Trace* trace) {
  switch (guard->op()) {
    case Guard::LT:
      DCHECK(!trace->mentions_reg(guard->reg()));
      macro_assembler->IfRegisterGE(guard->reg(), guard->value(),
                                    trace->backtrack());
      break;
    case Guard::GEQ:
      DCHECK(!trace->mentions_reg(guard->reg()));
      macro_assembler->IfRegisterLT(guard->reg(), guard->value(),
                                    trace->backtrack());
      break;
  }
}

namespace {

#ifdef DEBUG
bool ContainsOnlyUtf16CodeUnits(unibrow::uchar* chars, int length) {
  static_assert(sizeof(unibrow::uchar) == 4);
  for (int i = 0; i < length; i++) {
    if (chars[i] > String::kMaxUtf16CodeUnit) return false;
  }
  return true;
}
#endif  // DEBUG

// Returns the number of characters in the equivalence class, omitting those
// that cannot occur in the source string because it is Latin1.  This is called
// both for unicode modes /ui and /vi, and also for legacy case independent
// mode /i.  In the case of Unicode modes we handled surrogate pair expansions
// earlier so at this point it's all about single-code-unit expansions.
int GetCaseIndependentLetters(Isolate* isolate, base::uc16 character,
                              RegExpCompiler* compiler, unibrow::uchar* letters,
                              int letter_length) {
  bool one_byte_subject = compiler->one_byte();
  bool unicode = IsEitherUnicode(compiler->flags());
  static const base::uc16 kMaxAscii = 0x7f;
  if (!unicode && character <= kMaxAscii) {
    // Fast case for common characters.
    base::uc16 upper = character & ~0x20;
    if ('A' <= upper && upper <= 'Z') {
      letters[0] = upper;
      letters[1] = upper | 0x20;
      return 2;
    }
    letters[0] = character;
    return 1;
  }
#ifdef V8_INTL_SUPPORT

  if (!unicode && RegExpCaseFolding::IgnoreSet().contains(character)) {
    if (one_byte_subject && character > String::kMaxOneByteCharCode) {
      // This function promises not to return a character that is impossible
      // for the subject encoding.
      return 0;
    }
    letters[0] = character;
    DCHECK(ContainsOnlyUtf16CodeUnits(letters, 1));
    return 1;
  }
  bool in_special_add_set =
      RegExpCaseFolding::SpecialAddSet().contains(character);

  icu::UnicodeSet set;
  set.add(character);
  set = set.closeOver(unicode ? USET_SIMPLE_CASE_INSENSITIVE
                              : USET_CASE_INSENSITIVE);

  UChar32 canon = 0;
  if (in_special_add_set && !unicode) {
    canon = RegExpCaseFolding::Canonicalize(character);
  }

  int32_t range_count = set.getRangeCount();
  int items = 0;
  for (int32_t i = 0; i < range_count; i++) {
    UChar32 start = set.getRangeStart(i);
    UChar32 end = set.getRangeEnd(i);
    CHECK(end - start + items <= letter_length);
    for (UChar32 cu = start; cu <= end; cu++) {
      if (one_byte_subject && cu > String::kMaxOneByteCharCode) continue;
      if (!unicode && in_special_add_set &&
          RegExpCaseFolding::Canonicalize(cu) != canon) {
        continue;
      }
      letters[items++] = static_cast<unibrow::uchar>(cu);
    }
  }
  DCHECK(ContainsOnlyUtf16CodeUnits(letters, items));
  return items;
#else
  int length =
      isolate->jsregexp_uncanonicalize()->get(character, '\0', letters);
  // Unibrow returns 0 or 1 for characters where case independence is
  // trivial.
  if (length == 0) {
    letters[0] = character;
    length = 1;
  }

  if (one_byte_subject) {
    int new_length = 0;
    for (int i = 0; i < length; i++) {
      if (letters[i] <= String::kMaxOneByteCharCode) {
        letters[new_length++] = letters[i];
      }
    }
    length = new_length;
  }

  DCHECK(ContainsOnlyUtf16CodeUnits(letters, length));
  return length;
#endif  // V8_INTL_SUPPORT
}

inline bool EmitSimpleCharacter(Isolate* isolate, RegExpCompiler* compiler,
                                base::uc16 c, Label* on_failure, int cp_offset,
                                bool check, bool preloaded) {
  RegExpMacroAssembler* assembler = compiler->macro_assembler();
  bool bound_checked = false;
  if (!preloaded) {
    assembler->LoadCurrentCharacter(cp_offset,
```