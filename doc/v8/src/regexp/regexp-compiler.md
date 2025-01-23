Response: The user wants me to summarize the functionality of the C++ source code file `v8/src/regexp/regexp-compiler.cc`.
The code seems to be part of the V8 JavaScript engine and deals with compiling regular expressions.
I need to extract the key functionalities described in the comments.
If the code relates to JavaScript, I need to provide a JavaScript example illustrating the connection.

Here's a breakdown of the functionalities mentioned:
1. **Parsing**: Transforms regular expression syntax into an Abstract Syntax Tree (AST).
2. **Node Network Creation**: Converts the AST into a network of `RegExpNode` objects, representing execution states.
3. **Optimization**: Performs optimizations on the node network.
4. **Code Generation**: Generates either bytecode or native machine code from the node network.
5. **Execution Model**: Describes the conceptual execution flow of regular expressions, involving choice nodes, action nodes, matching nodes, and end nodes.
6. **State Management**: Explains the state maintained during execution, including capture registers, other registers, current position, and a backtracking stack.
7. **Optimization Techniques**:  Highlights optimizations like 1-character lookahead (not yet implemented), simple greedy loop optimization, and state virtualization.
8. **State Virtualization**: Describes the `Trace` object and how it delays state updates for efficiency.
9. **Case-Insensitive Matching**: Contains logic for handling case-insensitive matching, including Unicode support and integration with ICU (if enabled).
10. **Character Class Handling**:  Provides mechanisms for efficiently matching character classes.
11. **Boyer-Moore Optimization**:  Mentions Boyer-Moore algorithm for lookahead optimization.
12. **Quick Check Optimization**:  Introduces a quick check mechanism to rapidly rule out non-matching inputs.

The connection to JavaScript is evident since this code compiles JavaScript regular expressions.

**JavaScript Example:**

```javascript
const regex = /ab?c/i;
const text = "aBc";
const match = text.match(regex);
console.log(match); // Output: ['aBc', index: 0, input: 'aBc', groups: undefined]
```
This JavaScript code uses a regular expression `/ab?c/i` which will be processed and compiled by the C++ code in `regexp-compiler.cc`. The `i` flag signifies case-insensitivity, a feature handled by this C++ code.
这个C++源代码文件 `v8/src/regexp/regexp-compiler.cc` 的主要功能是**将正则表达式编译成可以执行的代码**。 这是 V8 JavaScript 引擎中负责处理正则表达式的核心组件。

更具体地说，它执行以下任务：

1. **将正则表达式的抽象语法树（AST）转换为节点网络**:  输入是正则表达式解析器生成的抽象语法树，输出是一个由 `RegExpNode` 子类构成的网络。这些节点代表了正则表达式执行过程中的各种状态。

2. **对节点网络进行优化**:  在生成最终代码之前，会对节点网络进行各种优化，以提高正则表达式的执行效率。 文档中提到了几种优化策略，例如：
    * **Choice节点的前瞻优化**:  根据下一个字符来排除某些选项（尚未实现）。
    * **简单贪婪循环的优化**:  减少回溯信息的存储。
    * **状态虚拟化**:  延迟执行某些操作，并允许多次生成代码以实现更高效的版本。

3. **生成字节码或本地机器码**:  根据节点网络，生成可以直接执行的字节码或本地机器码来完成正则表达式的匹配工作。

4. **管理正则表达式执行的状态**:  生成的代码在执行时会维护一些状态信息，包括：
    * 捕获寄存器（用于存储捕获的子字符串）
    * 其他寄存器（用于计数器等）
    * 当前匹配位置
    * 回溯信息栈

5. **实现正则表达式的执行模型**:  代码实现了正则表达式的匹配逻辑，包括如何处理：
    * **Choice节点**:  表示有多种匹配可能性的地方（例如 `|` 或 `*`, `+`, `?`, `{}`).
    * **Action节点**:  表示需要执行某些动作的地方（例如记录捕获组的位置，更新计数器等）。
    * **Matching节点**:  尝试匹配输入字符串中的特定元素（例如字符类，普通字符串，反向引用）。
    * **End节点**:  表示成功匹配或匹配失败时需要执行的操作。

6. **支持大小写不敏感匹配**:  代码中包含了处理大小写不敏感匹配的逻辑，并且在启用了国际化支持 (`V8_INTL_SUPPORT`) 的情况下，会利用 ICU 库来进行更复杂的 Unicode 大小写转换。

**与 JavaScript 功能的关系以及 JavaScript 例子：**

这个 `regexp-compiler.cc` 文件直接关系到 JavaScript 中正则表达式的功能。当你创建一个 JavaScript 正则表达式并使用它进行匹配时，V8 引擎会调用这里的代码来编译这个正则表达式。编译后的代码才能被 V8 的正则表达式引擎执行。

**JavaScript 例子：**

```javascript
const regex = /ab?c/i; // 创建一个正则表达式，/i 表示忽略大小写
const text = "ABc";
const match = text.match(regex);
console.log(match); // 输出: ['ABc']
```

**解释：**

* 当 JavaScript 引擎执行 `const regex = /ab?c/i;` 时，它会创建一个正则表达式对象。
* 当执行 `text.match(regex)` 时，V8 引擎会调用 `regexp-compiler.cc` 中的代码来编译正则表达式 `/ab?c/i`。
* 编译过程会根据正则表达式的结构和标志（例如 `i` 表示忽略大小写）生成相应的机器码或字节码。
* 生成的代码在执行时会按照 `regexp-compiler.cc` 中描述的执行模型进行匹配。
* 在这个例子中，由于使用了 `/i` 标志，`regexp-compiler.cc` 中的大小写不敏感匹配逻辑会被激活，使得正则表达式能够匹配到 "ABc"。

总结来说，`v8/src/regexp/regexp-compiler.cc` 是 V8 引擎中将 JavaScript 正则表达式转化为可执行代码的关键部分，它负责解析、优化和生成用于匹配的指令，并直接影响 JavaScript 正则表达式的性能和功能。

### 提示词
```
这是目录为v8/src/regexp/regexp-compiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```
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
    assembler->LoadCurrentCharacter(cp_offset, on_failure, check);
    bound_checked = true;
  }
  assembler->CheckNotCharacter(c, on_failure);
  return bound_checked;
}

// Only emits non-letters (things that don't have case).  Only used for case
// independent matches.
inline bool EmitAtomNonLetter(Isolate* isolate, RegExpCompiler* compiler,
                              base::uc16 c, Label* on_failure, int cp_offset,
                              bool check, bool preloaded) {
  RegExpMacroAssembler* macro_assembler = compiler->macro_assembler();
  bool one_byte = compiler->one_byte();
  unibrow::uchar chars[4];
  int length = GetCaseIndependentLetters(isolate, c, compiler, chars, 4);
  if (length < 1) {
    // This can't match.  Must be an one-byte subject and a non-one-byte
    // character.  We do not need to do anything since the one-byte pass
    // already handled this.
    CHECK(one_byte);
    return false;  // Bounds not checked.
  }
  bool checked = false;
  // We handle the length > 1 case in a later pass.
  if (length == 1) {
    // GetCaseIndependentLetters promises not to return characters that can't
    // match because of the subject encoding.  This case is already handled by
    // the one-byte pass.
    CHECK_IMPLIES(one_byte, chars[0] <= String::kMaxOneByteCharCodeU);
    if (!preloaded) {
      macro_assembler->LoadCurrentCharacter(cp_offset, on_failure, check);
      checked = check;
    }
    macro_assembler->CheckNotCharacter(chars[0], on_failure);
  }
  return checked;
}

bool ShortCutEmitCharacterPair(RegExpMacroAssembler* macro_assembler,
                               bool one_byte, base::uc16 c1, base::uc16 c2,
                               Label* on_failure) {
  const uint32_t char_mask = CharMask(one_byte);
  base::uc16 exor = c1 ^ c2;
  // Check whether exor has only one bit set.
  if (((exor - 1) & exor) == 0) {
    // If c1 and c2 differ only by one bit.
    // Ecma262UnCanonicalize always gives the highest number last.
    DCHECK(c2 > c1);
    base::uc16 mask = char_mask ^ exor;
    macro_assembler->CheckNotCharacterAfterAnd(c1, mask, on_failure);
    return true;
  }
  DCHECK(c2 > c1);
  base::uc16 diff = c2 - c1;
  if (((diff - 1) & diff) == 0 && c1 >= diff) {
    // If the characters differ by 2^n but don't differ by one bit then
    // subtract the difference from the found character, then do the or
    // trick.  We avoid the theoretical case where negative numbers are
    // involved in order to simplify code generation.
    base::uc16 mask = char_mask ^ diff;
    macro_assembler->CheckNotCharacterAfterMinusAnd(c1 - diff, diff, mask,
                                                    on_failure);
    return true;
  }
  return false;
}

// Only emits letters (things that have case).  Only used for case independent
// matches.
inline bool EmitAtomLetter(Isolate* isolate, RegExpCompiler* compiler,
                           base::uc16 c, Label* on_failure, int cp_offset,
                           bool check, bool preloaded) {
  RegExpMacroAssembler* macro_assembler = compiler->macro_assembler();
  bool one_byte = compiler->one_byte();
  unibrow::uchar chars[4];
  int length = GetCaseIndependentLetters(isolate, c, compiler, chars, 4);
  // The 0 and 1 case are handled by earlier passes.
  if (length <= 1) return false;
  // We may not need to check against the end of the input string
  // if this character lies before a character that matched.
  if (!preloaded) {
    macro_assembler->LoadCurrentCharacter(cp_offset, on_failure, check);
  }
  Label ok;
  switch (length) {
    case 2: {
      if (ShortCutEmitCharacterPair(macro_assembler, one_byte, chars[0],
                                    chars[1], on_failure)) {
      } else {
        macro_assembler->CheckCharacter(chars[0], &ok);
        macro_assembler->CheckNotCharacter(chars[1], on_failure);
        macro_assembler->Bind(&ok);
      }
      break;
    }
    case 4:
      macro_assembler->CheckCharacter(chars[3], &ok);
      [[fallthrough]];
    case 3:
      macro_assembler->CheckCharacter(chars[0], &ok);
      macro_assembler->CheckCharacter(chars[1], &ok);
      macro_assembler->CheckNotCharacter(chars[2], on_failure);
      macro_assembler->Bind(&ok);
      break;
    default:
      UNREACHABLE();
  }
  return true;
}

void EmitBoundaryTest(RegExpMacroAssembler* masm, int border,
                      Label* fall_through, Label* above_or_equal,
                      Label* below) {
  if (below != fall_through) {
    masm->CheckCharacterLT(border, below);
    if (above_or_equal != fall_through) masm->GoTo(above_or_equal);
  } else {
    masm->CheckCharacterGT(border - 1, above_or_equal);
  }
}

void EmitDoubleBoundaryTest(RegExpMacroAssembler* masm, int first, int last,
                            Label* fall_through, Label* in_range,
                            Label* out_of_range) {
  if (in_range == fall_through) {
    if (first == last) {
      masm->CheckNotCharacter(first, out_of_range);
    } else {
      masm->CheckCharacterNotInRange(first, last, out_of_range);
    }
  } else {
    if (first == last) {
      masm->CheckCharacter(first, in_range);
    } else {
      masm->CheckCharacterInRange(first, last, in_range);
    }
    if (out_of_range != fall_through) masm->GoTo(out_of_range);
  }
}

// even_label is for ranges[i] to ranges[i + 1] where i - start_index is even.
// odd_label is for ranges[i] to ranges[i + 1] where i - start_index is odd.
void EmitUseLookupTable(RegExpMacroAssembler* masm,
                        ZoneList<base::uc32>* ranges, uint32_t start_index,
                        uint32_t end_index, base::uc32 min_char,
                        Label* fall_through, Label* even_label,
                        Label* odd_label) {
  static const uint32_t kSize = RegExpMacroAssembler::kTableSize;
  static const uint32_t kMask = RegExpMacroAssembler::kTableMask;

  base::uc32 base = (min_char & ~kMask);
  USE(base);

  // Assert that everything is on one kTableSize page.
  for (uint32_t i = start_index; i <= end_index; i++) {
    DCHECK_EQ(ranges->at(i) & ~kMask, base);
  }
  DCHECK(start_index == 0 || (ranges->at(start_index - 1) & ~kMask) <= base);

  char templ[kSize];
  Label* on_bit_set;
  Label* on_bit_clear;
  int bit;
  if (even_label == fall_through) {
    on_bit_set = odd_label;
    on_bit_clear = even_label;
    bit = 1;
  } else {
    on_bit_set = even_label;
    on_bit_clear = odd_label;
    bit = 0;
  }
  for (uint32_t i = 0; i < (ranges->at(start_index) & kMask) && i < kSize;
       i++) {
    templ[i] = bit;
  }
  uint32_t j = 0;
  bit ^= 1;
  for (uint32_t i = start_index; i < end_index; i++) {
    for (j = (ranges->at(i) & kMask); j < (ranges->at(i + 1) & kMask); j++) {
      templ[j] = bit;
    }
    bit ^= 1;
  }
  for (uint32_t i = j; i < kSize; i++) {
    templ[i] = bit;
  }
  Factory* factory = masm->isolate()->factory();
  // TODO(erikcorry): Cache these.
  Handle<ByteArray> ba = factory->NewByteArray(kSize, AllocationType::kOld);
  for (uint32_t i = 0; i < kSize; i++) {
    ba->set(i, templ[i]);
  }
  masm->CheckBitInTable(ba, on_bit_set);
  if (on_bit_clear != fall_through) masm->GoTo(on_bit_clear);
}

void CutOutRange(RegExpMacroAssembler* masm, ZoneList<base::uc32>* ranges,
                 uint32_t start_index, uint32_t end_index, uint32_t cut_index,
                 Label* even_label, Label* odd_label) {
  bool odd = (((cut_index - start_index) & 1) == 1);
  Label* in_range_label = odd ? odd_label : even_label;
  Label dummy;
  EmitDoubleBoundaryTest(masm, ranges->at(cut_index),
                         ranges->at(cut_index + 1) - 1, &dummy, in_range_label,
                         &dummy);
  DCHECK(!dummy.is_linked());
  // Cut out the single range by rewriting the array.  This creates a new
  // range that is a merger of the two ranges on either side of the one we
  // are cutting out.  The oddity of the labels is preserved.
  for (uint32_t j = cut_index; j > start_index; j--) {
    ranges->at(j) = ranges->at(j - 1);
  }
  for (uint32_t j = cut_index + 1; j < end_index; j++) {
    ranges->at(j) = ranges->at(j + 1);
  }
}

// Unicode case.  Split the search space into kSize spaces that are handled
// with recursion.
void SplitSearchSpace(ZoneList<base::uc32>* ranges, uint32_t start_index,
                      uint32_t end_index, uint32_t* new_start_index,
                      uint32_t* new_end_index, base::uc32* border) {
  static const uint32_t kSize = RegExpMacroAssembler::kTableSize;
  static const uint32_t kMask = RegExpMacroAssembler::kTableMask;

  base::uc32 first = ranges->at(start_index);
  base::uc32 last = ranges->at(end_index) - 1;

  *new_start_index = start_index;
  *border = (ranges->at(start_index) & ~kMask) + kSize;
  while (*new_start_index < end_index) {
    if (ranges->at(*new_start_index) > *border) break;
    (*new_start_index)++;
  }
  // new_start_index is the index of the first edge that is beyond the
  // current kSize space.

  // For very large search spaces we do a binary chop search of the non-Latin1
  // space instead of just going to the end of the current kSize space.  The
  // heuristics are complicated a little by the fact that any 128-character
  // encoding space can be quickly tested with a table lookup, so we don't
  // wish to do binary chop search at a smaller granularity than that.  A
  // 128-character space can take up a lot of space in the ranges array if,
  // for example, we only want to match every second character (eg. the lower
  // case characters on some Unicode pages).
  uint32_t binary_chop_index = (end_index + start_index) / 2;
  // The first test ensures that we get to the code that handles the Latin1
  // range with a single not-taken branch, speeding up this important
  // character range (even non-Latin1 charset-based text has spaces and
  // punctuation).
  if (*border - 1 > String::kMaxOneByteCharCode &&  // Latin1 case.
      end_index - start_index > (*new_start_index - start_index) * 2 &&
      last - first > kSize * 2 && binary_chop_index > *new_start_index &&
      ranges->at(binary_chop_index) >= first + 2 * kSize) {
    uint32_t scan_forward_for_section_border = binary_chop_index;
    uint32_t new_border = (ranges->at(binary_chop_index) | kMask) + 1;

    while (scan_forward_for_section_border < end_index) {
      if (ranges->at(scan_forward_for_section_border) > new_border) {
        *new_start_index = scan_forward_for_section_border;
        *border = new_border;
        break;
      }
      scan_forward_for_section_border++;
    }
  }

  DCHECK(*new_start_index > start_index);
  *new_end_index = *new_start_index - 1;
  if (ranges->at(*new_end_index) == *border) {
    (*new_end_index)--;
  }
  if (*border >= ranges->at(end_index)) {
    *border = ranges->at(end_index);
    *new_start_index = end_index;  // Won't be used.
    *new_end_index = end_index - 1;
  }
}

// Gets a series of segment boundaries representing a character class.  If the
// character is in the range between an even and an odd boundary (counting from
// start_index) then go to even_label, otherwise go to odd_label.  We already
// know that the character is in the range of min_char to max_char inclusive.
// Either label can be nullptr indicating backtracking.  Either label can also
// be equal to the fall_through label.
void GenerateBranches(RegExpMacroAssembler* masm, ZoneList<base::uc32>* ranges,
                      uint32_t start_index, uint32_t end_index,
                      base::uc32 min_char, base::uc32 max_char,
                      Label* fall_through, Label* even_label,
                      Label* odd_label) {
  DCHECK_LE(min_char, String::kMaxUtf16CodeUnit);
  DCHECK_LE(max_char, String::kMaxUtf16CodeUnit);

  base::uc32 first = ranges->at(start_index);
  base::uc32 last = ranges->at(end_index) - 1;

  DCHECK_LT(min_char, first);

  // Just need to test if the character is before or on-or-after
  // a particular character.
  if (start_index == end_index) {
    EmitBoundaryTest(masm, first, fall_through, even_label, odd_label);
    return;
  }

  // Another almost trivial case:  There is one interval in the middle that is
  // different from the end intervals.
  if (start_index + 1 == end_index) {
    EmitDoubleBoundaryTest(masm, first, last, fall_through, even_label,
                           odd_label);
    return;
  }

  // It's not worth using table lookup if there are very few intervals in the
  // character class.
  if (end_index - start_index <= 6) {
    // It is faster to test for individual characters, so we look for those
    // first, then try arbitrary ranges in the second round.
    static uint32_t kNoCutIndex = -1;
    uint32_t cut = kNoCutIndex;
    for (uint32_t i = start_index; i < end_index; i++) {
      if (ranges->at(i) == ranges->at(i + 1) - 1) {
        cut = i;
        break;
      }
    }
    if (cut == kNoCutIndex) cut = start_index;
    CutOutRange(masm, ranges, start_index, end_index, cut, even_label,
                odd_label);
    DCHECK_GE(end_index - start_index, 2);
    GenerateBranches(masm, ranges, start_index + 1, end_index - 1, min_char,
                     max_char, fall_through, even_label, odd_label);
    return;
  }

  // If there are a lot of intervals in the regexp, then we will use tables to
  // determine whether the character is inside or outside the character class.
  static const int kBits = RegExpMacroAssembler::kTableSizeBits;

  if ((max_char >> kBits) == (min_char >> kBits)) {
    EmitUseLookupTable(masm, ranges, start_index, end_index, min_char,
                       fall_through, even_label, odd_label);
    return;
  }

  if ((min_char >> kBits) != first >> kBits) {
    masm->CheckCharacterLT(first, odd_label);
    GenerateBranches(masm, ranges, start_index + 1, end_index, first, max_char,
                     fall_through, odd_label, even_label);
    return;
  }

  uint32_t new_start_index = 0;
  uint32_t new_end_index = 0;
  base::uc32 border = 0;

  SplitSearchSpace(ranges, start_index, end_index, &new_start_index,
                   &new_end_index, &border);

  Label handle_rest;
  Label* above = &handle_rest;
  if (border == last + 1) {
    // We didn't find any section that started after the limit, so everything
    // above the border is one of the terminal labels.
    above = (end_index & 1) != (start_index & 1) ? odd_label : even_label;
    DCHECK(new_end_index == end_index - 1);
  }

  DCHECK_LE(start_index, new_end_index);
  DCHECK_LE(new_start_index, end_index);
  DCHECK_LT(start_index, new_start_index);
  DCHECK_LT(new_end_index, end_index);
  DCHECK(new_end_index + 1 == new_start_index ||
         (new_end_index + 2 == new_start_index &&
          border == ranges->at(new_end_index + 1)));
  DCHECK_LT(min_char, border - 1);
  DCHECK_LT(border, max_char);
  DCHECK_LT(ranges->at(new_end_index), border);
  DCHECK(border < ranges->at(new_start_index) ||
         (border == ranges->at(new_start_index) &&
          new_start_index == end_index && new_end_index == end_index - 1 &&
          border == last + 1));
  DCHECK(new_start_index == 0 || border >= ranges->at(new_start_index - 1));

  masm->CheckCharacterGT(border - 1, above);
  Label dummy;
  GenerateBranches(masm, ranges, start_index, new_end_index, min_char,
                   border - 1, &dummy, even_label, odd_label);
  if (handle_rest.is_linked()) {
    masm->Bind(&handle_rest);
    bool flip = (new_start_index & 1) != (start_index & 1);
    GenerateBranches(masm, ranges, new_start_index, end_index, border, max_char,
                     &dummy, flip ? odd_label : even_label,
                     flip ? even_label : odd_label);
  }
}

void EmitClassRanges(RegExpMacroAssembler* macro_assembler,
                     RegExpClassRanges* cr, bool one_byte, Label* on_failure,
                     int cp_offset, bool check_offset, bool preloaded,
                     Zone* zone) {
  ZoneList<CharacterRange>* ranges = cr->ranges(zone);
  CharacterRange::Canonicalize(ranges);

  // Now that all processing (like case-insensitivity) is done, clamp the
  // ranges to the set of ranges that may actually occur in the subject string.
  if (one_byte) CharacterRange::ClampToOneByte(ranges);

  const int ranges_length = ranges->length();
  if (ranges_length == 0) {
    if (!cr->is_negated()) {
      macro_assembler->GoTo(on_failure);
    }
    if (check_offset) {
      macro_assembler->CheckPosition(cp_offset, on_failure);
    }
    return;
  }

  const base::uc32 max_char = MaxCodeUnit(one_byte);
  if (ranges_length == 1 && ranges->at(0).IsEverything(max_char)) {
    if (cr->is_negated()) {
      macro_assembler->GoTo(on_failure);
    } else {
      // This is a common case hit by non-anchored expressions.
      if (check_offset) {
        macro_assembler->CheckPosition(cp_offset, on_failure);
      }
    }
    return;
  }

  if (!preloaded) {
    macro_assembler->LoadCurrentCharacter(cp_offset, on_failure, check_offset);
  }

  if (cr->is_standard(zone) && macro_assembler->CheckSpecialClassRanges(
                                   cr->standard_type(), on_failure)) {
    return;
  }

  static constexpr int kMaxRangesForInlineBranchGeneration = 16;
  if (ranges_length > kMaxRangesForInlineBranchGeneration) {
    // For large range sets, emit a more compact instruction sequence to avoid
    // a potentially problematic increase in code size.
    // Note the flipped logic below (we check InRange if negated, NotInRange if
    // not negated); this is necessary since the method falls through on
    // failure whereas we want to fall through on success.
    if (cr->is_negated()) {
      if (macro_assembler->CheckCharacterInRangeArray(ranges, on_failure)) {
        return;
      }
    } else {
      if (macro_assembler->CheckCharacterNotInRangeArray(ranges, on_failure)) {
        return;
      }
    }
  }

  // Generate a flat list of range boundaries for consumption by
  // GenerateBranches. See the comment on that function for how the list should
  // be structured
  ZoneList<base::uc32>* range_boundaries =
      zone->New<ZoneList<base::uc32>>(ranges_length * 2, zone);

  bool zeroth_entry_is_failure = !cr->is_negated();

  for (int i = 0; i < ranges_length; i++) {
    CharacterRange& range = ranges->at(i);
    if (range.from() == 0) {
      DCHECK_EQ(i, 0);
      zeroth_entry_is_failure = !zeroth_entry_is_failure;
    } else {
      range_boundaries->Add(range.from(), zone);
    }
    // `+ 1` to convert from inclusive to exclusive `to`.
    // [from, to] == [from, to+1[.
    range_boundaries->Add(range.to() + 1, zone);
  }
  int end_index = range_boundaries->length() - 1;
  if (range_boundaries->at(end_index) > max_char) {
    end_index--;
  }

  Label fall_through;
  GenerateBranches(macro_assembler, range_boundaries,
                   0,  // start_index.
                   end_index,
                   0,  // min_char.
                   max_char, &fall_through,
                   zeroth_entry_is_failure ? &fall_through : on_failure,
                   zeroth_entry_is_failure ? on_failure : &fall_through);
  macro_assembler->Bind(&fall_through);
}

}  // namespace

RegExpNode::~RegExpNode() = default;

RegExpNode::LimitResult RegExpNode::LimitVersions(RegExpCompiler* compiler,
                                                  Trace* trace) {
  // If we are generating a greedy loop then don't stop and don't reuse code.
  if (trace->stop_node() != nullptr) {
    return CONTINUE;
  }

  RegExpMacroAssembler* macro_assembler = compiler->macro_assembler();
  if (trace->is_trivial()) {
    if (label_.is_bound() || on_work_list() || !KeepRecursing(compiler)) {
      // If a generic version is already scheduled to be generated or we have
      // recursed too deeply then just generate a jump to that code.
      macro_assembler->GoTo(&label_);
      // This will queue it up for generation of a generic version if it hasn't
      // already been queued.
      compiler->AddWork(this);
      return DONE;
    }
    // Generate generic version of the node and bind the label for later use.
    macro_assembler->Bind(&label_);
    return CONTINUE;
  }

  // We are being asked to make a non-generic version.  Keep track of how many
  // non-generic versions we generate so as not to overdo it.
  trace_count_++;
  if (KeepRecursing(compiler) && compiler->optimize() &&
      trace_count_ < kMaxCopiesCodeGenerated) {
    return CONTINUE;
  }

  // If we get here code has been generated for this node too many times or
  // recursion is too deep.  Time to switch to a generic version.  The code for
  // generic versions above can handle deep recursion properly.
  bool was_limiting = compiler->limiting_recursion();
  compiler->set_limiting_recursion(true);
  trace->Flush(compiler, this);
  compiler->set_limiting_recursion(was_limiting);
  return DONE;
}

bool RegExpNode::KeepRecursing(RegExpCompiler* compiler) {
  return !compiler->limiting_recursion() &&
         compiler->recursion_depth() <= RegExpCompiler::kMaxRecursion;
}

void ActionNode::FillInBMInfo(Isolate* isolate, int offset, int budget,
                              BoyerMooreLookahead* bm, bool not_at_start) {
  std::optional<RegExpFlags> old_flags;
  if (action_type_ == MODIFY_FLAGS) {
    // It is not guaranteed that we hit the resetting modify flags node, due to
    // recursion budget limitation for filling in BMInfo. Therefore we reset the
    // flags manually to the previous state after recursing.
    old_flags = bm->compiler()->flags();
    bm->compiler()->set_flags(flags());
  }
  if (action_type_ == BEGIN_POSITIVE_SUBMATCH) {
    // We use the node after the lookaround to fill in the eats_at_least info
    // so we have to use the same node to fill in the Boyer-Moore info.
    success_node()->on_success()->FillInBMInfo(isolate, offset, budget - 1, bm,
                                               not_at_start);
  } else if (action_type_ != POSITIVE_SUBMATCH_SUCCESS) {
    // We don't use the node after a positive submatch success because it
    // rewinds the position.  Since we returned 0 as the eats_at_least value for
    // this node, we don't need to fill in any data.
    on_success()->FillInBMInfo(isolate, offset, budget - 1, bm, not_at_start);
  }
  SaveBMInfo(bm, not_at_start, offset);
  if (old_flags.has_value()) {
    bm->compiler()->set_flags(*old_flags);
  }
}

void ActionNode::GetQuickCheckDetails(QuickCheckDetails* details,
                                      RegExpCompiler* compiler, int filled_in,
                                      bool not_at_start) {
  if (action_type_ == SET_REGISTER_FOR_LOOP) {
    on_success()->GetQuickCheckDetailsFromLoopEntry(details, compiler,
                                                    filled_in, not_at_start);
  } else if (action_type_ == BEGIN_POSITIVE_SUBMATCH) {
    // We use the node after the lookaround to fill in the eats_at_least info
    // so we have to use the same node to fill in the QuickCheck info.
    success_node()->on_success()->GetQuickCheckDetails(details, compiler,
                                                       filled_in, not_at_start);
  } else if (action_type() != POSITIVE_SUBMATCH_SUCCESS) {
    // We don't use the node after a positive submatch success because it
    // rewinds the position.  Since we returned 0 as the eats_at_least value
    // for this node, we don't need to fill in any data.
    if (action_type() == MODIFY_FLAGS) {
      compiler->set_flags(flags());
    }
    on_success()->GetQuickCheckDetails(details, compiler, filled_in,
                                       not_at_start);
  }
}

void AssertionNode::FillInBMInfo(Isolate* isolate, int offset, int budget,
                                 BoyerMooreLookahead* bm, bool not_at_start) {
  // Match the behaviour of EatsAtLeast on this node.
  if (assertion_type() == AT_START && not_at_start) return;
  on_success()->FillInBMInfo(isolate, offset, budget - 1, bm, not_at_start);
  SaveBMInfo(bm, not_at_start, offset);
}

void NegativeLookaroundChoiceNode::GetQuickCheckDetails(
    QuickCheckDetails* details, RegExpCompiler* compiler, int filled_in,
    bool not_at_start) {
  RegExpNode* node = continue_node();
  return node->GetQuickCheckDetails(details, compiler, filled_in, not_at_start);
}

namespace {

// Takes the left-most 1-bit and smears it out, setting all bits to its right.
inline uint32_t SmearBitsRight(uint32_t v) {
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  return v;
}

}  // namespace

bool QuickCheckDetails::Rationalize(bool asc) {
  bool found_useful_op = false;
  const uint32_t char_mask = CharMask(asc);
  mask_ = 0;
  value_ = 0;
  int char_shift = 0;
  for (int i = 0; i < characters_; i++) {
    Position* pos = &positions_[i];
    if ((pos->mask & String::kMaxOneByteCharCode) != 0) {
      found_useful_op = true;
    }
    mask_ |= (pos->mask & char_mask) << char_shift;
    value_ |= (pos->value & char_mask) << char_shift;
    char_shift += asc ? 8 : 16;
  }
  return found_useful_op;
}

uint32_t RegExpNode::EatsAtLeast(bool not_at_start) {
  return not_at_start ? eats_at_least_.eats_at_least_from_not_start
                      : eats_at_least_.eats_at_least_from_possibly_start;
}

EatsAtLeastInfo RegExpNode::EatsAtLeastFromLoopEntry() {
  // SET_REGISTER_FOR_LOOP is only used to initialize loop counters, and it
  // implies that the following node must be a LoopChoiceNode. If we need to
  // set registers to constant values for other reasons, we could introduce a
  // new action type SET_REGISTER that doesn't imply anything about its
  // successor.
  UNREACHABLE();
}

void RegExpNode::GetQuickCheckDetailsFromLoopEntry(QuickCheckDetails* details,
                                                   RegExpCompiler* compiler,
                                                   int characters_filled_in,
                                                   bool not_at_start) {
  // See comment in RegExpNode::EatsAtLeastFromLoopEntry.
  UNREACHABLE();
}

EatsAtLeastInfo LoopChoiceNode::EatsAtLeastFromLoopEntry() {
  DCHECK_EQ(alternatives_->length(), 2);  // There's just loop and continue.

  if (read_backward()) {
    // The eats_at_least value is not used if reading backward. The
    // EatsAtLeastPropagator should've zeroed it as well.
    DCHECK_EQ(eats_at_least_info()->eats_at_least_from_possibly_start, 0);
    DCHECK_EQ(eats_at_least_info()->eats_at_least_from_not_start, 0);
    return {};
  }

  // Figure out how much the loop body itself eats, not including anything in
  // the continuation case. In general, the nodes in the loop body should report
  // that they eat at least the number eaten by the continuation node, since any
  // successful match in the loop body must also include the continuation node.
  // However, in some cases involving positive lookaround, the loop body under-
  // reports its appetite, so use saturated math here to avoid negative numbers.
  // For this to work correctly, we explicitly need to use signed integers here.
  uint8_t loop_body_from_not_start = base::saturated_cast<uint8_t>(
      static_cast<int>(loop_node_->EatsAtLeast(true)) -
      static_cast<int>(continue_node_->EatsAtLeast(true)));
  uint8_t loop_body_from_possibly_start = base::saturated_cast<uint8_t>(
      static_cast<int>(loop_node_->EatsAtLeast(false)) -
      static_cast<int>(continue_node_->EatsAtLeast(true)));

  // Limit the number of loop iterations to avoid overflow in subsequent steps.
  int loop_iterations = base::saturated_cast<uint8_t>(min_loop_iterations());

  EatsAtLeastInfo result;
  result.eats_at_least_from_not_start =
      base::saturated_cast<uint8_t>(loop_iterations * loop_body_from_not_start +
                                    continue_node_->EatsAtLeast(true));
  if (loop_iterations > 0 && loop_body_from_possibly_start > 0) {
    // First loop iteration eats at least one, so all subsequent iterations
    // and the after-loop chunk are guaranteed to not be at the start.
    result.eats_at_least_from_possibly_start = base::saturated_cast<uint8_t>(
        loop_body_from_possibly_start +
        (loop_iterations - 1) * loop_body_from_not_start +
        continue_node_->EatsAtLeast(true));
  } else {
    // Loop body might eat nothing, so only continue node contributes.
    result.eats_at_least_from_possibly_start =
        continue_node_->EatsAtLeast(false);
  }
  return result;
}

bool RegExpNode::EmitQuickCheck(RegExpCompiler* compiler,
                                Trace* bounds_check_trace, Trace* trace,
                                bool preload_has_checked_bounds,
                                Label* on_possible_success,
                                QuickCheckDetails* details,
                                bool fall_through_on_failure,
                                ChoiceNode* predecessor) {
  DCHECK_NOT_NULL(predecessor);
  if (details->characters() == 0) return false;
  GetQuickCheckDetails(details, compiler, 0,
                       trace->at_start() == Trace::FALSE_VALUE);
  if (details->cannot_match()) return false;
  if (!details->Rationalize(compiler->one_byte())) return false;
  DCHECK(details->characters() == 1 ||
         compiler->macro_assembler()->CanReadUnaligned());
  uint32_t mask = details->mask();
  uint32_t value = details->value();

  RegExpMacroAssembler* assembler = compiler->macro_assembler();

  if (trace->characters_preloaded() != details->characters()) {
    DCHECK(trace->cp_offset() == bounds_check_trace->cp_offset());
    // The bounds check is performed using the minimum number of characters
    // any choice would eat, so if the bounds check fails, then none of the
    // choices can succeed, so we can just immediately backtrack, rather
    // than go to the next choice. The number of characters preloaded may be
    // less than the number used for the bounds check.
    int eats_at_least = predecessor->EatsAtLeast(
        bounds_check_trace->at_start() == Trace::FALSE_VALUE);
    DCHECK_GE(eats_at_least, details->characters());
    assembler->LoadCurrentCharacter(
        trace->cp_offset(), bounds_check_trace->backtrack(),
        !preload_has_checked_bounds, details->characters(), eats_at_least);
  }

  bool need_mask = true;

  if (details->characters() == 1) {
    // If number of characters preloaded is 1 then we used a byte or 16 bit
    // load so the value is already masked down.
    const uint32_t char_mask = CharMask(compiler->one_byte());
    if ((mask & char_mask) == char_mask) need_mask = false;
    mask &= char_mask;
  } else {
    // For 2-character preloads in one-byte mode or 1-character preloads in
    // two-byte mode we also use a 16 bit load with zero extend.
    static const uint32_t kTwoByteMask = 0xFFFF;
    static const uint32_t kFourByteMask = 0xFFFFFFFF;
    if (details->characters() == 2 && compiler->one_byte()) {
      if ((mask & kTwoByteMask) == kTwoByteMask) need_mask = false;
    } else if (details->characters() == 1 && !compiler->one_byte()) {
      if ((mask & kTwoByteMask) == kTwoByteMask) need_mask = false;
    } else {
      if (mask == kFourByteMask) need_mask = false;
    }
  }

  if (fall_through_on_failure) {
    if (need_mask) {
      assembler->CheckCharacterAfterAnd(value, mask, on_possible_success);
    } else {
      assembler->CheckCharacter(value, on_possible_success);
    }
  } else {
    if (need_mask) {
      assembler->CheckNotCharacterAfterAnd(value, mask, trace->backtrack());
    } else {
      assembler->CheckNotCharacter(value, trace->backtrack());
    }
  }
  return true;
}

// Here is the meat of GetQuickCheckDetails (see also the comment on the
// super-class in the .h file).
//
// We iterate along the text object, building up for each character a
// mask and value that can be used to test for a quick failure to match.
// The masks and values for the positions will be combined into a single
// machine word for the current character width in order to be used in
// generating a quick check.
void TextNode::GetQuickCheckDetails(QuickCheckDetails* details,
                                    RegExpCompiler* compiler,
                                    int characters_filled_in,
                                    bool not_at_start) {
  // Do not collect any quick check details if the text node reads backward,
  // since it reads in the opposite direction than we use for quick checks.
  if (read_backward()) return;
  Isolate* isolate = compiler->macro_assembler()->isolate();
  DCHECK(characters_filled_in < details->characters());
  int characters = details->characters();
  const uint32_t char_mask = CharMask(compiler->one_byte());
  for (int k = 0; k < elements()->length(); k++) {
    TextElement elm = elements()->at(k);
    if (elm.text_type() == TextElement::ATOM) {
      base::Vector<const base::uc16>
```