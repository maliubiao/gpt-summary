Response:
The user wants a summary of the C++ code provided. I need to analyze the code and identify its core functionality.

Here's a breakdown of the thinking process:

1. **Identify the file's purpose:** The filename `regexp-bytecode-peephole.cc` and the included headers (`regexp-bytecodes.h`) strongly suggest this code is about optimizing regular expression bytecode. The term "peephole" often refers to a specific type of optimization that looks at small sequences of instructions.

2. **Analyze the core classes/structs:**
    * `BytecodeArgument`:  Represents an argument within a bytecode instruction. It stores the offset and length of the argument.
    * `BytecodeArgumentMapping`: Extends `BytecodeArgument` and includes information about how an argument in an old bytecode maps to an argument in a new, optimized bytecode.
    * `BytecodeArgumentCheck`:  Extends `BytecodeArgument` and defines conditions that must be met for a sequence of bytecodes to be considered optimizable. These checks can be based on address or value comparisons.
    * `BytecodeSequenceNode`: This appears to be the core data structure for representing sequences of bytecodes that can be optimized. It's likely a node in a Trie or similar structure. It stores the bytecode, a potential replacement bytecode, and information about arguments and checks. The methods like `FollowedBy`, `ReplaceWith`, `MapArgument`, and `IfArgumentEqualsOffset` strongly suggest this.
    * `RegExpBytecodePeephole`: This class seems to orchestrate the optimization process. It holds the bytecode sequences to look for and the logic to perform the replacements.

3. **Understand the optimization process (high-level):** The code seems to define "sequences" of bytecodes that are candidates for optimization. When such a sequence is found, it can be replaced with a more efficient bytecode. This involves:
    * **Defining sequences:**  The `DefineStandardSequences()` method suggests predefined optimization patterns.
    * **Matching sequences:** The `TryOptimizeSequence()` method likely compares the incoming bytecode stream against the defined sequences.
    * **Replacing sequences:** The `EmitOptimization()` method handles the actual replacement, potentially remapping arguments.
    * **Handling jumps:** The code has logic for handling jumps (`jump_edges_`, `jump_source_fixups_`, `jump_destination_fixups_`), which is crucial because replacing bytecode can shift jump targets.

4. **Infer the relationship with JavaScript:** Regular expressions are a fundamental part of JavaScript. V8 is the JavaScript engine, so this code directly impacts how JavaScript regexps are executed efficiently. The optimization at the bytecode level suggests it's happening *after* the initial compilation of the regular expression.

5. **Identify potential programming errors:**  The jump handling logic hints at a common error: incorrect jump targets after modifying code. If the offsets aren't adjusted correctly, the program will jump to the wrong location.

6. **Address the specific questions in the prompt:**
    * **Functionality:**  Summarize the core purpose (optimizing regexp bytecode).
    * **`.tq` extension:**  Note that the file doesn't have this extension and therefore isn't Torque code.
    * **JavaScript relationship:** Explain that it optimizes how JavaScript regexps are executed and provide a simple example.
    * **Code logic reasoning:**  Create a simple example of a bytecode sequence and how it might be optimized, illustrating the input and output.
    * **Common programming errors:** Give an example of an incorrect jump target after optimization.

7. **Structure the answer:** Organize the findings into a clear and logical explanation, addressing each point in the prompt. Use headings and bullet points for readability.

**(Self-correction during the process):** Initially, I might focus too much on the details of each struct. However, the prompt asks for a high-level overview of the *functionality*. Therefore, I need to prioritize explaining *what* the code does rather than *how* it does it in minute detail. Also, the prompt specifically asks about JavaScript examples and potential programming errors, so I must ensure these are included. The mention of "Torque" is a specific point to address directly.
Based on the provided C++ source code for `v8/src/regexp/regexp-bytecode-peephole.cc`, here's a breakdown of its functionality:

**Core Functionality:**

This code implements a **peephole optimizer** for regular expression bytecode within the V8 JavaScript engine. Peephole optimization is a local optimization technique that examines a small "window" (the peephole) of instructions and replaces inefficient sequences with more efficient ones.

**Key Components and Their Roles:**

* **`BytecodeArgument`:**  A simple structure to represent an argument of a bytecode instruction, storing its offset and length within the bytecode.

* **`BytecodeArgumentMapping`:**  Extends `BytecodeArgument` and is used when replacing bytecode sequences. It indicates how an argument from the original sequence maps to an argument in the new, optimized bytecode, including its new length if it changes.

* **`BytecodeArgumentCheck`:** Defines conditions that must be met for a sequence of bytecodes to be considered a candidate for optimization. These checks can verify:
    * **`kCheckAddress`:**  If an argument in the current bytecode points to a specific offset within the sequence (e.g., a jump target pointing to the beginning of the sequence).
    * **`kCheckValue`:** If an argument in the current bytecode has the same value as an argument in another bytecode within the sequence.

* **`BytecodeSequenceNode`:**  A crucial class representing a node in a Trie (prefix tree) that stores sequences of bytecode instructions that can be optimized.
    * **`FollowedBy(int bytecode)`:** Adds a subsequent bytecode to the sequence.
    * **`ReplaceWith(int bytecode)`:** Marks the end of a recognized sequence and specifies the bytecode to replace the entire sequence with.
    * **`MapArgument(...)`:** Defines how arguments from the original bytecode sequence are mapped to the arguments of the replacement bytecode.
    * **`IfArgumentEqualsOffset(...)` and `IfArgumentEqualsValueAtOffset(...)`:**  Define the conditions (using `BytecodeArgumentCheck`) that must be satisfied for the sequence to be a valid optimization candidate.
    * **`IgnoreArgument(...)`:**  Indicates that an argument in the original sequence is not needed in the optimized bytecode.
    * **`CheckArguments(...)`:**  Verifies if the current bytecode sequence matches the conditions defined in the node.
    * **`IsSequence()`:**  Checks if the node marks the end of a recognizable and optimizable sequence.
    * **`OptimizedBytecode()`:** Returns the bytecode to replace the sequence with.

* **`RegExpBytecodePeephole`:** The main class responsible for performing the peephole optimization.
    * **`OptimizeBytecode(const uint8_t* bytecode, int length)`:**  The core function that iterates through the input bytecode, identifies optimizable sequences using the `BytecodeSequenceNode` Trie, and replaces them with optimized instructions.
    * **`DefineStandardSequences()`:**  Sets up the predefined bytecode sequences that the optimizer will look for. These are common inefficient patterns that can be improved.
    * **`TryOptimizeSequence(...)`:** Attempts to match a sequence of bytecodes starting at a given position against the defined sequences.
    * **`EmitOptimization(...)`:**  Writes the optimized bytecode into the internal buffer, handling argument mapping.
    * **Methods for handling jumps (`AddJumpSourceFixup`, `AddJumpDestinationFixup`, `FixJumps`):**  Crucially important for ensuring that jump targets remain correct after bytecode replacement, as the offsets might change.

**Relationship with JavaScript:**

This code is directly related to the performance of regular expressions in JavaScript. When a JavaScript regular expression is compiled by V8, it's translated into a sequence of bytecode instructions. This `regexp-bytecode-peephole.cc` file optimizes that bytecode, making the regular expression execution faster.

**Example in JavaScript:**

While you don't directly interact with this C++ code in JavaScript, the optimizations it performs affect the underlying execution of your regexps. For example, consider a simple regex like `/ab/`. The initial bytecode might have separate instructions to load 'a', check if it matches, advance the position, load 'b', check if it matches, and then proceed. The peephole optimizer could recognize a common pattern and replace it with a more efficient single instruction or a shorter sequence.

```javascript
const regex = /ab/;
const text = "cab";
const match = regex.test(text); // This will benefit from bytecode optimization
```

**Code Logic Reasoning (Hypothetical Example):**

**Assumption:** Let's assume we have a simple optimization rule defined in `DefineStandardSequences()`:

* **Sequence:** `BC_LOAD_CURRENT_CHAR`, `BC_CHECK_CHAR`, `BC_ADVANCE_CP_AND_GOTO`
* **Replacement:** `BC_SKIP_UNTIL_CHAR`
* **Condition:** The `BC_ADVANCE_CP_AND_GOTO` instruction jumps back to the start of the sequence (implying a loop).

**Hypothetical Input Bytecode:**

```
0: BC_LOAD_CURRENT_CHAR  (offset: 0)
4: BC_CHECK_CHAR         (char: 'a', goto_if_match: 12)
12: BC_ADVANCE_CP_AND_GOTO (advance: 1, goto: 0)
...
```

**Reasoning:**

The `TryOptimizeSequence` function would recognize the sequence `BC_LOAD_CURRENT_CHAR`, `BC_CHECK_CHAR`, and `BC_ADVANCE_CP_AND_GOTO` starting at offset 0. The `IfArgumentEqualsOffset` check on the `BC_ADVANCE_CP_AND_GOTO` instruction would verify if its jump target (the value at offset 4 of the instruction, which is the address 0) matches the starting address of the sequence (0).

**Hypothetical Output Bytecode (after optimization):**

```
0: BC_SKIP_UNTIL_CHAR (load_offset: 0, advance_by: 1, character: 'a', goto_if_match: 12, goto_if_fail: next instruction after the loop)
...
```

The three original instructions are replaced by a single `BC_SKIP_UNTIL_CHAR` instruction, which efficiently skips characters until 'a' is found. The arguments of the new instruction are derived from the arguments of the original instructions using the `MapArgument` definitions. The jump targets are also adjusted accordingly.

**User Common Programming Errors (Related Concept):**

While users don't directly write or modify this bytecode, understanding the concept of jump targets is important when dealing with low-level programming or assembly. A common error would be:

* **Incorrectly calculating jump offsets after modifying code:** If you were manually manipulating bytecode (which is generally not done in typical JavaScript development), a mistake in calculating the new jump target after inserting or deleting instructions would lead to the program jumping to the wrong place, causing crashes or unexpected behavior. The `RegExpBytecodePeephole` carefully handles this during optimization.

**Summary of Functionality (Part 1):**

The `v8/src/regexp/regexp-bytecode-peephole.cc` file implements a peephole optimizer for V8's regular expression bytecode. It identifies inefficient sequences of bytecode instructions based on predefined patterns and replaces them with more efficient equivalents. This process involves defining these optimizable sequences, checking conditions for their applicability, and carefully mapping arguments and adjusting jump targets to ensure the optimized bytecode functions correctly. This optimization directly contributes to the performance of regular expressions in JavaScript.

### 提示词
```
这是目录为v8/src/regexp/regexp-bytecode-peephole.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/regexp-bytecode-peephole.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/regexp/regexp-bytecode-peephole.h"

#include "src/flags/flags.h"
#include "src/objects/fixed-array-inl.h"
#include "src/regexp/regexp-bytecodes.h"
#include "src/utils/memcopy.h"
#include "src/utils/utils.h"
#include "src/zone/zone-containers.h"
#include "src/zone/zone.h"

namespace v8 {
namespace internal {

namespace {

struct BytecodeArgument {
  int offset;
  int length;

  BytecodeArgument(int offset, int length) : offset(offset), length(length) {}
};

struct BytecodeArgumentMapping : BytecodeArgument {
  int new_length;

  BytecodeArgumentMapping(int offset, int length, int new_length)
      : BytecodeArgument(offset, length), new_length(new_length) {}
};

struct BytecodeArgumentCheck : BytecodeArgument {
  enum CheckType { kCheckAddress = 0, kCheckValue };
  CheckType type;
  int check_offset;
  int check_length;

  BytecodeArgumentCheck(int offset, int length, int check_offset)
      : BytecodeArgument(offset, length),
        type(kCheckAddress),
        check_offset(check_offset) {}
  BytecodeArgumentCheck(int offset, int length, int check_offset,
                        int check_length)
      : BytecodeArgument(offset, length),
        type(kCheckValue),
        check_offset(check_offset),
        check_length(check_length) {}
};

// Trie-Node for storing bytecode sequences we want to optimize.
class BytecodeSequenceNode {
 public:
  // Dummy bytecode used when we need to store/return a bytecode but it's not a
  // valid bytecode in the current context.
  static constexpr int kDummyBytecode = -1;

  BytecodeSequenceNode(int bytecode, Zone* zone);
  // Adds a new node as child of the current node if it isn't a child already.
  BytecodeSequenceNode& FollowedBy(int bytecode);
  // Marks the end of a sequence and sets optimized bytecode to replace all
  // bytecodes of the sequence with.
  BytecodeSequenceNode& ReplaceWith(int bytecode);
  // Maps arguments of bytecodes in the sequence to the optimized bytecode.
  // Order of invocation determines order of arguments in the optimized
  // bytecode.
  // Invoking this method is only allowed on nodes that mark the end of a valid
  // sequence (i.e. after ReplaceWith()).
  // bytecode_index_in_sequence: Zero-based index of the referred bytecode
  // within the sequence (e.g. the bytecode passed to CreateSequence() has
  // index 0).
  // argument_offset: Zero-based offset to the argument within the bytecode
  // (e.g. the first argument that's not packed with the bytecode has offset 4).
  // argument_byte_length: Length of the argument.
  // new_argument_byte_length: Length of the argument in the new bytecode
  // (= argument_byte_length if omitted).
  BytecodeSequenceNode& MapArgument(int bytecode_index_in_sequence,
                                    int argument_offset,
                                    int argument_byte_length,
                                    int new_argument_byte_length = 0);
  // Adds a check to the sequence node making it only a valid sequence when the
  // argument of the current bytecode at the specified offset matches the offset
  // to check against.
  // argument_offset: Zero-based offset to the argument within the bytecode
  // (e.g. the first argument that's not packed with the bytecode has offset 4).
  // argument_byte_length: Length of the argument.
  // check_byte_offset: Zero-based offset relative to the beginning of the
  // sequence that needs to match the value given by argument_offset. (e.g.
  // check_byte_offset 0 matches the address of the first bytecode in the
  // sequence).
  BytecodeSequenceNode& IfArgumentEqualsOffset(int argument_offset,
                                               int argument_byte_length,
                                               int check_byte_offset);
  // Adds a check to the sequence node making it only a valid sequence when the
  // argument of the current bytecode at the specified offset matches the
  // argument of another bytecode in the sequence.
  // This is similar to IfArgumentEqualsOffset, except that this method matches
  // the values of both arguments.
  BytecodeSequenceNode& IfArgumentEqualsValueAtOffset(
      int argument_offset, int argument_byte_length,
      int other_bytecode_index_in_sequence, int other_argument_offset,
      int other_argument_byte_length);
  // Marks an argument as unused.
  // All arguments that are not mapped explicitly have to be marked as unused.
  // bytecode_index_in_sequence: Zero-based index of the referred bytecode
  // within the sequence (e.g. the bytecode passed to CreateSequence() has
  // index 0).
  // argument_offset: Zero-based offset to the argument within the bytecode
  // (e.g. the first argument that's not packed with the bytecode has offset 4).
  // argument_byte_length: Length of the argument.
  BytecodeSequenceNode& IgnoreArgument(int bytecode_index_in_sequence,
                                       int argument_offset,
                                       int argument_byte_length);
  // Checks if the current node is valid for the sequence. I.e. all conditions
  // set by IfArgumentEqualsOffset and IfArgumentEquals are fulfilled by this
  // node for the actual bytecode sequence.
  bool CheckArguments(const uint8_t* bytecode, int pc);
  // Returns whether this node marks the end of a valid sequence (i.e. can be
  // replaced with an optimized bytecode).
  bool IsSequence() const;
  // Returns the length of the sequence in bytes.
  int SequenceLength() const;
  // Returns the optimized bytecode for the node or kDummyBytecode if it is not
  // the end of a valid sequence.
  int OptimizedBytecode() const;
  // Returns the child of the current node matching the given bytecode or
  // nullptr if no such child is found.
  BytecodeSequenceNode* Find(int bytecode) const;
  // Returns number of arguments mapped to the current node.
  // Invoking this method is only allowed on nodes that mark the end of a valid
  // sequence (i.e. if IsSequence())
  size_t ArgumentSize() const;
  // Returns the argument-mapping of the argument at index.
  // Invoking this method is only allowed on nodes that mark the end of a valid
  // sequence (i.e. if IsSequence())
  BytecodeArgumentMapping ArgumentMapping(size_t index) const;
  // Returns an iterator to begin of ignored arguments.
  // Invoking this method is only allowed on nodes that mark the end of a valid
  // sequence (i.e. if IsSequence())
  ZoneLinkedList<BytecodeArgument>::iterator ArgumentIgnoredBegin() const;
  // Returns an iterator to end of ignored arguments.
  // Invoking this method is only allowed on nodes that mark the end of a valid
  // sequence (i.e. if IsSequence())
  ZoneLinkedList<BytecodeArgument>::iterator ArgumentIgnoredEnd() const;
  // Returns whether the current node has ignored argument or not.
  bool HasIgnoredArguments() const;

 private:
  // Returns a node in the sequence specified by its index within the sequence.
  BytecodeSequenceNode& GetNodeByIndexInSequence(int index_in_sequence);
  Zone* zone() const;

  int bytecode_;
  int bytecode_replacement_;
  int index_in_sequence_;
  int start_offset_;
  BytecodeSequenceNode* parent_;
  ZoneUnorderedMap<int, BytecodeSequenceNode*> children_;
  ZoneVector<BytecodeArgumentMapping>* argument_mapping_;
  ZoneLinkedList<BytecodeArgumentCheck>* argument_check_;
  ZoneLinkedList<BytecodeArgument>* argument_ignored_;

  Zone* zone_;
};

// These definitions are here in order to please the linker, which in debug mode
// sometimes requires static constants to be defined in .cc files.
constexpr int BytecodeSequenceNode::kDummyBytecode;

class RegExpBytecodePeephole {
 public:
  RegExpBytecodePeephole(Zone* zone, size_t buffer_size,
                         const ZoneUnorderedMap<int, int>& jump_edges);

  // Parses bytecode and fills the internal buffer with the potentially
  // optimized bytecode. Returns true when optimizations were performed, false
  // otherwise.
  bool OptimizeBytecode(const uint8_t* bytecode, int length);
  // Copies the internal bytecode buffer to another buffer. The caller is
  // responsible for allocating/freeing the memory.
  void CopyOptimizedBytecode(uint8_t* to_address) const;
  int Length() const;

 private:
  // Sets up all sequences that are going to be used.
  void DefineStandardSequences();
  // Starts a new bytecode sequence.
  BytecodeSequenceNode& CreateSequence(int bytecode);
  // Checks for optimization candidates at pc and emits optimized bytecode to
  // the internal buffer. Returns the length of replaced bytecodes in bytes.
  int TryOptimizeSequence(const uint8_t* bytecode, int bytecode_length,
                          int start_pc);
  // Emits optimized bytecode to the internal buffer. start_pc points to the
  // start of the sequence in bytecode and last_node is the last
  // BytecodeSequenceNode of the matching sequence found.
  void EmitOptimization(int start_pc, const uint8_t* bytecode,
                        const BytecodeSequenceNode& last_node);
  // Adds a relative jump source fixup at pos.
  // Jump source fixups are used to find offsets in the new bytecode that
  // contain jump sources.
  void AddJumpSourceFixup(int fixup, int pos);
  // Adds a relative jump destination fixup at pos.
  // Jump destination fixups are used to find offsets in the new bytecode that
  // can be jumped to.
  void AddJumpDestinationFixup(int fixup, int pos);
  // Sets an absolute jump destination fixup at pos.
  void SetJumpDestinationFixup(int fixup, int pos);
  // Prepare internal structures used to fixup jumps.
  void PrepareJumpStructures(const ZoneUnorderedMap<int, int>& jump_edges);
  // Updates all jump targets in the new bytecode.
  void FixJumps();
  // Update a single jump.
  void FixJump(int jump_source, int jump_destination);
  void AddSentinelFixups(int pos);
  template <typename T>
  void EmitValue(T value);
  template <typename T>
  void OverwriteValue(int offset, T value);
  void CopyRangeToOutput(const uint8_t* orig_bytecode, int start, int length);
  void SetRange(uint8_t value, int count);
  void EmitArgument(int start_pc, const uint8_t* bytecode,
                    BytecodeArgumentMapping arg);
  int pc() const;
  Zone* zone() const;

  ZoneVector<uint8_t> optimized_bytecode_buffer_;
  BytecodeSequenceNode* sequences_;
  // Jumps used in old bytecode.
  // Key: Jump source (offset where destination is stored in old bytecode)
  // Value: Destination
  ZoneMap<int, int> jump_edges_;
  // Jumps used in new bytecode.
  // Key: Jump source (offset where destination is stored in new bytecode)
  // Value: Destination
  ZoneMap<int, int> jump_edges_mapped_;
  // Number of times a jump destination is used within the bytecode.
  // Key: Jump destination (offset in old bytecode).
  // Value: Number of times jump destination is used.
  ZoneMap<int, int> jump_usage_counts_;
  // Maps offsets in old bytecode to fixups of sources (delta to new bytecode).
  // Key: Offset in old bytecode from where the fixup is valid.
  // Value: Delta to map jump source from old bytecode to new bytecode in bytes.
  ZoneMap<int, int> jump_source_fixups_;
  // Maps offsets in old bytecode to fixups of destinations (delta to new
  // bytecode).
  // Key: Offset in old bytecode from where the fixup is valid.
  // Value: Delta to map jump destinations from old bytecode to new bytecode in
  // bytes.
  ZoneMap<int, int> jump_destination_fixups_;

  Zone* zone_;

  DISALLOW_IMPLICIT_CONSTRUCTORS(RegExpBytecodePeephole);
};

template <typename T>
T GetValue(const uint8_t* buffer, int pos) {
  DCHECK(IsAligned(reinterpret_cast<Address>(buffer + pos), alignof(T)));
  return *reinterpret_cast<const T*>(buffer + pos);
}

int32_t GetArgumentValue(const uint8_t* bytecode, int offset, int length) {
  switch (length) {
    case 1:
      return GetValue<uint8_t>(bytecode, offset);
    case 2:
      return GetValue<int16_t>(bytecode, offset);
    case 4:
      return GetValue<int32_t>(bytecode, offset);
    default:
      UNREACHABLE();
  }
}

BytecodeSequenceNode::BytecodeSequenceNode(int bytecode, Zone* zone)
    : bytecode_(bytecode),
      bytecode_replacement_(kDummyBytecode),
      index_in_sequence_(0),
      start_offset_(0),
      parent_(nullptr),
      children_(ZoneUnorderedMap<int, BytecodeSequenceNode*>(zone)),
      argument_mapping_(zone->New<ZoneVector<BytecodeArgumentMapping>>(zone)),
      argument_check_(zone->New<ZoneLinkedList<BytecodeArgumentCheck>>(zone)),
      argument_ignored_(zone->New<ZoneLinkedList<BytecodeArgument>>(zone)),
      zone_(zone) {}

BytecodeSequenceNode& BytecodeSequenceNode::FollowedBy(int bytecode) {
  DCHECK(0 <= bytecode && bytecode < kRegExpBytecodeCount);

  if (children_.find(bytecode) == children_.end()) {
    BytecodeSequenceNode* new_node =
        zone()->New<BytecodeSequenceNode>(bytecode, zone());
    // If node is not the first in the sequence, set offsets and parent.
    if (bytecode_ != kDummyBytecode) {
      new_node->start_offset_ = start_offset_ + RegExpBytecodeLength(bytecode_);
      new_node->index_in_sequence_ = index_in_sequence_ + 1;
      new_node->parent_ = this;
    }
    children_[bytecode] = new_node;
  }

  return *children_[bytecode];
}

BytecodeSequenceNode& BytecodeSequenceNode::ReplaceWith(int bytecode) {
  DCHECK(0 <= bytecode && bytecode < kRegExpBytecodeCount);

  bytecode_replacement_ = bytecode;

  return *this;
}

BytecodeSequenceNode& BytecodeSequenceNode::MapArgument(
    int bytecode_index_in_sequence, int argument_offset,
    int argument_byte_length, int new_argument_byte_length) {
  DCHECK(IsSequence());
  DCHECK_LE(bytecode_index_in_sequence, index_in_sequence_);

  BytecodeSequenceNode& ref_node =
      GetNodeByIndexInSequence(bytecode_index_in_sequence);
  DCHECK_LT(argument_offset, RegExpBytecodeLength(ref_node.bytecode_));

  int absolute_offset = ref_node.start_offset_ + argument_offset;
  if (new_argument_byte_length == 0) {
    new_argument_byte_length = argument_byte_length;
  }

  argument_mapping_->push_back(BytecodeArgumentMapping{
      absolute_offset, argument_byte_length, new_argument_byte_length});

  return *this;
}

BytecodeSequenceNode& BytecodeSequenceNode::IfArgumentEqualsOffset(
    int argument_offset, int argument_byte_length, int check_byte_offset) {
  DCHECK_LT(argument_offset, RegExpBytecodeLength(bytecode_));
  DCHECK(argument_byte_length == 1 || argument_byte_length == 2 ||
         argument_byte_length == 4);

  int absolute_offset = start_offset_ + argument_offset;

  argument_check_->push_back(BytecodeArgumentCheck{
      absolute_offset, argument_byte_length, check_byte_offset});

  return *this;
}

BytecodeSequenceNode& BytecodeSequenceNode::IfArgumentEqualsValueAtOffset(
    int argument_offset, int argument_byte_length,
    int other_bytecode_index_in_sequence, int other_argument_offset,
    int other_argument_byte_length) {
  DCHECK_LT(argument_offset, RegExpBytecodeLength(bytecode_));
  DCHECK_LE(other_bytecode_index_in_sequence, index_in_sequence_);
  DCHECK_EQ(argument_byte_length, other_argument_byte_length);

  BytecodeSequenceNode& ref_node =
      GetNodeByIndexInSequence(other_bytecode_index_in_sequence);
  DCHECK_LT(other_argument_offset, RegExpBytecodeLength(ref_node.bytecode_));

  int absolute_offset = start_offset_ + argument_offset;
  int other_absolute_offset = ref_node.start_offset_ + other_argument_offset;

  argument_check_->push_back(
      BytecodeArgumentCheck{absolute_offset, argument_byte_length,
                            other_absolute_offset, other_argument_byte_length});

  return *this;
}

BytecodeSequenceNode& BytecodeSequenceNode::IgnoreArgument(
    int bytecode_index_in_sequence, int argument_offset,
    int argument_byte_length) {
  DCHECK(IsSequence());
  DCHECK_LE(bytecode_index_in_sequence, index_in_sequence_);

  BytecodeSequenceNode& ref_node =
      GetNodeByIndexInSequence(bytecode_index_in_sequence);
  DCHECK_LT(argument_offset, RegExpBytecodeLength(ref_node.bytecode_));

  int absolute_offset = ref_node.start_offset_ + argument_offset;

  argument_ignored_->push_back(
      BytecodeArgument{absolute_offset, argument_byte_length});

  return *this;
}

bool BytecodeSequenceNode::CheckArguments(const uint8_t* bytecode, int pc) {
  bool is_valid = true;
  for (auto check_iter = argument_check_->begin();
       check_iter != argument_check_->end() && is_valid; check_iter++) {
    auto value =
        GetArgumentValue(bytecode, pc + check_iter->offset, check_iter->length);
    if (check_iter->type == BytecodeArgumentCheck::kCheckAddress) {
      is_valid &= value == pc + check_iter->check_offset;
    } else if (check_iter->type == BytecodeArgumentCheck::kCheckValue) {
      auto other_value = GetArgumentValue(
          bytecode, pc + check_iter->check_offset, check_iter->check_length);
      is_valid &= value == other_value;
    } else {
      UNREACHABLE();
    }
  }
  return is_valid;
}

bool BytecodeSequenceNode::IsSequence() const {
  return bytecode_replacement_ != kDummyBytecode;
}

int BytecodeSequenceNode::SequenceLength() const {
  return start_offset_ + RegExpBytecodeLength(bytecode_);
}

int BytecodeSequenceNode::OptimizedBytecode() const {
  return bytecode_replacement_;
}

BytecodeSequenceNode* BytecodeSequenceNode::Find(int bytecode) const {
  auto found = children_.find(bytecode);
  if (found == children_.end()) return nullptr;
  return found->second;
}

size_t BytecodeSequenceNode::ArgumentSize() const {
  DCHECK(IsSequence());
  return argument_mapping_->size();
}

BytecodeArgumentMapping BytecodeSequenceNode::ArgumentMapping(
    size_t index) const {
  DCHECK(IsSequence());
  DCHECK(argument_mapping_ != nullptr);
  DCHECK_LT(index, argument_mapping_->size());

  return argument_mapping_->at(index);
}

ZoneLinkedList<BytecodeArgument>::iterator
BytecodeSequenceNode::ArgumentIgnoredBegin() const {
  DCHECK(IsSequence());
  DCHECK(argument_ignored_ != nullptr);
  return argument_ignored_->begin();
}

ZoneLinkedList<BytecodeArgument>::iterator
BytecodeSequenceNode::ArgumentIgnoredEnd() const {
  DCHECK(IsSequence());
  DCHECK(argument_ignored_ != nullptr);
  return argument_ignored_->end();
}

bool BytecodeSequenceNode::HasIgnoredArguments() const {
  return argument_ignored_ != nullptr;
}

BytecodeSequenceNode& BytecodeSequenceNode::GetNodeByIndexInSequence(
    int index_in_sequence) {
  DCHECK_LE(index_in_sequence, index_in_sequence_);

  if (index_in_sequence < index_in_sequence_) {
    DCHECK(parent_ != nullptr);
    return parent_->GetNodeByIndexInSequence(index_in_sequence);
  } else {
    return *this;
  }
}

Zone* BytecodeSequenceNode::zone() const { return zone_; }

RegExpBytecodePeephole::RegExpBytecodePeephole(
    Zone* zone, size_t buffer_size,
    const ZoneUnorderedMap<int, int>& jump_edges)
    : optimized_bytecode_buffer_(zone),
      sequences_(zone->New<BytecodeSequenceNode>(
          BytecodeSequenceNode::kDummyBytecode, zone)),
      jump_edges_(zone),
      jump_edges_mapped_(zone),
      jump_usage_counts_(zone),
      jump_source_fixups_(zone),
      jump_destination_fixups_(zone),
      zone_(zone) {
  optimized_bytecode_buffer_.reserve(buffer_size);
  PrepareJumpStructures(jump_edges);
  DefineStandardSequences();
  // Sentinel fixups at beginning of bytecode (position -1) so we don't have to
  // check for end of iterator inside the fixup loop.
  // In general fixups are deltas of original offsets of jump
  // sources/destinations (in the old bytecode) to find them in the new
  // bytecode. All jump targets are fixed after the new bytecode is fully
  // emitted in the internal buffer.
  AddSentinelFixups(-1);
  // Sentinel fixups at end of (old) bytecode so we don't have to check for
  // end of iterator inside the fixup loop.
  DCHECK_LE(buffer_size, std::numeric_limits<int>::max());
  AddSentinelFixups(static_cast<int>(buffer_size));
}

void RegExpBytecodePeephole::DefineStandardSequences() {
  // Commonly used sequences can be found by creating regexp bytecode traces
  // (--trace-regexp-bytecodes) and using v8/tools/regexp-sequences.py.
  CreateSequence(BC_LOAD_CURRENT_CHAR)
      .FollowedBy(BC_CHECK_BIT_IN_TABLE)
      .FollowedBy(BC_ADVANCE_CP_AND_GOTO)
      // Sequence is only valid if the jump target of ADVANCE_CP_AND_GOTO is the
      // first bytecode in this sequence.
      .IfArgumentEqualsOffset(4, 4, 0)
      .ReplaceWith(BC_SKIP_UNTIL_BIT_IN_TABLE)
      .MapArgument(0, 1, 3)      // load offset
      .MapArgument(2, 1, 3, 4)   // advance by
      .MapArgument(1, 8, 16)     // bit table
      .MapArgument(1, 4, 4)      // goto when match
      .MapArgument(0, 4, 4)      // goto on failure
      .IgnoreArgument(2, 4, 4);  // loop jump

  CreateSequence(BC_CHECK_CURRENT_POSITION)
      .FollowedBy(BC_LOAD_CURRENT_CHAR_UNCHECKED)
      .FollowedBy(BC_CHECK_CHAR)
      .FollowedBy(BC_ADVANCE_CP_AND_GOTO)
      // Sequence is only valid if the jump target of ADVANCE_CP_AND_GOTO is the
      // first bytecode in this sequence.
      .IfArgumentEqualsOffset(4, 4, 0)
      .ReplaceWith(BC_SKIP_UNTIL_CHAR_POS_CHECKED)
      .MapArgument(1, 1, 3)      // load offset
      .MapArgument(3, 1, 3, 2)   // advance_by
      .MapArgument(2, 1, 3, 2)   // c
      .MapArgument(0, 1, 3, 4)   // eats at least
      .MapArgument(2, 4, 4)      // goto when match
      .MapArgument(0, 4, 4)      // goto on failure
      .IgnoreArgument(3, 4, 4);  // loop jump

  CreateSequence(BC_CHECK_CURRENT_POSITION)
      .FollowedBy(BC_LOAD_CURRENT_CHAR_UNCHECKED)
      .FollowedBy(BC_AND_CHECK_CHAR)
      .FollowedBy(BC_ADVANCE_CP_AND_GOTO)
      // Sequence is only valid if the jump target of ADVANCE_CP_AND_GOTO is the
      // first bytecode in this sequence.
      .IfArgumentEqualsOffset(4, 4, 0)
      .ReplaceWith(BC_SKIP_UNTIL_CHAR_AND)
      .MapArgument(1, 1, 3)      // load offset
      .MapArgument(3, 1, 3, 2)   // advance_by
      .MapArgument(2, 1, 3, 2)   // c
      .MapArgument(2, 4, 4)      // mask
      .MapArgument(0, 1, 3, 4)   // eats at least
      .MapArgument(2, 8, 4)      // goto when match
      .MapArgument(0, 4, 4)      // goto on failure
      .IgnoreArgument(3, 4, 4);  // loop jump

  // TODO(pthier): It might make sense for short sequences like this one to only
  // optimize them if the resulting optimization is not longer than the current
  // one. This could be the case if there are jumps inside the sequence and we
  // have to replicate parts of the sequence. A method to mark such sequences
  // might be useful.
  CreateSequence(BC_LOAD_CURRENT_CHAR)
      .FollowedBy(BC_CHECK_CHAR)
      .FollowedBy(BC_ADVANCE_CP_AND_GOTO)
      // Sequence is only valid if the jump target of ADVANCE_CP_AND_GOTO is the
      // first bytecode in this sequence.
      .IfArgumentEqualsOffset(4, 4, 0)
      .ReplaceWith(BC_SKIP_UNTIL_CHAR)
      .MapArgument(0, 1, 3)      // load offset
      .MapArgument(2, 1, 3, 2)   // advance by
      .MapArgument(1, 1, 3, 2)   // character
      .MapArgument(1, 4, 4)      // goto when match
      .MapArgument(0, 4, 4)      // goto on failure
      .IgnoreArgument(2, 4, 4);  // loop jump

  CreateSequence(BC_LOAD_CURRENT_CHAR)
      .FollowedBy(BC_CHECK_CHAR)
      .FollowedBy(BC_CHECK_CHAR)
      // Sequence is only valid if the jump targets of both CHECK_CHAR bytecodes
      // are equal.
      .IfArgumentEqualsValueAtOffset(4, 4, 1, 4, 4)
      .FollowedBy(BC_ADVANCE_CP_AND_GOTO)
      // Sequence is only valid if the jump target of ADVANCE_CP_AND_GOTO is the
      // first bytecode in this sequence.
      .IfArgumentEqualsOffset(4, 4, 0)
      .ReplaceWith(BC_SKIP_UNTIL_CHAR_OR_CHAR)
      .MapArgument(0, 1, 3)      // load offset
      .MapArgument(3, 1, 3, 4)   // advance by
      .MapArgument(1, 1, 3, 2)   // character 1
      .MapArgument(2, 1, 3, 2)   // character 2
      .MapArgument(1, 4, 4)      // goto when match
      .MapArgument(0, 4, 4)      // goto on failure
      .IgnoreArgument(2, 4, 4)   // goto when match 2
      .IgnoreArgument(3, 4, 4);  // loop jump

  CreateSequence(BC_LOAD_CURRENT_CHAR)
      .FollowedBy(BC_CHECK_GT)
      // Sequence is only valid if the jump target of CHECK_GT is the first
      // bytecode AFTER the whole sequence.
      .IfArgumentEqualsOffset(4, 4, 56)
      .FollowedBy(BC_CHECK_BIT_IN_TABLE)
      // Sequence is only valid if the jump target of CHECK_BIT_IN_TABLE is
      // the ADVANCE_CP_AND_GOTO bytecode at the end of the sequence.
      .IfArgumentEqualsOffset(4, 4, 48)
      .FollowedBy(BC_GOTO)
      // Sequence is only valid if the jump target of GOTO is the same as the
      // jump target of CHECK_GT (i.e. both jump to the first bytecode AFTER the
      // whole sequence.
      .IfArgumentEqualsValueAtOffset(4, 4, 1, 4, 4)
      .FollowedBy(BC_ADVANCE_CP_AND_GOTO)
      // Sequence is only valid if the jump target of ADVANCE_CP_AND_GOTO is the
      // first bytecode in this sequence.
      .IfArgumentEqualsOffset(4, 4, 0)
      .ReplaceWith(BC_SKIP_UNTIL_GT_OR_NOT_BIT_IN_TABLE)
      .MapArgument(0, 1, 3)      // load offset
      .MapArgument(4, 1, 3, 2)   // advance by
      .MapArgument(1, 1, 3, 2)   // character
      .MapArgument(2, 8, 16)     // bit table
      .MapArgument(1, 4, 4)      // goto when match
      .MapArgument(0, 4, 4)      // goto on failure
      .IgnoreArgument(2, 4, 4)   // indirect loop jump
      .IgnoreArgument(3, 4, 4)   // jump out of loop
      .IgnoreArgument(4, 4, 4);  // loop jump
}

bool RegExpBytecodePeephole::OptimizeBytecode(const uint8_t* bytecode,
                                              int length) {
  int old_pc = 0;
  bool did_optimize = false;

  while (old_pc < length) {
    int replaced_len = TryOptimizeSequence(bytecode, length, old_pc);
    if (replaced_len > 0) {
      old_pc += replaced_len;
      did_optimize = true;
    } else {
      int bc = bytecode[old_pc];
      int bc_len = RegExpBytecodeLength(bc);
      CopyRangeToOutput(bytecode, old_pc, bc_len);
      old_pc += bc_len;
    }
  }

  if (did_optimize) {
    FixJumps();
  }

  return did_optimize;
}

void RegExpBytecodePeephole::CopyOptimizedBytecode(uint8_t* to_address) const {
  MemCopy(to_address, &(*optimized_bytecode_buffer_.begin()), Length());
}

int RegExpBytecodePeephole::Length() const { return pc(); }

BytecodeSequenceNode& RegExpBytecodePeephole::CreateSequence(int bytecode) {
  DCHECK(sequences_ != nullptr);
  DCHECK(0 <= bytecode && bytecode < kRegExpBytecodeCount);

  return sequences_->FollowedBy(bytecode);
}

int RegExpBytecodePeephole::TryOptimizeSequence(const uint8_t* bytecode,
                                                int bytecode_length,
                                                int start_pc) {
  BytecodeSequenceNode* seq_node = sequences_;
  BytecodeSequenceNode* valid_seq_end = nullptr;

  int current_pc = start_pc;

  // Check for the longest valid sequence matching any of the pre-defined
  // sequences in the Trie data structure.
  while (current_pc < bytecode_length) {
    seq_node = seq_node->Find(bytecode[current_pc]);
    if (seq_node == nullptr) break;
    if (!seq_node->CheckArguments(bytecode, start_pc)) break;

    if (seq_node->IsSequence()) valid_seq_end = seq_node;
    current_pc += RegExpBytecodeLength(bytecode[current_pc]);
  }

  if (valid_seq_end) {
    EmitOptimization(start_pc, bytecode, *valid_seq_end);
    return valid_seq_end->SequenceLength();
  }

  return 0;
}

void RegExpBytecodePeephole::EmitOptimization(
    int start_pc, const uint8_t* bytecode,
    const BytecodeSequenceNode& last_node) {
#ifdef DEBUG
  int optimized_start_pc = pc();
#endif
  // Jump sources that are mapped or marked as unused will be deleted at the end
  // of this method. We don't delete them immediately as we might need the
  // information when we have to preserve bytecodes at the end.
  // TODO(pthier): Replace with a stack-allocated data structure.
  ZoneLinkedList<int> delete_jumps = ZoneLinkedList<int>(zone());

  uint32_t bc = last_node.OptimizedBytecode();
  EmitValue(bc);

  for (size_t arg = 0; arg < last_node.ArgumentSize(); arg++) {
    BytecodeArgumentMapping arg_map = last_node.ArgumentMapping(arg);
    int arg_pos = start_pc + arg_map.offset;
    // If we map any jump source we mark the old source for deletion and insert
    // a new jump.
    auto jump_edge_iter = jump_edges_.find(arg_pos);
    if (jump_edge_iter != jump_edges_.end()) {
      int jump_source = jump_edge_iter->first;
      int jump_destination = jump_edge_iter->second;
      // Add new jump edge add current position.
      jump_edges_mapped_.emplace(Length(), jump_destination);
      // Mark old jump edge for deletion.
      delete_jumps.push_back(jump_source);
      // Decrement usage count of jump destination.
      auto jump_count_iter = jump_usage_counts_.find(jump_destination);
      DCHECK(jump_count_iter != jump_usage_counts_.end());
      int& usage_count = jump_count_iter->second;
      --usage_count;
    }
    // TODO(pthier): DCHECK that mapped arguments are never sources of jumps
    // to destinations inside the sequence.
    EmitArgument(start_pc, bytecode, arg_map);
  }
  DCHECK_EQ(pc(), optimized_start_pc +
                      RegExpBytecodeLength(last_node.OptimizedBytecode()));

  // Remove jumps from arguments we ignore.
  if (last_node.HasIgnoredArguments()) {
    for (auto ignored_arg = last_node.ArgumentIgnoredBegin();
         ignored_arg != last_node.ArgumentIgnoredEnd(); ignored_arg++) {
      auto jump_edge_iter = jump_edges_.find(start_pc + ignored_arg->offset);
      if (jump_edge_iter != jump_edges_.end()) {
        int jump_source = jump_edge_iter->first;
        int jump_destination = jump_edge_iter->second;
        // Mark old jump edge for deletion.
        delete_jumps.push_back(jump_source);
        // Decrement usage count of jump destination.
        auto jump_count_iter = jump_usage_counts_.find(jump_destination);
        DCHECK(jump_count_iter != jump_usage_counts_.end());
        int& usage_count = jump_count_iter->second;
        --usage_count;
      }
    }
  }

  int fixup_length = RegExpBytecodeLength(bc) - last_node.SequenceLength();

  // Check if there are any jumps inside the old sequence.
  // If so we have to keep the bytecodes that are jumped to around.
  auto jump_destination_candidate = jump_usage_counts_.upper_bound(start_pc);
  int jump_candidate_destination = jump_destination_candidate->first;
  int jump_candidate_count = jump_destination_candidate->second;
  // Jump destinations only jumped to from inside the sequence will be ignored.
  while (jump_destination_candidate != jump_usage_counts_.end() &&
         jump_candidate_count == 0) {
    ++jump_destination_candidate;
    jump_candidate_destination = jump_destination_candidate->first;
    jump_candidate_count = jump_destination_candidate->second;
  }

  int preserve_from = start_pc + last_node.SequenceLength();
  if (jump_destination_candidate != jump_usage_counts_.end() &&
      jump_candidate_destination < start_pc + last_node.SequenceLength()) {
    preserve_from = jump_candidate_destination;
    // Check if any jump in the sequence we are preserving has a jump
    // destination inside the optimized sequence before the current position we
    // want to preserve. If so we have to preserve all bytecodes starting at
    // this jump destination.
    for (auto jump_iter = jump_edges_.lower_bound(preserve_from);
         jump_iter != jump_edges_.end() &&
         jump_iter->first /* jump source */ <
             start_pc + last_node.SequenceLength();
         ++jump_iter) {
      int jump_destination = jump_iter->second;
      if (jump_destination > start_pc && jump_destination < preserve_from) {
        preserve_from = jump_destination;
      }
    }

    // We preserve everything to the end of the sequence. This is conservative
    // since it would be enough to preserve all bytecudes up to an unconditional
    // jump.
    int preserve_length = start_pc + last_node.SequenceLength() - preserve_from;
    fixup_length += preserve_length;
    // Jumps after the start of the preserved sequence need fixup.
    AddJumpSourceFixup(fixup_length,
                       start_pc + last_node.SequenceLength() - preserve_length);
    // All jump targets after the start of the optimized sequence need to be
    // fixed relative to the length of the optimized sequence including
    // bytecodes we preserved.
    AddJumpDestinationFixup(fixup_length, start_pc + 1);
    // Jumps to the sequence we preserved need absolute fixup as they could
    // occur before or after the sequence.
    SetJumpDestinationFixup(pc() - preserve_
```