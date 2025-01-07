Response:
The user wants a summary of the functionality of the provided C++ header file. The request also asks to identify if it's a Torque file, if it relates to Javascript, provide Javascript examples, explain code logic with examples, highlight common programming errors, and summarize its function as part 3 of a 4-part series.

**Plan:**

1. **Identify file type:** Check the file extension.
2. **Core functionality:** Analyze the code, focusing on the `REDUCE` macros, to understand what optimizations it performs. Look for patterns in the optimizations.
3. **Javascript relation:** Determine if the optimizations are specific to Javascript concepts or V8 internals. If related, provide Javascript examples that might trigger these optimizations.
4. **Code logic and examples:** For key optimization patterns, create hypothetical input and output scenarios.
5. **Common errors:**  Think about common mistakes related to the operations being optimized (e.g., bit manipulation, comparisons).
6. **Part 3 summary:**  Synthesize the identified functionalities into a concise summary, keeping in mind it's part of a larger sequence.
这是 `v8/src/compiler/turboshaft/machine-optimization-reducer.h` 文件的第三部分代码。这个头文件定义了一个 `MachineOptimizationReducer` 类，该类的主要功能是在 Turboshaft 编译器的机器码优化阶段，对中间表示（IR）图进行简化和优化。

**功能列举:**

这部分代码主要关注以下类型的操作的优化：

* **比较操作 (`Comparison`)**:
    * 尝试移除 `Word32ToWord64Conversion` 操作，如果比较的两边都是从 32 位转换为 64 位，并且符号扩展方式一致，则可以直接比较 32 位值。
    * 如果比较的一边是符号扩展，另一边不是，并且比较是有符号的，则转换为无符号比较。

* **位移操作 (`Shift`)**:
    * 如果位移量是常量，并且位移对象也是常量，则直接计算位移结果。
    * 如果位移量为 0，则直接返回位移对象。
    * 尝试简化左移操作，例如 `(x >> K) << L` 的情况。
    * 尝试简化右移后立即左移相同量的操作，例如 `(x >>> K) << K` 或 `(x >> K) << K`。
    * 尝试识别并优化特定的位移模式，例如 `x << (bit_width - 1) >> (bit_width - 1)` 和 `x << (bit_width - 8) >> (bit_width - 8)`。
    * 如果目标平台安全，则移除与 `0x1F` 的按位与操作，如果该操作是为了符合 JavaScript 的位移规范。

* **分支操作 (`Branch`)**:
    * 如果分支条件是布尔常量，则直接跳转到相应的分支。
    * 尝试简化分支条件，例如将 `if (x == 0)` 转换为 `if (x)` 并交换分支。

* **反优化断言 (`DeoptimizeIf`)**:
    * 如果条件是布尔常量，并且不需要反优化，则移除该操作。
    * 尝试简化条件。

* **Wasm陷阱 (`TrapIf`)**:
    * 如果条件是布尔常量，并且不需要触发陷阱，则移除该操作。
    * 尝试简化条件。

* **选择操作 (`Select`)**:
    * 如果条件是布尔常量，则直接选择相应的值。

* **静态断言 (`StaticAssert`)**:
    * 如果条件是布尔常量 `true`，则移除该断言。

* **Switch 语句 (`Switch`)**:
    * 如果 `switch` 的输入是常量，则直接跳转到匹配的 `case` 或 `default` 分支。

* **存储操作 (`Store`)**:
    * 尝试移除存储值的 `Word32ToWord64Conversion` 操作，如果存储的大小不超过 4 字节。
    * 尝试将索引的一部分移动到偏移量中进行优化。
    * 如果基地址是加法操作 `left + right` 并且没有索引，则尝试将 `right` 作为索引。
    * 根据存储的数据类型，对存储的值进行截断优化。

* **加载操作 (`Load`)**:
    * 尝试将索引的一部分移动到偏移量中进行优化。
    * 如果基地址是一个常量堆对象，并且正在加载 map 字段，则尝试常量折叠。
    * 如果基地址是加法操作 `left + right` 并且没有索引，则尝试将 `right` 作为索引。

* **Wasm SIMD 操作 (`Simd128ExtractLane`)**:
    * （仅在启用了 `turboshaft_wasm_instruction_selection_staged` 标志并且目标架构是 ARM64 时）尝试识别 SIMD 通道提取操作是否是由一系列 SIMD 洗牌和二元操作构成，并将其优化为 `Simd128Reduce` 操作。

**关于文件类型:**

`v8/src/compiler/turboshaft/machine-optimization-reducer.h` 以 `.h` 结尾，所以它是 **C++ 头文件**，而不是 Torque 源文件。 Torque 源文件以 `.tq` 结尾。

**与 Javascript 的关系:**

这个文件直接参与了 V8 编译器的优化过程，因此与 Javascript 的执行性能密切相关。 这里列举的优化都是为了提高最终生成的机器码的效率，从而加速 Javascript 代码的执行。

**Javascript 举例说明:**

* **比较操作优化:**
  ```javascript
  function compare(a) {
    const b = 10;
    if (a == b) { // 这里可能会触发常量比较的优化
      return true;
    }
    return false;
  }
  ```
  如果 `b` 是一个常量，编译器可以优化 `a == b` 的比较。

* **位移操作优化:**
  ```javascript
  function shift(x) {
    return x << 2; // 如果 x 是常量，可以直接计算结果
  }

  function mask(x) {
    return (x >> 3) & 0xFF; // 编译器可能优化位移和掩码操作
  }
  ```

* **分支操作优化:**
  ```javascript
  function branch(x) {
    if (true) { // 条件是常量，编译器会直接跳转
      return 1;
    } else {
      return 0;
    }
  }

  function compareAndBranch(x) {
    if (x == 0) { // 编译器可能将 x == 0 简化为 !x
      return "zero";
    } else {
      return "non-zero";
    }
  }
  ```

* **存储和加载操作优化:**
  ```javascript
  const arr = [1, 2, 3];
  function accessArray(i) {
    return arr[0]; // 访问常量索引，编译器可能直接计算偏移量
  }

  function storeToArray(i, value) {
    arr[0] = value;
  }
  ```

**代码逻辑推理 (假设输入与输出):**

**假设输入 (Comparison):**
`left`:  一个表示 `Word32ToWord64Conversion` 操作的 `OpIndex`，其输入是一个 `Word32` 类型的常量 `5`。
`right`: 一个表示 `Word32ToWord64Conversion` 操作的 `OpIndex`，其输入是一个 `Word32` 类型的常量 `10`。
`kind`: `ComparisonOp::Kind::kEqual`
`rep`: `RegisterRepresentation::Word64()`

**输出:**
一个新的 `OpIndex`，表示一个 `Word32Constant` 操作，其值为 `0` (因为 5 不等于 10)。

**假设输入 (Shift):**
`left`: 一个表示 `Word32Constant` 操作的 `OpIndex`，其值为 `5`。
`right`: 一个表示 `Word32Constant` 操作的 `OpIndex`，其值为 `2`。
`kind`: `ShiftOp::Kind::kShiftLeft`
`rep`: `WordRepresentation::Word32()`

**输出:**
一个新的 `OpIndex`，表示一个 `Word32Constant` 操作，其值为 `20` (5 << 2)。

**涉及用户常见的编程错误:**

* **不必要的类型转换:** 用户可能显式地将 32 位整数转换为 64 位整数进行比较，而实际上可以直接比较 32 位值。
  ```javascript
  function compareInts(a) {
    const b = 10;
    if (BigInt(a) === BigInt(b)) { // 这里 BigInt 的转换在某些情况下可能是不必要的
      return true;
    }
    return false;
  }
  ```
  优化器可以识别出这种模式并进行简化。

* **复杂的位运算:** 用户可能会写出复杂的位运算，而优化器可以将其简化为更直接的形式。
  ```javascript
  function complexShift(x) {
    return (x >> 3) << 3; // 如果本意是清除低 3 位，优化器可能会简化
  }
  ```

* **冗余的条件判断:**  条件始终为真或假的分支。
  ```javascript
  function alwaysTrue() {
    if (1 + 1 === 2) { // 条件始终为真
      return "yes";
    } else {
      return "no";
    }
  }
  ```

**功能归纳 (作为第 3 部分):**

作为 Turboshaft 编译器的机器码优化阶段的一部分，此部分 `MachineOptimizationReducer` 的主要功能是**针对特定的机器码操作（如比较、位移、分支、存储、加载等）应用基于模式匹配的简化和优化**。它旨在通过识别可以进行常量折叠、代数简化或等价转换的 IR 节点，来生成更高效的目标代码。 这部分优化器专注于操作的本地特性，尝试在不改变程序语义的前提下，减少指令的数量和复杂度。它依赖于前面阶段构建的 IR 图，并为后续的指令选择和代码生成阶段做准备。

Prompt: 
```
这是目录为v8/src/compiler/turboshaft/machine-optimization-reducer.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/machine-optimization-reducer.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
::kUnsignedLessThanOrEqual;
                case Kind::kEqual:
                  UNREACHABLE();
              }
            };
            return __ Comparison(
                UndoWord32ToWord64Conversion(V<Word64>::Cast(left)),
                UndoWord32ToWord64Conversion(V<Word64>::Cast(right)),
                SetSigned(kind, false), WordRepresentation::Word32());
          } else if (left_sign_extended != false &&
                     right_sign_extended != false) {
            // Both sides were sign-extended, this preserves both signed and
            // unsigned comparisons.
            return __ Comparison(
                UndoWord32ToWord64Conversion(V<Word64>::Cast(left)),
                UndoWord32ToWord64Conversion(V<Word64>::Cast(right)), kind,
                WordRepresentation::Word32());
          }
        }
      }
    }
    return Next::ReduceComparison(left, right, kind, rep);
  }

  OpIndex REDUCE(Shift)(OpIndex left, OpIndex right, ShiftOp::Kind kind,
                        WordRepresentation rep) {
    if (ShouldSkipOptimizationStep()) {
      return Next::ReduceShift(left, right, kind, rep);
    }

    if (rep == WordRepresentation::Word32()) {
      left = TryRemoveWord32ToWord64Conversion(left);
    }

    using Kind = ShiftOp::Kind;
    uint64_t c_unsigned;
    int64_t c_signed;
    if (matcher_.MatchIntegralWordConstant(left, rep, &c_unsigned, &c_signed)) {
      if (uint32_t amount;
          matcher_.MatchIntegralWord32Constant(right, &amount)) {
        amount = amount & (rep.bit_width() - 1);
        switch (kind) {
          case Kind::kShiftRightArithmeticShiftOutZeros:
            if (base::bits::CountTrailingZeros(c_signed) < amount) {
              // This assumes that we never hoist operations to before their
              // original place in the control flow.
              __ Unreachable();
              return OpIndex::Invalid();
            }
            [[fallthrough]];
          case Kind::kShiftRightArithmetic:
            switch (rep.value()) {
              case WordRepresentation::Word32():
                return __ Word32Constant(static_cast<int32_t>(c_signed) >>
                                         amount);
              case WordRepresentation::Word64():
                return __ Word64Constant(c_signed >> amount);
            }
          case Kind::kShiftRightLogical:
            switch (rep.value()) {
              case WordRepresentation::Word32():
                return __ Word32Constant(static_cast<uint32_t>(c_unsigned) >>
                                         amount);
              case WordRepresentation::Word64():
                return __ Word64Constant(c_unsigned >> amount);
            }
          case Kind::kShiftLeft:
            return __ WordConstant(c_unsigned << amount, rep);
          case Kind::kRotateRight:
            switch (rep.value()) {
              case WordRepresentation::Word32():
                return __ Word32Constant(base::bits::RotateRight32(
                    static_cast<uint32_t>(c_unsigned), amount));
              case WordRepresentation::Word64():
                return __ Word64Constant(
                    base::bits::RotateRight64(c_unsigned, amount));
            }
          case Kind::kRotateLeft:
            switch (rep.value()) {
              case WordRepresentation::Word32():
                return __ Word32Constant(base::bits::RotateLeft32(
                    static_cast<uint32_t>(c_unsigned), amount));
              case WordRepresentation::Word64():
                return __ Word64Constant(
                    base::bits::RotateLeft64(c_unsigned, amount));
            }
        }
      }
    }
    if (int32_t amount; matcher_.MatchIntegralWord32Constant(right, &amount) &&
                        0 <= amount && amount < rep.bit_width()) {
      if (amount == 0) {
        return left;
      }
      if (kind == Kind::kShiftLeft) {
        // If x >> K only shifted out zeros:
        // (x >> K) << L => x           if K == L
        // (x >> K) << L => x >> (K-L) if K > L
        // (x >> K) << L => x << (L-K)  if K < L
        // Since this is used for Smi untagging, we currently only need it for
        // signed shifts.
        int k;
        OpIndex x;
        if (matcher_.MatchConstantShift(
                left, &x, Kind::kShiftRightArithmeticShiftOutZeros, rep, &k)) {
          int32_t l = amount;
          if (k == l) {
            return x;
          } else if (k > l) {
            return __ ShiftRightArithmeticShiftOutZeros(
                x, __ Word32Constant(k - l), rep);
          } else if (k < l) {
            return __ ShiftLeft(x, __ Word32Constant(l - k), rep);
          }
        }
        // (x >>> K) << K => x & ~(2^K - 1)
        // (x >> K) << K => x & ~(2^K - 1)
        if (matcher_.MatchConstantRightShift(left, &x, rep, &k) &&
            k == amount) {
          return __ WordBitwiseAnd(
              x, __ WordConstant(rep.MaxUnsignedValue() << k, rep), rep);
        }
      }
      if (kind == any_of(Kind::kShiftRightArithmetic,
                         Kind::kShiftRightArithmeticShiftOutZeros)) {
        OpIndex x;
        int left_shift_amount;
        // (x << k) >> k
        if (matcher_.MatchConstantShift(left, &x, ShiftOp::Kind::kShiftLeft,
                                        rep, &left_shift_amount) &&
            amount == left_shift_amount) {
          // x << (bit_width - 1) >> (bit_width - 1)  =>  0 - x  if x is 0 or 1
          if (amount == rep.bit_width() - 1 && IsBit(x)) {
            return __ WordSub(__ WordConstant(0, rep), x, rep);
          }
          // x << (bit_width - 8) >> (bit_width - 8)  =>  x  if x is within Int8
          if (amount <= rep.bit_width() - 8 && IsInt8(x)) {
            return x;
          }
          // x << (bit_width - 8) >> (bit_width - 8)  =>  x  if x is within Int8
          if (amount <= rep.bit_width() - 16 && IsInt16(x)) {
            return x;
          }
        }
      }
      if (rep == WordRepresentation::Word32() &&
          SupportedOperations::word32_shift_is_safe()) {
        // Remove the explicit 'and' with 0x1F if the shift provided by the
        // machine instruction matcher_.Matches that required by JavaScript.
        if (V<Word32> a, b; matcher_.MatchBitwiseAnd(
                right, &a, &b, WordRepresentation::Word32())) {
#if defined(__clang__)
          static_assert(0x1f == WordRepresentation::Word32().bit_width() - 1);
#endif
          if (uint32_t b_value;
              matcher_.MatchIntegralWord32Constant(b, &b_value) &&
              b_value == 0x1f) {
            return __ Shift(left, a, kind, rep);
          }
        }
      }
    }
    return Next::ReduceShift(left, right, kind, rep);
  }

  OpIndex REDUCE(Branch)(OpIndex condition, Block* if_true, Block* if_false,
                         BranchHint hint) {
    LABEL_BLOCK(no_change) {
      return Next::ReduceBranch(condition, if_true, if_false, hint);
    }
    if (ShouldSkipOptimizationStep()) goto no_change;

    // Try to replace the Branch by a Goto.
    if (std::optional<bool> decision = MatchBoolConstant(condition)) {
      __ Goto(*decision ? if_true : if_false);
      return OpIndex::Invalid();
    }

    // Try to simplify the Branch's condition (eg, `if (x == 0) A else B` can
    // become `if (x) B else A`).
    bool negated = false;
    if (std::optional<OpIndex> new_condition =
            ReduceBranchCondition(condition, &negated)) {
      if (negated) {
        std::swap(if_true, if_false);
        hint = NegateBranchHint(hint);
      }

      return __ ReduceBranch(new_condition.value(), if_true, if_false, hint);
    }

    goto no_change;
  }

  V<None> REDUCE(DeoptimizeIf)(V<Word32> condition, V<FrameState> frame_state,
                               bool negated,
                               const DeoptimizeParameters* parameters) {
    if (ShouldSkipOptimizationStep()) {
      return Next::ReduceDeoptimizeIf(condition, frame_state, negated,
                                      parameters);
    }
    if (std::optional<bool> decision = MatchBoolConstant(condition)) {
      if (*decision != negated) {
        __ Deoptimize(frame_state, parameters);
      }
      // `DeoptimizeIf` doesn't produce a value.
      return OpIndex::Invalid();
    }
    if (std::optional<V<Word32>> new_condition =
            ReduceBranchCondition(condition, &negated)) {
      return __ ReduceDeoptimizeIf(new_condition.value(), frame_state, negated,
                                   parameters);
    } else {
      return Next::ReduceDeoptimizeIf(condition, frame_state, negated,
                                      parameters);
    }
  }

#if V8_ENABLE_WEBASSEMBLY
  V<None> REDUCE(TrapIf)(V<Word32> condition, OptionalV<FrameState> frame_state,
                         bool negated, TrapId trap_id) {
    LABEL_BLOCK(no_change) {
      return Next::ReduceTrapIf(condition, frame_state, negated, trap_id);
    }
    if (ShouldSkipOptimizationStep()) goto no_change;
    if (std::optional<bool> decision = MatchBoolConstant(condition)) {
      if (*decision != negated) {
        Next::ReduceTrapIf(condition, frame_state, negated, trap_id);
        __ Unreachable();
      }
      // `TrapIf` doesn't produce a value.
      return V<None>::Invalid();
    }
    if (std::optional<V<Word32>> new_condition =
            ReduceBranchCondition(condition, &negated)) {
      return __ ReduceTrapIf(new_condition.value(), frame_state, negated,
                             trap_id);
    } else {
      goto no_change;
    }
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  V<Any> REDUCE(Select)(V<Word32> cond, V<Any> vtrue, V<Any> vfalse,
                        RegisterRepresentation rep, BranchHint hint,
                        SelectOp::Implementation implem) {
    LABEL_BLOCK(no_change) {
      return Next::ReduceSelect(cond, vtrue, vfalse, rep, hint, implem);
    }
    if (ShouldSkipOptimizationStep()) goto no_change;

    // Try to remove the Select.
    if (std::optional<bool> decision = MatchBoolConstant(cond)) {
      return *decision ? vtrue : vfalse;
    }

    goto no_change;
  }

  V<None> REDUCE(StaticAssert)(V<Word32> condition, const char* source) {
    LABEL_BLOCK(no_change) {
      return Next::ReduceStaticAssert(condition, source);
    }
    if (std::optional<bool> decision = MatchBoolConstant(condition)) {
      if (*decision) {
        // Drop the assert, the condition holds true.
        return OpIndex::Invalid();
      } else {
        // Leave the assert, as the condition is not true.
        goto no_change;
      }
    }
    goto no_change;
  }

  V<None> REDUCE(Switch)(V<Word32> input, base::Vector<SwitchOp::Case> cases,
                         Block* default_case, BranchHint default_hint) {
    LABEL_BLOCK(no_change) {
      return Next::ReduceSwitch(input, cases, default_case, default_hint);
    }
    if (ShouldSkipOptimizationStep()) goto no_change;
    if (int32_t value; matcher_.MatchIntegralWord32Constant(input, &value)) {
      for (const SwitchOp::Case& if_value : cases) {
        if (if_value.value == value) {
          __ Goto(if_value.destination);
          return {};
        }
      }
      __ Goto(default_case);
      return {};
    }
    goto no_change;
  }

  OpIndex REDUCE(Store)(OpIndex base_idx, OptionalOpIndex index, OpIndex value,
                        StoreOp::Kind kind, MemoryRepresentation stored_rep,
                        WriteBarrierKind write_barrier, int32_t offset,
                        uint8_t element_scale,
                        bool maybe_initializing_or_transitioning,
                        IndirectPointerTag maybe_indirect_pointer_tag) {
    LABEL_BLOCK(no_change) {
      return Next::ReduceStore(base_idx, index, value, kind, stored_rep,
                               write_barrier, offset, element_scale,
                               maybe_initializing_or_transitioning,
                               maybe_indirect_pointer_tag);
    }
    if (ShouldSkipOptimizationStep()) goto no_change;
#if V8_TARGET_ARCH_32_BIT
    if (kind.is_atomic && stored_rep.SizeInBytes() == 8) {
      // AtomicWord32PairOp (as used by Int64Lowering) cannot handle
      // element_scale != 0 currently.
      // TODO(jkummerow): Add support for element_scale in AtomicWord32PairOp.
      goto no_change;
    }
#endif
    if (stored_rep.SizeInBytes() <= 4) {
      value = TryRemoveWord32ToWord64Conversion(value);
    }
    index = ReduceMemoryIndex(index.value_or_invalid(), &offset, &element_scale,
                              kind.tagged_base);
    switch (stored_rep) {
      case MemoryRepresentation::Uint8():
      case MemoryRepresentation::Int8():
        value = ReduceWithTruncation(value, std::numeric_limits<uint8_t>::max(),
                                     WordRepresentation::Word32());
        break;
      case MemoryRepresentation::Uint16():
      case MemoryRepresentation::Int16():
        value =
            ReduceWithTruncation(value, std::numeric_limits<uint16_t>::max(),
                                 WordRepresentation::Word32());
        break;
      case MemoryRepresentation::Uint32():
      case MemoryRepresentation::Int32():
        value =
            ReduceWithTruncation(value, std::numeric_limits<uint32_t>::max(),
                                 WordRepresentation::Word32());
        break;
      default:
        break;
    }

    // If index is invalid and base is `left+right`, we use `left` as base and
    // `right` as index.
    if (!index.valid() && matcher_.Is<Opmask::kWord64Add>(base_idx)) {
      DCHECK_EQ(element_scale, 0);
      const WordBinopOp& base = matcher_.Cast<WordBinopOp>(base_idx);
      base_idx = base.left();
      index = base.right();
      // We go through the Store stack again, which might merge {index} into
      // {offset}, or just do other optimizations on this Store.
      __ Store(base_idx, index, value, kind, stored_rep, write_barrier, offset,
               element_scale, maybe_initializing_or_transitioning,
               maybe_indirect_pointer_tag);
      return OpIndex::Invalid();
    }

    return Next::ReduceStore(base_idx, index, value, kind, stored_rep,
                             write_barrier, offset, element_scale,
                             maybe_initializing_or_transitioning,
                             maybe_indirect_pointer_tag);
  }

  OpIndex REDUCE(Load)(OpIndex base_idx, OptionalOpIndex index,
                       LoadOp::Kind kind, MemoryRepresentation loaded_rep,
                       RegisterRepresentation result_rep, int32_t offset,
                       uint8_t element_scale) {
    LABEL_BLOCK(no_change) {
      return Next::ReduceLoad(base_idx, index, kind, loaded_rep, result_rep,
                              offset, element_scale);
    }
    if (ShouldSkipOptimizationStep()) goto no_change;
#if V8_TARGET_ARCH_32_BIT
    if (kind.is_atomic && loaded_rep.SizeInBytes() == 8) {
      // AtomicWord32PairOp (as used by Int64Lowering) cannot handle
      // element_scale != 0 currently.
      // TODO(jkummerow): Add support for element_scale in AtomicWord32PairOp.
      goto no_change;
    }
#endif

    while (true) {
      index = ReduceMemoryIndex(index.value_or_invalid(), &offset,
                                &element_scale, kind.tagged_base);
      if (!kind.tagged_base && !index.valid()) {
        if (V<WordPtr> left, right;
            matcher_.MatchWordAdd(base_idx, &left, &right,
                                  WordRepresentation::WordPtr()) &&
            TryAdjustOffset(&offset, matcher_.Get(right), element_scale,
                            kind.tagged_base)) {
          base_idx = left;
          continue;
        }
      }
      break;
    }

    if (!index.valid() && matcher_.Is<ConstantOp>(base_idx)) {
      const ConstantOp& base = matcher_.Cast<ConstantOp>(base_idx);
      if (base.kind == any_of(ConstantOp::Kind::kHeapObject,
                              ConstantOp::Kind::kCompressedHeapObject)) {
        if (offset == HeapObject::kMapOffset) {
          // Only few loads should be loading the map from a ConstantOp
          // HeapObject, so unparking the JSHeapBroker here rather than before
          // the optimization pass itself it probably more efficient.

          DCHECK_IMPLIES(
              __ data()->pipeline_kind() != TurboshaftPipelineKind::kCSA,
              broker != nullptr);
          if (broker != nullptr) {
            UnparkedScopeIfNeeded scope(broker);
            AllowHandleDereference allow_handle_dereference;
            OptionalMapRef map = TryMakeRef(broker, base.handle()->map());
            if (MapLoadCanBeConstantFolded(map)) {
              return __ HeapConstant(map->object());
            }
          }
        }
        // TODO(dmercadier): consider constant-folding other accesses, in
        // particular for constant objects (ie, if
        // base.handle()->InReadOnlySpace() is true). We have to be a bit
        // careful though, because loading could be invalid (since we could
        // be in unreachable code). (all objects have a map, so loading the map
        // should always be safe, regardless of whether we are generating
        // unreachable code or not)
      }
    }

    // If index is invalid and base is `left+right`, we use `left` as base and
    // `right` as index.
    if (!index.valid() && matcher_.Is<Opmask::kWord64Add>(base_idx)) {
      DCHECK_EQ(element_scale, 0);
      const WordBinopOp& base = matcher_.Cast<WordBinopOp>(base_idx);
      base_idx = base.left();
      index = base.right();
      // We go through the Load stack again, which might merge {index} into
      // {offset}, or just do other optimizations on this Load.
      return __ Load(base_idx, index, kind, loaded_rep, result_rep, offset,
                     element_scale);
    }

    return Next::ReduceLoad(base_idx, index, kind, loaded_rep, result_rep,
                            offset, element_scale);
  }

#if V8_ENABLE_WEBASSEMBLY
#ifdef V8_TARGET_ARCH_ARM64
  V<Any> REDUCE(Simd128ExtractLane)(V<Simd128> input,
                                    Simd128ExtractLaneOp::Kind kind,
                                    uint8_t lane) {
    LABEL_BLOCK(no_change) {
      return Next::ReduceSimd128ExtractLane(input, kind, lane);
    }
    if (ShouldSkipOptimizationStep()) goto no_change;

    // Turbofan and the RecreateSchedulePhase don't support the optimized
    // reduce operation.
    if (!v8_flags.turboshaft_wasm_instruction_selection_staged) goto no_change;

    if (lane != 0) {
      goto no_change;
    }

    const Simd128BinopOp* binop = matcher_.TryCast<Simd128BinopOp>(input);
    if (!binop) {
      goto no_change;
    }

    // Support pairwise addition: int and fp.
    switch (binop->kind) {
      default:
        goto no_change;
      case Simd128BinopOp::Kind::kI8x16Add:
      case Simd128BinopOp::Kind::kI16x8Add:
      case Simd128BinopOp::Kind::kI32x4Add:
      case Simd128BinopOp::Kind::kF32x4Add:
      case Simd128BinopOp::Kind::kI64x2Add:
      case Simd128BinopOp::Kind::kF64x2Add:
        break;
    }

    auto MatchUnaryShuffle =
        [this](V<Simd128> maybe_shuffle) -> const Simd128ShuffleOp* {
      if (const Simd128ShuffleOp* shuffle =
              matcher_.TryCast<Simd128ShuffleOp>(maybe_shuffle)) {
        if (shuffle->left() == shuffle->right()) {
          return shuffle;
        }
      }
      return nullptr;
    };

    auto MatchBinop =
        [this](
            V<Simd128> maybe_binop,
            Simd128BinopOp::Kind required_binop_kind) -> const Simd128BinopOp* {
      if (const Simd128BinopOp* binop =
              matcher_.TryCast<Simd128BinopOp>(maybe_binop)) {
        if (required_binop_kind == binop->kind) {
          return binop;
        }
      }
      return nullptr;
    };

    // We're going to look for vector reductions performed with
    // shuffles and binops. The TS operations are defined as pairwise
    // to map well onto hardware, although the ordering is only
    // important for FP operations. For an example of the Word32
    // UpperToLower case:
    //
    // input    = (V<Simd128>)
    // shuffle1 = (Simd128ShuffleOp input, input, [ 2, 3, X, X])
    // add1     = (Simd128BinopOp input, shuffle1)
    // shuffle2 = (Simd128ShuffleOp add1, add1, [1, X, X, X])
    // add2     = (Simd128BinopOp add1, shuffle2)
    // result   = (ExtractLaneOp add2, 0)

    // Walk up from binop to discover the tree of binops and shuffles:
    // (extract (binop (binop (reduce_input), shuffle), shuffle), 0)
    base::SmallVector<const Simd128ShuffleOp*, 4> shuffles;
    base::SmallVector<const Simd128BinopOp*, 4> binops;
    binops.push_back(binop);
    while (!binops.empty()) {
      const Simd128BinopOp* binop = binops.back();
      binops.pop_back();
      V<Simd128> operands[2] = {binop->left(), binop->right()};
      for (unsigned i = 0; i < 2; ++i) {
        V<Simd128> operand = operands[i];
        if (const Simd128ShuffleOp* shuffle = MatchUnaryShuffle(operand)) {
          // Ensure that the input to the shuffle is also the other input to
          // current binop.
          V<Simd128> shuffle_in = shuffle->left();
          DCHECK_EQ(shuffle_in, shuffle->right());
          V<Simd128> other_operand = operands[i ^ 1];
          if (shuffle_in != other_operand) {
            break;
          }
          shuffles.push_back(shuffle);
          if (const Simd128BinopOp* other_binop =
                  MatchBinop(shuffle_in, binop->kind)) {
            binops.push_back(other_binop);
            break;
          }
        }
      }
    }
    if (shuffles.empty()) {
      goto no_change;
    }

    // Reverse so that they're in execution order, just for readability.
    std::reverse(shuffles.begin(), shuffles.end());
    V<Simd128> reduce_input = shuffles.front()->left();
    MachineRepresentation rep = Simd128ExtractLaneOp::element_rep(kind);
    switch (rep) {
      default:
        goto no_change;
      case MachineRepresentation::kWord8: {
        if (shuffles.size() == 4) {
          const uint8_t* shuffle1 = shuffles[0]->shuffle;
          const uint8_t* shuffle2 = shuffles[1]->shuffle;
          const uint8_t* shuffle3 = shuffles[2]->shuffle;
          const uint8_t* shuffle4 = shuffles[3]->shuffle;
          if (wasm::SimdShuffle::TryMatch8x16UpperToLowerReduce(
                  shuffle1, shuffle2, shuffle3, shuffle4)) {
            V<Simd128> reduce = __ Simd128Reduce(
                reduce_input, Simd128ReduceOp::Kind::kI8x16AddReduce);
            return __ Simd128ExtractLane(reduce, kind, 0);
          }
        }
        break;
      }
      case MachineRepresentation::kWord16: {
        if (shuffles.size() == 3) {
          const uint8_t* shuffle1 = shuffles[0]->shuffle;
          const uint8_t* shuffle2 = shuffles[1]->shuffle;
          const uint8_t* shuffle3 = shuffles[2]->shuffle;
          if (wasm::SimdShuffle::TryMatch16x8UpperToLowerReduce(
                  shuffle1, shuffle2, shuffle3)) {
            V<Simd128> reduce = __ Simd128Reduce(
                reduce_input, Simd128ReduceOp::Kind::kI16x8AddReduce);
            return __ Simd128ExtractLane(reduce, kind, 0);
          }
        }
        break;
      }
      case MachineRepresentation::kWord32: {
        if (shuffles.size() == 2) {
          const uint8_t* shuffle1 = shuffles[0]->shuffle;
          const uint8_t* shuffle2 = shuffles[1]->shuffle;
          if (wasm::SimdShuffle::TryMatch32x4UpperToLowerReduce(shuffle1,
                                                                shuffle2)) {
            V<Simd128> reduce = __ Simd128Reduce(
                reduce_input, Simd128ReduceOp::Kind::kI32x4AddReduce);
            return __ Simd128ExtractLane(reduce, kind, 0);
          }
        }
        break;
      }
      case MachineRepresentation::kFloat32: {
        if (shuffles.size() == 2) {
          const uint8_t* shuffle1 = shuffles[0]->shuffle;
          const uint8_t* shuffle2 = shuffles[1]->shuffle;
          if (wasm::SimdShuffle::TryMatch32x4PairwiseReduce(shuffle1,
                                                            shuffle2)) {
            V<Simd128> reduce = __ Simd128Reduce(
                reduce_input, Simd128ReduceOp::Kind::kF32x4AddReduce);
            return __ Simd128ExtractLane(reduce, kind, 0);
          }
        }
        break;
      }
      case MachineRepresentation::kWord64:
      case MachineRepresentation::kFloat64: {
        if (shuffles.size() == 1) {
          uint8_t shuffle64x2[2];
          if (wasm::SimdShuffle::TryMatch64x2Shuffle(shuffles[0]->shuffle,
                                                     shuffle64x2) &&
              wasm::SimdShuffle::TryMatch64x2Reduce(shuffle64x2)) {
            V<Simd128> reduce =
                rep == MachineRepresentation::kWord64
                    ? __ Simd128Reduce(reduce_input,
                                       Simd128ReduceOp::Kind::kI64x2AddReduce)
                    : __ Simd128Reduce(reduce_input,
                                       Simd128ReduceOp::Kind::kF64x2AddReduce);
            return __ Simd128ExtractLane(reduce, kind, 0);
          }
        }
        break;
      }
    }
    goto no_change;
  }
#endif  // V8_TARGET_ARCH_ARM64
#endif  // V8_ENABLE_WEBASSEMBLY

 private:
  V<Word32> ReduceCompareEqual(V<Any> left, V<Any> right,
                               RegisterRepresentation rep) {
    if (left == right && !rep.IsFloat()) {
      return __ Word32Constant(1);
    }
    if (rep == WordRepresentation::Word32()) {
      left = TryRemoveWord32ToWord64Conversion(V<Word>::Cast(left));
      right = TryRemoveWord32ToWord64Conversion(V<Word>::Cast(right));
    }
    if (matcher_.Is<ConstantOp>(left) && !matcher_.Is<ConstantOp>(right)) {
      return ReduceCompareEqual(right, left, rep);
    }
    if (matcher_.Is<ConstantOp>(right)) {
      if (matcher_.Is<ConstantOp>(left)) {
        // k1 == k2  =>  k
        switch (rep.value()) {
          case RegisterRepresentation::Word32():
          case RegisterRepresentation::Word64(): {
            if (uint64_t k1, k2; matcher_.MatchIntegralWordConstant(
                                     left, WordRepresentation(rep), &k1) &&
                                 matcher_.MatchIntegralWordConstant(
                                     right, WordRepresentation(rep), &k2)) {
              return __ Word32Constant(k1 == k2);
            }
            break;
          }
          case RegisterRepresentation::Float32(): {
            if (float k1, k2; matcher_.MatchFloat32Constant(left, &k1) &&
                              matcher_.MatchFloat32Constant(right, &k2)) {
              return __ Word32Constant(k1 == k2);
            }
            break;
          }
          case RegisterRepresentation::Float64(): {
            if (double k1, k2; matcher_.MatchFloat64Constant(left, &k1) &&
                               matcher_.MatchFloat64Constant(right, &k2)) {
              return __ Word32Constant(k1 == k2);
            }
            break;
          }
          case RegisterRepresentation::Tagged(): {
            if (Handle<HeapObject> o1, o2;
                matcher_.MatchHeapConstant(left, &o1) &&
                matcher_.MatchHeapConstant(right, &o2)) {
              UnparkedScopeIfNeeded unparked(broker);
              if (IsString(*o1) && IsString(*o2)) {
                // If handles refer to the same object, we can eliminate the
                // check.
                if (o1.address() == o2.address()) return __ Word32Constant(1);
                // But if they are different, we cannot eliminate the
                // comparison, because the objects might be different now, but
                // if they contain the same content, they might be internalized
                // to the same object eventually.
                break;
              }
              return __ Word32Constant(o1.address() == o2.address());
            }
            break;
          }
          default:
            UNREACHABLE();
        }
      }
      if (rep.IsWord()) {
        WordRepresentation rep_w{rep};
        // x - y == 0  =>  x == y
        if (V<Word> x, y; matcher_.MatchWordSub(left, &x, &y, rep_w) &&
                          matcher_.MatchZero(right)) {
          return ReduceCompareEqual(x, y, rep);
        }
        {
          //     ((x >> shift_amount) & mask) == k
          // =>  (x & (mask << shift_amount)) == (k << shift_amount)
          V<Word> shift, x, mask_op;
          int shift_amount;
          uint64_t mask, k;
          if (matcher_.MatchBitwiseAnd(left, &shift, &mask_op, rep_w) &&
              matcher_.MatchConstantRightShift(shift, &x, rep_w,
                                               &shift_amount) &&
              matcher_.MatchIntegralWordConstant(mask_op, rep_w, &mask) &&
              matcher_.MatchIntegralWordConstant(right, rep_w, &k) &&
              mask <= rep.MaxUnsignedValue() >> shift_amount &&
              k <= rep.MaxUnsignedValue() >> shift_amount) {
            return ReduceCompareEqual(
                __ WordBitwiseAnd(
                    x, __ WordConstant(mask << shift_amount, rep_w), rep_w),
                __ WordConstant(k << shift_amount, rep_w), rep_w);
          }
        }
        {
          // (x >> k1) == k2  =>  x == (k2 << k1)  if shifts reversible
          // Only perform the transformation if the shift is not used yet, to
          // avoid keeping both the shift and x alive.
          V<Word> x;
          uint16_t k1;
          int64_t k2;
          if (matcher_.MatchConstantShiftRightArithmeticShiftOutZeros(
                  left, &x, rep_w, &k1) &&
              matcher_.MatchIntegralWordConstant(right, rep_w, &k2) &&
              CountLeadingSignBits(k2, rep_w) > k1 &&
              matcher_.Get(left).saturated_use_count.IsZero()) {
            return __ Equal(
                x, __ WordConstant(base::bits::Unsigned(k2) << k1, rep_w),
                rep_w);
          }
        }
        // Map 64bit to 32bit equals.
        if (rep_w == WordRepresentation::Word64()) {
          std::optional<bool> left_sign_extended;
          std::optional<bool> right_sign_extended;
          if (IsWord32ConvertedToWord64(left, &left_sign_extended) &&
              IsWord32ConvertedToWord64(right, &right_sign_extended)) {
            if (left_sign_extended == right_sign_extended) {
              return __ Equal(
                  UndoWord32ToWord64Conversion(V<Word64>::Cast(left)),
                  UndoWord32ToWord64Conversion(V<Word64>::Cast(right)),
                  WordRepresentation::Word32());
            }
          }
        }
      }
    }
    return Next::ReduceComparison(left, right, ComparisonOp::Kind::kEqual, rep);
  }

  // Try to match a constant and add it to `offset`. Return `true` if
  // successful.
  bool TryAdjustOffset(int32_t* offset, const Operation& maybe_constant,
                       uint8_t element_scale, bool tagged_base) {
    if (!maybe_constant.Is<ConstantOp>()) return false;
    const ConstantOp& constant = maybe_constant.Cast<ConstantOp>();
    if (constant.rep != WordRepresentation::WordPtr() ||
        !constant.IsIntegral()) {
      // This can only happen in unreachable code. Ideally, we identify this
      // situation and use `__ Unreachable()`. However, this is difficult to
      // do from within this helper, so we just don't perform the reduction.
      return false;
    }
    int64_t diff = constant.signed_integral();
    int32_t new_offset;
    if (element_scale > 31) return false;
    if (diff <= (std::numeric_limits<int32_t>::max() >> element_scale) &&
        diff >= (std::numeric_limits<int32_t>::min() >> element_scale) &&
        !base::bits::SignedAddOverflow32(
            *offset,
            static_cast<int32_t>(base::bits::Unsigned(diff) << element_scale),
            &new_offset) &&
        LoadOp::OffsetIsValid(new_offset, tagged_base)) {
      *offset = new_offset;
      return true;
    }
    return false;
  }

  bool TryAdjustIndex(int32_t offset, OpIndex* index,
                      const Operation& maybe_constant, uint8_t element_scale) {
    if (!maybe_constant.Is<ConstantOp>()) return false;
    const ConstantOp& constant = maybe_constant.Cast<ConstantOp>();
    if (constant.rep != WordRepresentation::WordPtr() ||
        !constant.IsIntegral()) {
      // This can only happen in unreachable code. Ideally, we identify this
      // situation and use `__ Unreachable()`. However, this is difficult to
      // do from within this helper, so we just don't perform the reduction.
      return false;
    }
    int64_t diff = constant.signed_integral();
    int64_t new_index;
    if (!base::bits::SignedAddOverflow64(offset, diff << el
"""


```