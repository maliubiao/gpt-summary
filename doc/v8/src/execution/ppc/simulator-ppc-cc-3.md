Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of the V8 JavaScript engine's simulator for the PowerPC architecture. I need to:

1. **Identify the main purpose:** The code simulates the execution of individual PowerPC instructions.
2. **List the supported instruction types:**  The `switch` statement and `case` labels clearly show which instructions are handled. These fall into categories like arithmetic, logical, memory access, and floating-point operations.
3. **Determine if it's Torque code:**  The filename doesn't end with `.tq`, so it's not Torque.
4. **Check for JavaScript relevance:** As a CPU simulator for V8, it directly enables the execution of JavaScript code on a simulated PowerPC architecture.
5. **Provide a JavaScript example:** A simple arithmetic operation in JavaScript can be used to illustrate the kind of functionality this code makes possible at a lower level.
6. **Give an example of code logic inference:**  Choose a simple instruction like `ADD` and show how the simulator processes it with example inputs and outputs.
7. **Illustrate common programming errors:** Focus on errors that arise from misunderstanding CPU architecture details, like integer overflow.
8. **Summarize the overall function:**  Reiterate that it simulates PowerPC instructions for the V8 engine.
这是目录为v8/src/execution/ppc/simulator-ppc.cc的一个v8源代码， 它的功能是**模拟PowerPC架构的CPU指令执行**。

这个代码片段展示了`ExecuteInstruction`函数中的一部分，该函数负责根据给定的指令`instr`的类型（由`opcode`决定）来模拟其行为。  它涵盖了多种PowerPC指令，包括：

* **算术运算:**  如 `ADD`, `SUBF`, `MULLW`, `MULLD`, `DIVW`, `DIVWU`, `DIVD`, `DIVDU` （加法、减法、乘法、除法，带符号和无符号，字和双字）。
* **逻辑运算:** 如 `XORX`, `ORX`, `ORC` (异或、或、或非)。
* **寄存器操作:** 如 `MFSPR` (将特殊寄存器移到通用寄存器), `MTSPR` (将通用寄存器移到特殊寄存器), `MFCR` (将条件寄存器移到通用寄存器)。
* **内存访问:** 如 `STWUX`, `STWX`, `STBUX`, `STBX`, `STHUX`, `STHX`, `LWZX`, `LWZUX`, `LWAX`, `LDX`, `LDUX`, `LDBRX`, `LWBRX`, `STDBRX`, `STWBRX`, `STHBRX`, `STDX`, `STDUX`, `LBZX`, `LBZUX`, `LHZX`, `LHZUX`, `LHAX`, `LBARX`, `LHARX`, `LWARX`, `LDARX` (存储字、字节、半字、双字，加载字、字节、半字、双字，带更新和不带更新)。
* **浮点运算:** 如 `FCFIDS`, `FCFIDUS`, `FDIV`, `FSUB`, `FADD`, `FSQRT`, `FSEL`, `FMUL`, `FMSUB`, `FMADD`, `FCMPU`, `FRIN`, `FRIZ`, `FRIP`, `FRIM`, `FRSP`, `FCFID`, `FCFIDU`, `FCTID`, `FCTIDZ`, `FCTIDU`, `FCTIDUZ`, `FCTIW`, `FCTIWZ`, `FCTIWU`, `FCTIWUZ`, `FNEG`, `FCPSGN`, `FMR`, `MTFSFI`, `MTFSF`, `MFFS`, `MCRFS` (浮点数的转换、除法、减法、加法、平方根、选择、乘法、乘减、乘加、比较、舍入操作、取反、复制符号、移动、设置浮点状态与控制寄存器、移动浮点状态)。
* **其他:** 如 `ISEL` (条件选择), `DCBF` (数据缓存块刷新), `BRW`, `BRD` (字节反转)。

**如果v8/src/execution/ppc/simulator-ppc.cc以.tq结尾，那它是个v8 torque源代码**

这个文件的确是以 `.cc` 结尾，所以它是一个 C++ 源代码文件，而不是 Torque 源代码。 Torque 文件通常用于定义 V8 内部的 Builtins 函数。

**如果它与javascript的功能有关系，请用javascript举例说明**

是的，`v8/src/execution/ppc/simulator-ppc.cc` 与 JavaScript 的功能有直接关系。  V8 引擎需要在不同的 CPU 架构上运行 JavaScript 代码。 当 V8 运行在 PowerPC 架构的机器上，或者在一个模拟 PowerPC 架构的环境中时，这个文件中的代码就负责模拟 PowerPC 的指令执行，从而使得 V8 能够执行 JavaScript 代码。

例如，考虑以下简单的 JavaScript 代码：

```javascript
let a = 5;
let b = 10;
let sum = a + b;
console.log(sum);
```

当 V8 在 PowerPC 架构上执行这段代码时，加法运算 `a + b` 会被编译成 PowerPC 的机器指令，例如 `ADD` 指令。  `v8/src/execution/ppc/simulator-ppc.cc` 中的 `case ADDX:` 部分的代码就负责模拟这条 `ADD` 指令的执行过程：从寄存器中读取 `a` 和 `b` 的值，进行加法运算，并将结果存储到另一个寄存器中。

**如果有代码逻辑推理，请给出假设输入与输出**

假设我们执行以下 PowerPC 指令 (以伪代码表示，实际指令会是二进制编码):

```assembly
ADDX r3, r1, r2  // 将寄存器 r1 和 r2 的值相加，结果存入 r3
```

并且假设在执行这条指令之前：

* 寄存器 `r1` 的值为 `5` (十进制)。
* 寄存器 `r2` 的值为 `10` (十进制)。

根据 `v8/src/execution/ppc/simulator-ppc.cc` 中的 `ADDX` 的 `case` 分支：

* `rt = instr->RTValue();` 会得到目标寄存器 `r3`。
* `ra = instr->RAValue();` 会得到源寄存器 `r1`。
* `rb = instr->RBValue();` 会得到源寄存器 `r2`。
* `intptr_t ra_val = get_register(ra);` 会从模拟的寄存器文件中读取 `r1` 的值，即 `5`。
* `intptr_t rb_val = get_register(rb);` 会从模拟的寄存器文件中读取 `r2` 的值，即 `10`。
* `intptr_t alu_out = ra_val + rb_val;` 计算结果 `5 + 10 = 15`。
* `set_register(rt, alu_out);` 将结果 `15` 写入模拟的寄存器 `r3`。

**假设输入:**  执行 `ADDX r3, r1, r2` 指令前，`r1 = 5`, `r2 = 10`。
**输出:** 执行 `ADDX r3, r1, r2` 指令后，`r3 = 15`。

**如果涉及用户常见的编程错误，请举例说明**

在低级编程中，尤其是在进行类似 CPU 指令模拟时，一些常见的错误与对数据类型和溢出的理解不足有关。  例如，考虑 `MULLW` (字乘法) 指令：

```assembly
MULLW r3, r1, r2  // 将寄存器 r1 和 r2 的值相乘（字），结果存入 r3
```

假设在 JavaScript 中，我们有类似的操作，但 JavaScript 会自动处理大整数：

```javascript
let a = 2147483647; // 32位有符号整数的最大值
let b = 2;
let product = a * b;
console.log(product); // 输出 4294967294
```

但在 PowerPC 的 `MULLW` 指令中，如果寄存器 `r1` 和 `r2` 存储的是 32 位有符号整数，并且它们的乘积超出了 32 位有符号整数的范围，就会发生溢出。  `v8/src/execution/ppc/simulator-ppc.cc` 中的 `MULLW` 的 `case` 分支虽然进行了乘法运算，但它模拟的是底层硬件的行为，**不会像 JavaScript 那样自动转换为更大的数据类型**。

**用户常见的编程错误 (如果直接操作或理解底层指令时):**

* **整数溢出:**  程序员可能没有意识到乘法结果会超出 32 位有符号整数的范围，导致结果不正确。 例如，如果 `r1 = 2147483647` 且 `r2 = 2`，则 `alu_out` 的值会发生溢出，其结果在 32 位有符号整数中可能是一个负数或一个较小的正数，而不是预期的 `4294967294`。
* **符号扩展问题:**  在不同的指令中，如何处理有符号数和无符号数可能会导致错误。 例如，在加载字节或半字时，没有正确理解是否进行了符号扩展，会导致读取的值不正确。
* **寄存器使用错误:**  错误地使用了寄存器，例如将结果写入了错误的寄存器，或者使用了未初始化的寄存器。

**这是第4部分，共6部分，请归纳一下它的功能**

总而言之，作为第 4 部分，这段 `v8/src/execution/ppc/simulator-ppc.cc` 代码的主要功能是 **V8 引擎在 PowerPC 架构上的指令级模拟器的一部分，负责模拟各种 PowerPC 指令的执行，包括算术运算、逻辑运算、寄存器操作、内存访问和浮点运算。**  它使得 V8 可以在 PowerPC 架构上运行 JavaScript 代码，即使实际的硬件可能不是 PowerPC，这对于开发、测试和调试 V8 在该架构上的行为至关重要。  它也展示了在底层 CPU 指令级别进行操作时需要考虑的细节，例如数据类型、溢出和寄存器使用。

### 提示词
```
这是目录为v8/src/execution/ppc/simulator-ppc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/ppc/simulator-ppc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(alu_out);
      }
      break;
    }
    case MULLW: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      int32_t ra_val = (get_register(ra) & 0xFFFFFFFF);
      int32_t rb_val = (get_register(rb) & 0xFFFFFFFF);
      int32_t alu_out = ra_val * rb_val;
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(alu_out);
      }
      // todo - handle OE bit
      break;
    }
    case MULLD: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      int64_t ra_val = get_register(ra);
      int64_t rb_val = get_register(rb);
      int64_t alu_out = ra_val * rb_val;
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(alu_out);
      }
      // todo - handle OE bit
      break;
    }
    case DIVW: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      int32_t ra_val = get_register(ra);
      int32_t rb_val = get_register(rb);
      bool overflow = (ra_val == kMinInt && rb_val == -1);
      // result is undefined if divisor is zero or if operation
      // is 0x80000000 / -1.
      int32_t alu_out = (rb_val == 0 || overflow) ? -1 : ra_val / rb_val;
      set_register(rt, alu_out);
      if (instr->Bit(10)) {  // OE bit set
        if (overflow) {
          special_reg_xer_ |= 0xC0000000;  // set SO,OV
        } else {
          special_reg_xer_ &= ~0x40000000;  // clear OV
        }
      }
      if (instr->Bit(0)) {  // RC bit set
        bool setSO = (special_reg_xer_ & 0x80000000);
        SetCR0(alu_out, setSO);
      }
      break;
    }
    case DIVWU: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      uint32_t ra_val = get_register(ra);
      uint32_t rb_val = get_register(rb);
      bool overflow = (rb_val == 0);
      // result is undefined if divisor is zero
      uint32_t alu_out = (overflow) ? -1 : ra_val / rb_val;
      set_register(rt, alu_out);
      if (instr->Bit(10)) {  // OE bit set
        if (overflow) {
          special_reg_xer_ |= 0xC0000000;  // set SO,OV
        } else {
          special_reg_xer_ &= ~0x40000000;  // clear OV
        }
      }
      if (instr->Bit(0)) {  // RC bit set
        bool setSO = (special_reg_xer_ & 0x80000000);
        SetCR0(alu_out, setSO);
      }
      break;
    }
    case DIVD: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      int64_t ra_val = get_register(ra);
      int64_t rb_val = get_register(rb);
      int64_t one = 1;  // work-around gcc
      int64_t kMinLongLong = (one << 63);
      // result is undefined if divisor is zero or if operation
      // is 0x80000000_00000000 / -1.
      int64_t alu_out =
          (rb_val == 0 || (ra_val == kMinLongLong && rb_val == -1))
              ? -1
              : ra_val / rb_val;
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(alu_out);
      }
      // todo - handle OE bit
      break;
    }
    case DIVDU: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      uint64_t ra_val = get_register(ra);
      uint64_t rb_val = get_register(rb);
      // result is undefined if divisor is zero
      uint64_t alu_out = (rb_val == 0) ? -1 : ra_val / rb_val;
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(alu_out);
      }
      // todo - handle OE bit
      break;
    }
    case ADDX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      // int oe = instr->Bit(10);
      intptr_t ra_val = get_register(ra);
      intptr_t rb_val = get_register(rb);
      intptr_t alu_out = ra_val + rb_val;
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(alu_out);
      }
      // todo - handle OE bit
      break;
    }
    case XORX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      intptr_t alu_out = rs_val ^ rb_val;
      set_register(ra, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(alu_out);
      }
      break;
    }
    case ORX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      intptr_t alu_out = rs_val | rb_val;
      set_register(ra, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(alu_out);
      }
      break;
    }
    case ORC: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      intptr_t alu_out = rs_val | ~rb_val;
      set_register(ra, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(alu_out);
      }
      break;
    }
    case MFSPR: {
      int rt = instr->RTValue();
      int spr = instr->Bits(20, 11);
      if (spr != 256) {
        UNIMPLEMENTED();  // Only LRLR supported
      }
      set_register(rt, special_reg_lr_);
      break;
    }
    case MTSPR: {
      int rt = instr->RTValue();
      intptr_t rt_val = get_register(rt);
      int spr = instr->Bits(20, 11);
      if (spr == 256) {
        special_reg_lr_ = rt_val;
      } else if (spr == 288) {
        special_reg_ctr_ = rt_val;
      } else if (spr == 32) {
        special_reg_xer_ = rt_val;
      } else {
        UNIMPLEMENTED();  // Only LR supported
      }
      break;
    }
    case MFCR: {
      int rt = instr->RTValue();
      set_register(rt, condition_reg_);
      break;
    }
    case STWUX:
    case STWX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int32_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      WriteW(ra_val + rb_val, rs_val);
      if (opcode == STWUX) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + rb_val);
      }
      break;
    }
    case STBUX:
    case STBX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int8_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      WriteB(ra_val + rb_val, rs_val);
      if (opcode == STBUX) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + rb_val);
      }
      break;
    }
    case STHUX:
    case STHX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int16_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      WriteH(ra_val + rb_val, rs_val);
      if (opcode == STHUX) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + rb_val);
      }
      break;
    }
    case LWZX:
    case LWZUX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      set_register(rt, ReadWU(ra_val + rb_val));
      if (opcode == LWZUX) {
        DCHECK(ra != 0 && ra != rt);
        set_register(ra, ra_val + rb_val);
      }
      break;
    }
    case LWAX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      set_register(rt, ReadW(ra_val + rb_val));
      break;
    }
    case LDX:
    case LDUX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      intptr_t result = ReadDW(ra_val + rb_val);
      set_register(rt, result);
      if (opcode == LDUX) {
        DCHECK(ra != 0 && ra != rt);
        set_register(ra, ra_val + rb_val);
      }
      break;
    }
    case LDBRX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      intptr_t result = ByteReverse<int64_t>(ReadDW(ra_val + rb_val));
      set_register(rt, result);
      break;
    }
    case LWBRX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      intptr_t result = ByteReverse<int32_t>(ReadW(ra_val + rb_val));
      set_register(rt, result);
      break;
    }
    case STDBRX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      WriteDW(ra_val + rb_val, ByteReverse<int64_t>(rs_val));
      break;
    }
    case STWBRX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      WriteW(ra_val + rb_val, ByteReverse<int32_t>(rs_val));
      break;
    }
    case STHBRX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      WriteH(ra_val + rb_val, ByteReverse<int16_t>(rs_val));
      break;
    }
    case STDX:
    case STDUX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      WriteDW(ra_val + rb_val, rs_val);
      if (opcode == STDUX) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + rb_val);
      }
      break;
    }
    case LBZX:
    case LBZUX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      set_register(rt, ReadBU(ra_val + rb_val) & 0xFF);
      if (opcode == LBZUX) {
        DCHECK(ra != 0 && ra != rt);
        set_register(ra, ra_val + rb_val);
      }
      break;
    }
    case LHZX:
    case LHZUX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      set_register(rt, ReadHU(ra_val + rb_val) & 0xFFFF);
      if (opcode == LHZUX) {
        DCHECK(ra != 0 && ra != rt);
        set_register(ra, ra_val + rb_val);
      }
      break;
    }
    case LHAX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      set_register(rt, ReadH(ra_val + rb_val));
      break;
    }
    case LBARX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      set_register(rt, ReadExBU(ra_val + rb_val) & 0xFF);
      break;
    }
    case LHARX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      set_register(rt, ReadExHU(ra_val + rb_val));
      break;
    }
    case LWARX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      set_register(rt, ReadExWU(ra_val + rb_val));
      break;
    }
    case LDARX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      set_register(rt, ReadExDWU(ra_val + rb_val));
      break;
    }
    case DCBF: {
      // todo - simulate dcbf
      break;
    }
    case ISEL: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      int condition_bit = instr->RCValue();
      int condition_mask = 0x80000000 >> condition_bit;
      intptr_t ra_val = (ra == 0) ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      intptr_t value = (condition_reg_ & condition_mask) ? ra_val : rb_val;
      set_register(rt, value);
      break;
    }

    case STBU:
    case STB: {
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int8_t rs_val = get_register(rs);
      int offset = SIGN_EXT_IMM16(instr->Bits(15, 0));
      WriteB(ra_val + offset, rs_val);
      if (opcode == STBU) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + offset);
      }
      break;
    }

    case LHZU:
    case LHZ: {
      int ra = instr->RAValue();
      int rt = instr->RTValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int offset = SIGN_EXT_IMM16(instr->Bits(15, 0));
      uintptr_t result = ReadHU(ra_val + offset) & 0xFFFF;
      set_register(rt, result);
      if (opcode == LHZU) {
        set_register(ra, ra_val + offset);
      }
      break;
    }

    case LHA:
    case LHAU: {
      int ra = instr->RAValue();
      int rt = instr->RTValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int offset = SIGN_EXT_IMM16(instr->Bits(15, 0));
      intptr_t result = ReadH(ra_val + offset);
      set_register(rt, result);
      if (opcode == LHAU) {
        set_register(ra, ra_val + offset);
      }
      break;
    }

    case STHU:
    case STH: {
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int16_t rs_val = get_register(rs);
      int offset = SIGN_EXT_IMM16(instr->Bits(15, 0));
      WriteH(ra_val + offset, rs_val);
      if (opcode == STHU) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + offset);
      }
      break;
    }

    case LMW:
    case STMW: {
      UNIMPLEMENTED();
    }

    case LFSU:
    case LFS: {
      int frt = instr->RTValue();
      int ra = instr->RAValue();
      int32_t offset = SIGN_EXT_IMM16(instr->Bits(15, 0));
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int32_t val = ReadW(ra_val + offset);
      float* fptr = reinterpret_cast<float*>(&val);
#if V8_HOST_ARCH_IA32 || V8_HOST_ARCH_X64
      // Conversion using double changes sNan to qNan on ia32/x64
      if ((val & 0x7F800000) == 0x7F800000) {
        int64_t dval = static_cast<int64_t>(val);
        dval = ((dval & 0xC0000000) << 32) | ((dval & 0x40000000) << 31) |
               ((dval & 0x40000000) << 30) | ((dval & 0x7FFFFFFF) << 29) | 0x0;
        set_d_register(frt, dval);
      } else {
        set_d_register_from_double(frt, static_cast<double>(*fptr));
      }
#else
      set_d_register_from_double(frt, static_cast<double>(*fptr));
#endif
      if (opcode == LFSU) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + offset);
      }
      break;
    }

    case LFDU:
    case LFD: {
      int frt = instr->RTValue();
      int ra = instr->RAValue();
      int32_t offset = SIGN_EXT_IMM16(instr->Bits(15, 0));
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int64_t dptr = ReadDW(ra_val + offset);
      set_d_register(frt, dptr);
      if (opcode == LFDU) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + offset);
      }
      break;
    }

    case STFSU:
      [[fallthrough]];
    case STFS: {
      int frs = instr->RSValue();
      int ra = instr->RAValue();
      int32_t offset = SIGN_EXT_IMM16(instr->Bits(15, 0));
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      float frs_val = static_cast<float>(get_double_from_d_register(frs));
      int32_t* p;
#if V8_HOST_ARCH_IA32 || V8_HOST_ARCH_X64
      // Conversion using double changes sNan to qNan on ia32/x64
      int32_t sval = 0;
      int64_t dval = get_d_register(frs);
      if ((dval & 0x7FF0000000000000) == 0x7FF0000000000000) {
        sval = ((dval & 0xC000000000000000) >> 32) |
               ((dval & 0x07FFFFFFE0000000) >> 29);
        p = &sval;
      } else {
        p = reinterpret_cast<int32_t*>(&frs_val);
      }
#else
      p = reinterpret_cast<int32_t*>(&frs_val);
#endif
      WriteW(ra_val + offset, *p);
      if (opcode == STFSU) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + offset);
      }
      break;
    }
    case STFDU:
    case STFD: {
      int frs = instr->RSValue();
      int ra = instr->RAValue();
      int32_t offset = SIGN_EXT_IMM16(instr->Bits(15, 0));
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int64_t frs_val = get_d_register(frs);
      WriteDW(ra_val + offset, frs_val);
      if (opcode == STFDU) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + offset);
      }
      break;
    }
    case BRW: {
      constexpr int kBitsPerWord = 32;
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      uint64_t rs_val = get_register(rs);
      uint32_t rs_high = rs_val >> kBitsPerWord;
      uint32_t rs_low = (rs_val << kBitsPerWord) >> kBitsPerWord;
      uint64_t result = ByteReverse<int32_t>(rs_high);
      result = (result << kBitsPerWord) | ByteReverse<int32_t>(rs_low);
      set_register(ra, result);
      break;
    }
    case BRD: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      uint64_t rs_val = get_register(rs);
      set_register(ra, ByteReverse<int64_t>(rs_val));
      break;
    }
    case FCFIDS: {
      // fcfids
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      int64_t frb_val = get_d_register(frb);
      double frt_val = static_cast<float>(frb_val);
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FCFIDUS: {
      // fcfidus
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      uint64_t frb_val = get_d_register(frb);
      double frt_val = static_cast<float>(frb_val);
      set_d_register_from_double(frt, frt_val);
      return;
    }

    case FDIV: {
      int frt = instr->RTValue();
      int fra = instr->RAValue();
      int frb = instr->RBValue();
      double fra_val = get_double_from_d_register(fra);
      double frb_val = get_double_from_d_register(frb);
      double frt_val = fra_val / frb_val;
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FSUB: {
      int frt = instr->RTValue();
      int fra = instr->RAValue();
      int frb = instr->RBValue();
      double fra_val = get_double_from_d_register(fra);
      double frb_val = get_double_from_d_register(frb);
      double frt_val = fra_val - frb_val;
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FADD: {
      int frt = instr->RTValue();
      int fra = instr->RAValue();
      int frb = instr->RBValue();
      double fra_val = get_double_from_d_register(fra);
      double frb_val = get_double_from_d_register(frb);
      double frt_val = fra_val + frb_val;
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FSQRT: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      double frb_val = get_double_from_d_register(frb);
      double frt_val = std::sqrt(frb_val);
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FSEL: {
      int frt = instr->RTValue();
      int fra = instr->RAValue();
      int frb = instr->RBValue();
      int frc = instr->RCValue();
      double fra_val = get_double_from_d_register(fra);
      double frb_val = get_double_from_d_register(frb);
      double frc_val = get_double_from_d_register(frc);
      double frt_val = ((fra_val >= 0.0) ? frc_val : frb_val);
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FMUL: {
      int frt = instr->RTValue();
      int fra = instr->RAValue();
      int frc = instr->RCValue();
      double fra_val = get_double_from_d_register(fra);
      double frc_val = get_double_from_d_register(frc);
      double frt_val = fra_val * frc_val;
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FMSUB: {
      int frt = instr->RTValue();
      int fra = instr->RAValue();
      int frb = instr->RBValue();
      int frc = instr->RCValue();
      double fra_val = get_double_from_d_register(fra);
      double frb_val = get_double_from_d_register(frb);
      double frc_val = get_double_from_d_register(frc);
      double frt_val = (fra_val * frc_val) - frb_val;
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FMADD: {
      int frt = instr->RTValue();
      int fra = instr->RAValue();
      int frb = instr->RBValue();
      int frc = instr->RCValue();
      double fra_val = get_double_from_d_register(fra);
      double frb_val = get_double_from_d_register(frb);
      double frc_val = get_double_from_d_register(frc);
      double frt_val = (fra_val * frc_val) + frb_val;
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FCMPU: {
      int fra = instr->RAValue();
      int frb = instr->RBValue();
      double fra_val = get_double_from_d_register(fra);
      double frb_val = get_double_from_d_register(frb);
      int cr = instr->Bits(25, 23);
      int bf = 0;
      if (fra_val < frb_val) {
        bf |= 0x80000000;
      }
      if (fra_val > frb_val) {
        bf |= 0x40000000;
      }
      if (fra_val == frb_val) {
        bf |= 0x20000000;
      }
      if (std::isunordered(fra_val, frb_val)) {
        bf |= 0x10000000;
      }
      int condition_mask = 0xF0000000 >> (cr * 4);
      int condition = bf >> (cr * 4);
      condition_reg_ = (condition_reg_ & ~condition_mask) | condition;
      return;
    }
    case FRIN: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      double frb_val = get_double_from_d_register(frb);
      double frt_val = std::round(frb_val);
      set_d_register_from_double(frt, frt_val);
      if (instr->Bit(0)) {  // RC bit set
                            //  UNIMPLEMENTED();
      }
      return;
    }
    case FRIZ: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      double frb_val = get_double_from_d_register(frb);
      double frt_val = std::trunc(frb_val);
      set_d_register_from_double(frt, frt_val);
      if (instr->Bit(0)) {  // RC bit set
                            //  UNIMPLEMENTED();
      }
      return;
    }
    case FRIP: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      double frb_val = get_double_from_d_register(frb);
      double frt_val = std::ceil(frb_val);
      set_d_register_from_double(frt, frt_val);
      if (instr->Bit(0)) {  // RC bit set
                            //  UNIMPLEMENTED();
      }
      return;
    }
    case FRIM: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      double frb_val = get_double_from_d_register(frb);
      double frt_val = std::floor(frb_val);
      set_d_register_from_double(frt, frt_val);
      if (instr->Bit(0)) {  // RC bit set
                            //  UNIMPLEMENTED();
      }
      return;
    }
    case FRSP: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      // frsp round 8-byte double-precision value to
      // single-precision value
      double frb_val = get_double_from_d_register(frb);
      double frt_val = static_cast<float>(frb_val);
      set_d_register_from_double(frt, frt_val);
      if (instr->Bit(0)) {  // RC bit set
                            //  UNIMPLEMENTED();
      }
      return;
    }
    case FCFID: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      int64_t frb_val = get_d_register(frb);
      double frt_val = static_cast<double>(frb_val);
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FCFIDU: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      uint64_t frb_val = get_d_register(frb);
      double frt_val = static_cast<double>(frb_val);
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FCTID:
    case FCTIDZ: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      double frb_val = get_double_from_d_register(frb);
      int mode = (opcode == FCTIDZ) ? kRoundToZero
                                    : (fp_condition_reg_ & kFPRoundingModeMask);
      int64_t frt_val;
      int64_t one = 1;  // work-around gcc
      int64_t kMinVal = (one << 63);
      int64_t kMaxVal = kMinVal - 1;
      bool invalid_convert = false;

      if (std::isnan(frb_val)) {
        frt_val = kMinVal;
        invalid_convert = true;
      } else {
        switch (mode) {
          case kRoundToZero:
            frb_val = std::trunc(frb_val);
            break;
          case kRoundToPlusInf:
            frb_val = std::ceil(frb_val);
            break;
          case kRoundToMinusInf:
            frb_val = std::floor(frb_val);
            break;
          default:
            UNIMPLEMENTED();  // Not used by V8.
        }
        if (frb_val < static_cast<double>(kMinVal)) {
          frt_val = kMinVal;
          invalid_convert = true;
        } else if (frb_val >= static_cast<double>(kMaxVal)) {
          frt_val = kMaxVal;
          invalid_convert = true;
        } else {
          frt_val = (int64_t)frb_val;
        }
      }
      set_d_register(frt, frt_val);
      if (invalid_convert) SetFPSCR(VXCVI);
      return;
    }
    case FCTIDU:
    case FCTIDUZ: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      double frb_val = get_double_from_d_register(frb);
      int mode = (opcode == FCTIDUZ)
                     ? kRoundToZero
                     : (fp_condition_reg_ & kFPRoundingModeMask);
      uint64_t frt_val;
      uint64_t kMinVal = 0;
      uint64_t kMaxVal = kMinVal - 1;
      bool invalid_convert = false;

      if (std::isnan(frb_val)) {
        frt_val = kMinVal;
        invalid_convert = true;
      } else {
        switch (mode) {
          case kRoundToZero:
            frb_val = std::trunc(frb_val);
            break;
          case kRoundToPlusInf:
            frb_val = std::ceil(frb_val);
            break;
          case kRoundToMinusInf:
            frb_val = std::floor(frb_val);
            break;
          default:
            UNIMPLEMENTED();  // Not used by V8.
        }
        if (frb_val < static_cast<double>(kMinVal)) {
          frt_val = kMinVal;
          invalid_convert = true;
        } else if (frb_val >= static_cast<double>(kMaxVal)) {
          frt_val = kMaxVal;
          invalid_convert = true;
        } else {
          frt_val = (uint64_t)frb_val;
        }
      }
      set_d_register(frt, frt_val);
      if (invalid_convert) SetFPSCR(VXCVI);
      return;
    }
    case FCTIW:
    case FCTIWZ: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      double frb_val = get_double_from_d_register(frb);
      int mode = (opcode == FCTIWZ) ? kRoundToZero
                                    : (fp_condition_reg_ & kFPRoundingModeMask);
      int64_t frt_val;
      int64_t kMinVal = kMinInt;
      int64_t kMaxVal = kMaxInt;
      bool invalid_convert = false;

      if (std::isnan(frb_val)) {
        frt_val = kMinVal;
      } else {
        switch (mode) {
          case kRoundToZero:
            frb_val = std::trunc(frb_val);
            break;
          case kRoundToPlusInf:
            frb_val = std::ceil(frb_val);
            break;
          case kRoundToMinusInf:
            frb_val = std::floor(frb_val);
            break;
          case kRoundToNearest: {
            double orig = frb_val;
            frb_val = lround(frb_val);
            // Round to even if exactly halfway.  (lround rounds up)
            if (std::fabs(frb_val - orig) == 0.5 && ((int64_t)frb_val % 2)) {
              frb_val += ((frb_val > 0) ? -1.0 : 1.0);
            }
            break;
          }
          default:
            UNIMPLEMENTED();  // Not used by V8.
        }
        if (frb_val < kMinVal) {
          frt_val = kMinVal;
          invalid_convert = true;
        } else if (frb_val > kMaxVal) {
          frt_val = kMaxVal;
          invalid_convert = true;
        } else {
          frt_val = (int64_t)frb_val;
        }
      }
      set_d_register(frt, frt_val);
      if (invalid_convert) SetFPSCR(VXCVI);
      return;
    }
    case FCTIWU:
    case FCTIWUZ: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      double frb_val = get_double_from_d_register(frb);
      int mode = (opcode == FCTIWUZ)
                     ? kRoundToZero
                     : (fp_condition_reg_ & kFPRoundingModeMask);
      uint64_t frt_val;
      uint64_t kMinVal = kMinUInt32;
      uint64_t kMaxVal = kMaxUInt32;
      bool invalid_convert = false;

      if (std::isnan(frb_val)) {
        frt_val = kMinVal;
      } else {
        switch (mode) {
          case kRoundToZero:
            frb_val = std::trunc(frb_val);
            break;
          case kRoundToPlusInf:
            frb_val = std::ceil(frb_val);
            break;
          case kRoundToMinusInf:
            frb_val = std::floor(frb_val);
            break;
          default:
            UNIMPLEMENTED();  // Not used by V8.
        }
        if (frb_val < kMinVal) {
          frt_val = kMinVal;
          invalid_convert = true;
        } else if (frb_val > kMaxVal) {
          frt_val = kMaxVal;
          invalid_convert = true;
        } else {
          frt_val = (uint64_t)frb_val;
        }
      }
      set_d_register(frt, frt_val);
      if (invalid_convert) SetFPSCR(VXCVI);
      return;
    }
    case FNEG: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      double frb_val = get_double_from_d_register(frb);
      double frt_val = -frb_val;
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FCPSGN: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      int fra = instr->RAValue();
      double frb_val = get_double_from_d_register(frb);
      double fra_val = get_double_from_d_register(fra);
      double frt_val = std::copysign(frb_val, fra_val);
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FMR: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      int64_t frb_val = get_d_register(frb);
      set_d_register(frt, frb_val);
      return;
    }
    case MTFSFI: {
      int bf = instr->Bits(25, 23);
      int imm = instr->Bits(15, 12);
      int fp_condition_mask = 0xF0000000 >> (bf * 4);
      fp_condition_reg_ &= ~fp_condition_mask;
      fp_condition_reg_ |= (imm << (28 - (bf * 4)));
      if (instr->Bit(0)) {  // RC bit set
        condition_reg_ &= 0xF0FFFFFF;
        condition_reg_ |= (imm << 23);
      }
      return;
    }
    case MTFSF: {
      int frb = instr->RBValue();
      int64_t frb_dval = get_d_register(frb);
      int32_t frb_ival = static_cast<int32_t>((frb_dval)&0xFFFFFFFF);
      int l = instr->Bits(25, 25);
      if (l == 1) {
        fp_condition_reg_ = frb_ival;
      } else {
        UNIMPLEMENTED();
      }
      if (instr->Bit(0)) {  // RC bit set
        UNIMPLEMENTED();
        // int w = instr->Bits(16, 16);
        // int flm = instr->Bits(24, 17);
      }
      return;
    }
    case MFFS: {
      int frt = instr->RTValue();
      int64_t lval = static_cast<int64_t>(fp_condition_reg_);
      set_d_register(frt, lval);
      return;
    }
    case MCRFS: {
      int bf = instr->Bits(25, 23);
      int bfa = instr->Bits(20, 18);
      int cr_shift = (7 - bf) * CRWIDTH;
      int fp_shift = (7 - bfa) * CRWIDTH;
      int field_val = (fp_condition_reg_ >> fp_shift) & 0xF;
      condition_reg_ &= ~(0x0F << cr_shift);
      condition_reg_ |= (field_val << cr_shift);
      // Clear copied exception bits
```