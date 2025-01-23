Response:
Let's break down the request and the provided C++ header file.

**Understanding the Request:**

The request asks for an analysis of the `constants-s390.h` file, specifically focusing on:

1. **Functionality:** What does this file do?
2. **Torque Source:** Is it a Torque file (`.tq` extension)?
3. **JavaScript Relevance:**  Does it relate to JavaScript functionality, and if so, how (with an example)?
4. **Code Logic Inference:** Are there logical operations where we can infer input and output?
5. **Common Programming Errors:** Does it relate to common errors?
6. **Overall Function (Part 1 of 5):** A summary of its purpose.

**Analyzing the `constants-s390.h` file:**

* **Filename and Path:** `v8/src/codegen/s390/constants-s390.h`. This strongly suggests it's related to code generation for the s390 architecture within the V8 JavaScript engine. The "constants" part hints at defining symbolic names for values.

* **Header Guards:** `#ifndef V8_CODEGEN_S390_CONSTANTS_S390_H_` and `#define V8_CODEGEN_S390_CONSTANTS_S390_H_` are standard header guards to prevent multiple inclusions.

* **Includes:**
    * `<inttypes.h>` and `<stdint.h>`:  Standard C headers for integer types and formatting.
    * `"src/base/logging.h"` and `"src/base/macros.h"`: V8 internal headers for logging and common macros.
    * `"src/common/code-memory-access.h"`: V8 header likely related to accessing code memory.
    * `"src/common/globals.h"`: V8 header containing global definitions.

* **`UNIMPLEMENTED_S390()` Macro:**  A debugging macro that prints a message if a function or feature for the s390 architecture is not yet implemented. This confirms the file's focus on s390.

* **ABI Definitions (`ABI_USES_FUNCTION_DESCRIPTORS`, `ABI_PASSES_HANDLES_IN_REGS`, `ABI_RETURNS_OBJECTPAIR_IN_REGS`, `ABI_CALL_VIA_IP`):** These macros define aspects of the Application Binary Interface (ABI) for the s390 platform, specifically for z/OS and other environments. They dictate how functions are called, how arguments are passed, and how return values are handled.

* **`kMaxPCRelativeCodeRangeInMB`:**  A constant defining the maximum range for PC-relative calls, important for code optimization and linking.

* **`kHasFunctionDescriptorBitShift`, `kHasFunctionDescriptorBitMask`:** Constants likely related to encoding information about function descriptors, specific to the z/OS ABI.

* **`kNumRegisters`, `kNumDoubleRegisters`, `kNoRegister`:** Constants defining the number of general-purpose and floating-point registers on the s390 architecture, and a value representing "no register."

* **`kRootRegisterBias`:** A constant used in calculating the offset of the root register.

* **`SIGN_EXT_IMM16`, `SIGN_EXT_IMM26` Macros:** Macros for sign-extending immediate values, essential for dealing with signed operands in s390 instructions.

* **`Condition` Enum:** This is a crucial part. It defines symbolic names for the condition codes used in s390 branch instructions (e.g., `eq` for equal, `ne` for not equal). It also includes cross-platform aliases like `kEqual` and `kNotEqual`.

* **`to_condition()`, `is_signed()`, `NegateCondition()` Functions:** These utility functions work with the `Condition` enum, allowing for conversions, checking if a condition is signed, and negating conditions.

* **`Instr`, `TwoByteInstr`, `FourByteInstr`, `SixByteInstr` Type Aliases:** These define types for representing s390 instructions of different sizes.

* **`S390_RSY_A_OPCODE_LIST`, `S390_RSY_B_OPCODE_LIST`, etc. Macros:**  These are massive macros that define lists of s390 opcodes (instruction names) and their corresponding numerical values. The naming convention (e.g., `RSY_A`) likely refers to the instruction format.

**Mental Walkthrough/Pre-computation:**

* **Torque:** The file ends in `.h`, not `.tq`, so it's not a Torque source file.
* **JavaScript Relation:** While this is low-level architecture-specific code, it's *essential* for V8 to be able to execute JavaScript on s390. The compiler and code generator use these constants to emit the correct machine code for JavaScript operations.
* **Code Logic:** The `Condition` enum and its related functions are the most obvious area of code logic. We can infer input/output based on condition negations.
* **Programming Errors:** Incorrectly using or interpreting condition codes or ABI conventions are potential errors.

**Drafting the Response (Iterative Refinement):**

Based on this analysis, I'd start drafting the response, making sure to cover all the requested points. I'd use the identified components (ABI definitions, condition codes, opcode lists) as key features to describe. I'd also make sure to explicitly address the negative cases (not a Torque file).

**Self-Correction/Refinement during Drafting:**

* Initially, I might focus too much on the individual opcode definitions. I'd need to step back and summarize the *purpose* of these definitions (representing s390 instructions).
* I'd need to be careful not to get too deep into the technical details of each s390 instruction unless the request specifically asked for it. The goal is a high-level understanding of the file's function.
* The JavaScript example needs to be simple and illustrate how these low-level constants ultimately enable JavaScript execution.
*  I need to make sure the "common programming errors" are relevant to the *context* of this file (s390 assembly/code generation within V8), not just general JavaScript errors.

By following these steps, I can systematically analyze the provided code and generate a comprehensive and accurate response to the user's request.
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_CODEGEN_S390_CONSTANTS_S390_H_
#define V8_CODEGEN_S390_CONSTANTS_S390_H_

// Get the standard printf format macros for C99 stdint types.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>
#include <stdint.h>

#include "src/base/logging.h"
#include "src/base/macros.h"
#include "src/common/code-memory-access.h"
#include "src/common/globals.h"

// UNIMPLEMENTED_ macro for S390.
#ifdef DEBUG
#define UNIMPLEMENTED_S390()                                               \
  v8::internal::PrintF("%s, \tline %d: \tfunction %s not implemented. \n", \
                       __FILE__, __LINE__, __func__)
#else
#define UNIMPLEMENTED_S390()
#endif

#if V8_OS_ZOS
#define ABI_USES_FUNCTION_DESCRIPTORS 1
#define ABI_PASSES_HANDLES_IN_REGS 1
#define ABI_RETURNS_OBJECTPAIR_IN_REGS 1
#ifdef _EXT
// Defined in stdlib.h and conflict with those in S390_RS_A_OPCODE_LIST below:
#undef cs
#undef cds
#endif
#else
#define ABI_USES_FUNCTION_DESCRIPTORS 0
#define ABI_PASSES_HANDLES_IN_REGS 1

// ObjectPair is defined under runtime/runtime-util.h.
// On 64-bit, ObjectPair is a Struct. ABI dictaes Structs be
//            returned in a storage buffer allocated by the caller,
//            with the address of this buffer passed as a hidden
//            argument in r2. (Does NOT return in Regs)
// For x86 linux, ObjectPair is returned in registers.
#define ABI_RETURNS_OBJECTPAIR_IN_REGS 0
#endif

#define ABI_CALL_VIA_IP 1

namespace v8 {
namespace internal {

// The maximum size of the code range s.t. pc-relative calls are possible
// between all Code objects in the range.
constexpr size_t kMaxPCRelativeCodeRangeInMB = 4096;

#if V8_OS_ZOS
// Used to encode a boolean value when emitting 32 bit
// opcodes which will indicate the presence of function descriptors
constexpr int kHasFunctionDescriptorBitShift = 4;
constexpr int kHasFunctionDescriptorBitMask = 1
                                              << kHasFunctionDescriptorBitShift;
#endif

// Number of registers
const int kNumRegisters = 16;

// FP support.
const int kNumDoubleRegisters = 16;

const int kNoRegister = -1;

// The actual value of the kRootRegister is offset from the IsolateData's start
// to take advantage of negative displacement values.
constexpr int kRootRegisterBias = 128;

// sign-extend the least significant 16-bits of value <imm>
#define SIGN_EXT_IMM16(imm) ((static_cast<int>(imm) << 16) >> 16)

// sign-extend the least significant 26-bits of value <imm>
#define SIGN_EXT_IMM26(imm) ((static_cast<int>(imm) << 6) >> 6)

// -----------------------------------------------------------------------------
// Conditions.

// Defines constants and accessor classes to assemble, disassemble and
// simulate z/Architecture instructions.
//
// Section references in the code refer to the "z/Architecture Principles
// Of Operation" http://publibfi.boulder.ibm.com/epubs/pdf/dz9zr009.pdf
//

// Constants for specific fields are defined in their respective named enums.
// General constants are in an anonymous enum in class Instr.
enum Condition : int {
  kNoCondition = -1,
  eq = 0x8,  // Equal.
  ne = 0x7,  // Not equal.
  ge = 0xa,  // Greater or equal.
  lt = 0x4,  // Less than.
  gt = 0x2,  // Greater than.
  le = 0xc,  // Less then or equal
  al = 0xf,  // Always.

  CC_NOP = 0x0,           // S390 NOP
  CC_EQ = 0x08,           // S390 condition code 0b1000
  CC_LT = 0x04,           // S390 condition code 0b0100
  CC_LE = CC_EQ | CC_LT,  // S390 condition code 0b1100
  CC_GT = 0x02,           // S390 condition code 0b0010
  CC_GE = CC_EQ | CC_GT,  // S390 condition code 0b1010
  CC_OF = 0x01,           // S390 condition code 0b0001
  CC_NOF = 0x0E,          // S390 condition code 0b1110
  CC_ALWAYS = 0x0F,       // S390 always taken branch
  unordered = CC_OF,      // Floating-point unordered
  ordered = CC_NOF,       // floating-point ordered
  overflow = CC_OF,       // Summary overflow
  nooverflow = CC_NOF,

  mask0x0 = 0,  // no jumps
  mask0x1 = 1,
  mask0x2 = 2,
  mask0x3 = 3,
  mask0x4 = 4,
  mask0x5 = 5,
  mask0x6 = 6,
  mask0x7 = 7,
  mask0x8 = 8,
  mask0x9 = 9,
  mask0xA = 10,
  mask0xB = 11,
  mask0xC = 12,
  mask0xD = 13,
  mask0xE = 14,
  mask0xF = 15,

  // Unified cross-platform condition names/aliases.
  // Do not set unsigned constants equal to their signed variants.
  // We need to be able to differentiate between signed and unsigned enum
  // constants in order to emit the right instructions (i.e CmpS64 vs CmpU64).
  kEqual = eq,
  kNotEqual = ne,
  kLessThan = lt,
  kGreaterThan = gt,
  kLessThanEqual = le,
  kGreaterThanEqual = ge,
  kUnsignedLessThan = 16,
  kUnsignedGreaterThan = 17,
  kUnsignedLessThanEqual = 18,
  kUnsignedGreaterThanEqual = 19,
  kOverflow = overflow,
  kNoOverflow = nooverflow,
  kZero = 20,
  kNotZero = 21,
};

inline Condition to_condition(Condition cond) {
  switch (cond) {
    case kUnsignedLessThan:
      return lt;
    case kUnsignedGreaterThan:
      return gt;
    case kUnsignedLessThanEqual:
      return le;
    case kUnsignedGreaterThanEqual:
      return ge;
    case kZero:
      return eq;
    case kNotZero:
      return ne;
    default:
      break;
  }
  return cond;
}

inline bool is_signed(Condition cond) {
  switch (cond) {
    case kEqual:
    case kNotEqual:
    case kLessThan:
    case kGreaterThan:
    case kLessThanEqual:
    case kGreaterThanEqual:
    case kOverflow:
    case kNoOverflow:
    case kZero:
    case kNotZero:
      return true;

    case kUnsignedLessThan:
    case kUnsignedGreaterThan:
    case kUnsignedLessThanEqual:
    case kUnsignedGreaterThanEqual:
      return false;

    default:
      UNREACHABLE();
  }
}

inline Condition NegateCondition(Condition cond) {
  DCHECK(cond != al);
  switch (cond) {
    case eq:
      return ne;
    case ne:
      return eq;
    case ge:
      return lt;
    case gt:
      return le;
    case le:
      return gt;
    case lt:
      return ge;
    case lt | gt:
      return eq;
    case le | ge:
      return CC_OF;
    case CC_OF:
      return CC_NOF;
    case kUnsignedLessThan:
      return kUnsignedGreaterThanEqual;
    case kUnsignedGreaterThan:
      return kUnsignedLessThanEqual;
    case kUnsignedLessThanEqual:
      return kUnsignedGreaterThan;
    case kUnsignedGreaterThanEqual:
      return kUnsignedLessThan;
    default:
      DCHECK(false);
  }
  return al;
}

// -----------------------------------------------------------------------------
// Instructions encoding.

// Instr is merely used by the Assembler to distinguish 32bit integers
// representing instructions from usual 32 bit values.
// Instruction objects are pointers to 32bit values, and provide methods to
// access the various ISA fields.
using Instr = int32_t;
using TwoByteInstr = uint16_t;
using FourByteInstr = uint32_t;
using SixByteInstr = uint64_t;

#define S390_RSY_A_OPCODE_LIST(V)                                              \
  V(lmg, LMG, 0xEB04)     /* type = RSY_A LOAD MULTIPLE (64)  */               \
  V(srag, SRAG, 0xEB0A)   /* type = RSY_A SHIFT RIGHT SINGLE (64)  */          \
  V(slag, SLAG, 0xEB0B)   /* type = RSY_A SHIFT LEFT SINGLE (64)  */           \
  V(srlg, SRLG, 0xEB0C)   /* type = RSY_A SHIFT RIGHT SINGLE LOGICAL (64)  */  \
  V(sllg, SLLG, 0xEB0D)   /* type = RSY_A SHIFT LEFT SINGLE LOGICAL (64)  */   \
  V(tracg, TRACG, 0xEB0F) /* type = RSY_A TRACE (64)  */                       \
  V(csy, CSY, 0xEB14)     /* type = RSY_A COMPARE AND SWAP (32)  */            \
  V(rllg, RLLG, 0xEB1C)   /* type = RSY_A ROTATE LEFT SINGLE LOGICAL (64)  */  \
  V(rll, RLL, 0xEB1D)     /* type = RSY_A ROTATE LEFT SINGLE LOGICAL (32)  */  \
  V(stmg, STMG, 0xEB24)   /* type = RSY_A STORE MULTIPLE (64)  */              \
  V(stctg, STCTG, 0xEB25) /* type = RSY_A STORE CONTROL (64)  */               \
  V(stmh, STMH, 0xEB26)   /* type = RSY_A STORE MULTIPLE HIGH (32)  */         \
  V(lctlg, LCTLG, 0xEB2F) /* type = RSY_A LOAD CONTROL (64)  */                \
  V(csg, CSG, 0xEB30)     /* type = RSY_A COMPARE AND SWAP (64)  */            \
  V(cdsy, CDSY, 0xEB31)   /* type = RSY_A COMPARE DOUBLE AND SWAP (32)  */     \
  V(cdsg, CDSG, 0xEB3E)   /* type = RSY_A COMPARE DOUBLE AND SWAP (64)  */     \
  V(bxhg, BXHG, 0xEB44)   /* type = RSY_A BRANCH ON INDEX HIGH (64)  */        \
  V(bxleg, BXLEG, 0xEB45) /* type = RSY_A BRANCH ON INDEX LOW OR EQUAL (64) */ \
  V(ecag, ECAG, 0xEB4C)   /* type = RSY_A EXTRACT CPU ATTRIBUTE  */            \
  V(mvclu, MVCLU, 0xEB8E) /* type = RSY_A MOVE LONG UNICODE  */                \
  V(clclu, CLCLU, 0xEB8F) /* type = RSY_A COMPARE LOGICAL LONG UNICODE  */     \
  V(stmy, STMY, 0xEB90)   /* type = RSY_A STORE MULTIPLE (32)  */              \
  V(lmh, LMH, 0xEB96)     /* type = RSY_A LOAD MULTIPLE HIGH (32)  */          \
  V(lmy, LMY, 0xEB98)     /* type = RSY_A LOAD MULTIPLE (32)  */               \
  V(lamy, LAMY, 0xEB9A)   /* type = RSY_A LOAD ACCESS MULTIPLE  */             \
  V(stamy, STAMY, 0xEB9B) /* type = RSY_A STORE ACCESS MULTIPLE  */            \
  V(srak, SRAK, 0xEBDC)   /* type = RSY_A SHIFT RIGHT SINGLE (32)  */          \
  V(slak, SLAK, 0xEBDD)   /* type = RSY_A SHIFT LEFT SINGLE (32)  */           \
  V(srlk, SRLK, 0xEBDE)   /* type = RSY_A SHIFT RIGHT SINGLE LOGICAL (32)  */  \
  V(sllk, SLLK, 0xEBDF)   /* type = RSY_A SHIFT LEFT SINGLE LOGICAL (32)  */   \
  V(lang, LANG, 0xEBE4)   /* type = RSY_A LOAD AND AND (64)  */                \
  V(laog, LAOG, 0xEBE6)   /* type = RSY_A LOAD AND OR (64)  */                 \
  V(laxg, LAXG, 0xEBE7)   /* type = RSY_A LOAD AND EXCLUSIVE OR (64)  */       \
  V(laag, LAAG, 0xEBE8)   /* type = RSY_A LOAD AND ADD (64)  */                \
  V(laalg, LAALG, 0xEBEA) /* type = RSY_A LOAD AND ADD LOGICAL (64)  */        \
  V(lan, LAN, 0xEBF4)     /* type = RSY_A LOAD AND AND (32)  */                \
  V(lao, LAO, 0xEBF6)     /* type = RSY_A LOAD AND OR (32)  */                 \
  V(lax, LAX, 0xEBF7)     /* type = RSY_A LOAD AND EXCLUSIVE OR (32)  */       \
  V(laa, LAA, 0xEBF8)     /* type = RSY_A LOAD AND ADD (32)  */                \
  V(laal, LAAL, 0xEBFA)   /* type = RSY_A LOAD AND ADD LOGICAL (32)  */

#define S390_RSY_B_OPCODE_LIST(V)                                              \
  V(clmh, CLMH,                                                                \
    0xEB20) /* type = RSY_B COMPARE LOGICAL CHAR. UNDER MASK (high)  */        \
  V(clmy, CLMY,                                                                \
    0xEB21) /* type = RSY_B COMPARE LOGICAL CHAR. UNDER MASK (low)  */         \
  V(clt, CLT, 0xEB23)   /* type = RSY_B COMPARE LOGICAL AND TRAP (32)  */      \
  V(clgt, CLGT, 0xEB2B) /* type = RSY_B COMPARE LOGICAL AND TRAP (64)  */      \
  V(stcmh, STCMH,                                                              \
    0xEB2C) /* type = RSY_B STORE CHARACTERS UNDER MASK (high)  */             \
  V(stcmy, STCMY, 0xEB2D) /* type = RSY_B STORE CHARACTERS UNDER MASK (low) */ \
  V(icmh, ICMH, 0xEB80) /* type = RSY_B INSERT CHARACTERS UNDER MASK (high) */ \
  V(icmy, ICMY, 0xEB81) /* type = RSY_B INSERT CHARACTERS UNDER MASK (low)  */ \
  V(locfh, LOCFH, 0xEBE0)   /* type = RSY_B LOAD HIGH ON CONDITION (32)  */    \
  V(stocfh, STOCFH, 0xEBE1) /* type = RSY_B STORE HIGH ON CONDITION  */        \
  V(locg, LOCG, 0xEBE2)     /* type = RSY_B LOAD ON CONDITION (64)  */         \
  V(stocg, STOCG, 0xEBE3)   /* type = RSY_B STORE ON CONDITION (64)  */        \
  V(loc, LOC, 0xEBF2)       /* type = RSY_B LOAD ON CONDITION (32)  */         \
  V(stoc, STOC, 0xEBF3)     /* type = RSY_B STORE ON CONDITION (32)  */

#define S390_RXE_OPCODE_LIST(V)                                                \
  V(lcbb, LCBB, 0xE727) /* type = RXE   LOAD COUNT TO BLOCK BOUNDARY  */       \
  V(ldeb, LDEB, 0xED04) /* type = RXE   LOAD LENGTHENED (short to long BFP) */ \
  V(lxdb, LXDB,                                                                \
    0xED05) /* type = RXE   LOAD LENGTHENED (long to extended BFP)  */         \
  V(lxeb, LXEB,                                                                \
    0xED06) /* type = RXE   LOAD LENGTHENED (short to extended BFP)  */        \
  V(mxdb, MXDB, 0xED07) /* type = RXE   MULTIPLY (long to extended BFP)  */    \
  V(keb, KEB, 0xED08)   /* type = RXE   COMPARE AND SIGNAL (short BFP)  */     \
  V(ceb, CEB, 0xED09)   /* type = RXE   COMPARE (short BFP)  */                \
  V(aeb, AEB, 0xED0A)   /* type = RXE   ADD (short BFP)  */                    \
  V(seb, SEB, 0xED0B)   /* type = RXE   SUBTRACT (short BFP)  */               \
  V(mdeb, MDEB, 0xED0C) /* type = RXE   MULTIPLY (short to long BFP)  */       \
  V(deb, DEB, 0xED0D)   /* type = RXE   DIVIDE (short BFP)  */                 \
  V(tceb, TCEB, 0xED10) /* type = RXE   TEST DATA CLASS (short BFP)  */        \
  V(tcdb, TCDB, 0xED11) /* type = RXE   TEST DATA CLASS (long BFP)  */         \
  V(tcxb, TCXB, 0xED12) /* type = RXE   TEST DATA CLASS (extended BFP)  */     \
  V(sqeb, SQEB, 0xED14) /* type = RXE   SQUARE ROOT (short BFP)  */            \
  V(sqdb, SQDB, 0xED15) /* type = RXE   SQUARE ROOT (long BFP)  */             \
  V(meeb, MEEB, 0xED17) /* type = RXE   MULTIPLY (short BFP)  */               \
  V(kdb, KDB, 0xED18)   /* type = RXE   COMPARE AND SIGNAL (long BFP)  */      \
  V(cdb, CDB, 0xED19)   /* type = RXE   COMPARE (long BFP)  */                 \
  V(adb, ADB, 0xED1A)   /* type = RXE   ADD (long BFP)  */                     \
  V(sdb, SDB, 0xED1B)   /* type = RXE   SUBTRACT (long BFP)  */                \
  V(mdb, MDB, 0xED1C)   /* type = RXE   MULTIPLY (long BFP)  */                \
  V(ddb, DDB, 0xED1D)   /* type = RXE   DIVIDE (long BFP)  */                  \
  V(lde, LDE, 0xED24) /* type = RXE   LOAD LENGTHENED (short to long HFP)  */  \
  V(lxd, LXD,                                                                  \
    0xED25) /* type = RXE   LOAD LENGTHENED (long to extended HFP)  */         \
  V(lxe, LXE,                                                                  \
    0xED26) /* type = RXE   LOAD LENGTHENED (short to extended HFP)  */        \
  V(sqe, SQE, 0xED34)     /* type = RXE   SQUARE ROOT (short HFP)  */          \
  V(sqd, SQD, 0xED35)     /* type = RXE   SQUARE ROOT (long HFP)  */           \
  V(mee, MEE, 0xED37)     /* type = RXE   MULTIPLY (short HFP)  */             \
  V(tdcet, TDCET, 0xED50) /* type = RXE   TEST DATA CLASS (short DFP)  */      \
  V(tdget, TDGET, 0xED51) /* type = RXE   TEST DATA GROUP (short DFP)  */      \
  V(tdcdt, TDCDT, 0xED54) /* type = RXE   TEST DATA CLASS (long DFP)  */       \
  V(tdgdt, TDGDT, 0xED55) /* type = RXE   TEST DATA GROUP (long DFP)  */       \
  V(tdcxt, TDCXT, 0xED58) /* type = RXE   TEST DATA CLASS (extended DFP)  */   \
  V(tdgxt, TDGXT, 0xED59) /* type = RXE   TEST DATA GROUP (extended DFP)  */

#define S390_RRF_A_OPCODE_LIST(V)                                           \
  V(ipte, IPTE, 0xB221)     /* type = RRF_A INVALIDATE PAGE TABLE ENTRY  */ \
  V(mdtra, MDTRA, 0xB3D0)   /* type = RRF_A MULTIPLY (long DFP)  */         \
  V(ddtra, DDTRA, 0xB3D1)   /* type = RRF_A DIVIDE (long DFP)  */           \
  V(adtra, ADTRA, 0xB3D2)   /* type = RRF_A ADD (long DFP)  */              \
  V(sdtra, SDTRA, 0xB3D3)   /* type = RRF_A SUBTRACT (long DFP)  */         \
  V(mxtra, MXTRA, 0xB3D8)   /* type = RRF_A MULTIPLY (extended DFP)  */     \
  V(msrkc, MSRKC, 0xB9FD)   /* type = RRF_A MULTIPLY (32)*/                 \
  V(msgrkc, MSGRKC, 0xB9ED) /* type = RRF_A MULTIPLY (64)*/                 \
  V(dxtra, DXTRA, 0xB3D9)   /* type = RRF_A DIVIDE (extended DFP)  */       \
  V(axtra, AXTRA, 0xB3DA)   /* type = RRF_A ADD (extended DFP)  */          \
  V(sxtra, SXTRA, 0xB3DB)   /* type = RRF_A SUBTRACT (extended DFP)  */     \
  V(ahhhr, AHHHR, 0xB9C8)   /* type = RRF_A ADD HIGH (32)  */               \
  V(shhhr, SHHHR, 0xB9C9)   /* type = RRF_A SUBTRACT HIGH (32)  */          \
  V(alhhhr, ALHHHR, 0xB9CA) /* type = RRF_A ADD LOGICAL HIGH (32)  */       \
  V(slhhhr, SLHHHR, 0xB9CB) /* type = RRF_A SUBTRACT LOGICAL HIGH (32)  */  \
  V(ahhlr, AHHLR, 0xB9D8)   /* type = RRF_A ADD HIGH (32)  */               \
  V(shhlr, SHHLR, 0xB9D9)   /* type = RRF_A SUBTRACT HIGH (32)  */          \
  V(alhhlr, ALHHLR, 0xB9DA) /* type = RRF_A ADD LOGICAL HIGH (32)  */       \
  V(slhhlr, SLHHLR, 0xB9DB) /* type = RRF_A SUBTRACT LOGICAL HIGH (32)  */  \
  V(ngrk, NGRK, 0xB9E4)     /* type = RRF_A AND (64)  */                    \
  V(ogrk, OGRK, 0xB9E6)     /* type = RRF_A OR (64)  */                     \
  V(xgrk, XGRK, 0xB9E7)     /* type = RRF_A EXCLUSIVE OR (64)  */           \
  V(agrk, AGRK, 0xB9E8)     /* type = RRF_A ADD (64)  */                    \
  V(sgrk, SGRK, 0xB9E9)     /* type = RRF_A SUBTRACT (64)  */               \
  V(mgrk, MGRK, 0xB9EC)     /* type = RRF_A MULTIPLY (64->128)  */          \
  V(algrk, ALGRK, 0xB9EA)   /* type = RRF_A ADD LOGICAL (64)  */            \
  V(slgrk, SLGRK, 0xB9EB)   /* type = RRF_A SUBTRACT LOGICAL (64)  */       \
  V(nrk, NRK, 0xB9F4)       /* type = RRF_A AND (32)  */                    \
  V(ork, ORK, 0xB9F6)       /* type = RRF_A OR (32)  */                     \
  V(xrk, XRK, 0xB9F7)       /* type = RRF_A EXCLUSIVE OR (32)  */           \
  V(ark,
### 提示词
```
这是目录为v8/src/codegen/s390/constants-s390.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/s390/constants-s390.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_CODEGEN_S390_CONSTANTS_S390_H_
#define V8_CODEGEN_S390_CONSTANTS_S390_H_

// Get the standard printf format macros for C99 stdint types.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>
#include <stdint.h>

#include "src/base/logging.h"
#include "src/base/macros.h"
#include "src/common/code-memory-access.h"
#include "src/common/globals.h"

// UNIMPLEMENTED_ macro for S390.
#ifdef DEBUG
#define UNIMPLEMENTED_S390()                                               \
  v8::internal::PrintF("%s, \tline %d: \tfunction %s not implemented. \n", \
                       __FILE__, __LINE__, __func__)
#else
#define UNIMPLEMENTED_S390()
#endif

#if V8_OS_ZOS
#define ABI_USES_FUNCTION_DESCRIPTORS 1
#define ABI_PASSES_HANDLES_IN_REGS 1
#define ABI_RETURNS_OBJECTPAIR_IN_REGS 1
#ifdef _EXT
// Defined in stdlib.h and conflict with those in S390_RS_A_OPCODE_LIST below:
#undef cs
#undef cds
#endif
#else
#define ABI_USES_FUNCTION_DESCRIPTORS 0
#define ABI_PASSES_HANDLES_IN_REGS 1

// ObjectPair is defined under runtime/runtime-util.h.
// On 64-bit, ObjectPair is a Struct.  ABI dictaes Structs be
//            returned in a storage buffer allocated by the caller,
//            with the address of this buffer passed as a hidden
//            argument in r2. (Does NOT return in Regs)
// For x86 linux, ObjectPair is returned in registers.
#define ABI_RETURNS_OBJECTPAIR_IN_REGS 0
#endif

#define ABI_CALL_VIA_IP 1

namespace v8 {
namespace internal {

// The maximum size of the code range s.t. pc-relative calls are possible
// between all Code objects in the range.
constexpr size_t kMaxPCRelativeCodeRangeInMB = 4096;

#if V8_OS_ZOS
// Used to encode a boolean value when emitting 32 bit
// opcodes which will indicate the presence of function descriptors
constexpr int kHasFunctionDescriptorBitShift = 4;
constexpr int kHasFunctionDescriptorBitMask = 1
                                              << kHasFunctionDescriptorBitShift;
#endif

// Number of registers
const int kNumRegisters = 16;

// FP support.
const int kNumDoubleRegisters = 16;

const int kNoRegister = -1;

// The actual value of the kRootRegister is offset from the IsolateData's start
// to take advantage of negative displacement values.
constexpr int kRootRegisterBias = 128;

// sign-extend the least significant 16-bits of value <imm>
#define SIGN_EXT_IMM16(imm) ((static_cast<int>(imm) << 16) >> 16)

// sign-extend the least significant 26-bits of value <imm>
#define SIGN_EXT_IMM26(imm) ((static_cast<int>(imm) << 6) >> 6)

// -----------------------------------------------------------------------------
// Conditions.

// Defines constants and accessor classes to assemble, disassemble and
// simulate z/Architecture instructions.
//
// Section references in the code refer to the "z/Architecture Principles
// Of Operation" http://publibfi.boulder.ibm.com/epubs/pdf/dz9zr009.pdf
//

// Constants for specific fields are defined in their respective named enums.
// General constants are in an anonymous enum in class Instr.
enum Condition : int {
  kNoCondition = -1,
  eq = 0x8,  // Equal.
  ne = 0x7,  // Not equal.
  ge = 0xa,  // Greater or equal.
  lt = 0x4,  // Less than.
  gt = 0x2,  // Greater than.
  le = 0xc,  // Less then or equal
  al = 0xf,  // Always.

  CC_NOP = 0x0,           // S390 NOP
  CC_EQ = 0x08,           // S390 condition code 0b1000
  CC_LT = 0x04,           // S390 condition code 0b0100
  CC_LE = CC_EQ | CC_LT,  // S390 condition code 0b1100
  CC_GT = 0x02,           // S390 condition code 0b0010
  CC_GE = CC_EQ | CC_GT,  // S390 condition code 0b1010
  CC_OF = 0x01,           // S390 condition code 0b0001
  CC_NOF = 0x0E,          // S390 condition code 0b1110
  CC_ALWAYS = 0x0F,       // S390 always taken branch
  unordered = CC_OF,      // Floating-point unordered
  ordered = CC_NOF,       // floating-point ordered
  overflow = CC_OF,       // Summary overflow
  nooverflow = CC_NOF,

  mask0x0 = 0,  // no jumps
  mask0x1 = 1,
  mask0x2 = 2,
  mask0x3 = 3,
  mask0x4 = 4,
  mask0x5 = 5,
  mask0x6 = 6,
  mask0x7 = 7,
  mask0x8 = 8,
  mask0x9 = 9,
  mask0xA = 10,
  mask0xB = 11,
  mask0xC = 12,
  mask0xD = 13,
  mask0xE = 14,
  mask0xF = 15,

  // Unified cross-platform condition names/aliases.
  // Do not set unsigned constants equal to their signed variants.
  // We need to be able to differentiate between signed and unsigned enum
  // constants in order to emit the right instructions (i.e CmpS64 vs CmpU64).
  kEqual = eq,
  kNotEqual = ne,
  kLessThan = lt,
  kGreaterThan = gt,
  kLessThanEqual = le,
  kGreaterThanEqual = ge,
  kUnsignedLessThan = 16,
  kUnsignedGreaterThan = 17,
  kUnsignedLessThanEqual = 18,
  kUnsignedGreaterThanEqual = 19,
  kOverflow = overflow,
  kNoOverflow = nooverflow,
  kZero = 20,
  kNotZero = 21,
};

inline Condition to_condition(Condition cond) {
  switch (cond) {
    case kUnsignedLessThan:
      return lt;
    case kUnsignedGreaterThan:
      return gt;
    case kUnsignedLessThanEqual:
      return le;
    case kUnsignedGreaterThanEqual:
      return ge;
    case kZero:
      return eq;
    case kNotZero:
      return ne;
    default:
      break;
  }
  return cond;
}

inline bool is_signed(Condition cond) {
  switch (cond) {
    case kEqual:
    case kNotEqual:
    case kLessThan:
    case kGreaterThan:
    case kLessThanEqual:
    case kGreaterThanEqual:
    case kOverflow:
    case kNoOverflow:
    case kZero:
    case kNotZero:
      return true;

    case kUnsignedLessThan:
    case kUnsignedGreaterThan:
    case kUnsignedLessThanEqual:
    case kUnsignedGreaterThanEqual:
      return false;

    default:
      UNREACHABLE();
  }
}

inline Condition NegateCondition(Condition cond) {
  DCHECK(cond != al);
  switch (cond) {
    case eq:
      return ne;
    case ne:
      return eq;
    case ge:
      return lt;
    case gt:
      return le;
    case le:
      return gt;
    case lt:
      return ge;
    case lt | gt:
      return eq;
    case le | ge:
      return CC_OF;
    case CC_OF:
      return CC_NOF;
    case kUnsignedLessThan:
      return kUnsignedGreaterThanEqual;
    case kUnsignedGreaterThan:
      return kUnsignedLessThanEqual;
    case kUnsignedLessThanEqual:
      return kUnsignedGreaterThan;
    case kUnsignedGreaterThanEqual:
      return kUnsignedLessThan;
    default:
      DCHECK(false);
  }
  return al;
}

// -----------------------------------------------------------------------------
// Instructions encoding.

// Instr is merely used by the Assembler to distinguish 32bit integers
// representing instructions from usual 32 bit values.
// Instruction objects are pointers to 32bit values, and provide methods to
// access the various ISA fields.
using Instr = int32_t;
using TwoByteInstr = uint16_t;
using FourByteInstr = uint32_t;
using SixByteInstr = uint64_t;

#define S390_RSY_A_OPCODE_LIST(V)                                              \
  V(lmg, LMG, 0xEB04)     /* type = RSY_A LOAD MULTIPLE (64)  */               \
  V(srag, SRAG, 0xEB0A)   /* type = RSY_A SHIFT RIGHT SINGLE (64)  */          \
  V(slag, SLAG, 0xEB0B)   /* type = RSY_A SHIFT LEFT SINGLE (64)  */           \
  V(srlg, SRLG, 0xEB0C)   /* type = RSY_A SHIFT RIGHT SINGLE LOGICAL (64)  */  \
  V(sllg, SLLG, 0xEB0D)   /* type = RSY_A SHIFT LEFT SINGLE LOGICAL (64)  */   \
  V(tracg, TRACG, 0xEB0F) /* type = RSY_A TRACE (64)  */                       \
  V(csy, CSY, 0xEB14)     /* type = RSY_A COMPARE AND SWAP (32)  */            \
  V(rllg, RLLG, 0xEB1C)   /* type = RSY_A ROTATE LEFT SINGLE LOGICAL (64)  */  \
  V(rll, RLL, 0xEB1D)     /* type = RSY_A ROTATE LEFT SINGLE LOGICAL (32)  */  \
  V(stmg, STMG, 0xEB24)   /* type = RSY_A STORE MULTIPLE (64)  */              \
  V(stctg, STCTG, 0xEB25) /* type = RSY_A STORE CONTROL (64)  */               \
  V(stmh, STMH, 0xEB26)   /* type = RSY_A STORE MULTIPLE HIGH (32)  */         \
  V(lctlg, LCTLG, 0xEB2F) /* type = RSY_A LOAD CONTROL (64)  */                \
  V(csg, CSG, 0xEB30)     /* type = RSY_A COMPARE AND SWAP (64)  */            \
  V(cdsy, CDSY, 0xEB31)   /* type = RSY_A COMPARE DOUBLE AND SWAP (32)  */     \
  V(cdsg, CDSG, 0xEB3E)   /* type = RSY_A COMPARE DOUBLE AND SWAP (64)  */     \
  V(bxhg, BXHG, 0xEB44)   /* type = RSY_A BRANCH ON INDEX HIGH (64)  */        \
  V(bxleg, BXLEG, 0xEB45) /* type = RSY_A BRANCH ON INDEX LOW OR EQUAL (64) */ \
  V(ecag, ECAG, 0xEB4C)   /* type = RSY_A EXTRACT CPU ATTRIBUTE  */            \
  V(mvclu, MVCLU, 0xEB8E) /* type = RSY_A MOVE LONG UNICODE  */                \
  V(clclu, CLCLU, 0xEB8F) /* type = RSY_A COMPARE LOGICAL LONG UNICODE  */     \
  V(stmy, STMY, 0xEB90)   /* type = RSY_A STORE MULTIPLE (32)  */              \
  V(lmh, LMH, 0xEB96)     /* type = RSY_A LOAD MULTIPLE HIGH (32)  */          \
  V(lmy, LMY, 0xEB98)     /* type = RSY_A LOAD MULTIPLE (32)  */               \
  V(lamy, LAMY, 0xEB9A)   /* type = RSY_A LOAD ACCESS MULTIPLE  */             \
  V(stamy, STAMY, 0xEB9B) /* type = RSY_A STORE ACCESS MULTIPLE  */            \
  V(srak, SRAK, 0xEBDC)   /* type = RSY_A SHIFT RIGHT SINGLE (32)  */          \
  V(slak, SLAK, 0xEBDD)   /* type = RSY_A SHIFT LEFT SINGLE (32)  */           \
  V(srlk, SRLK, 0xEBDE)   /* type = RSY_A SHIFT RIGHT SINGLE LOGICAL (32)  */  \
  V(sllk, SLLK, 0xEBDF)   /* type = RSY_A SHIFT LEFT SINGLE LOGICAL (32)  */   \
  V(lang, LANG, 0xEBE4)   /* type = RSY_A LOAD AND AND (64)  */                \
  V(laog, LAOG, 0xEBE6)   /* type = RSY_A LOAD AND OR (64)  */                 \
  V(laxg, LAXG, 0xEBE7)   /* type = RSY_A LOAD AND EXCLUSIVE OR (64)  */       \
  V(laag, LAAG, 0xEBE8)   /* type = RSY_A LOAD AND ADD (64)  */                \
  V(laalg, LAALG, 0xEBEA) /* type = RSY_A LOAD AND ADD LOGICAL (64)  */        \
  V(lan, LAN, 0xEBF4)     /* type = RSY_A LOAD AND AND (32)  */                \
  V(lao, LAO, 0xEBF6)     /* type = RSY_A LOAD AND OR (32)  */                 \
  V(lax, LAX, 0xEBF7)     /* type = RSY_A LOAD AND EXCLUSIVE OR (32)  */       \
  V(laa, LAA, 0xEBF8)     /* type = RSY_A LOAD AND ADD (32)  */                \
  V(laal, LAAL, 0xEBFA)   /* type = RSY_A LOAD AND ADD LOGICAL (32)  */

#define S390_RSY_B_OPCODE_LIST(V)                                              \
  V(clmh, CLMH,                                                                \
    0xEB20) /* type = RSY_B COMPARE LOGICAL CHAR. UNDER MASK (high)  */        \
  V(clmy, CLMY,                                                                \
    0xEB21) /* type = RSY_B COMPARE LOGICAL CHAR. UNDER MASK (low)  */         \
  V(clt, CLT, 0xEB23)   /* type = RSY_B COMPARE LOGICAL AND TRAP (32)  */      \
  V(clgt, CLGT, 0xEB2B) /* type = RSY_B COMPARE LOGICAL AND TRAP (64)  */      \
  V(stcmh, STCMH,                                                              \
    0xEB2C) /* type = RSY_B STORE CHARACTERS UNDER MASK (high)  */             \
  V(stcmy, STCMY, 0xEB2D) /* type = RSY_B STORE CHARACTERS UNDER MASK (low) */ \
  V(icmh, ICMH, 0xEB80) /* type = RSY_B INSERT CHARACTERS UNDER MASK (high) */ \
  V(icmy, ICMY, 0xEB81) /* type = RSY_B INSERT CHARACTERS UNDER MASK (low)  */ \
  V(locfh, LOCFH, 0xEBE0)   /* type = RSY_B LOAD HIGH ON CONDITION (32)  */    \
  V(stocfh, STOCFH, 0xEBE1) /* type = RSY_B STORE HIGH ON CONDITION  */        \
  V(locg, LOCG, 0xEBE2)     /* type = RSY_B LOAD ON CONDITION (64)  */         \
  V(stocg, STOCG, 0xEBE3)   /* type = RSY_B STORE ON CONDITION (64)  */        \
  V(loc, LOC, 0xEBF2)       /* type = RSY_B LOAD ON CONDITION (32)  */         \
  V(stoc, STOC, 0xEBF3)     /* type = RSY_B STORE ON CONDITION (32)  */

#define S390_RXE_OPCODE_LIST(V)                                                \
  V(lcbb, LCBB, 0xE727) /* type = RXE   LOAD COUNT TO BLOCK BOUNDARY  */       \
  V(ldeb, LDEB, 0xED04) /* type = RXE   LOAD LENGTHENED (short to long BFP) */ \
  V(lxdb, LXDB,                                                                \
    0xED05) /* type = RXE   LOAD LENGTHENED (long to extended BFP)  */         \
  V(lxeb, LXEB,                                                                \
    0xED06) /* type = RXE   LOAD LENGTHENED (short to extended BFP)  */        \
  V(mxdb, MXDB, 0xED07) /* type = RXE   MULTIPLY (long to extended BFP)  */    \
  V(keb, KEB, 0xED08)   /* type = RXE   COMPARE AND SIGNAL (short BFP)  */     \
  V(ceb, CEB, 0xED09)   /* type = RXE   COMPARE (short BFP)  */                \
  V(aeb, AEB, 0xED0A)   /* type = RXE   ADD (short BFP)  */                    \
  V(seb, SEB, 0xED0B)   /* type = RXE   SUBTRACT (short BFP)  */               \
  V(mdeb, MDEB, 0xED0C) /* type = RXE   MULTIPLY (short to long BFP)  */       \
  V(deb, DEB, 0xED0D)   /* type = RXE   DIVIDE (short BFP)  */                 \
  V(tceb, TCEB, 0xED10) /* type = RXE   TEST DATA CLASS (short BFP)  */        \
  V(tcdb, TCDB, 0xED11) /* type = RXE   TEST DATA CLASS (long BFP)  */         \
  V(tcxb, TCXB, 0xED12) /* type = RXE   TEST DATA CLASS (extended BFP)  */     \
  V(sqeb, SQEB, 0xED14) /* type = RXE   SQUARE ROOT (short BFP)  */            \
  V(sqdb, SQDB, 0xED15) /* type = RXE   SQUARE ROOT (long BFP)  */             \
  V(meeb, MEEB, 0xED17) /* type = RXE   MULTIPLY (short BFP)  */               \
  V(kdb, KDB, 0xED18)   /* type = RXE   COMPARE AND SIGNAL (long BFP)  */      \
  V(cdb, CDB, 0xED19)   /* type = RXE   COMPARE (long BFP)  */                 \
  V(adb, ADB, 0xED1A)   /* type = RXE   ADD (long BFP)  */                     \
  V(sdb, SDB, 0xED1B)   /* type = RXE   SUBTRACT (long BFP)  */                \
  V(mdb, MDB, 0xED1C)   /* type = RXE   MULTIPLY (long BFP)  */                \
  V(ddb, DDB, 0xED1D)   /* type = RXE   DIVIDE (long BFP)  */                  \
  V(lde, LDE, 0xED24) /* type = RXE   LOAD LENGTHENED (short to long HFP)  */  \
  V(lxd, LXD,                                                                  \
    0xED25) /* type = RXE   LOAD LENGTHENED (long to extended HFP)  */         \
  V(lxe, LXE,                                                                  \
    0xED26) /* type = RXE   LOAD LENGTHENED (short to extended HFP)  */        \
  V(sqe, SQE, 0xED34)     /* type = RXE   SQUARE ROOT (short HFP)  */          \
  V(sqd, SQD, 0xED35)     /* type = RXE   SQUARE ROOT (long HFP)  */           \
  V(mee, MEE, 0xED37)     /* type = RXE   MULTIPLY (short HFP)  */             \
  V(tdcet, TDCET, 0xED50) /* type = RXE   TEST DATA CLASS (short DFP)  */      \
  V(tdget, TDGET, 0xED51) /* type = RXE   TEST DATA GROUP (short DFP)  */      \
  V(tdcdt, TDCDT, 0xED54) /* type = RXE   TEST DATA CLASS (long DFP)  */       \
  V(tdgdt, TDGDT, 0xED55) /* type = RXE   TEST DATA GROUP (long DFP)  */       \
  V(tdcxt, TDCXT, 0xED58) /* type = RXE   TEST DATA CLASS (extended DFP)  */   \
  V(tdgxt, TDGXT, 0xED59) /* type = RXE   TEST DATA GROUP (extended DFP)  */

#define S390_RRF_A_OPCODE_LIST(V)                                           \
  V(ipte, IPTE, 0xB221)     /* type = RRF_A INVALIDATE PAGE TABLE ENTRY  */ \
  V(mdtra, MDTRA, 0xB3D0)   /* type = RRF_A MULTIPLY (long DFP)  */         \
  V(ddtra, DDTRA, 0xB3D1)   /* type = RRF_A DIVIDE (long DFP)  */           \
  V(adtra, ADTRA, 0xB3D2)   /* type = RRF_A ADD (long DFP)  */              \
  V(sdtra, SDTRA, 0xB3D3)   /* type = RRF_A SUBTRACT (long DFP)  */         \
  V(mxtra, MXTRA, 0xB3D8)   /* type = RRF_A MULTIPLY (extended DFP)  */     \
  V(msrkc, MSRKC, 0xB9FD)   /* type = RRF_A MULTIPLY (32)*/                 \
  V(msgrkc, MSGRKC, 0xB9ED) /* type = RRF_A MULTIPLY (64)*/                 \
  V(dxtra, DXTRA, 0xB3D9)   /* type = RRF_A DIVIDE (extended DFP)  */       \
  V(axtra, AXTRA, 0xB3DA)   /* type = RRF_A ADD (extended DFP)  */          \
  V(sxtra, SXTRA, 0xB3DB)   /* type = RRF_A SUBTRACT (extended DFP)  */     \
  V(ahhhr, AHHHR, 0xB9C8)   /* type = RRF_A ADD HIGH (32)  */               \
  V(shhhr, SHHHR, 0xB9C9)   /* type = RRF_A SUBTRACT HIGH (32)  */          \
  V(alhhhr, ALHHHR, 0xB9CA) /* type = RRF_A ADD LOGICAL HIGH (32)  */       \
  V(slhhhr, SLHHHR, 0xB9CB) /* type = RRF_A SUBTRACT LOGICAL HIGH (32)  */  \
  V(ahhlr, AHHLR, 0xB9D8)   /* type = RRF_A ADD HIGH (32)  */               \
  V(shhlr, SHHLR, 0xB9D9)   /* type = RRF_A SUBTRACT HIGH (32)  */          \
  V(alhhlr, ALHHLR, 0xB9DA) /* type = RRF_A ADD LOGICAL HIGH (32)  */       \
  V(slhhlr, SLHHLR, 0xB9DB) /* type = RRF_A SUBTRACT LOGICAL HIGH (32)  */  \
  V(ngrk, NGRK, 0xB9E4)     /* type = RRF_A AND (64)  */                    \
  V(ogrk, OGRK, 0xB9E6)     /* type = RRF_A OR (64)  */                     \
  V(xgrk, XGRK, 0xB9E7)     /* type = RRF_A EXCLUSIVE OR (64)  */           \
  V(agrk, AGRK, 0xB9E8)     /* type = RRF_A ADD (64)  */                    \
  V(sgrk, SGRK, 0xB9E9)     /* type = RRF_A SUBTRACT (64)  */               \
  V(mgrk, MGRK, 0xB9EC)     /* type = RRF_A MULTIPLY (64->128)  */          \
  V(algrk, ALGRK, 0xB9EA)   /* type = RRF_A ADD LOGICAL (64)  */            \
  V(slgrk, SLGRK, 0xB9EB)   /* type = RRF_A SUBTRACT LOGICAL (64)  */       \
  V(nrk, NRK, 0xB9F4)       /* type = RRF_A AND (32)  */                    \
  V(ork, ORK, 0xB9F6)       /* type = RRF_A OR (32)  */                     \
  V(xrk, XRK, 0xB9F7)       /* type = RRF_A EXCLUSIVE OR (32)  */           \
  V(ark, ARK, 0xB9F8)       /* type = RRF_A ADD (32)  */                    \
  V(srk, SRK, 0xB9F9)       /* type = RRF_A SUBTRACT (32)  */               \
  V(alrk, ALRK, 0xB9FA)     /* type = RRF_A ADD LOGICAL (32)  */            \
  V(slrk, SLRK, 0xB9FB)     /* type = RRF_A SUBTRACT LOGICAL (32)  */

#define S390_RXF_OPCODE_LIST(V)                                                \
  V(maeb, MAEB, 0xED0E) /* type = RXF   MULTIPLY AND ADD (short BFP)  */       \
  V(mseb, MSEB, 0xED0F) /* type = RXF   MULTIPLY AND SUBTRACT (short BFP)  */  \
  V(madb, MADB, 0xED1E) /* type = RXF   MULTIPLY AND ADD (long BFP)  */        \
  V(msdb, MSDB, 0xED1F) /* type = RXF   MULTIPLY AND SUBTRACT (long BFP)  */   \
  V(mae, MAE, 0xED2E)   /* type = RXF   MULTIPLY AND ADD (short HFP)  */       \
  V(mse, MSE, 0xED2F)   /* type = RXF   MULTIPLY AND SUBTRACT (short HFP)  */  \
  V(mayl, MAYL,                                                                \
    0xED38) /* type = RXF   MULTIPLY AND ADD UNNRM. (long to ext. low HFP)  */ \
  V(myl, MYL,                                                                  \
    0xED39) /* type = RXF   MULTIPLY UNNORM. (long to ext. low HFP)  */        \
  V(may, MAY,                                                                  \
    0xED3A) /* type = RXF   MULTIPLY & ADD UNNORMALIZED (long to ext. HFP)  */ \
  V(my, MY,                                                                    \
    0xED3B) /* type = RXF   MULTIPLY UNNORMALIZED (long to ext. HFP)  */       \
  V(mayh, MAYH,                                                                \
    0xED3C) /* type = RXF   MULTIPLY AND ADD UNNRM. (long to ext. high HFP) */ \
  V(myh, MYH,                                                                  \
    0xED3D) /* type = RXF   MULTIPLY UNNORM. (long to ext. high HFP)  */       \
  V(mad, MAD, 0xED3E)   /* type = RXF   MULTIPLY AND ADD (long HFP)  */        \
  V(msd, MSD, 0xED3F)   /* type = RXF   MULTIPLY AND SUBTRACT (long HFP)  */   \
  V(sldt, SLDT, 0xED40) /* type = RXF   SHIFT SIGNIFICAND LEFT (long DFP)  */  \
  V(srdt, SRDT, 0xED41) /* type = RXF   SHIFT SIGNIFICAND RIGHT (long DFP)  */ \
  V(slxt, SLXT,                                                                \
    0xED48) /* type = RXF   SHIFT SIGNIFICAND LEFT (extended DFP)  */          \
  V(srxt, SRXT,                                                                \
    0xED49) /* type = RXF   SHIFT SIGNIFICAND RIGHT (extended DFP)  */

#define S390_IE_OPCODE_LIST(V) \
  V(niai, NIAI, 0xB2FA) /* type = IE    NEXT INSTRUCTION ACCESS INTENT  */

#define S390_RRF_B_OPCODE_LIST(V)                                           \
  V(diebr, DIEBR, 0xB353) /* type = RRF_B DIVIDE TO INTEGER (short BFP)  */ \
  V(didbr, DIDBR, 0xB35B) /* type = RRF_B DIVIDE TO INTEGER (long BFP)  */  \
  V(cpsdr, CPSDR, 0xB372) /* type = RRF_B COPY SIGN (long)  */              \
  V(qadtr, QADTR, 0xB3F5) /* type = RRF_B QUANTIZE (long DFP)  */           \
  V(iedtr, IEDTR,                                                           \
    0xB3F6) /* type = RRF_B INSERT BIASED EXPONENT (64 to long DFP)  */     \
  V(rrdtr, RRDTR, 0xB3F7) /* type = RRF_B REROUND (long DFP)  */            \
  V(qaxtr, QAXTR, 0xB3FD) /* type = RRF_B QUANTIZE (extended DFP)  */       \
  V(iextr, IEXTR,                                                           \
    0xB3FE) /* type = RRF_B INSERT BIASED EXPONENT (64 to extended DFP)  */ \
  V(rrxtr, RRXTR, 0xB3FF) /* type = RRF_B REROUND (extended DFP)  */        \
  V(kmctr, KMCTR, 0xB92D) /* type = RRF_B CIPHER MESSAGE WITH COUNTER  */   \
  V(idte, IDTE, 0xB98E)   /* type = RRF_B INVALIDATE DAT TABLE ENTRY  */    \
  V(crdte, CRDTE,                                                           \
    0xB98F) /* type = RRF_B COMPARE AND REPLACE DAT TABLE ENTRY  */         \
  V(lptea, LPTEA, 0xB9AA) /* type = RRF_B LOAD PAGE TABLE ENTRY ADDRESS  */

#define S390_RRF_C_OPCODE_LIST(V)                                           \
  V(sske, SSKE, 0xB22B)   /* type = RRF_C SET STORAGE KEY EXTENDED  */      \
  V(cu21, CU21, 0xB2A6)   /* type = RRF_C CONVERT UTF-16 TO UTF-8  */       \
  V(cu12, CU12, 0xB2A7)   /* type = RRF_C CONVERT UTF-8 TO UTF-16  */       \
  V(ppa, PPA, 0xB2E8)     /* type = RRF_C PERFORM PROCESSOR ASSIST  */      \
  V(cgrt, CGRT, 0xB960)   /* type = RRF_C COMPARE AND TRAP (64)  */         \
  V(clgrt, CLGRT, 0xB961) /* type = RRF_C COMPARE LOGICAL AND TRAP (64)  */ \
  V(crt, CRT, 0xB972)     /* type = RRF_C COMPARE AND TRAP (32)  */         \
  V(clrt, CLRT, 0xB973)   /* type = RRF_C COMPARE LOGICAL AND TRAP (32)  */ \
  V(trtt, TRTT, 0xB990)   /* type = RRF_C TRANSLATE TWO TO TWO  */          \
  V(trto, TRTO, 0xB991)   /* type = RRF_C TRANSLATE TWO TO ONE  */          \
  V(trot, TROT, 0xB992)   /* type = RRF_C TRANSLATE ONE TO TWO  */          \
  V(troo, TROO, 0xB993)   /* type = RRF_C TRANSLATE ONE TO ONE  */          \
  V(cu14, CU14, 0xB9B0)   /* type = RRF_C CONVERT UTF-8 TO UTF-32  */       \
  V(cu24, CU24, 0xB9B1)   /* type = RRF_C CONVERT UTF-16 TO UTF-32  */      \
  V(trtre, TRTRE,                                                           \
    0xB9BD) /* type = RRF_C TRANSLATE AND TEST REVERSE EXTENDED  */         \
  V(trte, TRTE, 0xB9BF)     /* type = RRF_C TRANSLATE AND TEST EXTENDED  */ \
  V(locfhr, LOCFHR, 0xB9E0) /* type = RRF_C LOAD HIGH ON CONDITION (32)  */ \
  V(locgr, LOCGR, 0xB9E2)   /* type = RRF_C LOAD ON CONDITION (64)  */      \
  V(locr, LOCR, 0xB9F2)     /* type = RRF_C LOAD ON CONDITION (32)  */

#define S390_MII_OPCODE_LIST(V) \
  V(bprp, BPRP, 0xC5) /* type = MII   BRANCH PREDICTION RELATIVE PRELOAD  */

#define S390_RRF_D_OPCODE_LIST(V)                                         \
  V(ldetr, LDETR,                                                         \
    0xB3D4) /* type = RRF_D LOAD LENGTHENED (short to long DFP)  */       \
  V(lxdtr, LXDTR,                                                         \
    0xB3DC) /* type = RRF_D LOAD LENGTHENED (long to extended DFP)  */    \
  V(csdtr, CSDTR,                                                         \
    0xB3E3) /* type = RRF_D CONVERT TO SIGNED PACKED (long DFP to 64)  */ \
  V(csxtr, CSXTR,                                                         \
    0xB3EB) /* type = RRF_D CONVERT TO SIGNED PACKED (extended DFP to 128)  */

#define S390_RRF_E_OPCODE_LIST(V)                                              \
  V(ledbra, LEDBRA,                                                            \
    0xB344) /* type = RRF_E LOAD ROUNDED (long to short BFP)  */               \
  V(ldxbra, LDXBRA,                                                            \
    0xB345) /* type = RRF_E LOAD ROUNDED (extended to long BFP)  */            \
  V(lexbra, LEXBRA,                                                            \
    0xB346) /* type = RRF_E LOAD ROUNDED (extended to short BFP)  */           \
  V(fixbra, FIXBRA, 0xB347) /* type = RRF_E LOAD FP INTEGER (extended BFP)  */ \
  V(tbedr, TBEDR,                                                              \
    0xB350)             /* type = RRF_E CONVERT HFP TO BFP (long to short)  */ \
  V(tbdr, TBDR, 0xB351) /* type = RRF_E CONVERT HFP TO BFP (long)  */          \
  V(fiebra, FIEBRA, 0xB357) /* type = RRF_E LOAD FP INTEGER (short BFP)  */    \
  V(fidbra, FIDBRA, 0xB35F) /* type = RRF_E LOAD FP INTEGER (long BFP)  */     \
  V(celfbr, CELFBR,                                                            \
    0xB390) /* type = RRF_E CONVERT FROM LOGICAL (32 to short BFP)  */         \
  V(cdlfbr, CDLFBR,                                                            \
    0xB391) /* type = RRF_E CONVERT FROM LOGICAL (32 to long BFP)  */          \
  V(cxlfbr, CXLFBR,                                                            \
    0xB392) /* type = RRF_E CONVERT FROM LOGICAL (32 to extended BFP)  */      \
  V(cefbra, CEFBRA,                                                            \
    0xB394) /* type = RRF_E CONVERT FROM FIXED (32 to short BFP)  */           \
  V(cdfbra, CDFBRA,                                                            \
    0xB395) /* type = RRF_E CONVERT FROM FIXED (32 to long BFP)  */            \
  V(cxfbra, CXFBRA,                                                            \
    0xB396) /* type = RRF_E CONVERT FROM FIXED (32 to extended BFP)  */        \
  V(cfebra, CFEBRA,                                                            \
    0xB398) /* type = RRF_E CONVERT TO FIXED (short BFP to 32)  */             \
  V(cfdbra, CFDBRA,                                                            \
    0xB399) /* type = RRF_E CONVERT TO FIXED (long BFP to 32)  */              \
  V(cfxbra, CFXBRA,                                                            \
    0xB39A) /* type = RRF_E CONVERT TO FIXED (extended BFP to 32)  */          \
  V(clfebr, CLFEBR,                                                            \
    0xB39C) /* type = RRF_E CONVERT TO LOGICAL (short BFP to 32)  */           \
  V(clfdbr, CLFDBR,                                                            \
    0xB39D) /* type = RRF_E CONVERT TO LOGICAL (long BFP to 32)  */            \
  V(clfxbr, CLFXBR,                                                            \
    0xB39E) /* type = RRF_E CONVERT TO LOGICAL (extended BFP to 32)  */        \
  V(celgbr, CELGBR,                                                            \
    0xB3A0) /* type = RRF_E CONVERT FROM LOGICAL (64 to short BFP)  */         \
  V(cdlgbr, CDLGBR,                                                            \
    0xB3A1) /* type = RRF_E CONVERT FROM LOGICAL (64 to long BFP)  */          \
  V(cxlgbr, CXLGBR,                                                            \
    0xB3A2) /* type = RRF_E CONVERT FROM LOGICAL (64 to extended BFP)  */      \
  V(cegbra, CEGBRA,                                                            \
    0xB3A4) /* type = RRF_E CONVERT FROM FIXED (64 to short BFP)  */           \
  V(cdgbra, CDGBRA,                                                            \
    0xB3A5) /* type = RRF_E CONVERT FROM FIXED (64 to long BFP)  */            \
  V(cxgbra, CXGBRA,                                                            \
    0xB3A6) /* type = RRF_E CONVERT FROM FIXED (64 to extended BFP)  */        \
  V(cgebra, CGEBRA,                                                            \
    0xB3A8) /* type = RRF_E CONVERT TO FIXED (short BFP to 64)  */             \
  V(cgdbra, CGDBRA,                                                            \
    0xB3A9) /* type = RRF_E CONVERT TO FIXED (long BFP to 64)  */              \
  V(cgxbra, CGXBRA,                                                            \
    0xB3AA) /* type = RRF_E CONVERT TO FIXED (extended BFP to 64)  */          \
  V(clgebr, CLGEBR,                                                            \
    0xB3AC) /* type = RRF_E CONVERT TO LOGICAL (short BFP to 64)  */           \
  V(clgdbr, CLGDBR,                                                            \
    0xB3AD) /* type = RRF_E CONVERT TO LOGICAL (long BFP to 64)  */            \
  V(clgxbr, CLGXBR,                                                            \
    0xB3AE) /* type = RRF_E CONVERT TO LOGICAL (extended BFP to 64)  */        \
  V(cfer, CFER, 0xB3B8) /* type = RRF_E CONVERT TO FIXED (short HFP to 32)  */ \
  V(cfdr, CFDR, 0xB3B9) /* type = RRF_E CONVERT TO FIXED (long HFP to 32)  */  \
  V(cfxr, CFXR,                                                                \
    0xB3BA) /* type = RRF_E CONVERT TO FIXED (extended HFP to 32)  */          \
  V(cger, CGER, 0xB3C8) /* type = RRF_E CONVERT TO FIXED (short HFP to 64)  */ \
  V(cgdr, CGDR, 0xB3C9) /* type = RRF_E CONVERT TO FIXED (long HFP to 64)  */  \
  V(cgxr, CGXR,                                                                \
    0xB3CA) /* type = RRF_E CONVERT TO FIXED (extended HFP to 64)  */          \
  V(ledtr, LEDTR, 0xB3D5) /* type = RRF_E LOAD ROUNDED (long to short DFP)  */ \
  V(fidtr, FIDTR, 0xB3D7) /* type = RRF_E LOAD FP INTEGER (long DFP)  */       \
  V(ldxtr, LDXTR,                                                              \
    0xB3DD) /* type = RRF_E LOAD ROUNDED (extended to long DFP)  */            \
  V(fixtr, FIXTR, 0xB3DF) /* type = RRF_E LOAD FP INTEGER (extended DFP)  */   \
  V(cgdtra, CGDTRA,                                                            \
    0xB3E1) /* type = RRF_E CONVERT TO FIXED (long DFP to 64)  */              \
  V(cgxtra, CGXTRA,                                                            \
    0xB3E9) /* type = RRF_E CONVERT TO FIXED (extended DFP to 64)  */          \
  V(cdgtra, CDGTRA,                                                            \
    0xB3F1) /* type = RRF_E CONVERT FROM FIXED (64 to long DFP)  */            \
  V(cxgtra, CXGTRA,                                                            \
    0xB3F9) /* type = RRF_E CONVERT FROM FIXED (64 to extended DFP)  */        \
  V(cfdtr, CFDTR, 0xB941) /* type = RRF_E CONVERT TO FIXED (long DFP to 32) */ \
  V(clgdtr, CLGDTR,                                                            \
    0xB942) /* type = RRF_E CONVERT TO LOGICAL (long DFP to 64)  */            \
  V(clfdtr, CLFDTR,                                                            \
    0xB943) /* type = RRF_E CONVERT TO LOGICAL (long DFP to 32)  */            \
  V(cfxtr, CFXTR,                                                              \
    0xB949) /* type = RRF_E CONVERT TO FIXED (extended DFP to 32)  */          \
  V(clgxtr, CLGXTR,                                                            \
    0xB94A) /* type = RRF_E CONVERT TO LOGICAL (extended DFP to 64)  */        \
  V(clfxtr, CLFXTR,                                                            \
    0xB94B) /* type = RRF_E CONVERT TO LOGICAL (extended DFP to 32)  */        \
  V(cdlgtr, CDLGTR,                                                            \
    0xB952) /* type = RRF_E CONVERT FROM LOGICAL (64 to long DFP)  */          \
  V(cdlftr, CDLFTR,                                                            \
    0xB953) /* type = RRF_E CONVERT FROM LOGICAL (32 to long DFP)  */          \
  V(cxlgtr, CXLGTR,                                                            \
    0xB95A) /* type = RRF_E CONVERT FROM LOGICAL (64 to extended DFP)  */      \
  V(cxlftr, CXLFTR,                                                            \
    0xB95B) /* type = RRF_E CONVERT FROM LOGICAL (32 to extended DFP)  */

#define S390_VRR_A_OPCODE_LIST(V)                                              \
  V(vpopct, VPOPCT, 0xE750) /* type = VRR_A VECTOR POPULATION COUNT  */        \
  V(vctz, VCTZ, 0xE752)     /* type = VRR_A VECTOR COUNT TRAILING ZEROS  */    \
  V(vclz, VCLZ, 0xE753)     /* type = VRR_A VECTOR COUNT LEADING ZEROS  */     \
  V(vlr, VLR, 0xE756)       /* type = VRR_A VECTOR LOAD  */                    \
  V(vistr, VISTR, 0xE75C)   /* type = VRR_A VECTOR ISOLATE STRING  */          \
  V(vseg, VSEG, 0xE75F) /* type = VRR_A VECTOR SIGN EXTEND TO DOUBLEWORD  */   \
  V(vclgd, VCLGD,                                                              \
    0xE7C0) /* type = VRR_A VECTOR FP CONVERT TO LOGICAL 64-BIT  */            \
  V(vcdlg, VCDLG,                                                              \
```