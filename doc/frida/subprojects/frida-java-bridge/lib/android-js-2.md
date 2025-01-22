Response:
### 功能归纳

该源代码文件是Frida动态插桩工具的一部分，主要用于在Android平台上对ART（Android Runtime）进行动态插桩和调试。具体功能包括：

1. **ART方法头的内联复制检测与插桩**：
   - 通过扫描内存中的特定模式（如ARM64指令模式），检测ART方法头的内联复制。
   - 使用`validateGetOatQuickMethodHeaderInlinedMatchArm64`等函数验证匹配的模式，并生成相应的插桩代码。

2. **ART方法替换与重定向**：
   - 通过`instrumentGetOatQuickMethodHeaderInlinedCopyArm64`等函数，生成跳转代码（trampoline），将原始方法的执行重定向到替换方法。
   - 支持ARM、ARM64、x86、x64等多种架构的代码生成。

3. **ART方法的栈回溯（Backtrace）**：
   - 通过`backtrace`函数，获取当前线程的调用栈信息，并将其转换为JSON格式。
   - 支持获取方法的签名、类名、方法名、文件名、行号等信息。

4. **ART方法的替换与恢复**：
   - 通过`revertGlobalPatches`函数，恢复被替换的ART方法。
   - 支持恢复全局的类、方法、插桩点等。

5. **ART方法的快速代码替换**：
   - 通过`writeArtQuickCodeReplacementTrampolineArm64`等函数，生成快速代码替换的跳转代码，支持在方法执行时动态替换代码。

6. **ART方法的快速代码入口插桩**：
   - 通过`writeArtQuickCodePrologueArm64`等函数，在方法的入口处插入跳转代码，支持在方法执行时动态插桩。

### 二进制底层与Linux内核相关

1. **内存扫描与模式匹配**：
   - 使用`Memory.scanSync`扫描内存中的特定模式，检测ART方法头的内联复制。
   - 例如，`validateGetOatQuickMethodHeaderInlinedMatchArm64`函数通过解析ARM64指令，验证内存中的模式是否符合预期。

2. **指令解析与重定位**：
   - 使用`Instruction.parse`解析ARM64指令，获取寄存器、操作数等信息。
   - 使用`ThumbRelocator`和`Arm64Relocator`等工具，重定位指令并生成跳转代码。

3. **线程状态转换与栈遍历**：
   - 通过`art_thread_get_long_jump_context`获取线程的上下文信息，支持栈遍历。
   - 使用`art_stack_visitor_walk_stack`遍历调用栈，获取方法的调用链。

### LLDB调试示例

假设我们想要复现`validateGetOatQuickMethodHeaderInlinedMatchArm64`函数的功能，可以使用LLDB进行调试。以下是一个LLDB Python脚本示例，用于解析ARM64指令并验证内存中的模式：

```python
import lldb

def validate_get_oat_quick_method_header_inlined_match_arm64(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    # 获取当前指令地址
    pc = frame.GetPC()
    print(f"Current PC: {pc}")

    # 读取指令
    instruction = target.ReadMemory(pc, 4, lldb.SBError())
    print(f"Instruction: {instruction.hex()}")

    # 解析指令
    # 这里假设指令是LDR指令，解析寄存器和操作数
    # 实际解析逻辑需要根据ARM64指令集实现
    opcode = int.from_bytes(instruction, byteorder='little')
    if (opcode & 0xFFC00000) == 0xF9400000:  # LDR指令的opcode
        rt = (opcode >> 0) & 0x1F
        rn = (opcode >> 5) & 0x1F
        imm12 = (opcode >> 10) & 0xFFF
        print(f"LDR指令: rt={rt}, rn={rn}, imm12={imm12}")

    # 继续解析后续指令
    # ...

# 注册LLDB命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f validate_get_oat_quick_method_header_inlined_match_arm64.validate_get_oat_quick_method_header_inlined_match_arm64 validate_get_oat_quick_method_header_inlined_match_arm64')
```

### 假设输入与输出

**假设输入**：
- 内存中的ARM64指令序列：`LDR x0, [x1, #0x18]`，`B.EQ 0x1234`，`LDR x2, [x1, #0x14]`。

**假设输出**：
- 解析出`methodReg = x1`，`scratchReg = x0`，`targetWhenTrue = 0x1234`，`targetWhenRegularMethod`和`targetWhenRuntimeMethod`分别指向不同的分支。

### 用户常见错误

1. **内存扫描失败**：
   - 用户可能错误地指定了内存扫描的范围或模式，导致无法找到预期的指令序列。
   - 例如，`Memory.scanSync`的`base`和`size`参数设置不当，可能导致扫描失败。

2. **指令解析错误**：
   - 用户可能错误地解析了指令的操作数或寄存器，导致生成的跳转代码无法正确执行。
   - 例如，`validateGetOatQuickMethodHeaderInlinedMatchArm64`函数中，如果`ldrDst`或`ldrSrc`解析错误，可能导致后续的跳转逻辑错误。

3. **线程状态转换失败**：
   - 用户可能错误地调用了`art_thread_get_long_jump_context`，导致无法获取线程的上下文信息。
   - 例如，线程未正确挂起或上下文信息未正确保存，可能导致栈遍历失败。

### 用户操作步骤

1. **启动Frida并附加到目标进程**：
   - 用户通过Frida命令行工具或脚本，附加到目标Android进程。

2. **加载并执行插桩脚本**：
   - 用户加载包含`maybeInstrumentGetOatQuickMethodHeaderInlineCopies`等函数的脚本，执行插桩操作。

3. **触发目标方法执行**：
   - 用户通过应用程序或测试用例，触发目标方法的执行，观察插桩效果。

4. **获取调用栈信息**：
   - 用户通过`backtrace`函数，获取当前线程的调用栈信息，分析方法的调用链。

5. **恢复原始代码**：
   - 用户通过`revertGlobalPatches`函数，恢复被替换的ART方法，确保应用程序的正常运行。

### 总结

该源代码文件实现了Frida在Android平台上对ART的动态插桩功能，支持多种架构的代码生成与替换。通过内存扫描、指令解析、线程状态转换等技术，实现了对ART方法的动态插桩与调试。用户可以通过Frida工具链，加载并执行这些功能，实现对Android应用程序的动态分析与调试。
Prompt: 
```
这是目录为frida/subprojects/frida-java-bridge/lib/android.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第3部分，共5部分，请归纳一下它的功能

"""
    '1f fc ff ff',
          '1f 00 00 ff',
          'e0 ff ff ff'
        ],
        offset: 1,
        validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm64
      }
    ],
    instrument: instrumentGetOatQuickMethodHeaderInlinedCopyArm64
  }
};

function validateGetOatQuickMethodHeaderInlinedMatchArm ({ address, size }) {
  const ldr = Instruction.parse(address.or(1));
  const [ldrDst, ldrSrc] = ldr.operands;
  const methodReg = ldrSrc.value.base;
  const scratchReg = ldrDst.value;

  const branch = Instruction.parse(ldr.next.add(2));
  const targetWhenTrue = ptr(branch.operands[0].value);
  const targetWhenFalse = branch.address.add(branch.size);

  let targetWhenRegularMethod, targetWhenRuntimeMethod;
  if (branch.mnemonic === 'beq') {
    targetWhenRegularMethod = targetWhenFalse;
    targetWhenRuntimeMethod = targetWhenTrue;
  } else {
    targetWhenRegularMethod = targetWhenTrue;
    targetWhenRuntimeMethod = targetWhenFalse;
  }

  return parseInstructionsAt(targetWhenRegularMethod.or(1), tryParse, { limit: 3 });

  function tryParse (insn) {
    const { mnemonic } = insn;
    if (!(mnemonic === 'ldr' || mnemonic === 'ldr.w')) {
      return null;
    }

    const { base, disp } = insn.operands[1].value;
    if (!(base === methodReg && disp === 0x14)) {
      return null;
    }

    return {
      methodReg,
      scratchReg,
      target: {
        whenTrue: targetWhenTrue,
        whenRegularMethod: targetWhenRegularMethod,
        whenRuntimeMethod: targetWhenRuntimeMethod
      }
    };
  }
}

function validateGetOatQuickMethodHeaderInlinedMatchArm64 ({ address, size }) {
  const [ldrDst, ldrSrc] = Instruction.parse(address).operands;
  const methodReg = ldrSrc.value.base;
  const scratchReg = 'x' + ldrDst.value.substring(1);

  const branch = Instruction.parse(address.add(8));
  const targetWhenTrue = ptr(branch.operands[0].value);
  const targetWhenFalse = address.add(12);

  let targetWhenRegularMethod, targetWhenRuntimeMethod;
  if (branch.mnemonic === 'b.eq') {
    targetWhenRegularMethod = targetWhenFalse;
    targetWhenRuntimeMethod = targetWhenTrue;
  } else {
    targetWhenRegularMethod = targetWhenTrue;
    targetWhenRuntimeMethod = targetWhenFalse;
  }

  return parseInstructionsAt(targetWhenRegularMethod, tryParse, { limit: 3 });

  function tryParse (insn) {
    if (insn.mnemonic !== 'ldr') {
      return null;
    }

    const { base, disp } = insn.operands[1].value;
    if (!(base === methodReg && disp === 0x18)) {
      return null;
    }

    return {
      methodReg,
      scratchReg,
      target: {
        whenTrue: targetWhenTrue,
        whenRegularMethod: targetWhenRegularMethod,
        whenRuntimeMethod: targetWhenRuntimeMethod
      }
    };
  }
}

function maybeInstrumentGetOatQuickMethodHeaderInlineCopies () {
  if (getAndroidApiLevel() < 31) {
    return false;
  }

  const handler = artGetOatQuickMethodHeaderInlinedCopyHandler[Process.arch];
  if (handler === undefined) {
    // Not needed on x86 and x64, at least not for now...
    return false;
  }

  const signatures = handler.signatures.map(({ pattern, offset = 0, validateMatch = returnEmptyObject }) => {
    return {
      pattern: new MatchPattern(pattern.join('')),
      offset,
      validateMatch
    };
  });

  const impls = [];
  for (const { base, size } of getApi().module.enumerateRanges('--x')) {
    for (const { pattern, offset, validateMatch } of signatures) {
      const matches = Memory.scanSync(base, size, pattern)
        .map(({ address, size }) => {
          return { address: address.sub(offset), size: size + offset };
        })
        .filter(match => {
          const validationResult = validateMatch(match);
          if (validationResult === null) {
            return false;
          }
          match.validationResult = validationResult;
          return true;
        });
      impls.push(...matches);
    }
  }

  if (impls.length === 0) {
    return false;
  }

  impls.forEach(handler.instrument);

  return true;
}

function returnEmptyObject () {
  return {};
}

class InlineHook {
  constructor (address, size, trampoline) {
    this.address = address;
    this.size = size;
    this.originalCode = address.readByteArray(size);
    this.trampoline = trampoline;
  }

  revert () {
    Memory.patchCode(this.address, this.size, code => {
      code.writeByteArray(this.originalCode);
    });
  }
}

function instrumentGetOatQuickMethodHeaderInlinedCopyArm ({ address, size, validationResult }) {
  const { methodReg, target } = validationResult;

  const trampoline = Memory.alloc(Process.pageSize);
  let redirectCapacity = size;

  Memory.patchCode(trampoline, 256, code => {
    const writer = new ThumbWriter(code, { pc: trampoline });

    const relocator = new ThumbRelocator(address, writer);
    for (let i = 0; i !== 2; i++) {
      relocator.readOne();
    }
    relocator.writeAll();

    relocator.readOne();
    relocator.skipOne();
    writer.putBCondLabel('eq', 'runtime_or_replacement_method');

    const vpushFpRegs = [0x2d, 0xed, 0x10, 0x0a]; /* vpush {s0-s15} */
    writer.putBytes(vpushFpRegs);

    const savedRegs = ['r0', 'r1', 'r2', 'r3'];
    writer.putPushRegs(savedRegs);

    writer.putCallAddressWithArguments(artController.replacedMethods.isReplacement, [methodReg]);
    writer.putCmpRegImm('r0', 0);

    writer.putPopRegs(savedRegs);

    const vpopFpRegs = [0xbd, 0xec, 0x10, 0x0a]; /* vpop {s0-s15} */
    writer.putBytes(vpopFpRegs);

    writer.putBCondLabel('ne', 'runtime_or_replacement_method');
    writer.putBLabel('regular_method');

    relocator.readOne();

    const tailIsRegular = relocator.input.address.equals(target.whenRegularMethod);

    writer.putLabel(tailIsRegular ? 'regular_method' : 'runtime_or_replacement_method');
    relocator.writeOne();
    while (redirectCapacity < 10) {
      const offset = relocator.readOne();
      if (offset === 0) {
        redirectCapacity = 10;
        break;
      }
      redirectCapacity = offset;
    }
    relocator.writeAll();
    writer.putBranchAddress(address.add(redirectCapacity + 1));

    writer.putLabel(tailIsRegular ? 'runtime_or_replacement_method' : 'regular_method');
    writer.putBranchAddress(target.whenTrue);

    writer.flush();
  });

  inlineHooks.push(new InlineHook(address, redirectCapacity, trampoline));

  Memory.patchCode(address, redirectCapacity, code => {
    const writer = new ThumbWriter(code, { pc: address });
    writer.putLdrRegAddress('pc', trampoline.or(1));
    writer.flush();
  });
}

function instrumentGetOatQuickMethodHeaderInlinedCopyArm64 ({ address, size, validationResult }) {
  const { methodReg, scratchReg, target } = validationResult;

  const trampoline = Memory.alloc(Process.pageSize);

  Memory.patchCode(trampoline, 256, code => {
    const writer = new Arm64Writer(code, { pc: trampoline });

    const relocator = new Arm64Relocator(address, writer);
    for (let i = 0; i !== 2; i++) {
      relocator.readOne();
    }
    relocator.writeAll();

    relocator.readOne();
    relocator.skipOne();
    writer.putBCondLabel('eq', 'runtime_or_replacement_method');

    const savedRegs = [
      'd0', 'd1',
      'd2', 'd3',
      'd4', 'd5',
      'd6', 'd7',
      'x0', 'x1',
      'x2', 'x3',
      'x4', 'x5',
      'x6', 'x7',
      'x8', 'x9',
      'x10', 'x11',
      'x12', 'x13',
      'x14', 'x15',
      'x16', 'x17'
    ];
    const numSavedRegs = savedRegs.length;

    for (let i = 0; i !== numSavedRegs; i += 2) {
      writer.putPushRegReg(savedRegs[i], savedRegs[i + 1]);
    }

    writer.putCallAddressWithArguments(artController.replacedMethods.isReplacement, [methodReg]);
    writer.putCmpRegReg('x0', 'xzr');

    for (let i = numSavedRegs - 2; i >= 0; i -= 2) {
      writer.putPopRegReg(savedRegs[i], savedRegs[i + 1]);
    }

    writer.putBCondLabel('ne', 'runtime_or_replacement_method');
    writer.putBLabel('regular_method');

    relocator.readOne();
    const tailInstruction = relocator.input;

    const tailIsRegular = tailInstruction.address.equals(target.whenRegularMethod);

    writer.putLabel(tailIsRegular ? 'regular_method' : 'runtime_or_replacement_method');
    relocator.writeOne();
    writer.putBranchAddress(tailInstruction.next);

    writer.putLabel(tailIsRegular ? 'runtime_or_replacement_method' : 'regular_method');
    writer.putBranchAddress(target.whenTrue);

    writer.flush();
  });

  inlineHooks.push(new InlineHook(address, size, trampoline));

  Memory.patchCode(address, size, code => {
    const writer = new Arm64Writer(code, { pc: address });
    writer.putLdrRegAddress(scratchReg, trampoline);
    writer.putBrReg(scratchReg);
    writer.flush();
  });
}

function makeMethodMangler (methodId) {
  return new MethodMangler(methodId);
}

function translateMethod (methodId) {
  return artController.replacedMethods.translate(methodId);
}

function backtrace (vm, options = {}) {
  const { limit = 16 } = options;

  const env = vm.getEnv();

  if (backtraceModule === null) {
    backtraceModule = makeBacktraceModule(vm, env);
  }

  return backtraceModule.backtrace(env, limit);
}

function makeBacktraceModule (vm, env) {
  const api = getApi();

  const performImpl = Memory.alloc(Process.pointerSize);

  const cm = new CModule(`
#include <glib.h>
#include <stdbool.h>
#include <string.h>
#include <gum/gumtls.h>
#include <json-glib/json-glib.h>

typedef struct _ArtBacktrace ArtBacktrace;
typedef struct _ArtStackFrame ArtStackFrame;

typedef struct _ArtStackVisitor ArtStackVisitor;
typedef struct _ArtStackVisitorVTable ArtStackVisitorVTable;

typedef struct _ArtClass ArtClass;
typedef struct _ArtMethod ArtMethod;
typedef struct _ArtThread ArtThread;
typedef struct _ArtContext ArtContext;

typedef struct _JNIEnv JNIEnv;

typedef struct _StdString StdString;
typedef struct _StdTinyString StdTinyString;
typedef struct _StdLargeString StdLargeString;

typedef enum {
  STACK_WALK_INCLUDE_INLINED_FRAMES,
  STACK_WALK_SKIP_INLINED_FRAMES,
} StackWalkKind;

struct _StdTinyString
{
  guint8 unused;
  gchar data[(3 * sizeof (gpointer)) - 1];
};

struct _StdLargeString
{
  gsize capacity;
  gsize size;
  gchar * data;
};

struct _StdString
{
  union
  {
    guint8 flags;
    StdTinyString tiny;
    StdLargeString large;
  };
};

struct _ArtBacktrace
{
  GChecksum * id;
  GArray * frames;
  gchar * frames_json;
};

struct _ArtStackFrame
{
  ArtMethod * method;
  gsize dexpc;
  StdString description;
};

struct _ArtStackVisitorVTable
{
  void (* unused1) (void);
  void (* unused2) (void);
  bool (* visit) (ArtStackVisitor * visitor);
};

struct _ArtStackVisitor
{
  ArtStackVisitorVTable * vtable;

  guint8 padding[512];

  ArtStackVisitorVTable vtable_storage;

  ArtBacktrace * backtrace;
};

struct _ArtMethod
{
  guint32 declaring_class;
  guint32 access_flags;
};

extern GumTlsKey current_backtrace;

extern void (* perform_art_thread_state_transition) (JNIEnv * env);

extern ArtContext * art_thread_get_long_jump_context (ArtThread * thread);

extern void art_stack_visitor_init (ArtStackVisitor * visitor, ArtThread * thread, void * context, StackWalkKind walk_kind,
    size_t num_frames, bool check_suspended);
extern void art_stack_visitor_walk_stack (ArtStackVisitor * visitor, bool include_transitions);
extern ArtMethod * art_stack_visitor_get_method (ArtStackVisitor * visitor);
extern void art_stack_visitor_describe_location (StdString * description, ArtStackVisitor * visitor);
extern ArtMethod * translate_method (ArtMethod * method);
extern void translate_location (ArtMethod * method, guint32 pc, const gchar ** source_file, gint32 * line_number);
extern void get_class_location (StdString * result, ArtClass * klass);
extern void cxx_delete (void * mem);
extern unsigned long strtoul (const char * str, char ** endptr, int base);

static bool visit_frame (ArtStackVisitor * visitor);
static void art_stack_frame_destroy (ArtStackFrame * frame);

static void append_jni_type_name (GString * s, const gchar * name, gsize length);

static void std_string_destroy (StdString * str);
static gchar * std_string_get_data (StdString * str);

void
init (void)
{
  current_backtrace = gum_tls_key_new ();
}

void
finalize (void)
{
  gum_tls_key_free (current_backtrace);
}

ArtBacktrace *
_create (JNIEnv * env,
         guint limit)
{
  ArtBacktrace * bt;

  bt = g_new (ArtBacktrace, 1);
  bt->id = g_checksum_new (G_CHECKSUM_SHA1);
  bt->frames = (limit != 0)
      ? g_array_sized_new (FALSE, FALSE, sizeof (ArtStackFrame), limit)
      : g_array_new (FALSE, FALSE, sizeof (ArtStackFrame));
  g_array_set_clear_func (bt->frames, (GDestroyNotify) art_stack_frame_destroy);
  bt->frames_json = NULL;

  gum_tls_key_set_value (current_backtrace, bt);

  perform_art_thread_state_transition (env);

  gum_tls_key_set_value (current_backtrace, NULL);

  return bt;
}

void
_on_thread_state_transition_complete (ArtThread * thread)
{
  ArtContext * context;
  ArtStackVisitor visitor = {
    .vtable_storage = {
      .visit = visit_frame,
    },
  };

  context = art_thread_get_long_jump_context (thread);

  art_stack_visitor_init (&visitor, thread, context, STACK_WALK_SKIP_INLINED_FRAMES, 0, true);
  visitor.vtable = &visitor.vtable_storage;
  visitor.backtrace = gum_tls_key_get_value (current_backtrace);

  art_stack_visitor_walk_stack (&visitor, false);

  cxx_delete (context);
}

static bool
visit_frame (ArtStackVisitor * visitor)
{
  ArtBacktrace * bt = visitor->backtrace;
  ArtStackFrame frame;
  const gchar * description, * dexpc_part;

  frame.method = art_stack_visitor_get_method (visitor);

  art_stack_visitor_describe_location (&frame.description, visitor);

  description = std_string_get_data (&frame.description);
  if (strstr (description, " '<") != NULL)
    goto skip;

  dexpc_part = strstr (description, " at dex PC 0x");
  if (dexpc_part == NULL)
    goto skip;
  frame.dexpc = strtoul (dexpc_part + 13, NULL, 16);

  g_array_append_val (bt->frames, frame);

  g_checksum_update (bt->id, (guchar *) &frame.method, sizeof (frame.method));
  g_checksum_update (bt->id, (guchar *) &frame.dexpc, sizeof (frame.dexpc));

  return true;

skip:
  std_string_destroy (&frame.description);
  return true;
}

static void
art_stack_frame_destroy (ArtStackFrame * frame)
{
  std_string_destroy (&frame->description);
}

void
_destroy (ArtBacktrace * backtrace)
{
  g_free (backtrace->frames_json);
  g_array_free (backtrace->frames, TRUE);
  g_checksum_free (backtrace->id);
  g_free (backtrace);
}

const gchar *
_get_id (ArtBacktrace * backtrace)
{
  return g_checksum_get_string (backtrace->id);
}

const gchar *
_get_frames (ArtBacktrace * backtrace)
{
  GArray * frames = backtrace->frames;
  JsonBuilder * b;
  guint i;
  JsonNode * root;

  if (backtrace->frames_json != NULL)
    return backtrace->frames_json;

  b = json_builder_new_immutable ();

  json_builder_begin_array (b);

  for (i = 0; i != frames->len; i++)
  {
    ArtStackFrame * frame = &g_array_index (frames, ArtStackFrame, i);
    gchar * description, * ret_type, * paren_open, * paren_close, * arg_types, * token, * method_name, * class_name;
    GString * signature;
    gchar * cursor;
    ArtMethod * translated_method;
    StdString location;
    gsize dexpc;
    const gchar * source_file;
    gint32 line_number;

    description = std_string_get_data (&frame->description);

    ret_type = strchr (description, '\\'') + 1;

    paren_open = strchr (ret_type, '(');
    paren_close = strchr (paren_open, ')');
    *paren_open = '\\0';
    *paren_close = '\\0';

    arg_types = paren_open + 1;

    token = strrchr (ret_type, '.');
    *token = '\\0';

    method_name = token + 1;

    token = strrchr (ret_type, ' ');
    *token = '\\0';

    class_name = token + 1;

    signature = g_string_sized_new (128);

    append_jni_type_name (signature, class_name, method_name - class_name - 1);
    g_string_append_c (signature, ',');
    g_string_append (signature, method_name);
    g_string_append (signature, ",(");

    if (arg_types != paren_close)
    {
      for (cursor = arg_types; cursor != NULL;)
      {
        gsize length;
        gchar * next;

        token = strstr (cursor, ", ");
        if (token != NULL)
        {
          length = token - cursor;
          next = token + 2;
        }
        else
        {
          length = paren_close - cursor;
          next = NULL;
        }

        append_jni_type_name (signature, cursor, length);

        cursor = next;
      }
    }

    g_string_append_c (signature, ')');

    append_jni_type_name (signature, ret_type, class_name - ret_type - 1);

    translated_method = translate_method (frame->method);
    dexpc = (translated_method == frame->method) ? frame->dexpc : 0;

    get_class_location (&location, GSIZE_TO_POINTER (translated_method->declaring_class));

    translate_location (translated_method, dexpc, &source_file, &line_number);

    json_builder_begin_object (b);

    json_builder_set_member_name (b, "signature");
    json_builder_add_string_value (b, signature->str);

    json_builder_set_member_name (b, "origin");
    json_builder_add_string_value (b, std_string_get_data (&location));

    json_builder_set_member_name (b, "className");
    json_builder_add_string_value (b, class_name);

    json_builder_set_member_name (b, "methodName");
    json_builder_add_string_value (b, method_name);

    json_builder_set_member_name (b, "methodFlags");
    json_builder_add_int_value (b, translated_method->access_flags);

    json_builder_set_member_name (b, "fileName");
    json_builder_add_string_value (b, source_file);

    json_builder_set_member_name (b, "lineNumber");
    json_builder_add_int_value (b, line_number);

    json_builder_end_object (b);

    std_string_destroy (&location);
    g_string_free (signature, TRUE);
  }

  json_builder_end_array (b);

  root = json_builder_get_root (b);
  backtrace->frames_json = json_to_string (root, FALSE);
  json_node_unref (root);

  return backtrace->frames_json;
}

static void
append_jni_type_name (GString * s,
                      const gchar * name,
                      gsize length)
{
  gchar shorty = '\\0';
  gsize i;

  switch (name[0])
  {
    case 'b':
      if (strncmp (name, "boolean", length) == 0)
        shorty = 'Z';
      else if (strncmp (name, "byte", length) == 0)
        shorty = 'B';
      break;
    case 'c':
      if (strncmp (name, "char", length) == 0)
        shorty = 'C';
      break;
    case 'd':
      if (strncmp (name, "double", length) == 0)
        shorty = 'D';
      break;
    case 'f':
      if (strncmp (name, "float", length) == 0)
        shorty = 'F';
      break;
    case 'i':
      if (strncmp (name, "int", length) == 0)
        shorty = 'I';
      break;
    case 'l':
      if (strncmp (name, "long", length) == 0)
        shorty = 'J';
      break;
    case 's':
      if (strncmp (name, "short", length) == 0)
        shorty = 'S';
      break;
    case 'v':
      if (strncmp (name, "void", length) == 0)
        shorty = 'V';
      break;
  }

  if (shorty != '\\0')
  {
    g_string_append_c (s, shorty);

    return;
  }

  if (length > 2 && name[length - 2] == '[' && name[length - 1] == ']')
  {
    g_string_append_c (s, '[');
    append_jni_type_name (s, name, length - 2);

    return;
  }

  g_string_append_c (s, 'L');

  for (i = 0; i != length; i++)
  {
    gchar ch = name[i];
    if (ch != '.')
      g_string_append_c (s, ch);
    else
      g_string_append_c (s, '/');
  }

  g_string_append_c (s, ';');
}

static void
std_string_destroy (StdString * str)
{
  bool is_large = (str->flags & 1) != 0;
  if (is_large)
    cxx_delete (str->large.data);
}

static gchar *
std_string_get_data (StdString * str)
{
  bool is_large = (str->flags & 1) != 0;
  return is_large ? str->large.data : str->tiny.data;
}
`, {
    current_backtrace: Memory.alloc(Process.pointerSize),
    perform_art_thread_state_transition: performImpl,
    art_thread_get_long_jump_context: api['art::Thread::GetLongJumpContext'],
    art_stack_visitor_init: api['art::StackVisitor::StackVisitor'],
    art_stack_visitor_walk_stack: api['art::StackVisitor::WalkStack'],
    art_stack_visitor_get_method: api['art::StackVisitor::GetMethod'],
    art_stack_visitor_describe_location: api['art::StackVisitor::DescribeLocation'],
    translate_method: artController.replacedMethods.translate,
    translate_location: api['art::Monitor::TranslateLocation'],
    get_class_location: api['art::mirror::Class::GetLocation'],
    cxx_delete: api.$delete,
    strtoul: Module.getExportByName('libc.so', 'strtoul')
  });

  const _create = new NativeFunction(cm._create, 'pointer', ['pointer', 'uint'], nativeFunctionOptions);
  const _destroy = new NativeFunction(cm._destroy, 'void', ['pointer'], nativeFunctionOptions);

  const fastOptions = { exceptions: 'propagate', scheduling: 'exclusive' };
  const _getId = new NativeFunction(cm._get_id, 'pointer', ['pointer'], fastOptions);
  const _getFrames = new NativeFunction(cm._get_frames, 'pointer', ['pointer'], fastOptions);

  const performThreadStateTransition = makeArtThreadStateTransitionImpl(vm, env, cm._on_thread_state_transition_complete);
  cm._performData = performThreadStateTransition;
  performImpl.writePointer(performThreadStateTransition);

  cm.backtrace = (env, limit) => {
    const handle = _create(env, limit);
    const bt = new Backtrace(handle);
    Script.bindWeak(bt, destroy.bind(null, handle));
    return bt;
  };

  function destroy (handle) {
    _destroy(handle);
  }

  cm.getId = handle => {
    return _getId(handle).readUtf8String();
  };

  cm.getFrames = handle => {
    return JSON.parse(_getFrames(handle).readUtf8String());
  };

  return cm;
}

class Backtrace {
  constructor (handle) {
    this.handle = handle;
  }

  get id () {
    return backtraceModule.getId(this.handle);
  }

  get frames () {
    return backtraceModule.getFrames(this.handle);
  }
}

function revertGlobalPatches () {
  patchedClasses.forEach(entry => {
    entry.vtablePtr.writePointer(entry.vtable);
    entry.vtableCountPtr.writeS32(entry.vtableCount);
  });
  patchedClasses.clear();

  for (const interceptor of artQuickInterceptors.splice(0)) {
    interceptor.deactivate();
  }

  for (const hook of inlineHooks.splice(0)) {
    hook.revert();
  }
}

function unwrapMethodId (methodId) {
  const api = getApi();

  const runtimeOffset = getArtRuntimeSpec(api).offset;
  const jniIdManagerOffset = runtimeOffset.jniIdManager;
  const jniIdsIndirectionOffset = runtimeOffset.jniIdsIndirection;

  if (jniIdManagerOffset !== null && jniIdsIndirectionOffset !== null) {
    const runtime = api.artRuntime;

    const jniIdsIndirection = runtime.add(jniIdsIndirectionOffset).readInt();

    if (jniIdsIndirection !== kPointer) {
      const jniIdManager = runtime.add(jniIdManagerOffset).readPointer();
      return api['art::jni::JniIdManager::DecodeMethodId'](jniIdManager, methodId);
    }
  }

  return methodId;
}

const artQuickCodeReplacementTrampolineWriters = {
  ia32: writeArtQuickCodeReplacementTrampolineIA32,
  x64: writeArtQuickCodeReplacementTrampolineX64,
  arm: writeArtQuickCodeReplacementTrampolineArm,
  arm64: writeArtQuickCodeReplacementTrampolineArm64
};

function writeArtQuickCodeReplacementTrampolineIA32 (trampoline, target, redirectSize, constraints, vm) {
  const threadOffsets = getArtThreadSpec(vm).offset;
  const artMethodOffsets = getArtMethodSpec(vm).offset;

  let offset;
  Memory.patchCode(trampoline, 128, code => {
    const writer = new X86Writer(code, { pc: trampoline });
    const relocator = new X86Relocator(target, writer);

    const fxsave = [0x0f, 0xae, 0x04, 0x24]; /* fxsave [esp] */
    const fxrstor = [0x0f, 0xae, 0x0c, 0x24]; /* fxrstor [esp] */

    // Save core args & callee-saves.
    writer.putPushax();

    writer.putMovRegReg('ebp', 'esp');

    // Save FPRs + alignment padding.
    writer.putAndRegU32('esp', 0xfffffff0);
    writer.putSubRegImm('esp', 512);
    writer.putBytes(fxsave);

    writer.putMovRegFsU32Ptr('ebx', threadOffsets.self);
    writer.putCallAddressWithAlignedArguments(artController.replacedMethods.findReplacementFromQuickCode, ['eax', 'ebx']);

    writer.putTestRegReg('eax', 'eax');
    writer.putJccShortLabel('je', 'restore_registers', 'no-hint');

    // Set value of eax in the current frame.
    writer.putMovRegOffsetPtrReg('ebp', 7 * 4, 'eax');

    writer.putLabel('restore_registers');

    // Restore FPRs.
    writer.putBytes(fxrstor);

    writer.putMovRegReg('esp', 'ebp');

    // Restore core args & callee-saves.
    writer.putPopax();

    writer.putJccShortLabel('jne', 'invoke_replacement', 'no-hint');

    do {
      offset = relocator.readOne();
    } while (offset < redirectSize && !relocator.eoi);

    relocator.writeAll();

    if (!relocator.eoi) {
      writer.putJmpAddress(target.add(offset));
    }

    writer.putLabel('invoke_replacement');

    writer.putJmpRegOffsetPtr('eax', artMethodOffsets.quickCode);

    writer.flush();
  });

  return offset;
}

function writeArtQuickCodeReplacementTrampolineX64 (trampoline, target, redirectSize, constraints, vm) {
  const threadOffsets = getArtThreadSpec(vm).offset;
  const artMethodOffsets = getArtMethodSpec(vm).offset;

  let offset;
  Memory.patchCode(trampoline, 256, code => {
    const writer = new X86Writer(code, { pc: trampoline });
    const relocator = new X86Relocator(target, writer);

    const fxsave = [0x0f, 0xae, 0x04, 0x24]; /* fxsave [rsp] */
    const fxrstor = [0x0f, 0xae, 0x0c, 0x24]; /* fxrstor [rsp] */

    // Save core args & callee-saves.
    writer.putPushax();

    writer.putMovRegReg('rbp', 'rsp');

    // Save FPRs + alignment padding.
    writer.putAndRegU32('rsp', 0xfffffff0);
    writer.putSubRegImm('rsp', 512);
    writer.putBytes(fxsave);

    writer.putMovRegGsU32Ptr('rbx', threadOffsets.self);
    writer.putCallAddressWithAlignedArguments(artController.replacedMethods.findReplacementFromQuickCode, ['rdi', 'rbx']);

    writer.putTestRegReg('rax', 'rax');
    writer.putJccShortLabel('je', 'restore_registers', 'no-hint');

    // Set value of rdi in the current frame.
    writer.putMovRegOffsetPtrReg('rbp', 8 * 8, 'rax');

    writer.putLabel('restore_registers');

    // Restore FPRs.
    writer.putBytes(fxrstor);

    writer.putMovRegReg('rsp', 'rbp');

    // Restore core args & callee-saves.
    writer.putPopax();

    writer.putJccShortLabel('jne', 'invoke_replacement', 'no-hint');

    do {
      offset = relocator.readOne();
    } while (offset < redirectSize && !relocator.eoi);

    relocator.writeAll();

    if (!relocator.eoi) {
      writer.putJmpAddress(target.add(offset));
    }

    writer.putLabel('invoke_replacement');

    writer.putJmpRegOffsetPtr('rdi', artMethodOffsets.quickCode);

    writer.flush();
  });

  return offset;
}

function writeArtQuickCodeReplacementTrampolineArm (trampoline, target, redirectSize, constraints, vm) {
  const artMethodOffsets = getArtMethodSpec(vm).offset;

  const targetAddress = target.and(THUMB_BIT_REMOVAL_MASK);

  let offset;
  Memory.patchCode(trampoline, 128, code => {
    const writer = new ThumbWriter(code, { pc: trampoline });
    const relocator = new ThumbRelocator(targetAddress, writer);

    const vpushFpRegs = [0x2d, 0xed, 0x10, 0x0a]; /* vpush {s0-s15} */
    const vpopFpRegs = [0xbd, 0xec, 0x10, 0x0a]; /* vpop {s0-s15} */

    // Save core args, callee-saves, LR.
    writer.putPushRegs([
      'r1',
      'r2',
      'r3',
      'r5',
      'r6',
      'r7',
      'r8',
      'r10',
      'r11',
      'lr'
    ]);

    // Save FPRs.
    writer.putBytes(vpushFpRegs);

    // Save ArtMethod* + alignment padding.
    writer.putSubRegRegImm('sp', 'sp', 8);
    writer.putStrRegRegOffset('r0', 'sp', 0);

    writer.putCallAddressWithArguments(artController.replacedMethods.findReplacementFromQuickCode, ['r0', 'r9']);

    writer.putCmpRegImm('r0', 0);
    writer.putBCondLabel('eq', 'restore_registers');

    // Set value of r0 in the current frame.
    writer.putStrRegRegOffset('r0', 'sp', 0);

    writer.putLabel('restore_registers');

    // Restore ArtMethod*
    writer.putLdrRegRegOffset('r0', 'sp', 0);
    writer.putAddRegRegImm('sp', 'sp', 8);

    // Restore FPRs.
    writer.putBytes(vpopFpRegs);

    // Restore LR, callee-saves & core args.
    writer.putPopRegs([
      'lr',
      'r11',
      'r10',
      'r8',
      'r7',
      'r6',
      'r5',
      'r3',
      'r2',
      'r1'
    ]);

    writer.putBCondLabel('ne', 'invoke_replacement');

    do {
      offset = relocator.readOne();
    } while (offset < redirectSize && !relocator.eoi);

    relocator.writeAll();

    if (!relocator.eoi) {
      writer.putLdrRegAddress('pc', target.add(offset));
    }

    writer.putLabel('invoke_replacement');

    writer.putLdrRegRegOffset('pc', 'r0', artMethodOffsets.quickCode);

    writer.flush();
  });

  return offset;
}

function writeArtQuickCodeReplacementTrampolineArm64 (trampoline, target, redirectSize, { availableScratchRegs }, vm) {
  const artMethodOffsets = getArtMethodSpec(vm).offset;

  let offset;
  Memory.patchCode(trampoline, 256, code => {
    const writer = new Arm64Writer(code, { pc: trampoline });
    const relocator = new Arm64Relocator(target, writer);

    // Save FPRs.
    writer.putPushRegReg('d0', 'd1');
    writer.putPushRegReg('d2', 'd3');
    writer.putPushRegReg('d4', 'd5');
    writer.putPushRegReg('d6', 'd7');

    // Save core args, callee-saves & LR.
    writer.putPushRegReg('x1', 'x2');
    writer.putPushRegReg('x3', 'x4');
    writer.putPushRegReg('x5', 'x6');
    writer.putPushRegReg('x7', 'x20');
    writer.putPushRegReg('x21', 'x22');
    writer.putPushRegReg('x23', 'x24');
    writer.putPushRegReg('x25', 'x26');
    writer.putPushRegReg('x27', 'x28');
    writer.putPushRegReg('x29', 'lr');

    // Save ArtMethod* + alignment padding.
    writer.putSubRegRegImm('sp', 'sp', 16);
    writer.putStrRegRegOffset('x0', 'sp', 0);

    writer.putCallAddressWithArguments(artController.replacedMethods.findReplacementFromQuickCode, ['x0', 'x19']);

    writer.putCmpRegReg('x0', 'xzr');
    writer.putBCondLabel('eq', 'restore_registers');

    // Set value of x0 in the current frame.
    writer.putStrRegRegOffset('x0', 'sp', 0);

    writer.putLabel('restore_registers');

    // Restore ArtMethod*
    writer.putLdrRegRegOffset('x0', 'sp', 0);
    writer.putAddRegRegImm('sp', 'sp', 16);

    // Restore core args, callee-saves & LR.
    writer.putPopRegReg('x29', 'lr');
    writer.putPopRegReg('x27', 'x28');
    writer.putPopRegReg('x25', 'x26');
    writer.putPopRegReg('x23', 'x24');
    writer.putPopRegReg('x21', 'x22');
    writer.putPopRegReg('x7', 'x20');
    writer.putPopRegReg('x5', 'x6');
    writer.putPopRegReg('x3', 'x4');
    writer.putPopRegReg('x1', 'x2');

    // Restore FPRs.
    writer.putPopRegReg('d6', 'd7');
    writer.putPopRegReg('d4', 'd5');
    writer.putPopRegReg('d2', 'd3');
    writer.putPopRegReg('d0', 'd1');

    writer.putBCondLabel('ne', 'invoke_replacement');

    do {
      offset = relocator.readOne();
    } while (offset < redirectSize && !relocator.eoi);

    relocator.writeAll();

    if (!relocator.eoi) {
      const scratchReg = Array.from(availableScratchRegs)[0];
      writer.putLdrRegAddress(scratchReg, target.add(offset));
      writer.putBrReg(scratchReg);
    }

    writer.putLabel('invoke_replacement');

    writer.putLdrRegRegOffset('x16', 'x0', artMethodOffsets.quickCode);
    writer.putBrReg('x16');

    writer.flush();
  });

  return offset;
}

const artQuickCodePrologueWriters = {
  ia32: writeArtQuickCodePrologueX86,
  x64: writeArtQuickCodePrologueX86,
  arm: writeArtQuickCodePrologueArm,
  arm64: writeArtQuickCodePrologueArm64
};

function writeArtQuickCodePrologueX86 (target, trampoline, redirectSize) {
  Memory.patchCode(target, 16, code => {
    const writer = new X86Writer(code, { pc: target });

    writer.putJmpAddress(trampoline);
    writer.flush();
  });
}

function writeArtQuickCodePrologueArm (target, trampoline, redirectSize) {
  const targetAddress = target.and(THUMB_BIT_REMOVAL_MASK);

  Memory.patchCode(targetAddress, 16, code => {
    const writer = new ThumbWriter(code, { pc: targetAddress });

    writer.putLdrRegAddress('pc', trampoline.or(1));
    writer.flush();
  });
}

function writeArtQuickCodePrologueArm64 (target, trampoline, redirectSize) {
  Memory.patchCode(target, 16, code => {
    const writer = new Arm64Writer(code, { pc: target });

    if (redirectSize === 16) {
      writer.putLdrRegAddress('x16', trampoline);
    } else {
      writer.putAdrpRegAddress('x16', trampoline);
    }

    writer.putBrReg('x16');

    writer.flush();
  });
}

const artQuickCodeHookRedirectSize = {
  ia32: 5,
  x64: 16,
  arm: 8
"""


```