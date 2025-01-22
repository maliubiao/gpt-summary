Response:
### 功能概述

`reportcrash.js` 是 Frida 工具中的一个脚本，主要用于在 macOS 系统中捕获和分析崩溃报告（Crash Report）。它通过拦截和修改系统崩溃报告相关的函数，实现了对崩溃报告的定制化处理。以下是该脚本的主要功能：

1. **崩溃报告捕获**：
   - 通过拦截 `CrashReport` 类的初始化方法，捕获崩溃报告的相关信息，如崩溃的进程 ID（PID）、线程状态等。
   - 通过拦截 `isActionable` 方法，强制将崩溃报告标记为可操作的（actionable），即使系统认为该崩溃报告不可操作。

2. **符号化处理**：
   - 通过拦截 `CSSymbolicatorGetSymbolWithAddressAtTime` 和 `CSIsNull` 等函数，实现对崩溃报告中地址的符号化处理，即将内存地址转换为可读的函数名。

3. **日志处理**：
   - 通过拦截 `rename`、`open_dprotected_np` 和 `write` 等系统调用，捕获崩溃报告的日志内容，并将其保存到内存中。
   - 通过拦截 `OSAPreferencesGetBoolValue` 函数，强制启用崩溃报告的符号化处理。

4. **动态库信息处理**：
   - 通过拦截 `dyld_process_info_base::make` 和 `withRemoteBuffer` 等函数，处理动态库的加载信息，确保崩溃报告中包含所有相关的动态库信息。

5. **堆栈修复**：
   - 通过拦截 `VMUSampler` 和 `VMUBacktrace` 类的方法，修复崩溃报告中的堆栈信息，确保堆栈信息的准确性。

### 二进制底层与 Linux 内核

虽然该脚本主要针对 macOS 系统，但其中涉及的一些概念和技术在 Linux 系统中也有类似的应用。例如：

- **符号化处理**：在 Linux 系统中，`addr2line` 和 `gdb` 等工具可以用于将内存地址转换为函数名和源代码行号。
- **动态库信息处理**：在 Linux 系统中，`dlopen` 和 `dlsym` 等函数可以用于动态加载和解析共享库中的符号。
- **堆栈修复**：在 Linux 系统中，`backtrace` 和 `backtrace_symbols` 等函数可以用于获取和解析堆栈信息。

### LLDB 调试示例

假设我们想要复现 `reportcrash.js` 中捕获崩溃报告的功能，可以使用 LLDB 进行调试。以下是一个简单的 LLDB Python 脚本示例，用于捕获崩溃报告的相关信息：

```python
import lldb

def capture_crash_report(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()

    # 获取崩溃的线程 ID 和进程 ID
    thread_id = thread.GetThreadID()
    process_id = process.GetProcessID()

    # 打印崩溃信息
    print(f"Crash detected in thread {thread_id} of process {process_id}")

    # 获取堆栈信息
    for frame in thread:
        print(f"Frame {frame.GetFrameID()}: {frame.GetFunctionName()} at {frame.GetPC()}")

# 注册 LLDB 命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f lldb_script.capture_crash_report capture_crash_report')
```

### 假设输入与输出

假设输入为一个崩溃的进程，输出为捕获的崩溃报告信息。例如：

- **输入**：一个崩溃的进程，崩溃时触发了 `CrashReport` 类的初始化方法。
- **输出**：
  ```
  Crash detected in thread 12345 of process 67890
  Frame 0: main at 0x100000000
  Frame 1: foo at 0x100000100
  Frame 2: bar at 0x100000200
  ```

### 用户常见错误

1. **符号化失败**：
   - **错误**：崩溃报告中的地址无法符号化，显示为内存地址而非函数名。
   - **原因**：可能缺少符号文件或符号化工具未正确配置。
   - **解决方法**：确保符号文件存在，并正确配置符号化工具。

2. **崩溃报告丢失**：
   - **错误**：崩溃报告未生成或未保存。
   - **原因**：可能由于权限问题或路径配置错误。
   - **解决方法**：检查权限和路径配置，确保崩溃报告能够正确生成和保存。

### 用户操作步骤

1. **启动 Frida**：用户启动 Frida 并加载 `reportcrash.js` 脚本。
2. **触发崩溃**：用户运行目标应用程序，并触发崩溃。
3. **捕获崩溃报告**：Frida 脚本拦截崩溃报告相关的系统调用，捕获崩溃信息。
4. **符号化处理**：Frida 脚本对捕获的崩溃信息进行符号化处理，生成可读的崩溃报告。
5. **保存日志**：Frida 脚本将崩溃报告保存到指定路径，供用户分析。

通过以上步骤，用户可以一步步地捕获和分析崩溃报告，定位应用程序中的问题。
Prompt: 
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/src/darwin/agent/reportcrash.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
const LIBSYSTEM_KERNEL_PATH = '/usr/lib/system/libsystem_kernel.dylib';
const CORESYMBOLICATION_PATH = '/System/Library/PrivateFrameworks/CoreSymbolication.framework/CoreSymbolication';
const CRASH_REPORTER_SUPPORT_PATH = '/System/Library/PrivateFrameworks/CrashReporterSupport.framework/CrashReporterSupport';
const YES = ptr(1);

const CSTypeRef = ['pointer', 'pointer'];
const kCSNow = uint64('0x8000000000000000');
const NSUTF8StringEncoding = 4;

const { pointerSize } = Process;

const simpleFuncOptions = {
  scheduling: 'exclusive',
  exceptions: 'propagate'
};
const complexFuncOptions = {
  scheduling: 'cooperative',
  exceptions: 'propagate'
};
const _pidForTask = new NativeFunction(
    Module.getExportByName(LIBSYSTEM_KERNEL_PATH, 'pid_for_task'),
    'int',
    ['uint', 'pointer'],
    simpleFuncOptions
);
const unlink = new NativeFunction(
    Module.getExportByName(LIBSYSTEM_KERNEL_PATH, 'unlink'),
    'int',
    ['pointer'],
    simpleFuncOptions
);
const CSSymbolicatorGetSymbolWithAddressAtTime = new NativeFunction(
    Module.getExportByName(CORESYMBOLICATION_PATH, 'CSSymbolicatorGetSymbolWithAddressAtTime'),
    CSTypeRef,
    [CSTypeRef, 'uint64', 'uint64'],
    complexFuncOptions
);
const CSIsNull = new NativeFunction(
    Module.getExportByName(CORESYMBOLICATION_PATH, 'CSIsNull'),
    'int',
    [CSTypeRef],
    simpleFuncOptions
);
const mappedMemoryRead = new NativeFunction(
    Module.getExportByName(CORESYMBOLICATION_PATH, 'mapped_memory_read'),
    'uint',
    ['pointer', 'uint64', 'uint64', 'pointer'],
    simpleFuncOptions
);
const mappedMemoryReadPointer = new NativeFunction(
    Module.getExportByName(CORESYMBOLICATION_PATH, 'mapped_memory_read_pointer'),
    'uint',
    ['pointer', 'uint64', 'pointer'],
    simpleFuncOptions
);

const {
  AppleErrorReport,
  CrashReport,
  NSMutableDictionary,
  NSString,
  OSALog,
  OSAReport,
} = ObjC.classes;

const sessions = new Map();
let osaHookState = 'pending';

function initialize() {
  const listener = Interceptor.attach(Module.getExportByName(CRASH_REPORTER_SUPPORT_PATH, 'CRCreateDirectoryStructure'), () => {
    applyInstrumentation();
    listener.detach();
  });
}

function createSession(threadId, crashedPid) {
  const session = {
    crashedPid,
    is64Bit: null,
    forcedByUs: false,
    logPath: null,
    logFd: null,
    logChunks: [],
    mappedAgents: []
  };

  sessions.set(threadId, session);

  return session;
}

function terminateSession(threadId) {
  const session = getSession(threadId, 'terminateSession');

  send(['crash-received', session.crashedPid, session.logChunks.join('')]);

  sessions.delete(threadId);
}

function getSession(threadId, operation) {
  const session = sessions.get(threadId);
  if (session === undefined) {
    throw new Error(`${operation}: missing session for thread ${threadId}`);
  }
  return session;
}

function findSession(threadId) {
  return sessions.get(threadId) ?? null;
}

function applyInstrumentation() {
  const CrashReportImpl = findCrashReportClass() ?? CrashReport;

  Interceptor.attach(CrashReportImpl['- initWithTask:exceptionType:thread:threadStateFlavor:threadState:threadStateCount:'].implementation, {
    onEnter(args) {
      const task = args[2].toUInt32();
      const crashedPid = pidForTask(task);

      const session = createSession(this.threadId, crashedPid);

      send(['crash-detected', crashedPid]);
      const op = recv('mapped-agents', message => {
        session.mappedAgents = message.payload.map(agent => {
          return {
            machHeaderAddress: uint64(agent.machHeaderAddress),
            uuid: agent.uuid,
            path: agent.path,
          };
        });
      });
      op.wait();
    }
  });

  Interceptor.attach(CrashReportImpl['- isActionable'].implementation, {
    onLeave(retval) {
      const isActionable = !!retval.toInt32();
      const session = getSession(this.threadId, 'isActionable');
      if (!isActionable) {
        retval.replace(YES);
        session.forcedByUs = true;
      }
    },
  });

  Interceptor.attach(Module.getExportByName(CORESYMBOLICATION_PATH, 'task_is_64bit'), {
    onEnter(args) {
      this.pid = pidForTask(args[0].toUInt32());
    },
    onLeave(retval) {
      const session = findSession(this.threadId);
      if (this.pid === session?.crashedPid)
        session.is64Bit = !!retval.toUInt32();
    }
  });

  Interceptor.attach(CrashReportImpl['- isActionable'].implementation, {
    onLeave(retval) {
      const isActionable = !!retval.toInt32();
      const session = getSession(this.threadId, 'isActionable');
      if (!isActionable) {
        retval.replace(YES);
        session.forcedByUs = true;
      }
    },
  });

  const methodName = (OSAReport !== undefined)
      ? '- osa_logCounter_isLog:byKey:count:withinLimit:withOptions:'
      : '- logCounter_isLog:byKey:count:withinLimit:withOptions:';
  Interceptor.attach(NSMutableDictionary[methodName].implementation, {
    onLeave(retval) {
      const isWithinLimit = !!retval.toInt32();
      const session = getSession(this.threadId, 'isWithinLimit');
      if (!isWithinLimit) {
        retval.replace(YES);
        session.forcedByUs = true;
      }
    },
  });

  const saveImpl = (OSAReport !== undefined)
      ? OSAReport['- saveWithOptions:'].implementation
      : AppleErrorReport['- saveToDir:'].implementation;
  Interceptor.attach(saveImpl, {
    onLeave(retval) {
      const session = findSession(this.threadId);
      if (session === null)
        return;

      if (session.forcedByUs)
        unlink(Memory.allocUtf8String(session.logPath));

      terminateSession(this.threadId);
    },
  });

  const createForSubmission = OSALog?.['+ createForSubmission:metadata:options:error:writing:'];
  if (createForSubmission !== undefined) {
    Interceptor.attach(createForSubmission.implementation, {
      onLeave(retval) {
        const session = findSession(this.threadId);
        if (session === null)
          return;

        const log = new ObjC.Object(retval);
        const filePath = log.filepath();
        const logPath = filePath.toString();
        session.logPath = logPath;

        if (logPath.includes('.forced-by-frida'))
          session.forcedByUs = true;

        session.logChunks.push(NSString.stringWithContentsOfFile_encoding_error_(filePath, NSUTF8StringEncoding, NULL).toString());
      }
    });
  } else {
    Interceptor.attach(Module.getExportByName(LIBSYSTEM_KERNEL_PATH, 'rename'), {
      onEnter(args) {
        const newPath = args[1].readUtf8String();
        const session = getSession(this.threadId, 'rename');
        if (/\.ips$/.test(newPath))
          session.logPath = newPath;
      },
    });

    Interceptor.attach(Module.getExportByName(LIBSYSTEM_KERNEL_PATH, 'open_dprotected_np'), {
      onEnter(args) {
        const path = args[0].readUtf8String();
        this.isCrashLog = /\.ips$/.test(path);
      },
      onLeave(retval) {
        const session = getSession(this.threadId, 'open_dprotected_np');
        if (this.isCrashLog)
          session.logFd = retval.toInt32();
      },
    });

    Interceptor.attach(Module.getExportByName(LIBSYSTEM_KERNEL_PATH, 'write'), {
      onEnter(args) {
        const fd = args[0].toInt32();
        this.buf = args[1];

        const session = findSession(this.threadId);
        if (session !== null) {
          this.session = session;
          this.isCrashLog = (fd === session.logFd);
        } else {
          this.isCrashLog = false;
        }
      },
      onLeave(retval) {
        if (!this.isCrashLog)
          return;

        const n = retval.toInt32();
        if (n === -1)
          return;

        const chunk = this.buf.readUtf8String(n);
        const { session } = this;
        if (session !== undefined)
          session.logChunks.push(chunk);
      }
    });
  }

  Interceptor.attach(Module.getExportByName(CRASH_REPORTER_SUPPORT_PATH, 'OSAPreferencesGetBoolValue'), {
    onEnter(args) {
      this.name = new ObjC.Object(args[0]).toString();
      this.domain = new ObjC.Object(args[1]).toString();
      this.successPtr = args[2];
    },
    onLeave(retval) {
      if (this.name === 'SymbolicateCrashes' && this.domain === 'com.apple.CrashReporter') {
        if (!this.successPtr.isNull())
          this.successPtr.writeU8(1);
        retval.replace(YES);
      }
    }
  });

  const libdyld = findLibdyldInternals();
  if (libdyld !== null) {
    const allImageInfoSizes = new Map([
      [15, 304],
      [16, 328],
      [17, 368],
    ]);
    const imageElementSize = 3 * pointerSize;

    const procInfoInvocations = new Map();

    Interceptor.attach(libdyld['dyld_process_info_base::make'].implementation, {
      onEnter(args) {
        const session = findSession(this.threadId);
        if (session === null)
          return;

        const pid = pidForTask(args[0].toUInt32());
        const allImageInfo = args[1];

        const version = allImageInfo.readU32();
        const count = allImageInfo.add(4).readU32();
        const array = allImageInfo.add(8).readU64();

        const size = allImageInfoSizes.get(version);
        if (size === undefined) {
          console.error('Unsupported dyld_all_image_infos_64; please add support for version ' + version);
          return;
        }

        const extraCount = session.mappedAgents.length;
        const copy = Memory.dup(allImageInfo, size);
        copy.add(4).writeU32(count + extraCount);
        this.allImageInfo = copy;
        args[1] = copy;

        const realSize = count * imageElementSize;
        const fakeSize = realSize + (extraCount * imageElementSize);

        const paths = new Map();

        procInfoInvocations.set(this.threadId, {
          session,
          array,
          realSize,
          fakeSize,
          paths
        });
      },
      onLeave(retval) {
        procInfoInvocations.delete(this.threadId);
      }
    });

    const { withRemoteBuffer } = libdyld;
    const blockArgIndex = withRemoteBuffer.arity - 1;
    Interceptor.attach(withRemoteBuffer.implementation, {
      onEnter(args) {
        const invocation = procInfoInvocations.get(this.threadId);
        if (invocation === undefined)
          return;

        const { session } = invocation;

        const remoteAddress = uint64(args[1].toString());

        if (remoteAddress.equals(invocation.array)) {
          const realSize = invocation.realSize;

          args[2] = ptr(realSize);

          this.block = wrapBlock(args[blockArgIndex], (impl, buffer, size) => {
            const copy = Memory.alloc(invocation.fakeSize);
            Memory.copy(copy, buffer, realSize);

            let element = copy.add(realSize);
            const paths = invocation.paths;
            for (const agent of session.mappedAgents) {
              const loadAddress = agent.machHeaderAddress;
              const filePath = loadAddress.sub(4096);
              const modDate = 0;

              if (session.is64Bit) {
                element
                    .writeU64(loadAddress).add(8)
                    .writeU64(filePath).add(8)
                    .writeU64(modDate);
              } else {
                element
                    .writeU32(loadAddress).add(4)
                    .writeU32(filePath).add(4)
                    .writeU32(modDate);
              }

              paths.set(filePath.toString(), agent);

              element = element.add(imageElementSize);
            }

            return impl(copy, size);
          });

          return;
        }

        const agent = invocation.paths.get(remoteAddress.toString());
        if (agent !== undefined) {
          this.block = wrapBlock(args[blockArgIndex], (impl, buffer, size) => {
            const copy = Memory.dup(buffer, size);
            copy.writeUtf8String(agent.path);
            return impl(copy, size);
          });
        }
      }
    });
  }

  if (Process.arch === 'arm64') {
    Interceptor.attach(ObjC.classes.VMUSampler['- sampleAllThreadsOnceWithFramePointers:'].implementation, {
      onEnter(args) {
        args[2] = YES;
      }
    });

    Interceptor.attach(ObjC.classes.VMUBacktrace['- fixupStackWithSamplingContext:symbolicator:'].implementation, {
      onEnter(args) {
        this.self = new ObjC.Object(args[0]);
        this.samplingContext = args[2];
        this.symbolicator = [args[3], args[4]];
      },
      onLeave() {
        const session = getSession(this.threadId, 'fixupStackWithSamplingContext');
        if (!session.is64Bit)
          return;

        const { self, samplingContext, symbolicator } = this;

        const [, frames, framePtrs, length] = self.$ivars._callstack;
        const mappedMemory = new MappedMemory(samplingContext.add(8).readPointer());

        for (let i = 0; i !== length; i++) {
          const frameSlot = frames.add(i * 8);
          const frame = frameSlot.readU64();

          const symbol = CSSymbolicatorGetSymbolWithAddressAtTime(symbolicator, frame, kCSNow);
          if (!CSIsNull(symbol))
            continue;

          const framePtrAbove = (i > 0) ? framePtrs.add((i - 1) * 8).readU64() : null;

          const functionAddress = tryParseInterceptorTrampoline(frame, framePtrAbove, mappedMemory);
          if (functionAddress !== null)
            frameSlot.writeU64(functionAddress);
        }
      },
    });
  }
}

function findCrashReportClass() {
  const { api } = ObjC;

  const reporter = Process.enumerateModules()[0];
  const reporterStart = reporter.base;
  const reporterEnd = reporterStart.add(reporter.size);

  const numClasses = api.objc_getClassList(NULL, 0);
  const classHandles = Memory.alloc(numClasses * pointerSize);
  api.objc_getClassList(classHandles, numClasses);

  const classGetName = api.class_getName;

  for (let i = numClasses - 1; i >= 0; i--) {
    const classHandle = classHandles.add(i * pointerSize).readPointer();
    const rawName = classGetName(classHandle);
    if (rawName.compare(reporterStart) >= 0 && rawName.compare(reporterEnd) < 0) {
      const name = rawName.readUtf8String();
      if (name === 'LegacyCrashReport' || name === 'CrashReport')
        return new ObjC.Object(classHandle);
    }
  }

  return null;
}

function findLibdyldInternals() {
  if (Process.arch !== 'arm64')
    return null;

  const { base, size } = Process.getModuleByName('/usr/lib/system/libdyld.dylib');

  /*
   * Verified on:
   * - 12.4
   * - 13.2.2
   * - 13.3
   * - 13.5
   * - 14.0
   * - 14.7.1
   */
  const signatures = {
    'dyld_process_info_base::make': [
      [
        // make(unsigned int, dyld_all_image_infos_64 const &, unsigned long long, int *)
        '28 e0 02 91', // add x8, x1, 0xb8
        { arity: 4 }
      ],
    ],
    'withRemoteBuffer': [
      [
        // New: withRemoteBuffer(unsigned int, unsigned long long, unsigned long, bool, int *, void (void *, unsigned long) block_pointer)
        '9f 00 00 f1 ?? ?? ?? ?? 15 00 84 9a : ff ff ff ff ff ff ff ff 1f fc ff ff', // cmp x4, 0; <any instruction>; csel x21, $reg, x4, eq
        { arity: 6 }
      ],
      [
        // Old: withRemoteBuffer(unsigned int, unsigned long long, unsigned long, bool, bool, int *, void (void *, unsigned long) block_pointer)
        'bf 00 00 f1 ?? ?? ?? ?? 14 00 85 9a : ff ff ff ff ff ff ff ff 1f fc ff ff', // cmp x5, 0; <any instruction>; csel x20, $reg, x5, eq
        { arity: 7 }
      ],
    ],
  };

  let prologPattern;
  const isArm64e = !ptr(1).sign().equals(1);
  if (isArm64e) {
    const pacibsp = '7f 23 03 d5';
    prologPattern = pacibsp;
  } else {
    const subSpSpImm = 'ff 03 00 d1 : ff 03 e0 ff';
    prologPattern = subSpSpImm;
  }

  const result = {};
  const missing = [];
  for (const [name, candidates] of Object.entries(signatures)) {
    let found = false;

    for (const [pattern, details] of candidates) {
      const matches = Memory.scanSync(base, size, pattern);
      if (matches.length !== 1)
        continue;
      const match = matches[0].address;

      const prologs = Memory.scanSync(match.sub(256), 256, prologPattern);
      if (prologs.length === 0)
        continue;

      result[name] = Object.assign({ implementation: prologs[prologs.length - 1].address }, details);

      found = true;
      break;
    }

    if (!found)
      missing.push(name);
  }

  if (missing.length !== 0) {
    console.error(`Unsupported version of libdyld.dylib; missing:\n\t${missing.join('\n\t')}`);
    return null;
  }

  return result;
}

function pidForTask(task) {
  const pidBuf = Memory.alloc(4);
  _pidForTask(task, pidBuf);
  return pidBuf.readU32();
}

const pointerBuf = Memory.alloc(8);

class MappedMemory {
  constructor(handle) {
    this.handle = handle;
  }

  read(address, size) {
    const kr = mappedMemoryRead(this.handle, address, size, pointerBuf);
    if (kr !== 0)
      throw new Error('Invalid address: 0x' + address.toString(16));
    return pointerBuf.readPointer().readByteArray(size);
  }

  readPointer(address) {
    const kr = mappedMemoryReadPointer(this.handle, address, pointerBuf);
    if (kr !== 0)
      throw new Error('Invalid address: 0x' + address.toString(16));
    return pointerBuf.readU64();
  }
}

function tryParseInterceptorTrampoline(code, stackFrameAbove, mappedMemory) {
  let instructions;
  try {
    instructions = new Uint32Array(mappedMemory.read(code, 16));
  } catch (e) {
    return null;
  }

  const result = tryParseInterceptorOnLeaveTrampoline(instructions, code, mappedMemory);
  if (result !== null)
    return result;

  return tryParseInterceptorCallbackTrampoline(instructions, code, stackFrameAbove, mappedMemory);
}

function tryParseInterceptorOnLeaveTrampoline(instructions, code, mappedMemory) {
  let ldr;

  ldr = tryParseLdrRegAddress(instructions[0], code);
  if (ldr === null)
    return null;
  if (ldr[0] !== 'x17')
    return null;
  const functionContextDPtr = ldr[1];

  ldr = tryParseLdrRegAddress(instructions[1], code.add(4));
  if (ldr === null)
    return null;
  if (ldr[0] !== 'x16')
    return null;

  const isBrX16 = ((instructions[2] & 0xfffff7e0) >>> 0) === 0xd61f0200;
  if (!isBrX16)
    return null;

  return tryReadInterceptorFunctionContextDoublePointer(functionContextDPtr, mappedMemory);
}

const interceptorCallbackTrampolineSignature = [
  0x910043ff, // add sp, sp, 0x10
  0xa8c103e1, // ldp x1, x0, [sp], 0x10
  0xa8c10be1, // ldp x1, x2, [sp], 0x10
  0xa8c113e3, // ldp x3, x4, [sp], 0x10
];

function tryParseInterceptorCallbackTrampoline(instructions, code, stackFrameAbove, mappedMemory) {
  if (stackFrameAbove === null)
    return null;

  const matches = interceptorCallbackTrampolineSignature.every((insn, index) => instructions[index] === insn);
  if (!matches)
    return null;

  const cpuContextStart = stackFrameAbove.add(16 + 8);
  const x17Start = cpuContextStart.add(19 * 8);
  return tryReadInterceptorFunctionContextDoublePointer(x17Start, mappedMemory);
}

function tryReadInterceptorFunctionContextDoublePointer(functionContextDPtr, mappedMemory) {
  try {
    const functionContext = mappedMemory.readPointer(functionContextDPtr);
    const functionAddress = mappedMemory.readPointer(functionContext);
    return functionAddress;
  } catch (e) {
    return null;
  }
}

function tryParseLdrRegAddress(instruction, pc) {
  if ((instruction & 0xff000000) !== 0x58000000)
    return null;

  const reg = instruction & 0x1f;

  const distance = (instruction >>> 5) & 0x7ffff;
  const imm = pc.add(distance * 4);

  return ['x' + reg, imm];
}

function wrapBlock(handle, wrapper) {
  const block = new ObjC.Block(handle);

  const impl = block.implementation;

  block.implementation = (...args) => wrapper(impl, ...args);

  return block;
}

initialize();

"""

```