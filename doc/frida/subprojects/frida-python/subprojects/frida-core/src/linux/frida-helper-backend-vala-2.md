Response:
### 功能归纳

`frida-helper-backend.vala` 文件是 Frida 动态插桩工具的核心部分之一，主要负责在 Linux 系统上实现对目标进程的内存操作、线程控制、远程调用等功能。以下是该文件的主要功能归纳：

1. **内存读写操作**：
   - `read_memory` 和 `write_memory` 函数用于读取和写入目标进程的内存。这些函数通过 `ptrace` 系统调用或 `process_vm_readv`/`process_vm_writev` 系统调用来实现内存操作。
   - `write_memory_string` 函数用于将字符串写入目标进程的内存。

2. **远程调用**：
   - `RemoteCallBuilder` 和 `RemoteCall` 类用于构建和执行远程调用。这些类通过设置目标进程的寄存器状态、堆栈指针等，实现在目标进程中执行指定的函数。
   - `RemoteCallResult` 类用于存储远程调用的结果，包括返回值、状态和寄存器状态。

3. **线程控制**：
   - `ThreadSuspendScope` 类用于挂起和恢复目标进程中的线程。它通过 `ptrace` 系统调用实现对线程的控制。
   - `ProcessCodeSwapScope` 类用于在目标进程中替换代码段，并在执行完毕后恢复原始代码。

4. **进程和线程的附加与分离**：
   - `SeizeSession` 类用于附加到目标进程，并通过 `ptrace` 系统调用实现对进程的控制。
   - `AttachState` 枚举用于表示进程的附加状态。

5. **系统调用和信号处理**：
   - `ChildProcess` 命名空间中的函数用于处理目标进程的信号，如等待信号、处理信号等。
   - `PosixStatus` 命名空间中的函数用于解析进程的状态信息。

6. **文件描述符管理**：
   - `FileDescriptor` 和 `PidFileDescriptor` 类用于管理文件描述符，支持通过 `pidfd` 系统调用获取目标进程的文件描述符。

7. **内存映射管理**：
   - `ProcMapsEntry` 类用于解析 `/proc/[pid]/maps` 文件，获取目标进程的内存映射信息。

8. **PTY 和终端配置**：
   - `make_pty` 函数用于创建伪终端（PTY），并配置终端的属性。

### 二进制底层与 Linux 内核相关功能

1. **`ptrace` 系统调用**：
   - `ptrace` 是 Linux 内核提供的系统调用，用于调试和控制目标进程。Frida 通过 `ptrace` 实现内存读写、寄存器操作、线程挂起等功能。
   - 例如，`ptrace(PEEKDATA, tid, (void *) address)` 用于读取目标进程的内存，`ptrace(POKEDATA, tid, (void *) address, (void *) word)` 用于写入目标进程的内存。

2. **`process_vm_readv` 和 `process_vm_writev` 系统调用**：
   - 这些系统调用允许直接读取和写入目标进程的内存，而不需要暂停目标进程。Frida 在支持这些系统调用的系统上优先使用它们来提高性能。

3. **`pidfd` 系统调用**：
   - `pidfd_open` 和 `pidfd_getfd` 是 Linux 5.3 及以上版本引入的系统调用，用于通过进程 ID 获取文件描述符。Frida 使用这些系统调用来管理目标进程的文件描述符。

### LLDB 调试示例

假设我们想要使用 LLDB 来复刻 Frida 的 `read_memory` 功能，可以使用以下 LLDB Python 脚本：

```python
import lldb

def read_memory(pid, address, size):
    # 附加到目标进程
    target = lldb.debugger.CreateTarget("")
    process = target.AttachToProcessWithID(lldb.SBListener(), pid)

    # 读取内存
    error = lldb.SBError()
    memory = process.ReadMemory(address, size, error)
    
    if error.Success():
        return memory
    else:
        print(f"Failed to read memory: {error}")
        return None

# 示例：读取进程 1234 的内存地址 0x1000 处的 16 字节
pid = 1234
address = 0x1000
size = 16
memory = read_memory(pid, address, size)
if memory:
    print(f"Memory at {hex(address)}: {memory}")
```

### 假设输入与输出

假设我们有一个目标进程，其内存地址 `0x1000` 处存储了字符串 "Hello, Frida!"，我们可以使用 `read_memory` 函数读取该内存区域：

- **输入**：
  - `pid = 1234`
  - `address = 0x1000`
  - `size = 13` (字符串 "Hello, Frida!" 的长度)

- **输出**：
  - `Memory at 0x1000: b'Hello, Frida!'`

### 常见使用错误

1. **权限不足**：
   - 用户尝试附加到需要 root 权限的进程时，可能会遇到 `EPERM` 错误。解决方法是以 root 用户运行 Frida 或调整系统权限设置。

2. **进程不存在**：
   - 如果目标进程在调试过程中退出，可能会遇到 `ESRCH` 错误。解决方法是在调试前确保目标进程处于运行状态。

3. **内存访问错误**：
   - 如果尝试访问无效的内存地址，可能会遇到 `EFAULT` 错误。解决方法是在访问内存前确保地址有效。

### 用户操作路径

1. **启动 Frida**：
   - 用户通过命令行或脚本启动 Frida，指定目标进程的 PID 或名称。

2. **附加到目标进程**：
   - Frida 使用 `ptrace` 或 `pidfd` 系统调用附加到目标进程。

3. **执行内存操作**：
   - 用户通过 Frida 的 API 调用 `read_memory` 或 `write_memory` 函数，Frida 在底层使用 `ptrace` 或 `process_vm_readv`/`process_vm_writev` 系统调用执行内存操作。

4. **远程调用**：
   - 用户通过 Frida 的 API 构建远程调用，Frida 设置目标进程的寄存器状态并执行指定的函数。

5. **调试结束**：
   - 用户结束调试会话，Frida 分离目标进程并释放相关资源。

通过以上步骤，用户可以逐步深入到 Frida 的底层实现，了解其如何与 Linux 内核交互，实现对目标进程的动态插桩和调试。
### 提示词
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/src/linux/frida-helper-backend.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```
ffset += chunk_size;
			}

			return result;
		}

		public void write_memory (uint64 address, uint8[] data) throws Error {
			if (data.length == 0)
				return;

#if X86 || X86_64
			if (process_vm_writev != null) {
				var local = Posix.iovector ();
				local.iov_base = data;
				local.iov_len = data.length;

				var remote = Posix.iovector ();
				remote.iov_base = (void *) address;
				remote.iov_len = data.length;

				ssize_t res = process_vm_writev (pid, (Posix.iovector[]) &local, (Posix.iovector[]) &remote, 0);
				if (res != -1)
					return;
				if (errno == Posix.ENOSYS)
					process_vm_writev = null;
				else if (errno != Posix.EPERM && errno != Posix.EFAULT)
					throw new Error.NOT_SUPPORTED ("Unable to write to process memory: %s", strerror (errno));
			}
#endif

			size_t offset = 0;
			size_t size = data.length;
			uint bytes_per_word = (uint) sizeof (size_t);
			while (offset != size) {
				size_t word = 0;
				size_t chunk_size = size_t.min (size - offset, bytes_per_word);
				if (chunk_size < bytes_per_word)
					word = (size_t) ptrace (PEEKDATA, tid, (void *) (address + offset));
				Memory.copy (&word, (uint8 *) data + offset, chunk_size);

				ptrace (POKEDATA, tid, (void *) (address + offset), (void *) word);

				offset += chunk_size;
			}
		}

		public void write_memory_string (uint64 address, string str) throws Error {
			unowned uint8[] data = str.data;
			write_memory (address, data[:data.length + 1]);
		}

		private static ssize_t process_vm_readv_impl (uint pid,
				[CCode (array_length_type = "unsigned long")]
				Posix.iovector[] local_iov,
				[CCode (array_length_type = "unsigned long")]
				Posix.iovector[] remote_iov,
				ulong flags) {
			return Linux.syscall (SysCall.process_vm_readv, pid, local_iov, local_iov.length, remote_iov, remote_iov.length,
				flags);
		}

		private static ssize_t process_vm_writev_impl (uint pid,
				[CCode (array_length_type = "unsigned long")]
				Posix.iovector[] local_iov,
				[CCode (array_length_type = "unsigned long")]
				Posix.iovector[] remote_iov,
				ulong flags) {
			return Linux.syscall (SysCall.process_vm_writev, pid, local_iov, local_iov.length, remote_iov, remote_iov.length,
				flags);
		}
	}

	protected enum AttachState {
		ATTACHED,
		ALREADY_ATTACHED,
	}

	private class ProcessCodeSwapScope {
		private State state = INACTIVE;

		private SeizeSession session;
		private ThreadSuspendScope thread_suspend_scope;
		public uint64 code_start;
		public uint64 code_end;
		private uint8[] original_code;

		private enum State {
			INACTIVE,
			ACTIVE
		}

		public async ProcessCodeSwapScope (SeizeSession session, uint8[] code, Cancellable? cancellable) throws Error, IOError {
			this.session = session;

			Gum.Linux.enumerate_ranges ((Posix.pid_t) session.pid, READ | EXECUTE, d => {
				if (d.range.size >= code.length) {
					code_start = d.range.base_address + d.range.size - round_size_to_page_size (code.length);
					code_end = code_start + code.length;
				}
				return code_start == 0;
			});
			if (code_start == 0)
				throw new Error.NOT_SUPPORTED ("Unable to find suitable code pages");

			thread_suspend_scope = new ThreadSuspendScope (session.pid);
			thread_suspend_scope.exclude (session.tid);
			yield thread_suspend_scope.enable (cancellable);

			original_code = session.read_memory (code_start, code.length);
			session.write_memory (code_start, code);
			state = ACTIVE;
		}

		~ProcessCodeSwapScope () {
			try {
				revert ();
			} catch (Error e) {
			}
		}

		public void revert () throws Error {
			if (state == ACTIVE) {
				session.write_memory (code_start, original_code);

				thread_suspend_scope.disable ();

				state = INACTIVE;
			}
		}
	}

	private class ThreadSuspendScope {
		private State state = INACTIVE;

		private uint pid;
		private Gee.Set<uint> excluded_tids = new Gee.HashSet<uint> ();
		private Gee.List<SeizeSession> suspended = new Gee.ArrayList<SeizeSession> ();

		private enum State {
			INACTIVE,
			ACTIVE
		}

		private delegate void CompletionNotify ();

		public ThreadSuspendScope (uint pid) throws Error {
			this.pid = pid;
		}

		public void exclude (uint tid) {
			assert (state == INACTIVE);
			excluded_tids.add (tid);
		}

		public async void enable (Cancellable? cancellable) throws Error, IOError {
			assert (state == INACTIVE);
			state = ACTIVE;

			uint pending = 1;

			CompletionNotify on_complete = () => {
				pending--;
				if (pending == 0) {
					var source = new IdleSource ();
					source.set_callback (enable.callback);
					source.attach (MainContext.get_thread_default ());
				}
			};

			var discovered_tids = new Gee.HashSet<uint> ();
			uint new_discoveries = 0;
			Error? pending_error = null;
			do {
				Dir dir;
				try {
					dir = Dir.open ("/proc/%u/task".printf (pid));
				} catch (FileError e) {
					pending_error = new Error.PROCESS_NOT_FOUND ("Process exited unexpectedly");
					break;
				}

				new_discoveries = 0;
				string? name;
				while ((name = dir.read_name ()) != null) {
					var tid = uint.parse (name);

					if (excluded_tids.contains (tid))
						continue;

					if (!discovered_tids.contains (tid)) {
						discovered_tids.add (tid);
						new_discoveries++;

						pending++;
						suspend_thread.begin (tid, cancellable, on_complete);
					}
				}
			} while (new_discoveries > 0);

			on_complete ();

			yield;

			on_complete = null;

			if (pending_error != null)
				throw pending_error;
		}

		private async void suspend_thread (uint tid, Cancellable? cancellable, CompletionNotify on_complete) {
			try {
				var session = yield ThreadSuspendSession.open (pid, tid, cancellable);
				suspended.add (session);
			} catch (GLib.Error e) {
			}

			on_complete ();
		}

		public void disable () throws Error {
			assert (state == ACTIVE);
			state = INACTIVE;

			foreach (SeizeSession session in suspended)
				session.close ();
			suspended.clear ();
		}
	}

	private class RemoteCallBuilder {
		private uint64 target;
		private uint64[] args = {};
		private GPRegs regs;

		public RemoteCallBuilder (uint64 target, GPRegs regs) {
			this.target = target;
			this.regs = regs;

			this.regs.orig_syscall = -1;
			uint64 new_sp;
			this
				.reserve_stack_space (RED_ZONE_SIZE, out new_sp)
				.align_stack ();
		}

		public RemoteCallBuilder add_argument (uint64 val) {
			args += val;
			assert (args.length <= 6);

			return this;
		}

		public RemoteCallBuilder reserve_stack_space (size_t size, out uint64 location) {
			size_t allocated_size;
			if (size % STACK_ALIGNMENT != 0)
				allocated_size = size + (STACK_ALIGNMENT - (size % STACK_ALIGNMENT));
			else
				allocated_size = size;

			uint64 new_sp = regs.stack_pointer - allocated_size;
			regs.stack_pointer = new_sp;

			location = new_sp;

			return this;
		}

		private RemoteCallBuilder align_stack () {
			uint64 sp = regs.stack_pointer;
			sp -= sp % STACK_ALIGNMENT;
			regs.stack_pointer = sp;

			return this;
		}

		public RemoteCall build (SeizeSession session) {
			return new RemoteCall (session, target, args, regs);
		}
	}

	private class RemoteCall {
		private SeizeSession session;
		private uint64 target;
		private uint64[] args;
		private GPRegs initial_regs;

		internal RemoteCall (SeizeSession session, uint64 target, uint64[] args, GPRegs regs) {
			this.session = session;
			this.target = target;
			this.args = args;
			this.initial_regs = regs;
		}

		public async RemoteCallResult execute (Cancellable? cancellable) throws Error, IOError {
			GPRegs regs = initial_regs;

			uint64 target_address = target;

#if X86
			if (args.length > 0) {
				uint32[] slots = {};
				foreach (uint64 arg in args)
					slots += (uint32) arg;

				unowned uint8[] raw_slots = (uint8[]) slots;
				raw_slots.length = slots.length * 4;

				regs.esp -= (uint32) ((regs.esp - (args.length * 4)) % STACK_ALIGNMENT);
				regs.esp -= raw_slots.length;
				session.write_memory (regs.esp, raw_slots);
			}

			regs.esp -= 4;
			uint32 return_address = (uint32) DUMMY_RETURN_ADDRESS;
			session.write_memory (regs.esp, (uint8[]) &return_address);
#elif X86_64
			uint i = 0;
			foreach (uint64 arg in args) {
				switch (i) {
					case 0:
						regs.rdi = arg;
						break;
					case 1:
						regs.rsi = arg;
						break;
					case 2:
						regs.rdx = arg;
						break;
					case 3:
						regs.rcx = arg;
						break;
					case 4:
						regs.r8 = arg;
						break;
					case 5:
						regs.r9 = arg;
						break;
					default:
						assert_not_reached ();
				}
				i++;
			}

			regs.rsp -= 8;
			uint64 return_address = DUMMY_RETURN_ADDRESS;
			session.write_memory (regs.rsp, (uint8[]) &return_address);
#elif ARM
			uint i = 0;
			foreach (uint64 arg in args) {
				regs.r[i++] = (uint32) arg;
				if (i == 4)
					break;
			}

			if (args.length > 4) {
				uint32[] slots = {};
				while (i < args.length)
					slots += (uint32) args[i++];

				unowned uint8[] raw_slots = (uint8[]) slots;
				raw_slots.length = slots.length * 4;

				regs.sp -= (uint32) ((regs.sp - ((args.length - 4) * 4)) % STACK_ALIGNMENT);
				regs.sp -= raw_slots.length;
				session.write_memory (regs.sp, raw_slots);
			}

			regs.lr = (uint32) DUMMY_RETURN_ADDRESS;

			if ((target_address & 1) != 0) {
				target_address &= ~1;
				regs.cpsr |= PSR_T_BIT;
			} else {
				regs.cpsr &= ~PSR_T_BIT;
			}
#elif ARM64
			uint i = 0;
			foreach (uint64 arg in args)
				regs.x[i++] = arg;

			regs.lr = DUMMY_RETURN_ADDRESS;
#elif MIPS
			regs.t9 = (size_t) target_address;

			uint i = 0;
			foreach (uint64 arg in args) {
				regs.a[i++] = (size_t) arg;
				if (i == 4)
					break;
			}

			if (args.length > 4) {
				uint32[] slots = {};
				while (i < args.length)
					slots += (uint32) args[i++];

				unowned uint8[] raw_slots = (uint8[]) slots;
				raw_slots.length = (int) (slots.length * sizeof (size_t));

				regs.sp -= (uint32) ((regs.sp - ((args.length - 4) * sizeof (size_t))) % STACK_ALIGNMENT);
				regs.sp -= raw_slots.length;
				session.write_memory (regs.sp, raw_slots);
			}

			/*
			 * We need to reserve space for 'incoming arguments', as per
			 * http://math-atlas.sourceforge.net/devel/assembly/mipsabi32.pdf section 3-15
			 */
			regs.sp -= 4 * sizeof (size_t);

			regs.ra = DUMMY_RETURN_ADDRESS;
#endif

			regs.program_counter = target_address;

			int sig = -1;
			var result_regs = GPRegs ();
			session.set_regs (regs);
			bool restored = false;
			try {
				session.resume ();
				sig = yield session.wait_for_signals ({ SEGV, STOP }, cancellable);

				session.get_regs (&result_regs);

				restored = true;
				session.set_regs (session.saved_registers);
			} finally {
				if (!restored) {
					try {
						session.set_regs (session.saved_registers);
					} catch (Error e) {
					}
				}
			}

			RemoteCallStatus status = (result_regs.program_counter == DUMMY_RETURN_ADDRESS)
				? RemoteCallStatus.COMPLETED
				: RemoteCallStatus.RAISED_SIGNAL;
			int stop_signal = (status == COMPLETED) ? -1 : sig;

			uint64 return_value;
			if (status == COMPLETED) {
#if X86
				return_value = result_regs.eax;
#elif X86_64
				return_value = result_regs.rax;
#elif ARM
				return_value = result_regs.r[0];
#elif ARM64
				return_value = result_regs.x[0];
#elif MIPS
				return_value = result_regs.v[0];
#endif
			} else {
				return_value = ~0;
			}

			return new RemoteCallResult (status, stop_signal, return_value, result_regs);
		}
	}

	private class RemoteCallResult {
		public RemoteCallStatus status;
		public int stop_signal;
		public uint64 return_value;
		public GPRegs regs;

		public RemoteCallResult (RemoteCallStatus status, int stop_signal, uint64 return_value, GPRegs regs) {
			this.status = status;
			this.stop_signal = stop_signal;
			this.return_value = return_value;
			this.regs = regs;
		}
	}

	private enum RemoteCallStatus {
		COMPLETED,
		RAISED_SIGNAL,
	}

	private enum PtraceRequest {
		TRACEME			= 0x0000,
		PEEKDATA		= 0x0002,
		POKEDATA		= 0x0005,
		CONT			= 0x0007,
		SINGLESTEP		= 0x0009,
		ATTACH			= 0x0010,
		SYSCALL			= 0x0018,
		GETREGS			= 0x000c,
		SETREGS			= 0x000d,
		GETFPREGS		= 0x000e,
		SETFPREGS		= 0x000f,
		DETACH			= 0x0011,
		SETOPTIONS		= 0x4200,
		GETREGSET		= 0x4204,
		SETREGSET		= 0x4205,
		SEIZE			= 0x4206,
		INTERRUPT		= 0x4207,
	}

	[Flags]
	private enum PtraceOptions {
		TRACESYSGOOD	= (1 << 0),
		TRACEEXEC	= (1 << 4),
	}

	private const uint NT_PRSTATUS = 1;
	private const uint NT_PRFPREG = 2;

	private const uint32 PSR_T_BIT = 0x20;

	private const size_t RED_ZONE_SIZE = 128;
	private const size_t STACK_ALIGNMENT = 16;

	protected struct GPRegs {
#if X86
		uint32 ebx;
		uint32 ecx;
		uint32 edx;
		uint32 esi;
		uint32 edi;
		uint32 ebp;
		uint32 eax;
		uint32 xds;
		uint32 xes;
		uint32 xfs;
		uint32 xgs;
		int32 orig_eax;
		uint32 eip;
		uint32 xcs;
		uint32 eflags;
		uint32 esp;
		uint32 xss;

		public uint64 program_counter {
			get { return eip; }
			set { eip = (uint32) value; }
		}

		public uint64 stack_pointer {
			get { return esp; }
			set { esp = (uint32) value; }
		}

		public int orig_syscall {
			get { return orig_eax; }
			set { orig_eax = value; }
		}

		public string to_string () {
			var builder = new StringBuilder ();

			append_register_value (builder, "eip", eip);
			append_register_value (builder, "esp", esp);
			append_register_value (builder, "ebp", ebp);

			append_register_value (builder, "eax", eax);
			append_register_value (builder, "ecx", ecx);
			append_register_value (builder, "edx", edx);
			append_register_value (builder, "ebx", ebx);
			append_register_value (builder, "esi", esi);
			append_register_value (builder, "edi", edi);

			return builder.str;
		}
#elif X86_64
		uint64 r15;
		uint64 r14;
		uint64 r13;
		uint64 r12;
		uint64 rbp;
		uint64 rbx;
		uint64 r11;
		uint64 r10;
		uint64 r9;
		uint64 r8;
		uint64 rax;
		uint64 rcx;
		uint64 rdx;
		uint64 rsi;
		uint64 rdi;
		int64 orig_rax;
		uint64 rip;
		uint64 cs;
		uint64 eflags;
		uint64 rsp;
		uint64 ss;
		uint64 fs_base;
		uint64 gs_base;
		uint64 ds;
		uint64 es;
		uint64 fs;
		uint64 gs;

		public uint64 program_counter {
			get { return rip; }
			set { rip = value; }
		}

		public uint64 stack_pointer {
			get { return rsp; }
			set { rsp = value; }
		}

		public int orig_syscall {
			get { return (int) orig_rax; }
			set { orig_rax = value; }
		}

		public string to_string () {
			var builder = new StringBuilder ();

			append_register_value (builder, "rip", rip);
			append_register_value (builder, "rsp", rsp);
			append_register_value (builder, "rbp", rbp);

			append_register_value (builder, "rax", rax);
			append_register_value (builder, "rcx", rcx);
			append_register_value (builder, "rdx", rdx);
			append_register_value (builder, "rbx", rbx);
			append_register_value (builder, "rsi", rsi);
			append_register_value (builder, "rdi", rdi);

			append_register_value (builder, "r8", r8);
			append_register_value (builder, "r9", r9);
			append_register_value (builder, "r10", r10);
			append_register_value (builder, "r11", r11);
			append_register_value (builder, "r12", r12);
			append_register_value (builder, "r13", r13);
			append_register_value (builder, "r14", r14);
			append_register_value (builder, "r15", r15);

			return builder.str;
		}
#elif ARM
		uint32 r[11];
		uint32 fp;
		uint32 ip;
		uint32 sp;
		uint32 lr;
		uint32 pc;
		uint32 cpsr;
		int32 orig_r0;

		public uint64 program_counter {
			get { return pc; }
			set { pc = (uint32) value; }
		}

		public uint64 stack_pointer {
			get { return sp; }
			set { sp = (uint32) value; }
		}

		public int orig_syscall {
			get { return orig_r0; }
			set { orig_r0 = value; }
		}

		public string to_string () {
			var builder = new StringBuilder ();

			append_register_value (builder, "pc", pc);
			append_register_value (builder, "lr", lr);
			append_register_value (builder, "sp", sp);

			for (uint i = 0; i != r.length; i++)
				append_register_value (builder, "r%u".printf (i), r[i]);

			return builder.str;
		}
#elif ARM64
		uint64 x[30];
		uint64 lr;
		uint64 sp;
		uint64 pc;
		uint64 pstate;

		public uint64 get_pc () {
			return pc;
		}

		public uint64 program_counter {
			get { return pc; }
			set { pc = value; }
		}

		public uint64 stack_pointer {
			get { return sp; }
			set { sp = value; }
		}

		public int orig_syscall {
			get { return -1; }
			set {}
		}

		public string to_string () {
			var builder = new StringBuilder ();

			append_register_value (builder, "pc", pc);
			append_register_value (builder, "lr", lr);
			append_register_value (builder, "sp", sp);

			for (uint i = 0; i != x.length; i++)
				append_register_value (builder, "x%u".printf (i), x[i]);

			return builder.str;
		}
#elif MIPS
		uint64 zero;

		uint64 at;

		uint64 v[2];
		uint64 a[4];
		uint64 t[8];
		uint64 s[8];
		uint64 t8;
		uint64 t9;
		uint64 k[2];

		uint64 gp;
		uint64 sp;
		uint64 fp;
		uint64 ra;

		uint64 lo;
		uint64 hi;

		uint64 pc;
		uint64 badvaddr;
		uint64 status;
		uint64 cause;

		uint64 padding[8];

		public uint64 program_counter {
			get { return pc; }
			set { pc = value; }
		}

		public uint64 stack_pointer {
			get { return sp; }
			set { sp = value; }
		}

		public int orig_syscall {
			get { return (int) v[0]; }
			set { v[0] = value; }
		}

		public string to_string () {
			var builder = new StringBuilder ();

			append_register_value (builder, "pc", pc);
			append_register_value (builder, "ra", ra);
			append_register_value (builder, "sp", sp);
			append_register_value (builder, "fp", fp);

			append_register_value (builder, "at", at);
			append_register_value (builder, "gp", gp);

			for (uint i = 0; i != v.length; i++)
				append_register_value (builder, "v%u".printf (i), v[i]);
			for (uint i = 0; i != a.length; i++)
				append_register_value (builder, "a%u".printf (i), a[i]);
			for (uint i = 0; i != t.length; i++)
				append_register_value (builder, "t%u".printf (i), t[i]);
			for (uint i = 0; i != s.length; i++)
				append_register_value (builder, "s%u".printf (i), s[i]);
			append_register_value (builder, "t8", t8);
			append_register_value (builder, "t9", t9);
			for (uint i = 0; i != k.length; i++)
				append_register_value (builder, "k%u".printf (i), k[i]);

			return builder.str;
		}
#endif
	}

	protected struct FPRegs {
#if X86
		long cwd;
		long swd;
		long twd;
		long fip;
		long fcs;
		long foo;
		long fos;
		long st_space[20];
#elif X86_64
		uint16 cwd;
		uint16 swd;
		uint16 ftw;
		uint16 fop;
		uint64 rip;
		uint64 rdp;
		uint mxcsr;
		uint mxcr_mask;
		uint st_space[32];
		uint xmm_space[64];
		uint padding[24];
#elif ARM
		uint8 fpregs[8 * 12];
		uint fpsr;
		uint fpcr;
		uint8 ftype[8];
		uint init_flag;
#elif ARM64
		uint8 vregs[32 * 16];
		uint32 fpsr;
		uint32 fpcr;
		uint64 padding;
#elif MIPS
		ulong fpregs[64];
#endif
	}

	private void append_register_value (StringBuilder builder, string name, uint64 val) {
		if (builder.len != 0)
			builder.append_c ('\n');
		builder.append_c ('\t');
		builder.append_printf ("%3s: %" + ((sizeof (void *) == 8) ? "016" : "08") + uint64.FORMAT_MODIFIER + "x", name, val);
	}

	[CCode (cname = "execve", cheader_filename = "unistd.h")]
	private extern int execve (string pathname,
		[CCode (array_length = false, array_null_terminated = true)]
		string[] argv,
		[CCode (array_length = false, array_null_terminated = true)]
		string[] envp);

	private long ptrace (PtraceRequest request, uint pid = 0, void * addr = null, void * data = null) throws Error {
		errno = 0;
		long res = _ptrace (request, pid, addr, data);
		if (errno != 0)
			throw_ptrace_error (request, pid, errno);
		return res;
	}

	[CCode (cname = "ptrace", cheader_filename = "sys/ptrace.h")]
	private extern long _ptrace (PtraceRequest request, uint pid = 0, void * addr = null, void * data = null);

	[NoReturn]
	private void throw_ptrace_error (PtraceRequest request, uint pid, int err) throws Error {
		switch (err) {
			case Posix.ESRCH:
				throw new Error.PROCESS_NOT_FOUND ("Process not found");
			case Posix.EPERM:
				throw new Error.PERMISSION_DENIED (
					"Unable to access process with pid %u due to system restrictions;" +
					" try `sudo sysctl kernel.yama.ptrace_scope=0`, or run Frida as root",
					pid);
			default:
				throw new Error.NOT_SUPPORTED ("Unable to perform ptrace %s: %s",
					Marshal.enum_to_nick<PtraceRequest> (request),
					strerror (err));
		}
	}

	namespace ChildProcess {
		private async void wait_for_early_signal (uint pid, Posix.Signal sig, Cancellable? cancellable) throws Error, IOError {
			while (true) {
				Posix.Signal next_signal = yield wait_for_next_signal (pid, cancellable);
				if (next_signal == sig)
					return;

				ptrace (CONT, pid);
			}
		}

		private async void wait_for_signal (uint pid, Posix.Signal sig, Cancellable? cancellable) throws Error, IOError {
			yield wait_for_signals (pid, { sig }, cancellable);
		}

		private async Posix.Signal wait_for_signals (uint pid, Posix.Signal[] sigs, Cancellable? cancellable) throws Error, IOError {
			while (true) {
				Posix.Signal next_signal = yield wait_for_next_signal (pid, cancellable);
				if (next_signal in sigs)
					return next_signal;

				ptrace (CONT, pid, null, (void *) next_signal);
			}
		}

		private async Posix.Signal wait_for_next_signal (uint pid, Cancellable? cancellable) throws Error, IOError {
			var main_context = MainContext.get_thread_default ();

			bool timed_out = false;
			var timeout_source = new TimeoutSource.seconds (5);
			timeout_source.set_callback (() => {
				timed_out = true;
				return Source.REMOVE;
			});
			timeout_source.attach (main_context);

			int status = 0;
			uint[] delays = { 0, 1, 2, 5, 10, 20, 50, 250 };
			try {
				for (uint i = 0; !timed_out && !cancellable.set_error_if_cancelled (); i++) {
					int res = Posix.waitpid ((Posix.pid_t) pid, out status, Posix.WNOHANG);
					if (res == -1)
						throw new Error.NOT_SUPPORTED ("Unable to wait for next signal: %s", strerror (errno));
					if (res != 0)
						break;

					uint delay_ms = (i < delays.length) ? delays[i] : delays[delays.length - 1];
					var delay_source = new TimeoutSource (delay_ms);
					delay_source.set_callback (wait_for_next_signal.callback);
					delay_source.attach (main_context);

					var cancel_source = new CancellableSource (cancellable);
					cancel_source.set_callback (wait_for_next_signal.callback);
					cancel_source.attach (main_context);

					yield;

					cancel_source.destroy ();
					delay_source.destroy ();
				}
			} finally {
				timeout_source.destroy ();
			}

			if (timed_out)
				throw new Error.TIMED_OUT ("Unexpectedly timed out while waiting for signal from process with PID %u", pid);

			if (PosixStatus.is_exit (status)) {
				throw new Error.NOT_SUPPORTED ("Target exited with status %u",
					PosixStatus.parse_exit_status (status));
			}

			if (PosixStatus.is_signaled (status)) {
				throw new Error.NOT_SUPPORTED ("Target terminated with signal %u",
					PosixStatus.parse_termination_signal (status));
			}

			if (!PosixStatus.is_stopped (status))
				throw new Error.NOT_SUPPORTED ("Unexpected status: 0x%08x", status);
			return PosixStatus.parse_stop_signal (status);
		}
	}

	namespace PosixStatus {
		[CCode (cname = "WIFEXITED", cheader_filename = "sys/wait.h")]
		private extern bool is_exit (int status);

		[CCode (cname = "WIFSIGNALED", cheader_filename = "sys/wait.h")]
		private extern bool is_signaled (int status);

		[CCode (cname = "WIFSTOPPED", cheader_filename = "sys/wait.h")]
		private extern bool is_stopped (int status);

		[CCode (cname = "WEXITSTATUS", cheader_filename = "sys/wait.h")]
		private extern uint parse_exit_status (int status);

		[CCode (cname = "WTERMSIG", cheader_filename = "sys/wait.h")]
		private extern Posix.Signal parse_termination_signal (int status);

		[CCode (cname = "WSTOPSIG", cheader_filename = "sys/wait.h")]
		private extern Posix.Signal parse_stop_signal (int status);
	}

	private int tgkill (uint tgid, uint tid, Posix.Signal sig) {
		return Linux.syscall (SysCall.tgkill, tgid, tid, sig);
	}

	private uint linux_major = 0;
	private uint linux_minor = 0;

	public bool check_kernel_version (uint major, uint minor) {
		if (linux_major == 0) {
			var name = Posix.utsname ();
			name.release.scanf ("%u.%u", out linux_major, out linux_minor);
		}

		return (linux_major == major && linux_minor >= minor) || linux_major > major;
	}

	public extern bool _syscall_satisfies (int syscall_id, LinuxSyscall mask);

	public class FileDescriptor : Object, FileDescriptorBased {
		public int handle;

		public FileDescriptor (int handle) {
			this.handle = handle;
		}

		~FileDescriptor () {
			if (handle != -1)
				Posix.close (handle);
		}

		public int steal () {
			int result = handle;
			handle = -1;
			return result;
		}

		public int get_fd () {
			return handle;
		}
	}

	public class PidFileDescriptor : FileDescriptor {
		private uint pid;

		private PidFileDescriptor (int fd, uint pid) {
			base (fd);
			this.pid = pid;
		}

		public static bool is_supported () {
			return check_kernel_version (5, 3);
		}

		public static bool getfd_is_supported () {
			return check_kernel_version (5, 6);
		}

		public static PidFileDescriptor from_pid (uint pid) throws Error {
			int fd = pidfd_open (pid, 0);
			if (fd == -1)
				throw_pidfd_error (pid, errno);
			return new PidFileDescriptor (fd, pid);
		}

		public FileDescriptor getfd (int targetfd) throws Error {
			int fd = pidfd_getfd (handle, targetfd, 0);
			if (fd == -1)
				throw_pidfd_error (pid, errno);
			return new FileDescriptor (fd);
		}

		private static int pidfd_open (uint pid, uint flags) {
			return Linux.syscall (SysCall.pidfd_open, pid, flags);
		}

		private static int pidfd_getfd (int pidfd, int targetfd, uint flags) {
			return Linux.syscall (SysCall.pidfd_getfd, pidfd, targetfd, flags);
		}

		[NoReturn]
		private static void throw_pidfd_error (uint pid, int err) throws Error {
			switch (err) {
				case Posix.ESRCH:
					throw new Error.PROCESS_NOT_FOUND ("Process not found");
				case Posix.EPERM:
					throw new Error.PERMISSION_DENIED ("Unable to use pidfd for pid %u: %s", pid, strerror (err));
				default:
					throw new Error.NOT_SUPPORTED ("Unable to use pidfd for pid %u: %s", pid, strerror (err));
			}
		}
	}

	namespace MemoryFileDescriptor {
		public bool is_supported () {
			return check_kernel_version (3, 17);
		}

		public static FileDescriptor from_bytes (string name, Bytes bytes) {
			assert (is_supported ());

			var fd = new FileDescriptor (memfd_create (name, 0));
			unowned uint8[] data = bytes.get_data ();
			ssize_t n = Posix.write (fd.handle, data, data.length);
			assert (n == data.length);
			return fd;
		}

		private int memfd_create (string name, uint flags) {
			return Linux.syscall (SysCall.memfd_create, name, flags);
		}
	}

	private void make_pty (out FileDescriptor read, out FileDescriptor write) throws Error {
#if HAVE_OPENPTY
		int rfd = -1, wfd = -1;
		char name[Posix.Limits.PATH_MAX];
		if (Linux.openpty (out rfd, out wfd, name, null, null) == -1)
			throw new Error.NOT_SUPPORTED ("Unable to open PTY: %s", strerror (errno));

		enable_close_on_exec (rfd);
		enable_close_on_exec (wfd);

		configure_terminal_attributes (rfd);

		read = new FileDescriptor (rfd);
		write = new FileDescriptor (wfd);
#else
		try {
			int fds[2];
			Unix.open_pipe (fds, Posix.FD_CLOEXEC);

			read = new FileDescriptor (fds[0]);
			write = new FileDescriptor (fds[1]);
		} catch (GLib.Error e) {
			throw new Error.NOT_SUPPORTED ("Unable to open pipe: %s", e.message);
		}
#endif
	}

#if HAVE_OPENPTY
	private void enable_close_on_exec (int fd) {
		Posix.fcntl (fd, Posix.F_SETFD, Posix.fcntl (fd, Posix.F_GETFD) | Posix.FD_CLOEXEC);
	}

	private void configure_terminal_attributes (int fd) {
		var tios = Posix.termios ();
		Posix.tcgetattr (fd, out tios);

		tios.c_oflag &= ~Posix.ONLCR;
		tios.c_cflag = (tios.c_cflag & Posix.CLOCAL) | Posix.CS8 | Posix.CREAD | Posix.HUPCL;
		tios.c_lflag &= ~Posix.ECHO;

		Posix.tcsetattr (fd, 0, tios);
	}
#endif

	private class ProcMapsEntry {
		public uint64 base_address;
		public string path;
		public string identity;

		private ProcMapsEntry (uint64 base_address, string path, string identity) {
			this.base_address = base_address;
			this.path = path;
			this.identity = identity;
		}

		public static ProcMapsEntry? find_by_address (uint pid, uint64 address) {
			var iter = MapsIter.for_pid (pid);
			while (iter.next ()) {
				uint64 start = iter.start_address;
				uint64 end = iter.end_address;
				if (address >= start && address < end)
					return new ProcMapsEntry (start, iter.path, iter.identity);
			}

			return null;
		}

		public static ProcMapsEntry? find_by_path (uint pid, string path) {
			var iter = MapsIter.for_pid (pid);
			while (iter.next ()) {
				string candidate_path = iter.path;
				if (candidate_path == path) {
#if ANDROID
					if (candidate_path == Gum.Process.query_libc_name () && iter.flags[3] == 's')
						continue;
#endif
					return new ProcMapsEntry (iter.start_address, candidate_path, iter.identity);
				}
			}

			return null;
		}

		private class MapsIter {
			private string? contents;
			private MatchInfo? info;
			private uint offset = 0;

			public uint64 start_address {
				get {
					return uint64.parse (info.fetch (1), 16);
				}
			}

			public uint64 end_address {
				get {
					return uint64.parse (info.fetch (2), 16);
				}
			}

			public string flags {
				owned get {
					return info.fetch (3);
				}
			}

			public string identity {
				owned get {
					return info.fetch (4);
				}
			}

			public string path {
				owned get {
					return info.fetch (5);
				}
			}

			public static MapsIter for_pid (uint pid) {
				return new MapsIter (pid);
			}

			private MapsIter (uint pid) {
				try {
					FileUtils.get_contents ("/proc/%u/maps".printf (pid), out contents);
				} catch (FileError e) {
					return;
				}

				if (!/^([0-9a-f]+)-([0-9a-f]+) (\S{4}) [0-9a-f]+ ([0-9a-f]{2,}:[0-9a-f]{2,} \d+) +([^\n]+)$/m.match (
						contents, 0, out info)) {
					assert_not_reached ();
				}
			}

			public bool next () {
				if (info == null)
					return false;

				if (offset > 0) {
					try {
						info.next ();
					} catch (RegexError e) {
						return false;
					}
				}
				offset++;

				return info.matches ();
			}
		}
	}

	private size_t round_size_to_page_size (size_t size) {
		size_t page_size = Gum.query_page_size ();
		return (size + page_size - 1) & ~(page_size - 1);
	}
}
```