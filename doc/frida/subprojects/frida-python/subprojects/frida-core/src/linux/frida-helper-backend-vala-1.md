Response:
### 功能归纳

`frida-helper-backend.vala` 是 Frida 工具中用于在 Linux 系统上实现动态插桩（Dynamic Instrumentation）的核心模块之一。它主要负责在目标进程中注入代码、管理内存分配、处理系统调用、以及与目标进程的通信。以下是该文件的主要功能归纳：

1. **内存管理**：
   - 通过 `mmap` 和 `munmap` 系统调用在目标进程中分配和释放内存。
   - 使用 `allocate_memory` 和 `deallocate_memory` 方法在目标进程中动态分配和释放内存。

2. **代码注入**：
   - 通过 `bootstrap` 方法将引导代码（bootstrapper code）注入到目标进程中，并执行该代码以初始化 Frida 的运行时环境。
   - 使用 `RemoteCallBuilder` 构建远程调用，并在目标进程中执行这些调用。

3. **进程控制**：
   - 通过 `ptrace` 系统调用控制目标进程的执行，包括暂停、恢复、单步执行等操作。
   - 使用 `SeizeSession` 类管理目标进程的线程状态，支持挂起和恢复线程。

4. **通信机制**：
   - 通过 Unix 套接字（Unix Socket）与目标进程中的 Frida Agent 进行通信，传递控制信息和数据。
   - 使用 `RemoteAgent` 类管理与目标进程的通信会话，处理连接建立、消息传递和会话终止。

5. **错误处理**：
   - 处理在代码注入、内存分配、进程控制等过程中可能出现的错误，并通过异常机制向上层传递错误信息。

6. **系统调用拦截与处理**：
   - 通过 `HelperLibcApi` 结构体封装了常见的 libc 函数（如 `mmap`、`munmap`、`dlopen` 等），并在目标进程中调用这些函数。

7. **调试支持**：
   - 提供调试功能，如设置断点、单步执行、读取和修改寄存器等。

### 二进制底层与 Linux 内核相关功能

1. **`ptrace` 系统调用**：
   - `ptrace` 是 Linux 内核提供的系统调用，用于调试和控制进程的执行。Frida 使用 `ptrace` 来挂起目标进程、读取和修改寄存器和内存、以及注入代码。
   - 例如，`SeizeSession` 类中的 `suspend` 和 `resume` 方法通过 `ptrace` 系统调用来控制目标进程的执行。

2. **`mmap` 和 `munmap` 系统调用**：
   - `mmap` 和 `munmap` 是 Linux 内核提供的系统调用，用于在进程的地址空间中映射和取消映射内存区域。Frida 使用这些系统调用来在目标进程中动态分配和释放内存。
   - 例如，`allocate_memory` 和 `deallocate_memory` 方法通过 `mmap` 和 `munmap` 系统调用来管理目标进程的内存。

3. **`process_vm_readv` 和 `process_vm_writev` 系统调用**：
   - 这些系统调用允许一个进程读取和写入另一个进程的内存。Frida 使用这些系统调用来读取和修改目标进程的内存内容。
   - 例如，`read_memory` 和 `write_memory` 方法通过 `process_vm_readv` 和 `process_vm_writev` 系统调用来访问目标进程的内存。

### LLDB 调试示例

假设我们想要使用 LLDB 来调试 Frida 的代码注入过程，以下是一个简单的 LLDB Python 脚本示例，用于在目标进程中设置断点并观察代码执行：

```python
import lldb

def set_breakpoint_and_run(debugger, target, process, breakpoint_address):
    # 设置断点
    breakpoint = target.BreakpointCreateByAddress(breakpoint_address)
    print(f"Breakpoint set at address: {hex(breakpoint_address)}")

    # 继续执行进程
    process.Continue()

    # 等待进程停止
    state = process.GetState()
    while state == lldb.eStateRunning:
        state = process.GetState()

    # 打印寄存器状态
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()
    registers = frame.GetRegisters()
    for reg in registers:
        print(reg)

# 初始化 LLDB
debugger = lldb.SBDebugger.Create()
debugger.SetAsync(False)
target = debugger.CreateTarget("target_process")
process = target.LaunchSimple(None, None, os.getcwd())

# 设置断点地址（假设我们要在代码注入的入口处设置断点）
breakpoint_address = 0x12345678  # 替换为实际的代码注入地址

# 设置断点并运行
set_breakpoint_and_run(debugger, target, process, breakpoint_address)
```

### 假设输入与输出

**假设输入**：
- 目标进程的 PID 为 `1234`。
- 代码注入的入口地址为 `0x12345678`。

**假设输出**：
- LLDB 在地址 `0x12345678` 处设置断点，并暂停目标进程的执行。
- 打印目标进程的寄存器状态，显示当前执行的指令和寄存器值。

### 用户常见错误与调试线索

1. **错误：无法注入代码**：
   - **可能原因**：目标进程的权限不足，或者目标进程已经处于调试状态。
   - **调试线索**：检查目标进程的权限，确保 Frida 有足够的权限进行代码注入。使用 `ps` 命令查看目标进程的状态，确保它没有被其他调试器控制。

2. **错误：内存分配失败**：
   - **可能原因**：目标进程的地址空间不足，或者 `mmap` 系统调用失败。
   - **调试线索**：使用 `strace` 跟踪目标进程的系统调用，查看 `mmap` 调用的返回值。检查目标进程的内存映射情况，确保有足够的可用内存。

3. **错误：断点未触发**：
   - **可能原因**：断点地址设置错误，或者目标进程的代码路径未经过断点。
   - **调试线索**：使用 `objdump` 或 `gdb` 反汇编目标进程的代码，确认断点地址是否正确。检查目标进程的执行路径，确保代码注入的逻辑正确。

### 用户操作如何一步步到达这里

1. **启动 Frida**：用户通过命令行或脚本启动 Frida，指定目标进程的 PID 或名称。
2. **注入代码**：Frida 使用 `ptrace` 系统调用挂起目标进程，并通过 `mmap` 分配内存，将引导代码注入到目标进程中。
3. **执行引导代码**：Frida 恢复目标进程的执行，引导代码在目标进程中运行，初始化 Frida 的运行时环境。
4. **建立通信**：Frida 通过 Unix 套接字与目标进程中的 Frida Agent 建立通信，传递控制信息和数据。
5. **调试与监控**：用户通过 Frida 提供的 API 或命令行工具，对目标进程进行调试和监控，观察代码执行、修改内存、拦截系统调用等操作。

通过以上步骤，用户可以逐步深入到 Frida 的底层实现，了解代码注入、内存管理、进程控制等核心功能的实现细节。
### 提示词
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/src/linux/frida-helper-backend.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```
p with agent");
			} finally {
				cancel_source.destroy ();
				timeout_source.destroy ();
			}

			agent.ack ();

			return agent;
		}

		private async BootstrapResult bootstrap (size_t loader_size, Cancellable? cancellable) throws Error, IOError {
			var result = new BootstrapResult ();

			unowned uint8[] bootstrapper_code = Frida.Data.HelperBackend.get_bootstrapper_bin_blob ().data;
			size_t bootstrapper_size = round_size_to_page_size (bootstrapper_code.length);

			size_t stack_size = 64 * 1024;

			uint64 allocation_base = 0;
			size_t allocation_size = size_t.max (bootstrapper_size, loader_size) + stack_size;

			uint64 remote_mmap = 0;
			uint64 remote_munmap = 0;
			ProcMapsEntry? remote_libc = ProcMapsEntry.find_by_path (pid, local_libc.path);
			bool same_libc = remote_libc != null && remote_libc.identity == local_libc.identity;
			if (same_libc) {
				remote_mmap = remote_libc.base_address + mmap_offset;
				remote_munmap = remote_libc.base_address + munmap_offset;
			}

			if (remote_mmap != 0) {
				allocation_base = yield allocate_memory (remote_mmap, allocation_size,
					Posix.PROT_READ | Posix.PROT_WRITE | Posix.PROT_EXEC, cancellable);
			} else {
				var code_swap = yield new ProcessCodeSwapScope (this, bootstrapper_code, cancellable);
				uint64 code_start = code_swap.code_start;
				uint64 code_end = code_start + bootstrapper_size;
				maybe_fixup_helper_code (code_start, bootstrapper_code);

				var call_builder = new RemoteCallBuilder (code_start, saved_regs);

				uint64 bootstrap_ctx_location;
				call_builder.reserve_stack_space (sizeof (HelperBootstrapContext), out bootstrap_ctx_location);

				var bootstrap_ctx = HelperBootstrapContext ();
				bootstrap_ctx.allocation_size = allocation_size;
				write_memory (bootstrap_ctx_location, (uint8[]) &bootstrap_ctx);

				call_builder.add_argument (bootstrap_ctx_location);

				RemoteCallResult bootstrap_result = yield call_builder.build (this).execute (cancellable);
				var status = (HelperBootstrapStatus) bootstrap_result.return_value;
				if (bootstrap_result.status != COMPLETED || status != ALLOCATION_SUCCESS)
					throw_bootstrap_error (bootstrap_result, status, code_start, code_end);

				uint8[] output_context = read_memory (bootstrap_ctx_location, sizeof (HelperBootstrapContext));
				Memory.copy (&bootstrap_ctx, output_context, output_context.length);

				allocation_base = (uintptr) bootstrap_ctx.allocation_base;
				code_swap.revert ();
			}

			result.allocated_stack.stack_base = (void *) (allocation_base + allocation_size - stack_size);
			result.allocated_stack.stack_size = stack_size;

			try {
				write_memory (allocation_base, bootstrapper_code);
				maybe_fixup_helper_code (allocation_base, bootstrapper_code);
				uint64 code_start = allocation_base;
				uint64 code_end = code_start + bootstrapper_size;

				HelperBootstrapStatus status = SUCCESS;
				do {
					GPRegs regs = saved_regs;
					regs.stack_pointer = result.allocated_stack.stack_root;
					var call_builder = new RemoteCallBuilder (code_start, regs);

					unowned uint8[] fallback_ld_data = fallback_ld.data;
					unowned uint8[] fallback_libc_data = fallback_libc.data;

					uint64 libc_api_location, bootstrap_ctx_location, fallback_ld_location, fallback_libc_location;
					call_builder
						.reserve_stack_space (sizeof (HelperLibcApi), out libc_api_location)
						.reserve_stack_space (sizeof (HelperBootstrapContext), out bootstrap_ctx_location)
						.reserve_stack_space (fallback_ld_data.length + 1, out fallback_ld_location)
						.reserve_stack_space (fallback_libc_data.length + 1, out fallback_libc_location);

					var bootstrap_ctx = HelperBootstrapContext ();
					bootstrap_ctx.allocation_base = (void *) allocation_base;
					bootstrap_ctx.allocation_size = allocation_size;
					bootstrap_ctx.page_size = Gum.query_page_size ();
					bootstrap_ctx.fallback_ld = (string *) fallback_ld_location;
					bootstrap_ctx.fallback_libc = (string *) fallback_libc_location;
					bootstrap_ctx.enable_ctrlfds = PidFileDescriptor.getfd_is_supported ();
					bootstrap_ctx.libc = (HelperLibcApi *) libc_api_location;
					write_memory (bootstrap_ctx_location, (uint8[]) &bootstrap_ctx);
					unowned uint8[] fallback_ld_cstr = fallback_ld_data[:fallback_ld_data.length + 1];
					unowned uint8[] fallback_libc_cstr = fallback_libc_data[:fallback_libc_data.length + 1];
					write_memory (fallback_ld_location, fallback_ld_cstr);
					write_memory (fallback_libc_location, fallback_libc_cstr);
					call_builder.add_argument (bootstrap_ctx_location);

					RemoteCall bootstrap_call = call_builder.build (this);
					RemoteCallResult bootstrap_result = yield bootstrap_call.execute (cancellable);
					status = (HelperBootstrapStatus) bootstrap_result.return_value;

					bool restart_after_libc_load =
						bootstrap_result.status == RAISED_SIGNAL && bootstrap_result.stop_signal == Posix.Signal.STOP;
					if (restart_after_libc_load) {
						bootstrap_result = yield bootstrap_call.execute (cancellable);
						status = (HelperBootstrapStatus) bootstrap_result.return_value;
					}

					if (!(bootstrap_result.status == COMPLETED && (status == SUCCESS || status == TOO_EARLY)))
						throw_bootstrap_error (bootstrap_result, status, code_start, code_end);

					uint8[] output_context = read_memory (bootstrap_ctx_location, sizeof (HelperBootstrapContext));
					Memory.copy (&result.context, output_context, output_context.length);

					uint8[] output_libc = read_memory (libc_api_location, sizeof (HelperLibcApi));
					Memory.copy (&result.libc, output_libc, output_libc.length);

					result.context.libc = &result.libc;

					if (result.context.rtld_flavor == ANDROID && result.libc.dlopen == null) {
						ProcMapsEntry? remote_ld = ProcMapsEntry.find_by_address (pid, (uintptr) result.context.rtld_base);
						bool same_ld = remote_ld != null && local_android_ld != null && remote_ld.identity == local_android_ld.identity;
						if (!same_ld)
							throw new Error.NOT_SUPPORTED ("Unable to locate Android dynamic linker; please file a bug");
						result.libc.dlopen = rebase_pointer ((uintptr) dlopen, local_android_ld, remote_ld);
						result.libc.dlclose = rebase_pointer ((uintptr) dlclose, local_android_ld, remote_ld);
						result.libc.dlsym = rebase_pointer ((uintptr) dlsym, local_android_ld, remote_ld);
						result.libc.dlerror = rebase_pointer ((uintptr) dlerror, local_android_ld, remote_ld);
					}

					if (status == TOO_EARLY)
						yield resume_until_execution_reaches ((uintptr) result.context.r_brk, cancellable);
				} while (status == TOO_EARLY);
			} catch (GLib.Error e) {
				if (remote_munmap != 0) {
					try {
						yield deallocate_memory (remote_munmap, allocation_base, allocation_size, null);
					} catch (GLib.Error e) {
					}
				}

				throw_api_error (e);
			}

			return result;
		}

		[NoReturn]
		private static void throw_bootstrap_error (RemoteCallResult bootstrap_result, HelperBootstrapStatus status,
				uint64 code_start, uint64 code_end) throws Error {
			if (bootstrap_result.status == COMPLETED) {
				throw new Error.NOT_SUPPORTED ("Bootstrapper failed due to '%s'; " +
					"please file a bug",
					Marshal.enum_to_nick<HelperBootstrapStatus> (status));
			} else {
				uint64 pc = bootstrap_result.regs.program_counter;
				if (pc >= code_start && pc < code_end) {
					throw new Error.NOT_SUPPORTED (
						"Bootstrapper crashed with signal %d at offset 0x%x; please file a bug\n%s",
						bootstrap_result.stop_signal,
						(uint) (pc - code_start),
						bootstrap_result.regs.to_string ());
				} else {
					throw new Error.NOT_SUPPORTED ("Bootstrapper crashed with signal %d; please file a bug\n%s",
						bootstrap_result.stop_signal,
						bootstrap_result.regs.to_string ());
				}
			}
		}

		private static void * rebase_pointer (uintptr local_ptr, ProcMapsEntry local_module, ProcMapsEntry remote_module) {
			var offset = local_ptr - local_module.base_address;
			return (void *) (remote_module.base_address + offset);
		}

		private static string make_fallback_address () {
			return "/frida-" + Uuid.string_random ();
		}

		private Future<RemoteAgent> establish_connection (LoaderLaunch launch, InjectSpec spec, BootstrapResult bres,
				UnixConnection? agent_ctrl, string fallback_address, Cancellable? cancellable) throws Error, IOError {
			var promise = new Promise<RemoteAgent> ();

			FileDescriptor? sockfd = null;
			if (PidFileDescriptor.getfd_is_supported () && bres.context.ctrlfds[0] != -1) {
				try {
					var pidfd = PidFileDescriptor.from_pid (pid);
					sockfd = pidfd.getfd (bres.context.ctrlfds[0]);
				} catch (Error e) {
				}
			}

			if (sockfd != null) {
				Socket socket;
				try {
					socket = new Socket.from_fd (sockfd.steal ());
				} catch (GLib.Error e) {
					assert_not_reached ();
				}
				var connection = (UnixConnection) SocketConnection.factory_create_connection (socket);

				do_establish_connection.begin (connection, launch, spec, bres, agent_ctrl, promise, cancellable);
			} else {
				var server_address = new UnixSocketAddress.with_type (fallback_address, -1, UnixSocketAddressType.ABSTRACT);

				Socket server_socket;
				try {
					var socket = new Socket (SocketFamily.UNIX, SocketType.STREAM, SocketProtocol.DEFAULT);
					socket.bind (server_address, true);
					socket.listen ();
					server_socket = socket;
				} catch (GLib.Error e) {
					throw new Error.TRANSPORT ("%s", e.message);
				}

				do_establish_connection_through_server.begin (server_socket, launch, spec, bres, agent_ctrl, promise,
					cancellable);
			}

			return promise.future;
		}

		private async void do_establish_connection (UnixConnection connection, LoaderLaunch launch, InjectSpec spec,
				BootstrapResult bres, UnixConnection? agent_ctrl, Promise<RemoteAgent> promise, Cancellable? cancellable) {
			try {
				var agent = yield RemoteAgent.start (launch, spec, pid, bres, connection, agent_ctrl, cancellable);
				promise.resolve (agent);
			} catch (Error e) {
				promise.reject (e);
			} catch (IOError e) {
				promise.reject (e);
			}
		}

		private async void do_establish_connection_through_server (Socket server_socket, LoaderLaunch launch, InjectSpec spec,
				BootstrapResult bres, UnixConnection? agent_ctrl, Promise<RemoteAgent> promise, Cancellable? cancellable) {
			var listener = new SocketListener ();
			try {
				listener.add_socket (server_socket, null);

				var connection = (UnixConnection) yield listener.accept_async (cancellable);
				do_establish_connection.begin (connection, launch, spec, bres, agent_ctrl, promise, cancellable);
			} catch (GLib.Error e) {
				if (e is IOError.CANCELLED)
					promise.reject ((IOError) e);
				else
					promise.reject (new Error.TRANSPORT ("%s", e.message));
			} finally {
				listener.close ();
			}
		}

		private void maybe_fixup_helper_code (uint64 base_address, uint8[] code) throws Error {
#if MIPS
			//
			// To avoid having to implement a dynamic linker, we carefully craft our helpers to avoid the need for relocations.
			// For MIPS however, it seems we cannot avoid them entirely. This means we need to fix up the .got section, as it
			// contains some absolute addresses. To find it without embedding the ELF of each helper and parsing that at
			// runtime, we use a linker script (helpers/helper.lds) to ensure that our .got is:
			// - Last
			// - Aligned on a 64-byte boundary
			// - Padded to 64 bytes
			// We assume that 64 bytes is sufficient for both of our helpers.
			//
			size_t padded_got_size = 64;
			size_t entries_start_offset = 8;
			size_t entries_size = padded_got_size - entries_start_offset;
			uint8[] entries = code[code.length - entries_size:];
			for (ulong offset = 0; offset != entries_size; offset += sizeof (size_t)) {
				size_t * entry = &entries[offset];
				*entry += base_address;
			}
			write_memory (base_address + code.length - entries_size, entries);
#endif
		}
	}

	public class InjectSpec {
		public FileDescriptorBased library_so {
			get;
			private set;
		}

		public string entrypoint {
			get;
			private set;
		}

		public string data {
			get;
			private set;
		}

		public AgentFeatures features {
			get;
			private set;
		}

		public uint id {
			get;
			private set;
		}

		public InjectSpec (FileDescriptorBased library_so, string entrypoint, string data, AgentFeatures features, uint id) {
			this.library_so = library_so;
			this.entrypoint = entrypoint;
			this.data = data;
			this.features = features;
			this.id = id;
		}

		public InjectSpec clone (uint clone_id, AgentFeatures features) {
			return new InjectSpec (library_so, entrypoint, data, features, clone_id);
		}
	}

	private class CleanupSession : SeizeSession {
		private CleanupSession (uint pid) {
			Object (pid: pid);
		}

		public static async CleanupSession open (uint pid, Cancellable? cancellable) throws Error, IOError {
			var session = new CleanupSession (pid);

			try {
				yield session.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return session;
		}

		public async void deallocate (BootstrapResult bres, Cancellable? cancellable) throws Error, IOError {
			yield deallocate_memory ((uintptr) bres.libc.munmap, (uintptr) bres.context.allocation_base,
				bres.context.allocation_size, cancellable);
		}
	}

	private class ThreadSuspendSession : SeizeSession {
		private ThreadSuspendSession (uint pid, uint tid) {
			Object (pid: pid, tid: tid);
		}

		public static async ThreadSuspendSession open (uint pid, uint tid, Cancellable? cancellable) throws Error, IOError {
			var session = new ThreadSuspendSession (pid, tid);

			try {
				yield session.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return session;
		}
	}

	private struct AllocatedStack {
		public void * stack_base;
		public size_t stack_size;

		public uint64 stack_root {
			get {
				return (uint64) stack_base + (uint64) stack_size;
			}
		}
	}


	private class BootstrapResult {
		public HelperBootstrapContext context;
		public HelperLibcApi libc;
		public AllocatedStack allocated_stack;

		public BootstrapResult clone () {
			var res = new BootstrapResult ();
			res.context = context;
			res.libc = libc;
			res.allocated_stack = allocated_stack;
			return res;
		}
	}

	private enum LoaderLaunch {
		FROM_SCRATCH,
		RELAUNCH
	}

	private class RemoteAgent : Object {
		public uint pid {
			get;
			construct;
		}

		public InjectSpec inject_spec {
			get;
			construct;
		}

		public BootstrapResult bootstrap_result {
			get;
			construct;
		}

		public UnixConnection frida_ctrl {
			get;
			construct;
		}

		public UnixConnection? agent_ctrl {
			get {
				return _agent_ctrl;
			}
			construct {
				_agent_ctrl = value;
			}
		}

		public State state {
			get {
				return _state;
			}
		}

		public UnloadPolicy unload_policy {
			get {
				return _unload_policy;
			}
		}

		public ProcessStatus process_status {
			get;
			set;
			default = NORMAL;
		}

		public enum State {
			STARTED,
			STOPPED,
			PAUSED
		}

		private State _state = STARTED;
		private UnloadPolicy _unload_policy = IMMEDIATE;

		public UnixConnection? _agent_ctrl;
		private FileDescriptor? agent_ctrlfd_for_peer;

		private Promise<bool>? start_request = new Promise<bool> ();
		private Promise<bool> cancel_request = new Promise<bool> ();
		private Cancellable io_cancellable = new Cancellable ();

		private RemoteAgent (uint pid, InjectSpec spec, BootstrapResult bres, UnixConnection frida_ctrl,
				UnixConnection? agent_ctrl = null) {
			Object (
				pid: pid,
				inject_spec: spec,
				bootstrap_result: bres,
				frida_ctrl: frida_ctrl,
				agent_ctrl: agent_ctrl
			);
		}

		public override void constructed () {
			if ((inject_spec.features & AgentFeatures.CONTROL_CHANNEL) != 0 && _agent_ctrl == null) {
				int fds[2];
				Posix.socketpair (Posix.AF_UNIX, Posix.SOCK_STREAM | SOCK_CLOEXEC, 0, fds);
				var agent_ctrlfd = new FileDescriptor (fds[0]);
				agent_ctrlfd_for_peer = new FileDescriptor (fds[1]);

				UnixSocket.tune_buffer_sizes (agent_ctrlfd.handle);
				UnixSocket.tune_buffer_sizes (agent_ctrlfd_for_peer.handle);

				Socket socket;
				try {
					socket = new Socket.from_fd (agent_ctrlfd.handle);
				} catch (GLib.Error e) {
					assert_not_reached ();
				}
				agent_ctrlfd.steal ();
				_agent_ctrl = (UnixConnection) SocketConnection.factory_create_connection (socket);
			}
		}

		internal static async RemoteAgent start (LoaderLaunch launch, InjectSpec spec, uint pid, BootstrapResult bres,
				UnixConnection frida_ctrl, UnixConnection? agent_ctrl, Cancellable? cancellable) throws Error, IOError {
			var agent = new RemoteAgent (pid, spec, bres, frida_ctrl, agent_ctrl);

			try {
				var io_priority = Priority.DEFAULT;

				if (launch == FROM_SCRATCH)
					frida_ctrl.send_fd (spec.library_so.get_fd (), cancellable);

				if (agent.agent_ctrlfd_for_peer != null) {
					frida_ctrl.send_fd (agent.agent_ctrlfd_for_peer.handle, cancellable);
					agent.agent_ctrlfd_for_peer = null;
				} else {
					yield frida_ctrl.get_output_stream ().write_async ({ 0 }, io_priority, cancellable);
				}
			} catch (GLib.Error e) {
				if (e is IOError.CANCELLED)
					throw (IOError) e;
				throw new Error.TRANSPORT ("%s", e.message);
			}

			agent.monitor.begin ();
			Future<bool> started = agent.start_request.future;
			yield started.wait_async (cancellable);
			return agent;
		}

		public void ack () {
			uint8 raw_type = HelperMessageType.ACK;
			frida_ctrl.get_output_stream ().write_all_async.begin ((uint8[]) &raw_type, Priority.DEFAULT, null);
		}

		private async void monitor () {
			Error? pending_start_error = null;
			try {
				var unload_policy = UnloadPolicy.IMMEDIATE;

				InputStream input = frida_ctrl.get_input_stream ();
				var io_priority = Priority.DEFAULT;
				size_t n;

				bool done = false;
				HelperHelloMessage? hello = null;
				HelperByeMessage? bye = null;
				do {
					uint8 raw_type = 0;
					yield input.read_all_async ((uint8[]) &raw_type, io_priority, io_cancellable, out n);
					if (n == 0)
						break;
					var type = (HelperMessageType) raw_type;

					switch (type) {
						case HELLO: {
							var m = HelperHelloMessage ();
							yield input.read_all_async ((uint8[]) &m, io_priority, io_cancellable, out n);
							if (n == 0)
								break;
							hello = m;

							break;
						}
						case READY: {
							if (start_request != null) {
								start_request.resolve (true);
								start_request = null;
							}
							break;
						}
						case BYE: {
							done = true;

							var m = HelperByeMessage ();
							yield input.read_all_async ((uint8[]) &m, io_priority, io_cancellable, out n);
							if (n == 0)
								break;
							bye = m;

							break;
						}
						case ERROR_DLOPEN:
						case ERROR_DLSYM: {
							uint16 length = 0;
							yield input.read_all_async ((uint8[]) &length, io_priority, io_cancellable, out n);
							if (n == 0)
								break;

							var data = new uint8[length + 1];
							yield input.read_all_async (data[:length], io_priority, io_cancellable, out n);
							if (n == 0)
								break;
							data[length] = 0;

							unowned string message = (string) data;

							pending_start_error = new Error.INVALID_ARGUMENT ("%s", message);

							break;
						}
						default:
							break;
					}
				} while (!done);

				if (bye != null)
					unload_policy = bye.unload_policy;

				if (hello != null) {
					string thread_path = "/proc/%u/task/%u".printf (pid, hello.thread_id);
					while (FileUtils.test (thread_path, EXISTS)) {
						var source = new TimeoutSource (50);
						source.set_callback (monitor.callback);
						source.attach (MainContext.get_thread_default ());
						yield;
					}
				}

				on_stop (unload_policy);
			} catch (GLib.Error e) {
				if (!(e is IOError.CANCELLED))
					on_stop (IMMEDIATE);
			} finally {
				if (start_request != null) {
					Error error = (pending_start_error != null)
						? pending_start_error
						: new Error.TRANSPORT ("Agent connection closed unexpectedly");
					start_request.reject (error);
					start_request = null;
				}
			}

			cancel_request.resolve (true);
		}

		public async void demonitor (Cancellable? cancellable) {
			io_cancellable.cancel ();

			try {
				yield cancel_request.future.wait_async (cancellable);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			_state = PAUSED;
			notify_property ("state");
		}

		public RemoteAgent clone (uint clone_id, AgentFeatures features) {
			var agent = new RemoteAgent (0, inject_spec.clone (clone_id, features), bootstrap_result.clone (), frida_ctrl);
			agent._state = _state;
			return agent;
		}

		public void stop () {
			on_stop (IMMEDIATE);
		}

		private void on_stop (UnloadPolicy unload_policy) {
			_unload_policy = unload_policy;
			_state = STOPPED;
			notify_property ("state");
		}
	}

	protected enum HelperBootstrapStatus {
		ALLOCATION_SUCCESS,
		ALLOCATION_ERROR,

		SUCCESS,
		AUXV_NOT_FOUND,
		TOO_EARLY,
		LIBC_LOAD_ERROR,
		LIBC_UNSUPPORTED,
	}

	protected struct HelperBootstrapContext {
		void * allocation_base;
		size_t allocation_size;

		size_t page_size;
		string * fallback_ld;
		string * fallback_libc;
		HelperRtldFlavor rtld_flavor;
		void * rtld_base;
		void * r_brk;
		bool enable_ctrlfds;
		int ctrlfds[2];
		HelperLibcApi * libc;
	}

	protected struct HelperLoaderContext {
		int ctrlfds[2]; // Must be first, as rejuvenate() assumes it.
		string * agent_entrypoint;
		string * agent_data;
		string * fallback_address;
		HelperLibcApi * libc;

		void * worker;
		void * agent_handle;
		void * agent_entrypoint_impl;
	}

	protected struct HelperLibcApi {
		void * printf;
		void * sprintf;

		void * mmap;
		void * munmap;
		void * socket;
		void * socketpair;
		void * connect;
		void * recvmsg;
		void * send;
		void * fcntl;
		void * close;

		void * pthread_create;
		void * pthread_detach;

		void * dlopen;
		int dlopen_flags;
		void * dlclose;
		void * dlsym;
		void * dlerror;
	}

	protected enum HelperMessageType {
		HELLO,
		READY,
		ACK,
		BYE,
		ERROR_DLOPEN,
		ERROR_DLSYM
	}

	protected struct HelperHelloMessage {
		uint thread_id;
	}

	protected struct HelperByeMessage {
		UnloadPolicy unload_policy;
	}

	protected enum HelperRtldFlavor {
		UNKNOWN,
		NONE,
		GLIBC,
		UCLIBC,
		MUSL,
		ANDROID,
	}

	protected enum HelperElfDynamicAddressState {
		PRISTINE,
		ADJUSTED
	}

	protected class SeizeSession : Object, AsyncInitable {
		public uint pid {
			get;
			construct;
		}

		public uint tid {
			get {
				return _tid;
			}
			construct {
				_tid = value;
			}
		}

		public InitBehavior on_init {
			get;
			construct;
			default = INTERRUPT;
		}

		public GPRegs saved_registers {
			get {
				return saved_regs;
			}
		}

		public enum InitBehavior {
			INTERRUPT,
			CONTINUE
		}

		private AttachState attach_state = ALREADY_ATTACHED;
		private uint _tid;
		protected GPRegs saved_regs;

		private static bool seize_supported;
		private static bool regset_supported = true;
		protected static ProcessVmIoFunc? process_vm_readv;
		protected static ProcessVmIoFunc? process_vm_writev;

		[CCode (has_target = false)]
		protected delegate ssize_t ProcessVmIoFunc (uint pid,
			[CCode (array_length_type = "unsigned long")]
			Posix.iovector[] local_iov,
			[CCode (array_length_type = "unsigned long")]
			Posix.iovector[] remote_iov,
			ulong flags);

		static construct {
			seize_supported = check_kernel_version (3, 4);

			if (check_kernel_version (3, 2)) {
				process_vm_readv = process_vm_readv_impl;
				process_vm_writev = process_vm_writev_impl;
			}
		}

		public override void constructed () {
			if (_tid == 0)
				_tid = pid;
		}

		public override void dispose () {
			if (attach_state == ATTACHED)
				close_potentially_running.begin ();

			base.dispose ();
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			PtraceOptions options = PtraceOptions.TRACESYSGOOD | PtraceOptions.TRACEEXEC;

			PtraceRequest req;
			long res;
			if (seize_supported) {
				req = SEIZE;
				res = _ptrace (req, tid, null, (void *) options);
			} else {
				req = ATTACH;
				res = _ptrace (req, tid);
			}
			int errsv = errno;

			switch (on_init) {
				case INTERRUPT: {
					bool maybe_already_attached = res == -1 && errsv == Posix.EPERM;
					if (maybe_already_attached) {
						get_regs (&saved_regs);

						attach_state = ALREADY_ATTACHED;
					} else {
						if (res == -1)
							throw_ptrace_error (req, pid, errsv);

						attach_state = ATTACHED;

						if (seize_supported) {
							ptrace (INTERRUPT, tid);
							yield wait_for_signal (TRAP, cancellable);
						} else {
							yield wait_for_signal (STOP, cancellable);
							ptrace (SETOPTIONS, tid, null, (void *) options);
						}

						get_regs (&saved_regs);
					}

					break;
				}
				case CONTINUE:
					if (res == -1)
						throw_ptrace_error (req, pid, errsv);

					attach_state = ATTACHED;

					if (!seize_supported) {
						yield wait_for_signal (STOP, cancellable);
						ptrace (SETOPTIONS, tid, null, (void *) options);
						ptrace (CONT, tid);
					}

					break;
			}

			return true;
		}

		public void close () throws Error {
			if (attach_state == ATTACHED) {
				ptrace (DETACH, tid);
				attach_state = ALREADY_ATTACHED;
			}
		}

		private async void close_potentially_running () {
			try {
				close ();
				return;
			} catch (Error e) {
			}

			try {
				yield suspend (null);
				close ();
			} catch (Error e) {
				// If the process is gone, then there's no point in retrying.
				if (e is Error.PROCESS_NOT_FOUND)
					attach_state = ALREADY_ATTACHED;
			} catch (GLib.Error e) {
			}
		}

		public async void suspend (Cancellable? cancellable) throws Error, IOError {
			if (seize_supported) {
				ptrace (INTERRUPT, tid);
				yield wait_for_signal (TRAP, cancellable);
			} else {
				tgkill (pid, tid, STOP);
				yield wait_for_signal (STOP, cancellable);
			}
		}

		public void resume () throws Error {
			ptrace (CONT, tid);
		}

		public void step () throws Error {
			ptrace (SINGLESTEP, tid);
		}

		public async void resume_until_execution_reaches (uint64 target, Cancellable? cancellable) throws Error, IOError {
			uint64 target_address = target;

			unowned uint8[] breakpoint_data;
#if X86 || X86_64
			uint8 breakpoint_val = 0xcc;
			breakpoint_data = (uint8[]) &breakpoint_val;
#elif ARM
			target_address &= ~1;

			uint32 arm_breakpoint_val = 0xe7f001f0U;
			uint16 thumb_breakpoint_val = 0xde01;
			bool is_thumb = (target & 1) != 0;
			if (is_thumb)
				breakpoint_data = (uint8[]) &thumb_breakpoint_val;
			else
				breakpoint_data = (uint8[]) &arm_breakpoint_val;
#elif ARM64
			uint32 breakpoint_val = 0xd4200000U;
			breakpoint_data = (uint8[]) &breakpoint_val;
#elif MIPS
			uint32 breakpoint_val = 0x0000000dU;
			breakpoint_data = (uint8[]) &breakpoint_val;
#endif

			if (saved_regs.program_counter == target) {
				step ();
				yield wait_for_signal (TRAP, cancellable);
				get_regs (&saved_regs);
			}

			uint8[] original_code = read_memory (target_address, breakpoint_data.length);
			write_memory (target_address, breakpoint_data);

			bool restored = false;
			try {
				resume ();
				yield wait_for_signal (TRAP, cancellable);

				restored = true;
				get_regs (&saved_regs);
				write_memory (target_address, original_code);

				bool hit_breakpoint = saved_regs.program_counter == target_address ||
					saved_regs.program_counter == target_address + breakpoint_data.length;
				if (!hit_breakpoint)
					throw new Error.NOT_SUPPORTED ("Unable to reach breakpoint (got unknown trap)");

				saved_regs.program_counter = target_address;
				set_regs (saved_regs);
			} finally {
				if (!restored) {
					try {
						get_regs (&saved_regs);
						write_memory (target_address, original_code);
					} catch (Error e) {
					}
				}
			}
		}

		public async void wait_for_signal (Posix.Signal sig, Cancellable? cancellable) throws Error, IOError {
			yield ChildProcess.wait_for_signal (tid, sig, cancellable);
		}

		public async Posix.Signal wait_for_signals (Posix.Signal[] sigs, Cancellable? cancellable) throws Error, IOError {
			return yield ChildProcess.wait_for_signals (tid, sigs, cancellable);
		}

		public async Posix.Signal wait_for_next_signal (Cancellable? cancellable) throws Error, IOError {
			return yield ChildProcess.wait_for_next_signal (tid, cancellable);
		}

		public void get_regs (GPRegs * regs) throws Error {
#if !MIPS
			if (regset_supported) {
				var io = Posix.iovector ();
				io.iov_base = regs;
				io.iov_len = sizeof (GPRegs);
				long res = _ptrace (GETREGSET, tid, (void *) NT_PRSTATUS, &io);
				if (res == 0)
					return;
				if (errno == Posix.EPERM || errno == Posix.ESRCH)
					throw_ptrace_error (GETREGSET, pid, errno);
				regset_supported = false;
			}
#endif

			ptrace (GETREGS, tid, null, regs);
		}

		public void get_fpregs (FPRegs * regs) throws Error {
			if (regset_supported) {
				var io = Posix.iovector ();
				io.iov_base = regs;
				io.iov_len = sizeof (FPRegs);
				long res = _ptrace (GETREGSET, tid, (void *) NT_PRFPREG, &io);
				if (res == 0)
					return;
				if (errno == Posix.EPERM || errno == Posix.ESRCH)
					throw_ptrace_error (GETREGSET, pid, errno);
				regset_supported = false;
			}

			ptrace (GETFPREGS, tid, null, regs);
		}

		public void set_regs (GPRegs regs) throws Error {
#if !MIPS
			if (regset_supported) {
				var io = Posix.iovector ();
				io.iov_base = &regs;
				io.iov_len = sizeof (GPRegs);
				long res = _ptrace (SETREGSET, tid, (void *) NT_PRSTATUS, &io);
				if (res == 0)
					return;
				if (errno == Posix.EPERM || errno == Posix.ESRCH)
					throw_ptrace_error (SETREGSET, pid, errno);
				regset_supported = false;
			}
#endif

			ptrace (SETREGS, tid, null, &regs);
		}

		public void set_fpregs (FPRegs regs) throws Error {
			if (regset_supported) {
				var io = Posix.iovector ();
				io.iov_base = &regs;
				io.iov_len = sizeof (FPRegs);
				long res = _ptrace (SETREGSET, tid, (void *) NT_PRFPREG, &io);
				if (res == 0)
					return;
				if (errno == Posix.EPERM || errno == Posix.ESRCH)
					throw_ptrace_error (SETREGSET, pid, errno);
				regset_supported = false;
			}

			ptrace (SETFPREGS, tid, null, &regs);
		}

		public async uint64 allocate_memory (uint64 mmap_impl, size_t size, int prot, Cancellable? cancellable)
				throws Error, IOError {
			var builder = new RemoteCallBuilder (mmap_impl, saved_regs);
			builder
				.add_argument (0)
				.add_argument (size)
				.add_argument (prot)
				.add_argument (Posix.MAP_PRIVATE | MAP_ANONYMOUS)
				.add_argument (~0)
				.add_argument (0);
			RemoteCall call = builder.build (this);

			RemoteCallResult res = yield call.execute (cancellable);
			if (res.status != COMPLETED)
				throw new Error.NOT_SUPPORTED ("Unexpected crash while trying to allocate memory");
			if (res.return_value == MAP_FAILED)
				throw new Error.NOT_SUPPORTED ("Unexpected failure while trying to allocate memory");
			return res.return_value;
		}

		public async void deallocate_memory (uint64 munmap_impl, uint64 address, size_t size, Cancellable? cancellable)
				throws Error, IOError {
			var builder = new RemoteCallBuilder (munmap_impl, saved_regs);
			builder
				.add_argument (address)
				.add_argument (size);
			RemoteCall call = builder.build (this);

			RemoteCallResult res = yield call.execute (cancellable);
			if (res.status != COMPLETED)
				throw new Error.NOT_SUPPORTED ("Unexpected crash while trying to deallocate memory");
			if (res.return_value != 0)
				throw new Error.NOT_SUPPORTED ("Unexpected failure while trying to deallocate memory");
		}

		public uint8[] read_memory (uint64 address, size_t size) throws Error {
			if (size == 0)
				return {};

			var result = new uint8[size];

			if (process_vm_readv != null) {
				var local = Posix.iovector ();
				local.iov_base = result;
				local.iov_len = result.length;

				var remote = Posix.iovector ();
				remote.iov_base = (void *) address;
				remote.iov_len = size;

				ssize_t res = process_vm_readv (pid, (Posix.iovector[]) &local, (Posix.iovector[]) &remote, 0);
				if (res != -1)
					return result;
				if (errno == Posix.ENOSYS)
					process_vm_readv = null;
				else if (errno != Posix.EPERM && errno != Posix.EFAULT)
					throw new Error.NOT_SUPPORTED ("Unable to read from process memory: %s", strerror (errno));
			}

			size_t offset = 0;
			uint bytes_per_word = (uint) sizeof (size_t);
			while (offset != size) {
				size_t word = (size_t) ptrace (PEEKDATA, tid, (void *) (address + offset));
				size_t chunk_size = size_t.min (size - offset, bytes_per_word);
				Memory.copy ((uint8 *) result + offset, &word, chunk_size);

				o
```