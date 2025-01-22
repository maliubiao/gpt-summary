Response:
### 功能归纳

`frida-helper-backend.vala` 是 Frida 工具的核心组件之一，主要负责在 Linux 系统上实现动态插桩（Dynamic Instrumentation）功能。它通过 `ptrace` 系统调用与目标进程进行交互，实现对目标进程的控制、注入、监控等操作。以下是该文件的主要功能归纳：

1. **进程管理**：
   - **进程创建与监控**：通过 `fork()` 和 `execve()` 创建新进程，并使用 `ptrace` 进行监控。支持通过 `SpawnedProcess` 类管理进程的生命周期，包括进程的启动、终止、输入输出等。
   - **进程状态管理**：通过 `ProcessStatus` 枚举管理进程的状态（如 `NORMAL` 和 `EXEC_PENDING`），并在进程状态变化时更新相关状态。

2. **动态插桩与注入**：
   - **库注入**：通过 `inject_library` 方法将共享库（`.so` 文件）注入到目标进程中，并执行指定的入口函数。支持通过 `InjectSpec` 结构体传递注入参数。
   - **远程代理管理**：通过 `RemoteAgent` 类管理注入的远程代理，支持代理的启动、暂停、恢复、销毁等操作。

3. **系统调用拦截**：
   - **系统调用监控**：通过 `PausedSyscallSession` 类拦截目标进程的系统调用，支持等待特定系统调用的发生，并在系统调用发生时暂停进程。
   - **系统调用恢复**：通过 `resume_syscall` 方法恢复被暂停的系统调用，使目标进程继续执行。

4. **进程间通信**：
   - **控制通道**：通过 `request_control_channel` 方法建立与目标进程的控制通道，支持通过 `UnixConnection` 进行进程间通信。
   - **输入输出管理**：通过 `SpawnedProcess` 类管理目标进程的标准输入输出，支持通过管道（`pipe`）或伪终端（`pty`）进行输入输出重定向。

5. **进程调试与监控**：
   - **调试会话管理**：通过 `ExecTransitionSession` 和 `PausedSyscallSession` 类管理调试会话，支持在进程执行 `exec` 系统调用时进行监控，并在系统调用发生时暂停进程。
   - **调试任务队列**：通过 `TaskEntry` 和 `Task` 接口管理调试任务的执行顺序，确保任务按顺序执行。

6. **错误处理与资源管理**：
   - **错误处理**：通过 `Error` 和 `IOError` 处理各种错误情况，如进程未找到、权限不足、系统调用失败等。
   - **资源释放**：通过 `deallocate_agent` 方法释放注入的远程代理占用的资源，确保资源不会泄漏。

### 二进制底层与 Linux 内核相关功能

1. **`ptrace` 系统调用**：
   - 该文件大量使用 `ptrace` 系统调用来监控和控制目标进程。例如，`ptrace(TRACEME)` 用于让目标进程被调试，`ptrace(CONT)` 用于继续执行被暂停的进程，`ptrace(SYSCALL)` 用于拦截系统调用。

2. **`fork()` 和 `execve()`**：
   - 通过 `fork()` 创建新进程，并通过 `execve()` 执行目标程序。在 `execve()` 执行前，使用 `ptrace(TRACEME)` 让目标进程进入调试状态。

3. **系统调用拦截**：
   - 通过 `ptrace(SYSCALL)` 拦截目标进程的系统调用，并在系统调用发生时暂停进程。通过 `get_regs()` 和 `set_regs()` 获取和设置寄存器的值，从而控制进程的执行流程。

### LLDB 调试示例

假设我们想要使用 LLDB 调试 `frida-helper-backend.vala` 中实现的调试功能，可以通过以下步骤进行：

1. **启动目标进程**：
   - 使用 `spawn` 方法启动目标进程，并通过 `ptrace` 进行监控。

2. **拦截系统调用**：
   - 使用 `await_syscall` 方法拦截目标进程的系统调用，并在系统调用发生时暂停进程。

3. **使用 LLDB 调试**：
   - 在 LLDB 中附加到目标进程，查看寄存器和内存状态。

```python
import lldb

# 启动 LLDB 调试器
debugger = lldb.SBDebugger.Create()
debugger.SetAsync(True)

# 创建目标进程
target = debugger.CreateTarget("target_process")
if not target:
    print("Failed to create target")
    exit(1)

# 附加到目标进程
process = target.AttachToProcessWithID(lldb.SBListener(), target_process_pid)
if not process:
    print("Failed to attach to process")
    exit(1)

# 设置断点
breakpoint = target.BreakpointCreateByName("syscall")
if not breakpoint:
    print("Failed to set breakpoint")
    exit(1)

# 继续执行进程
process.Continue()

# 等待断点触发
event = lldb.SBEvent()
while True:
    if process.GetListener().WaitForEvent(1, event):
        if lldb.SBProcess.EventIsProcessEvent(event):
            state = process.GetState()
            if state == lldb.eStateStopped:
                # 获取寄存器状态
                thread = process.GetSelectedThread()
                frame = thread.GetSelectedFrame()
                registers = frame.GetRegisters()

                # 打印寄存器值
                for reg in registers:
                    print(reg.GetName(), reg.GetValue())

                # 继续执行
                process.Continue()
            elif state == lldb.eStateExited:
                break
```

### 假设输入与输出

1. **输入**：
   - 目标进程的路径和启动参数。
   - 要注入的共享库路径和入口函数。

2. **输出**：
   - 目标进程的 PID。
   - 注入的远程代理的 ID。
   - 系统调用的拦截结果。

### 常见使用错误

1. **权限不足**：
   - 用户可能没有足够的权限来执行 `ptrace` 或 `fork` 操作，导致进程无法启动或注入失败。

2. **目标进程不存在**：
   - 如果目标进程的 PID 无效或进程已经退出，操作将失败。

3. **注入失败**：
   - 如果共享库路径无效或入口函数不存在，注入操作将失败。

### 用户操作步骤

1. **启动目标进程**：
   - 用户通过 `spawn` 方法启动目标进程，并获取进程的 PID。

2. **注入共享库**：
   - 用户通过 `inject_library` 方法将共享库注入到目标进程中，并指定入口函数。

3. **拦截系统调用**：
   - 用户通过 `await_syscall` 方法拦截目标进程的系统调用，并在系统调用发生时暂停进程。

4. **调试与分析**：
   - 用户通过 LLDB 或其他调试工具附加到目标进程，查看寄存器和内存状态，分析进程的执行流程。

通过这些步骤，用户可以逐步实现动态插桩和调试功能，并分析目标进程的行为。
Prompt: 
```
这是目录为frida/subprojects/frida-core/src/linux/frida-helper-backend.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共3部分，请归纳一下它的功能

"""
namespace Frida {
	public class LinuxHelperBackend : Object, LinuxHelper {
		public signal void idle ();

		public bool is_idle {
			get {
				return agents.is_empty;
			}
		}

		private Gee.Map<uint, SpawnedProcess> spawned_processes = new Gee.HashMap<uint, SpawnedProcess> ();
		private Gee.Map<uint, ExecTransitionSession> exec_transitions = new Gee.HashMap<uint, ExecTransitionSession> ();
		private Gee.Map<uint, AwaitExecTransitionTask> exec_waiters = new Gee.HashMap<uint, AwaitExecTransitionTask> ();
		private Gee.Map<uint, PausedSyscallSession> paused_syscalls = new Gee.HashMap<uint, PausedSyscallSession> ();
		private Gee.Map<uint, RemoteAgent> agents = new Gee.HashMap<uint, RemoteAgent> ();
		private Gee.Map<uint, Source> agent_expiries = new Gee.HashMap<uint, Source> ();
		private Gee.Map<uint, Gee.Queue<TaskEntry>> task_queues = new Gee.HashMap<uint, Gee.Queue<TaskEntry>> ();

		public async void close (Cancellable? cancellable) throws IOError {
			if (!is_idle) {
				var idle_handler = idle.connect (() => {
					close.callback ();
				});
				yield;
				disconnect (idle_handler);
			}

			foreach (SpawnedProcess p in spawned_processes.values)
				p.close ();
		}

		public async uint spawn (string path, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
			if (!FileUtils.test (path, EXISTS))
				throw new Error.EXECUTABLE_NOT_FOUND ("Unable to find executable at '%s'", path);

			string[] argv = options.compute_argv (path);
			string[] envp = options.compute_envp ();

			StdioPipes? pipes = null;
			FileDescriptor? stdin_read = null, stdin_write = null;
			FileDescriptor? stdout_read = null, stdout_write = null;
			FileDescriptor? stderr_read = null, stderr_write = null;
			switch (options.stdio) {
				case INHERIT:
					break;
				case PIPE: {
					make_pty (out stdin_read, out stdin_write);
					make_pty (out stdout_read, out stdout_write);
					make_pty (out stderr_read, out stderr_write);
					pipes = new StdioPipes (stdin_write, stdout_read, stderr_read);
					break;
				}
			}

			string? old_cwd = null;
			if (options.cwd.length > 0) {
				old_cwd = Environment.get_current_dir ();
				if (Environment.set_current_dir (options.cwd) != 0)
					throw new Error.INVALID_ARGUMENT ("Unable to change directory to '%s'", options.cwd);
			}

			Posix.pid_t pid;
			try {
				pid = Posix.fork ();
				if (pid == -1)
					throw new Error.NOT_SUPPORTED ("Unable to fork(): %s", strerror (errno));

				if (pid == 0) {
					Posix.setsid ();

					if (options.stdio == PIPE) {
						Posix.dup2 (stdin_read.handle, 0);
						Posix.dup2 (stdout_write.handle, 1);
						Posix.dup2 (stderr_write.handle, 2);
					}

					if (_ptrace (TRACEME) == -1) {
						stderr.printf ("Unexpected error while spawning process (ptrace failed: %s)\n", Posix.strerror (errno));
						Posix._exit (1);
					}
					Posix.raise (Posix.Signal.STOP);

					if (execve (path, argv, envp) == -1) {
						stderr.printf ("Unexpected error while spawning process (execve failed: %s)\n", Posix.strerror (errno));
						Posix._exit (2);
					}
				}
			} finally {
				if (old_cwd != null)
					Environment.set_current_dir (old_cwd);
			}

			bool ready = false;
			try {
				yield ChildProcess.wait_for_early_signal (pid, STOP, cancellable);
				ptrace (CONT, pid);
				yield ChildProcess.wait_for_early_signal (pid, TRAP, cancellable);
				ready = true;
			} finally {
				if (!ready)
					Posix.kill (pid, Posix.Signal.KILL);
			}

			var p = new SpawnedProcess (pid, pipes);
			p.terminated.connect (on_spawned_process_terminated);
			p.output.connect (on_spawned_process_output);
			spawned_processes[pid] = p;

			return pid;
		}

		private void on_spawned_process_terminated (SpawnedProcess process) {
			spawned_processes.unset (process.pid);
		}

		private void on_spawned_process_output (SpawnedProcess process, int fd, uint8[] data) {
			output (process.pid, fd, data);
		}

		public async void prepare_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			yield perform<ExecTransitionSession> (new PrepareExecTransitionTask (this), pid, cancellable);
		}

		private class PrepareExecTransitionTask : Object, Task<ExecTransitionSession> {
			private weak LinuxHelperBackend backend;

			public PrepareExecTransitionTask (LinuxHelperBackend backend) {
				this.backend = backend;
			}

			public async ExecTransitionSession run (uint pid, Cancellable? cancellable) throws Error, IOError {
				SpawnedProcess? p = backend.spawned_processes[pid];
				if (p != null)
					p.demonitor ();

				var session = yield ExecTransitionSession.open (pid, cancellable);
				backend.exec_transitions[pid] = session;

				backend.update_process_status (pid, EXEC_PENDING);

				return session;
			}
		}

		public async void await_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			if (exec_waiters.has_key (pid))
				throw new Error.INVALID_ARGUMENT ("Wait operation already in progress");

			var task = new AwaitExecTransitionTask (this);
			exec_waiters[pid] = task;
			try {
				yield perform<ExecTransitionSession> (task, pid, cancellable);
			} finally {
				exec_waiters.unset (pid);

				SpawnedProcess? p = spawned_processes[pid];
				if (p != null)
					p.monitor ();

				update_process_status (pid, NORMAL);
			}
		}

		private class AwaitExecTransitionTask : Object, Task<ExecTransitionSession> {
			private weak LinuxHelperBackend backend;

			private Cancellable wait_cancellable = new Cancellable ();

			public AwaitExecTransitionTask (LinuxHelperBackend backend) {
				this.backend = backend;
			}

			public async ExecTransitionSession run (uint pid, Cancellable? cancellable) throws Error, IOError {
				ExecTransitionSession? session = backend.exec_transitions[pid];
				if (session == null)
					throw new Error.INVALID_ARGUMENT ("Invalid PID");

				var cancel_source = new CancellableSource (cancellable);
				cancel_source.set_callback (() => {
					wait_cancellable.cancel ();
					return Source.REMOVE;
				});
				cancel_source.attach (MainContext.get_thread_default ());

				GLib.Error? pending_error = null;
				try {
					yield session.wait_for_exec (wait_cancellable);
				} catch (GLib.Error e) {
					pending_error = e;
				} finally {
					cancel_source.destroy ();
				}

				if (pending_error != null) {
					backend.exec_transitions.unset (pid);
					try {
						session.close ();
					} catch (Error e) {
						yield session.suspend (null);
						try {
							session.close ();
						} catch (Error e) {
						}
					}
					throw_api_error (pending_error);
				}

				return session;
			}

			public void cancel () {
				wait_cancellable.cancel ();
			}
		}

		public async void cancel_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			AwaitExecTransitionTask? task = exec_waiters[pid];
			if (task == null)
				throw new Error.INVALID_ARGUMENT ("Invalid PID");

			task.cancel ();

			yield perform<FlushExecTransitionTask> (new FlushExecTransitionTask (), pid, cancellable);
		}

		private class FlushExecTransitionTask : Object, Task<FlushExecTransitionTask> {
			public FlushExecTransitionTask () {
			}

			public async FlushExecTransitionTask run (uint pid, Cancellable? cancellable) throws Error, IOError {
				return this;
			}
		}

		public async void await_syscall (uint pid, LinuxSyscall mask, Cancellable? cancellable) throws Error, IOError {
			yield perform<PausedSyscallSession> (new AwaitSyscallTask (this, mask), pid, cancellable);
		}

		private class AwaitSyscallTask : Object, Task<PausedSyscallSession> {
			private weak LinuxHelperBackend backend;
			private LinuxSyscall mask;

			public AwaitSyscallTask (LinuxHelperBackend backend, LinuxSyscall mask) {
				this.backend = backend;
				this.mask = mask;
			}

			public async PausedSyscallSession run (uint pid, Cancellable? cancellable) throws Error, IOError {
				var session = yield PausedSyscallSession.open (pid, cancellable);
				yield session.wait_for_syscall (mask, cancellable);
				backend.paused_syscalls[pid] = session;
				return session;
			}
		}

		public async void resume_syscall (uint pid, Cancellable? cancellable) throws Error, IOError {
			PausedSyscallSession session;
			if (!paused_syscalls.unset (pid, out session))
				throw new Error.INVALID_ARGUMENT ("Invalid PID");

			session.close ();
		}

		public async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			SpawnedProcess? p = spawned_processes[pid];
			if (p == null)
				throw new Error.INVALID_ARGUMENT ("Invalid PID");
			yield p.input (data, cancellable);
		}

		public async void resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			yield perform<SpawnedProcess> (new ResumeTask (this), pid, cancellable);
		}

		private class ResumeTask : Object, Task<SpawnedProcess?> {
			private weak LinuxHelperBackend backend;

			public ResumeTask (LinuxHelperBackend backend) {
				this.backend = backend;
			}

			public async SpawnedProcess? run (uint pid, Cancellable? cancellable) throws Error, IOError {
				if (backend.exec_waiters.has_key (pid))
					throw new Error.INVALID_OPERATION ("Invalid operation");

				ExecTransitionSession session;
				if (backend.exec_transitions.unset (pid, out session)) {
					session.close ();
					return null;
				}

				SpawnedProcess? p = backend.spawned_processes[pid];
				if (p != null) {
					p.resume ();
					return p;
				}

				throw new Error.INVALID_ARGUMENT ("Invalid PID");
			}
		}

		public async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
			Posix.kill ((Posix.pid_t) pid, Posix.Signal.KILL);
		}

		public async void inject_library (uint pid, UnixInputStream library_so, string entrypoint, string data,
				AgentFeatures features, uint id, Cancellable? cancellable) throws Error, IOError {
			var spec = new InjectSpec (library_so, entrypoint, data, features, id);
			var task = new InjectTask (this, spec);
			RemoteAgent agent = yield perform (task, pid, cancellable);
			take_agent (agent);
		}

		private class InjectTask : Object, Task<RemoteAgent> {
			private weak LinuxHelperBackend backend;
			private InjectSpec spec;

			public InjectTask (LinuxHelperBackend backend, InjectSpec spec) {
				this.backend = backend;
				this.spec = spec;
			}

			public async RemoteAgent run (uint pid, Cancellable? cancellable) throws Error, IOError {
				PausedSyscallSession? pss = backend.paused_syscalls[pid];
				if (pss != null)
					yield pss.interrupt (cancellable);
				var session = yield InjectSession.open (pid, cancellable);
				RemoteAgent agent = yield session.inject (spec, cancellable);
				session.close ();
				return agent;
			}
		}

		public async IOStream request_control_channel (uint id, Cancellable? cancellable) throws Error, IOError {
			RemoteAgent agent = agents[id];
			if (agent == null)
				throw new Error.INVALID_ARGUMENT ("Invalid ID");

			UnixConnection agent_ctrl = agent.agent_ctrl;
			if (agent_ctrl == null)
				throw new Error.NOT_SUPPORTED ("Control channel feature not enabled");

			return agent_ctrl;
		}

		private void update_process_status (uint pid, ProcessStatus status) {
			foreach (RemoteAgent agent in agents.values) {
				if (agent.pid == pid)
					agent.process_status = status;
			}
		}

		private void take_agent (RemoteAgent agent) {
			if (agent.state == STOPPED) {
				var source = new IdleSource ();
				source.set_callback (() => {
					on_agent_stopped (agent);
					return Source.REMOVE;
				});
				source.attach (MainContext.get_thread_default ());
				return;
			}
			agents[agent.inject_spec.id] = agent;
			agent.notify["state"].connect (on_agent_state_changed);
		}

		private void on_agent_state_changed (Object object, ParamSpec pspec) {
			var agent = (RemoteAgent) object;
			if (agent.state == STOPPED)
				on_agent_stopped (agent);
		}

		private void on_agent_stopped (RemoteAgent agent) {
			uint id = agent.inject_spec.id;

			uninjected (id);

			if (agent.unload_policy == IMMEDIATE && agent.process_status == NORMAL) {
				// TODO: Implement did_not_exec() guard.
				deallocate_agent.begin (agent);
			} else {
				agents.unset (id);
				maybe_emit_idle ();
			}
		}

		private async void deallocate_agent (RemoteAgent agent) {
			uint pid = agent.pid;
			try {
				yield perform<RemoteAgent> (new DeallocateTask (agent), pid, null);
			} catch (GLib.Error e) {
			}

			agents.unset (agent.inject_spec.id);
			maybe_emit_idle ();
		}

		private class DeallocateTask : Object, Task<RemoteAgent> {
			private RemoteAgent agent;

			public DeallocateTask (RemoteAgent agent) {
				this.agent = agent;
			}

			public async RemoteAgent run (uint pid, Cancellable? cancellable) throws Error, IOError {
				var session = yield CleanupSession.open (pid, cancellable);
				yield session.deallocate (agent.bootstrap_result, cancellable);
				session.close ();
				return agent;
			}
		}

		public async void demonitor (uint id, Cancellable? cancellable) throws Error, IOError {
			RemoteAgent? agent = agents[id];
			if (agent == null || agent.state != STARTED)
				throw new Error.INVALID_ARGUMENT ("Invalid ID");

			yield agent.demonitor (cancellable);

			schedule_agent_expiry_for_id (id);
		}

		public async void demonitor_and_clone_injectee_state (uint id, uint clone_id, AgentFeatures features,
				Cancellable? cancellable) throws Error, IOError {
			RemoteAgent? agent = agents[id];
			if (agent == null || agent.state != STARTED)
				throw new Error.INVALID_ARGUMENT ("Invalid ID");

			yield agent.demonitor (cancellable);

			agents[clone_id] = agent.clone (clone_id, features);

			schedule_agent_expiry_for_id (id);
			schedule_agent_expiry_for_id (clone_id);
		}

		public async void recreate_injectee_thread (uint pid, uint id, Cancellable? cancellable) throws Error, IOError {
			RemoteAgent? old_agent = agents[id];
			if (old_agent == null || old_agent.state != PAUSED)
				throw new Error.INVALID_ARGUMENT ("Invalid ID");

			cancel_agent_expiry_for_id (id);

			var task = new RejuvenateTask (old_agent);
			RemoteAgent new_agent = yield perform (task, pid, cancellable);
			take_agent (new_agent);
		}

		private class RejuvenateTask : Object, Task<RemoteAgent> {
			private RemoteAgent old_agent;

			public RejuvenateTask (RemoteAgent old_agent) {
				this.old_agent = old_agent;
			}

			public async RemoteAgent run (uint pid, Cancellable? cancellable) throws Error, IOError {
				var session = yield InjectSession.open (pid, cancellable);
				RemoteAgent new_agent = yield session.rejuvenate (old_agent, cancellable);
				session.close ();
				return new_agent;
			}
		}

		private void maybe_emit_idle () {
			if (is_idle)
				idle ();
		}

		private void schedule_agent_expiry_for_id (uint id) {
			Source previous_source;
			if (agent_expiries.unset (id, out previous_source))
				previous_source.destroy ();

			var source = new TimeoutSource.seconds (20);
			source.set_callback (() => {
				bool removed = agent_expiries.unset (id);
				assert (removed);

				RemoteAgent agent = agents[id];
				agent.stop ();

				return Source.REMOVE;
			});
			source.attach (MainContext.get_thread_default ());
			agent_expiries[id] = source;
		}

		private void cancel_agent_expiry_for_id (uint id) {
			Source source;
			bool found = agent_expiries.unset (id, out source);
			assert (found);

			source.destroy ();
		}

		private async T perform<T> (Task<T> task, uint pid, Cancellable? cancellable) throws Error, IOError {
			Gee.Queue<TaskEntry> queue = task_queues[pid];
			if (queue == null) {
				queue = new Gee.ArrayQueue<TaskEntry> ();
				task_queues[pid] = queue;

				var source = new IdleSource ();
				source.set_callback (() => {
					process_tasks.begin (queue, pid);
					return Source.REMOVE;
				});
				source.attach (MainContext.get_thread_default ());
			}

			var entry = new TaskEntry ((Task<Object>) task, cancellable);
			queue.offer (entry);

			return yield entry.promise.future.wait_async (cancellable);
		}

		private async void process_tasks (Gee.Queue<TaskEntry> queue, uint pid) {
			var main_context = MainContext.get_thread_default ();

			TaskEntry entry;
			while ((entry = queue.poll ()) != null) {
				try {
					entry.cancellable.set_error_if_cancelled ();
					var result = yield entry.task.run (pid, entry.cancellable);
					entry.promise.resolve (result);
				} catch (GLib.Error e) {
					entry.promise.reject (e);
				}

				var source = new IdleSource ();
				source.set_callback (process_tasks.callback);
				source.attach (main_context);
				yield;
			}

			task_queues.unset (pid);
		}

		private class TaskEntry {
			public Task<Object> task;
			public Cancellable? cancellable;
			public Promise<Object> promise = new Promise<Object> ();

			public TaskEntry (Task<Object> task, Cancellable? cancellable) {
				this.task = task;
				this.cancellable = cancellable;
			}
		}

		private interface Task<T> : Object {
			public abstract async T run (uint pid, Cancellable? cancellable) throws Error, IOError;
		}
	}

	public unowned string arch_name_from_pid (uint pid) throws Error {
		Gum.CpuType cpu_type = cpu_type_from_pid (pid);

		switch (cpu_type) {
			case Gum.CpuType.IA32:
			case Gum.CpuType.ARM:
			case Gum.CpuType.MIPS:
				return "32";

			case Gum.CpuType.AMD64:
			case Gum.CpuType.ARM64:
				return "64";

			default:
				assert_not_reached ();
		}
	}

	public Gum.CpuType cpu_type_from_file (string path) throws Error {
		try {
			return Gum.Linux.cpu_type_from_file (path);
		} catch (Gum.Error e) {
			if (e is Gum.Error.NOT_FOUND)
				throw new Error.EXECUTABLE_NOT_FOUND ("Unable to find executable at '%s'", path);
			else if (e is Gum.Error.NOT_SUPPORTED)
				throw new Error.EXECUTABLE_NOT_SUPPORTED ("Unable to parse executable at '%s'", path);
			else if (e is Gum.Error.PERMISSION_DENIED)
				throw new Error.PERMISSION_DENIED ("Unable to access executable at '%s'", path);
			else
				throw new Error.NOT_SUPPORTED ("%s", e.message);
		}
	}

	public Gum.CpuType cpu_type_from_pid (uint pid) throws Error {
		try {
			return Gum.Linux.cpu_type_from_pid ((Posix.pid_t) pid);
		} catch (Gum.Error e) {
			if (e is Gum.Error.NOT_FOUND)
				throw new Error.PROCESS_NOT_FOUND ("Unable to find process with pid %u", pid);
			else if (e is Gum.Error.PERMISSION_DENIED)
				throw new Error.PERMISSION_DENIED ("Unable to access process with pid %u", pid);
			else
				throw new Error.NOT_SUPPORTED ("%s", e.message);
		}
	}

	private class SpawnedProcess : Object {
		public signal void terminated ();
		public signal void output (int fd, uint8[] data);

		public uint pid {
			get;
			construct;
		}

		public StdioPipes? pipes {
			get;
			construct;
		}

		private State state = SUSPENDED;
		private uint watch_id;
		private OutputStream? stdin_stream;

		private Cancellable io_cancellable = new Cancellable ();

		private enum State {
			SUSPENDED,
			RUNNING,
		}

		public SpawnedProcess (uint pid, StdioPipes? pipes) {
			Object (pid: pid, pipes: pipes);
		}

		~SpawnedProcess () {
			try {
				resume ();
			} catch (Error e) {
			}
		}

		construct {
			monitor ();

			if (pipes != null) {
				stdin_stream = new UnixOutputStream (pipes.input.handle, false);
				process_next_output_from.begin (new UnixInputStream (pipes.output.handle, false), 1);
				process_next_output_from.begin (new UnixInputStream (pipes.error.handle, false), 2);
			}
		}

		public void close () {
			demonitor ();

			io_cancellable.cancel ();
		}

		public void resume () throws Error {
			if (state == SUSPENDED) {
				ptrace (DETACH, pid);
				state = RUNNING;
			}
		}

		public void monitor () {
			if (watch_id == 0)
				watch_id = ChildWatch.add ((Pid) pid, on_termination);
		}

		public void demonitor () {
			if (watch_id != 0) {
				Source.remove (watch_id);
				watch_id = 0;
			}
		}

		private void on_termination (Pid pid, int status) {
			watch_id = 0;
			stdin_stream = null;

			terminated ();
		}

		public async void input (uint8[] data, Cancellable? cancellable) throws Error, IOError {
			if (stdin_stream == null)
				throw new Error.NOT_SUPPORTED ("Unable to pass input to process spawned without piped stdio");

			try {
				yield stdin_stream.write_all_async (data, Priority.DEFAULT, cancellable, null);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s", e.message);
			}
		}

		private async void process_next_output_from (InputStream stream, int fd) {
			try {
				var buf = new uint8[4096];
				var n = yield stream.read_async (buf, Priority.DEFAULT, io_cancellable);

				var data = buf[0:n];
				output (fd, data);

				if (n > 0)
					process_next_output_from.begin (stream, fd);
			} catch (GLib.Error e) {
				if (!(e is IOError.CANCELLED))
					output (fd, {});
			}
		}
	}

	private class StdioPipes : Object {
		public FileDescriptor input {
			get;
			construct;
		}

		public FileDescriptor output {
			get;
			construct;
		}

		public FileDescriptor error {
			get;
			construct;
		}

		public StdioPipes (FileDescriptor input, FileDescriptor output, FileDescriptor error) {
			Object (input: input, output: output, error: error);
		}

		construct {
			try {
				Unix.set_fd_nonblocking (input.handle, true);
				Unix.set_fd_nonblocking (output.handle, true);
				Unix.set_fd_nonblocking (error.handle, true);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}
	}

	private class ExecTransitionSession : SeizeSession {
		private ExecTransitionSession (uint pid) {
			Object (pid: pid, on_init: SeizeSession.InitBehavior.CONTINUE);
		}

		public static async ExecTransitionSession open (uint pid, Cancellable? cancellable) throws Error, IOError {
			var session = new ExecTransitionSession (pid);

			try {
				yield session.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return session;
		}

		public async void wait_for_exec (Cancellable? cancellable) throws Error, IOError {
			yield wait_for_signal (TRAP, cancellable);
			step ();
			yield wait_for_signal (TRAP, cancellable);
		}
	}

	private class PausedSyscallSession : SeizeSession {
		private State state = PENDING;

		private enum State {
			PENDING,
			SATISFIED
		}

		private PausedSyscallSession (uint pid) {
			Object (pid: pid);
		}

		public static async PausedSyscallSession open (uint pid, Cancellable? cancellable) throws Error, IOError {
			var session = new PausedSyscallSession (pid);

			try {
				yield session.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return session;
		}

		public async void wait_for_syscall (LinuxSyscall mask, Cancellable? cancellable) throws Error, IOError {
			bool on_syscall_entry = true;
			int pending_signal = 0;
			do {
				ptrace (SYSCALL, tid, null, (void *) pending_signal);
				pending_signal = 0;

				Posix.Signal sig = yield wait_for_next_signal (cancellable);
				if (sig != (TRAP | 0x80)) {
					on_syscall_entry = !on_syscall_entry;
					pending_signal = sig;
					continue;
				}

				if (on_syscall_entry) {
					get_regs (&saved_regs);
					if (_syscall_satisfies (get_syscall_id (saved_regs), mask))
						state = SATISFIED;
				}

				on_syscall_entry = !on_syscall_entry;
			} while (state != SATISFIED);
		}

		public async void interrupt (Cancellable? cancellable) throws Error, IOError {
			ptrace (CONT, tid, null, (void *) Posix.Signal.STOP);
			yield wait_for_signal (STOP, cancellable);
			var regs = GPRegs ();
			get_regs (&regs);

			saved_regs.orig_syscall = -1;
			saved_regs.program_counter = regs.program_counter;
			set_regs (saved_regs);
		}

		private static int get_syscall_id (GPRegs regs) {
#if X86
			return regs.orig_eax;
#elif X86_64
			return (int) regs.orig_rax;
#elif ARM
			return (int) regs.r[7];
#elif ARM64
			return (int) regs.x[8];
#elif MIPS
			return (int) regs.v[0];
#endif
		}
	}

	private const size_t DUMMY_RETURN_ADDRESS = 0x320;

	public enum ProcessStatus {
		NORMAL,
		EXEC_PENDING
	}

	private const size_t MAP_FAILED = ~0;

	private const uint64 SOCK_CLOEXEC = 0x80000;

	private class InjectSession : SeizeSession {
		private static ProcMapsEntry local_libc;
		private static uint64 mmap_offset;
		private static uint64 munmap_offset;

		private static string fallback_ld;
		private static string fallback_libc;

		private static ProcMapsEntry? local_android_ld;

		static construct {
			string libc_name = Gum.Process.query_libc_name ();
			uint local_pid = Posix.getpid ();
			local_libc = ProcMapsEntry.find_by_path (local_pid, libc_name);
			assert (local_libc != null);
			mmap_offset = (uint64) (uintptr) Gum.Module.find_export_by_name (libc_name, "mmap") - local_libc.base_address;
			munmap_offset = (uint64) (uintptr) Gum.Module.find_export_by_name (libc_name, "munmap") - local_libc.base_address;

			try {
				var program = new Gum.ElfModule.from_file ("/proc/self/exe");
				fallback_ld = program.interpreter;
				fallback_libc = Path.get_basename (local_libc.path);
			} catch (Gum.Error e) {
				assert_not_reached ();
			}

			try {
				string target = FileUtils.read_link (fallback_ld);
				string parent_dir = Path.get_dirname (fallback_ld);
				fallback_ld = Filename.canonicalize (target, parent_dir);
			} catch (FileError e) {
			}

#if ANDROID
			local_android_ld = ProcMapsEntry.find_by_path (local_pid, fallback_ld);
#endif
		}

		private InjectSession (uint pid) {
			Object (pid: pid);
		}

		public static async InjectSession open (uint pid, Cancellable? cancellable) throws Error, IOError {
			var session = new InjectSession (pid);

			try {
				yield session.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return session;
		}

		public async RemoteAgent inject (InjectSpec spec, Cancellable? cancellable) throws Error, IOError {
			string fallback_address = make_fallback_address ();
			LoaderLayout loader_layout = compute_loader_layout (spec, fallback_address);

			BootstrapResult bootstrap_result = yield bootstrap (loader_layout.size, cancellable);
			uint64 loader_base = (uintptr) bootstrap_result.context.allocation_base;

			try {
				unowned uint8[] loader_code = Frida.Data.HelperBackend.get_loader_bin_blob ().data;
				write_memory (loader_base, loader_code);
				maybe_fixup_helper_code (loader_base, loader_code);

				var loader_ctx = HelperLoaderContext ();
				loader_ctx.ctrlfds = bootstrap_result.context.ctrlfds;
				loader_ctx.agent_entrypoint = (string *) (loader_base + loader_layout.agent_entrypoint_offset);
				loader_ctx.agent_data = (string *) (loader_base + loader_layout.agent_data_offset);
				loader_ctx.fallback_address = (string *) (loader_base + loader_layout.fallback_address_offset);
				loader_ctx.libc = (HelperLibcApi *) (loader_base + loader_layout.libc_api_offset);
				write_memory (loader_base + loader_layout.ctx_offset, (uint8[]) &loader_ctx);
				write_memory (loader_base + loader_layout.libc_api_offset, (uint8[]) &bootstrap_result.libc);
				write_memory_string (loader_base + loader_layout.agent_entrypoint_offset, spec.entrypoint);
				write_memory_string (loader_base + loader_layout.agent_data_offset, spec.data);
				write_memory_string (loader_base + loader_layout.fallback_address_offset, fallback_address);

				return yield launch_loader (FROM_SCRATCH, spec, bootstrap_result, null, fallback_address, loader_layout,
					cancellable);
			} catch (GLib.Error error) {
				try {
					yield deallocate_memory ((uintptr) bootstrap_result.libc.munmap, loader_base, loader_layout.size,
						null);
				} catch (GLib.Error e) {
				}

				if (error is IOError)
					throw (IOError) error;
				throw (Error) error;
			}
		}

		public async RemoteAgent rejuvenate (RemoteAgent old_agent, Cancellable? cancellable) throws Error, IOError {
			InjectSpec spec = old_agent.inject_spec;
			BootstrapResult bootstrap_result = old_agent.bootstrap_result;

			string fallback_address = make_fallback_address ();
			LoaderLayout loader_layout = compute_loader_layout (spec, fallback_address);
			uint64 loader_base = (uintptr) bootstrap_result.context.allocation_base;
			uint64 loader_ctrlfds_location = loader_base + loader_layout.ctx_offset;

			if (bootstrap_result.context.enable_ctrlfds) {
				var builder = new RemoteCallBuilder ((uintptr) bootstrap_result.libc.socketpair, saved_regs);
				builder
					.add_argument (Posix.AF_UNIX)
					.add_argument (Posix.SOCK_STREAM | SOCK_CLOEXEC)
					.add_argument (0)
					.add_argument (loader_ctrlfds_location);
				RemoteCall call = builder.build (this);
				RemoteCallResult res = yield call.execute (cancellable);
				if (res.status != COMPLETED)
					throw new Error.NOT_SUPPORTED ("Unexpected crash while trying to re-create ctrlfds");
				if (res.return_value == 0) {
					uint8[] raw_fds = read_memory (loader_ctrlfds_location, 2 * sizeof (int));
					Memory.copy (&bootstrap_result.context.ctrlfds, raw_fds, raw_fds.length);
				} else {
					bootstrap_result.context.ctrlfds[0] = -1;
					bootstrap_result.context.ctrlfds[1] = -1;
				}
			}

			write_memory (loader_base + loader_layout.fallback_address_offset, fallback_address.data);

			return yield launch_loader (RELAUNCH, spec, bootstrap_result, old_agent.agent_ctrl, fallback_address, loader_layout,
				cancellable);
		}

		private struct LoaderLayout {
			public size_t size;

			public size_t ctx_offset;
			public size_t libc_api_offset;
			public size_t agent_entrypoint_offset;
			public size_t agent_data_offset;
			public size_t fallback_address_offset;
		}

		private LoaderLayout compute_loader_layout (InjectSpec spec, string fallback_address) {
			var layout = LoaderLayout ();

			unowned uint8[] code = Frida.Data.HelperBackend.get_loader_bin_blob ().data;

			size_t code_size = round_size_to_page_size (code.length);

			size_t agent_entrypoint_size = spec.entrypoint.data.length + 1;
			size_t agent_data_size = spec.data.data.length + 1;

			size_t data_size = 0;
			data_size += sizeof (HelperLoaderContext);
			data_size += sizeof (HelperLibcApi);
			data_size += agent_entrypoint_size;
			data_size += agent_data_size;
			data_size += fallback_address.data.length + 1;
			data_size = round_size_to_page_size (data_size);

			layout.size = code_size + data_size;

			layout.ctx_offset = code_size;
			layout.libc_api_offset = layout.ctx_offset + sizeof (HelperLoaderContext);
			layout.agent_entrypoint_offset = layout.libc_api_offset + sizeof (HelperLibcApi);
			layout.agent_data_offset = layout.agent_entrypoint_offset + agent_entrypoint_size;
			layout.fallback_address_offset = layout.agent_data_offset + agent_data_size;

			return layout;
		}

		private async RemoteAgent launch_loader (LoaderLaunch launch, InjectSpec spec, BootstrapResult bres,
				UnixConnection? agent_ctrl, string fallback_address, LoaderLayout loader_layout, Cancellable? cancellable)
				throws Error, IOError {
			Future<RemoteAgent> future_agent =
				establish_connection (launch, spec, bres, agent_ctrl, fallback_address, cancellable);

			uint64 loader_base = (uintptr) bres.context.allocation_base;
			GPRegs regs = saved_regs;
			regs.stack_pointer = bres.allocated_stack.stack_root;
			var call_builder = new RemoteCallBuilder (loader_base, regs);
			call_builder.add_argument (loader_base + loader_layout.ctx_offset);
			RemoteCall loader_call = call_builder.build (this);
			RemoteCallResult loader_result = yield loader_call.execute (cancellable);
			if (loader_result.status != COMPLETED) {
				uint64 pc = loader_result.regs.program_counter;
				if (pc >= loader_base && pc < loader_base + Frida.Data.HelperBackend.get_loader_bin_blob ().data.length) {
					throw new Error.NOT_SUPPORTED (
						"Loader crashed with signal %d at offset 0x%x; please file a bug\n%s",
						loader_result.stop_signal,
						(uint) (pc - loader_base),
						loader_result.regs.to_string ());
				} else {
					throw new Error.NOT_SUPPORTED ("Loader crashed with signal %d; please file a bug\n%s",
						loader_result.stop_signal,
						loader_result.regs.to_string ());
				}
			}

			var establish_cancellable = new Cancellable ();
			var main_context = MainContext.get_thread_default ();

			var timeout_source = new TimeoutSource.seconds (5);
			timeout_source.set_callback (() => {
				establish_cancellable.cancel ();
				return Source.REMOVE;
			});
			timeout_source.attach (main_context);

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (() => {
				establish_cancellable.cancel ();
				return Source.REMOVE;
			});
			cancel_source.attach (main_context);

			RemoteAgent agent = null;
			try {
				agent = yield future_agent.wait_async (establish_cancellable);
			} catch (IOError e) {
				cancellable.set_error_if_cancelled ();
				throw new Error.PROCESS_NOT_RESPONDING ("Unexpectedly timed out trying to sync u
"""


```