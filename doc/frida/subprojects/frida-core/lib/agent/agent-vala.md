Response:
### 功能归纳

`agent.vala` 是 Frida 工具的核心部分，负责管理动态插桩（Dynamic Instrumentation）的代理（Agent）生命周期、会话管理、进程间通信、以及与其他组件的交互。以下是该文件的主要功能归纳：

1. **代理生命周期管理**：
   - 代理的启动、暂停、恢复和卸载。
   - 处理进程的 `fork`、`exec` 等系统调用时的状态恢复。
   - 支持“永恒化”（Eternalization），即代理在目标进程中的持久化运行。

2. **会话管理**：
   - 创建和管理与目标进程的会话（`AgentSession`）。
   - 支持多种会话类型，包括实时会话（`LiveAgentSession`）和模拟会话（`EmulatedAgentSession`）。
   - 处理会话的打开、关闭、迁移等操作。

3. **进程间通信**：
   - 通过 D-Bus 与 Frida 核心进行通信。
   - 处理 D-Bus 连接的生命周期，包括连接的建立、关闭和消息过滤。

4. **子进程管理**：
   - 支持子进程的监控和管理（`Child Gating`），确保在 `fork` 或 `exec` 时能够正确处理子进程的状态。
   - 提供子进程的挂起、恢复和状态同步功能。

5. **脚本引擎管理**：
   - 支持多种脚本引擎（如 QuickJS 和 V8），允许用户选择不同的运行时环境。
   - 管理脚本的加载、执行和卸载。

6. **调试功能**：
   - 提供调试相关的功能，如线程挂起监控（`ThreadSuspendMonitor`）、异常处理（`Exceptor`）等。
   - 支持调试会话的创建和管理，允许用户通过 D-Bus 接口与目标进程进行交互。

7. **错误处理和恢复**：
   - 处理各种错误情况，如连接中断、会话关闭、进程崩溃等。
   - 提供错误恢复机制，确保代理在异常情况下能够继续运行或优雅退出。

8. **多平台支持**：
   - 支持 Linux、macOS、FreeBSD 等多个操作系统平台。
   - 处理不同平台下的系统调用和进程管理差异。

### 二进制底层与 Linux 内核相关功能

1. **进程管理**：
   - 通过 `fork`、`exec` 等系统调用管理进程的生命周期。
   - 使用 `Gum` 库（Frida 的底层库）进行进程和线程的监控。

2. **内存管理**：
   - 使用 `Gum.MemoryRange` 管理代理的内存范围，确保代理代码在目标进程中的正确加载和执行。
   - 通过 `Gum.Cloak` 隐藏代理的内存区域，防止被目标进程检测到。

3. **文件描述符管理**：
   - 在 Linux 和 FreeBSD 上，使用 `FileDescriptorTablePadder` 管理文件描述符，确保在 `fork` 时文件描述符的正确传递。

4. **线程管理**：
   - 使用 `Gum.ThreadId` 和 `pthread` 管理线程的创建、挂起和恢复。
   - 通过 `ThreadSuspendMonitor` 监控线程的挂起状态，确保调试会话的稳定性。

### 调试功能示例

假设你想使用 LLDB 调试 Frida 代理的某个功能，比如 `fork` 后的状态恢复。你可以使用以下 LLDB 命令或 Python 脚本来复现调试功能：

#### LLDB 命令示例

```bash
# 启动 LLDB 并附加到目标进程
lldb -p <target_pid>

# 设置断点在 `recover_from_fork_in_child` 函数
b recover_from_fork_in_child

# 继续执行
c

# 当断点触发时，查看当前线程状态
thread list

# 查看变量值
p fork_child_pid
p fork_parent_pid

# 单步执行
n

# 继续执行
c
```

#### LLDB Python 脚本示例

```python
import lldb

def recover_from_fork_in_child(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()

    # 设置断点在 `recover_from_fork_in_child` 函数
    breakpoint = target.BreakpointCreateByName("recover_from_fork_in_child")
    process.Continue()

    # 当断点触发时，打印相关信息
    if thread.GetStopReason() == lldb.eStopReasonBreakpoint:
        frame = thread.GetSelectedFrame()
        fork_child_pid = frame.FindVariable("fork_child_pid")
        fork_parent_pid = frame.FindVariable("fork_parent_pid")
        print(f"fork_child_pid: {fork_child_pid.GetValue()}")
        print(f"fork_parent_pid: {fork_parent_pid.GetValue()}")

    # 继续执行
    process.Continue()

# 注册 LLDB 命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f recover_from_fork_in_child recover_from_fork_in_child')
```

### 假设输入与输出

假设输入是一个 `fork` 操作，目标进程会创建一个子进程。Frida 代理会捕获这个 `fork` 操作，并在子进程中恢复代理的状态。

- **输入**：目标进程执行 `fork` 系统调用。
- **输出**：Frida 代理在子进程中恢复运行，继续监控目标进程。

### 用户常见错误

1. **未正确设置子进程监控**：
   - 用户可能忘记启用 `Child Gating`，导致在 `fork` 或 `exec` 时代理无法正确处理子进程。
   - **解决方法**：确保在代理启动时启用 `Child Gating`。

2. **D-Bus 连接中断**：
   - 由于网络问题或目标进程崩溃，D-Bus 连接可能会中断，导致代理无法与 Frida 核心通信。
   - **解决方法**：检查网络连接，确保目标进程稳定运行。

3. **脚本引擎加载失败**：
   - 用户可能尝试加载不支持的脚本引擎（如在不支持 V8 的环境中加载 V8 引擎）。
   - **解决方法**：检查目标平台支持的脚本引擎，并选择合适的引擎。

### 用户操作路径

1. **启动 Frida 代理**：
   - 用户通过 Frida 命令行工具或 API 启动代理，注入到目标进程中。

2. **创建会话**：
   - 用户通过 D-Bus 接口创建与目标进程的会话，开始监控和调试。

3. **执行动态插桩**：
   - 用户通过会话加载脚本，对目标进程进行动态插桩。

4. **处理进程状态变化**：
   - 当目标进程执行 `fork` 或 `exec` 时，Frida 代理会自动处理状态恢复，确保插桩继续生效。

5. **结束会话**：
   - 用户关闭会话，代理卸载并退出目标进程。

### 总结

`agent.vala` 是 Frida 工具的核心组件，负责管理代理的生命周期、会话、进程间通信和调试功能。它通过底层系统调用和内存管理，确保代理在目标进程中的稳定运行。用户可以通过 D-Bus 接口与代理进行交互，执行动态插桩和调试操作。
### 提示词
```
这是目录为frida/subprojects/frida-core/lib/agent/agent.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
namespace Frida.Agent {
	public void main (string agent_parameters, ref Frida.UnloadPolicy unload_policy, void * injector_state) {
		if (Runner.shared_instance == null)
			Runner.create_and_run (agent_parameters, ref unload_policy, injector_state);
		else
			Runner.resume_after_transition (ref unload_policy, injector_state);
	}

	private enum StopReason {
		UNLOAD,
		PROCESS_TRANSITION
	}

	private class Runner : Object, ProcessInvader, AgentSessionProvider, ExitHandler, ForkHandler, SpawnHandler {
		public static Runner shared_instance = null;
		public static Mutex shared_mutex;
		private static string? cached_agent_path = null;
		private static Gum.MemoryRange cached_agent_range;

		public string agent_parameters {
			get;
			construct;
		}

		public string? agent_path {
			get;
			construct;
		}

		public string? emulated_agent_path {
			get;
			set;
		}

		public StopReason stop_reason {
			get;
			set;
			default = UNLOAD;
		}

		public bool is_eternal {
			get {
				return _is_eternal;
			}
		}
		private bool _is_eternal = false;

		private bool stop_thread_on_unload = true;

		private Gum.ThreadId agent_tid;
		private void * agent_pthread;
		private Thread<bool>? agent_gthread;

		private MainContext main_context;
		private MainLoop main_loop;
		private DBusConnection connection;
		private AgentController? controller;
		private Error? start_error = null;
		private bool unloading = false;
		private uint filter_id = 0;
		private uint registration_id = 0;
		private uint pending_calls = 0;
		private Promise<bool> pending_close;
		private Gee.Map<AgentSessionId?, LiveAgentSession> sessions =
			new Gee.HashMap<AgentSessionId?, LiveAgentSession> (AgentSessionId.hash, AgentSessionId.equal);
		private Gee.Map<AgentSessionId?, EmulatedAgentSession> emulated_sessions =
			new Gee.HashMap<AgentSessionId?, EmulatedAgentSession> (AgentSessionId.hash, AgentSessionId.equal);
		private Gee.Map<DBusConnection, DirectConnection> direct_connections =
			new Gee.HashMap<DBusConnection, DirectConnection> ();
		private Gee.Map<PortalMembershipId?, PortalClient> portal_clients =
			new Gee.HashMap<PortalMembershipId?, PortalClient> (PortalMembershipId.hash, PortalMembershipId.equal);
		private uint next_portal_membership_id = 1;
		private Gee.ArrayList<Gum.Script> eternalized_scripts = new Gee.ArrayList<Gum.Script> ();

		private Gum.MemoryRange agent_range;
		private Gum.ScriptBackend? qjs_backend;
		private Gum.ScriptBackend? v8_backend;
		private ExitMonitor? exit_monitor;
		private Gum.Interceptor interceptor;
		private Gum.Exceptor? exceptor;

		private uint child_gating_subscriber_count = 0;
		private ForkMonitor? fork_monitor;
		private FileDescriptorGuard? fd_guard;
		private ThreadCountCloaker? thread_count_cloaker;
		private ThreadListCloaker? thread_list_cloaker;
		private FDListCloaker? fd_list_cloaker;
		private uint fork_parent_pid;
		private uint fork_child_pid;
		private HostChildId fork_child_id;
		private uint fork_parent_injectee_id;
		private uint fork_child_injectee_id;
		private Socket fork_child_socket;
		private HostChildId specialized_child_id;
		private uint specialized_injectee_id;
		private string? specialized_pipe_address;
		private TransitionRecoveryState transition_recovery_state;
		private Mutex transition_mutex;
		private Cond transition_cond;
		private SpawnMonitor? spawn_monitor;
		private ThreadSuspendMonitor? thread_suspend_monitor;
		private UnwindSitter? unwind_sitter;

		private delegate void CompletionNotify ();

		private enum TransitionRecoveryState {
			RECOVERING,
			RECOVERED
		}

		private enum ForkActor {
			PARENT,
			CHILD
		}

		public static void create_and_run (string agent_parameters, ref Frida.UnloadPolicy unload_policy,
				void * opaque_injector_state) {
			Environment._init ();

			{
				Gum.MemoryRange? mapped_range = null;

#if DARWIN
				var injector_state = (DarwinInjectorState *) opaque_injector_state;
				if (injector_state != null)
					mapped_range = injector_state.mapped_range;
#endif

				if (cached_agent_path == null) {
					cached_agent_range = detect_own_range_and_path (mapped_range, out cached_agent_path);
					Gum.Cloak.add_range (cached_agent_range);
				}

				var fdt_padder = FileDescriptorTablePadder.obtain ();

#if LINUX || FREEBSD
				var injector_state = (PosixInjectorState *) opaque_injector_state;
				if (injector_state != null) {
					fdt_padder.move_descriptor_if_needed (ref injector_state.fifo_fd);
					Gum.Cloak.add_file_descriptor (injector_state.fifo_fd);
				}
#endif

#if LINUX
				var linjector_state = (LinuxInjectorState *) opaque_injector_state;
				string? agent_parameters_with_transport_uri = null;
				if (linjector_state != null) {
					int agent_ctrlfd = linjector_state->agent_ctrlfd;
					linjector_state->agent_ctrlfd = -1;

					fdt_padder.move_descriptor_if_needed (ref agent_ctrlfd);

					agent_parameters_with_transport_uri = "socket:%d%s".printf (agent_ctrlfd, agent_parameters);
					agent_parameters = agent_parameters_with_transport_uri;
				}
#endif

				var ignore_scope = new ThreadIgnoreScope (FRIDA_THREAD);

				shared_instance = new Runner (agent_parameters, cached_agent_path, cached_agent_range);

				try {
					shared_instance.run ((owned) fdt_padder);
				} catch (Error e) {
					GLib.info ("Unable to start agent: %s", e.message);
				}

				if (shared_instance.stop_reason == PROCESS_TRANSITION) {
#if LINUX || FREEBSD
					if (injector_state != null)
						Gum.Cloak.remove_file_descriptor (injector_state.fifo_fd);
#endif
					unload_policy = DEFERRED;
					return;
				} else if (shared_instance.is_eternal) {
					unload_policy = RESIDENT;
					shared_instance.keep_running_eternalized ();
					return;
				} else {
					release_shared_instance ();
				}

				ignore_scope = null;
			}

			Environment._deinit ();
		}

		public static void resume_after_transition (ref Frida.UnloadPolicy unload_policy, void * opaque_injector_state) {
			{
#if LINUX || FREEBSD
				var injector_state = (PosixInjectorState *) opaque_injector_state;
				if (injector_state != null) {
					FileDescriptorTablePadder.obtain ().move_descriptor_if_needed (ref injector_state.fifo_fd);
					Gum.Cloak.add_file_descriptor (injector_state.fifo_fd);
				}
#endif

				var ignore_scope = new ThreadIgnoreScope (FRIDA_THREAD);

				shared_instance.run_after_transition ();

				if (shared_instance.stop_reason == PROCESS_TRANSITION) {
#if LINUX || FREEBSD
					if (injector_state != null)
						Gum.Cloak.remove_file_descriptor (injector_state.fifo_fd);
#endif
					unload_policy = DEFERRED;
					return;
				} else if (shared_instance.is_eternal) {
					unload_policy = RESIDENT;
					shared_instance.keep_running_eternalized ();
					return;
				} else {
					release_shared_instance ();
				}

				ignore_scope = null;
			}

			Environment._deinit ();
		}

		private static void release_shared_instance () {
			shared_mutex.lock ();
			var instance = shared_instance;
			shared_instance = null;
			shared_mutex.unlock ();

			instance = null;
		}

		private Runner (string agent_parameters, string? agent_path, Gum.MemoryRange agent_range) {
			Object (agent_parameters: agent_parameters, agent_path: agent_path);

			this.agent_range = agent_range;
		}

		construct {
			agent_tid = Gum.Process.get_current_thread_id ();
			agent_pthread = get_current_pthread ();

			main_context = MainContext.default ();
			main_loop = new MainLoop (main_context);
		}

		~Runner () {
			var interceptor = this.interceptor;
			interceptor.begin_transaction ();

			disable_child_gating ();

			exceptor = null;

			exit_monitor = null;

			interceptor.end_transaction ();

			interceptor.begin_transaction ();

			thread_suspend_monitor = null;
			unwind_sitter = null;

			invalidate_dbus_context ();

			interceptor.end_transaction ();
		}

		private void run (owned FileDescriptorTablePadder padder) throws Error {
			main_context.push_thread_default ();

			start.begin ((owned) padder);

			main_loop.run ();

			main_context.pop_thread_default ();

			if (start_error != null)
				throw start_error;
		}

		private async void start (owned FileDescriptorTablePadder padder) {
			string[] tokens = agent_parameters.split ("|");
			unowned string transport_uri = tokens[0];
			bool enable_exceptor = true;
#if DARWIN
			enable_exceptor = !Gum.Darwin.query_hardened ();
#endif
			bool enable_exit_monitor = true;
			bool enable_thread_suspend_monitor = true;
			bool enable_unwind_sitter = true;
			foreach (unowned string option in tokens[1:]) {
				if (option == "eternal")
					ensure_eternalized ();
				else if (option == "sticky")
					stop_thread_on_unload = false;
				else if (option == "exceptor:off")
					enable_exceptor = false;
				else if (option == "exit-monitor:off")
					enable_exit_monitor = false;
				else if (option == "thread-suspend-monitor:off")
					enable_thread_suspend_monitor = false;
				else if (option == "unwind-sitter:off")
					enable_unwind_sitter = false;
			}

			if (!enable_exceptor)
				Gum.Exceptor.disable ();

			{
				var interceptor = Gum.Interceptor.obtain ();
				interceptor.begin_transaction ();

				if (enable_exit_monitor)
					exit_monitor = new ExitMonitor (this, main_context);

				if (enable_thread_suspend_monitor)
					thread_suspend_monitor = new ThreadSuspendMonitor (this);

				if (enable_unwind_sitter)
					unwind_sitter = new UnwindSitter (this);

				this.interceptor = interceptor;
				this.exceptor = Gum.Exceptor.obtain ();

				interceptor.end_transaction ();
			}

			try {
				yield setup_connection_with_transport_uri (transport_uri);
			} catch (Error e) {
				start_error = e;
				main_loop.quit ();
				return;
			}

			Gum.ScriptBackend.get_scheduler ().push_job_on_js_thread (Priority.DEFAULT, () => {
				schedule_idle (start.callback);
			});
			yield;

			padder = null;
		}

		private void keep_running_eternalized () {
			agent_gthread = new Thread<bool> ("frida-eternal-agent", () => {
				var ignore_scope = new ThreadIgnoreScope (FRIDA_THREAD);

				agent_tid = Gum.Process.get_current_thread_id ();

				main_context.push_thread_default ();
				main_loop.run ();
				main_context.pop_thread_default ();

				ignore_scope = null;

				return true;
			});
		}

		private bool supports_async_exit () {
			// Avoid deadlocking in case a fork() happened that we weren't made aware of.
			return Gum.Process.has_thread (agent_tid);
		}

		private async void prepare_to_exit () {
			yield prepare_for_termination (TerminationReason.EXIT);
		}

		public void prepare_to_exit_sync () {
		}

		private void run_after_transition () {
			agent_tid = Gum.Process.get_current_thread_id ();
			agent_pthread = get_current_pthread ();
			stop_reason = UNLOAD;

			transition_mutex.lock ();
			transition_mutex.unlock ();

			main_context.push_thread_default ();
			main_loop.run ();
			main_context.pop_thread_default ();
		}

		private void prepare_to_fork () {
			var fdt_padder = FileDescriptorTablePadder.obtain ();

			schedule_idle (() => {
				do_prepare_to_fork.begin ();
				return false;
			});
			stop_agent_thread ();

			suspend_subsystems ();

			fdt_padder = null;
		}

		private async void do_prepare_to_fork () {
			stop_reason = PROCESS_TRANSITION;

#if !WINDOWS
			if (controller != null) {
				try {
					fork_parent_pid = get_process_id ();
					fork_child_id = yield controller.prepare_to_fork (fork_parent_pid, null,
						out fork_parent_injectee_id, out fork_child_injectee_id, out fork_child_socket);
				} catch (GLib.Error e) {
#if ANDROID
					error ("Oops, SELinux rule probably missing for your system. Symptom: %s", e.message);
#else
					error ("%s", e.message);
#endif
				}
			}
#endif

			main_loop.quit ();
		}

		private void recover_from_fork_in_parent () {
			recover_from_fork (ForkActor.PARENT, null);
		}

		private void recover_from_fork_in_child (string? identifier) {
			recover_from_fork (ForkActor.CHILD, identifier);
		}

		private void recover_from_fork (ForkActor actor, string? identifier) {
			var fdt_padder = FileDescriptorTablePadder.obtain ();

			if (actor == PARENT) {
				resume_subsystems ();
			} else if (actor == CHILD) {
				resume_subsystems_in_child ();

				fork_child_pid = get_process_id ();

				try {
					acquire_child_gating ();
				} catch (Error e) {
					assert_not_reached ();
				}

				discard_connections ();
			}

			transition_mutex.lock ();

			transition_recovery_state = RECOVERING;

			schedule_idle (() => {
				recreate_agent_thread_after_fork.begin (actor);
				return false;
			});

			main_context.push_thread_default ();
			main_loop.run ();
			main_context.pop_thread_default ();

			schedule_idle (() => {
				finish_recovery_from_fork.begin (actor, identifier);
				return false;
			});

			while (transition_recovery_state != RECOVERED)
				transition_cond.wait (transition_mutex);

			transition_mutex.unlock ();

			fdt_padder = null;
		}

		private static void suspend_subsystems () {
#if !WINDOWS
			GumJS.prepare_to_fork ();
			Gum.prepare_to_fork ();
			GIOFork.prepare_to_fork ();
			GLibFork.prepare_to_fork ();
#endif
		}

		private static void resume_subsystems () {
#if !WINDOWS
			GLibFork.recover_from_fork_in_parent ();
			GIOFork.recover_from_fork_in_parent ();
			Gum.recover_from_fork_in_parent ();
			GumJS.recover_from_fork_in_parent ();
#endif
		}

		private static void resume_subsystems_in_child () {
#if !WINDOWS
			GLibFork.recover_from_fork_in_child ();
			GIOFork.recover_from_fork_in_child ();
			Gum.recover_from_fork_in_child ();
			GumJS.recover_from_fork_in_child ();
#endif
		}

		private void stop_agent_thread () {
			if (agent_gthread != null) {
				agent_gthread.join ();
				agent_gthread = null;
			} else if (agent_pthread != null) {
				join_pthread (agent_pthread);
			}
			agent_pthread = null;
		}

		private async void recreate_agent_thread_after_fork (ForkActor actor) {
			uint pid, injectee_id;
			if (actor == PARENT) {
				pid = fork_parent_pid;
				injectee_id = fork_parent_injectee_id;
			} else if (actor == CHILD) {
				yield flush_all_sessions ();

				if (fork_child_socket != null) {
					var stream = SocketConnection.factory_create_connection (fork_child_socket);
					try {
						yield setup_connection_with_stream (stream);
					} catch (Error e) {
						assert_not_reached ();
					}
				}

				pid = fork_child_pid;
				injectee_id = fork_child_injectee_id;
			} else {
				assert_not_reached ();
			}

			if (controller != null) {
				try {
					yield controller.recreate_agent_thread (pid, injectee_id, null);
				} catch (GLib.Error e) {
					assert_not_reached ();
				}
			} else {
				agent_gthread = new Thread<bool> ("frida-eternal-agent", () => {
					var ignore_scope = new ThreadIgnoreScope (FRIDA_THREAD);
					run_after_transition ();
					ignore_scope = null;

					return true;
				});
			}

			main_loop.quit ();
		}

		private async void finish_recovery_from_fork (ForkActor actor, string? identifier) {
			if (actor == CHILD && controller != null) {
				var info = HostChildInfo (fork_child_pid, fork_parent_pid, ChildOrigin.FORK);
				if (identifier != null)
					info.identifier = identifier;

				var controller_proxy = controller as DBusProxy;
				var previous_timeout = controller_proxy.get_default_timeout ();
				controller_proxy.set_default_timeout (int.MAX);
				try {
					yield controller.wait_for_permission_to_resume (fork_child_id, info, null);
				} catch (GLib.Error e) {
					// The connection will/did get closed and we will unload...
				}
				controller_proxy.set_default_timeout (previous_timeout);
			}

			if (actor == CHILD)
				release_child_gating ();

			fork_parent_pid = 0;
			fork_child_pid = 0;
			fork_child_id = HostChildId (0);
			fork_parent_injectee_id = 0;
			fork_child_injectee_id = 0;
			fork_child_socket = null;

			transition_mutex.lock ();
			transition_recovery_state = RECOVERED;
			transition_cond.signal ();
			transition_mutex.unlock ();
		}

		private void prepare_to_specialize (string identifier) {
			schedule_idle (() => {
				do_prepare_to_specialize.begin (identifier);
				return false;
			});
			stop_agent_thread ();

			discard_connections ();

			suspend_subsystems ();
		}

		private async void do_prepare_to_specialize (string identifier) {
			stop_reason = PROCESS_TRANSITION;

			if (controller != null) {
				try {
					specialized_child_id = yield controller.prepare_to_specialize (get_process_id (), identifier, null,
						out specialized_injectee_id, out specialized_pipe_address);
				} catch (GLib.Error e) {
					error ("%s", e.message);
				}
			}

			main_loop.quit ();
		}

		private void recover_from_specialization (string identifier) {
			resume_subsystems ();

			transition_mutex.lock ();

			transition_recovery_state = RECOVERING;

			schedule_idle (() => {
				recreate_agent_thread_after_specialization.begin ();
				return false;
			});

			main_context.push_thread_default ();
			main_loop.run ();
			main_context.pop_thread_default ();

			schedule_idle (() => {
				finish_recovery_from_specialization.begin (identifier);
				return false;
			});

			while (transition_recovery_state != RECOVERED)
				transition_cond.wait (transition_mutex);

			transition_mutex.unlock ();
		}

		private async void recreate_agent_thread_after_specialization () {
			if (specialized_pipe_address != null) {
				try {
					yield setup_connection_with_transport_uri (specialized_pipe_address);
					yield controller.recreate_agent_thread (get_process_id (), specialized_injectee_id, null);
				} catch (GLib.Error e) {
					assert_not_reached ();
				}
			} else {
				agent_gthread = new Thread<bool> ("frida-eternal-agent", () => {
					var ignore_scope = new ThreadIgnoreScope (FRIDA_THREAD);
					run_after_transition ();
					ignore_scope = null;

					return true;
				});
			}

			main_loop.quit ();
		}

		private async void finish_recovery_from_specialization (string identifier) {
			if (controller != null) {
				uint pid = get_process_id ();
				uint parent_pid = pid;
				var info = HostChildInfo (pid, parent_pid, ChildOrigin.EXEC);
				info.identifier = identifier;

				var controller_proxy = controller as DBusProxy;
				var previous_timeout = controller_proxy.get_default_timeout ();
				controller_proxy.set_default_timeout (int.MAX);
				try {
					yield controller.wait_for_permission_to_resume (specialized_child_id, info, null);
				} catch (GLib.Error e) {
					// The connection will/did get closed and we will unload...
				}
				controller_proxy.set_default_timeout (previous_timeout);
			}

			specialized_child_id = HostChildId (0);
			specialized_injectee_id = 0;
			specialized_pipe_address = null;

			transition_mutex.lock ();
			transition_recovery_state = RECOVERED;
			transition_cond.signal ();
			transition_mutex.unlock ();
		}

		private async void prepare_to_exec (HostChildInfo * info) {
			yield prepare_for_termination (TerminationReason.EXEC);

			if (controller == null)
				return;

			try {
				yield controller.prepare_to_exec (*info, null);
			} catch (GLib.Error e) {
			}
		}

		private async void cancel_exec (uint pid) {
			unprepare_for_termination ();

			if (controller == null)
				return;

			try {
				yield controller.cancel_exec (pid, null);
			} catch (GLib.Error e) {
			}
		}

		private async void acknowledge_spawn (HostChildInfo * info, SpawnStartState start_state) {
			if (controller == null)
				return;

			try {
				yield controller.acknowledge_spawn (*info, start_state, null);
			} catch (GLib.Error e) {
			}
		}

		public SpawnStartState query_current_spawn_state () {
			return RUNNING;
		}

		public Gum.MemoryRange get_memory_range () {
			return agent_range;
		}

		public Gum.ScriptBackend get_script_backend (ScriptRuntime runtime) throws Error {
			switch (runtime) {
				case DEFAULT:
					break;
				case QJS:
					if (qjs_backend == null) {
						qjs_backend = Gum.ScriptBackend.obtain_qjs ();
						if (qjs_backend == null) {
							throw new Error.NOT_SUPPORTED (
								"QuickJS runtime not available due to build configuration");
						}
					}
					return qjs_backend;
				case V8:
					if (v8_backend == null) {
						v8_backend = Gum.ScriptBackend.obtain_v8 ();
						if (v8_backend == null) {
							throw new Error.NOT_SUPPORTED (
								"V8 runtime not available due to build configuration");
						}
					}
					return v8_backend;
			}

			try {
				return get_script_backend (QJS);
			} catch (Error e) {
			}
			return get_script_backend (V8);
		}

		public Gum.ScriptBackend? get_active_script_backend () {
			return (v8_backend != null) ? v8_backend : qjs_backend;
		}

		private async void open (AgentSessionId id, HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			if (unloading)
				throw new Error.INVALID_OPERATION ("Agent is unloading");

			var opts = SessionOptions._deserialize (options);

			AgentMessageSink sink;
			try {
				sink = yield connection.get_proxy (null, ObjectPath.for_agent_message_sink (id), DO_NOT_LOAD_PROPERTIES,
					cancellable);
			} catch (IOError e) {
				throw_dbus_error (e);
			}

			if (opts.realm == EMULATED) {
				string? path = opts.emulated_agent_path;
				if (path == null)
					throw new Error.NOT_SUPPORTED ("Emulated realm is not supported on this OS");
				if (emulated_agent_path == null)
					emulated_agent_path = path;

				AgentSessionProvider emulated_provider = yield get_emulated_provider (cancellable);

				var emulated_opts = new SessionOptions ();
				emulated_opts.persist_timeout = opts.persist_timeout;

				try {
					yield emulated_provider.open (id, emulated_opts._serialize (), cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}

				var emulated_connection = ((DBusProxy) emulated_provider).get_connection ();

				var emulated_session = new EmulatedAgentSession (emulated_connection);

				string session_path = ObjectPath.for_agent_session (id);
				string sink_path = ObjectPath.for_agent_message_sink (id);

				AgentSession session;
				try {
					session = yield emulated_connection.get_proxy (null, session_path, DO_NOT_LOAD_PROPERTIES,
						cancellable);
				} catch (IOError e) {
					throw_dbus_error (e);
				}

				try {
					emulated_session.session_registration_id = connection.register_object (session_path, session);
					emulated_session.sink_registration_id = emulated_connection.register_object (sink_path, sink);
				} catch (IOError e) {
					assert_not_reached ();
				}

				emulated_sessions[id] = emulated_session;

				return;
			}

			MainContext dbus_context = yield get_dbus_context ();

			var session = new LiveAgentSession (this, id, opts.persist_timeout, sink, dbus_context);
			sessions[id] = session;
			session.closed.connect (on_session_closed);
			session.script_eternalized.connect (on_script_eternalized);

			try {
				session.registration_id = connection.register_object (ObjectPath.for_agent_session (id),
					(AgentSession) session);
			} catch (IOError io_error) {
				assert_not_reached ();
			}

			opened (id);
		}

		private void detach_emulated_session (EmulatedAgentSession session) {
			connection.unregister_object (session.session_registration_id);
			session.connection.unregister_object (session.sink_registration_id);
		}

		private async void close_all_sessions () {
			uint pending = 1;
			var handlers = new Gee.HashMap<BaseAgentSession, ulong> ();

			CompletionNotify on_complete = () => {
				pending--;
				if (pending == 0)
					schedule_idle (close_all_sessions.callback);
			};

			foreach (var session in sessions.values.to_array ()) {
				pending++;
				handlers[session] = session.closed.connect (session => {
					session.disconnect (handlers[session]);
					on_complete ();
				});
				session.close.begin (null);
			}

			on_complete ();

			yield;

			assert (sessions.is_empty);

			on_complete = null;
		}

		private async void flush_all_sessions () {
			uint pending = 1;

			CompletionNotify on_complete = () => {
				pending--;
				if (pending == 0)
					schedule_idle (flush_all_sessions.callback);
			};

			foreach (var session in sessions.values.to_array ()) {
				pending++;
				flush_session.begin (session, on_complete);
			}

			on_complete ();

			yield;

			on_complete = null;
		}

		private async void flush_session (LiveAgentSession session, CompletionNotify on_complete) {
			yield session.flush ();

			on_complete ();
		}

		private void on_session_closed (BaseAgentSession base_session) {
			LiveAgentSession session = (LiveAgentSession) base_session;

			closed (session.id);

			unregister_session (session);

			session.script_eternalized.disconnect (on_script_eternalized);
			session.closed.disconnect (on_session_closed);
			sessions.unset (session.id);

			foreach (var dc in direct_connections.values) {
				if (dc.session == session) {
					detach_and_steal_direct_dbus_connection (dc.connection);
					break;
				}
			}
		}

		private void unregister_session (LiveAgentSession session) {
			var id = session.registration_id;
			if (id != 0) {
				connection.unregister_object (id);
				session.registration_id = 0;
			}
		}

		private void on_script_eternalized (Gum.Script script) {
			eternalized_scripts.add (script);
			ensure_eternalized ();
		}

#if !WINDOWS
		private async void migrate (AgentSessionId id, Socket to_socket, Cancellable? cancellable) throws Error, IOError {
			if (emulated_sessions.has_key (id)) {
				AgentSessionProvider emulated_provider = yield get_emulated_provider (cancellable);
				try {
					yield emulated_provider.migrate (id, to_socket, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
				return;
			}

			if (!sessions.has_key (id))
				throw new Error.INVALID_ARGUMENT ("Invalid session ID");
			var session = sessions[id];

			var dc = new DirectConnection (session);

			DBusConnection connection;
			AgentMessageSink sink;
			try {
				connection = yield new DBusConnection (SocketConnection.factory_create_connection (to_socket), null,
					DELAY_MESSAGE_PROCESSING, null, cancellable);
				sink = yield connection.get_proxy (null, ObjectPath.for_agent_message_sink (id), DO_NOT_LOAD_PROPERTIES,
					cancellable);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s", e.message);
			}
			dc.connection = connection;

			try {
				dc.registration_id = connection.register_object (ObjectPath.for_agent_session (id), (AgentSession) session);
			} catch (IOError io_error) {
				assert_not_reached ();
			}

			session.message_sink = sink;

			connection.start_message_processing ();

			this.connection.unregister_object (session.registration_id);
			session.registration_id = 0;

			direct_connections[connection] = dc;
			connection.on_closed.connect (on_direct_connection_closed);
		}
#endif

		private void on_direct_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			var dc = detach_and_steal_direct_dbus_connection (connection);

			dc.session.close.begin (null);
		}

		private DirectConnection detach_and_steal_direct_dbus_connection (DBusConnection connection) {
			connection.on_closed.disconnect (on_direct_connection_closed);

			DirectConnection dc;
			bool found = direct_connections.unset (connection, out dc);
			assert (found);

			connection.unregister_object (dc.registration_id);

			return dc;
		}

		private async void unload (Cancellable? cancellable) throws Error, IOError {
			if (unloading)
				throw new Error.INVALID_OPERATION ("Agent is already unloading");
			unloading = true;
			perform_unload.begin ();
		}

		private async void perform_unload () {
			Promise<bool> operation = null;

			AgentSessionProvider? emulated_provider;
			try {
				emulated_provider = yield try_get_emulated_provider (null);
			} catch (IOError e) {
				assert_not_reached ();
			}
			if (emulated_provider != null)
				emulated_provider.unload.begin (null);

			lock (pending_calls) {
				if (pending_calls > 0) {
					pending_close = new Promise<bool> ();
					operation = pending_close;
				}
			}

			if (operation != null) {
				try {
					yield operation.future.wait_async (null);
				} catch (GLib.Error e) {
					assert_not_reached ();
				}
			}

			yield close_all_sessions ();

			yield teardown_connection ();

			if (!is_eternal)
				teardown_emulated_provider ();

			if (stop_thread_on_unload) {
				schedule_idle (() => {
					main_loop.quit ();
					return false;
				});
			}
		}

		private void ensure_eternalized () {
			if (!_is_eternal) {
				_is_eternal = true;
				eternalized ();
			}
		}

		public void acquire_child_gating () throws Error {
			child_gating_subscriber_count++;
			if (child_gating_subscriber_count == 1)
				enable_child_gating ();
			child_gating_changed (child_gating_subscriber_count);
		}

		public void release_child_gating () {
			child_gating_subscriber_count--;
			if (child_gating_subscriber_count == 0)
				disable_child_gating ();
			child_gating_changed (child_gating_subscriber_count);
		}

		private void enable_child_gating () {
			if (spawn_monitor != null)
				return;

			var interceptor = Gum.Interceptor.obtain ();
			interceptor.begin_transaction ();

			fork_monitor = new ForkMonitor (this);
			fd_guard = new FileDescriptorGuard (agent_range);

			thread_count_cloaker = new ThreadCountCloaker ();
			thread_list_cloaker = new ThreadListCloaker ();
			fd_list_cloaker = new FDListCloaker ();

			spawn_monitor = new SpawnMonitor (this, main_context);

			interceptor.end_transaction ();
		}

		private void disable_child_gating () {
			if (spawn_monitor == null)
				return;

			var interceptor = Gum.Interceptor.obtain ();
			interceptor.begin_transaction ();

			spawn_monitor = null;

			fd_list_cloaker = null;
			thread_list_cloaker = null;
			thread_count_cloaker = null;

			fd_guard = null;
			fork_monitor = null;

			interceptor.end_transaction ();
		}

		public async PortalMembershipId join_portal (string address, PortalOptions options,
				Cancellable? cancellable) throws Error, IOError {
			string executable_path = get_executable_path ();
			string identifier = executable_path; // TODO: Detect app ID
			string name = Path.get_basename (executable_path); // TODO: Detect app name
			uint pid = get_process_id ();
			var app_info = HostApplicationInfo (identifier, name, pid, make_parameters_dict ());
			app_info.parameters["system"] = compute_system_parameters ();

			var client = new PortalClient (this, parse_cluster_address (address), address, options.certificate, options.token,
				options.acl, app_info);
			client.kill.connect (on_kill);
			yield client.start (cancellable);

			var id = PortalMembershipId (next_portal_membership_id++);
			portal_clients[id] = client;

			ensure_eternalized ();

			return id;
		}

		public async void leave_portal (PortalMembershipId membership_id, Cancellable? cancellable) throws Error, IOError {
			PortalClient client;
			if (!portal_clients.unset (membership_id, out client))
				throw new Error.INVALID_ARGUMENT ("Invalid membership ID");

			yield client.stop (cancellable);
		}

		private void on_kill () {
			kill_process (get_process_id ());
		}

		public void schedule_idle (owned SourceFunc function) {
			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (main_context);
		}

		public void schedule_timeout (uint delay, owned SourceFunc function) {
			var source = new TimeoutSource (delay);
			source.set_callback ((owned) function);
			source.attach (main_context);
		}

		private async void setup_connection_with_transport_uri (string transport_uri) throws Error {
			IOStream stream;
			try {
				if (transport_uri.has_prefix ("socket:")) {
					var socket = new Socket.from_fd (int.parse (transport_uri[7:]));
					stream = SocketConnection.factory_create_connection (socket);
				} else if (transport_uri.has_prefix ("pipe:")) {
					stream = yield Pipe.open (transport_uri, null).wait_async (null);
				} else {
					throw new Error.INVALID_ARGUMENT ("Invalid transport URI: %s", transport_uri);
				}
			} catch (GLib.Error e) {
				if (e is Error)
					throw (Error) e;
				throw new Error.TRANSPORT ("%s", e.message);
			}

			yield setup_connection_with_stream (stream);
		}

		private async void setup_connection_with_stream (IOStream stream) throws Error {
			try {
				connection = yield new DBusConnection (stream, null, AUTHENTICATION_CLIENT | DELAY_MESSAGE_PROCESSING);
				connection.on_closed.connect (on_connection_closed);
				filter_id = connection.add_filter (on_connection_message);

				AgentSessionProvider provider = this;
				registration_id = connection.register_object (ObjectPath.AGENT_SESSION_PROVIDER, provider);

				controller = yield connection.get_proxy (null, ObjectPath.AGENT_CONTROLLER, DO_NOT_LOAD_PROPERTIES, null);

				connection.start_message_processing ();
			} catch
```