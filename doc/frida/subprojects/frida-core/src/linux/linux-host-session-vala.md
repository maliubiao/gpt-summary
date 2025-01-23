Response:
### 功能归纳

`linux-host-session.vala` 是 Frida 动态插桩工具的核心模块之一，主要负责在 Linux 系统上实现与目标进程的交互、注入、调试等功能。以下是该文件的主要功能归纳：

1. **Linux 主机会话管理**：
   - `LinuxHostSessionBackend` 类负责启动和停止本地会话提供者（`LinuxHostSessionProvider`）。
   - `LinuxHostSessionProvider` 类负责创建和管理本地系统的会话，提供与目标进程的交互接口。

2. **进程管理与注入**：
   - `LinuxHostSession` 类负责与目标进程的交互，包括进程的枚举、注入、挂起、恢复、终止等操作。
   - 通过 `Linjector` 类实现将 Frida Agent 注入到目标进程中，并建立与目标进程的控制通道。

3. **Android 特定功能**：
   - 在 Android 环境下，提供了对 Zygote 进程的管理，支持应用启动、停止、崩溃监控等功能。
   - 通过 `RoboLauncher` 类管理 Android 应用的启动和注入，支持应用启动时的挂起和恢复。

4. **崩溃监控与处理**：
   - 在 Android 环境下，通过 `CrashMonitor` 类监控目标进程的崩溃，并收集崩溃信息。

5. **系统会话与代理管理**：
   - 通过 `AgentContainer` 类管理系统会话的代理，支持与目标进程的通信和控制。

6. **进程枚举与应用管理**：
   - 提供了枚举当前系统进程和应用程序的功能，支持获取进程的详细信息（如 PID、名称、参数等）。

### 二进制底层与 Linux 内核相关功能

1. **进程注入**：
   - 通过 `Linjector` 类实现将 Frida Agent 注入到目标进程中。注入过程涉及 Linux 的 `ptrace` 系统调用，用于挂起目标进程并修改其内存空间。
   - 示例：`Linjector.inject_library_resource` 方法将 Frida Agent 注入到目标进程中，并启动 Agent 的主函数。

2. **进程控制**：
   - 通过 `LinuxHelper` 类实现对目标进程的控制，包括挂起、恢复、终止等操作。这些操作依赖于 Linux 的 `kill` 系统调用和信号机制。
   - 示例：`LinuxHelper.resume` 方法通过发送 `SIGCONT` 信号恢复目标进程的执行。

3. **崩溃监控**：
   - 在 Android 环境下，通过 `CrashMonitor` 类监控目标进程的崩溃。崩溃监控依赖于 Linux 的信号处理机制，特别是 `SIGSEGV` 和 `SIGABRT` 等信号。

### LLDB 调试示例

假设我们想要使用 LLDB 调试 Frida 的注入过程，可以通过以下步骤实现：

1. **启动目标进程**：
   - 使用 LLDB 启动目标进程并挂起它：
     ```bash
     lldb target_process
     (lldb) process launch --stop-at-entry
     ```

2. **附加到目标进程**：
   - 使用 LLDB 附加到目标进程：
     ```bash
     lldb -p <pid>
     ```

3. **设置断点**：
   - 在 Frida 的注入函数处设置断点，例如 `Linjector.inject_library_resource`：
     ```bash
     (lldb) b Linjector.inject_library_resource
     ```

4. **继续执行**：
   - 继续执行目标进程，观察 Frida 的注入过程：
     ```bash
     (lldb) continue
     ```

5. **观察注入结果**：
   - 使用 LLDB 查看目标进程的内存和寄存器状态，确认 Frida Agent 是否成功注入：
     ```bash
     (lldb) memory read --format x --size 8 <address>
     ```

### 假设输入与输出

1. **输入**：
   - 目标进程的 PID 和 Frida Agent 的路径。
   - 示例输入：`pid = 1234`, `agent_path = "/path/to/frida-agent.so"`

2. **输出**：
   - 成功注入后，Frida Agent 会在目标进程中启动，并建立与 Frida 主机的控制通道。
   - 示例输出：`Agent injected successfully, control channel established.`

### 用户常见错误

1. **权限不足**：
   - 用户尝试注入一个没有足够权限的进程（如 root 进程），导致注入失败。
   - 示例错误：`Error: Permission denied`

2. **目标进程不存在**：
   - 用户提供的 PID 对应的进程不存在或已经终止。
   - 示例错误：`Error: Process not found`

3. **注入失败**：
   - 目标进程的内存布局不兼容，导致注入失败。
   - 示例错误：`Error: Injection failed, invalid memory address`

### 用户操作路径

1. **启动 Frida**：
   - 用户启动 Frida 并选择目标进程。

2. **注入 Agent**：
   - Frida 调用 `LinuxHostSession` 的 `perform_attach_to` 方法，尝试将 Agent 注入到目标进程中。

3. **建立控制通道**：
   - 注入成功后，Frida 与目标进程建立控制通道，用户可以开始调试或监控目标进程。

4. **调试与监控**：
   - 用户通过 Frida 提供的 API 与目标进程交互，执行脚本、监控函数调用等操作。

### 总结

`linux-host-session.vala` 是 Frida 在 Linux 系统上实现动态插桩的核心模块，主要负责进程管理、注入、调试等功能。通过 LLDB 可以复现和调试 Frida 的注入过程，用户在使用过程中可能会遇到权限不足、目标进程不存在等常见错误。
### 提示词
```
这是目录为frida/subprojects/frida-core/src/linux/linux-host-session.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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
namespace Frida {
	public class LinuxHostSessionBackend : Object, HostSessionBackend {
		private LinuxHostSessionProvider local_provider;

		public async void start (Cancellable? cancellable) throws IOError {
			assert (local_provider == null);
			local_provider = new LinuxHostSessionProvider ();
			provider_available (local_provider);
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			assert (local_provider != null);
			provider_unavailable (local_provider);
			yield local_provider.close (cancellable);
			local_provider = null;
		}
	}

	public class LinuxHostSessionProvider : Object, HostSessionProvider {
		public string id {
			get { return "local"; }
		}

		public string name {
			get { return "Local System"; }
		}

		public Variant? icon {
			get { return null; }
		}

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.LOCAL; }
		}

		private LinuxHostSession host_session;

		public async void close (Cancellable? cancellable) throws IOError {
			if (host_session == null)
				return;
			host_session.agent_session_detached.disconnect (on_agent_session_detached);
			yield host_session.close (cancellable);
			host_session = null;
		}

		public async HostSession create (HostSessionOptions? options, Cancellable? cancellable) throws Error, IOError {
			if (host_session != null)
				throw new Error.INVALID_OPERATION ("Already created");

			var tempdir = new TemporaryDirectory ();

			host_session = new LinuxHostSession (new LinuxHelperProcess (tempdir), tempdir);
			host_session.agent_session_detached.connect (on_agent_session_detached);

			return host_session;
		}

		public async void destroy (HostSession session, Cancellable? cancellable) throws Error, IOError {
			if (session != host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");

			host_session.agent_session_detached.disconnect (on_agent_session_detached);

			yield host_session.close (cancellable);
			host_session = null;
		}

		public async AgentSession link_agent_session (HostSession host_session, AgentSessionId id, AgentMessageSink sink,
				Cancellable? cancellable) throws Error, IOError {
			if (host_session != this.host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");

			return yield this.host_session.link_agent_session (id, sink, cancellable);
		}

		private void on_agent_session_detached (AgentSessionId id, SessionDetachReason reason, CrashInfo crash) {
			agent_session_detached (id, reason, crash);
		}
	}

	public class LinuxHostSession : BaseDBusHostSession {
		public LinuxHelper helper {
			get;
			construct;
		}

		public TemporaryDirectory tempdir {
			get;
			construct;
		}

		public bool report_crashes {
			get;
			construct;
		}

		private AgentContainer system_session_container;

		private AgentDescriptor? agent;

#if ANDROID
		private RoboLauncher robo_launcher;
		internal SystemServerAgent system_server_agent;
		private CrashMonitor? crash_monitor;
#endif

#if !ANDROID
		private ApplicationEnumerator application_enumerator = new ApplicationEnumerator ();
#endif
		private ProcessEnumerator process_enumerator = new ProcessEnumerator ();

		public LinuxHostSession (owned LinuxHelper helper, owned TemporaryDirectory tempdir, bool report_crashes = true) {
			Object (
				helper: helper,
				tempdir: tempdir,
				report_crashes: report_crashes
			);
		}

		construct {
			helper.output.connect (on_output);

			injector = new Linjector (helper, false, tempdir);
			injector.uninjected.connect (on_uninjected);

#if HAVE_EMBEDDED_ASSETS
			var blob32 = Frida.Data.Agent.get_frida_agent_32_so_blob ();
			var blob64 = Frida.Data.Agent.get_frida_agent_64_so_blob ();
			var emulated_arm = Frida.Data.Agent.get_frida_agent_arm_so_blob ();
			var emulated_arm64 = Frida.Data.Agent.get_frida_agent_arm64_so_blob ();
			agent = new AgentDescriptor (PathTemplate ("frida-agent-<arch>.so"),
				new Bytes.static (blob32.data),
				new Bytes.static (blob64.data),
				new AgentResource[] {
					new AgentResource ("frida-agent-arm.so", new Bytes.static (emulated_arm.data), tempdir),
					new AgentResource ("frida-agent-arm64.so", new Bytes.static (emulated_arm64.data), tempdir),
				},
				AgentMode.INSTANCED,
				tempdir);
#endif

#if ANDROID
			system_server_agent = new SystemServerAgent (this);
			system_server_agent.unloaded.connect (on_system_server_agent_unloaded);

			robo_launcher = new RoboLauncher (this, io_cancellable);
			robo_launcher.spawn_added.connect (on_robo_launcher_spawn_added);
			robo_launcher.spawn_removed.connect (on_robo_launcher_spawn_removed);

			if (report_crashes) {
				crash_monitor = new CrashMonitor ();
				crash_monitor.process_crashed.connect (on_process_crashed);
			}
#endif
		}

		public override async void preload (Cancellable? cancellable) throws Error, IOError {
#if ANDROID
			yield system_server_agent.preload (cancellable);

			yield robo_launcher.preload (cancellable);
#endif
		}

		public override async void close (Cancellable? cancellable) throws IOError {
#if ANDROID
			yield robo_launcher.close (cancellable);
			robo_launcher.spawn_added.disconnect (on_robo_launcher_spawn_added);
			robo_launcher.spawn_removed.disconnect (on_robo_launcher_spawn_removed);

			system_server_agent.unloaded.disconnect (on_system_server_agent_unloaded);
			yield system_server_agent.close (cancellable);
#endif

			yield base.close (cancellable);

#if ANDROID
			if (crash_monitor != null) {
				crash_monitor.process_crashed.disconnect (on_process_crashed);
				yield crash_monitor.close (cancellable);
			}
#endif

			var linjector = (Linjector) injector;

			yield wait_for_uninject (injector, cancellable, () => {
				return linjector.any_still_injected ();
			});

			injector.uninjected.disconnect (on_uninjected);
			yield injector.close (cancellable);

			if (system_session_container != null) {
				yield system_session_container.destroy (cancellable);
				system_session_container = null;
			}

			yield helper.close (cancellable);
			helper.output.disconnect (on_output);

			agent = null;

			tempdir.destroy ();
		}

		protected override async AgentSessionProvider create_system_session_provider (Cancellable? cancellable,
				out DBusConnection connection) throws Error, IOError {
			unowned string arch_name = (sizeof (void *) == 8) ? "64" : "32";

			string? path = null;
			PathTemplate? tpl = null;
#if HAVE_EMBEDDED_ASSETS
			if (MemoryFileDescriptor.is_supported ()) {
				string agent_name = agent.name_template.expand (arch_name);
				AgentResource resource = agent.resources.first_match (r => r.name == agent_name);
				path = "/proc/self/fd/%d".printf (resource.get_memfd ().fd);
			} else {
				tpl = agent.get_path_template ();
			}
#else
			tpl = PathTemplate (Config.FRIDA_AGENT_PATH);
#endif
			if (path == null)
				path = tpl.expand (arch_name);

			system_session_container = yield AgentContainer.create (path, cancellable);

			connection = system_session_container.connection;

			return system_session_container;
		}

		public override async HostApplicationInfo get_frontmost_application (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			var opts = FrontmostQueryOptions._deserialize (options);
#if ANDROID
			var app = yield system_server_agent.get_frontmost_application (opts, cancellable);
			if (app.pid == 0)
				return app;

			if (opts.scope != MINIMAL) {
				var process_opts = new ProcessQueryOptions ();
				process_opts.select_pid (app.pid);
				process_opts.scope = METADATA;

				var processes = yield process_enumerator.enumerate_processes (process_opts);
				if (processes.length == 0)
					return HostApplicationInfo.empty ();

				add_app_process_state (app, processes[0].parameters);
			}

			return app;
#else
			return System.get_frontmost_application (opts);
#endif
		}

		public override async HostApplicationInfo[] enumerate_applications (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			var opts = ApplicationQueryOptions._deserialize (options);
#if ANDROID
			var apps = yield system_server_agent.enumerate_applications (opts, cancellable);

			if (opts.scope != MINIMAL) {
				var app_index_by_pid = new Gee.HashMap<uint, uint> ();
				int i = 0;
				foreach (var app in apps) {
					if (app.pid != 0)
						app_index_by_pid[app.pid] = i;
					i++;
				}

				if (!app_index_by_pid.is_empty) {
					var process_opts = new ProcessQueryOptions ();
					foreach (uint pid in app_index_by_pid.keys)
						process_opts.select_pid (pid);
					process_opts.scope = METADATA;

					var processes = yield process_enumerator.enumerate_processes (process_opts);

					foreach (var process in processes) {
						add_app_process_state (apps[app_index_by_pid[process.pid]], process.parameters);
						app_index_by_pid.unset (process.pid);
					}

					foreach (uint index in app_index_by_pid.values)
						apps[index].pid = 0;
				}
			}

			return apps;
#else
			return yield application_enumerator.enumerate_applications (opts);
#endif
		}

#if ANDROID
		private void add_app_process_state (HostApplicationInfo app, HashTable<string, Variant> process_params) {
			var app_params = app.parameters;
			app_params["user"] = process_params["user"];
			app_params["ppid"] = process_params["ppid"];
			app_params["started"] = process_params["started"];
		}
#endif

		public override async HostProcessInfo[] enumerate_processes (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			var opts = ProcessQueryOptions._deserialize (options);
			var processes = yield process_enumerator.enumerate_processes (opts);

#if ANDROID
			var process_index_by_pid = new Gee.HashMap<uint, uint> ();
			int i = 0;
			foreach (var process in processes)
				process_index_by_pid[process.pid] = i++;

			var extra = yield system_server_agent.get_process_parameters (process_index_by_pid.keys.to_array (), opts.scope,
				cancellable);

			foreach (var entry in extra.entries) {
				uint pid = entry.key;
				HashTable<string, Variant> extra_parameters = entry.value;

				uint index = process_index_by_pid[pid];
				HashTable<string, Variant> parameters = processes[index].parameters;
				extra_parameters.foreach ((key, val) => {
					if (key == "$name")
						processes[index].name = val.get_string ();
					else
						parameters[key] = val;
				});
			}
#endif

			return processes;
		}

		public override async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
#if ANDROID
			yield robo_launcher.enable_spawn_gating (cancellable);
#else
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
#endif
		}

		public override async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
#if ANDROID
			yield robo_launcher.disable_spawn_gating (cancellable);
#else
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
#endif
		}

		public override async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError {
#if ANDROID
			return robo_launcher.enumerate_pending_spawn ();
#else
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
#endif
		}

		public override async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable)
				throws Error, IOError {
#if ANDROID
			if (!program.has_prefix ("/"))
				return yield robo_launcher.spawn (program, options, cancellable);
#endif

			return yield helper.spawn (program, options, cancellable);
		}

		protected override bool try_handle_child (HostChildInfo info) {
#if ANDROID
			return robo_launcher.try_handle_child (info);
#else
			return false;
#endif
		}

		protected override void notify_child_resumed (uint pid) {
#if ANDROID
			robo_launcher.notify_child_resumed (pid);
#endif
		}

		protected override void notify_child_gating_changed (uint pid, uint subscriber_count) {
#if ANDROID
			robo_launcher.notify_child_gating_changed (pid, subscriber_count);
#endif
		}

		protected override async void prepare_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			yield helper.prepare_exec_transition (pid, cancellable);
		}

		protected override async void await_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			yield helper.await_exec_transition (pid, cancellable);
		}

		protected override async void cancel_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			yield helper.cancel_exec_transition (pid, cancellable);
		}

		protected override bool process_is_alive (uint pid) {
			return Posix.kill ((Posix.pid_t) pid, 0) == 0 || Posix.errno == Posix.EPERM;
		}

		public override async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			yield helper.input (pid, data, cancellable);
		}

		protected override async void perform_resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			yield helper.resume (pid, cancellable);
		}

		public override async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
#if ANDROID
			if (yield system_server_agent.try_stop_package_by_pid (pid, cancellable))
				return;
#endif

			yield helper.kill (pid, cancellable);
		}

		protected override async Future<IOStream> perform_attach_to (uint pid, HashTable<string, Variant> options,
				Cancellable? cancellable, out Object? transport) throws Error, IOError {
			uint id;
			string entrypoint = "frida_agent_main";
			string parameters = make_agent_parameters (pid, "", options);
			AgentFeatures features = CONTROL_CHANNEL;
			var linjector = (Linjector) injector;
#if HAVE_EMBEDDED_ASSETS
			id = yield linjector.inject_library_resource (pid, agent, entrypoint, parameters, features, cancellable);
#else
			id = yield linjector.inject_library_file_with_template (pid, PathTemplate (Config.FRIDA_AGENT_PATH), entrypoint,
				parameters, features, cancellable);
#endif
			injectee_by_pid[pid] = id;

			var stream_request = new Promise<IOStream> ();
			IOStream stream = yield linjector.request_control_channel (id, cancellable);
			stream_request.resolve (stream);

			transport = null;

			return stream_request.future;
		}

		protected override string? get_emulated_agent_path (uint pid) throws Error {
			unowned string name;
			switch (cpu_type_from_pid (pid)) {
				case Gum.CpuType.IA32:
					name = "frida-agent-arm.so";
					break;
				case Gum.CpuType.AMD64:
					name = "frida-agent-arm64.so";
					break;
				default:
					throw new Error.NOT_SUPPORTED ("Emulated realm is not supported on this architecture");
			}

			AgentResource? resource = agent.resources.first_match (r => r.name == name);
			if (resource == null)
				throw new Error.NOT_SUPPORTED ("Unable to handle emulated processes due to build configuration");

			return resource.get_file ().path;
		}

#if ANDROID
		private void on_system_server_agent_unloaded (InternalAgent dead_agent) {
			dead_agent.unloaded.disconnect (on_system_server_agent_unloaded);

			system_server_agent = new SystemServerAgent (this);
			system_server_agent.unloaded.connect (on_system_server_agent_unloaded);
		}

		private void on_robo_launcher_spawn_added (HostSpawnInfo info) {
			spawn_added (info);
		}

		private void on_robo_launcher_spawn_removed (HostSpawnInfo info) {
			spawn_removed (info);
		}

		protected override async CrashInfo? try_collect_crash (uint pid, Cancellable? cancellable) throws IOError {
			if (crash_monitor == null)
				return null;
			return yield crash_monitor.try_collect_crash (pid, cancellable);
		}

		private void on_process_crashed (CrashInfo info) {
			process_crashed (info);

			if (crash_monitor != null && still_attached_to (info.pid)) {
				/*
				 * May take a while as a Java fatal exception typically won't terminate the process until
				 * the user dismisses the dialog.
				 */
				crash_monitor.disable_crash_delivery_timeout (info.pid);
			}
		}
#endif

		private void on_output (uint pid, int fd, uint8[] data) {
			output (pid, fd, data);
		}
	}

#if ANDROID
	private class RoboLauncher : Object {
		public signal void spawn_added (HostSpawnInfo info);
		public signal void spawn_removed (HostSpawnInfo info);

		public weak LinuxHostSession host_session {
			get;
			construct;
		}

		public Cancellable io_cancellable {
			get;
			construct;
		}

		private Promise<bool> ensure_request;

		private Gee.HashMap<uint, ZygoteAgent> zygote_agents = new Gee.HashMap<uint, ZygoteAgent> ();

		private bool spawn_gating_enabled = false;
		private Gee.HashMap<string, Promise<uint>> spawn_requests = new Gee.HashMap<string, Promise<uint>> ();
		private Gee.HashMap<uint, HostSpawnInfo?> pending_spawn = new Gee.HashMap<uint, HostSpawnInfo?> ();

		private delegate void CompletionNotify (GLib.Error? error);

		public RoboLauncher (LinuxHostSession host_session, Cancellable io_cancellable) {
			Object (
				host_session: host_session,
				io_cancellable: io_cancellable
			);
		}

		public async void preload (Cancellable? cancellable) throws Error, IOError {
			yield ensure_loaded (cancellable);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (ensure_request != null) {
				try {
					yield ensure_loaded (cancellable);
				} catch (GLib.Error e) {
				}
			}

			foreach (var request in spawn_requests.values.to_array ())
				request.reject (new Error.INVALID_OPERATION ("Cancelled by shutdown"));
			spawn_requests.clear ();

			foreach (var agent in zygote_agents.values.to_array ())
				yield agent.close (cancellable);
			zygote_agents.clear ();
		}

		public async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			yield ensure_loaded (cancellable);

			spawn_gating_enabled = true;
		}

		public async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			spawn_gating_enabled = false;

			var pending = pending_spawn.values.to_array ();
			pending_spawn.clear ();
			foreach (var spawn in pending) {
				spawn_removed (spawn);

				host_session.resume.begin (spawn.pid, io_cancellable);
			}
		}

		public HostSpawnInfo[] enumerate_pending_spawn () {
			var result = new HostSpawnInfo[pending_spawn.size];
			var index = 0;
			foreach (var spawn in pending_spawn.values)
				result[index++] = spawn;
			return result;
		}

		public async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
			string package = program;

			if (options.has_argv)
				throw new Error.NOT_SUPPORTED ("The 'argv' option is not supported when spawning Android apps");

			if (options.has_envp)
				throw new Error.NOT_SUPPORTED ("The 'envp' option is not supported when spawning Android apps");

			if (options.has_env)
				throw new Error.NOT_SUPPORTED ("The 'env' option is not supported when spawning Android apps");

			if (options.cwd.length > 0)
				throw new Error.NOT_SUPPORTED ("The 'cwd' option is not supported when spawning Android apps");

			if (options.stdio != INHERIT)
				throw new Error.NOT_SUPPORTED ("Redirected stdio is not supported when spawning Android apps");

			var entrypoint = PackageEntrypoint.parse (package, options);

			yield ensure_loaded (cancellable);

			var system_server_agent = host_session.system_server_agent;

			var process_name = yield system_server_agent.get_process_name (package, entrypoint.uid, cancellable);

			if (spawn_requests.has_key (process_name))
				throw new Error.INVALID_OPERATION ("Spawn already in progress for the specified package name");

			var request = new Promise<uint> ();
			spawn_requests[process_name] = request;

			uint pid = 0;
			try {
				yield system_server_agent.stop_package (package, entrypoint.uid, cancellable);
				yield system_server_agent.start_package (package, entrypoint, cancellable);

				var timeout = new TimeoutSource.seconds (20);
				timeout.set_callback (() => {
					request.reject (new Error.TIMED_OUT ("Unexpectedly timed out while waiting for app to launch"));
					return false;
				});
				timeout.attach (MainContext.get_thread_default ());
				try {
					pid = yield request.future.wait_async (cancellable);
				} finally {
					timeout.destroy ();
				}
			} catch (GLib.Error e) {
				if (!spawn_requests.unset (process_name)) {
					var pending_pid = request.future.value;
					if (pending_pid != 0)
						host_session.resume.begin (pending_pid, io_cancellable);
				}

				throw_api_error (e);
			}

			return pid;
		}

		public bool try_handle_child (HostChildInfo info) {
			var agent = zygote_agents[info.parent_pid];
			if (agent == null)
				return false;

			uint pid = info.pid;
			string identifier = info.identifier;

			if (identifier == "usap32" || identifier == "usap64") {
				handle_usap_child.begin (pid, identifier);
				return true;
			}

			Promise<uint> spawn_request;
			if (spawn_requests.unset (identifier, out spawn_request)) {
				spawn_request.resolve (pid);
				return true;
			}

			if (spawn_gating_enabled) {
				var spawn_info = HostSpawnInfo (pid, identifier);
				pending_spawn[pid] = spawn_info;
				spawn_added (spawn_info);
				return true;
			}

			if (agent.child_gating_only_used_by_us) {
				var source = new IdleSource ();
				var host_session = this.host_session;
				source.set_callback (() => {
					host_session.resume.begin (pid, io_cancellable);
					return false;
				});
				source.attach (MainContext.get_thread_default ());
				return true;
			}

			return false;
		}

		public void notify_child_resumed (uint pid) {
			HostSpawnInfo? info;
			if (pending_spawn.unset (pid, out info))
				spawn_removed (info);
		}

		public void notify_child_gating_changed (uint pid, uint subscriber_count) {
			var agent = zygote_agents[pid];
			if (agent != null)
				agent.child_gating_only_used_by_us = subscriber_count == 1;
		}

		private async void ensure_loaded (Cancellable? cancellable) throws Error, IOError {
			while (ensure_request != null) {
				try {
					yield ensure_request.future.wait_async (cancellable);
					return;
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}
			ensure_request = new Promise<bool> ();

			uint pending = 1;
			GLib.Error? first_error = null;

			CompletionNotify on_complete = error => {
				pending--;
				if (error != null && first_error == null)
					first_error = error;

				if (pending == 0) {
					var source = new IdleSource ();
					source.set_callback (ensure_loaded.callback);
					source.attach (MainContext.get_thread_default ());
				}
			};

			foreach (HostProcessInfo info in System.enumerate_processes (new ProcessQueryOptions ())) {
				var name = info.name;
				if (name == "zygote" || name == "zygote64" || name == "usap32" || name == "usap64") {
					uint pid = info.pid;
					if (zygote_agents.has_key (pid))
						continue;

					pending++;
					do_inject_zygote_agent.begin (pid, name, cancellable, on_complete);
				}
			}

			on_complete (null);

			yield;

			on_complete = null;

			if (first_error == null) {
				ensure_request.resolve (true);
			} else {
				ensure_request.reject (first_error);
				ensure_request = null;

				throw_api_error (first_error);
			}
		}

		private async void do_inject_zygote_agent (uint pid, string name, Cancellable? cancellable, CompletionNotify on_complete) {
			try {
				yield inject_zygote_agent (pid, name, cancellable);

				on_complete (null);
			} catch (GLib.Error e) {
				on_complete (e);
			}
		}

		private async void inject_zygote_agent (uint pid, string name, Cancellable? cancellable) throws Error, IOError {
			var agent = new ZygoteAgent (host_session, pid, name);
			zygote_agents[pid] = agent;
			agent.unloaded.connect (on_zygote_agent_unloaded);

			try {
				yield agent.load (cancellable);
			} catch (GLib.Error e) {
				agent.unloaded.disconnect (on_zygote_agent_unloaded);
				zygote_agents.unset (pid);

				if (e is Error.PERMISSION_DENIED) {
					throw new Error.NOT_SUPPORTED (
						"Unable to access PID %u (%s) while preparing for app launch; " +
						"try disabling Magisk Hide in case it is active",
						pid, name);
				}

				if (e is IOError)
					throw (IOError) e;

				throw (Error) e;
			}
		}

		private async void handle_usap_child (uint pid, string name) throws GLib.Error {
			try {
				yield inject_zygote_agent (pid, name, io_cancellable);
			} finally {
				host_session.resume.begin (pid, io_cancellable);
			}
		}

		private void on_zygote_agent_unloaded (InternalAgent dead_internal_agent) {
			var dead_agent = (ZygoteAgent) dead_internal_agent;
			dead_agent.unloaded.disconnect (on_zygote_agent_unloaded);
			zygote_agents.unset (dead_agent.pid);

			if (dead_agent.name.has_prefix ("zygote") && ensure_request != null && ensure_request.future.ready)
				ensure_request = null;
		}
	}

	private class ZygoteAgent : InternalAgent {
		public uint pid {
			get;
			construct;
		}

		public string name {
			get;
			construct;
		}

		public bool child_gating_only_used_by_us {
			get;
			set;
		}

		public ZygoteAgent (LinuxHostSession host_session, uint pid, string name) {
			Object (
				host_session: host_session,
				pid: pid,
				name: name
			);
		}

		public async void load (Cancellable? cancellable) throws Error, IOError {
#if ARM || ARM64
			LinuxHelper helper = ((LinuxHostSession) host_session).helper;
			yield helper.await_syscall (pid, POLL_LIKE, cancellable);
			try {
#endif
				yield ensure_loaded (cancellable);

				try {
					yield session.enable_child_gating (cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
#if ARM || ARM64
			} finally {
				helper.resume_syscall.begin (pid, null);
			}
#endif
		}

		protected override async uint get_target_pid (Cancellable? cancellable) throws Error, IOError {
			return pid;
		}

		protected override async string? load_source (Cancellable? cancellable) throws Error, IOError {
			return null;
		}
	}

	private class SystemServerAgent : InternalAgent {
		private delegate void CompletionNotify ();

		public SystemServerAgent (LinuxHostSession host_session) {
			Object (
				host_session: host_session,
#if HAVE_V8
				script_runtime: ScriptRuntime.V8
#else
				script_runtime: ScriptRuntime.DEFAULT
#endif
			);
		}

		public async void preload (Cancellable? cancellable) throws Error, IOError {
			yield enumerate_applications (new ApplicationQueryOptions (), cancellable);

			try {
				yield get_process_name ("", 0, cancellable);
			} catch (Error e) {
			}

			try {
				yield start_package ("", new DefaultActivityEntrypoint (), cancellable);
			} catch (Error e) {
			}
		}

		public async HostApplicationInfo get_frontmost_application (FrontmostQueryOptions options,
				Cancellable? cancellable) throws Error, IOError {
			var scope = options.scope;
			var scope_node = new Json.Node.alloc ().init_string (scope.to_nick ());

			Json.Node result = yield call ("getFrontmostApplication", new Json.Node[] { scope_node }, null, cancellable);

			if (result.get_node_type () == NULL)
				return HostApplicationInfo.empty ();

			var item = result.get_array ();
			var identifier = item.get_string_element (0);
			var name = item.get_string_element (1);
			var pid = (uint) item.get_int_element (2);
			var info = HostApplicationInfo (identifier, name, pid, make_parameters_dict ());
			if (scope != MINIMAL)
				add_parameters_from_json (info.parameters, item.get_object_element (3));
			return info;
		}

		public async HostApplicationInfo[] enumerate_applications (ApplicationQueryOptions options,
				Cancellable? cancellable) throws Error, IOError {
			var identifiers_array = new Json.Array ();
			options.enumerate_selected_identifiers (identifier => {
				identifiers_array.add_string_element (identifier);
			});
			var identifiers_node = new Json.Node.alloc ().init_array (identifiers_array);

			var scope = options.scope;
			var scope_node = new Json.Node.alloc ().init_string (scope.to_nick ());

			Json.Node apps = yield call ("enumerateApplications", new Json.Node[] { identifiers_node, scope_node }, null,
				cancellable);

			var items = apps.get_array ();
			var length = items.get_length ();

			var result = new HostApplicationInfo[length];

			for (var i = 0; i != length; i++) {
				var item = items.get_array_element (i);
				var identifier = item.get_string_element (0);
				var name = item.get_string_element (1);
				var pid = (uint) item.get_int_element (2);
				var info = HostApplicationInfo (identifier, name, pid, make_parameters_dict ());
				if (scope != MINIMAL)
					add_parameters_from_json (info.parameters, item.get_object_element (3));
				result[i] = info;
			}

			return result;
		}

		public async string get_process_name (string package, int uid, Cancellable? cancellable) throws Error, IOError {
			var package_name_node = new Json.Node.alloc ().init_string (package);
			var uid_node = new Json.Node.alloc ().init_int (uid);

			Json.Node name = yield call ("getProcessName", new Json.Node[] { package_name_node, uid_node }, null, cancellable);

			return name.get_string ();
		}

		public async Gee.Map<uint, HashTable<string, Variant>> get_process_parameters (uint[] pids, Scope scope,
				Cancellable? cancellable) throws Error, IOError {
			var pids_array = new Json.Array ();
			foreach (uint pid in pids)
				pids_array.add_int_element ((int64) pid);
			var pids_node = new Json.Node.alloc ().init_array (pids_array);

			var scope_node = new Json.Node.alloc ().init_string (scope.to_nick ());

			Json.Node by_pid = yield call ("getProcessParameters", new Json.Node[] { pids_node, scope_node }, null,
				cancellable);

			var result = new Gee.HashMap<uint, HashTable<string, Variant>> ();
			by_pid.get_object ().foreach_member ((object, pid_str, parameters_node) => {
				uint pid = uint.parse (pid_str);

				var parameters = make_parameters_dict ();
				add_parameters_from_json (parameters, parameters_node.get_object ());

				result[pid] = parameters;
			});
			return result;
		}

		public async void start_package (string package, PackageEntrypoint entrypoint, Cancellable? cancellable)
				throws Error, IOError {
			var package_node = new Json.Node.alloc ().init_string (package);
			var uid_node = new Json.Node.alloc ().init_int (entrypoint.uid);

			if (entrypoint is DefaultActivityEntrypoint) {
				var activity_node = new Json.Node.alloc ().init_null ();

				yield call ("startActivity", new Json.Node[] { package_node, activity_node, uid_node }, null, cancellable);
			} else if (entrypoint is ActivityEntrypoint) {
				var e = entrypoint as ActivityEntrypoint;

				var activity_node = new Json.Node.alloc ().init_string (e.activity);

				yield call ("startActivity", new Json.Node[] { package_node, activity_node, uid_node }, null, cancellable);
			} else if (entrypoint is BroadcastReceiverEntrypoint) {
				var e = entrypoint as BroadcastReceiverEntrypoint;

				var receiver_node = new Json.Node.alloc ().init_string (e.receiver);
				var action_node = new Json.Node.alloc ().init_string (e.action);

				yield call ("sendBroadcast", new Json.Node[] { package_node, receiver_node, action_node, uid_node }, null,
					cancellable);
			} else {
				assert_not_reached ();
			}
		}

		public async void stop_package (string package, int uid, Cancellable? cancellable) throws Error, IOError {
			var package_node = new Json.Node.alloc ().init_string (package);
			var uid_node = new Json.Node.alloc ().init_int (uid);

			yield call ("stopPackage", new Json.Node[] { package_node, uid_node }, null, cancellable);
		}

		public async bool try_stop_package_by_pid (uint pid, Cancellable? cancellable) throws Error, IOError {
			var pid_node = new Json.Node.alloc ().init_int (pid);

			Json.Node success = yield call ("tryStopPackageByPid", new Json.Node[] { pid_node }, null, cancellable);

			return success.get_boolean ();
		}

		protected override async uint get_target_pid (Cancellable? cancellable) throws Error, IOError {
			return LocalProcesses.get_pid ("system_server");
		}

		protected override async string? load_source (Cancellable? cancellable) throws Error, IOError {
			return (string) Frida.Data.Android.get_system_server_js_blob ().data;
		}

#if ARM || ARM64
		protected override async void load_script (Cancellable? cancellable) throws Error, IOError {
			var suspended_threads = yield suspend_sensitive_threads (cancellable);
			try {
				yield base.load_script (cancellable);
			} finally {
				resume_threads (suspended_threads);
			}
		}

		private async Gee.List<uint> suspend_sensitive_threads (Cancellable? cancellable) throws Error, IOError {
			var thread_ids = new Gee.ArrayList<uint> ();
			Dir dir;
			try {
				dir = Dir.open ("/proc/%u/task".printf (target_pid));
			} catch (FileError e) {
				throw new Error.PROCESS_NOT_FOUND ("Unable to query system_server threads: %s", e.m
```