Response:
### 功能概述

`frida-core/src/freebsd/binjector.vala` 是 Frida 动态插桩工具的核心部分，主要负责在 FreeBSD 系统上实现进程注入、进程监控、线程管理等功能。以下是该文件的主要功能：

1. **进程注入**：
   - 通过 `inject_library_file`、`inject_library_blob` 和 `inject_library_resource` 方法，将共享库（如 `.so` 文件）注入到目标进程中。
   - 支持通过文件路径、二进制数据或资源描述符来指定要注入的库。

2. **进程监控**：
   - 通过 `spawn` 方法启动新进程，并监控其输出（标准输出和标准错误）。
   - 通过 `monitor_child` 和 `demonitor_child` 方法监控子进程的生命周期。

3. **进程执行控制**：
   - 通过 `prepare_exec_transition`、`await_exec_transition` 和 `cancel_exec_transition` 方法控制进程的执行状态，支持进程的挂起和恢复。

4. **线程管理**：
   - 通过 `recreate_thread` 方法重新创建目标进程中的线程。
   - 通过 `RemoteThreadSession` 类管理与目标进程的线程会话。

5. **资源管理**：
   - 通过 `ResourceStore` 类管理临时文件和资源，确保在注入过程中使用的文件可以被正确清理。

6. **符号解析**：
   - 通过 `SymbolResolver` 类解析目标进程中的符号地址，支持动态链接库（如 `libc` 和 `ld-elf.so`）中的函数地址查找。

7. **信号处理**：
   - 通过 `output` 信号处理目标进程的输出，并将其传递给上层调用者。

### 二进制底层与 Linux 内核相关

1. **进程注入**：
   - 在 FreeBSD 上，进程注入通常涉及 `ptrace` 系统调用或 `procfs` 文件系统。`_do_inject` 方法可能使用这些底层机制来修改目标进程的内存空间，加载共享库并执行注入代码。

2. **线程管理**：
   - `_recreate_injectee_thread` 方法可能使用 FreeBSD 的线程管理 API（如 `pthread_create`）来重新创建线程。

3. **符号解析**：
   - `SymbolResolver` 类通过解析 ELF 文件格式来查找函数地址。ELF 是 Unix 和 Linux 系统中常见的可执行文件和共享库格式。

### LLDB 调试示例

假设我们想要调试 `inject_library_file` 方法的执行过程，可以使用 LLDB 进行调试。以下是一个 LLDB Python 脚本示例，用于复刻 `inject_library_file` 的功能：

```python
import lldb

def inject_library_file(pid, path, entrypoint, data, temp_path, id):
    # 获取目标进程
    target = lldb.debugger.GetSelectedTarget()
    process = target.GetProcess()

    # 加载共享库
    error = lldb.SBError()
    module = target.AddModule(path, None, None)
    if not module.IsValid():
        print(f"Failed to load module: {path}")
        return

    # 查找入口点
    entrypoint_symbol = module.FindSymbol(entrypoint)
    if not entrypoint_symbol.IsValid():
        print(f"Failed to find entrypoint: {entrypoint}")
        return

    entrypoint_address = entrypoint_symbol.GetStartAddress().GetLoadAddress(target)
    print(f"Entrypoint address: {hex(entrypoint_address)}")

    # 注入代码
    # 这里假设我们已经通过某种方式将代码注入到目标进程的内存中
    # 例如，使用 ptrace 或 procfs 修改目标进程的内存

    # 执行注入代码
    # 这里假设我们已经将代码注入到目标进程的内存中，并准备执行
    # 例如，使用 ptrace 设置目标进程的指令指针到入口点地址

    print(f"Injected library {path} into process {pid} with entrypoint {entrypoint}")

# 使用示例
inject_library_file(1234, "/path/to/library.so", "entrypoint_function", "data", "/tmp", 1)
```

### 逻辑推理与假设输入输出

假设我们调用 `inject_library_file` 方法，输入如下：

- `pid`: 1234
- `path`: `/path/to/library.so`
- `entrypoint`: `entrypoint_function`
- `data`: `"data"`
- `temp_path`: `/tmp`
- `id`: 1

假设输出为：

- 成功注入库文件，并返回注入的 ID。
- 如果库文件不存在或入口点未找到，抛出错误。

### 用户常见错误

1. **库文件路径错误**：
   - 用户可能提供了错误的库文件路径，导致 `inject_library_file` 方法抛出 `Error.EXECUTABLE_NOT_FOUND` 错误。

2. **入口点未找到**：
   - 用户可能提供了错误的入口点名称，导致 `inject_library_file` 方法无法找到对应的符号，抛出错误。

3. **权限不足**：
   - 用户可能没有足够的权限来注入目标进程，导致操作失败。

### 用户操作步骤与调试线索

1. **启动目标进程**：
   - 用户通过 `spawn` 方法启动目标进程，并监控其输出。

2. **注入库文件**：
   - 用户调用 `inject_library_file` 方法，尝试将库文件注入到目标进程中。

3. **监控注入结果**：
   - 用户通过 `output` 信号监控目标进程的输出，检查注入是否成功。

4. **调试注入过程**：
   - 如果注入失败，用户可以通过 LLDB 调试 `inject_library_file` 方法，检查库文件加载和符号解析的过程。

### 总结

`binjector.vala` 文件实现了 Frida 在 FreeBSD 系统上的核心注入功能，涉及进程注入、线程管理、符号解析等底层操作。通过 LLDB 调试工具，用户可以复刻和调试这些功能，排查注入过程中可能遇到的问题。
### 提示词
```
这是目录为frida/subprojects/frida-core/src/freebsd/binjector.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
```

### 源代码
```
namespace Frida {
	public class Binjector : Object, Injector {
		public signal void output (uint pid, int fd, uint8[] data);

		public string temp_directory {
			owned get {
				return resource_store.tempdir.path;
			}
		}

		public ResourceStore resource_store {
			get {
				if (_resource_store == null) {
					try {
						_resource_store = new ResourceStore ();
					} catch (Error e) {
						assert_not_reached ();
					}
				}
				return _resource_store;
			}
		}
		private ResourceStore _resource_store;

		private Gee.HashMap<uint, uint> pid_by_id = new Gee.HashMap<uint, uint> ();
		private Gee.HashMap<uint, TemporaryFile> blob_file_by_id = new Gee.HashMap<uint, TemporaryFile> ();
		private uint next_injectee_id = 1;
		private uint next_blob_id = 1;

		public Gee.HashMap<uint, void *> spawn_instances = new Gee.HashMap<uint, void *> ();
		private Gee.HashMap<uint, uint> watch_sources = new Gee.HashMap<uint, uint> ();
		private Gee.HashMap<uint, OutputStream> stdin_streams = new Gee.HashMap<uint, OutputStream> ();

		public Gee.HashMap<uint, void *> exec_instances = new Gee.HashMap<uint, void *> ();
		private Gee.HashMap<uint, uint> exec_waiters = new Gee.HashMap<uint, uint> ();
		private uint next_waiter_id = 1;

		public Gee.HashMap<uint, void *> inject_instances = new Gee.HashMap<uint, void *> ();
		private Gee.HashMap<uint, RemoteThreadSession> inject_sessions = new Gee.HashMap<uint, RemoteThreadSession> ();
		private Gee.HashMap<uint, uint> inject_expiry_by_id = new Gee.HashMap<uint, uint> ();

		public uint next_id = 0;

		private Cancellable io_cancellable = new Cancellable ();

		~Binjector () {
			foreach (var instance in spawn_instances.values)
				_free_spawn_instance (instance);
			foreach (var instance in exec_instances.values)
				_free_exec_instance (instance);
			foreach (var instance in inject_instances.values)
				_free_inject_instance (instance, RESIDENT);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			io_cancellable.cancel ();

			_resource_store = null;
		}

		public async uint spawn (string path, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
			if (!FileUtils.test (path, EXISTS))
				throw new Error.EXECUTABLE_NOT_FOUND ("Unable to find executable at '%s'", path);

			StdioPipes? pipes;
			var child_pid = _do_spawn (path, options, out pipes);

			monitor_child (child_pid);

			if (pipes != null) {
				stdin_streams[child_pid] = new UnixOutputStream (pipes.input, false);
				process_next_output_from.begin (new UnixInputStream (pipes.output, false), child_pid, 1, pipes);
				process_next_output_from.begin (new UnixInputStream (pipes.error, false), child_pid, 2, pipes);
			}

			return child_pid;
		}

		private void monitor_child (uint pid) {
			watch_sources[pid] = ChildWatch.add ((Pid) pid, on_child_dead);
		}

		private void demonitor_child (uint pid) {
			uint watch_id;
			if (watch_sources.unset (pid, out watch_id))
				Source.remove (watch_id);
		}

		private void on_child_dead (Pid pid, int status) {
			watch_sources.unset (pid);

			stdin_streams.unset (pid);

			void * instance;
			if (spawn_instances.unset (pid, out instance))
				_free_spawn_instance (instance);
		}

		private async void process_next_output_from (InputStream stream, uint pid, int fd, Object resource) {
			try {
				var buf = new uint8[4096];
				var n = yield stream.read_async (buf, Priority.DEFAULT, io_cancellable);

				var data = buf[0:n];
				output (pid, fd, data);

				if (n > 0)
					process_next_output_from.begin (stream, pid, fd, resource);
			} catch (GLib.Error e) {
				if (!(e is IOError.CANCELLED))
					output (pid, fd, new uint8[0]);
			}
		}

		public async void prepare_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			bool is_child = spawn_instances.has_key (pid);
			if (is_child)
				demonitor_child (pid);

			try {
				_do_prepare_exec_transition (pid);
			} catch (Error e) {
				if (is_child)
					monitor_child (pid);
				throw e;
			}

			_notify_exec_pending (pid, true);
		}

		public async void await_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			var instance = exec_instances[pid];
			if (instance == null)
				throw new Error.INVALID_ARGUMENT ("Invalid PID");

			if (!_try_transition_exec_instance (instance)) {
				uint id = next_waiter_id++;
				Error? pending_error = null;

				exec_waiters[pid] = id;

				Timeout.add (50, () => {
					var cancelled = !exec_waiters.has (pid, id);
					if (cancelled) {
						await_exec_transition.callback ();
						return false;
					}

					try {
						if (_try_transition_exec_instance (instance)) {
							await_exec_transition.callback ();
							return false;
						}
					} catch (Error e) {
						pending_error = e;
						await_exec_transition.callback ();
						return false;
					}

					return true;
				});

				yield;

				var cancelled = !exec_waiters.has (pid, id);
				if (cancelled)
					throw new Error.INVALID_OPERATION ("Cancelled");
				exec_waiters.unset (pid);

				if (pending_error != null) {
					exec_instances.unset (pid);

					_resume_exec_instance (instance);
					_free_exec_instance (instance);

					_notify_exec_pending (pid, false);

					throw pending_error;
				}
			}

			if (spawn_instances.has_key (pid))
				monitor_child (pid);
		}

		public async void cancel_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			void * instance;
			if (!exec_instances.unset (pid, out instance))
				throw new Error.INVALID_ARGUMENT ("Invalid PID");

			exec_waiters.unset (pid);

			_suspend_exec_instance (instance);
			_resume_exec_instance (instance);
			_free_exec_instance (instance);

			if (spawn_instances.has_key (pid))
				monitor_child (pid);
			_notify_exec_pending (pid, false);
		}

		public async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			var stream = stdin_streams[pid];
			if (stream == null)
				throw new Error.INVALID_ARGUMENT ("Invalid PID");
			try {
				yield stream.write_all_async (data, Priority.DEFAULT, null, null);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s", e.message);
			}
		}

		public async void resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			void * instance;
			bool instance_found;

			instance_found = spawn_instances.unset (pid, out instance);
			if (instance_found) {
				_resume_spawn_instance (instance);
				_free_spawn_instance (instance);
				return;
			}

			if (exec_waiters.has_key (pid))
				throw new Error.INVALID_OPERATION ("Invalid operation");

			instance_found = exec_instances.unset (pid, out instance);
			if (instance_found) {
				_resume_exec_instance (instance);
				_free_exec_instance (instance);
				return;
			}

			throw new Error.INVALID_ARGUMENT ("Invalid PID");
		}

		public async uint inject_library_file (uint pid, string path, string entrypoint, string data, Cancellable? cancellable)
				throws Error, IOError {
			uint id = next_injectee_id++;
			_do_inject (pid, path, entrypoint, data, temp_directory, id);

			pid_by_id[id] = pid;

			yield establish_session (id, pid);

			return id;
		}

		public async uint inject_library_blob (uint pid, Bytes blob, string entrypoint, string data, Cancellable? cancellable)
				throws Error, IOError {
			var name = "blob%u.so".printf (next_blob_id++);
			var file = new TemporaryFile.from_stream (name, new MemoryInputStream.from_bytes (blob), resource_store.tempdir);
			var path = file.path;
			FileUtils.chmod (path, 0755);

			var id = yield inject_library_file (pid, path, entrypoint, data, cancellable);

			blob_file_by_id[id] = file;

			return id;
		}

		public async uint inject_library_resource (uint pid, AgentDescriptor descriptor, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			return yield inject_library_file (pid, resource_store.ensure_copy_of (descriptor), entrypoint, data, cancellable);
		}

		public async void demonitor (uint id, Cancellable? cancellable) throws Error, IOError {
			var instance = inject_instances[id];
			if (instance == null)
				throw new Error.INVALID_ARGUMENT ("Invalid ID");

			RemoteThreadSession session;
			if (inject_sessions.unset (id, out session)) {
				session.ended.disconnect (on_remote_thread_session_ended);
				yield session.cancel ();
			}

			_demonitor (instance);

			schedule_inject_expiry_for_id (id);
		}

		public async uint demonitor_and_clone_state (uint id, Cancellable? cancellable) throws Error, IOError {
			var instance = inject_instances[id];
			if (instance == null)
				throw new Error.INVALID_ARGUMENT ("Invalid ID");

			RemoteThreadSession session;
			if (inject_sessions.unset (id, out session)) {
				session.ended.disconnect (on_remote_thread_session_ended);
				yield session.cancel ();
			}

			uint clone_id = next_injectee_id++;

			_demonitor_and_clone_injectee_state (instance, clone_id);

			schedule_inject_expiry_for_id (id);
			schedule_inject_expiry_for_id (clone_id);

			return clone_id;
		}

		public async void recreate_thread (uint pid, uint id, Cancellable? cancellable) throws Error, IOError {
			var instance = inject_instances[id];
			if (instance == null)
				throw new Error.INVALID_ARGUMENT ("Invalid ID");

			cancel_inject_expiry_for_id (id);

			_recreate_injectee_thread (instance, pid);

			yield establish_session (id, pid);
		}

		private async void establish_session (uint id, uint pid) throws Error {
			var fifo = _get_fifo_for_inject_instance (inject_instances[id]);

			var session = new RemoteThreadSession (id, pid, fifo);
			try {
				yield session.establish ();
			} catch (Error e) {
				_destroy_inject_instance (id, IMMEDIATE);
				throw e;
			}

			inject_sessions[id] = session;
			session.ended.connect (on_remote_thread_session_ended);
		}

		private void on_remote_thread_session_ended (RemoteThreadSession session, UnloadPolicy unload_policy) {
			var id = session.id;

			session.ended.disconnect (on_remote_thread_session_ended);
			inject_sessions.unset (id);

			Timeout.add (50, () => {
				_destroy_inject_instance (id, unload_policy);
				return false;
			});
		}

		protected void _destroy_inject_instance (uint id, UnloadPolicy unload_policy) {
			void * instance;
			bool found = inject_instances.unset (id, out instance);
			assert (found);

			_free_inject_instance (instance, unload_policy);

			on_uninjected (id);
		}

		private void schedule_inject_expiry_for_id (uint id) {
			uint previous_timer;
			if (inject_expiry_by_id.unset (id, out previous_timer))
				Source.remove (previous_timer);

			inject_expiry_by_id[id] = Timeout.add_seconds (20, () => {
				var removed = inject_expiry_by_id.unset (id);
				assert (removed);

				_destroy_inject_instance (id, IMMEDIATE);

				return false;
			});
		}

		private void cancel_inject_expiry_for_id (uint id) {
			uint timer;
			var found = inject_expiry_by_id.unset (id, out timer);
			assert (found);

			Source.remove (timer);
		}

		public bool any_still_injected () {
			return !pid_by_id.is_empty;
		}

		public bool is_still_injected (uint id) {
			return pid_by_id.has_key (id);
		}

		private void on_uninjected (uint id) {
			pid_by_id.unset (id);
			blob_file_by_id.unset (id);

			uninjected (id);
		}

		protected extern uint _do_spawn (string path, HostSpawnOptions options, out StdioPipes? pipes) throws Error;
		protected extern void _resume_spawn_instance (void * instance);
		protected extern void _free_spawn_instance (void * instance);

		protected extern void _do_prepare_exec_transition (uint pid) throws Error;
		protected extern void _notify_exec_pending (uint pid, bool pending);
		protected extern bool _try_transition_exec_instance (void * instance) throws Error;
		protected extern void _suspend_exec_instance (void * instance);
		protected extern void _resume_exec_instance (void * instance);
		protected extern void _free_exec_instance (void * instance);

		protected extern void _do_inject (uint pid, string path, string entrypoint, string data, string temp_path, uint id)
			throws Error;
		protected extern void _demonitor (void * instance);
		protected extern uint _demonitor_and_clone_injectee_state (void * instance, uint clone_id);
		protected extern void _recreate_injectee_thread (void * instance, uint pid) throws Error;
		protected extern InputStream _get_fifo_for_inject_instance (void * instance);
		protected extern void _free_inject_instance (void * instance, UnloadPolicy unload_policy);

		public class ResourceStore {
			public TemporaryDirectory tempdir {
				get;
				private set;
			}

			private Gee.HashMap<string, TemporaryFile> agents = new Gee.HashMap<string, TemporaryFile> ();

			public ResourceStore () throws Error {
				tempdir = new TemporaryDirectory ();
				FileUtils.chmod (tempdir.path, 0755);
			}

			~ResourceStore () {
				foreach (var tempfile in agents.values)
					tempfile.destroy ();
				tempdir.destroy ();
			}

			public string ensure_copy_of (AgentDescriptor desc) throws Error {
				var temp_agent = agents[desc.name];
				if (temp_agent == null) {
					temp_agent = new TemporaryFile.from_stream (desc.name, desc.sofile, tempdir);
					FileUtils.chmod (temp_agent.path, 0755);
					agents[desc.name] = temp_agent;
				}
				return temp_agent.path;
			}
		}
	}

	public class AgentDescriptor : Object {
		public string name {
			get;
			construct;
		}

		public InputStream sofile {
			get {
				reset_stream (_sofile);
				return _sofile;
			}

			construct {
				_sofile = value;
			}
		}
		private InputStream _sofile;

		public AgentDescriptor (string name, InputStream sofile) {
			Object (name: name, sofile: sofile);

			assert (sofile is Seekable);
		}

		private void reset_stream (InputStream stream) {
			try {
				((Seekable) stream).seek (0, SeekType.SET);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}
	}

	public Gum.Address _find_entrypoint (uint pid) throws Error {
		string program_path;
		try {
			program_path = Gum.Freebsd.query_program_path_for_pid ((Posix.pid_t) pid);
		} catch (Gum.Error e) {
			throw new Error.NOT_SUPPORTED ("Unable to detect entrypoint: %s", e.message);
		}

		Gum.ElfModule? program_module = null;
		Gum.Address program_base = 0;
		Gum.Freebsd.enumerate_ranges ((Posix.pid_t) pid, READ, details => {
			unowned Gum.FileMapping? file = details.file;
			if (file == null || file.offset != 0 || file.path != program_path)
				return true;

			try {
				program_module = new Gum.ElfModule.from_file (file.path);
				program_base = details.range.base_address;
			} catch (Gum.Error e) {
			}
			return false;
		});
		if (program_module == null)
			throw new Error.NOT_SUPPORTED ("Unable to detect entrypoint: program module not found");

		return program_base + program_module.entrypoint;
	}

	public string _detect_libthr_name () {
		string? name = null;
		Gum.Freebsd.enumerate_ranges (Posix.getpid (), READ, details => {
			unowned Gum.FileMapping? file = details.file;
			if (file == null || file.offset != 0)
				return true;

			if (file.path.has_prefix ("/lib/libthr.so.")) {
				name = file.path;
				return false;
			}

			return true;
		});
		assert (name != null);
		return name;
	}

	protected class SymbolResolver : Object {
		private RemoteModule? ld;
		private RemoteModule? libc;

		public SymbolResolver (uint pid) {
			Gum.Freebsd.enumerate_ranges ((Posix.pid_t) pid, READ, details => {
				unowned Gum.FileMapping? file = details.file;
				if (file == null || file.offset != 0)
					return true;

				unowned string path = file.path;
				Gum.Address base_address = details.range.base_address;

				if (path.has_prefix ("/libexec/ld-elf.so."))
					ld = RemoteModule.try_open (base_address, path);
				else if (path.has_prefix ("/lib/libc.so."))
					libc = RemoteModule.try_open (base_address, path);

				return true;
			});
		}

		public Gum.Address find_ld_function (string function_name) {
			if (ld == null)
				return 0;
			return ld.resolve (function_name);
		}

		public Gum.Address find_libc_function (string function_name) {
			if (libc == null)
				return 0;
			return libc.resolve (function_name);
		}
	}

	private class RemoteModule {
		private Gum.Address base_address;
		private Gum.ElfModule module;

		public static RemoteModule? try_open (Gum.Address base_address, string path) {
			try {
				var module = new Gum.ElfModule.from_file (path);
				return new RemoteModule (base_address, module);
			} catch (Gum.Error e) {
				return null;
			}
		}

		private RemoteModule (Gum.Address base_address, Gum.ElfModule module) {
			this.base_address = base_address;
			this.module = module;
		}

		public Gum.Address resolve (string function_name) {
			Gum.Address relative_address = 0;
			module.enumerate_exports (details => {
				if (details.name == function_name) {
					relative_address = details.address;
					return false;
				}
				return true;
			});
			if (relative_address == 0)
				return 0;

			return base_address + relative_address;
		}
	}

	private class RemoteThreadSession : Object {
		public signal void ended (UnloadPolicy unload_policy);

		public uint id {
			get;
			construct;
		}

		public uint pid {
			get;
			construct;
		}

		public InputStream input {
			get;
			construct;
		}

		private Promise<bool> cancel_request = new Promise<bool> ();
		private Cancellable cancellable = new Cancellable ();

		public RemoteThreadSession (uint id, uint pid, InputStream input) {
			Object (id: id, pid: pid, input: input);
		}

		public async void establish () throws Error {
			var timeout = Timeout.add_seconds (2, () => {
				cancellable.cancel ();
				return false;
			});

			ssize_t size = 0;
			var byte_buf = new uint8[1];
			try {
				size = yield input.read_async (byte_buf, Priority.DEFAULT, cancellable);
			} catch (IOError e) {
				if (e is IOError.CANCELLED) {
					throw new Error.PROCESS_NOT_RESPONDING (
						"Unexpectedly timed out while waiting for FIFO to establish");
				} else {
					Source.remove (timeout);

					throw new Error.PROCESS_NOT_RESPONDING ("%s", e.message);
				}
			}

			Source.remove (timeout);

			if (size == 1 && byte_buf[0] != ProgressMessageType.HELLO)
				throw new Error.PROTOCOL ("Unexpected message received");

			if (size == 0) {
				cancel_request.resolve (true);

				Idle.add (() => {
					ended (IMMEDIATE);
					return false;
				});
			} else {
				monitor.begin ();
			}
		}

		public async void cancel () {
			cancellable.cancel ();

			try {
				yield cancel_request.future.wait_async (null);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}

		private async void monitor () {
			try {
				var unload_policy = UnloadPolicy.IMMEDIATE;

				var byte_buf = new uint8[1];
				var size = yield input.read_async (byte_buf, Priority.DEFAULT, cancellable);
				if (size == 1) {
					unload_policy = (UnloadPolicy) byte_buf[0];

					var tid_buf = new uint8[4];
					yield input.read_all_async (tid_buf, Priority.DEFAULT, cancellable, null);
					var tid = *((uint *) tid_buf);

					yield input.read_async (byte_buf, Priority.DEFAULT, cancellable);

					while (_process_has_thread (pid, tid)) {
						Timeout.add (50, monitor.callback);
						yield;
					}
				}

				ended (unload_policy);
			} catch (GLib.Error e) {
				if (!(e is IOError.CANCELLED))
					ended (IMMEDIATE);
			}

			cancel_request.resolve (true);
		}
	}

	public extern bool _process_has_thread (uint pid, long tid);

	protected enum ProgressMessageType {
		HELLO = 0xff
	}

	protected class StdioPipes : Object {
		public int input {
			get;
			construct;
		}

		public int output {
			get;
			construct;
		}

		public int error {
			get;
			construct;
		}

		public StdioPipes (int input, int output, int error) {
			Object (input: input, output: output, error: error);
		}

		construct {
			try {
				Unix.set_fd_nonblocking (input, true);
				Unix.set_fd_nonblocking (output, true);
				Unix.set_fd_nonblocking (error, true);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}

		~StdioPipes () {
			Posix.close (input);
			Posix.close (output);
			Posix.close (error);
		}
	}
}
```