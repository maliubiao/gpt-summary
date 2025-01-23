Response:
### 功能归纳

`gadget.vala` 是 Frida 工具的核心模块之一，主要负责动态插桩（Dynamic Instrumentation）的功能。它通过加载和运行脚本，实现对目标进程的监控、修改和控制。以下是该文件的主要功能：

1. **配置管理 (`Config` 类)**:
   - 负责加载和解析配置文件（如 `config.json`），配置包括交互方式、脚本路径、代码签名策略等。
   - 支持多种交互方式，如脚本加载、监听端口、连接到远程服务器等。

2. **脚本管理 (`ScriptInteraction`, `ScriptDirectoryInteraction` 类)**:
   - 管理单个脚本的加载、运行和监控。
   - 支持脚本目录的监控，自动加载目录下的所有脚本，并根据配置决定是否在脚本变化时重新加载。

3. **进程过滤 (`ProcessFilter` 类)**:
   - 根据可执行文件路径、Bundle ID、Objective-C 类名等条件过滤目标进程。

4. **网络交互 (`SocketInteraction`, `ListenInteraction`, `ConnectInteraction` 类)**:
   - 支持通过 TCP 或 UNIX 套接字与外部工具（如 Frida CLI）进行通信。
   - 提供监听端口、连接到远程服务器等功能。

5. **脚本引擎 (`ScriptEngine` 类)**:
   - 负责脚本的加载、执行和销毁。
   - 支持多种脚本运行时（如 QuickJS 和 V8）。

6. **进程控制 (`Controller` 接口及其实现类)**:
   - 控制目标进程的启动、暂停、恢复和终止。
   - 支持子进程的监控和管理。

7. **调试功能**:
   - 提供调试功能，如断点设置、内存读写、函数调用跟踪等。
   - 支持通过 LLDB 或其他调试工具进行调试。

### 二进制底层与 Linux 内核相关功能

1. **内存操作 (`Gum.MemoryRange`)**:
   - 通过 `Gum` 库操作目标进程的内存，如读取、写入、分配和释放内存。
   - 示例：`Gum.Cloak.add_range(location.range)` 用于隐藏指定内存区域，防止被其他工具检测到。

2. **代码签名 (`Gum.CodeSigningPolicy`)**:
   - 控制代码签名的验证策略，如是否允许未签名的代码执行。
   - 示例：`Gum.Process.set_code_signing_policy(config.code_signing)` 设置代码签名策略。

3. **进程和线程管理**:
   - 通过 `Gum.Process` 和 `Gum.Thread` 管理目标进程和线程，如挂起、恢复、获取线程 ID 等。
   - 示例：`Gum.Process.set_teardown_requirement(config.teardown)` 设置进程的销毁要求。

### LLDB 调试示例

假设我们想要调试 `gadget.vala` 中的 `load` 函数，可以使用以下 LLDB 命令或 Python 脚本：

#### LLDB 命令

```bash
# 启动 LLDB 并附加到目标进程
lldb -p <pid>

# 设置断点
b gadget.vala:load

# 运行到断点
continue

# 查看变量
frame variable

# 单步执行
next

# 继续执行
continue
```

#### LLDB Python 脚本

```python
import lldb

def debug_load_function(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    # 设置断点
    breakpoint = target.BreakpointCreateByLocation("gadget.vala", 1000)  # 假设 load 函数在第 1000 行
    print(f"Breakpoint set at {breakpoint.GetLocationAtIndex(0).GetAddress()}")

    # 运行到断点
    process.Continue()

    # 查看变量
    path_var = frame.FindVariable("path")
    print(f"Path: {path_var.GetSummary()}")

    # 单步执行
    thread.StepOver()

    # 继续执行
    process.Continue()

# 注册命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f debug_load_function debug_load')
```

### 假设输入与输出

#### 输入
- 配置文件 `config.json` 包含以下内容：
  ```json
  {
    "interaction": {
      "type": "script",
      "path": "/path/to/script.js",
      "on_change": "reload"
    },
    "teardown": "minimal",
    "runtime": "v8"
  }
  ```

#### 输出
- Frida 工具加载并执行 `/path/to/script.js` 脚本。
- 如果脚本文件发生变化，Frida 会自动重新加载脚本。
- 工具监听指定端口，等待外部连接。

### 常见使用错误

1. **配置文件路径错误**:
   - 用户提供的配置文件路径不正确，导致 Frida 无法加载配置。
   - 示例：`config.json` 文件不存在或路径错误。

2. **脚本路径错误**:
   - 用户提供的脚本路径不正确，导致 Frida 无法加载脚本。
   - 示例：`/path/to/script.js` 文件不存在或路径错误。

3. **权限不足**:
   - 用户没有足够的权限访问目标进程或文件。
   - 示例：尝试调试系统进程时，未以 root 权限运行 Frida。

4. **脚本语法错误**:
   - 脚本文件包含语法错误，导致 Frida 无法正确解析和执行。
   - 示例：`script.js` 文件中存在未闭合的括号或拼写错误。

### 用户操作步骤

1. **启动 Frida**:
   - 用户通过命令行启动 Frida，并指定目标进程或应用程序。

2. **加载配置文件**:
   - Frida 读取并解析用户提供的配置文件 `config.json`。

3. **加载脚本**:
   - Frida 根据配置文件中的路径加载脚本文件 `script.js`。

4. **执行脚本**:
   - Frida 执行脚本，开始监控和修改目标进程的行为。

5. **监控脚本变化**:
   - 如果配置了 `on_change: reload`，Frida 会监控脚本文件的变化，并在文件修改时自动重新加载脚本。

6. **与外部工具交互**:
   - Frida 监听指定端口，等待外部工具（如 Frida CLI）连接并进行交互。

通过以上步骤，用户可以逐步调试和监控目标进程的行为，并根据需要修改脚本以实现特定的功能。
### 提示词
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/lib/gadget/gadget.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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
namespace Frida.Gadget {
	private class Config : Object, Json.Serializable {
		public Object interaction {
			get;
			set;
			default = new ListenInteraction ();
		}

		public Gum.TeardownRequirement teardown {
			get;
			set;
			default = Gum.TeardownRequirement.MINIMAL;
		}

		public ScriptRuntime runtime {
			get;
			set;
			default = ScriptRuntime.DEFAULT;
		}

		public Gum.CodeSigningPolicy code_signing {
			get;
			set;
			default = Gum.CodeSigningPolicy.OPTIONAL;
		}

		private ObjectClass klass = (ObjectClass) typeof (Config).class_ref ();

		public Json.Node serialize_property (string property_name, GLib.Value value, GLib.ParamSpec pspec) {
			return default_serialize_property (property_name, value, pspec);
		}

		public bool deserialize_property (string property_name, out Value value, ParamSpec pspec, Json.Node property_node) {
			if (property_name == "interaction" && property_node.get_node_type () == Json.NodeType.OBJECT) {
				var interaction_node = property_node.get_object ();
				var interaction_type = interaction_node.get_string_member ("type");
				if (interaction_type != null) {
					Type t = 0;

					switch (interaction_type) {
						case "script":
							t = typeof (ScriptInteraction);
							break;
						case "script-directory":
							t = typeof (ScriptDirectoryInteraction);
							break;
						case "listen":
							t = typeof (ListenInteraction);
							break;
						case "connect":
							t = typeof (ConnectInteraction);
							break;
					}

					if (t != 0) {
						var obj = Json.gobject_deserialize (t, property_node);
						if (obj != null) {
							bool valid = true;

							if (obj is ScriptInteraction) {
								valid = ((ScriptInteraction) obj).path != null;
							} else if (obj is ScriptDirectoryInteraction) {
								valid = ((ScriptDirectoryInteraction) obj).path != null;
							}

							if (valid) {
								var v = Value (t);
								v.set_object (obj);
								value = v;
								return true;
							}
						}
					}
				}
			}

			value = Value (pspec.value_type);
			return false;
		}

		public unowned ParamSpec? find_property (string name) {
			return klass.find_property (name);
		}

		public new Value get_property (ParamSpec pspec) {
			var val = Value (pspec.value_type);
			base.get_property (pspec.name, ref val);
			return val;
		}

		public new void set_property (ParamSpec pspec, Value value) {
			base.set_property (pspec.name, value);
		}
	}

	private class ScriptInteraction : Object, Json.Serializable {
		public string path {
			get;
			set;
			default = null;
		}

		public Json.Node parameters {
			get;
			set;
			default = make_empty_json_object ();
		}

		public Script.ChangeBehavior on_change {
			get;
			set;
			default = Script.ChangeBehavior.IGNORE;
		}

		private ObjectClass klass = (ObjectClass) typeof (ScriptInteraction).class_ref ();

		public Json.Node serialize_property (string property_name, GLib.Value value, GLib.ParamSpec pspec) {
			return default_serialize_property (property_name, value, pspec);
		}

		public bool deserialize_property (string property_name, out Value value, ParamSpec pspec, Json.Node property_node) {
			if (property_name == "parameters" && property_node.get_node_type () == Json.NodeType.OBJECT) {
				var v = Value (typeof (Json.Node));
				v.set_boxed (property_node);
				value = v;
				return true;
			}

			value = Value (pspec.value_type);
			return false;
		}

		public unowned ParamSpec? find_property (string name) {
			return klass.find_property (name);
		}

		public new Value get_property (ParamSpec pspec) {
			var val = Value (pspec.value_type);
			base.get_property (pspec.name, ref val);
			return val;
		}

		public new void set_property (ParamSpec pspec, Value value) {
			base.set_property (pspec.name, value);
		}
	}

	private class ScriptDirectoryInteraction : Object {
		public string path {
			get;
			set;
			default = null;
		}

		public ChangeBehavior on_change {
			get;
			set;
			default = ChangeBehavior.IGNORE;
		}

		public enum ChangeBehavior {
			IGNORE,
			RESCAN
		}
	}

	private class ScriptConfig : Object, Json.Serializable {
		public ProcessFilter? filter {
			get;
			set;
			default = null;
		}

		public Json.Node parameters {
			get;
			set;
			default = make_empty_json_object ();
		}

		public Script.ChangeBehavior on_change {
			get;
			set;
			default = Script.ChangeBehavior.IGNORE;
		}

		private ObjectClass klass = (ObjectClass) typeof (ScriptConfig).class_ref ();

		public Json.Node serialize_property (string property_name, GLib.Value value, GLib.ParamSpec pspec) {
			return default_serialize_property (property_name, value, pspec);
		}

		public bool deserialize_property (string property_name, out Value value, ParamSpec pspec, Json.Node property_node) {
			if (property_name == "parameters" && property_node.get_node_type () == Json.NodeType.OBJECT) {
				var v = Value (typeof (Json.Node));
				v.set_boxed (property_node.copy ());
				value = v;
				return true;
			}

			value = Value (pspec.value_type);
			return false;
		}

		public unowned ParamSpec? find_property (string name) {
			return klass.find_property (name);
		}

		public new Value get_property (ParamSpec pspec) {
			var val = Value (pspec.value_type);
			base.get_property (pspec.name, ref val);
			return val;
		}

		public new void set_property (ParamSpec pspec, Value value) {
			base.set_property (pspec.name, value);
		}
	}

	private class ProcessFilter : Object {
		public string[] executables {
			get;
			set;
			default = new string[0];
		}

		public string[] bundles {
			get;
			set;
			default = new string[0];
		}

		public string[] objc_classes {
			get;
			set;
			default = new string[0];
		}
	}

	private abstract class SocketInteraction : Object {
		public string? address {
			get;
			set;
		}

		public uint16 port {
			get;
			set;
		}

		public string? certificate {
			get;
			set;
		}

		public string? token {
			get;
			set;
		}
	}

	private class ListenInteraction : SocketInteraction {
		public PortConflictBehavior on_port_conflict {
			get;
			set;
			default = PortConflictBehavior.FAIL;
		}

		public LoadBehavior on_load {
			get;
			set;
			default = LoadBehavior.WAIT;
		}

		public enum LoadBehavior {
			RESUME,
			WAIT
		}

		public string? origin {
			get;
			set;
		}

		public string? asset_root {
			get;
			set;
		}
	}

	private class ConnectInteraction : SocketInteraction, Json.Serializable {
		public string[]? acl {
			get;
			set;
		}

		public Json.Node parameters {
			get;
			set;
			default = make_empty_json_object ();
		}

		private ObjectClass klass = (ObjectClass) typeof (ConnectInteraction).class_ref ();

		public bool deserialize_property (string property_name, out Value value, ParamSpec pspec, Json.Node property_node) {
			if (property_name == "parameters" && property_node.get_node_type () == Json.NodeType.OBJECT) {
				var v = Value (typeof (Json.Node));
				v.set_boxed (property_node);
				value = v;
				return true;
			}

			value = Value (pspec.value_type);
			return false;
		}

		public unowned ParamSpec? find_property (string name) {
			return klass.find_property (name);
		}

		public new Value get_property (ParamSpec pspec) {
			var val = Value (pspec.value_type);
			base.get_property (pspec.name, ref val);
			return val;
		}

		public new void set_property (ParamSpec pspec, Value value) {
			base.set_property (pspec.name, value);
		}
	}

	private class Location : Object {
		public string executable_name {
			get;
			construct;
		}

		public string? bundle_id {
			get {
				if (!did_fetch_bundle_id) {
					cached_bundle_id = Environment.detect_bundle_id ();
					did_fetch_bundle_id = true;
				}
				return cached_bundle_id;
			}
		}

		public string? bundle_name {
			get {
				if (!did_fetch_bundle_name) {
					cached_bundle_name = Environment.detect_bundle_name ();
					did_fetch_bundle_name = true;
				}
				return cached_bundle_name;
			}
		}

		public string? path {
			get;
			construct;
		}

		public string? asset_dir {
			get {
				if (!did_compute_asset_dir) {
					string? gadget_path = path;
					if (gadget_path != null) {
						string? dir = null;
#if DARWIN
						dir = try_derive_framework_resource_dir_from_module_path (gadget_path);
#endif
						if (dir == null)
							dir = Path.get_dirname (gadget_path);
						cached_asset_dir = dir;
					}
					did_compute_asset_dir = true;
				}
				return cached_asset_dir;
			}
		}

		public Gum.MemoryRange range {
			get;
			construct;
		}

		private bool did_fetch_bundle_id = false;
		private string? cached_bundle_id = null;

		private bool did_fetch_bundle_name = false;
		private string? cached_bundle_name = null;

		private bool did_compute_asset_dir = false;
		private string? cached_asset_dir = null;

		public Location (string executable_name, string? path, Gum.MemoryRange range) {
			Object (
				executable_name: executable_name,
				path: path,
				range: range
			);
		}

#if ANDROID
		construct {
			if (executable_name.has_prefix ("app_process")) {
				try {
					string cmdline;
					FileUtils.get_contents ("/proc/self/cmdline", out cmdline);
					if (cmdline != "zygote" && cmdline != "zygote64") {
						executable_name = cmdline;

						cached_bundle_id = cmdline.split (":", 2)[0];
						cached_bundle_name = cached_bundle_id;
						did_fetch_bundle_id = true;
						did_fetch_bundle_name = true;
					}
				} catch (FileError e) {
				}
			}
		}
#endif

		public string resolve_asset_path (string asset_path) {
			if (!Path.is_absolute (asset_path)) {
				string? dir = asset_dir;
				if (dir != null)
					return Path.build_filename (dir, asset_path);
			}

			return asset_path;
		}
	}

	private enum State {
		CREATED,
		STARTED,
		STOPPED,
		DETACHED
	}

	private bool loaded = false;
	private State state = State.CREATED;
	private Config? config;
	private Location? location;
	private bool wait_for_resume_needed;
	private MainLoop? wait_for_resume_loop;
	private MainContext? wait_for_resume_context;
	private ThreadIgnoreScope? worker_ignore_scope;
	private Controller? controller;
	private Gum.Interceptor? interceptor;
	private Gum.Exceptor? exceptor;
	private Mutex mutex;
	private Cond cond;

	public void load (Gum.MemoryRange? mapped_range, string? config_data, int * result) {
		if (loaded)
			return;
		loaded = true;

		Environment.init ();

		Gee.Promise<int>? request = null;
		if (result != null)
			request = new Gee.Promise<int> ();

		location = detect_location (mapped_range);

		try {
			config = (config_data != null)
				? parse_config (config_data)
				: load_config (location);
		} catch (Error e) {
			log_warning (e.message);
			return;
		}

		Gum.Process.set_teardown_requirement (config.teardown);
		Gum.Process.set_code_signing_policy (config.code_signing);

		Gum.Cloak.add_range (location.range);

		interceptor = Gum.Interceptor.obtain ();
		interceptor.begin_transaction ();
		exceptor = Gum.Exceptor.obtain ();

		try {
			var interaction = config.interaction;
			if (interaction is ScriptInteraction) {
				controller = new ScriptRunner (config, location);
			} else if (interaction is ScriptDirectoryInteraction) {
				controller = new ScriptDirectoryRunner (config, location);
			} else if (interaction is ListenInteraction) {
				controller = new ControlServer (config, location);
			} else if (interaction is ConnectInteraction) {
				controller = new ClusterClient (config, location);
			} else {
				throw new Error.NOT_SUPPORTED ("Invalid interaction specified");
			}
		} catch (Error e) {
			resume ();

			if (request != null) {
				request.set_exception (e);
			} else {
				log_warning ("Failed to start: " + e.message);
			}
		}

		interceptor.end_transaction ();

		if (controller == null)
			return;

		wait_for_resume_needed = true;

		var listen_interaction = config.interaction as ListenInteraction;
		if (listen_interaction != null && listen_interaction.on_load == ListenInteraction.LoadBehavior.RESUME) {
			wait_for_resume_needed = false;
		}

		if (!wait_for_resume_needed)
			resume ();

		if (wait_for_resume_needed && Environment.can_block_at_load_time ()) {
			var scheduler = Gum.ScriptBackend.get_scheduler ();

			scheduler.disable_background_thread ();

			wait_for_resume_context = scheduler.get_js_context ();

			var ignore_scope = new ThreadIgnoreScope (APPLICATION_THREAD);

			start (request);

			var loop = new MainLoop (wait_for_resume_context, true);
			wait_for_resume_loop = loop;

			wait_for_resume_context.push_thread_default ();
			loop.run ();
			wait_for_resume_context.pop_thread_default ();

			scheduler.enable_background_thread ();

			ignore_scope = null;
		} else {
			start (request);
		}

		if (result != null) {
			try {
				*result = request.future.wait ();
			} catch (Gee.FutureError e) {
				*result = -1;
			}
		}
	}

	public void wait_for_permission_to_resume () {
		mutex.lock ();
		while (state != State.STARTED)
			cond.wait (mutex);
		mutex.unlock ();
	}

	public void unload () {
		if (!loaded)
			return;
		loaded = false;

		{
			var source = new IdleSource ();
			source.set_callback (() => {
				stop.begin ();
				return false;
			});
			source.attach (Environment.get_worker_context ());
		}

		State final_state;
		mutex.lock ();
		while (state < State.STOPPED)
			cond.wait (mutex);
		final_state = state;
		mutex.unlock ();

		if (final_state == DETACHED)
			return;

		if (config.teardown == Gum.TeardownRequirement.FULL) {
			config = null;

			invalidate_dbus_context ();

			Environment.deinit ();
		}
	}

	public void resume () {
		mutex.lock ();
		if (state != State.CREATED) {
			mutex.unlock ();
			return;
		}
		state = State.STARTED;
		cond.signal ();
		mutex.unlock ();

		if (wait_for_resume_context != null) {
			var source = new IdleSource ();
			source.set_callback (() => {
				wait_for_resume_loop.quit ();
				return false;
			});
			source.attach (wait_for_resume_context);
		}
	}

	public void kill () {
		kill_process (get_process_id ());
	}

	private State peek_state () {
		State result;

		mutex.lock ();
		result = state;
		mutex.unlock ();

		return result;
	}

	private void start (Gee.Promise<int>? request) {
		var source = new IdleSource ();
		source.set_callback (() => {
			perform_start.begin (request);
			return false;
		});
		source.attach (Environment.get_worker_context ());
	}

	private async void perform_start (Gee.Promise<int>? request) {
		worker_ignore_scope = new ThreadIgnoreScope (FRIDA_THREAD);

		try {
			yield controller.start ();

			var server = controller as ControlServer;
			if (server != null) {
				var listen_address = server.listen_address;
				var inet_address = listen_address as InetSocketAddress;
				if (inet_address != null) {
					uint16 listen_port = inet_address.get_port ();
					Environment.set_thread_name ("frida-gadget-tcp-%u".printf (listen_port));
					if (request != null) {
						request.set_value (listen_port);
					} else {
						log_info ("Listening on %s TCP port %u".printf (
							inet_address.get_address ().to_string (),
							listen_port));
					}
				} else {
#if !WINDOWS
					var unix_address = (UnixSocketAddress) listen_address;
					Environment.set_thread_name ("frida-gadget-unix");
					if (request != null) {
						request.set_value (0);
					} else {
						log_info ("Listening on UNIX socket at “%s”".printf (unix_address.get_path ()));
					}
#else
					assert_not_reached ();
#endif
				}
			} else {
				if (request != null)
					request.set_value (0);
			}
		} catch (GLib.Error e) {
			resume ();

			if (request != null) {
				request.set_exception (e);
			} else {
				log_warning ("Failed to start: " + e.message);
			}
		}
	}

	private async void stop () {
		State pending_state = STOPPED;

		if (controller != null) {
			if (controller.is_eternal) {
				pending_state = DETACHED;
			} else {
				if (config.teardown == Gum.TeardownRequirement.MINIMAL) {
					yield controller.prepare_for_termination (TerminationReason.EXIT);
				} else {
					yield controller.stop ();
					controller = null;

					exceptor = null;
					interceptor = null;
				}
			}
		}

		if (pending_state == STOPPED)
			worker_ignore_scope = null;

		mutex.lock ();
		state = pending_state;
		cond.signal ();
		mutex.unlock ();
	}

	private Config load_config (Location location) throws Error {
		unowned string? gadget_path = location.path;
		if (gadget_path == null)
			return new Config ();

		string? config_path = null;
#if DARWIN
		string? resource_dir = try_derive_framework_resource_dir_from_module_path (gadget_path);
		if (resource_dir != null)
			config_path = Path.build_filename (resource_dir, "config.json");
#endif
		if (config_path == null)
			config_path = derive_config_path_from_file_path (gadget_path);

#if IOS || TVOS
		if (resource_dir == null && !FileUtils.test (config_path, FileTest.EXISTS)) {
			var config_dir = Path.get_dirname (config_path);
			if (Path.get_basename (config_dir) == "Frameworks") {
				var app_dir = Path.get_dirname (config_dir);
				config_path = Path.build_filename (app_dir, Path.get_basename (config_path));
			}
		}
#endif

#if ANDROID
		if (!FileUtils.test (config_path, FileTest.EXISTS)) {
			var ext_index = config_path.last_index_of_char ('.');
			if (ext_index != -1) {
				config_path = config_path[0:ext_index] + ".config.so";
			} else {
				config_path = config_path + ".config.so";
			}
		}
#endif

		string config_data;
		try {
			load_asset_text (config_path, out config_data);
		} catch (FileError e) {
			if (e is FileError.NOENT)
				return new Config ();
			throw new Error.PERMISSION_DENIED ("%s", e.message);
		}

		try {
			return Json.gobject_from_data (typeof (Config), config_data) as Config;
		} catch (GLib.Error e) {
			throw new Error.INVALID_ARGUMENT ("Invalid config: %s", e.message);
		}
	}

	private Config parse_config (string config_data) throws Error {
		try {
			return Json.gobject_from_data (typeof (Config), config_data) as Config;
		} catch (GLib.Error e) {
			throw new Error.INVALID_ARGUMENT ("Invalid config: %s", e.message);
		}
	}

	private Location detect_location (Gum.MemoryRange? mapped_range) {
		string? executable_name = null;
		string? executable_path = null;
		Gum.MemoryRange? executable_range = null;
		string? our_path = null;
		Gum.MemoryRange? our_range = mapped_range;

		Gum.Address our_address = Gum.Address.from_pointer (Gum.strip_code_pointer ((void *) detect_location));

		var index = 0;
		Gum.Process.enumerate_modules ((details) => {
			var range = details.range;

			if (index == 0) {
				executable_name = details.name;
				executable_path = details.path;
				executable_range = details.range;
			}

			if (mapped_range != null)
				return false;

			if (our_address >= range.base_address && our_address < range.base_address + range.size) {
				our_path = details.path;
				our_range = range;
				return false;
			}

			index++;

			return true;
		});

		assert (our_range != null);

		return new Location (executable_name, our_path, our_range);
	}

	private interface Controller : Object {
		public abstract bool is_eternal {
			get;
		}

		public abstract async void start () throws Error, IOError;
		public abstract async void prepare_for_termination (TerminationReason reason);
		public abstract async void stop ();
	}

	private abstract class BaseController : Object, Controller, ProcessInvader, ExitHandler {
		public bool is_eternal {
			get {
				return _is_eternal;
			}
		}
		protected bool _is_eternal = false;

		public Config config {
			get;
			construct;
		}

		public Location location {
			get;
			construct;
		}

		private ExitMonitor exit_monitor;
		private ThreadSuspendMonitor thread_suspend_monitor;
		private UnwindSitter unwind_sitter;

		private Gum.ScriptBackend? qjs_backend;
		private Gum.ScriptBackend? v8_backend;

		private Gee.Map<PortalMembershipId?, PortalClient> portal_clients =
			new Gee.HashMap<PortalMembershipId?, PortalClient> (PortalMembershipId.hash, PortalMembershipId.equal);
		private uint next_portal_membership_id = 1;

		construct {
			exit_monitor = new ExitMonitor (this, MainContext.default ());
			thread_suspend_monitor = new ThreadSuspendMonitor (this);
			unwind_sitter = new UnwindSitter (this);
		}

		public async void start () throws Error, IOError {
			yield on_start ();
		}

		protected abstract async void on_start () throws Error, IOError;

		public async void prepare_for_termination (TerminationReason reason) {
			yield on_terminate (reason);
		}

		protected abstract async void on_terminate (TerminationReason reason);

		public async void stop () {
			yield on_stop ();
		}

		protected abstract async void on_stop ();

		protected SpawnStartState query_current_spawn_state () {
			return (peek_state () == CREATED)
				? SpawnStartState.SUSPENDED
				: SpawnStartState.RUNNING;
		}

		protected Gum.MemoryRange get_memory_range () {
			return location.range;
		}

		protected Gum.ScriptBackend get_script_backend (ScriptRuntime runtime) throws Error {
			switch (runtime) {
				case DEFAULT:
					var config_runtime = config.runtime;
					if (config_runtime != DEFAULT)
						return get_script_backend (config_runtime);
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

		protected Gum.ScriptBackend? get_active_script_backend () {
			return (v8_backend != null) ? v8_backend : qjs_backend;
		}

		protected void acquire_child_gating () throws Error {
			throw new Error.NOT_SUPPORTED ("Not yet implemented");
		}

		protected void release_child_gating () {
		}

		protected async PortalMembershipId join_portal (string address, PortalOptions options,
				Cancellable? cancellable) throws Error, IOError {
			var client = new PortalClient (this, parse_cluster_address (address), address, options.certificate, options.token,
				options.acl, compute_app_info ());
			client.eternalized.connect (on_eternalized);
			client.resume.connect (Frida.Gadget.resume);
			client.kill.connect (Frida.Gadget.kill);
			yield client.start (cancellable);

			var id = PortalMembershipId (next_portal_membership_id++);
			portal_clients[id] = client;

			_is_eternal = true;

			return id;
		}

		protected async void leave_portal (PortalMembershipId membership_id, Cancellable? cancellable) throws Error, IOError {
			PortalClient client;
			if (!portal_clients.unset (membership_id, out client))
				throw new Error.INVALID_ARGUMENT ("Invalid membership ID");

			yield client.stop (cancellable);
		}

		private void on_eternalized () {
			_is_eternal = true;
		}

		private bool supports_async_exit () {
			// Avoid deadlocking in case a fork() happened that we weren't made aware of.
			return Gum.Process.has_thread (Environment.get_worker_tid ());
		}

		protected async void prepare_to_exit () {
			yield on_terminate (TerminationReason.EXIT);
		}

		protected void prepare_to_exit_sync () {
		}

		protected virtual HostApplicationInfo compute_app_info () {
			string identifier = location.bundle_id;
			if (identifier == null)
				identifier = get_executable_path ();

			string name = location.bundle_name;
			if (name == null)
				name = Path.get_basename (get_executable_path ());

			uint pid = get_process_id ();

			var info = HostApplicationInfo (identifier, name, pid, make_parameters_dict ());
			info.parameters["system"] = compute_system_parameters ();

			return info;
		}
	}

	private class ScriptRunner : BaseController {
		private ScriptEngine engine;
		private Script script;

		public ScriptRunner (Config config, Location location) {
			Object (config: config, location: location);
		}

		construct {
			engine = new ScriptEngine (this);

			var path = resolve_script_path (config, location);
			var interaction = config.interaction as ScriptInteraction;
			script = new Script (path, interaction.parameters, interaction.on_change, engine);
		}

		protected override async void on_start () throws Error, IOError {
			yield script.start ();

			Frida.Gadget.resume ();
		}

		protected override async void on_terminate (TerminationReason reason) {
			yield script.prepare_for_termination (reason);
		}

		protected override async void on_stop () {
			yield script.stop ();

			yield engine.close ();
		}

		private static string resolve_script_path (Config config, Location location) {
			var raw_path = ((ScriptInteraction) config.interaction).path;

			if (!Path.is_absolute (raw_path)) {
				string? documents_dir = Environment.detect_documents_dir ();
				if (documents_dir != null) {
					var script_path = Path.build_filename (documents_dir, raw_path);
					if (FileUtils.test (script_path, FileTest.EXISTS))
						return script_path;
				}
			}

			return location.resolve_asset_path (raw_path);
		}
	}

	private class ScriptDirectoryRunner : BaseController {
		public string directory_path {
			get;
			construct;
		}

		private ScriptEngine engine;
		private Gee.HashMap<string, Script> scripts = new Gee.HashMap<string, Script> ();
		private bool scan_in_progress = false;
		private GLib.FileMonitor monitor;
		private Source unchanged_timeout;

		public ScriptDirectoryRunner (Config config, Location location) {
			Object (
				config: config,
				location: location,
				directory_path: location.resolve_asset_path (((ScriptDirectoryInteraction) config.interaction).path)
			);
		}

		construct {
			engine = new ScriptEngine (this);
		}

		protected override async void on_start () throws Error, IOError {
			var interaction = config.interaction as ScriptDirectoryInteraction;

			if (interaction.on_change == ScriptDirectoryInteraction.ChangeBehavior.RESCAN) {
				try {
					var path = directory_path;
					var monitor = File.new_for_path (path).monitor_directory (FileMonitorFlags.NONE);
					monitor.changed.connect (on_file_changed);
					this.monitor = monitor;
				} catch (GLib.Error e) {
					log_warning ("Failed to watch directory: " + e.message);
				}
			}

			yield scan ();

			Frida.Gadget.resume ();
		}

		protected override async void on_terminate (TerminationReason reason) {
			foreach (var script in scripts.values.to_array ())
				yield script.prepare_for_termination (reason);
		}

		protected override async void on_stop () {
			if (monitor != null) {
				monitor.changed.disconnect (on_file_changed);
				monitor.cancel ();
				monitor = null;
			}

			foreach (var script in scripts.values.to_array ())
				yield script.stop ();
			scripts.clear ();

			yield engine.close ();
		}

		private async void scan () throws Error {
			scan_in_progress = true;

			try {
				var directory_path = this.directory_path;

				Dir dir;
				try {
					dir = Dir.open (directory_path);
				} catch (FileError e) {
					return;
				}

				string? name;
				var names_seen = new Gee.HashSet<string> ();
				while ((name = dir.read_name ()) != null) {
					if (name[0] == '.' || !name.has_suffix (".js"))
						continue;

					names_seen.add (name);

					var script_path = Path.build_filename (directory_path, name);
					var config_path = derive_config_path_from_file_path (script_path);

					try {
						var config = load_config (config_path);

						var matches_filter = current_process_matches (config.filter);
						if (matches_filter) {
							var script = scripts[name];
							var parameters = config.parameters;
							var on_change = config.on_change;

							if (script != null && (!script.parameters.equal (parameters) ||
									script.on_change != on_change)) {
								yield script.stop ();
								script = null;
							}

							if (script == null) {
								script = new Script (script_path, parameters, on_change, engine);
								yield script.start ();
							}

							scripts[name] = script;
						}

						Script script = null;
						if (!matches_filter && scripts.unset (name, out script)) {
							yield script.stop ();
						}
					} catch (Error e) {
						log_warning ("Skipping %s: %s".printf (name, e.message));
						continue;
					}
				}

				foreach (var script_name in scripts.keys.to_array ()) {
					var deleted = !names_seen.contains (script_name);
					if (deleted) {
						Script script;
						scripts.unset (script_name, out script);
						yield script.stop ();
					}
				}
			} finally {
				scan_in_progress = false;
			}
		}

		private bool current_process_matches (ProcessFilter? filter) {
			if (filter == null)
				return true;

			var executables = filter.executables;
			var num_executables = executables.length;
			if (num_executables > 0) {
				var executable_name = location.executable_name;

				for (var index = 0; index != num_executables; index++) {
					if (executables[index] == executable_name)
						return true;
				}
			}

			var bundles = filter.bundles;
			var num_bundles = bundles.length;
			if (num_bundles > 0) {
				var bundle_id = location.bundle_id;
				if (bundle_id != null) {
					for (var index = 0; index != num_bundles; index++) {
						if (bundles[index] == bundle_id)
							return true;
					}
				}
			}

			var classes = filter.objc_classes;
			var num_classes = classes.length;
			for (var index = 0; index != num_classes; index++) {
				if (Environment.has_objc_class (classes[index]))
					return true;
			}

			return false;
		}

		private void on_file_changed (File file, File? other_file, FileMonitorEvent event_type) {
			if (event_type == FileMonitorEvent.CHANGES_DONE_HINT)
				return;

			var source = new TimeoutSource (50);
			source.set_callback (() => {
				if (scan_in_progress)
					return true;
				scan.begin ();
				return false;
			});
			source.attach (Environment.get_worker_context ());

			if (unchanged_timeout != null)
				unchanged_timeout.destroy ();
			unchanged_timeout = source;
		}

		private ScriptConfig load_config (string path) throws Error {
			string data;
			try {
				load_asset_text (path, out data);
			} catch (FileError e) {
				if (e is FileError.NOENT)
					return new ScriptConfig ();
				throw new Error.PERMISSION_DENIED ("%s", e.message);
			}

			try {
				return Json.gobject_from_data (typeof (ScriptConfig), data) as ScriptConfig;
			} catch (GLib.Error e) {
				throw new Error.INVALID_ARGUMENT ("Invalid config: %s", e.message);
			}
		}
	}

	private class Script : Object, RpcPeer {
		private const uint8 QUICKJS_BYTECODE_MAGIC = 0x02;

		public enum ChangeBehavior {
			IGNORE,
			RELOAD
		}

		public signal void message (string json, Bytes? data);

		public string path {
			get;
			construct;
		}

		public Json.Node parameters {
			get;
			construct;
		}

		public ChangeBehavior on_change {
			get;
			construct;
		}

		public ScriptEngine engine {
			get;
			construct;
		}

		private AgentScriptId id;
		private bool load_in_progress = false;
		private GLib.FileMonitor monitor;
		private Source unchanged_timeout;
		private RpcClient rpc_client;

		public Script (string path, Json.Node parameters, ChangeBehavior on_change, ScriptEngine engine) {
			Object (
				path: path,
				parameters: parameters,
				on_change: on_change,
				engine: engine
			);
		}

		construct {
			rpc_client = new RpcClient (this);
		}

		public async void start () throws Error {
			engine.message_from_script.connect (on_message);

			if (on_change == ChangeBehavior.RELOAD) {
				try {
					var monitor = File.new_for_path (path).monitor_file (FileMonitorFlags.NONE);
					monitor.changed.connect (on_file_changed);
					this.monitor = monitor;
				} catch (GLib.Error e) {
					log_warning ("Failed to watch %s: %s".printf (path, e.message));
				}

				yield try_reload ();
			} else {
				try {
					yield load ();
				} catch (Error e) {
					engine.message_from_script.disconnect (on_message);
					throw e;
				}
			}
		}

		public async void prepare_for_termination (TerminationReason reason) {
			yield engine.prepare_for_termination (reason);
		}

		public async void stop () {
			if (monitor != null) {
				monitor.changed.disconnect (on_file_changed);
				monitor.cancel ();
				monitor = null;
			}

			if (id.handle != 0) {
				try {
					yield engine.destroy_script (id);
				} catch (Error e) {
				}
				id = AgentScriptId (0);
			}

			engine.message_from_script.disconnect (on_message);
		}

		private async void try_reload () {
			try {
				yield load ();
			} catch (Error e) {
				log_warning ("Failed to load %s: %s".printf (path, e.message));
			}
		}

		private async void load () throws Error {
			load_in_pro
```