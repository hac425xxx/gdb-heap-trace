import gdb
import binascii


def hex_decode(hex_string):
    return binascii.a2b_hex(hex_string)


def hex_encode(raw):
    return binascii.b2a_hex(raw)


def parse_number(v):
    ret = string_to_number(v)
    return ret


def cached_lookup_type(_type):
    try:
        return gdb.lookup_type(_type).strip_typedefs()
    except RuntimeError:
        return None


def get_memory_alignment(in_bits=False):
    res = cached_lookup_type("size_t")
    if res is not None:
        return res.sizeof if not in_bits else res.sizeof * 8
    try:
        return gdb.parse_and_eval("$pc").type.sizeof
    except:
        pass
    raise EnvironmentError("GEF is running under an unsupported mode")


def string_to_number(s):
    ret = 0
    try:
        try:
            ret = long(s)
        except:
            ret = long(s, 16)
    except:
        try:
            ret = int(s)
        except:
            ret = int(s, 16)

    pointer_size = get_memory_alignment()
    if pointer_size == 4:
        ret = ret & 0xffffffff
    elif pointer_size == 8:
        ret = ret & 0xffffffffffffffff
    else:
        raise Exception(
            "string_to_number: Unknown pointer size: {}".format(pointer_size))
    return ret


def write_memory(addr, buf, size):
    inferior = gdb.selected_inferior()
    return inferior.write_memory(addr, buf, size)


def read_memory(addr, size):
    inferior = gdb.selected_inferior()
    mem = inferior.read_memory(addr, size)
    # print(type(mem))
    # print(dir(mem))
    ret = ""
    try:
        ret = mem.tobytes()
    except:
        ret = str(mem)
    return ret


def read_register(name):
    value = gdb.parse_and_eval("${}".format(name))
    ret = string_to_number(value)
    return ret


def get_backtrace():
    gdb.execute("bt 20")
    print("\n\n\n")




# http://sourceware.org/gdb/current/onlinedocs/gdb/Breakpoints-In-Python.html
class FunctionReturnValueBreakpoint(gdb.Breakpoint):
    def __init__(self, name, func_name, heap_trace_info):
        super(FunctionReturnValueBreakpoint, self).__init__(
            name, gdb.BP_BREAKPOINT, internal=False, temporary=True)
        # self.func_result_dict = func_result_dict
        self.func_name = func_name
        self.is_trigger = False

        self.heap_trace_info = heap_trace_info

    def stop(self):
        ret = read_register("rax")
        print("\n{} return: 0x{:x}".format(self.func_name, ret))

        self.heap_trace_info[ret] = {}
        self.heap_trace_info[ret]['backtrace'] = gdb.execute("bt", to_string=True)

        get_backtrace()
        print("\n\n")

        self.is_trigger = True
        return False

    def is_executed(self):
        return self.is_trigger




class AllocFunction(gdb.Breakpoint):
    def __init__(self, name, func_name, heap_trace_info):
        super(AllocFunction, self).__init__(
            name, gdb.BP_BREAKPOINT, internal=False)
        self.hitcount = 0
        self.func_name = func_name
        self.last_return_bp = None
        self.heap_trace_info = heap_trace_info

        self.return_value_bp_list = []

    def stop(self):
        if self.last_return_bp != None:
            self.last_return_bp.delete()

        delete_list = []

        for bp in self.return_value_bp_list:
            if bp.is_executed():
                delete_list.append(bp)
        
        for bp in delete_list:
            bp.delete()
            self.return_value_bp_list.remove(bp)


        sz = 0
        if self.func_name == "malloc":
            sz = read_register("rdi")
        elif self.func_name == "calloc":
            sz = read_register("rdi") * read_register("rsi")
        elif self.func_name == "realloc":
            ptr = read_register("rdi")
            sz = read_register("rsi")

            if ptr in self.heap_trace_info:
                del self.heap_trace_info[ptr]


        current_frame = gdb.selected_frame()
        caller = current_frame.older().pc()

        print("[{}] size: 0x{:x}, caller:0x{:x}\n".format(self.func_name, sz, caller))
        bp = FunctionReturnValueBreakpoint("*0x{:x}".format(caller), self.func_name, self.heap_trace_info)
        self.return_value_bp_list.append(bp)


        return False


class FreeFunction(gdb.Breakpoint):
    def __init__(self, name, heap_trace_info):
        super(FreeFunction, self).__init__(
            name, gdb.BP_BREAKPOINT, internal=False)
        
        self.heap_trace_info = heap_trace_info

    def stop(self):
        rdi = read_register("rdi")
        if rdi in self.heap_trace_info:
            print("free: 0x{:X}".format(rdi))
            get_backtrace()

            # self.heap_trace_info.remove(rdi)
            del self.heap_trace_info[rdi]

        return False



class DumpTraceLog(gdb.Command):
  def __init__(self, heap_trace_info):
    super(DumpTraceLog, self).__init__("dump-trace-log", gdb.COMMAND_USER)
    self.heap_trace_info = heap_trace_info

  def invoke(self, arg, from_tty):
    print("*" * 8 + "heap trace log" + "*" * 8)
    for k, v in self.heap_trace_info.items():
        print("\n")
        print("[ 0x{:x} ]".format(k))
        print("[ backtrace ]")
        print(v['backtrace'])





gdb.execute("set confirm off")
gdb.execute("set history save on")
gdb.execute("set pagination off")
gdb.execute("set verbose off")
gdb.execute("handle SIGALRM print nopass")
try:
    gdb.execute("set disable-randomization on")
    # this will raise a gdb.error unless we're on x86
    gdb.execute("set disassembly-flavor intel")
except gdb.error:
    # we can safely ignore this
    pass


gdb.execute("b main")
gdb.execute("r")

gdb.execute("set logging file dbg.txt")
gdb.execute("set logging on")
gdb.execute("set logging overwrite on")
gdb.execute("set logging redirect on")

heap_trace_info = {}



AllocFunction("*__GI___libc_realloc", "realloc", heap_trace_info)
AllocFunction("*__GI___libc_malloc", "malloc", heap_trace_info)
AllocFunction("*__libc_calloc", "calloc", heap_trace_info)


FreeFunction("*__GI___libc_free", heap_trace_info)

DumpTraceLog(heap_trace_info)


gdb.execute("c")

gdb.execute("source /home/hac425/.gdbinit-gef.py")

