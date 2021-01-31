## gef 修改

主要是在 `heap bins` 的过程中记录了处于 `free` 状态的 `chunk`, 然后在 `heap chunks`的时候显示出来


```
heap bins
heap chunks

# 打印记录的free chunk 的地址
gef-config-freelist show  

# 清除记录的 free chunk 地址列表
gef-config-freelist clean

```



## heaptrace.py 

通过断点来 hook 堆分配函数，获取内存分配的调用栈和返回的地址


```
dump-trace-log json out.txt
把记录的堆分配日志保存json到 out.txt

dump-trace-log
打印剩余没有分配内存的调用栈信息
```

## 插件联动

首先让 `gef` 加载记录的堆日志

```
dump-trace-log json out.txt
gef-load-heaptrace out.txt
```

然后使用 `heap chunks` 就可以在打印 `chunk` 时把处于使用状态的 `chunk` 的调用栈打印出来

示例输出

```
Chunk(addr=0x55f2b9ecc490, size=0x50, flags=)

    [alloc backtrace]
    #0  0x00007f58beeee674 in sudoersensure_buffer_stack () at toke.c:4371
    #1  0x00007f58beeee70d in sudoers_switch_to_buffer (new_buffer=0x55f2b9ec8430) at toke.c:3857
    #2  0x00007f58beeeeaec in push_include_int (path=0x55f2b9ecf394 "/etc/sudoers.d/README", path@entry=0x55f2b9ec6ea4 "", isdir=isdir@entry=true) at toke.l:1019
    #3  0x00007f58beef08af in sudoerslex () at toke.l:323
    #4  0x00007f58beee3d0d in sudoersparse () at gram.c:1149
    #5  0x00007f58beec601b in sudo_file_parse (nss=0x7f58bef0d980 <sudo_nss_file>) at ../../../plugins/sudoers/file.c:114
    #6  0x00007f58beed9016 in sudoers_policy_init (info=info@entry=0x7ffdd89d96f0, envp=envp@entry=0x7ffdd89d9a10) at ../../../plugins/sudoers/sudoers.c:204
    #7  0x00007f58beed36eb in sudoers_policy_open (version=<optimized out>, conversation=<optimized out>, plugin_printf=<optimized out>, settings=0x55f2b9ebbeb0, user_info=0x55f2b9eb9820, envp=0x7ffdd89d9a10, args=0x0) at ../../../plugins/sudoers/policy.c:797
    #8  0x000055f2b8250b42 in policy_open (plugin=0x55f2b82717a0 <policy_plugin>, user_env=0x7ffdd89d9a10, user_info=0x55f2b9eb9820, settings=<optimized out>) at ../../src/sudo.c:1084
    #9  main (argc=<optimized out>, argv=<optimized out>, envp=0x7ffdd89d9a10) at ../../src/sudo.c:217
    

    [0x000055f2b9ecc490     70 93 eb b9 f2 55 00 00 00 00 00 00 00 00 00 00    p....U..........]
Chunk(addr=0x55f2b9ecc4e0, size=0x2da0, flags=PREV_INUSE, FREE_CHUNK)
```



