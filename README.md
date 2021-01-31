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
