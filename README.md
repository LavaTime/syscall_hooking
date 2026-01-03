# getdents64 hooking using kprobes

## What does this do?
This is a LKM that hooks getdents64 (get directory entries 64 bit) syscall for hiding files from directory listing of anykind. using kprobe (at the end, since new kernels do not actually use the Syscall table)

## Why did I decide on using kprobe at the end?
Since Linux v6.9 as can be seen in commit 1e3ad78334a69b36e107232e337f9d693dcc9df2 the syscall table is not used anymore, it's there, but is only used for tracing, so patching the address there is not gonna change anything. So we need to change the the switch statement code for jumping to the syscalls.
That requires writing to an eXecuteable page, so requires on multi-core systems to `stop_machine` so basically repeating the whole job of kprobe which does just that.

So, using kprobes, we can hook right before the function call, and right after, and modify the return to hide our file


## How to compile
```bash
make
```

## How to insert
```bash
sudo insmod ./syscall_hooking.c
```

## How to see it working
```bash
echo "pasten" > secret.txt
ls # You will see the secret.txt
<insert LKM like above>
ls # You will not see the secret.txt
<remove LKM like above>
ls # You will see again the secret.txt
```

## How to remove
```bash
sudo rmmod syscall_hooking
```

# IMPORTANT
DO NOT USE FOR MALICIOUS OR ILLEGAL ACTIVIY, I WROTE THIS FOR LEARNING PURPOSES ONLY, AND WILL NOT USE AGAINST ANYONE BUT MYSELF. I DO NOT TAKE RESPONSIABLITY FOR ANY BAD USAGE OF THIS YOU HAVE BEEN WARNED! DON'T BE EVIL :)
