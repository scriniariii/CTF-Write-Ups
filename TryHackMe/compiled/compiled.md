hi, here is how i successfully solved the ctf https://tryhackme.com/room/compiled
![compiled](https://github.com/user-attachments/assets/97a82e83-21db-4c6a-8566-c36e73f9b14d)
<br><br><br>


# Extracting Strings
Normally, the first step in parsing a binary is to use the strings command to extract readable text that might reveal useful information, such as format strings, function names and error messages.

Since the machine description explicitly states that strings would not reveal much, I did not expect to find anything significant. However, running the command still provided a few useful hints
<pre><code>> strings compiled.md Compiled-1688545393558.Compiled 
/lib64/ld-linux-x86-64.so.2
jKUhR
__cxa_finalize
__libc_start_main
strcmp
stdout
__isoc99_scanf
fwrite
printf
libc.so.6
GLIBC_2.7
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
StringsIH
sForNoobH
Password: 
DoYouEven%sCTF
__dso_handle
_init
Correct!
Try again!
;*3$"
GCC: (Debian 11.3.0-5) 11.3.0
Scrt1.o
__abi_tag
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
zzz.c
__FRAME_END__
_DYNAMIC
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_start_main@GLIBC_2.34
_ITM_deregisterTMCloneTable
stdout@GLIBC_2.2.5
_edata
_fini
printf@GLIBC_2.2.5
__data_start
strcmp@GLIBC_2.2.5
__gmon_start__
__dso_handle
_IO_stdin_used
_end
__bss_start
main
__isoc99_scanf@GLIBC_2.7
fwrite@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@GLIBC_2.2.5
_init
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.got.plt
.data
.bss
.comment</code></pre>
<br><br><br>

# Understanding the Authentication Logic with Ghidra

Decompiling the binary with Ghidra, we can analyze the main function:

The program prompts the user for a password in the format DoYouEven%sCTF, where the middle part is captured in the variable local_28. Then, it compares this input with “__dso_handle”, and if it is within a given range, it displays “Try again!”. Subsequently, it compares the input with “_init”, and if it matches exactly, it prints “Correct!”; otherwise, it displays “Try again!”
<pre><code>
undefined8 main(void)

{
  int iVar1;
  char local_28 [32];
  
  fwrite("Password: ",1,10,stdout);
  __isoc99_scanf("DoYouEven%sCTF",local_28);
  iVar1 = strcmp(local_28,"__dso_handle");
  if ((-1 < iVar1) && (iVar1 = strcmp(local_28,"__dso_handle"), iVar1 < 1)) {
    printf("Try again!");
    return 0;
  }
  iVar1 = strcmp(local_28,"_init");
  if (iVar1 == 0) {
    printf("Correct!");
  }
  else {
    printf("Try again!");
  }
  return 0;
}
</code></pre>
<br><br><br>


Knowing this, the only thing left to do is to try
![2025-02-13_08-52](https://github.com/user-attachments/assets/14e4510e-8c1e-4e8a-b430-bd62faa4db2f)
