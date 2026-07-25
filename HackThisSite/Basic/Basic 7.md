	
> [!NOTE] Challenge description
> This time Network Security sam has saved the unencrypted level7 password in an obscurely named file saved in this very directory.  In other unrelated news, Sam has set up a script that returns the output from the UNIX cal command. Here is the script:
  
  
Two facts from the description, presented as unrelated, are actually the whole challenge

The password lives in an obscurely-named file, somewhere in the current directory

There's a script that wraps the UNIX cal command and returns its output

A script that shells out to a system command and echoes the result back to the user is a command injection candidate

 does the script sanitize the input before passing it to the shell? Testing that directly is the fastest way to find out
 
 UNIX lets you chain commands with `;` so appending a second command after a legitimate cal argument tells us immediately whether input is filtered

```bash
cal 2007; ls
```

No filtering, both commands executed, and the calendar output came bundled with a full directory listing

```bash
cal 2007; ls

........
       December 2007
Mon Tue Wed Thu Fri Sat Sun
                      1   2
  3   4   5   6   7   8   9
 10  11  12  13  14  15  16
 17  18  19  20  21  22  23
 24  25  26  27  28  29  30
 31


index.php
level7.php
cal.pl
.
..
k1kh31b1n55h.php
```

That last file  `k1kh31b1n55h.php`  is clearly the "obscurely named file" the description promised, sitting right there in `ls` output

With the filename in hand, the same injection technique reads its contents directly
