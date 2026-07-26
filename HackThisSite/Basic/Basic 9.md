> [!NOTE] 
> Network Security Sam is going down with the ship - he's determined to keep obscuring the password file, no matter how many times people manage to recover it. This time the file is saved in /var/www/hackthissite.org/html/missions/basic/9/.  
> 
> In the last level, however, in my attempt to limit people to using server side includes to display the directory listing to level 8 only, I have mistakenly screwed up somewhere.. there is a way to get the obscured level 9 password. See if you can figure out how...  
> 
> This level seems a lot trickier then it actually is, and it helps to have an understanding of how the script validates the user's input. The script finds the first occurance of '<--', and looks to see what follows directly after it.

The description confirms what the Level 8 writeup already hinted at, the SSI sandbox from Level 8 was only meant to scope command execution to that level's directory, and the scoping was implemented incorrectly

This level doesn't require a new vulnerability, it's an incomplete fix on the previous one

The extra hint about input validation, the script only checks for the first occurrenceof `<--` and inspects what comes right after it

Anything structured so that a different `<--` appears earlier than expected, or that the validation logic doesn't fully account for, can slip past the intended restriction

Reused the exact SSI injection primitive from Level 8, but instead of trying to list the current directory, walked back up and across into the Level 9 folder directly

`<!--#exec cmd="ls ../../9/" -->`

This works because the "restriction to level 8 only" clearly isn't enforced against arbitrary relative paths, it's a filter that's easy to route around once you know the sandbox is defined by directory context rather than a hard server-side boundary

`p91e283zc3.php` is the obscured password file for this level, reached via the Level 8 injection point before Level 9's own protections were ever engaged