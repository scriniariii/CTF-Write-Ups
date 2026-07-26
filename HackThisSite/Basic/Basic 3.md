
> [!NOTE] 
> This time Network Security Sam remembered to upload the password file, but there were deeper problems than that.


This time Sam did upload the password file, The phrase "deeper problems than that" is a strong hint the vulnerability isn't in the logic anymore, it's in how the file itself is exposed

Checked the page source to see how the login form is built

```html
<form action="[/missions/basic/3/index.php](view-source:https://www.hackthissite.org/missions/basic/3/index.php)" method="post"> <input type="hidden" name="file" value="password.php" /> <input type="password" name="password" /><br /><br /> <input type="submit" value="submit" /></form>
```

A hidden field named `file` points directly at `password.php`, that's the name of the file the backend reads the real password from , and now we know exactly where it lives

If `password.php` sits in the same directory as the form and there's no server-side restriction stopping direct access to it, we should be able to request it straight from the browser

```
view-source:https://www.hackthissite.org/missions/basic/3/password.php
```

Sure enough, the file returns in plaintext instead of being executed or blocked