> [!NOTE] Challenge description
> This time Sam hardcoded the password into the script. However, the password is long and complex, and Sam is often forgetful. So he wrote a script that would email his password to him automatically in case he forgot. Here is the script:

The description points us straight at a "forgot password" style feature

Sam built himself an email reminder script, went to view page source looking for it

Found the relevant form referencing `level4.php`

```html
<form action="[/missions/basic/4/level4.php](view-source:https://www.hackthissite.org/missions/basic/4/level4.php)" method="post"> <input type="hidden" name="to" value="sam@hackthissite.org" /><input type="submit" value="Send password to Sam" /></form></center><br /><br /><center><b>Password:</b><br />
```

There's a hidden field to hardcoded to Sam's email, so the button is designed to send the password reminder to him, not to us., submitting it as-is just confirms the flow:

`Password reminder successfully sent.`

The recipient address is controlled entirely client-side, via a hidden input the script trusts without validation, using dev tools inspector, the value of the to field can be edited before submission

```html
<input type="hidden" name="to" value="youremail" /><input 
```

it has to match the email registered on your own HackThisSite account, since the server checks it against your profile before actually sending anything

```html
<center><b>Password reminder successfully sent to <i>youremail@123.com</i></b><br /><br />(Note: If this is not the email address on your HackThisSite profile, no email will actually be sent.)</center>
```
