
> [!NOTE] 
> This level is what we call "The Idiot Test", if you can't complete it, don't give up on learning all you can, but, don't go begging to someone else for the answer, thats one way to get you hated/made fun of. Enter the password and you can continue.


The challenge presents a login page with a single password field. No other functionality, no hints in the UI itself

Given the "idiot test" framing, the natural first move on any web-based CTF login page is to check the page source before touching the input field at all


```
Ctrl+U  →  View Page Source
```


Right below the intro text, sitting in plain sight inside an HTML comment, is the password

```html
<br /><center> <br /> <b>Level 1(the idiot test)</b> </center><br /><br /> This level is what we call "The Idiot Test", if you can't complete it, don't give up on learning all you can, but, don't go begging to someone else for the answer, thats one way to get you hated/made fun of. Enter the password and you can continue. <br /><br /> <!-- the first few levels are extremely easy: password is urthebestgoon? --> 
```