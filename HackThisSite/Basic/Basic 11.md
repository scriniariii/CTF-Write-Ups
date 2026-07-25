
> [!NOTE] Challenge description
> Sam decided to make a music site. Unfortunately he does not understand Apache. This mission is a bit harder than the other basics.

Every page reload serves up a different Elton John lyric

```html
I love my music! 
"Funeral for a Friend/Love Lies Bleeding" is the best!

 <!--We even have our own collection - if you could find it!-->
```

That HTML comment is a direct invitation: there's a "collection" hidden somewhere on the server, and given the "he does not understand Apache" line in the description, the vulnerability is almost certainly a misconfiguration, not application logic

Started poking at directory listings and found one exposed `Index of /missions/basic/11/e/`

Followed the trail letter by letter `e/`, `e/l/`, `e/l/t/`, `e/l/t/o/`, `e/l/t/o/n/` , each one a directory named after a letter, spelling out "Elton" (fitting, given the lyric theme)

This reads like someone built the structure as a scavenger hunt rather than an actual access control mechanism

At `e/l/t/o/n/`, directory listing stops working, no more browsable index, this is where "he doesn't understand Apache" becomes the actual lead to chase

check for a `.htaccess` file, since that's the standard place per-directory Apache config lives, and misconfigured `.htaccess` files are a classic way to leak more than intended

Requesting `.htaccess` directly returned its contents in plaintext

```
IndexIgnore DaAnswer.* .htaccess
<Files .htaccess>
require all granted
</Files>
```

Two mistakes stacked in four lines

- `IndexIgnore DaAnswer.* .htaccess`: this hides files matching `DaAnswer.*` (and `.htaccess` itself) from directory listings, but does nothing to block direct requests to those files
- `<Files .htaccess> require all granted </Files>`: this explicitly makes `.htaccess` itself directly readable, which is exactly how its contents (including the `IndexIgnore` rule naming the hidden file) got exposed in the first place

With the hidden filename pattern known, requesting it directly bypassed the listing restriction entirely