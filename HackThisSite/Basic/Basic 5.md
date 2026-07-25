

> [!NOTE] Challenge description
> Sam has gotten wise to all the people who wrote their own forms to get the password. Rather than actually learn the password, he decided to make his email program a little more secure.

The description implies Sam patched the exact issue from Level 4, people crafting their own forms to hijack the email recipient, so the expectation going in was that the to field would no longer be trustable client-side, or that some server-side validation had been added against form tampering

Repeated the same procedure as Level 4, inspected the page source, found the hidden to field, edited it via dev tools to point to my own HackThisSite-registered email, then submitted the form.

It worked, first try, no differences observed in behavior or response compared to Level 4

