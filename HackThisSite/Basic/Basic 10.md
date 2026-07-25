Clicking the submit button lands on a new page that just says access to the content is not authorized

Nothing else on the page no visible form fields, no obvious injection point, no hints

With nothing exploitable in the page content itself, the next place to check is client-side state, specifically the session cookie, since an "authorized / not authorized" gate is a candidate for being tracked client-side instead of being properly enforced server-side

Inspecting the cookies via dev tools turned up this

| Name               | Value |
| ------------------ | ----- |
| level10_authorized | no    |
A boolean authorization flag sitting in a cookie the client fully controls is about as direct a vulnerability as it gets

Reloaded the page with the modified cookie in place