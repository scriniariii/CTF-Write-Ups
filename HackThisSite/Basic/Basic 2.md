
> [!NOTE] 
> Network Security Sam set up a password protection script. He made it load the real password from an unencrypted text file and compare it to the password the user enters. However, he neglected to upload the password file...


The description already tells us most of the story, sam's login script reads the "real" password from a plaintext file on the server and compares it against whatever the user submits

he never uploaded the password file. So when the script tries to read it, the file doesn't exist server-side

That means one of two things happens depending on how the backend handles a missing file

it throws an error, or it silently reads the file as empty and gets back a null / empty string as the "expected" password

Given the challenge is solvable, it's the second case

if the expected password resolves to an empty string, the login only succeeds when the input field is also empty

```
password field  --> (leave blank)
Submit
```

