
> [!NOTE] 
> Network Security Sam has encrypted his password. The encryption system is publically available and can be accessed with this form:You have recovered his encrypted password. It is:  
  

This level provides an encrypted string and access to the public encryption form Sam used to generate it

```
You have recovered his encrypted password. It is:  
  
**0gh<4=l@**  
  
Decrypt the password and enter it below to advance to the next level.
```

Fed a known plaintext into the encryptor to observe its behavior

```
input:  aaaa
output: abcd
```

Each identical input character came out different depending on its position  `a → a`, `a → b`, `a → c`, `a → d`

That rules out a Caesar cipher (constant shift for the whole string) and points to a positional / progressive shift, each character's offset depends on its index in the string, not on a fixed key

Formalizing the pattern

```python
encrypted[i] = chr(ord(plaintext[i]) + i)
```


| Position | Shift Applied |
| -------- | ------------- |
| 0        | +0            |
| 1        | +1            |
| 2        | +2            |
| i        | +i            |

This is effectively a homemade polyalphabetic cipher where the offset grows linearly and predictably with the index

There's no real secret key, the "key" is just the shift logic itself, and once identified, it's trivially reversible


Since encryption applies +i per character, decryption is just the inverse, -i, applied character by character

```python
encrypted = {yourpass}
decrypted = ""

for i in range(len(encrypted))
    decrypted += chr(ord(encrypted[i]) - i)

print("Decrypted password:", decrypted)
```


