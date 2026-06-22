# Writeup: FindLicenseKey | Reversing a Crackme with Ghidra

**Binary:** `findlicensekey` (ELF 64-bit PIE, x86-64, stripped) 
**Objective:** generate a valid license key 

## 1. recon

The program asks for a license key and validates whether it matches what the program expects internally. 

```bash
./findlicensekey <username>
```


## 2. ghdira

Using ghidra i decompiled one of the functions.

```c
undefined8 FUN_0010121a(int param_1,undefined8 *param_2)
{
  int iVar1;
  undefined8 uVar2;
  long in_FS_OFFSET;
  char local_218 [256];
  char local_118 [264];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_1 == 2) {
    FUN_00101189(param_2[1],local_118);
    puts("Enter license key to continue: ");
    fflush(stdout);
    iVar1 = __isoc23_scanf("%255s",local_218);
    if (iVar1 == 1) {
      fflush(stdin);
      iVar1 = strcmp(local_218,local_118);
      if (iVar1 == 0) {
        puts("Key validated");
        uVar2 = 0;
      }
      else {
        puts("Invalid key");
        uVar2 = 2;
      }
    }
    else {
      puts("Error reading input");
      uVar2 = 1;
    }
  }
  else {
    printf("Error: usage: %s <username>\n",*param_2);
    uVar2 = 2;
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar2;
}
```

Translated into words

It starts by setting up a stack canary (local_10 = (long )(in_FS_OFFSET + 0x28)), which is just standard buffer overflow protection, nothing relevant.

Then it checks that exactly one argument was passed (param_1 == 2, meaning argv[0] + argv[1]). If not, it prints usage and exits with code 2.

If the argument is present, it calls FUN_00101189(argv[1], local_118), which transforms the argument somehow and stores the result in local_118. 

Next it prompts the user to enter a license key and reads up to 255 characters into local_218 via scanf. 

Finally it does a plain strcmp(local_218, local_118) 

The key detail here is that `FUN_00101189` is called before the input is requested, meaning the expected key is computed purely from the username passed on the command line. There's no embedded secret that depends on the user's input, the entire challenge lies in understanding that generation function.

## 3. Analyzing the Key Generation Function

Ghidra decompiled `FUN_00101189` as follows:

```c
void FUN_00101189(long param_1,long param_2)
{
  int local_20;
  
  for (local_20 = 0; (local_20 < 0x18 && (local_20 < 0xff)); local_20 = local_20 + 1) {
    *(char *)(param_2 + local_20) =
         "QAZPLWSXOKMEYDCIJNRFVUHBTGqpalzmwoeirutyskdjfhgxncbv1750284369"
         [(local_20 + *(char *)(param_1 + local_20)) % 0x3e];
  }
  *(undefined1 *)(param_2 + local_20) = 0;
  return;
}
```

### Identifying parameters and structure

- param_1 → pointer to the username (input)
- param_2 → pointer to the output buffer (where the expected key is written)
- local_20 → loop counter (i)

The long embedded string is a substitution table of exactly 62 characters
0x18 = 24 (decimal), 0x3e = 62 (decimal),  0xff = 255 (decimal)

### The loop's termination condition

```c
for (local_20 = 0; (local_20 < 0x18 && (local_20 < 0xff)); local_20 = local_20 + 1)
```

There are two conditions, local_20 < 0x18 (24) is always more restrictive than local_20 < 0xff (255), so in practice the loop always iterates exactly 24 times, regardless of the username's actual length. The second condition never ends up being the one that cuts the loop short, it's likely a leftover from a larger data type in the original source code, irrelevant to the observed behavior.

### The core operation

```c
TABLE[(i + username[i]) % 0x3e]
```

For each position [i] goes from 0 to 23:

- Reads the username byte at that position: username[i]
- Adds the position index: username[i] + i
- Reduces module 62 (the exact size of the table): % 0x3e
- Uses the result as an index to pull a character from the substitution table

the null terminator is appended:

```c
*(undefined1 *)(param_2 + local_20) = 0;
```

### Why module 62?

This table:

```
QAZPLWSXOKMEYDCIJNRFVUHBTGqpalzmwoeirutyskdjfhgxncbv1750284369
```

has exactly 62 characters (26 uppercase + 26 lowercase + 10 digits = 62). The % 0x3e (62) guarantees that the calculated index always falls within the table's valid range, regardless of how large [i] + username [i] gets.

## 4. Why Does the Username Need 24 Characters

This is a subtle point that isn't obvious at first glance, but it follows directly from analyzing the loop.

There is no strlen(username) check anywhere in the code. The loop in FUN_00101189 iterates a fixed 24 times, reading username 0 through username 23, without verifying whether the actual string is that long.

This has a direct consequence, if the username is shorter than 24 characters, the loop keeps reading memory past the null byte that terminates the string. Those bytes are whatever happens to be sitting on the stack at that moment, uninitialized content, leftover data from previous execution. The result is non-deterministic: the same input can produce different keys across separate runs.

If the username is 24 characters or longer, every byte read by the loop is real, known data from the username, so the generated key is always the same for the same input.

For an external keygen (written in C, for example) to match exactly what the real binary does, it's necessary to use a username of exactly 24 ASCII characters, this eliminates any dependency on uninitialized memory and makes the result reproducible.

## 5. Reconstructed Algorithm

```
function generate_key(username):
    ALPHABET = "QAZPLWSXOKMEYDCIJNRFVUHBTGqpalzmwoeirutyskdjfhgxncbv1750284369"
    output = ""
    for i in 0..23:
        index = (username[i] + i) % 62
        output += ALPHABET[index]
    return output
```

## 6. C Implementation

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define ALPHABET "QAZPLWSXOKMEYDCIJNRFVUHBTGqpalzmwoeirutyskdjfhgxncbv1750284369"
#define LENGTH 24

void generate_key(const unsigned char *username, char *output) {
    for (int i = 0; i < LENGTH; i++) {
        output[i] = ALPHABET[(username[i] + i) % (int)strlen(ALPHABET)];
    }
    output[LENGTH] = '\0';
}

int main(int argc, char **argv) {
    if (argc != 2 || strlen(argv[1]) != LENGTH) {
        fprintf(stderr, "usage: %s <24-char-username>\n", argv[0]);
        return 1;
    }

    char output[LENGTH + 1];
    generate_key((const unsigned char *)argv[1], output);
    printf("%s\n", output);
    return 0;
}
```
