## Challenge Overview

**Binary:** ZEXORv1_wayland  
**Platform:** Linux x86-64 (Wayland)  
**Language:** C/C++  
**Difficulty:** 1.0/5  
**Author:** svidnet  
**rar password:** "crackmes.one"

ZEXOR v0.1 is a beginner-friendly license checker application that presents a GTK3 GUI window requesting a valid license key. The goal is to either discover the correct license key or bypass the validation mechanism.

## Initial Analysis

### Running the Binary

```bash
chmode +x ZEXORv1_wayland
./ ZEXORv1_wayland
```

Upon execution, the application displays a GTK3 window with:
- Title: "ZEXOR v0.1"
- An input field labeled "Enter License Key:"
- A "Check License" button

When an incorrect key is entered, the application shows an error dialog with the message: "Wrong key dude. Keep trying!(no cheating .)"

### Static Analysis with `strings`

The first step(i guess) in analyzing any binary is examining its readable strings. This often reveals valuable information about the program's logic, hardcoded values, and potential vulnerabilities.

```bash
strings ZEXORv1_wayland
```

## Key Findings

Among the various GTK library function names and standard strings, one particular string stood out as unusual:

```
notgonnadothatlmao
```

This string appeared suspicious for several reasons:

1. **Unusual format**: It doesn't match typical library strings or function names
2. **Mixed alphanumeric pattern**: Contains both letters and numbers in a seemingly random sequence
3. **Context**: Found near the success/failure message strings
4. **Length**: 18 characters, which is reasonable for a license key

### Other Notable Strings

The binary also contained revealing success and failure messages:

**Success message:**
```
<span foreground='green' size='large'>
 NICE! You cracked it!</span>
Congrats! You actually did it!
```

**Failure message:**
```
<span foreground='red' size='large'>YOU FAILED</span>
Wrong key dude. Keep trying!(no cheating .)
```

These strings use GTK markup language, confirming the GUI framework and showing the application has two distinct code paths.

## Understanding the Validation Logic

From the strings output, we can identify several important function calls:

```
gtk_entry_get_text
strcmp@GLIBC_2.2.5
```

This suggests the validation likely works as follows:

1. User enters a key in the GTK entry widget
2. `gtk_entry_get_text()` retrieves the user's input
3. `strcmp()` compares it against a hardcoded string
4. Based on the comparison result, either the success or failure dialog is displayed

The presence of `strcmp` (string comparison function) indicates this is a simple string matching implementation rather than a complex cryptographic validation.

## Solution

### Testing the Hypothesis

Based on the static analysis, I tested the suspicious string as the license key:


**Result:** The application displayed the green success message.
