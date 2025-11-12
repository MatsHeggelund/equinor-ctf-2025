# Flagchecker Writeup - Team B00S

`Author: Bludsoe`

By loading up the binary in the IDA, we can take a look at the executable actually does with the flag.

```C
printf("Please enter your flag:\n> ");
__isoc99_scanf("%[^\n]s", s);
v3 = strlen(s);
encode(s, s1, v3);
if ( !strcmp(s1, "VHM{WQQQDCPPGXNSLQBQCQNHVEFV}") )
    puts("CORRECT!");
else
    puts("WRONG!");
return 0;
```

Above you can a snippout of the main() function, and what it mainly does. It prompts us to give the correct flag, then it copies the length of our input, calls the encode() function using our input, the actual flag, and the length of our input. After that, it checks if s1 (which has now been changed by the encode function) is equal and if they are it prints out CORRECT!, otherwise it prints out WRONG!.

To find the correct flag, we need to figure out what the `encode()` function does with the actual flag. 

```C
for ( i = 0; ; ++i )
    {
    result = i;
    if ( (int)i >= a3 )
        break;
    if ( *(char *)((int)i + a1) <= 64 || *(char *)((int)i + a1) > 90 )
        *(_BYTE *)((int)i + a2) = *(_BYTE *)((int)i + a1);
    else
        *(_BYTE *)((int)i + a2) = (int)(*(char *)((int)i + a1) - 65 + i + 17) % 26 + 65;
    }
return result;
```

From the above code we can see what the function does. The for-loop is technically just an infinite loop, because there is no max value set for it. However, the statement `if ( (int)i >= a3)` checks if the current value of i is greater or equal to the integer a3 which is the length of our input from main(), and then stops the loop if that is the case.

The next statement `if ( *(char *)((int)i + a1) <= 64 || *(char *)((int)i + a1) > 90 )` checks whether the character at the current index value is either a lowercase letter, or a special character. In other words, it checks if the ASCII value of the character at index i is not between 65 and 89 which are uppercase characters, and if it is not, it changes this character to be the character from the flag at the same index. This is also why the encoded version of the flag still keeps the characters "{" and "}"

The final statement ` *(_BYTE *)((int)i + a2) = (int)(*(char *)((int)i + a1) - 65 + i + 17) % 26 + 65;` is where the actual obfuscation of the flag happens. Since we now know the character at the current index i is an uppercase letter, that's when the code will change the character. It basically performs a caeasar cipher shift, however it uses the current index value of the character, and not it's ASCII value (hence why it starts and ends by subtracting and adding 65). It then adds 17 to this index to shift it, and does modulo 26 to make sure it doesn't go outside the range of the alphabet. This means that if we take the start of the flag EPT, the encoding will go as follows:

```
Encoded first part of the flag: VHM
i = 0
E -> 69 - 65 = 4 + 0 + 17 = 21 % 26 = 21 + 65 = 86 -> V
i = 1
P -> 80 - 65 = 15 + 1 + 17 = 33 % 26 = 7 + 65 = 72 -> H
i = 2
T -> 84 - 65 = 19 + 2 + 17 = 38 % 26 = 12 + 65 = 77 -> M
```

As we can see, by doing the encoding we get the encoded first part of the flag from the actual flag, meaning we have figure out how the flag is encoded. Now we simply have to reverse this encoding, which we can do using the following Python script:

```Python
def decode(ct):
    out = []
    for i,ch in enumerate(ct):
        if 'A' <= ch <= 'Z':
            x = (ord(ch)-65 - (i + 17)) % 26
            out.append(chr(x + 65))
        else:
            out.append(ch)
    return "".join(out)

decode("VHM{WQQQDCPPGXNSLQBQCQNHVEFV}")
```

By inputting what the script decoded, we can check if the flag is correct

<img src="./images/flagchecker.gif" width=75%>

By checking the flag, we can see that it is indeed correct. The flag from this task is: `EPT{BUTSECONDTIMEISGREATGOOD}`