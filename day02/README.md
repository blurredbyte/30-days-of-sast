# Day 02: Manual Code Review Basics - Finding Vulnerabilities with `grep`

**Summary:** Today, we'll dive into manual code review using a simple yet powerful command-line tool: `grep`. We'll learn how to search for common vulnerable functions and patterns in C code, specifically focusing on the dangerous `gets()` function.

**Today's Focus:** Using `grep` to find uses of `gets()` in C code.

## Try it yourself

1.  **Create `example.c`** with the content below.
2.  **Scan for `gets`**:
    ```shell
    grep "gets(" example.c
    ```
3.  **Scan for `gets` with line numbers and color (if your grep supports it)**:
    ```shell
    grep -n --color=auto "gets(" example.c
    ```
4.  **Search in all C files in the current directory**:
    ```shell
    grep "gets(" *.c
    ```

## Code Explanation

The `example.c` file demonstrates a common vulnerability in C programming: the use of `gets()`.

```c
// example.c
#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    printf("Enter your name: ");
    gets(buffer); // Vulnerable: gets() does not check buffer size
    printf("Hello, %s!\n", buffer);
    return 0;
}
```

*   **`#include <stdio.h>`**: Includes standard input/output functions like `printf` and `gets`.
*   **`char buffer[10];`**: Declares a character array (string) named `buffer` with a size of 10 bytes.
*   **`gets(buffer);`**: This is the vulnerable function. `gets()` reads a line from standard input and stores it into `buffer`. However, it doesn't perform any bounds checking. If the user enters more than 9 characters (plus the null terminator), `gets()` will write past the end of `buffer`, leading to a buffer overflow.
*   **Buffer Overflow**: This can overwrite adjacent memory, potentially corrupting data, crashing the program, or even allowing an attacker to execute arbitrary code.

`grep "gets(" example.c` searches for the literal string "gets(" in `example.c`, helping us quickly identify its usage. While simple, `grep` is a fundamental first step in manual SAST.

---
[Back to Main README](../README.md)
