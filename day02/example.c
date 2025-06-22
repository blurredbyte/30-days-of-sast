// example.c
#include <stdio.h>
#include <string.h> // Not strictly needed for this version, but often used with strings

int main() {
    char buffer[10]; // Allocate a small buffer

    printf("Enter your name: ");
    gets(buffer); // Vulnerable function: gets() does not check buffer boundaries.
                  // If user input is longer than 9 characters (plus null terminator),
                  // a buffer overflow will occur.

    printf("Hello, %s!\n", buffer);

    // A safer alternative would be fgets:
    // char safe_buffer[10];
    // printf("Enter your name safely: ");
    // if (fgets(safe_buffer, sizeof(safe_buffer), stdin) != NULL) {
    //     // Remove trailing newline if present
    //     safe_buffer[strcspn(safe_buffer, "\n")] = 0;
    //     printf("Hello safely, %s!\n", safe_buffer);
    // }

    return 0;
}
