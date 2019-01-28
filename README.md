# HIBPPasswordChecker
C# implementation of a k-anonymity based password check against the Have I Been Pwned database

The program is a Windows Console application that let's you enter passwords and based on the 5 first characters of the SHA-1 hash (prefix)
a request is sent to the Have I Been PWNED Web API. This returns a list of password hashes that start with the hashprefix of the password to check.
Then the console application locally checks if the full hash value is present in the result list letting you determine if the checked password
is in the database and therefore has been compromised which would be a clear indicator to change this password asap if still in use.

![Alt text](/HIBPPasswordChecker_screen.png?raw=true "Screenshot")

This is a quick and dirty implementation so please bear with me for bugs, bad programming style and other flaws. Feedback welcome
