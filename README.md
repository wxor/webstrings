# webstrings
String enumeration tool for webpages.

This tool takes an output file from feroxbuster and searches for potentially sensitive strings in found files.

Currently implemented strings:

        # Sensitive strings
        (r"(passw.*[=,:].+)", "Sensitive string"),
        (r"(cred.*[=,:].+)", "Sensitive string"),
        (r"(datab.*[=,:].+)", "Sensitive string"),
        (r"(server.*[=,:].+)", "Sensitive string"),
        (r"(DB_.*)", "Sensitive string"),
        (r"(PRIVATE.*[ ].+)", "Sensitive string"),

        #bcrypt
        (r"(\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}([./A-Za-z0-9]{31})?\b)", "bcrypt"),

        # MD5
        (r"(\b[a-fA-F0-9]{32}\b)", "MD5"),

        # SHA-1
        (r"(\b[a-fA-F0-9]{40}\b)", "SHA-1"),

        #scrypt
        (r"\$scrypt\$\b.+", "scrypt"),

        # Email Addresses
        (r"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)", "Email")


### Example output

```python webstrings.py -f ferox.dmp -t 2 -i ".js"```

![image](https://github.com/wxor/webstrings/assets/32234633/3c9e2613-86db-426d-90d6-b6c541e8c09c)

### Notes

Tested on Python 3.11
Be careful with the threads
