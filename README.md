# CodeQL Tutorials

A brief note on how to start using CodeQL from scratch.

---

## Setting Up CodeQL

My test environment is a Linux server. Follow the steps below to get started:

1. **Download the CodeQL Bundle**  
   Get the latest CodeQL bundle from the official GitHub Releases page:  
   [https://github.com/github/codeql-action/releases](https://github.com/github/codeql-action/releases)

2. **Extract and Configure the Environment Path**  
   Unpack the bundle and add the `<root>/codeql` directory to your system `PATH`:
   ```bash
   export PATH=$PATH:/your/path/to/codeql
   ```

3. **Verify the Installation**  
   Check whether CodeQL is working correctly by running:
   ```bash
   codeql resolve packs
   ```

4. **Download Language Packs**  
   You need to download language packs based on the language of the codebase you want to analyze.  
   Example for JavaScript:
   ```bash
   codeql pack download codeql/javascript-all
   ```
   Note: Each language pack is tailored to a specific language (e.g., Java, Python, JavaScript, etc.). Be sure to download the correct one for your project.

5. **List Installed Language Packs**  
   You can verify which packs are installed using:
   ```bash
   codeql resolve qlpacks --format=json
   ```

---

## A Simple Example: Analyzing Code with CodeQL

Now that CodeQL is set up, let’s walk through a basic example of how to analyze a codebase using a custom query.


### Step 1: Prepare a Sample C Project

You can use any small C/C++ project. For this example, let’s use a simple C program with a deliberate vulnerability (password leakage):

```c
#include <stdio.h>
#include <string.h>

void login(const char* username, const char* password) {
    if (strcmp(username, "admin") == 0 && strcmp(password, "secret123") == 0) {
        printf("Login successful\n");
    } else {
        printf("Login failed for user: %s with password: %s\n", username, password); // 🔥 Vulnerability: password leakage!
    }
}

int main() {
    login("admin", "secret123");
    return 0;
}
```

### Step 2: Create a CodeQL Database

Before running a query, you need to create a **CodeQL database** from the source code. This involves compiling the project so CodeQL can analyze the code structure.

Run the following command:

```bash
codeql database create sample-db \
  --language=c \
  --source-root=/path/to/testcode \
  --command="gcc -o sample sample.c"
```

> 💡 This will create a folder named `sample-db` containing the CodeQL database.

If successful, you will see output similar to:

```
Initializing database at /xxx/codeql/tests/sample-db.
Running build command: [gcc, -o, sample, sample.c]
Running command in /xxx/codeql/tests: [gcc, -o, sample, sample.c]
Finalizing database at /xxx/codeql/tests/sample-db.
Running pre-finalize script /xxx/codeql/codeql/cpp/tools/pre-finalize.sh in /xxx/codeql/tests.
Running command in /xxx/codeql/tests: [/xxx/codeql/codeql/cpp/tools/pre-finalize.sh]
Running TRAP import for CodeQL database at /xxx/codeql/tests/sample-db...
Grouping TRAP files by link target
Grouping unlinked TRAP files together
Scanning TRAP files
Importing TRAP files
Merging relations
Finished writing database (relations: 48.20 KiB; string pool: 2.08 MiB).
TRAP import complete (964ms).
Finished zipping source archive (46.47 KiB).
Successfully created database at /xxx/codeql/tests/sample-db.
```


### Step 3: Write a Custom Query

To run a custom query in CodeQL, you need to organize your query inside a **QL pack**. A QL pack defines your query's metadata and dependencies.

You need include a `qlpack.yml` and a `leakpass.ql`.

#### What is `qlpack.yml`?

This file defines a "CodeQL pack" — a unit of reusable queries and libraries. It tells CodeQL what language your queries are for, and which dependencies they rely on.

Create a file named `qlpack.yml`:

```yaml
name: leakpass-cpp-query
version: 0.0.1
dependencies:
  codeql/cpp-all: "*"
```

**Explanation:**
- `name`: A unique name for your query pack.
- `version`: The version of your query pack.
- `dependencies`: The libraries your query needs — here we depend on all CodeQL support for C/C++ (`cpp-all`).

Place this file in the same directory as your `.ql` query.


#### What does `leakpass.ql` do?

Now create the query file `leakpass.ql` in the same directory. This query checks if a variable named `"password"` is passed to the `printf()` function — a sign of a possible sensitive data leak.

```ql
/**
 * Detects usage of a variable named 'password' as a parameter to printf.
 */
import cpp

/**
 * Returns true if the expression refers to a variable named "password".
 */
predicate isPasswordVariable(Expr e) {
  e instanceof VariableAccess and
  e.(VariableAccess).getTarget().getName() = "password"
}

/**
 * Looks for printf calls where any argument is the 'password' variable.
 */
from FunctionCall fc, Expr arg
where
  fc.getTarget().getName() = "printf" and
  arg = fc.getArgument(_) and
  isPasswordVariable(arg)
select fc, "Possible password leak via printf"
```

**Explanation:**
- `import cpp`: Loads the C/C++ language model.
- `isPasswordVariable`: Checks if an expression refers to a variable named `password`.
- `from FunctionCall fc, Expr arg`: Looks at all function calls and their arguments.
- `fc.getTarget().getName() = "printf"`: Filters to `printf()` calls.
- `arg = fc.getArgument(_)`: Looks at all arguments to `printf`.
- `isPasswordVariable(arg)`: Checks if any of the arguments are the `password` variable.


### Step 4: Run the Query

Use the following command to run the query against the database:

```bash
codeql query run --database=sample-db leakpass.ql
```

If a match is found, you will see output like:

```
[1/1] Found in cache: /xxx/codeql/tests/leakpass.ql.
leakpass.ql: Evaluation completed (183ms).
|       fc       |               col1                |
+----------------+-----------------------------------+
| call to printf | Possible password leak via printf |
Shutting down query evaluator.
```

## References
- https://github.com/github/codeql-action/releases
- https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-cpp
- https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/setting-up-the-codeql-cli
- CHATGPT

