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

---

## Query Usage Cases

### Working with `DataFlow::Node`

### 1. Check if a node is related to a specific function or variable

#### A. Match a **specific function call**
```ql
FunctionCall fileFunc |
  fileFunc.getTarget().hasName("open")
```

#### B. Match a **function name containing a substring** (case-insensitive)
```ql
FunctionCall fileFunc |
  fileFunc.getTarget().getName().toLowerCase().matches("%open%")
```

#### C. Match a **variable name containing a substring**
```ql
Variable var |
  var.getName().toLowerCase().matches("%key%")
```

#### D. Check if a node represents a variable **access**
```ql
node.asExpr() = var.getAnAccess()
```

#### E. Check if a node is the **right-hand side of an assignment** to a variable
```ql
AssignExpr ae |
  ae.getLValue() = var.getAnAccess() and
  node.asExpr() = ae.getRValue()
```


### 2. Data Flow

Data flow analysis allows you to track how data moves through a program. This can help detect issues like sensitive data leakage, improper propagation of tainted input, or unexpected side effects.

In CodeQL, **`DataFlow::Node`** is used to represent locations in code where data can flow *from* (sources) or *to* (sinks).


#### A. Local Data Flow

Local data flow tracks how values propagate **within a single function or basic block**. It’s useful for lightweight, fast analysis when you don't need full interprocedural flow.


Local flow is ideal when:
- You want **quick** and **lightweight** taint/data tracking
- You're analyzing **well-isolated functions**
- **Function calls**, **returns**, and **field accesses** are **not involved**

> Note: **Local flow does not** track across function boundaries, indirect calls, or return values. For those cases, use **Global Data Flow** or **TaintTracking**.


##### Common Interface: `DataFlow::Node`

In local flow (as with global flow), `DataFlow::Node` represents an abstract point in the code (like an expression, parameter, or value). You can project it back to code with helpful methods:

```ql
class DataFlow::Node {
  /**
   * Gets the expression corresponding to this node, if any.
   */
  Expr asExpr();

  /**
   * Gets an indirect (dereferenced) expression from this node.
   * Index = number of dereference steps.
   */
  Expr asIndirectExpr(int index);

  /**
   * Gets the parameter corresponding to this node, if any.
   */
  Parameter asParameter();

  /**
   * Gets a dereferenced parameter at given index.
   */
  Parameter asParameter(int index);
}
```

##### Local Flow Example Query

Let’s say you want to check if a file pointer returned by `fopen()` is derived from another tainted source **within the same function**.

```ql
import cpp
import semmle.code.cpp.dataflow.new.DataFlow

from Function fopen, FunctionCall fc, Expr src, DataFlow::Node source, DataFlow::Node sink
where
  fopen.hasGlobalName("fopen") and
  fc.getTarget() = fopen and
  source.asIndirectExpr(1) = src and
  sink.asIndirectExpr(1) = fc.getArgument(0) and
  DataFlow::localFlow(source, sink)
select src, "This expression flows into a file pointer argument."
```

Understading the flow:
- `fopen.hasGlobalName("fopen")`: identifies the function `fopen`
- `fc.getTarget() = fopen`: matches calls to `fopen`
- `source.asIndirectExpr(1) = src`: gets a dereferenced expression (e.g., pointer data)
- `sink.asIndirectExpr(1) = fc.getArgument(0)`: analyzes where the input to `fopen()` came from
- `DataFlow::localFlow(source, sink)`: ensures the flow occurs **within one function**



#### B. Global Data Flow
Global data flow analysis follows values through:
- variable assignments
- function calls and returns
- member accesses
- control structures across multiple functions and files

To use global data flow, you define a configuration module implementing `DataFlow::ConfigSig`.


##### Required Predicates

- `predicate isSource(DataFlow::Node source)`  
  Defines where the data originates.  
  Example: untrusted input from a file, network, or user.

- `predicate isSink(DataFlow::Node sink)`  
  Defines where data is *dangerous* or *sensitive* if it reaches.  
  Example: writing to a sensitive variable or calling a security-sensitive function.

##### Optional Predicates

- `predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ)`  
  Specifies custom data flow transitions that aren't captured by default rules.  
  Use this for tracking flow across unusual APIs or indirect expressions.

- `predicate isBarrier(DataFlow::Node node)`  
  Stops data from flowing through the given node.  
  Useful for whitelisting, sanitizers, or modeling filtering logic.

##### **Basic Query:**
```ql
import semmle.code.cpp.dataflow.new.DataFlow

module MyFlowConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    ...
  }

  predicate isSink(DataFlow::Node sink) {
    ...
  }
}

module MyFlow = DataFlow::Global<MyFlowConfiguration>;
from DataFlow::Node source, DataFlow::Node sink
where MyFlow::flow(source, sink)
select sink, source, "Tainted data flows from here to a sink."
```

Understading the flow:
- `flow(source, sink)` is true when data originating at `source` can reach `sink`.
- CodeQL tracks intermediate expressions and control flow behind the scenes.
- You can use `DataFlow::PathGraph` for visualizing full flow paths (great for debugging).



#### Tips

- Use `isAdditionalFlowStep` to track custom APIs
- Use `isBarrier` for whitelisting or stopping taint propagation
- Add `flowPath(source, sink)` to your query to get intermediate steps
- Use `TaintTracking` module if you want built-in support for return flows and sanitizers

---

### Taint Analysis
Taint analysis is a powerful static analysis technique that helps identify vulnerabilities caused by untrusted data flowing through a program into sensitive operations. In CodeQL, taint tracking is configured using taint sources, sinks, and optionally sanitizers, which are defined using special predicates or helper classes.

#### TaintFunction

In CodeQL, when you want to describe how taint flows through specific functions, you can subclass the `TaintFunction` class. This is useful for functions where the taint doesn't start or end, but passes through—such as strdup, which copies a string, or memcpy, which transfers memory contents.

A `TaintFunction` tells the CodeQL engine how taint propagates from input parameters to output values for a given function. It is typically used in libraries or utility functions that don't themselves create vulnerabilities, but may pass tainted data along to other parts of the code.

**Example: Modeling Taint Propagation in `strcpy`**

The `strcpy` function copies a string from a **source** to a **destination**. If the source string (second parameter) is tainted, then:
- The **destination** (first parameter) becomes tainted.
- The **return value** (which is typically the same as the destination) is also tainted.

Here’s how to model this behavior:
```ql
/**
 * A TaintFunction that models the behavior of `strcpy`,
 * where taint from the source parameter (param 1) flows to
 * both the destination parameter (param 0) and the return value.
 */
class StrcpyFunction extends TaintFunction {
  StrcpyFunction() {
    this.hasName("strcpy")
  }

  override predicate hasTaintFlow(FunctionInput i, FunctionOutput o) {
    i.isParameter(1) and
    (
      o.isParameter(0) or
      o.isReturnValue()
    )
  }
}
```

Understading the flow:

- **`StrcpyFunction`** extends `TaintFunction` to describe how taint flows through the standard C function `strcpy`.
- **`this.hasName("strcpy")`** binds this model to calls to the `strcpy` function.
- **`i.isParameter(1)`** identifies the second argument (`src`), where the tainted data comes from.
- **`o.isParameter(0)`** matches the first argument (`dest`), which gets tainted by the copy.
- **`o.isReturnValue()`** indicates that the return value (which is usually the same as `dest`) also becomes tainted.

This rule captures the behavior: _“If the source string is tainted, both the destination and the return value should be treated as tainted.”_

---

## References
- https://github.com/github/codeql-action/releases
- https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-cpp
- https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/setting-up-the-codeql-cli
- CHATGPT

