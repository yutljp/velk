# Function signatures

`velk --summary BIN FUNCTION` returns a JSON object. Its `signature` contains:

| Field | Meaning |
| --- | --- |
| `return` | Recovered C return type. |
| `params` | Named parameters in order, including stack parameters, with `name` and `type`. |
| `parameterCount` | Number of named parameters in `params`. |
| `callingConvention` | Convention used by the analysis, such as `SysV`, `Win64`, `Aapcs64`, `Aapcs32` or `Cdecl`. |
| `variadic` | Whether the recovered declaration takes further arguments. |

JavaScript `f.signature()` returns these fields too. JavaScript and MCP can read
the summary with this script (pass it to `velk_run_script` for MCP):

```js
const f = velk.open("tests/fixtures/metrics/calls.x86_64.O0.debug.elf").getFunction("sum_varargs");
({signature: f.signature(), summary: f.summary()});
```

The summary's `calls` array describes calls remaining after analysis. Each entry
has `block` (a block address), `statement` (an index within that block), `target`
(an address or null), `indirect`, `callingConvention`, `argumentCount` (a number
or null), `candidates` (possible function addresses), and `signature` (a usable
callee declaration or recovered signature with the fields above, or null). Statement indices are
not instruction addresses. A resolved pointer call has a target and is no longer
indirect. An empty candidate list does not prove that no target exists.

On x86 and ARM32, parameter recovery for internal calls uses the registers the callee may change.
A register preserved by the callee can hold an argument read after the call.
Constant boolean assignments can distinguish paths through a join when a later
condition guards a register read. This analysis has a state budget; on exhaustion
it retains the conservative parameter estimate.
For AArch64 and Go, parameter recovery treats calls as writes to every register
the convention allows them to change; save/restore reads can otherwise introduce
extra parameters.

A Go function that returns several values in registers is printed as returning
`struct velk_resultsN`, with one `int64_t` member, `r0` onwards, for each value. A direct
call reads the members it uses, and a function that returns what its callee returned
returns the call. The number of values is the furthest result register some path
from a direct call reads before anything writes it. A caller that returns with such
a register unread passes on its own number, through at most two callers. A register
counts only if the function writes it on every path to a return or takes it as an
argument. A function with no direct caller, such as a method called only through an
interface, is printed with one result. A call through a pointer, and a register past
the callee's number, keep the comment `/* also returned by the call */`. A function of
Go's assembly convention returns on the stack and keeps `/* also returns ... */`.
The summary's `return` stays the type of the first value.

Pointer tracking follows stored function addresses and constant data words at the
target's pointer width. Overlapping writes invalidate stored values. Unknown
pointers and incompatible paths can prevent resolution.

Counts and types are estimates when no usable declaration exists. Unused source
parameters cannot always be recovered from machine code. Variadic declarations
can come from debug information or recognized register saves; this does not
determine the arguments at every call to an arbitrary variadic function. An
unknown call count remains null. Convention names describe the analysis's model,
not a guarantee that every function follows the platform's default ABI.
