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

Pointer tracking follows stored function addresses and constant data words at the
target's pointer width. Overlapping writes invalidate stored values. Unknown
pointers and incompatible paths can prevent resolution.

Counts and types are estimates when no usable declaration exists. Unused source
parameters cannot always be recovered from machine code. Variadic declarations
can come from debug information or recognized register saves; this does not
determine the arguments at every call to an arbitrary variadic function. An
unknown call count remains null. Convention names describe the analysis's model,
not a guarantee that every function follows the platform's default ABI.
