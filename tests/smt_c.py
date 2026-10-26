"""Translate Clang's typed AST of rendered scalar C to SMT bit vectors.

Run through uv. No Python packages or runtime dependencies are required.
Unsupported syntax fails the test instead of silently reducing coverage.
"""

import json
import re
import subprocess
import sys


def integer_type(node):
    info = node["type"]
    text = info.get("desugaredQualType", info["qualType"])
    text = text.replace("const ", "")
    if text == "_Bool":
        return 1, False
    if text.startswith("uint") or text.startswith("int"):
        match = re.fullmatch(r"(u?)int(8|16|32|64|128)_t", text)
        if match:
            return int(match[2]), not match[1]
    widths = {"char": 8, "short": 16, "int": 32, "long": 64, "long long": 64, "__int128": 128}
    signed = not text.startswith("unsigned ")
    plain = text.removeprefix("unsigned ").removeprefix("signed ")
    if plain not in widths:
        raise ValueError(f"unsupported C integer type: {text}")
    return widths[plain], signed


def bv(n, bits):
    return f"(_ bv{n % (1 << bits)} {bits})"


def cast(term, old, new, signed):
    if old > new:
        return f"((_ extract {new - 1} 0) {term})"
    if old < new:
        return f"((_ {'sign_extend' if signed else 'zero_extend'} {new - old}) {term})"
    return term


def truth(term, bits):
    return f"(not (= {term} {bv(0, bits)}))"


def bounds(node):
    bits, signed = integer_type(node)
    full = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1)
    children = node.get("inner", [])
    kind = node["kind"]
    if kind == "IntegerLiteral":
        value = int(node["value"])
        return value, value
    if kind in ("ParenExpr", "ConstantExpr"):
        return bounds(children[0])
    if kind in ("ImplicitCastExpr", "CStyleCastExpr"):
        inner = bounds(children[0])
        if full[0] <= inner[0] and inner[1] <= full[1]:
            return inner
    return full


def expression(node, parameters):
    kind = node["kind"]
    children = node.get("inner", [])
    if kind == "CallExpr":
        callee = children[0]
        while callee.get("inner"):
            callee = callee["inner"][0]
        name = callee["referencedDecl"]["name"]
        a, width, _, valid = expression(children[1], parameters)
        if name.startswith("__builtin_bitreverse"):
            term = f"((_ extract 0 0) {a})"
            for index in range(1, width):
                term = f"(concat {term} ((_ extract {index} {index}) {a}))"
            return term, width, False, valid
        if name.startswith(("__builtin_clz", "__builtin_ctz")):
            bits, sign = integer_type(node)
            leading = name.startswith("__builtin_clz")
            result = bv(width, bits)
            for index in range(width):
                bit = index if leading else width - 1 - index
                result = f"(ite (= ((_ extract {bit} {bit}) {a}) #b1) {bv(width - 1 - index, bits)} {result})"
            if name.endswith("g"):
                assert not integer_type(children[1])[1]
                fallback, fallback_bits, fallback_sign, fallback_valid = expression(children[2], parameters)
                fallback = cast(fallback, fallback_bits, bits, fallback_sign)
                result = f"(ite (= {a} {bv(0, width)}) {fallback} {result})"
                valid = f"(and {valid} {fallback_valid})"
            else:
                valid = f"(and {valid} {truth(a, width)})"
            return result, bits, sign, valid
        raise ValueError(f"unsupported C call: {name}")
    bits, signed = integer_type(node)
    if kind == "IntegerLiteral":
        return bv(int(node["value"]), bits), bits, signed, "true"
    if kind == "DeclRefExpr":
        name = node["referencedDecl"]["name"]
        return cast(parameters[name], 64, bits, False), bits, signed, "true"
    if kind in ("ParenExpr", "ConstantExpr"):
        return expression(children[0], parameters)
    if kind in ("ImplicitCastExpr", "CStyleCastExpr"):
        a, old, sign, defined = expression(children[0], parameters)
        if node.get("castKind") == "IntegralToBoolean":
            a = f"(ite {truth(a, old)} {bv(1, bits)} {bv(0, bits)})"
        else:
            a = cast(a, old, bits, sign)
        return a, bits, signed, defined
    if kind == "ConditionalOperator":
        condition, cbits, _, cd = expression(children[0], parameters)
        a, _, _, ad = expression(children[1], parameters)
        b, _, _, bd = expression(children[2], parameters)
        condition = truth(condition, cbits)
        return f"(ite {condition} {a} {b})", bits, signed, f"(and {cd} (ite {condition} {ad} {bd}))"
    if kind == "UnaryOperator":
        a, abits, _, defined = expression(children[0], parameters)
        op = node["opcode"]
        if op == "!":
            return f"(ite {truth(a, abits)} {bv(0, bits)} {bv(1, bits)})", bits, signed, defined
        if op == "-":
            if signed:
                defined = f"(and {defined} (not (= {a} {bv(1 << (bits - 1), bits)})))"
            a = f"(bvneg {a})"
        elif op == "~":
            a = f"(bvnot {a})"
        elif op != "+":
            raise ValueError(f"unsupported unary C operator: {op}")
        return a, bits, signed, defined
    if kind != "BinaryOperator":
        raise ValueError(f"unsupported C AST node: {kind}")
    a, abits, asign, ad = expression(children[0], parameters)
    b, bbits, _, bd = expression(children[1], parameters)
    op = node["opcode"]
    defined = f"(and {ad} {bd})"
    if op in ("&&", "||"):
        at, bt = truth(a, abits), truth(b, bbits)
        result = f"({'and' if op == '&&' else 'or'} {at} {bt})"
        defined = f"(and {ad} (ite {at} {bd if op == '&&' else 'true'} {'true' if op == '&&' else bd}))"
        return f"(ite {result} {bv(1, bits)} {bv(0, bits)})", bits, signed, defined
    if op in ("==", "!=", "<", ">", "<=", ">="):
        assert abits == bbits
        operator = {"==": "=", "!=": "=", "<": "lt", ">": "gt", "<=": "le", ">=": "ge"}[op]
        if operator != "=":
            operator = "bv" + ("s" if asign else "u") + operator
        result = f"({operator} {a} {b})"
        if op == "!=":
            result = f"(not {result})"
        return f"(ite {result} {bv(1, bits)} {bv(0, bits)})", bits, signed, defined
    if op in ("<<", ">>"):
        count_ok = f"(and (bvuge {b} {bv(0, bbits)}) (bvult {b} {bv(bits, bbits)}))"
        b = cast(b, bbits, bits, False)
        operator = "bvshl" if op == "<<" else ("bvashr" if signed else "bvlshr")
        result = f"({operator} {a} {b})"
        defined = f"(and {defined} {count_ok})"
        if signed and op == "<<":
            wide = f"(bvshl ((_ zero_extend {bits}) {a}) ((_ zero_extend {bits}) {b}))"
            defined = f"(and {defined} (bvsge {a} {bv(0, bits)}) (= {wide} ((_ sign_extend {bits}) {result})))"
        return result, bits, signed, defined
    assert abits == bbits == bits
    operator = {"+": "bvadd", "-": "bvsub", "*": "bvmul", "&": "bvand", "|": "bvor", "^": "bvxor", "/": "bvsdiv" if signed else "bvudiv", "%": "bvsrem" if signed else "bvurem"}[op]
    result = f"({operator} {a} {b})"
    if op in ("/", "%"):
        defined = f"(and {defined} (not (= {b} {bv(0, bits)})))"
        if signed:
            defined = f"(and {defined} (not (and (= {a} {bv(1 << (bits - 1), bits)}) (= {b} {bv(-1, bits)}))))"
    if signed and op in ("+", "-", "*"):
        al, ah = bounds(children[0])
        bl, bh = bounds(children[1])
        if op == "+":
            possible = (al + bl, ah + bh)
        elif op == "-":
            possible = (al - bh, ah - bl)
        else:
            products = [al * bl, al * bh, ah * bl, ah * bh]
            possible = min(products), max(products)
        if possible[0] < -(1 << (bits - 1)) or possible[1] >= 1 << (bits - 1):
            wide = f"({operator} ((_ sign_extend {bits}) {a}) ((_ sign_extend {bits}) {b}))"
            defined = f"(and {defined} (= {wide} ((_ sign_extend {bits}) {result})))"
    return result, bits, signed, defined


def main():
    request = json.load(sys.stdin)
    result = subprocess.run(["clang", "-x", "c", "-std=c11", "-Werror=implicit-function-declaration", "-Xclang", "-ast-dump=json", "-fsyntax-only", "-"], input=request["source"], text=True, capture_output=True, check=False)
    if result.returncode:
        raise ValueError(result.stderr)
    tree = json.loads(result.stdout)
    output = []
    names = set(request["names"])
    for node in tree["inner"]:
        if node["kind"] != "FunctionDecl" or node["name"] not in names:
            continue
        name = node["name"]
        parameters = {}
        for child in node["inner"]:
            if child["kind"] == "ParmVarDecl":
                parameters[child["name"]] = f"r{[7, 6, 2][len(parameters)]}"
        body = node["inner"][-1]
        if body["kind"] != "CompoundStmt":
            raise ValueError(f"{name}: expected a function body")
        term, defined = statements(body.get("inner", []), parameters, "true")
        output.append({"name": name, "term": term, "defined": defined})
    if len(output) != len(names):
        raise ValueError("Clang did not return every requested function")
    json.dump(output, sys.stdout)


def statements(nodes, values, defined):
    values = dict(values)
    for index, node in enumerate(nodes):
        kind = node["kind"]
        children = node.get("inner", [])
        if kind == "ReturnStmt":
            term, bits, sign, valid = expression(children[0], values)
            return cast(term, bits, 64, sign), f"(and {defined} {valid})"
        if kind == "DeclStmt":
            for declaration in children:
                if declaration["kind"] != "VarDecl":
                    raise ValueError(f"unsupported declaration: {declaration['kind']}")
                initializers = declaration.get("inner", [])
                if initializers:
                    term, bits, sign, valid = expression(initializers[-1], values)
                    values[declaration["name"]] = cast(term, bits, 64, sign)
                    defined = f"(and {defined} {valid})"
            continue
        if kind in ("BinaryOperator", "CompoundAssignOperator") and node["opcode"].endswith("="):
            lhs, rhs = children
            if lhs["kind"] != "DeclRefExpr":
                raise ValueError("assignment target must be a scalar variable")
            if node["opcode"] != "=":
                # Clang records the arithmetic type separately from the destination.
                calculation = dict(node, kind="BinaryOperator", opcode=node["opcode"][:-1], type=node["computeResultType"])
                calculation["inner"] = [dict(kind="CStyleCastExpr", type=node["computeLHSType"], inner=[lhs]), rhs]
                rhs = dict(kind="CStyleCastExpr", type=lhs["type"], inner=[calculation])
            term, bits, sign, valid = expression(rhs, values)
            values[lhs["referencedDecl"]["name"]] = cast(term, bits, 64, sign)
            defined = f"(and {defined} {valid})"
            continue
        if kind == "IfStmt":
            condition, cbits, _, valid = expression(children[0], values)
            branches = []
            for arm in [children[1], children[2] if len(children) > 2 else None]:
                prefix = [] if arm is None else (arm.get("inner", []) if arm["kind"] == "CompoundStmt" else [arm])
                branches.append(statements(prefix + nodes[index + 1:], values, f"(and {defined} {valid})"))
            test = truth(condition, cbits)
            return f"(ite {test} {branches[0][0]} {branches[1][0]})", f"(ite {test} {branches[0][1]} {branches[1][1]})"
        if kind == "NullStmt":
            continue
        raise ValueError(f"unsupported C statement: {kind}")
    raise ValueError("scalar function must return on every path")


if __name__ == "__main__":
    main()
