#pragma once

// A question, written down.
//
// The solve can answer "which input makes the machine do X", and the
// useful X is rarely a single slot holding a single number. A checker
// compares a hash, a length and a magic constant, in that order, and each
// of those is a different shape of question about the state the run left
// behind.
//
// So a goal is written in a small language over the machine's own state
// -- the register file the layout inference found, the bytecode buffer,
// arbitrary memory at arbitrary width, the interpreter's registers -- and
// this file is that language: the parse tree, the parser, and the
// renderer that turns a tree back into the text a report shows. Nothing
// here knows what a virtual machine is; it knows what an expression is.
//
// The grammar, loosest binding first:
//
//     goal    := disj
//     disj    := conj ('||' conj)*
//     conj    := rel ('&&' rel)*
//     rel     := bitor (RELOP bitor)?
//     RELOP   := '==' | '=' | '!=' | '<u' | '<=u' | '>u' | '>=u'
//              | '<' | '<=' | '>' | '>=' | '<s' | '<=s' | '>s' | '>=s'
//     bitor   := bitxor ('|' bitxor)*
//     bitxor  := bitand ('^' bitand)*
//     bitand  := shift ('&' shift)*
//     shift   := add (('<<' | '>>') add)*
//     add     := mul (('+' | '-') mul)*
//     mul     := unary ('*' unary)*
//     unary   := ('~' | '-' | '!') unary | primary
//     primary := number | ident | ident '[' goal ']'
//              | 'mem' [width] '[' goal ']' | '(' goal ')'
//
// The precedence is C's, because a person writing a condition has C's in
// their fingers and a language that quietly disagreed would be a trap.
//
// A bare `<` and `<=` are unsigned, which is what a machine's own compare
// is; the suffix says so out loud and the `s` forms are the signed
// reading, kept because a checker's length test is often signed and a
// goal that reads it the other way is a different question.
//
// The names it accepts as leaves are the ones the report already prints,
// so a goal can be written by reading a report:
//
//     vst[i]        the register file at the layout-inferred element
//                   width, i a byte offset from its base exactly as a
//                   slot write prints it
//     code[i]       one byte of the bytecode buffer
//     mem64[a]      memory at a width (mem8/mem16/mem32/mem64; a bare
//                   `mem[a]` is mem64)
//     rax, rsp, …   a general register, as the last row carried it
//
// and the operators are the machine's own arithmetic at the width of
// their operands.

#include <cstdint>
#include <string>
#include <vector>

namespace occ::devirt::lift {

// One node of a parsed goal. A tree rather than a DAG: a goal is written
// by a person and is the size a person writes, and a tree is the shape
// that can be rendered back without a budget.
struct GoalNode {
    enum class Kind : std::uint8_t {
        Const,
        // The register file at a byte offset from its base, at the
        // element width the layout inference found.
        Regfile,
        // One byte of the bytecode buffer.
        Code,
        // Memory at `imm` bits, addressed by kids[0].
        Memory,
        // A general register of the interpreter.
        Register,
        Add, Sub, Mul, And, Or, Xor, Shl, Shr,
        Eq, Ne, Ult, Ule, Slt, Sle,
        Not, Neg, LogNot, LogAnd, LogOr,
    };
    Kind kind = Kind::Const;
    std::uint64_t imm = 0;  // Const: the value; Memory: the width in bits
    std::string name;       // Register: which one, in kRowGprNames spelling
    std::vector<GoalNode> kids;
};

// Parses `text`. On failure returns false and puts a sentence in
// `*error` naming what was expected and where -- an offset is more use
// than "syntax error" when the text is a hundred characters of C.
[[nodiscard]] bool parse_goal(const std::string& text, GoalNode* out,
                              std::string* error);

// The text a report shows for a tree. It is not the caller's text
// verbatim: a goal is echoed after the machine's own names have replaced
// any shorthand, so the report and the answer use the same vocabulary.
[[nodiscard]] std::string render_goal(const GoalNode& node);

// Whether the tree's root is a condition -- something that can be true or
// false -- as opposed to a value. A goal that names a value and stops has
// not asked a question, and saying so is better than comparing it to
// nothing.
[[nodiscard]] bool goal_is_condition(const GoalNode& node);

}  // namespace occ::devirt::lift
