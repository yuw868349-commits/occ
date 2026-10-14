#include "occ/devirt/goal.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace occ::devirt::lift {

namespace {

// How deep a goal may nest before the parser calls it a runaway. A
// hundred-character condition nests five deep; the cap is a guard against
// a generated goal, not a policy about hand-written ones.
constexpr unsigned kMaxGoalDepth = 200;

// C's binding levels, loosest first. The parser is a descent through
// them and the renderer walks the same table in reverse to decide where a
// parenthesis is needed, so the two cannot disagree about what a goal
// means.
enum class Level : int {
    kLogOr = 1,
    kLogAnd,
    kRel,
    kBitOr,
    kBitXor,
    kBitAnd,
    kShift,
    kAdd,
    kMul,
    kUnary,
    kPrimary,
};

class Parser {
public:
    explicit Parser(const std::string& text) : s_(text) {}

    [[nodiscard]] bool parse(GoalNode* out, std::string* error) {
        skip();
        GoalNode n = disjunction(0);
        skip();
        if (!failed_ && pos_ != s_.size()) {
            fail(std::string("unexpected '") + s_.substr(pos_) +
                 "' after the condition");
        }
        if (failed_) {
            *error = error_;
            return false;
        }
        if (n.kind == GoalNode::Kind::Const) {
            // `--goal 0` asks nothing. Saying so is better than silently
            // solving for a condition nobody wrote.
            fail("a goal has to be a condition -- something that can be "
                 "true or false -- and this is a value");
            *error = error_;
            return false;
        }
        *out = std::move(n);
        return true;
    }

private:
    void skip() {
        while (pos_ < s_.size() &&
               std::isspace(static_cast<unsigned char>(s_[pos_])) != 0) {
            ++pos_;
        }
    }

    [[nodiscard]] bool at(const char* what) const {
        const std::size_t n = std::char_traits<char>::length(what);
        return s_.compare(pos_, n, what) == 0;
    }

    bool eat(const char* what) {
        if (at(what)) {
            pos_ += std::char_traits<char>::length(what);
            return true;
        }
        return false;
    }

    void fail(std::string what) {
        if (failed_) {
            return;
        }
        failed_ = true;
        char b[32];
        std::snprintf(b, sizeof(b), "at offset %zu: ", pos_);
        error_ = std::string(b) + std::move(what);
    }

    [[nodiscard]] static GoalNode leaf(GoalNode::Kind kind) {
        GoalNode n;
        n.kind = kind;
        return n;
    }

    [[nodiscard]] static GoalNode unary_node(GoalNode::Kind kind,
                                             GoalNode kid) {
        GoalNode n = leaf(kind);
        n.kids.push_back(std::move(kid));
        return n;
    }

    [[nodiscard]] static GoalNode binary_node(GoalNode::Kind kind, GoalNode a,
                                              GoalNode b) {
        GoalNode n = leaf(kind);
        n.kids.push_back(std::move(a));
        n.kids.push_back(std::move(b));
        return n;
    }

    [[nodiscard]] GoalNode disjunction(unsigned depth) {
        GoalNode a = conjunction(depth);
        while (!failed_) {
            skip();
            if (!eat("||")) {
                return a;
            }
            a = binary_node(GoalNode::Kind::LogOr, std::move(a),
                            conjunction(depth));
        }
        return a;
    }

    [[nodiscard]] GoalNode conjunction(unsigned depth) {
        GoalNode a = relation(depth);
        while (!failed_) {
            skip();
            if (!eat("&&")) {
                return a;
            }
            a = binary_node(GoalNode::Kind::LogAnd, std::move(a),
                            relation(depth));
        }
        return a;
    }

    // RELOP, longest first: '<=' before '<', '<u' before '<'. Getting this
    // order wrong turns `a <= b` into a comparison of `a` with `= b`.
    [[nodiscard]] bool relation_op(GoalNode::Kind* kind, unsigned* consumed) {
        struct Entry {
            const char* text;
            GoalNode::Kind kind;
        };
        static const Entry kTable[] = {
            {"<=", GoalNode::Kind::Ule}, {"<u", GoalNode::Kind::Ult},
            {"<s", GoalNode::Kind::Slt}, {">=", GoalNode::Kind::Ule},
            {">u", GoalNode::Kind::Ult}, {">s", GoalNode::Kind::Slt},
            {"==", GoalNode::Kind::Eq},  {"!=", GoalNode::Kind::Ne},
            {"=", GoalNode::Kind::Eq},   {"<", GoalNode::Kind::Ult},
            {">", GoalNode::Kind::Ult},
        };
        for (const Entry& e : kTable) {
            const std::size_t n = std::char_traits<char>::length(e.text);
            if (s_.compare(pos_, n, e.text) != 0) {
                continue;
            }
            // '<<' and '>>' are shifts, not two comparisons, and a
            // comparison written '<' immediately before '<' is a goal
            // that meant the shift.
            if ((e.text[0] == '<' && at("<<")) ||
                (e.text[0] == '>' && at(">>"))) {
                continue;
            }
            *kind = e.kind;
            *consumed = static_cast<unsigned>(n);
            // A `>` swaps its operands so the tree only ever holds the
            // unsigned or signed *less than* it can express: fewer kinds,
            // one rendering, no second printing rule.
            return true;
        }
        return false;
    }

    [[nodiscard]] GoalNode relation(unsigned depth) {
        GoalNode a = bit_or(depth);
        skip();
        GoalNode::Kind kind = GoalNode::Kind::Eq;
        unsigned consumed = 0;
        if (!relation_op(&kind, &consumed)) {
            return a;
        }
        const bool swapped = s_[pos_] == '>';
        pos_ += consumed;
        GoalNode b = bit_or(depth);
        if (failed_) {
            return a;
        }
        if (swapped) {
            std::swap(a, b);
        }
        return binary_node(kind, std::move(a), std::move(b));
    }

    [[nodiscard]] GoalNode bit_or(unsigned depth) {
        GoalNode a = bit_xor(depth);
        while (!failed_) {
            skip();
            // '||' belongs to the level above; eating one operand of it
            // here would read a disjunction as a bitwise or.
            if (at("||") || !eat("|")) {
                return a;
            }
            a = binary_node(GoalNode::Kind::Or, std::move(a), bit_xor(depth));
        }
        return a;
    }

    [[nodiscard]] GoalNode bit_xor(unsigned depth) {
        GoalNode a = bit_and(depth);
        while (!failed_) {
            skip();
            if (!eat("^")) {
                return a;
            }
            a = binary_node(GoalNode::Kind::Xor, std::move(a), bit_and(depth));
        }
        return a;
    }

    [[nodiscard]] GoalNode bit_and(unsigned depth) {
        GoalNode a = shift(depth);
        while (!failed_) {
            skip();
            if (at("&&") || !eat("&")) {
                return a;
            }
            a = binary_node(GoalNode::Kind::And, std::move(a), shift(depth));
        }
        return a;
    }

    [[nodiscard]] GoalNode shift(unsigned depth) {
        GoalNode a = add(depth);
        while (!failed_) {
            skip();
            if (eat("<<")) {
                a = binary_node(GoalNode::Kind::Shl, std::move(a), add(depth));
            } else if (eat(">>")) {
                a = binary_node(GoalNode::Kind::Shr, std::move(a), add(depth));
            } else {
                return a;
            }
        }
        return a;
    }

    [[nodiscard]] GoalNode add(unsigned depth) {
        GoalNode a = mul(depth);
        while (!failed_) {
            skip();
            if (eat("+")) {
                a = binary_node(GoalNode::Kind::Add, std::move(a), mul(depth));
            } else if (pos_ < s_.size() && s_[pos_] == '-') {
                ++pos_;
                a = binary_node(GoalNode::Kind::Sub, std::move(a), mul(depth));
            } else {
                return a;
            }
        }
        return a;
    }

    [[nodiscard]] GoalNode mul(unsigned depth) {
        GoalNode a = unary(depth);
        while (!failed_) {
            skip();
            if (!eat("*")) {
                return a;
            }
            a = binary_node(GoalNode::Kind::Mul, std::move(a), unary(depth));
        }
        return a;
    }

    [[nodiscard]] GoalNode unary(unsigned depth) {
        skip();
        if (depth > kMaxGoalDepth) {
            fail("the goal nests too deeply");
            return leaf(GoalNode::Kind::Const);
        }
        if (eat("~")) {
            return unary_node(GoalNode::Kind::Not, unary(depth + 1));
        }
        if (eat("!")) {
            // '!=' is a comparison and was already eaten by the level
            // above; a '!' that survives to here is a negation.
            return unary_node(GoalNode::Kind::LogNot, unary(depth + 1));
        }
        if (pos_ < s_.size() && s_[pos_] == '-') {
            ++pos_;
            return unary_node(GoalNode::Kind::Neg, unary(depth + 1));
        }
        return primary(depth);
    }

    [[nodiscard]] GoalNode parenthesized(unsigned depth) {
        skip();
        if (!eat("(")) {
            return GoalNode{};
        }
        GoalNode inner = disjunction(depth + 1);
        skip();
        if (!eat(")")) {
            fail("a '(' is never closed");
        }
        return inner;
    }

    [[nodiscard]] GoalNode number() {
        const std::size_t start = pos_;
        if (at("0x") || at("0X")) {
            pos_ += 2;
            while (pos_ < s_.size() &&
                   std::isxdigit(static_cast<unsigned char>(s_[pos_])) != 0) {
                ++pos_;
            }
        } else {
            while (pos_ < s_.size() &&
                   std::isdigit(static_cast<unsigned char>(s_[pos_])) != 0) {
                ++pos_;
            }
        }
        GoalNode n = leaf(GoalNode::Kind::Const);
        n.imm = std::strtoull(s_.substr(start, pos_ - start).c_str(), nullptr,
                              0);
        return n;
    }

    [[nodiscard]] GoalNode identifier() {
        const std::size_t start = pos_;
        while (pos_ < s_.size() &&
               (std::isalnum(static_cast<unsigned char>(s_[pos_])) != 0 ||
                s_[pos_] == '_')) {
            ++pos_;
        }
        const std::string name = s_.substr(start, pos_ - start);

        // `mem8`..`mem64`, and a bare `mem` for the machine's own width.
        if (name.rfind("mem", 0) == 0) {
            const std::string tail = name.substr(3);
            unsigned bits = 64;
            if (!tail.empty()) {
                bool digits = true;
                for (const char c : tail) {
                    digits = digits && std::isdigit(
                                            static_cast<unsigned char>(c)) != 0;
                }
                if (!digits) {
                    fail("'" + name +
                         "' is not a memory width; write mem8, mem16, mem32 "
                         "or mem64");
                    return leaf(GoalNode::Kind::Const);
                }
                bits = static_cast<unsigned>(std::strtoul(tail.c_str(),
                                                          nullptr, 10));
                if (bits != 8 && bits != 16 && bits != 32 && bits != 64) {
                    fail("a memory width is 8, 16, 32 or 64 bits, not '" +
                         tail + "'");
                    return leaf(GoalNode::Kind::Const);
                }
            }
            GoalNode n = leaf(GoalNode::Kind::Memory);
            n.imm = bits;
            return with_index(std::move(n), name);
        }
        if (name == "vst" || name == "regfile") {
            return with_index(leaf(GoalNode::Kind::Regfile), name);
        }
        if (name == "code") {
            return with_index(leaf(GoalNode::Kind::Code), name);
        }
        // Anything else is a register. It is not checked against the
        // machine's register names here: whether the interpreter carried
        // it is a fact about the trace, and the replay is the only place
        // that knows -- a name the trace did not carry becomes a variable
        // of its own and is counted as one.
        GoalNode reg = leaf(GoalNode::Kind::Register);
        reg.name = name;
        return reg;
    }

    // The `[index]` a named leaf needs.
    [[nodiscard]] GoalNode with_index(GoalNode n, const std::string& name) {
        skip();
        if (!at("[")) {
            fail("'" + name + "' needs an index: write " + name + "[...]");
            return n;
        }
        pos_ += 1;
        GoalNode index = disjunction(0);
        skip();
        if (!eat("]")) {
            fail("a '[' is never closed");
            return n;
        }
        n.kids.push_back(std::move(index));
        return n;
    }

    [[nodiscard]] GoalNode primary(unsigned depth) {
        skip();
        if (pos_ >= s_.size()) {
            fail("the goal ends where an operand was expected");
            return leaf(GoalNode::Kind::Const);
        }
        if (s_[pos_] == '(') {
            return parenthesized(depth);
        }
        if (std::isdigit(static_cast<unsigned char>(s_[pos_])) != 0) {
            return number();
        }
        if (std::isalpha(static_cast<unsigned char>(s_[pos_])) != 0 ||
            s_[pos_] == '_') {
            return identifier();
        }
        fail(std::string("'") + s_[pos_] + "' is not the start of an operand");
        return leaf(GoalNode::Kind::Const);
    }

    const std::string& s_;
    std::size_t pos_ = 0;
    bool failed_ = false;
    std::string error_;
};

// The parser's own binding levels, for the renderer. They are the same
// numbers the descent walked, so a rendering re-parsed reads the same
// tree.
[[nodiscard]] int level_of(const GoalNode& n) {
    switch (n.kind) {
    case GoalNode::Kind::LogOr:  return static_cast<int>(Level::kLogOr);
    case GoalNode::Kind::LogAnd: return static_cast<int>(Level::kLogAnd);
    case GoalNode::Kind::Eq:
    case GoalNode::Kind::Ne:
    case GoalNode::Kind::Ult:
    case GoalNode::Kind::Ule:
    case GoalNode::Kind::Slt:
    case GoalNode::Kind::Sle:    return static_cast<int>(Level::kRel);
    case GoalNode::Kind::Or:     return static_cast<int>(Level::kBitOr);
    case GoalNode::Kind::Xor:    return static_cast<int>(Level::kBitXor);
    case GoalNode::Kind::And:    return static_cast<int>(Level::kBitAnd);
    case GoalNode::Kind::Shl:
    case GoalNode::Kind::Shr:    return static_cast<int>(Level::kShift);
    case GoalNode::Kind::Add:
    case GoalNode::Kind::Sub:    return static_cast<int>(Level::kAdd);
    case GoalNode::Kind::Mul:    return static_cast<int>(Level::kMul);
    case GoalNode::Kind::Not:
    case GoalNode::Kind::Neg:
    case GoalNode::Kind::LogNot: return static_cast<int>(Level::kUnary);
    default:                     return static_cast<int>(Level::kPrimary);
    }
}

[[nodiscard]] const char* rel_text(GoalNode::Kind kind) {
    switch (kind) {
    case GoalNode::Kind::Eq:  return " == ";
    case GoalNode::Kind::Ne:  return " != ";
    case GoalNode::Kind::Ule: return " <=u ";
    case GoalNode::Kind::Sle: return " <=s ";
    case GoalNode::Kind::Slt: return " <s ";
    default:                  return " <u ";
    }
}

void render_into(const GoalNode& n, int parent_level, std::string* out) {
    const int level = level_of(n);
    const bool paren = level < parent_level;
    if (paren) {
        *out += "(";
    }
    char buf[32];
    switch (n.kind) {
    case GoalNode::Kind::Const:
        std::snprintf(buf, sizeof(buf), "0x%llx",
                      static_cast<unsigned long long>(n.imm));
        *out += buf;
        break;
    case GoalNode::Kind::Register:
        *out += n.name;
        break;
    case GoalNode::Kind::Regfile:
        *out += "vst[";
        render_into(n.kids[0], 0, out);
        *out += "]";
        break;
    case GoalNode::Kind::Code:
        *out += "code[";
        render_into(n.kids[0], 0, out);
        *out += "]";
        break;
    case GoalNode::Kind::Memory:
        *out += "mem" + std::to_string(n.imm) + "[";
        render_into(n.kids[0], 0, out);
        *out += "]";
        break;
    case GoalNode::Kind::Not:
        *out += "~";
        render_into(n.kids[0], level, out);
        break;
    case GoalNode::Kind::Neg:
        *out += "-";
        render_into(n.kids[0], level, out);
        break;
    case GoalNode::Kind::LogNot:
        *out += "!";
        render_into(n.kids[0], level, out);
        break;
    default: {
        // A relation was stored in the one direction the tree has; the
        // `>` spellings are the same node with its operands the other way
        // round, so a goal written `a > b` prints as `b <u a` -- one
        // direction, one rendering, no second rule to get wrong.
        if (n.kind == GoalNode::Kind::Ult || n.kind == GoalNode::Kind::Ule ||
            n.kind == GoalNode::Kind::Slt || n.kind == GoalNode::Kind::Sle) {
            render_into(n.kids[0], level, out);
            *out += rel_text(n.kind);
            render_into(n.kids[1], level, out);
            break;
        }
        // The right operand is rendered one level tighter, because every
        // binary operator here associates to the left: a tree whose right
        // operand is another operator of the same level came from an
        // explicit parenthesis, and dropping it would change the goal.
        render_into(n.kids[0], level, out);
        switch (n.kind) {
        case GoalNode::Kind::Eq:  *out += " == "; break;
        case GoalNode::Kind::Ne:  *out += " != "; break;
        case GoalNode::Kind::LogOr:  *out += " || "; break;
        case GoalNode::Kind::LogAnd: *out += " && "; break;
        case GoalNode::Kind::Add: *out += " + "; break;
        case GoalNode::Kind::Sub: *out += " - "; break;
        case GoalNode::Kind::Mul: *out += " * "; break;
        case GoalNode::Kind::Or:  *out += " | "; break;
        case GoalNode::Kind::Xor: *out += " ^ "; break;
        case GoalNode::Kind::And: *out += " & "; break;
        case GoalNode::Kind::Shl: *out += " << "; break;
        case GoalNode::Kind::Shr: *out += " >> "; break;
        default: break;
        }
        render_into(n.kids[1], level + 1, out);
        break;
    }
    }
    if (paren) {
        *out += ")";
    }
}

}  // namespace

bool parse_goal(const std::string& text, GoalNode* out, std::string* error) {
    Parser p(text);
    return p.parse(out, error);
}

std::string render_goal(const GoalNode& node) {
    std::string out;
    render_into(node, 0, &out);
    return out;
}

bool goal_is_condition(const GoalNode& node) {
    switch (node.kind) {
    case GoalNode::Kind::Eq:
    case GoalNode::Kind::Ne:
    case GoalNode::Kind::Ult:
    case GoalNode::Kind::Ule:
    case GoalNode::Kind::Slt:
    case GoalNode::Kind::Sle:
    case GoalNode::Kind::LogAnd:
    case GoalNode::Kind::LogOr:
    case GoalNode::Kind::LogNot:
        return true;
    default:
        return false;
    }
}

}  // namespace occ::devirt::lift
