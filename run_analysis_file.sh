#!/usr/bin/env bash

result=$(/opt/clang/15/bin/clang-query -c 'm stmt(unaryOperator(anyOf(hasOperatorName("++"), hasOperatorName("--")), hasUnaryOperand(declRefExpr(to(varDecl(hasType(anyOf(asString("pte_t *"), asString("pmd_t *"), asString("pud_t *"), asString("p4d_t *"), asString("pgd_t *")))))))))' --extra-arg=-Wno-unknown-warning-option --extra-arg=-Wno-gnu-variable-sized-type-not-at-end --extra-arg=-Wno-debug-compression-unavailable --extra-arg=-Wno-ignored-optimization-argument "$1" 2>&1 | rg --no-config -v '^error:')

if [ "$result" = "0 matches." ]; then
	echo "@@ $1"
	exit 0
fi

echo

echo '----------------------------------------------------'
echo "$1"
echo '----------------------------------------------------'

echo

echo "$result"

echo
