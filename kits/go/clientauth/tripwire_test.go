package clientauth

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// A tripwire, not a proof: it fails when the comparison of two secrets stops being a call of subtle.ConstantTimeCompare over the
// digests, which no behaviour test can see (`==` on the same values gives the same answers, only faster when they differ). It
// does not show that the comparison takes the same time; REQ-CLIENT-015 stays partial until a test can.
func TestTripwireTheComparisonOfSecretsIsSubtleConstantTimeCompare(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "clientauth.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var equal *ast.FuncDecl
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "equal" {
			equal = fn
		}
	}
	if equal == nil {
		t.Fatal("the package has no function equal: the comparison of secrets moved, and this test with it")
	}
	var calls, compares int
	ast.Inspect(equal.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "subtle" && sel.Sel.Name == "ConstantTimeCompare" {
					calls++
				}
			}
		case *ast.BinaryExpr:
			if x.Op == token.EQL || x.Op == token.NEQ {
				compares++
			}
		}
		return true
	})
	// The result of ConstantTimeCompare is compared with 1, which is the one == there is.
	if calls != 1 || compares != 1 {
		t.Errorf("equal calls subtle.ConstantTimeCompare %d times and has %d comparisons with == or !=, want 1 and 1", calls, compares)
	}
	for _, imp := range f.Imports {
		if imp.Path.Value == `"bytes"` {
			t.Error("the package imports bytes, whose Equal is not constant time")
		}
	}
	// Authenticate compares through the one function, which tests replace to count.
	var viaCompare bool
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "Authenticate" {
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok {
					if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "compare" {
						viaCompare = true
					}
				}
				return true
			})
		}
	}
	if !viaCompare {
		t.Error("Authenticate does not compare through a.compare")
	}
}
