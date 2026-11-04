package rpc

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"testing"
)

// A normal build of the package must not contain WithNameResolver: product code could use it to rename its callers.
// go/build with the default context leaves the file with the tag sluis_test out, as a normal `go build` does, so
// this check holds whatever tags the test run itself uses.
func TestNormalBuildHasNoNameResolverSeam(t *testing.T) {
	pkg, err := build.Default.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, name := range pkg.GoFiles {
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "WithNameResolver" {
				t.Fatalf("%s declares WithNameResolver in a build without the tag sluis_test", name)
			}
		}
	}
}
