package main

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Used to "fix" imports
// Run like so:
//  go run ../fix/ ~/Downloads/github.com/aws github.com/aws/aws-sdk-go github.com/Netflix/titus-executor/aws/aws-sdk-go

func iterate(fset *token.FileSet, file *ast.File, name, srcDir, originalPrefix, newPrefix string) error {
	path, err := filepath.Rel(srcDir, name)
	if err != nil {
		return err
	}
	//fmt.Printf("Moving file %s -> %s\n", name, path)
	// fmt.Println("SrcDir: " + srcDir)
	// Borrowed from: https://github.com/golang/tools/blob/master/go/ast/astutil/imports.go#L329
	for _, imp := range file.Imports {
		t, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return err
		}
		if strings.HasPrefix(t, originalPrefix) {
			newImportPath := newPrefix + t[len(originalPrefix):]
			imp.EndPos = imp.End()
			imp.Path.Value = strconv.Quote(newImportPath)
		}
	}
	out, err := os.OpenFile(path, os.O_RDWR|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer out.Close()
	err = printer.Fprint(out, fset, file)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	srcDir := os.Args[1]
	originalPrefix := os.Args[2]
	newPrefix := os.Args[3]
	_ = originalPrefix
	walk := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relpath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			err = os.MkdirAll(relpath, 0755)
			if err != nil {
				return err
			}

			fset := token.NewFileSet()
			pkgs, err := parser.ParseDir(fset, path, nil, parser.ParseComments)
			if err != nil {
				return err
			}
			/*
				fset.Iterate(func(file *token.File) bool {
					err = iterate(file, srcDir, newDir, originalPrefix)
					if err != nil {
						return false
					}
					return true
				})
			*/
			for _, pkg := range pkgs {
				for name, file := range pkg.Files {
					err = iterate(fset, file, name, srcDir, originalPrefix, newPrefix)
					if err != nil {
						return err
					}
				}
			}

		}
		return nil
	}
	err := filepath.Walk(srcDir, walk)
	if err != nil {
		panic(err)
	}
}
