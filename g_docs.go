// Copyright 2013 bee authors
//
// Licensed under the Apache License, Version 2.0 (the "License"): you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package swaggergen

import (
	"archive/zip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/astaxie/beego/logs"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"gopkg.in/yaml.v2"

	"github.com/astaxie/beego/utils"
	beeLogger "github.com/beego/bee/logger"
	bu "github.com/beego/bee/utils"
)

const (
	ajson  = "application/json"
	axml   = "application/xml"
	aplain = "text/plain"
	ahtml  = "text/html"
	aform  = "multipart/form-data"
)

const (
	astTypeArray  = "array"
	astTypeObject = "object"
	astTypeMap    = "map"
)

var (
	pkgCache           map[string]struct{} //pkg:controller:function:comments comments: key:value
	controllerComments map[string]string
	importlist         map[string]string
	controllerList     map[string]map[string]*Item //controllername Paths items
	modelsList         map[string]map[string]Schema
	rootapi            Swagger
	astPkgs            []*ast.Package
)

// refer to builtin.go
var basicTypes = map[string]string{
	"bool":       "boolean:",
	"uint":       "integer:int32",
	"uint8":      "integer:int32",
	"uint16":     "integer:int32",
	"uint32":     "integer:int32",
	"uint64":     "integer:int64",
	"int":        "integer:int64",
	"int8":       "integer:int32",
	"int16":      "integer:int32",
	"int32":      "integer:int32",
	"int64":      "integer:int64",
	"uintptr":    "integer:int64",
	"float32":    "number:float",
	"float64":    "number:double",
	"string":     "string:",
	"complex64":  "number:float",
	"complex128": "number:double",
	"byte":       "string:byte",
	"rune":       "string:byte",
	// builtin golang objects
	"time.Time":       "string:datetime",
	"json.RawMessage": "object:",
}

var stdlibObject = map[string]string{
	"&{time Time}":       "time.Time",
	"&{json RawMessage}": "json.RawMessage",
}

func init() {
	pkgCache = make(map[string]struct{})
	controllerComments = make(map[string]string)
	importlist = make(map[string]string)
	controllerList = make(map[string]map[string]*Item)
	modelsList = make(map[string]map[string]Schema)
	astPkgs = make([]*ast.Package, 0)
}

func AutoInstallSwagger() error {
	swaggerPath := "swagger"
	//检查是否存在swagger文件夹,不存在时自动创建
	_, err := os.Stat(swaggerPath)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(swaggerPath, os.ModePerm); err != nil {
			return err
		}
	}
	//检查是否存在index.html
	_, err = os.Stat(fmt.Sprintf("%s/%s", swaggerPath, "index.html"))
	if os.IsNotExist(err) {
		//自动下载文件
		logs.Notice("开始下载swagger相关的文件")
		//生成swaggerzip
		swaggerZip, err := base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/").
			DecodeString(zipFileBaseStr)
		if err != nil {
			return err
		}
		if err := ioutil.WriteFile("swagger.zip", swaggerZip, 0777); err != nil {
			return err
		}

		logs.Notice("开始解压swagger的相关文件")
		read, err := zip.OpenReader("swagger.zip")
		if err != nil {
			return err
		}
		for _, k := range read.Reader.File {
			r, err := k.Open()
			if err != nil {
				return err
			}
			NewFile, err := os.Create(fmt.Sprintf("%s/%s", swaggerPath, k.FileInfo().Name()))
			if err != nil {
				return err
			}
			if _, err := io.Copy(NewFile, r); err != nil {
				return err
			}
			r.Close()
			NewFile.Close()
		}
	}
	return nil
}

// ParsePackagesFromDir parses packages from a given directory
func parsePackagesFromDir(dirpath string) {
	c := make(chan error)

	go func() {
		filepath.Walk(dirpath, func(fpath string, fileInfo os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !fileInfo.IsDir() {
				return nil
			}

			// skip folder if it's a 'vendor' folder within dirpath or its child,
			// all 'tests' folders and dot folders wihin dirpath
			d, _ := filepath.Rel(dirpath, fpath)
			if !(d == "vendor" || strings.HasPrefix(d, "vendor"+string(os.PathSeparator))) &&
				!strings.Contains(d, "tests") &&
				!(d[0] == '.') {
				err = parsePackageFromDir(fpath, dirpath)
				if err != nil {
					// Send the error to through the channel and continue walking
					c <- fmt.Errorf("error while parsing directory: %s", err.Error())
					return nil
				}
			}
			return nil
		})
		close(c)
	}()

	for err := range c {
		beeLogger.Log.Warnf("%s", err)
	}
}

func parsePackageFromDir(path, sourPath string) error {
	fileSet := token.NewFileSet()
	folderPkgs, err := parser.ParseDir(fileSet, path, func(info os.FileInfo) bool {
		name := info.Name()
		return !info.IsDir() && !strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".go")
	}, parser.ParseComments)
	if err != nil {
		return err
	}
	for _, v := range folderPkgs {
		if strings.Contains(path, "/") {
			v.Name = strings.Replace(path, sourPath+"/", "", -1)
			v.Name = strings.Replace(v.Name, "/", ".", -1)
		} else if strings.Contains(path, `\`) {
			v.Name = strings.Replace(path, sourPath+`\`, "", -1)
			v.Name = strings.Replace(v.Name, `\`, ".", -1)
		}
		astPkgs = append(astPkgs, v)
	}

	return nil
}

func GenerateDocs(curpath string) {
	rootapi.Infos = Information{}
	rootapi.SwaggerVersion = "2.0"
	parsePackagesFromDir(curpath)
	filepath.Walk(filepath.Join(curpath, "routers"), func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			generateDocs(curpath, info.Name())
		}
		return nil
	})
}

// GenerateDocs generates documentations for a given path.
func generateDocs(curpath, name string) {
	fset := token.NewFileSet()

	f, err := parser.ParseFile(fset, filepath.Join(curpath, "routers", name), nil, parser.ParseComments)
	if err != nil {
		beeLogger.Log.Fatalf("Error while parsing router.go: %s", err)
	}

	// Analyse API comments
	if f.Comments != nil {
		for _, c := range f.Comments {
			for _, s := range strings.Split(c.Text(), "\n") {
				if strings.HasPrefix(s, "@APIVersion") {
					rootapi.Infos.Version = strings.TrimSpace(s[len("@APIVersion"):])
				} else if strings.HasPrefix(s, "@Title") {
					rootapi.Infos.Title = strings.TrimSpace(s[len("@Title"):])
				} else if strings.HasPrefix(s, "@Description") {
					rootapi.Infos.Description = strings.TrimSpace(s[len("@Description"):])
				} else if strings.HasPrefix(s, "@TermsOfServiceUrl") {
					rootapi.Infos.TermsOfService = strings.TrimSpace(s[len("@TermsOfServiceUrl"):])
				} else if strings.HasPrefix(s, "@Contact") {
					rootapi.Infos.Contact.EMail = strings.TrimSpace(s[len("@Contact"):])
				} else if strings.HasPrefix(s, "@Name") {
					rootapi.Infos.Contact.Name = strings.TrimSpace(s[len("@Name"):])
				} else if strings.HasPrefix(s, "@URL") {
					rootapi.Infos.Contact.URL = strings.TrimSpace(s[len("@URL"):])
				} else if strings.HasPrefix(s, "@LicenseUrl") {
					if rootapi.Infos.License == nil {
						rootapi.Infos.License = &License{URL: strings.TrimSpace(s[len("@LicenseUrl"):])}
					} else {
						rootapi.Infos.License.URL = strings.TrimSpace(s[len("@LicenseUrl"):])
					}
				} else if strings.HasPrefix(s, "@License") {
					if rootapi.Infos.License == nil {
						rootapi.Infos.License = &License{Name: strings.TrimSpace(s[len("@License"):])}
					} else {
						rootapi.Infos.License.Name = strings.TrimSpace(s[len("@License"):])
					}
				} else if strings.HasPrefix(s, "@Schemes") {
					rootapi.Schemes = strings.Split(strings.TrimSpace(s[len("@Schemes"):]), ",")
				} else if strings.HasPrefix(s, "@Host") {
					rootapi.Host = strings.TrimSpace(s[len("@Host"):])
				} else if strings.HasPrefix(s, "@SecurityDefinition") {
					if len(rootapi.SecurityDefinitions) == 0 {
						rootapi.SecurityDefinitions = make(map[string]Security)
					}
					var out Security
					p := getparams(strings.TrimSpace(s[len("@SecurityDefinition"):]))
					if len(p) < 2 {
						beeLogger.Log.Fatalf("Not enough params for security: %d\n", len(p))
					}
					out.Type = p[1]
					switch out.Type {
					case "oauth2":
						if len(p) < 6 {
							beeLogger.Log.Fatalf("Not enough params for oauth2: %d\n", len(p))
						}
						if !(p[3] == "implicit" || p[3] == "password" || p[3] == "application" || p[3] == "accessCode") {
							beeLogger.Log.Fatalf("Unknown flow type: %s. Possible values are `implicit`, `password`, `application` or `accessCode`.\n", p[1])
						}
						out.AuthorizationURL = p[2]
						out.Flow = p[3]
						if len(p)%2 != 0 {
							out.Description = strings.Trim(p[len(p)-1], `" `)
						}
						out.Scopes = make(map[string]string)
						for i := 4; i < len(p)-1; i += 2 {
							out.Scopes[p[i]] = strings.Trim(p[i+1], `" `)
						}
					case "apiKey":
						if len(p) < 4 {
							beeLogger.Log.Fatalf("Not enough params for apiKey: %d\n", len(p))
						}
						if !(p[3] == "header" || p[3] == "query") {
							beeLogger.Log.Fatalf("Unknown in type: %s. Possible values are `query` or `header`.\n", p[4])
						}
						out.Name = p[2]
						out.In = p[3]
						if len(p) > 4 {
							out.Description = strings.Trim(p[4], `" `)
						}
					case "basic":
						if len(p) > 2 {
							out.Description = strings.Trim(p[2], `" `)
						}
					default:
						beeLogger.Log.Fatalf("Unknown security type: %s. Possible values are `oauth2`, `apiKey` or `basic`.\n", p[1])
					}
					rootapi.SecurityDefinitions[p[0]] = out
				} else if strings.HasPrefix(s, "@Security") {
					if len(rootapi.Security) == 0 {
						rootapi.Security = make([]map[string][]string, 0)
					}
					rootapi.Security = append(rootapi.Security, getSecurity(s))
				}
			}
		}
	}
	// Analyse controller package
	for _, im := range f.Imports {
		localName := ""
		if im.Name != nil {
			localName = im.Name.Name
		}
		analyseControllerPkg(path.Join(curpath, "vendor"), localName, im.Path.Value)
	}
	for _, d := range f.Decls {
		switch specDecl := d.(type) {
		case *ast.FuncDecl:
			for _, l := range specDecl.Body.List {
				switch stmt := l.(type) {
				case *ast.AssignStmt:
					for _, l := range stmt.Rhs {
						if v, ok := l.(*ast.CallExpr); ok {
							// Analyze NewNamespace, it will return version and the subfunction
							selExpr, selOK := v.Fun.(*ast.SelectorExpr)
							if !selOK || selExpr.Sel.Name != "NewNamespace" {
								continue
							}
							version, params := analyseNewNamespace(v)
							if rootapi.BasePath == "" && version != "" {
								if !strings.Contains(version, "/") {
									version = "/" + version
								}
								rootapi.BasePath = version
							}
							for _, p := range params {
								switch pp := p.(type) {
								case *ast.CallExpr:
									var controllerName string
									if selname := pp.Fun.(*ast.SelectorExpr).Sel.String(); selname == "NSNamespace" {
										prefix, others := analyseNewNamespace(pp)
										if !strings.Contains(prefix, "/") {
											prefix = "/" + prefix
										}
										findNS(prefix, others)
									} else if selname == "NSInclude" {
										controllerName = analyseNSInclude("", pp)
										if v, ok := controllerComments[controllerName]; ok {
											rootapi.Tags = append(rootapi.Tags, Tag{
												Name:        controllerName, // if the NSInclude has no prefix, we use the controllername as the tag
												Description: v,
											})
										}
									}
								}
							}
						}

					}
				}
			}
		}
	}
	os.Mkdir(path.Join(curpath, "swagger"), 0755)
	fd, err := os.Create(path.Join(curpath, "swagger", "swagger.json"))
	if err != nil {
		panic(err)
	}
	fdyml, err := os.Create(path.Join(curpath, "swagger", "swagger.yml"))
	if err != nil {
		panic(err)
	}
	defer fdyml.Close()
	defer fd.Close()
	dt, err := json.MarshalIndent(rootapi, "", "    ")
	dtyml, erryml := yaml.Marshal(rootapi)
	if err != nil || erryml != nil {
		panic(err)
	}
	_, err = fd.Write(dt)
	_, erryml = fdyml.Write(dtyml)
	if err != nil || erryml != nil {
		panic(err)
	}
}

func findNS(s string, params []ast.Expr) {
	for _, sp := range params {
		switch pp := sp.(type) {
		case *ast.CallExpr:
			if pp.Fun.(*ast.SelectorExpr).Sel.String() == "NSInclude" {
				controllerName := analyseNSInclude(s, pp)
				if v, ok := controllerComments[controllerName]; ok {
					isExit, name := false, func() string {
						if strings.Contains(s, "/") {
							return s[strings.LastIndex(s, "/")+1:]
						}
						return strings.Trim(s, "/")
					}()
					for _, v := range rootapi.Tags { //tags不存在时再添加
						if v.Name == name {
							isExit = true
						}
					}
					if !isExit {
						rootapi.Tags = append(rootapi.Tags, Tag{
							Name:        name,
							Description: v,
						})
					}
				}
			} else if pp.Fun.(*ast.SelectorExpr).Sel.String() == "NSNamespace" {
				prefix, others := analyseNewNamespace(pp)
				if !strings.Contains(prefix, "/") {
					prefix = "/" + prefix
				}
				findNS(s+prefix, others)
			} else if pp.Fun.(*ast.SelectorExpr).Sel.String() == "NSRouter" {
				controllerName := analyseNSRouter(s, pp)
				if v, ok := controllerComments[controllerName]; ok {
					isExit, name := false, func() string {
						if strings.Contains(s, "/") {
							return s[strings.LastIndex(s, "/")+1:]
						}
						return strings.Trim(s, "/")
					}()
					for _, v := range rootapi.Tags { //tags不存在时再添加
						if v.Name == name {
							isExit = true
						}
					}
					if !isExit {
						rootapi.Tags = append(rootapi.Tags, Tag{
							Name:        name,
							Description: v,
						})
					}

				}

			}
		}
	}
}

// 分析用NewNamespace得添加得方式
func analyseNewNamespace(ce *ast.CallExpr) (first string, others []ast.Expr) {
	for i, p := range ce.Args {
		if i == 0 {
			switch pp := p.(type) {
			case *ast.BasicLit:
				first = strings.Trim(pp.Value, `"`)
			}
			continue
		}
		others = append(others, p)
	}
	return
}

//分析用NSInclude注册路由得方式
func analyseNSInclude(baseurl string, ce *ast.CallExpr) string {
	cname := ""
	for _, p := range ce.Args {
		var x *ast.SelectorExpr
		var p1 interface{} = p
		if ident, ok := p1.(*ast.Ident); ok {
			if assign, ok := ident.Obj.Decl.(*ast.AssignStmt); ok {
				if len(assign.Rhs) > 0 {
					p1 = assign.Rhs[0].(*ast.UnaryExpr)
				}
			}
		}
		if _, ok := p1.(*ast.UnaryExpr); ok {
			x = p1.(*ast.UnaryExpr).X.(*ast.CompositeLit).Type.(*ast.SelectorExpr)
		} else {
			beeLogger.Log.Warnf("Couldn't determine type\n")
			continue
		}
		if v, ok := importlist[fmt.Sprint(x.X)]; ok {
			cname = v + x.Sel.Name
		}
		if apis, ok := controllerList[cname]; ok {
			for rt, item := range apis {
				tag := cname
				if baseurl != "" {
					rt = baseurl + rt
					tag = strings.Trim(baseurl, "/")
				}
				tag = func() string {
					if strings.Contains(tag, "/") {
						return tag[strings.LastIndex(tag, "/")+1:]
					}
					return tag
				}()
				if item.Get != nil {
					item.Get.Tags = []string{tag}
				}
				if item.Post != nil {
					item.Post.Tags = []string{tag}
				}
				if item.Put != nil {
					item.Put.Tags = []string{tag}
				}
				if item.Patch != nil {
					item.Patch.Tags = []string{tag}
				}
				if item.Head != nil {
					item.Head.Tags = []string{tag}
				}
				if item.Delete != nil {
					item.Delete.Tags = []string{tag}
				}
				if item.Options != nil {
					item.Options.Tags = []string{tag}
				}
				if len(rootapi.Paths) == 0 {
					rootapi.Paths = make(map[string]*Item)
				}
				rt = urlReplace(rt)
				rootapi.Paths[rt] = item
			}
		}
	}
	return cname
}

//分析用NSRouter注册路由得方式
func analyseNSRouter(baseurl string, ce *ast.CallExpr) string {
	cname := ""
	//ce.Args[0] 为 NSRouter得第一个参数
	//ce.Args[1] 为 NSRouter得第二个参数
	for _, p := range ce.Args[2:] { //解析mappingMethods参数
		var x *ast.SelectorExpr
		var p1 interface{} = ce.Args[1]
		if _, ok := p1.(*ast.UnaryExpr); ok {
			x = p1.(*ast.UnaryExpr).X.(*ast.CompositeLit).Type.(*ast.SelectorExpr)
		} else {
			beeLogger.Log.Warnf("Couldn't determine type\n")
			return ""
		}
		if v, ok := importlist[fmt.Sprint(x.X)]; ok {
			cname = v + x.Sel.Name
		}
		if apis, ok := controllerList[cname]; ok {
			mappingMethodsParam := strings.Split(strings.Trim(p.(*ast.BasicLit).Value, `"`), ";")
			for _, v := range mappingMethodsParam {
				mappingMethods := strings.Split(v, ":")
				if mappingMethods[0] == "*" {
					for funcName, item := range apis {
						if funcName != mappingMethods[1] {
							continue
						}
						rt := ce.Args[0].(*ast.BasicLit).Value
						rt = strings.Trim(rt, `"`)
						tag := cname
						if baseurl != "" {
							rt = baseurl + func() string {
								if strings.Contains(rt, "/") {
									return rt
								}
								return fmt.Sprintf("/%s", rt)
							}()
							tag = strings.Trim(baseurl, "/")
						}
						tag = func() string {
							if strings.Contains(tag, "/") {
								return tag[strings.LastIndex(tag, "/")+1:]
							}
							return tag
						}()
						item.Get.Tags = []string{tag}
						item.Post.Tags = []string{tag}
						item.Put.Tags = []string{tag}
						item.Patch.Tags = []string{tag}
						item.Head.Tags = []string{tag}
						item.Delete.Tags = []string{tag}
						item.Options.Tags = []string{tag}
						if len(rootapi.Paths) == 0 {
							rootapi.Paths = make(map[string]*Item)
						}
						rt = urlReplace(rt)
						rootapi.Paths[rt] = item
						break
					}
				} else {
					for ctlfuncName, item := range apis {
						if ctlfuncName != mappingMethods[1] {
							continue
						}
						rt := ce.Args[0].(*ast.BasicLit).Value
						rt = strings.Trim(rt, `"`)
						tag := cname
						if baseurl != "" {
							rt = baseurl + func() string {
								if strings.Contains(rt, "/") {
									return rt
								}
								return fmt.Sprintf("/%s", rt)
							}()
							tag = strings.Trim(baseurl, "/")
						}
						tag = func() string {
							if strings.Contains(tag, "/") {
								return tag[strings.LastIndex(tag, "/")+1:]
							}
							return tag
						}()
						tempItem := new(Item)

						if strings.ToLower(mappingMethods[0]) == "get" {
							tempItem.Get, tempItem.Ref = copyOperation(item)
							tempItem.Get.Tags = []string{tag}
						}
						if strings.ToLower(mappingMethods[0]) == "post" {
							tempItem.Post, tempItem.Ref = copyOperation(item)
							tempItem.Post.Tags = []string{tag}
						}
						if strings.ToLower(mappingMethods[0]) == "put" {
							tempItem.Put, tempItem.Ref = copyOperation(item)
							tempItem.Put.Tags = []string{tag}
						}
						if strings.ToLower(mappingMethods[0]) == "patch" {
							tempItem.Patch, tempItem.Ref = copyOperation(item)
							tempItem.Patch.Tags = []string{tag}
						}
						if strings.ToLower(mappingMethods[0]) == "head" {
							tempItem.Head, tempItem.Ref = copyOperation(item)
							tempItem.Head.Tags = []string{tag}
						}
						if strings.ToLower(mappingMethods[0]) == "delete" {
							tempItem.Delete, tempItem.Ref = copyOperation(item)
							tempItem.Delete.Tags = []string{tag}
						}
						if strings.ToLower(mappingMethods[0]) == "options" {
							tempItem.Options, tempItem.Ref = copyOperation(item)
							tempItem.Options.Tags = []string{tag}
						}
						if len(rootapi.Paths) == 0 {
							rootapi.Paths = make(map[string]*Item)
						}
						rt = urlReplace(rt)
						rootapi.Paths[rt] = tempItem
						break
					}
				}
			}
		}
	}
	return cname
}

func copyOperation(item *Item) (*Operation, string) {
	operation := new(Operation)
	if item.Get != nil {
		operation.Tags = item.Get.Tags
		operation.Summary = item.Get.Summary
		operation.Description = item.Get.Description
		operation.OperationID = item.Get.OperationID
		operation.Consumes = item.Get.Consumes
		operation.Produces = item.Get.Produces
		operation.Schemes = item.Get.Schemes
		operation.Parameters = item.Get.Parameters
		operation.Responses = item.Get.Responses
		operation.Security = item.Get.Security
		operation.Deprecated = item.Get.Deprecated
	} else if item.Post != nil {
		operation.Tags = item.Post.Tags
		operation.Summary = item.Post.Summary
		operation.Description = item.Post.Description
		operation.OperationID = item.Post.OperationID
		operation.Consumes = item.Post.Consumes
		operation.Produces = item.Post.Produces
		operation.Schemes = item.Post.Schemes
		operation.Parameters = item.Post.Parameters
		operation.Responses = item.Post.Responses
		operation.Security = item.Post.Security
		operation.Deprecated = item.Post.Deprecated
	} else if item.Put != nil {
		operation.Tags = item.Put.Tags
		operation.Summary = item.Put.Summary
		operation.Description = item.Put.Description
		operation.OperationID = item.Put.OperationID
		operation.Consumes = item.Put.Consumes
		operation.Produces = item.Put.Produces
		operation.Schemes = item.Put.Schemes
		operation.Parameters = item.Put.Parameters
		operation.Responses = item.Put.Responses
		operation.Security = item.Put.Security
		operation.Deprecated = item.Put.Deprecated
	} else if item.Delete != nil {
		operation.Tags = item.Delete.Tags
		operation.Summary = item.Delete.Summary
		operation.Description = item.Delete.Description
		operation.OperationID = item.Delete.OperationID
		operation.Consumes = item.Delete.Consumes
		operation.Produces = item.Delete.Produces
		operation.Schemes = item.Delete.Schemes
		operation.Parameters = item.Delete.Parameters
		operation.Responses = item.Delete.Responses
		operation.Security = item.Delete.Security
		operation.Deprecated = item.Delete.Deprecated
	} else if item.Head != nil {
		operation.Tags = item.Head.Tags
		operation.Summary = item.Head.Summary
		operation.Description = item.Head.Description
		operation.OperationID = item.Head.OperationID
		operation.Consumes = item.Head.Consumes
		operation.Produces = item.Head.Produces
		operation.Schemes = item.Head.Schemes
		operation.Parameters = item.Head.Parameters
		operation.Responses = item.Head.Responses
		operation.Security = item.Head.Security
		operation.Deprecated = item.Head.Deprecated
	} else if item.Options != nil {
		operation.Tags = item.Options.Tags
		operation.Summary = item.Options.Summary
		operation.Description = item.Options.Description
		operation.OperationID = item.Options.OperationID
		operation.Consumes = item.Options.Consumes
		operation.Produces = item.Options.Produces
		operation.Schemes = item.Options.Schemes
		operation.Parameters = item.Options.Parameters
		operation.Responses = item.Options.Responses
		operation.Security = item.Options.Security
		operation.Deprecated = item.Options.Deprecated
	} else if item.Patch != nil {
		operation.Tags = item.Patch.Tags
		operation.Summary = item.Patch.Summary
		operation.Description = item.Patch.Description
		operation.OperationID = item.Patch.OperationID
		operation.Consumes = item.Patch.Consumes
		operation.Produces = item.Patch.Produces
		operation.Schemes = item.Patch.Schemes
		operation.Parameters = item.Patch.Parameters
		operation.Responses = item.Patch.Responses
		operation.Security = item.Patch.Security
		operation.Deprecated = item.Patch.Deprecated
	}
	return operation, item.Ref
}

func analyseControllerPkg(vendorPath, localName, pkgpath string) {
	pkgpath = strings.Trim(pkgpath, "\"")
	if isSystemPackage(pkgpath) {
		return
	}
	if pkgpath == "github.com/astaxie/beego" {
		return
	}
	if localName != "" {
		importlist[localName] = pkgpath
	} else {
		pps := strings.Split(pkgpath, "/")
		importlist[pps[len(pps)-1]] = pkgpath
	}
	gopaths := bu.GetGOPATHs()
	if len(gopaths) == 0 {
		beeLogger.Log.Fatal("GOPATH environment variable is not set or empty")
	}
	pkgRealpath := ""

	wg, _ := filepath.EvalSymlinks(filepath.Join(vendorPath, pkgpath))
	if utils.FileExists(wg) {
		pkgRealpath = wg
	} else {
		wgopath := gopaths
		for _, wg := range wgopath {
			wg, _ = filepath.EvalSymlinks(filepath.Join(wg, "src", pkgpath))
			if utils.FileExists(wg) {
				pkgRealpath = wg
				break
			}
		}
	}
	if pkgRealpath != "" {
		if _, ok := pkgCache[pkgpath]; ok {
			return
		}
		pkgCache[pkgpath] = struct{}{}
	} else {
		beeLogger.Log.Fatalf("Package '%s' does not exist in the GOPATH or vendor path", pkgpath)
	}

	fileSet := token.NewFileSet()
	astPkgs, err := parser.ParseDir(fileSet, pkgRealpath, func(info os.FileInfo) bool {
		name := info.Name()
		return !info.IsDir() && !strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".go")
	}, parser.ParseComments)
	if err != nil {
		beeLogger.Log.Fatalf("Error while parsing dir at '%s': %s", pkgpath, err)
	}
	for _, pkg := range astPkgs {
		for _, fl := range pkg.Files {
			for _, d := range fl.Decls {
				switch specDecl := d.(type) {
				case *ast.FuncDecl:
					if specDecl.Recv != nil && len(specDecl.Recv.List) > 0 {
						if t, ok := specDecl.Recv.List[0].Type.(*ast.StarExpr); ok {
							// Parse controller method
							parserComments(specDecl, fmt.Sprint(t.X), pkgpath)
						}
					}
				case *ast.GenDecl:
					if specDecl.Tok == token.TYPE {
						for _, s := range specDecl.Specs {
							switch tp := s.(*ast.TypeSpec).Type.(type) {
							case *ast.StructType:
								_ = tp.Struct
								// Parse controller definition comments
								if strings.TrimSpace(specDecl.Doc.Text()) != "" {
									controllerComments[pkgpath+s.(*ast.TypeSpec).Name.String()] = specDecl.Doc.Text()
								}
							}
						}
					}
				}
			}
		}
	}
}

func isSystemPackage(pkgpath string) bool {
	goroot := os.Getenv("GOROOT")
	if goroot == "" {
		goroot = runtime.GOROOT()
	}
	if goroot == "" {
		beeLogger.Log.Fatalf("GOROOT environment variable is not set or empty")
	}

	wg, _ := filepath.EvalSymlinks(filepath.Join(goroot, "src", "pkg", pkgpath))
	if utils.FileExists(wg) {
		return true
	}

	//support go1.4
	wg, _ = filepath.EvalSymlinks(filepath.Join(goroot, "src", pkgpath))
	return utils.FileExists(wg)
}

func peekNextSplitString(ss string) (s string, spacePos int) {
	spacePos = strings.IndexFunc(ss, unicode.IsSpace)
	if spacePos < 0 {
		s = ss
		spacePos = len(ss)
	} else {
		s = strings.TrimSpace(ss[:spacePos])
	}
	return
}

//解析注释
func parserComments(f *ast.FuncDecl, controllerName, pkgpath string) error {
	var routerPath string
	var HTTPMethod string
	opts := Operation{
		Responses: make(map[string]Response),
	}
	funcName := f.Name.String()
	comments := f.Doc
	funcParamMap := buildParamMap(f.Type.Params)
	// resultMap := buildParamMap(f.Type.Results)
	if comments != nil && comments.List != nil {
		for _, c := range comments.List {
			t := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
			if strings.HasPrefix(t, "@router") {
				elements := strings.TrimSpace(t[len("@router"):])
				e1 := strings.SplitN(elements, " ", 2)
				if len(e1) < 1 {
					return errors.New("you should has router infomation")
				}
				routerPath = e1[0]
				if len(e1) == 2 && e1[1] != "" {
					e1 = strings.SplitN(e1[1], " ", 2)
					HTTPMethod = strings.ToUpper(strings.Trim(e1[0], "[]"))
				} else {
					HTTPMethod = "GET"
				}
			} else if strings.HasPrefix(t, "@Title") {
				opts.OperationID = controllerName + "." + strings.TrimSpace(t[len("@Title"):])
			} else if strings.HasPrefix(t, "@Description") {
				opts.Description = strings.TrimSpace(t[len("@Description"):])
			} else if strings.HasPrefix(t, "@Summary") {
				opts.Summary = strings.TrimSpace(t[len("@Summary"):])
			} else if strings.HasPrefix(t, "@Success") {
				ss := strings.TrimSpace(t[len("@Success"):])
				rs := Response{}
				respCode, pos := peekNextSplitString(ss)
				ss = strings.TrimSpace(ss[pos:])
				respType, pos := peekNextSplitString(ss)
				if respType == "{object}" || respType == "{array}" {
					isArray := respType == "{array}"
					ss = strings.TrimSpace(ss[pos:])
					schemaName, pos := peekNextSplitString(ss)
					if schemaName == "" {
						beeLogger.Log.Fatalf("[%s.%s] Schema must follow {object} or {array}", controllerName, funcName)
					}
					if strings.HasPrefix(schemaName, "[]") {
						schemaName = schemaName[2:]
						isArray = true
					}
					schema := Schema{}
					if sType, ok := basicTypes[schemaName]; ok {
						typeFormat := strings.Split(sType, ":")
						schema.Type = typeFormat[0]
						schema.Format = typeFormat[1]
					} else {
						m, mod, realTypes := getModel(schemaName)
						schema.Ref = "#/definitions/" + m
						if _, ok := modelsList[pkgpath+controllerName]; !ok {
							modelsList[pkgpath+controllerName] = make(map[string]Schema)
						}
						modelsList[pkgpath+controllerName][schemaName] = mod
						appendModels(pkgpath, controllerName, realTypes)
					}
					if isArray {
						rs.Schema = &Schema{
							Type:  astTypeArray,
							Items: &schema,
						}
					} else {
						rs.Schema = &schema
					}
					rs.Description = strings.TrimSpace(ss[pos:])
				} else {
					rs.Description = strings.TrimSpace(ss)
				}
				opts.Responses[respCode] = rs
			} else if strings.HasPrefix(t, "@Param") {
				para := Parameter{}
				p := getparams(strings.TrimSpace(t[len("@Param "):]))
				if len(p) < 4 {
					beeLogger.Log.Fatal(controllerName + "_" + funcName + "'s comments @Param should have at least 4 params")
				}
				paramNames := strings.SplitN(p[0], "=>", 2)
				para.Name = paramNames[0]
				funcParamName := para.Name
				if len(paramNames) > 1 {
					funcParamName = paramNames[1]
				}
				paramType, ok := funcParamMap[funcParamName]
				if ok {
					delete(funcParamMap, funcParamName)
				}

				switch p[1] {
				case "query":
					fallthrough
				case "header":
					fallthrough
				case "path":
					fallthrough
				case "formData":
					fallthrough
				case "body":
					break
				default:
					beeLogger.Log.Warnf("[%s.%s] Unknown param location: %s. Possible values are `query`, `header`, `path`, `formData` or `body`.\n", controllerName, funcName, p[1])
				}
				para.In = p[1]
				pp := strings.Split(p[2], ".")
				typ := pp[len(pp)-1]
				if len(pp) >= 2 {
					isArray := false
					if p[1] == "body" && strings.HasPrefix(p[2], "[]") {
						p[2] = p[2][2:]
						isArray = true
					}
					m, mod, realTypes := getModel(p[2])
					if isArray {
						para.Schema = &Schema{
							Type: astTypeArray,
							Items: &Schema{
								Ref: "#/definitions/" + m,
							},
						}
					} else {
						para.Schema = &Schema{
							Ref: "#/definitions/" + m,
						}
					}

					if _, ok := modelsList[pkgpath+controllerName]; !ok {
						modelsList[pkgpath+controllerName] = make(map[string]Schema)
					}
					modelsList[pkgpath+controllerName][typ] = mod
					appendModels(pkgpath, controllerName, realTypes)
				} else {
					if typ == "auto" {
						typ = paramType
					}
					setParamType(&para, typ, pkgpath, controllerName)
				}
				switch len(p) {
				case 5:
					para.Required, _ = strconv.ParseBool(p[3])
					para.Description = strings.Trim(p[4], `" `)
				case 6:
					para.Default = str2RealType(p[3], para.Type)
					para.Required, _ = strconv.ParseBool(p[4])
					para.Description = strings.Trim(p[5], `" `)
				default:
					para.Description = strings.Trim(p[3], `" `)
				}
				opts.Parameters = append(opts.Parameters, para)
			} else if strings.HasPrefix(t, "@Failure") {
				rs := Response{}
				st := strings.TrimSpace(t[len("@Failure"):])
				var cd []rune
				var start bool
				for i, s := range st {
					if unicode.IsSpace(s) {
						if start {
							rs.Description = strings.TrimSpace(st[i+1:])
							break
						} else {
							continue
						}
					}
					start = true
					cd = append(cd, s)
				}
				opts.Responses[string(cd)] = rs
			} else if strings.HasPrefix(t, "@Deprecated") {
				opts.Deprecated, _ = strconv.ParseBool(strings.TrimSpace(t[len("@Deprecated"):]))
			} else if strings.HasPrefix(t, "@Accept") {
				accepts := strings.Split(strings.TrimSpace(strings.TrimSpace(t[len("@Accept"):])), ",")
				for _, a := range accepts {
					switch a {
					case "json":
						opts.Consumes = append(opts.Consumes, ajson)
						opts.Produces = append(opts.Produces, ajson)
					case "xml":
						opts.Consumes = append(opts.Consumes, axml)
						opts.Produces = append(opts.Produces, axml)
					case "plain":
						opts.Consumes = append(opts.Consumes, aplain)
						opts.Produces = append(opts.Produces, aplain)
					case "html":
						opts.Consumes = append(opts.Consumes, ahtml)
						opts.Produces = append(opts.Produces, ahtml)
					case "form":
						opts.Consumes = append(opts.Consumes, aform)
					}
				}
			} else if strings.HasPrefix(t, "@Security") {
				if len(opts.Security) == 0 {
					opts.Security = make([]map[string][]string, 0)
				}
				opts.Security = append(opts.Security, getSecurity(t))
			}
		}
	}

	//if routerPath != ""{
	//Go over function parameters which were not mapped and create swagger params for them
	for name, typ := range funcParamMap {
		para := Parameter{}
		para.Name = name
		setParamType(&para, typ, pkgpath, controllerName)
		if paramInPath(name, routerPath) {
			para.In = "path"
		} else {
			para.In = "query"
		}
		opts.Parameters = append(opts.Parameters, para)
	}

	var item *Item
	if itemList, ok := controllerList[pkgpath+controllerName]; ok {
		if len(routerPath) != 0 {
			if it, ok := itemList[routerPath]; !ok {
				item = &Item{}
			} else {
				item = it
			}
		}
		if it, ok := itemList[funcName]; !ok {
			item = &Item{}
		} else {
			item = it
		}
	} else {
		controllerList[pkgpath+controllerName] = make(map[string]*Item)
		item = &Item{}
	}
	for _, hm := range strings.Split(HTTPMethod, ",") {
		switch hm {
		case "GET":
			item.Get = &opts
		case "POST":
			item.Post = &opts
		case "PUT":
			item.Put = &opts
		case "PATCH":
			item.Patch = &opts
		case "DELETE":
			item.Delete = &opts
		case "HEAD":
			item.Head = &opts
		case "OPTIONS":
			item.Options = &opts
		default:
			item.Get = &opts
			item.Post = &opts
			item.Put = &opts
			item.Patch = &opts
			item.Delete = &opts
			item.Head = &opts
			item.Options = &opts
		}
	}
	if len(routerPath) != 0 {
		controllerList[pkgpath+controllerName][routerPath] = item
	}
	//增加通过Method名找到item
	controllerList[pkgpath+controllerName][funcName] = item
	//}
	return nil
}

func setParamType(para *Parameter, typ string, pkgpath, controllerName string) {
	isArray := false
	paraType := ""
	paraFormat := ""

	if strings.HasPrefix(typ, "[]") {
		typ = typ[2:]
		isArray = true
	}
	if typ == "string" || typ == "number" || typ == "integer" || typ == "boolean" ||
		typ == astTypeArray || typ == "file" {
		paraType = typ
		if para.In == "body" {
			para.Schema = &Schema{
				Type: paraType,
			}
		}
	} else if sType, ok := basicTypes[typ]; ok {
		typeFormat := strings.Split(sType, ":")
		paraType = typeFormat[0]
		paraFormat = typeFormat[1]
		if para.In == "body" {
			para.Schema = &Schema{
				Type:   paraType,
				Format: paraFormat,
			}
		}
	} else {
		m, mod, realTypes := getModel(typ)
		para.Schema = &Schema{
			Ref: "#/definitions/" + m,
		}
		if _, ok := modelsList[pkgpath+controllerName]; !ok {
			modelsList[pkgpath+controllerName] = make(map[string]Schema)
		}
		modelsList[pkgpath+controllerName][typ] = mod
		appendModels(pkgpath, controllerName, realTypes)
	}
	if isArray {
		if para.In == "body" {
			para.Schema = &Schema{
				Type: astTypeArray,
				Items: &Schema{
					Type:   paraType,
					Format: paraFormat,
				},
			}
		} else {
			para.Type = astTypeArray
			para.Items = &ParameterItems{
				Type:   paraType,
				Format: paraFormat,
			}
		}
	} else {
		para.Type = paraType
		para.Format = paraFormat
	}

}

func paramInPath(name, route string) bool {
	return strings.HasSuffix(route, ":"+name) ||
		strings.Contains(route, ":"+name+"/")
}

func getFunctionParamType(t ast.Expr) string {
	switch paramType := t.(type) {
	case *ast.Ident:
		return paramType.Name
	// case *ast.Ellipsis:
	// 	result := getFunctionParamType(paramType.Elt)
	// 	result.array = true
	// 	return result
	case *ast.ArrayType:
		return "[]" + getFunctionParamType(paramType.Elt)
	case *ast.StarExpr:
		return getFunctionParamType(paramType.X)
	case *ast.SelectorExpr:
		return getFunctionParamType(paramType.X) + "." + paramType.Sel.Name
	default:
		return ""

	}
}

func buildParamMap(list *ast.FieldList) map[string]string {
	i := 0
	result := map[string]string{}
	if list != nil {
		funcParams := list.List
		for _, fparam := range funcParams {
			param := getFunctionParamType(fparam.Type)
			var paramName string
			if len(fparam.Names) > 0 {
				paramName = fparam.Names[0].Name
			} else {
				paramName = fmt.Sprint(i)
				i++
			}
			result[paramName] = param
		}
	}
	return result
}

// analisys params return []string
// @Param	query		form	 string	true		"The email for login"
// [query form string true "The email for login"]
func getparams(str string) []string {
	var s []rune
	var j int
	var start bool
	var r []string
	var quoted int8
	for _, c := range str {
		if unicode.IsSpace(c) && quoted == 0 {
			if !start {
				continue
			} else {
				start = false
				j++
				r = append(r, string(s))
				s = make([]rune, 0)
				continue
			}
		}

		start = true
		if c == '"' {
			quoted ^= 1
			continue
		}
		s = append(s, c)
	}
	if len(s) > 0 {
		r = append(r, string(s))
	}
	return r
}

func getModel(str string) (definitionName string, m Schema, realTypes []string) {
	strs := strings.Split(str, ".")
	// strs = [packageName].[objectName]
	packageName := ""
	if len(strs) < 3 {
		packageName = strs[0]
	} else {
		packageName = strings.Join(strs[:len(strs)-1], ".")
	}
	objectname := strs[len(strs)-1]

	// Default all swagger schemas to object, if no other type is found
	m.Type = astTypeObject

L:
	for _, pkg := range astPkgs {
		if !strings.Contains(str, ".") {
			return
		}
		if str[:strings.LastIndex(str, ".")] == pkg.Name {
			for _, fl := range pkg.Files {
				for k, d := range fl.Scope.Objects {
					if d.Kind == ast.Typ {
						if k != objectname {
							// Still searching for the right object
							continue
						}
						parseObject(d, k, &m, &realTypes, astPkgs, packageName)

						// When we've found the correct object, we can stop searching
						break L
					}
				}
			}
		}
	}

	if m.Title == "" {
		// Don't log when error has already been logged
		if _, found := rootapi.Definitions[str]; !found {
			beeLogger.Log.Warnf("Cannot find the object: %s", str)
		}
		m.Title = objectname
		// remove when all type have been supported
	}
	if len(rootapi.Definitions) == 0 {
		rootapi.Definitions = make(map[string]Schema)
	}
	rootapi.Definitions[str] = m
	return str, m, realTypes
}

func parseObject(d *ast.Object, k string, m *Schema, realTypes *[]string, astPkgs []*ast.Package, packageName string) {
	ts, ok := d.Decl.(*ast.TypeSpec)
	if !ok {
		beeLogger.Log.Fatalf("Unknown type without TypeSec: %v", d)
	}
	// support other types, such as `MapType`, `InterfaceType` etc...
	switch t := ts.Type.(type) {
	case *ast.ArrayType:
		m.Title = k
		m.Type = astTypeArray
		if isBasicType(fmt.Sprint(t.Elt)) {
			typeFormat := strings.Split(basicTypes[fmt.Sprint(t.Elt)], ":")
			m.Format = typeFormat[0]
		} else {
			objectName := packageName + "." + fmt.Sprint(t.Elt)
			if _, ok := rootapi.Definitions[objectName]; !ok {
				objectName, _, _ = getModel(objectName)
			}
			m.Items = &Schema{
				Ref: "#/definitions/" + objectName,
			}
		}
	case *ast.Ident:
		parseIdent(t, k, m, astPkgs)
	case *ast.StructType:
		parseStruct(t, k, m, realTypes, astPkgs, packageName)
	}
}

// parse as enum, in the package, find out all consts with the same type
func parseIdent(st *ast.Ident, k string, m *Schema, astPkgs []*ast.Package) {
	m.Title = k
	basicType := fmt.Sprint(st)
	if object, isStdLibObject := stdlibObject[basicType]; isStdLibObject {
		basicType = object
	}
	if t, ok := basicTypes[basicType]; ok {
		typeFormat := strings.Split(t, ":")
		m.Type = typeFormat[0]
		m.Format = typeFormat[1]
	}
	enums := make(map[int]string)
	enumValues := make(map[int]interface{})
	for _, pkg := range astPkgs {
		for _, fl := range pkg.Files {
			for _, obj := range fl.Scope.Objects {
				if obj.Kind == ast.Con {
					vs, ok := obj.Decl.(*ast.ValueSpec)
					if !ok {
						beeLogger.Log.Fatalf("Unknown type without ValueSpec: %v", vs)
					}

					ti, ok := vs.Type.(*ast.Ident)
					if !ok {
						// type inference, iota not support yet
						continue
					}
					// Only add the enums that are defined by the current identifier
					if ti.Name != k {
						continue
					}

					// For all names and values, aggregate them by it's position so that we can sort them later.
					for i, val := range vs.Values {
						v, ok := val.(*ast.BasicLit)
						if !ok {
							beeLogger.Log.Warnf("Unknown type without BasicLit: %v", v)
							continue
						}
						enums[int(val.Pos())] = fmt.Sprintf("%s = %s", vs.Names[i].Name, v.Value)
						switch v.Kind {
						case token.INT:
							vv, err := strconv.Atoi(v.Value)
							if err != nil {
								beeLogger.Log.Warnf("Unknown type with BasicLit to int: %v", v.Value)
								continue
							}
							enumValues[int(val.Pos())] = vv
						case token.FLOAT:
							vv, err := strconv.ParseFloat(v.Value, 64)
							if err != nil {
								beeLogger.Log.Warnf("Unknown type with BasicLit to int: %v", v.Value)
								continue
							}
							enumValues[int(val.Pos())] = vv
						default:
							enumValues[int(val.Pos())] = strings.Trim(v.Value, `"`)
						}

					}
				}
			}
		}
	}
	// Sort the enums by position
	if len(enums) > 0 {
		var keys []int
		for k := range enums {
			keys = append(keys, k)
		}
		sort.Ints(keys)
		for _, k := range keys {
			m.Enum = append(m.Enum, enums[k])
		}
		// Automatically use the first enum value as the example.
		m.Example = enumValues[keys[0]]
	}

}

func parseStruct(st *ast.StructType, k string, m *Schema, realTypes *[]string, astPkgs []*ast.Package, packageName string) {
	m.Title = k
	if st.Fields.List != nil {
		m.Properties = make(map[string]Propertie)
		for _, field := range st.Fields.List {
			isSlice, realType, sType := typeAnalyser(field)
			if (isSlice && isBasicType(realType)) || sType == astTypeObject {
				if len(strings.Split(realType, " ")) > 1 {
					realType = strings.Replace(realType, " ", ".", -1)
					realType = strings.Replace(realType, "&", "", -1)
					realType = strings.Replace(realType, "{", "", -1)
					realType = strings.Replace(realType, "}", "", -1)
				} else {
					realType = packageName + "." + realType
				}
			}
			*realTypes = append(*realTypes, realType)
			mp := Propertie{}
			isObject := false
			if isSlice {
				mp.Type = astTypeArray
				if t, ok := basicTypes[(strings.Replace(realType, "[]", "", -1))]; ok {
					typeFormat := strings.Split(t, ":")
					mp.Items = &Propertie{
						Type:   typeFormat[0],
						Format: typeFormat[1],
					}
				} else {
					mp.Items = &Propertie{
						Ref: "#/definitions/" + realType,
					}
				}
			} else {
				if sType == astTypeObject {
					isObject = true
					mp.Ref = "#/definitions/" + realType
				} else if isBasicType(realType) {
					typeFormat := strings.Split(sType, ":")
					mp.Type = typeFormat[0]
					mp.Format = typeFormat[1]
				} else if realType == astTypeMap {
					typeFormat := strings.Split(sType, ":")
					mp.AdditionalProperties = &Propertie{
						Type:   typeFormat[0],
						Format: typeFormat[1],
					}
				}
			}
			if field.Names != nil {

				// set property name as field name
				var name = field.Names[0].Name

				// if no tag skip tag processing
				if field.Tag == nil {
					m.Properties[name] = mp
					continue
				}

				var tagValues []string

				stag := reflect.StructTag(strings.Trim(field.Tag.Value, "`"))

				defaultValue := stag.Get("doc")
				if defaultValue != "" {
					r, _ := regexp.Compile(`default\((.*)\)`)
					if r.MatchString(defaultValue) {
						res := r.FindStringSubmatch(defaultValue)
						mp.Default = str2RealType(res[1], realType)

					} else {
						beeLogger.Log.Warnf("Invalid default value: %s", defaultValue)
					}
				}

				tag := stag.Get("json")
				if tag != "" {
					tagValues = strings.Split(tag, ",")
				}

				// dont add property if json tag first value is "-"
				if len(tagValues) == 0 || tagValues[0] != "-" {

					// set property name to the left most json tag value only if is not omitempty
					if len(tagValues) > 0 && tagValues[0] != "omitempty" {
						name = tagValues[0]
					}

					if thrifttag := stag.Get("thrift"); thrifttag != "" {
						ts := strings.Split(thrifttag, ",")
						if ts[0] != "" {
							name = ts[0]
						}
					}
					if required := stag.Get("required"); required != "" {
						m.Required = append(m.Required, name)
					}
					if desc := stag.Get("description"); desc != "" {
						mp.Description = desc
					}

					if example := stag.Get("example"); example != "" && !isObject && !isSlice {
						mp.Example = str2RealType(example, realType)
					}
					if !isObject {
						m.Properties[name] = mp
					} else {
						m.Properties[name] = Propertie{
							AllOf: []Propertie{
								{
									Ref:                  mp.Ref,
									Title:                mp.Title,
									Default:              mp.Default,
									Type:                 mp.Type,
									Example:              mp.Example,
									Required:             mp.Required,
									Format:               mp.Format,
									ReadOnly:             mp.ReadOnly,
									Properties:           mp.Properties,
									Items:                mp.Items,
									AdditionalProperties: mp.AdditionalProperties,
								},
							},
							Title:                mp.Title,
							Description:          mp.Description,
							Default:              mp.Default,
							Type:                 mp.Type,
							Example:              mp.Example,
							Required:             mp.Required,
							Format:               mp.Format,
							ReadOnly:             mp.ReadOnly,
							Properties:           mp.Properties,
							Items:                mp.Items,
							AdditionalProperties: mp.AdditionalProperties,
						}
					}
				}
				if ignore := stag.Get("ignore"); ignore != "" {
					continue
				}
			} else {
				// only parse case of when embedded field is TypeName
				// cases of *TypeName and Interface are not handled, maybe useless for swagger spec
				tag := ""
				if field.Tag != nil {
					stag := reflect.StructTag(strings.Trim(field.Tag.Value, "`"))
					tag = stag.Get("json")
				}

				if tag != "" {
					tagValues := strings.Split(tag, ",")
					if tagValues[0] == "-" {
						//if json tag is "-", omit
						continue
					} else {
						//if json tag is "something", output: something #definition/pkgname.Type
						m.Properties[tagValues[0]] = mp
						continue
					}
				} else {
					//if no json tag, expand all fields of the type here
					nm := &Schema{}
					for _, pkg := range astPkgs {
						for _, fl := range pkg.Files {
							for nameOfObj, obj := range fl.Scope.Objects {
								if fmt.Sprintf("%s.%s", pkg.Name, obj.Name) == realType {
									parseObject(obj, nameOfObj, nm, realTypes, astPkgs, pkg.Name)
								}
							}
						}
					}
					for name, p := range nm.Properties {
						m.Properties[name] = p
					}
					continue
				}
			}
		}
	}
}

func typeAnalyser(f *ast.Field) (isSlice bool, realType, swaggerType string) {
	if arr, ok := f.Type.(*ast.ArrayType); ok {
		if isBasicType(fmt.Sprint(arr.Elt)) {
			return true, fmt.Sprintf("[]%v", arr.Elt), basicTypes[fmt.Sprint(arr.Elt)]
		}
		if mp, ok := arr.Elt.(*ast.MapType); ok {
			return false, fmt.Sprintf("map[%v][%v]", mp.Key, mp.Value), astTypeObject
		}
		if star, ok := arr.Elt.(*ast.StarExpr); ok {
			return true, fmt.Sprint(star.X), astTypeObject
		}
		return true, fmt.Sprint(arr.Elt), astTypeObject
	}
	switch t := f.Type.(type) {
	case *ast.StarExpr:
		basicType := fmt.Sprint(t.X)
		if object, isStdLibObject := stdlibObject[basicType]; isStdLibObject {
			basicType = object
		}
		if k, ok := basicTypes[basicType]; ok {
			return false, basicType, k
		}
		return false, basicType, astTypeObject
	case *ast.MapType:
		val := fmt.Sprintf("%v", t.Value)
		if isBasicType(val) {
			return false, astTypeMap, basicTypes[val]
		}
		return false, val, astTypeObject
	}
	basicType := fmt.Sprint(f.Type)
	if object, isStdLibObject := stdlibObject[basicType]; isStdLibObject {
		basicType = object
	}
	if k, ok := basicTypes[basicType]; ok {
		return false, basicType, k
	}
	return false, basicType, astTypeObject
}

func isBasicType(Type string) bool {
	if _, ok := basicTypes[Type]; ok {
		return true
	}
	return false
}

// append models
func appendModels(pkgpath, controllerName string, realTypes []string) {
	for _, realType := range realTypes {
		if realType != "" && !isBasicType(strings.TrimLeft(realType, "[]")) &&
			!strings.HasPrefix(realType, astTypeMap) && !strings.HasPrefix(realType, "&") {
			if _, ok := modelsList[pkgpath+controllerName][realType]; ok {
				continue
			}
			_, mod, newRealTypes := getModel(realType)
			modelsList[pkgpath+controllerName][realType] = mod
			appendModels(pkgpath, controllerName, newRealTypes)
		}
	}
}

func getSecurity(t string) (security map[string][]string) {
	security = make(map[string][]string)
	p := getparams(strings.TrimSpace(t[len("@Security"):]))
	if len(p) == 0 {
		beeLogger.Log.Fatalf("No params for security specified\n")
	}
	security[p[0]] = make([]string, 0)
	for i := 1; i < len(p); i++ {
		security[p[0]] = append(security[p[0]], p[i])
	}
	return
}

func urlReplace(src string) string {
	pt := strings.Split(src, "/")
	for i, p := range pt {
		if len(p) > 0 {
			if p[0] == ':' {
				pt[i] = "{" + p[1:] + "}"
			} else if p[0] == '?' && p[1] == ':' {
				pt[i] = "{" + p[2:] + "}"
			}

			if pt[i][0] == '{' && strings.Contains(pt[i], ":") {
				pt[i] = pt[i][:strings.Index(pt[i], ":")] + "}"
			} else if pt[i][0] == '{' && strings.Contains(pt[i], "(") {
				pt[i] = pt[i][:strings.Index(pt[i], "(")] + "}"
			}
		}
	}
	return strings.Join(pt, "/")
}

func str2RealType(s string, typ string) interface{} {
	var err error
	var ret interface{}

	switch typ {
	case "int", "int64", "int32", "int16", "int8":
		ret, err = strconv.Atoi(s)
	case "uint", "uint64", "uint32", "uint16", "uint8":
		ret, err = strconv.ParseUint(s, 10, 0)
	case "bool":
		ret, err = strconv.ParseBool(s)
	case "float64":
		ret, err = strconv.ParseFloat(s, 64)
	case "float32":
		ret, err = strconv.ParseFloat(s, 32)
	default:
		return s
	}

	if err != nil {
		beeLogger.Log.Warnf("Invalid default value type '%s': %s", typ, s)
		return s
	}

	return ret
}
