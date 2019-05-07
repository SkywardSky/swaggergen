# swaggergen
beego得自动化文档升级版，不在只支持 NewNamespace+NSNamespace+NSInclude 的写法了，而是支持 NewNamespace+NSNamespace...+NSInclude 和 NewNamespace+NSNamespace...+NSRouter

#swagger注解得标签
https://beego.me/docs/advantage/docs.md

#注意事项
使用NewNamespace+NSNamespace...+NSInclude得方式时，需要用beego得bee工具run一下项目，以生成beego得注解路由文件

#下载包
go get -u github.com/bufio/swaggergen

#使用方式
~~~
1.beego得app.conf
    EnableDocs = true
    
2.使用
func main(){
    //获取相对于执行文件的工作目录的绝对路径，并且把路径设置为工作目录
    if err := os.Chdir(filepath.Dir(os.Args[0])); err != nil {
        log.Fatal("设置工作目录失败：", err)
    }
    if beego.BConfig.RunMode == "dev" {
        //安装swagger得文件，原理是通过将swagger得文件从base64字符串中生成swagger.zip，最后解压出来
        //根据swagger中得index.html是否存在，判断是否需要安装
        if err := swaggergen.AutoInstallSwagger(); err != nil {
            panic(err)
        }
        curPath, err := os.Getwd()
        if err != nil {
        	panic(err)
        }
        //开始生成文档
        swaggergen.GenerateDocs(curPath)
        
        beego.BConfig.WebConfig.DirectoryIndex = true
        beego.BConfig.WebConfig.StaticDir["/swagger"] = "swagger"
    }
}

 ~~~
