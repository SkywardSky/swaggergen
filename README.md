# swaggergen
beego得自动化文档升级版，不在只支持 namespace+Include 的写法了，而是支持 namespace......+Include


#下载包
go get github.com/bufio/swaggergen

#使用方式
~~~
1.beego得app.conf
    EnableDocs = true
    
2.使用
func main(){
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

3.beego得自动化文档使用方式：https://beego.me/docs/advantage/docs.md
 ~~~
