# swaggergen
beego得自动化文档升级版，不在只支持 namespace+Include 的写法了，而是支持 namespace......+Include


#下载包
go get github.com/bufio/swaggergen

#使用方式
~~~
func main(){
    if beego.BConfig.RunMode == "dev" {
        if err := swaggergen.AutoInstallSwagger(); err != nil {
            panic(err)
        }
        curPath, err := os.Getwd()
        if err != nil {
        	panic(err)
        }
        swaggergen.GenerateDocs(curPath)
        
        beego.BConfig.WebConfig.DirectoryIndex = true
        beego.BConfig.WebConfig.StaticDir["/swagger"] = "swagger"
    }
}
 ~~~
