package main
import "fmt"
import "strings"
func main(){
// your code goes here
var st string
st = "arch=b64"
take := strings.ContainsRune(st, int32("arch"))
fmt.Println(take)
}