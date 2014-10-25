package main

import (
	"encoding/json"
	"io/ioutil"
	"fmt"
)

type Map struct {
	Name  string
	Id  int
}

type Config struct {
	Xmap []Map
}

func main() {
	content, err := ioutil.ReadFile("netlinkAudit/audit.rules.json")
	if err!=nil{
        fmt.Print("Error:",err)
	}

	var rules interface{}
	err = json.Unmarshal(content, &rules)

	m := rules.(map[string]interface{})
	for k, v := range m {
    	switch k {
    		case "syscall_rule":
    			vi := v.(map[string]interface{})
    			content2, err := ioutil.ReadFile("netlinkAudit/audit_x86.json")
				if err!=nil{
			        fmt.Print("Error:",err)
				}
    
				var conf Config
				err = json.Unmarshal([]byte(content2), &conf)
				if err != nil {
					fmt.Print("Error:", err)
				}
				for l := range conf.Xmap {
					//fmt.Println(vi["name"])
					if conf.Xmap[l].Name == vi["name"] {
						fmt.Println(conf.Xmap[l].Name, conf.Xmap[l].Id)
					}
				}
		    //default:
		    //    fmt.Println(k, "is not yet supported")
		    }
	}
}
