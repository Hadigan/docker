package main

import (
	"fmt"
	"os/exec"
	"regexp"
)

// func checkBWLimitInit() error {
// 	outTmp, err := exec.Command("tc", "qdisc", "show").Output()
// 	if err != nil {
// 		logrus.Errorf("1196%v", err)
// 		return err
// 	}
// 	out1 := string(outTmp)
// 	//检查是否已经为docker0配置了htb
// 	docker0ConfigHTB, err := regexp.MatchString("htb 172: dev docker0 root", out1)
// 	if err != nil {
// 		logrus.Errorf("1203%v", err)
// 		return err
// 	}
// 	if docker0ConfigHTB == false {
// 		//先执行删除qdisc命令，防止设置了其他的qdisc
// 		_, err = exec.Command("tc", "qdisc", "del", "dev", "docker0", "root").Output()
// 		if err != nil {
// 			logrus.Errorf("1210%v", err)
// 			return err
// 		}
// 		//为docker0配置htb，handle固定为172号
// 		_, err = exec.Command("tc", "qdisc", "add", "dev", "docker0", "root", "handle", "172:", "htb").Output()
// 		if err != nil {
// 			logrus.Errorf("1216%v", err)
// 			return err
// 		}
// 		//建立根分类
// 		_, err = exec.Command("tc", "class", "add", "dev", "docker0", "parent",
// 			"172:", "classid", "172:1", "htb", "rate", "1000gbit", "ceil", "1000gbit").Output()
// 		if err != nil {
// 			logrus.Errorf("1223%v", err)
// 			return err
// 		}
// 	}
// 	//是否为docker0配置了ingress
// 	docker0ConfigIngress, err := regexp.MatchString("ingress ffff: dev docker0", out1)
// 	if err != nil {
// 		logrus.Errorf("1230%v", err)
// 		return err
// 	}
// 	if docker0ConfigIngress == false {
// 		//为docker0配置ingress
// 		_, err = exec.Command("tc", "qdisc", "add", "dev", "docker0", "handle", "ffff:", "ingress").Output()
// 		if err != nil {
// 			logrus.Errorf("1237%v", err)
// 			return err
// 		}
// 	}
// 	//是否加载并配置了ifb0
// 	configIfb0, err := regexp.MatchString("htb 173: dev ifb0 root", out1)
// 	if err != nil {
// 		logrus.Errorf("1244%v", err)
// 		return err
// 	}
// 	if configIfb0 == false {
// 		//加载ifb模块
// 		_, err = exec.Command("modprobe", "ifb").Output()
// 		if err != nil {
// 			logrus.Errorf("1251%v", err)
// 			return err
// 		}
// 		//启动ifb0接口
// 		_, err = exec.Command("ip", "link", "set", "ifb0", "up").Output()
// 		if err != nil {
// 			logrus.Errorf("1257%v", err)
// 			return err
// 		}
// 		//将docker0的下行流量重定向到ifb0
// 		_, err = exec.Command("tc", "filter", "add", "dev", "docker0",
// 			"parent", "ffff:", "protocol", "ip", "u32", "match", "u32",
// 			"0", "0", "action", "mirred", "egress", "redirect", "dev", "ifb0").Output()
// 		if err != nil {
// 			logrus.Errorf("1265%v", err)
// 			return err
// 		}
// 		_, err = exec.Command("tc", "qdisc", "del", "dev", "ifb0", "root").Output()
// 		if err != nil {
// 			logrus.Errorf("1270%v", err)
// 			return err
// 		}
// 		//为ifb0配置htb
// 		_, err = exec.Command("tc", "qdisc", "add", "dev", "ifb0", "root", "handle", "173:", "htb").Output()
// 		if err != nil {
// 			logrus.Errorf("1270%v", err)
// 			return err
// 		}
// 		//添加根分类
// 		_, err = exec.Command("tc", "class", "add", "dev", "ifb0", "parent",
// 			"173:", "classid", "173:1", "htb", "rate", "1000gbit", "ceil", "1000gbit").Output()
// 		if err != nil {
// 			logrus.Errorf("1283%v", err)
// 			return err
// 		}
// 	}
// 	return nil
// }

func main() {
	outTmp, err := exec.Command("tc", "qdisc", "show").Output()
	if err != nil {
		fmt.Println("1203" + err.Error())
	}
	out1 := string(outTmp)
	//检查是否已经为docker0配置了htb
	docker0ConfigHTB, err := regexp.MatchString("htb 172: dev docker0 root", out1)
	if err != nil {
		fmt.Println("1203" + err.Error())
	}
	if docker0ConfigHTB == false {
		//先执行删除qdisc命令，防止设置了其他的qdisc
		_, err = exec.Command("tc", "qdisc", "del", "dev", "docker0", "root").Output()
		if err != nil {
			fmt.Println("1210" + err.Error())
		}
		//为docker0配置htb，handle固定为172号
		_, err = exec.Command("tc", "qdisc", "add", "dev", "docker0", "root", "handle", "172:", "htb").Output()
		if err != nil {
			fmt.Println("1216" + err.Error())
		}
		//建立根分类
		_, err = exec.Command("tc", "class", "add", "dev", "docker0", "parent",
			"172:", "classid", "172:1", "htb", "rate", "1000gbit", "ceil", "1000gbit").Output()
		if err != nil {
			fmt.Println("1223" + err.Error())
		}
	}
}
