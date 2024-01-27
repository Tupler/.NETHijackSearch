package main

import (
	"errors"
	"flag"
	"fmt"
	peparser "github.com/saferwall/pe"
	"os"
	"path/filepath"
	"strings"
)

// clrHeader Flags
const (
	COMIMAGE_FLAGS_ILONLY            = 0x00000001
	OMIMAGE_FLAGS_32BITREQUIRED      = 0x00000002
	COMIMAGE_FLAGS_IL_LIBRARY        = 0x00000004
	COMIMAGE_FLAGS_STRONGNAMESIGNED  = 0x00000008
	COMIMAGE_FLAGS_NATIVE_ENTRYPOINT = 0x00000010
	COMIMAGE_FLAGS_TRACKDEBUGDATA    = 0x00010000
	COMIMAGE_FLAGS_32BITPREFERRED    = 0x00020000
)

// 判断.net编译的选项是 any CPU,x86,x64
func checkIs32bit(flag int) (bool, error) {
	switch flag {
	case COMIMAGE_FLAGS_ILONLY:
		return false, nil
	case COMIMAGE_FLAGS_STRONGNAMESIGNED | COMIMAGE_FLAGS_STRONGNAMESIGNED:
		return false, nil
	case COMIMAGE_FLAGS_ILONLY | COMIMAGE_FLAGS_IL_LIBRARY:
		return false, nil
	case COMIMAGE_FLAGS_ILONLY | COMIMAGE_FLAGS_NATIVE_ENTRYPOINT:
		return false, nil
	case COMIMAGE_FLAGS_ILONLY | COMIMAGE_FLAGS_TRACKDEBUGDATA:
		return false, nil
	case COMIMAGE_FLAGS_ILONLY | OMIMAGE_FLAGS_32BITREQUIRED:
		return true, nil
	case COMIMAGE_FLAGS_32BITPREFERRED:
		return true, nil

	}
	return false, errors.New("未找到正确的值")
}

func checkDotFile(path string) {
	pe, err := peparser.New(path, &peparser.Options{})

	if err != nil {
		fmt.Printf("%v", err)
		return
	}

	err = pe.Parse()
	if err != nil {
		//fmt.Printf("不是有效的PE文件 详细原因:%v", err)
		return
	}

	cb := pe.CLR.CLRHeader.Cb

	if cb == 0 {
		//	fmt.Println("不是.net文件")
		return
	}

	is32, err := checkIs32bit(int(pe.CLR.CLRHeader.Flags))
	if err != nil {
		//log.Fatalf("Error while parsing file: %s, reason: %v", path, err)
		return
	}
	if is32 {
		fmt.Printf("文件路径:%s 位数:32bit\n", path)
	} else {
		fmt.Printf("文件路径:%s 位数:64bit\n", path)
	}
}

func visit(path string, f os.DirEntry, err error) error {
	if err != nil {
		fmt.Println(err) // 如果发生错误，输出错误信息并继续
		return err
	}

	//fmt.Println(path)
	// 如果是目录，则递归遍历
	if f.IsDir() && !strings.Contains(f.Name(), "$") {

		subEntries, err := os.ReadDir(path)
		//无法读取目录 ->可能原因
		if err != nil {
			fmt.Println("无法读取目录 Error->", err)
		}
		//循环递归子目录文件
		for _, subEntry := range subEntries {
			subPath := filepath.Join(path, subEntry.Name())
			//递归
			err := visit(subPath, subEntry, nil)
			if err != nil {
				return err
			}
		}
	} else {
		//判断后缀是否是.exe
		if path[len(path)-4:] == ".exe" {
			checkDotFile(path)
		}

	}
	return nil

}

var Path string

// 参数初始化
func init() {
	flag.StringVar(&Path, "p", "C:\\", "设置一个要搜索的目录,默认C盘根目录")
}

func main() {
	//dir := "C:\\Program Files (x86)" // 指定要遍历的目录，这里是当前目录
	err := filepath.WalkDir(Path, visit)
	if err != nil {
		fmt.Println(err)
		return
	}
	return

}
