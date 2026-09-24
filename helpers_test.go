package main

import "strings"

// fileContent 生成可辨认的文件内容
func fileContent(size int) string {
	var b strings.Builder
	for i := 0; b.Len() < size; i++ {
		b.WriteByte(byte('a' + i%26))
	}
	return b.String()[:size]
}
