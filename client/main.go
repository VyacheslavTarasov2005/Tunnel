package main

import (
	"HITS_CyberSecurity/crypt"
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
)

func main() {
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// 1) Генерация ключей клиента и отправка публичного
	privC, pubC, err := crypt.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Приватный ключ клиента: %x\n", privC)
	fmt.Printf("Публичный ключ клиента: %x\n", pubC)
	if _, err := conn.Write(pubC); err != nil {
		panic(err)
	}

	// 2) Получаем публичный ключ сервера
	pubS := make([]byte, 32)
	if _, err := io.ReadFull(conn, pubS); err != nil {
		panic(err)
	}
	fmt.Printf("Получен публичный ключ сервера: %x\n", pubS)

	// 3) Получаем размер и зашифрованный симметричный ключ
	var L uint16
	if err := binary.Read(conn, binary.BigEndian, &L); err != nil {
		panic(err)
	}
	encKey := make([]byte, L)
	if _, err := io.ReadFull(conn, encKey); err != nil {
		panic(err)
	}
	fmt.Printf("Получен зашифрованный симметричный ключ: %x\n", encKey)

	// 4) Дешифруем симметричный ключ
	symmKey, err := crypt.DecryptSymmetricKey(encKey, pubS, privC)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Расшифрованный симметричный ключ: %x\n", symmKey)

	// 5) Шифруем и отправляем сообщения по symmKey
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Введите сообщение:")
	for scanner.Scan() {
		text := scanner.Text()
		nonce, ct, err := crypt.EncryptAESGCM(symmKey, []byte(text))
		if err != nil {
			fmt.Println("Ошибка шифрования:", err)
			continue
		}
		conn.Write(nonce)
		binary.Write(conn, binary.BigEndian, uint16(len(ct)))
		conn.Write(ct)
		fmt.Println("Сообщение отправлено")
	}
}
