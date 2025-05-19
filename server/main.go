package main

import (
	"HITS_CyberSecurity/crypt"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

func main() {
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	fmt.Println("Сервер слушает на порту 8080")

	conn, err := ln.Accept()
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// 1) Генерация ключей сервера
	privS, pubS, err := crypt.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Приватный ключ сервера: %x\n", privS)
	fmt.Printf("Публичный ключ сервера: %x\n", pubS)

	// 2) Получаем публичный ключ клиента
	pubC := make([]byte, 32)
	if _, err := io.ReadFull(conn, pubC); err != nil {
		panic(err)
	}
	fmt.Printf("Получен публичный ключ клиента: %x\n", pubC)

	// 3) Отправляем свой публичный ключ клиенту
	if _, err := conn.Write(pubS); err != nil {
		panic(err)
	}

	// 4) Генерируем случайный симметричный ключ
	symmKey := make([]byte, 32)
	if _, err := rand.Read(symmKey); err != nil {
		panic(err)
	}
	fmt.Printf("Сгенерирован симметричный ключ: %x\n", symmKey)

	// 5) Шифруем симметричный ключ публичным ключом клиента
	encKey, err := crypt.EncryptSymmetricKey(symmKey, pubC, privS)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Зашифрованный симметричный ключ: %x\n", encKey)

	// 6) Отправляем длину и данные
	if err := binary.Write(conn, binary.BigEndian, uint16(len(encKey))); err != nil {
		panic(err)
	}
	if _, err := conn.Write(encKey); err != nil {
		panic(err)
	}
	fmt.Println("Отправлен зашифрованный симметричный ключ")

	// 7) Приём и расшифровка сообщений по symmKey
	for {
		// Получаем nonce
		nonce := make([]byte, 12)
		if _, err := io.ReadFull(conn, nonce); err != nil {
			fmt.Println("Ошибка чтения nonce:", err)
			return
		}
		fmt.Printf("Получен nonce (%d байт): %x\n", len(nonce), nonce)

		// Получаем длину зашифрованного сообщения
		var L uint16
		if err := binary.Read(conn, binary.BigEndian, &L); err != nil {
			fmt.Println("Ошибка чтения длины:", err)
			return
		}
		fmt.Printf("Длина зашифрованного сообщения: %d байт\n", L)

		// Получаем само зашифрованное сообщение
		ct := make([]byte, L)
		if _, err := io.ReadFull(conn, ct); err != nil {
			fmt.Println("Ошибка чтения зашифрованного сообщения:", err)
			return
		}
		fmt.Printf("Получено зашифрованное сообщение (%d байт): %x\n", len(ct), ct)

		pt, err := crypt.DecryptAESGCM(symmKey, nonce, ct)
		if err != nil {
			fmt.Println("Ошибка расшифровки:", err)
			return
		}
		fmt.Printf("Получено сообщение: %s\n", string(pt))
	}
}
