package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	server "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"os"
)

func main() {
	server.Handle(func(s server.Session) {
		data := new(bytes.Buffer)
		buf := make([]byte, 1024)

		n, err := io.WriteString(s, fmt.Sprintf("user: %s connected\n", s.User()))
		if err != nil {
			log.Printf("error writing to connection, %v", err)
		}
		for {
			n, err = s.Read(buf)
			if err == io.EOF {
				_, err = s.Write([]byte(fmt.Sprintf("done reading\n\n")))
				if err != nil {
					log.Printf("error writing to connection, %v", err)
					return
				}
				break
			}
			if err != nil {
				log.Printf("read error: %v", err)
				return
			}
			_, err = s.Write([]byte(fmt.Sprintf("got %d bytes\n", n)))
			if err != nil {
				log.Printf("error writing to connection, %v", err)
				return
			}
			data.Write(buf[:n])
		}
		_, err = s.Write(data.Bytes())
		if err != nil {
			log.Printf("error writing to connection, %v", err)
			return
		}
	})

	publicKeyOption := server.PublicKeyAuth(func(ctx server.Context, incomingKey server.PublicKey) bool {
		ik := ssh.MarshalAuthorizedKey(incomingKey)
		log.Printf("user with key: %s coming...\n", ik)
		keys, err := os.Open("./.authorized_keys")
		defer func() {
			err = errors.Join(err, keys.Close())
		}()

		if err != nil {
			log.Printf("authorized keys reading error:%v\n", err)
			return false
		}

		r := bufio.NewReader(keys)

		for {
			key, _, err := r.ReadLine()
			if err != nil {
				break
			}

			if len(key) > 0 {
				publicKey, _, _, _, err := ssh.ParseAuthorizedKey(key)
				if err != nil {
					log.Printf("authorized keys parsing error:%v\n", err)
					continue
				}

				if server.KeysEqual(incomingKey, publicKey) {
					log.Println(">> Authorized user, access granted")
					return true
				}
			}
		}

		return false
	})

	log.Println("starting ssh server on port 2222...")
	log.Fatal(server.ListenAndServe(":2222", nil, publicKeyOption))
}
