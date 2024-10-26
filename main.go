package main

import (
	"bufio"
	"errors"
	"fmt"
	server "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

type HttpTunnel struct {
	w    io.Writer
	done chan struct{}
}

var (
	DeadlineTimeout = 30 * time.Second
	IdleTimeout     = 10 * time.Second
	tunnels         = make(map[int]chan HttpTunnel)
	mu              = sync.RWMutex{}
)

func main() {
	go func() {
		http.HandleFunc("/", handleHttpRequest)
		log.Fatal(http.ListenAndServe(":8080", nil))
	}()

	server.Handle(func(s server.Session) {
		_, err := io.WriteString(s, fmt.Sprintf("user: %s connected\n", s.User()))
		if err != nil {
			log.Printf("error writing to connection, %v", err)
		}

		id := rand.Intn(math.MaxInt)

		mu.Lock()
		tunnels[id] = make(chan HttpTunnel)
		mu.Unlock()

		log.Printf("tunnel ID -> %d\n", id)

		mu.RLock()
		tunnel := <-tunnels[id]
		mu.RUnlock()
		log.Println("tunnel is ready")

		_, err = io.Copy(tunnel.w, s)
		if err != nil {
			return
		}

		close(tunnel.done)

		_, err = io.MultiWriter(tunnel.w, s).Write([]byte("\n\n!!! DONE"))
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
	log.Printf("connections will only last %s\n", DeadlineTimeout)
	srv := &server.Server{
		Addr:        ":2222",
		MaxTimeout:  DeadlineTimeout,
		IdleTimeout: IdleTimeout,
	}
	err := srv.SetOption(publicKeyOption)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(srv.ListenAndServe())
}

func handleHttpRequest(w http.ResponseWriter, r *http.Request) {
	idParam := r.URL.Query().Get("id")
	if idParam == "" {
		return
	}
	id, err := strconv.Atoi(idParam)
	if err != nil {
		log.Printf("error parsing id: %v\n", err)
		return
	}

	mu.RLock()
	tunnel, ok := tunnels[id]
	mu.RUnlock()

	if !ok {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("tunnel not found\n"))
		return
	}

	doneCh := make(chan struct{})
	tunnel <- HttpTunnel{w: w, done: doneCh}
	<-doneCh
}
