package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	ctclient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
)

func main() {
	url := "https://ct.googleapis.com/logs/argon2021"
	fmt.Printf("Testing URL: %s\n", url)

	client, err := ctclient.New(url, &http.Client{
		Timeout: 30 * time.Second,
	}, jsonclient.Options{})
	if err != nil {
		fmt.Printf("Error creating client: %v\n", err)
		return
	}

	fmt.Println("Client created successfully")

	ctx := context.Background()
	sth, err := client.GetSTH(ctx)
	if err != nil {
		fmt.Printf("Error getting STH: %v\n", err)
		return
	}

	fmt.Printf("Tree size: %d\n", sth.TreeSize)
}
