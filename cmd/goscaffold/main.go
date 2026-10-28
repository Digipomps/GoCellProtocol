// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

// Command goscaffold is a small Go scaffold for cross-language tests.
//
//	goscaffold serve -addr 127.0.0.1:8090 -public-url ws://127.0.0.1:8090 -allow-insecure-loopback
//	goscaffold probe -url ws://127.0.0.1:8080/bridgehead/<uuid>/Vault -allow-insecure-loopback
//
// serve hosts named Cells behind an authenticated /bridgehead route
// (org.haven.bridge-channel.v1) and the invitation landing under /i/. probe connects as a fresh identity,
// authenticates, asks for the Cell description and prints it as JSON.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	cellprotocol "github.com/Digipomps/GoCellProtocol"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "probe":
		probe(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: goscaffold serve|probe [flags]")
	os.Exit(2)
}

func serve(args []string) {
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := flags.String("addr", "127.0.0.1:8090", "listen address")
	publicURL := flags.String("public-url", os.Getenv("GOCELL_PUBLIC_URL"), "this node's own origin, e.g. wss://node.example")
	insecure := flags.Bool("allow-insecure-loopback", os.Getenv("GOCELL_ALLOW_INSECURE_LOOPBACK") == "1", "allow ws:// on a loopback public URL")
	cells := flags.String("cells", "Echo,Vault", "comma-separated named Cells to host")
	inviteRateLimit := flags.Bool("invite-rate-limit", os.Getenv("GOCELL_INVITE_RATE_LIMIT") != "0", "rate limit short-code lookups and replies on /i/, as Swift does")
	_ = flags.Parse(args)

	ctx := context.Background()
	vault := cellprotocol.NewInMemoryIdentityVault()
	owner, err := vault.Identity(ctx, "scaffold", true)
	if err != nil {
		log.Fatal(err)
	}
	resolver := cellprotocol.NewCellResolver()
	for _, name := range strings.Split(*cells, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if err := resolver.RegisterNamedEmitCell(ctx, name, cellprotocol.NewGeneralCell(owner, name), cellprotocol.RegisterOptions{}); err != nil {
			log.Fatal(err)
		}
	}
	head := cellprotocol.NewResolverBridgehead(resolver, owner, cellprotocol.BridgeheadOptions{
		PublicURL:             *publicURL,
		AllowInsecureLoopback: *insecure,
	})
	head.OnClose = func(code string) {
		if code != "" {
			log.Printf("bridge closed: %s", code)
		}
	}
	mux := http.NewServeMux()
	mux.Handle("/bridgehead/", head)
	// /i/... is the same invitation landing a Swift CellScaffold serves.
	landing := cellprotocol.NewInviteLanding(nil)
	landing.RateLimit = *inviteRateLimit
	mux.Handle("/i/", landing)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"service":"goscaffold","status":"ok"}`))
	})
	if *publicURL == "" {
		log.Print("no -public-url: every bridge connection will be refused")
	}
	log.Printf("goscaffold listening on %s", *addr)
	server := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(server.ListenAndServe())
}

func probe(args []string) {
	flags := flag.NewFlagSet("probe", flag.ExitOnError)
	url := flags.String("url", "", "bridgehead URL")
	insecure := flags.Bool("allow-insecure-loopback", false, "allow ws:// to a loopback host")
	_ = flags.Parse(args)
	if *url == "" {
		usage()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	identity, err := cellprotocol.NewInMemoryIdentityVault().Identity(ctx, "probe", true)
	if err != nil {
		log.Fatal(err)
	}
	bridge := cellprotocol.NewCloudBridge(*url, identity, cellprotocol.CloudBridgeOptions{
		Authenticate:           true,
		AllowInsecureWebSocket: *insecure,
	})
	if err := bridge.Ready(ctx); err != nil {
		log.Fatal(err)
	}
	defer bridge.CloseConnection()
	response, err := bridge.SendCommand(ctx, cellprotocol.BridgeCommand{Cmd: "description"})
	if err != nil {
		log.Fatal(err)
	}
	out, _ := json.Marshal(map[string]any{
		"admitted":    bridge.AdmittedChannel().Identity.UUID == identity.UUID,
		"transcript":  bridge.AdmittedChannel().TranscriptDigest,
		"description": response.Payload,
	})
	fmt.Println(string(out))
}
