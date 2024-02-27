package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

/*
Cyclone's Metamask Vault Decryptor
POC tool to decrypt metamask vault wallets
This tool is proudly the first publicly released Metamask Vault decryptor / cracker to support the new Metamask wallet vaults which have a dynamic iteration
Tool will be superseded by hashcat once a custom hashcat kernel is released
coded by cyclone in Go

GNU General Public License v2.0
https://github.com/cyclone-github/metamask_decryptor/blob/main/LICENSE

version history
v0.1.0; initial github release

TO-DO:
    add multi-threading support
*/

// version func
func versionFunc() {
	fmt.Fprintln(os.Stderr, "Cyclone's Metamask Vault Decryptor v0.1.0; initial github release\nhttps://github.com/cyclone-github/metamask_decryptor\n")
}

// help func
func helpFunc() {
	versionFunc()
	str := `Supports both old and new Metamask vaults with or without 'KeyMetadata'

Example vaults supported:
	- Old vault format: {"data": "","iv": "","salt": ""}
	- New vault format: {"data": "","iv": "","keyMetadata": {"algorithm": "PBKDF2","params": {"iterations": }},"salt": ""}

Usage: ./metamask_decryptor.bin -h {wallet_json} -w {wordlist}`
	fmt.Fprintln(os.Stderr, str)
}

// MetamaskVault vault struct
type MetamaskVault struct {
	Data        string       `json:"data"`
	Iv          string       `json:"iv"`
	Salt        string       `json:"salt"`
	KeyMetadata *KeyMetadata `json:"keyMetadata,omitempty"`
	Decrypted   bool         `json:"-"` // mark vault as decrypted so it's not run again
}

// KeyMetadata struct (newer metamask vaults)
type KeyMetadata struct {
	Algorithm string    `json:"algorithm"` // PBKDF2
	Params    KeyParams `json:"params"`    // PBKDF2 params
}

// PBKDF2 parameters (newer metamask vaults)
type KeyParams struct {
	Iterations int `json:"iterations"` // iterations, old default is 10000
}

// Vault struct (for seed key)
type Vault struct {
	Type string `json:"type"`
	Data struct {
		Mnemonic []byte `json:"mnemonic"` // seed phrase
	} `json:"data"`
}

// main func
func main() {
	hashFlag := flag.String("h", "", "Path to Metamask JSON file")
	wordlistFlag := flag.String("w", "", "Path to wordlist file")
	version := flag.Bool("version", false, "Program version:")
	cyclone := flag.Bool("cyclone", false, "Metamask Decryptor")
	help := flag.Bool("help", false, "Help message")
	flag.Parse()

	// run sanity checks for special flags
	if *version {
		versionFunc()
		os.Exit(0)
	}
	if *cyclone {
		line := "Q29kZWQgYnkgY3ljbG9uZSA7KQo="
		str, _ := base64.StdEncoding.DecodeString(line)
		fmt.Println(string(str))
		os.Exit(0)
	}
	if *help {
		helpFunc()
		os.Exit(0)
	}

	if *hashFlag == "" || *wordlistFlag == "" {
		fmt.Println("Usage: -h <path to Metamask JSON file> -w <path to wordlist file>")
		return
	}

	vaults, err := ReadMetamaskJSON(*hashFlag)
	if err != nil {
		fmt.Println("Error reading Metamask JSON:", err)
		return
	}

	for _, vault := range vaults {
		if err := ReadWordlist(*wordlistFlag, &vault); err != nil {
			fmt.Println("Error:", err)
			return
		}
	}
}

// parse metamask json
func ReadMetamaskJSON(filePath string) ([]MetamaskVault, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	uniqueVaults := make(map[string]MetamaskVault)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		originalLine := scanner.Text()
		line := strings.TrimSpace(originalLine)
		line = strings.Replace(line, "\\", "", -1)

		if line == "" {
			continue
		}

		var vault MetamaskVault
		if err := json.Unmarshal([]byte(line), &vault); err != nil {
			// if line is not a valid json string, print warning to terminal and skip this line
			fmt.Printf("Skipping invalid Vault: %s\n", originalLine)
			continue
		}

		// store vaults into map to deduplicate
		key := vault.Data + ":" + vault.Iv + ":" + vault.Salt
		uniqueVaults[key] = vault
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	var dedupedVaults []MetamaskVault
	for _, vault := range uniqueVaults {
		dedupedVaults = append(dedupedVaults, vault)
	}

	return dedupedVaults, nil
}

// read passwords from wordlist
func ReadWordlist(filePath string, vault *MetamaskVault) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		password := scanner.Text()
		if vault.Decrypted {
			break // skip vault since it's already decrypted
		}
		if decryptVault(password, vault) {
			vault.Decrypted = true // mark vault as decrypted
			break                  // continue to next vault
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

// decrypt metamask vault
func decryptVault(password string, vault *MetamaskVault) bool {
	salt, _ := base64.StdEncoding.DecodeString(vault.Salt)
	iterations := 10000 // default iterations for v1 vaults
	if vault.KeyMetadata != nil {
		iterations = vault.KeyMetadata.Params.Iterations // use custom iterations from vault metadata for v2 vaults
	}

	key := pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return false
	}

	iv, _ := base64.StdEncoding.DecodeString(vault.Iv)
	data, _ := base64.StdEncoding.DecodeString(vault.Data)
	gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return false
	}

	decryptedData, err := gcm.Open(nil, iv, data, nil)
	if err != nil {
		return false
	}

	var vaultData []Vault
	if err := json.Unmarshal(decryptedData, &vaultData); err != nil {
		return false
	}

	for _, v := range vaultData {
		if len(v.Data.Mnemonic) > 0 {
			fmt.Printf("\nDecrypted Vault: '%s'\nSeed Phrase:\t'%s'\nVault Password:\t'%s'\n", vault, string(v.Data.Mnemonic), password)
			return true
		}
	}

	return false
}

// end code
