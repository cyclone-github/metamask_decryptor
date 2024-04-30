[![Readme Card](https://github-readme-stats.vercel.app/api/pin/?username=cyclone-github&repo=metamask_decryptor&theme=gruvbox)](https://github.com/cyclone-github/)
# Metamask Vault Decryptor
### POC tool to decrypt metamask vault wallets
_**This tool is proudly the first publicly released Metamask Vault decryptor / cracker to support the new Metamask wallet vaults which have a dynamic iteration.**_
```
./metamask_decryptor_amd64.bin -h metamask_json.txt -w wordlist.txt
 ------------------------------------ 
| Cyclone's Metamask Vault Decryptor |
 ------------------------------------ 

Vault file:     metamask_json.txt
Valid Vaults:   1
CPU Threads:    16
Wordlist:       wordlist.txt
Working...

Decrypted: 0/1  5430.89 h/s     00h:01m:00s
```
### Info:
- Supports previous Metamask vaults as well as new vaults with "KeyMetadata" which have dynamic iterations
- If you need help extracting Metamask vaults, use `Metamask Extractor` https://github.com/cyclone-github/metamask_extractor
- _`Metamask Vault Decryptor` will be superseded by hashcat once a custom hashcat kernel is released, however, `Metamask Vault Decryptor` also displays the seed phrase alongside the vault password, which hashcat does not currently support_

### Example vaults supported:
- Old vault format: `{"data": "","iv": "","salt": ""}`
- New vault format: `{"data": "","iv": "","keyMetadata": {"algorithm": "PBKDF2","params": {"iterations": }},"salt": ""}`

### Usage example:
- `./metamask_decryptor.bin -h {wallet_json} -w {wordlist}`

### Output example:
If the tool successfully decrypts the vault, tool will print the vault json, seed phrase and vault password
```
Decrypted Vault: '{}'
Seed Phrase:    ''
Vault Password: ''
```

### Compile from source:
- If you want the latest features, compiling from source is the best option since the release version may run several revisions behind the source code.
- This assumes you have Go and Git installed
  - `git clone https://github.com/cyclone-github/metamask_decryptor.git`
  - `cd metamask_decryptor`
  - `go mod init metamask_decryptor`
  - `go mod tidy`
  - `go build -ldflags="-s -w" metamask_decryptor.go`
- Compile from source code how-to:
  - https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt
