package sshup

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
)

const (
	keyMagic   = "openssh-key-v1\x00"
	keyType    = "ssh-ed25519"
	pemType    = "OPENSSH PRIVATE KEY"
	cipherNone = "none"
)

// newHostKey returns an ed25519 host key in OpenSSH's own private key format and its public line
func newHostKey() ([]byte, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	var check [4]byte
	if _, err := rand.Read(check[:]); err != nil {
		return nil, "", err
	}
	blob := publicBlob(pub)

	var secret bytes.Buffer
	secret.Write(check[:])
	secret.Write(check[:])
	putString(&secret, []byte(keyType))
	putString(&secret, pub)
	putString(&secret, priv)
	putString(&secret, nil)
	for i := byte(1); secret.Len()%8 != 0; i++ {
		secret.WriteByte(i)
	}

	var body bytes.Buffer
	body.WriteString(keyMagic)
	putString(&body, []byte(cipherNone))
	putString(&body, []byte(cipherNone))
	putString(&body, nil)
	_ = binary.Write(&body, binary.BigEndian, uint32(1))
	putString(&body, blob)
	putString(&body, secret.Bytes())
	text := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: body.Bytes()})
	return text, keyType + " " + base64.StdEncoding.EncodeToString(blob), nil
}

// publicLine reads the public key line out of an unencrypted OpenSSH ed25519 private key
func publicLine(text []byte) (string, error) {
	block, _ := pem.Decode(text)
	if block == nil || block.Type != pemType {
		return "", errors.New("not an OpenSSH private key")
	}
	rest, ok := bytes.CutPrefix(block.Bytes, []byte(keyMagic))
	if !ok {
		return "", errors.New("the key lacks OpenSSH's magic")
	}
	var fields [3][]byte
	for i := range fields {
		if fields[i], rest, ok = getString(rest); !ok {
			return "", errors.New("the key is truncated")
		}
	}
	if string(fields[0]) != cipherNone || string(fields[1]) != cipherNone {
		return "", errors.New("the key is encrypted")
	}
	if len(rest) < 4 || binary.BigEndian.Uint32(rest) != 1 {
		return "", errors.New("the key file must hold one key")
	}
	blob, _, ok := getString(rest[4:])
	if !ok {
		return "", errors.New("the key is truncated")
	}
	kind, pub, ok := getString(blob)
	if !ok || string(kind) != keyType {
		return "", fmt.Errorf("the key is not %s", keyType)
	}
	if raw, tail, ok := getString(pub); !ok || len(raw) != ed25519.PublicKeySize || len(tail) > 0 {
		return "", errors.New("the public key has the wrong length")
	}
	return keyType + " " + base64.StdEncoding.EncodeToString(blob), nil
}

func publicBlob(pub ed25519.PublicKey) []byte {
	var b bytes.Buffer
	putString(&b, []byte(keyType))
	putString(&b, pub)
	return b.Bytes()
}

// putString writes the SSH wire form, a 32-bit big-endian length and the bytes
func putString(b *bytes.Buffer, s []byte) {
	_ = binary.Write(b, binary.BigEndian, uint32(len(s)))
	b.Write(s)
}

func getString(b []byte) ([]byte, []byte, bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}
