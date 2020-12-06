package kryptik

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func verifyMessage(pubkeyFile string, message []byte, signature []byte) error {
	pubKey := decodePublicKey(pubkeyFile)

	block, err := armor.Decode(bytes.NewReader(signature))

	if err != nil || block.Type != openpgp.SignatureType {
		log.Error("Cannot decode signature")
		return err
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()

	if err != nil {
		log.Error("Cannot read packet")
		return err
	}

	sig, ok := pkt.(*packet.Signature)
	if !ok {
		log.Error("Cannot parse signature")
		return err
	}

	hash := sig.Hash.New()
	io.Copy(hash, bytes.NewReader(message))

	err = pubKey.VerifySignature(hash, sig)
	if err != nil {
		log.Error("Cannot verify signature")
	} else {
		log.Info("Signature verification success")
	}
	return err
}

func signMessage(privkeyFile string, pubkeyFile string, message []byte) ([]byte, error) {

	privKey := decodePrivateKey(privkeyFile)
	pubKey := decodePublicKey(pubkeyFile)
	signer := createEntityFromKeys(pubKey, privKey)

	var signatureBuffer bytes.Buffer

	err := openpgp.ArmoredDetachSign(&signatureBuffer, signer, bytes.NewBuffer(message), nil)

	if err != nil {
		log.Error("Error encountered while signing: ", err)
		return signatureBuffer.Bytes(), err
	} else {
		return signatureBuffer.Bytes(), nil
	}
}

func GetSignedMessage(privkeyFile string, pubkeyFile string, message []byte) (SignedMessage, error) {
	sign, err := signMessage(privkeyFile, pubkeyFile, message)
	if err != nil {
		log.Error("Cannot get a signature for message: ", message)
		return SignedMessage{}, err
	}
	return SignedMessage{Message: message, Signature: sign}, nil
}

func VerifySignedMessage(pubkeyFile string, msg SignedMessage) bool {
	err := verifyMessage(pubkeyFile, msg.Message, msg.Signature)
	if err != nil {
		log.Error("Failure to verify signed message: ", err)
		return false
	}
	return true
}

func GenerateKeysToFiles(prefix string) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal("Error Generating keys: ", err)
		return
	}

	// Encode private key
	f, err := os.Create(prefix + ".privkey")
	w, err := armor.Encode(f, openpgp.PrivateKeyType, make(map[string]string))
	if err != nil {
		log.Fatal("Error Opening file: ", err)
		return
	}
	pgpKey := packet.NewRSAPrivateKey(time.Now(), key)
	err = pgpKey.Serialize(w)
	if err != nil {
		log.Fatal("Error writing to file privkey: ", err)
		return
	}
	err = w.Close()

	// Encode public key
	f, err = os.Create(prefix + ".pubkey")
	w, err = armor.Encode(f, openpgp.PublicKeyType, make(map[string]string))
	if err != nil {
		log.Fatal("Error Opening file: ", err)
		return
	}
	pgpKey2 := packet.NewRSAPublicKey(time.Now(), &key.PublicKey)
	err = pgpKey2.Serialize(w)
	if err != nil {
		log.Fatal("Error writing to file pubkey: ", err)
		return
	}
	err = w.Close()
}

func decodePrivateKey(filename string) *packet.PrivateKey {
	// open ascii armored private key
	in, err := os.Open(filename)
	if err != nil {
		log.Error("Error opening private key: ", err)
		return nil
	}
	defer in.Close()

	block, err := armor.Decode(in)
	if err != nil {
		log.Error("Error decoding private key: ", err)
		return nil
	}

	if block.Type != openpgp.PrivateKeyType {
		log.Error("Not a private key: ", filename)
		return nil
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()

	if err != nil {
		log.Error("Error reading private key: ", err)
		return nil
	}

	key, ok := pkt.(*packet.PrivateKey)
	if !ok {
		log.Error("Invalid private key: ", err)
		return nil
	}
	return key
}

func decodePublicKey(filename string) *packet.PublicKey {
	// open ascii armored public key
	in, err := os.Open(filename)
	if err != nil {
		log.Error("Error opening public key: ", err)
		return nil
	}
	defer in.Close()

	block, err := armor.Decode(in)
	if err != nil {
		log.Error("Error decoding public key: ", err)
		return nil
	}

	if block.Type != openpgp.PublicKeyType {
		log.Error("Not a public key: ", filename)
		return nil
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()

	if err != nil {
		log.Error("Error reading public key: ", err)
		return nil
	}

	key, ok := pkt.(*packet.PublicKey)
	if !ok {
		log.Error("Invalid public key: ", ok)
		return nil
	}
	return key
}

func createEntityFromKeys(pubKey *packet.PublicKey, privKey *packet.PrivateKey) *openpgp.Entity {
	config := packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig: &packet.CompressionConfig{
			Level: 9,
		},
		RSABits: 4096,
	}
	currentTime := config.Now()
	uid := packet.NewUserId("", "", "")

	e := openpgp.Entity{
		PrimaryKey: pubKey,
		PrivateKey: privKey,
		Identities: make(map[string]*openpgp.Identity),
	}
	isPrimaryId := false

	e.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Name,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: currentTime,
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			Hash:         config.Hash(),
			IsPrimaryId:  &isPrimaryId,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &e.PrimaryKey.KeyId,
		},
	}

	keyLifetimeSecs := uint32(86400 * 365 * 2)

	e.Subkeys = make([]openpgp.Subkey, 1)
	e.Subkeys[0] = openpgp.Subkey{
		PublicKey:  pubKey,
		PrivateKey: privKey,
		Sig: &packet.Signature{
			CreationTime:              currentTime,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                packet.PubKeyAlgoRSA,
			Hash:                      config.Hash(),
			PreferredHash:             []uint8{8}, // SHA-256
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &e.PrimaryKey.KeyId,
			KeyLifetimeSecs:           &keyLifetimeSecs,
		},
	}
	return &e
}

// func main() {
// 	prefix := "hello"
// 	message := "this is the long message"

// 	log.Info("Generating keys")
// 	GenerateKeysToFiles(prefix)

// 	log.Info("Sign message")
// 	signed, err := GetSignedMessage(prefix+".privkey", prefix+".pubkey", []byte(message))
// 	if err != nil {
// 		log.Error("Error signing message")
// 	}

// 	log.Info("Decode message")

// 	if VerifySignedMessage(prefix+".pubkey", signed) {
// 		log.Info("Signature verified")
// 	} else {
// 		log.Error("Signature is wrong")
// 	}
// }

type SignedMessage struct {
	Message   []byte `json:"message"`
	Signature []byte `json:"signature"`
}
