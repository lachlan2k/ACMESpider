package nonce

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	log "github.com/sirupsen/logrus"
)

type NonceController interface {
	Gen() (string, error)
	ValidateAndConsume(nonce string) (bool, error)
}

type InMemController struct {
	lock         sync.Mutex
	usedMap      []bool
	innerCounter uint16
	outerCounter uint32
	maxLifetime  time.Duration
	aead         cipher.AEAD
}

type nonceData struct {
	t            uint64
	innerCounter uint16
	outerCounter uint32
}

const nonceDataSize = 8 + 2 + 4
const maxStoredNonces = uint16(65535)

func NewInMemCtrl() NonceController {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		log.WithError(err).Fatal("failed to generate key for nonce controller")
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		log.WithError(err).Fatal("failed to make chacha")
	}

	return &InMemController{
		usedMap:     make([]bool, maxStoredNonces),
		aead:        aead,
		maxLifetime: time.Minute,
	}
}

func (ctrl *InMemController) enc(data nonceData) ([]byte, error) {
	msgBuff := make([]byte, nonceDataSize)
	binary.LittleEndian.PutUint64(msgBuff, data.t)
	binary.LittleEndian.PutUint16(msgBuff[8:], data.innerCounter)
	binary.LittleEndian.PutUint32(msgBuff[10:], data.outerCounter)

	cryptNonce := make([]byte, ctrl.aead.NonceSize(), ctrl.aead.NonceSize()+len(msgBuff)+ctrl.aead.Overhead())
	_, err := rand.Read(cryptNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce for nonce encryption: %w", err)
	}

	return ctrl.aead.Seal(cryptNonce, cryptNonce, msgBuff, nil), nil
}

func (ctrl *InMemController) dec(encMsg []byte) (nonceData, error) {
	if len(encMsg) < ctrl.aead.NonceSize() {
		return nonceData{}, fmt.Errorf("failed to decrypt nonce data, message too small (size %d, expected %d)", len(encMsg), ctrl.aead.NonceSize())
	}

	cryptNonce, ciphertext := encMsg[:ctrl.aead.NonceSize()], encMsg[ctrl.aead.NonceSize():]
	plaintext, err := ctrl.aead.Open(nil, cryptNonce, ciphertext, nil)
	if err != nil {
		return nonceData{}, fmt.Errorf("failed to decrypt nonce data: %w", err)
	}

	if len(plaintext) != nonceDataSize {
		return nonceData{}, fmt.Errorf("decrypted nonce was %d bytes, expected %d", len(plaintext), nonceDataSize)
	}

	return nonceData{
		t:            binary.LittleEndian.Uint64(plaintext[0:8]),
		innerCounter: binary.LittleEndian.Uint16(plaintext[8:10]),
		outerCounter: binary.LittleEndian.Uint32(plaintext[10:]),
	}, nil
}

func (ctrl *InMemController) Gen() (string, error) {
	ctrl.lock.Lock()
	defer ctrl.lock.Unlock()

	encNonce, err := ctrl.enc(nonceData{
		t:            uint64(time.Now().Unix()),
		innerCounter: ctrl.innerCounter,
		outerCounter: ctrl.outerCounter,
	})
	if err != nil {
		return "", err
	}

	ctrl.usedMap[ctrl.innerCounter] = false

	ctrl.innerCounter++

	if ctrl.innerCounter >= maxStoredNonces {
		ctrl.innerCounter = 0
		ctrl.outerCounter++
	}

	return base64.RawURLEncoding.EncodeToString(encNonce), nil
}

func (ctrl *InMemController) ValidateAndConsume(nonce string) (bool, error) {
	ctrl.lock.Lock()
	defer ctrl.lock.Unlock()

	encNonce, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		return false, fmt.Errorf("failed to b64 decode nonce: %w", err)
	}

	d, err := ctrl.dec(encNonce)
	if err != nil {
		return false, fmt.Errorf("failed to decrypt nonce: %w", err)
	}

	now := time.Now()
	expiry := time.Unix(int64(d.t), 0).Add(ctrl.maxLifetime)
	if now.After(expiry) {
		// Expired nonce
		return false, fmt.Errorf("nonce expired %f seconds ago", now.Sub(expiry).Seconds())
	}

	// The two conditions that are valid are:
	// 1) The outer counter matches. That means the current innerCounter and lower of the usedMap belong to this rotation
	// 2) The outer counter is -1 of the current. That means values in usedMap that are >innerCounter belong to the last outer cycle
	// this gives us something resembling a circular buffer
	validThisLoop := d.outerCounter == ctrl.outerCounter && d.innerCounter <= ctrl.innerCounter
	validLastLoop := d.outerCounter == ctrl.outerCounter-1 && d.innerCounter > ctrl.innerCounter

	if !(validThisLoop || validLastLoop) {
		return false, fmt.Errorf("nonce counter invalid (outer %d vs %d, inner %d vs %d)", d.outerCounter, ctrl.outerCounter, d.innerCounter, ctrl.innerCounter)
	}

	if ctrl.usedMap[d.innerCounter] {
		// already used
		return false, fmt.Errorf("nonce %d already used", d.innerCounter)
	}

	// Not used yet, mark as used and return true
	ctrl.usedMap[d.innerCounter] = true
	return true, nil
}
