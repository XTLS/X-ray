package shadowsocks

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"hash/crc64"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/protocol"
)

// Validator stores valid Shadowsocks users.
type Validator struct {
	sync.RWMutex
	users []*protocol.MemoryUser

	behaviorSeed  uint64
	behaviorFused bool
}

// Add a Shadowsocks user.
func (v *Validator) Add(u *protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()

	account := u.Account.(*MemoryAccount)
	if !account.Cipher.IsAEAD() && len(v.users) > 0 {
		return newError("The cipher is not support Single-port Multi-user")
	}
	v.users = append(v.users, u)

	if !v.behaviorFused {
		hashkdf := hmac.New(sha256.New, []byte("SSBSKDF"))
		hashkdf.Write(account.Key)
		v.behaviorSeed = crc64.Update(v.behaviorSeed, crc64.MakeTable(crc64.ECMA), hashkdf.Sum(nil))
	}

	return nil
}

// Del a Shadowsocks user with a non-empty Email.
func (v *Validator) Del(email string) error {
	if email == "" {
		return newError("Email must not be empty.")
	}

	v.Lock()
	defer v.Unlock()

	email = strings.ToLower(email)
	idx := -1
	for i, u := range v.users {
		if strings.EqualFold(u.Email, email) {
			idx = i
			break
		}
	}

	if idx == -1 {
		return newError("User ", email, " not found.")
	}
	ulen := len(v.users)

	v.users[idx] = v.users[ulen-1]
	v.users[ulen-1] = nil
	v.users = v.users[:ulen-1]

	return nil
}

// Get a Shadowsocks user.
func (v *Validator) Get(bs []byte, command protocol.RequestCommand) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	v.RLock()
	defer v.RUnlock()

	for _, user := range v.users {
		if account := user.Account.(*MemoryAccount); account.Cipher.IsAEAD() {
			aeadCipher := account.Cipher.(*AEADCipher)
			ivLen = aeadCipher.IVSize()
			subkey := make([]byte, 32)
			subkey = subkey[:aeadCipher.KeyBytes]
			hkdfSHA1(account.Key, bs[:ivLen], subkey)
			aead = aeadCipher.AEADAuthCreator(subkey)

			switch command {
			case protocol.RequestCommandTCP:
				data := make([]byte, 16)
				ret, err = aead.Open(data[:0], data[4:16], bs[ivLen:ivLen+18], nil)
			case protocol.RequestCommandUDP:
				data := make([]byte, 8192)
				ret, err = aead.Open(data[:0], data[8180:8192], bs[ivLen:], nil)
			}

			if err == nil {
				u = user
				break
			}
		} else {
			u = user
			ivLen = u.Account.(*MemoryAccount).Cipher.IVSize()
			break
		}
	}

	return
}

func (v *Validator) GetBehaviorSeed() uint64 {
	v.Lock()
	defer v.Unlock()

	v.behaviorFused = true
	if v.behaviorSeed == 0 {
		v.behaviorSeed = dice.RollUint64()
	}
	return v.behaviorSeed
}
