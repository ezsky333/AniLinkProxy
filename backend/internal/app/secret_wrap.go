package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

const appSecretEncPrefix = "enc:v1:"

func sealAppSecret(plain string, key []byte) (string, error) {
	if plain == "" {
		return plain, nil
	}
	if len(key) != 32 {
		return plain, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plain), nil)
	blob := append(append([]byte{}, nonce...), ciphertext...)
	return appSecretEncPrefix + base64.StdEncoding.EncodeToString(blob), nil
}

func unsealAppSecret(stored string, key []byte) (string, error) {
	if stored == "" {
		return "", nil
	}
	if !strings.HasPrefix(stored, appSecretEncPrefix) {
		return stored, nil
	}
	if len(key) != 32 {
		return "", errors.New("数据库中的 AppSecret 已加密，但未配置有效的 SECRET_WRAP_KEY")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, appSecretEncPrefix))
	if err != nil {
		return "", fmt.Errorf("解密封存密钥失败: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return "", errors.New("密文长度无效")
	}
	nonce, ct := raw[:ns], raw[ns:]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("解密 AppSecret 失败: %w", err)
	}
	return string(plain), nil
}
