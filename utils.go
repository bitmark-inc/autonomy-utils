package utils

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"blockwatch.cc/tzgo/tezos"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	BitmarkBlockchain  = "bitmark"
	EthereumBlockchain = "ethereum"
	TezosBlockchain    = "tezos"
	UnknownBlockchain  = ""
)

func EthereumChecksumAddress(address string) string {
	return common.HexToAddress(address).Hex()
}

// AssetIndexID returns a source-based unique asset id. It is constructed by
// source of the asset data and the asset id from the source site.
func AssetIndexID(source, id string) string {
	return fmt.Sprintf("%s-%s", source, id)
}

// GetBlockchainByAddress returns underlying blockchain of a given address
func GetBlockchainByAddress(address string) string {
	if strings.HasPrefix(address, "0x") {
		return EthereumBlockchain
	} else if len(address) == 50 {
		return BitmarkBlockchain
	} else if strings.HasPrefix(address, "tz") || strings.HasPrefix(address, "KT1") {
		return TezosBlockchain
	}

	return UnknownBlockchain
}

// GetBlockchainByContractAddress returns underlying blockchain of a given contract address
func GetBlockchainByContractAddress(address string) string {
	if strings.HasPrefix(address, "0x") {
		return EthereumBlockchain
	} else if strings.HasPrefix(address, "KT1") {
		_, err := tezos.ParseAddress(address)
		if err != nil {
			return UnknownBlockchain
		}
		return TezosBlockchain
	}

	return UnknownBlockchain
}

// EpochStringToTime returns the time object of a milliseconds epoch time string
func EpochStringToTime(ts string) (time.Time, error) {
	t, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return time.Time{}, err
	}

	return time.Unix(0, t*1000000), nil
}

// IsTimeInRange ensures a given timestamp is within a range of a target time
func IsTimeInRange(actual, target time.Time, deviationInMinutes float64) bool {
	duration := target.Sub(actual)
	return math.Abs(duration.Minutes()) < deviationInMinutes
}

// VerifyETHSignature verifies a signature with a given message and address
func VerifyETHSignature(message, signature, address string) (bool, error) {
	hash := accounts.TextHash([]byte(message))
	signatureBytes := common.FromHex(signature)

	if len(signatureBytes) != 65 {
		return false, fmt.Errorf("signature must be 65 bytes long")
	}

	// see crypto.Ecrecover description
	if signatureBytes[64] == 27 || signatureBytes[64] == 28 {
		signatureBytes[64] -= 27
	}

	// get ecdsa public key
	sigPublicKeyECDSA, err := crypto.SigToPub(hash, signatureBytes)
	if err != nil {
		return false, err
	}

	// check for address match
	sigAddress := crypto.PubkeyToAddress(*sigPublicKeyECDSA)
	if sigAddress.String() != address {
		return false, fmt.Errorf("address doesn't match with signature's")
	}

	return true, nil
}

// VerifyTezosSignature verifies a signature with a given message and address
func VerifyTezosSignature(message, signature, address, publicKey string) (bool, error) {
	return VerifyTezosSignatureMessageInBytes([]byte(message), signature, address, publicKey)
}

// VerifyTezosSignature verifies a signature with a given message in bytes and address
func VerifyTezosSignatureMessageInBytes(message []byte, signature, address, publicKey string) (bool, error) {
	ta, err := tezos.ParseAddress(address)
	if err != nil {
		return false, err
	}
	pk, err := tezos.ParseKey(publicKey)
	if err != nil {
		return false, err
	}
	if pk.Address().String() != ta.String() {
		return false, errors.New("publicKey address is different from provided address")
	}
	sig, err := tezos.ParseSignature(signature)
	if err != nil {
		return false, err
	}
	dmp := tezos.Digest(message)
	err = pk.Verify(dmp[:], sig)
	if err != nil {
		return false, err
	}
	return true, nil
}

// Untar a file
func Untar(reader io.Reader, target string) error {
	tarReader := tar.NewReader(reader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		path := filepath.Join(target, header.Name)
		info := header.FileInfo()
		if info.IsDir() {
			if err = os.MkdirAll(path, info.Mode()); err != nil {
				return err
			}
			continue
		}

		file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
		if err != nil {
			return err
		}

		_, err = io.Copy(file, tarReader)
		if err != nil {
			return err
		}

		file.Close()
	}
	return nil
}

// Tar a file
func Tar(source, target string) (io.Reader, error) {
	filename := filepath.Base(source)
	target = filepath.Join(target, fmt.Sprintf("%s.tar", filename))

	tarFile, err := os.Create(target)
	if err != nil {
		return nil, err
	}

	defer tarFile.Close()

	tarball := tar.NewWriter(tarFile)
	defer tarball.Close()

	err = filepath.Walk(source,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			header, err := tar.FileInfoHeader(info, info.Name())
			if err != nil {
				return err
			}

			header.Name = strings.TrimPrefix(path, source)

			if err := tarball.WriteHeader(header); err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			file, err := os.Open(path)
			if err != nil {
				return err
			}

			defer file.Close()

			_, err = io.Copy(tarball, file)
			return err
		})

	if err != nil {
		return nil, err
	}

	f, err := os.Open(target)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	buff := bytes.NewBuffer(nil)

	_, err = io.Copy(buff, f)
	if err != nil {
		return nil, err
	}

	return buff, nil
}
