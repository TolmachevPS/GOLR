package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/fullsailor/pkcs7"
	"github.com/go-yaml/yaml"
)

type YAMLmetaFile struct {
	Name           string   `yaml:"name"`
	OriginalSize   uint64   `yaml:"original_size"`
	CompressedSize uint64   `yaml:"compressed_size"`
	ModTime        string   `yaml:"mod_time"`
	Sha1Hash       [20]byte `yaml:"sha1_hash"`
}

func main() {
	var mode, hash, cert, pkey, source, destination string

	flag.StringVar(&mode, "mode", "i", "Режим работы: zip(архивация), unzip(разархивация),info(информация)")

	flag.StringVar(&hash, "hash", "UNDEF", "хэш")

	flag.StringVar(&cert, "cert", "./my.crt", "сертификат")

	flag.StringVar(&pkey, "pkey", "./my.key", "")

	flag.StringVar(&source, "s", "UNDEF", "Файл, который нужно (раз)архивировать")

	flag.StringVar(&destination, "d", "./", "Путь до файла")

	flag.Parse()

	switch mode {
	case "zip":

		if source == "UNDEF" {
			fmt.Println("Файл не найден")
			os.Exit(-1)
		}

		err := CreateSzip(source, destination, cert, pkey)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		fmt.Printf("Архивация выполнена\n")
		os.Exit(0)

	case "unzip":

		if source == "UNDEF" {
			fmt.Println("Файл не найден")
			os.Exit(-1)
		}

		err := Unzip(source, destination, cert, pkey, hash)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		fmt.Printf("Разархивация выполнена\n")
		os.Exit(0)

	case "info":
		info(source, cert, pkey, hash)
		os.Exit(0)

	default:
		os.Exit(-1)
	}

}

func CreateSzip(source string, destination string, cert string, pkey string) error {
	//Создание буффера и райтера для zip-архива
	zipBuf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(zipBuf)

	//буффер для мета-файлов
	var meta []YAMLmetaFile

	//Zip
	err := ZipFileWriter(source, filepath.Base(source)+"/", zipWriter, &meta)
	if err != nil {
		return err
	}

	//закрытие райтера
	//если не закрыт, данные потеряны
	err = zipWriter.Close()
	if err != nil {
		return err
	}

	//получение мета(во все тяжкие, так сказать)
	yamlMeta, err := yaml.Marshal(&meta)
	if err != nil {
		return err
	}

	//Создание сжатых метаданных
	zipMetaBuf := new(bytes.Buffer)
	zipMetaWriter := zip.NewWriter(zipMetaBuf)
	m, err := zipMetaWriter.Create("meta.yaml")
	if err != nil {
		return err
	}

	_, err = m.Write(yamlMeta)
	if err != nil {
		return err
	}

	//закрытие метаданных
	err = zipMetaWriter.Close()
	if err != nil {
		return err
	}

	//Создание .szp файла
	metaSize := new(bytes.Buffer)
	err = binary.Write(metaSize, binary.BigEndian, uint32(binary.Size(zipMetaBuf.Bytes())))
	if err != nil {
		return err
	}

	stufToSign := append(metaSize.Bytes(), zipMetaBuf.Bytes()...)
	stufToSign = append(stufToSign, zipBuf.Bytes()...)

	err = SignArchive(stufToSign, destination, filepath.Base(source)+".szp", cert, pkey)
	if err != nil {
		return err
	}

	return nil
}

func Unzip(source string, destination string, cert string, pkey string, hash string) error {
	err, sign := CheckSZP(source, cert, pkey, hash)
	if err != nil {
		return err
	}

	err, fileMetas := GetMeta(sign)
	if err != nil {
		return err
	}

	metaSize := int64(binary.BigEndian.Uint32(sign.Content[:4]))

	//чтение архива
	bytedArchive := bytes.NewReader(sign.Content[4+metaSize:])

	zipReader, err := zip.NewReader(bytedArchive, bytedArchive.Size())
	if err != nil {
		return err
	}

	err = ZipFileReader(zipReader, fileMetas, destination)
	if err != nil {
		return err
	}
	return nil
}

func info(source string, cert string, pkey string, hash string) error {
	err, sign := CheckSZP(source, cert, pkey, hash)
	if err != nil {
		return err
	}

	err, fileMetas := GetMeta(sign)
	if err != nil {
		return err
	}

	for _, file := range fileMetas {
		fmt.Printf("%+v\n", file)
	}

	return nil
}

func CheckSZP(source string, cert string, pkey string, hash string) (error, *pkcs7.PKCS7) {
	//чтение .szp файла
	szp, err := ioutil.ReadFile(source)
	if err != nil {
		return err, nil
	}

	sign, err := pkcs7.Parse(szp)
	if err != nil {
		return err, nil
	}

	//проверка сертификата
	err = sign.Verify()
	if err != nil {
		return err, nil
	}

	signer := sign.GetOnlySigner()
	if signer == nil {
		return errors.New("ERROR: There are more or less than one signer"), nil
	}

	if hash != "UNDEF" {
		if hash != fmt.Sprintf("%x", sha1.Sum(signer.Raw)) {
			fmt.Println(fmt.Sprintf("%x", sha1.Sum(signer.Raw)))
			return errors.New("ERROR: Certificate hash is corrupted"), nil
		}
	}

	//парсинг сертификата
	certificate, err := tls.LoadX509KeyPair(cert, pkey)
	if err != nil {
		return err, nil
	}

	//получение необходимого ключа
	rsaCert, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return err, nil
	}

	if bytes.Compare(rsaCert.Raw, signer.Raw) != 0 {
		return errors.New("ERROR: сертификаты не совпадают"), nil
	}
	return nil, sign
}

func GetMeta(p *pkcs7.PKCS7) (error, []YAMLmetaFile) {
	//чтение мета
	metaSize := int64(binary.BigEndian.Uint32(p.Content[:4]))
	bytedMeta := bytes.NewReader(p.Content[4 : metaSize+4])

	readableMeta, err := zip.NewReader(bytedMeta, bytedMeta.Size())
	if err != nil {
		return err, nil
	}

	metaCompressed := readableMeta.File[0] //meta.yaml

	metaUncompressed, err := metaCompressed.Open()
	if err != nil {
		return err, nil
	}
	defer metaUncompressed.Close()

	var fileMetas []YAMLmetaFile
	metaUncompressedBody, err := ioutil.ReadAll(metaUncompressed)
	if err != nil {
		return err, nil
	}
	err = yaml.Unmarshal(metaUncompressedBody, &fileMetas)
	if err != nil {
		return err, nil
	}

	return nil, fileMetas
}

func FileToMeta(header *zip.FileHeader, fileBody []byte) YAMLmetaFile {
	fileMeta := YAMLmetaFile{
		Name:           header.Name,
		OriginalSize:   header.UncompressedSize64,
		CompressedSize: header.CompressedSize64,
		ModTime:        header.Modified.Format("Monday, 02-Jan-06 15:04:05 MST"),
		Sha1Hash:       sha1.Sum(fileBody),
	}

	return fileMeta
}

func ZipFileWriter(source string, pathTrace string, zipWriter *zip.Writer, meta *[]YAMLmetaFile) error {

	//получение всех файлов из указанного источника
	filesToWrite, err := ioutil.ReadDir(source)
	if err != nil {
		return err
	}

	//создание папки для распаковки в текущей директории
	zipWriter.Create(pathTrace)

	//поиск всех файлов
	for _, file := range filesToWrite {
		if file.IsDir() {
			ZipFileWriter(source+"/"+file.Name(), pathTrace+file.Name()+"/", zipWriter, meta)
		} else {
			f, err := zipWriter.Create(pathTrace + file.Name())
			if err != nil {
				return err
			}

			fileBody, err := ioutil.ReadFile(filepath.Join(source, file.Name()))
			if err != nil {
				return err
			}

			_, err = f.Write(fileBody)
			if err != nil {
				return err
			}

			fileHeader, err := zip.FileInfoHeader(file)
			if err != nil {
				return err
			}

			*meta = append(*meta, FileToMeta(fileHeader, fileBody))
		}

	}

	return nil
}

func ZipFileReader(zipReader *zip.Reader, fileMetas []YAMLmetaFile, destination string) error {
	for _, file := range zipReader.File {
		fileContent, err := file.Open()
		if err != nil {
			return err
		}

		fileBody, err := ioutil.ReadAll(fileContent)
		if err != nil {
			return err
		}

		for _, meta := range fileMetas {
			if meta.Name == filepath.Base(file.Name) {
				fileHash := sha1.Sum(fileBody)
				if meta.Sha1Hash != fileHash {
					return errors.New("ERROR: получен поврежденный хэш файла " + file.Name)
				}
			}
		}

		fileInfo := file.FileInfo()
		if fileInfo.IsDir() {
			_, err := os.Stat(filepath.Join(destination, file.Name))
			if os.IsNotExist(err) {
				os.MkdirAll(filepath.Join(destination, file.Name), os.ModePerm)
			} else {
				return errors.New("ERROR: директория " + file.Name + " уже существует")
			}
		} else {
			f, err := os.Create(filepath.Join(destination, file.Name))
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = f.Write(fileBody)
			if err != nil {
				return err
			}
		}

		fileContent.Close()
	}

	return nil
}

func SignArchive(stufToSign []byte, destination string, name string, cert string, pkey string) error {
	//создание данных подписи
	signedData, err := pkcs7.NewSignedData(stufToSign)
	if err != nil {
		return err
	}

	certificate, err := tls.LoadX509KeyPair(cert, pkey)
	if err != nil {
		return err
	}

	//получение необходимого ключа
	rsaPKey := certificate.PrivateKey
	rsaCert, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return err
	}

	//подпись данных
	err = signedData.AddSigner(rsaCert, rsaPKey, pkcs7.SignerInfoConfig{})
	if err != nil {
		return err
	}

	CreateSzip, err := signedData.Finish()
	if err != nil {
		return err
	}

	fmt.Printf("хэш сертификата: %x\n", sha1.Sum(rsaCert.Raw))

	szpFile, err := os.Create(filepath.Join(destination, name))
	if err != nil {
		return err
	}
	defer szpFile.Close()

	_, err = szpFile.Write(CreateSzip)
	if err != nil {
		return err
	}

	return nil
}