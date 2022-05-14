package cypher

type Cypher interface {
	Encrypt(key string, value string) (string, error)
	Decrypt(key string, value string) (string, error)
}
