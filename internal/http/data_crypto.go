package http

import (
	"portlyn/internal/secureconfig"
)

func (s *Server) dataEncryptJSON(value map[string]string) (string, error) {
	return secureconfig.EncryptJSONV2([]byte(s.cfg.DataEncryptionSecret), value)
}

func (s *Server) dataDecryptJSON(value string) (map[string]string, error) {
	return secureconfig.DecryptJSONAuto(s.dataSecrets(), value)
}

func (s *Server) dataDecryptJSONWithActiveKey(value string) (map[string]string, error) {
	return secureconfig.DecryptJSONAuto([][]byte{[]byte(s.cfg.DataEncryptionSecret)}, value)
}

func (s *Server) dataSecrets() [][]byte {
	values := s.cfg.DataEncryptionSecrets()
	out := make([][]byte, 0, len(values))
	for _, value := range values {
		out = append(out, []byte(value))
	}
	return out
}
