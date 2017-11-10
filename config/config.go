// Config is put into a different package to prevent cyclic imports in case
// it is needed in several locations

package config

import "time"

type Config struct {
	Period           time.Duration      `config:"period"`
	Servers          map[string]*Server `config:servers`
	DeltaWildcard    string             `config:"deltawildcard"`
	DeltaKeyWildcard string             `config:"deltakeywildcard"`
}

type Server struct {
	Hostname          string  `config:"hostname"`
	Port              string  `config:"port"`
	Username          string  `config:"username"`
	Password          string  `config:"password"`
	EncryptedPassword string  `config:"encrypted_password"`
	Queries           []Query `config:"queries"`
}

type Query struct {
	QueryStr  string `config:"query"`
	QueryType string `config:"type"`
}

var DefaultConfig = Config{
	Period:           10 * time.Second,
	DeltaWildcard:    "__DELTA",
	DeltaKeyWildcard: "__DELTAKEY",
}
