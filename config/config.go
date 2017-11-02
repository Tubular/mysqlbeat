// Config is put into a different package to prevent cyclic imports in case
// it is needed in several locations

package config

import "time"

type Config struct {
	Period            time.Duration `config:"period"`
	Hostname          string        `config:"hostname"`
	Port              string        `config:"port"`
	Username          string        `config:"username"`
	Password          string        `config:"password"`
	EncryptedPassword string        `config:"encryptedpassword"`
	Queries           []string      `config:"queries"`
	QueryTypes        []string      `config:"querytypes"`
	DeltaWildcard     string        `config:"deltawildcard"`
	DeltaKeyWildcard  string        `config:"deltakeywildcard"`
}

var DefaultConfig = Config{
	Period:           10 * time.Second,
	Hostname:         "127.0.0.1",
	Port:             "3306",
	Username:         "mysqlbeat_user",
	Password:         "mysqlbeat_pass",
	DeltaWildcard:    "__DELTA",
	DeltaKeyWildcard: "__DELTAKEY",
}
