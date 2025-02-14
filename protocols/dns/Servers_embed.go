package dns

import "encoding/json"
import _ "embed"
import "fmt"

//go:embed Servers.json
var embedded_servers []byte

func init() {

	err := json.Unmarshal(embedded_servers, &Servers)

	if err != nil {
		fmt.Println("ERROR: Cannot decompress embedded Servers.json")
	}

}
