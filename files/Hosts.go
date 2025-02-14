package files

import "dnsquery/types"
import "os"
import "sort"
import "strings"

var HostsMarker string = "# Do NOT edit below this line (managed by dnsquery)"

type Hosts struct {
	File           string              `json:"file"`
	Unmanaged      string              `json:"unmanaged"`
	ManagedDomains map[string][]string `json:"managed_hosts"`
}

func ParseHosts(file string) Hosts {

	var hosts Hosts

	hosts.File = file
	hosts.ManagedDomains = make(map[string][]string, 0)
	hosts.Parse()

	return hosts

}

func (hosts *Hosts) Parse() bool {

	var result bool = false

	buffer, err := os.ReadFile(hosts.File)

	if err == nil {

		content := strings.TrimSpace(string(buffer))

		if strings.Contains(content, HostsMarker) {

			unmanaged := content[0:strings.Index(content, HostsMarker)]
			managed := content[strings.Index(content, HostsMarker)+len(HostsMarker):]

			// Keep user-edited hosts as-is
			hosts.Unmanaged = strings.TrimSpace(unmanaged)

			lines := strings.Split(strings.TrimSpace(managed), "\n")

			for l := 0; l < len(lines); l++ {

				line := strings.TrimSpace(lines[l])

				if strings.HasPrefix(line, "#") {
					// Do Nothing
				} else if strings.Contains(line, "#") {
					line = strings.TrimSpace(line[0:strings.Index(line, "#")])
				}

				if strings.Contains(line, " ") {

					ip := line[0:strings.Index(line, " ")]
					domains := strings.Split(strings.TrimSpace(line[strings.Index(line, " ")+1:]), " ")

					for _, domain := range domains {
						hosts.Add(domain, ip)
					}

				}

			}

			result = true

		} else {

			unmanaged := strings.TrimSpace(content)

			// Keep user-edited hosts as-is
			hosts.Unmanaged = unmanaged
			result = true

		}

	}

	return result

}

func (hosts *Hosts) Lookup(domain string) []string {

	var result []string

	tmp, ok := hosts.ManagedDomains[domain]

	if ok == true {
		result = tmp
	}

	return result

}

func (hosts *Hosts) Add(domain string, ip string) bool {

	var result bool = false

	if types.IsIPv6(ip) {

		_, ok := hosts.ManagedDomains[domain]

		if ok == true {
			hosts.ManagedDomains[domain] = append(hosts.ManagedDomains[domain], ip)
		} else {
			hosts.ManagedDomains[domain] = []string{ip}
		}

	} else if types.IsIPv4(ip) {

		_, ok := hosts.ManagedDomains[domain]

		if ok == true {
			hosts.ManagedDomains[domain] = append(hosts.ManagedDomains[domain], ip)
		} else {
			hosts.ManagedDomains[domain] = []string{ip}
		}

	}

	return result

}

func (hosts *Hosts) Write() bool {

	var result bool = false

	buffer := hosts.Unmanaged + "\n"
	buffer += "\n" + HostsMarker + "\n\n"

	for domain, ips := range hosts.ManagedDomains {

		sort.Strings(ips)

		for i := 0; i < len(ips); i++ {

			ip := ips[i]

			if types.IsIPv4(ip) {

				buffer += ip + " " + domain + "\n"

			} else if types.IsIPv6(ip) {

				if strings.HasPrefix(ip, "[") && strings.HasSuffix(ip, "]") {
					buffer += ip[1:len(ip)-1] + " " + domain + "\n"
				} else {
					buffer += ip + " " + domain + "\n"
				}

			}

		}

	}

	// resolv sometimes expects trailing newline
	buffer = strings.TrimSpace(buffer) + "\n"

	if hosts.File != "" {

		err := os.WriteFile(hosts.File, []byte(buffer), 0666)

		if err == nil {
			result = true
		}

	}

	return result

}
