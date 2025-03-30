package actions

import "dnsquery/console"
import "dnsquery/files"
import "dnsquery/protocols/dns"
import "slices"

func Resolve(hosts *files.Hosts, subject string) bool {

	var result bool

	console.Group("Resolve \"" + subject + "\"")

	response, err := dns.Resolve(subject)

	if err == nil && len(response.Answers) > 0 {

		for a := 0; a < len(response.Answers); a++ {

			record := response.Answers[a]

			if record.Type == dns.TypeA {

				domain := record.ToDomain()
				ipv4 := record.ToIPv4()

				if slices.Contains(hosts.Lookup(domain), ipv4) == false {
					console.Log("> Adding IPv4 \"" + ipv4 + "\"")
					hosts.Add(domain, ipv4)
					result = true
				}

			} else if record.Type == dns.TypeAAAA {

				domain := record.ToDomain()
				ipv6 := record.ToIPv6()

				if slices.Contains(hosts.Lookup(domain), ipv6) == false {
					console.Log("> Adding IPv6 \"" + ipv6 + "\"")
					hosts.Add(domain, ipv6)
					result = true
				}

			} else if record.Type == dns.TypeCNAME {

				domain := record.ToDomain()

				if domain != "" && domain != subject {
					result = Resolve(hosts, domain)
				}

			}

		}

	}

	if result == false {
		console.Warn("> Resolved IPs already cached")
	}

	console.GroupEnd()

	return result

}
