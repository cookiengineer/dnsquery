package main

import "dnsquery/files"
import "dnsquery/protocols/dns"
import "fmt"
import "os"
import "slices"
import "strings"

func main() {

	subjects := make([]string, 0)
	result := false

	if len(os.Args) > 1 {

		for a := 1; a < len(os.Args); a++ {

			subject := strings.TrimSpace(strings.ToLower(os.Args[a]))

			if subject != "" {
				subjects = append(subjects, subject)
			}

		}

	}

	if len(subjects) > 0 {

		changed_hosts := false
		hosts := files.ParseHosts("/etc/hosts")

		for s := 0; s < len(subjects); s++ {

			subject := subjects[s]

			if subject != "" {

				fmt.Println("/-- Resolving " + subject)

				changed_subject := false
				response, err := dns.Resolve(subject)

				if err == nil && len(response.Answers) > 0 {

					for a := 0; a < len(response.Answers); a++ {

						record := response.Answers[a]

						if record.Type == dns.TypeA {

							domain := record.ToDomain()
							ipv4 := record.ToIPv4()

							if slices.Contains(hosts.Lookup(domain), ipv4) == false {
								fmt.Println("|-> Adding IPv4 " + ipv4)
								hosts.Add(domain, ipv4)
								changed_subject = true
							}

						} else if record.Type == dns.TypeAAAA {

							domain := record.ToDomain()
							ipv6 := record.ToIPv6()

							if slices.Contains(hosts.Lookup(domain), ipv6) == false {
								fmt.Println("|-> Adding IPv6 " + ipv6)
								hosts.Add(domain, ipv6)
								changed_subject = true
							}

						} else if record.Type == dns.TypeCNAME {

							// TODO: Lookup CNAME domain

						}

					}

				}

				if changed_subject == true {
					changed_hosts = true
				} else {
					fmt.Println("|-> Resolved IPs already cached")
				}

				fmt.Println("\\--")

			}

		}

		if changed_hosts == true {

			fmt.Println("> Writing /etc/hosts")

			if hosts.Write() == true {
				result = true
			} else {
				fmt.Println("ERROR: Could not write /etc/hosts")
			}

		} else {
			result = true
		}

	}

	if result == true {
		os.Exit(0)
	} else {
		os.Exit(1)
	}

}
