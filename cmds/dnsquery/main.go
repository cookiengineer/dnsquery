package main

import "dnsquery/console"
import "dnsquery/actions"
import "dnsquery/files"
import "os"
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

			subject := strings.TrimSpace(subjects[s])

			if subject != "" {

				changed_subject := actions.Resolve(&hosts, subject)

				if changed_subject == true {
					changed_hosts = true
				}

			}

		}

		if changed_hosts == true {

			if hosts.Write() == true {
				console.Info("Write /etc/hosts")
				result = true
			} else {
				console.Error("Write /etc/hosts")
				console.Error("ERROR: Could not write /etc/hosts")
			}

		} else {
			console.Warn("Skip /etc/hosts")
			result = true
		}

	}

	if result == true {
		console.Info("SUCCESS")
		os.Exit(0)
	} else {
		console.Error("ERROR")
		os.Exit(1)
	}

}
