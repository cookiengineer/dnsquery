
# dnsquery

Dead-simple DNS client implemented in pure go that uses a ronin and caches the results in
the local `/etc/hosts` file to prevent DNS tracking in hostile environments.


## Installation

```bash
# Clone
git clone https://github.com/cookiengineer/dnsquery.git ./dnsquery;

# Build
cd ./dnsquery;
go build -o dnsquery ./cmds/dnsquery/main.go;

# Install
sudo mv dnsquery /usr/bin/dnsquery;
sudo chmod +x /usr/bin/dnsquery;
```


## Usage

```bash
# Allow writes to /etc/hosts for non-root users
sudo chmod +w /etc/hosts;

# Resolve a censored domain through DNS ronin
dnsquery libgen.li;

# If it fails to resolve (exit code 1), try again
dnsquery libgen.li;
```


## Work-in-Progress

- [ ] Support Windows and `C:\%WINDIR%\system32\etc\hosts` file path?


## License

This project is licensed under the [GNU AGPL 3.0](./AGPL-3.0.md) license.


## Sponsorship

If you like the work that I do and want me to continue working on things
like this; it would be awesome if you would sponsor this project:

https://github.com/sponsors/cookiengineer

