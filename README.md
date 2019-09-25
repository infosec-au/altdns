# Altdns - Subdomain discovery through alterations and permutations

Altdns is a DNS recon tool that allows for the discovery of subdomains that conform to patterns. Altdns takes in words that could be present in subdomains under a domain (such as test, dev, staging) as well as takes in a list of subdomains that you know of.

From these two lists that are provided as input to altdns, the tool then generates a _massive_ output of "altered" or "mutated" potential subdomains that could be present. It saves this output so that it can then be used by your favourite DNS bruteforcing tool.

Alternatively, the `-r` flag can be passed to altdns so that once this output is generated, the tool can then resolve these subdomains (multi-threaded) and save the results to a file.

Altdns works best with large datasets. Having an initial dataset of 200 or more subdomains should churn out some valid subdomains via the alterations generated.

Further information on attack methodology and this tool release can be found here: https://docs.google.com/presentation/d/1PCnjzCeklOeGMoWiE2IUzlRGOBxNp8K5hLQuvBNzrFY/

# Installation

`pip install py-altdns`

# Usage

`# altdns -i subdomains.txt -o data_output -w words.txt -r -s results_output.txt`

- `subdomains.txt` contains the known subdomains for an organization
- `data_output` is a file that will contain the _massive_ list of altered and permuted subdomains
- `words.txt` is your list of words that you'd like to permute your current subdomains with (i.e. `admin`, `staging`, `dev`, `qa`) - one word per line
- the `-r` command resolves each generated, permuted subdomain
- the `-s` command tells altdns where to save the results of the resolved permuted subdomains. `results_output.txt` will contain the final list of permuted subdomains found that are valid and have a DNS record.
- the `-t` command limits how many threads the resolver will use simultaneously
- `-d 1.2.3.4` overrides the system default DNS resolver and will use the specified IP address as the resolving server. Setting this to the authoritative DNS server of the target domain *may* increase resolution performance 

# Screenshots

<img src="https://i.imgur.com/fkfZqkl.png" width="600px"/>

<img src="https://i.imgur.com/Jyfue26.png" width="600px"/>

# Show some love

If this tool was useful at all to you during DNS recon stages - we'd love to know. Any suggestions or ideas for this tool are welcome - just tweet [@infosec_au](https://twitter.com/infosec_au) or [@nnwakelam](https://twitter.com/nnwakelam) and we'll work on it.
