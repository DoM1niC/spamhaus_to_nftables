# Example
`python spamhaus_to_nftables.py`

# NFTables

```
	chain input {
            type filter hook input priority 0; policy drop;
			
			# Blacklists
			ip saddr {$Blocklist_v4} drop
			ip6 saddr {$Blocklist_v6} drop
	}
	chain forward {
		    type filter hook forward priority filter; policy drop;

			# Blacklists
			ip saddr {$Blocklist_v4} drop
			ip6 saddr {$Blocklist_v6} drop
	}
```
