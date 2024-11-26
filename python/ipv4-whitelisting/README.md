# Ipv4 whitelisting

In one of the projects I needed to implement a solution that can remove
certain Ipv4 addresses or Ipv4 ranges from a big list (hundred of thousands) of Ipv4
addresses.

The constraints were roughly this (doesn't include all):
* the solution must be relatively fast - in order of seconds, max 10s of
  seconds
* the whitelists can be given both as ranges (e.g. 10.0.1.0/24) and addresses
  (e.g. 10.0.1.1). 
* the whitelists itself may be relatively big.
* the list of whitelisted addresses/ranges is not known at the beginning of the
  runtime
* the list of whitelisted addresses/ranges may change during the runtime (and thus
  has to be dynamically realoaded)

### Sample files:
* `ipv4.py` - implements some utility functions for working with ipv4 addresses
* `whitelist.py` - implements the whitelisting logic
* `test_xy.py` - tests for respective modules
